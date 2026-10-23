from pathlib import Path
from bisect import bisect_right
import argparse,gzip,hashlib,json,struct
q=argparse.ArgumentParser();q.add_argument('artifact',type=Path);a=q.parse_args();capture=a.artifact/'uat'
m=json.loads((capture/'manifest.json').read_text());plan=json.loads((capture/'replay-plan.json').read_text());held=json.loads((a.artifact/'held-phase.json').read_text());native=json.loads((a.artifact/'native-verification.json').read_text())
assert m['complete']and not m.get('scope')and m['width']==43 and m['page_size']==0x4000
assert not m['table_addresses_changed_during_capture']and not m['contexts_changed_during_capture']
assert native['pass']and native['all_producers_held']and native['full_UAT_capture']and native['source_replacements']==0
assert all(o['changed']and o['correct']and o['actual']==o['expected']for o in native['outputs'])
chunks=sorted(m['chunks'],key=lambda c:c['pa']);starts=[c['pa']for c in chunks];cache={};total=0
assert all(c['pa']%0x4000==0 and c['size']>0 and c['size']%0x4000==0 for c in chunks)
assert all(x['pa']+x['size']<=y['pa']for x,y in zip(chunks,chunks[1:]))
for c in chunks:
 data=gzip.decompress((capture/c['file']).read_bytes());assert len(data)==c['size']and hashlib.sha256(data).hexdigest()==c['sha256'];total+=len(data)
for pa in m['table_addresses']:
 data=(capture/f'table-{pa:x}.bin').read_bytes();assert len(data)==0x4000 and hashlib.sha256(data).hexdigest()==m['table_sha256'][hex(pa)]
def physical(pa,size):
 result=bytearray()
 while size:
  i=bisect_right(starts,pa)-1;assert i>=0;c=chunks[i];assert pa<c['pa']+c['size']
  if i not in cache:cache[i]=gzip.decompress((capture/c['file']).read_bytes())
  n=min(size,c['pa']+c['size']-pa);at=pa-c['pa'];result.extend(cache[i][at:at+n]);pa+=n;size-=n
 return bytes(result)
maps={}
for mapping in m['mappings']:
 if not mapping['dram']:continue
 maps.setdefault(mapping['context'],[]).append(mapping)
 pa=mapping['pa'];end=pa+mapping['size']
 while pa<end:
  i=bisect_right(starts,pa)-1;assert i>=0 and pa<chunks[i]['pa']+chunks[i]['size'];pa=min(end,chunks[i]['pa']+chunks[i]['size'])
for rows in maps.values():rows.sort(key=lambda x:x['va'])
def virtual(context,va,size):
 result=bytearray();rows=maps[context];starts_va=[r['va']for r in rows]
 while size:
  i=bisect_right(starts_va,va)-1;assert i>=0;r=rows[i];assert va<r['va']+r['size']
  n=min(size,r['va']+r['size']-va);result.extend(physical(r['pa']+va-r['va'],n));va+=n;size-=n
 return bytes(result)
assert plan['submissions']==held['groups']and held['complete']
for pub in plan['publications']:
 assert virtual(-1,pub['cursors'][2]['va'],4)==struct.pack('<I',pub['old'])
 for message in pub['all_messages']:
  assert virtual(-1,pub['ring']+message['slot']*24,24)==bytes.fromhex(message['message'])
  for item in message['items']:
   group=held['groups'][item['group']]if item['kind']==15 else None
   ring=group['ring']if group else struct.unpack_from('<Q',virtual(-1,message['queue'],24),8)[0]
   assert virtual(-1,ring+item['index']*8,8)==struct.pack('<Q',item['work'])
   assert virtual(-1,item['work'],4)==struct.pack('<I',item['kind'])
   if group:assert virtual(-1,item['work'],0xc0)==(a.artifact/group['wrapper_file']).read_bytes()
   else:assert virtual(-1,item['work'],0x40)==bytes.fromhex(item['data'])
for o in plan['outputs']:
 assert o['size']==160 and len(bytes.fromhex(o['seed']))==len(bytes.fromhex(o['expected']))==160
 assert o['seed']!=o['expected']and virtual(o['context'],o['va'],o['size'])==bytes.fromhex(o['seed'])
 assert physical(o['pa'],o['size'])==bytes.fromhex(o['seed'])
 assert bytes.fromhex(o['expected'])[-64:]==b'\xa5'*64
 if plan['phase']=='late'and o['role']=='parent':
  assert struct.unpack_from('<8I',bytes.fromhex(o['expected']),64)==tuple(0x5a220000|i for i in range(8))
descriptors=[]
for g in plan['submissions']:
 assert g['unique_pending_descriptor']and g['descriptor']
 pending=[c for c in g['candidates']if c['pending']and c['grid']==g['grid']];assert len(pending)==1;c=pending[0]
 body=virtual(-1,c['descriptor'],0x1000);assert body==(a.artifact/c['body_file']).read_bytes()
 assert struct.unpack_from('<I',body)[0]==3 and struct.unpack_from('<I',body,0xc)[0]==g['context']
 record=virtual(-1,g['scratch_high']+c['slot']*512,512)
 snapshot=(a.artifact/g['record_file']).read_bytes();assert len(snapshot)==0x20000 and record==snapshot[c['slot']*512:(c['slot']+1)*512]
 assert struct.unpack_from('<Q',record,0x10)[0]==g['descriptor']and struct.unpack_from('<Q',record,0x18)[0]==g['queue']
 assert struct.unpack_from('<I',body,0xf50)[0]==c['ready']*256 and struct.unpack_from('<I',body,0xf60)[0]==c['ready']
 descriptors.append(dict(queue=g['queue'],context=g['context'],descriptor=g['descriptor'],slot=c['slot'],ready=c['ready'],local_count=c['local_count'],completed_stamp=c['completed_stamp'],expected_stamp=c['expected_stamp']))
report=dict(pass_=True,phase=plan['phase'],total_bytes=total,tables=len(m['table_addresses']),groups=len(plan['submissions']),descriptors=descriptors,contexts=sorted({o['context']for o in plan['outputs']}),output_bytes=sum(o['size']for o in plan['outputs']),unique_parent_job_markers=plan['unique_job_markers_required'],native_outputs_verified=True,all_mappings_covered=True,stable_tables_and_contexts=True,all_hardware_producers_held=True,plain_replay_qualified=False,source_replacement_pages=0,apple_binary_disassembly_performed=False,manifest_sha256=hashlib.sha256((capture/'manifest.json').read_bytes()).hexdigest());report['pass']=report.pop('pass_');(a.artifact/'capture-validation.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS stable held capture',plan['phase'],total,'bytes',len(descriptors),'bounded pending descriptors, all output/progress/guard seeds; cold replay still required')
