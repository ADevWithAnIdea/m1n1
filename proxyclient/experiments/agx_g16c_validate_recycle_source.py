#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Match complete production Rust objects to the two-client recycling capture.

Run from the bootloader checkout after validating native-recycle-v1 and the
independent cold-recycle-v2 replay. Compile the actual production versions macro,
Default templates and constructors. Compare every byte of two descriptors, two
SKSM records, two wrappers, two close controls and sixteen register writes.
The reference resets client-local counts while retaining the scratch sequence.
Captured payload bytes are comparison oracles, never Rust construction inputs.
Hardware source replacement is qualified separately by its actual replay result.
"""
from pathlib import Path
from bisect import bisect_right
import gzip,json,hashlib,struct,subprocess,sys
import argparse
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--artifact',type=Path,required=True,
    help='Validated fresh-client reference containing native-recycle-v1 and cold-recycle-v2')
parser.add_argument('--linux',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True,help='Fresh output directory')
args=parser.parse_args()
out=args.artifact.resolve();linux=args.linux.resolve();tests=linux/'drivers/gpu/drm/asahi/tests';sys.path.insert(0,str(tests));import host_versions
root=out/'native-recycle-v1';baseline=json.loads((out/'cold-recycle-v2/result.json').read_text());assert baseline['pass']and baseline['both_fresh_client_phases_qualified']and not baseline['firmware_failed']and not baseline['hypervisor_used']
build=args.output.resolve();build.mkdir(exist_ok=False);flags=host_versions.build(build)
class Capture:
 def __init__(self,path):
  self.path=path;self.m=json.loads((path/'manifest.json').read_text());self.chunks=sorted(self.m['chunks'],key=lambda r:r['pa']);self.starts=[r['pa']for r in self.chunks];self.cache={};self.maps=sorted([r for r in self.m['mappings']if r['context']==-1 and r['dram']],key=lambda r:r['va']);self.vs=[r['va']for r in self.maps]
 def read(self,va,size):
  result=bytearray()
  while size:
   j=bisect_right(self.vs,va)-1;assert j>=0;r=self.maps[j];assert va<r['va']+r['size'];pa=r['pa']+va-r['va'];i=bisect_right(self.starts,pa)-1;assert i>=0;c=self.chunks[i];assert pa<c['pa']+c['size']
   if i not in self.cache:self.cache[i]=gzip.decompress((self.path/c['file']).read_bytes())
   n=min(size,r['va']+r['size']-va,c['pa']+c['size']-pa);at=pa-c['pa'];result.extend(self.cache[i][at:at+n]);va+=n;size-=n
  return bytes(result)
sha=lambda data:hashlib.sha256(data).hexdigest()
code=['#![allow(dead_code)]\nuse std::path::Path;\n']
for name,source in [('wire','scheduled_compute.rs'),('work','scheduled_work.rs'),('execution','scheduled_execution_g16c.rs'),('lifetime','scheduled_lifetime.rs')]:code.append(f'#[path={json.dumps(str(tests.parent/source))}] mod {name};\n')
code.append('fn main(){let d=std::env::args().nth(1).unwrap();let d=Path::new(&d);\n')
manifest=dict(source_payload_bytes_copied=False,baseline=str(out/'cold-recycle-v2/result.json'),baseline_sha256=sha((out/'cold-recycle-v2/result.json').read_bytes()),phases={},source_sha256={str(p.relative_to(linux)):sha(p.read_bytes())for p in [tests.parent/'scheduled_compute.rs',tests.parent/'scheduled_work.rs',tests.parent/'scheduled_execution_g16c.rs',tests.parent/'scheduled_lifetime.rs',linux/'rust/macros/versions.rs']});expected={};serial=0
inventory={}
for name in ['recycle-0','recycle-1']:
 capture=Capture(root/name/'uat');plan=json.loads((root/name/'uat/replay-plan.json').read_text());phase=dict(objects=[],transactions_file=name+'-transactions.bin');manifest['phases'][name]=phase
 descriptors=([dict(context=g['context'],queue=g['queue'],scratch_high=g['scratch_high'],**r)for g in inventory['rows']for r in g['records']if r['pending']]if name=='late'else[dict(context=g['context'],queue=g['queue'],scratch_high=g['scratch_high'],descriptor=g['descriptor'],slot=g['item'])for g in plan['submissions']])
 for row in descriptors:
  address=row['descriptor'];body=capture.read(address,0x1000);q=lambda at:struct.unpack_from('<Q',body,at)[0];w=lambda at:struct.unpack_from('<I',body,at)[0];h=lambda at:struct.unpack_from('<H',body,at)[0]
  pairs=[struct.unpack_from('<IQ',body,0x40+i*12)for i in range(h(0x1e))];values=dict(pairs);first=lambda reg:next(v for n,v in pairs if n==reg)
  params=dict(save_area=values[0x1a510],cdm=values[0x1a420],identity=values[0x1a540],context=w(0xc),ordinal=values[0x10201]&255,robustness=values[0x14070]&~1,operand_state=values[0xa5c1]-5,helper_binary=values.get(0x11841,0),helper_data=values.get(0x11849,0),helper_config=values.get(0x11f81,0),execution_gate=values[0x14028],register_a599=first(0xa599))
  usc='Some('+str(values[0x10071])+')'if 0x10071 in values else'None'
  code.append('let program=wire::ProgramParameters{'+','.join(f'{k}:{v}'for k,v in params.items())+',usc_exec_base:'+usc+'};\nlet program=wire::ComputeProgramG16C::new(&program).unwrap();\n')
  code.append('assert_eq!(program.registers(),&['+','.join(f'({n},{v})'for n,v in pairs)+']);\n')
  descriptor=dict(save_area=values[0x1a510],cdm=values[0x1a420],identity=values[0x1a540],sequence=q(4),context=w(0xc),scheduler=q(0x10),alias=q(0x740)-0x40,terminator=q(0xee0),sampler_array=q(0xf2c),sampler_count=w(0xf34),grid=w(0xf54),queue_submission=w(0xf50)>>8,queue_ordinal=w(0xf58),submission_index=w(0xf60),ordinal=w(0xf70),support=q(0xfb2),support_control=w(0xfba),support_flags=w(0xfbe),support_kind=h(0xfc5),support_phase=body[0xfd3],zero_page=q(0xfcb))
  code.append('let p=wire::Parameters{'+','.join(f'{k}:{v}'for k,v in descriptor.items())+f',dispatch:[{q(0xf40)},{q(0xf48)}],status:[{q(0xf7c)},{q(0xf84)}],timestamps:[{q(0xf8c)},{q(0xf94)}]'+'};\n')
  filename=f'{name}-{serial:02d}-descriptor.bin';serial+=1
  code.append(f'let mut raw=vec![0u8;0x1000];wire::ComputeDescriptorG16C::write(&mut raw,&p,program.registers()).unwrap();std::fs::write(d.join("{filename}"),&raw).unwrap();\n');expected[filename]=body;phase['objects'].append(dict(kind='descriptor',address=address,bytes=0x1000,file=filename,inputs=descriptor,program_inputs=params))
  record_address=row['scratch_high']+row['slot']*512;raw=capture.read(record_address,512);rq=lambda at:struct.unpack_from('<Q',raw,at)[0];header=rq(0);dep=rq(0x20);points=[];enabled=dep&0xffffffff;assert enabled in [1,3,7,15]
  for i in range(enabled.bit_count()):
   point=rq(0x28+i*8);points.append((point>>40,point&0xffffffff))
  grid=descriptor['grid'];own=[v for g,v in points if g==grid];assert len(own)==1
  assert struct.unpack_from('<I',raw,0x144)[0]in(0,0x40000000)
  fields=dict(ready=bool(struct.unpack_from('<I',raw,0x144)[0]),descriptor=address,queue=row['queue'],grid=grid,item=own[0],primary_count=h(0x1e)-2,timeout=dep>>48,retire_control=rq(0x138),flags=header&0xf000000000000000,control=(dep>>32)&0xffff,control_130=rq(0x130))
  filename=f'{name}-{serial:02d}-record.bin';serial+=1
  code.append('let p=work::RecordParametersG16C{'+','.join(f'{k}:{str(v).lower() if isinstance(v,bool) else v}'for k,v in fields.items())+f',header_grid:Some({(header>>42)&127}),header_count:Some({(header>>2)&0x3fffffff}),'+ '..Default::default()};\n')
  code.append(f'let raw=work::WorkRecordG16C::for_compute_control_dependencies(&p,{fields["control"]},&['+','.join(f'({g},{v})'for g,v in points)+f']).unwrap();std::fs::write(d.join("{filename}"),raw.as_bytes()).unwrap();\n');expected[filename]=raw;phase['objects'].append(dict(kind='record',address=record_address,bytes=512,file=filename,inputs=fields,dependencies=points))
 for group in plan['submissions']:
  address=group['work'];raw=capture.read(address,0xc0);q=lambda at:struct.unpack_from('<Q',raw,at)[0];h=lambda at:struct.unpack_from('<H',raw,at)[0]
  fields=dict(scratch_low=q(8),scratch_high=q(0x10),support=q(0x36),queue_control=q(0x4a),grid=h(0x18),item=h(0x2a),ordinal=h(0x3e),context=h(0x32),support_id=h(0x56),uuid=h(0x5a),scheduler=h(0x1e),scheduler_hint=h(0x46),field_52=h(0x52),field_5e=h(0x5e),field_62=h(0x62))
  filename=f'{name}-{serial:02d}-wrapper.bin';serial+=1
  code.append('let p=work::WrapperParameters{'+','.join(f'{k}:{str(v).lower() if isinstance(v,bool) else v}'for k,v in fields.items())+',first:'+('true'if h(0x1a)else'false')+'};\n')
  code.append(f'let raw=work::WorkWrapperG16C::new(&p).unwrap();std::fs::write(d.join("{filename}"),raw.as_bytes()).unwrap();\n');expected[filename]=raw;phase['objects'].append(dict(kind='wrapper',address=address,bytes=0xc0,file=filename,inputs=fields,first=bool(h(0x1a))))
 code.append('let mut transactions=Vec::<u8>::new();\n')
 emit=lambda event,g,resume:code.append(f'for(offset,width,value)in execution::BindingG16C::compute({event},{g["scratch_low"]}).unwrap().'+('resume_transactions()'if resume else'transactions()')+'{transactions.extend_from_slice(&(offset as u32).to_le_bytes());transactions.push(width);transactions.extend_from_slice(&value.to_le_bytes());}\n')
 emit(0,plan['submissions'][0],name=='recycle-1')
 code.append(f'std::fs::write(d.join("{phase["transactions_file"]}"),transactions).unwrap();\n')
controls=json.loads((root/'recycle-1/startup-history.json').read_text())['controls'];assert [r['kind']for r in controls]==[0x2e,0x14];manifest['controls']=[]
for i,row in enumerate(controls):
 raw=bytes.fromhex(row['message']);filename=f'close-{i}.bin'
 if row['kind']==0x2e:code.append('let raw=lifetime::LifetimeTickG16C::default();\n')
 else:
  context=struct.unpack_from('<Q',raw,12)[0];close_flags=struct.unpack_from('<I',raw,8)[0];prefix=[(close_flags>>8)&255,(close_flags>>16)&255,0,0]
  code.append(f'let raw=lifetime::ContextCloseG16C::new({context},[{prefix[0]},{prefix[1]},0,0]).unwrap();\n')
 code.append(f'std::fs::write(d.join("{filename}"),raw.bytes()).unwrap();\n');expected[filename]=raw;manifest['controls'].append(dict(kind=row['kind'],file=filename,bytes=64,sha256=sha(raw)))
code.append('}\n');(build/'source.rs').write_text(''.join(code));subprocess.run(['rustc','--edition=2021','-Dwarnings',str(build/'source.rs'),*flags,'-o',str(build/'source-builder')],check=True);subprocess.run([str(build/'source-builder'),str(build)],check=True)
for filename,data in expected.items():
 actual=(build/filename).read_bytes()
 if actual!=data:
  differences=[i for i,(a,b)in enumerate(zip(actual,data))if a!=b];raise ValueError((filename,len(actual),len(data),differences[:24]))
for name,phase in manifest['phases'].items():
 for obj in phase['objects']:obj['sha256']=sha((build/obj['file']).read_bytes());assert obj['bytes']==(build/obj['file']).stat().st_size
 history=json.loads((root/name/'startup-history.json').read_text());writes=[w for w in history['writes']if not w['before_init']and w['address']-0x288000000 in(0xd06030,0x4090,0x4098,0x21068,0x21070)]
 if name=='recycle-1':assert len(writes)==16;writes=writes[12:]
 else:assert len(writes)==12
 want=b''.join(struct.pack('<IBQ',w['address']-0x288000000,w['width'],w['value'])for w in writes);assert(build/phase['transactions_file']).read_bytes()==want;phase['transactions_sha256']=sha(want);phase['transactions_count']=len(writes)
from collections import Counter
assert Counter(obj['kind']for phase in manifest['phases'].values()for obj in phase['objects'])=={'descriptor':2,'record':2,'wrapper':2}
assert sum(phase['transactions_count']for phase in manifest['phases'].values())==16
assert len(manifest['controls'])==2 and sum(len(v)for v in expected.values())==9728
manifest.update(all_generated_bytes_match_complete_captured_objects=True,descriptors=2,records=2,wrappers=2,source_object_bytes=sum(len(v)for v in expected.values()),source_file_sha256=sha((build/'source.rs').read_bytes()),kernel_source_unchanged=True,hardware_source_replay_qualified=False)
(build/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print('PASS production macro-generated Rust:2 complete descriptors,2 full SKSM records,2 wrappers,2 close controls,16 ordered transactions match RE bytes; no payload bytes copied')
