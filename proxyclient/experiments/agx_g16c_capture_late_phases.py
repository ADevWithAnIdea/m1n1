# SPDX-License-Identifier: MIT
"""Capture one own Metal compute at its kick in a single-user native guest.

Load with run_guest.py -m and M4MAX_COMPUTE_ARTIFACT set to a fresh directory.
The console launcher arms this hook with the workload's actual GPU address.
Hold the producer until the kick so autonomous firmware cannot race the page
copy. All earlier native work passes through. No source replacements run in
this guest; replay and bisection use a separately reset plain m1n1 session.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import struct
import subprocess
import time
import traceback

from m1n1.g16c.memory import AddressSpace, PA_MASK
from m1n1.hv import TraceMode
from m1n1.toolchain import Toolchain
from m1n1.utils import irange

assert iface.devpath == '/dev/cu.usbmodemJPWWJRX2N01'
assert u.adt.model == 'Mac16,5' and p.get_chipid() == 0x6041
assert '-s' in hv.tba.cmdline.split(), 'GPU reference captures require single-user mode'
hv.wdt_cpu = None
hv.map_vuart()
try:
    del hv.adt['/arm-io/qspi/spinor/anvram']
except KeyError:
    pass
single_directory = Path(os.environ['M4MAX_COMPUTE_ARTIFACT'])
single_directory.mkdir(parents=True, exist_ok=True)
assert not (single_directory/'armed').exists()
single_state = dict(mailbox=0, installed=False, held=None,
                    single_user=True, apple_binary_disassembly_performed=False)
single_target_submissions=int(os.environ.get('M4MAX_SINGLE_USER_COMPUTE_SUBMISSIONS','1'))
assert single_target_submissions in (1,2)
single_state.update(target_submissions=single_target_submissions,submissions=[],deferred_kicks=[],
                    auxiliary_publications=[])
single_state['hold_render_pair'] = os.environ.get('M4MAX_SINGLE_USER_HOLD_RENDER_PAIR')=='1'
single_state['render_kick_only_pair'] = os.environ.get('M4MAX_SINGLE_USER_RENDER_KICK_ONLY_PAIR')=='1'
single_capture_first = os.environ.get('M4MAX_SINGLE_USER_CAPTURE_FIRST') == '1'
single_two_compute_queues = os.environ.get('M4MAX_SINGLE_USER_TWO_COMPUTE_QUEUES') == '1'
single_hold_two_compute_producers = os.environ.get('M4MAX_SINGLE_USER_HOLD_TWO_COMPUTE_PRODUCERS') == '1'
assert not single_hold_two_compute_producers or single_two_compute_queues
single_profile = os.environ.get('M4MAX_SINGLE_USER_WORKLOAD', 'compute')
assert single_profile in ('compute', 'render-pixel', 'render-compute','compute-render')
single_state['workload'] = single_profile
single_render = None
assert not single_capture_first or single_target_submissions == 2
assert not single_two_compute_queues or (single_profile == 'compute'
    and single_target_submissions == 2 and not single_capture_first)
single_state['two_compute_queues'] = single_two_compute_queues
single_history_enabled = os.environ.get('M4MAX_SINGLE_USER_STARTUP_HISTORY') == '1'
single_history = dict(single_user=True,hypervisor_used=True,
    apple_binary_disassembly_performed=False,writes=[],controls=[],truncated=False,
    write_limit=25000,aperture=list(hv.adt['/arm-io/sgx'].get_reg(0)))
single_tc = Toolchain()
single_elf = Path('build/m1n1-raw.elf')
single_symbols = subprocess.check_output([single_tc.NM,'--defined-only',str(single_elf)],text=True)
single_offsets = re.findall(r'^([0-9a-fA-F]+)\s+\w\s+sptm$',single_symbols,re.M)
assert len(single_offsets) == 1
single_sptm_offset = int(single_offsets[0],16)
single_dwarf = subprocess.check_output([str(Path(single_tc.NM).with_name('llvm-dwarfdump')),
    '--name=uat_global_state',str(single_elf)],text=True)
single_offsets = re.findall(r'DW_AT_data_member_location\s+\((0x[0-9a-fA-F]+)\)',single_dwarf)
assert len(single_offsets) == 1
single_member_offset = int(single_offsets[0],16)
single_state['elf_sha256'] = hashlib.sha256(single_elf.read_bytes()).hexdigest()


def single_global_root():
    state = p.read64(u.base+single_sptm_offset+single_member_offset)
    assert state and not state & 0x3fff
    return p.read64(state+0x10) & PA_MASK


def single_space(context):
    ttbs = hv.adt['/arm-io/sgx'].gpu_region_base
    p.dc_ivac(ttbs+context*16,16)
    roots = [p.read64(ttbs+context*16+i*8) & PA_MASK for i in range(2)]
    if context == 0:
        roots[1] = single_global_root()
    assert all(roots)
    return AddressSpace(u,context,*roots)


def single_read(address,size):
    return single_space(0).read(address,size)


def single_history_save():
    temporary = single_directory/'startup-history.tmp'
    temporary.write_text(json.dumps(single_history,indent=2)+'\n')
    temporary.replace(single_directory/'startup-history.json')


def single_startup_config(evt):
    capture_next_phase()
    if single_state.get('captured'):
        return
    if len(single_history['writes']) >= single_history['write_limit']:
        single_history['truncated'] = True
        return
    single_history['writes'].append(dict(address=evt.addr,value=evt.data,
        width=8 << evt.flags.WIDTH,before_init=not single_state['installed'],time=time.time(),capture_directory=str(single_directory)))
    if len(single_history['writes']) % 100 == 0:
        single_history_save()


def single_control(address,value,width,route):
    capture_next_phase()
    assert width == 32 and 0 <= value < 256
    if single_state.get('captured'):
        # The kick-boundary history is complete. Forward later guest cleanup
        # without recording it as part of the replay prefix.
        p.write32(address,value)
        return
    old = p.read32(address)
    count = (value-old) % 256
    assert count <= 32
    for index in range(count):
        assert len(single_history['controls']) < 512, 'bound startup control history'
        slot = (old+index) % 256
        message = single_read(route[3]+slot*0x40,0x40)
        serial = len(single_history['controls'])
        kind = struct.unpack_from('<I',message)[0]
        entry = dict(serial=serial,slot=slot,kind=kind,message=message.hex(),time=time.time())
        if kind == 0x20:
            context = struct.unpack_from('<I',message,4)[0]
            support,table,end = struct.unpack_from('<3Q',message,0x14)
            assert 1 <= context < 64 and support
            data = single_read(support,0x100)
            filename = f'startup-support-{serial:04d}.bin'
            (single_directory/filename).write_bytes(data)
            entry.update(context=context,support=support,table=table,end=end,
                support_file=filename,resource_class=struct.unpack_from('<I',data,0x10)[0])
            if (entry['resource_class'] in (1,2)
                    and struct.unpack_from('<I',data,0x1c)[0] == 0x200000
                    and struct.unpack_from('<Q',data,0x30)[0] == table
                    and struct.unpack_from('<I',data,0x40)[0] == 4):
                filename = f'startup-table-{serial:04d}.bin'
                (single_directory/filename).write_bytes(single_space(context).read(table,0x1000))
                entry['table_file'] = filename
        single_history['controls'].append(entry)
    single_history_save()
    p.write32(address,value)


# Source appended to the established single-user boot/history hooks by the
# prepare script. These are protocol DATA observations, never disassembly.
capture_root=single_directory
capture_phase=None
capture_parent_context=None

def capture_next_phase():
    global capture_phase,single_directory
    request=capture_root/'phase-request.json'
    if not request.exists():return
    spec=json.loads(request.read_text())
    if capture_phase is not None and capture_phase['spec']['name']==spec['name']:return
    assert spec['name']in ('warm','late','resume')
    assert capture_phase is None or capture_phase.get('complete')
    single_directory=capture_root/spec['name'];single_directory.mkdir(exist_ok=False)
    capture_phase=dict(spec=spec,producers={},queue_heads={},publications=[],groups=[],kicks=[],complete=False)
    (single_directory/'output-spec.json').write_text(json.dumps(spec,indent=2)+'\n')
    single_state.update(held=None,submissions=[],deferred_kicks=[],auxiliary_publications=[],captured=False)
    print('Armed held full-UAT phase',spec['name'],flush=True)

def capture_save():
    (single_directory/'held-phase.json').write_text(json.dumps(capture_phase,indent=2)+'\n')

def single_producer_read(address,width,channel,route):
    capture_next_phase();assert width==32
    if capture_phase is not None and not capture_phase['complete']:
        row=capture_phase['producers'].get(str(address))
        if row:return row['new']
    return p.read32(address)

def capture_group(work,queue,header,pointers,ring,jobs,previous,head,index,channel,route):
    wrapper=single_read(work,0xc0);assert struct.unpack_from('<I',wrapper)[0]==15
    context=struct.unpack_from('<H',wrapper,0x32)[0];assert 1<=context<64
    scratch_low,scratch_high=struct.unpack_from('<2Q',wrapper,8)
    grid=struct.unpack_from('<H',wrapper,0x18)[0]
    gi=len(capture_phase['groups']);prefix=f'group-{gi:03d}'
    (single_directory/(prefix+'-wrapper.bin')).write_bytes(wrapper)
    records=single_read(scratch_high,0x20000);(single_directory/(prefix+'-sksm.bin')).write_bytes(records)
    candidates=[]
    for slot in range(256):
        record=records[slot*512:(slot+1)*512]
        record_header=struct.unpack_from('<Q',record)[0]
        descriptor,record_queue=struct.unpack_from('<2Q',record,0x10)
        ready=(record_header>>2)&0x3fffffff
        if record_queue!=queue or (record_header>>42)&127!=grid:continue
        if not 1<=ready<=0xffffff or slot!=(ready&255):continue
        if not 0xfffffc20c0018000<=descriptor<0xfffffc2100000000 or descriptor&31:continue
        body=single_read(descriptor,0x1000)
        if struct.unpack_from('<I',body)[0]!=3 or struct.unpack_from('<I',body,0xc)[0]!=context:continue
        filename=f'{prefix}-candidate-{slot:03d}.bin';(single_directory/filename).write_bytes(body)
        stamp_address=struct.unpack_from('<Q',body,0xf40)[0]
        stamp=struct.unpack('<I',single_read(stamp_address,4))[0]
        expected_stamp=struct.unpack_from('<I',body,0xf50)[0]
        generation=struct.unpack_from('<I',body,0xf60)[0]
        candidate=dict(slot=slot,descriptor=descriptor,body_file=filename,ready=ready,
            local_count=struct.unpack_from('<Q',body,4)[0],stamp_address=stamp_address,
            completed_stamp=stamp,expected_stamp=expected_stamp,generation=generation,
            grid=struct.unpack_from('<I',body,0xf54)[0],
            scheduler=struct.unpack_from('<Q',body,0x10)[0],
            pending=(stamp<expected_stamp and expected_stamp==ready*256 and generation==ready))
        candidates.append(candidate)
    group=dict(work=work,queue=queue,pointers=pointers,ring=ring,jobs=jobs,
        previous=previous,head=head,ring_index=index,context=context,
        scratch_low=scratch_low,scratch_high=scratch_high,grid=grid,
        wrapper_local_item=struct.unpack_from('<H',wrapper,0x2a)[0],
        support=struct.unpack_from('<Q',wrapper,0x36)[0],
        control=struct.unpack_from('<Q',header,0x9c)[0],
        channel=channel,route=list(route),candidates=candidates,
        record_file=prefix+'-sksm.bin',wrapper_file=prefix+'-wrapper.bin')
    pending=[c for c in candidates if c['pending']and c['grid']==grid]
    if len(pending)==1:
        group.update(descriptor=pending[0]['descriptor'],item=pending[0]['slot'],scheduler=pending[0]['scheduler'])
    group['unique_pending_descriptor']=len(pending)==1
    return group

def single_producer_impl(address,value,width,channel,route):
    global capture_parent_context
    capture_next_phase();assert width==32 and 0<=value<256
    if capture_phase is None or capture_phase['complete']:
        p.write32(address,value);return
    producers=capture_phase['producers'];key=str(address)
    if key not in producers:
        old=p.read32(address)
        producers[key]=dict(address=address,old=old,new=old,width=32,channel=channel,route=list(route))
    producer=producers[key];assert p.read32(address)==producer['old'],'held producer changed'
    old=producer['new'];count=(value-old)%256;assert count<=64
    for n in range(count):
        slot=(old+n)%256;message=single_read(route[3]+slot*24,24)
        queue=struct.unpack_from('<Q',message,8)[0];header=single_read(queue,0xa8)
        pointers,ring,jobs=struct.unpack_from('<3Q',header)
        pointer_data=single_read(pointers,0x80);capacity=struct.unpack_from('<I',pointer_data,0x60)[0]
        head=struct.unpack_from('<I',message,20)[0]&0xffff
        previous=capture_phase['queue_heads'].get(str(queue),struct.unpack_from('<I',pointer_data,0x30)[0])
        assert 0<capacity<=2048 and 0<=head<capacity and 0<=previous<capacity
        size=(head-previous)%capacity;assert size<=128
        pub=dict(address=address,channel=channel,route=list(route),slot=slot,message=message.hex(),
            queue=queue,previous=previous,head=head,capacity=capacity,items=[])
        for i in range(size):
            index=(previous+i)%capacity;work=struct.unpack('<Q',single_read(ring+index*8,8))[0]
            kind=struct.unpack('<I',single_read(work,4))[0]
            item=dict(kind=kind,work=work,index=index)
            if kind==15:
                group=capture_group(work,queue,header,pointers,ring,jobs,previous,head,index,channel,route)
                group.update(message=message.hex(),producer=address,old=producer['old'],new=value)
                if capture_parent_context is None:capture_parent_context=group['context']
                capture_phase['groups'].append(group);item['group']=len(capture_phase['groups'])-1
                single_state['held']=group
            else:
                assert kind in (14,16),'unqualified item kind; preserve rather than silently skip'
                item['data']=single_read(work,0x40).hex()
            pub['items'].append(item)
        capture_phase['publications'].append(pub);capture_phase['queue_heads'][str(queue)]=head
    producer['new']=value;single_state['submissions']=capture_phase['groups'];capture_save()
    # Physical firmware-visible producer stays unchanged. Guest reads above
    # see the shadow and may publish another group/process before capture.

def single_producer(*args,**kwargs):
    try:return single_producer_impl(*args,**kwargs)
    except Exception as error:
        capture_phase['error']=repr(error);capture_save();traceback.print_exc();raise SystemExit(2)from error

def single_capture_kick(payload,endpoint):
    capture_next_phase()
    if capture_phase is None or capture_phase['complete']:return False
    if endpoint&255!=0x21:return False
    # Bound work/control doorbells belonging to this known protocol family.
    if payload>>48!=0x83:return False
    capture_phase['kicks'].append(dict(payload=payload,endpoint=endpoint))
    capture_save()
    spec=capture_phase['spec'];groups=capture_phase['groups']
    contexts=sorted({g['context']for g in groups});queues={g['queue']for g in groups}
    if len(groups)<spec['minimum_groups']or len(contexts)<spec['contexts']or len(queues)<spec['queues']:
        return True
    if spec['name']=='late':assert capture_parent_context in contexts and len(contexts)==2
    else:assert contexts==[capture_parent_context]
    single_history_save()
    outputs=[]
    for requested in spec['outputs']:
        context=(capture_parent_context if requested['role']=='parent'else next(c for c in contexts if c!=capture_parent_context))
        space=single_space(context);data=space.read(requested['gpu_va'],requested['size'])
        assert data.hex()==requested['seed'],'all output/marker/guard bytes must remain poisoned'
        outputs.append(dict(context=context,role=requested['role'],va=requested['gpu_va'],
            pa=space.translate(requested['gpu_va']),size=requested['size'],seed=requested['seed'],expected=requested['expected']))
    for row in capture_phase['producers'].values():assert p.read32(row['address'])==row['old']
    helper=runpy.run_path('proxyclient/experiments/agx_g16c_capture_full_uat.py');capture=single_directory/'uat'
    helper['capture_full_uat'](hv,capture,single_global_root(),
        'own three-phase late ASID '+spec['name']+'; all pending producers held; full output/progress/guard checks')
    firmware=single_space(0);publications=[]
    for row in capture_phase['producers'].values():
        route=row['route'];pubs=[r for r in capture_phase['publications']if r['address']==row['address']]
        assert pubs
        last=pubs[-1]
        publications.append(dict(address=row['address'],value=row['new'],old=row['old'],width=32,channel=row['channel'],
            cursors=[dict(va=va,pa=firmware.translate(va),value=struct.unpack('<I',firmware.read(va,4))[0])for va in route[:3]],
            ring=route[3],ring_slot=last['slot'],ring_message=last['message'],all_messages=pubs))
    first=groups[0];pub=publications[0]
    plan=dict(phase=spec['name'],root=single_state['root'],main=single_state['main'],held=first,
        submissions=groups,publication=pub,publications=publications,cursors=pub['cursors'],
        ring=pub['ring'],ring_slot=pub['ring_slot'],ring_message=pub['ring_message'],
        output=outputs[0],outputs=outputs,application_context=first['context'],queue=first['queue'],
        channel=pub['channel'],kicks=capture_phase['kicks']+[dict(payload=0x0083000000000010,endpoint=0x21)],
        gpu_registers={hex(off):p.read32(0x288000000+off)for off in (0xd06030,0xd14000,0x1000104,0x1000108)},
        single_user=True,two_compute_queues=len(queues)==2,both_compute_producers_held=True,
        same_metal_API_queue=False,logical_parent_submissions=spec.get('parent_commands',0),
        unique_job_markers_required=spec.get('parent_commands',0),source_replacements=0)
    (capture/'replay-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    for row in capture_phase['producers'].values():
        assert p.read32(row['address'])==row['old'];p.write32(row['address'],row['new']);p.dc_cvac(row['address'],4)
    for kick in plan['kicks']:
        p.write64(0x28a608800,kick['payload']);p.write64(0x28a608808,kick['endpoint'])
    deadline=time.monotonic()+15
    while True:
        actual=[single_space(o['context']).read(o['va'],o['size'])for o in outputs]
        if all(data.hex()==o['expected']for data,o in zip(actual,outputs))or time.monotonic()>deadline:break
        time.sleep(.02)
    verification=dict(outputs=[dict(**o,actual=data.hex(),changed=data.hex()!=o['seed'],correct=data.hex()==o['expected'])for o,data in zip(outputs,actual)],
        all_producers_held=True,full_UAT_capture=True,source_replacements=0,plain_replay_qualified=False)
    verification['pass']=all(o['changed']and o['correct']for o in verification['outputs'])
    (single_directory/'native-verification.json').write_text(json.dumps(verification,indent=2)+'\n')
    assert verification['pass'],'native output/progress/guard oracle after held release failed'
    capture_phase['complete']=True;single_state['captured']=True;capture_save()
    print('Held native phase PASS',spec['name'],'all outputs/markers/guards; cold replay still required',flush=True)
    return True

def single_mailbox(address,value,width):
    capture_next_phase()
    if width == 128:
        single_mailbox(address,value[0],64)
        single_mailbox(address+8,value[1],64)
        return
    assert width == 64
    if address == 0x28a608800:
        single_state['mailbox'] = value
    elif value & 255 == 0x20 and single_state['mailbox'] >> 48 == 0x81 and not single_state['installed']:
        root = 0xfffff00000000000 | single_state['mailbox'] & ((1<<44)-1)
        main = struct.unpack_from('<Q',single_read(root,0xc8),0x18)[0]
        if single_history_enabled:
            bounded=[w for w in single_history['writes'] if w['width']==32 and
                (0x288e80000<=w['address']<0x288e80200 or
                 0x288e90000<=w['address']<0x288e95400)]
            single_history['pre_init_configuration_readback']={hex(w['address']):p.read32(w['address'])
                for w in bounded}
            single_history_save()
            helper = runpy.run_path('proxyclient/experiments/agx_g16c_capture_full_uat.py')
            helper['capture_full_uat'](hv,single_directory/'pre-init-uat',single_global_root(),
                'before initial GPU firmware graph publication')
        single_state.update(installed=True,root=root,main=main)
        data = single_read(main,0x500)
        if single_history_enabled:
            route = struct.unpack_from('<4Q',data,0x20+12*32)
            physical = single_space(0).translate(route[2])
            assert physical is not None
            single_history.update(root=root,main=main,control_ring=route[3])
            hv.add_tracer(irange(physical,4),'MaxSingleUserControlHistory',TraceMode.HOOK,
                write=single_control,route=route)
        channels = (tuple(range(12)) if single_profile in ('render-compute','compute-render') else
                    tuple(i for i in range(12) if i % 3 != 2) if single_render else (2,5,8,11))
        for channel in channels:
            route = struct.unpack_from('<4Q',data,0x20+channel*32)
            physical = single_space(0).translate(route[2])
            assert physical is not None
            hv.add_tracer(irange(physical,4),f'MaxSingleUserCompute{channel}',TraceMode.HOOK,
                          read=single_producer_read if single_hold_two_compute_producers else None,
                          write=single_producer,channel=channel,route=route)
    elif single_state['held'] is not None and not single_state.get('captured'):
        try:
            if single_capture_kick(single_state['mailbox'],value):
                return
        except Exception as error:
            single_state['error'] = repr(error)
            (single_directory/'capture-failure.json').write_text(json.dumps(single_state,indent=2)+'\n')
            traceback.print_exc()
            # A failed kick capture is terminal; do not re-enter an
            # unattended debug shell and overwrite the preserved capture.
            raise SystemExit(2) from error
    p.write64(address,value)


if single_profile in ('render-pixel','render-compute','compute-render'):
    assert not single_capture_first
    from m1n1.g16c.reference_render import Capture
    single_render = Capture(hv,p,u,single_state,single_directory,single_read,
                            single_space,single_global_root,single_history_save)
hv.add_tracer(irange(0x28a608800,16),'MaxSingleUserComputeMailbox',TraceMode.HOOK,write=single_mailbox)
if single_history_enabled:
    first,size = hv.adt['/arm-io/sgx'].get_reg(0)
    hv.add_tracer(irange(first,size),'MaxSingleUserStartupConfig',TraceMode.WSYNC,
        write=single_startup_config)
    single_history_save()
print('Single-user own-'+single_profile+' kick capture installed:',single_directory,flush=True)
