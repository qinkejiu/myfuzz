"""Code-owned single-GPIO fixed firmware, separate from candidate instruction slots.

Only the source-pinned PULP causal GPIO and registered native CPU IRQ adapters are
admitted by the live adapter. Encoding by itself grants no execution authority.
"""
from copy import deepcopy
from hashlib import sha256
import json
from .rv32_fixed_firmware import _lui_addi_load, _addi, _lw, _sw, _jal


def build_irq_firmware(*,image_start,image_end,first_fetch,gpio_base,pin,register_count=32):
    if type(register_count) is not int or register_count not in (16,32):
        raise ValueError('shared-IRQ-register-bank-unsupported')
    scratch_register=register_count-1
    if (any(type(v) is not int for v in (image_start,image_end,first_fetch,gpio_base,pin))
            or image_start%4096 or image_end%4 or image_end-image_start<=0x1100
            or not image_start<=first_fetch<image_start+0x180 or first_fetch%4
            or gpio_base%4096 or not 0<=gpio_base<2**32-4096 or not 0<=pin<32):
        raise ValueError('shared-IRQ-firmware-layout-unsupported')
    vector=image_start+0x200;handler=image_start+0x400;scratch=image_start+0xc00
    result=image_start+0xc40;dynamic=image_start+0x1000
    type_offset=28 if pin<16 else 32;type_value=2<<(2*(pin%16));mask=1<<pin
    # Fixed bootstrap: clear results/pending, enable the chosen physical pin,
    # configure both-edge type, then enable machine external/global IRQs.
    boot=[*_lui_addi_load(1,gpio_base),*_lui_addi_load(2,mask),_sw(2,1,4),_sw(2,1,24),
          *_lui_addi_load(2,type_value),_sw(2,1,type_offset),_lw(2,1,36),
          *_lui_addi_load(3,result),_sw(0,3,0),_sw(0,3,4),_sw(0,3,8),
          *_lui_addi_load(2,vector),(0x305<<20)|(2<<15)|(1<<12)|0x73,
          *_lui_addi_load(2,scratch),(0x340<<20)|(2<<15)|(1<<12)|0x73,
          *_lui_addi_load(2,1<<11),(0x304<<20)|(2<<15)|(2<<12)|0x73,
          _addi(2,0,8),(0x300<<20)|(2<<15)|(2<<12)|0x73]
    boot.append(_jal(first_fetch+4*len(boot),dynamic))
    # Preserve every register used by this handler. INTSTATUS is read-to-clear,
    # with pre-edge native trigger taking priority over that clear in the RTL.
    swap=(0x340<<20)|(scratch_register<<15)|(1<<12)|(scratch_register<<7)|0x73
    isr=[swap,*[_sw(r,scratch_register,(r-1)*4) for r in (1,2,3,4)],
         *_lui_addi_load(1,gpio_base),_lw(2,1,8),*_lui_addi_load(3,result),_sw(2,3,0),
         _lw(2,1,36),_sw(2,3,4),_lw(4,3,8),_addi(4,4,1),_sw(4,3,8),
         *[_lw(r,scratch_register,(r-1)*4) for r in (1,2,3,4)],swap,0x30200073]
    segments=[]
    for name,address,words in [('vector_direct',vector,[_jal(vector,handler)]),
            ('vector_external',vector+11*4,[_jal(vector+11*4,handler)]),
            ('handler',handler,isr),('bootstrap',first_fetch,boot)]:
        segments.append(dict(name=name,address=address,data_hex=b''.join(w.to_bytes(4,'little') for w in words).hex()))
    intervals=[(s['address'],s['address']+len(bytes.fromhex(s['data_hex']))) for s in segments]
    if any(not image_start<=a<b<=image_start+0x800 for a,b in intervals) or any(a<d and c<b for i,(a,b) in enumerate(intervals) for c,d in intervals[i+1:]):
        raise ValueError('shared-IRQ-fixed-images-overlap')
    return dict(schema_version='shared_gpio_IRQ_firmware.v1',image_start=image_start,image_end=image_end,
        first_fetch=first_fetch,dynamic_start=dynamic,vector=vector,handler=handler,scratch=scratch,
        result=result,result_words=3,segments=segments,
        gpio=dict(base=gpio_base,pin=pin,enable_mask=mask,type_offset=type_offset,type_value=type_value,
                  padin_offset=8,status_offset=36,ack='read_clear_unless_new_trigger'))


def firmware_digest(document):
    return sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def irq_firmware_register_count(profile):
    """Select the scratch register from the declared base ISA and parameters."""
    cpu=profile.cpu
    if cpu is None or cpu.xlen!=32:
        raise ValueError('shared-IRQ-RV32-base-ISA-required')
    extensions=set(cpu.extensions)
    if ('e' in extensions)==('i' in extensions):
        raise ValueError('shared-IRQ-unambiguous-base-ISA-required')
    count=16 if 'e' in extensions else 32
    parameters=dict(profile.source.elaboration.parameters)
    if 'RV32E' in parameters and parameters['RV32E']!=str(int(count==16)):
        raise ValueError('shared-IRQ-base-ISA-parameter-mismatch')
    return count


def admit_irq_firmware(runtime):
    from myfuzz.local_harness.pulp_gpio_probe_contract import (
        verify_pulp_gpio_source_contract,pulp_gpio_register_map)
    from myfuzz.local_harness.native_irq_receipt_contract import verify_native_irq_receipt_artifact
    verify_pulp_gpio_source_contract(runtime.artifacts[runtime.target_id].plan.profile,base_dir=runtime.base_dir)
    verify_native_irq_receipt_artifact(runtime.artifacts[runtime.cpu_id],base_dir=runtime.base_dir)
    registers=pulp_gpio_register_map()['registers']
    expected={4:('GPIOEN','overwrite'),8:('PADIN','read_pre_r_gpio_in'),24:('INTEN','overwrite'),
              28:('INTTYPE_LOW','packed_two_bits_pins_0_15'),32:('INTTYPE_HIGH','packed_two_bits_pins_16_31'),
              36:('INTSTATUS','read_pre_status_clear_unless_pre_native_trigger')}
    if any(registers[str(offset)]!={'name':name,'semantics':semantics} for offset,(name,semantics) in expected.items()):
        raise ValueError('shared-IRQ-register-contract-changed')
    sources=[s for s in runtime.f5_binding.path['sources'] if s['kind']=='external_pin']
    if len(sources)!=1 or sources[0]['width']!=1:raise ValueError('shared-IRQ-single-pin-required')
    pin=sources[0]['bit_offset']
    windows=[w for w in runtime.inputs['request'].wiring.windows if w.target_instance==runtime.target_id]
    if len(windows)!=1 or windows[0].size<128:raise ValueError('shared-IRQ-GPIO-window-required')
    parameters=dict(image_start=runtime.start,image_end=runtime.end,gpio_base=windows[0].base,pin=pin)
    count=irq_firmware_register_count(runtime.artifacts[runtime.cpu_id].plan.profile)
    if count!=32:parameters['register_count']=count
    return parameters


def expected_boot_fetch(runtime):
    """Validate the artifact's configured input, then predict its pinned boot PC."""
    from .cpu_boot_contract import source_backed_boot_fetch
    artifact=runtime.artifacts[runtime.cpu_id]
    ports=[p for p in artifact.runtime_document['plan']['ports'] if p['port']=='boot_addr_i']
    boot=artifact.runtime_document['boot_contract']
    if (len(ports)!=1 or ports[0].get('disposition')!='constant' or ports[0].get('direction')!='input'
            or ports[0].get('bits')!={'hi':31,'lo':0} or ports[0].get('port_width')!=32
            or type(ports[0].get('value')) is not int
            or boot.get('configured_boot_base')!=ports[0]['value']):
        raise ValueError('shared-IRQ-typed-fixed-boot-contract-required')
    return source_backed_boot_fetch(artifact.plan.profile,base_dir=runtime.base_dir,
        configured_boot_base=ports[0]['value'])


def firmware_images(runtime,document):
    from myfuzz.scenario.genome import MemoryImage
    return tuple(MemoryImage('irq-fixed-'+s['name'],runtime.cpu_id,s['address'],s['data_hex'])
                 for s in document['segments'])


def advance_irq_bootstrap(runtime):
    """Execute existing fixed initial images; retain every real warmup step."""
    from .compiled_f4 import _borrow_exact_events
    cpu=runtime.runner.sessions[runtime.cpu_id];document=runtime.irq_firmware
    if runtime.first_fetch['address']!=document['first_fetch']:
        raise ValueError('shared-IRQ-actual-first-fetch-mismatch')
    for _ in range(4096):
        if cpu.waiting_instruction_address==document['dynamic_start']:break
        receipt=runtime.session.advance_initial(tuple(runtime.runner.sessions))
        if receipt.status!='running' or receipt.violations:raise ValueError('shared-IRQ-bootstrap-session-failed')
    if cpu.waiting_instruction_address!=document['dynamic_start']:
        raise ValueError('shared-IRQ-bootstrap-did-not-reach-case-entry')
    deliveries=[e for e in _borrow_exact_events(runtime.runner) if e.get('kind')=='mmio_delivery'
        and e.get('component')==runtime.cpu_id and e.get('device_id')==runtime.access['device_id']]
    gpio=document['gpio'];expected=[(4,True,gpio['enable_mask']),(24,True,gpio['enable_mask']),
        (gpio['type_offset'],True,gpio['type_value']),(36,False,None)]
    actual=[(e.get('offset'),e.get('write'),e.get('write_value') if e.get('write') else None) for e in deliveries]
    if actual!=expected:raise ValueError('shared-IRQ-bootstrap-actual-MMIO-mismatch')
    runtime.cursor=document['dynamic_start']
    runtime.irq_bootstrap=dict(case_entry=runtime.cursor,actual_first_fetch=deepcopy(runtime.first_fetch),
        actual_MMIO_events=[e['event_id'] for e in deliveries],firmware_sha256=firmware_digest(document))


def verify_irq_successor(runtime,receipt,mret,events,beats,*,by_id=None):
    """Join the real successor retirement to the actual native response.

    ``by_id`` is the caller's ``{event_id: event}`` index of the same borrowed
    snapshot; it is built here only when the caller has none.
    """
    from myfuzz.scenario.irq_return_successor import (PC_INSN_ORDER_ONLY_AUTHORITY,
        retirement_authority,retirement_serial_unobservable,validate_return_successor)
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    cpu_contract=native_irq_receipt_contract(runtime.artifacts[runtime.cpu_id])
    authority=retirement_authority(cpu_contract)
    limited=authority==PC_INSN_ORDER_ONLY_AUTHORITY
    following=[e for e in receipt.events if e.get('kind')=='cpu_retire' and e.get('component')==runtime.cpu_id
               and e['event_id']>mret['event_id']]
    if not following:raise ValueError('native-ISR-return-successor-pending')
    successor=following[0]
    pc=validate_return_successor(mret,successor,start=runtime.irq_firmware['dynamic_start'],
        end=runtime.result,authority=authority)
    if limited:
        # trap/halt/intr/serial/mem_* are not driven by this CPU. Their absence
        # is required; a zero would be a fabricated observation.
        _reject_unobserved_fields(cpu_contract,mret,what='mret-retirement')
        _reject_unobserved_fields(cpu_contract,successor,what='successor-retirement')
        if (successor.get('valid')!=1 or successor.get('schema_version')!='cpu_retire.v2'
                or successor.get('observation_contract')!=cpu_contract
                or successor.get('trap') is not None or successor.get('halt') is not None
                or 'intr' in successor
                or not retirement_serial_unobservable(successor)):
            raise ValueError('native-ISR-successor-retire-scope-mismatch')
    elif (successor.get('valid')!=1 or successor.get('schema_version')!='cpu_retire.v2' or successor.get('observation_contract')!=cpu_contract
            or successor.get('trap') or successor.get('halt')):
        raise ValueError('native-ISR-successor-retire-scope-mismatch')
    case=next(c for c in runtime.session.cases if c.case_id==receipt.case_id)
    supports=[s for s in case.support_instructions if s.component==runtime.cpu_id and s.address<=pc< s.address+len(s.data)]
    if len(supports)!=1:raise ValueError('native-ISR-successor-current-source-bytes-unavailable')
    support=supports[0];word=support.data[pc-support.address:pc-support.address+4]
    if successor['insn']!=int.from_bytes(word,'little'):raise ValueError('native-ISR-successor-source-instruction-mismatch')
    # One pass over the borrowed snapshot fills all three candidate sets; the
    # read set is narrowed by the transaction the chosen response names.
    responses=[];reads=[];sources=[]
    for event in events:
        if event.get('component')!=runtime.cpu_id:continue
        kind=event.get('kind')
        if kind=='instr_response':
            if (event.get('address')==pc and event.get('rdata')==successor['insn']
                    and event.get('error')==0 and type(event.get('response_tick')) is int
                    and event['response_tick']<=successor['local_tick']):
                responses.append(event)
        elif kind=='memory_read':
            if event.get('address')==pc:reads.append(event)
        elif kind=='instruction_source':
            if (event.get('source_event_id')==support.action_id
                    and event.get('address')==support.address
                    and event.get('data_hex')==support.data.hex()):
                sources.append(event)
    if not responses:raise ValueError('native-ISR-successor-native-response-missing')
    response=responses[-1];transaction=response['transaction']
    reads=[e for e in reads if e.get('transaction')==transaction]
    if len(reads)!=1 or len(sources)!=1:raise ValueError('native-ISR-successor-source-version-missing')
    read=reads[0];snapshot=response['snapshot'];beat=beats.get(('instr',transaction['source_sequence']))
    actual=runtime.runner.sessions[runtime.cpu_id].memory.read(pc,4,transaction_id='irq-return-proof:'+receipt.case_id)
    if (read.get('data_hex')!=word.hex() or read.get('memory_id')!=runtime.image['port']
            or tuple(read.get('writer_event_ids',()))!=(support.action_id,)*4
            or actual.data!=word or actual.writer_event_ids!=(support.action_id,)*4 or actual.writer_kinds!=('INSTRUCTION_SOURCE',)*4
            or [list(v) for v in read.get('versions',())]!=[list(v) for v in actual.versions]
            or read.get('generation')!=sources[0].get('generation') or read.get('width_bytes')!=4
            or any(json.dumps(snapshot.get(k),sort_keys=True)!=json.dumps(read.get(k),sort_keys=True)
                   for k in ('data_hex','versions','writer_event_ids','memory_id','generation','byte_offset'))
            or snapshot.get('value')!=successor['insn']
            or beat is None or beat['address']!=pc or beat['rdata']!=successor['insn']
            or not beat['acceptance_event']<=read['producer_event_id']<beat['response_event']):
        raise ValueError('native-ISR-successor-native-byte-version-mismatch')
    by_id=by_id if by_id is not None else {e['event_id']:e for e in events}
    backend_step=by_id.get(response.get('producer_event_id'),{})
    physical_step=by_id.get(beat['response_event'],{})
    samples=backend_step.get('outputs',{}).get('driver_samples',[])
    backend=samples[0].get('pre',{}).get('backend',{}) if len(samples)==1 else {}
    outputs=backend_step.get('outputs',{})
    if (backend_step.get('component')!=runtime.cpu_id or physical_step.get('component')!=runtime.cpu_id
            or backend_step.get('local_tick')!=response['response_tick']
            or physical_step.get('local_tick')!=response['response_tick']+1
            or physical_step['local_tick']>successor['local_tick']
            or any(backend.get(k)!=v for k,v in dict(i_rsp_valid=1,i_rsp_ready=1,i_rsp_error=0,i_rsp_rdata=successor['insn']).items())
            or outputs.get('instr_rsp_consumed')!=1 or outputs.get('instr_rsp_rdata')!=successor['insn']
            or outputs.get('instr_rsp_source_sequence')!=transaction['source_sequence']
            or outputs.get('instr_rsp_source_epoch')!=transaction['source_epoch']):
        raise ValueError('native-ISR-successor-backend-to-OBI-response-mismatch')
    proof=dict(return_target=pc,
        mret_event=mret['event_id'],raw_mret_pc_wdata=(None if limited else mret.get('pc_wdata')),
        successor_event=successor['event_id'],
        successor_rvfi_order=successor['order'],source_action_id=support.action_id,
        instruction_response_event=response['event_id'],backend_response_step=backend_step['event_id'],
        physical_response_step=physical_step['event_id'],memory_read_event=read['event_id'],
        versions=deepcopy(read['versions']),native_OBI=deepcopy(beat))
    if limited:
        proof.update(return_target_source='first_subsequent_valid_retirement_pc',
            retirement_authority=authority,
            unobserved_fields=list(cpu_contract['unobserved_retirement_fields']))
    else:
        proof['return_target_source']='first_subsequent_valid_RVFI_pc_rdata_with_instruction_response'
    return proof


def _verify_irq_retired_memory_path(runtime,fw,retired,events,beats,transactions,offsets,*,selected_read_events):
    """Join every fixed-path memory retirement, including dispatcher scratch."""
    operations=[e for e in retired if e['insn']&0x7f in (0x03,0x23)]
    positions={e['pc_rdata']:i for i,e in enumerate(operations)}
    selected=(fw['read_retirement_pcs'][8],fw['write_retirement_pcs'][0],
              fw['read_retirement_pcs'][36],fw['write_retirement_pcs'][4])
    if tuple(positions.get(pc) for pc in selected)!=tuple(offsets):
        raise ValueError('native-ISR-retired-memory-position-mismatch')
    origin=transactions[0];base=origin['source_sequence']-offsets[0]
    scope=('execution_id','testcase_id','source_component','source_epoch','channel_id')
    if base<1:raise ValueError('native-ISR-retired-memory-sequence-invalid')
    # One indexed pass over the snapshot: the owner candidate of every fixed
    # operation, keyed by its role and source sequence.
    owners={}
    for event in events:
        if event.get('component')!=runtime.cpu_id:continue
        kind=event.get('kind')
        if kind not in _LIMITED_MEMORY_KINDS:continue
        tx=event.get('source_transaction') if kind=='mmio_delivery' else event.get('transaction')
        if (type(tx) is not dict or type(tx.get('source_sequence')) is not int
                or any(tx.get(k)!=origin.get(k) for k in scope)):
            continue
        owners.setdefault((kind=='memory_write',tx['source_sequence']),[]).append(event)
    for index,retirement in enumerate(operations):
        sequence=base+index;write=retirement['insn']&0x7f==0x23
        beat=beats.get(('data',sequence));value=retirement.get('mem_wdata' if write else 'mem_rdata')
        if (beat is None or beat['write']!=int(write) or beat['address']!=retirement.get('mem_addr')
                or beat.get('value' if write else 'rdata')!=value or beat.get('byte_enable')!=15
                or retirement.get('mem_wmask' if write else 'mem_rmask')!=15
                or not beat['acceptance_event']<beat['response_event']<retirement['event_id']):
            raise ValueError('native-ISR-retired-memory-OBI-mismatch')
        candidates=owners.get((write,sequence),[])
        if len(candidates)!=1:raise ValueError('native-ISR-retired-memory-owner-missing')
        event=candidates[0]
        if (event.get('address')!=beat['address']
                or event.get('value' if write or event['kind']=='memory_read' else 'read_value')!=value):
            raise ValueError('native-ISR-retired-memory-service-mismatch')
        if event['kind']=='mmio_delivery':
            if event['event_id'] not in selected_read_events:
                raise ValueError('native-ISR-unchecked-MMIO-memory-operation')
        elif (event.get('producer_event_id')!=beat['acceptance_event']
                or not beat['acceptance_event']<event['event_id']<beat['response_event']
                or (write and event.get('byte_enable')!=15)
                or (not write and event.get('width_bytes')!=4)):
            raise ValueError('native-ISR-retired-memory-service-identity-mismatch')


_LIMITED_MEMORY_KINDS=('memory_read','memory_write','mmio_delivery')
_TRANSACTION_SCOPE=('execution_id','testcase_id','source_component','source_epoch','channel_id')
_REDIRECT_KIND='cpu_native_exception_redirect'
_REQUIRED_ACCEPTANCE=('ack_probe','id_probe','source_id','entry_pc_probe')
# Per-retirement observations a PC/order/insn-only CPU does not drive. A value
# for any of these would be fabricated and is refused, never read as zero.
_UNOBSERVED_RETIREMENT_FIELDS=('intr','trap','halt','mode','pc_wdata',
    'mem_addr','mem_rdata','mem_wdata','mem_rmask','mem_wmask')


def _unobserved_fields(contract):
    if type(contract) is not dict:
        raise ValueError('native-limited-retirement-scope-unavailable')
    declared=contract.get('unobserved_retirement_fields')
    if (type(declared) not in (list,tuple) or not declared
            or any(type(name) is not str or not name for name in declared)):
        raise ValueError('native-limited-retirement-scope-unavailable')
    return list(declared)


def _reject_unobserved_fields(contract,event,*,what):
    """Refuse a claimed value for a field this CPU never drives."""
    names=set(_UNOBSERVED_RETIREMENT_FIELDS)
    names.update(name.removeprefix('rvfi_') for name in _unobserved_fields(contract))
    for name in sorted(names):
        if event.get(name) is not None:
            raise ValueError('native-limited-fabricated-'+what+'-field:'+name)


def _signed_bits(value,bits):
    return value-(1<<bits) if value&(1<<(bits-1)) else value


def _register_value(provenance,values):
    kind=provenance[0]
    if kind=='const':return provenance[1]
    if kind=='load':
        index=provenance[1]
        return values[index] if 0<=index<len(values) else None
    if kind=='addi':
        base=_register_value(provenance[1],values)
        return None if base is None else (base+provenance[2])&0xffffffff
    return None


def fixed_memory_operations(path,*,mscratch=None):
    """Ordered data operations of one declared fixed instruction path.

    Addresses and values are derived from the admitted instruction words plus
    the firmware document's fixed ``mscratch`` seed. No GPIO/peripheral offset
    is assumed, and an underivable base register refuses instead of guessing.
    """
    registers=[('unk',) for _ in range(32)]
    operations=[]
    for pc,word in path:
        opcode=word&0x7f;rd=(word>>7)&31;funct3=(word>>12)&7
        rs1=(word>>15)&31;rs2=(word>>20)&31
        if opcode==0x37:registers[rd]=('const',word&0xfffff000)
        elif opcode==0x13 and funct3==0:
            immediate=_signed_bits(word>>20,12);base=registers[rs1]
            registers[rd]=(('const',(base[1]+immediate)&0xffffffff) if base[0]=='const'
                else ('addi',base,immediate))
        elif opcode==0x03 and funct3==2:
            base=registers[rs1]
            if base[0]!='const':raise ValueError('native-fixed-ISR-memory-base-unavailable')
            operations.append(dict(kind='read',address=(base[1]+_signed_bits(word>>20,12))&0xffffffff,
                value=None,pc=pc))
            registers[rd]=('load',len(operations)-1)
        elif opcode==0x23 and funct3==2:
            base=registers[rs1]
            if base[0]!='const':raise ValueError('native-fixed-ISR-memory-base-unavailable')
            immediate=_signed_bits(((word>>25)<<5)|((word>>7)&31),12)
            operations.append(dict(kind='write',address=(base[1]+immediate)&0xffffffff,
                value=registers[rs2],pc=pc))
        elif opcode==0x73:
            if (word>>20)==0x340 and funct3==1 and rd==rs1:
                registers[rd]=('const',mscratch) if mscratch is not None else ('unk',)
            elif rd:registers[rd]=('unk',)
        elif opcode in (0x0f,):
            continue
        elif rd:registers[rd]=('unk',)
    if not operations:raise ValueError('native-fixed-ISR-memory-operations-unavailable')
    return operations


def _jal_target(pc,word):
    value=(((word>>31)&1)<<20)|(((word>>21)&0x3ff)<<1)|(((word>>20)&1)<<11)|(((word>>12)&0xff)<<12)
    value=value-(1<<21) if value&(1<<20) else value
    return (pc+value)&0xffffffff


def fixed_isr_path(fw,entry_pc):
    """Exact retired (PC, word) path from the real entry PC to the MRET."""
    if type(entry_pc) is not int or entry_pc%4:
        raise ValueError('native-fixed-ISR-entry-PC-invalid')
    if 'retirement_path' in fw:
        path=[(pc,insn) for pc,insn in fw['retirement_path']]
        if (not path or any(type(pc) is not int or type(insn) is not int for pc,insn in path)
                or path[0][0]!=entry_pc or path[-1][1]!=0x30200073):
            raise ValueError('native-fixed-ISR-declared-path-invalid')
        return path
    handler=next(segment for segment in fw['segments'] if segment['name']=='handler')
    code=bytes.fromhex(handler['data_hex'])
    handler_path=[(handler['address']+i,int.from_bytes(code[i:i+4],'little'))
                  for i in range(0,len(code),4)]
    if entry_pc==handler['address']:return handler_path
    image={}
    for segment in fw['segments']:
        data=bytes.fromhex(segment['data_hex'])
        for i in range(0,len(data),4):
            image[segment['address']+i]=int.from_bytes(data[i:i+4],'little')
    declared=(fw['vector'],fw['vector']+44)
    if entry_pc not in declared or entry_pc not in image:
        raise ValueError('native-fixed-ISR-entry-outside-declared-ISR')
    word=image[entry_pc]
    if word&0x7f!=0x6f or _jal_target(entry_pc,word)!=handler['address']:
        raise ValueError('native-fixed-ISR-entry-trampoline-mismatch')
    return [(entry_pc,word)]+handler_path


def _limited_take_scope(take,certificate,acceptance,contract):
    """The actual pre-edge take of this certificate, never a saved dictionary."""
    if (type(take) is not dict or take.get('kind')!='cpu_external_irq_taken'
            or type(certificate.get('take_key')) is not list or len(certificate['take_key'])!=3
            or take.get('take_key')!=certificate['take_key']
            or take.get('irq_ack_pre')!=1
            or take.get('irq_taken_pre')!=1
            or take.get('irq_redirect_pre') not in (0,None)
            or type(take.get(acceptance['id_probe'])) is not int
            or take[acceptance['id_probe']]!=acceptance['source_id']
            or ('id_width' in acceptance and not 0<=take[acceptance['id_probe']]<(1<<acceptance['id_width']))
            or type(take.get(acceptance['entry_pc_probe'])) is not int
            or take[acceptance['entry_pc_probe']]%4
            or type(take.get('receipt_id')) is not dict
            or set(take['receipt_id'])!={'execution','sequence'}
            or type(take['receipt_id']['execution']) is not str or not take['receipt_id']['execution']
            or type(take['receipt_id']['sequence']) is not int or take['receipt_id']['sequence']<1
            or type(take.get('producer_event_id')) is not int
            or type(take.get('event_id')) is not int):
        raise ValueError('native-ISR-actual-pre-edge-take-unavailable')
    return take


def _limited_retirement_window(runtime,receipt,take,path,cpu_contract):
    """Retirements from the real entry PC to exactly one MRET at the fixed site."""
    retires=[event for event in receipt.events
        if (event.get('kind')=='cpu_retire' and event.get('component')==runtime.cpu_id
            and type(event.get('event_id')) is int and event['event_id']>take['event_id'])]
    entry_pc=path[0][0];wanted=path[-1]
    index=next((i for i,event in enumerate(retires) if event.get('pc_rdata')==entry_pc),None)
    if index is None:raise ValueError('native-ISR-entry-retirement-missing')
    pre_entry=[dict(event_id=e['event_id'],pc=e.get('pc_rdata'),insn=e.get('insn'),
        order=e.get('order')) for e in retires[:index]]
    retired=[]
    for event in retires[index:]:
        retired.append(event)
        if (event.get('pc_rdata'),event.get('insn'))==wanted:break
    actual=[(event.get('pc_rdata'),event.get('insn')) for event in retired]
    if actual!=path:raise ValueError('native-fixed-ISR-retire-sequence-mismatch')
    if any(event.get('valid')!=1 or event.get('schema_version')!='cpu_retire.v2'
            or event.get('observation_contract')!=cpu_contract for event in retired):
        raise ValueError('native-fixed-ISR-retire-scope-mismatch')
    for event in retired:
        _reject_unobserved_fields(cpu_contract,event,what='retirement')
    if (any(type(event.get('order')) is not int or event['order']<0 for event in retired)
            or any(b['order']!=a['order']+1 for a,b in zip(retired,retired[1:]))):
        raise ValueError('native-fixed-ISR-retirement-order-mismatch')
    mrets=[event for event in retired if event.get('insn')==0x30200073]
    if len(mrets)!=1 or mrets[0] is not retired[-1]:
        raise ValueError('native-fixed-ISR-single-MRET-required')
    return retired,pre_entry


def _redirect_rows(events,*,low,high):
    return [event for event in events if event.get('kind')==_REDIRECT_KIND
            and type(event.get('event_id')) is int and low<event['event_id']<high]


def _ordered_data_events(runtime,events,*,low,high):
    rows=[]
    for event in events:
        if event.get('component')!=runtime.cpu_id:continue
        if not low<event.get('event_id',-1)<high:continue
        kind=event.get('kind')
        if kind not in _LIMITED_MEMORY_KINDS:continue
        transaction=(event.get('source_transaction') if kind=='mmio_delivery'
                     else event.get('transaction'))
        if (type(transaction) is not dict or transaction.get('channel_id')!='data'
                or transaction.get('source_component')!=runtime.cpu_id):
            continue
        rows.append(event)
    rows.sort(key=lambda row:row['event_id'])
    return rows


def _event_data_value(event):
    kind=event.get('kind')
    if kind=='memory_write':
        value=event.get('value');return value if type(value) is int else None
    if kind=='mmio_delivery':
        value=event.get('read_value');return value if type(value) is int else None
    value=event.get('value')
    if type(value) is int:return value
    data=event.get('data_hex')
    if type(data) is str and len(data)==8:
        return int.from_bytes(bytes.fromhex(data),'little')
    return None


def _join_limited_memory_operations(runtime,*,expected,events,beats,low,high,fw):
    """Ordered join of fixed ISR data operations to actual native data events."""
    from .generated_storage_consumer import _join_delivery
    actual=_ordered_data_events(runtime,events,low=low,high=high)
    if len(actual)!=len(expected):
        raise ValueError('native-ISR-ordered-data-transaction-count-mismatch')
    origin=None;previous=None;values=[];ordered=[];reads=[];writes=[]
    result=fw.get('result')
    for event,operation in zip(actual,expected):
        kind=event.get('kind')
        transaction=(event.get('source_transaction') if kind=='mmio_delivery'
                     else event.get('transaction'))
        if origin is None:
            origin=transaction
        elif any(transaction.get(key)!=origin.get(key) for key in _TRANSACTION_SCOPE):
            raise ValueError('native-ISR-ordered-data-transaction-scope-mismatch')
        sequence=transaction.get('source_sequence')
        if type(sequence) is not int or sequence<1:
            raise ValueError('native-ISR-ordered-data-transaction-sequence-invalid')
        if previous is not None and sequence<=previous:
            raise ValueError('native-ISR-ordered-data-transaction-order-mismatch')
        previous=sequence
        if event.get('address')!=operation['address']:
            raise ValueError('native-ISR-ordered-data-transaction-address-mismatch')
        write=operation['kind']=='write'
        actual_write=(kind=='memory_write'
                      or (kind=='mmio_delivery' and event.get('write') is True))
        if actual_write!=write:
            raise ValueError('native-ISR-ordered-data-transaction-kind-mismatch')
        value=event.get('value') if write else _event_data_value(event)
        if type(value) is not int:
            raise ValueError('native-ISR-ordered-data-transaction-value-unavailable')
        if write:
            wanted=_register_value(operation['value'],values)
            if wanted is not None and value!=wanted:
                raise ValueError('native-ISR-ordered-data-transaction-value-mismatch')
            values.append(value)
        else:
            values.append(value)
        beat=beats.get(('data',sequence))
        if (beat is None or beat.get('write')!=int(write) or beat.get('address')!=operation['address']
                or beat.get('byte_enable')!=15
                or type(beat.get('acceptance_event')) is not int
                or type(beat.get('response_event')) is not int):
            raise ValueError('native-ISR-ordered-data-OBI-mismatch')
        if (beat.get('value') if write else beat.get('rdata'))!=value:
            raise ValueError('native-ISR-ordered-data-OBI-value-mismatch')
        if kind=='mmio_delivery':
            base=(fw.get('gpio') or {}).get('base')
            if type(base) is not int or not base<=operation['address']<base+0x1000:
                raise ValueError('native-ISR-ordered-data-transaction-device-mismatch')
            offset=operation['address']-base
            device=(getattr(runtime,'access',None) or {}).get('device_id')
            accepted=_join_delivery(events,delivery=event,component=runtime.cpu_id,
                device=device,address=operation['address'],offset=offset,write=write)
            if beat['acceptance_event']!=accepted.get('producer_event_id'):
                raise ValueError('native-ISR-ordered-data-acceptance-mismatch')
        elif event.get('producer_event_id')!=beat['acceptance_event']:
            raise ValueError('native-ISR-ordered-data-acceptance-mismatch')
        if not beat['acceptance_event']<event['event_id']<beat['response_event']:
            raise ValueError('native-ISR-ordered-data-transaction-boundary-mismatch')
        row=dict(kind=operation['kind'],address=operation['address'],value=value,
            event_id=event['event_id'],event_kind=kind,transaction=deepcopy(transaction),
            native_OBI=deepcopy(beat))
        ordered.append(row)
        if write:
            if type(result) is int and result<=operation['address']<result+64:
                writes.append(dict(event_id=event['event_id'],address=operation['address'],
                    value=value,native_OBI=deepcopy(beat),transaction=deepcopy(transaction)))
        elif kind=='mmio_delivery':
            base=(fw.get('gpio') or {}).get('base')
            offset=(operation['address']-base if type(base) is int
                    and base<=operation['address']<base+0x1000 else None)
            reads.append(dict(offset=offset,value=value,delivery_event=event['event_id'],
                transaction=deepcopy(transaction),native_OBI=deepcopy(beat)))
    return ordered,reads,writes


def _observe_limited_irq_isr(runtime,receipt,result,cpu_contract):
    """PC/order/insn-only ISR evidence: ordered join, no per-retirement mem_*.

    Missing links stay 'unknown'; nothing is rewarded or zero-filled.
    """
    from myfuzz.scenario.irq_return_successor import (PC_INSN_ORDER_ONLY_AUTHORITY,
        retirement_authority)
    from .native_obi_hops import collect_native_obi_beats
    from .compiled_f4 import _borrow_exact_events
    try:
        authority=retirement_authority(cpu_contract)
        if authority!=PC_INSN_ORDER_ONLY_AUTHORITY:
            raise ValueError('native-limited-retirement-authority-required')
        unobserved=_unobserved_fields(cpu_contract)
        acceptance=cpu_contract.get('decision_acceptance')
        if (type(acceptance) is not dict
                or any(type(acceptance.get(key)) is not int for key in ('source_id',))
                or any(type(acceptance.get(key)) is not str or not acceptance[key]
                       for key in ('ack_probe','id_probe','entry_pc_probe'))):
            raise ValueError('native-limited-decision-acceptance-unavailable')
        fw=runtime.irq_firmware
        # One borrowed snapshot and one event index for the whole case; the
        # redirect window below is filtered from a single pass as well.
        events=_borrow_exact_events(runtime.runner);by_id={e['event_id']:e for e in events}
        redirects=[event for event in events if event.get('kind')==_REDIRECT_KIND]
        ids={e['event_id'] for e in receipt.events}
        provider=runtime.runner.gpio_irq_dependency_evidence_report()
        serials=[certificate for certificate in provider['certificates']
                 if certificate.get('proof_scope')=='irq_acceptance'
                 and certificate.get('native_take_event_id') in ids]
        if not serials:raise ValueError('native-IRQ-acceptance-not-observed')
        beats=collect_native_obi_beats(events,cpu=runtime.cpu_id,traces=runtime.traces,
            error_policy=runtime.error_policy)
        for certificate in serials:
            trigger=by_id[certificate['source_trigger']['trigger_event_id']]
            source_case=next(case for case in runtime.session.cases if case.case_id==receipt.case_id)
            admission=runtime.runner._provenance.registry.get(source_case.source.action_id)
            causes=certificate.get('pin_causes')
            if (admission is None or admission.case_id!=receipt.case_id or admission.role!='fuzz_source'
                    or admission.input_kind!='source_event' or admission.component!=runtime.target_id
                    or admission.path_id!=runtime.f5_binding.path['runtime_path_identity']['path_id']
                    or trigger.get('origin_status')!='known'
                    or certificate.get('source_origin_status')!=trigger.get('origin_status')
                    or type(causes) is not list or len(causes)!=1
                    or causes[0]['current_sample'].get('origin_status')!='known'
                    or causes[0]['current_sample'].get('origin_refs')!=[admission.document()]
                    or causes[0]['current_sample'].get('value')!=source_case.source.value):
                raise ValueError('native-ISR-F5-source-admission-unattributed')
            take=by_id[certificate['native_take_event_id']]
            _limited_take_scope(take,certificate,acceptance,cpu_contract)
            producer=by_id.get(take['producer_event_id'])
            if (producer is None or producer.get('component')!=runtime.cpu_id
                    or producer.get('event_id')!=take['producer_event_id']
                    or producer.get('local_tick')!=take.get('local_tick')):
                raise ValueError('native-ISR-actual-take-producer-unavailable')
            entry_pc=take[acceptance['entry_pc_probe']]
            path=fixed_isr_path(fw,entry_pc)
            retired,pre_entry=_limited_retirement_window(runtime,receipt,take,path,cpu_contract)
            entry,returned_mret=retired[0],retired[-1]
            if _redirect_rows(redirects,low=take['event_id'],high=returned_mret['event_id']):
                raise ValueError('native-ISR-actual-exception-redirect-before-MRET')
            operations=fixed_memory_operations(path,mscratch=fw.get('scratch'))
            ordered,reads,writes=_join_limited_memory_operations(runtime,
                expected=operations,events=events,beats=beats,
                low=entry['event_id'],high=returned_mret['event_id'],fw=fw)
            returned=verify_irq_successor(runtime,receipt,returned_mret,events,beats,by_id=by_id)
            successor=by_id[returned['successor_event']]
            if _redirect_rows(redirects,low=take['event_id'],high=successor['event_id']):
                raise ValueError('native-ISR-actual-exception-redirect-before-successor')
            result['certificates'].append(dict(status='verified',case_id=receipt.case_id,
                retirement_authority=PC_INSN_ORDER_ONLY_AUTHORITY,
                unobserved_fields=list(unobserved),
                native_take_event_id=take['event_id'],
                native_IRQ=deepcopy(certificate),
                source_admission=admission.document(),
                entry_retirement=dict(event_id=entry['event_id'],pc=entry.get('pc_rdata'),
                    insn=entry.get('insn'),order=entry.get('order'),local_tick=entry.get('local_tick')),
                pre_entry_retirements=pre_entry,
                handler_retire_events=[event['event_id'] for event in retired],
                register_reads=reads,result_RAM=writes,
                mret_event=returned_mret['event_id'],raw_mret_pc_wdata=None,
                return_PC=returned['return_target'],return_proof=returned,
                per_retirement_join='unobservable',
                join_scope='ordered_retirement_to_actual_data_transaction',
                retirement_diversion_scope='unobservable',
                ordered_data_transactions=ordered))
        result['status']='verified'
    except (ValueError,KeyError,TypeError,StopIteration,AttributeError) as error:
        result['reason']=str(error)
        if 'successor-pending' in str(error):result['return_state']='pending'
    return result


def observe_irq_isr(runtime,receipt):
    """Check actual native ISR transactions; missing links stay unknown.

    This is invoked only by the successful shared submit path and consumes the
    live journal/provider. Saved certificate documents are never ingested.
    The registered CPU adapter selects the retirement authority; a CPU with no
    literal RVFI retirement stream uses the ordered data-transaction join.
    """
    from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
    from myfuzz.scenario.irq_return_successor import (PC_INSN_ORDER_ONLY_AUTHORITY,
        retirement_authority)
    result=dict(status='unknown',proof_scope='single_GPIO_native_IRQ_ISR',reward_eligible=False,
                grants_prerequisites=False,certificates=[])
    if not runtime._irq_firmware_enabled:return result
    cpu_contract=native_irq_receipt_contract(runtime.artifacts[runtime.cpu_id])
    authority=retirement_authority(cpu_contract)
    result['retirement_authority']=authority
    if authority==PC_INSN_ORDER_ONLY_AUTHORITY:
        return _observe_limited_irq_isr(runtime,receipt,result,cpu_contract)
    return _observe_full_irq_isr(runtime,receipt,result,cpu_contract)


def _observe_full_irq_isr(runtime,receipt,result,cpu_contract):
    from .native_obi_hops import collect_native_obi_beats
    from .generated_storage_consumer import _join_delivery
    from .gpio_f2_consumer import gpio_read_samples
    from .compiled_f4 import _borrow_exact_events
    events=_borrow_exact_events(runtime.runner);by_id={e['event_id']:e for e in events}
    ids={e['event_id'] for e in receipt.events};fw=runtime.irq_firmware
    handler=next(s for s in fw['segments'] if s['name']=='handler');code=bytes.fromhex(handler['data_hex'])
    custom_path='retirement_path' in fw
    expected=(list(map(tuple,fw['retirement_path'])) if custom_path else
        [(handler['address']+i,int.from_bytes(code[i:i+4],'little')) for i in range(0,len(code),4)])
    provider=runtime.runner.gpio_irq_dependency_evidence_report()
    try:
        beats=collect_native_obi_beats(events,cpu=runtime.cpu_id,traces=runtime.traces,error_policy=runtime.error_policy)
        serials=[c for c in provider['certificates'] if c['proof_scope']=='cpu_retirement_serial'
                 and c['acceptance']['native_take_event_id'] in ids]
        if not serials:raise ValueError('native-IRQ-serial-not-observed')
        for serial in serials:
            trigger=by_id[serial['acceptance']['source_trigger']['trigger_event_id']]
            source_case=next(case for case in runtime.session.cases if case.case_id==receipt.case_id)
            admission=runtime.runner._provenance.registry.get(source_case.source.action_id)
            causes=[c for c in trigger.get('causes',[]) if c.get('pin')==fw['gpio']['pin']]
            if (admission is None or admission.case_id!=receipt.case_id or admission.role!='fuzz_source'
                    or admission.input_kind!='source_event' or admission.component!=runtime.target_id
                    or admission.path_id!=runtime.f5_binding.path['runtime_path_identity']['path_id']
                    or trigger.get('origin_status')!='known' or len(causes)!=1
                    or causes[0]['current_sample'].get('origin_status')!='known'
                    or causes[0]['current_sample'].get('origin_refs')!=[admission.document()]
                    or causes[0]['current_sample'].get('value')!=source_case.source.value):
                raise ValueError('native-ISR-F5-source-admission-unattributed')
            first=by_id[serial['serial_certificate']['retirement_event_id']]
            if custom_path:
                if (not expected or expected[-1][1]!=0x30200073
                        or any(type(pc) is not int or pc%4 or type(insn) is not int for pc,insn in expected)):
                    raise ValueError('native-fixed-ISR-expected-path-invalid')
                retired=[]
                for event in receipt.events:
                    if (event.get('kind')=='cpu_retire' and event.get('component')==runtime.cpu_id
                            and event['event_id']>=first['event_id']):
                        retired.append(event)
                        if (event.get('pc_rdata'),event.get('insn'))==expected[-1]:break
                if (any(type(e.get('order')) is not int or e['order']<0 or e.get('valid')!=1 for e in retired)
                        or any(b['order']!=a['order']+1 for a,b in zip(retired,retired[1:]))):
                    raise ValueError('native-fixed-ISR-retirement-order-mismatch')
            else:
                retired=[e for e in receipt.events if e.get('kind')=='cpu_retire' and e.get('component')==runtime.cpu_id
                    and e['event_id']>=first['event_id'] and fw['handler']<=e.get('pc_rdata',-1)<fw['handler']+len(code)]
            if [(e['pc_rdata'],e['insn']) for e in retired]!=expected:
                raise ValueError('native-fixed-ISR-retire-sequence-missing')
            if any(e.get('schema_version')!='cpu_retire.v2' or e.get('observation_contract')!=cpu_contract
                    or e.get('trap') or e.get('halt') for e in retired):
                raise ValueError('native-fixed-ISR-retire-scope-mismatch')
            if first.get('pc_rdata') not in (fw['vector'],fw['vector']+44,fw['handler']):
                raise ValueError('native-IRQ-serial-outside-fixed-vector')
            result['return_diagnostic']=dict(mret=deepcopy(retired[-1]),following_retirements=deepcopy([e for e in receipt.events
                if e.get('kind')=='cpu_retire' and e.get('component')==runtime.cpu_id and e['event_id']>retired[-1]['event_id']][:3]))
            returned=verify_irq_successor(runtime,receipt,retired[-1],events,beats,by_id=by_id)
            relevant=[e for e in receipt.events if first['event_id']<e['event_id']<retired[-1]['event_id']]
            # One indexed pass over the window instead of a scan per register.
            deliveries={};result_writes={}
            for event in relevant:
                if event.get('component')!=runtime.cpu_id:continue
                kind=event.get('kind')
                if (kind=='mmio_delivery' and event.get('device_id')==runtime.access['device_id']
                        and event.get('write') is False):
                    if type(event.get('offset')) is int:
                        deliveries.setdefault(event['offset'],[]).append(event)
                elif (kind=='memory_write' and event.get('byte_enable')==15
                        and type(event.get('address')) is int and type(event.get('value')) is int):
                    result_writes.setdefault((event['address'],event['value']),[]).append(event)
            reads=[]
            for offset in (8,36):
                candidates=deliveries.get(offset,[])
                if len(candidates)!=1:raise ValueError('native-ISR-register-read-missing')
                delivery=candidates[0];value=delivery['read_value'];target=runtime.runner.sessions[runtime.target_id]
                accepted=_join_delivery(events,delivery=delivery,component=runtime.cpu_id,device=runtime.access['device_id'],
                    address=fw['gpio']['base']+offset,offset=offset,write=False)
                pre,post=gpio_read_samples(events,target=target,component=runtime.target_id,
                    producer_event_id=delivery['producer_event_id'],signals=target.artifact.runtime_document['base_protocol_trace']['signals'],
                    offset=offset,value=value,reset_epoch=target.reset_epoch)
                beat=beats.get(('data',delivery['source_transaction']['source_sequence']))
                if (beat is None or beat['acceptance_event']!=accepted['producer_event_id'] or beat['write']!=0
                        or beat['rdata']!=value or beat['address']!=fw['gpio']['base']+offset
                        or not accepted['event_id']<delivery['event_id']<beat['response_event']):
                    raise ValueError('native-ISR-OBI-register-read-mismatch')
                if 'read_retirement_pcs' in fw:
                    matches=[e for e in retired if e['pc_rdata']==fw['read_retirement_pcs'][offset]]
                    if len(matches)!=1:raise ValueError('native-ISR-read-retirement-PC-missing')
                    retired_read=matches[0]
                else:retired_read=retired[{8:7,36:11}[offset]]
                if (retired_read.get('mem_addr')!=fw['gpio']['base']+offset or retired_read.get('mem_rmask')!=15
                        or retired_read.get('mem_rdata')!=value
                        or not retired[0]['event_id']<beat['acceptance_event']<beat['response_event']<retired_read['event_id']):
                    raise ValueError('native-ISR-register-retirement-mismatch')
                if offset==36:
                    raw_pre=target._normalized_physical(pre['outputs']);raw_post=target._normalized_physical(post['outputs'])
                    expected_status=raw_pre['gpio_probe_status']|raw_pre['gpio_probe_irq_trigger_mask'] if raw_pre['gpio_probe_native_irq'] else 0
                    if raw_post['gpio_probe_status']!=expected_status:raise ValueError('native-ISR-status-read-clear-mismatch')
                reads.append(dict(offset=offset,value=value,delivery_event=delivery['event_id'],
                    native_pre_event=pre['event_id'],native_post_event=post['event_id'],transaction=deepcopy(delivery['source_transaction']),
                    native_OBI=deepcopy(beat)))
            writes=[]
            for offset,value in ((0,reads[0]['value']),(4,reads[1]['value'])):
                matches=result_writes.get((fw['result']+offset,value),[])
                if len(matches)!=1:raise ValueError('native-ISR-result-RAM-write-missing')
                event=matches[0];beat=beats.get(('data',event['transaction']['source_sequence']))
                if (beat is None or beat['write']!=1 or beat['address']!=event['address'] or beat['value']!=value
                        or beat['byte_enable']!=15 or beat['acceptance_event']!=event.get('producer_event_id')
                        or not beat['acceptance_event']<event['event_id']<beat['response_event']):
                    raise ValueError('native-ISR-result-RAM-OBI-mismatch')
                if 'write_retirement_pcs' in fw:
                    retirement_matches=[e for e in retired if e['pc_rdata']==fw['write_retirement_pcs'][offset]]
                    if len(retirement_matches)!=1:raise ValueError('native-ISR-write-retirement-PC-missing')
                    retired_write=retirement_matches[0]
                else:retired_write=retired[{0:10,4:12}[offset]]
                if (retired_write.get('mem_addr')!=event['address'] or retired_write.get('mem_wmask')!=15
                        or retired_write.get('mem_wdata')!=value or beat['response_event']>=retired_write['event_id']):
                    raise ValueError('native-ISR-result-retirement-mismatch')
                writes.append(dict(event_id=event['event_id'],address=fw['result']+offset,value=value,
                    native_OBI=deepcopy(beat),
                    transaction=deepcopy(matches[0]['transaction'])))
            transactions=[reads[0]['transaction'],writes[0]['transaction'],reads[1]['transaction'],writes[1]['transaction']]
            origin=transactions[0]
            offsets=fw.get('transaction_sequence_offsets',(0,1,2,3))
            if len(offsets)!=4 or any(type(i) is not int or i<0 for i in offsets) or len(set(offsets))!=4:
                raise ValueError('native-ISR-data-transaction-offsets-invalid')
            if any(any(tx.get(k)!=origin.get(k) for k in ('execution_id','testcase_id','source_component','source_epoch','channel_id'))
                    or tx.get('source_sequence')!=origin['source_sequence']+offsets[index]-offsets[0] for index,tx in enumerate(transactions)):
                raise ValueError('native-ISR-data-transaction-order-mismatch')
            if custom_path:
                _verify_irq_retired_memory_path(runtime,fw,retired,events,beats,transactions,offsets,
                    selected_read_events={r['delivery_event'] for r in reads})
            result['certificates'].append(dict(status='verified',case_id=receipt.case_id,native_IRQ=deepcopy(serial),source_admission=admission.document(),
                handler_retire_events=[e['event_id'] for e in retired],register_reads=reads,result_RAM=writes,
                mret_event=retired[-1]['event_id'],raw_mret_pc_wdata=retired[-1].get('pc_wdata'),
                return_PC=returned['return_target'],return_proof=returned))
        result['status']='verified'
    except (ValueError,KeyError,TypeError,StopIteration,AttributeError) as error:
        result['reason']=str(error)
        if 'successor-pending' in str(error):result['return_state']='pending'
    return result
