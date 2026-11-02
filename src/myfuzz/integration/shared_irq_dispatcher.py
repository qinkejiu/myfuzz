"""Pure single-CPU DMA/GPIO dispatcher compilation and explicit proof stages.

This code produces firmware bytes, not native entry/source or ISR authority.
Default single-source F6 firmware does not call this optional builder.
"""
from hashlib import sha256
import json
from .rv32_fixed_firmware import _lui_addi_load as load,_sw,_lw,_jal,_addi,_branch


def _require(ok,reason):
    if not ok:raise ValueError('shared-IRQ-dispatcher-'+reason)


def compile_gpio_irq_declaration(request,declaration,*,base_dir):
    from .f6_gpio_companion import select_gpio_companion_source,CONTRACT_ID
    keys={'component','pin','group_id','dma_handler_address','gpio_handler_address','scratch_address','result_address'}
    _require(type(declaration) is dict and set(declaration) in (keys,keys|{'irq_bit'}),'declaration')
    if 'irq_bit' in declaration:
        _require(type(declaration['irq_bit']) is int and 3<=declaration['irq_bit']<32,'custom-irq-bit')
    target=request.device(declaration['component'])
    _require(target is not None,'component')
    source=select_gpio_companion_source(target.profile,base_dir=base_dir,selection=dict(contract_id=CONTRACT_ID,register='GPIOEN'))
    windows=[w for w in request.wiring.windows if w.target_instance==target.instance_id]
    _require(len(windows)==1 and windows[0].size>=128,'window')
    _require(type(declaration['pin']) is int and 0<=declaration['pin']<32,'pin')
    links=[e for e in request.wiring.environment_links if e.component_instance==target.instance_id
           and e.bit_offset==declaration['pin'] and e.width==1]
    _require(len(links)==1,'declared-physical-pin-source')
    _require(type(declaration['group_id']) is str and declaration['group_id'].strip()==declaration['group_id'] and bool(declaration['group_id']),'group-id')
    for key in ('dma_handler_address','gpio_handler_address','scratch_address','result_address'):
        _require(type(declaration[key]) is int and 0<=declaration[key]<=0xffffff00 and declaration[key]%4==0,key)
    return dict(declaration,schema_version='shared_gpio_IRQ_dispatch.v1',gpio_base=windows[0].base,
        source_contract_digest=source['digest'],status_offset=36,status_ack='read_clear_unless_new_trigger',
        type_offset=28 if declaration['pin']<16 else 32,type_value=2<<(2*(declaration['pin']%16)))


def _gpio_handler(base,result):
    swap=(0x340<<20)|(31<<15)|(1<<12)|(31<<7)|0x73
    # Dispatcher has already authenticated/read-cleared status into result+4.
    words=[swap,*[_sw(r,31,(r-1)*4) for r in (1,2,3,4)],*load(1,base),_lw(2,1,8),
           *load(3,result),_sw(2,3,0),_lw(4,3,8),_addi(4,4,1),_sw(4,3,8),
           *[_lw(r,31,(r-1)*4) for r in (1,2,3,4)],swap,0x30200073]
    return words


def gpio_boot_words(declaration):
    """Fixed GPIO/mscratch initialization, placed before enabling CPU MIE."""
    d=declaration;mask=1<<d['pin']
    return [*load(6,d['gpio_base']),*load(7,mask),_sw(7,6,4),_sw(7,6,24),
        *load(7,d['type_value']),_sw(7,6,d['type_offset']),_lw(7,6,36),
        *load(6,d['result_address']),_sw(0,6,0),_sw(0,6,4),_sw(0,6,8),
        *load(7,d['scratch_address']),(0x340<<20)|(7<<15)|(1<<12)|0x73,
        _addi(10,0,1),_addi(11,0,1)]


def build_common_irq_firmware(*,entry_address,dma_isr_bytes,declaration):
    d=declaration;dma=d['dma_handler_address'];gpio=d['gpio_handler_address']
    _require(d.get('schema_version')=='shared_gpio_IRQ_dispatch.v1' and entry_address%256==44,'typed-entry')
    _require(type(dma_isr_bytes) is bytes and len(dma_isr_bytes)%4==0 and bool(dma_isr_bytes),'DMA-bytes')
    swap=(0x340<<20)|(31<<15)|(1<<12)|(31<<7)|0x73
    words=[swap,_sw(6,31,0),_sw(7,31,4),*load(6,d['gpio_base']),_lw(7,6,36),0,
        *load(6,d['result_address']),_sw(7,6,4),_lw(6,31,0),_lw(7,31,4),swap,0]
    dma_branch=len(words);words += [_lw(6,31,0),_lw(7,31,4),swap,0]
    words[6]=_branch(7,0,(dma_branch-6)*4)
    words[13]=_jal(entry_address+13*4,gpio)
    words[-1]=_jal(entry_address+(len(words)-1)*4,dma)
    encode=lambda values:b''.join(w.to_bytes(4,'little') for w in values)
    dispatcher=encode(words);gpio_code=encode(_gpio_handler(d['gpio_base'],d['result_address']))
    segments=[(entry_address,dispatcher),(dma,dma_isr_bytes),(gpio,gpio_code)]
    spans=[(a,len(code)) for a,code in segments]+[(d['scratch_address'],64),(d['result_address'],12)]
    for i,(address,size) in enumerate(spans):
        _require(address%4==0 and address+size<=1<<32 and not any(address<b+n and b<address+size for b,n in spans[:i]),'layout-overlap')
    _require(entry_address<dma<gpio and entry_address+len(dispatcher)<=dma and dma+len(dma_isr_bytes)<=gpio,'stage-order')
    end=gpio+len(gpio_code);_require(end-entry_address<=4096,'fixed-span')
    combined=bytearray(b'\x13\x00\x00\x00'*((end-entry_address)//4))
    for a,code in segments:combined[a-entry_address:a-entry_address+len(code)]=code
    def stage(address,code):
        return dict(address=address,length=len(code),sha256=sha256(code).hexdigest(),
            instruction_addresses=list(range(address,address+len(code),4)),
            mret_addresses=[address+i for i in range(0,len(code),4) if code[i:i+4]==b'\x73\x00\x20\x30'])
    stages=dict(dispatcher=stage(entry_address,dispatcher),dma=stage(dma,dma_isr_bytes),gpio=stage(gpio,gpio_code),
        gpio_status_ack=entry_address+5*4,gpio_status_store=entry_address+9*4,source_branch=entry_address+6*4,
        dma_dispatch_path=list(range(entry_address,entry_address+7*4,4))+list(range(entry_address+dma_branch*4,entry_address+len(dispatcher),4)),
        gpio_dispatch_path=list(range(entry_address,entry_address+14*4,4)))
    _require(len(stages['dma']['mret_addresses'])==2 and len(stages['gpio']['mret_addresses'])==1,'typed-MRET-sites')
    document=dict(schema_version='shared_IRQ_firmware_stages.v1',entry_address=entry_address,
        address=entry_address,length=len(combined),sha256=sha256(combined).hexdigest(),stages=stages)
    document['identity_sha256']=sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(address=entry_address,data=bytes(combined),document=document)


def build_custom_irq_dispatcher(*, address, routes, return_word=0x0400000b):
    """Dispatch Pico q1 IRQ bits to separately generated handlers.

    Inputs are (IRQ bit, handler address) tuples. q2/q3 are interrupt ABI
    scratch; x30/x31 are saved there and restored before entering a handler.
    Simultaneous pending bits choose the first declared route; source lineage,
    other pending-bit handling and retirement remain unknown.
    """
    _require(type(address) is int and 0 <= address <= 0xffffff00 and address % 4 == 0,
             'custom-address')
    _require(type(routes) is tuple and 1 <= len(routes) <= 16 and all(
        type(row) is tuple and len(row) == 2 and type(row[0]) is int and 3 <= row[0] < 32
        and type(row[1]) is int and 0 <= row[1] <= 0xfffffffc and row[1] % 4 == 0
        for row in routes), 'custom-routes')
    _require(len({row[0] for row in routes}) == len(routes), 'custom-duplicate-irq-bit')
    _require(return_word == 0x0400000b, 'custom-return')
    def setq(q, reg): return 1 << 25 | reg << 15 | 2 << 12 | q << 7 | 0x0b
    def getq(reg, q): return q << 15 | 4 << 12 | reg << 7 | 0x0b
    words = [setq(2,30), setq(3,31), getq(31,1)]
    branches = []
    for bit, _ in routes:
        words += [*load(30,1 << bit), 30 << 20 | 31 << 15 | 7 << 12 | 30 << 7 | 0x33, 0]
        branches.append(len(words)-1)
    restore = [getq(30,2), getq(31,3)]
    words += [*restore, return_word]
    for branch, (_, handler) in zip(branches, routes):
        target = len(words)
        words[branch] = _branch(30,0,(target-branch)*4,funct3=1)
        words += [*restore, _jal(address+4*len(words)+8,handler)]
    data = b''.join(word.to_bytes(4,'little') for word in words)
    _require(address + len(data) <= 1 << 32, 'custom-range')
    return dict(schema_version='custom_irq_dispatcher.v1',address=address,data_hex=data.hex(),
        routes=[{'irq_bit':bit,'handler_address':handler} for bit,handler in routes],
        dispatch_policy='first_matching_q1_bit', simultaneous_pending='unknown',
        source_attribution='unknown',retirement='unknown',q_register_clobbers=['q2','q3'])


def custom_gpio_boot_words(declaration):
    """Configure the physical GPIO source; no machine CSR ABI is assumed."""
    d=declaration; mask=1<<d['pin']
    return [*load(6,d['gpio_base']),*load(7,mask),_sw(7,6,4),_sw(7,6,24),
        *load(7,d['type_value']),_sw(7,6,d['type_offset']),_lw(7,6,36),
        *load(6,d['result_address']),_sw(0,6,0),_sw(0,6,4),_sw(0,6,8),
        _addi(10,0,1),_addi(11,0,1)]


def build_custom_gpio_irq_firmware(*,entry_address,dma_isr_bytes,declaration,dma_irq_bit):
    """Build actual q1 vector dispatch and GPIO read-clear handling without proof claims."""
    d=declaration
    _require(d.get('schema_version')=='shared_gpio_IRQ_dispatch.v1' and
        type(d.get('irq_bit')) is int and d['irq_bit']!=dma_irq_bit,'custom-gpio-route')
    dma=d['dma_handler_address']; gpio=d['gpio_handler_address']
    dispatcher=build_custom_irq_dispatcher(address=entry_address,
        routes=((dma_irq_bit,dma),(d['irq_bit'],gpio)))
    dispatch=bytes.fromhex(dispatcher['data_hex'])
    setq=lambda q,r: 1<<25 | r<<15 | 2<<12 | q<<7 | 0x0b
    getq=lambda r,q: q<<15 | 4<<12 | r<<7 | 0x0b
    handler=[setq(2,31),*load(31,d['scratch_address']),
        *[_sw(r,31,(r-1)*4) for r in (1,2,3,4)],
        *load(1,d['gpio_base']),_lw(2,1,36),*load(3,d['result_address']),_sw(2,3,4),
        _lw(2,1,8),_sw(2,3,0),_lw(4,3,8),_addi(4,4,1),_sw(4,3,8),
        *[_lw(r,31,(r-1)*4) for r in (1,2,3,4)],getq(31,2),0x0400000b]
    gpio_bytes=b''.join(word.to_bytes(4,'little') for word in handler)
    _require(type(dma_isr_bytes) is bytes and bool(dma_isr_bytes) and len(dma_isr_bytes)%4==0,
        'custom-gpio-DMA-bytes')
    _require(entry_address+len(dispatch)<=dma and dma+len(dma_isr_bytes)<=gpio and
        gpio+len(gpio_bytes)-entry_address<=4096,'custom-gpio-layout')
    end=gpio+len(gpio_bytes)
    image=bytearray(b'\x13\x00\x00\x00'*((end-entry_address)//4))
    for address,data in ((entry_address,dispatch),(dma,dma_isr_bytes),(gpio,gpio_bytes)):
        image[address-entry_address:address-entry_address+len(data)]=data
    def stage(address,data):
        return dict(address=address,length=len(data),sha256=sha256(data).hexdigest(),
            mret_addresses=[],retirq_addresses=[address+i for i in range(0,len(data),4)
                if data[i:i+4]==b'\x0b\x00\x00\x04'])
    doc=dict(schema_version='shared_custom_IRQ_firmware.v1',entry_address=entry_address,
        address=entry_address,length=len(image),sha256=sha256(image).hexdigest(),
        stages={'dispatcher':stage(entry_address,dispatch),'dma':stage(dma,dma_isr_bytes),
                'gpio':stage(gpio,gpio_bytes)},routes=dispatcher['routes'],
        simultaneous_pending='unknown',source_attribution='unknown',retirement='unknown')
    doc['identity_sha256']=sha256(json.dumps(doc,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(address=entry_address,data=bytes(image),document=doc)


def build_declared_phase_irq_firmware(*, entry_address, dma_isr_bytes, declaration):
    """Dispatch by CPU-written phase, with no IRQ-source attribution.

    Phase 0 enters the DMA handler; nonzero enters the declared target handler.
    Both sources may be electrically active, so this choice is an intent only.
    """
    from .declared_irq_consumption import _digest
    d=declaration
    _require(type(d) is dict and d.get('schema_version')=='shared_declared_irq_contract.v1'
        and type(entry_address) is int and entry_address%256==44
        and type(dma_isr_bytes) is bytes and bool(dma_isr_bytes) and len(dma_isr_bytes)%4==0,
        'declared-phase-contract')
    phase=d['phase_address'];scratch=d['scratch_address'];result=d['result_address']
    dma=d['dma_handler_address'];target=d['target_handler_address'];base=d['target_window']['base']
    statuses=d['status_offsets'];clears=d['clear_writes']
    _require(type(statuses) is list and 1 <= len(statuses) <= 16 and
        all(type(v) is int and 0<=v<=4092 and v%4==0 for v in statuses), 'declared-status')
    _require(type(clears) is list and all(type(row) is list and len(row)==2 and
        type(row[0]) is int and 0<=row[0]<=4092 and row[0]%4==0 and
        type(row[1]) is int and 0<=row[1]<len(statuses) for row in clears), 'declared-clears')
    swap=(0x340<<20)|(31<<15)|(1<<12)|(31<<7)|0x73
    dispatcher=[swap,_sw(6,31,0),_sw(7,31,4),*load(6,phase),_lw(7,6,0),0,
                _lw(6,31,0),_lw(7,31,4),swap,0]
    dma_branch=len(dispatcher)
    dispatcher += [_lw(6,31,0),_lw(7,31,4),swap,0]
    dispatcher[6]=_branch(7,0,(dma_branch-6)*4)
    dispatcher[10]=_jal(entry_address+10*4,target)
    dispatcher[-1]=_jal(entry_address+(len(dispatcher)-1)*4,dma)
    handler=[swap,*[_sw(r,31,(r-1)*4) for r in (1,2,3,4)],*load(1,base),*load(3,result)]
    operations=[]
    for index,offset in enumerate(statuses):
        if offset < 2048:
            pc=target+4*len(handler);handler.append(_lw(2,1,offset))
        else:
            handler += list(load(4,base+offset));pc=target+4*len(handler);handler.append(_lw(2,4,0))
        operations.append(dict(index=len(operations),kind='read',pc=pc,offset=offset,
                               address=base+offset,width=4,target_register_index=index))
        pc=target+4*len(handler);handler.append(_sw(2,3,index*4))
        operations.append(dict(index=len(operations),kind='write',pc=pc,address=result+index*4,
                               width=4,result_index=index,value_source='read_value[%d]'%index))
        for ack_offset,source_index in clears:
            if source_index!=index:continue
            if ack_offset<2048:
                pc=target+4*len(handler);handler.append(_sw(2,1,ack_offset))
            else:
                handler += list(load(4,base+ack_offset));pc=target+4*len(handler);handler.append(_sw(2,4,0))
            operations.append(dict(index=len(operations),kind='write',pc=pc,offset=ack_offset,
                address=base+ack_offset,width=4,value_source='read_value[%d]'%index,
                role='declared_clear_or_ack'))
    handler += [*[_lw(r,31,(r-1)*4) for r in (1,2,3,4)],swap,0x30200073]
    encode=lambda words:b''.join(word.to_bytes(4,'little') for word in words)
    dispatcher_bytes=encode(dispatcher);target_bytes=encode(handler)
    pieces=[(entry_address,dispatcher_bytes),(dma,dma_isr_bytes),(target,target_bytes)]
    spans=[(a,len(data)) for a,data in pieces]+[(phase,4),(scratch,64),(result,64)]
    for i,(address,length) in enumerate(spans):
        _require(type(address) is int and address%4==0 and address+length<=1<<32 and
                 not any(address<b+n and b<address+length for b,n in spans[:i]),'declared-layout-overlap')
    _require(entry_address<dma<target and entry_address+len(dispatcher_bytes)<=dma and
             dma+len(dma_isr_bytes)<=target and target+len(target_bytes)-entry_address<=4096,
             'declared-stage-order')
    combined=bytearray(b'\x13\x00\x00\x00'*((target+len(target_bytes)-entry_address)//4))
    for address,data in pieces:combined[address-entry_address:address-entry_address+len(data)]=data
    mret=lambda address,data:[address+i for i in range(0,len(data),4) if data[i:i+4]==b'\x73\x00\x20\x30']
    stages=dict(dispatcher=dict(address=entry_address,length=len(dispatcher_bytes),sha256=sha256(dispatcher_bytes).hexdigest()),
        dma=dict(address=dma,length=len(dma_isr_bytes),sha256=sha256(dma_isr_bytes).hexdigest(),mret_addresses=mret(dma,dma_isr_bytes)),
        declared_target=dict(address=target,length=len(target_bytes),sha256=sha256(target_bytes).hexdigest(),mret_addresses=mret(target,target_bytes)))
    stages['dma_dispatch_path']=(list(range(entry_address,entry_address+7*4,4))
        + list(range(entry_address+dma_branch*4,entry_address+len(dispatcher_bytes),4)))
    _require(len(stages['dma']['mret_addresses'])==2 and len(stages['declared_target']['mret_addresses'])==1,
             'declared-return-sites')
    retirement_path=[[entry_address+4*i,word] for i,word in enumerate(dispatcher[:11])]
    retirement_path += [[target+4*i,word] for i,word in enumerate(handler)]
    declared_fw=dict(schema_version='declared_irq_f5_firmware.v1',handler=entry_address,
        vector=entry_address,entry_pcs=[entry_address],target_base=base,
        status_offsets=list(statuses),result_address=result,result_words=len(statuses),
        mret_pc=stages['declared_target']['mret_addresses'][0],mret_word=0x30200073,
        retirement_path=retirement_path,memory_operations=operations,
        segments=[dict(name='shared_dispatch_and_handlers',address=entry_address,data_hex=bytes(combined).hex())],
        source_attribution='unknown',phase_semantics='cpu_written_dispatch_intent_only')
    declared_fw['digest']=_digest(declared_fw)
    document=dict(schema_version='shared_IRQ_firmware_stages.v1',entry_address=entry_address,
        address=entry_address,length=len(combined),sha256=sha256(combined).hexdigest(),
        stages=stages,declared_firmware=declared_fw,source_attribution='unknown',
        phase_semantics='cpu_written_dispatch_intent_only')
    document['identity_sha256']=sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(address=entry_address,data=bytes(combined),document=document)
