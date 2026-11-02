"""Closed, source-verified static CPU-programmed four-word RAM DMA contract.

Compilation grants static support only. Runtime topology binding, native effects,
IRQ take, ISR return and evidence certification remain separate obligations.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

SCHEMA_VERSION='compiled_F6_cpu_dma_contract.v1'
EXPECTATION_IDS=('protocol_checker.receipt_violations','cross_component.declared_edge_hops',
    'dma.cpu_configuration','dma.word_transfer_join','dma.irq_isr_completion')
PROGRAM_KEYS={'boot_address','isr_address','park_address','slot_base','slot_count',
    'source_address','destination_address','result_base'}
CONTRACT_KEYS=set('schema_version flow_id path_id cpu dma instruction_source_id candidate_layout program_contract memory control master_routes irq termination expectation_ids'.split())


class F6ContractRefused(ValueError):
    def __init__(self,code,pointer,detail=None):
        self.code,self.pointer,self.detail=code,pointer,detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code,pointer,detail=None):
    raise F6ContractRefused(code,pointer,detail)


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)


def _sha(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _exact_json_containers(value):
    """JSON document containers and keys retain their exact Python types."""
    if type(value) is dict:
        return (all(type(key) is str for key in value)
                and all(_exact_json_containers(item) for item in value.values()))
    if type(value) is list:
        return all(_exact_json_containers(item) for item in value)
    return type(value) in (str, int, float, bool, type(None))


def require_exact(recomputed,supplied,*,pointer):
    try:
        matches=(_exact_json_containers(recomputed) and _exact_json_containers(supplied)
                 and _canonical(recomputed)==_canonical(supplied))
    except (TypeError,ValueError,RecursionError):
        matches=False
    if not matches:
        _refuse('contract-drift',pointer)
    return deepcopy(recomputed)


def _closed(value,keys,pointer):
    if type(value) is not dict or set(value)!=keys:
        _refuse('f6-fields-invalid',pointer,{'required':sorted(keys)})
    return value


def _marker(request,*,base_dir):
    marker=request.document.get('f6_execution')
    if not isinstance(marker,dict) or marker.get('schema_version')!=SCHEMA_VERSION:
        _refuse('f6-contract-version-unsupported','/f6_execution/schema_version')
    _closed(marker,{'schema_version','seed','program'} | (set(marker) & {'storage_support', 'shared_slots', 'gpio_irq', 'declared_irq', 'custom_irq_bit'}),'/f6_execution')
    if 'storage_support' in marker and 'shared_slots' in marker:
        _refuse('f6-fixed-and-dynamic-storage-exclusive', '/f6_execution')
    words=marker['seed']
    if (type(words) is not list or len(words)!=4 or any(type(w) is not int or not 0<=w<=2047 for w in words)
            or len(set(words))!=4):
        _refuse('f6-seed-invalid','/f6_execution/seed')
    program=_closed(marker['program'],PROGRAM_KEYS,'/f6_execution/program')
    for name,value in program.items():
        if type(value) is not int or (not 1<=value<=16 if name=='slot_count' else not 0<=value<2**32 or value%4):
            _refuse('f6-program-range-invalid','/f6_execution/program/'+name)
    if 'custom_irq_bit' not in marker and program['isr_address']%256!=44:
        _refuse('f6-isr-vector-invalid','/f6_execution/program/isr_address')
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    if program['boot_address']!=source_backed_boot_fetch(request.cpu.profile,base_dir=base_dir,
            configured_boot_base=request.cpu.profile.cpu.reset_vector):
        _refuse('f6-native-reset-entry-mismatch','/f6_execution/program/boot_address')
    return deepcopy(marker)



def compile_f6_execution_contract(request,*,base_dir):
    """Rebuild every field from the same request, source, wiring and firmware."""
    from .compiled_paths import (PathCompileRequest,_Assessment,_instruction_source,
        _validate_static_dma_routes,_wiring_resource_document,FUNCTION_INSTRUCTION_MASTER,FUNCTION_DATA_MASTER)
    from .f6_dma_source_provider import select_f6_dma_source_provider, f6_dma_static_bindings
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract_for_profile,verify_native_irq_cpu_source)
    if not isinstance(request,PathCompileRequest):
        _refuse('f6-compile-request-required','/request')
    cpu=request.cpu;wiring=request.wiring
    marker=_marker(request,base_dir=base_dir);program=marker['program']
    custom = 'custom_irq_bit' in marker
    if custom:
        from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_source
        bit = marker['custom_irq_bit']
        try:
            source = verify_custom_irq_source(cpu.profile,base_dir=base_dir)
            abi = cpu.profile.evidence['custom_irq_abi']
            if (type(bit) is not int or not 3 <= bit < 32 or abi['abi'] != 'picorv32_custom0'
                    or abi['handler_address'] != 16 or abi['retirq_encoding'] != 0x0400000b):
                raise ValueError('custom IRQ ABI or line unsupported')
        except (ValueError,KeyError,OSError) as error:
            _refuse('f6-cpu-provider-unsupported','/cpu/profile',str(error))
        provider=dict(schema_version='custom_irq_cpu_observation.v1',abi=abi['abi'],
            input_port=abi['input_port'],input_width=abi['width'],input_bit=bit,
            source_attribution='unknown',retirement='unknown',machine_external_take='unsupported')
    else:
        try:provider=native_irq_receipt_contract_for_profile(cpu.profile)
        except ValueError as error:_refuse('f6-cpu-provider-unsupported','/cpu/profile',str(error))
    try:
        _validate_static_dma_routes(cpu,request.devices,wiring)
    except ValueError as error:
        _refuse(getattr(error,'code','f6-route-invalid'),getattr(error,'pointer','/wiring/dma_master_routes'),str(error))
    routes=wiring.dma_master_routes
    if len(routes)!=2 or {r.operation for r in routes}!={'read','write'} or len({r.initiator_instance for r in routes})!=1:
        _refuse('f6-ram-routes-required','/wiring/dma_master_routes')
    mover=request.device(routes[0].initiator_instance)
    if mover is None:
        _refuse('f6-dma-provider-required','/devices')
    try:
        dma_provider=select_f6_dma_source_provider(mover.profile,base_dir=base_dir)
        dma_source=dma_provider.source
        cpu_source=source if custom else verify_native_irq_cpu_source(cpu.profile,base_dir=Path(base_dir))
        master, control_template=f6_dma_static_bindings(dma_provider,mover.profile,base_dir=base_dir)
        if master['endpoint_id'] != dma_provider.master_endpoint_id:
            raise ValueError('f6-dma-master-provider-drift')
    except F6ContractRefused:
        raise
    except (ValueError,KeyError,OSError) as error:
        _refuse('f6-source-provider-unsupported','/artifacts',str(error))
    instruction=request.role_pointer(FUNCTION_INSTRUCTION_MASTER)
    data=request.role_pointer(FUNCTION_DATA_MASTER)
    cpu_protocol=('wishbone','classic') if custom else ('obi','1')
    if (instruction is None or data is None or any(cpu.endpoint(e) is None or cpu.endpoint(e).protocol!=cpu_protocol for e in (instruction,data))):
        _refuse('f6-cpu-endpoints-unsupported','/cpu')
    image_check=_Assessment('F6')
    image=_instruction_source(image_check,cpu,wiring,{FUNCTION_INSTRUCTION_MASTER:instruction})
    if image is None or image_check.missing:
        _refuse('f6-instruction-source-required','/wiring/resources')
    resource,image_source=image
    if resource.component_instance!=cpu.instance_id or resource.write is not True:
        _refuse('f6-shared-memory-permission-required','/wiring/resources')
    for index,route in enumerate(routes):
        if (route.target!=dict(kind='persistent_memory',component_instance=cpu.instance_id,resource_id=resource.resource_id)
                or route.initiator_endpoint_id!=master['endpoint_id'] or route.byte_enable!=15
                or route.permissions!=(route.operation,) or route.readable_offsets or route.writable_offsets
                or route.accepted_write_values):
            _refuse('f6-ram-route-unsupported',f'/wiring/dma_master_routes/routes/{index}')
        binding=wiring.dma_master_route_bindings[index]
        require_exact(master['template_binding'],dict(binding['initiator']),pointer=f'/wiring/dma_master_route_bindings/{index}/initiator')
        address=program['source_address'] if route.operation=='read' else program['destination_address']
        if not route.base<=address or address+16>route.base+route.size:
            _refuse('f6-ram-route-range-invalid',f'/wiring/dma_master_routes/routes/{index}/base')
    controls=[w for w in wiring.windows if w.target_instance==mover.instance_id and
        mover.endpoint(w.endpoint_id) is not None and mover.endpoint(w.endpoint_id).function=='mmio_slave']
    if (len(controls)!=1 or controls[0].endpoint_id!=dma_provider.control_endpoint_id
            or mover.profile.address is None
            or not 16 <= controls[0].size <= mover.profile.address.window_size
            or controls[0].base % mover.profile.address.alignment
            or controls[0].base + controls[0].size > 2**32):
        _refuse('f6-control-window-required','/wiring/windows')
    control=controls[0]
    for aperture in wiring.resources:
        if (aperture.base is not None and aperture.size is not None
                and control.base < aperture.base+aperture.size
                and aperture.base < control.base+control.size):
            window_index=wiring.windows.index(control)
            _refuse('f6-control-window-overlaps-memory-resource',f'/wiring/windows/{window_index}',
                    {'resource_id':aperture.resource_id})
    irq_entries=[e for e in cpu.profile.endpoints if e.function=='interrupt_entry']
    irq_outputs=[e for e in mover.profile.endpoints if e.function=='interrupt_source']
    deliveries=[d for d in wiring.deliveries if d.producer_instance==mover.instance_id and d.consumer_instance==cpu.instance_id]
    if (len(irq_entries)!=1 or len(irq_outputs)!=1 or len(deliveries)!=1):
        _refuse('f6-native-irq-binding-required','/wiring/deliveries')
    delivery=deliveries[0]
    if (delivery.producer_endpoint_id!=irq_outputs[0].endpoint_id
            or delivery.producer_endpoint_id!=dma_provider.irq_endpoint_id
            or delivery.producer_signal!=dma_provider.irq_port
            or delivery.consumer_endpoint_id!=irq_entries[0].endpoint_id or delivery.trigger!=dma_provider.irq_trigger
            or cpu.profile.cpu.irq_entry_polarity!='active_high'):
        _refuse('f6-native-irq-binding-required','/wiring/deliveries')
    slices=[dict(source_id=f'{cpu.instance_id}.f6.word{i}',bit_offset=i*11,width=11,mask=2047,
        register=3,instruction_offset=offset) for i,offset in enumerate((40,48,56,64))]
    pc=dict(schema_version='compiled_F6_program.v1',**program,slot_bytes=256,online_prefix_bytes=128,
        result_stride=24,operand_instruction_offsets=[40,48,56,64],initial_image=[],initial_image_sha256=None,
        instruction_source_id=image_source['source_id'])
    if custom:
        pc['custom_irq']=dict(abi=abi['abi'],irq_bit=bit,handler_address=abi['handler_address'],
                              retirq_encoding=abi['retirq_encoding'])
    if 'storage_support' in marker:
        from myfuzz.integration.f6_storage_support import compile_storage_support
        pc['storage_support'] = compile_storage_support(request, marker['storage_support'], base_dir=base_dir)
    if 'shared_slots' in marker:
        from myfuzz.integration.shared_f6_slots import compile_shared_slots
        pc['shared_slots'] = compile_shared_slots(request, marker['shared_slots'],
            slot_count=program['slot_count'], base_dir=base_dir)
    if 'gpio_irq' in marker:
        from myfuzz.integration.shared_irq_dispatcher import compile_gpio_irq_declaration
        pc['gpio_irq'] = compile_gpio_irq_declaration(request,marker['gpio_irq'],base_dir=base_dir)
        gpio_bit=pc['gpio_irq'].get('irq_bit')
        if (custom and (gpio_bit is None or gpio_bit==bit)) or (not custom and gpio_bit is not None):
            _refuse('f6-custom-gpio-irq-bit-invalid','/f6_execution/gpio_irq/irq_bit')
    if 'declared_irq' in marker:
        from myfuzz.integration.shared_declared_irq import compile_declared_irq
        pc['declared_irq'] = compile_declared_irq(request, marker['declared_irq'], program, base_dir=base_dir)
    dma_behavior = dma_provider.behavior
    contract=dict(schema_version=SCHEMA_VERSION,flow_id='F6',path_id=f'F6:{slices[0]["source_id"]}',
        cpu=dict(instance_id=cpu.instance_id,profile_fingerprint=cpu.profile.profile_fingerprint,
            artifact_kind='wishbone_cpu' if custom else 'obi_cpu',instruction_endpoint_id=instruction,data_endpoint_id=data,
            source_verification_sha256=_sha(cpu_source),native_irq_provider=deepcopy(provider)),
        dma=dict(instance_id=mover.instance_id,profile_fingerprint=mover.profile.profile_fingerprint,
            artifact_kind='wishbone_dma',transfer_provider_id=mover.capability.feature_contract.provider_id,
            source_contract=dma_source,csr=dma_provider.csr,behavior=dma_behavior,master_endpoint_link=master,
            selected_template=dict(master=master['template_binding'],
                control=control_template)),
        instruction_source_id=image_source['source_id'],
        candidate_layout=dict(wire_bytes=8,record_limit=1,reserved_zero_mask=((1<<64)-(1<<44)),
            distinct=True,seed=marker['seed'],sources=slices),program_contract=pc,
        memory=dict(resource=_wiring_resource_document(resource),shared_object_required=True,
            cpu_service_owner=cpu.instance_id,dma_service_owner=mover.instance_id,
            service_lifecycle='preserve_constructor_service_and_ledger',
            source=dict(base=program['source_address'],size=16),destination=dict(base=program['destination_address'],size=16),
            results=dict(base=program['result_base'],size=24*program['slot_count'])),
        control=dict(device_id=control.device_id,endpoint_id=control.endpoint_id,base=control.base,size=control.size,
            configuration_order=['source','destination','length','control']),
        master_routes=dict(intents=wiring.document['dma_master_routes'],bindings=[dict(route_id=b['route_id'],initiator=dict(b['initiator']),target=dict(b['target'])) for b in wiring.dma_master_route_bindings],
            physical_endpoint_link=master,live_topology_binding_required=True),
        irq=dict(delivery_id=delivery.delivery_id,producer_instance=mover.instance_id,
            producer_endpoint_id=delivery.producer_endpoint_id,producer_port=dma_provider.irq_port,consumer_instance=cpu.instance_id,
            consumer_endpoint_id=delivery.consumer_endpoint_id,consumer_port=provider['input_port'],
            delivery_policy=('IrqPulseDelivery' if dma_provider.irq_trigger=='pulse' else 'level'),
            target_local_ticks=(16 if dma_provider.irq_trigger=='pulse' else 0),
            clear_policy=('fixed_expiry' if dma_provider.irq_trigger=='pulse' else 'software_write'),
            native_take_provider=deepcopy(provider),isr_return_schema=('unobservable' if custom else 'native_f6_isr_return.v1')),
        termination=('custom_irq_observation_only' if custom else 'native_dma_irq_then_cpu_isr_readback'),expectation_ids=list(EXPECTATION_IDS))
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    try:
        firmware=build_f6_firmware(contract)
    except ValueError as error:
        _refuse('f6-program-invalid','/f6_execution/program',str(error))
    pc['initial_image']=list(firmware.initial_segment_manifest)
    pc['initial_image_sha256']=firmware.manifest_sha256
    # Fixed executable regions, all slots (including unmaterialized prefixes),
    # data and results occupy disjoint intervals of this same declared resource.
    ranges=[('slots',program['slot_base'],256*program['slot_count']),
        ('source_address',program['source_address'],16),('destination_address',program['destination_address'],16),
        ('result_base',program['result_base'],24*program['slot_count'])]
    if 'storage_support' in pc:
        ranges += [(phase+'_support_result', pc['storage_support'][phase+'_result_address'], 4)
            for phase in ('before', 'after')]
    if 'shared_slots' in pc:
        ranges.append(('shared_storage_results', pc['shared_slots']['results_base'], 4*program['slot_count']))
        if 'scratch_address' in pc['shared_slots']:
            ranges.append(('shared_memory_scratch',pc['shared_slots']['scratch_address'],4))
    if 'gpio_irq' in pc:
        ranges += [('shared_irq_scratch',pc['gpio_irq']['scratch_address'],64),
            ('shared_irq_results',pc['gpio_irq']['result_address'],12)]
    if 'declared_irq' in pc:
        ranges += [('declared_irq_phase', pc['declared_irq']['phase_address'], 4),
                   ('declared_irq_scratch', pc['declared_irq']['scratch_address'], 64),
                   ('declared_irq_results', pc['declared_irq']['result_address'], 64)]
    ranges += [('initial_image',r['address'],r['length']) for r in pc['initial_image']
        if not program['slot_base']<=r['address']<program['slot_base']+256*program['slot_count']]
    for index,(name,base,size) in enumerate(ranges):
        if base<resource.base or base+size>resource.base+resource.size or base+size>2**32:
            _refuse('f6-program-outside-memory','/f6_execution/program/'+name)
        if base<control.base+control.size and control.base<base+size:
            _refuse('f6-program-mmio-overlap','/f6_execution/program/'+name)
        for other,obase,osize in ranges[:index]:
            if base<obase+osize and obase<base+size:
                _refuse('f6-program-overlap','/f6_execution/program/'+name,{'other':other})
    if not pc['initial_image'] or pc['initial_image_sha256']!=_sha(pc['initial_image']):
        _refuse('f6-initial-image-invalid','/program_contract/initial_image')
    return deepcopy(contract)


def validate_f6_execution_contract(document,*,request,base_dir):
    return require_exact(compile_f6_execution_contract(request,base_dir=base_dir),document,pointer='/execution_contract')
