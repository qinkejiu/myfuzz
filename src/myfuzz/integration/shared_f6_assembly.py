"""Validated pre-start F6 owners, reusable by a wider session assembler.

This seam allocates no process and grants no DMA/source authority. The caller
must still run the existing typed path, route, build and execution admissions.
The current F6 execution contract remains limited to its CPU/DMA pair.
"""
from dataclasses import dataclass
import json
from types import MappingProxyType

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner, Binding


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-F6-assembly-' + reason)


@dataclass(frozen=True)
class MemoryReservation:
    owner: str
    address: int
    size: int

    def __post_init__(self):
        _require(type(self.owner) is str and bool(self.owner)
            and type(self.address) is int and self.address >= 0
            and type(self.size) is int and self.size > 0
            and self.address + self.size <= 1 << 32, 'reservation-shape')


@dataclass(frozen=True)
class F6Assembly:
    memory: PersistentMemory
    cpu: object
    dma: GeneratedWishboneDmaScenarioSession
    runner: ScenarioRunner
    reservations: tuple[MemoryReservation, ...] = ()
    companions: object = None
    request: object = None
    _companion_json: str = '{}'
    companion_authorities: object = None

    def companion_document(self):
        return json.loads(self._companion_json)

    def validate(self, *, contract, artifacts, ownership, base_dir, cache_dir, request=None):
        return build_f6_assembly(contract=contract, artifacts=artifacts,
            ownership=ownership, base_dir=base_dir, cache_dir=cache_dir,
            memory=self.memory, cpu=self.cpu, dma=self.dma, runner=self.runner,
            reservations=self.reservations, companions=self.companions,
            request=request if request is not None else self.request)


def _validate_memory(memory, contract, program, reservations):
    from myfuzz.integration.compiled_f6_runtime_path import _memory_target_identity
    from myfuzz.scenario.runtime_path_contract import persistent_memory_route_identity_document
    _require(type(memory) is PersistentMemory, 'memory-type')
    resource = contract['memory']['resource']
    identity = persistent_memory_route_identity_document(memory,
        memory_id=resource['resource_id'], base=resource['base'], size=resource['size'])
    _require(identity == _memory_target_identity(resource), 'memory-contract')
    def resolve(address, size):
        start = memory.resolve_span(address, 1, write=True)
        end = memory.resolve_span(address + size - 1, 1, write=True)
        _require(start[:2] == end[:2] and end[2] == start[2] + size - 1,
            'memory-span')
        return start
    p = contract['program_contract']
    spans = [(address, len(data)) for address, data in program.initial_images.items()]
    spans += [(address, count * 4) for address, count in program.instruction_slots]
    spans += [(p['source_address'], 16), (p['destination_address'], 16),
              (p['result_base'], p['result_stride'] * p['slot_count'])]
    if 'shared_slots' in p:
        spans += [(p['shared_slots']['results_base'], 4*p['shared_slots']['slot_count'])]
        if 'scratch_address' in p['shared_slots']:
            spans += [(p['shared_slots']['scratch_address'],4)]
    if 'gpio_irq' in p:
        spans += [(p['gpio_irq']['scratch_address'],64),(p['gpio_irq']['result_address'],12)]
    if 'declared_irq' in p:
        spans += [(p['declared_irq']['phase_address'],4), (p['declared_irq']['scratch_address'],64),
                  (p['declared_irq']['result_address'],64)]
    if 'storage_support' in p:
        spans += [(p['storage_support'][phase+'_result_address'], 4) for phase in ('before', 'after')]
    _require(type(reservations) is tuple
        and all(type(row) is MemoryReservation for row in reservations), 'reservation-type')
    for index, reservation in enumerate(reservations):
        address, size = reservation.address, reservation.size
        resolve(address, size)
        _require(not any(address < start + length and start < address + size
            for start, length in spans), 'reservation-overlap')
        _require(not any(address < other.address + other.size
            and other.address < address + size for other in reservations[:index]),
            'reservation-overlap')
    for address, size in spans:
        memory_id, _, offset = resolve(address, size)
        _require(not any((memory_id, lane) in memory._bytes
            or (memory_id, lane) in memory._instruction_slots
            for lane in range(offset, offset + size)), 'occupied-F6-span')


def build_f6_assembly(*, contract, artifacts, ownership, base_dir, cache_dir,
                      memory=None, cpu=None, dma=None, dma_service=None,
                      runner=None, reservations=(), request=None, companions=None):
    """Allocate missing owners or reuse explicitly supplied pre-start owners.

    In particular, an outer assembler can supply its RAM and DMA MemoryService,
    or its complete CPU/router/DMA/runner. References are checked, never copied.
    Additional flow reservations must be disjoint from all F6 code/data spans.
    """
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    program = build_f6_firmware(contract)
    cpu_id, dma_id = contract['cpu']['instance_id'], contract['dma']['instance_id']
    from .f6_storage_companion import companion_artifact_documents, validate_companion_sessions
    companion_docs = companion_artifact_documents(contract=contract, artifacts=artifacts,
        request=request, base_dir=base_dir)
    _require(set(artifacts) == {cpu_id, dma_id, *companion_docs}, 'artifact-set')
    if companions is None:
        from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
        from .f6_gpio_companion import create_gpio_companion
        companions = {name: (create_gpio_companion(artifacts[name],base_dir=base_dir,cache_dir=cache_dir)
            if row.get('schema_version')=='compiled_F6_gpio_companion.v1' else
            GeneratedApb3RegisterSession(artifacts[name], base_dir=base_dir,
                cache_dir=cache_dir, setup_writes=(), probe_offsets=())) for name,row in companion_docs.items()}
    else:
        companions = dict(companions)
    _require(set(companions) == set(companion_docs), 'companion-session-set')
    validate_companion_sessions(documents=companion_docs, artifacts=artifacts, sessions=companions)
    from .f6_gpio_companion import gpio_companion_authority
    # Observation-only custom IRQ execution does not issue GPIO register or
    # reset certificates. Installing that authority would attach a reset
    # command recorder to every normal GPIO tick and exhaust it on long runs.
    custom_observation='custom_irq' in contract['program_contract']
    authorities = ({name:gpio_companion_authority(companions[name]) for name,row in companion_docs.items()
        if row.get('schema_version')=='compiled_F6_gpio_companion.v1'} if not custom_observation else {})
    support = (contract['program_contract'].get('storage_support')
        or contract['program_contract'].get('shared_slots'))
    if support is not None:
        target_id = support['component']
        _require(target_id in companion_docs
            and companion_docs[target_id]['source_contract']['digest'] == support['source_contract_digest'],
            'support-source-contract')
        from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority, _AUTHORITIES
        local = companions[target_id]
        if companion_docs[target_id].get('schema_version')=='compiled_F6_mmio_companion.v1':
            # Bus-only targets expose no internal state/version authority.
            authority = None
        elif companion_docs[target_id].get('schema_version')=='compiled_F6_gpio_companion.v1':
            authority=authorities.get(target_id)
        elif custom_observation:
            authority=None
        else:
            authority = _AUTHORITIES.get(local)
            if authority is None:
                authority = ApbStorageRegisterVersionAuthority(local)
            _require(type(authority) is ApbStorageRegisterVersionAuthority and authority.target is local,
                'support-authority-owner')
        if authority is not None:
            authorities[target_id] = authority
    if memory is None:
        memory = cpu.memory if type(cpu) in (GeneratedCve2Session, GeneratedWishboneCpuSession) else (
            dma.memory if type(dma) is GeneratedWishboneDmaScenarioSession else (
                dma_service.memory if type(dma_service) is MemoryService else None))
    if memory is None:
        resource = contract['memory']['resource']
        from myfuzz.isa.constraints import f1_isa_from_profile
        instruction_isa = f1_isa_from_profile(artifacts[cpu_id].plan.profile)
        memory = PersistentMemory(regions=(MemoryRegion(resource['resource_id'],
            resource['base'], resource['size'], readable=resource['read'],
            writable=resource['write']),), initialization_seed=0,
            max_initialized_bytes=resource['size'],
            instruction_isa=instruction_isa if len(instruction_isa.extensions) > 1 else None)
    else:
        from myfuzz.isa.constraints import f1_isa_from_profile
        supported_isa = f1_isa_from_profile(artifacts[cpu_id].plan.profile)
        if (memory.instruction_isa is not None
                and not set(memory.instruction_isa.extensions) <= set(supported_isa.extensions)):
            raise ValueError('shared-memory-instruction-isa-exceeds-cpu-profile')
    _validate_memory(memory, contract, program, reservations)
    if dma_service is not None:
        _require(type(dma_service) is MemoryService and dma_service.memory is memory,
            'DMA-service-memory-owner')
    if dma is None:
        if dma_service is None:
            dma_service = MemoryService(memory, TransactionLedger(),
                include_writer_kinds=True, commit_stream_capacity=256)
        dma = GeneratedWishboneDmaScenarioSession(artifacts[dma_id],
            base_dir=base_dir, cache_dir=cache_dir, memory_service=dma_service,
            source_component=dma_id, max_control_edges=32, max_events=10000)
    _require(type(dma) is GeneratedWishboneDmaScenarioSession, 'DMA-type')
    _require(dma_service is None or dma.memory_service is dma_service, 'DMA-service-owner')
    control = contract['control']
    windows = (DeviceWindow(control['device_id'], control['base'], control['size'], dma),)
    windows += tuple(DeviceWindow(name, row['window']['base'], row['window']['size'], companions[name])
        for name, row in sorted(companion_docs.items()))
    custom=contract['program_contract'].get('custom_irq')
    group=None if custom else shared_irq_group(contract,artifacts,base_dir=base_dir)
    custom_bindings=None
    if custom:
        _require(not contract['program_contract'].get('declared_irq'), 'custom-declared-IRQ-not-integrated')
        from .shared_custom_irq_cpu import build_shared_custom_irq_cpu
        from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
        verified=verify_custom_irq_artifact(artifacts[cpu_id],base_dir=base_dir)
        _require(verified['abi']==custom['abi'], 'custom-IRQ-ABI')
        irq_sources=[(dma_id,'irq',custom['irq_bit'])]
        gpio=contract['program_contract'].get('gpio_irq')
        if gpio is not None:
            gpio_id=gpio['component'];gpio_bit=gpio['irq_bit']
            _require(gpio_id in companion_docs and
                companion_docs[gpio_id].get('schema_version')=='compiled_F6_gpio_companion.v1',
                'custom-IRQ-gpio-companion')
            _require(gpio_bit!=custom['irq_bit'],'custom-IRQ-distinct-bits')
            irq_sources.append((gpio_id,companion_docs[gpio_id]['irq_source_port'],gpio_bit))
        custom_bindings=tuple(Binding(source,port,cpu_id,'irq',1,target_bit_offset=bit)
                              for source,port,bit in irq_sources)
        _require(ownership.field_width(cpu_id,'irq')==32 and all(
            ownership.binding_producer(cpu_id,'irq',bit,1)==source+'.'+port
            for source,port,bit in irq_sources),'custom-IRQ-ownership')
        source_bits={bit for _,_,bit in irq_sources}
        _require(all(owner.kind=='fixed' and owner.producer_ref in ('inactive','constant_zero')
                     for bit,owner in enumerate(ownership._bits[(cpu_id,'irq')])
                     if bit not in source_bits), 'custom-IRQ-inactive-bits')
        if cpu is None:
            shared=build_shared_custom_irq_cpu(artifact=artifacts[cpu_id],base_dir=base_dir,
                cache_dir=cache_dir,memory=memory,router=DataflowRouter(windows),
                irq_sources=tuple(irq_sources))
            cpu=shared.cpu
            _require(shared.bindings==custom_bindings,'custom-IRQ-binding')
    if cpu is None:
        cpu = GeneratedCve2Session(artifacts[cpu_id], base_dir=base_dir,
            cache_dir=cache_dir, memory=memory,
            router=DataflowRouter(windows), defer_mmio=True, native_irq_receipts=True,
            memory_commit_receipts=True, memory_readback_receipts=True,
            physical_tick_samples=True,**({'irq_input_port':group.target_port} if group is not None else {}))
    _require(type(cpu) is (GeneratedWishboneCpuSession if custom else GeneratedCve2Session), 'CPU-type')
    if not custom:
        _require(cpu.irq_input_port==(group.target_port if group is not None else 'irq'),'CPU-IRQ-input-port')
    _require(cpu.artifact is artifacts[cpu_id] and dma.artifact is artifacts[dma_id], 'artifact-owner')
    _require(cpu.memory is memory and cpu.service.memory is memory
        and dma.memory is memory and dma.memory_service.memory is memory, 'memory-owner')
    _require(type(cpu.service) is MemoryService and type(dma.memory_service) is MemoryService
        and type(cpu.service.ledger) is TransactionLedger
        and type(dma.memory_service.ledger) is TransactionLedger
        and cpu.service is not dma.memory_service
        and cpu.service.ledger is not dma.memory_service.ledger, 'service-owners')
    _require(cpu.defer_mmio and (cpu._custom_irq_contract is not None if custom else cpu.native_irq_receipts_enabled)
        and cpu.memory_commit_receipts_enabled and cpu.memory_readback_receipts_enabled
        and cpu._physical_tick_samples_enabled and cpu.service.commit_stream_enabled,
        'CPU-capabilities')
    _require(dma.memory_service.include_writer_kinds
        and dma.memory_service.commit_stream_enabled, 'DMA-capabilities')
    _require(type(cpu.router) is DataflowRouter and cpu.router.windows == windows, 'control-window')
    for local in (cpu, dma, *companions.values()):
        _require(local._process is None and local._case_id is None
            and local._execution == '' and local.local_ticks == 0, 'pre-start')
    for service in (cpu.service, dma.memory_service):
        _require(not service.events and not service.ledger._entries
            and service.pending_commit_count == 0, 'service-pre-start')
    binding = custom_bindings[0] if custom else Binding(dma_id, 'irq', cpu_id, 'irq', 1)
    bindings=custom_bindings if custom else ((binding,) if group is None else group.member_bindings())
    pulses=({binding:16} if contract['irq']['delivery_policy']=='IrqPulseDelivery' else {}) if custom else ({binding:16} if group is None else {b:member.pulse_width_ticks for b,member in zip(bindings,group.members) if member.mode=='pulse'})
    if custom and len(custom_bindings)>1:
        pulses[custom_bindings[1]]=4
    sessions = {cpu_id: cpu, dma_id: dma, **companions}
    if runner is None:
        runner = ScenarioRunner(sessions=sessions,
            ownership=ownership, bindings=bindings, irq_pulses=pulses,**({'irq_delivery_groups':(group,)} if group is not None else {}))
    _require(type(runner) is ScenarioRunner and runner.sessions == sessions,
        'runner-sessions')
    _require(runner._status == 'created' and not runner.execution_id
        and runner.event_count == 0 and not any(runner.local_ticks.values()), 'runner-pre-start')
    _require(runner.ownership.document() == ownership.document()
        and runner.bindings == bindings and set(runner._irq_pulses) == set(pulses)
        and all(runner._irq_pulses[b].width_ticks==width for b,width in pulses.items())
        and (group is None or all(runner.irq_group_for(b)==group for b in bindings)), 'runner-IRQ-contract')
    _require(getattr(runner, '_uart_ram_commit_join', None) is None, 'runner-already-configured')
    return F6Assembly(memory, cpu, dma, runner, reservations, MappingProxyType(companions),
        request, json.dumps(companion_docs, sort_keys=True, separators=(',', ':')),
        MappingProxyType(authorities))


def _declared_field_span(artifact,*,endpoint_id,role,direction,width):
    """Declared inclusive bit span of exactly one endpoint role.

    A profile that declares ``bit_range`` makes the physical port a real
    bit-slice; an undeclared one-bit role means the whole (one-bit) port.
    """
    endpoints=[e for e in artifact.plan.profile.endpoints if e.endpoint_id==endpoint_id]
    _require(len(endpoints)==1,'CPU-IRQ-endpoint')
    fields=[f for f in endpoints[0].fields if f.role==role
            and f.direction in (None,direction)]
    _require(len(fields)==1,'CPU-IRQ-endpoint-role')
    field=fields[0]
    _require(field.width is None or field.width==width,'CPU-IRQ-endpoint-width')
    span=field.bit_range
    if span is None:
        _require(width==1,'CPU-IRQ-endpoint-span')
        span=(0,0)
    _require(type(span) is tuple and 0<=span[0]<=span[1] and span[1]-span[0]+1==width,
        'CPU-IRQ-endpoint-span')
    return span


def verified_shared_cpu_irq_input(artifact,wire):
    """The one verified CPU IRQ input export its profile actually declares."""
    profile=artifact.plan.profile
    endpoint_id=profile.cpu.irq_entry_endpoint
    role=profile.cpu.irq_entry_role
    _require(type(endpoint_id) is str and type(role) is str,'CPU-IRQ-declaration')
    bit_lo,bit_hi=_declared_field_span(artifact,endpoint_id=endpoint_id,role=role,
        direction='input',width=1)
    inputs=[e for e in artifact.runtime_document['physical_exports']
            if e.get('runtime_name')==wire and e.get('direction')=='input'
            and type(e.get('bit_lo')) is int and type(e.get('bit_hi')) is int
            and type(e.get('width')) is int and e['width']>=1
            and e['bit_lo']<=bit_lo<=bit_hi<=e['bit_hi']
            and e.get('endpoint_id')==endpoint_id and e.get('role')==role
            and e.get('disposition')=='functional']
    _require(len(inputs)==1,'verified-CPU-IRQ-export')
    export=inputs[0]
    names=('physical_port','endpoint_id','role','direction','bit_lo','bit_hi','width')
    _require(sum(all(r.get(k)==export.get(k) for k in names)
        for r in artifact.structural.abi_document['ports'])==1,'verified-CPU-IRQ-ABI')
    return export


def cpu_irq_host_input_field(artifact,export,host_offset):
    """Host input width (the ABI row width) and its declared constant bits.

    Host coordinates are port-local: the host field is the ABI input row, so the
    offset is ``declared_bit - abi_bit_lo``. For a bit-slice CPU the row is the
    one-bit slice and the offset is therefore zero; the DUT line number stays
    documentary evidence. A wide ABI row may carry a non-zero offset, and every
    other host bit must be a constant zero the profile already declares.
    """
    _require(type(host_offset) is int and 0<=host_offset<export['width'],
        'CPU-IRQ-host-offset')
    port=export['physical_port'];fact=artifact.plan.facts.port(port)
    _require(fact is not None and fact.direction=='input','CPU-IRQ-physical-port')
    _require(type(fact.width) is int and fact.width>=export['bit_hi']+1,'CPU-IRQ-port-width')
    constants=set()
    for action in artifact.plan.profile.port_actions:
        if action.port==port and action.action=='constant' and action.value==0:
            constants.update(action.bits)
    host=[bit for bit in range(export['width']) if bit!=host_offset]
    _require(all(export['bit_lo']+bit in constants for bit in host),
        'CPU-IRQ-host-field-unclassified')
    return export['width'],host


def _shared_irq_group_and_export(contract,artifacts,*,base_dir):
    declaration=contract['program_contract'].get('gpio_irq')
    declared=contract['program_contract'].get('declared_irq')
    source=contract['dma'].get('source_contract',{})
    schema=source.get('schema_version')
    if schema is not None:
        from .f6_dma_behavior import f6_dma_irq_trigger
        dma_mode=f6_dma_irq_trigger(source)
    else:
        dma_mode='pulse'
    if declaration is None and declared is None and dma_mode=='pulse':return None,None,0
    from myfuzz.local_harness.native_irq_receipt_contract import verify_native_irq_receipt_artifact
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember
    cpu_id,dma_id=contract['cpu']['instance_id'],contract['dma']['instance_id']
    artifact=artifacts[cpu_id];wire=verify_native_irq_receipt_artifact(artifact,base_dir=base_dir)
    export=verified_shared_cpu_irq_input(artifact,wire)
    profile=artifact.plan.profile
    bit_lo,_=_declared_field_span(artifact,endpoint_id=profile.cpu.irq_entry_endpoint,
        role=profile.cpu.irq_entry_role,direction='input',width=1)
    host_offset=bit_lo-export['bit_lo']
    cpu_irq_host_input_field(artifact,export,host_offset)
    members=(IrqDeliveryMember(dma_id,'irq',mode=dma_mode,
        pulse_width_ticks=16 if dma_mode=='pulse' else None),)
    if declaration is not None:
        gpio_id=declaration['component'];gpio=artifacts[gpio_id]
        _require(verify_native_physical_observation(gpio),'verified-GPIO-IRQ-export')
        outputs=[e for e in gpio.runtime_document['physical_exports'] if e['role']=='irq' and e['direction']=='output'
                 and e['width']==1 and e['bit_lo']==e['bit_hi']==0]
        _require(len(outputs)==1,'unique-GPIO-IRQ-export')
        members+=(IrqDeliveryMember(gpio_id,outputs[0]['physical_port'],mode='pulse',pulse_width_ticks=4),)
    if declared is not None:
        _require(declaration is None or declaration['group_id'] == declared['group_id'], 'declared-IRQ-group-id')
        member = IrqDeliveryMember(**declared['irq_group_member'])
        _require(member.source_component in artifacts, 'declared-IRQ-artifact')
        members += (member,)
    group_id = declaration['group_id'] if declaration else (declared['group_id'] if declared else 'f6-'+dma_id+'-irq')
    group=IrqDeliveryGroup(group_id,cpu_id,export['physical_port'],members,
        target_bit_offset=host_offset,target_input_bit_lo=export['bit_lo'])
    return group,export,host_offset


def shared_irq_group(contract,artifacts,*,base_dir):
    """Use verified physical CPU/GPIO exports and the existing DMA adapter port."""
    if 'custom_irq' in contract['program_contract']:
        _require('declared_irq' not in contract['program_contract'], 'custom-declared-IRQ-not-integrated')
        return None
    return _shared_irq_group_and_export(contract,artifacts,base_dir=base_dir)[0]


def shared_custom_gpio_irq_route(contract,artifacts,*,base_dir):
    """Verified separate GPIO-to-CPU vector route for the shared F5 graph."""
    p=contract['program_contract']; custom=p.get('custom_irq'); gpio=p.get('gpio_irq')
    if custom is None or gpio is None:
        return None
    from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    cpu_id=contract['cpu']['instance_id']; gpio_id=gpio['component']
    verified=verify_custom_irq_artifact(artifacts[cpu_id],base_dir=base_dir)
    _require(verified['abi']==custom['abi'] and verified['input_port']=='irq','custom-IRQ-CPU-export')
    artifact=artifacts[gpio_id]
    _require(verify_native_physical_observation(artifact),'custom-IRQ-gpio-observation')
    outputs=[e for e in artifact.runtime_document['physical_exports']
             if e.get('role')=='irq' and e.get('direction')=='output' and e.get('width')==1
             and e.get('bit_lo')==e.get('bit_hi')==0]
    _require(len(outputs)==1,'custom-IRQ-gpio-export')
    return dict(schema_version='shared_custom_gpio_irq_route.v1',
        source_component=gpio_id,source_port=outputs[0]['physical_port'],source_bit_offset=0,
        target_component=cpu_id,target_port='irq',target_bit_offset=gpio['irq_bit'])


def shared_irq_ownership(ownership,contract,artifacts,*,base_dir):
    from myfuzz.scenario.ownership import compile_ownership,InputField,InputOwner
    group,export,offset=_shared_irq_group_and_export(contract,artifacts,base_dir=base_dir)
    if group is None:return ownership
    doc=ownership.document();cpu=group.target_component
    width,constants=cpu_irq_host_input_field(artifacts[cpu],export,offset)
    dma_ref=contract['dma']['instance_id']+'.irq'
    fields=[r for r in doc['fields'] if (r['component_id'],r['port']) not in ((cpu,'irq'),(cpu,group.target_port))]
    owners=[r for r in doc['owners'] if (r['component_id'],r['port']) not in ((cpu,'irq'),(cpu,group.target_port))]
    previous=[r for r in doc['owners'] if (r['component_id'],r['port']) in ((cpu,'irq'),(cpu,group.target_port))]
    _require(previous and all(
        (r['kind']=='bound' and r['width']==1
         and r['bit_offset']==(offset if r['port']==group.target_port else 0)
         and r['producer_ref'] in (dma_ref,group.owner_ref))
        or (r['port']==group.target_port and r['kind']=='fixed' and r['width']==1
            and r['bit_offset'] in constants and r['producer_ref']=='constant_zero')
        for r in previous),'IRQ-owner-transition')
    fields.append(dict(component_id=cpu,port=group.target_port,width=width))
    owners.extend(dict(component_id=cpu,port=group.target_port,bit_offset=bit,width=1,
        kind='fixed',producer_ref='constant_zero') for bit in constants)
    owners.append(dict(component_id=cpu,port=group.target_port,bit_offset=offset,width=1,
        kind='bound',producer_ref=group.owner_ref))
    return compile_ownership(tuple(InputField(**r) for r in fields),tuple(InputOwner(**r) for r in owners))


def build_f6_custom_irq_cpu(*, artifact, base_dir, cache_dir, memory, router, irq_sources):
    """Allocate the shared Wishbone CPU and real IRQ routes without F6 claims.

    Existing F6 execution and return certification still require their own
    custom-ABI integration; this pre-start seam only binds component resources.
    """
    from .shared_custom_irq_cpu import build_shared_custom_irq_cpu
    return build_shared_custom_irq_cpu(artifact=artifact,base_dir=base_dir,
        cache_dir=cache_dir,memory=memory,router=router,irq_sources=irq_sources)
