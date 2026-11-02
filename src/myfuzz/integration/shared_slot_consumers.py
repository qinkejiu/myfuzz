"""Existing F1/F2/F3 lowerers and consumers on the shared slot executor."""
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace


def _shared_apb_version_consumption(rows, *, before, reader_case_id, device_id, read_event):
    """Correlate a measured read with a sealed writer; never grant source credit."""
    result = dict(schema_version='shared_apb_version_consumption.v1', status='unknown',
        writer_case_id=None, reader_case_id=reader_case_id, read_event_id=read_event,
        source_origin='unknown', reward_eligible=False, native_authority=False)
    keys = ('register','reset_epoch','value','field_version','write_count',
            'artifact_digest','source_contract_digest')
    if (type(before) is not dict or any(k not in before for k in keys)
            or type(before['field_version']) is not int or before['field_version'] <= 0
            or type(read_event) is not int or read_event <= 0):
        return result
    for row in reversed(rows):
        if row.get('flow') != 'F4' or row.get('status') != 'passed':
            continue
        certificate = row.get('certificate', {})
        post = certificate.get('postcondition', {})
        commit = certificate.get('commit', {})
        context = commit.get('context', {})
        if (certificate.get('status') == 'certified' and certificate.get('case_id') == row.get('case_id')
                and type(row.get('case_id')) is str and row['case_id'] != reader_case_id
                and all(post.get(key) == before[key] for key in keys)
                and commit.get('after') == before['value']
                and commit.get('field_version') == before['field_version']
                and context.get('device_id') == device_id):
            result.update(status='observed', writer_case_id=row['case_id'],
                register=before['register'], reset_epoch=before['reset_epoch'],
                field_version=before['field_version'], value=before['value'])
            return result
    return result


def instruction_bindings(admission):
    from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
    from .compiled_f6_runtime_path import restore_prepared_runtime_paths
    prepared = restore_prepared_runtime_paths(admission)
    bindings = {}
    for flow,path in admission['shared_flow_paths'].items():
        if flow=='F5' and path.get('direction') == 'IP_TO_CPU':
            continue
        binding = InstructionImageSourceBinding(path_id=path['path_id'],direction='CPU_TO_IP',
            source_id=path['source_id'],logical_source_id=path['logical_source_id'],
            component=path['cpu_component'],memory_id=path['memory_id'],
            base=path['base'],size=path['size'],readable=True,writable=True)
        binding.validate_prepared(prepared)
        bindings[flow] = binding
    return bindings


def declare_slot(compiled_inputs, layout, admission, *, flow, raw, slot_index, instruction_isa=None):
    from .shared_f6_slots import declare_shared_writer
    from .rv32_fixed_firmware import _addi
    if flow == 'F4':
        return declare_shared_writer(compiled_inputs,layout,raw=raw,slot_index=slot_index)
    if flow=='F5':
        irq = admission['execution_contract']['program_contract'].get('declared_irq')
        if irq is not None:
            from .shared_declared_irq import compile_declared_irq_slot
            return compile_declared_irq_slot(irq, slot_index)
        from .shared_f5_slots import declare_shared_pin
        return declare_shared_pin(compiled_inputs,layout,admission,raw=raw,slot_index=slot_index)
    path, = [row for row in compiled_inputs['compiled']['paths'] if row['flow_id']==flow and row['status']=='executable']
    if flow in ('F1','F3'):
        from myfuzz.runtime.flows.memory import lower_memory_code
        bindings = instruction_bindings(admission)
        context = SimpleNamespace(memory_bindings=bindings,result=layout['scratch_address']+4,
                                  instruction_isa=instruction_isa)
        code,operation,address = lower_memory_code(context,raw,flow=flow)
        declaration = dict(schema_version='shared_memory_fragment.v1',flow_id=flow,
            raw_hex=raw.hex(),operation=operation,ram_address=address)
    elif flow == 'F2':
        from .compiled_f2_layout import compile_f2_candidate_layout
        from .generated_register_reader import declare_reader
        selected = compile_f2_candidate_layout(path).classify(raw)
        if not selected.accepted:
            raise ValueError('shared-slot-F2-candidate:'+str(selected.reason))
        source, = [source for source in path['sources'] if source['kind']=='cpu_load_stream']
        declaration = declare_reader(compiled_inputs['request'],compiled_inputs['compiled'],
            source_id=source['source_id'],address=selected.address,
            result_address=layout['results_base']+4*slot_index)
        code = bytes.fromhex(declaration['code_hex'])
    else:
        raise ValueError('shared-slot-flow-unsupported:'+str(flow))
    functional_bytes = len(code)
    footer = b''.join(word.to_bytes(4,'little') for word in (_addi(10,0,1),_addi(11,0,1)))
    if len(code)+len(footer)>128 or len(code)%4:
        raise ValueError('shared-slot-fragment-capacity')
    envelope = code+footer+bytes.fromhex('13000000')*((128-len(code)-len(footer))//4)
    return dict(declaration,code_hex=envelope.hex(),code_sha256=sha256(envelope).hexdigest(),
        functional_bytes=functional_bytes,scope='typed_online_fragment_in_shared_slot')


def submit_non_dma(runtime,raw,mapping,declaration):
    """Dispatch existing consumers after the one common slot executor."""
    if mapping['flow']=='F5':
        if 'declared_irq' in runtime.contract['program_contract']:
            from .shared_declared_irq import submit_declared_irq
            return submit_declared_irq(runtime, raw, mapping, declaration)
        from .shared_f5_slots import submit_pin
        return submit_pin(runtime,raw,mapping,declaration)
    from .shared_f6_slots import execute_fragment,seal_case
    from .compiled_f4 import _borrow_exact_events,_cpu_traces,_cpu_error_policy
    flow = mapping['flow']
    row, = [row for row in runtime.compiled_inputs['compiled']['paths'] if row['flow_id']==flow and row['status']=='executable']
    image = next(source for source in row['sources'] if source['kind']=='instruction_image')
    # Passive CPU traces are common to memory and MMIO paths. Their existing
    # resolver uses the stream's register access only to select the data port.
    data_endpoint = runtime.contract['cpu']['data_endpoint_id']
    stream = next((source for source in row['sources'] if source['kind']=='cpu_load_stream'),
        dict(register_access=dict(source_endpoint=data_endpoint)))
    traces = _cpu_traces(runtime.cpu.artifact,image,stream)
    error_policy = _cpu_error_policy(runtime.cpu.artifact,image,stream)
    before = None
    bus_only = runtime.contract['program_contract']['shared_slots'].get('observation_mode') == 'bus'
    if flow == 'F2' and not bus_only:
        from .compiled_f2_consumer import capture_f2_read_version
        register = row['execution_contract']['register']
        target_id = row['execution_contract']['target_component']
        authority = runtime.assembly.companion_authorities[target_id]
        before = capture_f2_read_version(authority,register=register,reset_epoch=authority.target.reset_epoch)
    receipt,address,action,boundary = execute_fragment(runtime,mapping,declaration)
    # Borrowed journal refs for the synchronous readers below: no record is
    # mutated or retained here, and each consumer detaches the values it keeps
    # (``_consume_f2``/``_consume_memory`` deep-copy the derived hop documents
    # before they are sealed or returned).
    events = _borrow_exact_events(runtime.runner)
    if flow == 'F2' and bus_only:
        certificate = _consume_f2_mmio(runtime,mapping,declaration,receipt,image,stream,traces,error_policy,
            events,address,action)
    elif flow == 'F2':
        certificate = _consume_f2(runtime,mapping,declaration,receipt,image,stream,traces,error_policy,
            authority,before,register,events,address,action)
    else:
        certificate = _consume_memory(runtime,mapping,declaration,receipt,image,traces,error_policy,
            events,address,action,raw)
    certificate.update(status='certified',case_id=mapping['case_id'],
        runtime_path_id=runtime.runtime_path_admission['shared_flow_paths'][flow]['path_id'],
        execution_binding_sha256=runtime.execution_binding_sha256,next_fetch=boundary)
    seal_case(runtime,mapping['case_id'],certificate,boundary)
    runtime._drain_observer_view()
    return deepcopy(certificate)


def _consume_f2_mmio(runtime,mapping,declaration,receipt,image,stream,traces,error_policy,events,address,action):
    from .compiled_mmio import observe_mmio_bus
    from .compiled_f2 import _f2_edges
    from .native_obi_hops import check_f2_exact_hops
    target_id = stream['register_access']['target_component']
    observed = observe_mmio_bus(declaration,receipt,target_artifact=runtime.artifacts[target_id],flow='F2')
    union = dict(runtime.compiled_inputs['compiled'],
        runtime_dependency_graph=runtime.runtime_path_admission['runtime_graph'],
        runtime_path_contract=runtime.runtime_path_admission['runtime_contract'])
    snapshots = [runtime.memory.read(address+offset,4,transaction_id=action+':check:'+str(offset))
                 for offset in range(0,32,4)]
    result = runtime.memory.read(declaration['result_address'],4,transaction_id=action+':result')
    exact = check_f2_exact_hops(events=events,declaration=declaration,image=image,stream=stream,
        traces=traces,address=address,source_event_id=action,joins=observed['joins'],
        declared_edges=_f2_edges(union,image,stream['register_access']),instruction_snapshots=snapshots,
        ram_event_id=observed['RAM_event'],error_policy=error_policy,result_snapshot=result,
        proof_scope='shared_CPU_APB_transport_no_internal_version')
    return dict(schema_version='compiled_F2_shared_mmio_chain.v1',flow_id='F2',
        address=declaration['address'],result_address=declaration['result_address'],
        observation=deepcopy(observed),exact_hops=deepcopy(exact),runtime_admitted=True,
        internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)


def _consume_f2(runtime,mapping,declaration,receipt,image,stream,traces,error_policy,
        authority,before,register,events,address,action):
    from .compiled_f2_consumer import check_f2_read_observation
    from .compiled_f2 import _f2_edges
    from .compiled_f2_consumer import stable_f2_read_version as stable_storage_version
    from .native_obi_hops import check_f2_exact_hops
    pre = before.document()
    token = authority.issue(register=register,reset_epoch=pre['reset_epoch'])
    observed,after = check_f2_read_observation(declaration,receipt,target_artifact=authority.target.artifact,
        authority=authority,token=token,before=before,register=register,
        reset_epoch=pre['reset_epoch'],prior_writes=pre['write_count'])
    union = dict(runtime.compiled_inputs['compiled'],
        runtime_dependency_graph=runtime.runtime_path_admission['runtime_graph'],
        runtime_path_contract=runtime.runtime_path_admission['runtime_contract'])
    snapshots = [runtime.memory.read(address+offset,4,transaction_id=action+':check:'+str(offset))
        for offset in range(0,32,4)]
    result = runtime.memory.read(declaration['result_address'],4,transaction_id=action+':result')
    exact = check_f2_exact_hops(events=events,declaration=declaration,image=image,stream=stream,
        traces=traces,address=address,source_event_id=action,joins=observed['joins'],
        declared_edges=_f2_edges(union,image,stream['register_access']),instruction_snapshots=snapshots,
        ram_event_id=observed['RAM_event'],error_policy=error_policy,result_snapshot=result,
        proof_scope='typed_F2_read_in_shared_CPU_RAM_DMA_session')
    from .shared_f6_slots import flow_records
    relation = _shared_apb_version_consumption(flow_records(runtime), before=pre,
        reader_case_id=mapping['case_id'], device_id=stream['register_access']['device_id'],
        read_event=observed['joins'][0]['native_APB_event'])
    if not hasattr(runtime,'shared_read_raw'):
        runtime.shared_read_raw = {}
    runtime.shared_read_raw[mapping['case_id']] = dict(before=pre,observation=deepcopy(observed))
    return dict(schema_version='compiled_F2_shared_slot_chain.v1',flow_id='F2',
        address=declaration['address'],result_address=declaration['result_address'],
        prerequisite=stable_storage_version(pre),postcondition=stable_storage_version(after),
        observation={key:(stable_storage_version(value) if key in ('version_witness','version_before')
            else deepcopy(value)) for key,value in observed.items()},
        exact_hops=deepcopy(exact), runtime_admitted=True,
        current_version_consumption=relation)


def _consume_memory(runtime,mapping,declaration,receipt,image,traces,error_policy,events,address,action,raw):
    from myfuzz.runtime.flows.memory import _observe_f3_write,observe_ram_read_documentary,observe_ram_read_physical
    from myfuzz.scenario.memory_dependency_evidence import MemoryDependencyEvidenceConsumer
    from .native_obi_hops import collect_native_obi_beats,verify_instruction_fetches
    sources = [event for event in events if event.get('kind')=='instruction_source'
        and event.get('component')==runtime.cpu_id and event.get('source_event_id')==action]
    if len(sources)!=1:
        raise ValueError('shared-memory-original-source-required')
    source = sources[0]
    scope = dict(execution_id='local-execution',testcase_id=runtime.session.template.testcase_id,
        source_component=runtime.cpu_id,source_epoch=runtime.cpu.reset_epoch)
    snapshots = [runtime.memory.read(address+offset,4,transaction_id=action+':check:'+str(offset))
        for offset in range(0,declaration['functional_bytes'],4)]
    hops = verify_instruction_fetches(events=events,cpu=runtime.cpu_id,address=address,
        code=bytes.fromhex(declaration['code_hex']),source_event_id=action,source=source,
        route_transaction=scope,instruction_snapshots=snapshots,
        completed=collect_native_obi_beats(events,cpu=runtime.cpu_id,traces=traces,error_policy=error_policy),
        image=image,functional_offsets=tuple(range(0,declaration['functional_bytes'],4)),error_prefix='shared-memory')
    common = dict(events=events,receipt=receipt,cpu=runtime.cpu_id,address=declaration['ram_address'],
        memory_id=image['port'],memory_base=image['range'][0],memory_generation=runtime.memory.generation,
        traces=traces,error_policy=error_policy)
    write = read = physical_read = None
    if mapping['flow']=='F3':
        write = _observe_f3_write(**common,value=int.from_bytes(raw,'little'),transaction_scope=scope)
        if write is None:
            raise ValueError('shared-memory-actual-store-unavailable')
    elif declaration['operation']=='ram_read_word':
        provider = runtime.runner._memory_dependency_consumer
        if type(provider) is not MemoryDependencyEvidenceConsumer:
            raise ValueError('shared-memory-live-dependency-provider-required')
        read = observe_ram_read_documentary(**common,report=MemoryDependencyEvidenceConsumer.report(provider))
        if read is None:
            physical_read = observe_ram_read_physical(**common, transaction_scope=scope,
                cpu_adapter=getattr(runtime, 'cpu_adapter', None))
    retirement = {'status': 'unknown', 'reward_eligible': False}
    if mapping['flow'] == 'F1' and declaration['operation'] == 'instruction' and bytes.fromhex(declaration['code_hex'])[:4] == raw:
        from myfuzz.isa.f1_retirement import observe_f1_retirement, observe_f1_word_retirements
        args = dict(cpu=runtime.cpu_id, execution_id=scope['execution_id'],
            epoch=scope['source_epoch'], address=address,
            source_event_id=max(source['event_id'], hops[0]['response_event']))
        retirement = (observe_f1_word_retirements(events, raw=raw, **args)
                      if raw[0] & 3 != 3 else
                      observe_f1_retirement(events, word=int.from_bytes(raw,'little'), **args))
    result = dict(schema_version='compiled_memory_shared_slot.v1',flow_id=mapping['flow'],
        operation=declaration['operation'],ram_address=declaration['ram_address'],
        instruction_address=address,instruction_hops=deepcopy(hops),retirement=retirement['status'],
        instruction_to_store_causality='unknown',memory_store_observation=deepcopy(write),
        memory_read_observation=deepcopy(read),memory_read='observed' if read or physical_read else 'unknown',
        proof_scope='native_instruction_consumption_and_documentary_host_RAM_versions')
    if physical_read is not None:
        result['memory_read_physical_observation'] = physical_read
    if mapping['flow'] == 'F1' and declaration['operation'] == 'instruction':
        result['retirement_observation'] = retirement
    return result
