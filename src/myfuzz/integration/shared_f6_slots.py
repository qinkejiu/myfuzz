"""Typed online storage/DMA slot declarations and shared writer envelopes."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import sys
from weakref import WeakKeyDictionary, ref

_RUNTIMES = WeakKeyDictionary()
_CPU_OWNERS = WeakKeyDictionary()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def require(condition, reason):
    if not condition:
        raise ValueError('shared-F4-F6-'+reason)


def compile_shared_slots(request, declaration, *, slot_count, base_dir):
    from .f6_storage_support import compile_storage_support
    require(type(declaration) is dict and {'component','contract_id','register','results_base'} <= set(declaration)
        and not set(declaration)-{'component','contract_id','register','read_register','observation_mode','results_base','flows','scratch_address'}, 'declaration')
    flows = declaration.get('flows', ['F4','F6'])
    require(type(flows) is list and len(set(flows))==len(flows) and {'F4','F6'} <= set(flows)
        and not set(flows)-{'F1','F2','F3','F4','F5','F6'}, 'flow-capabilities')
    if 'F5' in flows:
        require('F1' in flows and bool({'gpio_irq', 'declared_irq'} & set(request.document['f6_execution'])),
            'F5-typed-IRQ-and-memory-required')
    require(type(declaration['results_base']) is int, 'result-base')
    from .f6_gpio_companion import CONTRACT_ID as GPIO_CONTRACT_ID
    if declaration.get('observation_mode') == 'bus':
        from .shared_mmio_companion import shared_mmio_source
        require(declaration['contract_id'] == 'apb3.mmio.bus.v1'
            and declaration.get('read_register') == declaration['register'], 'bus-observation-selection')
        source = shared_mmio_source(request, declaration)
        proof = dict(source_contract_digest=source['digest'])
    elif declaration['contract_id'] == GPIO_CONTRACT_ID:
        from .f6_gpio_companion import select_gpio_companion_source
        source = select_gpio_companion_source(request.component(declaration['component']).profile,
            base_dir=base_dir,selection={key:declaration[key] for key in ('contract_id','register')})
        proof = dict(source_contract_digest=source['digest'])
    else:
        proof = compile_storage_support(request, dict(
            **{key: declaration[key] for key in ('component', 'contract_id', 'register')},
            before_value=0, after_value=0, before_result_address=declaration['results_base'],
            after_result_address=declaration['results_base']+4), base_dir=base_dir)
    result = dict(deepcopy(declaration), schema_version='shared_F4_F6_slots.v1',
        slot_count=slot_count, result_stride=4, enabled_flows=list(flows),
        ownership='typed_online_writer', source_contract_digest=proof['source_contract_digest'])
    if set(flows) & {'F1','F3'}:
        result['scratch_address'] = declaration.get('scratch_address', declaration['results_base']-4)
        require(type(result['scratch_address']) is int and result['scratch_address'] % 4 == 0, 'scratch-address')
    return result


def extend_runtime_paths(graph, contract, compiled):
    """Backward-compatible single-storage view of the common union builder."""
    from .shared_slot_paths import build_shared_flow_paths
    graph, contract, paths, mapping = build_shared_flow_paths(graph, contract, compiled, ('F4',))
    return graph, contract, paths[0][1], mapping['F4']


def declare_shared_writer(compiled_inputs, layout, *, raw, slot_index):
    from .compiled_candidate_layout import compile_candidate_layout
    from .generated_register_writer import declare_writer
    from .rv32_fixed_firmware import _addi
    row, = [row for row in compiled_inputs['compiled']['paths'] if row['flow_id'] == 'F4' and row['status'] == 'executable']
    source = next(source for source in row['sources'] if source['kind'] == 'cpu_mmio_stream')
    require(source['register_access']['target_component'] == layout['component']
        and source['register_access']['register'] == layout['register'], 'writer-owner')
    values = compile_candidate_layout(row).decode(raw)
    result = layout['results_base'] + layout['result_stride']*slot_index
    declaration = declare_writer(compiled_inputs['request'], compiled_inputs['compiled'],
        source_id=source['source_id'], value=values[source['source_id']], result_address=result)
    code = bytes.fromhex(declaration['code_hex'])
    require(len(code) == 48, 'writer-ABI')
    footer = b''.join(word.to_bytes(4, 'little') for word in (_addi(10, 0, 1), _addi(11, 0, 1)))
    envelope = code + footer + bytes.fromhex('13000000')*((128-len(code)-len(footer))//4)
    return dict(declaration, canonical_writer_code_hex=code.hex(),
        code_hex=envelope.hex(), code_sha256=sha256(envelope).hexdigest(),
        scope='typed_online_writer_in_shared_slot')


def install_slot_ledger(runtime):
    from .compiled_f6 import CompiledF6Runtime
    frame = sys._getframe(1)
    require(type(runtime) is CompiledF6Runtime and runtime not in _RUNTIMES
        and frame.f_code is CompiledF6Runtime.__init__.__wrapped__.__code__
        and frame.f_locals.get('self') is runtime, 'original-installation')
    _RUNTIMES[runtime] = dict(cpu=runtime.cpu, runner=runtime.runner, memory=runtime.memory,
        session=runtime.session, scope=None, rows=[], pins=tuple(
            (name, getattr(CompiledF6Runtime, name), getattr(CompiledF6Runtime, name).__code__)
            for name in ('submit', '_execute_case')))
    _CPU_OWNERS[runtime.cpu] = ref(runtime)


def _check_helpers():
    if any(globals().get(name) is not function or function.__code__ is not code
            for name, function, code in _HELPER_PINS):
        raise ValueError('shared-F4-F6-slot-helper-drift')


def _state(runtime, *, mutate=False):
    _check_helpers()
    state = _RUNTIMES.get(runtime)
    require(state is not None and state['cpu'] is runtime.cpu and state['runner'] is runtime.runner
        and state['memory'] is runtime.memory and state['session'] is runtime.session, 'live-slot-owner')
    for name, method, code in state['pins']:
        require(getattr(type(runtime), name) is method and method.__code__ is code
            and name not in vars(runtime), 'slot-method-owner')
    if mutate:
        frame = sys._getframe(1)
        found = False
        for _ in range(8):
            if frame is None:
                break
            if frame.f_locals.get('self') is runtime and any(frame.f_code is code for _, _, code in state['pins']):
                found = True
                break
            frame = frame.f_back
        require(found, 'original-slot-dispatch-required')
        cpu = runtime.cpu
        scope = (cpu._execution, cpu._case_id, cpu.reset_epoch, cpu.process)
        require(cpu.process is not None and cpu.process.poll() is None, 'live-CPU-required')
        if state['scope'] is None:
            state['scope'] = scope
        require(state['scope'] == scope, 'CPU-scope-drift')
    return state


def rebind_slot_scope(runtime, *, barrier_event_id, next_slot):
    """Keep sealed slots and bind their next entry to the measured new epoch."""
    from .compiled_f6 import CompiledF6Runtime
    frame = sys._getframe(1)
    require(frame.f_locals.get('self') is runtime
        and frame.f_code is CompiledF6Runtime.rebind_reset_epoch.__code__,
        'declared-reset-rebind-required')
    state = _state(runtime)
    prior = state['scope']
    binding = runtime._epoch_launch
    barrier = runtime.runner._event_ref_by_id(barrier_event_id)
    cpu = state['cpu']
    require(prior is not None and len(state['rows']) == next_slot
        and all(row['status'] == 'passed' for row in state['rows'])
        and type(binding) is dict and binding.get('barrier_event_id') == barrier_event_id
        and binding.get('reset_epoch') == cpu.reset_epoch
        and type(barrier) is dict and barrier.get('kind') == 'reset_barrier'
        and cpu.reset_epoch == prior[2] + 1 and cpu.process is not prior[3]
        and cpu._execution != prior[0] and cpu._case_id == prior[1]
        and cpu.process is not None and cpu.process.poll() is None,
        'measured-reset-required')
    state['scope'] = (cpu._execution, cpu._case_id, cpu.reset_epoch, cpu.process)


def next_slot_index(runtime):
    """Read the authenticated physical cursor without reserving an input."""
    state = _state(runtime,mutate=True)
    require(not state['rows'] or state['rows'][-1]['status']=='passed','next-slot')
    index = len(state['rows'])
    require(index < runtime.contract['program_contract']['slot_count'],'slot-budget')
    return index


def reserve_case(runtime, flow, raw):
    state = _state(runtime, mutate=True)
    require(flow in runtime.contract['program_contract']['shared_slots']['enabled_flows'] and type(raw) is bytes
        and (not state['rows'] or state['rows'][-1]['status'] == 'passed'), 'next-slot')
    slot = len(state['rows'])
    require(slot < runtime.contract['program_contract']['slot_count'], 'slot-budget')
    from .shared_slot_auxiliary import auxiliary_sources,expected_auxiliary_rows
    first_index = len(runtime.session._cases)
    prior = state['rows'][-1]['session_case_index']+1 if state['rows'] else 0
    require(first_index==prior, 'session-slot-order')
    auxiliary_count = len(auxiliary_sources(runtime.compiled_inputs['compiled'],runtime.runtime_path_admission,
        flow=flow,raw=raw))
    global_index = first_index+auxiliary_count
    logical = len(runtime.attempts) if flow == 'F6' else None
    case_id = (runtime.run_id+':case:'+str(logical) if flow == 'F6'
        else runtime.run_id+':'+flow+':'+str(global_index))
    row = dict(flow=flow, raw_hex=raw.hex(), slot_index=slot,
        session_case_index=global_index, f6_case_index=logical, case_id=case_id, status='reserved')
    if auxiliary_count:
        row['auxiliary_sources'] = expected_auxiliary_rows(runtime.compiled_inputs['compiled'],runtime.runtime_path_admission,
            flow=flow,raw=raw,case_id=case_id,first_session_index=first_index)
    state['rows'].append(row)
    return deepcopy(row)


def case_mapping(runtime, case_id):
    rows = [row for row in _state(runtime)['rows'] if row['case_id'] == case_id]
    require(len(rows) == 1, 'case-mapping')
    return deepcopy({key: value for key, value in rows[0].items() if not key.startswith('_')})


def f6_mapping(runtime, logical_index):
    rows = [row for row in _state(runtime)['rows']
        if row['flow'] == 'F6' and row['f6_case_index'] == logical_index]
    require(len(rows) == 1, 'F6-mapping')
    return case_mapping(runtime, rows[0]['case_id'])


def f6_slot(runtime, attempt):
    if 'shared_slots' not in runtime.contract['program_contract']:
        return attempt['case_index']
    row = f6_mapping(runtime, attempt['case_index'])
    require(row['case_id'] == attempt['case_id'] and row['raw_hex'] == attempt['raw8_hex']
        and row['slot_index'] == attempt['slot_index']
        and row['session_case_index'] == attempt['session_case_index'], 'F6-attempt-mapping')
    return row['slot_index']


def f6_slot_for_cpu(cpu, logical_index, case_id):
    owner = _CPU_OWNERS.get(cpu)
    require(owner is not None and owner() is not None, 'CPU-slot-owner')
    row = f6_mapping(owner(), logical_index)
    require(row['case_id'] == case_id, 'ISR-case-mapping')
    return row['slot_index']


def instruction_case_mapping(runtime, scenario, case, session_index):
    _check_helpers()
    state = _state(runtime)
    row = case_mapping(runtime, case.case_id)
    require(scenario is state['session'] and row['session_case_index'] == session_index
        and scenario._cases[session_index] is case, 'source-session-mapping')
    selected = runtime.runtime_path_admission['shared_flow_paths'][row['flow']]
    path, source_id = selected['path_id'],selected['source_id']
    require(case.path_id == path and case.source.source_id == source_id
        and case.source.address == runtime.contract['program_contract']['slot_base']+256*row['slot_index'],
        'typed-path-source-mapping')
    if row['flow'] != 'F6':
        from .shared_slot_consumers import declare_slot
        declaration = declare_slot(runtime.compiled_inputs,
            runtime.contract['program_contract']['shared_slots'],runtime.runtime_path_admission,
            flow=row['flow'],raw=bytes.fromhex(row['raw_hex']),slot_index=row['slot_index'],
            instruction_isa=getattr(runtime.memory, 'instruction_isa', None))
        require(case.source.data.hex() == declaration['code_hex'], 'typed-fragment-code')
    else:
        candidate = runtime.layout.decode(bytes.fromhex(row['raw_hex']))
        require(case.source.data == runtime.program.prefix(candidate, case_index=row['f6_case_index']),
            'typed-F6-code')
    return row


def seal_case(runtime, case_id, certificate, boundary):
    state = _state(runtime, mutate=True)
    row = state['rows'][-1]
    require(row['case_id'] == case_id and row['status'] == 'reserved'
        and runtime.session._cases[row['session_case_index']].case_id == case_id, 'case-seal-order')
    row.update(status='passed', certificate=deepcopy(certificate), _boundary=deepcopy(boundary))
    row['_material'] = _canonical({key: value for key, value in row.items() if key != '_material'})


def flow_records(runtime):
    state = _state(runtime)
    for row in state['rows']:
        if row['status'] == 'passed':
            require(row['_material'] == _canonical({key: value for key, value in row.items() if key != '_material'}),
                'sealed-record-drift')
    return [deepcopy({key: value for key, value in row.items() if not key.startswith('_')})
        for row in state['rows']]


def current_boundary_after(runtime, attempt, historical):
    state = _state(runtime)
    prior = f6_mapping(runtime, attempt['case_index'])
    row = state['rows'][prior['slot_index']]
    require(row['status'] == 'passed' and row['_boundary'] == historical, 'historical-F6-boundary')
    boundary = historical
    for intervening in state['rows'][prior['slot_index']+1:]:
        if intervening['status'] == 'reserved':
            break
        require(intervening['flow'] in runtime.contract['program_contract']['shared_slots']['enabled_flows']
            and intervening['flow'] != 'F6' and intervening['status'] == 'passed', 'intervening-flow')
        boundary = intervening['_boundary']
    flow_records(runtime)
    return deepcopy(boundary)


def submit_writer(runtime, raw, mapping):
    from .generated_storage_consumer import check_storage_observation, stable_storage_version
    from .compiled_f4 import check_f4_exact_hops, _f4_edges, _cpu_traces, _cpu_error_policy
    from .compiled_f4 import _borrow_exact_events
    layout = runtime.contract['program_contract']['shared_slots']
    declaration = declare_shared_writer(runtime.compiled_inputs, layout,
        raw=raw, slot_index=mapping['slot_index'])
    auxiliary_evidence = submit_auxiliary_sources(runtime,mapping)
    if layout.get('observation_mode') == 'bus':
        from .compiled_mmio import observe_mmio_bus
        receipt,address,action,boundary = execute_fragment(runtime,mapping,declaration)
        observed = observe_mmio_bus(declaration,receipt,
            target_artifact=runtime.artifacts[layout['component']],flow='F4')
        compiled = runtime.compiled_inputs['compiled']
        logical = next(row for row in compiled['paths'] if row['flow_id'] == 'F4')
        image = next(source for source in logical['sources'] if source['kind'] == 'instruction_image')
        stream = next(source for source in logical['sources'] if source['kind'] == 'cpu_mmio_stream')
        union = dict(compiled, runtime_dependency_graph=runtime.runtime_path_admission['runtime_graph'],
            runtime_path_contract=runtime.session.runtime_contract.document())
        snapshots = [runtime.memory.read(address+offset,4,transaction_id=action+':check:'+str(offset))
                     for offset in range(0,32,4)]
        exact = check_f4_exact_hops(events=_borrow_exact_events(runtime.runner),declaration=declaration,
            image=image,stream=stream,traces=_cpu_traces(runtime.cpu.artifact,image,stream),
            address=address,source_event_id=action,joins=observed['joins'],
            declared_edges=_f4_edges(union,image,stream['register_access']),instruction_snapshots=snapshots,
            ram_event_id=observed['RAM_event'],error_policy=_cpu_error_policy(runtime.cpu.artifact,image,stream),
            readback_value=observed['read_value'],proof_scope='shared_CPU_APB_transport_no_internal_version')
        certificate = dict(schema_version='compiled_F4_shared_mmio_chain.v1',status='certified',
            case_id=mapping['case_id'],value=declaration['candidate']['value'],
            instruction_address=address,instruction_sha256=declaration['code_sha256'],
            runtime_path_id=runtime.runtime_path_admission['shared_flow_paths']['F4']['path_id'],
            execution_binding_sha256=runtime.execution_binding_sha256,joins=observed['joins'],
            exact_hops=deepcopy(exact),next_fetch=boundary,read_value=observed['read_value'],
            internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)
        if auxiliary_evidence:certificate['auxiliary_sources']=auxiliary_evidence
        seal_case(runtime,mapping['case_id'],certificate,boundary)
        runtime._drain_observer_view()
        return deepcopy(certificate)
    authority = runtime.assembly.companion_authorities[layout['component']]
    target = authority.target
    before = authority.consume(authority.issue(register=layout['register'], reset_epoch=target.reset_epoch))
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    gpio = type(authority) is GpioRegisterVersionAuthority
    history = authority.writes() if gpio else None
    receipt,address,action,boundary = execute_fragment(runtime,mapping,declaration)
    if gpio:
        from .gpio_write_consumer import check_gpio_write_observation
        observed,commit,raw_after = check_gpio_write_observation(declaration,receipt,
            target_artifact=target.artifact,authority=authority,access=declaration['candidate']['access'],
            target_component=layout['component'],register=layout['register'],reset_epoch=target.reset_epoch,
            before=before,prior_writes=len(history))
        from .gpio_f2_consumer import gpio_version_document,stable_gpio_read_version
        prerequisite = stable_gpio_read_version(gpio_version_document(before,history))
        after = stable_gpio_read_version(gpio_version_document(raw_after,authority.writes()))
    else:
        token = authority.issue(register=layout['register'], reset_epoch=target.reset_epoch)
        observed, commit, after = check_storage_observation(declaration, receipt,
            target_artifact=target.artifact, authority=authority, token=token,
            register=layout['register'], reset_epoch=target.reset_epoch,
            before=before, prior_writes=before['write_count'])
        prerequisite = stable_storage_version(before)
    compiled = runtime.compiled_inputs['compiled']
    logical = next(row for row in compiled['paths'] if row['flow_id'] == 'F4')
    image = next(source for source in logical['sources'] if source['kind'] == 'instruction_image')
    stream = next(source for source in logical['sources'] if source['kind'] == 'cpu_mmio_stream')
    union = dict(compiled, runtime_dependency_graph=runtime.runtime_path_admission['runtime_graph'],
        runtime_path_contract=runtime.session.runtime_contract.document())
    snapshots = [runtime.memory.read(address+offset, 4, transaction_id=action+':check:'+str(offset))
        for offset in range(0, 32, 4)]
    # Borrowed journal refs for the synchronous reader below: no record is
    # mutated or retained here, and the derived hop document is detached before
    # it is sealed into the certificate.
    exact = check_f4_exact_hops(events=_borrow_exact_events(runtime.runner), declaration=declaration,
        image=image, stream=stream, traces=_cpu_traces(runtime.cpu.artifact, image, stream),
        address=address, source_event_id=action, joins=observed['joins'],
        declared_edges=_f4_edges(union, image, stream['register_access']),
        instruction_snapshots=snapshots, ram_event_id=observed['RAM_event'],
        error_policy=_cpu_error_policy(runtime.cpu.artifact, image, stream),
        proof_scope='typed_online_F4_in_shared_CPU_storage_DMA_session')
    certificate = dict(schema_version='compiled_F4_shared_slot_chain.v1', status='certified',
        case_id=mapping['case_id'], value=declaration['candidate']['value'],
        instruction_address=address, instruction_sha256=declaration['code_sha256'],
        runtime_path_id=runtime.runtime_path_admission['shared_flow_paths']['F4']['path_id'], execution_binding_sha256=runtime.execution_binding_sha256,
        prerequisite=prerequisite, commit=commit, postcondition=after,
        joins=observed['joins'], exact_hops=deepcopy(exact), next_fetch=boundary,
        native_samples=deepcopy(observed.get('native_samples',{})),
        storage_probes=deepcopy(observed.get('storage_probes',{})))
    if auxiliary_evidence:
        certificate['auxiliary_sources'] = auxiliary_evidence
    seal_case(runtime, mapping['case_id'], certificate, boundary)
    if not hasattr(runtime, 'shared_storage_raw'):
        runtime.shared_storage_raw = {}
    runtime.shared_storage_raw[mapping['case_id']] = dict(
        before=deepcopy(before), observation=deepcopy(observed))
    runtime._drain_observer_view()
    return deepcopy(certificate)


def auxiliary_case(runtime,case_id):
    for row in _state(runtime)['rows']:
        for auxiliary in row.get('auxiliary_sources',[]):
            if auxiliary['case_id']==case_id:
                return deepcopy(auxiliary)
    return None


def session_case_ids(runtime,*,admitted_only=False):
    rows = flow_records(runtime)
    result = []
    for row in rows:
        result.extend(auxiliary['case_id'] for auxiliary in row.get('auxiliary_sources',[]))
        result.append(row['case_id'])
    if not admitted_only:
        return result
    actual = [case.case_id for case in runtime.session._cases]
    require(actual==result[:len(actual)],'admitted-session-prefix')
    if len(actual) < len(result):
        last_size = 1+len(rows[-1].get('auxiliary_sources',[]))
        require(rows[-1]['status']=='reserved' and all(row['status']=='passed' for row in rows[:-1])
            and len(actual)>=len(result)-last_size,'only-current-reservation-may-be-unadmitted')
    return actual


def submit_auxiliary_sources(runtime,mapping):
    from myfuzz.scenario.session_runtime import OnlineCase
    from myfuzz.scenario.batch import BatchSourceEvent,BatchAdvance
    from .shared_slot_auxiliary import source_value
    _state(runtime,mutate=True)
    evidence = []
    for row in mapping.get('auxiliary_sources',[]):
        require(len(runtime.session._cases)==row['session_case_index'], 'auxiliary-session-index')
        case = OnlineCase(row['case_id'],row['direction'],row['path_id'],BatchSourceEvent(**source_value(row)),
            (BatchAdvance((row['component'],)),))
        receipt = runtime.session.submit_case(case)
        require(not receipt.violations and receipt.status=='running'
            and receipt.local_ticks_before[runtime.cpu_id]==receipt.local_ticks_after[runtime.cpu_id],
            'auxiliary-native-input-or-CPU-advance')
        steps = [event for event in receipt.events if event.get('component')==row['component']
            and type(event.get('inputs')) is dict and type(event.get('outputs')) is dict and 'kind' not in event]
        require(len(steps)==1 and type(steps[0]['inputs'].get(row['port'])) is int
            and (steps[0]['inputs'][row['port']] >> row['bit_offset']) & ((1 << row['width'])-1)==row['value'],
            'auxiliary-actual-pin-input')
        evidence.append(dict(row,native_step_event_id=steps[0]['event_id'],CPU_advanced=False,
            proof_scope='typed_auxiliary_source_actual_target_step_not_F5_credit'))
    require(len(runtime.session._cases)==mapping['session_case_index'], 'main-session-index')
    return evidence


def execute_fragment(runtime,mapping,declaration):
    """Run one typed prefix on the existing CPU and common session schedule."""
    from myfuzz.scenario.session_runtime import OnlineCase,BoundOnlineInstruction
    from .compiled_f6 import _f6_runtime_case_advances
    selected = runtime.runtime_path_admission['shared_flow_paths'][mapping['flow']]
    p = runtime.contract['program_contract']
    address = p['slot_base']+256*mapping['slot_index']
    action = mapping['case_id']+(':writer' if mapping['flow']=='F4' else ':source')
    case = OnlineCase(mapping['case_id'],'CPU_TO_IP',selected['path_id'],
        BoundOnlineInstruction(action,runtime.cpu_id,address,declaration['code_hex'],selected['source_id']),
        _f6_runtime_case_advances(runtime))
    next_slot = mapping['slot_index']+1
    expected = p['slot_base']+256*next_slot if next_slot < p['slot_count'] else p['park_address']
    receipt = runtime.session.submit_case(case,
        stop_after_advance=lambda _index: runtime.cpu.waiting_instruction_address==expected,
        stop_on_runner_failure=True)
    require(not receipt.violations and receipt.status=='running'
        and runtime.cpu.waiting_instruction_address==expected, 'fragment-native-boundary')
    request = runtime.cpu._request_evidence['instr']
    require(runtime.cpu._waiting_instr is not None and runtime.cpu.pending_responses==1
        and not runtime.cpu._queued_mmio and runtime.cpu._pending_data is None
        and request['address']==expected, 'fragment-quiescent-fetch')
    boundary = dict(kind='native_fetch_boundary',address=expected,
        execution=runtime.cpu._execution,native_testcase_id=runtime.cpu._case_id,
        reset_epoch=runtime.cpu.reset_epoch,transaction=runtime._jsonable(request['transaction']),
        local_tick=request['acceptance_tick'])
    return receipt,address,action,boundary


def fixed_support_case_mapping(runtime,scenario,case,session_index,support):
    """Resolve a real F5 pin case and its separately declared memory support."""
    from .shared_f5_slots import declare_shared_pin
    from myfuzz.scenario.batch import BatchSourceEvent
    from myfuzz.scenario.session_runtime import OnlineInstruction
    state = _state(runtime)
    row = case_mapping(runtime,case.case_id)
    require(row['flow']=='F5' and scenario is state['session']
        and row['session_case_index']==session_index and scenario._cases[session_index] is case,
        'fixed-support-case-mapping')
    declaration = declare_shared_pin(runtime.compiled_inputs,runtime.contract['program_contract']['shared_slots'],
        runtime.runtime_path_admission,raw=bytes.fromhex(row['raw_hex']),slot_index=row['slot_index'])
    source = case.source
    require(type(source) is BatchSourceEvent and type(support) is OnlineInstruction
        and len(case.support_instructions)==1 and case.support_instructions[0] is support
        and case.path_id==declaration['path_id'] and case.direction==declaration['direction']
        and all(getattr(source,key)==declaration[key] for key in ('component','port','bit_offset','width','value'))
        and support.component==runtime.cpu_id and support.address==declaration['instruction_address']
        and support.data.hex()==declaration['code_hex'], 'typed-fixed-support-fields')
    return dict({key:row[key] for key in ('flow','raw_hex','slot_index','session_case_index','f6_case_index','case_id')},
        declaration=declaration)


def projection_context(runtime, attempt):
    """Pass archived declarations only after authenticating the live mapping."""
    if 'shared_slots' not in runtime.contract['program_contract']:
        return None
    f6_slot(runtime, attempt)
    from .compiled_f6 import _f6_expected_online_plan
    return dict(online_plan=_f6_expected_online_plan(runtime),
        flow_records=flow_records(runtime), binding=deepcopy(runtime.execution_binding))


_HELPER_PINS = tuple((name, function, function.__code__)
    for name, function in tuple(globals().items())
    if callable(function) and getattr(function, '__module__', None) == __name__)
