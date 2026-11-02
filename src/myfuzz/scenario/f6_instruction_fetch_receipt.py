"""Original generated OBI fetch completion, with no decode/retirement grant.

The registry owns live objects. JSON records can describe an issuance but cannot
create one. The native-memory backend's observer/issuer is deliberately separate.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
import sys
from weakref import WeakKeyDictionary, ref

from .ledger import TransactionKey
from .memory import InstructionAcceptance, PersistentMemory, ReadSnapshot
from .memory_service import (MemoryService, _ARM_ISSUED_READ, _LOOKUP_ISSUED_READ,
    _VALIDATE_ISSUED_READ, _REVOKE_ISSUED_READ)


_FETCH_SCAN_MODE = ContextVar('f6_instruction_fetch_scan_mode', default='snapshot')


@contextmanager
def f6_instruction_fetch_scan_scope(mode):
    """Compare the same strict proof with one prefix read or legacy rescans."""
    if mode not in ('snapshot', 'legacy'):
        raise ValueError('F6 instruction fetch scan mode must be snapshot or legacy')
    token = _FETCH_SCAN_MODE.set(mode)
    try:
        yield
    finally:
        _FETCH_SCAN_MODE.reset(token)


_F6_ACCEPTANCE_ANCHOR_SCHEMA = 'compiled_F6_instruction_acceptance_anchor.v1'
_F6_ACCEPTANCE_ANCHOR_FIELDS = frozenset({
    'schema_version', 'memory_id', 'address', 'byte_offset', 'generation',
    'data_hex', 'source_event_id', 'versions', 'writer_event_ids', 'writer_kinds'})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=False,
        default=lambda value: {'bytes_hex': value.hex()} if type(value) is bytes else asdict(value))


def _f6_instruction_acceptance_anchor(acceptance):
    """Serialize the issued source acceptance as an independent service root."""
    if type(acceptance) is not InstructionAcceptance:
        raise ValueError('F6 instruction fetch acceptance anchor requires original acceptance')
    document = asdict(acceptance)
    document['data_hex'] = document.pop('data').hex()
    document['versions'] = [list(version) for version in document['versions']]
    document['writer_event_ids'] = list(document['writer_event_ids'])
    document['writer_kinds'] = list(document['writer_kinds'])
    anchor = dict(schema_version=_F6_ACCEPTANCE_ANCHOR_SCHEMA, **document)
    if set(anchor) != _F6_ACCEPTANCE_ANCHOR_FIELDS:
        raise ValueError('F6 instruction fetch acceptance anchor field inventory')
    return anchor


@dataclass(frozen=True, slots=True)
class F6InstructionFetchCompletion:
    key: TransactionKey
    snapshot: ReadSnapshot
    acceptance: InstructionAcceptance
    source: object
    admission: object
    run_id: str
    execution_binding_sha256: str
    case_id: str
    case_index: int
    execution: str
    testcase_id: str
    reset_epoch: int
    address: int
    acceptance_tick: int
    snapshot_tick: int
    response_tick: int
    request_scope: tuple
    response_scope: tuple
    request_pre: dict
    response_pre: dict
    response_post: dict
    backend_response_tick: int
    backend_response_scope: tuple
    backend_response_pre: dict
    backend_response_post: dict
    schema_version: str = 'compiled_F6_instruction_fetch_completion.v1'
    proof_scope: str = 'native_obi_instruction_fetch_completed'
    grants_source_authority: bool = False


class F6InstructionFetchIssuer:
    __slots__ = ('_owner',)

    def __init__(self, owner):
        object.__setattr__(self, '_owner', ref(owner))

    def __setattr__(self, name, value):
        raise AttributeError('F6 instruction fetch issuer is sealed')

    @property
    def acceptances(self):
        return _issuer_acceptances(self)

    def document(self):
        return _issuer_document(self)


def declared_error_tap(trace, error_capability):
    """The physical OBI error tap, or None when the profile declares none.

    A CPU whose ABI has no error pin cannot present an error tap.  Its absence
    is lawful only against an explicit ``error_response=False`` capability, so a
    missing tap can never be re-labelled as a zero-valued observation.
    """
    if type(trace) is not dict or type(error_capability) is not bool:
        raise ValueError('F6 instruction fetch: explicit OBI error capability required')
    signals = trace.get('signals')
    if type(signals) is not dict or any(type(name) is not str or not name
                                        for name in signals.values()):
        raise ValueError('F6 instruction fetch: OBI trace signals required')
    has_error = 'error' in signals
    if has_error != error_capability:
        raise ValueError('F6 instruction fetch: OBI error tap differs from the declared capability')
    return signals['error'] if has_error else None


def _receipt_registry(_canonical=_canonical):
    from myfuzz.integration.shared_f6_slots import (instruction_case_mapping as shared_instruction_case_mapping,
        fixed_support_case_mapping as shared_fixed_support_mapping)
    _OWNERS = WeakKeyDictionary()
    _PINS = {}
    _WRAPPED = {}


    def _seal_f6_fetch_provider(cls, names):
        if cls in _PINS:
            raise RuntimeError('F6 instruction fetch provider already sealed')
        if 'events_since' in names and '_event_ref_by_id' in names:
            names = (*names, '_event_refs_since')
        _PINS[cls] = tuple((name, getattr(cls, name),
            (getattr(cls, name).fget if type(getattr(cls, name)) is property else getattr(cls, name)).__code__)
            for name in names)
        _WRAPPED[cls] = tuple((name, getattr(cls, name).__wrapped__,
            getattr(cls, name).__wrapped__.__code__) for name in names
            if hasattr(getattr(cls, name), '__wrapped__'))


    # Memory ownership must be pinned at import, never at caller installation time.
    _seal_f6_fetch_provider(MemoryService, ('accept_instructions', 'read'))
    _seal_f6_fetch_provider(PersistentMemory, ('read', 'validate_instruction_acceptance', 'resolve_span'))


    def _require(state, condition, message):
        if not condition:
            if state is not None:
                state['invalid'] = True
            raise ValueError('F6 instruction fetch: ' + message)


    def _original(state, owner, cls):
        _require(state, type(owner) is cls and cls in _PINS, 'registered original owner required')
        for name, method, code in _PINS[cls]:
            _require(state, name not in vars(owner) and getattr(cls, name) is method
                and (method.fget if type(method) is property else method).__code__ is code,
                'original method drift: ' + name)
        for name, original, code in _WRAPPED[cls]:
            _require(state, getattr(getattr(cls, name), '__wrapped__', None) is original
                and original.__code__ is code, 'original wrapped method drift: ' + name)


    def _frame(state, owner, name, depth=2):
        caller = sys._getframe(depth)
        pins = {n: code for n, _, code in _PINS[type(owner)]}
        _require(state, caller.f_code is pins[name] and caller.f_locals.get('self') is owner,
            'requires original ' + name + ' callback')
        return caller


    def _scope(cpu):
        return (cpu._execution, cpu._case_id, cpu.reset_epoch, cpu.process)


    def _state(cpu):
        state = _OWNERS.get(cpu) if hasattr(cpu, '__weakref__') else None
        if state is None:
            _require(None, getattr(cpu, '_f6_instruction_fetch', None) is None, 'unregistered issuer')
            return None
        _require(state, not state['invalid'], 'issuer revoked')
        _original(state, cpu, state['cpu_type'])
        scenario, runner = state['scenario'], state['runner']
        _original(state, scenario, state['scenario_type'])
        _original(state, runner, state['runner_type'])
        _original(state, cpu.service, MemoryService)
        _original(state, cpu.memory, PersistentMemory)
        _original(state, state['journal'], state['journal_type'])
        _original(state, state['journal_records'], state['journal_records_type'])
        runtime = state['runtime']
        _original(state, runtime, state['runtime_type'])
        _require(state, cpu._f6_instruction_fetch is state['issuer']
            and state['issuer']._owner() is cpu and scenario.runner is runner
            and runner.sessions.get(cpu.source_component) is cpu
            and cpu.source_component == state['component']
            and cpu.service is state['service'] and cpu.memory is state['memory']
            and cpu.service.memory is cpu.memory and cpu.service.ledger is state['ledger']
            and type(cpu.reset_epoch) is int and 0 <= cpu.reset_epoch < 1 << 64
            and type(cpu.memory.generation) is int and cpu.memory.generation == state['generation']
            and runner._events is state['journal'] and runner._events.runner is runner
            and runner._events._records is state['journal_records']
            and runner._events._records._file is state['journal_file'],
            'owner/configuration drift')
        # Both artifact owners must still canonicalise to the installed
        # material.  The session normally keeps its own deep copy, so this
        # renders each own document once; only a session that shares one
        # object with its artifact skips the second render.  Structural
        # equality is not used: JSON value equality (1 vs 1.0) is not
        # canonical-equality, and that would weaken the drift guard.
        artifact = cpu._artifact_document
        artifact_owner = cpu.artifact.runtime_document
        artifact_material = _canonical(artifact)
        owner_material = (artifact_material if artifact_owner is artifact
            else _canonical(artifact_owner))
        _require(state, artifact_material == state['artifact']
            and owner_material == state['artifact']
            and _canonical(asdict(scenario.template)) == state['template']
            and runtime.cpu is cpu and runtime.session is scenario and runtime.runner is runner
            and runtime.run_id == state['run_id']
            and runtime.execution_binding_sha256 == state['binding']
            and runtime.max_cases == state['max_cases']
            and _canonical(runtime.contract) == state['contract']
            and runtime._f6_instruction_fetch is state['issuer'], 'owner/configuration drift')
        if state['scope'] is not None:
            _require(state, _scope(cpu) == state['scope'] and cpu.process is state['scope'][3],
                'execution/testcase/reset/process drift')
        return state


    def install_f6_instruction_fetch(cpu, scenario, *, contract, run_id,
                                     execution_binding_sha256, max_cases):
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        from myfuzz.local_harness.native_irq_receipt_contract import verify_native_irq_receipt_artifact
        from .session_runtime import ScenarioSession
        from .runner import ScenarioRunner, _EventLog
        from .event_journal import EventJournal
        from myfuzz.integration.compiled_f6 import CompiledF6Runtime
        caller = sys._getframe(1)
        runtime = caller.f_locals.get('self')
        _require(None, type(runtime) is CompiledF6Runtime and CompiledF6Runtime in _PINS,
            'original compiled F6 runtime construction required')
        _original(None, runtime, CompiledF6Runtime)
        original_code = next(code for name, _, code in _WRAPPED[CompiledF6Runtime] if name == '__init__')
        rebind = (caller.f_code is CompiledF6Runtime.rebind_reset_epoch.__code__)
        _require(None, (caller.f_code is original_code or rebind) and runtime.cpu is cpu
            and runtime.session is scenario and runtime.contract is contract
            and runtime.runner is scenario.runner and runtime.run_id == run_id
            and runtime.execution_binding_sha256 == execution_binding_sha256
            and runtime.max_cases == max_cases and caller.f_locals.get('cpu') is cpu,
            'original compiled F6 runtime construction owner join required')
        _original(None, cpu, GeneratedCve2Session)
        _original(None, scenario, ScenarioSession)
        _original(None, scenario.runner, ScenarioRunner)
        _original(None, scenario.runner._events, _EventLog)
        _original(None, scenario.runner._events._records, EventJournal)
        if rebind:
            epoch = getattr(runtime, '_f6_epoch_program', None)
            launch = getattr(runtime, '_epoch_launch', None)
            _require(None, cpu not in _OWNERS and getattr(cpu, '_f6_instruction_fetch', None) is runtime._f6_instruction_fetch
                and type(epoch) is dict and type(launch) is dict
                and epoch.get('reset_epoch') == cpu.reset_epoch == launch.get('reset_epoch')
                and epoch.get('barrier_event_id') == launch.get('barrier_event_id'),
                'measured reset reinstallation required')
        else:
            _require(None, cpu not in _OWNERS and getattr(cpu, '_f6_instruction_fetch', None) is None,
                'installation is once only')
        _require(None, type(run_id) is str and bool(run_id) and run_id.strip() == run_id
            and type(execution_binding_sha256) is str
            and re.fullmatch('[0-9a-f]{64}', execution_binding_sha256) is not None,
            'run and binding digest required')
        _require(None, type(contract) is dict
            and contract.get('schema_version') == 'compiled_F6_cpu_dma_contract.v1'
            and contract.get('flow_id') == 'F6'
            and contract['cpu']['instance_id'] == cpu.source_component
            and cpu.native_irq_receipts_enabled and cpu._rvfi_enabled
            and cpu._physical_tick_samples_enabled
            and scenario.runner.sessions.get(cpu.source_component) is cpu
            and scenario.runner.provenance_enabled
            and scenario.template.testcase_id == run_id + ':native', 'current F6 OBI configuration required')
        verify_native_irq_receipt_artifact(cpu.artifact, base_dir=cpu.base_dir)
        program = contract['program_contract']
        _require(None, type(max_cases) is int and 1 <= max_cases <= program['slot_count'] <= 16
            and program['slot_bytes'] == 256 and program['online_prefix_bytes'] == 128,
            'bounded F6 prefix/step configuration required')
        trace, = [trace for trace in cpu._artifact_document['base_protocol_traces']['traces']
            if trace['endpoint_id'] == contract['cpu']['instruction_endpoint_id']]
        _require(None, trace.get('sample_group') == 'protocol_taps' and trace.get('protocol') == 'obi',
            'original physical OBI trace required')
        try:
            declared_error_tap(trace, cpu.artifact.plan.profile.capabilities.get('error_response'))
        except ValueError as error:
            _require(None, False, 'OBI error tap policy: ' + str(error))
        issuer = F6InstructionFetchIssuer(cpu)
        _OWNERS[cpu] = dict(issuer=issuer, cpu_type=GeneratedCve2Session,
            runtime=runtime, runtime_type=CompiledF6Runtime, contract=_canonical(contract),
            scenario_type=ScenarioSession, runner_type=ScenarioRunner,
            scenario=scenario, runner=scenario.runner, component=cpu.source_component,
            journal=scenario.runner._events, journal_type=_EventLog,
            journal_records=scenario.runner._events._records, journal_records_type=EventJournal,
            journal_file=scenario.runner._events._records._file,
            service=cpu.service, memory=cpu.memory, ledger=cpu.service.ledger,
            generation=cpu.memory.generation, artifact=_canonical(cpu._artifact_document),
            template=_canonical(asdict(scenario.template)), program=deepcopy(program),
            source_id=contract['instruction_source_id'], trace=deepcopy(trace), run_id=run_id,
            error_capability=cpu.artifact.plan.profile.capabilities.get('error_response'),
            binding=execution_binding_sha256, max_cases=max_cases,
            max_sources=(program['slot_count'] if 'shared_slots' in program else max_cases),
            capacity=scenario.template.max_steps * (program['slot_count'] if 'shared_slots' in program else max_cases),
            scope=None, invalid=False, sources=[], fixed_supports={}, acceptances={}, snapshots={},
            request=None, candidate=None, issued={}, pending=None, used_keys=set(), consumed=set())
        cpu._f6_instruction_fetch = issuer
        return issuer


    def _live(state, cpu):
        _require(state, type(cpu._execution) is str and re.fullmatch('[0-9a-f]{32}', cpu._execution)
            and type(cpu._case_id) is str and bool(cpu._case_id), 'live CPU scope required')
        if state['scope'] is None:
            state['scope'] = _scope(cpu)
        _require(state, _scope(cpu) == state['scope'], 'live CPU scope changed')


    def _capture_f6_instruction_acceptance(cpu, acceptance):
        state = _state(cpu)
        if state is None:
            return
        frame = _frame(state, cpu, 'accept_instructions')
        _live(state, cpu)
        _require(state, frame.f_locals.get('acceptance') is acceptance
            and type(acceptance) is InstructionAcceptance
            and len(state['acceptances']) < state['max_sources'], 'actual acceptance return required')
        cpu.memory.validate_instruction_acceptance(acceptance)
        event = cpu.service.events[-1]
        _require(state, event == dict(kind='instruction_source', address=acceptance.address,
            data_hex=acceptance.data.hex(), source_event_id=acceptance.source_event_id,
            generation=acceptance.generation), 'actual instruction service event required')
        event['f6_acceptance_anchor'] = _f6_instruction_acceptance_anchor(acceptance)
        state['acceptances'][id(acceptance)] = (acceptance, event, _canonical(event))


    def _arm_f6_instruction_read(cpu, key):
        state = _state(cpu)
        if state is None:
            return
        caller = sys._getframe(1)
        _require(state, caller.f_code in {code for name, _, code in _PINS[type(cpu)]
            if name in ('_serve', '_resume_instruction')} and caller.f_locals.get('key') is key,
            'requires original instruction service invocation')
        _ARM_ISSUED_READ(cpu.service, key)


    def _capture_f6_instruction_snapshot(cpu, channel, snapshot):
        state = _state(cpu)
        if state is None or channel != 'instr':
            return
        _frame(state, cpu, '_freeze_snapshot')
        parent = sys._getframe(2)
        _require(state, parent.f_code in {code for name, _, code in _PINS[type(cpu)]
            if name in ('_serve', '_resume_instruction')} and parent.f_locals.get('snapshot') is snapshot,
            'actual CPU read return required')
        key = parent.f_locals.get('key')
        entry = cpu.service.ledger._entries.get(key)
        _require(state, type(key) is TransactionKey and type(snapshot) is ReadSnapshot
            and entry is not None and entry.status == 'complete' and entry.receipt is snapshot
            and snapshot.transaction_id == str(key) and len(snapshot.data) == 4,
            'original completed read snapshot required')
        handle = _LOOKUP_ISSUED_READ(cpu.service, cpu.memory, key, snapshot)
        _VALIDATE_ISSUED_READ(cpu.service, cpu.memory, key, snapshot, handle)
        event = cpu.service.events[-1]
        _require(state, event.get('kind') == 'memory_read' and event.get('transaction') == asdict(key)
            and event.get('data_hex') == snapshot.data.hex(), 'original memory read event required')
        # At most one outstanding instruction response; snapshots leave here at consume.
        _require(state, not state['snapshots'], 'one outstanding snapshot required')
        state['snapshots'][key] = (key, snapshot, _canonical(asdict(snapshot)), event,
            _canonical(event), cpu.local_ticks)


    def _bind_f6_instruction_source(cpu, scenario, case, case_index, admission, acceptance):
        from .session_runtime import BoundOnlineInstruction
        from .source_provenance import SourceAdmission
        state = _state(cpu)
        if state is None:
            return
        frame = _frame(state, scenario, '_execute_case')
        _require(state, scenario is state['scenario'] and frame.f_locals.get('case') is case
            and frame.f_locals.get('actual_instruction_acceptance') is acceptance
            and case_index == len(scenario._cases)-1 and scenario._cases[case_index] is case
            and 0 <= case_index and type(case.source) is BoundOnlineInstruction
            and type(admission) is SourceAdmission
            and admission in frame.f_locals['admissions'], 'original current source admission required')
        mapping = None
        if 'shared_slots' in state['program']:
            mapping = shared_instruction_case_mapping(state['runtime'], scenario, case, case_index)
        _require(state,(mapping['slot_index'] if mapping else case_index) < state['max_sources'], 'physical source slot budget')
        logical_index = mapping['f6_case_index'] if mapping else case_index
        slot_index = mapping['slot_index'] if mapping else case_index
        expected_source = (state['runtime'].runtime_path_admission['shared_flow_paths'][mapping['flow']]['source_id']
            if mapping else state['source_id'])
        expected_case_id = mapping['case_id'] if mapping else state['run_id'] + ':case:' + str(case_index)
        source, runner = case.source, state['runner']
        original = state['acceptances'].get(id(acceptance))
        _require(state, original is not None and original[0] is acceptance
            and _canonical(original[1]) == original[2], 'issued acceptance identity required')
        cpu.memory.validate_instruction_acceptance(acceptance)
        admission.__post_init__()
        _require(state, runner._provenance.registry.get(source.action_id) is admission
            and source.source_id == expected_source == admission.source_id
            and source.component == cpu.source_component == admission.component
            and source.action_id == admission.action_id == acceptance.source_event_id
            and admission.case_id == case.case_id == expected_case_id
            and admission.case_index == case_index and admission.path_id == case.path_id
            and admission.direction == case.direction == 'CPU_TO_IP'
            and admission.role == 'fuzz_source' and admission.input_kind == 'instruction'
            and admission.input_sha256 == sha256(_canonical({**asdict(source), 'kind':'instruction'}).encode()).hexdigest()
            and source.address == state['program']['slot_base'] + slot_index*256
            and acceptance.address == source.address and acceptance.data == source.data
            and len(source.data) == 128 and not any(row['session_case_index'] == case_index for row in state['sources']),
            'source/case/path/acceptance mismatch')
        tail = next(method for name, method, _ in _PINS[state['runner_type']]
            if name == '_event_refs_since')
        admissions = [event for event in tail(runner, frame.f_locals['start'])
            if event.get('kind') == 'source_admission' and event.get('admission') == admission.document()]
        _require(state, len(admissions) == 1, 'original admission journal reference required')
        before = runner.event_count
        runner._append_external_events(cpu.source_component, admissions[0]['event_id'])
        services = [e for e in tail(runner, before) if e.get('kind') == 'instruction_source'
            and e.get('source_event_id') == source.action_id]
        acceptance_anchor = _f6_instruction_acceptance_anchor(acceptance)
        _require(state, len(services) == 1 and services[0]['producer_event_id'] == admissions[0]['event_id'
            ] and services[0].get('f6_acceptance_anchor') == acceptance_anchor,
            'source acceptance boundary journal required')
        if mapping and mapping['flow'] != 'F6':
            return
        state['sources'].append(dict(case=case, case_index=logical_index,
            session_case_index=case_index, source=source,
            admission=admission, acceptance=acceptance,
            acceptance_anchor=acceptance_anchor,
            material=_canonical(dict(case_id=case.case_id, path_id=case.path_id, direction=case.direction,
                source=asdict(source), admission=admission.document())),
            admission_id=admissions[0]['event_id'], service_id=services[0]['event_id'],
            admission_tick=cpu.local_ticks))


    def _bind_shared_fixed_support(cpu,scenario,case,case_index,support,admission,acceptance):
        from .source_provenance import SourceAdmission
        state = _state(cpu)
        _require(state,state is not None and 'shared_slots' in state['program'], 'shared fixed support not enabled')
        frame = _frame(state,scenario,'_execute_case')
        _require(state,scenario is state['scenario'] and frame.f_locals.get('case') is case
            and frame.f_locals.get('support') is support
            and frame.f_locals.get('actual_fixed_support_acceptance') is acceptance
            and case_index==len(scenario._cases)-1 and type(admission) is SourceAdmission
            and admission in frame.f_locals['admissions'], 'original fixed support callback required')
        mapping = shared_fixed_support_mapping(state['runtime'],scenario,case,case_index,support)
        original = state['acceptances'].get(id(acceptance))
        _require(state,original is not None and original[0] is acceptance
            and _canonical(original[1])==original[2] and case.case_id not in state['fixed_supports'],
            'original once-only fixed support acceptance required')
        cpu.memory.validate_instruction_acceptance(acceptance)
        expected = dict(case_id=case.case_id,case_index=case_index,
            source_id=cpu.source_component+'.fixed_support',path_id=case.path_id,direction=case.direction,
            component=cpu.source_component,action_id=support.action_id,role='fixed_support',input_kind='instruction',
            input_sha256=sha256(_canonical({**asdict(support),'kind':'instruction'}).encode()).hexdigest())
        _require(state,all(getattr(admission,key)==value for key,value in expected.items())
            and state['runner']._provenance.registry.get(support.action_id) is admission
            and acceptance.address==support.address and acceptance.data==support.data
            and acceptance.source_event_id==support.action_id, 'fixed support source/admission identity')
        tail = next(method for name, method, _ in _PINS[state['runner_type']]
            if name == '_event_refs_since')
        roots = [row for row in tail(state['runner'], frame.f_locals['start'])
            if row.get('kind')=='source_admission' and row.get('admission')==admission.document()]
        _require(state,len(roots)==1,'original fixed support admission journal required')
        state['runner']._append_external_events(cpu.source_component,roots[0]['event_id'])
        state['fixed_supports'][case.case_id] = dict(case=case,support=support,admission=admission,
            acceptance=acceptance,mapping=mapping,material=_canonical(dict(
                support=asdict(support),admission=admission.document(),mapping=mapping)))


    def validate_shared_fixed_support(cpu,*,case_id):
        state = _state(cpu)
        _require(state,state is not None and case_id in state['fixed_supports'],'original fixed support required')
        row = state['fixed_supports'][case_id]
        case,support,admission,acceptance = (row[key] for key in ('case','support','admission','acceptance'))
        mapping = shared_fixed_support_mapping(state['runtime'],state['scenario'],case,
            row['mapping']['session_case_index'],support)
        _require(state,_canonical(dict(support=asdict(support),admission=admission.document(),mapping=mapping))
            == row['material'] and state['runner']._provenance.registry.get(support.action_id) is admission,
            'fixed support material drift')
        original = state['acceptances'].get(id(acceptance))
        _require(state,original is not None and original[0] is acceptance
            and _canonical(original[1])==original[2], 'fixed support original acceptance drift')
        cpu.memory.validate_instruction_acceptance(acceptance)
        return dict(schema_version='shared_F5_fixed_support_acceptance.v1',case_id=case_id,
            session_case_index=mapping['session_case_index'],slot_index=mapping['slot_index'],
            admission=admission.document(),acceptance_anchor=_f6_instruction_acceptance_anchor(acceptance),
            source=dict(asdict(support)),support_path_id=mapping['declaration']['support_path_id'],
            support_source_id=mapping['declaration']['support_source_id'],role='fixed_support',
            fuzz_authority=False,F6_authority=False)


    def _driver_scope(state, cpu, receipt):
        from myfuzz.local_harness.wire import DriverReceipt
        _live(state, cpu)
        _require(state, type(receipt) is DriverReceipt and receipt.status == 'result'
            and receipt.execution == cpu._execution and receipt.sequence == cpu._sequence
            and receipt.new_ticks == 1 and receipt.tick_after == receipt.tick_before+1
            and cpu.local_ticks == cpu._tick_base+receipt.tick_after
            and receipt.payload['samples'][0]['local_tick'] == receipt.tick_after,
            'actual current parsed driver receipt required')
        return (receipt.execution, receipt.sequence, cpu.reset_epoch, cpu.local_ticks)


    def _verify_obi_taps(state, raw_pre, backend, *, request):
        taps, signals = raw_pre.get('protocol_taps', {}), state['trace']['signals']
        _require(state, type(taps) is dict and all(type(taps.get(name)) is int for name in signals.values()),
            'complete original physical OBI PRE taps required')
        if request:
            _require(state, taps[signals['req']] == taps[signals['gnt']] == 1
                and taps[signals['addr']] == backend['i_req_addr'], 'physical OBI request PRE mismatch')
        # rvalid/rdata in PRE are the previous edge's registered CPU-side offer;
        # backend consumption becomes the CPU-side offer on this edge's POST.
        _require(state, raw_pre.get('backend') == backend, 'original OBI backend PRE mismatch')


    def _capture_f6_instruction_request(cpu, receipt, pre):
        state = _state(cpu)
        if state is None:
            return
        _frame(state, cpu, '_step_local')
        scope = _driver_scope(state, cpu, receipt)
        _require(state, pre is receipt.payload['pre_backend'] and pre['i_req_valid'] == pre['i_req_ready'] == 1
            and pre['i_req_write'] == 0 and pre['i_req_wdata'] == 0
            and pre['i_req_be'] == 15 and pre['i_req_addr'] % 4 == 0
            and state['request'] is None, 'exact request PRE handshake required')
        evidence = cpu._request_evidence['instr']
        key = (cpu._waiting_instr[0] if cpu._waiting_instr else
            next(key for key in state['snapshots'] if asdict(key) == evidence['transaction']))
        _require(state, evidence['transaction'] == asdict(key)
            and key.channel_id == 'instr' and key.source_epoch == cpu.reset_epoch
            and key.source_component == cpu.source_component and key.testcase_id == cpu._case_id,
            'complete original OBI key required')
        raw_pre = receipt.payload['samples'][0]['pre']
        _verify_obi_taps(state, raw_pre, pre, request=True)
        state['request'] = (key, _canonical(asdict(key)), scope, deepcopy(raw_pre), pre['i_req_addr'])


    def _source_row(state, cpu, row):
        source, admission, acceptance, case = (row[k] for k in ('source','admission','acceptance','case'))
        _require(state, state['scenario']._cases[row['session_case_index']] is case and case.source is source
            and state['runner']._provenance.registry.get(source.action_id) is admission
            and _canonical(dict(case_id=case.case_id, path_id=case.path_id, direction=case.direction,
                source=asdict(source), admission=admission.document())) == row['material'],
            'admitted source material drift')
        _require(state, row.get('acceptance_anchor') ==
            _f6_instruction_acceptance_anchor(acceptance),
            'source acceptance anchor drift')
        cpu.memory.validate_instruction_acceptance(acceptance)
        original = state['acceptances'][id(acceptance)]
        _require(state, original[0] is acceptance and _canonical(original[1]) == original[2], 'service event drift')


    def _complete_f6_instruction_fetch(cpu, receipt, pre, ipending):
        """Freeze backend acceptance. Its POST is only a CPU-side OBI offer."""
        state = _state(cpu)
        if state is None:
            return
        frame = _frame(state, cpu, '_step_local')
        scope = _driver_scope(state, cpu, receipt)
        request = state['request']
        _require(state, request is not None and frame.f_locals.get('receipt') is receipt
            and frame.f_locals.get('pre') is pre and frame.f_locals.get('ipending') is ipending
            and pre is receipt.payload['pre_backend']
            and pre['i_rsp_valid'] == pre['i_rsp_ready'] == 1 and pre['i_rsp_error'] == 0,
            'exact backend response acceptance PRE required')
        key, key_material, request_scope, request_pre, address = request
        actual = state['snapshots'].get(key)
        _require(state, actual is not None and actual[0] is key and _canonical(asdict(key)) == key_material,
            'same accepted OBI transaction required')
        snapshot = actual[1]
        entry = cpu.service.ledger._entries.get(key)
        _require(state, _canonical(asdict(snapshot)) == actual[2] and _canonical(actual[3]) == actual[4]
            and entry is not None and entry.status == 'complete' and entry.receipt is snapshot
            and ipending == (snapshot.value, 0, key.source_sequence)
            and pre['i_rsp_rdata'] == snapshot.value and request_scope[0] == scope[0]
            and request_scope[2] == scope[2] and request_scope[3] < scope[3]
            and state['candidate'] is None, 'unchanged actual four-byte read/response required')
        rows = [row for row in state['sources'] if row['source'].address <= address < row['source'].address+128]
        _require(state, len(rows) <= 1, 'unique admitted prefix required')
        row = rows[0] if rows else None
        if row is not None:
            _source_row(state, cpu, row)
            acceptance = row['acceptance']
            offset = address-acceptance.address
            _require(state, address % 4 == 0 and snapshot.memory_id == acceptance.memory_id
                and snapshot.generation == acceptance.generation
                and snapshot.byte_offset == acceptance.byte_offset+offset
                and snapshot.data == acceptance.data[offset:offset+4]
                and snapshot.versions == acceptance.versions[offset:offset+4]
                and snapshot.writer_event_ids == acceptance.writer_event_ids[offset:offset+4]
                and snapshot.writer_kinds == acceptance.writer_kinds[offset:offset+4]
                and snapshot.writer_kinds == ('INSTRUCTION_SOURCE',)*4
                and row['admission_tick'] <= actual[5] < scope[3]
                and key_material not in state['used_keys'], 'source bytes/order/duplicate mismatch')
        sample = receipt.payload['samples'][0]
        _verify_obi_taps(state, sample['pre'], pre, request=False)
        post, signals = sample['post'].get('protocol_taps', {}), state['trace']['signals']
        error_tap = declared_error_tap(state['trace'],
            state['error_capability'])
        _require(state, post.get(signals['rvalid']) == 1
            and post.get(signals['rdata']) == snapshot.value
            and (error_tap is None or post.get(error_tap) == 0),
            'actual OBI response POST offer required')
        event = cpu.cpu_events[-1]
        _require(state, event.get('kind') == 'instr_response' and event.get('transaction') == asdict(key)
            and event.get('response_tick') == cpu.local_ticks and event.get('rdata') == snapshot.value
            and event.get('response_boundary') == 'obi_adapter_backend_acceptance',
            'original backend instr_response event required')
        state['candidate'] = dict(key=key, key_material=key_material, actual=actual,
            request_scope=request_scope, request_pre=request_pre, address=address,
            row=row, backend_scope=scope, backend_receipt=receipt,
            backend_material=_canonical(asdict(receipt)), backend_pre=deepcopy(sample['pre']),
            backend_post=deepcopy(sample['post']), event=event, event_material=_canonical(event))
        state['request'] = None
        state['snapshots'].clear()
        _REVOKE_ISSUED_READ(cpu.service)


    def _observe_f6_native_instruction_response(cpu, receipt, pre):
        """Issue only at the next synchronous, no-backpressure OBI PRE sample."""
        state = _state(cpu)
        if state is None:
            return
        _frame(state, cpu, '_step_local')
        scope = _driver_scope(state, cpu, receipt)
        sample = receipt.payload['samples'][0]
        _verify_obi_taps(state, sample['pre'], pre, request=False)
        signals, taps = state['trace']['signals'], sample['pre']['protocol_taps']
        candidate = state['candidate']
        if candidate is None:
            _require(state, taps[signals['rvalid']] == 0, 'native OBI response has no original backend candidate')
            return
        key, actual = candidate['key'], candidate['actual']
        snapshot, backend_scope = actual[1], candidate['backend_scope']
        _require(state, scope[:1] == backend_scope[:1] and scope[2] == backend_scope[2]
            and scope[1] == backend_scope[1]+1 and scope[3] == backend_scope[3]+1
            and _canonical(asdict(candidate['backend_receipt'])) == candidate['backend_material']
            and _canonical(asdict(key)) == candidate['key_material']
            and _canonical(asdict(snapshot)) == actual[2]
            and _canonical(actual[3]) == actual[4]
            and _canonical(candidate['event']) == candidate['event_material']
            and cpu.service.ledger._entries[key].receipt is snapshot
            and taps[signals['rvalid']] == 1 and taps[signals['rdata']] == snapshot.value
            and (declared_error_tap(state['trace'], state['error_capability']) is None
                 or taps[declared_error_tap(state['trace'], state['error_capability'])] == 0),
            'next native OBI PRE response consumption mismatch')
        state['candidate'] = None
        row = candidate['row']
        if row is None:
            return  # boot/ISR/control transfer remains diagnostic-only
        _source_row(state, cpu, row)
        _require(state, state['pending'] is None and len(state['issued']) < state['capacity']
            and candidate['key_material'] not in state['used_keys'], 'completion queue/duplicate/capacity mismatch')
        completion = F6InstructionFetchCompletion(key=key, snapshot=snapshot,
            acceptance=row['acceptance'], source=row['source'], admission=row['admission'],
            run_id=state['run_id'], execution_binding_sha256=state['binding'],
            case_id=row['case'].case_id, case_index=row['case_index'],
            execution=cpu._execution, testcase_id=cpu._case_id, reset_epoch=cpu.reset_epoch,
            address=candidate['address'], acceptance_tick=candidate['request_scope'][3],
            snapshot_tick=actual[5], response_tick=scope[3],
            request_scope=candidate['request_scope'], response_scope=scope,
            request_pre=deepcopy(candidate['request_pre']), response_pre=deepcopy(sample['pre']),
            response_post=deepcopy(sample['post']), backend_response_tick=backend_scope[3],
            backend_response_scope=backend_scope, backend_response_pre=deepcopy(candidate['backend_pre']),
            backend_response_post=deepcopy(candidate['backend_post']))
        state['used_keys'].add(candidate['key_material'])
        state['issued'][id(completion)] = (completion, _canonical(asdict(completion)), row,
            candidate['event'], candidate['event_material'], key, snapshot,
            actual[3], actual[4], candidate['backend_receipt'], candidate['backend_material'],
            receipt, _canonical(asdict(receipt)))
        state['pending'] = completion


    def _f6_instruction_fetch_pending(cpu):
        state = _OWNERS.get(cpu)
        return int(state is not None and not state['invalid'] and state['candidate'] is not None)


    def validate_f6_instruction_fetch(cpu, completion):
        state = _state(cpu)
        _require(state, state is not None, 'current issuer required')
        issued = state['issued'].get(id(completion))
        _require(state, type(completion) is F6InstructionFetchCompletion and issued is not None
            and issued[0] is completion and _canonical(asdict(completion)) == issued[1]
            and completion.key is issued[5] and completion.snapshot is issued[6]
            and completion.acceptance is issued[2]['acceptance']
            and completion.source is issued[2]['source'] and completion.admission is issued[2]['admission']
            and cpu.service.ledger._entries[completion.key].receipt is completion.snapshot
            and _canonical(issued[3]) == issued[4] and _canonical(issued[7]) == issued[8]
            and _canonical(asdict(issued[9])) == issued[10]
            and _canonical(asdict(issued[11])) == issued[12], 'unchanged issued completion identity required')
        _source_row(state, cpu, issued[2])
        return completion


    def f6_instruction_fetch_receipts(cpu):
        state = _state(cpu)
        return tuple(row[0] for row in state['issued'].values()) if state is not None else ()


    def revoke_f6_instruction_fetch(cpu):
        state = _OWNERS.pop(cpu, None)
        if state is not None:
            state['invalid'] = True
            state['pending'] = None
            state['candidate'] = None
            state['request'] = None
            state['snapshots'].clear()
            _REVOKE_ISSUED_READ(cpu.service)


    def _drain_f6_instruction_fetches(runner, component):
        cpu = runner.sessions[component]
        state = _state(cpu)
        if state is None:
            return
        _frame(state, runner, '_drain_tick_samples')
        completion = state['pending']
        if completion is None:
            return
        validate_f6_instruction_fetch(cpu, completion)
        issued = state['issued'][id(completion)]
        row = issued[2]
        _require(state, id(completion) not in state['consumed'], 'duplicate Runner completion')

        def event(event_id):
            lookup = next(method for name, method, _ in _PINS[state['runner_type']]
                if name == '_event_ref_by_id')
            record = lookup(runner, event_id)
            _require(state, record is not None and record.get('event_id') == event_id, 'missing Runner reference')
            return record

        # No journal writer runs during this synchronous proof. Borrow this
        # complete prefix once, retaining every duplicate for all seven joins.
        journal_prefix = (tuple(state['journal']) if _FETCH_SCAN_MODE.get() == 'snapshot'
            else state['journal'])

        def one(predicate):
            matches = [e for e in journal_prefix if predicate(e)]
            _require(state, len(matches) == 1, 'unique original Runner reference required')
            return matches[0]

        admission, service = event(row['admission_id']), event(row['service_id'])
        acceptance_anchor = _f6_instruction_acceptance_anchor(completion.acceptance)
        _require(state, admission.get('kind') == 'source_admission'
            and admission.get('admission') == completion.admission.document()
            and service.get('kind') == 'instruction_source' and service.get('component') == component
            and service.get('producer_event_id') == admission['event_id']
            and service.get('f6_acceptance_anchor') == acceptance_anchor
            and all(service.get(k) == v for k, v in state['acceptances'][id(completion.acceptance)][1].items()),
            'admission/service original journal mismatch')
        response = one(lambda e: e.get('kind') == 'instr_response' and e.get('component') == component
            and e.get('transaction') == asdict(completion.key))
        _require(state, all(response.get(k) == v for k, v in issued[3].items()), 'instr_response journal mismatch')
        read_event = one(lambda e: e.get('kind') == 'memory_read' and e.get('component') == component
            and e.get('transaction') == asdict(completion.key))
        _require(state, all(read_event.get(k) == v for k, v in issued[7].items()),
            'original snapshot read journal mismatch')
        references = {}
        for phase in ('request', 'backend_response', 'response'):
            scope = getattr(completion, phase+'_scope')
            raw = one(lambda e: e.get('kind') == 'local_tick_sample' and e.get('component') == component
                and e.get('phase') == 'pre' and e.get('f6_obi_scope') == list(scope))
            producer = event(raw.get('producer_event_id'))
            expected = getattr(completion, phase+'_pre')
            _require(state, raw.get('outputs') == expected
                and producer.get('component') == component and producer.get('local_tick') == scope[3]
                and producer.get('outputs', {}).get('driver_samples', [{}])[0].get('pre', {}) == expected,
                'raw PRE/step producer mismatch')
            outputs = producer['outputs']
            if phase == 'request':
                _require(state, outputs.get('instr_req_accepted') == 1
                    and outputs.get('instr_addr') == completion.address,
                    'request step acceptance mismatch')
            elif phase == 'backend_response':
                _require(state, outputs.get('instr_rsp_consumed') == 1
                    and outputs.get('instr_rsp_source_epoch') == completion.reset_epoch
                    and outputs.get('instr_rsp_source_sequence') == completion.key.source_sequence
                    and outputs.get('instr_rsp_rdata') == completion.snapshot.value,
                    'response step transaction mismatch')
            references[phase+'_pre_event_id'] = raw['event_id']
            references[phase+'_producer_event_id'] = producer['event_id']
            if phase != 'request':
                post = one(lambda e: e.get('kind') == 'local_tick_sample' and e.get('component') == component
                    and e.get('phase') == 'post' and e.get('f6_obi_scope') == list(scope))
                _require(state, post.get('outputs') == getattr(completion, phase+'_post')
                    and post.get('producer_event_id') == producer['event_id']
                    and outputs['driver_samples'][0].get('post') == post['outputs'],
                    'original OBI POST/step producer mismatch')
                references[phase+'_post_event_id'] = post['event_id']
        _require(state, references['request_pre_event_id'] < references['backend_response_pre_event_id']
            < references['response_pre_event_id']
            and admission['event_id'] < service['event_id'] < read_event['event_id'] < response['event_id']
            and response['event_id'] < references['backend_response_pre_event_id']
            and response.get('producer_event_id') == references['backend_response_producer_event_id'],
            'Runner source/backend/native response order mismatch')
        document = asdict(completion)
        document['snapshot']['data_hex'] = document['snapshot'].pop('data').hex()
        document['acceptance']['data_hex'] = document['acceptance'].pop('data').hex()
        document['admission'] = completion.admission.document()
        document.update(kind='compiled_F6_instruction_fetch_completion', component=component,
            event_id=runner.event_count+1, producer_event_id=references['response_pre_event_id'],
            admission_event_id=admission['event_id'], service_event_id=service['event_id'],
            instr_response_event_id=response['event_id'], memory_read_event_id=read_event['event_id'], **references)
        runner._append_ordinary_observed_event(document)
        state['consumed'].add(id(completion))
        state['pending'] = None


    _F6_DRAIN_PRODUCER = (_drain_f6_instruction_fetches, _drain_f6_instruction_fetches.__code__)


    def _guard_f6_completion_publication(runner, document):
        cpu = runner.sessions.get(document.get('component'))
        state = _state(cpu)
        frame = sys._getframe(2)
        _require(state, state is not None and state['runner'] is runner
            and _drain_f6_instruction_fetches is _F6_DRAIN_PRODUCER[0]
            and frame.f_code is _F6_DRAIN_PRODUCER[1]
            and frame.f_locals.get('runner') is runner
            and frame.f_locals.get('document') is document
            and frame.f_locals.get('completion') is state['pending'],
            'completion publication requires original live Runner drain')


    def _issuer_acceptances(issuer):
        state = _state(issuer._owner())
        _require(state, state is not None and state['issuer'] is issuer, 'registered issuer required')
        return tuple(row['acceptance'] for row in state['sources'])


    def _issuer_document(issuer):
        state = _state(issuer._owner())
        _require(state, state is not None and state['issuer'] is issuer, 'registered issuer required')
        return dict(schema_version='compiled_F6_instruction_fetch_issuer.v1',
            run_id=state['run_id'], execution_binding_sha256=state['binding'],
            max_pending=1, max_receipts=state['capacity'])

    return (_seal_f6_fetch_provider,
            install_f6_instruction_fetch,
            _capture_f6_instruction_acceptance,
            _arm_f6_instruction_read,
            _capture_f6_instruction_snapshot,
            _bind_f6_instruction_source,
            _bind_shared_fixed_support,
            validate_shared_fixed_support,
            _capture_f6_instruction_request,
            _complete_f6_instruction_fetch,
            _observe_f6_native_instruction_response,
            _f6_instruction_fetch_pending,
            validate_f6_instruction_fetch,
            f6_instruction_fetch_receipts,
            revoke_f6_instruction_fetch,
            _drain_f6_instruction_fetches,
            _guard_f6_completion_publication,
            _issuer_acceptances,
            _issuer_document)


(_seal_f6_fetch_provider,
 install_f6_instruction_fetch,
 _capture_f6_instruction_acceptance,
 _arm_f6_instruction_read,
 _capture_f6_instruction_snapshot,
 _bind_f6_instruction_source,
 _bind_shared_fixed_support,
 validate_shared_fixed_support,
 _capture_f6_instruction_request,
 _complete_f6_instruction_fetch,
 _observe_f6_native_instruction_response,
 _f6_instruction_fetch_pending,
 validate_f6_instruction_fetch,
 f6_instruction_fetch_receipts,
 revoke_f6_instruction_fetch,
 _drain_f6_instruction_fetches,
 _guard_f6_completion_publication,
 _issuer_acceptances,
 _issuer_document) = _receipt_registry()
