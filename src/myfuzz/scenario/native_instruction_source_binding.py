"""Opt-in actual native host-input binding; no bus-completion/source grant.

Only the original actual execution hook issues bindings. Caller-created records
and serialized documents cannot establish live issuance.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re
import sys
from weakref import ref

from myfuzz.local_harness.native_session import GeneratedNativeMemorySession, _NATIVE_INSTRUCTION_ACCEPT_PRODUCER
from .memory import InstructionAcceptance, PersistentMemory, _NATIVE_INSTRUCTION_MEMORY_PRODUCERS
from .memory import ReadSnapshot
from .memory_service import (MemoryService, _NATIVE_INSTRUCTION_SERVICE_PRODUCER,
                             _LOOKUP_ISSUED_READ)
from .ledger import TransactionKey
from .native_cpu_events import NativeBusObserver
from .native_packet_session import NativePacketSession
from .runner import ScenarioRunner, _NATIVE_INSTRUCTION_RUNNER_PRODUCERS
from .session_runtime import (OnlineCase, OnlineInstruction, ScenarioSession, _resolve_case_source,
                              _NATIVE_INSTRUCTION_EXECUTION_PRODUCERS)
from .source_provenance import SourceAdmission


@dataclass(frozen=True, slots=True)
class NativeInstructionSourceBinding:
    """Bound host source input only; consumers must validate issued identity."""

    component: str
    execution: str
    reset_epoch: int
    case_index: int
    admission: SourceAdmission
    source: OnlineInstruction
    acceptance: InstructionAcceptance


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _binding_material(binding):
    if type(binding) is not NativeInstructionSourceBinding:
        raise ValueError('native source binding type required')
    document = asdict(binding)
    document['acceptance']['data'] = binding.acceptance.data.hex()
    return _canonical(document)


def _binding_document(binding):
    document = asdict(binding)
    document['admission'] = binding.admission.document()
    document['source'] = {**asdict(binding.source), 'kind': 'instruction'}
    document['acceptance']['data_hex'] = document['acceptance'].pop('data').hex()
    return document


_CANDIDATE_REFUSAL = 'native_source_candidate_refused'


def _refuse_candidate():
    raise ValueError(_CANDIDATE_REFUSAL)


def _classify_native_source_read(rows, snapshot, key, address, span, *,
                                 epoch, component, testcase_id, execution='native-execution',
                                 anchors=None, current_case_index=0):
    """Non-authoritative policy over typed inputs; only the registry can grant a binding.

    Each row is (binding, current case, registered admission, resolved source ID,
    current source role). A None result is diagnostic-only for unrelated fetches.
    A historical source span remains a candidate and is refused in a later case.
    """
    if (type(rows) is not tuple or (anchors is not None
            and (type(anchors) is not tuple or len(anchors) != len(rows)))
            or type(address) is not int or address < 0 or type(span) is not tuple
            or len(span) != 3 or type(epoch) is not int or epoch < 0
            or type(current_case_index) is not int or current_case_index < 0):
        _refuse_candidate()
    candidates = []
    for index, item in enumerate(rows):
        if type(item) is not tuple or len(item) != 5:
            _refuse_candidate()
        binding = item[0]
        if type(binding) is not NativeInstructionSourceBinding:
            _refuse_candidate()
        source, acceptance = binding.source, binding.acceptance
        if type(source) is not OnlineInstruction or type(acceptance) is not InstructionAcceptance:
            _refuse_candidate()
        anchor = (source.address, len(source.data), acceptance.memory_id,
                  acceptance.generation, acceptance.byte_offset) if anchors is None else anchors[index]
        if (type(anchor) is not tuple or len(anchor) != 5
                or any(type(value) is not int or value < 0 for value in
                       (anchor[0], anchor[1], anchor[3], anchor[4]))
                or type(anchor[2]) is not str or not anchor[2]):
            _refuse_candidate()
        source_address, source_length, memory_id, generation, byte_offset = anchor
        direct = source_address <= address < source_address + source_length
        physical = (span[0] == memory_id and span[1] == generation
                    and byte_offset <= span[2] < byte_offset + source_length)
        if direct or physical:
            candidates.append(item)
    if not candidates:
        return None
    if len(candidates) != 1:
        _refuse_candidate()
    binding, case, registered, source_id, role = candidates[0]
    source, acceptance, admission = binding.source, binding.acceptance, binding.admission
    offset = address - source.address
    if (type(snapshot) is not ReadSnapshot or type(key) is not TransactionKey
            or type(component) is not str or not component
            or type(testcase_id) is not str or not testcase_id
            or type(execution) is not str or not execution
            or binding.component != component or binding.execution != execution
            or binding.reset_epoch != epoch
            or binding.case_index != current_case_index
            or key.execution_id != 'local-execution'
            or key.testcase_id != testcase_id or key.source_component != component
            or key.source_epoch != epoch or key.channel_id != 'memory'
            or type(key.source_sequence) is not int or key.source_sequence < 1
            or snapshot.transaction_id != str(key)
            or type(offset) is not int or offset < 0 or offset % 4
            or offset + 4 > len(source.data) or address % 4
            or type(admission) is not SourceAdmission or registered is not admission
            or role != 'fuzz_source' or admission.role != 'fuzz_source'
            or admission.input_kind != 'instruction'
            or admission.component != component or source.component != component
            or admission.case_index != binding.case_index
            or case.source is not source or case.case_id != admission.case_id
            or case.path_id != admission.path_id
            or case.direction != admission.direction
            or admission.action_id != source.action_id
            or admission.source_id != source_id
            or admission.input_sha256 != hashlib.sha256(_canonical(
                {**asdict(source), 'kind': 'instruction'})).hexdigest()
            or acceptance.address != source.address
            or acceptance.data != source.data
            or acceptance.source_event_id != source.action_id
            or len(acceptance.data) % 4
            or len(acceptance.versions) != len(acceptance.data)
            or len(acceptance.writer_event_ids) != len(acceptance.data)
            or len(acceptance.writer_kinds) != len(acceptance.data)
            or snapshot.memory_id != acceptance.memory_id
            or snapshot.generation != acceptance.generation
            or snapshot.byte_offset != acceptance.byte_offset + offset
            or span != (snapshot.memory_id, snapshot.generation, snapshot.byte_offset)
            or type(snapshot.data) is not bytes or len(snapshot.data) != 4
            or snapshot.data != source.data[offset:offset + 4]
            or snapshot.versions != acceptance.versions[offset:offset + 4]
            or snapshot.writer_event_ids != acceptance.writer_event_ids[offset:offset + 4]
            or snapshot.writer_kinds != acceptance.writer_kinds[offset:offset + 4]
            or snapshot.writer_event_ids != (source.action_id,) * 4
            or snapshot.writer_kinds != ('INSTRUCTION_SOURCE',) * 4
            or len(set(snapshot.versions)) != 1
            or snapshot.versions[0][0] != acceptance.generation):
        _refuse_candidate()
    return binding


def _binding_registry():
    # Capture original producer identities, not an install-time callback.
    execution_pins, resolve_source = _NATIVE_INSTRUCTION_EXECUTION_PRODUCERS()
    native_pin = _NATIVE_INSTRUCTION_ACCEPT_PRODUCER()
    service_pin = _NATIVE_INSTRUCTION_SERVICE_PRODUCER()
    memory_pins = _NATIVE_INSTRUCTION_MEMORY_PRODUCERS()
    runner_pins = _NATIVE_INSTRUCTION_RUNNER_PRODUCERS()
    pins = (
        (ScenarioSession, '_execute_case', *execution_pins[0]),
        (GeneratedNativeMemorySession, 'accept_instructions', *native_pin),
        (MemoryService, 'accept_instructions', *service_pin),
        (PersistentMemory, 'validate_instruction_acceptance', *memory_pins[0]),
        (ScenarioRunner, 'register_source_admission', *runner_pins[0]),
        (PersistentMemory, 'resolve_span', *memory_pins[1]),
        (ScenarioRunner, '_append_external_events', *runner_pins[1]),
        (ScenarioRunner, '_append_ordinary_observed_event', *runner_pins[2]),
        (ScenarioSession, '_native_source_binding_configuration', *execution_pins[1]),
        (ScenarioSession, '_native_source_binding_case', *execution_pins[2]),
    )
    owners = {}

    def methods():
        for cls, name, method, code in pins:
            if getattr(cls, name) is not method or method.__code__ is not code:
                raise ValueError('native source binding producer drift:' + name)
        if _resolve_case_source is not resolve_source[0] or _resolve_case_source.__code__ is not resolve_source[1]:
            raise ValueError('native source binding path resolver drift')

    def execution_frame(session, frame):
        methods()
        if (type(session) is not NativePacketSession
                or frame.f_code is not pins[0][3]
                or frame.f_globals is not pins[0][2].__globals__
                or frame.f_locals.get('self') is not session
                or '_execute_case' in vars(session)
                or getattr(type(session), '_execute_case') is not pins[0][2]):
            raise ValueError('native source binding requires original actual execution')

    def setup(session):
        methods()
        runner = session.runner
        configuration = pins[8][2](session)
        if (type(session) is not NativePacketSession or configuration is None
                or type(runner) is not ScenarioRunner or not runner.provenance_enabled
                or session._runtime_prepared is None or session._register_program_runtime is not None
                or runner.persistent_memory_prerequisite_gate is not None):
            raise ValueError('native source binding requires configured owned packet provenance')
        cpu = runner.sessions.get('cpu')
        observer = getattr(cpu, '_native_bus_observer', None)
        method = getattr(cpu, 'accept_instructions', None)
        if (not isinstance(cpu, GeneratedNativeMemorySession)
                or cpu.artifact.runtime_document.get('kind') != 'native_memory_cpu'
                or type(observer) is not NativeBusObserver or observer.session is not cpu
                or observer.failed
                or getattr(method, '__self__', None) is not cpu
                or getattr(method, '__func__', None) is not pins[1][2]
                or 'accept_instructions' in vars(cpu)
                or type(cpu.service) is not MemoryService or cpu.service.memory is not cpu.memory
                or type(cpu.memory) is not PersistentMemory):
            raise ValueError('native source binding requires original live native owner')
        service_method = cpu.service.accept_instructions
        if (getattr(service_method, '__self__', None) is not cpu.service
                or getattr(service_method, '__func__', None) is not pins[2][2]
                or 'accept_instructions' in vars(cpu.service)):
            raise ValueError('native source binding service producer drift')
        for index in (4, 6, 7):
            _, name, expected, _ = pins[index]
            bound = getattr(runner, name, None)
            if (name in vars(runner) or getattr(bound, '__self__', None) is not runner
                    or getattr(bound, '__func__', None) is not expected):
                raise ValueError('native source binding runner producer drift:' + name)
        return runner, cpu, cpu.memory

    def context(session):
        runner, cpu, memory = setup(session)
        observer = cpu._native_bus_observer
        if (not session._begun or session._finished or session._halted
                or runner._status != 'running' or observer.execution != cpu._execution
                or observer.epoch != cpu.reset_epoch or cpu.reset_epoch != 0
                or cpu.process is None or cpu.process.poll() is not None
                or type(cpu._execution) is not str
                or re.fullmatch('[0-9a-f]{32}', cpu._execution) is None):
            raise ValueError('native source binding requires active owned process')
        return runner, cpu, memory

    def installed(session):
        row = owners.get(id(session))
        if row is None or row['session']() is not session or row['revoked']:
            raise ValueError('native source binding producer is not installed')
        runner, cpu, memory = context(session)
        if (row['runner']() is not runner or row['cpu']() is not cpu
                or row['memory']() is not memory or row['execution'] != cpu._execution
                or row['epoch'] != cpu.reset_epoch):
            raise ValueError('native source binding owner or process changed')
        return row, runner, cpu, memory

    def install(session):
        """Install once, from the original enabled post-accept execution hook."""
        execution_frame(session, sys._getframe(1))
        runner, cpu, memory = context(session)
        owner_id = id(session)
        existing = owners.get(owner_id)
        if existing is not None and existing['session']() is session:
            raise ValueError('native source binding producer installs once')

        def expired(reference):
            row = owners.get(owner_id)
            if row is not None and row['session'] is reference:
                owners.pop(owner_id)

        owners[owner_id] = dict(session=ref(session, expired), runner=ref(runner),
            cpu=ref(cpu), memory=ref(memory), execution=cpu._execution,
            epoch=cpu.reset_epoch, revoked=False, bad=False,
            acceptances={}, actions={}, issued={})

    def bind(session, case, case_index, admission, acceptance):
        frame = sys._getframe(1)
        execution_frame(session, frame)
        row, runner, cpu, memory = installed(session)
        if (type(case) is not OnlineCase or type(case.source) is not OnlineInstruction
                or type(case_index) is not int or case_index < 0
                or case_index != len(session._cases) - 1 or session._cases[case_index] is not case
                or session._case_source_roles.get(case.case_id) != 'fuzz_source'
                or type(admission) is not SourceAdmission):
            raise ValueError('native source binding requires current selected instruction case')
        event_index = frame.f_locals.get('native_service_event_start')
        if (frame.f_locals.get('actual_instruction_acceptance') is not acceptance
                or type(event_index) is not int or event_index < 0
                or len(cpu.service.events) != event_index + 1):
            raise ValueError('native source binding requires this actual successful service return')
        source = case.source
        registered = runner._provenance.registry.get(source.action_id)
        input_sha = hashlib.sha256(_canonical({**asdict(source), 'kind': 'instruction'})).hexdigest()
        expected_source = resolve_source[0](session._runtime_prepared, case)
        admission.__post_init__()
        if (registered is not admission or admission.case_id != case.case_id
                or admission.case_index != case_index or admission.action_id != source.action_id
                or admission.component != source.component or source.component != 'cpu'
                or admission.path_id != case.path_id or admission.direction != case.direction
                or admission.source_id != expected_source or admission.role != 'fuzz_source'
                or admission.input_kind != 'instruction' or admission.input_sha256 != input_sha):
            raise ValueError('native source binding admission or canonical input mismatch')
        pins[3][2](memory, acceptance)
        if (acceptance.address != source.address or acceptance.data != source.data
                or acceptance.source_event_id != source.action_id
                or acceptance.writer_event_ids != (source.action_id,) * len(source.data)
                or acceptance.writer_kinds != ('INSTRUCTION_SOURCE',) * len(source.data)
                or any(v[0] != acceptance.generation for v in acceptance.versions)):
            raise ValueError('native source binding exact full fragment mismatch')
        for offset in range(0, len(source.data), 4):
            span = pins[5][2](memory, source.address + offset, 4)
            if span != (acceptance.memory_id, acceptance.generation, acceptance.byte_offset + offset):
                raise ValueError('native source binding resolved memory span mismatch')
        if id(acceptance) in row['acceptances'] or source.action_id in row['actions']:
            raise ValueError('native source binding acceptance or action already bound')
        service_event = cpu.service.events[event_index]
        expected_event = dict(kind='instruction_source', address=source.address,
            data_hex=source.data_hex, source_event_id=source.action_id, generation=acceptance.generation)
        if service_event != expected_event:
            raise ValueError('native source binding successful service event mismatch')
        binding = NativeInstructionSourceBinding('cpu', cpu._execution, cpu.reset_epoch,
            case_index, admission, source, acceptance)
        row['issued'][id(binding)] = dict(binding=binding, material=_binding_material(binding),
            service_event=service_event, service_material=_canonical(expected_event),
            service_index=event_index, published=False,
            candidate_anchor=(source.address, len(source.data), acceptance.memory_id,
                              acceptance.generation, acceptance.byte_offset))
        row['acceptances'][id(acceptance)] = acceptance
        row['actions'][source.action_id] = binding
        return binding

    def validate(session, binding):
        row, _, _, memory = installed(session)
        issued = row['issued'].get(id(binding))
        if (issued is None or issued['binding'] is not binding
                or _binding_material(binding) != issued['material']):
            raise ValueError('native source binding is not an unchanged issued identity')
        pins[3][2](memory, binding.acceptance)
        return binding

    def lookup_source_for_read(session, service, memory, key, snapshot, address, epoch):
        """Return only an original, published live binding for this exact read."""
        try:
            runner, cpu, actual_memory = context(session)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError(_CANDIDATE_REFUSAL) from exc
        row = owners.get(id(session))
        if (service is not cpu.service or memory is not actual_memory
                or service.memory is not memory or type(key) is not TransactionKey
                or type(snapshot) is not ReadSnapshot):
            if row is not None and row['session']() is session:
                row['bad'] = True
            _refuse_candidate()
        if row is None:
            return None
        try:
            row, _, _, memory = installed(session)
            if row['bad']:
                _refuse_candidate()
            rows = []
            anchors = []
            for issued in row['issued'].values():
                binding = issued['binding']
                case, role = pins[9][2](session, binding.case_index)
                admission = runner._provenance.registry.get(binding.source.action_id)
                source_id = resolve_source[0](session._runtime_prepared, case)
                rows.append((binding, case, admission, source_id, role))
                anchors.append(issued['candidate_anchor'])
            span = pins[5][2](memory, address, 4)
            binding = _classify_native_source_read(tuple(rows), snapshot, key,
                address, span, epoch=epoch, component='cpu',
                testcase_id=cpu._case_id, execution=cpu._execution,
                anchors=tuple(anchors), current_case_index=len(session._cases) - 1)
            if binding is None:
                return None
            issued = row['issued'].get(id(binding))
            if (issued is None or issued['binding'] is not binding
                    or not issued['published']):
                _refuse_candidate()
            validate(session, binding)
            _LOOKUP_ISSUED_READ(service, memory, key, snapshot)
            return binding
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
            row['bad'] = True
            raise ValueError(_CANDIDATE_REFUSAL) from exc

    def publish(session, binding):
        frame = sys._getframe(1)
        execution_frame(session, frame)
        validate(session, binding)
        row, runner, cpu, _ = installed(session)
        issued = row['issued'][id(binding)]
        index = issued['service_index']
        if (issued['published'] or cpu.service.events[index] is not issued['service_event']
                or _canonical(cpu.service.events[index]) != issued['service_material']
                or runner._external_offsets.get(id(cpu.service.events), 0) != index):
            raise ValueError('native source binding service origin changed or already published')
        # This journal lookup assigns references to an already issued fact;
        # matching event dictionaries cannot issue a binding.
        start = frame.f_locals['start']
        admissions = [event for event in runner.events_since(start)
            if event.get('kind') == 'source_admission'
            and event.get('admission') == binding.admission.document()]
        if len(admissions) != 1:
            raise ValueError('native source binding original admission event required')
        before = runner.event_count
        pins[6][2](runner, 'cpu', admissions[0]['event_id'])
        services = [event for event in runner.events_since(before)
            if event.get('kind') == 'instruction_source'
            and event.get('source_event_id') == binding.source.action_id]
        if len(services) != 1 or services[0]['producer_event_id'] != admissions[0]['event_id']:
            raise ValueError('native source binding original service journal reference required')
        pins[7][2](runner, dict(event_id=runner.event_count + 1,
            producer_event_id=services[0]['event_id'], schema_version='native_instruction_source_binding.v1',
            kind='native_instruction_source_bound', proof_scope='host_instruction_input_bound',
            grants_source_authority=False, native_bus_completion_observed=False,
            retirement=False, grants_feedback=False, admission_event_id=admissions[0]['event_id'],
            service_event_index=index, **_binding_document(binding)))
        issued['published'] = True

    def revoke(session):
        row = owners.get(id(session))
        if row is not None and row['session']() is session:
            row['revoked'] = True

    return install, bind, validate, revoke, setup, publish, lookup_source_for_read


(_install_actual_execution_producer, bind_actual_selected_instruction,
 validate_issued_binding, revoke_bindings, preflight_source_binding,
 publish_bound_source, lookup_issued_source_for_read) = _binding_registry()
