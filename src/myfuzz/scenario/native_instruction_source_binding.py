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
from .memory_service import MemoryService, _NATIVE_INSTRUCTION_SERVICE_PRODUCER
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
            epoch=cpu.reset_epoch, revoked=False, acceptances={}, actions={}, issued={})

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
            service_index=event_index, published=False)
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

    return install, bind, validate, revoke, setup, publish


(_install_actual_execution_producer, bind_actual_selected_instruction,
 validate_issued_binding, revoke_bindings, preflight_source_binding,
 publish_bound_source) = _binding_registry()
