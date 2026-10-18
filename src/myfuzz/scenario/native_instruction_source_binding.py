"""Closed native host-input binding seam; no bus-completion/source grant.

The actual ScenarioSession execution path does not install or call this module
yet. Neither a caller-created record nor a serialized document is live issuance.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re
import sys
from weakref import ref

from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from .memory import InstructionAcceptance, PersistentMemory
from .memory_service import MemoryService
from .native_cpu_events import NativeBusObserver
from .native_packet_session import NativePacketSession
from .runner import ScenarioRunner
from .session_runtime import OnlineCase, OnlineInstruction, ScenarioSession, _resolve_case_source
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


def _binding_registry():
    # Capture original producer identities, not an install-time callback.
    pins = (
        (ScenarioSession, '_execute_case', ScenarioSession._execute_case, ScenarioSession._execute_case.__code__),
        (GeneratedNativeMemorySession, 'accept_instructions', GeneratedNativeMemorySession.accept_instructions,
         GeneratedNativeMemorySession.accept_instructions.__code__),
        (MemoryService, 'accept_instructions', MemoryService.accept_instructions, MemoryService.accept_instructions.__code__),
        (PersistentMemory, 'validate_instruction_acceptance', PersistentMemory.validate_instruction_acceptance,
         PersistentMemory.validate_instruction_acceptance.__code__),
        (ScenarioRunner, 'register_source_admission', ScenarioRunner.register_source_admission,
         ScenarioRunner.register_source_admission.__code__),
        (PersistentMemory, 'resolve_span', PersistentMemory.resolve_span, PersistentMemory.resolve_span.__code__),
    )
    resolve_source = (_resolve_case_source, _resolve_case_source.__code__)
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

    def context(session):
        methods()
        runner = session.runner
        if (type(runner) is not ScenarioRunner or not session._begun or session._finished
                or session._halted or runner._status != 'running'
                or not runner.provenance_enabled):
            raise ValueError('native source binding requires active owned provenance')
        cpu = runner.sessions.get('cpu')
        observer = getattr(cpu, '_native_bus_observer', None)
        method = getattr(cpu, 'accept_instructions', None)
        if (not isinstance(cpu, GeneratedNativeMemorySession)
                or cpu.artifact.runtime_document.get('kind') != 'native_memory_cpu'
                or type(observer) is not NativeBusObserver or observer.session is not cpu
                or observer.failed or observer.execution != cpu._execution
                or observer.epoch != cpu.reset_epoch
                or cpu.process is None or cpu.process.poll() is not None
                or type(cpu._execution) is not str
                or re.fullmatch('[0-9a-f]{32}', cpu._execution) is None
                or type(cpu.reset_epoch) is not int or cpu.reset_epoch < 0
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
        return runner, cpu, cpu.memory

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
        """Reserved for a future original execution hook; currently unreachable."""
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
        execution_frame(session, sys._getframe(1))
        row, runner, cpu, memory = installed(session)
        if (type(case) is not OnlineCase or type(case.source) is not OnlineInstruction
                or type(case_index) is not int or case_index < 0
                or case_index != len(session._cases) - 1 or session._cases[case_index] is not case
                or session._case_source_roles.get(case.case_id) != 'fuzz_source'
                or type(admission) is not SourceAdmission):
            raise ValueError('native source binding requires current selected instruction case')
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
        binding = NativeInstructionSourceBinding('cpu', cpu._execution, cpu.reset_epoch,
            case_index, admission, source, acceptance)
        row['issued'][id(binding)] = (binding, _binding_material(binding))
        row['acceptances'][id(acceptance)] = acceptance
        row['actions'][source.action_id] = binding
        return binding

    def validate(session, binding):
        row, _, _, memory = installed(session)
        issued = row['issued'].get(id(binding))
        if issued is None or issued[0] is not binding or _binding_material(binding) != issued[1]:
            raise ValueError('native source binding is not an unchanged issued identity')
        pins[3][2](memory, binding.acceptance)
        return binding

    def revoke(session):
        row = owners.get(id(session))
        if row is not None and row['session']() is session:
            row['revoked'] = True

    return install, bind, validate, revoke


(_install_actual_execution_producer, bind_actual_selected_instruction,
 validate_issued_binding, revoke_bindings) = _binding_registry()
