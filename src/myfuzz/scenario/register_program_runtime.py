"""Directed register programs rebuilt from installed runtime authority.

This adapter does not implement a causal decoder or certify execution results.
Saved manifests are comparisons, never inputs to address authorization.
"""
from dataclasses import asdict, dataclass, replace
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.composition.component_profile import bind_profile, load_component_profile
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
from .batch import BatchAdvance
from .genome import GenomeCodec
from .live_memory_prerequisites import PersistentMemoryPrerequisiteGate
from .ledger import TransactionKey
from .memory import PersistentMemory
from .router import DataflowRouter, DeviceWindow
from .register_program import compile_register_program, verify_register_program_document
from .rv32i_sources import MmioWindow
from .runner import guard_native_reset_evidence, guard_register_program_verifier
from .session_runtime import ScenarioSession, OnlineCase
from .source_actions import (SourceAction, TerminationObservation,
                            instruction_slot_unmaterialized_prerequisite)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


# Module-pinned Task2 guard: a replaced module alias cannot become a new baseline.
_NATIVE_RESET_OPERATION_GUARD = (guard_native_reset_evidence,
                                 guard_native_reset_evidence.__code__)


def _guard_native_reset_operation(runner, *, new_operation):
    function, code = _NATIVE_RESET_OPERATION_GUARD
    if guard_native_reset_evidence is not function or function.__code__ is not code:
        raise ValueError('register-runtime-native-reset-guard-drift')
    return function(runner, new_operation=new_operation)


def _uint(value):
    return type(value) is int and 0 <= value < 1 << 32


def validate_register_request(request):
    keys = {'schema_version', 'case_id', 'action_id', 'target_instance',
            'endpoint_id', 'register', 'field', 'operation', 'value',
            'allow_side_effect', 'result_address', 'read_modify_write'}
    if type(request) is not dict or set(request) != keys:
        raise ValueError('register-runtime-closed-request-required')
    if request['schema_version'] != 'register_program_request.v1':
        raise ValueError('register-runtime-request-version')
    for key in ('case_id', 'action_id', 'target_instance', 'endpoint_id', 'register', 'field'):
        text = request[key]
        if type(text) is not str or not 1 <= len(text) <= 256 or text.strip() != text:
            raise ValueError('register-runtime-request-text')
    if type(request['allow_side_effect']) is not bool or type(request['read_modify_write']) is not bool:
        raise ValueError('register-runtime-effect-authorization-boolean')
    if request['operation'] == 'register_write':
        valid = _uint(request['value']) and request['result_address'] is None
    elif request['operation'] == 'register_read':
        valid = request['value'] is None and _uint(request['result_address']) and not request['read_modify_write']
    else:
        valid = False
    if not valid:
        raise ValueError('register-runtime-operation-shape')
    return json.loads(_json(request))


@dataclass(frozen=True)
class PreparedRegisterProgram:
    source: object
    case: OnlineCase
    _manifest_json: str

    def document(self):
        return json.loads(self._manifest_json)


class RegisterProgramRuntime:
    def __init__(self, session, *, cpu_component, sidecars, advance_rounds,
                 max_program_bytes=16, max_records=4096):
        if type(session) is not ScenarioSession:
            raise ValueError('register-runtime-actual-session-required')
        if session._begun or session._finished or session.runner._status != 'created':
            raise ValueError('register-runtime-install-before-begin-required')
        if (type(cpu_component) is not str or not cpu_component
                or type(sidecars) is not dict or not sidecars
                or any(type(k) is not str or not k for k in sidecars)
                or type(advance_rounds) is not int or advance_rounds < 1
                or type(max_program_bytes) is not int or max_program_bytes < 16
                or max_program_bytes % 4 or max_program_bytes > 4096
                or type(max_records) is not int or not 1 <= max_records <= 65536):
            raise ValueError('register-runtime-invalid-configuration')
        self.session = session
        self.runner = session.runner
        self.cpu_component = cpu_component
        self.sidecars = {k: Path(v).resolve() for k, v in sidecars.items()}
        self.advance_rounds = advance_rounds
        self.max_program_bytes = max_program_bytes
        self.max_records = max_records
        self._records = []
        self._uncertain = False
        self._successful = {}
        self._active_submission = None
        self._objects = self._actual_objects()
        memory=self._objects[1]
        if type(memory) is not PersistentMemory or type(memory._instruction_slots) is not set:
            raise ValueError('register-runtime-actual-memory-required')
        self._memory_identity_method=PersistentMemory.identity_document
        self._memory_regions=memory._regions
        self._memory_windows=memory._windows
        self._memory_windows_json=_json([list(row[:2])+[asdict(row[2])] for row in memory._windows])
        self._memory_slots=memory._instruction_slots
        self._memory_slots_frozen=frozenset(memory._instruction_slots)
        self._memory_source=Path(__file__).with_name('memory.py')
        self._memory_source_sha256=hashlib.sha256(self._memory_source.read_bytes()).hexdigest()
        self._static_json = _json(self._static())
        self._configuration_sha256=hashlib.sha256(self._static_json.encode()).hexdigest()
        self._validation_static_json=_json(self._static(include_memory_slots=False))
        self._validation_method_pins={name:getattr(type(self),name) for name in
            ('validate','validate_static_configuration','_static','_actual_objects','_validate_memory_configuration')}
        session.attach_register_program_runtime(self)

    def _actual_objects(self):
        cpu = self.runner.sessions.get(self.cpu_component)
        gate = self.runner.persistent_memory_prerequisite_gate
        if (not isinstance(cpu, GeneratedCve2Session)
                or not isinstance(gate, PersistentMemoryPrerequisiteGate)
                or self.session.prerequisite_gate is not gate
                or self.runner._dependency_witness_lifecycle._gate is not gate
                or gate.tracker._consumer is not self.runner._memory_dependency_consumer
                or self.runner._dependency_witness_lifecycle._tracker is not gate.tracker
                or self.runner._dependency_witness_lifecycle._consumer is not gate.tracker._consumer
                or gate.enforce is not True
                or type(gate.max_actions) is not int or not 1 <= gate.max_actions <= 65536
                or gate.tracker._consumer._integrity is not True
                or gate.tracker._degraded or self.runner._dependency_witness_lifecycle._degraded
                or gate._slot_policy is None
                or gate.tracker._slot_policy is not gate._slot_policy
                or gate._slot_policy.component != self.cpu_component
                or gate._slot_policy.gate is not gate
                or gate.tracker._commit_authority is not gate.tracker._consumer._commit_authority
                or gate.tracker._read_authority is not gate.tracker._consumer._read_authority
                or cpu.service.memory is not cpu.memory):
            raise ValueError('register-runtime-installed-memory-gate-required')
        for authority in (gate.tracker._consumer._commit_authority,gate.tracker._consumer._read_authority):
            installed = authority._installed.get(self.cpu_component)
            if (authority.degraded or installed is None or installed[0] is not cpu.service
                    or installed[1] is not cpu.service.ledger or installed[2] is not cpu.memory):
                raise ValueError('register-runtime-memory-authority-binding')
        targets = tuple(self.runner.sessions.get(k) for k in sorted(self.sidecars))
        if any(target is None for target in targets):
            raise ValueError('register-runtime-unknown-target')
        return (cpu, cpu.memory, cpu.router, gate, gate._slot_policy, *targets)

    def _validate_memory_configuration(self):
        memory=self._objects[1]
        if (type(memory) is not PersistentMemory or PersistentMemory.identity_document is not self._memory_identity_method
                or 'identity_document' in vars(memory) or memory._regions is not self._memory_regions
                or memory._windows is not self._memory_windows
                or _json([list(row[:2])+[asdict(row[2])] for row in memory._windows])!=self._memory_windows_json
                or memory._instruction_slots is not self._memory_slots
                or type(memory._instruction_slots) is not set
                or memory._instruction_slots!=self._memory_slots_frozen
                or hashlib.sha256(self._memory_source.read_bytes()).hexdigest()!=self._memory_source_sha256):
            raise ValueError('register-runtime-memory-configuration-drift')

    def _static(self, *, include_memory_slots=True):
        cpu, memory, router, gate, policy, *_ = self._actual_objects()
        if type(router) is not DataflowRouter or type(router.windows) is not tuple:
            raise ValueError('register-runtime-actual-router-required')
        for index,window in enumerate(router.windows):
            if type(window) is not DeviceWindow:
                raise ValueError('register-runtime-actual-router-required')
            DeviceWindow(window.device_id,window.base,window.size,window.target)
            if any(window.base < other.base+other.size and other.base < window.base+window.size
                   for other in router.windows[index+1:]):
                raise ValueError('register-runtime-overlapping-routes')
        artifacts = {}
        for name in (self.cpu_component, *sorted(self.sidecars)):
            artifact = self.runner.sessions[name].artifact
            profile_path = self.runner.sessions[name].base_dir / artifact.plan.request.profile_path
            profile_bytes = profile_path.read_bytes()
            if (hashlib.sha256(profile_bytes).hexdigest() != artifact.plan.profile_sha256
                    or load_component_profile(json.loads(profile_bytes)).profile_fingerprint
                    != artifact.plan.profile.profile_fingerprint
                    or bind_profile(artifact.plan.profile,artifact.plan.facts) != artifact.plan.binding):
                raise ValueError('register-runtime-profile-or-binding-drift')
            verify_native_physical_observation(artifact)
            artifacts[name] = dict(plan=artifact.plan.document(),
                current_profile_fingerprint=artifact.plan.profile.profile_fingerprint,
                current_binding=asdict(artifact.plan.binding),
                source_verification=artifact.source_verification,
                profile_path=str(profile_path.resolve()),
                runtime=artifact.runtime_document,
                runtime_sha256=hashlib.sha256(artifact.runtime_sv.encode()).hexdigest(),
                driver_sha256=hashlib.sha256(artifact.cpp_text.encode()).hexdigest())
        return dict(schema_version='register_program_runtime_configuration.v1',
            cpu_component=self.cpu_component, advance_rounds=self.advance_rounds,
            max_program_bytes=self.max_program_bytes, max_records=self.max_records,
            sources={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                     for name in ('register_program_runtime.py','register_program.py','rv32i_sources.py',
                                  'source_actions.py','live_memory_prerequisites.py','session_runtime.py')},
            scope='directed_declarative_register_program_only', grants_functional=False,
            sidecars={k: dict(path=str(v), sha256=hashlib.sha256(v.read_bytes()).hexdigest())
                      for k, v in sorted(self.sidecars.items())},
            artifacts=artifacts, memory=(memory.identity_document() if include_memory_slots else
                dict(regions=[asdict(region) for region in memory._regions],
                    initialization_seed=memory.initialization_seed,initialization_algorithm='memory-init-v1',
                    max_initialized_bytes=memory.max_initialized_bytes)),
            provider=dict(runtime_contract_sha256=gate.tracker._consumer._runtime,
                          bounds=gate.tracker._consumer._bounds),
            tracker_bounds=dict(max_slots=gate.tracker.max_slots,max_effects=gate.tracker.max_effects,
                                max_age_events=gate.tracker.max_age_events),
            slots=list(self.session._instruction_slots), policy=policy.declaration(),
            template=json.loads(GenomeCodec.encode(self.session.template)),
            routes=[dict(device_id=w.device_id, base=w.base, size=w.size,
                         target=next((k for k,v in self.runner.sessions.items() if v is w.target), None))
                    for w in router.windows], gate_max_actions=gate.max_actions)

    def configuration(self):
        return json.loads(self._static_json)

    @property
    def configuration_sha256(self):
        return self._configuration_sha256

    def capability_preflight(self, *, requested_minimum_level=None):
        from .register_program_capabilities import capability_preflight
        return capability_preflight(self, requested_minimum_level=requested_minimum_level)

    def validate_static_configuration(self):
        if any(name in vars(self) or getattr(type(self),name) is not method
                for name,method in self._validation_method_pins.items()):
            raise ValueError('register-runtime-validation-method-drift')
        self._validate_memory_configuration()
        actual = self._actual_objects()
        if (self.session.runner is not self.runner
                or len(actual) != len(self._objects)
                or any(a is not b for a,b in zip(actual, self._objects))
                or _json(self._static(include_memory_slots=False)) != self._validation_static_json
                or self.session._runtime_prepared is not None or self.runner.provenance_enabled):
            raise ValueError('register-runtime-binding-drift')
        return True

    def validate(self):
        if self._uncertain:
            raise ValueError('register-runtime-uncertain-admission')
        return self._validation_method_pins['validate_static_configuration'](self)

    def _context(self, request):
        self.validate()
        cpu, memory, router, gate, policy, *_ = self._objects
        if (not self.session._begun or self.session._finished or self.session._halted
                or self.runner._status != 'running'):
            raise ValueError('register-runtime-active-directed-session-required')
        target = self.runner.sessions.get(request['target_instance'])
        if request['target_instance'] not in self.sidecars:
            raise ValueError('register-runtime-undeclared-target')
        profile = target.artifact.plan.profile
        endpoint = next((e for e in target.artifact.plan.binding.endpoints
                         if e.endpoint_id == request['endpoint_id']), None)
        if (endpoint is None or endpoint.function != 'mmio_slave'
                or sum(e.function == 'mmio_slave' for e in target.artifact.plan.binding.endpoints) != 1):
            raise ValueError('register-runtime-mmio-endpoint-required')
        routes = [w for w in router.windows if w.target is target
                  and w.device_id == request['target_instance']]
        if len(routes) != 1 or routes[0].size != profile.address.window_size:
            raise ValueError('register-runtime-exact-target-window-required')
        window = routes[0]
        address = cpu.waiting_instruction_address
        waiting = cpu._waiting_instr
        if (type(waiting) is not tuple or len(waiting) != 2 or type(waiting[0]) is not TransactionKey
                or waiting[0].source_component != self.cpu_component
                or waiting[0].source_epoch != cpu.reset_epoch
                or cpu._request_evidence.get('instr',{}).get('transaction') != asdict(waiting[0])
                or cpu._request_evidence.get('instr',{}).get('aligned_address') != address):
            raise ValueError('register-runtime-real-waiting-transaction-required')
        slots = [row for row in self.session._instruction_slots
                 if row[0] == self.cpu_component and row[1] <= address < row[1]+4*row[2]] if _uint(address) else []
        if len(slots) != 1 or address % 4 or not policy.first_address <= address < policy.last_address:
            raise ValueError('register-runtime-real-waiting-slot-required')
        size = min(self.max_program_bytes, slots[0][1]+4*slots[0][2]-address, policy.last_address-address)
        if size < 16 or any(not memory.instruction_slot_unmaterialized(word)
                            for word in range(address,address+size,4)):
            raise ValueError('register-runtime-unmaterialized-slot-required')
        result = request['result_address']
        if result is not None:
            spans = [(s,4*n) for c,s,n in self.session._instruction_slots if c == self.cpu_component]
            spans += [(image.address,len(image.data)) for image in self.session.template.initial_images
                      if image.component == self.cpu_component]
            spans += [(c.source.address,len(c.source.data)) for c in self.session.cases
                      if hasattr(c.source,'address') and c.source.component == self.cpu_component]
            spans += [(w.base,w.size) for w in router.windows]
            spans += [(action.payload['address'],len(bytes.fromhex(action.payload['words_hex'])))
                      for action in gate._actions.values() if action.kind == 'instruction'
                      and action.component == self.cpu_component and 'words_hex' in action.payload]
            if any(result < start+length and start < result+4 for start,length in spans):
                raise ValueError('register-runtime-result-overlaps-owned-span')
            memory_id,_,offset = memory.resolve_span(result,4)
            cells = [memory.inspect_byte(memory_id,offset+lane) for lane in range(4)]
            if any(cell is not None and cell.writer_kind in ('INITIAL_IMAGE','INSTRUCTION_SOURCE') for cell in cells):
                raise ValueError('register-runtime-result-overlaps-owned-bytes')
        context = dict(generation=memory.generation, reset_epoch=cpu.reset_epoch,
            tracker_epoch=gate.tracker._epoch,
            waiting_transaction=asdict(waiting[0]),
            command_epoch=self.runner.command_epoch, waiting_instruction_address=address,
            program_size=size, target_reset_epoch=target.reset_epoch,
            address_base=window.base, endpoint_id=endpoint.endpoint_id)
        cap = load_ip_test_capability(self.sidecars[request['target_instance']], profile=profile)
        operations = next((e.operations for e in cap.endpoint_capabilities
                           if e.endpoint_id == request['endpoint_id']),())
        if (('read' if request['operation']=='register_read' else 'write') not in operations
                or request['read_modify_write'] and 'read' not in operations):
            raise ValueError('register-runtime-endpoint-operation-not-declared')
        args = dict(register=request['register'],field=request['field'],operation=request['operation'],
            value=request['value'],allow_side_effect=request['allow_side_effect'],
            read_modify_write=request['read_modify_write'],
            address_base=window.base, windows=(MmioWindow(window.base,window.size),),
            cpu_component=self.cpu_component,action_id=request['action_id'],program_address=address,
            program_size=size,program_regions=memory._regions,result_address=result,
            result_regions=memory._regions if result is not None else ())
        return profile,cap,args,context

    def prepare(self, request, expected_manifest=None):
        guard_register_program_verifier(self.runner,new_operation=True)
        request = validate_register_request(request)
        self.session._register_capability_preflight()
        profile,cap,args,context = self._context(request)
        if len(self._records) >= self.max_records:
            raise ValueError('register-runtime-record-capacity')
        if request['case_id'] in self.session._receipts or request['action_id'] in self.session._source_ids:
            raise ValueError('register-runtime-duplicate-case-or-action')
        gate,policy = self._objects[3:5]
        if request['action_id'] in gate.action_ids or len(gate.action_ids) >= gate.max_actions:
            raise ValueError('register-runtime-action-capacity-or-conflict')
        program = compile_register_program(profile,cap,**args)
        verify_register_program_document(profile,cap,program.document(),**args)
        advances = tuple(BatchAdvance(self.session.template.schedule_order) for _ in range(self.advance_rounds))
        if (any(c not in self.runner.sessions for c in self.session.template.schedule_order)
                or self.advance_rounds*len(self.session.template.schedule_order)>self.session.template.max_steps):
            raise ValueError('register-runtime-schedule-exceeds-session')
        case = OnlineCase(request['case_id'], 'CPU_TO_IP_TO_CPU' if request['operation']=='register_read'
            else 'CPU_TO_IP', 'register_program', program.source, advances)
        action = SourceAction(action_id=request['action_id'],kind='instruction',
            component=self.cpu_component,source_id='declarative_register_program',ownership='fuzzable',
            flow_id='F4',payload=dict(address=program.source.address,words_hex=program.source.data_hex),
            termination_observation=TerminationObservation('incomplete','','F4'),
            local_step_budget=self.advance_rounds*len(self.session.template.schedule_order))
        admitted = replace(action,prerequisites=tuple(instruction_slot_unmaterialized_prerequisite(
            self.cpu_component,word,policy.reservation_ref(word))
            for word in range(program.source.address,program.source.address+len(program.fragment),4)),action_sha256='')
        doc = dict(schema_version='register_program_runtime_manifest.v1',request=request,
            configuration=self.configuration(),context=context,program=program.document(),
            source_action=action.document(),admitted_action=admitted.document())
        canonical = _json(doc)
        if expected_manifest is not None and _json(expected_manifest) != canonical:
            raise ValueError('register-runtime-saved-manifest-mismatch')
        return PreparedRegisterProgram(program.source,case,canonical)

    def submit(self, request, expected_manifest=None):
        request = validate_register_request(request)
        previous = self._successful.get(request['case_id'])
        if previous is not None:
            _guard_native_reset_operation(self.runner, new_operation=False)
            self.validate()
            self.session._register_capability_preflight()
            saved,receipt = previous
            doc = json.loads(saved)
            cpu,memory = self._objects[:2]
            context = doc['context']
            if (_json(request) != _json(doc['request'])
                    or expected_manifest is not None and _json(expected_manifest) != saved
                    or memory.generation != context['generation']
                    or cpu.reset_epoch != context['reset_epoch']
                    or self.runner.command_epoch != context['command_epoch']
                    or self._objects[3].tracker._epoch != context['tracker_epoch']
                    or self.runner.sessions[request['target_instance']].reset_epoch != context['target_reset_epoch']):
                raise ValueError('register-runtime-successful-retry-drift')
            return dict(manifest=doc,receipt=deepcopy(receipt))
        prepared = self.prepare(request,expected_manifest)
        # Rebuild immediately before mutation; prepared objects never grant authority.
        self.prepare(request,prepared.document())
        doc = prepared.document()
        attempt = dict(manifest=doc,status='attempted',phase='registration',case_index=None)
        self._records.append(attempt)
        try:
            admitted = self._objects[3].register(SourceAction.from_document(doc['source_action']))
            attempt['phase'] = 'registration_verification'
            if _json(admitted.document()) != _json(doc['admitted_action']):
                raise ValueError('register-runtime-unexpected-admitted-action')
            attempt['phase'] = 'session_submission'
            self._active_submission = (prepared.case,deepcopy(doc))
            receipt = self.session.submit_case(prepared.case)
        except BaseException as exc:
            self._uncertain = True
            self.session._halted = True
            if self.session._halt_reason is None:
                self.session._halt_reason = 'uncertain_effect'
            attempt.update(status='uncertain',error_type=type(exc).__name__)
            raise
        finally:
            self._active_submission = None
            attempt['case_index'] = next((i for i,case in enumerate(self.session.cases)
                                          if case is prepared.case),None)
        attempt.update(status='submitted',phase='submitted')
        self._successful[request['case_id']] = (prepared._manifest_json,deepcopy(receipt))
        return dict(manifest=prepared.document(),receipt=deepcopy(receipt))

    def snapshot(self):
        return json.loads(_json(dict(schema_version='register_program_runtime_state.v1',
            configuration=self.configuration(),uncertain=self._uncertain,records=self._records)))
