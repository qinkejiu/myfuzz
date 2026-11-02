"""Measured dual-role wbdmac edges with one outstanding master response.

Register accesses advance the same real DMA process. RAM and declared UART
target effects use only accepted RTL master payloads.
"""
from dataclasses import asdict, dataclass
from copy import deepcopy
import json
from importlib import import_module
from types import CodeType, FunctionType
from weakref import WeakKeyDictionary, ref

from .session import GeneratedLocalSession
from .f6_dma_response_fault import (_seal_f6_dma_session,
    _validate_f6_response_fault, _select_f6_response_fault)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.runtime_path_contract import (
    CompiledRuntimePathContract as _F6ScopeCompiledRuntimePathContract,
)


_F6_SCOPE_TRANSITION_ISSUER = object()
_F6_ROUTE_VALIDATOR_OWNERS = WeakKeyDictionary()
_F6_SCENARIO_RUNNER_CLASS_DATA = (
    'artifact_kind', 'max_local_ticks_per_step',
    'max_transaction_events_per_step', 'max_mmio_target_accesses_per_step')


def _class_implementation_pins(cls):
    rows = []
    for name, descriptor in vars(cls).items():
        if type(descriptor) is FunctionType:
            rows.append((name, descriptor, descriptor.__code__))
        elif type(descriptor) is property:
            accessors = tuple(accessor for accessor in
                (descriptor.fget, descriptor.fset, descriptor.fdel)
                if accessor is not None)
            rows.append((name, descriptor,
                tuple((accessor, accessor.__code__) for accessor in accessors)))
    return tuple(rows)


def _class_data_pins(cls):
    return tuple((name, type(vars(cls).get(name)), vars(cls).get(name))
        for name in _F6_SCENARIO_RUNNER_CLASS_DATA)


def _class_data_pins_match(cls, pins):
    current = _class_data_pins(cls)
    return (len(current) == len(pins)
        and all(name == pinned_name
                and value_type is pinned_type
                and value_type is type(value)
                and value == pinned_value
            for (name, value_type, value),
                (pinned_name, pinned_type, pinned_value)
            in zip(current, pins)))


def _class_implementation_pins_match(cls, pins):
    current = _class_implementation_pins(cls)
    if len(current) != len(pins):
        return False
    for current_row, pinned_row in zip(current, pins):
        if (current_row[0] != pinned_row[0]
                or current_row[1] is not pinned_row[1]):
            return False
        if type(current_row[2]) is not tuple:
            if current_row[2] is not pinned_row[2]:
                return False
        elif (type(pinned_row[2]) is not tuple
                or len(current_row[2]) != len(pinned_row[2])
                or any(current_accessor is not pinned_accessor
                       or current_code is not pinned_code
                       for (current_accessor, current_code),
                           (pinned_accessor, pinned_code)
                       in zip(current_row[2], pinned_row[2]))):
            return False
    return True


def _f6_dma_session_type_allowlist():
    """Return only the pinned base and ScenarioRunner DMA classes."""
    base_class = _F6_SCOPE_DMA_BASE_CLASS
    if globals().get('GeneratedWishboneDmaSession') is not base_class:
        raise ValueError('F6 DMA base session class alias drift')
    scenario_module = import_module(
        'myfuzz.local_harness.wishbone_dma_scenario_session')
    scenario_class = getattr(scenario_module,
        'GeneratedWishboneDmaScenarioSession', None)
    pins = _F6_SCOPE_DMA_CLASS_PINS
    if (type(pins) is not tuple or len(pins) != 4
            or pins[0] is not base_class
            or scenario_class is not pins[1]
            or type(pins[1]) is not type
            or pins[1].__module__ != scenario_module.__name__
            or pins[1].__name__ != 'GeneratedWishboneDmaScenarioSession'
            or pins[1].__qualname__ != 'GeneratedWishboneDmaScenarioSession'
            or pins[1].__bases__ != (base_class,)
            or not _class_implementation_pins_match(pins[1], pins[2])
            or not _class_data_pins_match(pins[1], pins[3])):
        raise ValueError('F6 DMA session class alias drift')
    return pins[0], pins[1]


def _f6_dma_session_instance_data_is_canonical(session):
    return (type(session) in _f6_dma_session_type_allowlist()
        and not any(name in vars(session)
                    for name in _F6_SCENARIO_RUNNER_CLASS_DATA))


def _register_f6_route_validator(session, admission, validator,
                                 topology_validator):
    """Record the original F6 route callback without retaining its owners."""
    registrar = globals().get('_F6_ROUTE_VALIDATOR_REGISTRAR')
    if (registrar is None
            or globals().get('_register_f6_route_validator') is not registrar
            or registrar.__code__ is not
                globals().get('_F6_ROUTE_VALIDATOR_REGISTRAR_CODE')):
        raise ValueError('F6 DMA route validator registrar drift')
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    if (type(session) not in _f6_dma_session_type_allowlist()
            or type(admission) is not DmaMasterRouteAdmission
            or type(admission._beat_policy) is not F6RamDmaPolicy
            or type(validator) is not type(lambda: None)):
        return
    try:
        admission_ref = ref(admission)
        validator_ref = ref(validator)
    except TypeError:
        return
    method = _F6_SCOPE_DMA_BASE_CLASS.configure_dma_route_admission
    nested = tuple(code for code in method.__code__.co_consts
        if isinstance(code, CodeType)
        and code.co_name == 'validate_pinned_route_admission')
    if len(nested) != 1 or validator.__code__ is not nested[0]:
        return
    topology_owner = None
    topology_function = None
    if topology_validator is not None:
        from types import MethodType
        expected_topology = (_F6_SCOPE_COMPILED_TOPOLOGY_DYNAMIC
            if admission._bound_topology.runtime_compilation._boundary_static_validation
            else _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE)
        if (type(topology_validator) is not MethodType
                or type(topology_validator.__self__) is not _F6ScopeCompiledRuntimePathContract
                or topology_validator.__self__ is not
                    admission._bound_topology.runtime_compilation
                or topology_validator.__func__ is not expected_topology
                or type(topology_validator.__self__).validate_topology is not
                    _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE
                or _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE.__code__ is not
                    type(topology_validator.__self__).validate_topology.__code__
                or 'validate_topology' in vars(topology_validator.__self__)
                or 'validate_dynamic_topology' in vars(topology_validator.__self__)
                or type(topology_validator.__self__).validate_dynamic_topology is not _F6_SCOPE_COMPILED_TOPOLOGY_DYNAMIC):
            return
        try:
            topology_owner = ref(topology_validator.__self__)
        except TypeError:
            return
        topology_function = topology_validator.__func__
    closure = dict(zip(validator.__code__.co_freevars,
        (cell.cell_contents for cell in validator.__closure__ or ())))
    if (set(closure) != {'admission', 'self', 'topology_validator'}
            or closure['admission'] is not admission
            or closure['self'] is not session
            or closure['topology_validator'] is not topology_validator):
        return
    _F6_ROUTE_VALIDATOR_OWNERS[session] = dict(
        admission_ref=admission_ref, validator_ref=validator_ref,
        nested_code=nested[0], closure_names=validator.__code__.co_freevars,
        identity_snapshot=session._dma_route_admission_identity,
        topology_ref=topology_owner,
        topology_function=topology_function)


_F6_ROUTE_VALIDATOR_REGISTRAR = _register_f6_route_validator
_F6_ROUTE_VALIDATOR_REGISTRAR_CODE = _register_f6_route_validator.__code__


def _verify_f6_dma_route_validator(session, *, admission=None):
    """Require the original source-owned F6 route validator callback."""
    registrar = globals().get('_F6_ROUTE_VALIDATOR_REGISTRAR')
    if (registrar is not _register_f6_route_validator
            or registrar is not _F6_ROUTE_VALIDATOR_REGISTRAR
            or registrar.__code__ is not _F6_ROUTE_VALIDATOR_REGISTRAR_CODE):
        raise ValueError('F6 DMA route validator registrar drift')
    row = _F6_ROUTE_VALIDATOR_OWNERS.get(session)
    if (not _f6_dma_session_instance_data_is_canonical(session)
            or row is None):
        raise ValueError('F6 DMA route validator is not original')
    if any(name in vars(session) for name in (
            'configure_dma_route_admission', 'configure_dma_route_validator',
            '_validate_dma_route_topology')):
        raise ValueError('F6 DMA route validator is not original')
    for name, expected in _F6_SESSION_METHOD_PINS.items():
        current = getattr(type(session), name, None)
        if current is not expected or getattr(current, '__code__', None) is not expected.__code__:
            raise ValueError('F6 DMA route validator is not original')
    current_admission = getattr(session, '_dma_route_admission', None)
    current_validator = getattr(session, '_dma_route_validator', None)
    if (row['admission_ref']() is None
            or row['admission_ref']() is not current_admission
            or admission is not None and current_admission is not admission
            or row['validator_ref']() is None
            or row['validator_ref']() is not current_validator
            or row['identity_snapshot'] is not
                getattr(session, '_dma_route_admission_identity', None)):
        raise ValueError('F6 DMA route validator is not original')
    callback = current_validator
    method = _F6_SCOPE_DMA_BASE_CLASS.configure_dma_route_admission
    nested = tuple(code for code in method.__code__.co_consts
        if isinstance(code, CodeType)
        and code.co_name == 'validate_pinned_route_admission')
    closure = dict(zip(callback.__code__.co_freevars,
        (cell.cell_contents for cell in callback.__closure__ or ())))
    topology_validator = closure.get('topology_validator')
    topology = current_admission._bound_topology
    if topology_validator is None:
        topology_ok = (row['topology_ref'] is None
                       and row['topology_function'] is None)
    else:
        from types import MethodType
        compilation = current_admission._bound_topology.runtime_compilation
        expected_topology = (_F6_SCOPE_COMPILED_TOPOLOGY_DYNAMIC
            if compilation._boundary_static_validation else _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE)
        topology_ok = (type(topology_validator) is MethodType
            and type(compilation) is _F6ScopeCompiledRuntimePathContract
            and row['topology_ref'] is not None
            and row['topology_ref']() is compilation
            and topology_validator.__func__ is row['topology_function']
            and topology_validator.__self__ is compilation
            and topology_validator.__func__ is expected_topology
            and type(compilation).validate_topology is
                _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE
            and _F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE.__code__ is
                type(compilation).validate_topology.__code__
            and 'validate_topology' not in vars(compilation)
            and 'validate_dynamic_topology' not in vars(compilation)
            and type(compilation).validate_dynamic_topology is _F6_SCOPE_COMPILED_TOPOLOGY_DYNAMIC)
    if (len(nested) != 1 or callback.__code__ is not nested[0]
            or callback.__code__ is not row['nested_code']
            or callback.__code__.co_freevars != row['closure_names']
            or set(closure) != {'admission', 'self', 'topology_validator'}
            or closure['admission'] is not current_admission
            or closure['self'] is not session
            or not topology_ok):
        raise ValueError('F6 DMA route validator is not original')
    return True


def _accepted_word_range_bounds(values):
    """Return accepted range endpoints without iterating the range."""
    if not isinstance(values, range) or not values:
        return None
    if values.step > 0:
        last = values.start + ((values.stop - 1 - values.start) // values.step) * values.step
    else:
        step = -values.step
        last = values.start - ((values.start - 1 - values.stop) // step) * step
    return values.start, last


def _valid_accepted_write_values(values):
    if isinstance(values, tuple):
        return all(type(value) is int and 0 <= value <= 0xffffffff
                   for value in values)
    if isinstance(values, range):
        bounds = _accepted_word_range_bounds(values)
        return (bounds is None or
                (0 <= min(bounds) and max(bounds) <= 0xffffffff))
    return False


def dma_route_endpoint_dynamic_identity(endpoint):
    """Runtime-config fields of the registered DMA adapter, without source JSON.

    Unknown adapters retain the full legacy identity check in the caller.
    """
    if type(endpoint) not in _f6_dma_session_type_allowlist():
        return None
    names = ('command_timeout_seconds', 'source_component', 'max_control_edges', 'max_events')
    return tuple((type(value), value) for value in (getattr(endpoint, name) for name in names))


def dma_route_endpoint_identity_document(endpoint):
    """Return stable route identity without asking a build/cache scanner."""
    def pin_provider(document):
        provider_identity = getattr(endpoint,
            'dma_master_target_provider_identity_document', None)
        if callable(provider_identity):
            document['dma_master_target_provider'] = deepcopy(provider_identity())
        return document

    method = getattr(endpoint, 'dma_route_endpoint_identity_document', None)
    if callable(method):
        return pin_provider(deepcopy(method()))
    artifact_document = getattr(endpoint, '_artifact_document', None)
    if type(artifact_document) is dict:
        artifact = getattr(endpoint, 'artifact', None)
        current = getattr(artifact, 'runtime_document', artifact_document)
        if current != artifact_document:
            raise ValueError('route endpoint artifact changed after session creation')
        return pin_provider(dict(schema_version='generated_local_route_endpoint.v1',
            runtime_artifact=deepcopy(artifact_document)))
    identity = getattr(endpoint, 'identity_document', None)
    if not callable(identity):
        raise ValueError('route endpoint has no stable identity document')
    return pin_provider(deepcopy(identity()))


def _canonical_dma_route_admission_identity(admission):
    """Serialize a detached admission identity for the session's pin."""
    identity = getattr(admission, 'identity_document', None)
    if not callable(identity):
        raise ValueError('DMA route admission must expose identity_document')
    document = identity()
    if type(document) is not dict or type(document.get('schema_version')) is not str:
        raise ValueError('DMA route admission identity document is invalid')
    try:
        return json.dumps(document, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('DMA route admission identity document is not canonical JSON') from error


@dataclass(frozen=True)
class MasterTargetWindow:
    """One explicit 32-bit DMA master destination backed by real target RTL."""

    component: str
    base: int
    size: int
    endpoint: object
    writable_offsets: tuple[int, ...]
    accepted_write_values: tuple[int, ...] | range
    byte_enable: int = 15
    readable_offsets: tuple[int, ...] = ()

    def __post_init__(self):
        if (type(self.component) is not str or not self.component
                or type(self.base) is not int or self.base < 0
                or self.base % 0x1000 or type(self.size) is not int
                or self.size < 4 or self.size % 4
                or self.base + self.size > 1 << 64
                or type(self.writable_offsets) is not tuple
                or any(type(offset) is not int or offset < 0
                       or offset % 4 or offset + 4 > self.size
                       for offset in self.writable_offsets)
                or len(set(self.writable_offsets)) != len(self.writable_offsets)
                or type(self.readable_offsets) is not tuple
                or any(type(offset) is not int or offset < 0
                       or offset % 4 or offset + 4 > self.size
                       for offset in self.readable_offsets)
                or len(set(self.readable_offsets)) != len(self.readable_offsets)
                or not (self.writable_offsets or self.readable_offsets)
                or (self.readable_offsets and
                    (self.component != 'uart' or self.readable_offsets != (0x18,)
                     or not callable(getattr(self.endpoint,
                         'read_register', None))))
                or not isinstance(self.accepted_write_values, (tuple, range))
                or bool(self.accepted_write_values) != bool(self.writable_offsets)
                or not _valid_accepted_write_values(self.accepted_write_values)
                or type(self.byte_enable) is not int or self.byte_enable != 15
                or not callable(getattr(self.endpoint, 'write_register', None))):
            raise ValueError('invalid DMA master target window')

    def contains(self, address):
        return self.base <= address and address + 4 <= self.base + self.size

    def accepts(self, address, write, value, byte_enable):
        return (self.contains(address) and byte_enable == self.byte_enable and
                ((write and address - self.base in self.writable_offsets and
                  value in self.accepted_write_values) or
                 (not write and address - self.base in self.readable_offsets)))

    def identity_document(self):
        values = self.accepted_write_values
        return dict(component=self.component, base=self.base, size=self.size,
            writable_offsets=list(self.writable_offsets),
            accepted_write_values=([values.start, values.stop - 1]
                if isinstance(values, range) and values else list(values)),
            readable_offsets=list(self.readable_offsets),
            byte_enable=self.byte_enable,
            endpoint_identity=self.endpoint.identity_document())

    def route_identity_document(self):
        """Injective v2 identity, kept separate from the historical v1 form."""
        values = self.accepted_write_values
        accepted = ({'kind': 'range', 'start': values.start,
                     'stop': values.stop, 'step': values.step}
                    if isinstance(values, range) else
                    {'kind': 'tuple', 'values': list(values)})
        return dict(schema_version='dma_master_target_window.v2',
            component=self.component, base=self.base, size=self.size,
            writable_offsets=list(self.writable_offsets),
            accepted_write_values=accepted,
            readable_offsets=list(self.readable_offsets),
            byte_enable=self.byte_enable,
            endpoint_identity=dma_route_endpoint_identity_document(self.endpoint))


class GeneratedWishboneDmaSession(GeneratedLocalSession):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if (cls.__module__ !=
                'myfuzz.local_harness.wishbone_dma_scenario_session'
                or cls.__name__ != 'GeneratedWishboneDmaScenarioSession'
                or cls.__qualname__ != 'GeneratedWishboneDmaScenarioSession'):
            return
        base_class = globals().get('_F6_SCOPE_DMA_BASE_CLASS')
        if base_class is None or cls.__bases__ != (base_class,):
            raise TypeError('F6 ScenarioRunner DMA class must directly extend its pinned base')
        pins = globals().get('_F6_SCOPE_DMA_CLASS_PINS')
        if pins is not None and (type(pins) is not tuple or pins[1] is not cls):
            raise TypeError('F6 ScenarioRunner DMA class object was already pinned')
        globals()['_F6_SCOPE_DMA_CLASS_PINS'] = (
            base_class, cls, _class_implementation_pins(cls),
            _class_data_pins(cls))

    def __init__(self, artifact, *, memory=None, memory_service=None,
                 source_component='dma', max_control_edges=32, max_events=10000,
                 master_targets=(),
                 **kwargs):
        super().__init__(artifact, **kwargs)
        if artifact.runtime_document['kind'] != 'wishbone_dma':
            raise ValueError('wishbone_dma artifact required')
        if (memory is None) == (memory_service is None):
            raise ValueError('provide exactly one memory or memory_service')
        if not source_component or type(max_control_edges) is not int or max_control_edges < 4:
            raise ValueError('invalid DMA session bounds')
        if type(max_events) is not int or max_events < 1:
            raise ValueError('invalid DMA event bound')
        if (type(master_targets) is not tuple or
                any(type(window) is not MasterTargetWindow for window in master_targets)):
            raise ValueError('invalid DMA master targets')
        for index, window in enumerate(master_targets):
            if any(window.base < old.base + old.size and
                   old.base < window.base + window.size
                   for old in master_targets[:index]):
                raise ValueError('overlapping DMA master targets')
        self.memory_service = (memory_service if memory_service is not None else
                               MemoryService(memory, TransactionLedger()))
        for window in master_targets:
            if any(window.base < region_base + region_size and
                   region_base < window.base + window.size
                   for region in self.memory_service.memory.identity_document()['regions']
                   for region_base, region_size in
                   ((region['base'], region['size']),
                    *((alias, region['size']) for alias in region['aliases']))):
                raise ValueError('DMA master target overlaps memory')
        self.master_targets = master_targets
        self.source_component = source_component
        self.max_control_edges = max_control_edges
        self.max_events = max_events
        self.events = []
        self._pending = None
        self._source_sequence = 0
        self._quiescing = False
        self._dma_route_validator = None
        self._dma_route_admission = None
        self._dma_route_admission_identity = None
        self._f6_response_fault = None

    def configure_dma_route_validator(self, callback):
        """Pin the compiled topology validator before this session starts."""
        if not callable(callback):
            raise ValueError('DMA route validator must be callable')
        if self._dma_route_validator is not None:
            raise ValueError('DMA route validator is already configured')
        if (self._execution or self._process is not None or self._case_id is not None
                or self.local_ticks != 0 or self.events):
            raise ValueError('DMA route validator must be configured before startup')
        self._dma_route_validator = callback

    def configure_dma_route_admission(self, admission):
        """Install a typed route-beat policy before the DMA process starts."""
        if (not callable(getattr(admission, 'accepted', None))
                or not callable(getattr(admission, 'completed', None))):
            raise ValueError('DMA route admission must implement accepted/completed')
        if self._dma_route_admission is not None:
            raise ValueError('DMA route admission is already configured')
        if (self._execution or self._process is not None or self._case_id is not None
                or self.local_ticks != 0 or self.events):
            raise ValueError('DMA route admission must be configured before startup')
        from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
        from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
        if (type(admission) is DmaMasterRouteAdmission
                and type(admission._beat_policy) is F6RamDmaPolicy):
            if type(self) not in _f6_dma_session_type_allowlist():
                raise ValueError('F6 DMA session class is not registered')
            registrar = globals().get('_F6_ROUTE_VALIDATOR_REGISTRAR')
            if (registrar is None
                    or globals().get('_register_f6_route_validator') is not registrar
                    or registrar.__code__ is not
                        globals().get('_F6_ROUTE_VALIDATOR_REGISTRAR_CODE')):
                raise ValueError('F6 DMA route validator registrar drift')
        identity_snapshot = _canonical_dma_route_admission_identity(admission)
        self._dma_route_admission = admission
        self._dma_route_admission_identity = identity_snapshot
        topology_validator = self._dma_route_validator

        def validate_pinned_route_admission():
            if self._dma_route_admission is not admission:
                raise ValueError('compiled DMA route admission changed')
            if (_canonical_dma_route_admission_identity(admission)
                    != self._dma_route_admission_identity):
                raise ValueError('compiled DMA route admission identity changed')
            if topology_validator is not None:
                topology_validator()

        self._dma_route_validator = validate_pinned_route_admission
        _register_f6_route_validator(self, admission,
            validate_pinned_route_admission, topology_validator)

    def dma_route_endpoint_identity_document(self):
        """Stable DMA master profile identity without build/cache inspection."""
        self._check_artifact_stable()
        return dict(schema_version='wishbone_dma_route_endpoint.v1',
            runtime_artifact=deepcopy(self._artifact_document),
            command_timeout_seconds=self.command_timeout_seconds,
            source_component=self.source_component,
            max_control_edges=self.max_control_edges,
            max_events=self.max_events, address_shift=2,
            byte_enable=('mwb_sel' if self._artifact_document.get('dma_edge_contract', {}).get('master_byte_enable_signal')
                == 'mwb_sel' else 15), max_outstanding=1)

    def _validate_dma_route_topology(self):
        if self._dma_route_validator is not None:
            self._dma_route_validator()

    @property
    def pending_responses(self):
        return int(self._pending is not None)

    def begin_case(self, testcase_id):
        self._validate_dma_route_topology()
        super().begin_case(testcase_id)
        self._pending = None
        self._source_sequence = 0
        self._quiescing = False
        self.events = []
        if self._dma_route_admission is not None:
            begin_case = getattr(self._dma_route_admission, 'begin_case', None)
            if callable(begin_case):
                begin_case(self._execution, self._case_id)
        fault = _validate_f6_response_fault(self)
        if fault is not None:
            fault.begin_case(0)

    def _advance_f6_logical_case(self, *, testcase_id, case_index,
                                 previous_case_index, expected_case_id,
                                 used_testcase_ids, expected_process,
                                 expected_process_id, expected_execution,
                                 expected_reset_epoch, route_matches_snapshot,
                                 policy_records_snapshot, _issuer=None):
        """Advance only F6's DMA transaction scope on the existing process.

        The runtime coordinator supplies a snapshot only after Task5 has frozen
        the completed case inventory and authenticated the CPU boundary. This
        method rechecks its DMA-local preconditions, then changes the logical
        testcase id and per-case source sequence without touching transport,
        process, clock, RAM, ledger, or cumulative event history.
        """
        if _issuer is not _F6_SCOPE_TRANSITION_ISSUER:
            raise ValueError('F6 DMA logical scope requires the runtime coordinator')
        from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
        from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
        from myfuzz.scenario.native_f6_isr_return import F6IsrReturnIssuer

        if (type(self) not in _f6_dma_session_type_allowlist()
                or type(testcase_id) is not str or not testcase_id
                or testcase_id.strip() != testcase_id
                or type(case_index) is not int or not 1 <= case_index < 16
                or type(previous_case_index) is not int
                or case_index != previous_case_index + 1
                or type(expected_case_id) is not str
                or expected_case_id != self._case_id
                or type(used_testcase_ids) is not tuple
                or any(type(item) is not str or not item for item in used_testcase_ids)
                or len(set(used_testcase_ids)) != len(used_testcase_ids)
                or expected_case_id not in used_testcase_ids
                or testcase_id in used_testcase_ids
                or expected_process is None or self._process is not expected_process
                or type(expected_process_id) is not int or expected_process_id < 1
                or getattr(self._process, 'pid', None) != expected_process_id
                or type(expected_execution) is not str
                or self._execution != expected_execution
                or type(expected_reset_epoch) is not int
                or self.reset_epoch != expected_reset_epoch
                or type(self._execution) is not str or not self._execution
                or type(self._case_id) is not str or not self._case_id
                or self._pending is not None or self.pending_responses
                or self._source_sequence < 0
                or self.memory_service.ledger.pending_keys
                or self.memory_service.ledger.unresolved_keys):
            raise ValueError('F6 DMA logical scope is not at a settled live boundary')

        if (type(self)._advance_f6_logical_case is not
                _F6_SCOPE_TRANSITION_METHOD
                or '_advance_f6_logical_case' in vars(self)):
            raise ValueError('f6-case-owner-method-drift')

        try:
            process_status = self._process.poll()
        except BaseException as error:
            raise ValueError('F6 DMA logical scope native identity is uncertain') from error
        if process_status is not None:
            raise ValueError('F6 DMA logical scope native identity is not live')

        admission = self._dma_route_admission
        if (type(admission) is not DmaMasterRouteAdmission
                or type(admission._beat_policy) is not F6RamDmaPolicy):
            raise ValueError('F6 DMA logical scope requires the registered route/policy pair')
        policy = admission._beat_policy
        if (DmaMasterRouteAdmission.begin_case is not _F6_SCOPE_ADMISSION_BEGIN
                or DmaMasterRouteAdmission.begin_case.__code__ is not
                    _F6_SCOPE_ADMISSION_BEGIN.__code__
                or 'begin_case' in getattr(admission, '__dict__', {})
                or F6RamDmaPolicy.begin_case is not _F6_SCOPE_POLICY_BEGIN
                or F6RamDmaPolicy.begin_case.__code__ is not
                    _F6_SCOPE_POLICY_BEGIN.__code__
                or 'begin_case' in vars(policy)
                or F6IsrReturnIssuer.begin_case is not _F6_SCOPE_ISR_BEGIN
                or F6IsrReturnIssuer.begin_case.__code__ is not
                    _F6_SCOPE_ISR_BEGIN.__code__):
            raise ValueError('f6-case-owner-method-drift')
        _verify_f6_dma_route_validator(self, admission=admission)
        if (type(case_index) is not int or case_index != previous_case_index + 1
                or policy._scope != (self._execution, self._case_id)):
            raise ValueError('F6 DMA logical scope case index or policy scope drift')
        if (policy.state not in ('idle', 'complete')
                or policy._pending is not None
                or policy.records != policy_records_snapshot
                or admission.route_matches != route_matches_snapshot):
            raise ValueError('F6 DMA logical scope evidence or policy is not settled')
        self._validate_dma_route_topology()

        fault = _validate_f6_response_fault(self)
        if fault is not None:
            if (fault._selected is not None or fault._active is not None
                    or fault._case_index != previous_case_index):
                raise ValueError('F6 DMA logical scope cannot advance an active/selected fault')
            new_scope = (self._execution, testcase_id, self.source_component,
                         self.reset_epoch)
            if fault._scope == new_scope or fault._scope != (
                    self._execution, self._case_id, self.source_component,
                    self.reset_epoch):
                raise ValueError('F6 DMA logical scope must use a new transaction identity')

        # All owners are now preflighted. These changes are local, synchronous
        # cursor transitions; keep rollback snapshots in case an owner method
        # has drifted from its preflight contract.
        old_case_id = self._case_id
        old_source_sequence = self._source_sequence
        old_matches = admission._route_matches.copy()
        old_policy = deepcopy(policy.__dict__)
        old_fault = None if fault is None else {
            name: getattr(fault, name) for name in
            ('_case_index', '_scope', '_counts', '_selected', '_active')}
        try:
            self._case_id = testcase_id
            self._source_sequence = 0
            admission.begin_case(self._execution, testcase_id)
            if fault is not None:
                fault.begin_case(case_index)
        except BaseException:
            self._case_id = old_case_id
            self._source_sequence = old_source_sequence
            admission._route_matches = old_matches
            policy.__dict__.clear()
            policy.__dict__.update(old_policy)
            if fault is not None:
                for name, value in old_fault.items():
                    object.__setattr__(fault, name, value)
            raise
        return dict(testcase_id=testcase_id, case_index=case_index,
            execution_id=self._execution, reset_epoch=self.reset_epoch,
            route_matches=route_matches_snapshot,
            policy_records=policy_records_snapshot)

    def begin_quiesce(self):
        self._quiescing = True

    def _deliver_target(self, key, target, address, write, value, byte_enable=15):
        before_tick = target.endpoint.local_ticks
        before_events = GeneratedWishboneDmaSession._target_event_count(target.endpoint)
        rdata = 0
        observation = None
        route_mode = None
        provider_receipt = None
        if write:
            provider = getattr(target.endpoint, 'dma_master_target_access', None)
            if callable(provider):
                delivery_context = dict(source_transaction=asdict(key),
                    device_id=target.component, address=address,
                    offset=address-target.base, write=True, value=value, be=byte_enable,
                    window_base=target.base, window_size=target.size)
                provider_receipt = provider(key, address=address,
                    offset=address-target.base, write=True, value=value,
                    byte_enable=byte_enable, delivery_context=deepcopy(delivery_context))
                self._validate_dma_master_target_provider_receipt(key,
                    provider_receipt, address=address,
                    offset=address-target.base, write=True, value=value,
                    byte_enable=byte_enable)
                rdata = provider_receipt['response']['rdata']
                observation = provider_receipt['target_access']
                route_mode = 'dma_master_target_access.v1'
            else:
                target.endpoint.write_register(address-target.base, value, be=byte_enable)
        else:
            master_access = (getattr(target.endpoint, 'master_target_access', None)
                if getattr(target.endpoint, 'source_provenance_enabled', False)
                else None)
            if callable(master_access):
                # S4: the DMA master read carries its own transaction identity,
                # so the UART pop can be authenticated instead of being an
                # unattributed ``read_register``.  The endpoint returns the very
                # same measured ``uart_rdata_access`` record.
                delivery_context = dict(source_transaction=asdict(key),
                    device_id=target.component, address=address,
                    offset=address-target.base, write=False, value=0, be=byte_enable,
                    window_base=target.base, window_size=target.size)
                reply = master_access(key, address=address,
                    offset=address-target.base, write=False, value=0, be=byte_enable,
                    delivery_context=delivery_context)
                rdata = reply['rdata']
                observation = reply.get('target_uart_access')
                route_mode = 'dma_master'
                if (not isinstance(observation, dict)
                        or observation.get('status') != 'observed'
                        or observation.get('read_value') != rdata):
                    raise RuntimeError(
                        'DMA UART RDATA read lacks real FIFO pop proof')
            else:
                rdata = target.endpoint.read_register(address-target.base)
                new_reads = [row for row in target.endpoint.uart_events[before_events:]
                    if row.get('kind') == 'uart_rdata_access']
                observation = new_reads[0] if len(new_reads) == 1 else None
                if (type(rdata) is not int or not 0 <= rdata <= 255
                        or type(observation) is not dict
                        or observation.get('status') != 'observed'
                        or observation.get('read_value') != rdata
                        or type(observation.get('access_id')) is not str
                        or not observation['access_id']
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_rvalid') != 1
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_rdata_re') != 1
                        or observation.get('read_capture', {}).get('pre', {}).get(
                            'probe_uart_fifo_under_rst') != 0):
                    raise RuntimeError('DMA UART RDATA read lacks real FIFO pop proof')
        target_receipt = dict(source_transaction=asdict(key),
            target_component=target.component, address=address,
            offset=address-target.base, write=write,
            value=value if write else rdata, byte_enable=byte_enable,
            target_tick_before=before_tick,
            target_tick_after=target.endpoint.local_ticks,
            target_event_range=[before_events,
                GeneratedWishboneDmaSession._target_event_count(target.endpoint)])
        if provider_receipt is not None:
            target_receipt.update(target_access_id=provider_receipt['target_access_id'],
                target_provider_receipt=deepcopy(provider_receipt),
                target_route_context_mode=route_mode)
        elif not write:
            target_receipt['target_access_id'] = observation['access_id']
            target_receipt['target_uart_access'] = observation
            target_receipt['target_route_context_mode'] = route_mode
        return rdata, target_receipt

    @staticmethod
    def _target_event_count(endpoint):
        for name in ('uart_events', 'gpio_events'):
            events = getattr(endpoint, name, None)
            if isinstance(events, (tuple, list)):
                return len(events)
        return 0

    @staticmethod
    def _validate_dma_master_target_provider_receipt(key, receipt, *,
            address, offset, write, value, byte_enable):
        required = {'schema_version', 'status', 'source_transaction',
            'request', 'response', 'target_access_id', 'target_access',
            'target_request', 'target_response', 'target_effect'}
        if (type(receipt) is not dict or set(receipt) != required
                or receipt.get('schema_version') != 'dma_master_target_access.v1'
                or receipt.get('status') != 'observed'):
            raise RuntimeError('DMA target provider receipt schema/status mismatch')
        key_document = asdict(key)

        def exact_identity(left, right):
            return (type(left) is dict and set(left) == set(right)
                and all(type(left[name]) is type(expected)
                        and left[name] == expected
                        for name, expected in right.items()))

        if not exact_identity(receipt.get('source_transaction'), key_document):
            raise RuntimeError('DMA target provider transaction key mismatch')
        expected_request = dict(address=address, offset=offset, write=write,
            value=value if write else 0, byte_enable=byte_enable)
        if not exact_identity(receipt.get('request'), expected_request):
            raise RuntimeError('DMA target provider request mismatch')
        response = receipt.get('response')
        if (type(response) is not dict or set(response) != {'rdata', 'error'}
                or type(response.get('rdata')) is not int
                or not 0 <= response['rdata'] <= 0xffffffff
                or type(response.get('error')) is not int
                or response['error'] != 0):
            raise RuntimeError('DMA target provider target response is invalid')
        access_id = receipt.get('target_access_id')
        if type(access_id) is not str or not access_id:
            raise RuntimeError('DMA target provider target evidence lacks access identity')
        for name in ('target_access', 'target_request', 'target_response'):
            witness = receipt.get(name)
            if (type(witness) is not dict or witness.get('status') != 'observed'
                    or not exact_identity(witness.get('source_transaction'), key_document)):
                raise RuntimeError('DMA target provider target evidence is incomplete')
            if (type(witness.get('access_id')) is not str
                    or witness['access_id'] != access_id):
                raise RuntimeError(
                    'DMA target provider target evidence access identity mismatch')
        if receipt['target_access'].get('access_id') != access_id:
            raise RuntimeError('DMA target provider target evidence access identity mismatch')
        effect = receipt.get('target_effect')
        if (type(effect) is not dict or effect.get('status') != 'observed'
                or not exact_identity(effect.get('source_transaction'), key_document)
                or not exact_identity(effect.get('request'), expected_request)):
            raise RuntimeError('DMA target provider target effect is incomplete')
        if (type(effect.get('access_id')) is not str
                or effect['access_id'] != access_id):
            raise RuntimeError(
                'DMA target provider target evidence access identity mismatch')

    def step_local(self, *, cyc=0, stb=0, we=0, adr=0, data=0, sel=15):
        _validate_f6_response_fault(self)
        self._validate_dma_route_topology()
        if len(self.events) >= self.max_events:
            raise RuntimeError('DMA edge event capacity exhausted')
        pending = self._pending
        stall = int(pending is not None or self._quiescing)
        deliver = pending is not None and pending['delay'] == 0
        ack = int(deliver and not pending['error'])
        err = int(deliver and pending['error'])
        edge_contract=self._artifact_document.get('dma_edge_contract', {})
        control_selected = edge_contract.get('control_byte_enable_signal') == 'swb_sel'
        master_selected = edge_contract.get('master_byte_enable_signal') == 'mwb_sel'
        if not control_selected and sel != 15:
            raise ValueError('DMA without SEL requires full-word control')
        fields = (cyc, stb, we, adr, data) + ((sel,) if control_selected else ()) + (stall, ack, pending['rdata'] if pending else 0, err)
        receipt = self.command(edge_contract['operation'], fields)
        if receipt.status != 'result' or receipt.new_ticks != 1:
            raise RuntimeError('DMA edge did not complete')
        payload = receipt.payload
        pre = payload['pre_backend']
        event = dict(kind='dma_edge', tick=receipt.tick_after, payload=payload)
        if pending is not None and not deliver:
            pending['delay'] -= 1
        if deliver:
            from myfuzz.scenario.memory_service import _complete_f6_dma_read
            _complete_f6_dma_read(self, pending, receipt)
            event['response'] = dict(pending)
            self._pending = None
        if pre['mwb_cyc'] and pre['mwb_stb'] and not stall:
            byte_enable = pre['mwb_sel'] if master_selected else 15
            self._source_sequence += 1
            key = TransactionKey(self._execution, self._case_id,
                self.source_component, self.reset_epoch, 'dma-memory', self._source_sequence)
            address = pre['mwb_adr'] << 2
            accepted = dict(transaction=asdict(key), address=address,
                word_address=pre['mwb_adr'], write=bool(pre['mwb_we']),
                value=pre['mwb_dat_w'], byte_enable=byte_enable)
            # Reject invalid resources before any service callback. Other failures
            # propagate; they must never be disguised as a peripheral bus error.
            target = next((window for window in self.master_targets
                           if window.contains(address)), None)
            admission = self._dma_route_admission
            if admission is not None:
                admission.accepted(key, address=address,
                    write=bool(pre['mwb_we']), value=pre['mwb_dat_w'],
                    byte_enable=byte_enable, target=target)
            invalid = False
            if target is None:
                try:
                    if pre['mwb_we']:
                        self.memory_service.memory.validate_write(
                            address,pre['mwb_dat_w'],width_bytes=4,byte_enable=byte_enable)
                    else:
                        self.memory_service.memory.validate_read(address,4)
                except ValueError as error:
                    if str(error) not in ('unmapped address; MMIO requires real IP response',
                                          'access crosses memory window',
                                          'read-only memory', 'write-only memory'):
                        raise
                    invalid = True
            else:
                invalid = not target.accepts(address, bool(pre['mwb_we']),
                                             pre['mwb_dat_w'], byte_enable)
                if invalid:
                    accepted['target_rejection'] = 'declared_master_target_access'
            selected_fault = False
            if not invalid and self._f6_response_fault is not None:
                # This closed selector sees only a real PRE key already admitted
                # by the pinned live route. Resource checks above have no effect.
                self._validate_dma_route_topology()
                selected_fault = _select_f6_response_fault(self, key,
                    operation='write' if pre['mwb_we'] else 'read')
            rdata = 0
            if selected_fault:
                fault_document = self._f6_response_fault.document()
                error_payload = dict(op='master_environment_error',
                    address=address, write=bool(pre['mwb_we']),
                    value=pre['mwb_dat_w'], byte_enable=byte_enable,
                    reason='declared_f6_response_fault',
                    selector=fault_document['selector'],
                    execution_binding_sha256=fault_document['execution_binding_sha256'])
                event['environment_error_receipt'] = self.memory_service.ledger.execute_once(
                    key, error_payload, lambda: dict(
                        schema_version='f6_dma_environment_error_receipt.v1',
                        owner=self.source_component, source_transaction=asdict(key),
                        error=1, target_effect=False, timing='before_target_effect',
                        **error_payload))
                # Error completion must never enter the policy's success branch.
                admission.completed(key, rdata=0, error=1)
            elif invalid:
                # ERR completes a real accepted master request even though no
                # target is touched. Enroll it in the same channel as successful
                # operations so later requests retain contiguous source order.
                rejected_payload = dict(op='master_environment_error',
                    address=address, write=bool(pre['mwb_we']),
                    value=pre['mwb_dat_w'], byte_enable=byte_enable,
                    reason=accepted.get('target_rejection', 'memory_access_rejected'))
                event['environment_error_receipt'] = self.memory_service.ledger.execute_once(
                    key, rejected_payload, lambda: dict(source_transaction=asdict(key),
                        error=1, target_effect=False, **rejected_payload))
            else:
                # Revalidate immediately before the configured target/service
                # can observe this accepted native DMA request.
                self._validate_dma_route_topology()
                if target is not None:
                    write = bool(pre['mwb_we'])
                    target_payload = dict(op='master_target_write' if write
                        else 'master_target_read', address=address,
                        value=pre['mwb_dat_w'] if write else 0,
                        byte_enable=byte_enable, target_component=target.component,
                        target_offset=address-target.base)
                    rdata, target_receipt = self.memory_service.ledger.execute_once(
                        key, target_payload, lambda: self._deliver_target(
                            key, target, address, write, pre['mwb_dat_w'], byte_enable))
                    accepted['target_delivery'] = target_receipt
                    event['target_delivery'] = target_receipt
                elif pre['mwb_we']:
                    self.memory_service.write(key,address,pre['mwb_dat_w'],width_bytes=4,byte_enable=byte_enable)
                else:
                    from myfuzz.scenario.memory_service import _arm_f6_dma_read
                    _arm_f6_dma_read(self, key)
                    rdata = self.memory_service.read(key,address,width_bytes=4).value
                if admission is not None:
                    admission.completed(key, rdata=rdata, error=0)
            # This pinned RTL registers its last-write ACK predictor. Give the
            # observed end of a write burst one extra settling edge. Uniform
            # latency environments are not verified by this session contract.
            self._pending = dict(transaction=asdict(key), rdata=rdata,error=int(invalid or selected_fault),delay=int(bool(pre['mwb_we'] and not
                payload['observations']['backend']['mwb_stb'])))
            event['accepted'] = accepted
        self.events.append(event)
        self.memory_service.memory.advance_step()
        return receipt

    def _access_register(self, offset, value, write, byte_enable):
        edge_contract=self._artifact_document.get('dma_edge_contract', {})
        selected = edge_contract.get('control_byte_enable_signal') == 'swb_sel'
        window=self.artifact.plan.profile.address.window_size
        if (type(offset) is not int or offset < 0 or offset % 4 or offset+4 > window
                or offset//4 > edge_contract['input_maxima'][3] or type(byte_enable) is not int
                or not 1 <= byte_enable <= 15 or not selected and byte_enable != 15):
            raise ValueError('DMA control requires aligned offset and supported byte enable')
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('DMA register value exceeds 32 bits')
        select = {'sel': byte_enable} if selected else {}
        accepted = False
        for _ in range(self.max_control_edges-1):
            receipt = self.step_local(cyc=1,stb=int(not accepted),we=int(write),
                                      adr=offset//4,data=value,**select)
            pre = receipt.payload['pre_backend']
            previously_accepted = accepted
            if not accepted and pre['swb_stall'] == 0:
                accepted = True
            if pre['swb_ack']:
                if not previously_accepted:
                    raise RuntimeError('DMA control ACK before registered acceptance')
                result = pre['swb_dat_r']
                self.step_local()
                return result
        raise TimeoutError('DMA control acceptance or ACK edge bound exceeded')

    routed_register_access_enabled = True

    def routed_register_access(self, key, *, address, offset, write, value, be,
                               delivery_context):
        """Translate one router-admitted CPU beat into measured real control edges.

        This is transaction-level routing between independent processes, not a
        claim of a synthesizable OBI/Wishbone bridge or shared hardware clock.
        """
        if not isinstance(key, TransactionKey) or type(write) is not bool:
            raise ValueError('DMA routed access requires a source transaction')
        start = len(self.events)
        rdata = self._access_register(offset,value,write,be)
        receipt = dict(source_transaction=asdict(key), address=address,
            offset=offset, write=write, value=value, byte_enable=be,
            delivery_context=deepcopy(delivery_context),
            edge_ticks=[event['tick'] for event in self.events[start:]])
        return dict(rdata=rdata, dma_control_receipt=receipt)

    def write_register(self, offset, value, *, byte_enable=15):
        return self._access_register(offset,value,True,byte_enable)

    def read_register(self, offset):
        return self._access_register(offset,0,False,15)

    def reset_local(self):
        cancelled = self.pending_responses
        super().reset_local()
        return dict(cancelled_responses=cancelled)

    def close(self):
        self.end_case()

    def identity_document(self):
        document = super().identity_document()
        document['dma_environment'] = dict(max_outstanding=1,
            response_delay_edges=1,
            write_burst_tail_extra_delay_edges=1, control_edge_bound=self.max_control_edges,
            max_events=self.max_events, address_shift=2,
            byte_enable=('mwb_sel' if self._artifact_document.get('dma_edge_contract', {}).get('master_byte_enable_signal')
                == 'mwb_sel' else 15),
            source_component=self.source_component)
        if self.master_targets:
            document['dma_environment']['master_targets'] = [
                window.identity_document() for window in self.master_targets]
        return document


# Pin all logical-scope transition owners before any live campaign can start.
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission as _F6ScopeAdmission
from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy as _F6ScopePolicy
from myfuzz.scenario.native_f6_isr_return import F6IsrReturnIssuer as _F6ScopeIsr
from myfuzz.local_harness.f6_dma_response_fault import F6ResponseFault as _F6ScopeFault
_F6_SCOPE_ADMISSION_BEGIN = _F6ScopeAdmission.begin_case
_F6_SCOPE_POLICY_BEGIN = _F6ScopePolicy.begin_case
_F6_SCOPE_ISR_BEGIN = _F6ScopeIsr.begin_case
_F6_SCOPE_FAULT_BEGIN = _F6ScopeFault.begin_case
_F6_SCOPE_DMA_BASE_CLASS = GeneratedWishboneDmaSession
_F6_SCOPE_DMA_CLASS_PINS = None
_F6_SCOPE_COMPILED_TOPOLOGY_DYNAMIC = _F6ScopeCompiledRuntimePathContract.validate_dynamic_topology
_F6_SCOPE_COMPILED_TOPOLOGY_VALIDATE = (
    _F6ScopeCompiledRuntimePathContract.validate_topology)
_F6_SCOPE_TRANSITION_METHOD = GeneratedWishboneDmaSession._advance_f6_logical_case
_F6_SESSION_METHOD_PINS = {
    name: getattr(GeneratedWishboneDmaSession, name) for name in (
        'configure_dma_route_admission', 'configure_dma_route_validator',
        '_validate_dma_route_topology')}

# Seal generated methods at module load, before callers can request a fault.
_seal_f6_dma_session(GeneratedWishboneDmaSession)
from myfuzz.scenario.memory_service import _seal_f6_dma_read_provider
_seal_f6_dma_read_provider(GeneratedWishboneDmaSession)
