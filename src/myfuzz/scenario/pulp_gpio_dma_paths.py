"""Prepared runtime route graph for one RAM word delivered to PULP PADOUT.

The graph declares a RAM image word, the DMA's typed RAM read, its ordered
internal transfer, and a typed DMA write to PULP GPIO PADOUT. Compilation
binds these declarations to the live DMA memory service, its exact target
window, and the registered GPIO session. This is topology evidence only; it
does not claim that a DMA transaction or APB effect has occurred.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from myfuzz.local_harness.wishbone_dma_session import (
    MasterTargetWindow, dma_route_endpoint_identity_document,
)
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
from myfuzz.scenario.ledger import TransactionKey

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource, SourceBinding, SourceBindings)
from .ledger import TransactionLedger
from .memory import PersistentMemory
from .memory_service import MemoryService
from .dma_route_admission import DmaMasterRouteAdmission
from .runtime_path_contract import (
    CompiledRuntimePathContract, DmaMasterRouteContract,
    PreparedRuntimePathContract,
    RuntimeEdgeContract, RuntimeNode, RuntimePathContract,
    canonical_runtime_identity_sha256, persistent_memory_route_identity_document,
)

RAM_SOURCE_NODE = 'ram.source_word'
DMA_READ_NODE = 'dma.read_data'
DMA_WRITE_NODE = 'dma.write_data'
GPIO_PADOUT_NODE = 'gpio.padout_effect'
GPIO_PADOUT_OFFSET = 0x0C
DMA_READ_ENDPOINT = 'read_master'
DMA_WRITE_ENDPOINT = 'write_master'
DEFAULT_DIRECTION = 'CPU_TO_IP'

RULES = (
    (DMA_READ_NODE, (RAM_SOURCE_NODE,), 'DMA_MASTER_TRANSFER'),
    (DMA_WRITE_NODE, (DMA_READ_NODE,), 'EVENT_ORDER'),
    (GPIO_PADOUT_NODE, (DMA_WRITE_NODE,), 'DMA_MASTER_TRANSFER'),
)


class PulpGpioDmaBeatAdmission:
    """Admit exactly one RAM-word read followed by its PADOUT write."""

    __slots__ = ('_image_address', '_gpio_window', '_write_address', '_state',
                 '_pending_key', '_read_value', '_route_config_frozen')
    _ROUTE_CONFIG_FIELDS = frozenset((
        '_image_address', '_gpio_window', '_write_address', '_route_config_frozen'))

    def __setattr__(self, name, value):
        if getattr(self, '_route_config_frozen', False) and name in self._ROUTE_CONFIG_FIELDS:
            raise AttributeError('PULP DMA route configuration is read-only')
        object.__setattr__(self, name, value)

    def __init__(self, *, image_address, gpio_window):
        if (type(image_address) is not int or image_address < 0
                or image_address % 4 or image_address + 4 > 1 << 64):
            raise ValueError('PULP DMA image address must be an aligned word address')
        if (type(gpio_window) is not MasterTargetWindow
                or gpio_window.byte_enable != 15
                or gpio_window.readable_offsets
                or gpio_window.writable_offsets != (GPIO_PADOUT_OFFSET,)
                or not gpio_window.accepted_write_values
                or GPIO_PADOUT_OFFSET + 4 > gpio_window.size):
            raise ValueError('PULP DMA admission requires the declared PADOUT window')
        self._route_config_frozen = False
        self._image_address = image_address
        self._gpio_window = gpio_window
        self._write_address = gpio_window.base + GPIO_PADOUT_OFFSET
        self.begin_case('', '')
        self._route_config_frozen = True

    @property
    def image_address(self):
        return self._image_address

    @property
    def gpio_window(self):
        return self._gpio_window

    @property
    def write_address(self):
        return self._write_address

    def identity_document(self):
        """Return a detached canonical identity for the selected beat policy."""
        return {
            'schema_version': 'pulp_gpio_dma_beat_admission_identity.v1',
            'profile': 'pulp_gpio_ram_word_to_padout.v1',
            'source': {
                'operation': 'read', 'address': self._image_address,
                'word_bytes': 4, 'byte_enable': 15},
            'target': {
                'operation': 'write', 'address': self._write_address,
                'offset': GPIO_PADOUT_OFFSET,
                'window': self._gpio_window.route_identity_document()},
            'transfer': {'word_count': 1, 'write_value': 'read_response'},
        }

    @property
    def state(self):
        return self._state

    def begin_case(self, _execution_id, _testcase_id):
        self._state = 'expect_read'
        self._pending_key = None
        self._read_value = None

    def accepted(self, key, *, address, write, value, byte_enable, target):
        if type(key) is not TransactionKey:
            raise ValueError('PULP DMA path requires a typed transaction key')
        if (type(address) is not int or type(write) is not bool
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(byte_enable) is not int or byte_enable != 15):
            raise ValueError('PULP DMA path requires an aligned full-word beat')
        if self._state == 'expect_read':
            if (write or address != self.image_address or target is not None):
                raise ValueError('PULP DMA path expected the declared RAM image word read')
            self._state = 'read_pending'
            self._pending_key = key
            return
        if self._state == 'expect_write':
            if (not write or address != self.write_address
                    or target is not self.gpio_window
                    or value != self._read_value
                    or not self.gpio_window.accepts(address, True, value, byte_enable)):
                if target is not self.gpio_window or address != self.write_address:
                    raise ValueError('PULP DMA path expected the declared PADOUT window')
                raise ValueError('PULP DMA PADOUT value must equal the same word read from RAM')
            self._state = 'write_pending'
            self._pending_key = key
            return
        if self._state == 'complete':
            raise ValueError('PULP DMA single word route is complete')
        raise ValueError('PULP DMA path received a beat before its previous response')

    def completed(self, key, *, rdata, error):
        if (key is not self._pending_key or type(rdata) is not int
                or not 0 <= rdata <= 0xffffffff or type(error) is not int
                or error != 0):
            raise ValueError('PULP DMA path response does not match admitted beat')
        if self._state == 'read_pending':
            self._read_value = rdata
            self._state = 'expect_write'
            self._pending_key = None
            return
        if self._state == 'write_pending':
            self._state = 'complete'
            self._pending_key = None
            return
        raise ValueError('PULP DMA path received an unexpected response')


PulpGpioD4RouteAdmission = DmaMasterRouteAdmission


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_aperture(base: int, size: int, label: str) -> None:
    if (type(base) is not int or base < 0 or base % 0x1000
            or type(size) is not int or size < 4 or size % 4
            or base + size > 1 << 64):
        raise ValueError(f'invalid declared {label} aperture')


def _route_declarations(runner, *, gpio_base, gpio_size, memory_component,
                        resource_id, image_id, direction):
    sessions = getattr(runner, 'sessions', None)
    if type(sessions) is not dict:
        raise ValueError('runner sessions are required for PULP DMA routes')
    dma = sessions.get('dma')
    memory_session = sessions.get(memory_component)
    if dma is None or memory_session is None:
        raise ValueError('DMA and RAM owner sessions are required')

    service = getattr(dma, 'memory_service', None)
    memory = getattr(service, 'memory', None)
    if (not isinstance(service, MemoryService)
            or not isinstance(service.ledger, TransactionLedger)
            or not isinstance(memory, PersistentMemory)
            or getattr(memory_session, 'memory', None) is not memory):
        raise ValueError('DMA RAM route requires the exact shared memory service/resource')
    regions = [region for region in memory._regions
               if region.memory_id == resource_id]
    if len(regions) != 1:
        raise ValueError('DMA source RAM region is missing or ambiguous')
    region = regions[0]
    if not region.readable:
        raise ValueError('DMA source RAM region is not readable')
    ram_base, ram_size = region.base, region.size
    ram_identity = persistent_memory_route_identity_document(
        memory, memory_id=resource_id, base=ram_base, size=ram_size)

    windows = getattr(dma, 'master_targets', None)
    if (type(windows) is not tuple
            or any(type(window) is not MasterTargetWindow for window in windows)):
        raise ValueError('DMA master target windows must be an immutable typed tuple')
    matches = [window for window in windows
               if (window.base, window.size) == (gpio_base, gpio_size)]
    if len(matches) != 1:
        raise ValueError('PULP GPIO DMA master window is missing or ambiguous')
    window = matches[0]
    gpio = sessions.get(window.component)
    if (not window.component or gpio is None or window.endpoint is not gpio):
        raise ValueError('PULP GPIO DMA window endpoint is not the registered session')
    if not callable(getattr(gpio, 'dma_master_target_access', None)):
        raise ValueError('PULP GPIO endpoint lacks dma_master_target_access')
    if getattr(gpio, 'routed_register_access_enabled', False) is not True:
        raise ValueError('PULP GPIO DMA target requires the measured APB observation contract')
    provider_identity = getattr(gpio,
        'dma_master_target_provider_identity_document', None)
    if not callable(provider_identity):
        raise ValueError('PULP GPIO DMA target lacks a versioned provider identity')
    expected_provider = {
        'schema_version': 'pulp_gpio_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'pulp_gpio_padout_apb3.v1',
        'observation_contract': pulp_gpio_observation_contract(),
        'operations': [{'operation': 'write', 'register': 'PADOUT',
                        'offset': GPIO_PADOUT_OFFSET, 'byte_enable': 15}],
    }
    if provider_identity() != expected_provider:
        raise ValueError('PULP GPIO DMA provider identity is unsupported')
    gpio_artifact = getattr(gpio, 'artifact', None)
    gpio_runtime = getattr(gpio_artifact, 'runtime_document', None)
    if (type(gpio_runtime) is not dict or gpio_runtime.get('kind') != 'apb_gpio'
            or gpio_runtime.get('gpio_observation_contract')
                != pulp_gpio_observation_contract()):
        raise ValueError('PULP GPIO DMA target observation artifact is not pinned')
    if (window.writable_offsets != (GPIO_PADOUT_OFFSET,)
            or window.readable_offsets
            or window.byte_enable != 15
            or not window.accepted_write_values):
        raise ValueError('PULP GPIO DMA window must declare only full-word PADOUT writes')

    endpoint_identity = dma_route_endpoint_identity_document(dma)
    endpoint_sha = canonical_runtime_identity_sha256(endpoint_identity)
    ram_route = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id=RAM_SOURCE_NODE, target_node_id=DMA_READ_NODE,
        initiator_component='dma', endpoint_id=DMA_READ_ENDPOINT,
        endpoint_identity_sha256=endpoint_sha,
        target_kind='persistent_memory', target_component=memory_component,
        target_id=resource_id, base=ram_base, size=ram_size,
        operation='read',
        permissions=tuple(sorted((['read'] if region.readable else [])
                                 + (['write'] if region.writable else []))),
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(),
        target_identity_sha256=canonical_runtime_identity_sha256(ram_identity))

    gpio_identity = window.route_identity_document()
    gpio_route = DmaMasterRouteContract(
        rule_index=2, prerequisite_index=0,
        source_node_id=DMA_WRITE_NODE, target_node_id=GPIO_PADOUT_NODE,
        initiator_component='dma', endpoint_id=DMA_WRITE_ENDPOINT,
        endpoint_identity_sha256=endpoint_sha,
        target_kind='peripheral', target_component=window.component,
        target_id=window.component, base=gpio_base, size=gpio_size,
        operation='write', permissions=('write',),
        byte_enable=window.byte_enable,
        readable_offsets=window.readable_offsets,
        writable_offsets=window.writable_offsets,
        accepted_write_values=window.accepted_write_values,
        target_identity_sha256=canonical_runtime_identity_sha256(gpio_identity))
    return region, window, (ram_route, gpio_route)


@dataclass(frozen=True)
class PulpGpioDmaRuntimePaths:
    """Immutable prepared declaration plus its live topology binding."""

    graph: DependencyGraph
    contract: RuntimePathContract
    direction: str
    path: DependencyPath
    path_id: str
    prepared: PreparedRuntimePathContract
    compiled: CompiledRuntimePathContract | None
    gpio_base: int
    gpio_size: int
    memory_component: str
    resource_id: str
    image_address: int
    image_id: str
    admission: PulpGpioDmaBeatAdmission
    source_bindings: SourceBindings

    def document(self) -> dict:
        if self.compiled is None:
            raise ValueError('PULP GPIO DMA runtime paths are not topology-bound')
        admission_identity = self.admission.identity_document()
        return {
            'schema_version': 'pulp_gpio_dma_runtime_paths.v1',
            'direction': self.direction,
            'path_id': self.path_id,
            'graph_sha256': self.contract.graph_sha256,
            'contract_sha256': self.contract.identity_sha256,
            'runtime_contract': self.contract.document(),
            'prepared_contract': self.prepared.document(),
            'compiled_topology': self.compiled.document(),
            'prepared_sha256': _digest(self.prepared.document()),
            'source_id': RAM_SOURCE_NODE,
            'target': GPIO_PADOUT_NODE,
            'gpio_window': [self.gpio_base, self.gpio_size],
            'ram_resource': [self.memory_component, self.resource_id],
            'image_address': self.image_address,
            'image_id': self.image_id,
            'source_bindings': [asdict(value)
                for value in self.source_bindings.entries],
            'dma_beat_admission': {
                'schema_version': 'pulp_gpio_dma_beat_admission.v2',
                'read_address': self.image_address,
                'write_address': self.gpio_base + GPIO_PADOUT_OFFSET,
                'write_offset': GPIO_PADOUT_OFFSET,
                'transfer_words': 1,
                'write_value_equals_read_response': True,
                'identity': admission_identity,
                'identity_sha256': _digest(admission_identity)},
        }

    def bind(self, runner):
        """Bind the immutable prepared graph to another compatible live runner."""
        compiled = self.prepared.bind(runner)
        dma = runner.sessions['dma']
        configure_admission = getattr(dma, 'configure_dma_route_admission', None)
        if not callable(configure_admission):
            raise ValueError('DMA endpoint lacks route beat admission hook')
        window = next(snapshot.window for snapshot in compiled._dma_routes
            if snapshot.route.key == (2, 0))
        admission = PulpGpioDmaBeatAdmission(image_address=self.image_address,
            gpio_window=window)
        configure_admission(admission)
        return compiled

    def validate_source_genomes(self, genomes):
        """Check the declared image identity/address against concrete cases."""
        if type(genomes) is not tuple:
            raise ValueError('PULP DMA source genome set must be an immutable tuple')
        self.source_bindings.validate(self.graph, None, genomes)


def prepare_pulp_gpio_dma_runtime_paths(runner, *, gpio_base=0x40001000,
        gpio_size=0x1000, memory_component='cpu', resource_id='ram',
        image_id='dma_payload', image_address=None, direction=DEFAULT_DIRECTION):
    """Prepare one RAM-image-word to PULP GPIO PADOUT route without binding.

    The DMA endpoint, shared RAM resource, and PULP GPIO target window are
    copied from the live runner. The returned prepared contract can be bound
    by D4 or by the legacy compatibility wrapper; no runner hooks are changed.
    Runtime transfer/effect evidence is separate.
    """
    _validate_aperture(gpio_base, gpio_size, 'PULP GPIO')
    if (type(memory_component) is not str or not memory_component
            or type(resource_id) is not str or not resource_id
            or type(image_id) is not str or not image_id
            or type(direction) is not str or not direction):
        raise ValueError('invalid PULP GPIO DMA route identity')

    region, window, routes = _route_declarations(runner,
        gpio_base=gpio_base, gpio_size=gpio_size,
        memory_component=memory_component, resource_id=resource_id,
        image_id=image_id, direction=direction)
    if image_address is None:
        image_address = region.base
    if (type(image_address) is not int or image_address % 4
            or image_address < region.base
            or image_address + 4 > region.base + region.size):
        raise ValueError('PULP GPIO DMA source image address must name one aligned RAM word')
    graph = DependencyGraph(
        sources=(FuzzableSource(RAM_SOURCE_NODE, memory_component, image_id,
            0, 32, (direction,), kind='memory_image',
            image_address=image_address),),
        rules=tuple(DependencyRule(target, prerequisites, kind)
                    for target, prerequisites, kind in RULES))
    nodes = (
        RuntimeNode(RAM_SOURCE_NODE, memory_component, 'state'),
        RuntimeNode(DMA_READ_NODE, 'dma', 'logical'),
        RuntimeNode(DMA_WRITE_NODE, 'dma', 'logical'),
        RuntimeNode(GPIO_PADOUT_NODE, window.component, 'state'),
    )
    edges = (
        RuntimeEdgeContract(0, 0, 'dma_master_route'),
        RuntimeEdgeContract(1, 0, 'causal_order'),
        RuntimeEdgeContract(2, 0, 'dma_master_route'),
    )
    contract = RuntimePathContract(_digest(graph.edge_document()), nodes,
        edges, dma_master_routes=routes)
    paths = graph.edge_paths_to(GPIO_PADOUT_NODE, direction=direction,
                                max_depth=8, max_paths=2)
    if len(paths) != 1 or paths[0].source_ids != (RAM_SOURCE_NODE,):
        raise ValueError('PULP GPIO DMA graph must resolve to one RAM word path')
    path = paths[0]
    prepared = PreparedRuntimePathContract(graph, contract,
        ((direction, path),))
    source_binding = SourceBinding(RAM_SOURCE_NODE, 'memory_image',
        memory_component, image_id, 0, 32,
        f'initial_image:{memory_component}:{image_id}', image_address)
    source_bindings = SourceBindings((source_binding,))
    admission = PulpGpioDmaBeatAdmission(image_address=image_address,
        gpio_window=window)
    return PulpGpioDmaRuntimePaths(graph=graph, contract=contract,
        direction=direction, path=path, path_id=prepared.path_ids[0],
        prepared=prepared, compiled=None,
        gpio_base=gpio_base, gpio_size=gpio_size,
        memory_component=memory_component, resource_id=resource_id,
        image_address=image_address, image_id=image_id,
        admission=admission, source_bindings=source_bindings)


def compile_pulp_gpio_dma_runtime_paths(runner, *, gpio_base=0x40001000,
        gpio_size=0x1000, memory_component='cpu', resource_id='ram',
        image_id='dma_payload', image_address=None, direction=DEFAULT_DIRECTION):
    """Prepare, bind once, and install the legacy one-word admission policy."""
    paths = prepare_pulp_gpio_dma_runtime_paths(runner,
        gpio_base=gpio_base, gpio_size=gpio_size,
        memory_component=memory_component, resource_id=resource_id,
        image_id=image_id, image_address=image_address, direction=direction)
    compiled = paths.prepared.bind(runner)
    dma = runner.sessions['dma']
    configure_admission = getattr(dma, 'configure_dma_route_admission', None)
    if not callable(configure_admission):
        raise ValueError('DMA endpoint lacks route beat admission hook')
    configure_admission(paths.admission)
    return replace(paths, compiled=compiled)
