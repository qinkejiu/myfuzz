"""Prepared one-word RAM to ZipCPU wbuart TXREG DMA route."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import re

from myfuzz.local_harness.wishbone_dma_session import (
    MasterTargetWindow, dma_route_endpoint_identity_document,
)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource, SourceBinding, SourceBindings)
from .memory import PersistentMemory
from .memory_service import MemoryService
from .runtime_path_contract import (
    CompiledRuntimePathContract, DmaMasterRouteContract,
    PreparedRuntimePathContract, RuntimeEdgeContract, RuntimeNode,
    RuntimePathContract, canonical_runtime_identity_sha256,
    persistent_memory_route_identity_document,
)


RAM_SOURCE_NODE = 'ram.source_word'
DMA_READ_NODE = 'dma.read_data'
DMA_WRITE_NODE = 'dma.write_data'
UART_TX_NODE = 'uart.pins.tx'
TXREG_OFFSET = 0x0C
UART_WINDOW_SIZE = 0x10
UART_TXREG_VALUES = range(256)
DMA_READ_ENDPOINT = 'read_master'
DMA_WRITE_ENDPOINT = 'write_master'
DEFAULT_DIRECTION = 'CPU_TO_IP'
RULES = (
    (DMA_READ_NODE, (RAM_SOURCE_NODE,), 'DMA_MASTER_TRANSFER'),
    (DMA_WRITE_NODE, (DMA_READ_NODE,), 'EVENT_ORDER'),
    (UART_TX_NODE, (DMA_WRITE_NODE,), 'DMA_MASTER_TRANSFER'),
)

_PROVIDER_SCHEMA = 'zipcpu_uart_dma_target_provider.v1'
_PROVIDER_API_SCHEMA = 'dma_master_target_access.v1'
_PROVIDER_PROFILE = 'zipcpu_wbuart_txreg_wishbone_serial.v1'
_WISHBONE_SIGNAL_ROLES = frozenset(('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack'))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _range_document(values: range) -> dict:
    return {'kind': 'range', 'start': values.start,
            'stop': values.stop, 'step': values.step}


def _validate_provider_identity(uart) -> dict:
    provider_method = getattr(uart,
        'dma_master_target_provider_identity_document', None)
    if not callable(provider_method):
        raise ValueError('ZipCPU UART target lacks its versioned DMA provider identity')
    if not callable(getattr(uart, 'dma_master_target_access', None)):
        raise ValueError('ZipCPU UART target lacks its keyed DMA target provider')

    artifact = getattr(uart, 'artifact', None)
    runtime = getattr(artifact, 'runtime_document', None)
    if type(runtime) is not dict or runtime.get('kind') != 'wishbone_uart':
        raise ValueError('ZipCPU UART DMA target artifact is not a Wishbone UART')
    artifact_digest = runtime.get('artifact_digest')
    if (type(artifact_digest) is not str
            or re.fullmatch(r'[0-9a-f]{64}', artifact_digest) is None):
        raise ValueError('ZipCPU UART DMA target artifact digest is invalid')
    captured_artifact = getattr(uart, '_artifact_document', runtime)
    if type(captured_artifact) is not dict or captured_artifact != runtime:
        raise ValueError('ZipCPU UART DMA target artifact changed after session creation')
    plan = getattr(artifact, 'plan', None)
    request = getattr(plan, 'request', None)
    instance_id = getattr(request, 'instance_id', None)
    if type(instance_id) is not str or not instance_id:
        raise ValueError('ZipCPU UART DMA target artifact instance is not pinned')

    identity = provider_method()
    if type(identity) is not dict:
        raise ValueError('ZipCPU UART DMA provider identity must be a document')
    identity = deepcopy(identity)
    try:
        _canonical(identity)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('ZipCPU UART provider identity is not canonical JSON') from error

    required_keys = {
        'schema_version', 'api_schema_version', 'implementation_profile',
        'artifact_digest', 'instance_id', 'endpoint_id', 'txreg',
        'startup_writes', 'serial', 'wishbone_signals'}
    if set(identity) != required_keys:
        raise ValueError('ZipCPU UART provider identity has an unsupported schema')
    if (identity['schema_version'] != _PROVIDER_SCHEMA
            or identity['api_schema_version'] != _PROVIDER_API_SCHEMA
            or identity['implementation_profile'] != _PROVIDER_PROFILE
            or identity['artifact_digest'] != artifact_digest
            or identity['instance_id'] != instance_id
            or identity['endpoint_id'] != 'uart.bus'):
        raise ValueError('ZipCPU UART provider identity is unsupported')
    if identity['txreg'] != {
            'operation': 'write', 'offset': TXREG_OFFSET,
            'accepted_write_values': _range_document(UART_TXREG_VALUES),
            'byte_enable': 15}:
        raise ValueError('ZipCPU UART provider identity does not pin byte-only TXREG writes')
    if identity['startup_writes'] != [[0, 25, 15]]:
        raise ValueError('ZipCPU UART provider identity does not pin SETUP 25 startup')

    serial = identity['serial']
    if (type(serial) is not dict
            or set(serial) != {'endpoint_id', 'role', 'format',
                               'clocks_per_bit', 'runtime_name'}
            or serial.get('endpoint_id') != 'uart.pins'
            or serial.get('role') != 'tx'
            or serial.get('format') != '8N1'
            or serial.get('clocks_per_bit') != 25
            or type(serial.get('runtime_name')) is not str
            or not serial['runtime_name']):
        raise ValueError('ZipCPU UART provider identity does not pin the serial TX effect')

    signals = identity['wishbone_signals']
    if (type(signals) is not dict or set(signals) != _WISHBONE_SIGNAL_ROLES
            or any(type(value) is not str or not value for value in signals.values())):
        raise ValueError('ZipCPU UART provider identity lacks its native Wishbone map')
    return identity


class ZipcpuUartDmaBeatAdmission:
    """Admit one RAM read followed by the same low byte to the selected TXREG."""

    __slots__ = ('_image_address', '_window', '_provider_identity_json',
                 '_read_key', '_pending_key', '_read_value', '_state',
                 '_route_config_frozen')
    _ROUTE_FIELDS = frozenset((
        '_image_address', '_window', '_provider_identity_json',
        '_route_config_frozen'))

    def __setattr__(self, name, value):
        if (getattr(self, '_route_config_frozen', False)
                and name in self._ROUTE_FIELDS):
            raise AttributeError('ZipCPU UART DMA route configuration is read-only')
        object.__setattr__(self, name, value)

    def __init__(self, *, image_address: int, window: MasterTargetWindow,
                 provider_identity: dict):
        if (type(image_address) is not int or image_address < 0
                or image_address % 4 or image_address + 4 > 1 << 64):
            raise ValueError('ZipCPU UART DMA image address must be one aligned word')
        if (type(window) is not MasterTargetWindow
                or window.component != 'uart' or window.size != UART_WINDOW_SIZE
                or window.writable_offsets != (TXREG_OFFSET,)
                or window.accepted_write_values != UART_TXREG_VALUES
                or window.byte_enable != 15 or window.readable_offsets):
            raise ValueError('ZipCPU UART DMA admission requires its TXREG-only window')
        if type(provider_identity) is not dict:
            raise ValueError('ZipCPU UART DMA provider identity is required')
        self._route_config_frozen = False
        self._image_address = image_address
        self._window = window
        self._provider_identity_json = _canonical(deepcopy(provider_identity))
        self.begin_case('', '')
        self._route_config_frozen = True

    @property
    def image_address(self):
        return self._image_address

    @property
    def window(self):
        return self._window

    @property
    def write_address(self):
        return self._window.base + TXREG_OFFSET

    @property
    def state(self):
        return self._state

    def identity_document(self) -> dict:
        return {
            'schema_version': 'zipcpu_uart_dma_beat_admission_identity.v1',
            'profile': 'ram_word_to_zipcpu_wbuart_txreg.v1',
            'source': {'operation': 'read', 'address': self._image_address,
                       'word_bytes': 4, 'byte_enable': 15},
            'target': {'operation': 'write', 'address': self.write_address,
                       'offset': TXREG_OFFSET,
                       'window': self._window.route_identity_document()},
            'transfer': {'word_count': 1,
                         'accepted_values': _range_document(UART_TXREG_VALUES),
                         'value_equals_read_response': True},
            'provider_identity': json.loads(self._provider_identity_json),
        }

    def begin_case(self, _execution_id, _testcase_id):
        self._state = 'expect_read'
        self._read_key = None
        self._pending_key = None
        self._read_value = None

    @staticmethod
    def _key_prefix(key: TransactionKey):
        return (key.execution_id, key.testcase_id, key.source_component,
                key.source_epoch, key.channel_id)

    def accepted(self, key, *, address, write, value, byte_enable, target):
        if type(key) is not TransactionKey:
            raise ValueError('ZipCPU UART DMA path requires a typed transaction key')
        if (type(address) is not int or type(write) is not bool
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(byte_enable) is not int or byte_enable != 15):
            raise ValueError('ZipCPU UART DMA path requires a full-word beat')
        if self._state == 'expect_read':
            if write or address != self.image_address or target is not None:
                raise ValueError('ZipCPU UART DMA path expected its declared RAM image word read')
            self._state = 'read_pending'
            self._read_key = key
            self._pending_key = key
            return
        if self._state == 'expect_write':
            valid_successor = (
                self._key_prefix(key) == self._key_prefix(self._read_key)
                and key.source_sequence == self._read_key.source_sequence + 1)
            if (not valid_successor or not write
                    or address != self.write_address or target is not self._window
                    or type(value) is not int or not 0 <= value <= 255
                    or value != self._read_value
                    or not self._window.accepts(address, True, value, byte_enable)):
                if target is not self._window or address != self.write_address:
                    raise ValueError('ZipCPU UART DMA path expected the declared TXREG target')
                if type(value) is not int or not 0 <= value <= 255:
                    raise ValueError('ZipCPU UART TXREG DMA value must be in 0..255')
                if value != self._read_value:
                    raise ValueError('ZipCPU UART TXREG value must equal the same source word')
                raise ValueError('ZipCPU UART DMA TXREG transaction identity is not the source successor')
            self._state = 'write_pending'
            self._pending_key = key
            return
        if self._state == 'complete':
            raise ValueError('ZipCPU UART single-word DMA route is complete')
        if self._state == 'refused':
            raise ValueError('ZipCPU UART DMA route refused the source value')
        raise ValueError('ZipCPU UART DMA path received a beat before its response')

    def completed(self, key, *, rdata, error):
        if (key is not self._pending_key or type(rdata) is not int
                or not 0 <= rdata <= 0xffffffff or type(error) is not int
                or error != 0):
            raise ValueError('ZipCPU UART DMA response does not match admitted beat')
        if self._state == 'read_pending':
            if rdata > 255:
                self._state = 'refused'
                self._pending_key = None
                raise ValueError('ZipCPU UART TXREG source value must be in 0..255')
            self._read_value = rdata
            self._state = 'expect_write'
            self._pending_key = None
            return
        if self._state == 'write_pending':
            self._state = 'complete'
            self._pending_key = None
            return
        raise ValueError('ZipCPU UART DMA path received an unexpected response')


def _route_declarations(runner, *, uart_base, memory_component, resource_id):
    sessions = getattr(runner, 'sessions', None)
    if type(sessions) is not dict:
        raise ValueError('runner sessions are required for ZipCPU UART DMA routes')
    dma = sessions.get('dma')
    memory_session = sessions.get(memory_component)
    uart = sessions.get('uart')
    if dma is None or memory_session is None or uart is None:
        raise ValueError('DMA, RAM owner and UART sessions are required')

    service = getattr(dma, 'memory_service', None)
    memory = getattr(service, 'memory', None)
    if (not isinstance(service, MemoryService)
            or not isinstance(service.ledger, TransactionLedger)
            or not isinstance(memory, PersistentMemory)
            or getattr(memory_session, 'memory', None) is not memory):
        raise ValueError('ZipCPU UART DMA route requires the exact shared memory service/resource')
    regions = [region for region in memory._regions
               if region.memory_id == resource_id]
    if len(regions) != 1:
        raise ValueError('ZipCPU UART DMA source RAM region is missing or ambiguous')
    region = regions[0]
    if not region.readable:
        raise ValueError('ZipCPU UART DMA source RAM region is not readable')
    ram_identity = persistent_memory_route_identity_document(
        memory, memory_id=resource_id, base=region.base, size=region.size)

    windows = getattr(dma, 'master_targets', None)
    if (type(windows) is not tuple
            or any(type(window) is not MasterTargetWindow for window in windows)):
        raise ValueError('DMA master target windows must be an immutable typed tuple')
    matches = [window for window in windows
        if window.component == 'uart'
        and (window.base, window.size) == (uart_base, UART_WINDOW_SIZE)]
    if len(matches) != 1:
        raise ValueError('ZipCPU UART DMA master window is missing or ambiguous')
    if len(windows) != 1:
        raise ValueError('ZipCPU UART DMA topology has unselected peripheral routes')
    window = matches[0]
    if window.endpoint is not uart:
        raise ValueError('ZipCPU UART DMA window endpoint is not the registered UART session')
    if (window.component != 'uart' or window.size != UART_WINDOW_SIZE
            or window.writable_offsets != (TXREG_OFFSET,)
            or window.accepted_write_values != UART_TXREG_VALUES
            or window.byte_enable != 15 or window.readable_offsets):
        raise ValueError('ZipCPU UART DMA window must admit only full-word TXREG byte writes')

    provider_identity = _validate_provider_identity(uart)
    endpoint_identity = dma_route_endpoint_identity_document(dma)
    endpoint_sha = canonical_runtime_identity_sha256(endpoint_identity)
    ram_route = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id=RAM_SOURCE_NODE, target_node_id=DMA_READ_NODE,
        initiator_component='dma', endpoint_id=DMA_READ_ENDPOINT,
        endpoint_identity_sha256=endpoint_sha,
        target_kind='persistent_memory', target_component=memory_component,
        target_id=resource_id, base=region.base, size=region.size,
        operation='read',
        permissions=tuple(sorted((['read'] if region.readable else [])
                                 + (['write'] if region.writable else []))),
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(),
        target_identity_sha256=canonical_runtime_identity_sha256(ram_identity))
    target_identity = window.route_identity_document()
    if (target_identity.get('endpoint_identity', {}).get('dma_master_target_provider')
            != provider_identity):
        raise ValueError('ZipCPU UART DMA window identity does not pin the live provider identity')
    uart_route = DmaMasterRouteContract(
        rule_index=2, prerequisite_index=0,
        source_node_id=DMA_WRITE_NODE, target_node_id=UART_TX_NODE,
        initiator_component='dma', endpoint_id=DMA_WRITE_ENDPOINT,
        endpoint_identity_sha256=endpoint_sha,
        target_kind='peripheral', target_component='uart', target_id='uart',
        base=uart_base, size=UART_WINDOW_SIZE, operation='write',
        permissions=('write',), byte_enable=window.byte_enable,
        readable_offsets=window.readable_offsets,
        writable_offsets=window.writable_offsets,
        accepted_write_values=window.accepted_write_values,
        target_identity_sha256=canonical_runtime_identity_sha256(target_identity))
    return region, window, provider_identity, (ram_route, uart_route)


@dataclass(frozen=True)
class ZipcpuUartDmaRuntimePaths:
    graph: DependencyGraph
    contract: RuntimePathContract
    direction: str
    path: DependencyPath
    path_id: str
    prepared: PreparedRuntimePathContract
    compiled: CompiledRuntimePathContract | None
    uart_base: int
    memory_component: str
    resource_id: str
    image_address: int
    image_id: str
    admission: ZipcpuUartDmaBeatAdmission
    source_bindings: SourceBindings
    _provider_identity_json: bytes

    @property
    def provider_identity(self) -> dict:
        return json.loads(self._provider_identity_json)

    def document(self) -> dict:
        if self.compiled is None:
            raise ValueError('ZipCPU UART runtime paths must be bound before serialization')
        identity = self.provider_identity
        admission_identity = self.admission.identity_document()
        return {
            'schema_version': 'zipcpu_uart_dma_runtime_paths.v1',
            'direction': self.direction,
            'path_id': self.path_id,
            'graph_sha256': self.contract.graph_sha256,
            'contract_sha256': self.contract.identity_sha256,
            'runtime_contract': self.contract.document(),
            'prepared_contract': self.prepared.document(),
            'compiled_topology': self.compiled.document(),
            'prepared_sha256': _digest(self.prepared.document()),
            'source_id': RAM_SOURCE_NODE,
            'target': UART_TX_NODE,
            'uart_window': [self.uart_base, UART_WINDOW_SIZE],
            'ram_resource': [self.memory_component, self.resource_id],
            'image_address': self.image_address,
            'image_id': self.image_id,
            'source_bindings': [asdict(value)
                for value in self.source_bindings.entries],
            'provider_identity': identity,
            'provider_identity_sha256': _digest(identity),
            'dma_beat_admission': {
                'schema_version': 'zipcpu_uart_dma_beat_admission.v1',
                'read_address': self.image_address,
                'write_address': self.uart_base + TXREG_OFFSET,
                'write_offset': TXREG_OFFSET,
                'transfer_words': 1,
                'accepted_byte_range': _range_document(UART_TXREG_VALUES),
                'write_value_equals_read_response': True,
                'identity': admission_identity,
                'identity_sha256': _digest(admission_identity)},
        }

    def validate_source_genomes(self, genomes):
        if type(genomes) is not tuple:
            raise ValueError('ZipCPU UART DMA source genome set must be an immutable tuple')
        self.source_bindings.validate(self.graph, None, genomes)


def prepare_zipcpu_uart_dma_runtime_paths(runner, *, uart_base=0x40003000,
        memory_component='cpu', resource_id='ram', image_id='dma_payload',
        image_address=None, direction=DEFAULT_DIRECTION):
    """Prepare the typed ZipCPU route without binding or installing admission."""
    if (type(uart_base) is not int or uart_base < 0 or uart_base % 0x1000
            or uart_base + UART_WINDOW_SIZE > 1 << 32):
        raise ValueError('invalid declared ZipCPU UART aperture')
    if (type(memory_component) is not str or not memory_component
            or type(resource_id) is not str or not resource_id
            or type(image_id) is not str or not image_id
            or type(direction) is not str or direction != DEFAULT_DIRECTION):
        raise ValueError('ZipCPU UART DMA route requires CPU_TO_IP and valid identities')

    region, window, provider_identity, routes = _route_declarations(runner,
        uart_base=uart_base, memory_component=memory_component,
        resource_id=resource_id)
    if image_address is None:
        image_address = region.base
    if (type(image_address) is not int or image_address % 4
            or image_address < region.base
            or image_address + 4 > region.base + region.size):
        raise ValueError('ZipCPU UART DMA source image must name one aligned RAM word')

    graph = DependencyGraph(
        sources=(FuzzableSource(RAM_SOURCE_NODE, memory_component, image_id,
            0, 32, (DEFAULT_DIRECTION,), kind='memory_image',
            image_address=image_address),),
        rules=tuple(DependencyRule(target, prerequisites, kind)
                    for target, prerequisites, kind in RULES))
    nodes = (
        RuntimeNode(RAM_SOURCE_NODE, memory_component, 'state'),
        RuntimeNode(DMA_READ_NODE, 'dma', 'logical'),
        RuntimeNode(DMA_WRITE_NODE, 'dma', 'logical'),
        RuntimeNode(UART_TX_NODE, 'uart', 'state'),
    )
    edges = (
        RuntimeEdgeContract(0, 0, 'dma_master_route'),
        RuntimeEdgeContract(1, 0, 'causal_order'),
        RuntimeEdgeContract(2, 0, 'dma_master_route'),
    )
    contract = RuntimePathContract(_digest(graph.edge_document()), nodes,
        edges, dma_master_routes=routes)
    paths = graph.edge_paths_to(UART_TX_NODE, direction=DEFAULT_DIRECTION,
                                max_depth=8, max_paths=2)
    if len(paths) != 1 or paths[0].source_ids != (RAM_SOURCE_NODE,):
        raise ValueError('ZipCPU UART DMA graph must resolve to one RAM word')
    path = paths[0]
    prepared = PreparedRuntimePathContract(graph, contract,
        ((DEFAULT_DIRECTION, path),))
    source_bindings = SourceBindings((SourceBinding(RAM_SOURCE_NODE,
        'memory_image', memory_component, image_id, 0, 32,
        f'initial_image:{memory_component}:{image_id}', image_address),))
    admission = ZipcpuUartDmaBeatAdmission(image_address=image_address,
        window=window, provider_identity=provider_identity)
    return ZipcpuUartDmaRuntimePaths(graph=graph, contract=contract,
        direction=DEFAULT_DIRECTION, path=path, path_id=prepared.path_ids[0],
        prepared=prepared, compiled=None, uart_base=uart_base,
        memory_component=memory_component, resource_id=resource_id,
        image_address=image_address, image_id=image_id,
        admission=admission, source_bindings=source_bindings,
        _provider_identity_json=_canonical(provider_identity))


def compile_zipcpu_uart_dma_runtime_paths(runner, *, uart_base=0x40003000,
        memory_component='cpu', resource_id='ram', image_id='dma_payload',
        image_address=None, direction=DEFAULT_DIRECTION):
    """Bind and install one RAM-word to ZipCPU UART TXREG route."""
    paths = prepare_zipcpu_uart_dma_runtime_paths(runner,
        uart_base=uart_base, memory_component=memory_component,
        resource_id=resource_id, image_id=image_id,
        image_address=image_address, direction=direction)
    compiled = paths.prepared.bind(runner)
    dma = runner.sessions['dma']
    configure_admission = getattr(dma, 'configure_dma_route_admission', None)
    if not callable(configure_admission):
        raise ValueError('DMA endpoint lacks route beat admission hook')
    configure_admission(paths.admission)
    return replace(paths, compiled=compiled)
