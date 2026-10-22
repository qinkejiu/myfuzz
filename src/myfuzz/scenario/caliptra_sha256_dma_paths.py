"""Prepared RAM-word to Caliptra SHA256 CTRL-start DMA route."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from myfuzz.local_harness.wishbone_dma_session import (
    MasterTargetWindow, dma_route_endpoint_identity_document,
)
from myfuzz.scenario.ledger import TransactionKey

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource, SourceBinding, SourceBindings)
from .ledger import TransactionLedger
from .memory import PersistentMemory
from .memory_service import MemoryService
from .runtime_path_contract import (
    CompiledRuntimePathContract, DmaMasterRouteContract,
    PreparedRuntimePathContract, RuntimeEdgeContract, RuntimeNode,
    RuntimePathContract, canonical_runtime_identity_sha256,
    persistent_memory_route_identity_document,
)
from .compiled_f6_runtime_path import (
    DmaTransferSourceWord, build_caliptra_runtime_graph,
    caliptra_route_declarations,
)

RAM_SOURCE_NODE = 'ram.source_word'
DMA_READ_NODE = 'dma.read_data'
DMA_WRITE_NODE = 'dma.write_data'
SHA_CTRL_NODE = 'sha.ctrl_start_effect'
SHA_CTRL_OFFSET = 0x10
SHA_CTRL_START_VALUE = 5
DMA_READ_ENDPOINT = 'read_master'
DMA_WRITE_ENDPOINT = 'write_master'
DEFAULT_DIRECTION = 'CPU_TO_IP'
def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class CaliptraSha256DmaBeatAdmission:
    """Admit only one declared RAM word and CTRL-start DMA transfer."""

    __slots__ = ('_image_address', '_window', '_read_value', '_pending_key',
                 '_state', '_route_config_frozen')
    _ROUTE_FIELDS = frozenset(('_image_address', '_window',
                               '_route_config_frozen'))

    def __setattr__(self, name, value):
        if getattr(self, '_route_config_frozen', False) and name in self._ROUTE_FIELDS:
            raise AttributeError('Caliptra DMA route configuration is read-only')
        object.__setattr__(self, name, value)

    def __init__(self, *, image_address: int, window: MasterTargetWindow):
        if (type(image_address) is not int or image_address < 0
                or image_address % 4 or image_address + 4 > 1 << 64):
            raise ValueError('Caliptra DMA image address must be one aligned word')
        if (type(window) is not MasterTargetWindow
                or window.byte_enable != 15
                or window.readable_offsets
                or window.writable_offsets != (SHA_CTRL_OFFSET,)
                or window.accepted_write_values != (SHA_CTRL_START_VALUE,)):
            raise ValueError('Caliptra DMA admission requires its CTRL-start window')
        self._route_config_frozen = False
        self._image_address = image_address
        self._window = window
        self.begin_case('', '')
        self._route_config_frozen = True

    @property
    def image_address(self):
        return self._image_address

    @property
    def window(self):
        return self._window

    @property
    def state(self):
        return self._state

    def identity_document(self):
        return {
            'schema_version': 'caliptra_sha256_dma_beat_admission_identity.v1',
            'profile': 'ram_word_to_caliptra_sha256_ctrl_start.v1',
            'source': {'operation': 'read', 'address': self._image_address,
                       'word_bytes': 4, 'byte_enable': 15},
            'target': {'operation': 'write', 'address':
                self._window.base + SHA_CTRL_OFFSET,
                'offset': SHA_CTRL_OFFSET,
                'window': self._window.route_identity_document()},
            'transfer': {'word_count': 1,
                         'write_value': SHA_CTRL_START_VALUE},
        }

    def begin_case(self, _execution_id, _testcase_id):
        self._state = 'expect_read'
        self._pending_key = None
        self._read_value = None

    def accepted(self, key, *, address, write, value, byte_enable, target):
        if type(key) is not TransactionKey:
            raise ValueError('Caliptra DMA path requires a typed transaction key')
        if (type(address) is not int or type(write) is not bool
                or type(value) is not int or not 0 <= value <= 0xffffffff
                or type(byte_enable) is not int or byte_enable != 15):
            raise ValueError('Caliptra DMA path requires a full-word beat')
        if self._state == 'expect_read':
            if write or address != self.image_address or target is not None:
                raise ValueError('Caliptra DMA path expected its declared RAM word read')
            self._state = 'read_pending'
            self._pending_key = key
            return
        if self._state == 'expect_write':
            if (not write or address != self.window.base + SHA_CTRL_OFFSET
                    or target is not self.window
                    or value != SHA_CTRL_START_VALUE
                    or value != self._read_value
                    or not self.window.accepts(address, True, value, byte_enable)):
                raise ValueError('Caliptra DMA path expected the declared CTRL start word')
            self._state = 'write_pending'
            self._pending_key = key
            return
        if self._state == 'complete':
            raise ValueError('Caliptra single-word DMA route is complete')
        raise ValueError('Caliptra DMA path received a beat before its response')

    def completed(self, key, *, rdata, error):
        if (key is not self._pending_key or type(rdata) is not int
                or not 0 <= rdata <= 0xffffffff or type(error) is not int
                or error != 0):
            raise ValueError('Caliptra DMA response does not match admitted beat')
        if self._state == 'read_pending':
            self._read_value = rdata
            self._state = 'expect_write'
            self._pending_key = None
            return
        if self._state == 'write_pending':
            self._state = 'complete'
            self._pending_key = None
            return
        raise ValueError('Caliptra DMA path received an unexpected response')


def _route_declarations(runner, *, sha_base, sha_size, memory_component,
                        resource_id):
    """Compatibility alias for the shared live Caliptra facts validator."""
    return caliptra_route_declarations(runner, sha_base=sha_base,
        sha_size=sha_size, memory_component=memory_component,
        resource_id=resource_id)


@dataclass(frozen=True)
class CaliptraSha256DmaRuntimePaths:
    graph: DependencyGraph
    contract: RuntimePathContract
    direction: str
    path: DependencyPath
    path_id: str
    prepared: PreparedRuntimePathContract
    compiled: CompiledRuntimePathContract | None
    sha_base: int
    sha_size: int
    memory_component: str
    resource_id: str
    image_address: int
    image_id: str
    admission: CaliptraSha256DmaBeatAdmission | None
    source_bindings: SourceBindings
    _target_window: MasterTargetWindow

    def document(self) -> dict:
        if self.compiled is None or self.admission is None:
            raise ValueError('Caliptra runtime path is not yet bound and admitted')
        identity = self.admission.identity_document()
        return {
            'schema_version': 'caliptra_sha256_dma_runtime_paths.v1',
            'direction': self.direction,
            'path_id': self.path_id,
            'graph_sha256': self.contract.graph_sha256,
            'contract_sha256': self.contract.identity_sha256,
            'runtime_contract': self.contract.document(),
            'prepared_contract': self.prepared.document(),
            'compiled_topology': self.compiled.document(),
            'prepared_sha256': _digest(self.prepared.document()),
            'source_id': RAM_SOURCE_NODE, 'target': SHA_CTRL_NODE,
            'sha_window': [self.sha_base, self.sha_size],
            'ram_resource': [self.memory_component, self.resource_id],
            'image_address': self.image_address, 'image_id': self.image_id,
            'source_bindings': [asdict(value)
                for value in self.source_bindings.entries],
            'dma_beat_admission': {
                'schema_version': 'caliptra_sha256_dma_beat_admission.v1',
                'read_address': self.image_address,
                'write_address': self.sha_base + SHA_CTRL_OFFSET,
                'write_offset': SHA_CTRL_OFFSET, 'transfer_words': 1,
                'write_value': SHA_CTRL_START_VALUE,
                'identity': identity, 'identity_sha256': _digest(identity)},
        }

    def validate_source_genomes(self, genomes):
        if type(genomes) is not tuple:
            raise ValueError('Caliptra DMA source genome set must be an immutable tuple')
        self.source_bindings.validate(self.graph, None, genomes)


def prepare_caliptra_sha256_dma_runtime_paths(runner, *,
        sha_base=0x40002000, sha_size=0x1000,
        memory_component='cpu', resource_id='ram',
        image_id='dma_payload', image_address=None,
        direction=DEFAULT_DIRECTION):
    """Prepare one typed RAM-word to Caliptra SHA256 CTRL route without binding."""
    if (type(sha_base) is not int or sha_base < 0 or sha_base % 0x1000
            or type(sha_size) is not int or sha_size < 4 or sha_size % 4
            or sha_base + sha_size > 1 << 32):
        raise ValueError('invalid declared Caliptra SHA256 aperture')
    if (type(memory_component) is not str or not memory_component
            or type(resource_id) is not str or not resource_id
            or type(image_id) is not str or not image_id
            or type(direction) is not str or not direction):
        raise ValueError('invalid Caliptra SHA256 DMA route identity')
    region, window, routes = _route_declarations(runner,
        sha_base=sha_base, sha_size=sha_size,
        memory_component=memory_component, resource_id=resource_id)
    if image_address is None:
        image_address = region.base
    if (type(image_address) is not int or image_address % 4
            or image_address < region.base
            or image_address + 4 > region.base + region.size):
        raise ValueError('Caliptra DMA source image must name one aligned RAM word')

    _, window, graph, contract, path, prepared = build_caliptra_runtime_graph(
        runner, DmaTransferSourceWord(memory_component, resource_id, image_id,
            image_address, 4, 15, direction), sha_base=sha_base,
        sha_size=sha_size)
    bindings = SourceBindings((SourceBinding(RAM_SOURCE_NODE, 'memory_image',
        memory_component, image_id, 0, 32,
        f'initial_image:{memory_component}:{image_id}', image_address),))
    return CaliptraSha256DmaRuntimePaths(graph=graph, contract=contract,
        direction=direction, path=path, path_id=prepared.path_ids[0],
        prepared=prepared, compiled=None,
        sha_base=sha_base, sha_size=sha_size,
        memory_component=memory_component, resource_id=resource_id,
        image_address=image_address, image_id=image_id,
        admission=None, source_bindings=bindings, _target_window=window)


def compile_caliptra_sha256_dma_runtime_paths(runner, *,
        sha_base=0x40002000, sha_size=0x1000,
        memory_component='cpu', resource_id='ram',
        image_id='dma_payload', image_address=None,
        direction=DEFAULT_DIRECTION):
    """Prepare, bind and admit one RAM-word to Caliptra SHA256 CTRL route."""
    prepared_paths = prepare_caliptra_sha256_dma_runtime_paths(runner,
        sha_base=sha_base, sha_size=sha_size,
        memory_component=memory_component, resource_id=resource_id,
        image_id=image_id, image_address=image_address, direction=direction)
    compiled = prepared_paths.prepared.bind(runner)
    admission = CaliptraSha256DmaBeatAdmission(
        image_address=prepared_paths.image_address,
        window=prepared_paths._target_window)
    dma = runner.sessions['dma']
    configure_admission = getattr(dma, 'configure_dma_route_admission', None)
    if not callable(configure_admission):
        raise ValueError('DMA endpoint lacks route beat admission hook')
    configure_admission(admission)
    return replace(prepared_paths, compiled=compiled, admission=admission)
