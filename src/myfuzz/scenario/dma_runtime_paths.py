"""Declared UART RX FIFO source graph for one-boot DMA descriptor cases (S4).

The graph names the real external serial producer and every transport hop the
runtime later joins against actual journal rows::

    uart.external_rx_byte          physical cio_rx_i source, 8 bits
      -> uart.rx_frame             measured 8N1 waveform (causal order)
      -> uart.fifo_entry           real RX FIFO entry (causal order)
      -> cpu.fifo_pop              routed CPU RDATA pop of the descriptor
      -> dma.fifo_pop              DMA master RDATA pop of the payload
      -> dma.ram_write             real DMA master write
      -> ram.destination_commit    persistent RAM commit (shared memory)
      -> dma.completion_irq        native wbdmac completion/error pulse
      -> cpu.dma_irq               declared one-bit IRQ binding
      -> cpu.isr                   real CPU ISR retirements

Compilation reuses :class:`PreparedRuntimePathContract` and
:class:`RuntimeEdgeIndex`: a missing edge, an incompatible relation, a graph
digest mismatch or a topology mismatch fails before any RTL command.  The DMA
master read hop is additionally checked against the DMA session's declared
``MasterTargetWindow`` (the same window the runtime really routes through);
until S4 that window had no transaction identity, so no authority was possible.

Nothing here invents a source.  ``SourceAdmission.create`` consumes only the
byte the caller is about to submit, and the resulting admission only becomes
authority when :class:`~myfuzz.scenario.uart_consumption.UartConsumptionTracker`
emits accepted retention/read proofs from real journal rows.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
    FuzzableSource)
from .runtime_edge_index import RuntimeEdgeIndex
from .runtime_path_contract import (PreparedRuntimePathContract,
    RuntimeEdgeContract, RuntimeNode, RuntimePathContract)
from .source_provenance import SourceAdmission

SOURCE_NODE = 'uart.external_rx_byte'
SOURCE_COMPONENT = 'uart'
SOURCE_PORT = 'uart_rx_byte'
SOURCE_BIT_OFFSET = 0
SOURCE_WIDTH = 8
SOURCE_DIRECTION = 'IP_TO_CPU'
UART_BASE = 0x50000000
UART_SIZE = 0x1000
UART_RDATA_OFFSET = 0x18
DMA_IRQ_ENDPOINT = ('dma', 'irq', 'cpu', 'irq', 1)
RAM_RESOURCE_ID = 'ram'
#: The only relation the shared runtime contract can express for a DMA master
#: window today.  The route itself is validated against the actual
#: ``MasterTargetWindow`` list below; the graph edge stays causal order because
#: ``RuntimePathContract`` has no DMA-master relation and adding one would
#: change shared topology semantics outside S4.
DMA_MASTER_EDGE_RELATION = 'causal_order'

NODES = (
    RuntimeNode(SOURCE_NODE, SOURCE_COMPONENT, 'physical', SOURCE_PORT,
                SOURCE_BIT_OFFSET, SOURCE_WIDTH),
    RuntimeNode('uart.rx_frame', 'uart', 'logical'),
    RuntimeNode('uart.fifo_entry', 'uart', 'state'),
    RuntimeNode('cpu.fifo_pop', 'cpu', 'logical'),
    RuntimeNode('dma.fifo_pop', 'dma', 'logical'),
    RuntimeNode('dma.ram_write', 'dma', 'logical'),
    RuntimeNode('ram.destination_commit', 'cpu', 'state'),
    RuntimeNode('dma.completion_irq', 'dma', 'physical', 'irq', 0, 1),
    RuntimeNode('cpu.dma_irq', 'cpu', 'physical', 'irq', 0, 1),
    RuntimeNode('cpu.isr', 'cpu', 'logical'),
)
#: ``(target, prerequisites, kind)`` in construction order; the index of a row
#: is its ``rule_index`` in the compiled graph.
RULES = (
    ('uart.rx_frame', (SOURCE_NODE,), 'EVENT_ORDER'),
    ('uart.fifo_entry', ('uart.rx_frame',), 'EVENT_ORDER'),
    ('cpu.fifo_pop', ('uart.fifo_entry',), 'EVENT_ORDER'),
    # A real RX_TO_RAM case pops the descriptor with CPU RDATA reads first and
    # only then lets the configured DMA master pop the payload; a RAM-sourced
    # case stops at the CPU pop.  The declared path is the superset of the RX
    # FIFO chain, never a per-case witness.
    ('dma.fifo_pop', ('cpu.fifo_pop',), 'EVENT_ORDER'),
    ('dma.ram_write', ('dma.fifo_pop',), 'EVENT_ORDER'),
    ('ram.destination_commit', ('dma.ram_write',), 'PERSISTENT_STATE_RULE'),
    ('dma.completion_irq', ('ram.destination_commit',), 'EVENT_ORDER'),
    ('cpu.dma_irq', ('dma.completion_irq',), 'DATA_BINDING'),
    ('cpu.isr', ('cpu.dma_irq',), 'EVENT_ORDER'),
)
TARGET_NODE = 'cpu.isr'


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _edges(*, uart_base, uart_size, resource_component, resource_id):
    return (
        RuntimeEdgeContract(0, 0, 'causal_order'),
        RuntimeEdgeContract(1, 0, 'causal_order'),
        RuntimeEdgeContract(2, 0, 'mmio_route', 'cpu', 'uart', uart_base,
                            uart_size),
        RuntimeEdgeContract(3, 0, DMA_MASTER_EDGE_RELATION),
        RuntimeEdgeContract(4, 0, 'causal_order'),
        RuntimeEdgeContract(5, 0, 'persistent_state',
                            resource_component=resource_component,
                            resource_id=resource_id),
        RuntimeEdgeContract(6, 0, 'causal_order'),
        RuntimeEdgeContract(7, 0, 'direct_binding'),
        RuntimeEdgeContract(8, 0, 'causal_order'),
    )


def compile_dma_runtime_paths(*, direction=SOURCE_DIRECTION,
        uart_base=UART_BASE, uart_size=UART_SIZE,
        resource_component='cpu', resource_id=RAM_RESOURCE_ID):
    """Build and self-check the declared UART-FIFO-to-ISR runtime path."""
    if direction != SOURCE_DIRECTION:
        raise ValueError('the UART RX FIFO source graph declares IP_TO_CPU only')
    if (type(uart_base) is not int or uart_base < 0 or uart_base % 0x1000
            or type(uart_size) is not int or uart_size < 4 or uart_size % 4
            or uart_base + uart_size > 1 << 64):
        raise ValueError('invalid declared UART aperture')
    if not isinstance(resource_component, str) or not resource_component:
        raise ValueError('invalid declared RAM resource component')
    graph = DependencyGraph(
        sources=(FuzzableSource(SOURCE_NODE, SOURCE_COMPONENT, SOURCE_PORT,
                SOURCE_BIT_OFFSET, SOURCE_WIDTH, (SOURCE_DIRECTION,)),),
        rules=tuple(DependencyRule(target, prerequisites, kind)
                    for target, prerequisites, kind in RULES))
    contract = RuntimePathContract(_digest(graph.edge_document()),
        NODES, _edges(uart_base=uart_base, uart_size=uart_size,
            resource_component=resource_component, resource_id=resource_id))
    paths = graph.edge_paths_to(TARGET_NODE, direction=direction)
    if len(paths) != 1:
        raise ValueError('the declared UART FIFO path graph must resolve to one path')
    path = paths[0]
    if path.source_ids != (SOURCE_NODE,):
        raise ValueError('the declared path must start at the external serial source')
    prepared = PreparedRuntimePathContract(graph, contract, ((direction, path),))
    return DmaRuntimePaths(graph=graph, contract=contract, direction=direction,
        path=path, path_id=prepared.path_ids[0], prepared=prepared,
        uart_base=uart_base, uart_size=uart_size,
        resource_component=resource_component, resource_id=resource_id)


@dataclass(frozen=True)
class DmaRuntimePaths:
    graph: DependencyGraph
    contract: RuntimePathContract
    direction: str
    path: DependencyPath
    path_id: str
    prepared: PreparedRuntimePathContract
    uart_base: int
    uart_size: int
    resource_component: str
    resource_id: str

    def document(self) -> dict:
        return dict(schema_version='dma_runtime_paths.v1',
            direction=self.direction, path_id=self.path_id,
            graph_sha256=self.contract.graph_sha256,
            contract_sha256=self.contract.identity_sha256,
            prepared_sha256=_digest(self.prepared.document()),
            source_id=SOURCE_NODE, target=self.path.target,
            uart_window=[self.uart_base, self.uart_size],
            ram_resource=[self.resource_component, self.resource_id],
            dma_irq_binding=list(DMA_IRQ_ENDPOINT))

    def bind(self, runner):
        return self.prepared.bind(runner)


@dataclass(frozen=True)
class DmaMasterRoute:
    """The declared DMA master target window the FIFO pop is routed through."""

    component: str
    base: int
    size: int
    readable_offsets: tuple[int, ...]
    writable_offsets: tuple[int, ...]
    endpoint_identity_sha256: str

    def document(self) -> dict:
        return dict(schema_version='dma_master_target_route.v1',
            component=self.component, base=self.base, size=self.size,
            readable_offsets=list(self.readable_offsets),
            writable_offsets=list(self.writable_offsets),
            endpoint_identity_sha256=self.endpoint_identity_sha256)


def declared_dma_master_route(runner, *, component='uart', base=UART_BASE,
        size=UART_SIZE, readable_offset=UART_RDATA_OFFSET):
    """Validate the real DMA session master window used for the FIFO pop.

    A window is accepted only when the DMA session itself would route a master
    read there, the endpoint is the very UART session in this Runner, and the
    UART endpoint declares ``master_target_access`` so the pop carries a DMA
    transaction identity.  Missing capability fails closed with the exact
    requirement instead of falling back to an unauthenticated read.
    """
    sessions = getattr(runner, 'sessions', None)
    if not isinstance(sessions, dict):
        raise ValueError('runner sessions are required for the DMA master route')
    dma = sessions.get('dma')
    uart = sessions.get(component)
    windows = tuple(getattr(dma, 'master_targets', ()) or ())
    matches = [window for window in windows
               if getattr(window, 'component', None) == component
               and getattr(window, 'base', None) == base
               and getattr(window, 'size', None) == size]
    if len(matches) != 1:
        raise ValueError(
            'DMA master target window for the UART FIFO pop is missing or ambiguous')
    window = matches[0]
    if getattr(window, 'endpoint', None) is not uart:
        raise ValueError('DMA master target window does not back the UART session')
    readable = tuple(getattr(window, 'readable_offsets', ()))
    if readable != (readable_offset,):
        raise ValueError(
            'DMA master target window must declare exactly the RDATA read offset')
    access = getattr(uart, 'master_target_access', None)
    if not callable(access):
        raise ValueError(
            'UART endpoint lacks master_target_access; an S4 DMA master FIFO '
            'pop cannot carry a transaction identity without it')
    return DmaMasterRoute(component=component, base=base, size=size,
        readable_offsets=readable,
        writable_offsets=tuple(getattr(window, 'writable_offsets', ())),
        endpoint_identity_sha256=_digest(window.endpoint.identity_document()))


def source_input_sha256(action_id, component, value):
    """The exact byte-action digest ``UartConsumptionTracker`` recomputes.

    ``_validate_frame`` hashes canonical
    ``{action_id, component, port='uart_rx_byte', value, bit_offset=0,
    width=8, kind='source_event'}``.  Using any other shape would produce
    ``uart_source_action_bytes_mismatch`` and never become authority.
    """
    if (not isinstance(action_id, str) or not action_id
            or type(value) is not int or not 0 <= value <= 255):
        raise ValueError('a source action needs an identity and one byte')
    document = dict(action_id=action_id, component=component,
        port=SOURCE_PORT, value=value, bit_offset=SOURCE_BIT_OFFSET,
        width=SOURCE_WIDTH, kind='source_event')
    return hashlib.sha256(_canonical(document)).hexdigest()


@dataclass(frozen=True)
class DmaSourceProvenance:
    """Installed authority context shared by the boot, admissions and replay."""

    paths: DmaRuntimePaths
    master_route: DmaMasterRoute
    source_id: str
    source_component: str
    source_port: str
    source_width: int
    direction: str
    producer_ref: str
    edge_index_sha256: str
    topology_sha256: str

    def admission(self, *, case_id, case_index, action_id, value):
        """Create the admission for one byte that is about to be submitted."""
        if type(case_index) is not int or case_index < 1:
            raise ValueError('case_index must be a positive integer')
        if not isinstance(case_id, str) or not case_id:
            raise ValueError('case_id is required')
        if not isinstance(action_id, str) or not action_id:
            raise ValueError('action_id is required')
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('only one serial byte may be admitted per action')
        return SourceAdmission.create(case_id=case_id,
            case_index=case_index - 1, source_id=self.source_id,
            path_id=self.paths.path_id, direction=self.direction,
            component=self.source_component, action_id=action_id,
            role='fuzz_source', input_kind='source_event',
            input_sha256=source_input_sha256(action_id,
                self.source_component, value))

    def document(self) -> dict:
        return dict(schema_version='dma_source_provenance.v1', installed=True,
            source_id=self.source_id, source_component=self.source_component,
            source_port=self.source_port, source_width=self.source_width,
            direction=self.direction, producer_ref=self.producer_ref,
            path_id=self.paths.path_id,
            graph_sha256=self.paths.contract.graph_sha256,
            contract_sha256=self.paths.contract.identity_sha256,
            topology_sha256=self.topology_sha256,
            edge_index_sha256=self.edge_index_sha256,
            master_route=self.master_route.document(),
            paths=self.paths.document())


NOT_INSTALLED = MappingProxyType(dict(schema_version='dma_source_provenance.v1',
    installed=False))


def compile_dma_source_provenance(runner, *, paths=None):
    """Compile, bind and install the declared source graph on a fresh Runner.

    Must run before the first RTL command (``ScenarioRunner.configure_provenance``
    requires that).  Any topology mismatch, missing DMA master window or missing
    UART ``master_target_access`` raises instead of degrading to an unproven
    run.
    """
    compiled_paths = paths or compile_dma_runtime_paths()
    master_route = declared_dma_master_route(runner)
    prepared = compiled_paths.prepared
    compiled = prepared.bind(runner)
    document = {**compiled.document(), 'declaration': prepared.document()}
    edge_index = RuntimeEdgeIndex(document, compiled_paths.contract.document())
    source = prepared.source_nodes_for(compiled_paths.path_id)[0]
    if (source.source_id != SOURCE_NODE
            or source.component != SOURCE_COMPONENT
            or source.port != SOURCE_PORT):
        raise ValueError('compiled source node differs from the external serial source')
    try:
        owner = runner.ownership.mutation_source(source.component, source.port,
            source.bit_offset, source.width, direction=compiled_paths.direction)
    except (AttributeError, ValueError) as exc:
        raise ValueError('runner does not declare the external serial source') from exc
    ref = edge_index.source_owner_ref(source.source_id, compiled_paths.path_id,
        compiled_paths.direction, source.component, source.port,
        source.bit_offset, source.width)
    if ref is None or owner != ref:
        raise ValueError('external serial source ownership differs from the compiled graph')
    runner.configure_provenance(edge_index)
    return DmaSourceProvenance(paths=compiled_paths, master_route=master_route,
        source_id=source.source_id, source_component=source.component,
        source_port=source.port, source_width=source.width,
        direction=compiled_paths.direction, producer_ref=ref,
        edge_index_sha256=edge_index.identity_sha256,
        topology_sha256=compiled.topology_sha256)


def register_case_admissions(runner, provenance, *, case_id, case_index,
        action_ids, source_bytes):
    """Register every byte admission of one case before its first source event.

    Registration order is the declared serial order, so a fresh replay that
    recomputes the same admissions reproduces the identical journal prefix.
    """
    if not isinstance(provenance, DmaSourceProvenance):
        raise ValueError('installed DMA source provenance is required')
    action_ids = tuple(action_ids)
    source_bytes = tuple(source_bytes)
    if len(action_ids) != len(source_bytes) or not action_ids:
        raise ValueError('one action identity per admitted serial byte is required')
    if len(set(action_ids)) != len(action_ids):
        raise ValueError('duplicate source action identity')
    admissions = []
    for action_id, value in zip(action_ids, source_bytes):
        admission = provenance.admission(case_id=case_id,
            case_index=case_index, action_id=action_id, value=value)
        runner.register_source_admission(admission)
        admissions.append(admission)
    return tuple(admissions)


__all__ = ['SOURCE_NODE', 'SOURCE_COMPONENT', 'SOURCE_PORT', 'SOURCE_WIDTH',
           'SOURCE_DIRECTION', 'UART_BASE', 'UART_SIZE', 'UART_RDATA_OFFSET',
           'DmaRuntimePaths', 'DmaMasterRoute', 'DmaSourceProvenance',
           'NOT_INSTALLED', 'compile_dma_runtime_paths',
           'compile_dma_source_provenance', 'declared_dma_master_route',
           'source_input_sha256', 'register_case_admissions']
