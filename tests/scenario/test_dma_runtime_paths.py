"""Pure tests for the declared UART RX FIFO source graph (S4)."""
import pytest

from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.dma_runtime_paths import (
    NODES, RULES, SOURCE_NODE, compile_dma_runtime_paths,
    compile_dma_source_provenance, declared_dma_master_route,
    register_case_admissions, source_input_sha256)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import (InputField, InputOwner, compile_ownership)
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimeEdgeContract, RuntimePathContract, _digest)
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory_service import MemoryService

UART_BASE = 0x50000000
UART_SIZE = 0x1000
DMA_BASE = 0x3000


class _UartFake:
    def __init__(self):
        self.master_access = True
        self.calls = []

    def identity_document(self):
        return {'component': 'uart', 'fake': True}

    def read_register(self, offset):
        return 0

    def write_register(self, offset, value, *, be=15):
        return None

    def master_target_access(self, key, *, address, offset, write, value, be,
                             delivery_context):
        self.calls.append(dict(address=address, offset=offset, write=write,
                               value=value, be=be,
                               delivery_context=delivery_context))
        return {'rdata': 0x5A, 'target_uart_access': {
            'kind': 'uart_rdata_access', 'status': 'observed',
            'read_value': 0x5A, 'access_id': 'uart-access:uart:0:1'}}


class _SessionFake:
    def __init__(self, *, memory=None, router=None):
        self.memory = memory
        self.router = router
        self.routed_register_access_enabled = True

    def identity_document(self):
        return {'component': getattr(self, 'component', 'session'), 'fake': True}

    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'fake_dma_route_endpoint.v1',
                'source_component': 'dma', 'fake': True}

    def configure_dma_route_validator(self, callback):
        if getattr(self, '_validator', None) is not None:
            raise ValueError('DMA route validator already configured')
        self._validator = callback


class _RunnerFake:
    def __init__(self, *, producer='external-serial-byte'):
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=17, max_initialized_bytes=0x20000)
        self.uart = _UartFake()
        self.cpu = _SessionFake(memory=memory)
        self.dma = _SessionFake()
        self.dma.memory_service = MemoryService(memory, TransactionLedger())
        self.dma.source_component = 'dma'
        self.sessions = {'cpu': self.cpu, 'dma': self.dma, 'uart': self.uart}
        self.cpu.router = DataflowRouter((
            DeviceWindow('dma', DMA_BASE, 16, self.dma),
            DeviceWindow('uart', UART_BASE, UART_SIZE, self.uart)))
        self.dma.master_targets = (MasterTargetWindow('uart', UART_BASE, UART_SIZE,
            self.uart, (0x1C,), range(256), readable_offsets=(0x18,)),)
        self.ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
             InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', producer)))
        self.bindings = (Binding('dma', 'irq', 'cpu', 'irq', 1),)
        self._provenance = None
        self.admissions = {}

    @property
    def provenance_enabled(self):
        return self._provenance is not None

    def configure_provenance(self, edge_index):
        if self._provenance is not None:
            raise AssertionError('provenance configured twice')
        self._provenance = edge_index

    def register_source_admission(self, admission):
        self.admissions[admission.action_id] = admission


def test_declared_graph_resolves_to_one_declared_source_path():
    paths = compile_dma_runtime_paths(_RunnerFake())
    assert paths.direction == 'IP_TO_CPU'
    assert paths.path.source_ids == (SOURCE_NODE,)
    assert paths.path.target == 'cpu.isr'
    assert sorted({edge.rule_index for edge in paths.path.edges}) == list(range(len(RULES)))
    assert len(paths.path.edges) == len(RULES) + 1 == 13
    assert [route.key for route in paths.contract.dma_master_routes] == [(3, 0), (7, 0)]
    assert paths.contract.document()['schema_version'] == 'runtime_path_contract.v2'
    assert paths.contract.dma_master_routes[0].operation == 'read'
    assert paths.contract.dma_master_routes[0].source_node_id == 'uart.fifo_entry'
    assert paths.contract.dma_master_routes[1].operation == 'write'
    assert paths.contract.dma_master_routes[1].target_node_id == 'ram.master_write'
    document = paths.document()
    assert document['graph_sha256'] == _digest(paths.graph.edge_document())
    assert document['contract_sha256'] == paths.contract.identity_sha256
    # Recompiling is deterministic: no host identity enters the declaration.
    assert compile_dma_runtime_paths(_RunnerFake()).path_id == paths.path_id
    assert {node.node_id for node in NODES} == {
        node.node_id for node in paths.contract.nodes}


def test_missing_dma_route_declaration_is_refused_at_prepare():
    paths = compile_dma_runtime_paths(_RunnerFake())
    edges = tuple(edge for edge in paths.contract.edges if edge.key != (3, 0))
    routes = tuple(route for route in paths.contract.dma_master_routes
                   if route.key != (3, 0))
    contract = RuntimePathContract(paths.contract.graph_sha256, NODES, edges, routes)
    with pytest.raises(ValueError, match='selected DMA master edges'):
        PreparedRuntimePathContract(paths.graph, contract,
            ((paths.direction, paths.path),))


def test_wrong_relation_is_refused():
    paths = compile_dma_runtime_paths(_RunnerFake())
    wrong = tuple(
        RuntimeEdgeContract(edge.rule_index, edge.prerequisite_index,
            'persistent_state', resource_component='cpu', resource_id='ram')
        if edge.key == (7, 0) else edge
        for edge in paths.contract.edges)
    contract = RuntimePathContract(paths.contract.graph_sha256, NODES, wrong)
    with pytest.raises(ValueError, match='relation incompatible'):
        PreparedRuntimePathContract(paths.graph, contract,
            ((paths.direction, paths.path),))


def test_wrong_graph_digest_is_refused():
    paths = compile_dma_runtime_paths(_RunnerFake())
    contract = RuntimePathContract('0' * 64, NODES, paths.contract.edges)
    with pytest.raises(ValueError, match='graph digest mismatch'):
        PreparedRuntimePathContract(paths.graph, contract,
            ((paths.direction, paths.path),))


def test_missing_node_declaration_is_refused():
    paths = compile_dma_runtime_paths(_RunnerFake())
    nodes = tuple(node for node in NODES if node.node_id != SOURCE_NODE)
    contract = RuntimePathContract(paths.contract.graph_sha256, nodes,
        paths.contract.edges)
    with pytest.raises(ValueError, match='source node component mismatch'):
        PreparedRuntimePathContract(paths.graph, contract,
            ((paths.direction, paths.path),))


def test_installed_provenance_resolves_the_real_source_owner():
    runner = _RunnerFake()
    provenance = compile_dma_source_provenance(runner)
    assert runner.provenance_enabled
    assert provenance.source_id == SOURCE_NODE
    assert provenance.source_component == 'uart'
    assert provenance.producer_ref == 'external-serial-byte'
    edge_index = runner._provenance
    assert edge_index.source_owner_ref(SOURCE_NODE, provenance.paths.path_id,
        'IP_TO_CPU', 'uart', 'uart_rx_byte', 0, 8) == 'external-serial-byte'
    # The producer reference is not the graph source id: it resolves nothing.
    assert edge_index.source_owner_ref('external-serial-byte',
        provenance.paths.path_id, 'IP_TO_CPU', 'uart', 'uart_rx_byte', 0,
        8) is None
    # A partial range is authority only inside the admitted source range.
    assert edge_index.source_owner_ref(SOURCE_NODE, provenance.paths.path_id,
        'IP_TO_CPU', 'uart', 'uart_rx_byte', 4, 4) == 'external-serial-byte'
    assert edge_index.source_owner_ref(SOURCE_NODE, provenance.paths.path_id,
        'IP_TO_CPU', 'uart', 'uart_rx_byte', 4, 8) is None


def test_non_source_ownership_is_refused_at_install():
    # The source bits must be owned by a fuzzable source; a fixed/bound owner
    # cannot be admitted as an external serial producer.
    runner = _RunnerFake()
    runner.ownership = compile_ownership(
        (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'dma.irq'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'fixed', 'fixed.pin')))
    with pytest.raises(ValueError):
        compile_dma_source_provenance(runner)
    assert not runner.provenance_enabled


def test_missing_master_target_window_capability_is_the_named_requirement():
    runner = _RunnerFake()
    runner.uart.master_target_access = None
    with pytest.raises(ValueError, match='master_target_access'):
        compile_dma_source_provenance(runner)
    assert not runner.provenance_enabled


def test_wrong_master_window_aperture_is_refused():
    runner = _RunnerFake()
    runner.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
        UART_SIZE, runner.uart, (0x1C,), range(256),
        readable_offsets=(0x18,)),)
    # A DMA session routing a different aperture cannot be the declared route.
    with pytest.raises(ValueError, match='missing or ambiguous'):
        declared_dma_master_route(runner, base=UART_BASE + 0x1000)
    with pytest.raises(ValueError, match='missing or ambiguous'):
        declared_dma_master_route(runner, size=0x2000)
    runner.dma.master_targets = ()
    with pytest.raises(ValueError, match='missing or ambiguous'):
        declared_dma_master_route(runner)


def test_readable_offsets_must_be_exactly_rdata():
    runner = _RunnerFake()
    # The declared window route is fixed at RDATA 0x18; a different declared
    # read offset cannot inherit that route.
    with pytest.raises(ValueError, match='RDATA'):
        declared_dma_master_route(runner, readable_offset=0x14)


def test_case_admissions_follow_serial_order_and_the_tracker_digest():
    runner = _RunnerFake()
    provenance = compile_dma_source_provenance(runner)
    admissions = register_case_admissions(runner, provenance,
        case_id='descriptor-case-1', case_index=1,
        action_ids=('descriptor-1-0', 'descriptor-1-1'),
        source_bytes=(0x5A, 0x00))
    assert [admission.action_id for admission in admissions] == [
        'descriptor-1-0', 'descriptor-1-1']
    assert [admission.input_sha256 for admission in admissions] == [
        source_input_sha256('descriptor-1-0', 'uart', 0x5A),
        source_input_sha256('descriptor-1-1', 'uart', 0x00)]
    assert all(admission.path_id == provenance.paths.path_id
               for admission in admissions)
    assert all(admission.case_id == 'descriptor-case-1'
               and admission.case_index == 0 for admission in admissions)
    assert set(runner.admissions) == {'descriptor-1-0', 'descriptor-1-1'}


def test_case_admissions_refuse_duplicates_and_mismatched_bytes():
    runner = _RunnerFake()
    provenance = compile_dma_source_provenance(runner)
    with pytest.raises(ValueError, match='duplicate'):
        register_case_admissions(runner, provenance, case_id='c1',
            case_index=1, action_ids=('a', 'a'), source_bytes=(1, 2))
    with pytest.raises(ValueError, match='one action identity'):
        register_case_admissions(runner, provenance, case_id='c1',
            case_index=1, action_ids=('a',), source_bytes=(1, 2))
    with pytest.raises(ValueError):
        register_case_admissions(runner, provenance, case_id='c1',
            case_index=1, action_ids=('a',), source_bytes=(256,))
    with pytest.raises(ValueError, match='installed DMA source provenance'):
        register_case_admissions(runner, object(), case_id='c1',
            case_index=1, action_ids=('a',), source_bytes=(1,))


def test_source_input_digest_is_the_declared_canonical_shape():
    import hashlib, json
    expected = hashlib.sha256(json.dumps(dict(action_id='a', component='uart',
        port='uart_rx_byte', value=0x5A, bit_offset=0, width=8,
        kind='source_event'), sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    assert source_input_sha256('a', 'uart', 0x5A) == expected
    with pytest.raises(ValueError):
        source_input_sha256('', 'uart', 0x5A)
    with pytest.raises(ValueError):
        source_input_sha256('a', 'uart', 0x100)


def test_provenance_document_is_stable_and_has_no_execution_identity():
    runner = _RunnerFake()
    provenance = compile_dma_source_provenance(runner)
    document = provenance.document()
    assert document['installed'] is True
    assert document['master_route']['base'] == UART_BASE
    assert document['master_route']['size'] == UART_SIZE
    assert document['master_route']['readable_offsets'] == [0x18]
    assert 'execution' not in repr(document)
