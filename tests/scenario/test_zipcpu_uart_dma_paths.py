"""Topology and beat-admission contracts for the ZipCPU UART DMA route."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.dependency import SourceBinding, SourceBindings
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.zipcpu_uart_dma_paths import (
    DMA_READ_NODE, DMA_WRITE_NODE, RAM_SOURCE_NODE, TXREG_OFFSET,
    UART_TX_NODE, ZipcpuUartDmaBeatAdmission,
    compile_zipcpu_uart_dma_runtime_paths,
)


RAM_BASE = 0x10000000
RAM_SIZE = 0x10000
UART_BASE = 0x40003000
UART_SIZE = 0x10
UART_ARTIFACT_SHA256 = 'a' * 64


def _provider_identity(artifact_digest=UART_ARTIFACT_SHA256):
    return {
        'schema_version': 'zipcpu_uart_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'zipcpu_wbuart_txreg_wishbone_serial.v1',
        'artifact_digest': artifact_digest,
        'instance_id': 'uart',
        'endpoint_id': 'uart.bus',
        'txreg': {
            'operation': 'write', 'offset': TXREG_OFFSET,
            'accepted_write_values': {
                'kind': 'range', 'start': 0, 'stop': 256, 'step': 1},
            'byte_enable': 15,
        },
        'startup_writes': [[0, 25, 15]],
        'serial': {
            'endpoint_id': 'uart.pins', 'role': 'tx',
            'format': '8N1', 'clocks_per_bit': 25,
            'runtime_name': 'obs_uart_tx_o',
        },
        # The route pins this provider map without re-resolving its contents.
        'wishbone_signals': {
            'cyc': 'cyc_i', 'stb': 'stb_i', 'we': 'we_i',
            'adr': 'adr_i', 'dat_w': 'dat_w_i', 'sel': 'sel_i',
            'ack': 'ack_o',
        },
    }


class _UartSession:
    def __init__(self, *, provider_identity=None):
        self._artifact_document = {
            'kind': 'wishbone_uart',
            'artifact_digest': UART_ARTIFACT_SHA256,
        }
        self.artifact = SimpleNamespace(runtime_document=self._artifact_document)
        self.artifact.plan = SimpleNamespace(request=SimpleNamespace(
            instance_id='uart'))
        self._provider_identity = (provider_identity or _provider_identity())
        self.register_writes = []

    def identity_document(self):
        return {'component': 'uart', 'profile': 'generated-zipcpu-wbuart'}

    def dma_master_target_provider_identity_document(self):
        return deepcopy(self._provider_identity)

    def dma_master_target_access(self, *_args, **_kwargs):
        raise AssertionError('route compilation must not access UART RTL')

    def write_register(self, *_args, **_kwargs):
        raise AssertionError('route compilation must not access UART RTL')


class _DmaSession:
    def __init__(self, memory_service, windows):
        self.memory_service = memory_service
        self.master_targets = windows
        self.validator = None
        self.admission = None

    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'test_wishbone_dma_endpoint.v1',
                'profile': 'zipcpu-wbdmac-test'}

    def configure_dma_route_validator(self, callback):
        if self.validator is not None:
            raise ValueError('route validator already configured')
        self.validator = callback

    def configure_dma_route_admission(self, admission):
        if self.admission is not None:
            raise ValueError('route admission already configured')
        self.admission = admission


class _Runner:
    def __init__(self, *, window=True, uart=None, memory=None,
                 duplicate=False, resource_id='ram'):
        self.memory = memory or PersistentMemory(
            regions=(MemoryRegion(resource_id, RAM_BASE, RAM_SIZE),),
            initialization_seed=23, max_initialized_bytes=RAM_SIZE)
        self.uart = uart or _UartSession()
        selected = (MasterTargetWindow('uart', UART_BASE, UART_SIZE, self.uart,
            (TXREG_OFFSET,), range(256)) if window else None)
        windows = (() if selected is None else
                   (selected, selected) if duplicate else (selected,))
        self.dma = _DmaSession(MemoryService(self.memory, TransactionLedger()), windows)
        self.cpu = SimpleNamespace(memory=self.memory)
        self.sessions = {'cpu': self.cpu, 'dma': self.dma, 'uart': self.uart}
        self.ownership = SimpleNamespace(_bits={})
        self.bindings = ()


def test_compiler_binds_exact_ram_dma_uart_and_provider_route():
    runner = _Runner()

    paths = compile_zipcpu_uart_dma_runtime_paths(runner,
        image_id='uart_byte', image_address=RAM_BASE + 0x100)

    assert paths.direction == 'CPU_TO_IP'
    assert paths.path.source_ids == (RAM_SOURCE_NODE,)
    assert paths.path.target == UART_TX_NODE
    assert [edge.kind for edge in paths.path.edges] == [
        'DMA_MASTER_TRANSFER', 'EVENT_ORDER', 'DMA_MASTER_TRANSFER']
    assert paths.graph.sources[RAM_SOURCE_NODE].image_address == RAM_BASE + 0x100
    assert paths.source_bindings.entries == (SourceBinding(
        RAM_SOURCE_NODE, 'memory_image', 'cpu', 'uart_byte', 0, 32,
        'initial_image:cpu:uart_byte', RAM_BASE + 0x100),)
    ram_route, uart_route = paths.contract.dma_master_routes
    assert (ram_route.source_node_id, ram_route.target_node_id) == (
        RAM_SOURCE_NODE, DMA_READ_NODE)
    assert (ram_route.operation, ram_route.target_kind, ram_route.target_id) == (
        'read', 'persistent_memory', 'ram')
    assert (uart_route.source_node_id, uart_route.target_node_id) == (
        DMA_WRITE_NODE, UART_TX_NODE)
    assert (uart_route.operation, uart_route.target_kind,
            uart_route.target_component, uart_route.writable_offsets,
            uart_route.accepted_write_values, uart_route.readable_offsets,
            uart_route.byte_enable) == (
        'write', 'peripheral', 'uart', (TXREG_OFFSET,), range(256), (), 15)
    assert paths.prepared.document()['schema_version'] == 'prepared_runtime_paths.v2'
    assert paths.compiled.document()['schema_version'] == 'runtime_path_compilation.v2'
    paths.compiled.validate_topology()
    assert runner.dma.validator is not None
    assert runner.dma.admission is paths.admission
    assert runner.uart.register_writes == []

    identity = runner.uart.dma_master_target_provider_identity_document()
    assert identity['schema_version'] == 'zipcpu_uart_dma_target_provider.v1'
    assert identity['api_schema_version'] == 'dma_master_target_access.v1'
    assert identity['implementation_profile'] == 'zipcpu_wbuart_txreg_wishbone_serial.v1'
    assert identity['artifact_digest'] == UART_ARTIFACT_SHA256
    assert identity['instance_id'] == 'uart'
    assert identity['endpoint_id'] == 'uart.bus'
    assert identity['txreg']['offset'] == TXREG_OFFSET
    assert identity['txreg']['accepted_write_values'] == {
        'kind': 'range', 'start': 0, 'stop': 256, 'step': 1}
    assert identity['txreg']['byte_enable'] == 15
    assert identity['startup_writes'] == [[0, 25, 15]]
    assert identity['serial'] == {
        'endpoint_id': 'uart.pins', 'role': 'tx',
        'format': '8N1', 'clocks_per_bit': 25,
        'runtime_name': 'obs_uart_tx_o'}
    assert paths.document()['provider_identity'] == identity
    assert paths.document()['provider_identity_sha256']


@pytest.mark.parametrize('kwargs,match', [
    ({'window': False}, 'window is missing or ambiguous'),
    ({'duplicate': True}, 'window is missing or ambiguous'),
    ({'resource_id': 'missing'}, 'RAM region is missing or ambiguous'),
])
def test_compiler_refuses_incomplete_or_ambiguous_topology(kwargs, match):
    with pytest.raises(ValueError, match=match):
        compile_zipcpu_uart_dma_runtime_paths(_Runner(**kwargs))


def test_compiler_requires_the_exact_registered_uart_session_object():
    runner = _Runner()
    other = _UartSession()
    runner.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
        UART_SIZE, other, (TXREG_OFFSET,), range(256)),)

    with pytest.raises(ValueError, match='endpoint is not the registered UART session'):
        compile_zipcpu_uart_dma_runtime_paths(runner)


@pytest.mark.parametrize('change', [
    'component', 'size', 'offset', 'values'])
def test_compiler_requires_the_unique_full_word_txreg_window(change):
    runner = _Runner()
    if change == 'component':
        runner.dma.master_targets = (MasterTargetWindow('other', UART_BASE,
            UART_SIZE, runner.uart, (TXREG_OFFSET,), range(256)),)
    elif change == 'size':
        runner.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
            0x20, runner.uart, (TXREG_OFFSET,), range(256)),)
    elif change == 'offset':
        runner.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
            UART_SIZE, runner.uart, (8,), range(256)),)
    elif change == 'values':
        runner.dma.master_targets = (MasterTargetWindow('uart', UART_BASE,
            UART_SIZE, runner.uart, (TXREG_OFFSET,), range(1, 256)),)

    with pytest.raises(ValueError, match='window|route|target'):
        compile_zipcpu_uart_dma_runtime_paths(runner)
    assert runner.uart.register_writes == []


def test_compiler_refuses_unselected_dma_target_windows():
    runner = _Runner()
    other = _UartSession()
    runner.sessions['other'] = other
    runner.dma.master_targets = (runner.dma.master_targets[0],
        MasterTargetWindow('other', 0x40004000, UART_SIZE, other,
                           (TXREG_OFFSET,), range(256)))

    with pytest.raises(ValueError, match='unselected peripheral routes'):
        compile_zipcpu_uart_dma_runtime_paths(runner)


def test_compiler_requires_the_dma_ram_owner_to_share_the_exact_memory_service_resource():
    runner = _Runner()
    other_memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=23, max_initialized_bytes=RAM_SIZE)
    runner.cpu.memory = other_memory

    with pytest.raises(ValueError, match='exact shared memory service/resource'):
        compile_zipcpu_uart_dma_runtime_paths(runner)


@pytest.mark.parametrize('field,value', [
    ('schema_version', 'wrong.v1'),
    ('api_schema_version', 'wrong.v1'),
    ('implementation_profile', 'other.v1'),
    ('artifact_digest', 'b' * 64),
])
def test_compiler_refuses_provider_identity_that_does_not_match_profile(field, value):
    identity = _provider_identity()
    identity[field] = value
    runner = _Runner(uart=_UartSession(provider_identity=identity))

    with pytest.raises(ValueError, match='provider identity|artifact'):
        compile_zipcpu_uart_dma_runtime_paths(runner)


@pytest.mark.parametrize('change', [
    'txreg_offset', 'txreg_range', 'txreg_byte_enable', 'startup',
    'serial_endpoint', 'serial_role', 'serial_timing', 'wishbone_roles'])
def test_compiler_refuses_provider_identity_outside_fixed_tx_and_serial_contract(change):
    identity = _provider_identity()
    if change == 'txreg_offset':
        identity['txreg']['offset'] = 8
    elif change == 'txreg_range':
        identity['txreg']['accepted_write_values']['stop'] = 257
    elif change == 'txreg_byte_enable':
        identity['txreg']['byte_enable'] = 1
    elif change == 'startup':
        identity['startup_writes'] = [[0, 24, 15]]
    elif change == 'serial_endpoint':
        identity['serial']['endpoint_id'] = 'other.pins'
    elif change == 'serial_role':
        identity['serial']['role'] = 'rx'
    elif change == 'serial_timing':
        identity['serial']['clocks_per_bit'] = 16
    else:
        identity['wishbone_signals'].pop('ack')
    runner = _Runner(uart=_UartSession(provider_identity=identity))

    with pytest.raises(ValueError, match='provider identity'):
        compile_zipcpu_uart_dma_runtime_paths(runner)


def test_compiled_topology_pins_the_full_live_provider_identity():
    runner = _Runner()
    paths = compile_zipcpu_uart_dma_runtime_paths(runner)
    pinned = deepcopy(paths.document()['provider_identity'])
    assert pinned == runner.uart.dma_master_target_provider_identity_document()

    runner.uart._provider_identity['wishbone_signals']['ack'] = 'wrong_ack'
    with pytest.raises(ValueError, match='topology|identity'):
        paths.compiled.validate_topology()


@pytest.mark.parametrize('byte_value', [0, 1, 0xA5, 255])
def test_admission_accepts_one_ram_byte_and_same_txreg_value(byte_value):
    runner = _Runner()
    paths = compile_zipcpu_uart_dma_runtime_paths(runner,
        image_address=RAM_BASE + 0x100)
    admission = paths.admission
    read_key = TransactionKey('dma-run', 'case', 'dma', 0,
                              'dma-memory', 1)
    write_key = TransactionKey('dma-run', 'case', 'dma', 0,
                               'dma-memory', 2)

    admission.accepted(read_key, address=RAM_BASE + 0x100, write=False,
        value=0, byte_enable=15, target=None)
    admission.completed(read_key, rdata=byte_value, error=0)
    admission.accepted(write_key, address=UART_BASE + TXREG_OFFSET,
        write=True, value=byte_value, byte_enable=15,
        target=runner.dma.master_targets[0])
    admission.completed(write_key, rdata=0, error=0)

    assert admission.state == 'complete'


@pytest.mark.parametrize('case', ['too_large', 'mismatch', 'wrong_target', 'replay'])
def test_admission_refuses_values_or_beats_outside_single_txreg_byte(case):
    runner = _Runner()
    admission = compile_zipcpu_uart_dma_runtime_paths(runner).admission
    read_key = TransactionKey('dma-run', 'case', 'dma', 0,
                              'dma-memory', 1)
    write_key = TransactionKey('dma-run', 'case', 'dma', 0,
                               'dma-memory', 2)

    admission.accepted(read_key, address=RAM_BASE, write=False,
        value=0, byte_enable=15, target=None)
    if case == 'too_large':
        with pytest.raises(ValueError, match='0..255|byte'):
            admission.completed(read_key, rdata=256, error=0)
        return
    admission.completed(read_key, rdata=0x5A, error=0)
    if case == 'mismatch':
        with pytest.raises(ValueError, match='same|source|TXREG'):
            admission.accepted(write_key, address=UART_BASE + TXREG_OFFSET,
                write=True, value=0x5B, byte_enable=15,
                target=runner.dma.master_targets[0])
    elif case == 'wrong_target':
        other = MasterTargetWindow('other', UART_BASE + 0x1000, UART_SIZE,
            _UartSession(), (TXREG_OFFSET,), range(256))
        with pytest.raises(ValueError, match='declared|TXREG|UART'):
            admission.accepted(write_key, address=UART_BASE + 0x1000 + TXREG_OFFSET,
                write=True, value=0x5A, byte_enable=15, target=other)
    else:
        admission.accepted(write_key, address=UART_BASE + TXREG_OFFSET,
            write=True, value=0x5A, byte_enable=15,
            target=runner.dma.master_targets[0])
        admission.completed(write_key, rdata=0, error=0)
        with pytest.raises(ValueError, match='complete'):
            admission.accepted(TransactionKey('dma-run', 'case', 'dma', 0,
                'dma-memory', 3), address=RAM_BASE, write=False,
                value=0, byte_enable=15, target=None)


def test_admission_rejects_out_of_order_or_untyped_source_transactions():
    admission = compile_zipcpu_uart_dma_runtime_paths(_Runner()).admission
    with pytest.raises(ValueError, match='typed transaction key'):
        admission.accepted('not-a-key', address=RAM_BASE, write=False,
            value=0, byte_enable=15, target=None)
    with pytest.raises(ValueError, match='declared RAM image word'):
        admission.accepted(TransactionKey('dma-run', 'case', 'dma', 0,
            'dma-memory', 1), address=RAM_BASE + 4, write=False,
            value=0, byte_enable=15, target=None)


def test_source_binding_matches_the_real_genome_image_address_and_byte():
    paths = compile_zipcpu_uart_dma_runtime_paths(_Runner(),
        image_id='uart_byte', image_address=RAM_BASE + 4)
    genome = ScenarioGenome('dma-source', 'CPU_TO_IP', paths.path_id,
        ('cpu',), 1, (), initial_images=(MemoryImage(
            'uart_byte', 'cpu', RAM_BASE + 4, 'a5000000'),))

    paths.validate_source_genomes((genome,))

    wrong_address = ScenarioGenome('dma-source-wrong', 'CPU_TO_IP', paths.path_id,
        ('cpu',), 1, (), initial_images=(MemoryImage(
            'uart_byte', 'cpu', RAM_BASE + 8, 'a5000000'),))
    with pytest.raises(ValueError, match='address differs'):
        paths.validate_source_genomes((wrong_address,))


def test_admission_identity_pins_the_word_and_txreg_window_read_only():
    paths = compile_zipcpu_uart_dma_runtime_paths(_Runner(),
        image_address=RAM_BASE + 0x40)
    admission = paths.admission
    identity = admission.identity_document()
    assert identity['source']['address'] == RAM_BASE + 0x40
    assert identity['target']['address'] == UART_BASE + TXREG_OFFSET
    assert identity['target']['offset'] == TXREG_OFFSET
    assert identity['transfer']['accepted_values'] == {
        'kind': 'range', 'start': 0, 'stop': 256, 'step': 1}
    assert identity['transfer']['value_equals_read_response'] is True
    with pytest.raises(AttributeError, match='read-only'):
        admission._image_address = RAM_BASE + 4
