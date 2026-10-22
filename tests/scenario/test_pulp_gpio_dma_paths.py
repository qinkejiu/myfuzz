"""Prepared RAM-to-PULP-GPIO DMA route declarations."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.pulp_gpio_dma_paths import (
    GPIO_PADOUT_OFFSET, GPIO_PADOUT_NODE, RAM_SOURCE_NODE,
    compile_pulp_gpio_dma_runtime_paths,
)
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimePathContract,
)

GPIO_BASE = 0x40001000
GPIO_SIZE = 0x1000
RAM_BASE = 0x10000000
RAM_SIZE = 0x10000


class _GpioSession:
    def __init__(self):
        self.calls = []
        self.routed_register_access_enabled = True
        self.artifact = SimpleNamespace(runtime_document={
            'kind': 'apb_gpio',
            'gpio_observation_contract': pulp_gpio_observation_contract()})

    def identity_document(self):
        return {'component': 'gpio', 'profile': 'pulp-apb3-test-v1'}

    def dma_master_target_provider_identity_document(self):
        return {
            'schema_version': 'pulp_gpio_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'pulp_gpio_padout_apb3.v1',
            'observation_contract': pulp_gpio_observation_contract(),
            'operations': [{'operation': 'write', 'register': 'PADOUT',
                            'offset': GPIO_PADOUT_OFFSET, 'byte_enable': 15}],
        }

    def write_register(self, offset, value, *, be=15):
        self.calls.append(('write_register', offset, value, be))

    def dma_master_target_access(self, *args, **kwargs):
        self.calls.append(('dma_master_target_access', args, kwargs))
        raise AssertionError('route compilation must not execute the target provider')


class _DmaSession:
    def __init__(self, memory_service, windows):
        self.memory_service = memory_service
        self.master_targets = windows
        self._route_validator = None
        self.route_admission = None

    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'test_wishbone_dma_endpoint.v1',
                'profile': 'zipcpu-wbdmac-test'}

    def configure_dma_route_validator(self, callback):
        if self._route_validator is not None:
            raise ValueError('DMA route validator already configured')
        self._route_validator = callback

    def configure_dma_route_admission(self, admission):
        if self.route_admission is not None:
            raise ValueError('DMA route admission already configured')
        self.route_admission = admission


class _Runner:
    def __init__(self, *, window=True, target=None, memory=None,
                 resource_id='ram', duplicate=False):
        self.memory = memory or PersistentMemory(
            regions=(MemoryRegion(resource_id, RAM_BASE, RAM_SIZE),),
            initialization_seed=13, max_initialized_bytes=RAM_SIZE)
        self.gpio = target or _GpioSession()
        self.window = (MasterTargetWindow('gpio', GPIO_BASE, GPIO_SIZE,
            self.gpio, (GPIO_PADOUT_OFFSET,), range(256)) if window else None)
        windows = (() if self.window is None else
                   (self.window, self.window) if duplicate else (self.window,))
        self.dma = _DmaSession(MemoryService(self.memory, TransactionLedger()),
                               windows)
        self.cpu = SimpleNamespace(memory=self.memory)
        self.sessions = {'cpu': self.cpu, 'dma': self.dma, 'gpio': self.gpio}
        self.ownership = SimpleNamespace(_bits={})
        self.bindings = ()


def test_prepare_builds_pulp_paths_without_binding_or_installing_admission():
    import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths

    prepare = getattr(pulp_paths, 'prepare_pulp_gpio_dma_runtime_paths', None)
    assert callable(prepare)
    runner = _Runner()

    paths = prepare(runner)

    assert paths.compiled is None
    assert runner.dma._route_validator is None
    assert runner.dma.route_admission is None
    assert paths.admission.image_address == RAM_BASE
    with pytest.raises(ValueError, match='not topology-bound'):
        paths.document()


def test_compile_pulp_paths_binds_prepared_object_once_and_installs_legacy_admission():
    from unittest.mock import patch
    import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths

    runner = _Runner()
    prepared_objects = []
    bound_objects = []
    original_prepare = pulp_paths.prepare_pulp_gpio_dma_runtime_paths
    original_bind = PreparedRuntimePathContract.bind

    def prepare_spy(*args, **kwargs):
        paths = original_prepare(*args, **kwargs)
        prepared_objects.append(paths)
        return paths

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(pulp_paths, 'prepare_pulp_gpio_dma_runtime_paths', prepare_spy), \
         patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        paths = pulp_paths.compile_pulp_gpio_dma_runtime_paths(runner)

    assert len(prepared_objects) == 1
    assert len(bound_objects) == 1
    assert bound_objects[0] is prepared_objects[0].prepared is paths.prepared
    assert paths.compiled is not None
    assert runner.dma.route_admission is paths.admission


def _runner_with_window(window):
    runner = _Runner()
    runner.dma.master_targets = (window,)
    return runner


def _rebind_with_route(runner, paths, *, route_key=(2, 0), **changes):
    changed_routes = tuple(
        replace(route, **changes) if route.key == route_key else route
        for route in paths.contract.dma_master_routes)
    changed_contract = RuntimePathContract(paths.contract.graph_sha256,
        paths.contract.nodes, paths.contract.edges, changed_routes)
    prepared = PreparedRuntimePathContract(paths.graph, changed_contract,
        ((paths.direction, paths.path),))
    return prepared.bind(runner)


def test_compiler_declares_and_binds_ram_read_to_gpio_padout_write():
    runner = _Runner()

    paths = compile_pulp_gpio_dma_runtime_paths(runner)

    assert paths.direction == 'CPU_TO_IP'
    assert paths.image_address == RAM_BASE
    assert paths.graph.sources[RAM_SOURCE_NODE].image_address == RAM_BASE
    assert paths.source_bindings.entries[0].image_address == RAM_BASE
    assert paths.path.source_ids == (RAM_SOURCE_NODE,)
    assert paths.path.target == GPIO_PADOUT_NODE
    assert [(edge.rule_index, edge.kind) for edge in paths.path.edges] == [
        (0, 'DMA_MASTER_TRANSFER'), (1, 'EVENT_ORDER'),
        (2, 'DMA_MASTER_TRANSFER')]
    read_route, write_route = paths.contract.dma_master_routes
    assert (read_route.key, read_route.operation, read_route.endpoint_id) == (
        (0, 0), 'read', 'read_master')
    assert (read_route.target_kind, read_route.target_component,
            read_route.target_id, read_route.base, read_route.size) == (
        'persistent_memory', 'cpu', 'ram', RAM_BASE, RAM_SIZE)
    assert read_route.permissions == ('read', 'write')
    assert (write_route.key, write_route.operation, write_route.endpoint_id) == (
        (2, 0), 'write', 'write_master')
    assert (write_route.target_kind, write_route.target_component,
            write_route.target_id, write_route.base, write_route.size) == (
        'peripheral', 'gpio', 'gpio', GPIO_BASE, GPIO_SIZE)
    assert write_route.writable_offsets == (GPIO_PADOUT_OFFSET,)
    assert write_route.readable_offsets == ()
    assert write_route.accepted_write_values == range(256)
    assert write_route.byte_enable == 15
    assert paths.prepared.document()['schema_version'] == 'prepared_runtime_paths.v2'
    assert paths.compiled.document()['schema_version'] == 'runtime_path_compilation.v2'
    assert len(paths.compiled.dma_master_routes) == 2
    paths.compiled.validate_topology()
    assert runner.dma._route_validator is not None
    assert runner.dma.route_admission is paths.admission
    assert runner.gpio.calls == []


def test_dma_admission_exposes_canonical_identity_and_read_only_route_config():
    paths = compile_pulp_gpio_dma_runtime_paths(_Runner(),
        image_address=RAM_BASE + 4)
    admission = paths.admission

    identity = admission.identity_document()
    assert identity['schema_version'] == 'pulp_gpio_dma_beat_admission_identity.v1'
    assert identity['profile'] == 'pulp_gpio_ram_word_to_padout.v1'
    assert identity['source'] == {
        'operation': 'read', 'address': RAM_BASE + 4,
        'word_bytes': 4, 'byte_enable': 15}
    assert identity['target']['operation'] == 'write'
    assert identity['target']['address'] == GPIO_BASE + GPIO_PADOUT_OFFSET
    assert identity['target']['offset'] == GPIO_PADOUT_OFFSET
    assert identity['target']['window'] == admission.gpio_window.route_identity_document()
    assert identity['transfer'] == {
        'word_count': 1, 'write_value': 'read_response'}
    canonical = json.dumps(identity, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8')
    admission_document = paths.document()['dma_beat_admission']
    assert admission_document['identity'] == identity
    assert admission_document['identity_sha256'] == hashlib.sha256(canonical).hexdigest()

    identity['target']['window']['base'] = 0
    assert admission.identity_document()['target']['window']['base'] == GPIO_BASE
    with pytest.raises(AttributeError):
        admission.image_address = RAM_BASE + 8
    with pytest.raises(AttributeError):
        admission.gpio_window = None
    with pytest.raises(AttributeError):
        admission.write_address = GPIO_BASE + 0x10


def test_source_binding_matches_the_real_genome_image_address_and_word():
    paths = compile_pulp_gpio_dma_runtime_paths(_Runner(),
        image_address=RAM_BASE + 4)
    genome = ScenarioGenome('dma-source', 'CPU_TO_IP', 'pulp-padout',
        ('cpu',), 1, (), initial_images=(MemoryImage(
            'dma_payload', 'cpu', RAM_BASE + 4, '78563412'),))

    paths.validate_source_genomes((genome,))

    wrong_address = ScenarioGenome('dma-source-wrong', 'CPU_TO_IP',
        'pulp-padout', ('cpu',), 1, (), initial_images=(MemoryImage(
            'dma_payload', 'cpu', RAM_BASE + 8, '78563412'),))
    with pytest.raises(ValueError, match='address differs'):
        paths.validate_source_genomes((wrong_address,))


def test_declared_image_address_changes_prepared_and_compiled_identity():
    first = compile_pulp_gpio_dma_runtime_paths(_Runner(), image_address=RAM_BASE)
    second = compile_pulp_gpio_dma_runtime_paths(_Runner(), image_address=RAM_BASE + 4)

    assert first.graph.edge_document()['schema_version'] == 'dependency_edge_graph.v2'
    assert first.graph.edge_document()['sources'][0]['image_address'] == RAM_BASE
    assert first.prepared.document()['graph']['sources'][0]['image_address'] == RAM_BASE
    assert first.contract.graph_sha256 != second.contract.graph_sha256
    assert first.prepared.document() != second.prepared.document()
    assert first.compiled.identity_sha256 != second.compiled.identity_sha256


@pytest.mark.parametrize('image_address', [RAM_BASE - 4, RAM_BASE + RAM_SIZE - 2,
                                           RAM_BASE + 1])
def test_source_image_word_must_be_aligned_and_inside_declared_ram(image_address):
    runner = _Runner()

    with pytest.raises(ValueError, match='image address'):
        compile_pulp_gpio_dma_runtime_paths(runner,
            image_address=image_address)

    assert runner.gpio.calls == []


@pytest.mark.parametrize('case', ['missing', 'ambiguous'])
def test_missing_or_ambiguous_gpio_master_window_is_rejected(case):
    runner = _Runner(window=case != 'missing', duplicate=case == 'ambiguous')

    with pytest.raises(ValueError):
        compile_pulp_gpio_dma_runtime_paths(runner)

    assert runner.gpio.calls == []


def test_unselected_dma_master_window_is_rejected():
    runner = _Runner()
    other = _GpioSession()
    extra = MasterTargetWindow('other', 0x40002000, GPIO_SIZE, other,
        (GPIO_PADOUT_OFFSET,), range(256))
    runner.dma.master_targets = (runner.window, extra)
    runner.sessions['other'] = other

    with pytest.raises(ValueError, match='selected peripheral routes'):
        compile_pulp_gpio_dma_runtime_paths(runner)

    assert runner.gpio.calls == []
    assert other.calls == []


def test_window_endpoint_must_be_the_registered_gpio_session():
    runner = _Runner()
    other_gpio = _GpioSession()
    runner.dma.master_targets = (replace(runner.window, endpoint=other_gpio),)

    with pytest.raises(ValueError):
        compile_pulp_gpio_dma_runtime_paths(runner)

    assert runner.gpio.calls == []
    assert other_gpio.calls == []


@pytest.mark.parametrize('change', ['wrong_resource', 'split_memory', 'missing_component'])
def test_dma_ram_read_requires_exact_live_shared_memory(change):
    runner = _Runner()
    if change == 'wrong_resource':
        resource_id = 'missing'
    elif change == 'split_memory':
        other_memory = PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
            initialization_seed=13, max_initialized_bytes=RAM_SIZE)
        runner.cpu.memory = other_memory
        resource_id = 'ram'
    else:
        resource_id = 'ram'

    with pytest.raises(ValueError):
        compile_pulp_gpio_dma_runtime_paths(runner,
            memory_component=('missing' if change == 'missing_component' else 'cpu'),
            resource_id=resource_id)

    assert runner.gpio.calls == []


def test_gpio_window_must_declare_full_word_padout_write():
    runner = _Runner()
    runner.dma.master_targets = (replace(runner.window,
        writable_offsets=(GPIO_PADOUT_OFFSET - 4,)),)

    with pytest.raises(ValueError):
        compile_pulp_gpio_dma_runtime_paths(runner)

    assert runner.gpio.calls == []


@pytest.mark.parametrize('change', ['offset', 'accepted_values', 'permissions'])
def test_contract_route_cannot_drift_from_live_gpio_window(change):
    source_runner = _Runner()
    paths = compile_pulp_gpio_dma_runtime_paths(source_runner)
    target_runner = _Runner()
    if change == 'offset':
        changed = {'writable_offsets': (GPIO_PADOUT_OFFSET - 4,)}
    elif change == 'accepted_values':
        changed = {'accepted_write_values': (0x5A,)}
    else:
        changed = {'readable_offsets': (0,), 'permissions': ('read', 'write')}

    with pytest.raises(ValueError):
        _rebind_with_route(target_runner, paths, **changed)

    assert target_runner.gpio.calls == []


def test_post_compile_master_window_replacement_invalidates_topology():
    runner = _Runner()
    paths = compile_pulp_gpio_dma_runtime_paths(runner)
    runner.dma.master_targets = (replace(runner.window,
        accepted_write_values=(0x5A,)),)

    with pytest.raises(ValueError, match='topology|window|identity'):
        paths.compiled.validate_topology()

    assert runner.gpio.calls == []


def test_dma_admission_requires_exact_single_word_read_then_same_word_padout_write():
    runner = _Runner()
    paths = compile_pulp_gpio_dma_runtime_paths(runner, image_address=RAM_BASE + 4)
    admission = paths.admission
    read_key = TransactionKey('exec', 'case', 'dma', 0, 'dma-memory', 1)
    write_key = TransactionKey('exec', 'case', 'dma', 0, 'dma-memory', 2)

    admission.accepted(read_key, address=RAM_BASE + 4, write=False,
        value=0, byte_enable=15, target=None)
    admission.completed(read_key, rdata=0x5a, error=0)
    admission.accepted(write_key, address=GPIO_BASE + GPIO_PADOUT_OFFSET,
        write=True, value=0x5a, byte_enable=15, target=runner.window)
    admission.completed(write_key, rdata=0, error=0)

    assert admission.state == 'complete'


@pytest.mark.parametrize('case', ['wrong_read_address', 'write_before_read',
                                  'wrong_write_value', 'wrong_target', 'extra_beat'])
def test_dma_admission_refuses_beats_outside_the_declared_single_word_path(case):
    runner = _Runner()
    paths = compile_pulp_gpio_dma_runtime_paths(runner, image_address=RAM_BASE + 4)
    admission = paths.admission
    read_key = TransactionKey('exec', 'case', 'dma', 0, 'dma-memory', 1)
    write_key = TransactionKey('exec', 'case', 'dma', 0, 'dma-memory', 2)
    other = _GpioSession()
    other_window = MasterTargetWindow('other', GPIO_BASE + 0x1000, GPIO_SIZE,
        other, (GPIO_PADOUT_OFFSET,), range(256))

    if case == 'wrong_read_address':
        with pytest.raises(ValueError, match='declared RAM image word'):
            admission.accepted(read_key, address=RAM_BASE + 8, write=False,
                value=0, byte_enable=15, target=None)
    elif case == 'write_before_read':
        with pytest.raises(ValueError, match='declared RAM image word read'):
            admission.accepted(write_key, address=GPIO_BASE + GPIO_PADOUT_OFFSET,
                write=True, value=0x5aa55aa5, byte_enable=15, target=runner.window)
    else:
        admission.accepted(read_key, address=RAM_BASE + 4, write=False,
            value=0, byte_enable=15, target=None)
        admission.completed(read_key, rdata=0x5a, error=0)
        if case == 'wrong_write_value':
            with pytest.raises(ValueError, match='same word read from RAM'):
                admission.accepted(write_key,
                    address=GPIO_BASE + GPIO_PADOUT_OFFSET, write=True,
                    value=0x5b, byte_enable=15, target=runner.window)
        elif case == 'wrong_target':
            with pytest.raises(ValueError, match='declared PADOUT window'):
                admission.accepted(write_key,
                    address=GPIO_BASE + 0x1000 + GPIO_PADOUT_OFFSET,
                    write=True, value=0x5a, byte_enable=15,
                    target=other_window)
        else:
            admission.accepted(write_key,
                address=GPIO_BASE + GPIO_PADOUT_OFFSET, write=True,
                value=0x5a, byte_enable=15, target=runner.window)
            admission.completed(write_key, rdata=0, error=0)
            with pytest.raises(ValueError, match='single word route is complete'):
                admission.accepted(TransactionKey('exec', 'case', 'dma', 0,
                    'dma-memory', 3), address=RAM_BASE + 4, write=False,
                    value=0, byte_enable=15, target=None)
