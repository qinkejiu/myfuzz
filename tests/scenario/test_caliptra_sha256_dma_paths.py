"""Topology and admission contracts for the Caliptra AHB DMA route."""
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.caliptra_sha256_dma_paths import (
    DMA_READ_NODE, DMA_WRITE_NODE, RAM_SOURCE_NODE, SHA_CTRL_NODE,
    SHA_CTRL_OFFSET, SHA_CTRL_START_VALUE,
    compile_caliptra_sha256_dma_runtime_paths,
)
from myfuzz.scenario.dependency import SourceBinding, SourceBindings
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


RAM_BASE = 0x10000000
RAM_SIZE = 0x10000
SHA_BASE = 0x40002000
SHA_SIZE = 0x1000


class _ShaSession:
    def __init__(self, *, instance='sha'):
        self.instance = instance
        self._artifact_document = {
            'kind': 'ahb_lite_register_observe',
            'artifact_digest': 'a' * 64,
            'base_protocol_trace': {
                'schema_version': 'ip_protocol_trace.v1',
                'protocol': 'ahb-lite', 'endpoint_id': 'sha256.bus',
                'signals': {
                    role: 'trace_' + role for role in (
                        'haddr', 'hwdata', 'hsel', 'hwrite', 'hreadyin',
                        'htrans', 'hsize', 'hresp', 'hreadyout', 'hrdata')},
                'signal_widths': {
                    'haddr': 32, 'hwdata': 32, 'hsel': 1, 'hwrite': 1,
                    'hreadyin': 1, 'htrans': 2, 'hsize': 3, 'hresp': 1,
                    'hreadyout': 1, 'hrdata': 32,
                },
            },
        }
        self.artifact = SimpleNamespace(runtime_document=self._artifact_document)
        self.artifact.plan = SimpleNamespace(request=SimpleNamespace(
            instance_id=instance))

    def identity_document(self):
        return {'component': 'sha', 'profile': 'caliptra-sha256-ahb-v1'}

    def dma_master_target_provider_identity_document(self):
        if self.instance != 'sha':
            return {'schema_version': 'wrong-instance'}
        return {
            'schema_version': 'caliptra_sha256_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
            'artifact_digest': self._artifact_document['artifact_digest'],
            'endpoint_id': 'sha256.bus', 'operation': 'write',
            'register': 'CTRL', 'offset': SHA_CTRL_OFFSET,
            'value': SHA_CTRL_START_VALUE, 'byte_enable': 15,
            'observation_contract_schema_version': 'ip_protocol_trace.v1',
        }

    def dma_master_target_access(self, *_args, **_kwargs):
        raise AssertionError('route compilation must not access Caliptra RTL')

    def write_register(self, *_args, **_kwargs):
        raise AssertionError('route compilation must not access Caliptra RTL')


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
    def __init__(self, *, window=True, target=None, memory=None,
                 duplicate=False, resource_id='ram'):
        self.memory = memory or PersistentMemory(
            regions=(MemoryRegion(resource_id, RAM_BASE, RAM_SIZE),),
            initialization_seed=23, max_initialized_bytes=RAM_SIZE)
        self.sha = target or _ShaSession()
        selected = (MasterTargetWindow('sha', SHA_BASE, SHA_SIZE, self.sha,
            (SHA_CTRL_OFFSET,), (SHA_CTRL_START_VALUE,)) if window else None)
        windows = (() if selected is None else
                   (selected, selected) if duplicate else (selected,))
        self.dma = _DmaSession(MemoryService(self.memory, TransactionLedger()), windows)
        self.cpu = SimpleNamespace(memory=self.memory)
        self.sessions = {'cpu': self.cpu, 'dma': self.dma, 'sha': self.sha}
        self.ownership = SimpleNamespace(_bits={})
        self.bindings = ()


def test_compiler_binds_exact_ram_dma_and_caliptra_ctrl_route():
    runner = _Runner()

    paths = compile_caliptra_sha256_dma_runtime_paths(runner,
        image_id='control_word', image_address=RAM_BASE + 0x100)

    assert paths.path.source_ids == (RAM_SOURCE_NODE,)
    assert paths.path.target == SHA_CTRL_NODE
    assert [edge.kind for edge in paths.path.edges] == [
        'DMA_MASTER_TRANSFER', 'EVENT_ORDER', 'DMA_MASTER_TRANSFER']
    assert paths.graph.sources[RAM_SOURCE_NODE].image_address == RAM_BASE + 0x100
    assert paths.source_bindings.entries == (SourceBinding(
        RAM_SOURCE_NODE, 'memory_image', 'cpu', 'control_word', 0, 32,
        'initial_image:cpu:control_word', RAM_BASE + 0x100),)
    ram_route, sha_route = paths.contract.dma_master_routes
    assert (ram_route.operation, ram_route.target_kind, ram_route.target_id) == (
        'read', 'persistent_memory', 'ram')
    assert (sha_route.operation, sha_route.target_kind, sha_route.target_component,
            sha_route.writable_offsets, sha_route.accepted_write_values) == (
        'write', 'peripheral', 'sha', (SHA_CTRL_OFFSET,), (SHA_CTRL_START_VALUE,))
    assert paths.prepared.document()['schema_version'] == 'prepared_runtime_paths.v2'
    assert paths.compiled.document()['schema_version'] == 'runtime_path_compilation.v2'
    paths.compiled.validate_topology()
    assert runner.dma.validator is not None
    assert runner.dma.admission is paths.admission
    assert runner.sha.artifact.runtime_document['kind'] == 'ahb_lite_register_observe'


def test_prepare_caliptra_sha256_dma_runtime_paths_is_pure():
    from myfuzz.scenario.caliptra_sha256_dma_paths import (
        prepare_caliptra_sha256_dma_runtime_paths,
    )

    runner = _Runner()
    paths = prepare_caliptra_sha256_dma_runtime_paths(runner,
        image_id='control_word', image_address=RAM_BASE + 0x100)

    assert paths.path.target == SHA_CTRL_NODE
    assert paths.prepared.document()['schema_version'] == 'prepared_runtime_paths.v2'
    assert paths.compiled is None
    assert paths.admission is None
    assert runner.dma.admission is None
    assert runner.dma.validator is None
    with pytest.raises(ValueError, match='not yet bound'):
        paths.document()


@pytest.mark.parametrize('entry_point', ('prepare', 'compile'))
def test_compatibility_entry_points_use_shared_caliptra_graph_builder(
        monkeypatch, entry_point):
    from myfuzz.scenario import caliptra_sha256_dma_paths as compatibility
    from myfuzz.scenario import compiled_f6_runtime_path as shared

    calls = []
    original = shared.build_caliptra_runtime_graph

    def record_builder(runner, source, **kwargs):
        calls.append((runner, source, kwargs))
        return original(runner, source, **kwargs)

    monkeypatch.setattr(compatibility, 'build_caliptra_runtime_graph',
                        record_builder)
    runner = _Runner()
    paths = getattr(compatibility,
        f'{entry_point}_caliptra_sha256_dma_runtime_paths')(
            runner, image_id='control_word', image_address=RAM_BASE + 0x100)

    assert len(calls) == 1
    called_runner, source, kwargs = calls[0]
    assert called_runner is runner
    assert isinstance(source, shared.DmaTransferSourceWord)
    assert (source.memory_component, source.resource_id, source.image_id,
            source.address) == ('cpu', 'ram', 'control_word', RAM_BASE + 0x100)
    assert kwargs == {'sha_base': SHA_BASE, 'sha_size': SHA_SIZE}
    assert paths.graph.sources[RAM_SOURCE_NODE].image_address == source.address


@pytest.mark.parametrize('kwargs,match', [
    ({'window': False}, 'window is missing or ambiguous'),
    ({'duplicate': True}, 'window is missing or ambiguous'),
    ({'resource_id': 'missing'}, 'RAM region is missing or ambiguous'),
])
def test_compiler_refuses_incomplete_or_ambiguous_topology(kwargs, match):
    runner = _Runner(**kwargs)
    with pytest.raises(ValueError, match=match):
        compile_caliptra_sha256_dma_runtime_paths(runner)


def test_compiler_refuses_same_profile_on_a_different_live_target_object():
    runner = _Runner()
    runner.dma.master_targets = (MasterTargetWindow('sha', SHA_BASE, SHA_SIZE,
        _ShaSession(), (SHA_CTRL_OFFSET,), (SHA_CTRL_START_VALUE,)),)

    with pytest.raises(ValueError, match='endpoint is not the registered SHA session'):
        compile_caliptra_sha256_dma_runtime_paths(runner)


def test_compiler_refuses_wrong_provider_identity_or_permissions():
    runner = _Runner(target=_ShaSession(instance='other'))
    with pytest.raises(ValueError, match='endpoint lacks|identity is unsupported'):
        compile_caliptra_sha256_dma_runtime_paths(runner)

    runner = _Runner()
    runner.dma.master_targets = (MasterTargetWindow('sha', SHA_BASE, SHA_SIZE,
        runner.sha, (0x14,), (SHA_CTRL_START_VALUE,)),)
    with pytest.raises(ValueError, match='window must admit only'):
        compile_caliptra_sha256_dma_runtime_paths(runner)


def test_admission_requires_the_same_declared_ram_value_then_ctrl_write():
    runner = _Runner()
    paths = compile_caliptra_sha256_dma_runtime_paths(runner,
        image_address=RAM_BASE + 0x100)
    admission = paths.admission
    read_key = TransactionKey('dma-run', 'case', 'dma', 0,
                              'dma-memory', 1)
    write_key = TransactionKey('dma-run', 'case', 'dma', 0,
                               'dma-memory', 2)

    admission.accepted(read_key, address=RAM_BASE + 0x100, write=False,
        value=0, byte_enable=15, target=None)
    admission.completed(read_key, rdata=SHA_CTRL_START_VALUE, error=0)
    admission.accepted(write_key, address=SHA_BASE + SHA_CTRL_OFFSET,
        write=True, value=SHA_CTRL_START_VALUE, byte_enable=15,
        target=runner.dma.master_targets[0])
    admission.completed(write_key, rdata=0, error=0)

    assert admission.state == 'complete'
    assert paths.document()['dma_beat_admission']['transfer_words'] == 1


def test_admission_refuses_wrong_source_value_target_or_replay():
    runner = _Runner()
    admission = compile_caliptra_sha256_dma_runtime_paths(runner).admission
    read_key = TransactionKey('dma-run', 'case', 'dma', 0,
                              'dma-memory', 1)
    admission.accepted(read_key, address=RAM_BASE, write=False,
        value=0, byte_enable=15, target=None)
    admission.completed(read_key, rdata=4, error=0)
    with pytest.raises(ValueError, match='declared CTRL start word'):
        admission.accepted(TransactionKey('dma-run', 'case', 'dma', 0,
                'dma-memory', 2), address=SHA_BASE + SHA_CTRL_OFFSET,
            write=True, value=SHA_CTRL_START_VALUE, byte_enable=15,
            target=runner.dma.master_targets[0])


def test_admission_identity_is_canonical_and_configuration_is_read_only():
    paths = compile_caliptra_sha256_dma_runtime_paths(_Runner(),
        image_address=RAM_BASE + 0x40)
    admission = paths.admission
    identity = admission.identity_document()
    assert identity['source']['address'] == RAM_BASE + 0x40
    assert identity['target']['address'] == SHA_BASE + SHA_CTRL_OFFSET
    assert identity['transfer']['write_value'] == SHA_CTRL_START_VALUE
    with pytest.raises(AttributeError, match='read-only'):
        admission._image_address = RAM_BASE + 4


def test_source_genome_binding_pins_initial_memory_image_address():
    paths = compile_caliptra_sha256_dma_runtime_paths(_Runner(),
        image_id='control_word', image_address=RAM_BASE + 0x100)
    binding = SourceBinding(RAM_SOURCE_NODE, 'memory_image', 'cpu',
        'control_word', 0, 32, 'initial_image:cpu:control_word', RAM_BASE + 0x100)
    assert paths.source_bindings == SourceBindings((binding,))
