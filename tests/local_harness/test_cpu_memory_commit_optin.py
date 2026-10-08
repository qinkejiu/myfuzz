"""The CPU host-memory commit stream is an explicit saved runtime mode."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow


def _cpu(*, enabled):
    artifact = SimpleNamespace(
        plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')),
        runtime_document={'kind': 'obi_cpu', 'backend_ports': [],
                          'physical_exports': []})
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', 0x20000, 0x1000),),
        initialization_seed=9, max_initialized_bytes=4096)
    target = SimpleNamespace(write_register=lambda *a, **k: None,
                             read_register=lambda *a, **k: 0)
    router = DataflowRouter((DeviceWindow('dummy', 0x40000000, 0x1000, target),))
    return GeneratedCve2Session(artifact, base_dir=Path(__file__).resolve().parents[2],
        cache_dir=Path(__file__).resolve().parents[2] / 'unused',
        memory=memory, router=router,
        memory_commit_receipts=enabled)


def test_memory_commit_stream_is_explicit_and_identity_bound():
    legacy = _cpu(enabled=False)
    assert not legacy.service.commit_stream_enabled
    enabled = _cpu(enabled=True)
    assert enabled.service.commit_stream_enabled
    with patch.object(GeneratedLocalSession, 'identity_document', return_value={}):
        assert 'memory_commit_stream' not in legacy.identity_document()
        assert enabled.identity_document()['memory_commit_stream'] == {
            'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
