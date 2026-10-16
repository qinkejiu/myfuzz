"""A completed environment ERR must not leave a hole in DMA source order."""
from pathlib import Path
import json
import os

import pytest

from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from test_wishbone_dma_transport import artifact

ROOT = Path(__file__).resolve().parents[2]


def test_error_then_valid_master_request_keeps_one_contiguous_ledger(artifact, tmp_path, monkeypatch):
    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
        regions=(MemoryRegion('ram', 0x1000, 16),))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=memory)
    session._execution = 'software-contract'
    session._case_id = 'error-then-valid'
    commands = []

    def command(op, fields):
        commands.append(fields)
        edge = len(commands)
        # Invalid read, its ERR response, then a valid write and its ACK.
        active = edge in (1, 3)
        pre = dict(mwb_cyc=int(active), mwb_stb=int(active),
            mwb_we=int(edge == 3), mwb_adr=(0x800 if edge == 1 else 0x400),
            mwb_dat_w=0x5a)
        return DriverReceipt('result', 'software-contract', edge, edge-1,
            edge, 1, payload={'pre_backend': pre,
                'observations': {'backend': {'mwb_stb': 1}}})

    monkeypatch.setattr(session, 'command', command)
    session.step_local()
    session.step_local()
    assert commands[1][6:9] == (0, 0, 1)
    assert session.memory_service.events == []
    session.step_local()
    session.step_local()
    assert commands[3][6:9] == (1, 0, 0)
    assert memory.read(0x1000, 4, transaction_id='assert').value == 0x5a
    assert [e['accepted']['transaction']['source_sequence'] for e in session.events
            if 'accepted' in e] == [1, 2]
    assert len(session.memory_service.events) == 1
    assert not session.memory_service.ledger.unresolved_keys


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_ERROR_RECOVERY_REAL') != '1',
    reason='explicit real DMA error recovery gate')
def test_real_error_then_reprogram_and_copy_in_same_process(artifact, tmp_path):
    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=8192,
        regions=(MemoryRegion('ram', 0x1000, 0x2000),))
    memory.preload(0x1000, (0x76543210).to_bytes(4, 'little'))
    memory.preload(0x2000, bytes(4))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=os.environ.get('MYFUZZ_DMA_ERROR_RECOVERY_CACHE', str(tmp_path/'cache')),
        memory=memory, command_timeout_seconds=30)
    output = Path(os.environ.get('MYFUZZ_DMA_ERROR_RECOVERY_EVIDENCE', str(tmp_path)))
    output.mkdir(parents=True, exist_ok=True)
    try:
        session.begin_case('error-then-valid')
        execution_id = session._execution
        process_id = session._process.pid
        for source in (0x3000, 0x1000):
            before = len(session.events)
            for offset, value in ((4, 1), (8, source), (12, 0x2000), (0, 0x0fed0001)):
                session.write_register(offset, value)
            for _ in range(400):
                edge = session.step_local()
                if any(edge.payload['observations']['physical'].values()):
                    break
            else:
                pytest.fail('native DMA completion/error pulse absent')
            segment = session.events[before:]
            if source == 0x3000:
                assert len([e for e in segment if 'accepted' in e]) == 1
                assert any(e.get('response', {}).get('error') == 1 for e in segment)
                assert memory.read(0x2000, 4, transaction_id='error-check').value == 0
                assert not session.memory_service.events
            else:
                assert [e['accepted']['write'] for e in segment if 'accepted' in e] == [False, True]
                assert any(e.get('response', {}).get('error') == 0 for e in segment)
        assert session._execution == execution_id and session._process.pid == process_id
        assert memory.read(0x2000, 4, transaction_id='final-check').value == 0x76543210
        assert [e['accepted']['transaction']['source_sequence'] for e in session.events
                if 'accepted' in e] == [1, 2, 3]
        assert not session.memory_service.ledger.unresolved_keys
        assert session.pending_responses == 0
        (output/'error-then-valid.json').write_text(json.dumps(dict(
            identity=session.identity_document(), events=session.events,
            memory_events=session.memory_service.events), indent=2)+'\n')
    finally:
        session.close()
