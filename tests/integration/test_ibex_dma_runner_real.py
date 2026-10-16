"""Real CPU configuration and DMA completion use ordinary Runner steps."""
import gzip
import json
import os
from pathlib import Path

import pytest


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_RUNNER_REAL') != '1',
    reason='explicit real CPU/DMA Runner gate')
def test_real_cpu_dma_irq_isr_in_standard_runner(tmp_path):
    from myfuzz.scenario.ibex_dma_runner import make_ibex_dma_runner
    from myfuzz.scenario.ibex_dma_example import DESTINATION, RESULT, WORDS
    cache = Path(os.environ.get('MYFUZZ_DMA_RUNNER_CACHE', str(tmp_path/'cache')))
    runner = make_ibex_dma_runner(cache_dir=cache)
    memory = runner.sessions['cpu'].memory
    schedule = []
    assert runner._step_tick_bounds('dma')['dma'] == 1
    saw_queued_control = False
    try:
        runner.begin_test('dma-standard-runner')
        for _ in range(2000):
            if 'dma' in runner.sessions['cpu'].router.ready_targets:
                assert runner._step_tick_bounds('dma')['dma'] == 33
                saw_queued_control = True
            runner.step('dma')
            runner.step('cpu')
            schedule.extend(('dma', 'cpu'))
            if memory.read(RESULT+24, 4, transaction_id='success-check').value == 1:
                break
        else:
            pytest.fail('real CPU ISR did not commit success')
        rows = list(runner.events)
        assert saw_queued_control
        accepted = [e['accepted'] for e in rows if e.get('kind') == 'dma_edge' and 'accepted' in e]
        assert len(accepted) == 8
        assert [e['value'] for e in accepted if e['write']] == list(WORDS)
        assert [memory.read(DESTINATION+4*i, 4, transaction_id='result').value
                for i in range(4)] == list(WORDS)
        assert memory.read(RESULT, 4, transaction_id='mcause').value == 0x8000000b
        assert any(e.get('kind') == 'cpu_external_irq_taken' for e in rows)
        assert any(e.get('kind') == 'source_start' for e in rows)
        assert any(e.get('kind') == 'local_tick_sample' and e['component'] == 'dma'
            and e['outputs']['irq'] == 1 for e in rows)
        assert len([e for e in rows if e.get('kind') == 'memory_write'
            and e['component'] == 'dma']) == 4
        assert len([e for e in rows if e.get('kind') == 'mmio_delivery']) >= 5
        raw_ticks = {e['local_tick'] for e in rows
            if e.get('kind') == 'local_tick_sample' and e['component'] == 'dma'}
        assert raw_ticks == set(range(1, runner.local_ticks['dma']+1))
        nonces = {n:s._execution for n,s in runner.sessions.items()}
        scenario_nonce = runner.execution_id
        identities = {n:s.identity_document() for n,s in runner.sessions.items()}
        if os.environ.get('MYFUZZ_DMA_RUNNER_EVIDENCE'):
            out = Path(os.environ['MYFUZZ_DMA_RUNNER_EVIDENCE'])
            out.mkdir(parents=True, exist_ok=True)
            data = dict(events=rows, local_ticks=runner.local_ticks,
                schedule=schedule, identities=identities)
            (out/'runner.json.gz').write_bytes(gzip.compress(
                json.dumps(data, sort_keys=True, indent=2).encode(), mtime=0))
    finally:
        for session in runner.sessions.values():
            session.end_case()

    fresh = make_ibex_dma_runner(cache_dir=cache)
    try:
        fresh.begin_test('dma-standard-runner')
        for component in schedule:
            fresh.step(component)
        fresh_rows = list(fresh.events)
        fresh_nonces = {n:s._execution for n,s in fresh.sessions.items()}
        assert all(fresh_nonces[n] != nonces[n] for n in nonces)
        assert {n:s.identity_document() for n,s in fresh.sessions.items()} == identities

        def normalized(events, native_ids, scenario_id):
            text = json.dumps(events, sort_keys=True)
            for name, nonce in native_ids.items():
                text = text.replace(nonce, 'native-execution:'+name)
            return json.loads(text.replace(scenario_id, 'scenario-execution'))

        assert normalized(rows, nonces, scenario_nonce) == normalized(
            fresh_rows, fresh_nonces, fresh.execution_id)
        assert fresh.sessions['cpu'].memory.read(RESULT+24, 4,
            transaction_id='fresh-success').value == 1
        if os.environ.get('MYFUZZ_DMA_RUNNER_EVIDENCE'):
            data = dict(events=fresh_rows, local_ticks=fresh.local_ticks,
                schedule=schedule, identities=identities, complete_prefix_matches=True,
                normalization='replace only two declared native UUIDs and Runner UUID')
            (out/'fresh.json.gz').write_bytes(gzip.compress(
                json.dumps(data, sort_keys=True, indent=2).encode(), mtime=0))
        before_reset = dict(fresh.local_ticks)
        fresh.reset_all('warm_all')
        fresh.step('dma')
        fresh.step('cpu')
        assert fresh.local_ticks['dma'] > before_reset['dma']
        epoch_samples = [e for e in fresh.events if e.get('kind') == 'local_tick_sample'
            and e['component'] == 'dma' and e['local_tick'] > before_reset['dma']]
        assert epoch_samples and all(e['local_tick'] > before_reset['dma'] for e in epoch_samples)
    finally:
        for session in fresh.sessions.values():
            session.end_case()
