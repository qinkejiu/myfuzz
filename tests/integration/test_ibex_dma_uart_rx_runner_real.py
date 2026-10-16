"""The standard Runner schedules a real UART FIFO source and DMA master."""
import gzip
import json
import os
from pathlib import Path

import pytest


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_RX_RUNNER_REAL') != '1',
    reason='explicit CPU DMA UART FIFO Runner gate')
def test_real_uart_rx_fifo_dma_in_standard_runner(tmp_path):
    from myfuzz.scenario.ibex_dma_runner import make_ibex_dma_uart_rx_runner
    from myfuzz.scenario.ibex_dma_example import RESULT, DESTINATION
    from myfuzz.scenario.contracts import ResourceBudget
    cache = Path(os.environ.get('MYFUZZ_DMA_RX_RUNNER_CACHE', str(tmp_path/'cache')))
    runner = make_ibex_dma_uart_rx_runner(cache_dir=cache)
    runner.set_resource_budget(ResourceBudget(max_wall_time_ms=300000))
    uart = runner.sessions['uart']
    memory = runner.sessions['cpu'].memory
    schedule = []

    def step(component):
        result = runner.step(component)
        schedule.append(component)
        return result

    try:
        runner.begin_test('dma-uart-rx-standard-runner')
        runner.inject_source('uart', 'uart_rx_byte', 0x5a, width=8,
            direction='IP_TO_CPU', action_id='serial-byte-1')
        for _ in range(200):
            step('dma');step('cpu')
            if 'uart' in runner.sessions['cpu'].router.ready_targets:
                step('uart')
                break
        else:
            pytest.fail('actual CPU UART CTRL write absent')
        for _ in range(1500):
            step('uart')
            tick = next(e for e in reversed(uart.uart_events)
                if e['kind'] == 'uart_tick_observation')
            if (tick['post']['probe_uart_fifo_depth'] > 0
                    and any(e['kind'] == 'uart_source_frame_end' and e['waveform_matched']
                            for e in uart.source_events)
                    and uart.register_access_conflict() is None):
                break
        else:
            pytest.fail('physical serial source did not enter real RX FIFO')
        for _ in range(500):
            step('dma');step('cpu');step('uart')
            if memory.read(RESULT+12, 4, transaction_id='isr-check').value == 1:
                break
        else:
            pytest.fail('CPU ISR did not observe FIFO DMA result')
        rows = list(runner.events)
        assert memory.read(DESTINATION, 4, transaction_id='dma-result').value == 0x5a
        assert memory.read(RESULT, 4, transaction_id='mcause').value == 0x8000000b
        reads = [e['target_delivery'] for e in rows if e.get('kind') == 'dma_edge'
            and 'target_delivery' in e]
        assert len(reads) == 1 and reads[0]['value'] == 0x5a
        assert reads[0]['write'] is False
        assert reads[0]['target_uart_access']['read_capture']['pre']['probe_uart_fifo_rdata_re'] == 1
        assert any(e.get('kind') == 'cpu_external_irq_taken' for e in rows)
        assert any(e.get('kind') == 'memory_write' and e['component'] == 'dma'
            and e['address'] == DESTINATION and e['value'] == 0x5a for e in rows)
        for component in ('dma', 'uart'):
            ticks = {e['local_tick'] for e in rows if e.get('kind') == 'local_tick_sample'
                and e['component'] == component}
            assert ticks == set(range(1, runner.local_ticks[component]+1))
        identities = {n:s.identity_document() for n,s in runner.sessions.items()}
        nonces = {n:s._execution for n,s in runner.sessions.items()}
        scenario_nonce = runner.execution_id
        if os.environ.get('MYFUZZ_DMA_RX_RUNNER_EVIDENCE'):
            out = Path(os.environ['MYFUZZ_DMA_RX_RUNNER_EVIDENCE'])
            out.mkdir(parents=True, exist_ok=True)
            data = dict(events=rows, schedule=schedule, local_ticks=runner.local_ticks,
                identities=identities)
            (out/'rx-runner.json.gz').write_bytes(gzip.compress(
                json.dumps(data, indent=2, sort_keys=True).encode(), mtime=0))
    finally:
        for session in runner.sessions.values():
            session.end_case()

    fresh = make_ibex_dma_uart_rx_runner(cache_dir=cache)
    fresh.set_resource_budget(ResourceBudget(max_wall_time_ms=300000))
    try:
        fresh.begin_test('dma-uart-rx-standard-runner')
        fresh.inject_source('uart', 'uart_rx_byte', 0x5a, width=8,
            direction='IP_TO_CPU', action_id='serial-byte-1')
        for component in schedule:
            fresh.step(component)
        fresh_rows = list(fresh.events)
        fresh_nonces = {n:s._execution for n,s in fresh.sessions.items()}
        assert all(fresh_nonces[n] != nonces[n] for n in nonces)
        assert {n:s.identity_document() for n,s in fresh.sessions.items()} == identities

        def normalize(events, driver_ids, execution):
            text = json.dumps(events, sort_keys=True)
            for name, nonce in driver_ids.items():
                text = text.replace(nonce, 'native-execution:'+name)
            return json.loads(text.replace(execution, 'scenario-execution'))

        assert normalize(rows, nonces, scenario_nonce) == normalize(
            fresh_rows, fresh_nonces, fresh.execution_id)
        assert fresh.sessions['cpu'].memory.read(RESULT+12, 4,
            transaction_id='fresh-success').value == 1
        if os.environ.get('MYFUZZ_DMA_RX_RUNNER_EVIDENCE'):
            data = dict(events=fresh_rows, schedule=schedule, identities=identities,
                local_ticks=fresh.local_ticks, complete_prefix_matches=True,
                normalization='three declared native UUIDs and Runner UUID only')
            (out/'rx-fresh.json.gz').write_bytes(gzip.compress(
                json.dumps(data, indent=2, sort_keys=True).encode(), mtime=0))
    finally:
        for session in fresh.sessions.values():
            session.end_case()
