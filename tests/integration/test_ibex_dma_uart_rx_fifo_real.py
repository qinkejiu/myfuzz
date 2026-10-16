"""Serial RX pin -> real UART FIFO -> DMA master read -> RAM -> Ibex ISR."""
import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

from myfuzz.scenario.ibex_dma_example import DMA_BASE, DESTINATION, RESULT, ISR
from myfuzz.scenario.ibex_dma_uart_example import UART_BASE
from myfuzz.scenario.ibex_dma_uart_rx_example import (
    RX_BYTE, UART_RDATA, advance_ibex_dma_uart_rx,
    make_ibex_dma_uart_rx_chain)


pytestmark = pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_UART_RX_REAL') != '1',
    reason='set MYFUZZ_DMA_UART_RX_REAL=1 for real Ibex/DMA/UART RX processes')


def _read(memory, address):
    return memory.read(address, 4, transaction_id='test-observation').value


def _run(cache_dir, evidence_dir, label, *, source=UART_RDATA, run=0):
    cpu, dma, uart, router, memory = make_ibex_dma_uart_rx_chain(
        cache_dir=cache_dir, source=source)
    schedule = []
    state = {'phase': 'cpu_ctrl', 'irq_latch': {}}
    try:
        uart.begin_case(label)
        dma.begin_case(label)
        cpu.begin_case(label)
        for step in range(1800):
            schedule.append(advance_ibex_dma_uart_rx(cpu, dma, uart, router,
                step=step, state=state))
            if source == UART_RDATA:
                if _read(memory, RESULT + 12) == 1:
                    break
            elif any(event.get('response', {}).get('error') == 1
                     for event in dma.events):
                break
        evidence = dict(schedule=schedule, dma_events=dma.events,
            cpu_events=cpu.cpu_events, cpu_memory=cpu.service.events,
            dma_memory=dma.memory_service.events,
            uart_events=uart.uart_events, uart_source_events=uart.source_events,
            uart_samples=uart.drain_tick_samples(),
            router_deliveries=[{**event,
                'source_transaction': asdict(event['source_transaction'])}
                for event in router.deliveries],
            result=[_read(memory, RESULT + offset) for offset in (0, 4, 8, 12)],
            destination=_read(memory, DESTINATION),
            cpu_identity=cpu.identity_document(),
            dma_identity=dma.identity_document(),
            uart_identity=uart.identity_document())
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / f'{label}-{run}.json').write_text(json.dumps(evidence, indent=2))
        return evidence, (cpu._execution, dma._execution, uart._execution)
    finally:
        cpu.end_case()
        dma.close()
        uart.end_case()


def _normal(evidence, executions):
    value = json.loads(json.dumps(evidence))
    for key in ('cpu_identity', 'dma_identity', 'uart_identity'):
        value.pop(key)
    def replace(item):
        if isinstance(item, dict):
            return {key: replace(val) for key, val in item.items()}
        if isinstance(item, list):
            return [replace(val) for val in item]
        if isinstance(item, str):
            for index, execution in enumerate(executions):
                item = item.replace(execution, f'fresh-{index}')
        return item
    return replace(value)


def test_two_fresh_serial_fifo_dma_ram_and_native_isr(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_UART_RX_CACHE', str(tmp_path / 'cache')))
    directory = Path(os.environ.get('MYFUZZ_DMA_UART_RX_EVIDENCE', str(tmp_path)))
    traces = []
    for run in range(2):
        evidence, executions = _run(cache, directory, 'valid', run=run)
        assert evidence['result'] == [0x8000000b, 0, RX_BYTE, 1]
        assert evidence['destination'] == RX_BYTE
        assert evidence['uart_identity']['source_mode'] == 'genome'
        assert evidence['uart_identity']['source_hex'] == ''
        assert any(row['kind'] == 'uart_source_frame_end' and
            row['waveform_matched'] and row['byte'] == RX_BYTE
            for row in evidence['uart_source_events'])
        assert any(row['kind'] == 'uart_tick_observation' and
            row['pre']['probe_uart_fifo_wvalid'] == 1 and
            row['pre']['probe_uart_fifo_wready'] == 1
            for row in evidence['uart_events'])
        read_access = [row for row in evidence['uart_events']
            if row['kind'] == 'uart_rdata_access']
        assert len(read_access) == 1
        assert read_access[0]['status'] == 'observed'
        assert read_access[0]['read_value'] == RX_BYTE
        assert read_access[0]['read_capture']['pre']['probe_uart_fifo_rvalid'] == 1
        assert read_access[0]['read_capture']['pre']['probe_uart_fifo_rdata_re'] == 1
        deliveries = evidence['router_deliveries']
        assert [(row['offset'], row['write_value']) for row in deliveries
                if row['device_id'] == 'uart' and row['write']] == [
                    (0x10, 0x80000003)]
        assert [(row['offset'], row['write_value']) for row in deliveries
                if row['device_id'] == 'dma' and row['write']] == [
                    (8, UART_RDATA), (12, DESTINATION), (4, 1),
                    (0, 0x0fed0001)]
        accepted = [row['accepted'] for row in evidence['dma_events']
            if 'accepted' in row]
        assert [(row['address'], row['write']) for row in accepted] == [
            (UART_RDATA, False), (DESTINATION, True)]
        target = accepted[0]['target_delivery']
        assert target['source_transaction'] == accepted[0]['transaction']
        assert (target['target_component'], target['address'], target['offset'],
                target['value'], target['byte_enable']) == (
                    'uart', UART_RDATA, 0x18, RX_BYTE, 15)
        assert target['target_access_id'] == read_access[0]['access_id']
        assert target['target_uart_access'] == read_access[0]
        assert read_access[0]['source_transaction'] is None
        assert accepted[1]['value'] == RX_BYTE
        assert len([row for row in evidence['dma_memory']
            if row['kind'] == 'memory_write' and
            row['address'] == DESTINATION and row['value'] == RX_BYTE]) == 1
        assert not any(row['kind'] == 'memory_read' and row['address'] == UART_RDATA
                       for row in evidence['dma_memory'])
        assert any(row['kind'] == 'cpu_external_irq_taken'
                   for row in evidence['cpu_events'])
        assert any(row['kind'] == 'cpu_retire' and
                   ISR <= row.get('pc_rdata', 0) < ISR + 80
                   for row in evidence['cpu_events'])
        assert any(row.get('cpu_irq_input') == 1 and
                   row.get('dma_native_irq_ticks')
                   for row in evidence['schedule'])
        traces.append(_normal(evidence, executions))
    assert traces[0] == traces[1]


def test_invalid_dma_rx_source_returns_environment_error_without_fifo_pop(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_UART_RX_CACHE', str(tmp_path / 'cache')))
    directory = Path(os.environ.get('MYFUZZ_DMA_UART_RX_EVIDENCE', str(tmp_path)))
    source = UART_BASE + 0x20
    evidence, _ = _run(cache, directory, 'invalid-source', source=source)
    accepted = [row['accepted'] for row in evidence['dma_events']
        if 'accepted' in row]
    assert accepted[0]['address'] == source and not accepted[0]['write']
    assert accepted[0]['target_rejection'] == 'declared_master_target_access'
    assert 'target_delivery' not in accepted[0]
    assert any(row.get('response', {}).get('error') == 1
               for row in evidence['dma_events'])
    assert not any(row['kind'] == 'uart_rdata_access'
                   for row in evidence['uart_events'])
    assert not any(row['kind'] == 'memory_write' and row['address'] == DESTINATION
                   for row in evidence['dma_memory'])
    assert evidence['destination'] == 0
    assert any(row['kind'] == 'uart_source_frame_end' and row['waveform_matched']
               for row in evidence['uart_source_events'])
