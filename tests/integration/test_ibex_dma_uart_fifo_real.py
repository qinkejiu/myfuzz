"""CPU-written RAM -> real DMA master -> real UART TX FIFO and serial pin."""
import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

from myfuzz.scenario.ibex_dma_uart_example import (
    make_ibex_dma_uart_chain, advance_ibex_dma_uart, TX_BYTE, UART_BASE,
    UART_WDATA, SOURCE, RESULT, DMA_BASE, ISR)


pytestmark = pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_UART_REAL') != '1',
    reason='set MYFUZZ_DMA_UART_REAL=1 for real Ibex/DMA/UART processes')


def _read(memory, address):
    return memory.read(address, 4, transaction_id='test-observation').value


def _run(cache_dir, evidence_dir, label, *, source_word=TX_BYTE,
         destination=UART_WDATA, run=0):
    cpu, dma, uart, router, memory = make_ibex_dma_uart_chain(
        cache_dir=cache_dir, source_word=source_word, destination=destination)
    schedule = []
    latch = {}
    try:
        uart.begin_case(label)
        dma.begin_case(label)
        cpu.begin_case(label)
        for step in range(1200):
            schedule.append(advance_ibex_dma_uart(cpu, dma, uart, router,
                step=step, irq_latch=latch))
            if destination == UART_WDATA and source_word == TX_BYTE:
                if _read(memory, RESULT + 8) == 1 and uart.peer.captured == [TX_BYTE]:
                    break
            elif any(event.get('response', {}).get('error') == 1
                     for event in dma.events):
                break
        evidence = dict(schedule=schedule, dma_events=dma.events,
            cpu_events=cpu.cpu_events, cpu_memory=cpu.service.events,
            dma_memory=dma.memory_service.events,
            uart_events=uart.uart_events, uart_samples=uart.drain_tick_samples(),
            serial_captured=list(uart.peer.captured),
            router_deliveries=[{**event,
                'source_transaction': asdict(event['source_transaction'])}
                for event in router.deliveries],
            result=[_read(memory, RESULT + offset) for offset in (0, 4, 8)],
            cpu_identity=cpu.identity_document(),
            dma_identity=dma.identity_document(), uart_identity=uart.identity_document())
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


def test_two_fresh_cpu_dma_uart_fifo_tx_and_native_isr(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_UART_CACHE', str(tmp_path / 'cache')))
    directory = Path(os.environ.get('MYFUZZ_DMA_UART_EVIDENCE', str(tmp_path)))
    traces = []
    for run in range(2):
        evidence, executions = _run(cache, directory, 'valid', run=run)
        assert evidence['result'] == [0x8000000b, 0, 1]
        assert evidence['serial_captured'] == [TX_BYTE]
        samples = evidence['uart_samples']
        assert any(row['post']['uart_tx'] == 0 for row in samples)
        assert any(row['post']['uart_tx'] == 1 for row in samples)
        cpu_source = [event for event in evidence['cpu_memory']
            if event['kind'] == 'memory_write' and event['address'] == SOURCE]
        assert len(cpu_source) == 1 and cpu_source[0]['value'] == TX_BYTE
        deliveries = evidence['router_deliveries']
        assert [(row['offset'], row['write_value']) for row in deliveries
                if row['device_id'] == 'uart' and row['write']] == [
                    (0x10, 0x80000003)]
        assert [(row['offset'], row['write_value']) for row in deliveries
                if row['device_id'] == 'dma' and row['write']] == [
                    (8, SOURCE), (12, UART_WDATA), (4, 1), (0, 0x0fed0001)]
        accepted = [row['accepted'] for row in evidence['dma_events']
            if 'accepted' in row]
        assert [(row['address'], row['write']) for row in accepted] == [
            (SOURCE, False), (UART_WDATA, True)]
        assert accepted[1]['value'] == TX_BYTE
        target = accepted[1]['target_delivery']
        assert target['source_transaction'] == accepted[1]['transaction']
        assert (target['target_component'], target['address'], target['offset'],
                target['value'], target['byte_enable']) == (
                    'uart', UART_WDATA, 0x1c, TX_BYTE, 15)
        assert target['target_tick_after'] > target['target_tick_before']
        assert target['target_event_range'][1] > target['target_event_range'][0]
        assert len([row for row in evidence['dma_memory']
            if row['kind'] == 'memory_read' and row['address'] == SOURCE]) == 1
        assert not any(row['kind'] == 'memory_write' and row['address'] == UART_WDATA
                       for row in evidence['dma_memory'])
        assert any(row['kind'] == 'cpu_external_irq_taken'
                   for row in evidence['cpu_events'])
        assert any(row['kind'] == 'cpu_retire' and
                   ISR <= row.get('pc_rdata', 0) < ISR + 48
                   for row in evidence['cpu_events'])
        assert any(row['cpu_irq_input'] == 1 and row['dma_native_irq_ticks']
                   for row in evidence['schedule'])
        traces.append(_normal(evidence, executions))
    assert traces[0] == traces[1]


@pytest.mark.parametrize('source_word,destination', [
    (TX_BYTE, UART_BASE + 0x20), (0x1ff, UART_WDATA)])
def test_invalid_dma_master_target_returns_environment_error_without_uart_tx(
        tmp_path, source_word, destination):
    cache = Path(os.environ.get('MYFUZZ_DMA_UART_CACHE', str(tmp_path / 'cache')))
    directory = Path(os.environ.get('MYFUZZ_DMA_UART_EVIDENCE', str(tmp_path)))
    evidence, _ = _run(cache, directory,
        f'invalid-{source_word:x}-{destination:x}',
        source_word=source_word, destination=destination)
    accepted = [row['accepted'] for row in evidence['dma_events']
        if 'accepted' in row]
    rejected = [row for row in accepted if row['write']]
    assert len(rejected) == 1
    assert rejected[0]['address'] == destination
    assert rejected[0]['target_rejection'] == 'declared_master_target_access'
    assert 'target_delivery' not in rejected[0]
    assert any(row.get('response', {}).get('error') == 1
               for row in evidence['dma_events'])
    assert evidence['serial_captured'] == []
    assert not any(row.get('kind') == 'memory_write' and row['address'] == destination
                   for row in evidence['dma_memory'])
