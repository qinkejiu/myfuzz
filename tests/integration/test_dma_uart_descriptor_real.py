"""Opt-in native S2 gate: one boot, three directions, multi-word FIFO.

Run only after the source tree is frozen (the S1/P7 gates share the same build
cache), then in one boot:

    MYFUZZ_DMA_DESCRIPTOR_REAL=1 \
    MYFUZZ_DMA_DESCRIPTOR_CACHE=<cache> \
    MYFUZZ_DMA_DESCRIPTOR_EVIDENCE=<evidence> \
    PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
        tests/integration/test_dma_uart_descriptor_real.py

Every case needs a real serial descriptor, real FIFO pops, real DMA master
beats, real RAM commit versions, a real native IRQ and ISR, and a fresh
full-prefix replay that reproduces the identical evidence.  The gate makes no
source-authority claim: ``fifo_origin`` stays ``unknown`` until S4.
"""
import gzip
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration.dma_uart_descriptor_runtime import (
    DescriptorCase, DescriptorResult, replay_descriptor_cases,
    run_descriptor_cases)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.ibex_dma_uart_descriptor import (
    DESTINATION, ILLEGAL_TARGET, ISR, MAIN, MTVEC_BASE, SOURCE_RAM, UART_BASE,
    UART_RDATA, UART_WDATA, descriptor_uart_images)

# Six cases: every direction, two multi-word cases, and a distinct payload per
# direction so a crossed destination or swapped word cannot pass unnoticed.
CASES = (
    DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1),
    DescriptorCase.create('RX_TO_RAM', dst_index=1, payload=0xA5, length=3),
    DescriptorCase.create('RAM_TO_RAM', dst_index=0, payload=0x00, length=1),
    DescriptorCase.create('RAM_TO_RAM', dst_index=2, payload=0x7E, length=2),
    DescriptorCase.create('RAM_TO_TX', dst_index=3, payload=0xFF, length=1),
    DescriptorCase.create('RAM_TO_TX', dst_index=0, payload=0x33, length=2),
)
EXPECTED_BEATS = tuple(2 * case.length for case in CASES)


def _settings(tmp_path):
    return dict(
        cache=Path(os.environ.get('MYFUZZ_DMA_DESCRIPTOR_CACHE',
            str(tmp_path / 'cache'))),
        evidence=Path(os.environ.get('MYFUZZ_DMA_DESCRIPTOR_EVIDENCE',
            str(tmp_path / 'evidence'))))


def _save(root, name, document):
    root.mkdir(parents=True, exist_ok=True)
    (root / (name + '.json.gz')).write_bytes(gzip.compress(
        json.dumps(document, sort_keys=True).encode(), mtime=0))


def _case_summary(case):
    return dict(case_index=case['case_index'], direction=case['direction'],
        length=case['spec']['length'], dst_index=case['spec']['dst_index'],
        payload=case['spec']['payload'],
        source_bytes=case['source_bytes'],
        program=case['program'], beat_count=case['beat_count'],
        fifo=dict(pushes=case['fifo']['pushes'],
            push_depths=case['fifo']['push_depths'],
            pops=case['fifo']['pops'],
            depth_after=case['fifo']['depth_after'],
            max_depth=case['fifo']['max_depth']),
        isr=case['isr'], irq=case['irq'],
        ram_commits=case['ram_commits'],
        cpu_source_versions=case['cpu_source_versions'],
        tx_captures=case['tx_captures'],
        completed=case['completed'], fifo_origin=case['fifo_origin'],
        source_authority=case['source_authority'],
        proof_grade=case['proof_grade'],
        command_start=case['command_start'], command_end=case['command_end'],
        event_start=case['event_start'], event_end=case['event_end'],
        ticks_before=case['ticks_before'], ticks_after=case['ticks_after'],
        prefix_sha256=case['prefix_sha256'])


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_DESCRIPTOR_REAL') != '1',
    reason='explicit native descriptor DMA gate')
def test_descriptor_three_directions_multiword_and_fresh_replay(tmp_path):
    settings = _settings(tmp_path)
    cache, evidence = settings['cache'], settings['evidence']
    budget = ResourceBudget(max_wall_time_ms=600000)
    result = run_descriptor_cases(CASES, cache_dir=cache, budget=budget,
        max_rounds_per_case=4096)
    _save(evidence, 'descriptor', result.to_document())
    (evidence / 'cases.json').write_text(json.dumps(
        [_case_summary(case) for case in result.cases], sort_keys=True, indent=1),
        encoding='utf-8')
    (evidence / 'source_pins.json').write_text(json.dumps(result.source_pins,
        sort_keys=True, indent=1), encoding='utf-8')
    (evidence / 'manifest.json').write_text(json.dumps(dict(
        gate='descriptor-three-directions', reference_budget=budget.to_document(),
        case_count=len(CASES), expected_beats=list(EXPECTED_BEATS),
        firmware=dict(main=MAIN, mtvec=MTVEC_BASE, isr=ISR,
            uart=UART_BASE, uart_rdata=UART_RDATA, uart_wdata=UART_WDATA,
            destination=DESTINATION, illegal_target=ILLEGAL_TARGET,
            images={hex(address): len(image) for address, image
                    in descriptor_uart_images().items()}),
        claim=dict(fifo_origin='unknown', source_authority='incomplete',
            error_isr='S3 not implemented', prefix_replay='S4 not implemented')
    ), sort_keys=True, indent=1), encoding='utf-8')

    assert result.phase == 'complete' and result.error is None
    assert len(result.cases) == len(CASES)
    assert [case['direction'] for case in result.cases] == [
        case.direction for case in CASES]
    assert sum(case['spec']['length'] > 1 for case in result.cases) >= 2
    for case, spec, beats in zip(result.cases, CASES, EXPECTED_BEATS):
        assert case['completed'] is True
        assert case['spec'] == spec.to_document()
        assert case['beat_count'] == beats
        assert case['isr']['mcause'] == 0x8000000B
        assert case['isr']['status_error'] == 0
        assert case['isr']['payload'] == spec.payload
        assert case['isr']['counter'] == case['case_index']
        assert case['irq']['edge_tick'] == case['irq']['source_tick']
        assert case['source_authority'] == 'incomplete'
        assert case['fifo_origin'] == 'unknown'
        assert case['fifo']['depth_after'] == 0
        assert case['fifo']['pushes'] == len(spec.source_bytes)
        # The real serial frames, FIFO pushes and pops cover the whole stream.
        assert len(case['fifo']['pops']) == len(spec.source_bytes)
        assert case['program']['source'] in (UART_RDATA, SOURCE_RAM)
        assert case['program']['destination'] in (
            UART_WDATA, DESTINATION, DESTINATION + 4, DESTINATION + 8,
            DESTINATION + 12)
        if spec.direction == 'RX_TO_RAM':
            dma_pops = [pop for pop in case['fifo']['pops'] if pop['kind'] == 'dma']
            assert len(dma_pops) == spec.length
            assert [pop['pre_depth'] for pop in dma_pops] == list(
                range(spec.length, 0, -1))
        else:
            assert all(pop['kind'] == 'cpu' for pop in case['fifo']['pops'])
        if spec.direction == 'RAM_TO_TX':
            assert case['tx_captures'] == [spec.payload] * spec.length
            assert case['ram_commits'] == []
        else:
            assert case['tx_captures'] == []
            assert len(case['ram_commits']) == spec.length
            assert [commit['value'] for commit in case['ram_commits']] == [
                spec.payload] * spec.length
    # The first multi-word case must establish and record the real len>1
    # status/nread/blocklen readings instead of a hard-coded expectation.
    multiword = next(case for case in result.cases if case['spec']['length'] > 1)
    (evidence / 'multiword-readings.json').write_text(json.dumps(dict(
        case_index=multiword['case_index'],
        direction=multiword['direction'],
        length=multiword['spec']['length'],
        status=multiword['isr']['status'],
        nread=multiword['isr']['status_nread'],
        blocklen_sub_one=multiword['isr']['status_blocklen_sub_one'],
        status_error=multiword['isr']['status_error'],
        length_register=multiword['isr']['length'],
        beat_count=multiword['beat_count'],
        fifo_pops=multiword['fifo']['pops'],
    ), sort_keys=True, indent=1), encoding='utf-8')

    # Fresh full-prefix replay: new native processes, identical plan/events/ticks
    # and identical per-case certificates (including the TX serial captures).
    loaded = DescriptorResult.from_document(
        json.loads(json.dumps(result.to_document())))
    fresh = replay_descriptor_cases(loaded, cache_dir=cache)
    _save(evidence, 'fresh', fresh.to_document())
    assert fresh.cases == result.cases
    assert fresh.local_ticks == result.local_ticks
    assert fresh.plan.commands == result.plan.commands
    assert fresh.identities == result.identities
    assert fresh.execution_ids != result.execution_ids
    assert fresh.phase == 'complete' and fresh.error is None
