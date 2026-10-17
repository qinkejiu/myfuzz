"""Opt-in native S3 gate: valid and invalid DMA cases in one boot.

Run only after the source tree is frozen (the S2/S1/P7 gates share the build
cache):

    MYFUZZ_DMA_ERROR_ISR_REAL=1 \
    MYFUZZ_DMA_ERROR_ISR_CACHE=<cache> \
    MYFUZZ_DMA_ERROR_ISR_EVIDENCE=<evidence> \
    PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
        tests/integration/test_dma_error_isr_real.py

One boot contains at least two successful cases and at least two declared
illegal cases.  Every invalid case needs a real rejected master read (real
``environment_error_receipt``, no target delivery), no destination RAM commit,
the real native DMA error IRQ, a real CPU take, and the real ISR status/length/
mcause/counter.  The status word is measured and saved in
``error-status-measured.json``; no expected status word is pre-baked here.  A
fresh full-prefix replay must reproduce the identical per-case evidence,
including the measured status bits.

The gate makes no source-authority claim: ``fifo_origin`` stays ``unknown``
until S4.
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
    UART_RDATA, UART_WDATA, dma_status_fields, descriptor_uart_images)

# Two valid cases and two declared illegal cases, interleaved so a success after
# an error (and an error after a success) both execute in one boot.  The S3
# acceptance requires at least two of each; the shorter boot keeps the full
# fresh-prefix replay inside the bounded native gate.
CASES = (
    DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1),
    DescriptorCase.create('ILLEGAL', dst_index=0, payload=0xA5, length=1),
    DescriptorCase.create('RAM_TO_RAM', dst_index=1, payload=0x00, length=2),
    DescriptorCase.create('ILLEGAL', dst_index=2, payload=0x7E, length=2),
)
EXPECTED_OUTCOMES = tuple(case.expect for case in CASES)
VALID_CASES = tuple(case for case in CASES if case.expect == 'complete')
INVALID_CASES = tuple(case for case in CASES if case.expect == 'environment_error')


def _settings(tmp_path):
    return dict(
        cache=Path(os.environ.get('MYFUZZ_DMA_ERROR_ISR_CACHE',
            str(tmp_path / 'cache'))),
        evidence=Path(os.environ.get('MYFUZZ_DMA_ERROR_ISR_EVIDENCE',
            str(tmp_path / 'evidence'))))


def _save(root, name, document):
    root.mkdir(parents=True, exist_ok=True)
    (root / (name + '.json.gz')).write_bytes(gzip.compress(
        json.dumps(document, sort_keys=True).encode(), mtime=0))


def _write(root, name, document):
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(json.dumps(document, sort_keys=True, indent=1),
        encoding='utf-8')


def _case_summary(case):
    return dict(case_index=case['case_index'], direction=case['direction'],
        outcome=case['outcome'], expect=case['spec']['expect'],
        length=case['spec']['length'], dst_index=case['spec']['dst_index'],
        payload=case['spec']['payload'],
        source_bytes=case['source_bytes'],
        program=case['program'], beat_count=case['beat_count'],
        ram_commits=case['ram_commits'],
        environment_error_receipt=case.get('environment_error_receipt'),
        environment_error=case.get('environment_error'),
        no_target_delivery=case.get('no_target_delivery'),
        destination_committed=case.get('destination_committed'),
        isr=case['isr'], irq=case['irq'],
        fifo=dict(pushes=case['fifo']['pushes'],
            push_depths=case['fifo']['push_depths'],
            pops=case['fifo']['pops'],
            dma_pops=case['fifo'].get('dma_pops'),
            depth_after=case['fifo']['depth_after'],
            max_depth=case['fifo']['max_depth']),
        tx_captures=case['tx_captures'],
        completed=case['completed'], sealed=case['sealed'],
        error_path=case.get('error_path'),
        fifo_origin=case['fifo_origin'],
        source_authority=case['source_authority'],
        proof_grade=case['proof_grade'],
        command_start=case['command_start'], command_end=case['command_end'],
        event_start=case['event_start'], event_end=case['event_end'],
        ticks_before=case['ticks_before'], ticks_after=case['ticks_after'],
        prefix_sha256=case['prefix_sha256'])


def _measured_error_status(case):
    status = case['isr']['status']
    fields = dma_status_fields(status)
    return dict(case_index=case['case_index'],
        direction=case['direction'], length=case['spec']['length'],
        illegal_target=ILLEGAL_TARGET,
        program=dict(source=case['program']['source'],
            destination=case['program']['destination'],
            length=case['program']['length'],
            control=case['program']['control']),
        status_raw=status, status_hex=hex(status),
        status_bits=list(fields['bits']),
        status_error=fields['error'], status_busy=fields['busy'],
        status_inc_s_n=fields['inc_s_n'],
        status_inc_d_n=fields['inc_d_n'],
        status_nread=fields['nread'],
        status_blocklen_sub_one=fields['blocklen_sub_one'],
        control_inc_s_n=case['isr']['control_inc_s_n'],
        control_inc_d_n=case['isr']['control_inc_d_n'],
        length_register=case['isr']['length'],
        mcause=case['isr']['mcause'], counter=case['isr']['counter'],
        receipt=case['environment_error_receipt'],
        irq=case['irq'],
        measured=True, source='real ISR DMA status MMIO delivery in this gate')


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_ERROR_ISR_REAL') != '1',
    reason='explicit native descriptor error-ISR gate')
def test_error_isr_valid_and_invalid_cases_one_boot_and_fresh_replay(tmp_path):
    settings = _settings(tmp_path)
    cache, evidence = settings['cache'], settings['evidence']
    budget = ResourceBudget(max_wall_time_ms=900000)
    result = run_descriptor_cases(CASES, cache_dir=cache, budget=budget,
        max_rounds_per_case=4096)
    _save(evidence, 'descriptor', result.to_document())
    _write(evidence, 'cases.json',
        [_case_summary(case) for case in result.cases])
    _write(evidence, 'source_pins.json', result.source_pins)

    assert result.phase == 'complete' and result.error is None
    assert len(result.cases) == len(CASES)
    assert tuple(case['outcome'] for case in result.cases) == EXPECTED_OUTCOMES
    assert sum(case['outcome'] == 'complete' for case in result.cases) \
        == len(VALID_CASES)
    assert sum(case['outcome'] == 'environment_error'
               for case in result.cases) == len(INVALID_CASES)
    assert len(INVALID_CASES) >= 2 and len(VALID_CASES) >= 2

    measured = []
    for case, spec in zip(result.cases, CASES):
        assert case['sealed'] is True
        assert case['spec'] == spec.to_document()
        assert case['isr']['mcause'] == 0x8000000B
        assert case['isr']['counter'] == case['case_index']
        assert case['irq']['edge_tick'] == case['irq']['source_tick']
        assert case['source_authority'] == 'incomplete'
        assert case['fifo_origin'] == 'unknown'
        assert case['fifo']['pushes'] == len(spec.source_bytes)
        assert case['fifo']['depth_after'] == 0
        if spec.expect == 'complete':
            assert case['completed'] is True
            assert case['outcome'] == 'complete'
            assert case['beat_count'] == 2 * spec.length
            assert case['isr']['status_error'] == 0
            assert case['isr']['payload'] == spec.payload
            assert 'environment_error_receipt' not in case
            assert len(case['fifo']['pops']) == len(spec.source_bytes)
        else:
            assert case['completed'] is False
            assert case['outcome'] == 'environment_error'
            assert case['error_path'] == 'declared_illegal_master_target'
            assert case['beats'] == [] and case['beat_count'] == 0
            assert case['ram_commits'] == []
            assert case['no_target_delivery'] is True
            assert case['destination_committed'] is False
            assert case['tx_captures'] == []
            receipt = case['environment_error_receipt']
            assert receipt['error'] == 1
            assert receipt['target_effect'] is False
            assert receipt['op'] == 'master_environment_error'
            assert receipt['address'] == ILLEGAL_TARGET
            assert receipt['write'] is False
            assert receipt['reason'] == 'declared_master_target_access'
            assert case['environment_error']['data_beats'] == 0
            assert case['environment_error']['destination_commits'] == 0
            assert case['environment_error']['fifo_dma_pops'] == 0
            assert case['environment_error']['no_target_delivery'] is True
            assert case['irq']['error'] is True
            # Every FIFO pop belongs to the CPU descriptor/payload drain; the
            # rejected DMA read must not pop the real RX FIFO.
            assert [pop['kind'] for pop in case['fifo']['pops']] \
                == ['cpu'] * len(spec.source_bytes)
            assert case['fifo']['dma_pops'] == 0
            # The measured status word is recorded, not a pre-baked constant.
            fields = dma_status_fields(case['isr']['status'])
            assert fields['bits'] == case['isr']['status_bits']
            assert fields['error'] == 1
            assert fields['busy'] == 0
            assert fields['inc_s_n'] == case['isr']['control_inc_s_n']
            assert fields['inc_d_n'] == case['isr']['control_inc_d_n']
            assert case['isr']['length'] == spec.length
            measured.append(_measured_error_status(case))
    _write(evidence, 'error-status-measured.json', dict(
        schema_version='dma_error_status_measured.v1',
        gate='descriptor-error-isr', cases=measured,
        note=('Measured in this real gate; no post-error status word was '
              'pre-baked before this observation.')))
    _write(evidence, 'manifest.json', dict(
        gate='descriptor-error-isr', reference_budget=budget.to_document(),
        case_count=len(CASES), expected_outcomes=list(EXPECTED_OUTCOMES),
        valid_cases=len(VALID_CASES), invalid_cases=len(INVALID_CASES),
        measured_error_status='error-status-measured.json',
        firmware=dict(main=MAIN, mtvec=MTVEC_BASE, isr=ISR,
            uart=UART_BASE, uart_rdata=UART_RDATA, uart_wdata=UART_WDATA,
            destination=DESTINATION, source_ram=SOURCE_RAM,
            illegal_target=ILLEGAL_TARGET,
            images={hex(address): len(image) for address, image
                    in descriptor_uart_images().items()}),
        claim=dict(fifo_origin='unknown', source_authority='incomplete',
            prefix_replay='S4 not implemented')))

    # Fresh full-prefix replay: new native processes, identical plan/events/
    # ticks and identical per-case certificates (including the measured status).
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
