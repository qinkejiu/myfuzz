"""Opt-in native S4 gate: accepted UART FIFO source authority + typed prefixes.

Run on the frozen snapshot (the S1/P7 gates share the build cache):

    MYFUZZ_DMA_PREFIX_REAL=1 \
    MYFUZZ_DMA_PREFIX_CACHE=<cache> \
    MYFUZZ_DMA_PREFIX_EVIDENCE=<evidence> \
    PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
        tests/integration/test_dma_prefix_replay_real.py

One boot executes two real RX_TO_RAM cases (one multi-word) and two declared
illegal cases.  Every case must carry accepted ``uart_fifo_retention`` and
``uart_fifo_read_consumption`` proofs joined to its real FIFO rows; the DMA pop
of each RX payload must carry the ``dma_master`` route identity.  A fresh full
replay must reproduce every typed event/tick/case prefix, reported at the first
difference.  No status value, byte or IRQ is baked in before observation.
"""
import gzip
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration.dma_prefix_replay import (
    compare_dma_prefix, prefix_reference)
from myfuzz.integration.dma_uart_descriptor_runtime import (
    DescriptorCase, DescriptorResult, replay_descriptor_cases,
    run_descriptor_cases)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.uart_fifo_authority import ACCEPTED, ACCEPTED_CHAIN

CASES = (
    DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=2),
    DescriptorCase.create('RX_TO_RAM', dst_index=1, payload=0xA5, length=1),
    DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x00, length=1),
    DescriptorCase.create('ILLEGAL', dst_index=2, payload=0xFF, length=2),
)
EXPECTED_OUTCOMES = ('complete', 'complete', 'environment_error',
                     'environment_error')


def _settings(tmp_path):
    return dict(
        cache=Path(os.environ.get('MYFUZZ_DMA_PREFIX_CACHE',
            str(tmp_path / 'cache'))),
        evidence=Path(os.environ.get('MYFUZZ_DMA_PREFIX_EVIDENCE',
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
    authority = case['source_authority_evidence']
    return dict(case_index=case['case_index'], direction=case['direction'],
        outcome=case['outcome'], source_bytes=case['source_bytes'],
        fifo_origin=case['fifo_origin'],
        source_authority=case['source_authority'],
        proof_grade=case['proof_grade'],
        authority=authority['authority'], missing=authority['missing'],
        retention=authority['retention'], reads=authority['reads'],
        fifo=dict(pushes=case['fifo']['pushes'],
                  pops=case['fifo']['pops'],
                  depth_after=case['fifo']['depth_after']),
        isr=case['isr'], irq=case['irq'], beats=case['beats'],
        ram_commits=case['ram_commits'], tx_captures=case['tx_captures'],
        command_start=case['command_start'], command_end=case['command_end'],
        event_start=case['event_start'], event_end=case['event_end'],
        ticks_before=case['ticks_before'], ticks_after=case['ticks_after'],
        prefix_sha256=case['prefix_sha256'])


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_PREFIX_REAL') != '1',
    reason='explicit native source-authority prefix gate')
def test_accepted_uart_fifo_authority_and_typed_prefix_replay(tmp_path):
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
    accepted_authority = None
    for case, spec in zip(result.cases, CASES):
        assert case['sealed'] is True
        assert case['spec'] == spec.to_document()
        assert case['fifo_origin'] == ACCEPTED
        assert case['source_authority'] == ACCEPTED
        assert case['proof_grade'] == ACCEPTED_CHAIN
        authority = case['source_authority_evidence']
        assert authority['missing'] == []
        assert authority['reason'] is None
        assert authority['authority']['installed'] is True
        assert authority['authority']['source_id'] == 'uart.external_rx_byte'
        assert authority['authority']['producer_ref'] == 'external-serial-byte'
        assert authority['authority']['path_id']
        assert authority['authority']['graph_sha256']
        assert authority['authority']['contract_sha256']
        assert authority['authority']['edge_index_sha256']
        assert len(authority['retention']) == len(spec.source_bytes)
        assert len(authority['reads']) == len(spec.source_bytes)
        assert sorted(row['entry_id'] for row in authority['retention']) == \
            sorted(row['entry_id'] for row in authority['reads'])
        assert all(row['graph_path_certified'] is True
                   for row in authority['retention'] + authority['reads'])
        assert all(row['path_id'] == authority['authority']['path_id']
                   for row in authority['retention'] + authority['reads'])
        if accepted_authority is None:
            accepted_authority = authority['authority']
        # Every real FIFO pop of the case has a matching accepted read proof.
        assert [pop['access_id'] for pop in case['fifo']['pops']] == [
            row['access_id'] for row in authority['reads']]
        if spec.direction == 'RX_TO_RAM':
            dma_reads = [row for row in authority['reads']
                         if row['route_context_mode'] == 'dma_master']
            assert len(dma_reads) == spec.length
            assert all(row['channel_id'] == 'dma-memory'
                       for row in dma_reads)
        else:
            assert all(row['route_context_mode'] == 'router'
                       for row in authority['reads'])
    assert accepted_authority is not None

    # Fresh full replay: new native processes, identical typed plan/events/
    # ticks/cases, and an accepted authority document per case.
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
    reference = prefix_reference(result)
    digests = {}
    for case_count in range(1, len(CASES) + 1):
        outcome = compare_dma_prefix(reference, fresh, case_count=case_count)
        digests[str(case_count)] = outcome.prefix_sha256
        assert outcome.event_count == reference.cases[case_count - 1]['event_end']
    _write(evidence, 'prefix-digests.json', dict(
        schema_version='dma_typed_prefix_digests.v1', prefixes=digests,
        reference_execution_ids=result.execution_ids,
        fresh_execution_ids=fresh.execution_ids,
        note='Typed normalizer only; no whole-JSON replacement is accepted.'))
    _write(evidence, 'manifest.json', dict(
        gate='descriptor-source-authority-prefix', case_count=len(CASES),
        expected_outcomes=list(EXPECTED_OUTCOMES),
        reference_budget=budget.to_document(),
        claim=dict(fifo_origin=ACCEPTED, source_authority=ACCEPTED,
            proof_grade=ACCEPTED_CHAIN,
            authority='AdmissionRegistry + OwnershipMap + RuntimeEdgeIndex + '
                      'UartConsumptionTracker retained/read proofs',
            prefix_replay='typed first-difference comparison per prefix',
            error_isr='S3 gate: test_dma_error_isr_real.py',
            three_directions='S2 gate: test_dma_uart_descriptor_real.py')))
