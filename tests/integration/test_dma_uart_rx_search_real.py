"""Opt-in native single-boot continuous DMA RX search acceptance.

The gate saves the search bundle, the guided positive result, a full fresh
prefix replay, a real bounded failure with its fresh replay, and an optional
uniform control arm. Every structural criterion is re-asserted from the saved
documents, and the decision stream is recomputed without any RTL.
"""
import gzip
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration import dma_uart_rx_search as search
from myfuzz.integration.dma_uart_rx_runtime import (
    ContinuousRxFailure, ContinuousRxResult, replay_continuous_uart_rx,
    run_continuous_uart_rx)
from myfuzz.scenario.contracts import ResourceBudget

DEFAULT_SEED = '5a17c0de0badf00d0e0d010203040506'


def _settings(tmp_path):
    return dict(
        cache=Path(os.environ.get('MYFUZZ_DMA_SEARCH_CACHE', str(tmp_path / 'cache'))),
        evidence=Path(os.environ.get('MYFUZZ_DMA_SEARCH_EVIDENCE',
            str(tmp_path / 'evidence'))),
        seconds=float(os.environ.get('MYFUZZ_DMA_SEARCH_SECONDS', '120')),
        seed=bytes.fromhex(os.environ.get('MYFUZZ_DMA_SEARCH_SEED', DEFAULT_SEED)))


def _save(root, name, document):
    root.mkdir(parents=True, exist_ok=True)
    (root / (name + '.json.gz')).write_bytes(gzip.compress(
        json.dumps(document, sort_keys=True).encode(), mtime=0))


def _save_search(evidence, result, *, strategy='guided'):
    _save(evidence, 'search', result.to_document())
    _save(evidence, 'positive', result.result.to_document())
    (evidence / 'decisions.jsonl').write_text(''.join(
        json.dumps(decision, sort_keys=True) + '\n' for decision in result.decisions),
        encoding='utf-8')
    (evidence / 'stats.json').write_text(json.dumps(result.stats, sort_keys=True,
        indent=1), encoding='utf-8')
    (evidence / 'source_pins.json').write_text(json.dumps(
        result.result.source_pins, sort_keys=True, indent=1), encoding='utf-8')
    return result.to_document()


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_SEARCH_REAL') != '1',
    reason='explicit native continuous DMA search gate')
def test_continuous_dma_rx_search_and_full_prefix_replay(tmp_path):
    settings = _settings(tmp_path)
    cache, evidence = settings['cache'], settings['evidence']
    budget = ResourceBudget(max_wall_time_ms=300000)
    result = search.search_continuous_dma(cache_dir=cache,
        seconds=settings['seconds'], seed=settings['seed'], strategy='guided',
        budget=budget, min_cases=3, max_cases=8)
    document = _save_search(evidence, result)
    stats = result.stats
    # Structural anti-fake-search criteria, re-derived from the saved document.
    assert stats['search_status'] == 'ok', stats['findings']
    assert stats['post_seed_cases'] >= 2
    assert stats['distinct_effective_specs'] >= 2
    assert stats['post_seed_completed_chains'] >= 1
    assert stats['feedback_influenced'] is True
    assert stats['effective_search_seconds'] <= stats['search_wall_seconds']
    assert result.failure is None
    assert all(case.prefix_sha256 for case in result.cases)
    assert all(case.completed_chain for case in result.cases)
    assert [case.source_byte for case in result.cases] == [
        command.value for command in result.result.plan.commands
        if isinstance(command, search.BatchSourceEvent)]
    # The whole decision stream must be recomputable from saved feedback only.
    recomputed = search.recompute_decisions(seed=settings['seed'], strategy='guided',
        cases=tuple(case.to_document() for case in result.cases))
    assert recomputed == result.decisions
    loaded_search = search.DmaSearchResult.from_document(document)
    assert loaded_search.decisions == result.decisions
    search._assert_real_search(loaded_search)
    # Full fresh prefix replay of the single search boot.
    loaded = ContinuousRxResult.from_document(
        json.loads(json.dumps(result.result.to_document())))
    fresh = replay_continuous_uart_rx(loaded, cache_dir=cache)
    _save(evidence, 'fresh', fresh.to_document())
    assert fresh.cases == result.result.cases
    assert fresh.local_ticks == result.result.local_ticks
    assert fresh.plan.commands == result.result.plan.commands
    assert fresh.phase == 'complete' and fresh.error is None
    # A real bounded host failure, kept and fresh-replayed unchanged.
    with pytest.raises(ContinuousRxFailure) as captured:
        run_continuous_uart_rx((0x33,), cache_dir=cache, max_source_ticks=1)
    failed = captured.value.result
    _save(evidence, 'failure', failed.to_document())
    assert failed.phase == 'source' and failed.case_index == 1
    assert failed.error['message'] == 'native serial frame exceeded source bound'
    failed_loaded = ContinuousRxResult.from_document(
        json.loads(json.dumps(failed.to_document())))
    failed_fresh = replay_continuous_uart_rx(failed_loaded, cache_dir=cache)
    _save(evidence, 'failure-fresh', failed_fresh.to_document())
    assert failed_fresh.error == failed.error
    assert failed_fresh.budget == failed.budget


@pytest.mark.skipif(
    os.environ.get('MYFUZZ_DMA_SEARCH_REAL') != '1'
    or os.environ.get('MYFUZZ_DMA_SEARCH_UNIFORM') != '1',
    reason='explicit native uniform control arm')
def test_uniform_control_arm_is_saved_beside_guided(tmp_path):
    settings = _settings(tmp_path)
    cache = settings['cache']
    evidence = settings['evidence'] / 'uniform'
    budget = ResourceBudget(max_wall_time_ms=300000)
    uniform = search.search_continuous_dma(cache_dir=cache,
        seconds=float(os.environ.get('MYFUZZ_DMA_SEARCH_UNIFORM_SECONDS',
            str(settings['seconds']))),
        seed=settings['seed'], strategy='uniform', budget=budget,
        min_cases=3, max_cases=8)
    _save_search(evidence, uniform, strategy='uniform')
    assert uniform.stats['search_status'] == 'ok', uniform.stats['findings']
    assert uniform.stats['feedback_influenced'] is False
    assert uniform.stats['post_seed_cases'] >= 2
    assert uniform.stats['distinct_effective_specs'] >= 2
    assert all(decision['parent_kind'] != 'corpus'
               for decision in uniform.decisions[1:])
    recomputed = search.recompute_decisions(seed=settings['seed'],
        strategy='uniform', cases=tuple(case.to_document() for case in uniform.cases))
    assert recomputed == uniform.decisions
    (evidence / 'guided-stats.json').write_text(json.dumps(
        json.loads((settings['evidence'] / 'stats.json').read_text()),
        sort_keys=True, indent=1), encoding='utf-8')
