"""Software controls and opt-in continuous native DMA RX acceptance."""
import gzip
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration.dma_uart_rx_runtime import (
    ContinuousRxFailure, ContinuousRxResult, _normalize,
    replay_continuous_uart_rx, run_continuous_uart_rx)


def test_identity_normalization_is_scoped_to_actual_ledger_fields():
    ids = {n: str(i) * 32 for i, n in enumerate(('cpu', 'dma', 'uart', 'runner'), 1)}
    key = f"TransactionKey(execution_id='{ids['dma']}', testcase_id='original', source_sequence=9)"
    record = dict(execution_id=ids['dma'], arbitrary=ids['dma'],
        source_value=key, pending_before_finalize=[key], pending_after_finalize=[key],
        markers=[dict(uncertain_transactions=[key])], writer_event_ids=[key])
    result = _normalize(record, ids)
    assert result['execution_id'] == 'execution:dma'
    assert result['arbitrary'] == ids['dma']
    assert result['source_value'] == key
    for value in (result['pending_before_finalize'][0], result['pending_after_finalize'][0],
            result['markers'][0]['uncertain_transactions'][0], result['writer_event_ids'][0]):
        assert value == key.replace(ids['dma'], 'execution:dma')
    unknown = key.replace(ids['dma'], 'f' * 32)
    assert _normalize(dict(uncertain_transactions=[unknown]), ids)['uncertain_transactions'] == [unknown]
    with pytest.raises(ValueError, match='distinct'):
        _normalize(record, {**ids, 'cpu': ids['dma']})


def _save(result, name):
    root = Path(os.environ['MYFUZZ_DMA_CONTINUOUS_EVIDENCE'])
    root.mkdir(parents=True, exist_ok=True)
    (root / (name + '.json.gz')).write_bytes(gzip.compress(
        json.dumps(result.to_document(), sort_keys=True).encode(), mtime=0))


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_CONTINUOUS_REAL') != '1', reason='explicit native continuous DMA gate')
def test_continuous_native_uart_dma_prefix_and_failure(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_CONTINUOUS_CACHE', str(tmp_path / 'cache')))
    result = None
    try:
        result = run_continuous_uart_rx((0x5a, 0, 0xa5, 0xa5), cache_dir=cache)
    except ContinuousRxFailure as exc:
        _save(exc.result, 'positive-attempt-failure')
        raise
    _save(result, 'positive')
    assert [c['source_byte'] for c in result.cases] == [0x5a, 0, 0xa5, 0xa5]
    assert all(c['fifo_origin'] == 'unknown' for c in result.cases)
    loaded = ContinuousRxResult.from_document(json.loads(json.dumps(result.to_document())))
    fresh = replay_continuous_uart_rx(loaded, cache_dir=cache)
    _save(fresh, 'fresh')
    assert fresh.cases == result.cases
    # Force a genuine host bound after the original external byte is admitted
    # and one native UART tick executes; replay must preserve that attempt.
    with pytest.raises(ContinuousRxFailure) as captured:
        run_continuous_uart_rx((0x33,), cache_dir=cache, max_source_ticks=1)
    failed = captured.value.result
    _save(failed, 'failure')
    assert failed.phase == 'source' and failed.case_index == 1
    assert failed.error['message'] == 'native serial frame exceeded source bound'
    failed_loaded = ContinuousRxResult.from_document(json.loads(json.dumps(failed.to_document())))
    failed_fresh = replay_continuous_uart_rx(failed_loaded, cache_dir=cache)
    _save(failed_fresh, 'failure-fresh')
    assert failed_fresh.error == failed.error
    assert failed_fresh.budget == failed.budget
