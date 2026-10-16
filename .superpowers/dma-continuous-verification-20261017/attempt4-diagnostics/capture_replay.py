"""Observe the existing frozen replay's actual result without replacing code."""
import gzip
import hashlib
import json
from pathlib import Path
import sys

from myfuzz.integration.dma_uart_rx_runtime import (
    ContinuousRxResult, _normalize, replay_continuous_uart_rx,
)

ROOT = Path('/root/fanzehui/system-20261016/dma-continuous-verification-20261017')
OUT = ROOT / 'attempt4-replay-diagnostic'
OUT.mkdir(exist_ok=True)
original_path = ROOT / 'attempt4/evidence/positive.json.gz'
reference = ContinuousRxResult.from_document(json.loads(gzip.decompress(original_path.read_bytes())))
captured = {}
target_code = replay_continuous_uart_rx.__wrapped__.__code__


def observe(frame, event, arg):
    if frame.f_code is target_code:
        if event == 'exception' and 'actual' in frame.f_locals:
            captured['actual'] = frame.f_locals['actual']
        return observe
    return None


def first_difference(left, right, path='$'):
    if type(left) is not type(right):
        return {'path': path, 'expected_type': type(left).__name__, 'actual_type': type(right).__name__}
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return {'path': path, 'expected_keys': sorted(left), 'actual_keys': sorted(right)}
        for key in left:
            result = first_difference(left[key], right[key], path + '.' + str(key))
            if result is not None:
                return result
    elif isinstance(left, (list, tuple)):
        for index, (a, b) in enumerate(zip(left, right)):
            result = first_difference(a, b, path + '[' + str(index) + ']')
            if result is not None:
                return result
        if len(left) != len(right):
            return {'path': path, 'expected_length': len(left), 'actual_length': len(right)}
    elif left != right:
        return {'path': path, 'expected': left, 'actual': right}
    return None


report = {'scope': 'observation of unchanged frozen implementation; not a passing gate',
          'reference_sha256': hashlib.sha256(original_path.read_bytes()).hexdigest()}
sys.settrace(observe)
try:
    captured['actual'] = replay_continuous_uart_rx(reference, cache_dir=ROOT / 'cache')
except Exception as exc:
    report['error'] = {'type': type(exc).__name__, 'message': str(exc)}
finally:
    sys.settrace(None)

actual = captured.get('actual')
if actual is not None:
    (OUT / 'actual.json.gz').write_bytes(gzip.compress(json.dumps(actual.to_document(), sort_keys=True).encode(), mtime=0))
    report.update(expected_event_count=len(reference.events), actual_event_count=len(actual.events),
                  expected_ticks=reference.local_ticks, actual_ticks=actual.local_ticks,
                  expected_status=reference.trace.status if reference.trace else None,
                  actual_status=actual.trace.status if actual.trace else None,
                  expected_execution_ids=reference.execution_ids, actual_execution_ids=actual.execution_ids,
                  events_first_difference=first_difference(_normalize(reference.events, reference.execution_ids),
                      _normalize(actual.events, actual.execution_ids)),
                  uncertain_first_difference=first_difference(_normalize(reference.uncertain_status, reference.execution_ids),
                      _normalize(actual.uncertain_status, actual.execution_ids)))
else:
    report['actual_available'] = False
(OUT / 'diagnostic.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report), flush=True)
