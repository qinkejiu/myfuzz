"""Pure saved-data comparison, never issues simulator commands."""
import gzip
import hashlib
import json
from pathlib import Path
from normalize_fn import _normalize

ROOT = Path('/root/fanzehui/system-20261016/dma-continuous-verification-20261017')
original = json.loads(gzip.decompress((ROOT / 'attempt4/evidence/positive.json.gz').read_bytes()))
actual = json.loads(gzip.decompress((ROOT / 'attempt4-replay-diagnostic/actual.json.gz').read_bytes()))
left = _normalize(original['events'], original['execution_ids'])
right = _normalize(actual['events'], actual['execution_ids'])
different = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]


def digest(rows):
    result = hashlib.sha256()
    for row in rows:
        result.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode())
        result.update(b'\n')
    return result.hexdigest()


report = dict(scope='offline frozen raw data comparison with proposed typed normalization; not new native gate',
    source_normalizer_sha256=hashlib.sha256(Path(__file__).with_name('normalize_fn.py').read_bytes()).hexdigest(),
    original_events=len(left), actual_events=len(right), differing_event_indexes=different[:10],
    events_equal=len(left) == len(right) and not different,
    expected_normalized_record_digest=digest(left), actual_normalized_record_digest=digest(right),
    ticks_equal=original['local_ticks'] == actual['local_ticks'],
    uncertain_equal=_normalize(original['uncertain_status'], original['execution_ids']) ==
        _normalize(actual['uncertain_status'], actual['execution_ids']),
    original_status=original['trace']['status'], actual_status=actual['trace']['status'])
if different:
    report['first_differing_records'] = {'expected': left[different[0]], 'actual': right[different[0]]}
(ROOT / 'attempt4-replay-diagnostic/proposed-normalization-audit.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report), flush=True)
