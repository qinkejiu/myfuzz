"""Fail-closed failure specimens replayed through the existing descriptor executor.

These files preserve reproduction inputs; they never establish a DUT bug or
acceptance, and regenerated case IDs are explicitly mapped by ordinal.
"""
from hashlib import sha256
import json
from pathlib import Path

SCHEMA = 'dependency_search_failure_specimen.v1'


def _read(path):
    return json.loads(Path(path).read_text())


def _write(path, document):
    Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')


def exception_signature(error):
    """Use the underlying exception rather than a descriptor wrapper message."""
    seen = set()
    while error.__cause__ is not None and id(error) not in seen:
        seen.add(id(error)); error = error.__cause__
    detail = getattr(error, 'detail', None)
    if isinstance(detail, dict) and 'error_type' in detail:
        return {'type':detail['error_type'], 'message':detail.get('reason', detail.get('error', str(error)))}
    return {'type':type(error).__name__, 'message':str(error)}


def _business_signature(signature):
    text = (signature['type'] + ' ' + signature['message']).lower()
    return not any(word in text for word in (
        'admission', 'refused', 'source changed', 'source mismatch', 'source identity',
        'static identity', 'executionvalidation', 'build', 'cleanup', 'configuration',
        'manifest', 'capability', 'permission', 'filenotfound', 'timeout', 'keyboardinterrupt'))


def _check_sources(rows):
    if not rows:
        raise ValueError('source-hashes-unavailable')
    for row in rows:
        if sha256(Path(row['path']).read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('source-bytes-mismatch')


def _original_gate(output):
    summary = _read(output / 'search-summary.json')
    boundary = summary.get('verification', {}).get('session_boundary', {})
    if summary.get('status') != 'failed' or boundary.get('status') != 'verified' or boundary.get('matches') is not True:
        raise ValueError('failed-search-with-verified-static-boundary-required')
    if (output / 'cleanup-errors.json').exists():
        raise ValueError('cleanup-failure-is-not-replayable')


def _attempts(output, flow):
    failure_path = output / 'failure.json'
    if (output / 'decisions.jsonl').exists() and failure_path.exists():
        from .journal import verify_journal
        failure = _read(failure_path)
        if failure.get('failure_phase') not in ('submit','feedback') or not failure.get('attempted_case_count'):
            raise ValueError('failure-is-not-an-attempted-business-execution')
        verify_journal(output / 'decisions.jsonl', expected_head=failure['journal_head'])
        decisions = [json.loads(line)['document'] for line in (output / 'decisions.jsonl').read_text().splitlines()]
        decisions = [row for row in decisions if row.get('kind') == 'decision']
        if len(decisions) != failure['attempted_case_count']:
            raise ValueError('attempted-prefix-count-mismatch')
        rows = []
        for item in decisions:
            case = item['case']; action = item['decision']['action_id']
            case_flow = item.get('flow') or ('F4' if action.startswith('write:') else 'F2' if action == 'read:current' else None)
            if case_flow not in ('F2','F4') or len(case['raw_records_hex']) != 1:
                raise ValueError('unsupported-native-attempt-mapping')
            rows.append({'flow':case_flow, 'raw_hex':case['raw_records_hex'][0],
                'original_case_id':case['testcase_id'], 'source_id':case['source_id'], 'path_id':case['path_id']})
        return rows
    partial = output / 'compiled_f6_partial_prefix.json'
    if flow == 'F6' and partial.exists():
        document = _read(partial)
        if not isinstance(document, dict) or not document.get('records'):
            raise ValueError('F6-complete-attempt-prefix-unavailable')
        attempts = document.get('attempts')
        if not isinstance(attempts, list) or len(attempts) != len(document['records']):
            raise ValueError('F6-complete-attempt-prefix-unavailable')
        binding = document.get('execution_binding', {})
        path_id = binding.get('path_id') or document.get('path_id')
        if not path_id:
            raise ValueError('F6-attempt-path-mapping-unavailable')
        rows = []
        for record, attempt in zip(document['records'], attempts):
            if any(record.get(key) != attempt.get(key) for key in ('case_id','raw8_hex')):
                raise ValueError('F6-attempt-record-mismatch')
            rows.append({'flow':'F6','raw_hex':record['raw8_hex'],
                'original_case_id':record['case_id'], 'path_id':path_id,
                'source_mapping':attempt.get('sources', []), 'execution_binding':binding})
        return rows
    raise ValueError('authenticated-attempt-prefix-unavailable; planned-sequence-is-not-evidence')


def export_failure_specimen(output, descriptor_path, sources, flow, rounds, capacity,
                            sequence=None, error=None, preparation_memory_flows=False, base_dir=None, cache_dir=None):
    """Export only an authenticated actual prefix; sequence is never fallback evidence."""
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    result = {'schema_version':SCHEMA, 'status':'refused', 'accepted':False, 'dut_bug':False}
    try:
        _original_gate(output)
        if error is None:
            raise ValueError('original-exception-unavailable')
        signature = exception_signature(error)
        if not _business_signature(signature):
            raise ValueError('infrastructure-or-admission-failure')
        base = Path(base_dir).resolve() if base_dir is not None else Path(__file__).resolve().parents[3]
        descriptor = Path(descriptor_path)
        descriptor = (base / descriptor).resolve() if not descriptor.is_absolute() else descriptor.resolve()
        pinned = []
        for row in sources:
            path = Path(row['path'])
            if row.get('base') not in (None, 'project'):
                raise ValueError('unsupported-source-root')
            pinned.append({'path':str((base / path).resolve() if not path.is_absolute() else path.resolve()), 'sha256':row['sha256']})
        _check_sources(pinned)
        rows = _attempts(output, flow)
        if not rows or type(capacity) is not int or not 1 <= len(rows) <= capacity or type(rounds) is not int or rounds < 1:
            raise ValueError('invalid-attempt-budget')
        packed = []
        for index,row in enumerate(rows):
            raw = bytes.fromhex(row['raw_hex'])
            if len(raw) != (8 if row['flow'] in ('F5','F6') else 4):
                raise ValueError('attempt-width-mismatch')
            packed.append(row['flow'] + ':' + raw.hex())
            row['ordinal'] = index
        result.update(status='ready', original_output=str(output.resolve()), base_dir=str(base),
            descriptor_path=str(descriptor), descriptor_sha256=sha256(descriptor.read_bytes()).hexdigest(),
            sources=pinned, flow=flow, rounds=rounds, capacity=capacity, sequence=packed,
            cache_dir=str((base / Path(cache_dir)).resolve()) if cache_dir is not None else None,
            case_mapping=rows, signature=signature, preparation_memory_flows=preparation_memory_flows)
    except (OSError, ValueError, KeyError, TypeError) as failure:
        result['reason'] = str(failure)
    _write(output / 'failure-specimen.json', result)
    return result


def run_worker(specimen_path, output):
    """Run inside a dedicated process; compare only after scope exit succeeds."""
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    result = {'status':'refused', 'accepted':False, 'dut_bug':False, 'trace_equal':False}
    try:
        specimen = _read(specimen_path)
        if specimen.get('schema_version') != SCHEMA or specimen.get('status') != 'ready':
            raise ValueError('specimen-not-ready')
        if specimen.get('backend') == 'gpio':
            from .gpio_search import replay_gpio_failure_specimen
            if not specimen.get('cache_dir'):
                raise ValueError('gpio-cache-directory-missing')
            result = replay_gpio_failure_specimen(specimen, output/'execution', specimen['cache_dir'])
            _write(output/'failure-replay.json', result)
            return result
        _original_gate(Path(specimen['original_output']))
        _check_sources(specimen['sources'])
        if sha256(Path(specimen['descriptor_path']).read_bytes()).hexdigest() != specimen['descriptor_sha256']:
            raise ValueError('descriptor-bytes-mismatch')
        if not _business_signature(specimen['signature']):
            raise ValueError('infrastructure-or-admission-failure')
        from myfuzz.local_harness.execution_validation import execution_validation_scope, static_validation
        from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
        descriptor = load_descriptor(specimen['descriptor_path'], base_dir=specimen['base_dir'])
        caught = None
        state = None
        try:
            with execution_validation_scope() as state:
                def validate_static():
                    _check_sources(specimen['sources'])
                    digest = sha256(Path(specimen['descriptor_path']).read_bytes()).hexdigest()
                    if digest != specimen['descriptor_sha256']:
                        raise ValueError('descriptor-bytes-mismatch')
                    return digest
                static_validation(('failure-replay-inputs', str(Path(specimen_path).resolve())), validate_static)
                try:
                    run_descriptor(descriptor, flow=specimen['flow'], mode='original',
                        case_root=output/'execution', base_dir=specimen['base_dir'], sequence=specimen['sequence'],
                        cache_dir=specimen.get('cache_dir'),
                        rounds=specimen['rounds'], execution_case_capacity=specimen['capacity'],
                        preparation_memory_flows=specimen['preparation_memory_flows'], execution_mode='search', log=lambda _:None)
                except Exception as error:
                    caught = error
                _check_sources(specimen['sources'])
        except Exception as error:
            result.update(status='refused', reason='replay-static-boundary-failed', error=str(error))
        else:
            if state.get('status') != 'verified':
                result.update(status='refused', reason='replay-static-boundary-unverified')
            elif caught is None:
                result.update(status='not-reproduced')
            else:
                signature = exception_signature(caught)
                result.update(status=('reproduced' if signature == specimen['signature'] else 'not-reproduced')
                    if _business_signature(signature) else 'refused', actual_signature=signature)
            result['case_mapping'] = [{**row, 'replayed_case_ordinal':row['ordinal'],
                'replayed_case_id':None, 'id_mapping':'ordinal-only; executor regenerates IDs'} for row in specimen['case_mapping']]
    except (OSError, ValueError, TypeError, KeyError) as error:
        result.update(status='refused', reason=str(error))
    except Exception as error:
        result.update(status='replay-error', error=str(error))
    _write(output/'failure-replay.json', result)
    return result


def launch_failure_replay(specimen_path, output, timeout=300):
    """Use the existing bounded child controller, without another execution engine."""
    import importlib.util
    root = Path(__file__).resolve().parents[3]
    script = root / 'scripts/reproduce_search_failure.py'
    spec = importlib.util.spec_from_file_location('_myfuzz_failure_launcher', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main(['--specimen', str(Path(specimen_path).resolve()),
                 '--output', str(Path(output).resolve()), '--timeout', str(timeout)])
    return _read(Path(output) / 'failure-replay.json')
