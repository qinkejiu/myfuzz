"""Same-call F2 output integrity. Saved JSON never supplies runtime authority."""
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def write_pinned_json(path, value, pins):
    """Prepare bytes once, replace atomically, and retain their initial hash."""
    path = Path(path)
    if path.name in pins:
        raise ValueError('compiled-F2-saved-output-already-pinned:' + path.name)
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    primary = None
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
        os.replace(temporary, path)
        if path.read_bytes() != raw:
            raise ValueError('compiled-F2-saved-output-initial-bytes:' + path.name)
        pins[path.name] = sha256(raw).hexdigest()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except BaseException as cleanup:
            if primary is None:
                raise
            primary.add_note('compiled-F2 temporary output cleanup: ' + repr(cleanup))
    return path


def expected_f2_documents(outcome):
    replay = outcome['replay']
    for document in (replay, outcome['verification']):
        if (document.get('matches') is not True
                or document.get('first_difference', 'missing') is not None
                or document.get('verification_scope') != 'full'):
            raise ValueError('compiled-F2-saved-output-full-fresh-required')
    if (type(replay.get('actual_prefix')) is not dict
            or type(replay.get('actual_events')) is not list
            or type(replay.get('execution_audit')) is not dict
            or replay['execution_audit'].get('closed') is not True):
        raise ValueError('compiled-F2-saved-output-fresh-material-required')
    summary = {key: value for key, value in replay.items()
               if key not in {'actual_prefix', 'actual_events', 'original_build', 'fresh_build'}}
    summary['actual_event_count'] = len(replay['actual_events'])
    return {
        'compiled_f2_prefix.json': outcome['plan'],
        'compiled_f2_replay.json': summary,
        'compiled_f2_fresh_prefix.json': replay['actual_prefix'],
        'compiled_f2_fresh_events.json': replay['actual_events'],
        'compiled_f2_fresh_execution_audit.json': replay['execution_audit'],
        'compiled_f2_fresh_verification.json': outcome['verification'],
        'compiled_f2_build_join.v1.json': outcome['build_join'],
        'compiled_f2_receipt_join.v1.json': outcome['join'],
        'compiled_assertion_results.v1.json': outcome['assertion_material']['assertions'],
        'compiled_assertion_evidence.v1.json': outcome['assertion_material']['assertion_evidence'],
    }


def verify_saved_compiled_f2_build_outputs(output_dir, *, outcome, harness_set, manifest):
    """Verify same-call documents and initial bytes before checking build identity."""
    from .compiled_f2_build_join import verify_compiled_f2_build_material
    expected = expected_f2_documents(outcome)
    initial = outcome.get('saved_output_hashes')
    if type(initial) is not dict or not set(expected) <= set(initial):
        raise ValueError('compiled-F2-saved-output-initial-byte-pins-required')
    saved, hashes = {}, {}
    for name, document in expected.items():
        raw = (Path(output_dir) / name).read_bytes()
        parsed = json.loads(raw)
        if _canonical(parsed) != _canonical(document):
            raise ValueError('compiled-F2-saved-output-mismatch:' + name)
        digest = sha256(raw).hexdigest()
        if digest != initial[name]:
            raise ValueError('compiled-F2-saved-output-bytes-changed:' + name)
        saved[name], hashes[name] = parsed, digest
    transport = outcome.get('transport_files')
    required = {'seed.bin', 'receipts.jsonl', 'online_session_manifest.json', 'online_plan.json'}
    names = {Path(name).name for name in transport} if type(transport) is dict else set()
    if not required <= names or not names & {'online_final_trace.json', 'online_events.jsonl', 'online_events.zlib'}:
        raise ValueError('compiled-F2-saved-transport-pins-required')
    for filename, digest in transport.items():
        path = Path(filename)
        if sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('compiled-F2-saved-transport-bytes-changed:' + str(path))
        hashes[str(path)] = digest
    verify_compiled_f2_build_material(saved['compiled_f2_build_join.v1.json'],
        harness_set=harness_set, manifest=manifest,
        prefix=saved['compiled_f2_prefix.json'], replay=saved['compiled_f2_replay.json'])
    return hashes


def save_f2_replay_outputs(output_dir, envelope, pins):
    """Attempt every available raw export, preserving the first export failure."""
    output = Path(output_dir)
    exports = []
    for key, name in (
            ('actual_events', 'compiled_f2_fresh_events.json'),
            ('actual_prefix', 'compiled_f2_fresh_prefix.json'),
            ('execution_audit', 'compiled_f2_fresh_execution_audit.json')):
        if envelope.get(key) is not None:
            exports.append((name, envelope[key]))
    summary = {key: value for key, value in envelope.items()
               if key not in {'actual_prefix', 'actual_events', 'original_build', 'fresh_build'}}
    if type(envelope.get('actual_events')) is list:
        summary['actual_event_count'] = len(envelope['actual_events'])
    exports.append(('compiled_f2_replay.json', summary))
    errors = []
    for name, value in exports:
        try:
            write_pinned_json(output / name, value, pins)
        except BaseException as error:
            errors.append(error)
    if errors:
        primary = errors[0]
        for error in errors[1:]:
            primary.add_note('compiled-F2 replay export: ' + repr(error))
        raise primary
