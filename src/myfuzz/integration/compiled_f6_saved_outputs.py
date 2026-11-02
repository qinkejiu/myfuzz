"""Same-call F6 output integrity. Saved JSON never supplies runtime authority."""
from hashlib import sha256
from itertools import chain
import json
import os
from pathlib import Path
import tempfile


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def write_pinned_json(path, value, pins):
    """Stream legacy JSON bytes, replace atomically, and pin verified bytes."""
    path = Path(path)
    if path.name in pins:
        raise ValueError('compiled-F6-saved-output-already-pinned:' + path.name)
    encoder = json.JSONEncoder(sort_keys=True, indent=2, allow_nan=False)
    expected_hash = sha256()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    primary = None
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            chunks = []
            characters = 0
            for chunk in chain(encoder.iterencode(value), ('\n',)):
                chunks.append(chunk)
                characters += len(chunk)
                if characters >= 65536:
                    raw = ''.join(chunks).encode()
                    stream.write(raw)
                    expected_hash.update(raw)
                    chunks.clear()
                    characters = 0
            if chunks:
                raw = ''.join(chunks).encode()
                stream.write(raw)
                expected_hash.update(raw)
        os.replace(temporary, path)
        actual_hash = sha256()
        with path.open('rb') as stream:
            while chunk := stream.read(65536):
                actual_hash.update(chunk)
        if actual_hash.digest() != expected_hash.digest():
            raise ValueError('compiled-F6-saved-output-initial-bytes:' + path.name)
        pins[path.name] = expected_hash.hexdigest()
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
            primary.add_note('compiled-F6 temporary output cleanup: ' + repr(cleanup))
    return path


def expected_f6_documents(outcome):
    if outcome.get('plan', {}).get('completed') is not True:
        raise ValueError('compiled-F6-saved-output-success-required')
    replay = outcome['replay']
    for document in (replay, outcome['verification']):
        if (document.get('matches') is not True
                or document.get('first_difference', 'missing') is not None
                or document.get('verification_scope') != 'full'):
            raise ValueError('compiled-F6-saved-output-full-fresh-required')
    if (type(replay.get('actual_prefix')) is not dict
            or type(replay.get('actual_events')) is not list
            or type(replay.get('execution_audit')) is not dict
            or replay['execution_audit'].get('closed') is not True):
        raise ValueError('compiled-F6-saved-output-fresh-material-required')
    summary = {key: value for key, value in replay.items()
               if key not in {'actual_prefix', 'actual_events', 'original_build', 'fresh_build'}}
    summary['actual_event_count'] = len(replay['actual_events'])
    return {
        'compiled_f6_prefix.json': outcome['plan'],
        'compiled_f6_replay.json': summary,
        'compiled_f6_fresh_prefix.json': replay['actual_prefix'],
        'compiled_f6_fresh_events.json': replay['actual_events'],
        'compiled_f6_fresh_execution_audit.json': replay['execution_audit'],
        'compiled_f6_fresh_verification.json': outcome['verification'],
        'compiled_f6_build_join.v1.json': outcome['build_join'],
        'compiled_f6_receipt_join.v1.json': outcome['join'],
        'compiled_assertion_results.v1.json': outcome['assertion_material']['assertions'],
        'compiled_assertion_evidence.v1.json': outcome['assertion_material']['assertion_evidence'],
    }


def verify_saved_compiled_f6_build_outputs(output_dir, *, outcome, harness_set, manifest):
    """Verify same-call documents and initial bytes before checking build identity."""
    from .compiled_f6_build_join import verify_compiled_f6_build_join
    expected = expected_f6_documents(outcome)
    initial = outcome.get('saved_output_hashes')
    if type(initial) is not dict or not set(expected) <= set(initial):
        raise ValueError('compiled-F6-saved-output-initial-byte-pins-required')
    saved, hashes = {}, {}
    for name, document in expected.items():
        raw = (Path(output_dir) / name).read_bytes()
        parsed = json.loads(raw)
        if _canonical(parsed) != _canonical(document):
            raise ValueError('compiled-F6-saved-output-mismatch:' + name)
        digest = sha256(raw).hexdigest()
        if digest != initial[name]:
            raise ValueError('compiled-F6-saved-output-bytes-changed:' + name)
        saved[name], hashes[name] = parsed, digest
    transport = outcome.get('transport_files')
    required = {'seed.bin', 'receipts.jsonl', 'online_session_manifest.json', 'online_plan.json'}
    names = {Path(name).name for name in transport} if type(transport) is dict else set()
    if not required <= names or not names & {'online_final_trace.json', 'online_events.jsonl', 'online_events.zlib'}:
        raise ValueError('compiled-F6-saved-transport-pins-required')
    for filename, digest in transport.items():
        path = Path(filename)
        if sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('compiled-F6-saved-transport-bytes-changed:' + str(path))
        hashes[str(path)] = digest
    runtime=outcome['runtime']
    replay=outcome['replay']
    verify_compiled_f6_build_join(saved['compiled_f6_build_join.v1.json'],
        artifacts=runtime.artifacts,execution_binding=runtime.execution_binding,
        original=outcome['plan']['original_build'],fresh=replay['fresh_build'])
    if _canonical(manifest)!=_canonical(runtime.session.manifest_document):
        raise ValueError('compiled-F6-saved-manifest-mismatch')
    actual={r['instance_id']:r['artifact_digest'] for r in harness_set['components']}
    if actual!=outcome['plan']['artifact_digests']:
        raise ValueError('compiled-F6-saved-harness-artifacts-mismatch')
    return hashes


def save_f6_replay_outputs(output_dir, envelope, pins):
    """Attempt every available raw export, preserving the first export failure."""
    output = Path(output_dir)
    exports = []
    for key, name in (
            ('actual_events', 'compiled_f6_fresh_events.json'),
            ('actual_prefix', 'compiled_f6_fresh_prefix.json'),
            ('execution_audit', 'compiled_f6_fresh_execution_audit.json')):
        if envelope.get(key) is not None:
            exports.append((name, envelope[key]))
    summary = {key: value for key, value in envelope.items()
               if key not in {'actual_prefix', 'actual_events', 'original_build', 'fresh_build'}}
    if type(envelope.get('actual_events')) is list:
        summary['actual_event_count'] = len(envelope['actual_events'])
    exports.append(('compiled_f6_replay.json', summary))
    errors = []
    for name, value in exports:
        try:
            write_pinned_json(output / name, value, pins)
        except BaseException as error:
            errors.append(error)
    if errors:
        primary = errors[0]
        for error in errors[1:]:
            primary.add_note('compiled-F6 replay export: ' + repr(error))
        raise primary


def verify_pins(output_dir, pins):
    for name, digest in pins.items():
        path = Path(output_dir)/name
        if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('compiled-F6-saved-output-bytes-changed:'+name)
    return dict(pins)


def expected_f6_failed_prefix_documents(outcome):
    """The controlled ERR prefix retains fresh material under its own scope."""
    plan,replay,verification=outcome['plan'],outcome['replay'],outcome['verification']
    if (plan.get('completed') is not False or plan.get('scope')!='failed_prefix_full'
            or plan.get('status')!='expected_error'
            or replay.get('actual_prefix',{}).get('scope')!='failed_prefix_full'
            or replay.get('actual_prefix',{}).get('completed') is not False
            or replay.get('matches') is not True or replay.get('verification_scope')!='failed_prefix_full'
            or replay.get('first_difference','absent') is not None
            or verification.get('verification_scope')!='failed_prefix_full'
            or replay.get('execution_audit',{}).get('closed') is not True):
        raise ValueError('compiled-F6-failed-prefix-full-required')
    summary={k:v for k,v in replay.items() if k not in {'actual_prefix','actual_events','original_build','fresh_build'}}
    summary['actual_event_count']=len(replay['actual_events'])
    return {'compiled_f6_prefix.json':plan,'compiled_f6_replay.json':summary,
        'compiled_f6_fresh_prefix.json':replay['actual_prefix'],'compiled_f6_fresh_events.json':replay['actual_events'],
        'compiled_f6_fresh_execution_audit.json':replay['execution_audit'],
        'compiled_f6_fresh_verification.json':verification,'compiled_f6_build_join.v1.json':outcome['build_join'],
        'compiled_f6_receipt_join.v1.json':outcome['join'],
        'compiled_assertion_results.v1.json':outcome['assertion_material']['assertions'],
        'compiled_assertion_evidence.v1.json':outcome['assertion_material']['assertion_evidence']}


def verify_saved_compiled_f6_failed_prefix_outputs(output_dir,*,outcome,harness_set,manifest):
    documents=expected_f6_failed_prefix_documents(outcome)
    pins=outcome.get('saved_output_hashes')
    if type(pins) is not dict or not set(documents)<=set(pins):
        raise ValueError('compiled-F6-failed-prefix-pins-required')
    verify_pins(output_dir,pins)
    for name,value in documents.items():
        if _canonical(json.loads((Path(output_dir)/name).read_bytes()))!=_canonical(value):
            raise ValueError('compiled-F6-failed-prefix-material-changed:'+name)
    transport=outcome.get('transport_files')
    if type(transport) is not dict or not transport:raise ValueError('compiled-F6-transport-pins-required')
    for name,digest in transport.items():
        if sha256(Path(name).read_bytes()).hexdigest()!=digest:raise ValueError('compiled-F6-transport-bytes-changed:'+name)
    from .compiled_f6_build_join import verify_compiled_f6_build_join
    runtime=outcome['runtime']
    verify_compiled_f6_build_join(outcome['build_join'],artifacts=runtime.artifacts,
        execution_binding=runtime.execution_binding,original=outcome['plan']['original_build'],fresh=outcome['replay']['fresh_build'])
    if _canonical(manifest)!=_canonical(runtime.session.manifest_document):raise ValueError('compiled-F6-saved-manifest-mismatch')
    if {r['instance_id']:r['artifact_digest'] for r in harness_set['components']}!=outcome['plan']['artifact_digests']:
        raise ValueError('compiled-F6-saved-harness-artifacts-mismatch')
    return dict(pins,**transport)
