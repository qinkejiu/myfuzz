"""Pure saved evidence joins for explicitly typed compiled F2 and F4 slices.

These documents describe observations supplied by live runtimes; they never
replace builder validation or authorize process startup.
"""
from copy import deepcopy
from hashlib import sha256
import json
import re

_FORMATS = {
    'F4': ('compiled_F4_execution_binding.v1', 'compiled_F4_build_join.v1'),
    'F2': ('compiled_F2_execution_binding.v1', 'compiled_F2_build_join.v1'),
}


def _format(flow):
    if type(flow) is not str or flow not in _FORMATS:
        raise ValueError('compiled-build-join-flow-unsupported')
    return _FORMATS[flow]
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def built_receipt_sha256(document):
    """Digest the complete stable receipt using its canonical UTF-8 encoding."""
    return sha256(_canonical(document)).hexdigest()


def _same(left, right):
    return _canonical(left) == _canonical(right)


def _require(condition, label):
    if not condition:
        raise ValueError('compiled-F4-build-join-' + label)


def _hex(value):
    return type(value) is str and _HEX.fullmatch(value) is not None


def validate_built_receipts(artifacts, receipts):
    """Validate exact component associations and canonical receipt identities."""
    _require(type(receipts) is dict and set(receipts) == set(artifacts), 'receipt-components')
    for component, artifact in artifacts.items():
        receipt = receipts[component]
        _require(type(receipt) is dict and set(receipt) == {'schema_version', 'artifact_digest', 'build_digest', 'build_identity', 'binary_sha256'}, 'receipt-shape')
        _require(receipt['schema_version'] == 'local_harness_built_receipt.v1', 'receipt-schema')
        identity = receipt['build_identity']
        _require(type(identity) is dict and identity.get('schema_version') == 'local_harness_build_identity.v1', 'build-identity-schema')
        _require(all(_hex(receipt[key]) for key in ('artifact_digest', 'build_digest', 'binary_sha256')), 'receipt-digests')
        _require(receipt['artifact_digest'] == artifact.runtime_document.get('artifact_digest') == identity.get('artifact_digest'), 'receipt-artifact')
        _require(identity.get('build_digest') == receipt['build_digest'] == built_receipt_sha256({k:v for k,v in identity.items() if k != 'build_digest'}), 'build-digest')
        _require(artifact.plan.request.instance_id == component, 'artifact-component')


def _binding_document(binding, *, flow):
    _require(type(binding) is dict or callable(getattr(binding, 'document', None)),
             'binding-required')
    document = binding if type(binding) is dict else binding.document()
    _require(type(document) is dict and document.get('schema_version') == _format(flow)[0], 'binding-schema')
    # Existing binding contract uses JSON's default ASCII escaping.
    unsigned = {k:v for k,v in document.items() if k != 'binding_sha256'}
    digest = sha256(json.dumps(unsigned, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    _require(document.get('binding_sha256') == digest, 'binding-digest')
    return document


def _validate(artifacts, binding, original, fresh):
    from .compiled_f4 import _artifact_execution_identity
    cpu = binding.get('cpu', {}).get('instance_id')
    target = binding.get('target', {}).get('component')
    _require(cpu != target and set(artifacts) == {cpu, target}, 'selected-components')
    _require(_same(binding.get('artifact_identities'), {c:_artifact_execution_identity(a) for c,a in artifacts.items()}), 'binding-artifacts')
    receipts = binding.get('built_executable_receipts')
    validate_built_receipts(artifacts, receipts)
    _require(binding.get('built_executable_receipts_sha256') == built_receipt_sha256(receipts), 'receipt-map-digest')
    pids = set(); nonces = set()
    for run in (original, fresh):
        _require(type(run) is dict, 'snapshot')
        _require('unavailable' not in run or (type(run['unavailable']) is dict
                 and not run['unavailable']), 'snapshot-unavailable')
        validate_built_receipts(artifacts, run.get('receipts'))
        _require(_same(receipts, run['receipts']), 'stable-receipts')
        observations = run.get('preparation_observations')
        _require(type(observations) is dict and set(observations) == set(artifacts) and all(type(v) is dict for v in observations.values()), 'preparation-components')
        audit = run.get('execution_audit')
        _require(type(audit) is dict and audit.get('closed') is True, 'audit-closed')
        identities = audit.get('identities'); exits = audit.get('exits')
        _require(type(identities) is dict and type(exits) is dict and set(identities) == set(exits) == set(artifacts), 'process-components')
        for component, receipt in receipts.items():
            row = identities[component]; exit_row = exits[component]
            _require(type(row) is dict and type(exit_row) is dict, 'process-row')
            expected = dict(component=component, role='cpu' if component == cpu else 'bound_target', artifact_digest=receipt['artifact_digest'], build_digest=receipt['build_digest'], binary_sha256=receipt['binary_sha256'], built_receipt_sha256=built_receipt_sha256(receipt), observed_executable_sha256=receipt['binary_sha256'], ready_artifact_digest=receipt['artifact_digest'])
            _require(all(_same(row.get(k),v) for k,v in expected.items()), 'process-receipt')
            pid = row.get('pid'); nonce = row.get('execution_nonce')
            _require(type(pid) is int and pid > 0 and type(nonce) is str and bool(nonce), 'process-identity')
            _require(pid not in pids and nonce not in nonces, 'process-reused')
            pids.add(pid); nonces.add(nonce)
            _require(type(exit_row.get('returncode')) is int and exit_row['returncode'] == 0 and exit_row.get('reaped') is True, 'process-exit')


def build_compiled_build_join(*, flow, artifacts, execution_binding, compiled_document_sha256, runtime_path_id, logical_path_id, original, fresh, error=None):
    """Build a complete strict join, or preserve available material on refusal."""
    binding = ({} if execution_binding is None and error is not None
               else _binding_document(execution_binding, flow=flow))
    if error is None:
        _require(_hex(compiled_document_sha256) and compiled_document_sha256 == binding.get('compiled_document_sha256'), 'compiled-document')
        _require(type(runtime_path_id) is str and bool(runtime_path_id) and runtime_path_id == binding.get('runtime_path_id'), 'runtime-path')
        _require(type(logical_path_id) is str and bool(logical_path_id) and logical_path_id == binding.get('path_id'), 'logical-path')
        _validate(artifacts, binding, original, fresh)
    receipts = binding.get('built_executable_receipts', {})
    return deepcopy(dict(
        schema_version=_format(flow)[1],
        status='complete' if error is None else 'refused',
        scope=f'selected compiled {flow} D2/build/native process association only; no cold-build cost or general throughput acceptance',
        error=None if error is None else (str(error) or type(error).__name__),
        execution_binding_sha256=binding.get('binding_sha256'),
        compiled_document_sha256=compiled_document_sha256,
        runtime_path_id=runtime_path_id, logical_path_id=logical_path_id,
        artifact_digests={c:a.runtime_document.get('artifact_digest')
                          for c,a in artifacts.items()},
        built_executable_receipts=receipts,
        built_executable_receipts_sha256=built_receipt_sha256(receipts),
        built_receipt_sha256={c:built_receipt_sha256(r) for c,r in receipts.items()},
        original=original, fresh=fresh))


def verify_compiled_build_join(document, *, flow, artifacts, execution_binding, original, fresh):
    """Crosscheck saved bytes' decoded content against the same-call evidence."""
    _require(type(document) is dict and document.get('schema_version') == _format(flow)[1], 'document-schema')
    binding = ({} if execution_binding is None and document.get('status') == 'refused'
               else _binding_document(execution_binding, flow=flow))
    _require(document.get('status') in ('complete', 'refused'), 'document-status')
    error = document.get('error')
    _require((document['status'] == 'complete' and error is None) or (document['status'] == 'refused' and type(error) is str and bool(error)), 'document-error')
    expected = build_compiled_build_join(
        flow=flow, artifacts=artifacts, execution_binding=execution_binding,
        compiled_document_sha256=(binding.get('compiled_document_sha256')
                                  if binding else document.get('compiled_document_sha256')),
        runtime_path_id=(binding.get('runtime_path_id')
                         if binding else document.get('runtime_path_id')),
        logical_path_id=(binding.get('path_id')
                         if binding else document.get('logical_path_id')),
        original=original, fresh=fresh, error=error)
    _require(_same(document, expected), 'saved-material')


def verify_compiled_build_material(document, *, flow, harness_set, manifest, prefix, replay):
    """Join complete same-call evidence to D2, frozen manifest and prefix.

    Call alongside ``verify_compiled_f4_build_join``: this check supplies the
    saved external material associations, while that check uses live artifacts
    and both independent runtime audit snapshots.
    """
    def mapping(value, label):
        _require(type(value) is dict, label)
        return value

    document = mapping(document, 'material-document')
    _require(document.get('schema_version') == _format(flow)[1]
             and document.get('status') == 'complete'
             and document.get('error') is None, 'material-complete')
    digests = mapping(document.get('artifact_digests'), 'material-artifacts')
    _require(bool(digests) and all(type(c) is str and bool(c) and _hex(d)
                                 for c,d in digests.items()), 'material-artifact-digests')
    receipts = mapping(document.get('built_executable_receipts'), 'material-receipts')
    _require(set(receipts) == set(digests), 'material-receipt-components')
    _require(document.get('built_executable_receipts_sha256') == built_receipt_sha256(receipts), 'material-receipt-map-digest')
    _require(_same(document.get('built_receipt_sha256'),
                   {c:built_receipt_sha256(r) for c,r in receipts.items()}), 'material-receipt-digests')
    for component, receipt in receipts.items():
        receipt = mapping(receipt, 'material-receipt')
        _require(receipt.get('artifact_digest') == digests[component], 'material-receipt-artifact')
    for name in ('original', 'fresh'):
        run = mapping(document.get(name), 'material-snapshot')
        _require(_same(run.get('receipts'), receipts), 'material-snapshot-receipts')

    harness_set = mapping(harness_set, 'material-harness-set')
    components = harness_set.get('components')
    _require(type(components) is list, 'material-harness-components')
    selected = {}
    for row in components:
        row = mapping(row, 'material-harness-row')
        component = row.get('instance_id')
        _require(type(component) is str and bool(component)
                 and component not in selected, 'material-harness-component')
        selected[component] = row.get('artifact_digest')
    _require(_same(selected, digests), 'material-harness-artifacts')

    prefix = mapping(prefix, 'material-prefix')
    binding = _binding_document(prefix.get('execution_binding'), flow=flow)
    _require(prefix.get('execution_binding_sha256') == binding['binding_sha256']
             == document.get('execution_binding_sha256'), 'material-prefix-binding-digest')
    _require(_same(binding.get('built_executable_receipts'), receipts)
             and binding.get('built_executable_receipts_sha256')
             == document['built_executable_receipts_sha256'], 'material-prefix-receipts')
    _require(_same(prefix.get('artifact_digests'), digests), 'material-prefix-artifacts')
    _require(binding.get('compiled_document_sha256') == document.get('compiled_document_sha256')
             and binding.get('runtime_path_id') == document.get('runtime_path_id')
             and binding.get('path_id') == document.get('logical_path_id'), 'material-prefix-path')

    manifest = mapping(manifest, 'material-manifest')
    runner = mapping(manifest.get('runner'), 'material-runner')
    sessions = mapping(runner.get('sessions'), 'material-sessions')
    _require(set(sessions) == set(receipts), 'material-session-components')
    from myfuzz.local_harness.generated_artifact_admission import _json_bytes
    artifact_identities = mapping(binding.get('artifact_identities'),
                                  'material-binding-artifacts')
    _require(set(artifact_identities) == set(receipts), 'material-binding-components')
    for component, receipt in receipts.items():
        session = mapping(sessions[component], 'material-session')
        identity = mapping(session.get('identity'), 'material-session-identity')
        runtime_artifact = mapping(identity.get('runtime_artifact'),
                                   'material-session-runtime-artifact')
        plan = mapping(runtime_artifact.get('plan'), 'material-session-artifact-plan')
        _require(runtime_artifact.get('schema_version') == 'local_runtime_artifact.v1'
                 and plan.get('instance_id') == component
                 and runtime_artifact.get('artifact_digest') == digests[component],
                 'material-session-artifact-association')
        artifact_identity = mapping(artifact_identities[component],
                                    'material-binding-artifact')
        generated_files = mapping(artifact_identity.get('generated_files_sha256'),
                                  'material-binding-generated-files')
        _require(sha256(_json_bytes(runtime_artifact)).hexdigest()
                 == generated_files.get('artifact.json'), 'material-session-artifact-bytes')
        _require(_same(identity.get('built_executable_receipt'), receipt), 'material-session-receipt')
        _require(_same(identity.get('build_identity'), receipt.get('build_identity')),
                 'material-session-build-identity')
    checker = mapping(manifest.get('checker'), 'material-checker')
    configuration = mapping(checker.get('config'), 'material-checker-config')
    _require(_same(configuration.get('execution_binding'), binding)
             and configuration.get('execution_binding_sha256') == binding['binding_sha256'],
             'material-checker-binding')

    replay = mapping(replay, 'material-replay')
    process_fields = (
        'component', 'role', 'pid', 'execution_nonce', 'artifact_digest',
        'build_digest', 'binary_sha256', 'built_receipt_sha256',
        'observed_executable_sha256', 'ready_artifact_digest')
    for snapshot_name, audit_name in (
            ('original', 'original_execution_audit'), ('fresh', 'execution_audit')):
        external = mapping(replay.get(audit_name), 'material-replay-audit')
        saved = mapping(document[snapshot_name].get('execution_audit'),
                        'material-saved-audit')
        _require(external.get('closed') is True and saved.get('closed') is True,
                 'material-replay-closed')
        external_rows = mapping(external.get('identities'), 'material-replay-identities')
        saved_rows = mapping(saved.get('identities'), 'material-saved-identities')
        external_exits = mapping(external.get('exits'), 'material-replay-exits')
        saved_exits = mapping(saved.get('exits'), 'material-saved-exits')
        _require(set(external_rows) == set(saved_rows) == set(external_exits)
                 == set(saved_exits) == set(receipts), 'material-replay-components')
        for component in receipts:
            observed = mapping(external_rows[component], 'material-replay-process')
            recorded = mapping(saved_rows[component], 'material-saved-process')
            _require(all(key in observed and key in recorded
                         and _same(observed[key], recorded[key])
                         for key in process_fields), 'material-replay-process-identity')
            for exits in (external_exits, saved_exits):
                exit_row = mapping(exits[component], 'material-replay-exit')
                _require(type(exit_row.get('returncode')) is int
                         and exit_row['returncode'] == 0
                         and exit_row.get('reaped') is True, 'material-replay-exit-status')
