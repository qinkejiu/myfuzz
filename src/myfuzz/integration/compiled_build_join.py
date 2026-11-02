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
    'F6': ('compiled_F6_execution_binding.v1', 'compiled_F6_build_join.v1'),
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
    if flow == 'F6':
        # F6 has its own closed execution-binding schema and UTF-8 digest
        # contract. Reuse that structural validator without consulting its
        # live-owner registry: a saved build join is descriptive evidence.
        from myfuzz.scenario.f6_execution_binding import CompiledF6ExecutionBinding
        return CompiledF6ExecutionBinding(document).document()
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


def _validate_f6(artifacts, binding, original, fresh):
    """Join the F6 CPU/DMA artifacts to both actual build audit snapshots.

    Unlike F2/F4, the F6 execution binding intentionally does not carry
    built-executable receipts. The original and fresh process-audit snapshots
    are the source of those receipts; this function checks both against the
    same closed F6 binding and the selected artifact objects.
    """
    from .compiled_f4 import _artifact_execution_identity

    _require(binding.get('flow_id') == 'F6', 'flow-id')
    cpu = binding.get('cpu', {}).get('instance_id')
    dma = binding.get('dma', {}).get('instance_id')
    issuers = binding.get('issuer_contracts')
    _require(type(issuers) is dict, 'issuer-contracts')
    companions = issuers.get('shared_companions', {})
    _require(type(cpu) is str and bool(cpu) and type(dma) is str and bool(dma)
        and cpu != dma and type(companions) is dict
        and set(companions) == set(artifacts) - {cpu, dma}
        and {cpu, dma} <= set(artifacts), 'selected-components')
    _require(_same(binding.get('artifact_identities'),
        {component: _artifact_execution_identity(artifact)
         for component, artifact in sorted(artifacts.items())}),
        'binding-artifacts')

    path = binding.get('runtime_path_admission')
    _require(type(path) is dict
        and path.get('schema_version') == 'compiled_F6_runtime_path_admission.v1',
        'runtime-path-admission')
    from .compiled_f6_runtime_path import _digest as _f6_digest
    path_body = {key: value for key, value in path.items()
                 if key != 'admission_sha256'}
    runtime_path_ids = path.get('runtime_path_ids')
    path_count = len(path['shared_flow_paths'])+1 if 'shared_flow_paths' in path else (3 if 'shared_storage_path' in path else 2)
    _require(type(runtime_path_ids) is list and len(runtime_path_ids) == path_count
        and all(type(value) is str and bool(value) for value in runtime_path_ids)
        and len(set(runtime_path_ids)) == path_count
        and path.get('admission_sha256') == _f6_digest(path_body)
        and binding.get('runtime_path_admission_sha256') == path['admission_sha256'],
        'runtime-path-admission-digest')
    logical_path = path.get('logical_path')
    contract = path.get('execution_contract')
    _require(type(logical_path) is dict
        and type(contract) is dict
        and logical_path.get('path_id') == binding.get('path_id')
        and binding.get('selected_path_sha256') == path.get('selected_path_sha256')
        and binding.get('selected_path_sha256') == _f6_digest(logical_path)
        and binding.get('compiled_document_sha256')
            == path.get('compiled_document_sha256'), 'logical-path-identity')
    _require(binding.get('request_sha256') == path.get('request_sha256')
        and binding.get('execution_contract_sha256')
            == path.get('execution_contract_sha256') == _f6_digest(contract)
        and binding.get('sparse_program_manifest')
            == path.get('sparse_program_manifest'), 'compiled-path-associations')
    from .compiled_f6_firmware import build_f6_firmware
    program_document = build_f6_firmware(contract).document()
    _require(binding.get('program_sha256') == _f6_digest(program_document),
        'program-manifest')
    _require(binding.get('expectation_ids') == contract.get('expectation_ids'),
        'expectation-scope')

    topology = binding.get('topology_binding')
    _require(type(topology) is dict
        and topology.get('identity_sha256') == binding.get('topology_binding_sha256')
        and binding.get('topology_binding_sha256') == _f6_digest({
            key: value for key, value in topology.items()
            if key != 'identity_sha256'}), 'topology-binding-digest')
    route_admission = binding.get('dma_route_admission')
    _require(type(route_admission) is dict
        and route_admission.get('schema_version') == 'dma_master_route_admission.v1'
        and route_admission.get('binding_identity_sha256')
            == binding.get('topology_binding_sha256')
        and binding.get('dma_route_admission_sha256')
            == _f6_digest(route_admission), 'route-admission-identity')
    memory = binding.get('memory')
    _require(type(memory) is dict and type(memory.get('identity')) is dict
        and memory.get('identity_sha256') == _f6_digest(memory['identity'])
        and memory.get('cpu_service_owner') == 'cpu'
        and memory.get('dma_service_owner') == 'dma'
        and memory.get('distinct_service_objects') is True
        and memory.get('distinct_ledger_objects') is True,
        'memory-identity')
    selected_routes = path.get('selected_dma_routes')
    _require(type(selected_routes) is list and len(selected_routes) == 2
        and binding.get('dma_routes') == selected_routes,
        'selected-dma-routes')
    routes_by_operation = {row.get('operation'): row for row in selected_routes
        if type(row) is dict}
    _require(set(routes_by_operation) == {'read', 'write'}
        and route_admission.get('path_id') in runtime_path_ids
        and route_admission.get('read_route_sha256')
            == routes_by_operation['read'].get('identity_sha256')
        and route_admission.get('write_route_sha256')
            == routes_by_operation['write'].get('identity_sha256')
        and routes_by_operation['read'].get('target_identity_sha256')
            == routes_by_operation['write'].get('target_identity_sha256')
        == memory.get('identity_sha256'), 'route-memory-association')
    beat_policy = route_admission.get('beat_policy')
    _require(type(beat_policy) is dict
        and beat_policy.get('schema_version') == 'f6_ram_dma_policy.v1'
        and beat_policy.get('contract') == contract,
        'route-policy-contract')
    expected_issuers = dict(response_fault_schema='f6_dma_response_fault.v1',
        task5_consumer='myfuzz.integration.compiled_f6_consumer.capture_f6_case',
        read_issuer_schema='f6_dma_read_result.v1',
        mret_issuer_schema='native_f6_isr_return.v1')
    if companions:
        from myfuzz.scenario.compiled_paths import load_path_wiring
        from .f6_storage_companion import validate_companion_build_documents
        wiring = load_path_wiring(path['dma_intent_binding']['wiring'])
        validate_companion_build_documents(companions, artifacts=artifacts, wiring=wiring)
        expected_issuers['shared_companions'] = companions
    _require(binding.get('issuer_contracts') == expected_issuers,
        'issuer-contracts')

    # Ensure the embedded route/runtime contract documents are structurally
    # consumable; the source/build join does not issue live topology authority.
    from .compiled_f6_runtime_path import restore_prepared_runtime_paths
    prepared = restore_prepared_runtime_paths(path)
    _require(list(prepared.path_ids) == runtime_path_ids, 'runtime-path-order')
    _require(set(path.get('artifact_identities', {})) == set(artifacts),
        'runtime-path-artifacts')
    for component, artifact in artifacts.items():
        row = path['artifact_identities'][component]
        _require(type(row) is dict
            and row.get('instance_id') == component
            and row.get('artifact_digest')
                == artifact.runtime_document.get('artifact_digest')
            and row.get('profile_fingerprint')
                == artifact.plan.profile.profile_fingerprint
            and row.get('runtime_artifact_sha256')
                == _f6_digest(artifact.runtime_document),
            'runtime-path-artifact-' + component)
    for role, component in (('cpu', cpu), ('dma', dma)):
        role_row = binding.get(role)
        artifact = artifacts[component]
        _require(type(role_row) is dict
            and role_row.get('instance_id') == component
            and role_row.get('profile_fingerprint')
                == artifact.plan.profile.profile_fingerprint
            and role_row.get('runtime_artifact_sha256')
                == _f6_digest(artifact.runtime_document),
            'role-artifact-' + role)
    _require(binding['cpu'].get('irq_provider')
        == contract.get('irq', {}).get('native_take_provider')
        and binding['cpu'].get('mret_issuer_schema')
            == 'native_f6_isr_return.v1', 'cpu-issuer-scope')

    pids = set()
    nonces = set()
    receipts = None
    for snapshot in (original, fresh):
        _require(type(snapshot) is dict, 'snapshot')
        unavailable = snapshot.get('unavailable', {})
        _require(type(unavailable) is dict and not unavailable,
            'snapshot-unavailable')
        current_receipts = snapshot.get('receipts')
        validate_built_receipts(artifacts, current_receipts)
        if receipts is None:
            receipts = deepcopy(current_receipts)
        else:
            _require(_same(current_receipts, receipts), 'stable-receipts')
        observations = snapshot.get('preparation_observations')
        _require(type(observations) is dict and set(observations) == set(artifacts)
            and all(type(value) is dict for value in observations.values()),
            'preparation-components')
        audit = snapshot.get('execution_audit')
        # `original_build`/`fresh_build` are BuiltProcessAudit snapshots. Their
        # embedded audit has this exact shape and deliberately has no separate
        # schema_version (the runtime's execution_audit() is a different row).
        _require(type(audit) is dict
            and set(audit) == {'identities', 'exits', 'closed'}
            and audit.get('closed') is True, 'audit-closed')
        identities, exits = audit.get('identities'), audit.get('exits')
        _require(type(identities) is dict and type(exits) is dict
            and set(identities) == set(exits) == set(artifacts),
            'process-components')
        for component, receipt in current_receipts.items():
            row, exit_row = identities[component], exits[component]
            _require(type(row) is dict and type(exit_row) is dict,
                'process-row')
            expected = dict(component=component,
                role='cpu' if component == cpu else 'bound_target',
                artifact_digest=receipt['artifact_digest'],
                build_digest=receipt['build_digest'],
                binary_sha256=receipt['binary_sha256'],
                built_receipt_sha256=built_receipt_sha256(receipt),
                observed_executable_sha256=receipt['binary_sha256'],
                ready_artifact_digest=receipt['artifact_digest'])
            _require(all(_same(row.get(key), value)
                for key, value in expected.items()), 'process-receipt')
            pid, nonce = row.get('pid'), row.get('execution_nonce')
            _require(type(pid) is int and pid > 0
                and type(nonce) is str and bool(nonce), 'process-identity')
            _require(pid not in pids and nonce not in nonces, 'process-reused')
            pids.add(pid)
            nonces.add(nonce)
            _require(type(exit_row.get('returncode')) is int
                and exit_row['returncode'] == 0
                and exit_row.get('reaped') is True, 'process-exit')
    return receipts


def build_compiled_build_join(*, flow, artifacts, execution_binding,
        compiled_document_sha256, runtime_path_id, logical_path_id, original,
        fresh, error=None, runtime_path_ids=None,
        runtime_path_admission=None, runtime_path_admission_sha256=None,
        selected_path_sha256=None):
    """Build a complete strict join, or preserve available material on refusal."""
    binding = ({} if execution_binding is None and error is not None
               else _binding_document(execution_binding, flow=flow))
    # F2/F4 refused joins historically retain receipt facts already present
    # in their binding. F6's binding intentionally carries no build receipts;
    # a refused F6 join must not derive authority from partial snapshots.
    receipts = (binding.get('built_executable_receipts', {})
        if error is not None and flow != 'F6' else {})
    if error is None:
        _require(_hex(compiled_document_sha256) and compiled_document_sha256 == binding.get('compiled_document_sha256'), 'compiled-document')
        if flow == 'F6':
            _require(type(runtime_path_ids) is list
                and runtime_path_ids == binding.get('runtime_path_admission', {}).get('runtime_path_ids'),
                'runtime-path-ids')
            _require(runtime_path_admission == binding.get('runtime_path_admission'),
                'runtime-path-admission')
            _require(runtime_path_admission_sha256
                == binding.get('runtime_path_admission_sha256'),
                'runtime-path-admission-digest')
            _require(selected_path_sha256 == binding.get('selected_path_sha256'),
                'selected-path-digest')
            _require(logical_path_id == binding.get('path_id'), 'logical-path')
            _require(runtime_path_id is None, 'f6-singular-runtime-path-forbidden')
            receipts = _validate_f6(artifacts, binding, original, fresh)
        else:
            _require(type(runtime_path_id) is str and bool(runtime_path_id) and runtime_path_id == binding.get('runtime_path_id'), 'runtime-path')
            _require(type(logical_path_id) is str and bool(logical_path_id) and logical_path_id == binding.get('path_id'), 'logical-path')
            _validate(artifacts, binding, original, fresh)
            receipts = binding.get('built_executable_receipts', {})
    common = dict(
        schema_version=_format(flow)[1],
        status='complete' if error is None else 'refused',
        scope=(f'selected compiled {flow} D2/build/native process association only; no cold-build cost or general throughput acceptance'
            if flow != 'F6' else 'compiled F6 build receipt and CPU/DMA process identity association only; no F6 dataflow, IRQ/ISR, fresh replay, or capability acceptance'),
        error=None if error is None else (str(error) or type(error).__name__),
        execution_binding_sha256=binding.get('binding_sha256'),
        compiled_document_sha256=compiled_document_sha256,
        artifact_digests={c:a.runtime_document.get('artifact_digest')
                          for c,a in artifacts.items()},
        built_executable_receipts=deepcopy(receipts),
        built_executable_receipts_sha256=built_receipt_sha256(receipts),
        built_receipt_sha256={c:built_receipt_sha256(r) for c,r in receipts.items()},
        original=original, fresh=fresh)
    if flow == 'F6':
        common.update(runtime_path_admission=deepcopy(runtime_path_admission),
            runtime_path_admission_sha256=runtime_path_admission_sha256,
            runtime_path_ids=deepcopy(runtime_path_ids),
            selected_path_sha256=selected_path_sha256,
            logical_path_id=logical_path_id)
    else:
        common.update(runtime_path_id=runtime_path_id,
            logical_path_id=logical_path_id)
    return deepcopy(common)


def verify_compiled_build_join(document, *, flow, artifacts, execution_binding, original, fresh):
    """Crosscheck saved bytes' decoded content against the same-call evidence."""
    _require(type(document) is dict and document.get('schema_version') == _format(flow)[1], 'document-schema')
    binding = ({} if execution_binding is None and document.get('status') == 'refused'
               else _binding_document(execution_binding, flow=flow))
    _require(document.get('status') in ('complete', 'refused'), 'document-status')
    error = document.get('error')
    _require((document['status'] == 'complete' and error is None) or (document['status'] == 'refused' and type(error) is str and bool(error)), 'document-error')
    common = dict(
        flow=flow, artifacts=artifacts, execution_binding=execution_binding,
        compiled_document_sha256=(binding.get('compiled_document_sha256')
                                  if binding else document.get('compiled_document_sha256')),
        original=original, fresh=fresh, error=error)
    if flow == 'F6':
        common.update(runtime_path_id=None,
            logical_path_id=(binding.get('path_id') if binding
                             else document.get('logical_path_id')),
            runtime_path_ids=(binding.get('runtime_path_admission', {}).get('runtime_path_ids')
                if binding else document.get('runtime_path_ids')),
            runtime_path_admission=(binding.get('runtime_path_admission')
                if binding else document.get('runtime_path_admission')),
            runtime_path_admission_sha256=(binding.get('runtime_path_admission_sha256')
                if binding else document.get('runtime_path_admission_sha256')),
            selected_path_sha256=(binding.get('selected_path_sha256')
                if binding else document.get('selected_path_sha256')))
    else:
        common.update(runtime_path_id=(binding.get('runtime_path_id')
            if binding else document.get('runtime_path_id')),
            logical_path_id=(binding.get('path_id') if binding
                else document.get('logical_path_id')))
    expected = build_compiled_build_join(**common)
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
