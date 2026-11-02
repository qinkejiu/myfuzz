"""F6 build joins bind CPU/DMA build receipts to one typed execution binding.

All process rows here are synthetic software fixtures. This module does not
launch a harness, build a native model, or grant F6 runtime authority.
"""
from copy import deepcopy
from hashlib import sha256
import json

import pytest

from tests.integration.test_compiled_f6_contract import ROOT, source_inputs


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


@pytest.fixture(scope='module')
def admitted():
    request, compiled, artifacts = source_inputs()
    from myfuzz.scenario.ownership import compile_ownership
    compiled_inputs = dict(request=request, compiled=compiled,
        ownership=compile_ownership((), ()), physical_port_map={})
    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path)
    path = admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=compiled_inputs, base_dir=ROOT)
    contract = path['execution_contract']

    from myfuzz.integration.compiled_f4 import _artifact_execution_identity
    from myfuzz.scenario.f6_execution_binding import CompiledF6ExecutionBinding
    cpu_id = contract['cpu']['instance_id']
    dma_id = contract['dma']['instance_id']
    memory = contract['memory']['resource']
    topology = {'schema_version': 'dma_intent_topology_binding.v1'}
    topology['identity_sha256'] = _digest(topology)
    from myfuzz.integration.compiled_f6_runtime_path import _memory_target_identity
    memory_identity = _memory_target_identity(memory)
    memory_identity_sha256 = _digest(memory_identity)
    selected_routes = deepcopy(path['selected_dma_routes'])
    routes_by_operation = {row['operation']: row for row in selected_routes}
    beat_policy = dict(schema_version='f6_ram_dma_policy.v1',
        contract=deepcopy(contract), read_words=4, write_words=4,
        order='four_reads_then_four_writes', byte_enable=15)
    route_admission = dict(schema_version='dma_master_route_admission.v1',
        binding_identity_sha256=topology['identity_sha256'],
        path_id=path['runtime_path_ids'][0],
        read_route_sha256=routes_by_operation['read']['identity_sha256'],
        write_route_sha256=routes_by_operation['write']['identity_sha256'],
        beat_policy=beat_policy)
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    program_document = build_f6_firmware(contract).document()
    body = dict(schema_version='compiled_F6_execution_binding.v1',
        run_id='synthetic-f6-build-join', path_id=contract['path_id'],
        flow_id='F6', compiled_document_sha256=path['compiled_document_sha256'],
        request_sha256=path['request_sha256'],
        execution_contract_sha256=path['execution_contract_sha256'],
        runtime_path_admission=deepcopy(path),
        runtime_path_admission_sha256=path['admission_sha256'],
        selected_path_sha256=path['selected_path_sha256'],
        sparse_program_manifest=deepcopy(path['sparse_program_manifest']),
        program_sha256=_digest(program_document),
        artifact_identities={name: _artifact_execution_identity(artifact)
            for name, artifact in sorted(artifacts.items())},
        topology_binding=topology,
        topology_binding_sha256=topology['identity_sha256'],
        dma_route_admission=route_admission,
        dma_route_admission_sha256=_digest(route_admission),
        dma_routes=selected_routes,
        cpu=dict(instance_id=cpu_id,
            profile_fingerprint=artifacts[cpu_id].plan.profile.profile_fingerprint,
            runtime_artifact_sha256=_digest(artifacts[cpu_id].runtime_document),
            irq_provider=deepcopy(contract['irq']['native_take_provider']),
            mret_issuer_schema='native_f6_isr_return.v1'),
        dma=dict(instance_id=dma_id,
            profile_fingerprint=artifacts[dma_id].plan.profile.profile_fingerprint,
            runtime_artifact_sha256=_digest(artifacts[dma_id].runtime_document)),
        memory=dict(identity=memory_identity,
            identity_sha256=memory_identity_sha256, cpu_service_owner='cpu',
            dma_service_owner='dma', distinct_service_objects=True,
            distinct_ledger_objects=True),
        issuer_contracts=dict(response_fault_schema='f6_dma_response_fault.v1',
            task5_consumer='myfuzz.integration.compiled_f6_consumer.capture_f6_case',
            read_issuer_schema='f6_dma_read_result.v1',
            mret_issuer_schema='native_f6_isr_return.v1'),
        expectation_ids=list(contract['expectation_ids']),
        ownership_sha256=_digest(compiled_inputs['ownership'].document()),
        physical_port_map_sha256=_digest([]),
        executor_source_closure_sha256='4' * 64)
    body['binding_sha256'] = _digest(body)
    binding = CompiledF6ExecutionBinding(body).document()

    from myfuzz.integration.compiled_build_join import built_receipt_sha256
    receipts = {}
    for component, artifact in sorted(artifacts.items()):
        identity = dict(schema_version='local_harness_build_identity.v1',
            artifact_digest=artifact.runtime_document['artifact_digest'],
            inputs=[], toolchain={})
        identity['build_digest'] = built_receipt_sha256(identity)
        receipts[component] = dict(
            schema_version='local_harness_built_receipt.v1',
            artifact_digest=identity['artifact_digest'],
            build_digest=identity['build_digest'], build_identity=identity,
            binary_sha256=_digest(['binary', component]))

    runs = []
    for label, offset in (('original', 100), ('fresh', 200)):
        identities = {}
        exits = {}
        for index, (component, receipt) in enumerate(sorted(receipts.items())):
            identities[component] = dict(component=component,
                role='cpu' if component == cpu_id else 'bound_target',
                pid=offset + index,
                execution_nonce=f'{label}-{component}',
                artifact_digest=receipt['artifact_digest'],
                build_digest=receipt['build_digest'],
                binary_sha256=receipt['binary_sha256'],
                built_receipt_sha256=built_receipt_sha256(receipt),
                observed_executable_sha256=receipt['binary_sha256'],
                ready_artifact_digest=receipt['artifact_digest'])
            exits[component] = dict(returncode=0, reaped=True)
        runs.append(dict(receipts=deepcopy(receipts),
            preparation_observations={component: dict(outcome='cache_hit')
                for component in receipts},
            execution_audit=dict(identities=identities, exits=exits, closed=True),
            unavailable={}))
    return dict(artifacts=artifacts, execution_binding=binding,
        original=runs[0], fresh=runs[1])


def issue(admitted):
    return deepcopy(admitted)


def test_complete_f6_join_preserves_full_ordered_path_and_detached_snapshots(admitted):
    from myfuzz.integration.compiled_f6_build_join import (
        build_compiled_f6_build_join, verify_compiled_f6_build_join)

    args = issue(admitted)
    document = build_compiled_f6_build_join(**args)
    binding = args['execution_binding']
    assert document['schema_version'] == 'compiled_F6_build_join.v1'
    assert document['status'] == 'complete'
    assert document['execution_binding_sha256'] == binding['binding_sha256']
    assert document['compiled_document_sha256'] == binding['compiled_document_sha256']
    assert document['runtime_path_admission'] == binding['runtime_path_admission']
    assert document['runtime_path_admission_sha256'] == binding['runtime_path_admission_sha256']
    assert document['runtime_path_ids'] == binding['runtime_path_admission']['runtime_path_ids']
    assert len(document['runtime_path_ids']) == 2
    assert document['selected_path_sha256'] == binding['selected_path_sha256']
    assert document['logical_path_id'] == binding['path_id']
    assert set(document['built_executable_receipts']) == set(args['artifacts'])
    verify_compiled_f6_build_join(document, **args)
    args['original']['preparation_observations']['cpu']['elapsed_seconds'] = 2.0
    assert 'elapsed_seconds' not in document['original']['preparation_observations']['cpu']


@pytest.mark.parametrize('mutation', [
    'missing_digest', 'wrong_digest', 'cross_flow', 'compiled_digest',
    'path_admission', 'path_ids_order', 'selected_path', 'logical_path',
    'artifact_identity', 'missing_receipt', 'extra_receipt',
    'receipt_artifact', 'receipt_digest', 'receipt_drift',
    'process_identity', 'process_role', 'observed_binary', 'ready_artifact',
    'exit_missing', 'exit_nonzero', 'exit_bool', 'not_reaped', 'audit_open',
    'audit_schema_forgery', 'pid_reused', 'nonce_reused', 'snapshot_unavailable',
])
def test_f6_join_rejects_cross_scope_or_incomplete_build_material(admitted, mutation):
    from myfuzz.integration.compiled_f6_build_join import build_compiled_f6_build_join

    args = issue(admitted)
    if mutation in ('missing_digest', 'wrong_digest', 'cross_flow',
            'compiled_digest', 'path_admission', 'path_ids_order',
            'selected_path', 'logical_path', 'artifact_identity'):
        binding = deepcopy(args['execution_binding'])
        if mutation == 'missing_digest':
            del binding['binding_sha256']
        elif mutation == 'wrong_digest':
            binding['binding_sha256'] = 'f' * 64
        elif mutation == 'cross_flow':
            binding['schema_version'] = 'compiled_F2_execution_binding.v1'
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        elif mutation == 'compiled_digest':
            binding['compiled_document_sha256'] = 'a' * 64
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        elif mutation == 'path_admission':
            binding['runtime_path_admission_sha256'] = 'b' * 64
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        elif mutation == 'path_ids_order':
            binding['runtime_path_admission']['runtime_path_ids'].reverse()
            binding['runtime_path_admission']['admission_sha256'] = _digest({
                k:v for k,v in binding['runtime_path_admission'].items()
                if k != 'admission_sha256'})
            binding['runtime_path_admission_sha256'] = binding['runtime_path_admission']['admission_sha256']
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        elif mutation == 'selected_path':
            binding['selected_path_sha256'] = 'c' * 64
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        elif mutation == 'logical_path':
            binding['path_id'] = 'different-logical-path'
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        else:
            binding['artifact_identities']['dma']['artifact_digest'] = 'd' * 64
            binding['binding_sha256'] = _digest({k:v for k,v in binding.items()
                if k != 'binding_sha256'})
        args['execution_binding'] = binding
    elif mutation in ('missing_receipt', 'extra_receipt', 'receipt_artifact',
            'receipt_digest', 'receipt_drift'):
        if mutation == 'missing_receipt':
            del args['fresh']['receipts']['dma']
        elif mutation == 'extra_receipt':
            args['fresh']['receipts']['other'] = deepcopy(args['fresh']['receipts']['dma'])
        elif mutation == 'receipt_artifact':
            args['fresh']['receipts']['dma']['artifact_digest'] = 'e' * 64
        elif mutation == 'receipt_digest':
            args['fresh']['receipts']['dma']['build_digest'] = 'e' * 64
        else:
            args['fresh']['receipts']['dma']['binary_sha256'] = 'e' * 64
    elif mutation in ('process_identity', 'process_role', 'observed_binary',
            'ready_artifact'):
        row = args['fresh']['execution_audit']['identities']['dma']
        if mutation == 'process_identity':
            row['build_digest'] = 'e' * 64
        elif mutation == 'process_role':
            row['role'] = 'cpu'
        elif mutation == 'observed_binary':
            row['observed_executable_sha256'] = 'e' * 64
        else:
            row['ready_artifact_digest'] = 'e' * 64
    elif mutation == 'exit_missing':
        del args['fresh']['execution_audit']['exits']['dma']
    elif mutation in ('exit_nonzero', 'exit_bool'):
        args['fresh']['execution_audit']['exits']['dma']['returncode'] = (
            False if mutation == 'exit_bool' else 1)
    elif mutation == 'not_reaped':
        args['fresh']['execution_audit']['exits']['dma']['reaped'] = False
    elif mutation == 'audit_open':
        args['fresh']['execution_audit']['closed'] = False
    elif mutation == 'audit_schema_forgery':
        args['fresh']['execution_audit']['schema_version'] = \
            'compiled_F6_execution_audit.v1'
    elif mutation == 'pid_reused':
        args['fresh']['execution_audit']['identities']['dma']['pid'] = \
            args['original']['execution_audit']['identities']['dma']['pid']
    elif mutation == 'nonce_reused':
        args['fresh']['execution_audit']['identities']['dma']['execution_nonce'] = \
            args['original']['execution_audit']['identities']['dma']['execution_nonce']
    else:
        args['fresh']['unavailable'] = {'dma': {'receipt': 'missing'}}

    with pytest.raises((TypeError, ValueError)):
        build_compiled_f6_build_join(**args)


def test_saved_f6_join_rejects_coherently_rehashed_path_or_receipt_mutation(admitted):
    from myfuzz.integration.compiled_f6_build_join import (
        build_compiled_f6_build_join, verify_compiled_f6_build_join)

    args = issue(admitted)
    document = build_compiled_f6_build_join(**args)
    document['runtime_path_ids'].reverse()
    document['built_executable_receipts']['dma']['binary_sha256'] = 'a' * 64
    document['built_executable_receipts_sha256'] = _digest(
        document['built_executable_receipts'])
    with pytest.raises(ValueError):
        verify_compiled_f6_build_join(document, **args)


def test_refused_f6_join_preserves_partial_snapshots_without_granting_receipts(admitted):
    from myfuzz.integration.compiled_f6_build_join import (
        build_compiled_f6_build_join, verify_compiled_f6_build_join)

    args = issue(admitted)
    args['execution_binding'] = None
    args['fresh'] = {'unavailable': {'dma': {'startup': 'not reached'}}}
    document = build_compiled_f6_build_join(**args, error='fresh startup refused')
    assert document['status'] == 'refused'
    assert document['execution_binding_sha256'] is None
    assert document['built_executable_receipts'] == {}
    assert document['fresh'] == args['fresh']
    verify_compiled_f6_build_join(document, **args)
