"""Explicit F2 driver dispatch; software doubles never claim native execution."""
import json
from copy import deepcopy
from contextlib import nullcontext
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.integration.test_auto_harness_test import (
    ROOT, TIMER_CPU, TIMER_IP, TIMER_CAPABILITY, TIMER_COMPOSE,
    run_cli, compiled_arguments)


def test_f2_entry_is_registered_without_a_family_fallback():
    from myfuzz.local_harness.auto_harness_test import COMPILED_EXECUTORS
    row = COMPILED_EXECUTORS['compiled-f2-rfuzz']
    assert row['flow'] == 'F2'
    assert row['entry'] == 'myfuzz.integration.compiled_f2_rfuzz:run_compiled_f2_rfuzz_session'
    assert row['family_fallback'] is False


def test_f2_cli_skip_session_has_real_support_without_native(tmp_path):
    output = tmp_path / 'skip-f2'
    result, summary = run_cli(*compiled_arguments(output, '--executor', 'compiled-f2-rfuzz', '--skip-session'))
    assert result.returncode == 0, result.stderr
    assert summary['runtime_family']['status'] == 'not_requested'
    assert summary['stages']['execution_projection']['status'] == 'ok'
    projection = json.loads((output / 'execution_projection.v1.json').read_text())
    assert projection['flow_id'] == 'F2' and projection['execution_supported'] == 1
    assert projection['runtime_admitted'] is False
    assert not (output / 'session').exists()


@pytest.mark.parametrize('late_swap', [None, 'raw', 'fresh', 'capability'])
def test_f2_driver_passes_same_call_objects_and_independent_typed_material(monkeypatch, tmp_path, late_swap):
    from myfuzz.local_harness import auto_harness_test as driver
    from myfuzz.integration import compiled_f2_saved_outputs as saved
    from myfuzz.integration.compiled_f2 import derive_f2_execution_binding
    from tests.scenario.test_capability_compiled_assertions import inputs as assertion_inputs
    output = tmp_path / 'f2-driver'
    client = tmp_path / 'client'; client.write_bytes(b'')
    cache = tmp_path / 'cache'; cache.mkdir()
    seen = {}
    load = driver.load_compiled_session_inputs
    def capture_load(**kwargs):
        assert kwargs['flow'] == 'F2'
        artifacts, inputs = load(**kwargs)
        assert inputs['compiled'] is kwargs['compiled']
        assert inputs['request'] is kwargs['request']
        seen.update(artifacts=artifacts, inputs=inputs)
        return artifacts, inputs
    monkeypatch.setattr(driver, 'load_compiled_session_inputs', capture_load)
    monkeypatch.setattr(driver, '_heavy_worker_lock', lambda base: nullcontext())
    monkeypatch.setattr(driver, 'run_compiled_session', lambda **kwargs: pytest.fail('F4 dispatch used'))
    def session(**kwargs):
        assert kwargs['artifacts'] is seen['artifacts']
        assert kwargs['compiled_inputs'] is seen['inputs']
        binding = derive_f2_execution_binding(artifacts=kwargs['artifacts'],
            compiled_inputs=kwargs['compiled_inputs'], base_dir=ROOT).document()
        # Synthetic build/process observations attached to the actual admitted
        # source artifacts. No compiler, native launch, or live token is claimed.
        from myfuzz.integration.compiled_f2 import CompiledF2ExecutionBinding
        from myfuzz.integration.compiled_f2_build_join import (
            build_compiled_f2_build_join, built_receipt_sha256)
        receipts = {}
        for component, artifact in kwargs['artifacts'].items():
            identity = dict(schema_version='local_harness_build_identity.v1',
                artifact_digest=artifact.runtime_document['artifact_digest'], inputs=[], toolchain={})
            identity['build_digest'] = built_receipt_sha256(identity)
            receipts[component] = dict(schema_version='local_harness_built_receipt.v1',
                artifact_digest=identity['artifact_digest'], build_digest=identity['build_digest'],
                build_identity=identity, binary_sha256=sha256(component.encode()).hexdigest())
        binding['built_executable_receipts'] = receipts
        binding['built_executable_receipts_sha256'] = built_receipt_sha256(receipts)
        binding = CompiledF2ExecutionBinding.build(binding).document()
        snapshots = []
        for offset in (100, 200):
            identities = {component: dict(component=component,
                role='cpu' if component == binding['cpu']['instance_id'] else 'bound_target',
                pid=offset+index, execution_nonce=f'synthetic-{offset}-{component}',
                artifact_digest=receipt['artifact_digest'], build_digest=receipt['build_digest'],
                binary_sha256=receipt['binary_sha256'], built_receipt_sha256=built_receipt_sha256(receipt),
                observed_executable_sha256=receipt['binary_sha256'],
                ready_artifact_digest=receipt['artifact_digest'])
                for index, (component, receipt) in enumerate(receipts.items())}
            snapshots.append(dict(receipts=deepcopy(receipts),
                preparation_observations={component: {'outcome':'synthetic_cache_hit'} for component in receipts},
                execution_audit=dict(identities=identities,
                    exits={component:dict(returncode=0,reaped=True) for component in receipts},closed=True)))
        build_join = build_compiled_f2_build_join(artifacts=kwargs['artifacts'],
            execution_binding=binding,compiled_document_sha256=binding['compiled_document_sha256'],
            runtime_path_id=binding['runtime_path_id'],logical_path_id=binding['path_id'],
            original=snapshots[0],fresh=snapshots[1])
        _, typed = assertion_inputs((kwargs['compiled_inputs']['compiled'], binding))
        material = {'assertions': typed['assertion_results'],
                    'assertion_evidence': typed['assertion_evidence']}
        seen['material'] = material
        session_dir = kwargs['session_dir']; session_dir.mkdir()
        manifest = dict(runner=dict(sessions={component:dict(identity=dict(
            built_executable_receipt=deepcopy(receipt),build_identity=deepcopy(receipt['build_identity']),
            runtime_artifact=deepcopy(kwargs['artifacts'][component].runtime_document)))
            for component, receipt in receipts.items()}),checker=dict(config=dict(
                execution_binding=deepcopy(binding),execution_binding_sha256=binding['binding_sha256'])))
        (session_dir / 'online_session_manifest.json').write_text(json.dumps(manifest))
        (session_dir / 'report.json').write_text(json.dumps({'tests': 1, 'statuses': {'certified': 1},
            'execution_status': 'complete', 'elapsed_seconds': 0.1, 'effective_search_seconds': 0.1}))
        from myfuzz.integration.compiled_f2_rfuzz import f2_seed_record
        path = next(p for p in kwargs['compiled_inputs']['compiled']['paths'] if p['path_id'] == binding['path_id'])
        (session_dir / 'seed.bin').write_bytes(f2_seed_record(path))
        for filename in ('receipts.jsonl', 'online_plan.json', 'online_final_trace.json'):
            (session_dir / filename).write_bytes(b'{}')
        plan = dict(execution_binding=binding,execution_binding_sha256=binding['binding_sha256'],
            artifact_digests=deepcopy(build_join['artifact_digests']),records=[])
        replay = dict(matches=True,first_difference=None,verification_scope='full',
            original_execution_audit=deepcopy(snapshots[0]['execution_audit']),
            execution_audit=deepcopy(snapshots[1]['execution_audit']),
            actual_prefix=deepcopy(plan),actual_events=[{'event_id':1,'synthetic_transport_only':True}])
        outcome = {'live': SimpleNamespace(tests=1, completed_feedback_exchanges=1,
            statuses={'certified': 1}, client_returncode=0, effective_search_seconds=0.1),
            'verification': {'schema_version':'fresh_verification.v1','matches':True,
                'first_difference':None,'verification_scope':'full'},
            'join': {'schema_version':'compiled_F2_receipt_join.v1','status':'ok',
                'path_id':binding['path_id'],'source_id':'source', 'rows':1},
            'plan':plan,'replay':replay,'build_join':build_join,
            'assertion_material':material, 'transport_files':{}, 'saved_output_hashes':{}}
        for name, document in saved.expected_f2_documents(outcome).items():
            saved.write_pinned_json(output / name,document,outcome['saved_output_hashes'])
        outcome['transport_files'] = {str(session_dir/name):sha256((session_dir/name).read_bytes()).hexdigest()
            for name in ('seed.bin','receipts.jsonl','online_session_manifest.json','online_plan.json','online_final_trace.json')}
        return outcome
    monkeypatch.setattr(driver, 'run_compiled_f2_session', session, raising=False)
    initial_writer = saved.write_pinned_json
    def late_writer(path, value, pins):
        result = initial_writer(path, value, pins)
        if late_swap == 'capability' and Path(path).name == 'capability-report.json':
            Path(path).write_bytes(Path(path).read_bytes() + b' ')
            seen['capability_swap'] = True
        return result
    monkeypatch.setattr(saved, 'write_pinned_json', late_writer)
    capability = driver.build_capability_report
    def capture_report(*args, **kwargs):
        assert kwargs['assertion_results'] is seen['material']['assertions']
        assert kwargs['assertion_evidence'] is seen['material']['assertion_evidence']
        report = capability(*args, **kwargs)
        baseline = capability(*args, **{k:v for k,v in kwargs.items() if k not in ('assertion_results','assertion_evidence')})
        assert [row['tiers'] for row in report['paths']] == [row['tiers'] for row in baseline['paths']]
        return report
    monkeypatch.setattr(driver, 'build_capability_report', capture_report)
    def bundle(*, session_dir, bundle_dir):
        if late_swap == 'raw': (session_dir / 'seed.bin').write_bytes(b'changed')
        if late_swap == 'fresh':
            path = output / 'compiled_f2_fresh_events.json'
            path.write_bytes(path.read_bytes() + b' ')
        bundle_dir.mkdir(); (bundle_dir / 'bundle-manifest.json').write_text('{}')
        return {'schema_version':'synthetic_bundle'}
    monkeypatch.setattr(driver, 'write_authenticated_bundle', bundle)
    summary = driver.run_auto_harness_test(cpu=ROOT / TIMER_CPU, ips=[ROOT / TIMER_IP],
        ip_capabilities=[ROOT / TIMER_CAPABILITY],compose=ROOT / TIMER_COMPOSE,
        output=output,base_dir=ROOT,executor='compiled-f2-rfuzz',client_binary=client,
        cache_dir=cache,budget_seconds=1,max_tests=1)
    assert 'material' in seen, summary['refusals']
    report = json.loads((output / 'capability-report.json').read_text())
    assert len(report['assertion_results']) == 2
    assert all(row['status'] == 'passed' for row in report['assertion_results'])
    if late_swap == 'capability':
        assert seen.get('capability_swap') is True
    if late_swap:
        assert summary['status'] == 'refused'
        assert any(row['code']=='compiled-build-saved-output-changed' for row in summary['refusals'])
        assert (output / '.incomplete').exists()
    else:
        assert summary['status'] == 'complete', summary['refusals']
        assert summary['executor']['detail']['useful_search_benefit_claimed'] is False
        assert summary['executor']['detail']['candidate_domain_size'] == 1
        published = summary['executor']['detail']['saved_output_hashes']
        assert published['capability-report.json'] == sha256((output/'capability-report.json').read_bytes()).hexdigest()


def test_f2_wrapper_forwards_exact_inputs(monkeypatch):
    from myfuzz.local_harness import auto_harness_test as driver
    from myfuzz.integration import compiled_f2_rfuzz
    seen = {}
    def wrapper(**kwargs): seen.update(kwargs); return object()
    monkeypatch.setattr(compiled_f2_rfuzz, 'run_compiled_f2_rfuzz_session', wrapper)
    artifacts, inputs = {}, {}
    driver.run_compiled_f2_session(artifacts=artifacts,compiled_inputs=inputs,
        base_dir=ROOT,cache_dir=ROOT,run_id='r',output_dir=ROOT,session_dir=ROOT,
        client_binary=ROOT,budget_seconds=1,max_tests=1,search_seed=1,max_runs_per_batch=1)
    assert seen['artifacts'] is artifacts and seen['compiled_inputs'] is inputs


from tests.integration.test_compiled_f4_spi_source_real import spi_d2_d3


def test_f2_spi_ownership_uses_fixed_d2_inputs_and_not_cpu_address(spi_d2_d3):
    from myfuzz.local_harness.auto_harness_test import load_compiled_session_inputs
    generated, _, _, source = spi_d2_d3
    artifacts, inputs = load_compiled_session_inputs(generated_root=generated,
        base_dir=ROOT, request=source['request'], compiled=source['compiled'], flow='F2')
    assert inputs['request'] is source['request'] and inputs['compiled'] is source['compiled']
    owners = inputs['ownership'].document()['owners']
    assert {(r['component_id'],r['port'],r['kind']) for r in owners} == {
        ('peripheral', f'spi.pins.sdi{lane}', 'fixed') for lane in range(4)}
    assert len(artifacts) == 2


def test_f2_modified_same_call_contract_refuses_before_constructor(monkeypatch, tmp_path):
    from myfuzz.local_harness import auto_harness_test as driver
    load = driver.load_compiled_session_inputs
    def modified(**kwargs):
        artifacts, inputs = load(**kwargs)
        path = next(p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F2')
        path['execution_contract']['address'] += 4
        return artifacts, inputs
    monkeypatch.setattr(driver, 'load_compiled_session_inputs', modified)
    monkeypatch.setattr(driver, 'run_compiled_f2_session', lambda **kwargs: pytest.fail('constructor reached'))
    output = tmp_path / 'changed-contract'
    summary = driver.run_auto_harness_test(cpu=ROOT / TIMER_CPU,ips=[ROOT / TIMER_IP],
        ip_capabilities=[ROOT / TIMER_CAPABILITY],compose=ROOT / TIMER_COMPOSE,
        output=output,base_dir=ROOT,executor='compiled-f2-rfuzz',skip_session=True)
    assert summary['status'] == 'refused'
    assert summary['executor']['status'] == 'refused'
    assert any(row['code']=='compiled-f2-target-unsupported' and row['pointer']=='/compiled_paths'
               for row in summary['refusals'])
    support = json.loads((output / 'execution_projection.v1.json').read_text())
    assert support['flow_id'] == 'F2' and support['execution_supported'] == 0
    assert support['reason']
    assert {p['path_id'] for p in support['unsupported_paths']} == {
        p['path_id'] for p in json.loads((output/'compiled_paths.v1.json').read_text())['paths']
        if p['flow_id'] != 'F2'}
