"""Saved joins crosscheck real admitted F4 artifacts, without native execution."""
from copy import deepcopy
import pytest
from myfuzz.integration.compiled_f4 import derive_f4_execution_binding, CompiledF4ExecutionBinding, _digest
from myfuzz.integration.compiled_f4_build_join import build_compiled_f4_build_join, verify_compiled_f4_build_join
from tests.integration.test_compiled_f4_storage_producer import timer_loaded, ROOT


@pytest.fixture(scope='module')
def admitted(tmp_path_factory):
    artifacts, inputs = timer_loaded(tmp_path_factory.mktemp('build-join'))
    binding = derive_f4_execution_binding(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT).document()
    receipts = {}
    for component, artifact in artifacts.items():
        identity = dict(schema_version='local_harness_build_identity.v1', artifact_digest=artifact.runtime_document['artifact_digest'], inputs=[], toolchain={})
        identity['build_digest'] = _digest(identity)
        receipts[component] = dict(schema_version='local_harness_built_receipt.v1', artifact_digest=identity['artifact_digest'], build_digest=identity['build_digest'], build_identity=identity, binary_sha256=_digest(component))
    binding['built_executable_receipts'] = receipts
    binding['built_executable_receipts_sha256'] = _digest(receipts)
    binding = CompiledF4ExecutionBinding.build(binding)
    runs = []
    for offset in (100, 200):
        rows = {c: dict(component=c, role='cpu' if c=='processor' else 'bound_target', pid=offset+i, execution_nonce=f'{offset}-{c}', artifact_digest=r['artifact_digest'], build_digest=r['build_digest'], binary_sha256=r['binary_sha256'], built_receipt_sha256=_digest(r), observed_executable_sha256=r['binary_sha256'], ready_artifact_digest=r['artifact_digest']) for i,(c,r) in enumerate(receipts.items())}
        runs.append(dict(receipts=deepcopy(receipts), preparation_observations={c:dict(outcome='cache_hit') for c in receipts}, execution_audit=dict(identities=rows, exits={c:dict(returncode=0,reaped=True) for c in receipts}, closed=True)))
    return artifacts,binding,runs


def issue(admitted):
    artifacts,binding,runs=deepcopy(admitted)
    args=dict(artifacts=artifacts,execution_binding=binding,compiled_document_sha256=binding.document()['compiled_document_sha256'],runtime_path_id=binding.document()['runtime_path_id'],logical_path_id=binding.document()['path_id'],original=runs[0],fresh=runs[1])
    return args


def test_complete_and_detached(admitted):
    args=issue(admitted)
    doc=build_compiled_f4_build_join(**args)
    assert doc['status']=='complete'
    verify_compiled_f4_build_join(doc, **{k:args[k] for k in ('artifacts','execution_binding','original','fresh')})
    args['original']['preparation_observations']['processor']['seconds']=99
    assert 'seconds' not in doc['original']['preparation_observations']['processor']


@pytest.mark.parametrize('mutation', ['swap','binary','exit','pid','nonce','ready','live','identity','component'])
def test_rejects_broken_joins(admitted,mutation):
    args=issue(admitted); run=args['fresh']; rows=run['execution_audit']['identities']; row=rows['processor']
    if mutation=='swap': rows['processor'],rows['peripheral']=rows['peripheral'],rows['processor']
    elif mutation=='binary': run['receipts']['processor']['binary_sha256']='a'*64;row['binary_sha256']='a'*64;row['built_receipt_sha256']=_digest(run['receipts']['processor'])
    elif mutation=='exit': del run['execution_audit']['exits']['processor']
    elif mutation=='pid': row['pid']=args['original']['execution_audit']['identities']['processor']['pid']
    elif mutation=='nonce': row['execution_nonce']=args['original']['execution_audit']['identities']['processor']['execution_nonce']
    elif mutation=='ready': row['ready_artifact_digest']='a'*64
    elif mutation=='live': row['observed_executable_sha256']='a'*64
    elif mutation=='identity': run['receipts']['processor']['build_identity']['artifact_digest']='a'*64
    else: run['receipts']['extra']=run['receipts']['processor']
    with pytest.raises(ValueError): build_compiled_f4_build_join(**args)


def test_diagnostics_can_differ_and_refusal_retains_partial(admitted):
    args=issue(admitted);args['fresh']['preparation_observations']['processor']={'outcome':'compiled_published','seconds':3.4}
    assert build_compiled_f4_build_join(**args)['status']=='complete'
    args['fresh']={}; doc=build_compiled_f4_build_join(**args,error='preparation failed')
    assert doc['status']=='refused' and doc['fresh']=={} and doc['error']=='preparation failed'


def test_rehashed_saved_swap_refuses(admitted):
    args=issue(admitted);doc=build_compiled_f4_build_join(**args)
    receipts=doc['built_executable_receipts'];receipts['processor'],receipts['peripheral']=receipts['peripheral'],receipts['processor']
    doc['built_executable_receipts_sha256']=_digest(receipts)
    with pytest.raises(ValueError): verify_compiled_f4_build_join(doc,**{k:args[k] for k in ('artifacts','execution_binding','original','fresh')})


@pytest.mark.parametrize('field', ['artifact','map_digest','binding_digest','compiled_document','path','exit_bool','closed'])
def test_external_associations_and_strict_types(admitted,field):
    args=issue(admitted)
    if field in ('artifact','map_digest','binding_digest'):
        binding=args['execution_binding'].document()
        if field=='artifact': binding['artifact_identities']['processor']['artifact_digest']='b'*64
        elif field=='map_digest': binding['built_executable_receipts_sha256']='b'*64
        else: binding['binding_sha256']='b'*64
        args['execution_binding']=binding if field=='binding_digest' else CompiledF4ExecutionBinding.build(binding).document()
    elif field=='compiled_document': args['compiled_document_sha256']='b'*64
    elif field=='path': args['logical_path_id']='other'
    elif field=='exit_bool': args['original']['execution_audit']['exits']['processor']['returncode']=False
    else: args['fresh']['execution_audit']['closed']=1
    with pytest.raises(ValueError): build_compiled_f4_build_join(**args)


def test_unicode_receipts_use_utf8(admitted):
    from myfuzz.integration.compiled_f4_build_join import built_receipt_sha256
    args=issue(admitted);binding=args['execution_binding'].document()
    for run in (binding,):
        for receipt in run['built_executable_receipts'].values():
            identity=receipt['build_identity'];identity['note']='编译'
            identity['build_digest']=built_receipt_sha256({k:v for k,v in identity.items() if k!='build_digest'})
            receipt['build_digest']=identity['build_digest']
    binding['built_executable_receipts_sha256']=built_receipt_sha256(binding['built_executable_receipts'])
    args['execution_binding']=CompiledF4ExecutionBinding.build(binding).document()
    for run in (args['original'],args['fresh']):
        run['receipts']=deepcopy(binding['built_executable_receipts'])
        for c,r in run['receipts'].items():
            run['execution_audit']['identities'][c].update(build_digest=r['build_digest'],built_receipt_sha256=built_receipt_sha256(r))
    assert build_compiled_f4_build_join(**args)['status']=='complete'


def test_prebinding_failure_retains_missing_material(admitted):
    args=issue(admitted);args.update(execution_binding=None, original={}, fresh={}, runtime_path_id=None, logical_path_id=None)
    doc=build_compiled_f4_build_join(**args,error='constructor failed')
    assert doc['execution_binding_sha256'] is None
    assert doc['built_executable_receipts']=={} and doc['status']=='refused'
    verify_compiled_f4_build_join(doc, **{k:args[k] for k in ('artifacts','execution_binding','original','fresh')})


def saved_material(admitted):
    args=issue(admitted); doc=build_compiled_f4_build_join(**args)
    binding=args['execution_binding'].document()
    harness=dict(components=[dict(instance_id=c,artifact_digest=d) for c,d in doc['artifact_digests'].items()])
    prefix=dict(execution_binding=binding, execution_binding_sha256=binding['binding_sha256'],artifact_digests=deepcopy(doc['artifact_digests']))
    manifest=dict(runner=dict(sessions={c:dict(identity=dict(built_executable_receipt=deepcopy(r),build_identity=deepcopy(r['build_identity']),runtime_artifact=deepcopy(args['artifacts'][c].runtime_document))) for c,r in doc['built_executable_receipts'].items()}),checker=dict(config=dict(execution_binding=deepcopy(binding),execution_binding_sha256=binding['binding_sha256'])))
    replay=dict(original_execution_audit=deepcopy(doc['original']['execution_audit']), execution_audit=deepcopy(doc['fresh']['execution_audit']))
    return doc,harness,manifest,prefix,replay


def test_saved_external_material(admitted):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


@pytest.mark.parametrize('mutation',['duplicate','artifact','missing','receipt_swap','identity','checker','prefix_digest','prefix_binding','partial','bool'])
def test_saved_external_material_refuses(admitted,mutation):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    if mutation=='duplicate': harness['components'].append(deepcopy(harness['components'][0]))
    elif mutation=='artifact': harness['components'][0]['artifact_digest']='b'*64
    elif mutation=='missing': del manifest['runner']['sessions']['processor']['identity']['build_identity']
    elif mutation=='receipt_swap':
        sessions=manifest['runner']['sessions']; sessions['processor']['identity']['built_executable_receipt']=sessions['peripheral']['identity']['built_executable_receipt']
    elif mutation=='identity': manifest['runner']['sessions']['processor']['identity']['build_identity']['workers']=True
    elif mutation=='checker': manifest['checker']['config']['execution_binding']['cpu']['instance_id']='other'
    elif mutation=='prefix_digest': prefix['execution_binding_sha256']='b'*64
    elif mutation=='prefix_binding':
        prefix['execution_binding']['built_executable_receipts']['processor']['binary_sha256']='b'*64
        prefix['execution_binding']['built_executable_receipts_sha256']=_digest(prefix['execution_binding']['built_executable_receipts'])
        prefix['execution_binding']=CompiledF4ExecutionBinding.build(prefix['execution_binding']).document()
        prefix['execution_binding_sha256']=prefix['execution_binding']['binding_sha256']
    elif mutation=='partial': doc['status']='refused'
    else: harness['components'][0]['artifact_digest']=True
    with pytest.raises(ValueError): verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


@pytest.mark.parametrize('part',['prefix_binding','manifest_runner','harness_components','session_identity','fresh_receipts'])
def test_saved_material_malformed_shapes_refuse(admitted,part):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    if part=='prefix_binding': prefix['execution_binding']=None
    elif part=='manifest_runner': manifest['runner']=[]
    elif part=='harness_components': harness['components']={}
    elif part=='session_identity': manifest['runner']['sessions']['processor']['identity']=False
    else: del doc['fresh']['receipts']
    with pytest.raises(ValueError): verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


def test_coherent_process_swap_disagrees_with_external_replay(admitted):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    doc['fresh']['execution_audit']['identities']['processor'].update(pid=9999,execution_nonce='replacement')
    with pytest.raises(ValueError):
        verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


def test_external_replay_ignores_diagnostic_process_extras(admitted):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    doc['fresh']['execution_audit']['identities']['processor']['argv']=['/cache/harness']
    doc['fresh']['execution_audit']['exits']['processor']['aborted']=False
    verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


@pytest.mark.parametrize('mutation', ['missing', 'swapped', 'digest', 'modified_body', 'rehashed_body', 'instance'])
def test_manifest_runtime_artifact_association_refuses(admitted,mutation):
    from myfuzz.integration.compiled_f4_build_join import verify_compiled_f4_build_material
    from myfuzz.local_harness.renderer import _sha
    doc,harness,manifest,prefix,replay=saved_material(admitted)
    identity=manifest['runner']['sessions']['processor']['identity']
    artifact=identity['runtime_artifact']
    if mutation=='missing': del identity['runtime_artifact']
    elif mutation=='swapped': identity['runtime_artifact']=manifest['runner']['sessions']['peripheral']['identity']['runtime_artifact']
    elif mutation=='digest': artifact['artifact_digest']='b'*64
    elif mutation=='instance': artifact['plan']['instance_id']='other'
    else:
        artifact['status']='tampered'
        if mutation=='rehashed_body':
            artifact['artifact_digest']=_sha({k:v for k,v in artifact.items() if k!='artifact_digest'})
    with pytest.raises(ValueError):
        verify_compiled_f4_build_material(doc,harness_set=harness,manifest=manifest,prefix=prefix,replay=replay)


@pytest.mark.parametrize('side',['original','fresh'])
def test_complete_join_rejects_retained_but_unavailable_snapshot(admitted,side):
    args=issue(admitted)
    args[side]['unavailable']={'processor':{'receipt':'pin removed'}}
    with pytest.raises(ValueError,match='snapshot-unavailable'):
        build_compiled_f4_build_join(**args)
    refused=build_compiled_f4_build_join(**args,error='pin removed')
    assert refused['status']=='refused' and refused[side]['unavailable']


@pytest.mark.parametrize('unavailable',[None,False,0,[],{'snapshot':'refused'}])
def test_complete_join_rejects_malformed_unavailable_markers(admitted,unavailable):
    args=issue(admitted)
    args['original']['unavailable']=unavailable
    with pytest.raises(ValueError,match='snapshot-unavailable'):
        build_compiled_f4_build_join(**args)
