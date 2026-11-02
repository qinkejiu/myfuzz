"""Typed F2/F4 build evidence separation on real admitted artifact fixtures."""
from copy import deepcopy
from hashlib import sha256
import importlib
import importlib.util
import json
import pytest
from tests.integration.test_compiled_f4_build_join import admitted, issue, saved_material


def module():
    name='myfuzz.integration.compiled_f2_build_join'
    assert importlib.util.find_spec(name) is not None, 'F2 build join is not installed'
    return importlib.import_module(name)


def f2_args(admitted):
    args=issue(admitted)
    binding=args['execution_binding'].document()
    binding.update(schema_version='compiled_F2_execution_binding.v1',path_id='F2:ram.image')
    binding.pop('binding_sha256')
    binding['binding_sha256']=sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    args.update(execution_binding=binding,logical_path_id=binding['path_id'])
    return args


def test_complete_f2_document_keeps_actual_build_associations(admitted):
    mod=module();args=f2_args(admitted)
    doc=mod.build_compiled_f2_build_join(**args)
    assert doc['status']=='complete' and doc['schema_version']=='compiled_F2_build_join.v1'
    mod.verify_compiled_f2_build_join(doc,**{k:args[k] for k in ('artifacts','execution_binding','original','fresh')})
    assert doc['built_executable_receipts']==args['original']['receipts']


def test_cross_flow_schema_never_accepted(admitted):
    from myfuzz.integration.compiled_f4_build_join import build_compiled_f4_build_join
    mod=module()
    with pytest.raises(ValueError):mod.build_compiled_f2_build_join(**issue(admitted))
    with pytest.raises(ValueError):build_compiled_f4_build_join(**f2_args(admitted))


def test_f2_join_rejects_coherent_saved_rewrite(admitted):
    mod=module();args=f2_args(admitted);doc=mod.build_compiled_f2_build_join(**args)
    doc['original']['execution_audit']['identities']['processor']['pid']+=1
    with pytest.raises(ValueError):mod.verify_compiled_f2_build_join(doc,**{k:args[k] for k in ('artifacts','execution_binding','original','fresh')})


def test_refused_f2_retains_partial_without_authority(admitted):
    args=f2_args(admitted);args.update(execution_binding=None,original={},fresh={},runtime_path_id=None,logical_path_id=None)
    doc=module().build_compiled_f2_build_join(**args,error='construction refused')
    assert doc['status']=='refused' and doc['execution_binding_sha256'] is None


def test_refusal_with_f2_binding_preserves_observed_receipts(admitted):
    args=f2_args(admitted)
    expected_receipts=deepcopy(args['execution_binding']['built_executable_receipts'])
    args['fresh']={'unavailable': {'peripheral': {'startup': 'not reached'}}}
    mod=module()
    doc=mod.build_compiled_f2_build_join(**args,error='fresh startup failed')
    assert doc['status']=='refused'
    assert doc['built_executable_receipts']==expected_receipts
    assert doc['fresh']==args['fresh']
    mod.verify_compiled_f2_build_join(doc, **{k:args[k] for k in (
        'artifacts','execution_binding','original','fresh')})
