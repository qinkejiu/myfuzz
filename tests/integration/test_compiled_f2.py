"""F2 runtime admission and descriptive identities; no native gate here."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch
import pytest
from tests.integration.test_compiled_f4_storage_producer import timer_loaded
ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture(scope='module')
def generated(tmp_path_factory):return timer_loaded(tmp_path_factory.mktemp('f2-runtime'))

def test_pure_f2_execution_binding_is_distinct_and_detached(generated):
    from myfuzz.integration.compiled_f2 import admit_f2,derive_f2_execution_binding,CompiledF2ExecutionBinding
    artifacts,inputs=generated
    with patch('subprocess.Popen',side_effect=AssertionError('native forbidden')):
        row=admit_f2(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
        binding=derive_f2_execution_binding(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    document=binding.document()
    assert row['flow_id']=='F2'
    assert document['schema_version']=='compiled_F2_execution_binding.v1'
    assert document['runtime_path_admission']['schema_version']=='compiled_F2_runtime_path_admission.v1'
    assert document['producer_binding']['register']['operation']=='read'
    assert document['candidate_layout']['byte_length']==4
    assert len(document['runtime_path_admission']['runtime_path_identity']['edges'])==3
    document['target'].clear();assert binding.document()['target']
    with pytest.raises(FrozenInstanceError):binding.document_json='x'
    from myfuzz.integration.compiled_f4 import derive_f4_execution_binding
    f4=derive_f4_execution_binding(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    with pytest.raises(ValueError):CompiledF2ExecutionBinding(f4.document_json)

@pytest.mark.parametrize('field',['sources','assertions','seed','bound_inputs','prerequisites','constraints','execution_contract'])
def test_forged_f2_refuses_before_native(generated,field):
    from myfuzz.integration.compiled_f2 import CompiledF2Runtime
    artifacts,inputs=generated;compiled=deepcopy(inputs['compiled'])
    row=next(p for p in compiled['paths'] if p['flow_id']=='F2');row[field]=None
    with patch('subprocess.Popen',side_effect=AssertionError('native forbidden')):
        with pytest.raises(ValueError):CompiledF2Runtime(artifacts=artifacts,compiled_inputs={**inputs,'compiled':compiled},base_dir=ROOT,cache_dir=ROOT/'.unused')

def test_private_f2_snapshot_is_reconstructed_and_detached(generated):
    from myfuzz.integration.compiled_f2 import _private_admission_snapshot,admit_f2
    from myfuzz.integration.compiled_f4 import _input_identity
    artifacts,inputs=generated
    private_artifacts,private_inputs=_private_admission_snapshot(artifacts,inputs,ROOT)
    assert _input_identity(private_inputs,private_artifacts)==_input_identity(inputs,artifacts)
    assert private_inputs['request'] is not inputs['request']
    assert private_artifacts['processor'] is not artifacts['processor']
    assert admit_f2(artifacts=private_artifacts,compiled_inputs=private_inputs,base_dir=ROOT)['flow_id']=='F2'
