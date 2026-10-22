from copy import deepcopy
import pytest
from tests.scenario.test_f2_read_contract import inputs, f2

def test_admission_preserves_f2_three_edges_and_detaches_cache(inputs):
    from myfuzz.integration.compiled_f2_runtime_path import admit_compiled_f2_runtime_path
    result=admit_compiled_f2_runtime_path(request=inputs['request'],compiled=inputs['compiled'])
    assert result.document()['schema_version']=='compiled_F2_runtime_path_admission.v1'
    assert len(result.document()['runtime_path_identity']['edges'])==3
    result.validate_cached_identity()
    detached=result.document();detached['selected_path'].clear();result.validate_cached_identity()

@pytest.mark.parametrize('mutation',['marker','source','graph','contract','prerequisite','edges'])
def test_admission_refuses_changed_document(inputs,mutation):
    from myfuzz.integration.compiled_f2_runtime_path import admit_compiled_f2_runtime_path
    compiled=deepcopy(inputs['compiled']);row=f2({'compiled':compiled})
    if mutation=='marker':row.pop('execution_contract')
    elif mutation=='source':row['sources'][-1]['component']='other'
    elif mutation=='graph':compiled['runtime_dependency_graph']['sources'][0]['component']='other'
    elif mutation=='contract':compiled['runtime_path_contract']['graph_sha256']='0'*64
    elif mutation=='prerequisite':row['prerequisites'][0]['kind']='ram_byte_version'
    else:row['runtime_path_identity']['edges'].reverse()
    with pytest.raises(ValueError):admit_compiled_f2_runtime_path(request=inputs['request'],compiled=compiled)

def test_source_backed_spi_recompile_marker_and_full_admission(tmp_path):
    from unittest.mock import patch
    from tests.integration import test_compiled_f4_storage_producer as fixture
    from myfuzz.scenario.compiled_paths import compile_paths, compiled_document_sha256
    from myfuzz.scenario.f2_read_contract import validate_f2_read_contract
    from myfuzz.integration.compiled_f2_runtime_path import admit_compiled_f2_runtime_path
    config=fixture.ROOT/'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p'
    with patch.object(fixture,'TIMER_CONFIG',config):
        _,generated=fixture.timer_loaded(tmp_path)
    assert compile_paths(generated['request'])==generated['compiled']
    row=f2(generated);marker=validate_f2_read_contract(row)
    assert marker['target_component']==generated['request'].devices[0].instance_id
    assert marker['source_component']==generated['request'].cpu.instance_id
    admitted=admit_compiled_f2_runtime_path(request=generated['request'],compiled=generated['compiled'],path=row)
    assert admitted.document()['execution_contract']==marker
    assert admitted.document()['compiled_document_sha256']==compiled_document_sha256(generated['compiled'])
    assert len(admitted.document()['runtime_path_identity']['edges'])==3
    admitted.validate_cached_identity()
