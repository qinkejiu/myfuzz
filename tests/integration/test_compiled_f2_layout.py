"""F2 bytes carry an address, never the peripheral's read value."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import pytest
from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
from tests.integration.test_compiled_f4_storage_producer import timer_loaded

@pytest.fixture(scope="module")
def f2_inputs(tmp_path_factory):
    _, inputs = timer_loaded(tmp_path_factory.mktemp("f2-layout"))
    return inputs

@pytest.fixture
def f2_path(f2_inputs):
    return next(p for p in f2_inputs['compiled']['paths'] if p['flow_id']=='F2')

def test_exact_address_record_and_immutable_identity(f2_path):
    layout = compile_f2_candidate_layout(f2_path)
    address = f2_path['execution_contract']['address']
    assert layout.classify(address.to_bytes(4,'little')).accepted
    assert layout.classify(address.to_bytes(4,'little')).address == address
    for raw in (b'', bytes(8), (address+4).to_bytes(4,'little'), bytearray(4)):
        assert not layout.classify(raw).accepted
    assert layout.digest == compile_f2_candidate_layout(deepcopy(f2_path)).digest
    document=layout.document(); document['schema_version']='tampered'
    assert layout.document()['schema_version']!='tampered'
    with pytest.raises(FrozenInstanceError): layout.digest='tampered'

@pytest.mark.parametrize('mutate',[
    lambda p:p.pop('execution_contract'),
    lambda p:p.update(seed=1),
    lambda p:p['constraints'].update(unknown=True),
    lambda p:p['sources'][1].update(mask=1),
    lambda p:p['constraints']['source_constraints'].pop(),
])
def test_bad_declarations_refuse(f2_path,mutate):
    p=deepcopy(f2_path); mutate(p)
    with pytest.raises(ValueError):compile_f2_candidate_layout(p)

@pytest.mark.parametrize('key,value',[('operation','write'),('value_origin','cpu_transaction_wdata'),
    ('allowed_byte_enables',[1]),('value_mask',1),('access_alignment',1)])
def test_mirrored_read_access_changes_refuse(f2_path,key,value):
    p=deepcopy(f2_path)
    for row in (p['sources'][1],p['constraints']['source_constraints'][1]):
        row['register_access'][key]=value
    with pytest.raises(ValueError): compile_f2_candidate_layout(p)

def test_path_identity_and_address_are_separate_from_response(f2_path):
    p=deepcopy(f2_path); original=compile_f2_candidate_layout(p)
    p['sources'][0]['origin_ref']={'changed':'image-origin'}
    assert compile_f2_candidate_layout(p).digest != original.digest
    assert original.source_slices[0].width==32
    assert original.source_slices[0].minimum==f2_path['execution_contract']['address']
