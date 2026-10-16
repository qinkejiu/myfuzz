"""Closed preflight admits real compiler READ shapes, without execution grants."""
from copy import deepcopy
import pytest
from tests.scenario.test_register_program_runtime import factory,installed
from myfuzz.scenario.register_program_capabilities import validate_register_capability_preflight_document


def test_actual_narrow_read_preflight_passes_closed_saved_validation(factory):
    runtime,_,_=installed(factory,max_program_bytes=36)
    doc=runtime.capability_preflight()
    reads=[c for c in doc['targets']['gpio_a']['operation_conditions'] if c['operation']=='register_read']
    assert any(c['scope']=='PADCFG_0.pin7' and c['program_bytes']==24 for c in reads)
    assert validate_register_capability_preflight_document(doc,configuration=runtime.configuration())==doc
    assert doc['verification'] is None and doc['grants_functional'] is False


@pytest.mark.parametrize('length',[True,0,17,18,36,40])
def test_saved_read_length_outside_closed_compiler_shapes_refuses(factory,length):
    runtime,_,_=installed(factory,max_program_bytes=36)
    doc=deepcopy(runtime.capability_preflight())
    c=next(c for c in doc['targets']['gpio_a']['operation_conditions'] if c['operation']=='register_read')
    c['program_bytes']=length
    with pytest.raises(ValueError,match='invalid-register-capability'):
        validate_register_capability_preflight_document(doc,configuration=runtime.configuration())


def test_allowed_read_shape_cannot_exceed_actual_configuration_budget(factory):
    runtime,_,_=installed(factory,max_program_bytes=16)
    doc=runtime.capability_preflight()
    c=next(c for c in doc['targets']['gpio_a']['operation_conditions'] if c['operation']=='register_read')
    assert c['program_bytes']==16
    c['program_bytes']=20
    with pytest.raises(ValueError,match='invalid-register-capability'):
        validate_register_capability_preflight_document(doc,configuration=runtime.configuration())


def test_read_shape_cannot_claim_read_modify_write(factory):
    runtime,_,_=installed(factory,max_program_bytes=36)
    doc=runtime.capability_preflight()
    c=next(c for c in doc['targets']['gpio_a']['operation_conditions'] if c['operation']=='register_read')
    c['read_modify_write']=True
    with pytest.raises(ValueError,match='invalid-register-capability'):
        validate_register_capability_preflight_document(doc,configuration=runtime.configuration())
