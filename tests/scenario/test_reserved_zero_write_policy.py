"""A declared full-word zero-outside-mask write is not a guessed RMW."""
from dataclasses import replace
import pytest
from tests.scenario.test_register_source_access import inputs
from myfuzz.scenario.compiled_paths import compile_paths
from myfuzz.scenario.register_source_access import validate_register_candidate

# The reviewed ZipCPU UART SETUP word: bits [30:0] store, bit 31 reads back 0,
# and a write resets UART state.  The policy and the side effect are declared
# separately; neither substitutes for the other.
UART_MASK = 0x7fffffff
UART_SIDE_EFFECT = 'write_resets_uart_state'


def candidate(policy='full_word_reserved_zero',value=1,be=15):
    request,_,_=inputs();device=request.devices[0]
    fields=tuple(replace(f,write_mask=7,read_mask=7,write_policy=policy) if f.register=='GPIOEN' else f
        for f in device.capability.register_semantics)
    request=replace(request,devices=(replace(device,capability=replace(device.capability,register_semantics=fields)),*request.devices[1:]))
    compiled=compile_paths(request)
    source=next(s for p in compiled['paths'] if p['flow_id']=='F4' for s in p['sources'] if s['kind']=='cpu_mmio_stream')
    access=source['register_access']
    return validate_register_candidate(request,compiled,source_id=source['source_id'],source_component=source['component'],
        source_endpoint=source['endpoint_id'],target_component=access['target_component'],address=access['address'],
        write=True,value=value,byte_enable=be)


def test_declared_full_word_zero_policy_preserves_value_without_merge():
    result=candidate(value=5)
    assert result['value']==5 and result['byte_enable']==15 and result['runtime_admitted'] is False


@pytest.mark.parametrize('policy,value,be,reason',[
    (None,1,15,'masked-merge-policy-undeclared'),
    ('read-modify-write',1,15,'masked-merge-policy-undeclared'),
    ('full_word_reserved_zero',8,15,'reserved-value-bits'),
    ('full_word_reserved_zero',1,1,'partial-access')])
def test_missing_policy_reserved_value_and_partial_byte_enable_remain_refused(policy,value,be,reason):
    with pytest.raises(ValueError,match=reason):candidate(policy,value,be)


def side_effectful(policy='full_word_reserved_zero',side_effect=UART_SIDE_EFFECT):
    """The same masked field, now with a real declared write side effect.

    Every other declared writable field is zero-masked so the compiler selects
    this one, exactly as it selects a side-effect-free field when one exists.
    """
    request,_,_=inputs();device=request.devices[0]
    profile=replace(device.profile,address=replace(device.profile.address,
        registers=tuple(replace(r,side_effect=side_effect) if r.name=='GPIOEN' else r
                        for r in device.profile.address.registers)))
    fields=tuple(replace(f,write_mask=UART_MASK,read_mask=UART_MASK,write_policy=policy,
                         side_effect=side_effect) if f.register=='GPIOEN' else replace(f,write_mask=0)
                 for f in device.capability.register_semantics)
    device=replace(device,profile=profile,
        capability=replace(device.capability,register_semantics=fields))
    request=replace(request,devices=(device,*request.devices[1:]))
    compiled=compile_paths(request)
    source=next(s for p in compiled['paths'] if p['flow_id']=='F4'
                for s in p['sources'] if s['kind']=='cpu_mmio_stream')
    access=source['register_access']
    assert access['value_mask']==UART_MASK
    options=dict(source_id=source['source_id'],source_component=source['component'],
        source_endpoint=source['endpoint_id'],target_component=access['target_component'],
        address=access['address'],write=True,byte_enable=15)
    return request,compiled,options


def test_real_masked_register_with_write_side_effect_accepts_a_legal_word():
    request,compiled,options=side_effectful()
    result=validate_register_candidate(request,compiled,value=0x55,**options)
    assert result['value']==0x55 and result['byte_enable']==15
    assert result['runtime_admitted'] is False
    assert result['access']['value_mask']==UART_MASK


def test_real_masked_register_keeps_refusing_reserved_value_bits():
    request,compiled,options=side_effectful()
    with pytest.raises(ValueError,match='register-candidate-reserved-value-bits'):
        validate_register_candidate(request,compiled,value=0x80000000,**options)


def test_masked_write_side_effect_must_match_the_profile_declaration():
    request,compiled,options=side_effectful()
    device=request.devices[0]
    fields=tuple(replace(f,side_effect='none') if f.register=='GPIOEN' else f
                 for f in device.capability.register_semantics)
    request=replace(request,devices=(replace(device,capability=replace(
        device.capability,register_semantics=fields)),*request.devices[1:]))
    with pytest.raises(ValueError,match='register-candidate-masked-write-side-effect-mismatch'):
        validate_register_candidate(request,compiled,value=0x55,**options)
