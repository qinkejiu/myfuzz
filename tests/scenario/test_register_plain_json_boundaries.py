"""Strict JSON shape checking must not coerce values or reject shared aliases."""
import pytest
from myfuzz.scenario.session_runtime import _register_plain_json


class Integer(int):
    pass


class Text(str):
    pass


class Sequence(list):
    pass


class Mapping(dict):
    pass


@pytest.mark.parametrize('value',[None,True,False,0,-1,2**100,'text',[],{},
    {'values':[None,True,False,1,'text']}])
def test_exact_json_types_are_accepted_without_coercion(value):
    assert _register_plain_json(value) is True


@pytest.mark.parametrize('value',[0.0,float('nan'),float('inf'),Integer(1),Text('text'),
    Sequence([1]),Mapping(a=1),(1,),{1:'integer key'},{True:'boolean key'},
    {Text('text'):'subclass key'},b'bytes',object()])
def test_non_json_and_subclass_types_are_rejected(value):
    assert _register_plain_json(value) is False


def test_shared_containers_are_legal_and_not_cycles():
    child={'bits':[True,1,False]}
    assert _register_plain_json({'left':child,'right':child,'also':[child,child]}) is True


@pytest.mark.parametrize('kind',['list','dict','mutual'])
def test_cyclic_containers_fail_closed_without_recursion_error(kind):
    if kind=='list':
        value=[];value.append(value)
    elif kind=='dict':
        value={};value['self']=value
    else:
        value=[];child={'parent':value};value.append(child)
    assert _register_plain_json(value) is False


class EqualToScalar(type):
    def __eq__(cls,other):
        return other is int or other is str
    __hash__=type.__hash__


class ForgedScalar(metaclass=EqualToScalar):
    pass


@pytest.mark.parametrize('shape',['root','pair_leaf','long_leaf','dict_leaf'])
def test_metaclass_equality_cannot_forge_exact_scalar_type(shape):
    value=ForgedScalar()
    document={'root':value,'pair_leaf':{'leaf':[0,value]},
        'long_leaf':{'leaf':[0,1,value]},'dict_leaf':{'leaf':{'value':value}}}[shape]
    assert _register_plain_json(document) is False
