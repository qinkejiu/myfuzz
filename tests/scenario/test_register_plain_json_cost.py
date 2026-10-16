"""Exact JSON validation traverses actual byte slots without recursive scalar calls."""
import sys
import pytest
from myfuzz.scenario.session_runtime import _register_plain_json
from tests.scenario.test_register_program_replay import actual_factory
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.genome import ScenarioGenome


def test_actual_byte_slot_traversal_has_no_recursive_function_dispatch(actual_factory):
    result=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    result.declare_instruction_slots('cpu',0x11000,31616)
    slots=[[name,offset] for name,offset in result.runner.sessions['cpu'].memory._instruction_slots]
    assert len(slots)==126464
    calls=[];code=_register_plain_json.__code__
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:calls.append(1)
    previous=sys.getprofile()
    try:
        sys.setprofile(profile);assert _register_plain_json({'slots':slots})
    finally:sys.setprofile(previous)
    assert len(calls)==1


class Integer(int):pass
class Text(str):pass
class Array(list):pass
class Object(dict):pass


@pytest.mark.parametrize('value',[1.0,float('nan'),Integer(1),Text('x'),Array([1]),Object(x=1),
    {1:'x'},{Text('x'):1},[object()],{'a':[{'b':object()}]},(1,2)])
def test_foreign_types_remain_rejected(value):assert _register_plain_json(value) is False


def test_shared_container_is_legal_but_cycles_are_rejected():
    shared={'x':[None,True,False,0,'']}
    assert _register_plain_json({'a':shared,'b':[shared]})
    cyclic=[];cyclic.append(cyclic)
    try:result=_register_plain_json(cyclic)
    except RecursionError:pytest.fail('cycle escaped bounded validation')
    assert result is False
    indirect={'x':[]};indirect['x'].append(indirect)
    assert _register_plain_json(indirect) is False


def test_scalar_byte_slot_pairs_do_not_allocate_container_frames(monkeypatch):
    import builtins
    import myfuzz.scenario.session_runtime as module
    slots=[['ram',offset] for offset in range(4096,130560)]
    calls=[]
    def tracked_iter(value):
        calls.append(1);return builtins.iter(value)
    monkeypatch.setattr(module,'iter',tracked_iter,raising=False)
    assert module._register_plain_json({'slots':slots})
    assert len(calls)<=2,'scalar-only slot pairs allocated traversal frames'


@pytest.mark.parametrize('nested',[False,True])
def test_foreign_metaclass_equality_cannot_impersonate_scalar_types(nested):
    class Equality(type):
        def __eq__(self,other):return True
    class Foreign(metaclass=Equality):pass
    value=Foreign()
    assert _register_plain_json([['ram',value]] if nested else value) is False
