"""Hot guards preserve exact memory authority without copying byte-slot documents."""
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory,adapter
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.genome import ScenarioGenome


def installed(factory):
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),factory())
    session.declare_instruction_slots('cpu',0x11000,31616)
    return adapter(session)


def test_hot_validation_never_serializes_full_byte_slot_configuration(actual_factory,monkeypatch):
    import myfuzz.scenario.register_program_runtime as module
    runtime=installed(actual_factory)
    before=runtime.configuration()
    assert len(before['memory']['instruction_slots'])==126464
    original=module._json
    def bounded(document):
        if type(document) is dict and type(document.get('memory')) is dict:
            assert 'instruction_slots' not in document['memory'],'hot guard copied byte-slot configuration'
        return original(document)
    monkeypatch.setattr(module,'_json',bounded)
    assert runtime.validate() is True
    assert runtime.configuration()==before


@pytest.mark.parametrize('mutation',['slot_pointer','same_count_slot','seed_bool','max_bytes',
    'regions','windows','identity_override'])
def test_memory_authority_drift_is_refused_without_materialization(actual_factory,mutation):
    runtime=installed(actual_factory)
    memory=runtime.runner.sessions['cpu'].memory
    before=dict(memory._bytes)
    if mutation=='slot_pointer':memory._instruction_slots=set(memory._instruction_slots)
    elif mutation=='same_count_slot':
        memory._instruction_slots.remove(('ram',4096));memory._instruction_slots.add(('ram',4095))
    elif mutation=='seed_bool':memory.initialization_seed=True
    elif mutation=='max_bytes':memory.max_initialized_bytes+=1
    elif mutation=='regions':memory._regions=tuple(reversed(memory._regions)) if len(memory._regions)>1 else (*memory._regions,memory._regions[0])
    elif mutation=='windows':memory._windows=list(reversed(memory._windows))+[memory._windows[0]]
    else:memory.identity_document=lambda:runtime.configuration()['memory']
    with pytest.raises(ValueError):runtime.validate()
    assert memory._bytes==before


@pytest.mark.parametrize('method',['validate_static_configuration','_static','_actual_objects',
    '_validate_memory_configuration'])
def test_runtime_guard_instance_dispatch_cannot_replace_actual_checks(actual_factory,method):
    runtime=installed(actual_factory)
    original=getattr(runtime,method)
    setattr(runtime,method,lambda *args,**kwargs:original(*args,**kwargs))
    with pytest.raises(ValueError):runtime.validate()
