"""Pure factory wiring controls using the real ScenarioRunner validator.

Only native/artifact endpoints are replaced; no hardware session is constructed.
"""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import pytest


def assembled(monkeypatch,tmp_path):
    from myfuzz.scenario import boom_gpio_irq_runner as factory
    for name in ('Popen','run','check_output'):
        monkeypatch.setattr(subprocess,name,lambda *a,**kw:pytest.fail('tool/model reached pure factory control'))
    ended=[]
    monkeypatch.setattr(factory,'_gpio_artifact',lambda repo:object())
    gpio=SimpleNamespace(end_case=lambda:ended.append('gpio'))
    monkeypatch.setattr(factory,'GeneratedPulpGpioSession',lambda *a,**kw:gpio)
    def cpu_endpoint(*a,**kw):
        return SimpleNamespace(router=kw['router'],program=kw['program'],
            observed_ram_addresses=kw['observed_ram_addresses'],end_case=lambda:ended.append('cpu'))
    monkeypatch.setattr(factory,'GeneratedBoomIrqScenarioSession',cpu_endpoint)
    return factory.make_boom_gpio_irq_runner(repo=tmp_path,cpu_output=tmp_path/'artifact',cache_dir=tmp_path/'cache'),ended


def test_factory_passes_actual_runner_binding_and_router_validation(monkeypatch,tmp_path):
    from myfuzz.scenario.runner import ScenarioRunner,Binding
    runner,ended=assembled(monkeypatch,tmp_path)
    assert type(runner) is ScenarioRunner
    binding=Binding('gpio','irq','cpu','irq',1)
    assert runner.bindings==(binding,)
    assert runner.ownership.binding_producer('cpu','irq',0,1)=='gpio.irq'
    assert runner._irq_pulses[binding].width_ticks==64
    assert runner.sessions['cpu'].router.windows[0].target is runner.sessions['gpio']
    assert runner.sessions['cpu'].router.windows[0].base==0x4000
    assert ended==[]


def test_factory_ownership_has_one_pin_source_and_exclusive_irq_binding(monkeypatch,tmp_path):
    runner,_=assembled(monkeypatch,tmp_path)
    owner=runner.ownership
    assert owner.mutation_source('gpio','gpio_in',0,1,direction='IP_TO_CPU')=='external_pin'
    for args in [('gpio','gpio_in',1,31),('cpu','irq',0,1)]:
        with pytest.raises(ValueError):owner.mutation_source(*args,direction='IP_TO_CPU')
    document=owner.document()
    assert {row['component_id'] for row in document['fields']}=={'cpu','gpio'}
    assert len(document['owners'])==3


def test_actual_runner_still_refuses_wrong_producer_ref():
    from myfuzz.scenario.runner import ScenarioRunner,Binding
    from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
    ownership=compile_ownership((InputField('cpu','irq',1),),(InputOwner('cpu','irq',0,1,'bound','gpio_irq'),))
    with pytest.raises(ValueError,match='binding producer'):
        ScenarioRunner(sessions={'cpu':SimpleNamespace(),'gpio':SimpleNamespace()},ownership=ownership,
            bindings=(Binding('gpio','irq','cpu','irq',1),))
