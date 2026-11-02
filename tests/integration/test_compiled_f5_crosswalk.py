"""F5 crosswalk binds the compiled physical plan to actual local sessions."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.scenario.compiled_paths import PathCompileRequest, PathComponent, compile_paths, load_path_wiring
from myfuzz.scenario.ibex_pulp_dual_source import (
    _artifact, CPU_PROFILE, CAUSAL_GPIO_PROFILE, make_pulp_dual_source_factory,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    import json
    artifacts = {name: _artifact(path, name) for name, path in (
        ('cpu', CPU_PROFILE), ('gpio_a', CAUSAL_GPIO_PROFILE), ('gpio_b', CAUSAL_GPIO_PROFILE))}
    cap = load_ip_test_capability(json.loads((ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json').read_text()),
                                  profile=artifacts['gpio_b'].plan.profile)
    cpu = PathComponent('cpu', artifacts['cpu'].plan.profile)
    a = PathComponent('gpio_a', artifacts['gpio_a'].plan.profile, cap)
    b = PathComponent('gpio_b', artifacts['gpio_b'].plan.profile, cap)
    wiring = load_path_wiring({'schema_version': 'path_wiring.v1',
        'cpu': {'instance_id':'cpu','data_endpoint':'processor.data'},
        'windows': [dict(device_id=n, target_instance=n, endpoint_id='gpio.bus',base=base,size=4096)
                    for n,base in [('gpio_a',0x40001000),('gpio_b',0x40000000)]],
        'resources':[dict(resource_id='ram',component_instance='cpu',base=0x10000,size=0x30000,
                          read=True,write=True,execute=True,initialization_policy='preload')],
        'deliveries':[dict(delivery_id='gpio_b_irq',producer_instance='gpio_b',producer_endpoint_id='gpio.interrupts',
                           producer_signal='interrupt',consumer_instance='cpu',consumer_endpoint_id='processor.interrupts',trigger='pulse')],
        'environment_links':[dict(link_id='gpio_b_pin8',component_instance='gpio_b',endpoint_id='gpio.pins',bit_offset=8,width=1,event_kind='pin_value')],
        'fixed_inputs':[dict(component_instance=c,port='gpio_in',bit_offset=lo,width=w,constant=0)
                        for c,lo,w in [('gpio_a',0,32),('gpio_b',0,8),('gpio_b',9,23)]]})
    request = PathCompileRequest(cpu, (a,b), wiring, {}, 'processor.data', 'processor.instruction')
    compiled = compile_paths(request)
    path = next(row for row in compiled['paths'] if row['flow_id']=='F5')
    source = next(row for row in path['sources'] if row['kind']=='external_pin')
    producer = next(row for row in path['bound_inputs'] if row['kind']=='ip_irq')
    ownership = compile_ownership((InputField('cpu','irq_external_i',1), InputField('gpio_a','gpio_in',32), InputField('gpio_b','gpio_in',32)),
        (InputOwner('cpu','irq_external_i',0,1,'bound',producer['input_id']),
         InputOwner('gpio_a','gpio_in',0,32,'fixed','constant_zero'),
         InputOwner('gpio_b','gpio_in',0,8,'fixed','constant_zero'),
         InputOwner('gpio_b','gpio_in',8,1,'source',source['source_id']),
         InputOwner('gpio_b','gpio_in',9,23,'fixed','constant_zero')))
    inputs = dict(request=request,compiled=compiled,ownership=ownership,
        physical_port_map={('cpu','irq_external_i'):'irq_external_i',('gpio_a','gpio_in'):'gpio_in',('gpio_b','gpio_in'):'gpio_in'})
    factory = make_pulp_dual_source_factory(tmp_path_factory.mktemp('f5-crosswalk-cache'), cpu_profile=CPU_PROFILE,
                    gpio_consumption=True, generated_artifacts=artifacts, f5_only=True)
    return artifacts, inputs, factory


def _validate(actual, runner=None, inputs=None, artifacts=None):
    from myfuzz.integration.compiled_f5_crosswalk import validate_compiled_f5_crosswalk
    a, i, factory = actual
    return validate_compiled_f5_crosswalk(artifacts=a if artifacts is None else artifacts,
                                          compiled_inputs=i if inputs is None else inputs,
                                          runner=factory() if runner is None else runner)


def test_actual_compiled_gpio_and_runner_are_bound(actual):
    evidence = _validate(actual)
    assert evidence['status'] == 'compatible'
    assert evidence['pulse_width_cpu_ticks'] == 4
    assert evidence['source']['physical_bit_offset'] == 8
    assert evidence['source']['compiled_source_id'] != evidence['source']['runtime_owner']
    assert evidence['runtime_enforcement'] == 'topology_only'


def test_rejects_modified_compiled_physical_endpoint(actual):
    inputs = dict(actual[1]); inputs['compiled'] = deepcopy(inputs['compiled'])
    node = next(row for row in inputs['compiled']['runtime_path_contract']['nodes'] if row['node_id']=='F5.ip_irq')
    node['port'] = 'gpio_out'
    with pytest.raises(ValueError): _validate(actual, inputs=inputs)


def test_rejects_modified_compiled_bit_range(actual):
    inputs = dict(actual[1]); inputs['compiled'] = deepcopy(inputs['compiled'])
    node = next(row for row in inputs['compiled']['runtime_path_contract']['nodes'] if row['node_id']=='F5.pin_event')
    node['bit_offset'] = 9
    with pytest.raises(ValueError): _validate(actual, inputs=inputs)


def test_rejects_wrong_actual_pulse_width(actual):
    runner = actual[2]()
    next(iter(runner._irq_pulses.values())).width_ticks = 5
    with pytest.raises(ValueError): _validate(actual, runner=runner)


def test_rejects_wrong_actual_logical_endpoint(actual):
    runner = actual[2]()
    runner.bindings = (Binding('gpio_b','gpio_out','cpu','irq',1),)
    with pytest.raises(ValueError): _validate(actual, runner=runner)


def test_rejects_swapped_actual_session_artifact(actual):
    runner = actual[2]()
    runner.sessions['gpio_b'].artifact = actual[0]['gpio_a']
    with pytest.raises(ValueError): _validate(actual, runner=runner)


def test_rejects_altered_actual_export(actual):
    artifacts = dict(actual[0]); original = artifacts['gpio_b']
    doc = deepcopy(original.runtime_document)
    next(row for row in doc['physical_exports'] if row['physical_port']=='interrupt')['direction'] = 'input'
    artifacts['gpio_b'] = replace(original, runtime_document=doc)
    runner = actual[2](); runner.sessions['gpio_b'].artifact = artifacts['gpio_b']
    with pytest.raises(ValueError): _validate(actual, runner=runner, artifacts=artifacts)


def test_fixed_input_declaration_is_not_just_a_runner_claim(actual):
    inputs = dict(actual[1]); request = inputs['request']
    fixed = list(request.wiring.fixed_inputs)
    fixed[0] = replace(fixed[0], constant=1)
    request = replace(request, wiring=replace(request.wiring, fixed_inputs=tuple(fixed)))
    inputs['request'] = request; inputs['compiled'] = compile_paths(request)
    with pytest.raises(ValueError): _validate(actual, inputs=inputs)


def test_fresh_runner_produces_the_same_topology_identity(actual):
    assert _validate(actual) == _validate(actual)


def test_document_cannot_mutate_preparation_graph(actual):
    evidence = _validate(actual)
    evidence['path_identity']['source_ids'].clear()
    assert _validate(actual)['path_identity']['source_ids'] == ['F5.pin_event']


def test_real_production_preparation_crosswalk(tmp_path):
    from myfuzz.runtime.preparation import create_preparation
    config = ROOT / 'configs/scenarios/compiled-f5-ibex-pulp-gpio'
    context = create_preparation(base_dir=ROOT, compose_path=config/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json', generated_dir=tmp_path/'generated', flow_ids=('F5',))
    try:
        factory = make_pulp_dual_source_factory(tmp_path/'cache', cpu_profile=CPU_PROFILE,
            gpio_consumption=True, generated_artifacts=context.artifacts, f5_only=True)
        result = _validate((context.artifacts, context.compiled_inputs(), factory))
        assert result['status'] == 'compatible'
    finally:
        context.close()
