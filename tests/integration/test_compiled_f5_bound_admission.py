"""F5 IRQ ownership is static artifact admission, not runtime proof."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
from myfuzz.runtime.preparation import create_preparation
from myfuzz.scenario.compiled_paths import compile_paths
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/compiled-f5-obi-tlul-uart'


@pytest.fixture(scope='module')
def f5_inputs(tmp_path_factory):
    context = create_preparation(base_dir=ROOT, compose_path=SCENARIO/'compose.json',
        capability_paths=(SCENARIO/'test_capability.json',),
        supplement_path=SCENARIO/'execution_supplement.json',
        generated_dir=tmp_path_factory.mktemp('f5-bound')/'generated', flow_ids=('F5',))
    try:
        inputs = context.compiled_inputs()
        yield context.artifacts, inputs['request'], inputs['compiled']
    finally:
        context.close()


def _admit(inputs, *, producer_ref=None, extra_bound=False, flow_ids=('F5',),
           artifacts=None, request=None, compiled=None, target_kind='bound'):
    original, original_request, original_compiled = inputs
    artifacts = original if artifacts is None else artifacts
    request = original_request if request is None else request
    compiled = original_compiled if compiled is None else compiled
    path = next(row for row in compiled['paths'] if row['flow_id']=='F5')
    source = next(row for row in path['sources'] if row['kind']=='external_pin')
    producer = next(row for row in path['bound_inputs'] if row['kind']=='ip_irq')
    fields = [InputField('peripheral','cio_rx_i',1), InputField('processor','irq_external_i',1)]
    owners = [InputOwner('peripheral','cio_rx_i',0,1,'source',source['source_id']),
        InputOwner('processor','irq_external_i',0,1,target_kind,
                   producer['input_id'] if producer_ref is None else producer_ref)]
    if extra_bound:
        fields[0] = InputField('peripheral','cio_rx_i',1)
        owners[0] = InputOwner('peripheral','cio_rx_i',0,1,'bound','other.output')
    ownership = compile_ownership(tuple(fields),tuple(owners))
    return admit_compiled_artifacts(artifacts=artifacts,request=request,compiled=compiled,
        ownership=ownership, physical_port_map={('peripheral','cio_rx_i'):'cio_rx_i',
            ('processor','irq_external_i'):'irq_external_i'},flow_ids=flow_ids)


def test_real_f5_irq_bound_admits_consistency_only(f5_inputs):
    result = _admit(f5_inputs)
    assert result['status']=='compatible', result['refusals']
    assert result['runtime_enforcement']=='not_admitted'


@pytest.mark.parametrize('producer_ref', ['peripheral.intr_rx_watermark_o',
    'foreign.uart.interrupts.irq', 'peripheral.uart.interrupts.other'])
def test_f5_irq_rejects_wrong_producer_identity(f5_inputs, producer_ref):
    result = _admit(f5_inputs,producer_ref=producer_ref)
    assert result['status']=='refused'


def test_unrelated_bound_input_stays_refused(f5_inputs):
    result = _admit(f5_inputs,extra_bound=True)
    assert result['status']=='refused'
    assert any(row['code']=='ownership-bound-producer-not-admitted' for row in result['refusals'])


@pytest.mark.parametrize('kind', ['source', 'fixed'])
def test_f5_irq_cannot_be_mutated_or_silently_fixed(f5_inputs,kind):
    result = _admit(f5_inputs,target_kind=kind)
    assert result['status']=='refused'
    assert any(row['code']=='compiled-irq-bound-unowned' for row in result['refusals'])


@pytest.mark.parametrize('component,port,mutation', [
    ('processor','irq_external_i','direction'), ('processor','irq_external_i','width'),
    ('peripheral','intr_rx_watermark_o','direction'),
    ('peripheral','intr_rx_watermark_o','width'),
    ('peripheral','intr_rx_watermark_o','missing')])
def test_f5_irq_rejects_altered_physical_export(f5_inputs,component,port,mutation):
    artifacts = dict(f5_inputs[0]); artifact = artifacts[component]
    runtime = deepcopy(artifact.runtime_document)
    row = next(row for row in runtime['physical_exports'] if row['physical_port']==port)
    if mutation=='direction': row['direction'] = 'output' if row['direction']=='input' else 'input'
    elif mutation=='width': row['width'] = 2
    else: runtime['physical_exports'].remove(row)
    artifacts[component] = replace(artifact, runtime_document=runtime)
    assert _admit(f5_inputs,artifacts=artifacts)['status']=='refused'


def test_f5_refuses_altered_compiled_graph(f5_inputs):
    compiled = deepcopy(f5_inputs[2])
    node = next(row for row in compiled['runtime_path_contract']['nodes']
                if row['node_id']=='F5.ip_irq')
    node['bit_offset'] += 1
    result = _admit(f5_inputs,compiled=compiled)
    assert result['status']=='refused'
    assert result['refusals'][0]['code']=='compiled-document-mismatch'


def test_flow_filter_does_not_accept_unknown_or_unexecutable_flow(f5_inputs):
    for flows in ((), ('F9',), ('F5','F5')):
        assert _admit(f5_inputs,flow_ids=flows)['status']=='refused'


@pytest.mark.parametrize('mutation', ['duplicate_delivery', 'foreign_delivery',
                                      'trigger', 'owner_range', 'target_port'])
def test_f5_irq_requires_exact_delivery_and_physical_owner(f5_inputs,mutation):
    from myfuzz.local_harness.compiled_artifact_admission import _f5_irq_bound
    artifacts, request, compiled = f5_inputs
    path = next(row for row in compiled['paths'] if row['flow_id']=='F5')
    producer = next(row for row in path['bound_inputs'] if row['kind']=='ip_irq')
    owner = dict(component_id='processor', bit_offset=0, width=1,
                 producer_ref=producer['input_id'])
    delivery = request.wiring.deliveries[0]
    target_port = 'irq_external_i'
    if mutation=='duplicate_delivery':
        request = replace(request, wiring=replace(request.wiring, deliveries=(delivery,
            replace(delivery, delivery_id='second'))))
    elif mutation=='foreign_delivery':
        request = replace(request, wiring=replace(request.wiring, deliveries=(delivery,
            replace(delivery, delivery_id='second', producer_instance='foreign'))))
    elif mutation=='trigger':
        request = replace(request, wiring=replace(request.wiring,
            deliveries=(replace(delivery, trigger='pulse'),)))
    elif mutation=='owner_range': owner['bit_offset']=1
    else: target_port='wrong_irq'
    assert not _f5_irq_bound(path,request,compiled,artifacts,owner,target_port)


def test_f5_only_does_not_require_f4_whole_gpio_source():
    """Real rendered GPIO and Ibex profiles: bit 8 is only the F5 source."""
    import json
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_driver, render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.compiled_paths import PathComponent, PathCompileRequest, load_path_wiring

    def render(profile, instance):
        doc = dict(schema_version='local_harness.v2', profile_path=profile,
            instance_id=instance, reset_assert_ticks=2, reset_release_ticks=3,
            max_wait_cycles=16, tuning={'raw_tick_stream': [{'sampling': 'pre_post'}]})
        plan = plan_local_harness(load_local_harness_request(doc), base_dir=ROOT)
        return render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)

    cpu = render('configs/cpus/ibex_obi_local/component_profile.json','cpu')
    gpio = render('configs/peripherals/pulp_gpio_causal_local/component_profile.json','gpio_b')
    capability = load_ip_test_capability(json.loads((ROOT/
        'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json').read_text()),
        profile=gpio.plan.profile)
    wiring = load_path_wiring({'schema_version':'path_wiring.v1',
        'cpu': {'instance_id':'cpu','data_endpoint':'processor.data'},
        'windows':[{'device_id':'gpio_b','target_instance':'gpio_b','endpoint_id':'gpio.bus',
                    'base':0x40000000,'size':4096}],
        'resources':[{'resource_id':'ram','component_instance':'cpu','base':0x10000,
            'size':0x30000,'read':True,'write':True,'execute':True,'initialization_policy':'preload'}],
        'deliveries':[{'delivery_id':'gpio_irq','producer_instance':'gpio_b',
            'producer_endpoint_id':'gpio.interrupts','producer_signal':'interrupt',
            'consumer_instance':'cpu','consumer_endpoint_id':'processor.interrupts','trigger':'pulse'}],
        'environment_links':[{'link_id':'gpio_pin8','component_instance':'gpio_b',
            'endpoint_id':'gpio.pins','bit_offset':8,'width':1}]})
    request = PathCompileRequest(PathComponent('cpu',cpu.plan.profile),
        (PathComponent('gpio_b',gpio.plan.profile,capability),), wiring, {},
        'processor.data','processor.instruction')
    compiled = compile_paths(request)
    f5 = next(row for row in compiled['paths'] if row['flow_id']=='F5')
    source = next(row for row in f5['sources'] if row['kind']=='external_pin')
    producer = next(row for row in f5['bound_inputs'] if row['kind']=='ip_irq')
    assert (source['bit_offset'],source['width'])==(8,1)
    ownership = compile_ownership((InputField('cpu','irq_external_i',1),
        InputField('gpio_b','gpio_in',32)), (
        InputOwner('cpu','irq_external_i',0,1,'bound',producer['input_id']),
        InputOwner('gpio_b','gpio_in',0,8,'fixed','low'),
        InputOwner('gpio_b','gpio_in',8,1,'source',source['source_id']),
        InputOwner('gpio_b','gpio_in',9,23,'fixed','high')))
    kwargs = dict(artifacts={'cpu':cpu,'gpio_b':gpio},request=request,compiled=compiled,
        ownership=ownership,physical_port_map={('cpu','irq_external_i'):'irq_external_i',
            ('gpio_b','gpio_in'):'gpio_in'})
    selected = admit_compiled_artifacts(**kwargs,flow_ids=('F5',))
    assert selected['status']=='compatible', selected['refusals']
    unfiltered = admit_compiled_artifacts(**kwargs)
    assert unfiltered['status']=='refused'
    assert any(row['code']=='compiled-physical-source-unowned' for row in unfiltered['refusals'])
