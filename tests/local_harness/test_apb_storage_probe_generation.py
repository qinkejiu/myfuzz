"""Pure probe controls: no elaboration, process, or live authority."""
import pytest
from myfuzz.local_harness.tuning import load_local_harness_tuning

SELECTOR = dict(endpoint_id='timer.bus', contract_id='pulp-apb-timer.ctrl0.source.v1', register='TIMER0_CTRL')


def test_optional_selector_roundtrip():
    tuning = load_local_harness_tuning({'apb_storage_observations': [SELECTOR]})
    assert tuning.document()['apb_storage_observations'] == [SELECTOR]
    assert 'apb_storage_observations' not in load_local_harness_tuning({}).document()


def test_duplicate_and_expression_refused():
    for rows in ([SELECTOR, SELECTOR], [dict(SELECTOR, expression='fabricated')]):
        with pytest.raises(ValueError):
            load_local_harness_tuning({'apb_storage_observations': rows})


def test_probe_consumer_rejects_missing_bool_and_overflow():
    from myfuzz.local_harness.apb_storage_probe_contract import validate_storage_probe_sample
    ports = [dict(name='storage_value', width=32, direction='output')]
    assert validate_storage_probe_sample({'storage_probes': {'storage_value': 7}}, ports) == {'storage_value': 7}
    for sample in ({}, {'storage_probes': {}}, {'storage_probes': {'storage_value': True}}, {'storage_probes': {'storage_value': 1 << 32}}):
        with pytest.raises(ValueError): validate_storage_probe_sample(sample, ports)

from tests.local_harness.test_generic_apb_identity import generated


def selected(generated, override=None):
    from dataclasses import replace
    from myfuzz.local_harness import runtime_renderer, render_local_harness
    from myfuzz.local_harness.tuning import load_local_harness_tuning
    artifact, _ = generated
    tuning = artifact.plan.request.tuning.document()
    tuning['apb_storage_observations'] = [dict(SELECTOR, endpoint_id=artifact.plan.binding.endpoints[0].endpoint_id)]
    if override is not None:
        tuning['apb_storage_observations'][0].update(override)
    request = replace(artifact.plan.request, tuning=load_local_harness_tuning(tuning))
    plan = replace(artifact.plan, request=request)
    return runtime_renderer.render_local_runtime(plan, render_local_harness(plan), artifact.source_verification, base_dir=ROOT)


from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]


def test_registered_generation_and_source_spoof_refusal(generated):
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    artifact, _ = generated
    if artifact.plan.profile.source.top_module != 'apb_timer':
        with pytest.raises(ValueError): selected(generated)
        return
    result = selected(generated)
    assert verify_apb_register_trace(result)
    doc = result.runtime_document
    assert len(doc['storage_probe_ports']) == 10
    assert all(not doc['storage_observation'][key] for key in ('hierarchy_verified','native_verified','reset_authority','version_authority','source_authority'))
    assert 'assign storage_value = u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1];' in result.runtime_sv
    assert 'assign storage_reset = reset;' in result.runtime_sv
    driver = render_local_driver(result, base_dir=ROOT)
    assert '"storage_probes"' in driver.cpp_text
    pins = {r['path'] for r in doc['selected_template']['executor']['binding']['implementation_sources']}
    assert 'src/myfuzz/local_harness/apb_storage_probe_contract.py' in pins
    assert 'src/myfuzz/local_harness/apb_storage_source_contract.py' in pins


def test_nonoptin_full_text_unchanged(generated):
    import types
    from myfuzz.local_harness.driver_renderer import render_local_driver
    artifact, _ = generated
    old = types.ModuleType('myfuzz.local_harness._old_probe_renderer')
    old.__file__ = str(ROOT/'src/myfuzz/local_harness/runtime_renderer.py')
    exec((ROOT/'.superpowers/apb-storage-probe-generation/runtime_renderer.before.py').read_text(), old.__dict__)
    prior = old._render_admitted_runtime(artifact.plan, artifact.structural, artifact.source_verification, ROOT, native_raw=False)
    assert prior.runtime_sv == artifact.runtime_sv
    olddriver = types.ModuleType('myfuzz.local_harness._old_probe_driver')
    olddriver.__file__ = str(ROOT/'src/myfuzz/local_harness/driver_renderer.py')
    exec((ROOT/'.superpowers/apb-storage-probe-generation/driver_renderer.before.py').read_text(), olddriver.__dict__)
    assert olddriver.render_local_driver(prior, base_dir=ROOT).cpp_text == render_local_driver(prior, base_dir=ROOT).cpp_text


@pytest.mark.parametrize('mutation', ('hierarchy','comment','procedural','metadata','duplicate'))
def test_selected_canonical_reprojection_refuses_rehashed_mutations(generated, mutation):
    import copy, hashlib
    from dataclasses import replace
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    artifact, _ = generated
    if artifact.plan.profile.source.top_module != 'apb_timer':
        pytest.skip('registered storage is timer only; GPIO rejection tested separately')
    artifact = selected(generated)
    text = artifact.runtime_sv
    doc = copy.deepcopy(artifact.runtime_document)
    if mutation == 'hierarchy': text = text.replace('TIMER_GEN[0]', 'TIMER_GEN[1]')
    elif mutation == 'comment': text = text.replace('assign storage_value =', '// assign storage_value =')
    elif mutation == 'procedural': text = text.replace('assign storage_value =', 'always_comb storage_value =')
    elif mutation == 'metadata': doc['storage_observation']['hierarchy_verified'] = True
    else: doc['storage_probe_ports'].append(copy.deepcopy(doc['storage_probe_ports'][0]))
    doc['runtime_sv_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    with pytest.raises(ValueError): verify_apb_register_trace(replace(artifact, runtime_sv=text, runtime_document=doc))


@pytest.mark.parametrize('override', [dict(endpoint_id='foreign.bus'), dict(contract_id='unknown'), dict(register='TIMER1_CTRL')])
def test_unknown_selection_refused_before_generation(generated, override):
    with pytest.raises(ValueError): selected(generated, override)


def test_spi_probe_uses_exact_source_hierarchy_and_digest():
    import hashlib, json
    from types import SimpleNamespace
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.apb_storage_probe_contract import generate_storage_probe
    from myfuzz.local_harness.apb_storage_source_contract import select_apb_storage_source_contract
    selector = dict(endpoint_id='spi.bus', contract_id='pulp-apb-spi.spicmd.source.v1', register='SPICMD')
    profile = load_component_profile(ROOT/'configs/peripherals/pulp_spi/component_profile.json')
    plan = SimpleNamespace(profile=profile,
        request=SimpleNamespace(tuning=load_local_harness_tuning({'apb_storage_observations':[selector]})),
        binding=SimpleNamespace(endpoints=profile.endpoints))
    wires = {role:'apb_'+role for role in ('paddr','psel','penable','pwrite','pwdata','prdata','pready','pslverr')}
    probe = generate_storage_probe(plan,wires,base_dir=ROOT)
    assert probe['selection']==selector
    assert probe['source_contract']==select_apb_storage_source_contract(profile,base_dir=ROOT,
        selection={k:selector[k] for k in ('contract_id','register')})
    assert probe['ports'][0]==dict(name='storage_value',direction='output',width=32,
        role='value',expression='u_component.u_dut.u_axiregs.spi_cmd')
    assert len(probe['ports'])==10
    assert all(probe[k] is False for k in ('hierarchy_verified','native_verified','reset_authority','version_authority','source_authority'))
    payload={k:v for k,v in probe.items() if k!='digest'}
    digest=lambda d:hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    assert probe['digest']==digest(payload)
    payload['source_contract']['decode']['mask']=0x1c
    assert probe['digest']!=digest(payload)
