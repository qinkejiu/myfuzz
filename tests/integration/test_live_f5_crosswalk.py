"""The generic F5 bridge consumes a live preparation and actual runner."""
from copy import deepcopy

import pytest

from myfuzz.runtime.preparation import create_preparation
from myfuzz.scenario.ibex_pulp_dual_source import CPU_PROFILE, make_pulp_dual_source_factory
from myfuzz.scenario.runner import Binding
from tests.integration.test_compiled_f5_crosswalk import ROOT


@pytest.fixture
def live(tmp_path):
    config = ROOT / 'configs/scenarios/compiled-f5-ibex-pulp-gpio'
    context = create_preparation(base_dir=ROOT, compose_path=config/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json', generated_dir=tmp_path/'generated', flow_ids=('F5',))
    factory = make_pulp_dual_source_factory(tmp_path/'cache', cpu_profile=CPU_PROFILE,
        gpio_consumption=True, generated_artifacts=context.artifacts, f5_only=True)
    runner = factory()
    path = next(row for row in context.compiled_inputs()['compiled']['paths'] if row['flow_id'] == 'F5')
    yield context, runner, path
    context.close()


def validate(live, **changes):
    from myfuzz.integration.compiled_f5_crosswalk import validate_live_f5_crosswalk
    context, runner, path = live
    return validate_live_f5_crosswalk(preparation=context, runner=runner, path=path,
        binding=Binding('gpio_b','irq','cpu','irq',1), pulse_width_ticks=4, **changes)


def test_live_crosswalk_checks_actual_preparation_and_returns_detached_identity(live):
    result = validate(live)
    assert result['runtime_enforcement'] == 'topology_only'
    assert result['source']['component'] == 'gpio_b'
    assert result['irq']['physical_consumer'] == 'irq_external_i'
    result['path_identity']['source_ids'].clear()
    assert validate(live)['path_identity']['source_ids'] == ['F5.pin_event']


def test_closed_preparation_is_rejected(live):
    live[0].close()
    with pytest.raises(ValueError):
        validate(live)


def test_foreign_path_cannot_install_source(live):
    path = deepcopy(live[2])
    next(row for row in path['sources'] if row['kind'] == 'external_pin')['component'] = 'cpu'
    with pytest.raises(ValueError):
        validate((live[0], live[1], path))


def test_actual_session_artifact_swap_is_rejected(live):
    live[1].sessions['gpio_b'].artifact = live[0].artifacts['gpio_a']
    with pytest.raises(ValueError):
        validate(live)


def test_actual_irq_binding_swap_is_rejected(live):
    live[1].bindings = (Binding('gpio_b','gpio_out','cpu','irq',1),)
    with pytest.raises(ValueError):
        validate(live)


def test_actual_pulse_width_swap_is_rejected(live):
    next(iter(live[1]._irq_pulses.values())).width_ticks = 3
    with pytest.raises(ValueError):
        validate(live)


def test_saved_preparation_document_cannot_install_authority(live):
    with pytest.raises(ValueError):
        validate(({}, live[1], live[2]))


def test_fixed_wrapper_consumes_generic_live_crosswalk(live, monkeypatch):
    import myfuzz.integration.compiled_f5_crosswalk as module
    calls = []
    original = module.validate_live_f5_crosswalk
    def checked(**kwargs):
        calls.append(kwargs['preparation'])
        return original(**kwargs)
    monkeypatch.setattr(module, 'validate_live_f5_crosswalk', checked)
    context, runner, _ = live
    result = module.validate_compiled_f5_crosswalk(compiled_inputs=context.compiled_inputs(),
        artifacts=context.artifacts, runner=runner, preparation=context)
    assert result['status'] == 'compatible'
    assert calls == [context]


def test_saved_artifact_dictionary_cannot_replace_actual_session(live):
    from types import SimpleNamespace
    actual = live[1].sessions['gpio_b']
    live[1].sessions['gpio_b'] = SimpleNamespace(artifact=actual.artifact,
        _artifact_document=actual._artifact_document)
    with pytest.raises(ValueError):
        validate(live)


def test_actual_bound_irq_owner_must_match_runtime_binding(live):
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    doc = live[1].ownership.document()
    for row in doc['owners']:
        if row['component_id'] == 'cpu' and row['port'] == 'irq':
            row['producer_ref'] = 'gpio_a.irq'
    live[1].ownership = compile_ownership(tuple(InputField(**row) for row in doc['fields']),
        tuple(InputOwner(**row) for row in doc['owners']))
    with pytest.raises(ValueError):
        validate(live)
