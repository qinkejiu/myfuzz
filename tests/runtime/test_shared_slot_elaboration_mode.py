"""A shared invocation pins frontend choice through accepting scope exit."""
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import pytest


def test_shared_entry_mode_remains_fixed_during_exceptional_scope_exit(tmp_path, monkeypatch):
    from myfuzz.runtime.flows.shared_slots import run_shared_slot_descriptor
    import myfuzz.runtime.preparation
    import myfuzz.runtime.generic_campaign
    import myfuzz.integration.compiled_f6
    from myfuzz.local_harness.execution_validation import static_validation
    from myfuzz.composition import component_profile as cp
    available = {'value': True}
    observed = []
    monkeypatch.setattr(cp, 'supervisor_available', lambda: (available['value'], 'test-host'))
    monkeypatch.setattr('myfuzz.local_harness.build.host_source_discovery_scope', lambda **kw: nullcontext())
    monkeypatch.setattr('myfuzz.local_harness.build.harness_validation_scope', lambda: nullcontext())

    def prepare(**kwargs):
        def frontend():
            value = cp._ELABORATION_MODE.get() or ('supervised' if available['value'] else 'direct')
            observed.append(value)
            return value
        static_validation('test-actual-frontend-choice', frontend)
        available['value'] = False
        raise RuntimeError('diagnostic-stop-before-DUT')

    monkeypatch.setattr('myfuzz.runtime.preparation.create_preparation', prepare)
    descriptor = SimpleNamespace(capability=Path('capability'), compose=Path('compose'),
        supplement=Path('supplement'), flow_ids=('F4','F6'), scenario_id='shared')
    with pytest.raises(RuntimeError, match='diagnostic-stop-before-DUT') as caught:
        run_shared_slot_descriptor(descriptor, cases=[('F4','55000000')], mode='original',
            case_root=tmp_path, base=tmp_path, cache=None, rounds=1, capacity=1,
            execution_mode='validation', max_wall_seconds=None, record_selector=None,
            selected_count=None, expected_records=None, command_trace=None)
    assert observed == ['supervised', 'supervised']
    assert not getattr(caught.value, '__notes__', ())
    evidence = json.loads((tmp_path/'original'/'elaboration-mode.json').read_text())
    assert evidence['effective_elaboration_mode'] == 'supervised'
    failure = json.loads((tmp_path/'original'/'failure.json').read_text())
    assert failure['effective_elaboration_mode'] == 'supervised'
    assert cp._ELABORATION_MODE.get() is None


def test_fresh_reuses_original_mode_and_refuses_unavailable_supervisor(tmp_path, monkeypatch):
    from myfuzz.runtime.flows.shared_slots import _shared_elaboration_mode
    from myfuzz.composition import component_profile as cp
    original = tmp_path/'original'; original.mkdir()
    def save(mode):
        (original/'summary.json').write_text(json.dumps({'shared_slots':True,'effective_elaboration_mode':mode}))
        (original/'elaboration-mode.json').write_text(json.dumps({'effective_elaboration_mode':mode}))
    save('direct')
    monkeypatch.setattr(cp,'supervisor_available',lambda:(True,''))
    assert _shared_elaboration_mode('fresh',tmp_path) == 'direct'
    save('supervised')
    monkeypatch.setattr(cp,'supervisor_available',lambda:(False,'host-unavailable'))
    with pytest.raises(ValueError,match='supervisor-unavailable'):_shared_elaboration_mode('fresh',tmp_path)
    save('direct')
    (original/'elaboration-mode.json').write_text(json.dumps({'effective_elaboration_mode':'supervised'}))
    with pytest.raises(ValueError,match='mode-mismatch'):_shared_elaboration_mode('fresh',tmp_path)
    save(None)
    with pytest.raises(ValueError,match='mode-missing'):_shared_elaboration_mode('fresh',tmp_path)


def test_real_direct_and_supervised_frontends_have_distinct_provenance():
    from myfuzz.composition.component_profile import (
        load_component_profile, elaborate_profile, supervisor_available, ComponentProfileError)
    if not supervisor_available()[0]:pytest.skip('process-group supervision unavailable')
    root = Path(__file__).resolve().parents[2]
    profile = load_component_profile(root/'configs/peripherals/pulp_timer/component_profile.json')
    direct = elaborate_profile(profile,base_dir=root,mode='direct')
    try:supervised = elaborate_profile(profile,base_dir=root,mode='supervised')
    except ComponentProfileError as error:
        if 'supervisor-unavailable' in str(error):pytest.skip(str(error))
        raise
    assert direct.ports == supervised.ports
    assert direct.content_hash != supervised.content_hash
    assert direct.modules == () and supervised.modules
