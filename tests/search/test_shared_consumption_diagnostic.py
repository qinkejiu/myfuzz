"""Diagnostic scheduling is explicit; evidence assertions never create facts."""
import pytest
from scripts.run_shared_consumption_diagnostic import DirectedConsumptionSelector,PLANS,validate_step
from myfuzz.search.shared_slot_ram_adapter import shared_slot_records


def test_directed_plans_fit_existing_eight_slots_and_preserve_one_full_catalog():
    for name,plan in PLANS.items():
        selector=DirectedConsumptionSelector(name)
        assert len(plan)<=8 and shared_slot_records(selector.rows)
        assert selector.document()['diagnostic']['kind']=='directed-native-consumption'
        assert {a.operator for a in selector.catalog.actions}=={f'F{i}' for i in range(1,7)}


def test_diagnostic_uses_real_policy_pending_without_substituting_settlement():
    from types import SimpleNamespace
    selector=DirectedConsumptionSelector('ram')
    selector._handle=SimpleNamespace(current_state=lambda:{'status':'unknown'})
    selector._pin_handle=SimpleNamespace(current_state=lambda:{'status':'unknown'})
    row=selector.choose()
    assert row==PLANS['ram'][0]
    assert selector.pending[1].id in selector.scheduler._pending
    assert selector.pending[1].reason=='uniform'
    assert selector.credit.policy is selector.scheduler is selector.pin_credit.policy


def test_ram_assertion_rejects_old_writer_even_same_value():
    step=dict(record='F1:03200000',case_id='read',RAM={'status':'observed','writer_attributed':True,
        'writer_case_ids':['new']*4},PIN={'status':'unknown'},
        report={'status':'verified','relations':[{'writer_case_ids':['old']*4,'read_case_id':'read'}]},
        transition={'credited_relations':[]})
    with pytest.raises(ValueError,match='latest_RAM_writer'):validate_step(step,last_ram='new',last_pin=None)


def test_pin_assertion_rejects_documentary_or_old_writer():
    step=dict(record='F2:08100040',case_id='read',RAM={'status':'unknown'},PIN={'status':'observed'},
        report={'status':'unknown','relations':[]},transition={'credited_relations':[]})
    with pytest.raises(ValueError,match='native_PIN'):validate_step(step,last_ram=None,last_pin='new')
