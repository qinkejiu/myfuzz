from pathlib import Path

import pytest

from myfuzz.runtime.generic_campaign import load_descriptor,select_case_records,GenericScenarioRefused

ROOT=Path(__file__).resolve().parents[2]
DESCRIPTOR=ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared/generic_scenario.json'


def test_shared_descriptor_accepts_f5_and_memory_without_f2():
    descriptor=load_descriptor(DESCRIPTOR,base_dir=ROOT)
    assert descriptor.flow_ids==('F1','F3','F4','F5')
    assert descriptor.records('F1')==['13000000','03200000']
    assert descriptor.records('F3')==['55000000','aa000000']
    assert select_case_records(descriptor,flow='mixed',records=['F1:13000000','F5:0000000100000000']) == (
        ('F1','13000000'),('F5','0000000100000000'))
    with pytest.raises(GenericScenarioRefused):
        select_case_records(descriptor,flow='mixed',records=['F2:20100040'])


def test_shared_f5_record_binds_declared_pin_source():
    from myfuzz.runtime.generic_campaign import case_sequence_for_plan
    result=case_sequence_for_plan(scenario_id='shared',plan_document={'paths':[{
        'flow_id':'F5','path_id':'pin','sources':[{'kind':'external_pin','origin':'fuzzable','source_id':'pin8'}]}]},
        plan_sha256='a'*64,cases=(('F5','0000000100000000'),))
    assert result['cases'][0]['source_id']=='pin8'


def test_search_catalog_preflights_shared_f5_and_ram_subsets():
    from myfuzz.search.descriptor_search import preflight_scenario
    base={'descriptor':str(DESCRIPTOR.relative_to(ROOT)),'flow':'mixed'}
    result=preflight_scenario({**base,'records':['F1:13000000','F5:0000000100000000']},ROOT)
    assert result['search_backend']=='record-catalog'
    ram=preflight_scenario({**base,'records':['F3:55000000','F1:03200000']},ROOT)
    assert ram['search_backend']=='live-ram'


def test_shared_pin_search_preflight_uses_same_explicit_descriptor_catalog():
    import json
    from myfuzz.search.descriptor_search import preflight_scenario
    config=json.loads((ROOT/'configs/search/gpio-shared-f2.json').read_text())
    result=preflight_scenario(config,ROOT)
    assert result['search_backend']=='live-gpio-pin'
    assert result['consumption_provider']=='installed_GPIO_PADIN_native_read.v1'
    assert {'F5:0000000100000000','F5:0000000000000000'} <= set(config['records'])
