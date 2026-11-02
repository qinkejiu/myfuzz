"""Single-flow live storage capability; no invented cross-case consumer."""
from pathlib import Path
from types import SimpleNamespace
import pytest

from myfuzz.search.single_storage import (
    SingleStorageCaseAdapter, SingleStorageRecordSelector, supports_single_storage,
    single_storage_view, same_case_readback,
)
from myfuzz.search.storage import CurrentVersion
from myfuzz.search.case_adapter import CaseAdapter

ROOT = Path(__file__).resolve().parents[2]


def current(value=85, version=1):
    return CurrentVersion(value, version, 0, 'live:version', 'source-contract')


def test_explicit_executor_capability_does_not_select_by_cpu_or_target_name():
    descriptor = SimpleNamespace(flow_ids=('F4',), executor=lambda flow:'compiled_f4_wishbone')
    assert supports_single_storage(descriptor, 'F4')
    assert not supports_single_storage(descriptor, 'mixed')
    assert not supports_single_storage(SimpleNamespace(flow_ids=('F2','F4'),executor=descriptor.executor), 'F4')


def test_single_storage_view_exposes_written_state_without_consumption_node():
    goal, snapshot = single_storage_view(current(), 85)
    assert goal.root == 'written:00000055'
    assert snapshot.get(goal.root).status == 'satisfied'
    assert snapshot.get('consumed:00000055').status == 'unknown'
    assert single_storage_view(None,85)[1].get(goal.root).status == 'unknown'


def test_same_case_readback_is_distinct_from_cross_case_current_state():
    cert = dict(schema_version='compiled_F4_wishbone_chain.v1', status='certified',
        postcondition=dict(value=85, field_version=1, reset_epoch=0, source_contract_digest='source-contract'),
        exact_hops={'schema_version':'compiled_F4_wishbone_exact_hops.v1'},
        assertions=[dict(expectation_id='cross_component.readback_ram_write_hop', status='passed')])
    assert same_case_readback(cert, current()) == 'certified'
    assert same_case_readback(cert, current(version=2)) == 'unknown'
    cert['status'] = 'submitted'
    assert same_case_readback(cert,current()) == 'unknown'


def test_live_single_flow_preflight_routes_wishbone_without_claiming_f2():
    from myfuzz.search.descriptor_search import preflight_scenario
    row = preflight_scenario(dict(descriptor='configs/scenarios/compiled-f4-obi-wb-uart-setup/generic_scenario.json',
        flow='F4', records=['F4:55000000','F4:2a000000']), ROOT)
    assert row['search_backend'] == 'live-storage-single-flow'
    assert row['live_state_conditioned'] is True
    assert row['cross_testcase_consumption'] == 'unsupported-no-read-only-flow'


def test_case_adapter_uses_common_read_current_and_submission_interface(monkeypatch):
    from myfuzz.search import single_storage
    from myfuzz.search.case_adapter import CaseContext
    from myfuzz.search.actions import Decision
    calls = []
    adapter = object.__new__(SingleStorageCaseAdapter)
    adapter.runtime = SimpleNamespace(_stable=lambda: calls.append('validate'),
        submit=lambda raw, **kwargs: calls.append((raw,kwargs)) or {'status':'submitted'})
    monkeypatch.setattr(single_storage, 'read_current', lambda runtime: current())
    assert isinstance(adapter,CaseAdapter)
    assert adapter.current_state() == current()
    decision = Decision(0,'goal','context','write',85,'frontier',0)
    adapter.execute(decision,CaseContext('case',on_prepared=lambda row:calls.append(row)))
    assert calls[0] == 'validate'
    assert calls[-1] == (bytes.fromhex('55000000'), {'flow':'F4'})
    with pytest.raises(ValueError,match='registered'):
        SingleStorageCaseAdapter(SimpleNamespace(),None)


def test_single_selector_frontier_feedback_never_becomes_relation_reward():
    from myfuzz.search import single_storage
    descriptor=SimpleNamespace(flow_ids=('F4',),executor=lambda flow:'compiled_f4_wishbone')
    selector=SingleStorageRecordSelector(descriptor,flow='F4',records=['F4:55000000'],
        policy='state',seed=7,cases=1)
    selector._replay_costs = [10]
    cert=dict(schema_version='compiled_F4_wishbone_chain.v1',status='certified',case_id='actual-case',
        postcondition=dict(value=85,field_version=1,reset_epoch=0,source_contract_digest='source-contract'),
        exact_hops={'schema_version':'compiled_F4_wishbone_exact_hops.v1'},
        assertions=[dict(expectation_id='cross_component.readback_ram_write_hop',status='passed')])
    adapter=object.__new__(SingleStorageCaseAdapter)
    adapter.policy=selector.scheduler
    adapter.current_state=lambda:current()
    selector.adapter=adapter
    selector.runtime=SimpleNamespace(records=[{'certificate':cert}])
    row=selector.choose(); selector.settle(row)
    document=selector.document()
    assert document['transitions'][0]['same_case_readback'] == 'certified'
    assert document['transitions'][0]['relation_features'] == []
    assert document['transitions'][0]['settlements'][0]['novel_features'] == [['frontier','written:00000055']]
    assert document['cross_testcase_consumption'] == 'unsupported-no-read-only-flow'
