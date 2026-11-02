"""Pure RAM state/credit contracts and fail-closed live installation boundary."""
import pytest
from myfuzz.search.ram_actions import RamActionSpace, ram_view, ram_identity, RamCredit
from myfuzz.search.ram import read_ram_current
from myfuzz.search.policy import Policy


def field(version=1, value=85, writer='writer'):
    return dict(status='observed', component='cpu', memory_id='ram', address=0x1000,
        reset_epoch=0, value=value, writer_attributed=True,
        writer_case_ids=[writer]*4, byte_resources=[dict(byte_offset=i,
            version=[0,version], value=(value >> (8*i)) & 255,
            writer_event_id='tx', observation_event_id=3) for i in range(4)])


def relation(current, reader='reader'):
    return dict(status='verified', reward_eligible=True, read_case_id=reader,
        writer_case_ids=current['writer_case_ids'], resource_identity=ram_identity(current),
        value=current['value'], component='cpu', memory_id='ram', address=0x1000)


def test_uninstalled_documents_cannot_supply_live_state():
    assert read_ram_current(field())['status'] == 'unknown'


def test_typed_public_actions_share_grammar_and_state_frontier():
    space = RamActionSpace(values=(85,), write_source='store', read_source='image')
    current = field()
    goal, snapshot = ram_view(current, {'relations': []}, values=space.values)
    from myfuzz.search.frontier import frontier
    assert frontier(goal, snapshot) == ('ram:consumed',)
    assert space.record(space.catalog.actions[0].id, 85) == 'F3:55000000'
    assert space.record('ram:read', 0) == 'F1:03200000'
    assert ram_view(current, {'relations': [relation(current)]}, values=space.values)[1].get('ram:consumed').status == 'satisfied'
    assert ram_view(field(version=2), {'relations': [relation(current)]}, values=space.values)[1].get('ram:consumed').status == 'unknown'


def test_exact_cross_case_consumption_conserves_credit_and_overwrite_censors():
    space = RamActionSpace(values=(85,), write_source='store', read_source='image')
    policy = Policy(seed=7, mode='state', max_decisions=4, epsilon=0)
    credit = RamCredit(policy)
    goal, snapshot = ram_view({'status':'unknown'}, {'relations':[]}, values=space.values)
    writer = policy.choose(goal, snapshot, space.catalog)
    current = field()
    assert writer.action_id.startswith('ram:write:')
    assert credit.observe(writer, 'writer', current, {'relations':[]}, 10)['pending'] == [writer.id]
    goal, snapshot = ram_view(current, {'relations':[]}, values=space.values)
    reader = policy.choose(goal, snapshot, space.catalog)
    assert reader.action_id == 'ram:read'
    result = credit.observe(reader, 'reader', current, {'relations':[relation(current)]}, 20)
    assert result['pending'] == []
    assert len(result['credited_relations']) == 1
    assert sum(row['reward'] for row in result['settlements']) == 2


def test_mismatched_versions_or_unattributed_relations_never_reward():
    space = RamActionSpace(values=(85,), write_source='store', read_source='image')
    policy = Policy(seed=7, mode='state', max_decisions=4, epsilon=0)
    credit = RamCredit(policy)
    goal, snapshot = ram_view({'status':'unknown'}, {'relations':[]}, values=space.values)
    writer = policy.choose(goal, snapshot, space.catalog)
    old = field()
    credit.observe(writer, 'writer', old, {'relations':[]}, 10)
    goal, snapshot = ram_view(old, {'relations':[]}, values=space.values)
    reader = policy.choose(goal, snapshot, space.catalog)
    result = credit.observe(reader, 'reader', field(version=2), {'relations':[relation(old)]}, 20)
    assert result['credited_relations'] == []
    assert all(row['reward'] in (0, None) for row in result['settlements'])


def test_actual_callback_tracker_current_version_overwrite_and_reset_without_read_effect():
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    from tests.scenario.test_classified_feedback import memory
    runner, cpu = memory()
    tracker = LiveMemoryEffectTracker(consumer=runner._memory_dependency_consumer)
    cpu._serve('data', 1, 0x20000, 85, 15)
    runner._append_external_events('cpu', 1)
    first = tracker.retained_ram_witnesses('ram', 0)
    assert len(first) == 1 and first[0].value == 85
    cpu._serve('data', 1, 0x20000, 85, 15)
    runner._append_external_events('cpu', 1)
    transaction_count = len(cpu.service.ledger._entries)
    second = tracker.retained_ram_witnesses('ram', 0)
    assert len(second) == 1 and second[0].version != first[0].version
    assert len(cpu.service.ledger._entries) == transaction_count
    tracker.reset(event_id=runner.event_count)
    assert tracker.retained_ram_witnesses('ram', 0) == ()


def test_cli_preflight_routes_only_explicit_typed_ram_catalog():
    import json
    from pathlib import Path
    from myfuzz.search.descriptor_search import preflight_scenario
    from myfuzz.search.ram_case_adapter import ram_records
    root = Path(__file__).resolve().parents[2]
    config = json.loads((root / 'configs/search/memory-consumption-ibex.json').read_text())
    result = preflight_scenario(config, root)
    assert result['search_backend'] == 'live-ram'
    assert result['live_state_conditioned'] is True
    assert result['native_executed'] is False
    assert not ram_records(['F3:55000000', 'F1:13000000'])
    assert not ram_records(['F3:55000000', 'F1:03200000', 'F4:55000000'])


def test_overwrite_then_read_rewards_only_new_actual_writer_and_repeat_is_deduplicated():
    space = RamActionSpace(values=(85,), write_source='store', read_source='image')
    policy = Policy(seed=7, mode='state', max_decisions=4, epsilon=0)
    credit = RamCredit(policy)
    unknown_goal, unknown_snapshot = ram_view({'status':'unknown'}, {'relations':[]}, values=space.values)
    writer1 = policy.choose(unknown_goal, unknown_snapshot, space.catalog)
    old = field(writer='writer1')
    credit.observe(writer1, 'writer1', old, {'relations':[]}, 10)
    writer2 = policy.choose(unknown_goal, unknown_snapshot, space.catalog)
    current = field(version=2, writer='writer2')
    replaced = credit.observe(writer2, 'writer2', current, {'relations':[]}, 10)
    assert replaced['settlements'][0]['decision_id'] == writer1.id
    assert replaced['settlements'][0]['censored'] is True
    goal, snapshot = ram_view(current, {'relations':[]}, values=space.values)
    reader = policy.choose(goal, snapshot, space.catalog)
    result = credit.observe(reader, 'reader', current,
        {'relations':[relation(old), relation(current)]}, 20)
    assert {row['decision_id'] for row in result['settlements']} == {writer2.id, reader.id}
    assert sum(row['reward'] for row in result['settlements']) == 2
    reader2 = policy.choose(goal, snapshot, space.catalog)
    repeated = credit.observe(reader2, 'reader2', current,
        {'relations':[relation(current, reader='reader2')]}, 20)
    assert repeated['credited_relations'] == []
    assert all(row['reward'] == 0 for row in repeated['settlements'])
