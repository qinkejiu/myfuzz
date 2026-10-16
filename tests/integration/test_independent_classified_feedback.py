"""Independent classified receipts and trusted fresh software replay."""
import json
import pytest
from tests.integration.test_candidate_exploration_cli import cli
from tests.integration.test_scenario_candidate_exploration import configured, drive


def test_independent_switch_needs_no_candidate_or_physical_exports():
    baseline = configured(available=False)
    executor = configured(available=False, classified_feedback=True)
    assert executor.candidate_exploration_state() is None
    assert executor._online_weights() == baseline._online_weights()
    drive(executor); drive(baseline)
    feedback = executor.receipts[0].interaction_feedback
    assert feedback['verified_dependency']['new_records'] == []
    assert feedback['functional_coverage']['status'] == 'unknown'
    assert feedback['legacy_target_coverage']['new_target_ids'] == ['local.observed']
    assert feedback['candidate_novelty']['status'] == 'disabled'
    assert 'functional_coverage' not in baseline.receipts[0].interaction_feedback
    assert executor.classified_feedback_state()['cases'] == 1
    drive(executor)
    assert executor.classified_feedback_state()['cases'] == 1


@pytest.mark.parametrize('args', [dict(classified_feedback=1), dict(classified_feedback_max_records=True),
    dict(classified_feedback_max_records=0)])
def test_independent_switch_and_bounds_are_strict(args):
    with pytest.raises(ValueError): configured(**args)


def test_independent_receipts_config_terminal_and_fresh_replay():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    from myfuzz.integration.scenario_rfuzz_replay import replay_candidate_exploration_files
    transport = TerminalIdentityTests(); transport.setUp()
    try:
        original = configured(available=False, classified_feedback=True)
        transport.run_transport(original, tests=((bytes(8),), (bytes((1,0,0,0,0,0,0,0)),)))
        report = json.loads((transport.output/'report.json').read_bytes())
        config = json.loads((transport.output/'online_run_identity.json').read_bytes())['identity']['run_config']
        assert 'candidate_exploration' not in config
        assert config['classified_feedback'] == report['classified_feedback']['configuration']
        fresh = configured(available=False, classified_feedback=True)
        replay = replay_candidate_exploration_files(transport.output, executor_factory=lambda:fresh)
        assert replay.matches
        assert 'classified_terminal_state' in replay.verification_scope
        assert 'candidate_case_scoring' not in replay.verification_scope
        assert fresh.classified_feedback_state() == original.classified_feedback_state()
    finally: transport.doCleanups()


def test_fresh_replay_refuses_independent_switch_mismatch_before_cases():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    from myfuzz.integration.scenario_rfuzz_replay import replay_candidate_exploration_files
    transport = TerminalIdentityTests(); transport.setUp()
    try:
        original = configured(available=False, classified_feedback=True)
        transport.run_transport(original, tests=((bytes(8),),))
        fresh = configured(available=False)
        with pytest.raises(ValueError): replay_candidate_exploration_files(transport.output, executor_factory=lambda:fresh)
        assert not fresh.receipts and not fresh.session.cases
    finally: transport.doCleanups()


def test_independent_base_coverage_uses_actual_protocol_projection_without_candidates():
    executor = configured(classified_feedback=True, protocol=True)
    drive(executor)
    drive(executor, buffer_id=2)
    feedback = executor.receipts[-1].interaction_feedback
    assert executor.candidate_exploration_state() is None
    assert feedback['base_coverage']['instances']['local']['counts']['event:bus:transaction_response'] == 1
    assert feedback['candidate_novelty']['candidate_energy'] == 0


def test_standalone_rejects_preexisting_cached_protocol_configuration_drift():
    def drift(runner):
        local = runner.sessions['local']
        projector = runner._ip_protocol_event_normalizer('local', local)
        projector.max_wait_cycles = True
    with pytest.raises(ValueError): configured(classified_feedback=True, protocol=True, change=drift)


@pytest.mark.parametrize('candidate,classified', [(False,False),(False,True),(True,False),(True,True)])
def test_switch_combinations_preserve_weights_and_observation_channels(candidate, classified):
    executor = configured(enabled=candidate, classified_feedback=classified)
    drive(executor)
    assert (executor.classified_feedback_state() is not None) is classified
    assert (executor.candidate_exploration_state() is not None) is candidate
    assert ('verified_dependency' in executor.receipts[0].interaction_feedback) is (candidate or classified)


@pytest.mark.parametrize('original', [False, True])
def test_explicit_classified_switch_drift_is_refused_before_case(original):
    executor = configured(enabled=not original, classified_feedback=original)
    executor.classified_feedback = not original
    with pytest.raises(ValueError, match='classified'): drive(executor)
    assert not executor.receipts and not executor.session.cases


def test_standalone_native_contract_is_rechecked_on_every_retry(monkeypatch):
    executor = configured(classified_feedback=True)
    from myfuzz.local_harness import native_physical_observation as policy
    original = policy.verify_native_physical_observation
    def refuse(artifact): raise ValueError('native drift')
    monkeypatch.setattr(policy, 'verify_native_physical_observation', refuse)
    for _ in range(2):
        with pytest.raises(ValueError, match='native drift'): drive(executor)
    assert not executor.receipts and not executor.session.cases
    monkeypatch.setattr(policy, 'verify_native_physical_observation', original)
    drive(executor)
    assert executor.classified_feedback_state()['cases'] == 1


@pytest.mark.parametrize('component', ['cpu', 'gpio_a'])
def test_actual_native_profile_drift_is_refused_repeatedly_and_can_restore(tmp_path, component):
    from dataclasses import replace
    from types import SimpleNamespace
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    from myfuzz.integration.classified_feedback import OnlineClassifiedFeedback
    runner = make_ibex_pulp_dual_source_factory(tmp_path, physical_observations=True)()
    executor = SimpleNamespace(online_decoder=object(), session=SimpleNamespace(runner=runner),
        classified_feedback=True, _candidate_exploration=None)
    adapter = OnlineClassifiedFeedback(executor)
    local = runner.sessions[component]; original = local.artifact
    profile = original.plan.profile
    if component == 'cpu':
        profile = replace(profile, cpu=replace(profile.cpu, irq_entry_role='forged'))
    else:
        profile = replace(profile, port_actions=tuple(a for a in profile.port_actions if a.port != 'interrupt'))
    local.artifact = replace(original, plan=replace(original.plan, profile=profile))
    for _ in range(2):
        with pytest.raises(ValueError): adapter.prepare_case()
    local.artifact = original
    adapter.prepare_case()
    assert adapter.state()['cases'] == 0


@pytest.mark.parametrize('target', ['physical', 'protocol', 'checker'])
def test_frozen_projector_configuration_cannot_follow_live_mutation(target):
    from copy import deepcopy
    executor = configured(classified_feedback=True, protocol=True)
    runner = executor.session.runner
    if target == 'physical':
        obj = runner._ip_base_event_normalizers['local']; attribute = '_exports'
        original = deepcopy(getattr(obj, attribute)); obj._exports[0]['width'] = True
    else:
        obj = (runner._ip_protocol_event_normalizers if target == 'protocol' else runner._ip_protocol_checkers)['local']
        attribute = '_signals'; original = deepcopy(obj._signals); obj._signals['pwrite'] = 'forged'
    for _ in range(2):
        with pytest.raises(ValueError): drive(executor)
    assert not executor.receipts and not executor.session.cases
    setattr(obj, attribute, original)
    drive(executor)
    assert executor.classified_feedback_state()['cases'] == 1


@pytest.mark.parametrize('enabled', [False, True])
def test_cli_forwards_independent_opt_in_only(cli, tmp_path, monkeypatch, enabled):
    from unittest.mock import Mock
    from types import SimpleNamespace
    runtime = Mock(return_value=SimpleNamespace(executor=object()))
    monkeypatch.setattr(cli, 'make_ibex_pulp_online_runtime', runtime)
    monkeypatch.setattr(cli, 'run_scenario_rfuzz_live', lambda **kw: SimpleNamespace(
        output_dir=tmp_path/'new', tests=1, statuses={}, elapsed_seconds=1, effective_search_seconds=1))
    args = ['run', '--client-binary', '/tmp/client', '--cache-dir', str(tmp_path), '--output', str(tmp_path/'new')]
    if enabled: args += ['--classified-feedback', '--classified-feedback-max-records', '8']
    assert cli.main(args) == 0
    assert 'candidate_exploration' not in runtime.call_args.kwargs
    assert ('classified_feedback' in runtime.call_args.kwargs) is enabled
    if enabled: assert runtime.call_args.kwargs['classified_feedback_max_records'] == 8


@pytest.mark.parametrize('field', ['enabled', 'explicit_requested'])
def test_saved_classified_configuration_bool_int_alias_rejected(field):
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
    from myfuzz.scenario.replay import ScenarioTrace
    transport = TerminalIdentityTests(); transport.setUp()
    try:
        executor = configured(available=False, classified_feedback=True)
        transport.run_transport(executor, tests=((bytes(8),),))
        path = transport.output/'report.json'; report = json.loads(path.read_bytes())
        report['classified_feedback']['configuration'][field] = 1
        path.write_text(json.dumps(report))
        trace_path = transport.output/'online_final_trace.json'
        trace = ScenarioTrace(**json.loads(trace_path.read_bytes()))
        with pytest.raises(ValueError, match='classified'):
            _verify_online_run_identity(transport.output, plan_path=transport.output/'online_plan.json', trace_path=trace_path, trace=trace)
    finally: transport.doCleanups()


def test_feedback_only_preserves_complete_source_selection_and_weights_for_same_raw_inputs():
    baseline = configured(two_sources=True, protocol=True)
    feedback = configured(two_sources=True, protocol=True, classified_feedback=True)
    for buffer_id, value in enumerate((0, 1, 1, 0, 1), 1):
        assert feedback._online_weights() == baseline._online_weights()
        drive(baseline, buffer_id=buffer_id, value=value)
        drive(feedback, buffer_id=buffer_id, value=value)
        before, after = baseline.online_decisions[-1], feedback.online_decisions[-1]
        for key in ('weights', 'source_id', 'source_action', 'source_selection_reason',
                    'candidate_disposition', 'interaction_source_gains', 'closed_loop_feedback'):
            assert after.get(key) == before.get(key), key
        assert feedback.receipts[-1].online_case == baseline.receipts[-1].online_case
        assert feedback._online_weights() == baseline._online_weights()
    assert feedback.candidate_exploration_state() is None
    assert feedback.classified_feedback_state()['cases'] == 5
