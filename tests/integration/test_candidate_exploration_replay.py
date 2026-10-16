"""Fresh production executor replay using software receipts, not real RTL."""
import hashlib
import json
from unittest.mock import Mock

import pytest

from tests.integration.test_scenario_candidate_exploration import configured


@pytest.fixture
def saved():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    original = configured(enabled=True, two_sources=True)
    transport.run_transport(original, tests=((bytes(8),), (bytes((1, 0, 0, 0, 0, 0, 0, 0)),),
                                             (bytes((2, 0, 0, 0, 0, 0, 0, 0)),)))
    try:
        yield transport.output, original
    finally:
        transport.doCleanups()


def replay(output, factory):
    from myfuzz.integration.scenario_rfuzz_replay import replay_candidate_exploration_files
    return replay_candidate_exploration_files(output, executor_factory=factory)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


@pytest.mark.parametrize('matching', (True, False))
def test_saved_assembly_is_identity_bound_and_compared_before_cases(matching):
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        original = configured(enabled=True, two_sources=True)
        original.set_online_assembly_configuration({'local_configuration': True})
        transport.run_transport(original, tests=((bytes(8),),))
        envelope = json.loads((transport.output / 'online_run_identity.json').read_bytes())
        assert envelope['identity']['run_config']['online_assembly'] == {'local_configuration': True}
        fresh = configured(enabled=True, two_sources=True)
        fresh.set_online_assembly_configuration({'local_configuration': matching})
        if matching:
            assert replay(transport.output, lambda: fresh).matches
        else:
            with pytest.raises(ValueError, match='assembly'):
                replay(transport.output, lambda: fresh)
            assert not fresh.receipts and not fresh.session.cases
            assert fresh.session._finished
    finally:
        transport.doCleanups()


def test_fresh_replay_recomputes_protocol_and_coverage_context():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        original = configured(enabled=True, protocol=True)
        transport.run_transport(original, tests=((bytes(8),), (bytes((1, 0, 0, 0, 0, 0, 0, 0)),)))
        fresh = configured(enabled=True, protocol=True)
        assert replay(transport.output, lambda: fresh).matches
        state = fresh.candidate_exploration_state()
        assert state['base_coverage']['instances']['local']['counts']['event:bus:transaction_response']
        assert any('coverage_context:' in feature for feature in state['discovery']['feature_counts'])
        assert canonical(state) == canonical(original.candidate_exploration_state())
    finally:
        transport.doCleanups()


def rewrite_receipts(output, mutate):
    path = output / 'receipts.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    mutate(rows)
    path.write_bytes(b''.join(canonical(row) + b'\n' for row in rows))
    identity_path = output / 'online_run_identity.json'
    envelope = json.loads(identity_path.read_bytes())
    envelope['identity']['artifacts']['receipts.jsonl'] = hashlib.sha256(path.read_bytes()).hexdigest()
    envelope['sha256'] = hashlib.sha256(canonical(envelope['identity'])).hexdigest()
    identity_path.write_bytes(canonical(envelope))
    report_path = output / 'report.json'
    report = json.loads(report_path.read_bytes())
    report['online_run_identity_sha256'] = envelope['sha256']
    report_path.write_bytes(canonical(report))


def test_replay_executes_fresh_sources_and_recomputes_each_budget_case(saved):
    output, original = saved
    fresh = []
    def factory():
        executor = configured(enabled=True, two_sources=True)
        fresh.append(executor)
        return executor
    result = replay(output, factory)
    assert result.matches, result.comparison.difference_context
    assert 'candidate_case_scoring' in result.verification_scope
    assert 'online_source_selection' in result.verification_scope
    assert len(fresh) == 1
    assert fresh[0].session.runner is not original.session.runner
    assert len(fresh[0].receipts) == 3
    assert fresh[0].candidate_exploration_state() == original.candidate_exploration_state()
    assert [r.online_weights for r in fresh[0].receipts] == [r.online_weights for r in original.receipts]
    assert fresh[0].session._finished


@pytest.mark.parametrize('field', ('candidate_energy', 'candidate_novelty',
                                  'non_candidate_new_energy', 'weights', 'source'))
def test_saved_scores_and_selection_are_comparisons_never_authority(saved, field):
    output, _ = saved
    def mutate(rows):
        if field == 'weights': rows[0]['online_weights']['local.pin'] += 1
        elif field == 'source': rows[0]['source_id'] = 'local.pin2' if rows[0]['source_id'] == 'local.pin' else 'local.pin'
        else: rows[0]['candidate_exploration'][field] = 1 - rows[0]['candidate_exploration'][field] if field != 'non_candidate_new_energy' else 10
    rewrite_receipts(output, mutate)
    fresh = []
    def factory():
        executor = configured(enabled=True, two_sources=True)
        fresh.append(executor)
        return executor
    with pytest.raises(ValueError, match='candidate.*(receipt|selection|scoring)'):
        replay(output, factory)
    assert not fresh or fresh[0].session._finished


def test_report_totals_are_recomputed_even_when_configuration_digest_matches(saved):
    output, _ = saved
    path = output / 'report.json'
    report = json.loads(path.read_bytes())
    report['candidate_exploration']['candidate_novelty'] += 1
    path.write_bytes(canonical(report))
    with pytest.raises(ValueError, match='candidate.*state'):
        replay(output, lambda: configured(enabled=True, two_sources=True))


def test_invalid_raw_input_rejected_before_factory(saved):
    output, _ = saved
    rewrite_receipts(output, lambda rows: rows[0].update(online_raw_records_hex=['not-hex']))
    factory = Mock(side_effect=AssertionError('must not create a runner'))
    with pytest.raises(ValueError, match='candidate.*raw'):
        replay(output, factory)
    factory.assert_not_called()


def test_changed_receipt_artifact_rejected_before_factory(saved):
    output, _ = saved
    path = output / 'receipts.jsonl'
    path.write_bytes(path.read_bytes() + b'{}\n')
    factory = Mock(side_effect=AssertionError('must not create a runner'))
    with pytest.raises(ValueError, match='artifact'):
        replay(output, factory)
    factory.assert_not_called()


def test_factory_configuration_mismatch_stops_before_case_commands(saved):
    output, _ = saved
    fresh = []
    def factory():
        executor = configured(enabled=True, two_sources=True, candidate_exploration_max_cases=10)
        fresh.append(executor)
        return executor
    with pytest.raises(ValueError, match='candidate.*configuration'):
        replay(output, factory)
    assert fresh[0].session.runner.local_ticks == {'local': 0}
    assert fresh[0].session._finished


def test_actual_session_checker_drift_cannot_hide_in_cached_begin_manifest(saved):
    output, _ = saved
    fresh = []
    def factory():
        executor = configured(enabled=True, two_sources=True)
        executor.session.checker = lambda receipt: ()
        fresh.append(executor)
        return executor
    with pytest.raises(ValueError, match='candidate.*(checker|manifest|configuration)'):
        replay(output, factory)
    assert fresh[0].session.runner.local_ticks == {'local': 0}
    assert fresh[0].session._finished


def _session_check(receipt):
    return ('session_checker_marker',)


def test_matching_actual_session_checker_is_reexecuted():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        original = configured(enabled=True, session_checker=_session_check)
        transport.run_transport(original)
        fresh = []
        def factory():
            executor = configured(enabled=True, session_checker=_session_check)
            fresh.append(executor)
            return executor
        result = replay(transport.output, factory)
        assert result.matches
        assert fresh[0].session.checker is _session_check
        assert fresh[0].receipts[0].violations == ('session_checker_marker',)
        assert fresh[0].receipts[0].status == 'dut_violation'
        assert fresh[0].session.runner.local_ticks == {'local': 1}
    finally:
        transport.doCleanups()


@pytest.mark.parametrize('field', ('closed_loop_energy', 'path_switch'))
def test_saved_switch_cannot_replace_boolean_with_equal_integer(saved, field):
    output, _ = saved
    identity_path = output / 'online_run_identity.json'
    envelope = json.loads(identity_path.read_bytes())
    envelope['identity']['run_config'][field] = 0
    envelope['sha256'] = hashlib.sha256(canonical(envelope['identity'])).hexdigest()
    identity_path.write_bytes(canonical(envelope))
    path = output / 'report.json'
    report = json.loads(path.read_bytes())
    report['online_run_identity_sha256'] = envelope['sha256']
    path.write_bytes(canonical(report))
    factory = Mock(side_effect=AssertionError('must not start a runner'))
    with pytest.raises(ValueError, match='candidate.*configuration'):
        replay(output, factory)
    factory.assert_not_called()


def test_used_executor_cannot_supply_replay_initial_state(saved):
    output, original = saved
    with pytest.raises(ValueError, match='candidate.*fresh'):
        replay(output, lambda: original)


@pytest.mark.parametrize('compressed', (False, True))
def test_refused_input_is_replayed_without_spending_case_energy(compressed):
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        original = configured(enabled=True)
        transport.run_transport(original, tests=((bytes(8), bytes(8)), (bytes(8),)),
                                compressed_trace=compressed)
        assert original.receipts[0].status == 'input_invalid'
        assert original.candidate_exploration_state()['cases'] == 1
        result = replay(transport.output, lambda: configured(enabled=True))
        assert result.matches
    finally:
        transport.doCleanups()


@pytest.mark.parametrize('policy', ('warm_all', 'cold_all'))
def test_reset_timeline_is_reexecuted_and_does_not_renew_novelty(policy):
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    def factory():
        executor = configured(enabled=True)
        local = executor.session.runner.sessions['local']
        def reset():
            local.reset_epoch += 1
            return {}
        local.reset_local = reset
        return executor
    try:
        original = factory()
        execute = original.execute_batch
        def execute_with_reset(batch, *, on_receipt=None):
            def observed(receipt):
                if on_receipt:
                    on_receipt(receipt)
                if len(original.receipts) == 1:
                    original.session.reset(policy)
            return execute(batch, on_receipt=observed)
        original.execute_batch = execute_with_reset
        transport.run_transport(original, tests=((bytes(8),), (bytes(8),)))
        assert original.online_decisions[1]['candidate_exploration']['candidate_novelty'] == 0
        assert json.loads((transport.output / 'online_plan.json').read_bytes())['schema_version'] == 14
        result = replay(transport.output, factory)
        assert result.matches
    finally:
        transport.doCleanups()


def test_deterministic_terminal_failure_replays_with_null_candidate_scoring():
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    def factory():
        return configured(enabled=True, change=lambda runner: setattr(
            runner.sessions['local'], 'error', 'physical receipt failure'))
    try:
        original = factory()
        transport.run_transport(original)
        assert original.receipts[0].status == 'environment_error'
        assert original.candidate_exploration_state()['cases'] == 0
        result = replay(transport.output, factory)
        assert result.matches
    finally:
        transport.doCleanups()


def test_replay_cleanup_error_does_not_mask_primary_configuration_error(saved):
    output, _ = saved
    fresh = []
    def factory():
        executor = configured(enabled=True, two_sources=True, candidate_exploration_max_cases=10)
        finish = executor.session.finish
        def failed_cleanup(**kwargs):
            finish(**kwargs)
            raise RuntimeError('cleanup receipt lost')
        executor.session.finish = failed_cleanup
        fresh.append(executor)
        return executor
    with pytest.raises(ValueError, match='candidate.*configuration') as failure:
        replay(output, factory)
    assert any('cleanup receipt lost' in note for note in failure.value.__notes__)
    assert fresh[0].session._finished


def test_actual_stateful_checker_configuration_survives_fresh_warmup():
    from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    def factory():
        executor = configured(enabled=True, session_checker=IbexPulpOnlineChecker(),
                              checker_configuration_only=True)
        executor.session.advance_initial(('local',))
        return executor
    try:
        original = factory()
        transport.run_transport(original)
        result = replay(transport.output, factory)
        assert result.matches, result.comparison.difference_context
    finally:
        transport.doCleanups()


def test_explicit_checker_configuration_drift_cannot_hide_in_cached_manifest():
    from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    def configured_checker():
        return configured(enabled=True, session_checker=IbexPulpOnlineChecker(),
                          checker_configuration_only=True)
    try:
        transport.run_transport(configured_checker())
        fresh = []
        def factory():
            executor = configured_checker()
            executor.session.checker.gpio_settle_ticks += 1
            fresh.append(executor)
            return executor
        with pytest.raises(ValueError, match='candidate.*configuration'):
            replay(transport.output, factory)
        assert fresh[0].session.runner.local_ticks == {'local': 0}
        assert fresh[0].session._finished
    finally:
        transport.doCleanups()


def test_fresh_replay_refuses_rehashed_functional_proof_from_legacy_target(saved):
    output, _ = saved
    def claim(rows):
        functional = rows[0]['interaction_feedback']['functional_coverage']
        functional['status'] = 'verified'
        functional['new_features'] = ['legacy_output_is_functional_completion']
    rewrite_receipts(output, claim)
    with pytest.raises(ValueError, match='candidate.*(receipt|selection|scoring)'):
        replay(output, lambda: configured(enabled=True, two_sources=True))
