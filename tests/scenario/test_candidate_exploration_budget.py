"""D8 budgets rank already legal sources; they never certify dependencies."""
import pytest


def budget(**kwargs):
    from myfuzz.scenario.candidate_exploration import CandidateExplorationBudget
    return CandidateExplorationBudget(legal_sources=('a', 'b'),
        feature_sources={'pair:value_match': 'b', 'pair:receipt_window': 'a'}, **kwargs)


def observe(policy, case='case', features=('pair:value_match',), energy=10, weights=None):
    return policy.observe_case(case_id=case, new_features=features,
        non_candidate_new_energy=energy, weights={'a': 100, 'b': 100} if weights is None else weights)


def test_candidate_channel_defaults_off_and_keeps_weights_exactly():
    policy = budget()
    answer = observe(policy)
    assert answer['candidate_novelty'] == 0 and answer['candidate_energy'] == 0
    assert policy.apply_weights({'a': 100, 'b': 100}) == {'a': 100, 'b': 100}
    assert policy.configuration()['enabled'] is False


def test_one_case_credits_at_most_one_novelty_and_one_energy_unit():
    policy = budget(enabled=True)
    answer = observe(policy, features=('pair:value_match', 'pair:receipt_window'), energy=100)
    assert answer['candidate_novelty'] == 1 and answer['candidate_energy'] == 1
    assert sum(policy.apply_weights({'a': 100, 'b': 100}).values()) == 201
    assert answer['proof_scope'] == 'legal_source_exploration_only'
    assert answer['grants_prerequisites'] is False


@pytest.mark.parametrize('energy', [0, 1, 9, 10, 11, 100])
def test_candidate_energy_is_bounded_by_ten_percent_of_new_non_candidate_energy(energy):
    policy = budget(enabled=True)
    answer = observe(policy, energy=energy)
    assert answer['candidate_novelty'] == 1
    assert answer['candidate_energy'] <= energy // 10
    assert answer['candidate_energy'] == int(energy >= 10)


def test_session_dedup_never_recredits_even_if_caller_reoffers_evicted_feature():
    policy = budget(enabled=True)
    assert observe(policy)['candidate_energy'] == 1
    answer = observe(policy, case='after-eviction')
    assert answer['candidate_novelty'] == 0 and answer['candidate_energy'] == 0
    assert policy.apply_weights({'a': 100, 'b': 100})['b'] == 101


def test_all_features_observed_in_one_case_are_spent_even_if_only_one_credited():
    policy = budget(enabled=True)
    observe(policy, features=('pair:value_match', 'pair:receipt_window'))
    assert observe(policy, case='later', features=('pair:receipt_window',))['candidate_novelty'] == 0
    assert observe(policy, case='latest')['candidate_novelty'] == 0


def test_same_case_is_idempotent_but_changed_case_content_is_rejected():
    policy = budget(enabled=True)
    first = observe(policy)
    assert observe(policy) == first
    first.clear()
    assert observe(policy)['candidate_energy'] == 1
    with pytest.raises(ValueError, match='case identity'):
        observe(policy, energy=20)
    assert policy.apply_weights({'a': 100, 'b': 100})['b'] == 101


def test_unknown_feature_and_illegal_weight_keys_fail_before_spending_novelty():
    policy = budget(enabled=True)
    with pytest.raises(ValueError):
        observe(policy, features=('unknown',))
    with pytest.raises(ValueError):
        observe(policy, weights={'a': 100, 'illegal': 100})
    assert observe(policy)['candidate_energy'] == 1


def test_saturated_source_cannot_claim_unapplied_candidate_energy():
    policy = budget(enabled=True)
    answer = observe(policy, weights={'a': 100, 'b': 65536})
    assert answer['candidate_novelty'] == 1 and answer['candidate_energy'] == 0
    assert policy.apply_weights({'a': 100, 'b': 65536})['b'] == 65536


def test_case_capacity_rejects_without_evicting_session_dedup():
    policy = budget(enabled=True, max_cases=1)
    first = observe(policy)
    with pytest.raises(ValueError, match='capacity'):
        observe(policy, case='next', features=('pair:receipt_window',))
    assert observe(policy) == first


def test_configuration_identity_is_detached_and_changes_with_opt_in():
    disabled, enabled = budget(), budget(enabled=True)
    assert disabled.configuration_sha256 != enabled.configuration_sha256
    config = enabled.configuration()
    config['feature_sources']['pair:value_match'] = 'illegal'
    assert enabled.configuration()['feature_sources']['pair:value_match'] == 'b'
    assert enabled.configuration_sha256 == budget(enabled=True).configuration_sha256


@pytest.mark.parametrize('changes', [dict(enabled=1), dict(max_cases=True), dict(max_cases=0)])
def test_configuration_rejects_non_boolean_switch_and_invalid_capacity(changes):
    with pytest.raises(ValueError):
        budget(**changes)


@pytest.mark.parametrize('energy', [True, -1, 65537, 10.0])
def test_invalid_case_energy_does_not_spend_feature_or_reserve_case(energy):
    policy = budget(enabled=True)
    with pytest.raises(ValueError):
        observe(policy, energy=energy)
    assert observe(policy)['candidate_energy'] == 1
