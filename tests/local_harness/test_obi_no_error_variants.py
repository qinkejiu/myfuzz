"""The OBI contract variants for CPUs that have no bus-error pins.

OBI does not require an error channel.  Two CPUs in this repository declare OBI
endpoints with genuinely different shapes:

* ``ibex_obi_local`` declares an ``error`` role on both endpoints
  (``instr_err_i`` / ``data_err_i``);
* ``cv32e40p`` declares none, and says so twice - in its profile prose and in
  ``capabilities.evidence``: "It has no instr_err_i/data_err_i physical pins".
  A grep for those pins under ``third_party/`` finds them only in the Ibex vendor
  documentation.

Before the no-error variants existed, the second CPU matched no admitted
template at all, so P7 could not onboard a CPU that conforms to OBI but cannot
represent a bus error.  That is a gap in the contract set, not a defect in the
CPU, and these tests pin both halves of the fix:

* each CPU selects exactly one variant per endpoint - the selector *refuses*
  ambiguity, so a well-meant variant that also matched the error-capable
  endpoints would silently stop Ibex from matching;
* the variants carry the fail-stop policy, because this CPU physically cannot
  raise an error to its own pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import load_local_harness_request, plan_local_harness
from myfuzz.local_harness.template_contracts import (list_template_contracts,
                                                     select_template_contract)

ROOT = Path(__file__).resolve().parents[2]
CPUS = ('ibex_obi_local', 'cv32e40p')
MEMORY_ENDPOINTS = ('processor.instruction', 'processor.data')


def plan(component: str):
    request = {'schema_version': 'local_harness.v1',
               'profile_path': f'configs/cpus/{component}/component_profile.json',
               'instance_id': 'cpu', 'reset_assert_ticks': 2,
               'reset_release_ticks': 2, 'max_wait_cycles': 16}
    return plan_local_harness(load_local_harness_request(request), base_dir=ROOT)


def selection(component: str) -> dict:
    """``endpoint_id -> variant_id`` through the real production planner."""
    planned = plan(component)
    chosen = {}
    for endpoint in planned.binding.endpoints:
        if endpoint.endpoint_id not in MEMORY_ENDPOINTS:
            continue
        chosen[endpoint.endpoint_id] = select_template_contract(
            endpoint, planned.profile.capabilities).contract.variant_id
    return chosen


def variants(variant_id: str):
    return [row for row in list_template_contracts()
            if row.variant_id == variant_id]


def test_the_two_cpus_declare_opposite_error_capabilities():
    """The fact the variants discriminate on is really declared, not assumed."""
    caps = {}
    for component in CPUS:
        profile = load_component_profile(json.loads(
            (ROOT / f'configs/cpus/{component}/component_profile.json')
            .read_text(encoding='utf-8')))
        caps[component] = profile.capabilities.get('error_response')
    assert caps == {'ibex_obi_local': True, 'cv32e40p': False}


def test_each_cpu_selects_exactly_one_variant_per_endpoint():
    """No ambiguity: the selector refuses ambiguity, so this is the real check."""
    assert selection('ibex_obi_local') == {
        'processor.instruction': 'read-only',
        'processor.data': 'read-write'}
    assert selection('cv32e40p') == {
        'processor.instruction': 'read-only-no-error-pins',
        'processor.data': 'read-write-no-error-pins'}


def test_the_no_error_variants_bind_the_declared_capability():
    """A limit alone would not discriminate, so the fact is required."""
    for endpoint_id, variant_id in (('processor.instruction',
                                     'read-only-no-error-pins'),
                                    ('processor.data',
                                     'read-write-no-error-pins')):
        contract, = variants(variant_id)
        facts = dict(contract.required_profile_facts)
        assert facts.get('error_response') is False, (
            f'{variant_id} must require the declared error_response fact, or it '
            'would also match an error-capable endpoint')
        limits = dict(contract.limits)
        assert limits['error_response'] is False
        assert limits['error_policy'] == (
            'cpu_cannot_represent_a_bus_error_adapter_must_fail_stop')
        assert 'error' not in contract.required_roles
        assert 'error' not in contract.optional_roles


def test_the_error_capable_variants_are_unchanged():
    """The fix must not have relaxed the variants Ibex depends on."""
    for variant_id in ('read-only', 'read-write'):
        contract, = variants(variant_id)
        assert 'error' in contract.required_roles
        assert dict(contract.limits)['error_response'] is True
        assert dict(contract.limits)['error_policy'] == 'propagate_error'


def test_a_no_error_variant_does_not_match_an_error_capable_endpoint():
    """The discriminator works, and by two independent mechanisms."""
    from myfuzz.local_harness.template_contracts import _match

    planned = plan('ibex_obi_local')
    endpoint = next(row for row in planned.binding.endpoints
                    if row.endpoint_id == 'processor.data')
    contract, = variants('read-write-no-error-pins')
    # Mechanism 1.  This endpoint declares a role the no-error variant does not
    # admit, so the role check rejects it.
    with pytest.raises(ValueError) as raised:
        _match(contract, endpoint, planned.profile.capabilities, False)
    assert 'template-missing-or-unknown-roles' in str(raised.value)


def test_only_the_declared_fact_separates_the_two_read_write_variants():
    """The no-error variant must state its precondition, not assume it.

    The role set is what actually separates the pairs on the two CPUs in this
    repository (``read-write`` requires an ``error`` role, this one does not).
    The required fact does a different job: ``_match`` only compares a limit
    against the capability when the profile *declares* that capability, so
    without the fact a CPU that merely omits ``error_response`` would match the
    no-error variant silently.  Requiring it turns "we did not say" into a
    refusal.
    """
    from myfuzz.local_harness.template_contracts import _match

    planned = plan('cv32e40p')
    endpoint = next(row for row in planned.binding.endpoints
                    if row.endpoint_id == 'processor.data')
    no_error, = variants('read-write-no-error-pins')
    capable, = variants('read-write')

    # Declaring the opposite capability is rejected by the required fact...
    with pytest.raises(ValueError) as raised:
        _match(no_error, endpoint,
               {**planned.profile.capabilities, 'error_response': True}, False)
    assert 'template-profile-fact-mismatch:error_response' in str(raised.value)

    # ...and omitting the capability entirely is refused too, which is the part a
    # limit-only variant could not do.
    omitted = {key: value for key, value in planned.profile.capabilities.items()
               if key != 'error_response'}
    with pytest.raises(ValueError) as raised:
        _match(no_error, endpoint, omitted, False)
    assert 'template-profile-fact-mismatch:error_response' in str(raised.value)

    # With its own declared capability it matches...
    assert _match(no_error, endpoint, planned.profile.capabilities,
                  False)['protocol'] == ['obi', '1']
    # ...and the error-capable variant does not want this endpoint at all, so the
    # role sets really do discriminate the two pairs.
    endpoint_roles = {row.role for row in endpoint.fields}
    assert 'error' not in endpoint_roles
    assert 'error' in capable.required_roles
    assert 'error' not in no_error.required_roles
