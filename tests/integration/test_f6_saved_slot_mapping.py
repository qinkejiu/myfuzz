"""Archived F6 slot-map joins stay shared for limited-authority CPUs.

The saved slot map is an independent archived fact: it is derived from the
attempt and the compiled program contract, never from the live issuer's
successor claim.  These tests pin that the limited-authority projection reuses
the same map and window as every other CPU.
"""
from copy import deepcopy

import pytest

from myfuzz.integration.f6_saved_slot_mapping import saved_slot_mapping
from tests.integration import test_compiled_f6_saved_semantics as legacy
from tests.integration.test_f6_saved_limited_rvfi import (
    build_full_archive, build_limited_archive, physical, project, return_row,
    take_row)


@pytest.fixture(scope='module')
def full_archive():
    return build_full_archive()


@pytest.fixture
def limited_archive(full_archive):
    return build_limited_archive(full_archive)


def rows(archive, kind):
    return [row for row in archive['events'] if row.get('kind') == kind]


def test_single_slot_mapping_is_the_logical_attempt_index(limited_archive):
    contract = deepcopy(limited_archive['contract'])
    contract['program_contract'].pop('shared_slots', None)
    for index in (0, 1, 3):
        attempt = dict(case_id='run:case:' + str(index), case_index=index)
        before = deepcopy(attempt)
        mapping = saved_slot_mapping(attempt, contract, [], None)
        assert mapping['slot_index'] == index
        assert mapping['session_case_index'] == index
        assert mapping['previous_case'] == (
            dict(case_id='run:case:' + str(index - 1), case_index=index - 1)
            if index else None)
        assert attempt == before


def test_shared_slot_contract_still_requires_independent_context(limited_archive):
    contract = deepcopy(limited_archive['contract'])
    contract['program_contract']['shared_slots'] = dict(
        enabled_flows=['F6'], component='shared_storage')
    attempt = dict(case_id=limited_archive['attempt']['case_id'],
        case_index=limited_archive['attempt']['case_index'])
    with pytest.raises(ValueError) as failure:
        saved_slot_mapping(attempt, contract, limited_archive['events'], None)
    assert 'saved-shared-slot-independent-plan-and-ledger-required' in str(
        failure.value)


def test_limited_projection_returns_inside_the_mapped_slot_window(limited_archive):
    contract, attempt = limited_archive['contract'], limited_archive['attempt']
    program = contract['program_contract']
    mapping = saved_slot_mapping(attempt, contract, limited_archive['events'], None)
    slot = program['slot_base'] + program['slot_bytes'] * mapping['slot_index']
    successor = physical(limited_archive, return_row(limited_archive)
        ['successor_local_tick'])
    result = project(limited_archive)
    assert result['outcome'] == 'passed', result['details'].get('issues')
    # The first successor is inside the same dynamic window the map selects.
    assert slot <= successor['rvfi_pc_rdata'] < slot + program['online_prefix_bytes'] + 8
    assert result['details']['return_target'] == successor['rvfi_pc_rdata']
    # It is the immediately following retirement of the fixed MRET.
    mret = physical(limited_archive, return_row(limited_archive)['local_tick'])
    assert successor['rvfi_order'] == mret['rvfi_order'] + 1


def test_slot_window_refusal_is_the_mapped_window_not_a_saved_claim(limited_archive):
    archive = deepcopy(limited_archive)
    program = archive['contract']['program_contract']
    returned = return_row(archive)
    slot = program['slot_base'] + program['slot_bytes'] * archive['attempt']['case_index']
    outside = slot + program['slot_bytes']
    for row in rows(archive, 'local_tick_sample'):
        if (row.get('local_tick') == returned['successor_local_tick']
                and row.get('phase') == 'post'
                and row.get('component') == archive['contract']['cpu']['instance_id']):
            row['outputs']['physical']['rvfi_pc_rdata'] = outside
    returned['successor_pc_rdata'] = outside
    returned['return_target'] = outside
    legacy.refresh(archive)
    result = project(archive)
    assert result['outcome'] == 'failed', result['details'].get('issues')
    assert any('not the current dynamic return' in issue['reason']
        for issue in result['details']['issues'])
