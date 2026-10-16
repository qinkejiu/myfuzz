"""Archived JSON cannot supply live CPU→IP handoff authority."""
from copy import deepcopy
from myfuzz.scenario.cpu_ip_protocol_join import archive_join_gap_report


def fixture():
    key=dict(execution_id='same-run',testcase_id='case',source_component='new-cpu',
        source_epoch=0,channel_id='data',source_sequence=1)
    return [dict(event_id=1,kind='mmio_acceptance',component='new-cpu',source_transaction=key),
        dict(event_id=2,kind='mmio_delivery',component='new-cpu',source_transaction=deepcopy(key))]


def test_matching_key_is_only_candidate_without_native_taps_and_live_seal():
    report=archive_join_gap_report(fixture(),source_component='new-cpu',target_components=('new-ip',),origin_ref='archive-sha256')
    assert report['status']=='gap' and not report['grants_verified']
    assert 'missing_live_handoff_authority' in report['missing_links']
    assert 'missing_cpu_raw_obi_taps' in report['missing_links']
    assert report['router_pair_candidates'][0]['status']=='matching_declared_host_key_only'


def test_changed_source_sequence_does_not_join_by_address_or_nearby_tick():
    rows=fixture();rows[1]['source_transaction']['source_sequence']=2
    report=archive_join_gap_report(rows,source_component='new-cpu',target_components=('new-ip',),origin_ref='archive-sha256')
    assert 'router_key_not_unique_or_missing' in report['missing_links']
    assert report['router_pair_candidates'][0]['delivery_event_refs']==[]


def test_cross_execution_key_does_not_join():
    rows=fixture();rows[1]['source_transaction']['execution_id']='other-run'
    report=archive_join_gap_report(rows,source_component='new-cpu',target_components=('new-ip',),origin_ref='archive-sha256')
    assert report['router_pair_candidates'][0]['status']=='gap'


def test_duplicate_delivery_keys_are_ambiguous():
    rows=fixture();rows.append(deepcopy(rows[1]));rows[-1]['event_id']=3
    report=archive_join_gap_report(rows,source_component='new-cpu',target_components=('new-ip',),origin_ref='archive')
    assert report['router_pair_candidates'][0]['status']=='gap'
    assert 'router_key_not_unique_or_missing' in report['missing_links']


def test_record_bound_is_strict():
    import pytest
    for value in (0,257,True,1.0):
        with pytest.raises(ValueError,match='bound-invalid'):
            archive_join_gap_report([],source_component='cpu',target_components=('gpio',),origin_ref='archive',max_records=value)
