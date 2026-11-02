from copy import deepcopy

import pytest


def _trace(endpoint_id, endpoint_role, prefix, *, master=False):
    roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'stall', 'ack', 'dat_r')
    widths = {'cyc': 1, 'stb': 1, 'we': 1,
              'adr': 30 if master else 2, 'dat_w': 32,
              'stall': 1, 'ack': 1, 'dat_r': 32}
    if master:
        roles += ('err',)
        widths['err'] = 1
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': 'wishbone',
        'endpoint_id': endpoint_id,
        'endpoint_role': endpoint_role,
        'clock_domain': 'core',
        'reset_domain': 'sys_rst',
        'max_wait_cycles': 3,
        'max_outstanding': 1,
        'same_edge_accept_completion': False,
        'signals': {role: prefix + '_' + role for role in roles},
        'signal_widths': widths,
        'sample_group': 'backend',
        'byte_enable': ({'signal': 'absent', 'partial_write': False,
                         'fixed_value': 15,
                         'basis': 'profile.capabilities.master_fixed_byte_enable'}
                        if master else
                        {'signal': 'absent', 'partial_write': False}),
    }


def _contract():
    return {
        'schema_version': 'wishbone_dma_protocol_checker.v1',
        'sampling': 'pre_post',
        'sample_group': 'backend',
        'traces': [
            _trace('dma.control', 'control_target', 'swb'),
            _trace('dma.memory', 'memory_master', 'mwb', master=True),
        ],
    }


def _raw(event_id, tick, **updates):
    backend = {
        'swb_cyc': 0, 'swb_stb': 0, 'swb_we': 0, 'swb_adr': 0,
        'swb_dat_w': 0, 'swb_stall': 0, 'swb_ack': 0, 'swb_dat_r': 0,
        'mwb_cyc': 0, 'mwb_stb': 0, 'mwb_we': 0, 'mwb_adr': 0,
        'mwb_dat_w': 0, 'mwb_stall': 0, 'mwb_ack': 0, 'mwb_dat_r': 0,
        'mwb_err': 0,
    }
    backend.update(updates)
    return {
        'event_id': event_id, 'kind': 'local_tick_sample', 'component': 'dma',
        'local_tick': tick, 'phase': 'pre',
        'outputs': {'backend': backend},
    }


def _checker():
    from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
    return WishboneDmaProtocolChecker(component_id='zipcpu_wbdmac',
        instance_id='dma', trace_set=_contract())


def test_dual_endpoint_checker_counts_the_same_real_pre_sample_and_reports_scope():
    checker = _checker()

    findings = checker.consume_local_tick(_raw(17, 4), reset_epoch=2)

    assert findings == ()
    report = checker.report()
    assert report['schema_version'] == 'wishbone_dma_protocol_checker_report.v1'
    assert report['status'] == 'clean'
    assert report['installed_endpoint_ids'] == ['dma.control', 'dma.memory']
    assert report['pre_sample_counts'] == {'dma.control': 1, 'dma.memory': 1}
    assert report['findings'] == []
    assert report['pending'] == {
        'dma.control': {'offers': 0, 'outstanding': 0},
        'dma.memory': {'offers': 0, 'outstanding': 0},
    }
    assert all(row['last_raw_sample_event_id'] == 17
               for row in report['endpoints'])


def test_checker_requires_explicit_no_select_full_word_contract_without_fabricating_sel():
    contract = _contract()
    target = contract['traces'][0]
    del target['byte_enable']
    with pytest.raises(ValueError, match='byte-enable-contract'):
        from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
        WishboneDmaProtocolChecker(component_id='zipcpu_wbdmac',
            instance_id='dma', trace_set=contract)

    contract = _contract()
    contract['traces'][1]['signals']['sel'] = 'mwb_sel'
    contract['traces'][1]['signal_widths']['sel'] = 4
    with pytest.raises(ValueError, match='wishbone-no-select-shape'):
        from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
        WishboneDmaProtocolChecker(component_id='zipcpu_wbdmac',
            instance_id='dma', trace_set=contract)


def test_checker_requires_both_distinct_endpoint_roles_and_reports_missing_samples():
    contract = _contract()
    contract['traces'][1]['endpoint_id'] = contract['traces'][0]['endpoint_id']
    with pytest.raises(ValueError, match='dual-endpoint-identity'):
        from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
        WishboneDmaProtocolChecker(component_id='zipcpu_wbdmac',
            instance_id='dma', trace_set=contract)

    report = _checker().report()
    assert report['status'] == 'incomplete'
    assert report['pre_sample_counts'] == {'dma.control': 0, 'dma.memory': 0}


def test_master_stall_payload_change_is_reported_with_endpoint_and_raw_sample():
    checker = _checker()
    assert checker.consume_local_tick(_raw(20, 8,
        mwb_cyc=1, mwb_stb=1, mwb_we=1, mwb_adr=4,
        mwb_dat_w=0x1234, mwb_stall=1), reset_epoch=0) == ()

    findings = checker.consume_local_tick(_raw(23, 9,
        mwb_cyc=1, mwb_stb=1, mwb_we=1, mwb_adr=8,
        mwb_dat_w=0x1234, mwb_stall=1), reset_epoch=0)

    assert [row['payload']['violation_code'] for row in findings] == [
        'wishbone_request_changed_while_stalled']
    report = checker.report()
    assert report['status'] == 'violation'
    assert report['findings'][0]['endpoint_id'] == 'dma.memory'
    assert report['findings'][0]['raw_event_id'] == 23


def test_run3_read_stall_ignores_only_invalid_write_data():
    checker = _checker()
    rows = [
        _raw(3902,242,mwb_cyc=1,mwb_stb=1,mwb_we=0,mwb_adr=34816,
             mwb_dat_w=1,mwb_stall=0,mwb_ack=0),
        _raw(3927,243,mwb_cyc=1,mwb_stb=1,mwb_we=0,mwb_adr=34817,
             mwb_dat_w=1,mwb_stall=1,mwb_ack=1,mwb_dat_r=5),
        _raw(3950,244,mwb_cyc=1,mwb_stb=1,mwb_we=0,mwb_adr=34817,
             mwb_dat_w=0,mwb_stall=0,mwb_ack=0),
    ]
    assert [checker.consume_local_tick(row, reset_epoch=0) for row in rows] == [(),(),()]
    assert checker.report()['pending']['dma.memory']['outstanding'] == 1


@pytest.mark.parametrize('changed', [
    {'mwb_adr':34818}, {'mwb_we':1},
])
def test_read_stall_still_rejects_address_or_direction_change(changed):
    checker = _checker()
    checker.consume_local_tick(_raw(20, 8, mwb_cyc=1,mwb_stb=1,mwb_we=0,
        mwb_adr=34817,mwb_dat_w=1,mwb_stall=1), reset_epoch=0)
    signals = dict(mwb_cyc=1,mwb_stb=1,mwb_we=0,mwb_adr=34817,
                   mwb_dat_w=0,mwb_stall=0)
    signals.update(changed)
    findings = checker.consume_local_tick(_raw(21, 9, **signals), reset_epoch=0)
    assert 'wishbone_request_changed_while_stalled' in [f['payload']['violation_code'] for f in findings]


def test_write_stall_still_rejects_write_data_change():
    checker = _checker()
    checker.consume_local_tick(_raw(20, 8, mwb_cyc=1,mwb_stb=1,mwb_we=1,
        mwb_adr=4,mwb_dat_w=1,mwb_stall=1), reset_epoch=0)
    findings = checker.consume_local_tick(_raw(21, 9, mwb_cyc=1,mwb_stb=1,mwb_we=1,
        mwb_adr=4,mwb_dat_w=0,mwb_stall=0), reset_epoch=0)
    assert 'wishbone_request_changed_while_stalled' in [f['payload']['violation_code'] for f in findings]


def test_master_orphan_err_and_response_from_old_reset_epoch_are_rejected():
    checker = _checker()
    orphan = checker.consume_local_tick(_raw(31, 1,
        mwb_cyc=1, mwb_err=1), reset_epoch=4)
    assert [row['payload']['violation_code'] for row in orphan] == [
        'wishbone_response_without_request']

    checker = _checker()
    checker.consume_local_tick(_raw(32, 1,
        mwb_cyc=1, mwb_stb=1, mwb_we=0, mwb_adr=0), reset_epoch=4)
    checker.consume_local_tick(_raw(33, 2), reset_epoch=5)
    stale = checker.consume_local_tick(_raw(34, 3,
        mwb_cyc=1, mwb_ack=1), reset_epoch=5)
    assert [row['payload']['violation_code'] for row in stale] == [
        'wishbone_response_without_request']


def test_single_outstanding_contract_is_enforced_and_pending_state_blocks_clean_status():
    checker = _checker()
    checker.consume_local_tick(_raw(40, 1,
        mwb_cyc=1, mwb_stb=1, mwb_we=0, mwb_adr=0), reset_epoch=0)
    overlap = checker.consume_local_tick(_raw(41, 2,
        mwb_cyc=1, mwb_stb=1, mwb_we=0, mwb_adr=1), reset_epoch=0)

    assert 'wishbone_single_outstanding_overlap' in [
        row['payload']['violation_code'] for row in overlap]
    assert checker.report()['status'] == 'violation'

    checker = _checker()
    checker.consume_local_tick(_raw(42, 1,
        mwb_cyc=1, mwb_stb=1, mwb_we=0, mwb_adr=0), reset_epoch=0)
    report = checker.report()
    assert report['status'] == 'incomplete'
    assert report['pending']['dma.memory']['outstanding'] == 1


def test_report_rejects_finding_cursor_past_current_finding_count():
    checker = _checker()
    with pytest.raises(ValueError, match='snapshot-invalid'):
        checker.report(since={
            'pre_sample_counts': {'dma.control': 0, 'dma.memory': 0},
            'finding_count': 1,
        })
