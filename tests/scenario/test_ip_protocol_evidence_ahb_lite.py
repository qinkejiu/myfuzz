"""AHB-Lite boundary receipts authenticate an address/data phase pair."""
from copy import deepcopy

from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer


_WIDTHS = {'haddr': 32, 'hwdata': 32, 'hsel': 1, 'hwrite': 1,
           'hreadyin': 1, 'htrans': 2, 'hsize': 3, 'hresp': 1,
           'hreadyout': 1, 'hrdata': 32}
_TRACE = {'schema_version': 'ip_protocol_trace.v1', 'protocol': 'ahb-lite',
          'endpoint_id': 'sha256.bus', 'clock_domain': 'core',
          'max_wait_cycles': 4,
          'signals': {role: 'tap_' + role for role in _WIDTHS},
          'signal_widths': dict(_WIDTHS)}
_CONFIG = {'sha': {'component_id': 'caliptra_sha256', 'instance_id': 'sha',
                   'protocol_trace': _TRACE}}


def _journal(*, corrupt_response=False):
    projector = IpProtocolEventNormalizer(**_CONFIG['sha'])
    rows = []
    next_id = 1
    for tick, values in enumerate((
            {'hsel': 1, 'htrans': 2, 'hwrite': 1, 'haddr': 0x80},
            {'hwdata': 0x12345678},
            {'hsel': 1, 'htrans': 2, 'haddr': 0x00},
            {'hrdata': 0x43414c49}), 1):
        signals = {role: 0 for role in _WIDTHS}
        signals.update(hsize=2, hreadyin=1, hreadyout=1)
        signals.update(values)
        raw = {'event_id': next_id, 'kind': 'local_tick_sample',
               'component': 'sha', 'local_tick': tick, 'phase': 'pre',
               'reset_epoch': 0,
               'observation_schema_version': 'ip_raw_observation.v1',
               'provenance': {'observed_case': {'case_id': 'case-1',
                                                'case_index': 0}},
               'outputs': {'backend': {'tap_' + role: value
                                       for role, value in signals.items()}}}
        rows.append(raw)
        next_id += 1
        for projected in projector.consume_local_tick(raw, reset_epoch=0):
            projected = deepcopy(projected)
            projected['event_id'] = next_id
            projected['kind'] = projected['event_type']
            if corrupt_response and projected['event_type'] == 'transaction_response':
                projected['payload']['value'] ^= 1
                corrupt_response = False
            rows.append(projected)
            next_id += 1
    return rows


def test_ahb_address_data_pairs_certify_from_raw_and_projected_events():
    proof = IpProtocolEvidenceConsumer(_CONFIG, runtime_contract_sha256='a' * 64)
    for row in _journal():
        proof.consume(row)
    report = proof.report()
    assert report['counts'] == {'verified': 2, 'pending': 0}
    assert [row['outcome'] for row in report['certificates']] == ['ok', 'ok']
    assert all(row['identity_gap'] == 'protocol_has_no_transaction_id'
               for row in report['certificates'])


def test_ahb_forged_response_value_cannot_certify():
    proof = IpProtocolEvidenceConsumer(_CONFIG, runtime_contract_sha256='a' * 64)
    for row in _journal(corrupt_response=True):
        proof.consume(row)
    report = proof.report()
    assert report['certificates'] == []
    assert report['diagnostics']['projection_mismatch'] >= 1
