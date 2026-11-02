"""The case's post-park settle window stays under the real OBI wait bound.

No RTL is started: this feeds synthetic pre-edge samples through the same
``IpProtocolChecker`` the runner installs on an OBI CPU trace.
"""
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker


def _trace(max_wait):
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': 'obi',
        'endpoint_id': 'processor.instruction',
        'clock_domain': 'core',
        'max_wait_cycles': max_wait,
        'max_outstanding': 1,
        'sample_group': 'protocol_taps',
        'signals': {'req': 'req', 'gnt': 'gnt', 'addr': 'addr',
                    'rvalid': 'rvalid', 'rdata': 'rdata',
                    'we': 'we', 'wdata': 'wdata', 'be': 'be', 'error': 'error'},
        'signal_widths': {'req': 1, 'gnt': 1, 'addr': 32, 'rvalid': 1,
                          'rdata': 32, 'we': 1, 'wdata': 32, 'be': 4, 'error': 1},
    }


def _sample(event_id, tick, *, addr, req, gnt, rvalid=0, rdata=0):
    return {'event_id': event_id, 'kind': 'local_tick_sample',
            'local_tick': tick, 'phase': 'pre',
            'outputs': {'protocol_taps': {
                'req': req, 'gnt': gnt, 'addr': addr, 'rvalid': rvalid,
                'rdata': rdata, 'we': 0, 'wdata': 0, 'be': 15, 'error': 0}}}


def _findings(max_wait, held):
    checker = IpProtocolChecker(component_id='cpu', instance_id='processor',
                                protocol_trace=_trace(max_wait))
    rows = []
    event_id = 0
    # One granted fetch whose response is withheld, plus the next offer.
    event_id += 1
    rows += checker.consume_local_tick(
        _sample(event_id, 1, addr=0x100A0, req=1, gnt=1), reset_epoch=0)
    for offset in range(1, held + 1):
        event_id += 1
        rows += checker.consume_local_tick(
            _sample(event_id, 1 + offset, addr=0x100A4, req=1, gnt=0),
            reset_epoch=0)
    return rows


def test_twelve_tick_settle_window_is_not_a_violation():
    codes = [row['payload']['violation_code'] for row in _findings(16, 12)]
    assert not [code for code in codes if code.endswith('_wait_budget_exceeded')]


def test_a_hold_past_the_declared_bound_is_reported():
    rows = _findings(16, 17)
    codes = [row['payload']['violation_code'] for row in rows]
    assert 'obi_response_wait_budget_exceeded' in codes
    assert 'obi_request_wait_budget_exceeded' in codes
    assert all(row['payload']['wait_cycles'] >= 16 for row in rows
               if row['payload']['violation_code'].endswith('_wait_budget_exceeded'))


def test_small_bound_still_keeps_a_margin():
    # fragment_boundary_park uses min(max(1, bound - 4), 12): 8 -> 4.
    codes = [row['payload']['violation_code'] for row in _findings(8, 4)]
    assert not [code for code in codes if code.endswith('_wait_budget_exceeded')]
