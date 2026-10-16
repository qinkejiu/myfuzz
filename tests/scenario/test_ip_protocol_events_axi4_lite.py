"""Generic-protocol projection for a real AXI4-Lite slave endpoint.

The other three admitted generic protocols (``tl-ul``, ``apb3``, ``wishbone``)
already project declared per-edge taps into ``ip_base_event.v1``.  AXI4-Lite is
the fourth and the only one whose request is split across two channels that may
handshake in either order, so these tests pin the channel semantics instead of
assuming a fixed AW-then-W sequence:

* a write is *accepted* only once both AW and W have handshaken, in any order;
* a write *responds* only when B has handshaken, and only after that accept;
* a read is accepted by the AR handshake and responds on R;
* reset with a transaction in flight cancels it in the old reset epoch;
* a stalled channel inside the wait budget is an observation, not a timeout.
"""
from __future__ import annotations

import importlib
import unittest


#: The 19 roles a real AXI4-Lite slave endpoint declares.  Kept literal here so
#: the test fails if the admitted role set silently changes.
AXI4_LITE_ROLES = (
    'awvalid', 'awready', 'awaddr', 'awprot',
    'wvalid', 'wready', 'wdata', 'wstrb',
    'bvalid', 'bready', 'bresp',
    'arvalid', 'arready', 'araddr', 'arprot',
    'rvalid', 'rready', 'rdata', 'rresp',
)
WIDTHS = {
    'awvalid': 1, 'awready': 1, 'awaddr': 32, 'awprot': 3,
    'wvalid': 1, 'wready': 1, 'wdata': 32, 'wstrb': 4,
    'bvalid': 1, 'bready': 1, 'bresp': 2,
    'arvalid': 1, 'arready': 1, 'araddr': 32, 'arprot': 3,
    'rvalid': 1, 'rready': 1, 'rdata': 32, 'rresp': 2,
}
#: Every role except the payload fields is a single-bit handshake or code.
BOOLEAN_ROLES = frozenset(role for role, width in WIDTHS.items() if width == 1)


def normalizer_type():
    module = importlib.import_module('myfuzz.scenario.ip_protocol_events')
    normalizer = getattr(module, 'IpProtocolEventNormalizer', None)
    if normalizer is None:
        raise AssertionError('component-neutral IP protocol event normalizer is missing')
    return normalizer


def axi4_lite_trace(*, endpoint='uart.bus', max_wait=2):
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': 'axi4-lite',
        'endpoint_id': endpoint,
        'clock_domain': 'sys_clk',
        'max_wait_cycles': max_wait,
        'signals': {role: 'trace_' + role for role in AXI4_LITE_ROLES},
        'signal_widths': {role: WIDTHS[role] for role in AXI4_LITE_ROLES},
    }


class Axi4LiteProjectionTests(unittest.TestCase):
    def normalizer(self, *, max_wait=2):
        return normalizer_type()(
            component_id='zipcpu_axiluart', instance_id='uart0',
            protocol_trace=axi4_lite_trace(max_wait=max_wait))

    @staticmethod
    def idle():
        return {role: 0 for role in AXI4_LITE_ROLES}

    @staticmethod
    def raw(normalizer, tick, **drive):
        """One pre-edge sample carrying only the roles named in ``drive``."""
        signals = Axi4LiteProjectionTests.idle()
        unknown = set(drive) - set(AXI4_LITE_ROLES)
        if unknown:
            raise AssertionError('unknown AXI4-Lite roles: ' + ','.join(sorted(unknown)))
        signals.update(drive)
        return {
            'event_id': tick, 'kind': 'local_tick_sample',
            'component': 'uart0', 'local_tick': tick, 'phase': 'pre',
            'outputs': {'backend': {normalizer._signals[role]: value
                                    for role, value in signals.items()}},
        }

    def types(self, events):
        return [event['event_type'] for event in events]

    def feed(self, normalizer, tick, *, epoch=0, **drive):
        return normalizer.consume_local_tick(self.raw(normalizer, tick, **drive),
                                             reset_epoch=epoch)

    # -- contract ---------------------------------------------------------
    def test_admitted_role_set_is_the_declared_slave_endpoint(self):
        normalizer = self.normalizer()
        self.assertEqual('axi4-lite', normalizer.protocol)
        self.assertEqual(set(AXI4_LITE_ROLES), set(normalizer._signals))

    def test_rejects_unknown_protocol_role_in_trace(self):
        broken = axi4_lite_trace()
        broken['signals'].pop('bresp')
        with self.assertRaisesRegex(ValueError, 'trace-signals-invalid'):
            normalizer_type()(component_id='zipcpu_axiluart',
                              instance_id='uart0', protocol_trace=broken)

    # -- write channel ----------------------------------------------------
    def test_write_address_then_data_accepts_write_once_then_b_responds(self):
        normalizer = self.normalizer()
        self.assertEqual((), self.feed(normalizer, 1))
        # AW handshakes alone: the write is offered but not yet accepted.
        offered = self.feed(normalizer, 2, awvalid=1, awready=1, awaddr=0x40000)
        self.assertEqual(['transaction_request'], self.types(offered))
        # The write group is named as a pair: neither channel alone is a write.
        self.assertEqual('aw+w', offered[0]['native_identity']['channel'])
        # W handshakes on a later edge: now the write is accepted exactly once.
        accepted = self.feed(normalizer, 3, wvalid=1, wready=1,
                             wdata=0x41, wstrb=0b0001)
        self.assertEqual(['transaction_accept'], self.types(accepted))
        # B handshakes: the response closes the write.
        response = self.feed(normalizer, 4, bvalid=1, bready=1)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0, response[0]['payload']['bresp'])
        self.assertEqual([], self.types(self.feed(normalizer, 5)))

    def test_write_data_before_address_accepts_write_once(self):
        """W may handshake first; the accept still needs both channels."""
        normalizer = self.normalizer()
        offered = self.feed(normalizer, 1, wvalid=1, wready=1,
                            wdata=0x41, wstrb=0b0001)
        self.assertEqual(['transaction_request'], self.types(offered))
        self.assertEqual(['transaction_accept'],
                         self.types(self.feed(normalizer, 2, awvalid=1, awready=1,
                                              awaddr=0x4000c)))
        self.assertEqual(['transaction_response'],
                         self.types(self.feed(normalizer, 3, bvalid=1, bready=1)))

    def test_simultaneous_aw_and_w_handshakes_offer_and_accept_on_one_edge(self):
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c,
                           wvalid=1, wready=1, wdata=0x41, wstrb=0b0001)
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         self.types(events))
        # The two projections of one edge must not collide on local_event_id.
        self.assertNotEqual(events[0]['local_event_id'], events[1]['local_event_id'])

    def test_write_response_payload_carries_the_accepted_address_and_data(self):
        normalizer = self.normalizer()
        self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c)
        self.feed(normalizer, 2, wvalid=1, wready=1, wdata=0x41, wstrb=0b0001)
        response = self.feed(normalizer, 3, bvalid=1, bready=1)
        payload = response[0]['payload']
        self.assertEqual(0x4000c, payload['awaddr'])
        self.assertEqual(0x41, payload['wdata'])
        self.assertEqual(0b0001, payload['wstrb'])
        self.assertEqual(0, payload['bresp'])

    def test_each_edge_emits_no_partial_accept_for_a_single_channel(self):
        """A read address must never be projected as a completed write."""
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         self.types(events))
        self.assertEqual('read', events[0]['native_identity']['direction'])

    # -- read channel -----------------------------------------------------
    def test_read_address_accepts_then_r_responds_with_data(self):
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         self.types(events))
        response = self.feed(normalizer, 2, rvalid=1, rready=1, rdata=0x5a)
        self.assertEqual(['transaction_response'], self.types(response))
        payload = response[0]['payload']
        for field, value in (('araddr', 0x40008), ('arprot', 0), ('rdata', 0x5a),
                             ('rresp', 0), ('matched_request', True),
                             ('direction', 'read'), ('channel', 'r')):
            self.assertEqual(value, payload[field], field)

    def test_stalled_read_address_is_an_observation_not_a_response(self):
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, arvalid=1, araddr=0x40008)
        self.assertEqual(['transaction_request'], self.types(events))
        waiting = self.feed(normalizer, 2, arvalid=1, araddr=0x40008)
        self.assertEqual(['wait_observation'], self.types(waiting))
        self.assertEqual('ar_without_ready', waiting[0]['payload']['reason'])

    def test_read_address_held_beyond_budget_times_out_once(self):
        normalizer = self.normalizer(max_wait=2)
        self.feed(normalizer, 1, arvalid=1, araddr=0x40008)
        self.assertEqual(['wait_observation'],
                         self.types(self.feed(normalizer, 2, arvalid=1, araddr=0x40008)))
        timed_out = self.feed(normalizer, 3, arvalid=1, araddr=0x40008)
        # The edge whose ordinal reaches the budget both observes and times out.
        self.assertEqual(['wait_observation', 'transaction_timeout'],
                         self.types(timed_out))
        # The timed-out read is closed: a still-held address starts a new one
        # rather than being answered twice or inheriting the old wait count.
        restarted = self.feed(normalizer, 4, arvalid=1, araddr=0x40008)
        self.assertEqual(['transaction_request'], self.types(restarted))
        self.assertNotEqual(timed_out[0]['local_event_id'],
                            restarted[0]['local_event_id'])

    # -- reset ------------------------------------------------------------
    def test_reset_cancels_an_inflight_write_in_the_old_epoch(self):
        normalizer = self.normalizer()
        self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c)
        cancelled = self.feed(normalizer, 2, epoch=1)
        self.assertEqual(['transaction_cancel'], self.types(cancelled))
        self.assertEqual(0, cancelled[0]['reset_epoch'])
        self.assertEqual('reset_epoch_changed', cancelled[0]['payload']['reason'])
        # The new epoch starts clean: the pre-reset AW is gone, so a fresh AW
        # opens exactly one new write offer instead of joining the cancelled
        # one, and its address is the one really presented in this epoch.
        first = self.feed(normalizer, 3, epoch=1, awvalid=1, awaddr=0x40008)
        self.assertEqual(['transaction_request'], self.types(first))
        self.assertEqual(1, first[0]['reset_epoch'])
        self.assertEqual(0x40008, first[0]['payload']['signals']['awaddr'])
        self.assertNotIn('wdata', first[0]['payload']['signals'],
                         'a channel that never presented must not be invented')

    def test_a_withdrawn_unaccepted_channel_is_a_protocol_error_not_a_merge(self):
        """Dropping VALID before READY must not silently fold into the next write."""
        normalizer = self.normalizer()
        normalizer.consume_local_tick(self.raw(normalizer, 1, awvalid=1,
                                               awaddr=0x40000), reset_epoch=0)
        events = normalizer.consume_local_tick(self.raw(normalizer, 2), reset_epoch=0)
        self.assertEqual(['protocol_error'], self.types(events))
        self.assertEqual('valid_withdrawn_before_ready',
                         events[0]['payload']['reason'])
        self.assertEqual('aw', events[0]['payload']['channel'])
        # A later, different AW is its own offer rather than the abandoned one.
        later = self.feed(normalizer, 3, awvalid=1, awaddr=0x4000c)
        self.assertEqual(['transaction_request'], self.types(later))
        self.assertEqual(0x4000c, later[0]['payload']['signals']['awaddr'])

    # -- error codes ------------------------------------------------------
    def test_slave_error_response_code_is_projected_as_its_own_value(self):
        normalizer = self.normalizer()
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        response = self.feed(normalizer, 2, rvalid=1, rready=1, rdata=0,
                             rresp=0b10)
        # The code is reported as the measured value, and a non-OKAY code is
        # additionally named as the native protocol error it is.
        self.assertEqual(['transaction_response', 'protocol_error'],
                         self.types(response))
        self.assertEqual(0b10, response[0]['payload']['rresp'])
        self.assertEqual('native_response_error',
                         response[1]['payload']['reason'])
        self.assertEqual(0b10, response[1]['payload']['rresp'])


class Axi4LiteDefectRegressionTests(Axi4LiteProjectionTests):
    """One test per independently reviewed defect, each reproducing a real bug.

    These sequences were found by an adversarial review of the first version of
    this projection and independently reproduced before the fix.  They stay in
    the suite so the same mistakes cannot come back silently.
    """

    def test_held_write_response_never_times_out_and_late_b_still_completes(self):
        """Review F1/F2: a slow-but-correct slave must not crash the run.

        The first version emitted a B-channel ``transaction_timeout`` and then
        cleared the write state, so the slave's own late (and legal) B raised
        ``KeyError: 'fields'`` while formatting the completion.
        """
        normalizer = self.normalizer(max_wait=3)
        # Both channels handshake on one edge: the write is offered and
        # accepted on that same edge, in causal order.
        self.assertEqual(['transaction_request', 'transaction_accept'],
                         self.types(self.feed(normalizer, 1, awvalid=1, awready=1,
                                              awaddr=0x4000c, wvalid=1, wready=1,
                                              wdata=0x41, wstrb=0b0001)))
        for tick in (2, 3, 4, 5, 6):
            events = self.feed(normalizer, tick)
            self.assertEqual(['wait_observation'], self.types(events),
                             f'tick {tick} must observe, not time out')
            self.assertEqual('b', events[0]['payload']['channel'])
        # A late B is still the answer to the accepted write.
        response = self.feed(normalizer, 7, bvalid=1, bready=1)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0x4000c, response[0]['payload']['awaddr'])
        self.assertEqual(0x41, response[0]['payload']['wdata'])

    def test_held_read_response_never_times_out_and_late_r_still_completes(self):
        """The B and R response phases must behave the same way."""
        normalizer = self.normalizer(max_wait=3)
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        for tick in (2, 3, 4, 5):
            events = self.feed(normalizer, tick)
            self.assertEqual(['wait_observation'], self.types(events))
            self.assertEqual('r', events[0]['payload']['channel'])
        response = self.feed(normalizer, 6, rvalid=1, rready=1, rdata=0x5a)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0x40008, response[0]['payload']['araddr'])
        self.assertEqual(0x5a, response[0]['payload']['rdata'])

    def test_response_without_any_accepted_request_is_an_error_not_a_crash(self):
        """Review F2: an unmatched B or R must be reported, never raise."""
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, bvalid=1, bready=1, bresp=0b10)
        self.assertEqual(['protocol_error'], self.types(events))
        self.assertEqual('response_without_accepted_request',
                         events[0]['payload']['reason'])
        self.assertEqual(0b10, events[0]['payload']['bresp'])
        read = self.feed(normalizer, 2, rvalid=1, rready=1, rresp=0b11)
        self.assertEqual(['protocol_error'], self.types(read))
        self.assertEqual('r', read[0]['payload']['channel'])

    def test_one_stalled_edge_is_counted_once_per_channel(self):
        """Review F4: the group and the channel must not both count one edge."""
        normalizer = self.normalizer(max_wait=16)
        self.feed(normalizer, 1, awvalid=1, awaddr=0x4000c)
        events = self.feed(normalizer, 2, awvalid=1, awaddr=0x4000c)
        self.assertEqual(['wait_observation'], self.types(events))
        self.assertEqual('aw', events[0]['payload']['channel'])
        self.assertEqual(1, events[0]['payload']['wait_ordinal'])
        # Counting an edge once means the budget lasts the declared number of
        # stalled edges: with max_wait=16 the 16th stalled edge times out.
        for tick in range(3, 17):
            observed = self.feed(normalizer, tick, awvalid=1, awaddr=0x4000c)
            self.assertEqual(['wait_observation'], self.types(observed), f'tick {tick}')
            self.assertEqual(tick - 1, observed[0]['payload']['wait_ordinal'])
        last = self.feed(normalizer, 17, awvalid=1, awaddr=0x4000c)
        self.assertEqual(['wait_observation', 'transaction_timeout'],
                         self.types(last))
        self.assertEqual(16, last[0]['payload']['wait_ordinal'])  # the 16th stalled edge

    def test_completing_a_handshake_is_never_also_reported_as_a_stall(self):
        """Review F3: the edge that completes AW must not time out AW."""
        normalizer = self.normalizer(max_wait=1)
        self.feed(normalizer, 1, awvalid=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=0b0001)
        events = self.feed(normalizer, 2, awvalid=1, awready=1)
        self.assertEqual(['transaction_accept'], self.types(events))

    def test_two_aw_handshakes_with_one_w_do_not_silently_lose_a_write(self):
        """Review F5/F12: a second AW must not overwrite the first transfer."""
        normalizer = self.normalizer()
        self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x40000)
        events = self.feed(normalizer, 2, awvalid=1, awready=1, awaddr=0x4000c)
        self.assertEqual(['protocol_error'], self.types(events))
        self.assertEqual('address_channel_reaccepted_before_completion',
                         events[0]['payload']['reason'])
        self.assertEqual(0x40000, events[0]['payload']['accepted_address'])
        self.assertEqual(0x4000c, events[0]['payload']['observed_address'])
        response = self.feed(normalizer, 3, wvalid=1, wready=1, wdata=0x41,
                             wstrb=0b0001)
        accept = next(event for event in response
                      if event['event_type'] == 'transaction_accept')
        self.assertEqual(0x4000c, accept['payload']['signals']['awaddr'])

    def test_reset_cancels_one_accepted_read_exactly_once(self):
        """Review F16: one read must not be cancelled twice."""
        normalizer = self.normalizer()
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        cancelled = self.feed(normalizer, 2, epoch=1)
        self.assertEqual(['transaction_cancel'], self.types(cancelled))
        self.assertEqual(0, cancelled[0]['reset_epoch'])


class Axi4LiteSecondReviewRegressionTests(Axi4LiteProjectionTests):
    """Regressions for the second independent review of this projection.

    Every sequence here reproduced a real defect before it was fixed, and the
    assertions pin the *fixed* behaviour rather than merely the current one.
    """

    def test_response_on_the_same_edge_as_its_own_acceptance_still_completes(self):
        """Review N1: a combinational B used to dereference a missing state."""
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c,
                           wvalid=1, wready=1, wdata=0x41, wstrb=0b0001,
                           bvalid=1, bready=1)
        # Causal order is preserved: the write is offered, accepted, answered.
        self.assertEqual(['transaction_request', 'transaction_accept',
                          'transaction_response'], self.types(events))
        self.assertEqual(0x4000c, events[2]['payload']['awaddr'])
        self.assertEqual(0x41, events[2]['payload']['wdata'])

    def test_read_response_on_the_same_edge_as_its_acceptance_is_not_an_orphan(self):
        """Review N12: the read side used to report an unmatched response."""
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008,
                           rvalid=1, rready=1, rdata=0x5a)
        self.assertEqual(['transaction_request', 'transaction_accept',
                          'transaction_response'], self.types(events))
        self.assertEqual(0x40008, events[2]['payload']['araddr'])
        self.assertEqual(0x5a, events[2]['payload']['rdata'])
        self.assertTrue(events[2]['payload']['matched_request'])

    def test_two_edge_write_keeps_its_request_reference(self):
        """Review N3: the completion must cite the request edge, not the accept edge."""
        normalizer = self.normalizer()
        request = self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c)[0]
        accepted = self.feed(normalizer, 2, wvalid=1, wready=1, wdata=0x41,
                             wstrb=0b0001)[0]
        response = self.feed(normalizer, 3, bvalid=1, bready=1)[0]
        self.assertEqual('transaction_request', request['event_type'])
        self.assertEqual('transaction_accept', accepted['event_type'])
        # Both the acceptance and the completion belong to the same request.
        self.assertEqual([request['raw_event_refs'][0]],
                         accepted['related_request_event_refs'])
        self.assertEqual([request['raw_event_refs'][0]],
                         response['related_request_event_refs'])

    def test_two_stalled_request_channels_each_keep_their_own_ordinal(self):
        """Review N5: one shared counter halved the declared wait budget."""
        normalizer = self.normalizer(max_wait=16)
        self.feed(normalizer, 1, awvalid=1, awaddr=0x4000c,
                  wvalid=1, wdata=0x41, wstrb=0b0001)
        for tick in range(2, 17):
            events = self.feed(normalizer, tick, awvalid=1, awaddr=0x4000c,
                               wvalid=1, wdata=0x41, wstrb=0b0001)
            self.assertEqual(['wait_observation', 'wait_observation'],
                             self.types(events), f'tick {tick}')
            self.assertEqual([tick - 1, tick - 1],
                             [row['payload']['wait_ordinal'] for row in events])
            self.assertNotIn('transaction_timeout', self.types(events))
        # The 16th stalled edge is the one that exhausts the declared budget.
        last = self.feed(normalizer, 17, awvalid=1, awaddr=0x4000c,
                         wvalid=1, wdata=0x41, wstrb=0b0001)
        self.assertEqual(['wait_observation', 'transaction_timeout',
                          'wait_observation', 'transaction_timeout'],
                         self.types(last))

    def test_a_timed_out_request_does_not_discard_another_accepted_read(self):
        """Review N6: the AR timeout used to clear an unrelated pending R."""
        normalizer = self.normalizer(max_wait=2)
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        self.feed(normalizer, 2, arvalid=1, araddr=0x4000c)
        self.feed(normalizer, 3, arvalid=1, araddr=0x4000c)
        # max_wait=2 means the second stalled edge exhausts the budget.
        timed_out = self.feed(normalizer, 4, arvalid=1, araddr=0x4000c)
        self.assertIn('transaction_timeout', self.types(timed_out))
        # The first read was accepted before the second one ever appeared, so
        # its own late response is still matched.
        response = self.feed(normalizer, 5, rvalid=1, rready=1, rdata=0x5a)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0x40008, response[0]['payload']['araddr'])

    def test_accepting_a_second_write_while_one_awaits_b_is_reported(self):
        """Review N7: the second transfer used to be dropped in silence."""
        normalizer = self.normalizer()
        self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c)
        self.feed(normalizer, 2, wvalid=1, wready=1, wdata=0x41, wstrb=0b0001)
        events = self.feed(normalizer, 3, awvalid=1, awready=1, awaddr=0x40000,
                           wvalid=1, wready=1, wdata=0x42, wstrb=0b0001)
        errors = [row for row in events if row['event_type'] == 'protocol_error']
        self.assertEqual(1, len(errors))
        self.assertEqual('write_accepted_with_response_outstanding',
                         errors[0]['payload']['reason'])
        self.assertEqual(0x40000, errors[0]['payload']['address'])
        # The first write is still the one the slave's B answers.
        response = self.feed(normalizer, 4, bvalid=1, bready=1)[0]
        self.assertEqual('transaction_response', response['event_type'])
        self.assertEqual(0x4000c, response['payload']['awaddr'])

    def test_accepting_a_second_read_while_one_awaits_r_is_reported(self):
        """The read side must not be the weak side of the same rule."""
        normalizer = self.normalizer()
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        events = self.feed(normalizer, 2, arvalid=1, arready=1, araddr=0x4000c)
        errors = [row for row in events if row['event_type'] == 'protocol_error']
        self.assertEqual(1, len(errors))
        self.assertEqual('read_accepted_with_response_outstanding',
                         errors[0]['payload']['reason'])
        self.assertEqual(0x4000c, errors[0]['payload']['address'])


class Axi4LiteOrphanResponseTests(Axi4LiteProjectionTests):
    """An unanswered response is reported from VALID alone, on both channels.

    Requiring READY as well made the projection blind to exactly the case where
    no master is listening, and put the projection and the protocol checker in
    disagreement about the same samples.
    """

    def test_an_unanswered_write_response_is_reported_without_ready(self):
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, bvalid=1, bresp=0b10)
        self.assertEqual(['protocol_error'], self.types(events))
        self.assertEqual('response_without_accepted_request',
                         events[0]['payload']['reason'])
        self.assertEqual('b', events[0]['payload']['channel'])
        self.assertEqual(0b10, events[0]['payload']['bresp'])

    def test_an_unanswered_read_response_is_reported_without_ready(self):
        normalizer = self.normalizer()
        events = self.feed(normalizer, 1, rvalid=1, rresp=0b11)
        self.assertEqual(['protocol_error'], self.types(events))
        self.assertEqual('r', events[0]['payload']['channel'])
        self.assertEqual(0b11, events[0]['payload']['rresp'])

    def test_a_presented_response_to_an_accepted_write_is_not_an_orphan(self):
        """The fix must not turn a waiting master into a protocol error."""
        normalizer = self.normalizer()
        self.feed(normalizer, 1, awvalid=1, awready=1, awaddr=0x4000c,
                  wvalid=1, wready=1, wdata=0x41, wstrb=0b0001)
        held = self.feed(normalizer, 2, bvalid=1, bready=0)
        self.assertEqual(['wait_observation'], self.types(held))
        self.assertEqual('b', held[0]['payload']['channel'])
        # It completes only on the real handshake, and not before.
        response = self.feed(normalizer, 3, bvalid=1, bready=1)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0x4000c, response[0]['payload']['awaddr'])

    def test_a_presented_response_to_an_accepted_read_completes_on_handshake(self):
        normalizer = self.normalizer()
        self.feed(normalizer, 1, arvalid=1, arready=1, araddr=0x40008)
        held = self.feed(normalizer, 2, rvalid=1, rready=0)
        self.assertEqual(['wait_observation'], self.types(held))
        response = self.feed(normalizer, 3, rvalid=1, rready=1, rdata=0x5a)
        self.assertEqual(['transaction_response'], self.types(response))
        self.assertEqual(0x5a, response[0]['payload']['rdata'])

    def test_the_projection_and_the_checker_agree_on_an_orphan(self):
        """Both layers must name the same fault for the same samples."""
        from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
        normalizer = self.normalizer()
        checker = IpProtocolChecker(component_id='zipcpu_axiluart',
                                    instance_id='uart0',
                                    protocol_trace=axi4_lite_trace())
        raw = self.raw(normalizer, 1, bvalid=1)
        projected = normalizer.consume_local_tick(raw, reset_epoch=0)
        checked = checker.consume_local_tick(raw, reset_epoch=0)
        self.assertEqual(['protocol_error'], self.types(projected))
        self.assertEqual(['axi4lite_write_response_without_request'],
                         [row['payload']['violation_code'] for row in checked])


if __name__ == '__main__':
    unittest.main()
