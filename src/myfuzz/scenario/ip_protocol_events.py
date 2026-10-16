"""Protocol-boundary event projection for the admitted generic IP templates."""
from __future__ import annotations

from collections.abc import Mapping


_SCHEMA_VERSION = 'ip_base_event.v1'
_TRACE_SCHEMA_VERSION = 'ip_protocol_trace.v1'
_REQUIRED_SIGNALS = {
    'tl-ul': ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_address',
              'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
              'd_data', 'd_error'),
    'apb3': ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
             'prdata', 'pslverr'),
    'wishbone': ('cyc', 'stb', 'we', 'ack', 'stall', 'dat_w', 'sel', 'dat_r'),
    'axi4-lite': ('awvalid', 'awready', 'awaddr', 'awprot',
                  'wvalid', 'wready', 'wdata', 'wstrb',
                  'bvalid', 'bready', 'bresp',
                  'arvalid', 'arready', 'araddr', 'arprot',
                  'rvalid', 'rready', 'rdata', 'rresp'),
}
_BOOLEAN_SIGNALS = frozenset((
    'a_valid', 'a_ready', 'd_valid', 'd_ready', 'd_error',
    'psel', 'penable', 'pwrite', 'pready', 'pslverr',
    'cyc', 'stb', 'we', 'ack', 'stall', 'err',
    'awvalid', 'awready', 'wvalid', 'wready',
    'bvalid', 'bready', 'arvalid', 'arready', 'rvalid', 'rready'))
#: Every state an AXI4-Lite reset epoch owns. Kept as one list so a reset that
#: forgets one of them fails loudly here rather than leaking a stale offer.
_AXI4_LITE_EPOCH_STATE = ('_axi4_write_offer', '_axi4_write_response',
                          '_axi4_read_request', '_axi4_read_offer',
                          '_axi4_read_response')


class IpProtocolEventNormalizer:
    """Project protocol handshakes from declared, raw per-edge signal taps.

    APB3 and Wishbone have no native transaction identifier. Their projected
    events therefore keep ``transaction_key`` null and link observations to
    the raw request event. TL-UL retains its native source field, scoped to the
    endpoint and reset epoch. A source may be reused after its response or a
    reset; a D timeout alone keeps it reserved for a possible late response.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 protocol_trace: Mapping[str, object]):
        if (type(component_id) is not str or not component_id
                or type(instance_id) is not str or not instance_id):
            raise ValueError('protocol-event-component-identity-required')
        if not isinstance(protocol_trace, Mapping):
            raise ValueError('protocol-event-trace-contract-required')
        protocol = protocol_trace.get('protocol')
        endpoint_id = protocol_trace.get('endpoint_id')
        clock_domain = protocol_trace.get('clock_domain')
        max_wait = protocol_trace.get('max_wait_cycles')
        signals = protocol_trace.get('signals')
        if (protocol_trace.get('schema_version') != _TRACE_SCHEMA_VERSION
                or type(protocol) is not str
                or protocol not in _REQUIRED_SIGNALS
                or type(endpoint_id) is not str or not endpoint_id
                or type(clock_domain) is not str or not clock_domain
                or type(max_wait) is not int or max_wait < 1
                or not isinstance(signals, Mapping)):
            raise ValueError('protocol-event-trace-contract-invalid')
        required = set(_REQUIRED_SIGNALS[protocol])
        if protocol == 'wishbone' and 'adr' in signals:
            required.add('adr')
        if (not required <= set(signals)
                or any(type(role) is not str or not role
                       or type(name) is not str or not name
                       for role, name in signals.items())):
            raise ValueError('protocol-event-trace-signals-invalid')
        if len(set(signals.values())) != len(signals):
            raise ValueError('protocol-event-trace-signals-invalid')
        self.component_id = component_id
        self.instance_id = instance_id
        self.protocol = protocol
        self.endpoint_id = endpoint_id
        self.clock_domain = clock_domain
        self.max_wait_cycles = max_wait
        self._signals = dict(signals)
        self._reset_epoch: int | None = None
        self._tl_offer: dict[str, object] | None = None
        self._tl_outstanding: dict[int, dict[str, object]] = {}
        self._tl_quarantined: dict[int, dict[str, object]] = {}
        self._apb_active: dict[str, object] | None = None
        self._wb_active: dict[str, object] | None = None
        # AXI4-Lite keeps one state per channel group. AW and W are held
        # separately because they may handshake in either order; B and R are
        # held separately because a response may be offered before, with, or
        # after the request edges it answers.
        for name in _AXI4_LITE_EPOCH_STATE:
            setattr(self, name, None)

    def _key(self, source: int, epoch: int) -> dict[str, object]:
        return {'protocol': 'tl-ul', 'endpoint_id': self.endpoint_id,
                'reset_epoch': epoch, 'source': source}

    def _event(self, raw: Mapping[str, object], *, event_type: str,
               reset_epoch: int, transaction_key: object,
               native_identity: object, payload: dict[str, object],
               related_request_event_refs: tuple[int, ...] = ()) -> dict[str, object]:
        event_id = raw['event_id']
        tick = raw['local_tick']
        identity_gap = ('protocol_has_no_transaction_id'
                        if transaction_key is None else None)
        return {
            'schema_version': _SCHEMA_VERSION,
            'event_type': event_type,
            'component_id': self.component_id,
            'instance_id': self.instance_id,
            'endpoint_id': self.endpoint_id,
            'role': 'protocol_transaction',
            'raw_event_refs': [event_id],
            'related_request_event_refs': list(related_request_event_refs),
            'local_event_id': (f'{self.instance_id}|{reset_epoch}|{self.protocol}|'
                               f'{tick}|pre|{event_type}|{len(payload)}'),
            'clock_domain': self.clock_domain,
            'tick': tick,
            'reset_epoch': reset_epoch,
            'transaction_key': transaction_key,
            'native_identity': native_identity,
            'identity_gap': identity_gap,
            'action_ref': None,
            'source_ref': None,
            'observation_mapping_id': None,
            'observation_property': 'measured_protocol_boundary',
            'payload': payload,
        }

    def _read_signals(self, raw: Mapping[str, object]) -> dict[str, int]:
        outputs = raw.get('outputs')
        backend = outputs.get('backend') if isinstance(outputs, Mapping) else None
        if not isinstance(backend, Mapping):
            raise ValueError('protocol-event-backend-sample-required')
        values: dict[str, int] = {}
        for role, name in self._signals.items():
            value = backend.get(name)
            if (type(value) is not int or value < 0
                    or role in _BOOLEAN_SIGNALS and value not in (0, 1)):
                raise ValueError('protocol-event-signal-invalid:' + role)
            values[role] = value
        return values

    def _make(self, raw, emitted, event_type, epoch, key, native, payload,
              request_refs=()):
        event = self._event(raw, event_type=event_type, reset_epoch=epoch,
                            transaction_key=key, native_identity=native,
                            payload=payload,
                            related_request_event_refs=request_refs)
        # The raw event id and event type identify each observation. Add its
        # position among this sample's projections to keep same-type events
        # collision-free without inventing a transaction identity.
        event['local_event_id'] += '|' + str(len(emitted))
        emitted.append(event)

    def _cancel_on_reset(self, raw, new_epoch: int, emitted) -> None:
        old_epoch = self._reset_epoch
        if old_epoch is None or old_epoch == new_epoch:
            self._reset_epoch = new_epoch
            return
        if self.protocol == 'tl-ul':
            rows = list(self._tl_outstanding.items())
            rows.extend(self._tl_quarantined.items())
            if self._tl_offer is not None:
                rows.append((self._tl_offer['source'], self._tl_offer))
            for source, state in rows:
                self._make(raw, emitted, 'transaction_cancel', old_epoch,
                           state['key'], {'channel': 'A', 'source': source},
                           {'reason': 'reset_epoch_changed',
                            'from_reset_epoch': old_epoch,
                            'to_reset_epoch': new_epoch},
                           (state['request_event_ref'],))
            self._tl_offer = None
            self._tl_outstanding.clear()
            self._tl_quarantined.clear()
        elif self.protocol == 'axi4-lite':
            # Every channel group in flight belongs to the old epoch. A write
            # whose AW was accepted but whose W or B never arrived, and a read
            # still waiting for R, are cancelled rather than silently dropped.
            # The accepted read is one transaction seen from two channels, so
            # it is cancelled once: `_axi4_read_offer` and
            # `_axi4_read_response` may be the same object.
            seen: list[int] = []
            for state in (self._axi4_write_offer, self._axi4_write_response,
                          self._axi4_read_request, self._axi4_read_offer,
                          self._axi4_read_response):
                if state is None or id(state) in seen:
                    continue
                seen.append(id(state))
                self._make(raw, emitted, 'transaction_cancel', old_epoch,
                           None, {'channel_protocol': 'axi4-lite',
                                  'channel': state.get('channel'),
                                  'direction': state.get('direction')},
                           {'reason': 'reset_epoch_changed',
                            'from_reset_epoch': old_epoch,
                            'to_reset_epoch': new_epoch},
                           (state['request_event_ref'],))
            for name in _AXI4_LITE_EPOCH_STATE:
                setattr(self, name, None)
        else:
            active = self._apb_active if self.protocol == 'apb3' else self._wb_active
            if active is not None:
                self._make(raw, emitted, 'transaction_cancel', old_epoch,
                           None, None,
                           {'reason': 'reset_epoch_changed',
                            'from_reset_epoch': old_epoch,
                            'to_reset_epoch': new_epoch},
                           (active['request_event_ref'],))
            if self.protocol == 'apb3':
                self._apb_active = None
            else:
                self._wb_active = None
        self._reset_epoch = new_epoch

    def consume_local_tick(self, raw_event: Mapping[str, object], *,
                           reset_epoch: int) -> tuple[dict[str, object], ...]:
        if (not isinstance(raw_event, Mapping)
                or raw_event.get('kind') != 'local_tick_sample'
                or type(raw_event.get('event_id')) is not int
                or raw_event['event_id'] < 1
                or type(raw_event.get('local_tick')) is not int
                or raw_event['local_tick'] < 1
                or raw_event.get('phase') not in ('pre', 'post')
                or type(reset_epoch) is not int or reset_epoch < 0):
            raise ValueError('protocol-event-raw-sample-invalid')
        # The pre sample is the value presented to the active clock edge.
        # Post samples are retained in the raw journal and port projection.
        if raw_event['phase'] == 'post':
            return ()
        emitted: list[dict[str, object]] = []
        self._cancel_on_reset(raw_event, reset_epoch, emitted)
        signals = self._read_signals(raw_event)
        if self.protocol == 'tl-ul':
            self._consume_tlul(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'apb3':
            self._consume_apb3(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'axi4-lite':
            self._consume_axi4_lite(raw_event, reset_epoch, signals, emitted)
        else:
            self._consume_wishbone(raw_event, reset_epoch, signals, emitted)
        return tuple(emitted)

    def _consume_tlul(self, raw, epoch, signals, emitted) -> None:
        a_valid = signals['a_valid'] == 1
        a_ready = signals['a_ready'] == 1
        if a_valid:
            source = signals['a_source']
            key = self._key(source, epoch)
            if self._tl_offer is None:
                request_ref = raw['event_id']
                state = {'source': source, 'key': key,
                         'request_event_ref': request_ref, 'wait_count': 0,
                         'payload': {role: value for role, value in signals.items()
                                     if role.startswith('a_')}}
                self._tl_offer = state
                self._make(raw, emitted, 'transaction_request', epoch, key,
                           {'channel': 'A', 'source': source},
                           {'channel': 'A', 'signals': state['payload']})
            state = self._tl_offer
            if state['source'] != source:
                self._make(raw, emitted, 'protocol_error', epoch, state['key'],
                           {'channel': 'A', 'source': state['source']},
                           {'reason': 'request_identity_changed_while_valid',
                            'observed_source': source},
                           (state['request_event_ref'],))
            if a_ready:
                if source in self._tl_outstanding:
                    self._make(raw, emitted, 'transaction_duplicate', epoch, key,
                               {'channel': 'A', 'source': source},
                               {'reason': 'source_id_already_outstanding'},
                               (state['request_event_ref'],))
                elif source in self._tl_quarantined:
                    self._make(raw, emitted, 'transaction_duplicate', epoch, key,
                               {'channel': 'A', 'source': source},
                               {'reason': 'source_id_not_released_after_timeout'},
                               (state['request_event_ref'],))
                elif state['source'] == source:
                    self._make(raw, emitted, 'transaction_accept', epoch, key,
                               {'channel': 'A', 'source': source},
                               {'channel': 'A', 'signals': state['payload']},
                               (state['request_event_ref'],))
                    outstanding = dict(state)
                    outstanding['wait_count'] = 0
                    self._tl_outstanding[source] = outstanding
                self._tl_offer = None
            elif state['source'] == source:
                self._make(raw, emitted, 'wait_observation', epoch, key,
                           {'channel': 'A', 'source': source},
                           {'channel': 'A', 'reason': 'valid_without_ready',
                            'wait_ordinal': state['wait_count'] + 1},
                           (state['request_event_ref'],))
                state['wait_count'] += 1
                if state['wait_count'] >= self.max_wait_cycles:
                    self._make(raw, emitted, 'transaction_timeout', epoch, key,
                               {'channel': 'A', 'source': source},
                               {'channel': 'A', 'wait_cycles': state['wait_count']},
                               (state['request_event_ref'],))
                    self._tl_offer = None
        elif self._tl_offer is not None:
            state = self._tl_offer
            self._make(raw, emitted, 'transaction_cancel', epoch, state['key'],
                       {'channel': 'A', 'source': state['source']},
                       {'reason': 'request_withdrawn_before_acceptance'},
                       (state['request_event_ref'],))
            self._tl_offer = None

        d_valid = signals['d_valid'] == 1
        d_ready = signals['d_ready'] == 1
        if d_valid and d_ready:
            source = signals['d_source']
            state = self._tl_outstanding.get(source)
            timed_out_state = self._tl_quarantined.get(source)
            matched_state = state if state is not None else timed_out_state
            key = (matched_state['key'] if matched_state is not None
                   else self._key(source, epoch))
            refs = ((matched_state['request_event_ref'],)
                    if matched_state is not None else ())
            response = {role: value for role, value in signals.items()
                        if role.startswith('d_')}
            response['matched_outstanding'] = state is not None
            response['matched_timed_out'] = timed_out_state is not None
            self._make(raw, emitted, 'transaction_response', epoch, key,
                       {'channel': 'D', 'source': source},
                       {'channel': 'D', 'signals': response}, refs)
            if signals['d_error']:
                self._make(raw, emitted, 'protocol_error', epoch, key,
                           {'channel': 'D', 'source': source},
                           {'reason': 'native_response_error', 'channel': 'D'}, refs)
            self._tl_outstanding.pop(source, None)
            self._tl_quarantined.pop(source, None)
        elif d_ready:
            for source, state in tuple(self._tl_outstanding.items()):
                state['wait_count'] += 1
                self._make(raw, emitted, 'wait_observation', epoch, state['key'],
                           {'channel': 'D', 'source': source},
                           {'channel': 'D', 'reason': 'response_not_valid',
                            'wait_ordinal': state['wait_count']},
                           (state['request_event_ref'],))
                if state['wait_count'] >= self.max_wait_cycles:
                    self._make(raw, emitted, 'transaction_timeout', epoch,
                               state['key'], {'channel': 'D', 'source': source},
                               {'channel': 'D', 'wait_cycles': state['wait_count']},
                               (state['request_event_ref'],))
                    self._tl_outstanding.pop(source, None)
                    self._tl_quarantined[source] = state
        elif d_valid:
            source = signals['d_source']
            state = (self._tl_outstanding.get(source)
                     or self._tl_quarantined.get(source))
            self._make(raw, emitted, 'wait_observation', epoch, self._key(source, epoch),
                       {'channel': 'D', 'source': source},
                       {'channel': 'D', 'reason': 'valid_without_ready'},
                       (state['request_event_ref'],) if state is not None else ())

    def _no_id_event(self, raw, emitted, event_type, epoch, active,
                     payload, native_identity=None):
        refs = ((active['request_event_ref'],) if active is not None else ())
        self._make(raw, emitted, event_type, epoch, None, native_identity,
                   payload, refs)

    def _consume_apb3(self, raw, epoch, signals, emitted) -> None:
        selected = signals['psel'] == 1
        access = selected and signals['penable'] == 1
        if selected and self._apb_active is None:
            self._apb_active = {'request_event_ref': raw['event_id'],
                                'wait_count': 0, 'accepted': False}
            self._no_id_event(raw, emitted, 'transaction_request', epoch,
                              self._apb_active,
                              {'channel': 'APB', 'signals': {
                                  role: value for role, value in signals.items()
                                  if role in ('paddr', 'pwrite', 'pwdata')}})
        active = self._apb_active
        if access:
            if signals['pready']:
                if active is None:
                    active = {'request_event_ref': raw['event_id'],
                              'wait_count': 0, 'accepted': False}
                    self._no_id_event(raw, emitted, 'transaction_request', epoch,
                                      active, {'channel': 'APB', 'signals': {}})
                self._no_id_event(raw, emitted, 'transaction_accept', epoch,
                                  active, {'channel': 'APB'})
                self._no_id_event(raw, emitted, 'transaction_response', epoch,
                                  active, {'channel': 'APB', 'rdata': signals['prdata'],
                                           'error': bool(signals['pslverr'])})
                if signals['pslverr']:
                    self._no_id_event(raw, emitted, 'protocol_error', epoch,
                                      active, {'reason': 'native_response_error',
                                               'channel': 'APB'})
                self._apb_active = None
            else:
                if active is None:
                    active = {'request_event_ref': raw['event_id'],
                              'wait_count': 0, 'accepted': False}
                    self._no_id_event(raw, emitted, 'transaction_request', epoch,
                                      active, {'channel': 'APB', 'signals': {}})
                    self._apb_active = active
                active['wait_count'] += 1
                self._no_id_event(raw, emitted, 'wait_observation', epoch,
                                  active, {'channel': 'APB',
                                           'reason': 'access_without_ready',
                                           'wait_ordinal': active['wait_count']})
                if active['wait_count'] >= self.max_wait_cycles:
                    self._no_id_event(raw, emitted, 'transaction_timeout', epoch,
                                      active, {'channel': 'APB',
                                               'wait_cycles': active['wait_count']})
                    self._apb_active = None
        elif not selected and active is not None:
            self._no_id_event(raw, emitted, 'transaction_cancel', epoch, active,
                              {'reason': 'select_withdrawn_before_completion'})
            self._apb_active = None

    def _line(self, signals, *roles) -> dict[str, int]:
        """Measured payload fields, skipping optional roles the endpoint omits."""
        return {role: signals[role] for role in roles if role in signals}

    def _axi4_channel(self, request_ref, direction, channel) -> dict[str, object]:
        """A channel state that is always complete enough to be reported.

        Every state carries its own ``fields``, ``channel`` and ``direction``,
        so a response offered before its request existed, a second response of
        the same kind, or a state cancelled by reset can still be projected as
        a protocol error instead of raising while formatting an event.
        """
        return {'request_event_ref': request_ref, 'wait_count': 0,
                'aw_wait_count': 0, 'w_wait_count': 0,
                'direction': direction, 'channel': channel, 'fields': {},
                'accepted': False}

    def _consume_axi4_lite(self, raw, epoch, signals, emitted) -> None:
        """Project one AXI4-Lite sample into its channel-group transactions.

        AXI4-Lite has no transaction identifier, so every projected transaction
        keeps ``transaction_key`` null and names its channel group in
        ``native_identity``.

        Two rules decide this projection, and both exist because the naive
        version of each was wrong:

        * A channel presents its request while its own VALID is high, and the
          write exists once AW and W have *each* been accepted at least once.
          A channel that is withdrawn while still unaccepted is a protocol
          error and is reported as one, never silently merged into the next
          offer.
        * A stalled edge is counted once per channel that was already
          presented before the edge and did not complete on it. Only the
          request channels carry a timeout budget; a held B or R is an
          observation, because the protocol states no limit on how long a
          slave may take to answer, and because timing out an already accepted
          write would contradict having accepted it.
        """
        aw_valid, aw_ready = signals['awvalid'] == 1, signals['awready'] == 1
        w_valid, w_ready = signals['wvalid'] == 1, signals['wready'] == 1
        b_valid, b_ready = signals['bvalid'] == 1, signals['bready'] == 1
        ar_valid, ar_ready = signals['arvalid'] == 1, signals['arready'] == 1
        r_valid, r_ready = signals['rvalid'] == 1, signals['rready'] == 1
        aw_handshake = aw_valid and aw_ready
        w_handshake = w_valid and w_ready
        ar_handshake = ar_valid and ar_ready
        # What was already open when this edge arrived. Stalls are counted from
        # this snapshot, so an edge that completes a channel is never also
        # counted as a stall of that channel.
        # Completions whose acceptance happens later on this same edge.
        after_accept: list = []
        offer_before = self._axi4_write_offer
        request_before = self._axi4_read_request
        response_before = self._axi4_write_response
        read_response_before = self._axi4_read_response

        # -- write response channel (B) --------------------------------------
        # Responses are settled before the requests of this edge are judged, so
        # an outstanding transaction that completes here is already complete.
        # A response that completes on the same edge as the write or read it
        # answers is put on `after_accept` instead, because its completion must
        # be emitted after the acceptance it belongs to.
        response = self._axi4_write_response
        accepted_here = (aw_handshake and w_handshake
                         and self._axi4_write_response is None
                         and (offer_before is None
                              or offer_before['aw_accepted'] is False
                              or offer_before['w_accepted'] is False))
        if response is None and b_valid and not accepted_here:
            # A response with nothing to answer is a protocol error as soon as
            # the slave presents it; requiring BREADY as well made the
            # projection blind to exactly the case where no master is
            # listening, and disagreed with the protocol checker on the very
            # same samples.
            self._axi4_orphan_response(raw, epoch, emitted, signals,
                                       'write', 'b', bresp=signals['bresp'])
        elif b_valid and b_ready:
            # Only a real handshake completes a write.
            if response is None and accepted_here:
                def _complete_write(raw=raw, epoch=epoch, emitted=emitted,
                                    signals=dict(signals)):
                    state = self._axi4_write_response or self._axi4_channel(
                        raw['event_id'], 'write', 'b')
                    self._axi4_write_response = None
                    self._axi4_b_completion(raw, epoch, emitted, state, signals)
                after_accept.append(_complete_write)
            elif response is not None:
                self._axi4_write_response = None
                self._axi4_b_completion(raw, epoch, emitted, response, signals)
        elif response is not None and response.get('accepted'):
            # A held B is reported as a stall observation only. It never times
            # out, and it never clears the state the eventual B has to join.
            self._axi4_wait(raw, epoch, emitted, response,
                            'response_not_valid', 'b', 'write')

        # -- read response channel (R) ---------------------------------------
        response = self._axi4_read_response
        read_accepted_here = ar_handshake and self._axi4_read_response is None
        if response is None and r_valid and not read_accepted_here:
            self._axi4_orphan_response(raw, epoch, emitted, signals,
                                       'read', 'r', rresp=signals['rresp'])
        elif r_valid and r_ready:
            if response is None and read_accepted_here:
                def _complete_read(raw=raw, epoch=epoch, emitted=emitted,
                                   signals=dict(signals)):
                    state = self._axi4_read_response or self._axi4_channel(
                        raw['event_id'], 'read', 'r')
                    self._axi4_read_response = None
                    self._axi4_read_offer = None
                    self._axi4_r_completion(raw, epoch, emitted, state, signals)
                after_accept.append(_complete_read)
            elif response is not None:
                self._axi4_read_response = None
                self._axi4_read_offer = None
                self._axi4_r_completion(raw, epoch, emitted, response, signals)
        elif response is not None and response.get('accepted'):
            self._axi4_wait(raw, epoch, emitted, response,
                            'response_not_valid', 'r', 'read')

        # -- write request channels (AW / W) --------------------------------
        offer = self._axi4_write_offer
        if offer is None and (aw_valid or w_valid):
            offer = {
                **self._axi4_channel(raw['event_id'], 'write', 'aw+w'),
                'aw_present': aw_valid, 'w_present': w_valid,
                'aw_accepted': False, 'w_accepted': False}
            offer['fields'] = self._line(
                signals, *(('awaddr', 'awprot') if aw_valid else ()) +
                (('wdata', 'wstrb') if w_valid else ()))
            self._axi4_write_offer = offer
            self._no_id_event(raw, emitted, 'transaction_request', epoch, offer,
                              {'channel_protocol': 'axi4-lite', 'direction': 'write',
                               'signals': dict(offer['fields'])},
                              {'channel_protocol': 'axi4-lite', 'channel': 'aw+w',
                               'direction': 'write'})
        if offer is not None:
            # A channel that stopped presenting before it was accepted did not
            # complete and must not be paired with a later, different transfer.
            for name, was_present, accepted, present, handshake in (
                    ('aw', offer_before is not None and offer_before['aw_present'],
                     offer['aw_accepted'], aw_valid, aw_handshake),
                    ('w', offer_before is not None and offer_before['w_present'],
                     offer['w_accepted'], w_valid, w_handshake)):
                if not was_present or accepted or handshake:
                    continue
                if not present:
                    self._no_id_event(
                        raw, emitted, 'protocol_error', epoch, offer,
                        {'channel_protocol': 'axi4-lite', 'direction': 'write',
                         'channel': name, 'reason': 'valid_withdrawn_before_ready'},
                        {'channel_protocol': 'axi4-lite', 'channel': name,
                         'direction': 'write'})
                    offer[f'{name}_present'] = False
                else:
                    self._axi4_wait(raw, epoch, emitted, offer,
                                    f'{name}_without_ready', name, 'write')
                    self._axi4_timeout(raw, epoch, emitted, offer, name, 'write')
            if aw_valid:
                offer['aw_present'] = True
            if w_valid:
                offer['w_present'] = True
            if aw_handshake:
                if offer['aw_accepted']:
                    # The variant admits one outstanding write, so a second
                    # accepted address before the first completed is a real
                    # protocol error. Reporting it is what keeps the second
                    # transfer from silently overwriting the first.
                    self._no_id_event(
                        raw, emitted, 'protocol_error', epoch, offer,
                        {'channel_protocol': 'axi4-lite', 'direction': 'write',
                         'channel': 'aw',
                         'reason': 'address_channel_reaccepted_before_completion',
                         'accepted_address': offer['fields'].get('awaddr'),
                         'observed_address': signals['awaddr']},
                        {'channel_protocol': 'axi4-lite', 'channel': 'aw',
                         'direction': 'write'})
                    offer['fields']['awaddr'] = signals['awaddr']
                    offer['fields']['awprot'] = signals['awprot']
                offer['aw_accepted'] = True
            if w_handshake:
                offer['w_accepted'] = True
            # Fields are sampled only while their own channel is presenting,
            # so a value captured on an earlier edge stays part of the transfer
            # instead of being overwritten by the idle value of a later edge.
            if aw_valid:
                offer['fields'].update(self._line(signals, 'awaddr', 'awprot'))
            if w_valid:
                offer['fields'].update(self._line(signals, 'wdata', 'wstrb'))
            # An offer whose presented channels were all withdrawn unaccepted
            # no longer describes a transfer, so it is closed; a later VALID
            # opens a genuinely new one instead of reviving this one.
            if (offer is self._axi4_write_offer
                    and not offer['aw_present'] and not offer['w_present']
                    and not offer['aw_accepted'] and not offer['w_accepted']):
                self._axi4_write_offer = None
            if offer is not None and offer['aw_accepted'] and offer['w_accepted']:
                state = {**offer, 'channel': 'aw+w'}
                self._no_id_event(raw, emitted, 'transaction_accept', epoch, state,
                                  {'channel_protocol': 'axi4-lite',
                                   'direction': 'write',
                                   'signals': dict(state['fields'])},
                                  {'channel_protocol': 'axi4-lite',
                                   'channel': 'aw+w', 'direction': 'write'})
                self._axi4_write_offer = None
                if self._axi4_write_response is not None:
                    # The variant admits one outstanding write, so a second
                    # accepted write while the first still awaits B is a real
                    # protocol error. Reporting it is what keeps the second
                    # transfer from being silently dropped.
                    self._no_id_event(
                        raw, emitted, 'protocol_error', epoch, state,
                        {'channel_protocol': 'axi4-lite', 'direction': 'write',
                         'channel': 'aw+w',
                         'reason': 'write_accepted_with_response_outstanding',
                         'address': state['fields'].get('awaddr')},
                        {'channel_protocol': 'axi4-lite', 'channel': 'aw+w',
                         'direction': 'write'})
                else:
                    # The accepted write now awaits B. Its request reference is
                    # the edge that first presented the request, not the edge
                    # that completed it: AW and W may be accepted on different
                    # edges, and the request event belongs to the offer.
                    self._axi4_write_response = {
                        **self._axi4_channel(state['request_event_ref'],
                                             'write', 'b'),
                        'fields': dict(state['fields']), 'accepted': True,
                        'aw_wait_count': state['aw_wait_count'],
                        'w_wait_count': state['w_wait_count']}

        # -- read address channel (AR) ---------------------------------------
        # Same rule: AR presents the read from its first VALID edge, and the
        # read is accepted when ARREADY completes the handshake.
        if ar_valid and self._axi4_read_request is None:
            request = {**self._axi4_channel(raw['event_id'], 'read', 'ar'),
                       'fields': self._line(signals, 'araddr', 'arprot')}
            self._axi4_read_request = request
            self._no_id_event(raw, emitted, 'transaction_request', epoch, request,
                              {'channel_protocol': 'axi4-lite', 'direction': 'read',
                               'signals': dict(request['fields'])},
                              {'channel_protocol': 'axi4-lite', 'channel': 'ar',
                               'direction': 'read'})
        elif (self._axi4_read_request is not None and request_before is not None
                and not ar_valid and not ar_handshake):
            self._no_id_event(
                raw, emitted, 'protocol_error', epoch, self._axi4_read_request,
                {'channel_protocol': 'axi4-lite', 'direction': 'read',
                 'channel': 'ar', 'reason': 'valid_withdrawn_before_ready'},
                {'channel_protocol': 'axi4-lite', 'channel': 'ar',
                 'direction': 'read'})
            self._axi4_read_request = None
        if (self._axi4_read_request is not None and request_before is not None
                and not ar_handshake):
            # This read address was already presented before this edge and did
            # not complete on it, so it stalled once. Waits are counted here,
            # once per stalled edge, instead of once per channel that happens
            # to be presenting.
            self._axi4_wait(raw, epoch, emitted, self._axi4_read_request,
                            'ar_without_ready', 'ar', 'read')
            self._axi4_timeout(raw, epoch, emitted, self._axi4_read_request,
                               'ar', 'read')
        if ar_handshake and self._axi4_read_request is not None:
            request = self._axi4_read_request
            request['fields'].update(self._line(signals, 'araddr', 'arprot'))
            self._no_id_event(raw, emitted, 'transaction_accept', epoch, request,
                              {'channel_protocol': 'axi4-lite', 'direction': 'read',
                               'signals': dict(request['fields'])},
                              {'channel_protocol': 'axi4-lite', 'channel': 'ar',
                               'direction': 'read'})
            self._axi4_read_offer = request
            self._axi4_read_request = None
            if self._axi4_read_response is not None:
                self._no_id_event(
                    raw, emitted, 'protocol_error', epoch, request,
                    {'channel_protocol': 'axi4-lite', 'direction': 'read',
                     'channel': 'ar',
                     'reason': 'read_accepted_with_response_outstanding',
                     'address': request['fields'].get('araddr')},
                    {'channel_protocol': 'axi4-lite', 'channel': 'ar',
                     'direction': 'read'})
                self._axi4_read_offer = None
            else:
                # One read, one transaction: the accepted read record and its
                # pending-R record are the same state, so a reset cancels it
                # once instead of reporting the same read twice.
                self._axi4_read_response = request
                request['accepted'] = True
        # Completions deferred because their acceptance happened on this edge.
        # Emitting them here keeps the causal order request, accept, response
        # while still settling them before the next edge is judged.
        for complete in after_accept:
            complete()

    def _axi4_orphan_response(self, raw, epoch, emitted, signals, direction,
                              channel, **code):
        """Project one response that has no accepted request to answer."""
        orphan = self._axi4_channel(raw['event_id'], direction, channel)
        self._no_id_event(
            raw, emitted, 'protocol_error', epoch, orphan,
            {'channel_protocol': 'axi4-lite', 'direction': direction,
             'channel': channel, 'reason': 'response_without_accepted_request',
             **code},
            {'channel_protocol': 'axi4-lite', 'channel': channel,
             'direction': direction})

    def _axi4_b_completion(self, raw, epoch, emitted, state, signals):
        """Emit one write completion for an AXI4-Lite B handshake."""
        self._no_id_event(raw, emitted, 'transaction_response', epoch, state,
                          {'channel_protocol': 'axi4-lite', 'direction': 'write',
                           'channel': 'b', 'bresp': signals['bresp'],
                           'matched_request': state.get('accepted') is True,
                           **dict(state['fields'])},
                          {'channel_protocol': 'axi4-lite', 'channel': 'b',
                           'direction': 'write'})
        if signals['bresp'] != 0:
            self._no_id_event(raw, emitted, 'protocol_error', epoch, state,
                              {'channel_protocol': 'axi4-lite',
                               'direction': 'write', 'channel': 'b',
                               'reason': 'native_response_error',
                               'bresp': signals['bresp']},
                              {'channel_protocol': 'axi4-lite', 'channel': 'b',
                               'direction': 'write'})

    def _axi4_r_completion(self, raw, epoch, emitted, state, signals):
        """Emit one read completion for an AXI4-Lite R handshake."""
        self._no_id_event(raw, emitted, 'transaction_response', epoch, state,
                          {'channel_protocol': 'axi4-lite', 'direction': 'read',
                           'channel': 'r', 'rdata': signals['rdata'],
                           'rresp': signals['rresp'],
                           'matched_request': state.get('accepted') is True,
                           **dict(state['fields'])},
                          {'channel_protocol': 'axi4-lite', 'channel': 'r',
                           'direction': 'read'})
        if signals['rresp'] != 0:
            self._no_id_event(raw, emitted, 'protocol_error', epoch, state,
                              {'channel_protocol': 'axi4-lite',
                               'direction': 'read', 'channel': 'r',
                               'reason': 'native_response_error',
                               'rresp': signals['rresp']},
                              {'channel_protocol': 'axi4-lite', 'channel': 'r',
                               'direction': 'read'})

    def _axi4_wait(self, raw, epoch, emitted, state, reason, channel, direction):
        """Count one stalled edge for one channel, and report it.

        AW and W are separate channels of one write, so each keeps its own
        stall ordinal. A write cannot proceed while either is stalled, so the
        budget is compared against the busiest request channel rather than
        against a counter both of them advance; sharing one counter made a
        doubly stalled write exhaust the declared budget in half the edges.
        """
        key = f'{channel}_wait_count' if channel in ('aw', 'w') else 'wait_count'
        state[key] = int(state.get(key) or 0) + 1
        self._no_id_event(raw, emitted, 'wait_observation', epoch, state,
                          {'channel_protocol': 'axi4-lite', 'direction': direction,
                           'channel': channel, 'reason': reason,
                           'wait_ordinal': state[key]},
                          {'channel_protocol': 'axi4-lite', 'channel': channel,
                           'direction': direction})

    def _axi4_stalled_ordinal(self, state, channel) -> int:
        if channel in ('aw', 'w'):
            return max(int(state.get('aw_wait_count') or 0),
                       int(state.get('w_wait_count') or 0))
        return int(state.get('wait_count') or 0)

    def _axi4_timeout(self, raw, epoch, emitted, state, channel, direction):
        """Close a request phase that has been held past the wait budget.

        Only request channels carry a budget. A response that was already
        accepted is never timed out: the protocol states no limit on how long
        the slave may take to answer, and discarding that answer would make the
        slave's own legal late response look like an orphaned one.
        """
        stalled = self._axi4_stalled_ordinal(state, channel)
        if stalled < self.max_wait_cycles:
            return
        self._no_id_event(raw, emitted, 'transaction_timeout', epoch, state,
                          {'channel_protocol': 'axi4-lite', 'direction': direction,
                           'channel': channel, 'wait_cycles': stalled},
                          {'channel_protocol': 'axi4-lite', 'channel': channel,
                           'direction': direction})
        if channel in ('aw', 'w'):
            self._axi4_write_offer = None
        elif channel == 'ar':
            self._axi4_read_request = None
            if not state.get('accepted'):
                # The read never reached its response phase, so nothing else
                # refers to it; an accepted read keeps its pending R.
                self._axi4_read_offer = None
                if self._axi4_read_response is state:
                    self._axi4_read_response = None

    def _consume_wishbone(self, raw, epoch, signals, emitted) -> None:
        request = signals['cyc'] == 1 and signals['stb'] == 1
        terminal = signals['ack'] == 1 or signals.get('err', 0) == 1
        if request and self._wb_active is None:
            self._wb_active = {'request_event_ref': raw['event_id'],
                               'wait_count': 0, 'accepted': False}
            self._no_id_event(raw, emitted, 'transaction_request', epoch,
                              self._wb_active,
                              {'channel': 'Wishbone', 'signals': {
                                  role: value for role, value in signals.items()
                                  if role in ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel')}})
        active = self._wb_active
        if request and not signals['stall'] and active is not None and not active['accepted']:
            active['accepted'] = True
            self._no_id_event(raw, emitted, 'transaction_accept', epoch, active,
                              {'channel': 'Wishbone', 'acceptance': 'cyc_stb_without_stall'})
        if terminal and signals['cyc']:
            if active is None:
                active = None
            payload = {'channel': 'Wishbone', 'ack': signals['ack'],
                       'err': signals.get('err', 0), 'rdata': signals['dat_r'],
                       'matched_request': active is not None}
            self._no_id_event(raw, emitted, 'transaction_response', epoch,
                              active, payload)
            if signals.get('err', 0):
                self._no_id_event(raw, emitted, 'protocol_error', epoch, active,
                                  {'reason': 'native_response_error',
                                   'channel': 'Wishbone'})
            self._wb_active = None
        elif active is not None and signals['cyc']:
            waiting = (signals['stall'] == 1 or
                       (active['accepted'] and signals['stb'] == 0))
            if waiting:
                active['wait_count'] += 1
                self._no_id_event(raw, emitted, 'wait_observation', epoch, active,
                                  {'channel': 'Wishbone',
                                   'reason': ('request_stalled' if signals['stall']
                                              else 'response_not_valid'),
                                   'wait_ordinal': active['wait_count']})
                if active['wait_count'] >= self.max_wait_cycles:
                    self._no_id_event(raw, emitted, 'transaction_timeout', epoch,
                                      active, {'channel': 'Wishbone',
                                               'wait_cycles': active['wait_count']})
                    self._wb_active = None
        elif active is not None and not signals['cyc']:
            self._no_id_event(raw, emitted, 'transaction_cancel', epoch, active,
                              {'reason': 'cycle_withdrawn_before_completion'})
            self._wb_active = None
