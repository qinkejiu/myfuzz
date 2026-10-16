"""Bounded accepted-event observations for a declared coherent TileLink subset.

The input is a transport's accepted A/C/D/E journal, not valid/ready samples.
This checker models a single client, no external probes, declared manager response ordering,
single beat puts, and release/release-data C messages. It proves neither that a
handshake occurred nor that the producing transport or program was accepted.
"""
from __future__ import annotations

from collections import Counter, deque
from collections.abc import Mapping
from copy import deepcopy


class CoherentProtocolEventNormalizer:
    """Project and structurally check accepted rows without granting authority.

    ``raw_event_ref`` must be the caller's unique raw journal identity. A row's
    own event_id or acceptance claims are never treated as trusted evidence.
    Errors poison this instance; start a new instance after an invalid stream.
    A reset epoch change explicitly cancels outstanding identities.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 endpoint_id: str, clock_domain: str, beat_bytes: int = 8,
                 max_size: int = 12, max_outstanding: int = 64,
                 max_events: int = 100000, manager_order: str = 'fifo',
                 single_client: bool = True, external_probes: bool = False,
                 address_bits: int = 64, source_bits: int = 16,
                 sink_bits: int = 16):
        if any(type(x) is not str or not x for x in
               (component_id, instance_id, endpoint_id, clock_domain)):
            raise ValueError('coherent-component-identity-required')
        if (type(beat_bytes) is not int or beat_bytes < 1
                or beat_bytes & (beat_bytes - 1)
                or any(type(x) is not int or x < 1 for x in
                       (max_size, max_outstanding, max_events,
                        address_bits, source_bits, sink_bits))
                or max_size > 20 or beat_bytes > 128
                or max(address_bits, source_bits, sink_bits) > 128):
            raise ValueError('coherent-bounds-invalid')
        if manager_order not in ('fifo', 'per_source') or single_client is not True or external_probes is not False:
            raise ValueError('coherent-subset-scope-unsupported')
        self.component_id, self.instance_id = component_id, instance_id
        self.endpoint_id, self.clock_domain = endpoint_id, clock_domain
        self.beat_bytes, self.max_size = beat_bytes, max_size
        self.address_bits, self.source_bits, self.sink_bits = address_bits, source_bits, sink_bits
        self.max_outstanding, self.max_events = max_outstanding, max_events
        self.manager_order = manager_order
        self._active_d = None
        self._epoch = None
        self._refs = set()
        self._pending = deque()
        self._sources = set()
        self._release = None
        self._sinks = {}
        self._counts = Counter()
        self._failed = False
        self._ordinal = 0

    def _fail(self, reason):
        self._failed = True
        raise ValueError('coherent-' + reason)

    def _integer(self, row, name):
        value = row.get(name)
        if type(value) is not int or value < 0:
            self._fail('field-invalid:' + name)
        return value

    def _unsigned(self, row, name, bits):
        value = self._integer(row, name)
        if value >= (1 << bits):
            self._fail('field-width-exceeded:' + name)
        return value

    def _beats(self, size):
        return max(1, (1 << size) // self.beat_bytes)

    def _event(self, kind, ref, payload, request=None):
        return {
            'schema_version': 'coherent_protocol_event.v1',
            'event_type': kind, 'component_id': self.component_id,
            'instance_id': self.instance_id, 'endpoint_id': self.endpoint_id,
            'clock_domain': self.clock_domain, 'reset_epoch': self._epoch,
            'local_event_id': f'{self.instance_id}|{self.endpoint_id}|{self._ordinal}|{kind}',
            'raw_event_refs': [ref],
            'related_request_event_refs': [] if request is None else [request['ref']],
            'transaction_key': None if request is None else {
                'protocol': 'tilelink-coherent', 'endpoint_id': self.endpoint_id,
                'reset_epoch': self._epoch, 'request_channel': request['channel'],
                'source': request['source'], 'request_event_ref': request['ref']},
            'source_ref': None, 'action_ref': None,
            'observation_property': 'accepted_event_journal_projection',
            'authority': 'observation_only', 'payload': deepcopy(payload),
        }

    def consume_accepted(self, raw_event: Mapping[str, object], *,
                         raw_event_ref: int, reset_epoch: int = 0):
        if self._failed:
            raise ValueError('coherent-stream-already-invalid')
        if (type(raw_event_ref) is not int or raw_event_ref < 1
                or raw_event_ref in self._refs
                or type(reset_epoch) is not int or reset_epoch < 0
                or not isinstance(raw_event, Mapping)):
            self._fail('raw-identity-invalid')
        if len(self._refs) >= self.max_events:
            self._fail('event-bound-exceeded')
        if self._epoch is not None and reset_epoch < self._epoch:
            self._fail('epoch-regressed')
        emitted = []
        if self._epoch is not None and reset_epoch != self._epoch:
            states = list(self._pending) + list(self._sinks.values())
            if self._release is not None:
                states.append(self._release)
            seen = set()
            for state in states:
                if state['ref'] in seen:
                    continue
                seen.add(state['ref'])
                event = self._event('transaction_cancel', raw_event_ref,
                    {'reason': 'reset_epoch_changed',
                     'to_reset_epoch': reset_epoch}, state)
                event['local_event_id'] += f"|{state['ref']}"
                emitted.append(event)
            self._counts['reset_cancellations'] += len(seen)
            self._pending.clear()
            self._active_d = None
            self._sources.clear()
            self._sinks.clear()
            self._release = None
        self._epoch = reset_epoch
        self._refs.add(raw_event_ref)
        self._ordinal += 1
        row = deepcopy(dict(raw_event))
        channel = row.get('channel')
        if channel not in ('A', 'C', 'D', 'E'):
            self._fail('channel-outside-no-probe-subset')
        request = None
        if channel == 'E':
            sink = self._unsigned(row, 'sink', self.sink_bits)
            request = self._sinks.get(sink)
            if request is None or not request['complete']:
                self._fail('grantack-without-complete-grant')
            del self._sinks[sink]
            kind = 'grant_acknowledgement'
        else:
            opcode = self._integer(row, 'opcode')
            size = self._integer(row, 'size')
            source = self._unsigned(row, 'source', self.source_bits)
            param = self._integer(row, 'param')
            if size > self.max_size:
                self._fail('size-bound-exceeded')
            if ((channel == 'A' and opcode in (0, 1))
                    or (channel == 'C' and opcode == 7)
                    or (channel == 'D' and opcode in (1, 5))
                    or 'data' in row):
                self._unsigned(row, 'data', self.beat_bytes * 8)
            if channel in ('A', 'C'):
                address = self._unsigned(row, 'address', self.address_bits)
                if address % (1 << size):
                    self._fail('request-address-unaligned')
                if channel == 'A':
                    mask = self._unsigned(row, 'mask', self.beat_bytes)
                    lanes = min(1 << size, self.beat_bytes)
                    expected_mask = ((1 << lanes) - 1) << (address % self.beat_bytes)
                    if (mask & ~expected_mask or
                            (opcode != 1 and mask != expected_mask)):
                        self._fail('a-mask-outside-transfer')
                elif 'mask' in row:
                    # C has no native mask; retain transport metadata only.
                    self._unsigned(row, 'mask', self.beat_bytes)
                namespace = (channel, source)
                if channel == 'A':
                    if opcode not in (0, 1, 4, 6, 7) or (opcode in (0, 1) and (1 << size) > self.beat_bytes):
                        self._fail('a-opcode-or-multibeat-put-unsupported')
                    if param not in ((0, 1, 2) if opcode in (6, 7) else (0,)):
                        self._fail('a-param-invalid')
                elif opcode not in (6, 7) or param not in range(6):
                    self._fail('c-release-opcode-or-param-invalid')
                if channel == 'C' and self._release is not None:
                    request = self._release
                    if (source, address, size, opcode, param) != request['signature']:
                        self._fail('release-multibeat-identity-changed')
                else:
                    if namespace in self._sources:
                        self._fail('source-reused-before-response')
                    if len(self._sources) >= self.max_outstanding:
                        self._fail('outstanding-bound-exceeded')
                    self._sources.add(namespace)
                    request = {'ref': raw_event_ref, 'channel': channel,
                        'source': source, 'size': size, 'address': address,
                        'opcode': opcode, 'received': 0, 'complete': False,
                        'signature': (source, address, size, opcode, param),
                        'd_opcode': ({0: 0, 1: 0, 4: 1, 6: 5, 7: 4}[opcode]
                                     if channel == 'A' else 6),
                        'd_param': (1 if param == 0 else 0) if channel == 'A' and opcode in (6, 7) else 0,
                        'd_beats': self._beats(size) if channel == 'A' and opcode in (4, 6) else 1,
                        'c_received': 0}
                    if channel == 'A':
                        self._pending.append(request)
                if channel == 'C':
                    request['c_received'] += 1
                    if request['c_received'] == (self._beats(size) if opcode == 7 else 1):
                        self._pending.append(request)
                        self._release = None
                    else:
                        self._release = request
                kind = 'transaction_accept'
            else:
                if not self._pending:
                    self._fail('response-without-request')
                if self._active_d is not None:
                    request = self._active_d
                elif self.manager_order == 'fifo':
                    request = self._pending[0]
                else:
                    namespace = 'C' if opcode == 6 else 'A'
                    matches = [state for state in self._pending
                               if state['channel'] == namespace
                               and state['source'] == source]
                    if len(matches) != 1:
                        self._fail('response-source-without-unique-request')
                    request = matches[0]
                beat = self._integer(row, 'beat')
                if (opcode, size, source, param, beat) != (request['d_opcode'], request['size'], request['source'], request['d_param'], request['received']):
                    self._fail('response-order-identity-or-beat-mismatch')
                if 'address' in row:
                    address = self._unsigned(row, 'address', self.address_bits)
                    if address != request['address']:
                        self._fail('response-address-mismatch')
                sink = self._unsigned(row, 'sink', self.sink_bits)
                if opcode in (4, 5):
                    if beat == 0:
                        if sink in self._sinks or len(self._sinks) >= self.max_outstanding:
                            self._fail('grant-sink-reuse-or-bound')
                        request['sink'] = sink
                        self._sinks[sink] = request
                    if sink != request['sink']:
                        self._fail('grant-sink-changed')
                self._active_d = request
                request['received'] += 1
                if request['received'] == request['d_beats']:
                    request['complete'] = True
                    self._pending.remove(request)
                    self._active_d = None
                    self._sources.remove((request['channel'], source))
                    self._counts['completed_requests'] += 1
                kind = 'transaction_response'
            self._counts[f'{channel}.opcode.{opcode}'] += 1
            self._counts[f'{channel}.size.{size}'] += 1
            if channel == 'D' and request['d_beats'] > 1:
                self._counts['D.multibeat_observations'] += 1
        self._counts[channel] += 1
        emitted.append(self._event(kind, raw_event_ref, {
            'channel': channel, 'signals': row,
            'beat_ordinal': row.get('beat', request.get('c_received', 1) - 1 if request else None),
            'request_address': None if request is None else request['address'],
            'request_size': None if request is None else request['size'],
            'request_complete': None if request is None else request['complete'],
        }, request))
        return tuple(emitted)

    def report(self):
        """Return structural state only; empty state does not imply runtime pass."""
        return {'schema_version': 'coherent_protocol_check.v1',
                'scope': 'single_client_no_external_probes_' + self.manager_order + '_manager',
                'structural_error': self._failed,
                'stream_closed': bool(self._refs) and not self._failed and not self._sources and not self._sinks,
                'pending_sources': len(self._sources), 'pending_sinks': len(self._sinks),
                'observed_events': len(self._refs), 'runtime_accepted': False,
                'semantic_accepted': False, 'source_authority': False}

    def coverage(self):
        """Bounded native observation counts, never semantic coverage credit."""
        return {'schema_version': 'coherent_protocol_coverage.v1',
                'scope': 'single_client_no_external_probes_' + self.manager_order + '_manager',
                'counts': dict(self._counts), 'authority': 'observation_only'}
