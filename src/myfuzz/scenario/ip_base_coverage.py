"""Finite, cursor-driven L1 coverage over declared IP observations.

Counters saturate at ``counter_cap`` (default 65535). The consumer retains only
bounded correlation state; callers own their immutable event journal. A consume
call returns new input rows with their absolute journal cursors unchanged.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re

from .feedback import CoverageTarget


_PROTOCOLS = frozenset(('tl-ul', 'apb3', 'wishbone', 'axi4-lite'))
_EVENT_TYPES = frozenset((
    'transaction_request', 'transaction_accept', 'transaction_response',
    'transaction_cancel', 'transaction_timeout', 'transaction_duplicate',
    'wait_observation', 'protocol_error'))
_LATENCY_BUCKETS = ('0', '1', '2-3', '4-7', '8-15', '16+')
_DIAGNOSTICS = ('latency_uncorrelated', 'pending_evicted', 'late_response')


@dataclass(frozen=True)
class ConsumedEvent:
    cursor: int
    event: Mapping[str, object]


class IpBaseCoverageConsumer:
    """Count finite base features independently of functional plugins.

    Physical targets name a declared runtime signal or an unambiguous physical
    port. Their masks address the already selected snapshot bits; ``bit_lo`` is
    slice identity, so the observed value is never shifted again. Older direct
    output records retain their original target port predicates.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 endpoint_protocols: Mapping[str, str],
                 physical_exports: Sequence[Mapping[str, object]] = (),
                 targets: Sequence[CoverageTarget] = (),
                 counter_cap: int = 65535, max_pending: int = 1024):
        if (type(component_id) is not str or not component_id
                or type(instance_id) is not str or not instance_id
                or type(counter_cap) is not int or counter_cap < 1
                or type(max_pending) is not int or max_pending < 1
                or not isinstance(endpoint_protocols, Mapping)):
            raise ValueError('base-coverage-contract-invalid')
        protocols = {}
        for endpoint, protocol in endpoint_protocols.items():
            if type(endpoint) is not str or not endpoint or protocol not in _PROTOCOLS:
                raise ValueError('base-coverage-protocol-invalid')
            protocols[endpoint] = protocol
        if (not isinstance(physical_exports, Sequence)
                or isinstance(physical_exports, (str, bytes, bytearray))
                or not isinstance(targets, Sequence)
                or isinstance(targets, (str, bytes, bytearray))):
            raise ValueError('base-coverage-declarations-invalid')
        slices = set()
        exports = []
        for row in physical_exports:
            if (not isinstance(row, Mapping)
                    or any(type(row.get(k)) is not str or not row[k]
                           for k in ('endpoint_id', 'role', 'physical_port', 'direction'))
                    or row['direction'] not in ('input', 'output')
                    or type(row.get('bit_lo')) is not int or row['bit_lo'] < 0
                    or type(row.get('width')) is not int or row['width'] < 1):
                raise ValueError('base-coverage-slice-invalid')
            slices.add((row['endpoint_id'], row['role'], row['direction'],
                        row['physical_port'], row['bit_lo'], row['width']))
            runtime_name = row.get('runtime_name')
            encoding = row.get('encoding', 'integer')
            if ((runtime_name is not None
                 and (type(runtime_name) is not str or not runtime_name))
                    or encoding not in ('integer', 'fixed_width_hex')):
                raise ValueError('base-coverage-export-invalid')
            if runtime_name is not None:
                exports.append({'physical_port': row['physical_port'],
                                'runtime_name': runtime_name,
                                'encoding': encoding, 'width': row['width']})
        target_ids = set()
        target_exports = {}
        for target in targets:
            if not isinstance(target, CoverageTarget) or target.target_id in target_ids:
                raise ValueError('base-coverage-target-invalid')
            target_ids.add(target.target_id)
            matches = [row for row in exports
                       if target.port in (row['physical_port'], row['runtime_name'])]
            if len(matches) > 1:
                raise ValueError('base-coverage-target-ambiguous')
            export = matches[0] if matches else None
            if export is not None and target.mask >= 1 << export['width']:
                raise ValueError('base-coverage-target-width')
            target_exports[target.target_id] = export
        self.component_id = component_id
        self.instance_id = instance_id
        self.counter_cap = counter_cap
        self.max_pending = max_pending
        self._protocols = protocols
        self._slices = frozenset(slices)
        self._targets = tuple(targets)
        self._target_exports = target_exports
        features = set()
        for endpoint, protocol in protocols.items():
            features.update(f'event:{endpoint}:{kind}' for kind in _EVENT_TYPES)
            operations = (('read', 'write') if protocol != 'tl-ul'
                          else tuple(f'opcode-{i}' for i in range(8)))
            features.update(f'transaction:{endpoint}:{op}' for op in operations)
            features.update(f'response:{endpoint}:{status}'
                            for status in ('ok', 'error'))
            features.update(f'latency:{endpoint}:{bucket}'
                            for bucket in _LATENCY_BUCKETS)
        features.update(self._slice_feature(slice_key) for slice_key in slices)
        features.update(f'target:{target_id}' for target_id in target_ids)
        self.feature_universe = frozenset(features)
        self.feature_capacity = len(features)
        self.counts: dict[str, int] = {}
        self.diagnostics: dict[str, int] = {}
        self.cursor = 0
        self._pending: OrderedDict[tuple[str, int, int], dict[str, object]] = OrderedDict()
        self._epochs: dict[str, int] = {}

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def snapshot(self) -> dict[str, object]:
        """Return detached, JSON-ready L1 coverage at the current cursor."""
        return {
            'schema_version': 'ip_base_coverage.v1',
            'category': 'base_coverage',
            'component_id': self.component_id,
            'instance_id': self.instance_id,
            'cursor': self.cursor,
            'counts': dict(self.counts),
            'diagnostics': dict(self.diagnostics),
            'feature_capacity': self.feature_capacity,
            'counter_cap': self.counter_cap,
            'pending_count': self.pending_count,
        }

    @staticmethod
    def _slice_feature(slice_key: tuple) -> str:
        return 'port_change:' + ':'.join(str(part) for part in slice_key)

    def _count(self, key: str) -> None:
        if key in self.feature_universe:
            self.counts[key] = min(self.counter_cap, self.counts.get(key, 0) + 1)

    def _diagnose(self, key: str) -> None:
        if key in _DIAGNOSTICS:
            self.diagnostics[key] = min(
                self.counter_cap, self.diagnostics.get(key, 0) + 1)

    @staticmethod
    def _latency_bucket(cycles: int) -> str:
        if cycles < 2:
            return str(cycles)
        if cycles < 4:
            return '2-3'
        if cycles < 8:
            return '4-7'
        if cycles < 16:
            return '8-15'
        return '16+'

    def _consume_raw(self, event: Mapping[str, object]) -> None:
        if (event.get('kind') != 'local_tick_sample'
                or type(event.get('event_id')) is not int or event['event_id'] < 1
                or type(event.get('local_tick')) is not int or event['local_tick'] < 1
                or event.get('phase') not in ('pre', 'post')):
            return
        outputs = event.get('outputs')
        if not isinstance(outputs, Mapping):
            return
        for target in self._targets:
            if event.get('component') != target.component:
                continue
            export = self._target_exports[target.target_id]
            if export is not None and 'physical' in outputs:
                physical = outputs['physical']
                if not isinstance(physical, Mapping):
                    continue
                value = physical.get(export['runtime_name'])
                if export['encoding'] == 'fixed_width_hex':
                    # Decode only admitted fixed-width hex snapshots. No sign,
                    # prefix, padding whitespace, separators or truncated rows.
                    if (type(value) is not str
                            or len(value) != (export['width'] + 3) // 4
                            or re.fullmatch(r'[0-9a-fA-F]+', value) is None):
                        continue
                    value = int(value, 16)
            else:
                # Legacy direct output targets remain valid. A nested name
                # without an export declaration never implies a physical bit.
                value = outputs.get(target.port)
            if (export is not None and (type(value) is not int
                    or not 0 <= value < 1 << export['width'])):
                continue
            if type(value) is int and value & target.mask == target.value:
                self._count(f'target:{target.target_id}')

    def _consume_base(self, event: Mapping[str, object]) -> None:
        if (event.get('schema_version') != 'ip_base_event.v1'
                or event.get('component_id') != self.component_id
                or event.get('instance_id') != self.instance_id):
            return
        endpoint = event.get('endpoint_id')
        kind = event.get('event_type')
        epoch, tick = event.get('reset_epoch'), event.get('tick')
        if (type(endpoint) is not str or not endpoint or type(kind) is not str
                or type(epoch) is not int or epoch < 0
                or type(tick) is not int or tick < 0):
            return
        if kind == 'signal_change':
            payload = event.get('payload')
            if not isinstance(payload, Mapping):
                return
            role, direction, port = (event.get(key) for key in
                                     ('role', 'direction', 'physical_port'))
            low, width = event.get('bit_lo'), payload.get('width')
            if (any(type(value) is not str for value in (role, direction, port))
                    or type(low) is not int or type(width) is not int):
                return
            slice_key = (endpoint, role, direction, port, low, width)
            if slice_key in self._slices:
                self._count(self._slice_feature(slice_key))
            return
        protocol = self._protocols.get(endpoint)
        if protocol is None or kind not in _EVENT_TYPES:
            return
        previous_epoch = self._epochs.get(endpoint)
        if previous_epoch is not None and previous_epoch != epoch:
            for key in tuple(self._pending):
                if key[0] == endpoint:
                    del self._pending[key]
        self._epochs[endpoint] = epoch
        self._count(f'event:{endpoint}:{kind}')
        payload = event.get('payload')
        payload = payload if isinstance(payload, Mapping) else {}
        raw_refs = event.get('raw_event_refs')
        refs = event.get('related_request_event_refs')
        own_ref = (raw_refs[0] if isinstance(raw_refs, (tuple, list)) and len(raw_refs) == 1
                   and type(raw_refs[0]) is int and raw_refs[0] > 0 else None)
        related_ref = (refs[0] if isinstance(refs, (tuple, list)) and len(refs) == 1
                       and type(refs[0]) is int and refs[0] > 0 else None)
        if kind == 'transaction_request':
            signals = payload.get('signals')
            signals = signals if isinstance(signals, Mapping) else {}
            if protocol == 'tl-ul':
                opcode = signals.get('a_opcode')
                operation = (f'opcode-{opcode}' if type(opcode) is int
                             and 0 <= opcode < 8 else None)
            elif protocol == 'axi4-lite':
                # AXI4-Lite has no write-enable bit on its request: a write is
                # the AW/W pair and a read is AR. The projection already names
                # which one this is, so the direction is read from it instead
                # of from a signal that this protocol does not have.
                direction = payload.get('direction')
                operation = direction if direction in ('read', 'write') else None
            else:
                bit = signals.get('pwrite' if protocol == 'apb3' else 'we')
                operation = (('write' if bit else 'read')
                             if type(bit) in (int, bool) and bit in (0, 1)
                             else None)
            if operation is not None:
                self._count(f'transaction:{endpoint}:{operation}')
            if own_ref is not None:
                key = (endpoint, epoch, own_ref)
                if key not in self._pending and len(self._pending) >= self.max_pending:
                    self._pending.popitem(last=False)
                    self._diagnose('pending_evicted')
                self._pending[key] = {'tick': tick, 'accepted_tick': None,
                                      'timed_out': False}
        elif kind == 'transaction_accept' and related_ref is not None:
            pending = self._pending.get((endpoint, epoch, related_ref))
            if (pending is not None and pending['accepted_tick'] is None
                    and tick >= pending['tick']):
                pending['accepted_tick'] = tick
        elif kind == 'transaction_timeout' and related_ref is not None:
            pending = self._pending.get((endpoint, epoch, related_ref))
            if pending is not None:
                pending['timed_out'] = True
        elif kind == 'transaction_cancel' and related_ref is not None:
            self._pending.pop((endpoint, epoch, related_ref), None)
        elif kind == 'transaction_response':
            response = payload.get('signals')
            response = response if isinstance(response, Mapping) else {}
            # Each protocol reports failure its own way: an explicit error
            # signal, APB3's PSLVERR, Wishbone's err, or AXI4-Lite's response
            # code. Reading a key the protocol does not define left the AXI
            # response family permanently unreachable.
            error = (response.get('d_error') if protocol == 'tl-ul'
                     else payload.get('error') if protocol == 'apb3'
                     else bool(payload.get('bresp', payload.get('rresp')))
                     if protocol == 'axi4-lite'
                     else payload.get('err'))
            if protocol == 'axi4-lite':
                error = 1 if error else 0
            if type(error) in (int, bool) and error in (0, 1):
                self._count(f'response:{endpoint}:{"error" if error else "ok"}')
            pending = (self._pending.pop((endpoint, epoch, related_ref), None)
                       if related_ref is not None else None)
            if (pending is None or pending['accepted_tick'] is None
                    or tick < pending['accepted_tick']):
                self._diagnose('latency_uncorrelated')
            else:
                self._count(f'latency:{endpoint}:'
                            f'{self._latency_bucket(tick - pending["accepted_tick"])}')
                if pending['timed_out'] or response.get('matched_timed_out'):
                    self._diagnose('late_response')

    def consume(self, events: Sequence[Mapping[str, object]], *,
                start_cursor: int) -> tuple[ConsumedEvent, ...]:
        """Consume only journal positions at or beyond the current cursor.

        ``start_cursor`` is the position of ``events[0]``. Overlapping prefixes
        are skipped; a missing range raises, so counts cannot silently diverge.
        """
        if (type(start_cursor) is not int or start_cursor < 0
                or start_cursor > self.cursor
                or not isinstance(events, Sequence)
                or isinstance(events, (str, bytes, bytearray))):
            raise ValueError('base-coverage-cursor-gap')
        first = max(0, self.cursor - start_cursor)
        consumed = []
        for offset in range(first, len(events)):
            event = events[offset]
            if not isinstance(event, Mapping):
                raise ValueError('base-coverage-event-invalid')
            cursor = start_cursor + offset
            self._consume_raw(event)
            self._consume_base(event)
            consumed.append(ConsumedEvent(cursor, event))
            self.cursor = cursor + 1
        return tuple(consumed)
