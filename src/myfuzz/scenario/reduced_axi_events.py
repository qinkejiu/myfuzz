"""Receipt-bound observation of the exact reduced dual AXI single-beat ABI.

This observes protocol edges; it supplies no retirement or memory authority.
Only pre is an accepting edge. Post is retained and checks stalled offers.
"""
from __future__ import annotations

import copy
import json
from myfuzz.local_harness.vexii_axi_fields import ABSENT, SHAPES

SCHEMA = 'reduced_axi_observation.v1'


class ReducedAxiObserver:
    def __init__(self, *, component_id, max_edges=100000, max_bytes=64*1024*1024,
                 max_scopes=1024):
        if not isinstance(component_id, str) or not component_id:
            raise ValueError('reduced_axi_component_required')
        if any(type(n) is not int or n < 1 for n in (max_edges, max_bytes, max_scopes)):
            raise ValueError('reduced_axi_budget_invalid')
        self.component_id = component_id
        self.events = []
        self.scope = None
        self.max_edges, self.max_bytes = max_edges, max_bytes
        self._edges = self._bytes = self._scopes = 0
        self.max_scopes = max_scopes
        self._budget_exhausted = False
        self.contract = {
            'schema_version': SCHEMA, 'variant': 'reduced_dual_single_beat.v1',
            'signal_shapes': {p: {r: {'direction': d, 'width': w}
                                  for r, (d, w) in shape.items()}
                              for p, shape in SHAPES.items()},
            'absent_roles': {r: 'not_exposed' for r in sorted(ABSENT)},
            'sampling': 'pre_acceptance_post_hold_only',
            'raw_reference_namespace': 'observer_stream_local_record_index',
            'budgets': {'max_edges': max_edges, 'max_raw_bytes': max_bytes,
                        'max_events_per_edge': 11, 'max_scopes': max_scopes,
                        'max_records': max_edges*11 + max_scopes + 2,
                        'read_per_face': 1,
                        'write_contexts': 1, 'beats_per_transaction': 1},
            'response_status': {'0': 'okay', '1': 'exclusive_response_unsupported',
                                '2': 'slave_error', '3': 'decode_error'},
            'authority': 'observation_only',
        }
        self._clear()

    def _clear(self):
        self._state = {p: {'read': None, 'aw': None, 'w': None, 'write': None}
                       for p in SHAPES}
        self._holds = {}
        self._tick = 0
        self._failed = False
        self.accepted = {p+'_'+c: 0 for p in SHAPES
                         for c in ('ar', 'r', 'aw', 'w', 'b')
                         if c+'valid' in SHAPES[p]}

    @property
    def pending(self):
        return {p: {k: v is not None for k, v in s.items()}
                for p, s in self._state.items()}

    def _emit(self, kind, **fields):
        event = {'schema_version': SCHEMA, 'kind': kind,
                 'component_id': self.component_id, 'scope': copy.deepcopy(self.scope),
                 'authority': 'observation_only', 'runtime_accepted': False,
                 'semantic_accepted': False, **copy.deepcopy(fields)}
        self.events.append(event)
        return event

    def end_scope(self):
        if self.scope is not None:
            self._emit('reduced_axi_reset', cancelled=self.pending,
                       pending_request_refs=self._state, next_scope=None)
        self.scope = None
        self._clear()

    def begin_scope(self, *, execution_id, testcase_id, reset_epoch):
        if (not all(isinstance(v, str) and v for v in (execution_id, testcase_id))
                or type(reset_epoch) is not int or reset_epoch < 0):
            raise ValueError('reduced_axi_scope_invalid')
        scope = dict(execution_id=execution_id, testcase_id=testcase_id,
                     reset_epoch=reset_epoch, source_component=self.component_id)
        if self._budget_exhausted:
            raise ValueError('reduced_axi_budget_exhausted')
        if self._scopes >= self.max_scopes:
            raise ValueError('reduced_axi_scope_budget')
        if scope == self.scope:
            raise ValueError('reduced_axi_scope_reuse')
        if self.scope is not None:
            self._emit('reduced_axi_reset', cancelled=self.pending,
                       pending_request_refs=self._state, next_scope=scope)
        self.scope = scope
        self._scopes += 1
        self._clear()

    def _fail(self, reason, raw_ref):
        self._failed = True
        if reason == 'budget':
            self._budget_exhausted = True
        self._emit('reduced_axi_violation', reason=reason, raw_event_refs=[raw_ref],
                   pending=self.pending, local_tick=self._tick)
        raise ValueError('reduced_axi_' + reason)

    def require_active(self):
        """Reject a poisoned stream before a caller advances its transport."""
        if self.scope is None or self._failed or self._budget_exhausted:
            raise ValueError('reduced_axi_scope_not_active')

    def observe(self, sample):
        self.require_active()
        # Keep the original failure edge even when shape or budgets fail.
        raw_ref = len(self.events) + 1
        self._emit('reduced_axi_raw', raw_event_ref=raw_ref, raw_sample=sample)
        self._edges += 1
        try:
            self._bytes += len(json.dumps(sample, sort_keys=True, allow_nan=False).encode())
        except (TypeError, ValueError):
            self._fail('shape', raw_ref)
        if self._edges > self.max_edges or self._bytes > self.max_bytes:
            self._fail('budget', raw_ref)
        if not isinstance(sample, dict):
            self._fail('shape', raw_ref)
        tick = sample.get('local_tick')
        if type(tick) is not int or tick <= self._tick:
            self._fail('tick', raw_ref)
        self._tick = tick
        expected = {p+'_'+r: w for p, s in SHAPES.items() for r, (_, w) in s.items()}
        rows = {}
        for phase in ('pre', 'post'):
            group = sample.get(phase)
            row = group.get('backend') if isinstance(group, dict) else None
            if (not isinstance(row, dict) or set(row) != set(expected)
                    or any(type(row[k]) is not int or not 0 <= row[k] < 1 << w
                           for k, w in expected.items())):
                self._fail('shape', raw_ref)
            rows[phase] = row
        # Check stable VALID plus all actual channel payload roles across both
        # pre→post and post→next-pre while the accepting pre had READY low.
        for p, shape in SHAPES.items():
            for c in ('ar', 'r', 'aw', 'w', 'b'):
                if c+'valid' not in shape:
                    continue
                roles = [r for r in shape if r.startswith(c) and r != c+'ready']
                before = {r: rows['pre'][p+'_'+r] for r in roles}
                after = {r: rows['post'][p+'_'+r] for r in roles}
                hold = self._holds.pop((p, c), None)
                if hold is not None and before != hold:
                    self._fail('hold', raw_ref)
                if before[c+'valid'] and not rows['pre'][p+'_'+c+'ready']:
                    if after != before:
                        self._fail('hold', raw_ref)
                    self._holds[p, c] = after
        for p, shape in SHAPES.items():
            row = {r: rows['pre'][p+'_'+r] for r in shape}
            state = self._state[p]
            hit = lambda c: bool(row.get(c+'valid', 0) and row.get(c+'ready', 0))
            # Responses consume only contexts from earlier measured edges.
            for c, slot, idrole in (('r', 'read', 'rid'), ('b', 'write', 'bid')):
                if row.get(c+'valid', 0):
                    pending = state[slot]
                    if pending is None:
                        self._fail('orphan_'+c, raw_ref)
                    if row[idrole] != pending['id']:
                        self._fail('response_id', raw_ref)
                    if c == 'r' and row['rlast'] != 1:
                        self._fail('last', raw_ref)
                    if row[c+'resp'] == 1:
                        self._fail('exclusive_response_unsupported', raw_ref)
                    if hit(c):
                        self.accepted[p+'_'+c] += 1
                        self._emit('reduced_axi_complete', endpoint_id=p, channel=c,
                                   local_tick=tick, payload=row,
                                   raw_event_refs=[raw_ref], request_refs=pending['refs'])
                        state[slot] = None
            for c in ('ar', 'aw', 'w'):
                if not hit(c):
                    continue
                slot = 'read' if c == 'ar' else c
                if state[slot] is not None or c in ('aw', 'w') and state['write'] is not None:
                    self._fail('outstanding_budget', raw_ref)
                if c in ('ar', 'aw'):
                    size, address = row[c+'size'], row[c+'addr']
                    if size > 2 or address % (1 << size):
                        self._fail('size_alignment', raw_ref)
                    pending = {'id': row[c+'id'], 'address': address,
                               'size': size, 'refs': [raw_ref], 'tick': tick}
                else:
                    if row['wlast'] != 1:
                        self._fail('last', raw_ref)
                    pending = {'strobe': row['wstrb'], 'refs': [raw_ref], 'tick': tick}
                state[slot] = pending
                self.accepted[p+'_'+c] += 1
                self._emit('reduced_axi_accept', endpoint_id=p, channel=c,
                           local_tick=tick, payload=row, raw_event_refs=[raw_ref])
            if state['aw'] is not None and state['w'] is not None:
                aw, w = state['aw'], state['w']
                allowed = ((1 << (1 << aw['size']))-1) << (aw['address'] & 3)
                if w['strobe'] & ~allowed:
                    self._fail('strobe_lanes', raw_ref)
                refs = aw['refs'] + w['refs']
                state['write'] = {**aw, 'refs': refs}
                state['aw'] = state['w'] = None
                order = ('same_edge' if aw['tick'] == w['tick'] else
                         'aw_before_w' if aw['tick'] < w['tick'] else 'w_before_aw')
                self._emit('reduced_axi_write_join', endpoint_id=p, local_tick=tick,
                           aw_w_order=order, raw_event_refs=refs, native_id=aw['id'])
