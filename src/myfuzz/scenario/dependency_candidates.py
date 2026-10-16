"""Bounded receipt correlations for exploration, never runtime proof.

The window is measured in journal positions, not presumed global hardware
cycles. Matching values and nearby receipts remain candidate records. This
consumer cannot drive inputs, modify topology or authorize prerequisites.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json

from .dependency_evidence import DependencyEvidence, _RELATION_SCOPES, _digest, _text
from .ip_base_coverage import IpBaseCoverageConsumer, _EVENT_TYPES


@dataclass(frozen=True)
class CandidateSignal:
    node_id: str
    component_id: str
    instance_id: str
    endpoint_id: str
    role: str
    physical_port: str
    direction: str
    bit_lo: int
    width: int
    observation_bit_lo: int | None = None
    observation_width: int | None = None

    def __post_init__(self):
        if (any(not _text(v) for v in (self.node_id, self.component_id, self.instance_id,
                                       self.endpoint_id, self.role, self.physical_port))
                or type(self.direction) is not str or self.direction not in ('input', 'output')
                or type(self.bit_lo) is not int or not 0 <= self.bit_lo < 65536
                or type(self.width) is not int or not 1 <= self.width <= 65536
                or self.bit_lo + self.width > 65536):
            raise ValueError('dependency-candidate-signal-invalid')
        low, width = self.observation_bit_lo, self.observation_width
        if (low is not None or width is not None) and (
                type(low) is not int or type(width) is not int or low < 0
                or not 1 <= width <= 65536 or low + width > 65536
                or low > self.bit_lo or self.bit_lo + self.width > low + width):
            raise ValueError('dependency-candidate-signal-observation-invalid')

    @property
    def key(self):
        return (self.component_id, self.instance_id, self.endpoint_id, self.role,
                self.physical_port, self.direction, self.bit_lo, self.width)

    @property
    def observation_key(self):
        if self.observation_bit_lo is None:
            return self.key
        return (*self.key[:-2], self.observation_bit_lo, self.observation_width)


@dataclass(frozen=True)
class CandidateRelation:
    relation_id: str
    source: str
    target: str
    relation: str
    declaration_ref: str | None = None

    def __post_init__(self):
        if (any(not _text(v) for v in (self.relation_id, self.source, self.target, self.relation))
                or self.relation not in _RELATION_SCOPES or self.source == self.target
                or self.declaration_ref is not None and not _digest(self.declaration_ref)):
            raise ValueError('dependency-candidate-relation-invalid')


class DependencyCandidateConsumer:
    def __init__(self, *, signals, relations, coverage_features=(), max_pending=1024,
                 max_event_gap=256, max_records=1024, counter_cap=65535, base_coverage=None,
                 allow_signal_aliases=False):
        if type(allow_signal_aliases) is not bool:
            raise ValueError('dependency-candidate-signal-alias-policy-invalid')
        for name, value in (('pending', max_pending), ('window', max_event_gap),
                            ('records', max_records), ('counter', counter_cap)):
            if type(value) is not int or not 1 <= value <= 65536:
                raise ValueError('dependency-candidate-bound-invalid:' + name)
        if (type(signals) is not tuple or not 1 <= len(signals) <= 1024
                or any(not isinstance(v, CandidateSignal) for v in signals)
                or type(relations) is not tuple or not 1 <= len(relations) <= 1024
                or any(not isinstance(v, CandidateRelation) for v in relations)
                or type(coverage_features) is not tuple or len(coverage_features) > 64
                or any(not _text(v) or len(v) > 1007 for v in coverage_features)
                or len(set(coverage_features)) != len(coverage_features)):
            raise ValueError('dependency-candidate-configuration-invalid')
        grouped = type(base_coverage) is tuple
        bases = base_coverage if grouped else (() if base_coverage is None else (base_coverage,))
        if (grouped and not 1 <= len(bases) <= 1024
                or any(not isinstance(base, IpBaseCoverageConsumer) or base.cursor != 0 for base in bases)
                or len({(base.component_id, base.instance_id) for base in bases}) != len(bases)):
            raise ValueError('dependency-candidate-coverage-configuration-invalid')
        self._grouped_coverage = grouped
        self._base_coverages = bases
        universe = {self._coverage_key(base, feature) for base in bases for feature in base.feature_universe}
        if any(feature not in universe for feature in coverage_features):
            raise ValueError('dependency-candidate-coverage-configuration-invalid')
        self._coverage_instances = {(base.component_id, base.instance_id): base for base in bases}
        # Reconstruct immutable configuration before retaining caller objects.
        signals = tuple(CandidateSignal(**vars(v)) for v in signals)
        relations = tuple(CandidateRelation(**vars(v)) for v in relations)
        nodes = {s.node_id: s for s in signals}
        if (len(nodes) != len(signals)
                or not allow_signal_aliases and len({s.key for s in signals}) != len(signals)
                or len({r.relation_id for r in relations}) != len(relations)
                or any(r.source not in nodes or r.target not in nodes for r in relations)):
            raise ValueError('dependency-candidate-configuration-invalid')
        self._signals = {}
        for signal in signals:
            self._signals.setdefault(signal.observation_key, []).append(signal)
        self._instances = {(s.component_id, s.instance_id) for s in signals}
        self._source_nodes = {r.source for r in relations}
        self._relations = relations
        self._coverage_features = frozenset(coverage_features)
        self._features = frozenset(f'{r.relation_id}:{reason}' for r in relations
                                  for reason in ('value_match', 'receipt_window',
                                                 *(f'coverage_context:{f}' for f in coverage_features)))
        self.max_pending, self.max_event_gap = max_pending, max_event_gap
        self.max_records, self.counter_cap = max_records, counter_cap
        self.cursor = 0
        self._pending = OrderedDict()
        self._epochs = {}
        self._base_coverage = base_coverage
        self._coverage_known = set()
        self._coverage_pending = {}
        self._seen = set()
        self._records = []
        self._diagnostics = {}

    def _diagnose(self, kind):
        self._diagnostics[kind] = min(self.counter_cap, self._diagnostics.get(kind, 0) + 1)

    @staticmethod
    def _valid_base_envelope(event):
        refs = event.get('raw_event_refs')
        identity = event.get('event_id')
        return (event.get('schema_version') == 'ip_base_event.v1'
                and all(_text(event.get(k)) for k in ('component_id', 'instance_id', 'endpoint_id',
                                                      'event_type', 'local_event_id'))
                and len(event['local_event_id']) <= 1019
                and type(identity) is int and identity > 0
                and type(event.get('tick')) is int and event['tick'] >= 0
                and type(event.get('reset_epoch')) is int and 0 <= event['reset_epoch'] < 1 << 64
                and isinstance(event.get('payload'), Mapping)
                and type(refs) is list and 1 <= len(refs) <= 64
                and all(type(ref) is int and 0 < ref < identity for ref in refs)
                and len(set(refs)) == len(refs))

    def _coverage_event(self, event):
        if event.get('kind') == 'local_tick_sample' and event.get('schema_version') != 'ip_base_event.v1':
            # The base consumer validates raw envelope and target snapshots.
            return event
        if not self._valid_base_envelope(event):
            return {}
        base = self._coverage_instances.get((event['component_id'], event['instance_id']))
        if base is None:
            return {}
        if event.get('event_type') in ('port_sample', 'signal_change', 'input_sample'):
            if not self._valid_physical_payload(event):
                return {}
            key = tuple(event.get(k) for k in ('endpoint_id', 'role', 'direction', 'physical_port',
                                              'bit_lo')) + (event['payload']['width'],)
            if any(type(v) is not str for v in key[:4]) or type(key[4]) is not int:
                return {}
            if key not in base._slices:
                return {}
        elif (event['event_type'] not in _EVENT_TYPES
              or event['endpoint_id'] not in base._protocols):
            return {}
        if not self._observe_epoch(event):
            return {}
        return event

    def _coverage_key(self, base, feature):
        return (json.dumps([base.component_id, base.instance_id, feature], separators=(',', ':'),
                           ensure_ascii=False) if self._grouped_coverage else feature)

    @staticmethod
    def _valid_physical_payload(event):
        payload = event['payload']
        width, value = payload.get('width'), payload.get('value')
        if (type(width) is not int or not 1 <= width <= 65536
                or type(value) is not int or not 0 <= value < 1 << width):
            return False
        if event['event_type'] == 'signal_change':
            previous = payload.get('previous_value')
            return type(previous) is int and 0 <= previous < 1 << width and previous != value
        return True

    def _observe_epoch(self, event):
        instance, epoch = event.get('instance_id'), event.get('reset_epoch')
        if (type(instance) is not str or (event.get('component_id'), instance) not in self._instances
                or type(epoch) is not int or not 0 <= epoch < 1 << 64):
            return False
        old = self._epochs.get(instance)
        if old is not None and epoch < old:
            self._diagnose('stale_epoch')
            return False
        if old is not None and old != epoch:
            self._coverage_pending.clear()
            for node, observed in tuple(self._pending.items()):
                if observed['instance'] == instance:
                    del self._pending[node]
                    self._diagnose('reset_invalidated')
        self._epochs[instance] = epoch
        return True

    def _sample(self, event, cursor):
        if not self._valid_base_envelope(event):
            return ()
        if event.get('event_type') not in ('port_sample', 'signal_change', 'reset_observation'):
            return ()
        payload = event.get('payload')
        if not self._valid_physical_payload(event):
            self._diagnose('invalid_sample')
            return ()
        key = tuple(event.get(k) for k in ('component_id', 'instance_id', 'endpoint_id', 'role',
                                          'physical_port', 'direction', 'bit_lo')) + (payload['width'],)
        if (any(type(v) is not str for v in key[:6]) or type(key[6]) is not int):
            self._diagnose('invalid_sample')
            return ()
        signals = self._signals.get(key)
        if signals is None or not self._observe_epoch(event):
            return ()
        if event.get('event_type') == 'reset_observation':
            return ()
        produced = []
        for signal in signals:
            low = signal.bit_lo - key[-2]
            mask = (1 << signal.width) - 1
            value = (payload['value'] >> low) & mask
            if (event['event_type'] == 'signal_change'
                    and (payload['previous_value'] >> low) & mask == value):
                continue
            produced.extend(self._observe_signal(signal, event, cursor, value))
        return tuple(produced)

    def _observe_signal(self, signal, event, cursor, value):
        observed = dict(cursor=cursor, event_id=event['event_id'],
                        ref='base:' + event['local_event_id'], instance=signal.instance_id,
                        epoch=event['reset_epoch'], value=value)
        produced = []
        for relation in self._relations:
            source = self._pending.get(relation.source)
            if relation.target != signal.node_id or source is None or source['event_id'] >= observed['event_id']:
                continue
            if source['ref'] == observed['ref']:
                self._diagnose('duplicate_reference')
                continue
            # Epochs are local. Different components need not have equal epoch
            # numbers, but a same-component pair cannot span a reset.
            if source['instance'] == observed['instance'] and source['epoch'] != observed['epoch']:
                continue
            reason = 'value_match' if source['value'] == observed['value'] else 'receipt_window'
            for rule in (reason, *(f'coverage_context:{f}' for f in sorted(self._coverage_pending))):
                feature = f'{relation.relation_id}:{rule}'
                if feature in self._seen:
                    continue
                if len(self._records) >= self.max_records:
                    self._seen.add(feature)
                    self._diagnose('record_limit')
                    continue
                refs = (source['ref'], observed['ref'])
                if rule.startswith('coverage_context:'):
                    coverage_ref = self._coverage_pending[rule[len('coverage_context:'):]][1]
                    refs = tuple(dict.fromkeys((*refs, coverage_ref)))
                record = DependencyEvidence(
                    evidence_type='candidate', relation=relation.relation,
                    source=relation.source, target=relation.target, scope='event_correlation',
                    evidence_refs=refs, rule_id=rule, rule_version='1',
                    epochs=tuple({source['instance']: source['epoch'],
                                  observed['instance']: observed['epoch']}.items()),
                    declaration_ref=relation.declaration_ref)
                self._seen.add(feature)
                self._records.append(record)
                produced.append(record)
        if signal.node_id in self._source_nodes:
            self._pending.pop(signal.node_id, None)
            self._pending[signal.node_id] = observed
            while len(self._pending) > self.max_pending:
                self._pending.popitem(last=False)
                self._diagnose('pending_eviction')
        return tuple(produced)

    def consume(self, events, *, start_cursor, new_base_features=()):
        if (type(start_cursor) is not int or not 0 <= start_cursor <= self.cursor
                or not isinstance(events, Sequence) or isinstance(events, (str, bytes))):
            raise ValueError('dependency-candidate-cursor-gap')
        # Coverage context comes from the real base consumer's newly observed
        # features. Callers cannot label even a known feature as newly covered.
        if type(new_base_features) is not tuple or new_base_features:
            raise ValueError('dependency-candidate-coverage-feature-invalid')
        produced = []
        for offset in range(max(0, self.cursor - start_cursor), len(events)):
            event = events[offset]
            if not isinstance(event, Mapping):
                raise ValueError('dependency-candidate-event-invalid')
            cursor = start_cursor + offset
            for node, observed in tuple(self._pending.items()):
                if cursor - observed['cursor'] > self.max_event_gap:
                    del self._pending[node]
                    self._diagnose('window_expired')
            for feature, (observed_cursor, _) in tuple(self._coverage_pending.items()):
                if cursor - observed_cursor > self.max_event_gap:
                    del self._coverage_pending[feature]
            if self._base_coverages:
                if any(base.cursor != cursor for base in self._base_coverages):
                    raise ValueError('dependency-candidate-coverage-cursor-gap')
                coverage_event = self._coverage_event(event)
                for base in self._base_coverages:
                    base.consume((coverage_event,), start_cursor=cursor)
                features = {self._coverage_key(base, feature)
                    for base in self._base_coverages for feature in base.counts} & self._coverage_features
                for feature in features - self._coverage_known:
                    self._coverage_pending[feature] = (cursor, f'journal:{cursor}')
                self._coverage_known.update(features)
            produced.extend(self._sample(event, cursor))
            self.cursor = cursor + 1
        return tuple(produced)

    def snapshot(self):
        return {'schema_version': 'dependency_candidate_discovery.v1',
                'proof_scope': 'exploration_suggestions_only', 'cursor': self.cursor,
                'feature_capacity': len(self._features),
                'feature_counts': {f: 1 for f in sorted(self._seen)},
                'candidate_records': [r.document() for r in self._records],
                'diagnostics': dict(self._diagnostics), 'pending_count': len(self._pending),
                'coverage_pending_count': len(self._coverage_pending),
                'bounds': {'max_pending': self.max_pending, 'max_event_gap': self.max_event_gap,
                           'max_records': self.max_records, 'counter_cap': self.counter_cap}}
