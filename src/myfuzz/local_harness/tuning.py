"""Typed declarative tuning; parsing does not enable an execution strategy."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import re


# Every value is a bounded integer, token or closed enum; no expression language.
_SCHEMAS = {
    'endpoint_policies': {'endpoint_id': 'token', 'template_id': 'token', 'template_version': 'token',
                          'variant_id': 'token', 'max_outstanding': 'positive'},
    'optional_signals': {'endpoint_id': 'token', 'role': 'token', 'policy': ('drive_constant', 'template_default')},
    'reset_policies': {'domain': 'token', 'assert_ticks': 'positive', 'release_ticks': 'ticks'},
    'irq_delivery': {'endpoint_id': 'token', 'role': 'token', 'delivery': ('follow_level', 'capture_pulse_event')},
    'boot': {'endpoint_id': 'token', 'entry_address': 'unsigned'},
    'environment_bindings': {'endpoint_id': 'token', 'role': 'token', 'source_id': 'token'},
    'peer_bindings': {'endpoint_id': 'token', 'peer_id': 'token'},
}
_KEYS = {'endpoint_policies': ('endpoint_id',), 'optional_signals': ('endpoint_id', 'role'),
         'reset_policies': ('domain',), 'irq_delivery': ('endpoint_id', 'role'),
         'boot': ('endpoint_id',), 'environment_bindings': ('endpoint_id', 'role'),
         'peer_bindings': ('endpoint_id',)}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _identity(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class TuningRecord:
    kind: str
    fields: tuple[tuple[str, str | int], ...]

    def document(self):
        return dict(self.fields)


@dataclass(frozen=True, slots=True)
class LocalHarnessTuning:
    records: tuple[TuningRecord, ...] = ()

    def document(self):
        result = {kind: [] for kind in _SCHEMAS if kind != 'boot'}
        for row in self.records:
            if row.kind == 'boot':
                result['boot'] = row.document()
            else:
                result[row.kind].append(row.document())
        return result

    @property
    def identity_sha256(self):
        return _identity(self.document())


def _parse_row(kind, row):
    if not isinstance(row, Mapping):
        raise ValueError('invalid-tuning-row:' + kind)
    shape = dict(_SCHEMAS[kind])
    if kind == 'optional_signals' and row.get('policy') == 'drive_constant':
        shape['value'] = 'unsigned'
    if set(row) != set(shape):
        raise ValueError('unexpected-or-missing-tuning-fields:' + kind)
    for key, rule in shape.items():
        value = row[key]
        if isinstance(rule, tuple):
            valid = isinstance(value, str) and value in rule
        elif rule == 'token':
            valid = isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]*', value) is not None and len(value) <= 128
        else:
            valid = type(value) is int and value >= (1 if rule == 'positive' else 0)
            if rule in ('positive', 'ticks'):
                valid = valid and value <= 1024
            else:
                valid = valid and value.bit_length() <= 4096
        if not valid:
            raise ValueError('invalid-tuning-value:' + kind + ':' + key)
    return TuningRecord(kind, tuple(sorted(row.items())))


def load_local_harness_tuning(document: Mapping[str, object]) -> LocalHarnessTuning:
    if not isinstance(document, Mapping):
        raise ValueError('invalid-tuning-document')
    if set(document) - set(_SCHEMAS):
        raise ValueError('unexpected-tuning-fields')
    records = []
    for kind in sorted(_SCHEMAS):
        if kind not in document:
            continue
        rows = [document[kind]] if kind == 'boot' else document[kind]
        if not isinstance(rows, list) or len(rows) > 1024:
            raise ValueError('invalid-tuning-list:' + kind)
        seen = set()
        for row in rows:
            record = _parse_row(kind, row)
            values = record.document()
            key = tuple(values[name] for name in _KEYS[kind])
            if key in seen:
                raise ValueError('duplicate-tuning-entry:' + kind)
            seen.add(key)
            records.append(record)
    return LocalHarnessTuning(tuple(sorted(records, key=lambda row: (row.kind, tuple(row.document()[k] for k in _KEYS[row.kind])))))


def _json_value(value):
    """Encode actual immutable dataclass facts, including profile-only semantics."""
    from dataclasses import fields, is_dataclass
    if is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise ValueError('unsupported-tuning-identity-value')


@dataclass(frozen=True, slots=True)
class ValidatedLocalHarnessTuning:
    """Frozen evidence of configuration validation, with no runtime capability."""
    _canonical_document: bytes

    def document(self):
        return json.loads(self._canonical_document)

    @property
    def identity_sha256(self):
        return hashlib.sha256(self._canonical_document).hexdigest()


def validate_local_harness_tuning(tuning: LocalHarnessTuning, *, profile, binding,
                                   registered_source_ids=None, bound_inputs=None) -> ValidatedLocalHarnessTuning:
    """Validate pure profile/binding facts, not source locks or runtime support.

    bound_inputs is the caller's complete upstream-owned (endpoint_id, role) set,
    not a list of desired overrides. None means that ownership is unproven.
    registered_source_ids is an explicit existing environment registry snapshot.
    These contexts are mandatory when selecting an environment source. No
    planner, renderer, builder or session invokes this validator automatically.
    """
    from myfuzz.composition.component_profile import ComponentProfile, ProfileBinding, bind_profile
    from myfuzz.composition.soc_port_dispositions import build_port_dispositions
    if not isinstance(tuning, LocalHarnessTuning):
        raise ValueError('local-tuning-required')
    # Direct dataclass construction cannot bypass schema/canonical checks.
    if load_local_harness_tuning(tuning.document()) != tuning:
        raise ValueError('noncanonical-local-tuning')
    if not isinstance(profile, ComponentProfile) or not isinstance(binding, ProfileBinding):
        raise ValueError('local-tuning-profile-binding-required')
    if binding.facts.selection != 'all':
        raise ValueError('local-tuning-full-top-required')
    if binding.facts.revision != profile.source.revision or binding.facts.top_module != profile.source.top_module:
        raise ValueError('local-tuning-source-facts-mismatch')
    if bind_profile(profile, binding.facts) != binding:
        raise ValueError('local-tuning-stale-binding')
    ledger = build_port_dispositions('tuning_validation', binding, clock_domain='local_clock',
        reset_domain='local_reset', profile_port_actions=profile.port_actions)
    sources = None if registered_source_ids is None else _source_context(registered_source_ids)
    owned = None if bound_inputs is None else _owned_context(bound_inputs, binding)
    for row in tuning.records:
        value = row.document()
        kind = row.kind
        if kind in ('endpoint_policies', 'boot', 'peer_bindings', 'optional_signals'):
            raise ValueError('local-tuning-capability-unverified:' + kind)
        if kind == 'reset_policies':
            resets = [reset for reset, _ in binding.resets if reset.domain == value['domain']]
            if not resets:
                raise ValueError('local-tuning-unknown-reset-domain')
            if any(reset.sequence_after for reset in resets):
                raise ValueError('local-tuning-reset-sequence-unverified')
            continue
        endpoint = binding.endpoint(value['endpoint_id'])
        physical = binding.field(value['endpoint_id'], value['role'])
        key = (physical.endpoint_id, physical.role)
        if kind == 'irq_delivery':
            declarations = [irq for irq in profile.interrupts if (irq.endpoint_id, irq.role) == key]
            if physical.direction != 'output' or len(declarations) != 1:
                raise ValueError('local-tuning-irq-fact-required')
            irq = declarations[0]
            if irq.clock_domain not in {clock.domain for clock, _ in binding.clocks}:
                raise ValueError('local-tuning-irq-clock-domain-unverified')
            expected = {'level': 'follow_level', 'pulse': 'capture_pulse_event'}.get(irq.trigger)
            if irq.polarity not in ('active_high', 'active_low') or irq.trigger == 'pulse' and (
                    type(irq.pulse_width_cycles) is not int or irq.pulse_width_cycles < 1):
                raise ValueError('local-tuning-invalid-irq-facts')
            if irq.bit is not None and (type(irq.bit) is not int or not 0 <= irq.bit < physical.width):
                raise ValueError('local-tuning-irq-bit-outside-field')
            if expected is None or value['delivery'] != expected:
                raise ValueError('local-tuning-irq-delivery-mismatch')
            continue
        if physical.direction != 'input':
            raise ValueError('local-tuning-cannot-drive-output')
        if owned is not None and key in owned:
            raise ValueError('local-tuning-input-already-bound')
        # Every selected physical bit must already have one established owner.
        segments = [entry for entry in ledger if entry.port == physical.port and
                    entry.bit_lo <= physical.raw_hi and entry.bit_hi >= physical.raw_lo]
        if kind == 'environment_bindings':
            if sources is None or owned is None:
                raise ValueError('local-tuning-environment-context-required')
            if value['source_id'] not in sources:
                raise ValueError('local-tuning-environment-source-unregistered')
            if endpoint.function != 'external_pins' or any(
                    entry.disposition not in ('external', 'fuzz') for entry in segments):
                raise ValueError('local-tuning-input-not-environment-owned')
    document = {
        'schema_version': 'local_harness_tuning_validation.v1',
        'status': 'validated_configuration_only', 'runtime_effective': False,
        'tuning': tuning.document(), 'binding_hash': binding.binding_hash,
        'profile_contract_sha256': _identity(_json_value(profile)),
        'ownership_context': {'registered_source_ids': None if sources is None else sorted(sources),
                              'bound_inputs': None if owned is None else [list(key) for key in sorted(owned)]},
    }
    return ValidatedLocalHarnessTuning(_canonical(document))


def _source_context(values):
    if not isinstance(values, (set, frozenset)) or any(
            not isinstance(value, str) or len(value) > 128 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]*', value) is None
            for value in values):
        raise ValueError('invalid-tuning-source-context')
    return frozenset(values)


def _owned_context(values, binding):
    if not isinstance(values, (set, frozenset)):
        raise ValueError('invalid-tuning-bound-input-context')
    for key in values:
        if not isinstance(key, tuple) or len(key) != 2 or not all(isinstance(item, str) for item in key):
            raise ValueError('invalid-tuning-bound-input-context')
        if binding.field(*key).direction != 'input':
            raise ValueError('invalid-tuning-bound-input-context')
    return frozenset(values)
