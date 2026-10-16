"""Bounded per-operation optional semantic evidence beside L1 observations.

Register and functional proofs retain distinct scopes. Missing providers do
not manufacture facts or withdraw protocol/binding evidence. This coordinator
neither grants prerequisites nor rewrites topology, raw or base events.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import re

from .semantic_evidence_plugins import provider_spec, create_provider


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _text(value):
    return type(value) is str and 0 < len(value) <= 512 and value.strip() == value


def _parameters(value, depth=0):
    # A finite data tree; no scripts, functions, arbitrary objects or NaN.
    if depth > 4:
        return False
    if type(value) is dict:
        return len(value) <= 64 and all(_text(k) and _parameters(v, depth+1)
                                      for k, v in value.items())
    if type(value) is list:
        return len(value) <= 64 and all(_parameters(v, depth+1) for v in value)
    return value is None or type(value) is bool or _text(value) or (
        type(value) is int and -(1 << 64) < value < 1 << 64)


class IpSemanticEvidenceConsumer:
    def __init__(self, configurations, *, runtime_contract_sha256,
                 max_operations=16, max_records=256, max_event_gap=4096,
                 max_accesses=256):
        if (any(type(v) is not int or not 1 <= v <= 65536 for v in
                (max_records, max_event_gap, max_accesses))
                or type(max_operations) is not int or not 1 <= max_operations <= 128
                or type(runtime_contract_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', runtime_contract_sha256) is None
                or type(configurations) is not dict
                or not 1 <= len(configurations) <= max_operations):
            raise ValueError('semantic-evidence-configuration-invalid')
        configs = deepcopy(configurations)
        for operation, config in configs.items():
            if (not _text(operation) or type(config) is not dict
                    or set(config) != {'level', 'provider', 'parameters'}
                    or type(config['level']) is not str or config['level'] not in ('L2', 'L3')
                    or config['provider'] is not None and not _text(config['provider'])
                    or type(config['parameters']) is not dict
                    or not _parameters(config['parameters'])
                    or len(_canonical(config['parameters'])) > 4096):
                raise ValueError('semantic-evidence-operation-invalid')
            spec = provider_spec(config['provider'])
            if spec is not None and spec[0] != config['level']:
                raise ValueError('semantic-evidence-provider-level-mismatch')
        self._bounds = dict(max_operations=max_operations,
            max_records_per_operation=max_records, max_event_gap=max_event_gap,
            max_accesses_per_operation=max_accesses)
        self._config_hash = hashlib.sha256(_canonical(dict(
            operations=configs, bounds=self._bounds,
            runtime_contract_sha256=runtime_contract_sha256))).hexdigest()
        self._runtime_hash = runtime_contract_sha256
        self._base_config_hash = self._config_hash
        self._capability_bindings = {}
        self._configs = configs
        self._providers = {}
        for operation, config in configs.items():
            if provider_spec(config['provider']) is not None:
                self._providers[operation] = create_provider(config['provider'],
                    config['parameters'], runtime_contract_sha256=runtime_contract_sha256,
                    max_records=max_records, max_event_gap=max_event_gap,
                    max_accesses=max_accesses)
        self._last_id = 0
        self._digests = OrderedDict()
        self._integrity = True

    def consume(self, event):
        try:
            if type(event) is not dict or type(event.get('event_id')) is not int:
                raise ValueError('malformed journal')
            digest = hashlib.sha256(_canonical(event)).hexdigest()
        except (TypeError, ValueError, OverflowError, RecursionError):
            self._integrity = False
            return
        event_id = event['event_id']
        if event_id <= self._last_id:
            if self._digests.get(event_id) != digest:
                self._integrity = False
            return
        if event_id != self._last_id + 1:
            self._integrity = False
        self._last_id = event_id
        self._digests[event_id] = digest
        while len(self._digests) > self._bounds['max_event_gap']:
            self._digests.popitem(last=False)
        if self._integrity:
            for provider in self._providers.values():
                provider.consume(event)

    def report(self):
        operations = {}
        counts = dict(register_version=0, functional_consumption=0)
        for operation, config in self._configs.items():
            provider = self._providers.get(operation)
            if provider is None:
                operations[operation] = dict(level=config['level'], provider=config['provider'],
                    scope=None, status='unknown' if self._integrity else 'incomplete',
                    reason='missing_semantic_provider' if self._integrity else 'journal_integrity_failed',
                    counts=dict(verified=0), evidence=None)
                continue
            evidence = provider.report()
            scope = provider_spec(config['provider'])[1]
            status = evidence['register_status'] if config['level'] == 'L2' else evidence['functional_status']
            count = evidence['counts']['verified']
            counts[scope] += count
            operations[operation] = dict(level=config['level'], provider=config['provider'],
                scope=scope, status=status if self._integrity else 'incomplete',
                reason=evidence['reason'] if self._integrity else 'journal_integrity_failed',
                counts=dict(verified=count), evidence=evidence)
        return deepcopy(dict(schema_version='ip_semantic_evidence_report.v1',
            proof_scope='historical_per_operation_semantic_observations',
            configuration_sha256=self._config_hash,
            runtime_contract_sha256=self._runtime_hash, journal_integrity=self._integrity,
            last_event_id=self._last_id, bounds=self._bounds,
            capability_bindings={name: binding.document()
                for name, binding in self._capability_bindings.items()},
            counts=counts, operations=operations))

    def bind_capabilities(self, alias, **kwargs):
        if (not _text(alias) or self._last_id or not self._integrity
                or alias in self._capability_bindings
                or len(self._capability_bindings) >= self._bounds['max_operations']):
            raise ValueError('semantic-capabilities-must-bind-once-before-ingest')
        from .ip_semantic_capabilities import SemanticCapabilityBinding
        binding = SemanticCapabilityBinding(alias, configurations=self._configs, **kwargs)
        self._capability_bindings[alias] = binding
        self._config_hash = hashlib.sha256(_canonical(dict(
            evidence_configuration=self._base_config_hash,
            capabilities={name: value.document() for name, value in
                          self._capability_bindings.items()}))).hexdigest()

    def capability_snapshot(self, alias):
        if type(alias) is not str or alias not in self._capability_bindings:
            raise ValueError('semantic-capabilities-not-bound')
        return self._capability_bindings[alias].snapshot(self.report())

    def derived_events(self):
        """Detached typed projections; no raw/base journal append or mutation."""
        events = []
        for operation, observation in self.report()['operations'].items():
            evidence = observation['evidence']
            if evidence is None:
                continue
            certificates = {row['evidence_id']: row for row in evidence['certificates']}
            for record in evidence['ledger']['records']['verified']:
                function = observation['level'] == 'L3'
                event = dict(schema_version='ip_function_event.v1' if function else 'ip_register_event.v1',
                    event_type='consumption' if function else 'register_version',
                    operation_id=operation, rule_id=record['rule_id'], rule_version=record['rule_version'],
                    proof_scope=record['scope'], evidence_id=record['evidence_id'],
                    validity=record['validity'], reset_epochs=record['epochs'],
                    raw_event_refs=[int(ref[8:]) for ref in record['evidence_refs'] if ref.startswith('journal:')],
                    base_event_refs=[], base_evidence_gap='native-observation-has-no-ip-base-projection',
                    observation_configuration_sha256=self._config_hash,
                    runtime_contract_sha256=self._runtime_hash,
                    payload=certificates[record['evidence_id']])
                event['derived_event_id'] = hashlib.sha256(_canonical(event)).hexdigest()
                events.append(event)
        return deepcopy(tuple(events))
