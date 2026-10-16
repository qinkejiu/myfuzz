"""Bind optional observations to the existing profile capability assessment.

An internal-consumption certificate does not prove every feature operation.
Only code-owned rules can say a scope covers a specific declared operation.
"""
from copy import deepcopy
from dataclasses import asdict

from myfuzz.composition.ip_test_levels import (
    assess_ip_test_level, VerifiedCapabilitySnapshot)
from .semantic_evidence_plugins import capability_binding_supported, capability_certificate_supported


class SemanticCapabilityBinding:
    def __init__(self, alias, *, profile, sidecar, runtime_support, bindings,
                 configurations, base_dir):
        assessment = assess_ip_test_level(profile, sidecar=sidecar, runtime_support=runtime_support)
        effective = {(r.endpoint_id, r.operation, r.scope): r.level
                     for r in assessment.support_matrix if r.effective}
        if type(bindings) is not dict or not 1 <= len(bindings) <= len(configurations):
            raise ValueError('semantic-capability-bindings-invalid')
        selected, gaps, rules = {}, {}, {}
        for operation_id, key in bindings.items():
            if (type(operation_id) is not str or operation_id not in configurations
                    or type(key) is not tuple or len(key) not in (2, 3)
                    or any(type(value) is not str or not value for value in key)):
                raise ValueError('semantic-capability-binding-invalid')
            key = key if len(key) == 3 else (*key, None)
            config = configurations[operation_id]
            if (effective.get(key) != config['level']
                    or config['parameters'].get('component', alias) != alias):
                raise ValueError('semantic-capability-binding-not-effective')
            supported, reason = capability_binding_supported(config['provider'],
                config['parameters'], profile=profile, sidecar=sidecar, key=key,
                base_dir=base_dir)
            if supported:
                selected[operation_id] = key
                rules[operation_id] = (config['provider'], deepcopy(config['parameters']))
            else:
                gaps[operation_id] = reason
        self._profile, self._sidecar = profile, sidecar
        self._selected = selected
        self._rules = rules
        self._material = dict(component_id=profile.component_id,
            profile_fingerprint=profile.profile_fingerprint,
            sidecar_fingerprint=sidecar.sidecar_fingerprint if sidecar else None,
            bindings={name: list(key) for name, key in bindings.items()}, gaps=gaps,
            runtime_preflight=asdict(runtime_support),
            effective_operations=[list(key) for key in sorted(effective,
                key=lambda v: (v[0], v[1], v[2] or ''))])

    def document(self):
        return deepcopy(self._material)

    def snapshot(self, report):
        operations = {}
        if report['journal_integrity']:
            for operation_id, key in self._selected.items():
                observation = report['operations'][operation_id]
                if observation['status'] != 'verified':
                    continue
                records = observation['evidence']['ledger']['records']['verified']
                certificates = {row['evidence_id']: row
                                for row in observation['evidence']['certificates']}
                name, parameters = self._rules[operation_id]
                refs = {'dependency_evidence:' + record['evidence_id'] for record in records
                    if capability_certificate_supported(name, parameters, key,
                        certificates[record['evidence_id']])}
                if refs:
                    operations[key] = tuple(sorted(set(operations.get(key, ())) | refs))[:64]
        return VerifiedCapabilitySnapshot.from_mapping(self._profile,
            sidecar=self._sidecar, operations=operations)
