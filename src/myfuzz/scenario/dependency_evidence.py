"""Separate declaration, correlation and proof records without changing topology.

Loading a well-formed verified record authenticates its document identity,
not its runtime facts. A runtime verifier must resolve its referenced journal
and rule before using it as a witness; this ledger grants no prerequisites.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re


EVIDENCE_SCHEMA = 'dependency_evidence.v1'
LEDGER_SCHEMA = 'dependency_evidence_ledger.v1'
EVIDENCE_TYPES = ('declared', 'candidate', 'verified')
_RELATION_SCOPES = {
    'direct_binding': {'binding_delivery_sample', 'irq_delivery'},
    'mmio_route': {'route_delivery', 'register_version'},
    'persistent_state': {'memory_byte_version', 'register_version'},
    'causal_order': {'functional_consumption', 'irq_acceptance', 'cpu_retirement'},
    'protocol_transaction': {'protocol_accept_response'},
}
_FIELDS = frozenset(('evidence_type', 'relation', 'source', 'target', 'scope',
                     'evidence_refs', 'rule_id', 'rule_version', 'epochs',
                     'declaration_ref', 'validity', 'invalidation_reason'))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _text(value):
    return type(value) is str and 0 < len(value) <= 1024 and value.strip() == value


def _digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


@dataclass(frozen=True)
class DependencyEvidence:
    evidence_type: str
    relation: str
    source: str
    target: str
    scope: str
    evidence_refs: tuple[str, ...]
    rule_id: str
    rule_version: str
    epochs: tuple[tuple[str, int], ...]
    declaration_ref: str | None = None
    validity: str = 'active'
    invalidation_reason: str | None = None

    def __post_init__(self):
        if (not _text(self.evidence_type) or self.evidence_type not in EVIDENCE_TYPES
                or not _text(self.relation) or self.relation not in _RELATION_SCOPES
                or any(not _text(v) for v in (self.source, self.target,
                                              self.scope, self.rule_id, self.rule_version))):
            raise ValueError('dependency-evidence-identity-invalid')
        if (type(self.evidence_refs) is not tuple or not 1 <= len(self.evidence_refs) <= 64
                or any(not _text(v) for v in self.evidence_refs)
                or len(set(self.evidence_refs)) != len(self.evidence_refs)):
            raise ValueError('dependency-evidence-references-invalid')
        if (type(self.epochs) is not tuple or len(self.epochs) > 64
                or any(type(v) is not tuple or len(v) != 2 or not _text(v[0])
                       or type(v[1]) is not int or not 0 <= v[1] < 1 << 64
                       for v in self.epochs)
                or len({v[0] for v in self.epochs}) != len(self.epochs)):
            raise ValueError('dependency-evidence-epochs-invalid')
        object.__setattr__(self, 'epochs', tuple(sorted(self.epochs)))
        if self.declaration_ref is not None and not _digest(self.declaration_ref):
            raise ValueError('dependency-evidence-declaration-ref-invalid')
        if self.evidence_type == 'declared':
            if self.scope != 'declared_topology' or self.epochs or self.declaration_ref is not None:
                raise ValueError('dependency-evidence-declaration-scope-invalid')
        elif self.evidence_type == 'candidate':
            if self.scope != 'event_correlation' or not self.epochs:
                raise ValueError('dependency-evidence-candidate-scope-invalid')
        elif (self.scope not in _RELATION_SCOPES[self.relation]
              or len(self.evidence_refs) < 2 or not self.epochs):
            raise ValueError('dependency-evidence-verified-scope-invalid')
        if (type(self.validity) is not str or self.validity not in
                ('active', 'historical', 'invalidated')
                or (self.validity == 'invalidated' and not _text(self.invalidation_reason))
                or (self.validity != 'invalidated' and self.invalidation_reason is not None)):
            raise ValueError('dependency-evidence-validity-invalid')

    def _body(self):
        body = asdict(self)
        body['schema_version'] = EVIDENCE_SCHEMA
        body['epochs'] = dict(self.epochs)
        body['evidence_refs'] = list(self.evidence_refs)
        return body

    @property
    def evidence_id(self):
        return hashlib.sha256(_canonical(self._body())).hexdigest()

    def document(self):
        return {**self._body(), 'evidence_id': self.evidence_id}

    @classmethod
    def from_document(cls, document):
        if (type(document) is not dict
                or set(document) != _FIELDS | {'schema_version', 'evidence_id'}
                or document['schema_version'] != EVIDENCE_SCHEMA
                or type(document['epochs']) is not dict
                or type(document['evidence_refs']) is not list):
            raise ValueError('dependency-evidence-schema-invalid')
        values = {k: document[k] for k in _FIELDS}
        values['epochs'] = tuple(document['epochs'].items())
        values['evidence_refs'] = tuple(document['evidence_refs'])
        result = cls(**values)
        if not _digest(document['evidence_id']) or result.evidence_id != document['evidence_id']:
            raise ValueError('dependency-evidence-digest-mismatch')
        return result


class DependencyEvidenceLedger:
    """Bounded classified storage, independent of runtime topology/witnesses.

    Capacity exhaustion rejects an append instead of silently losing proof
    history. Reports count records, never certified chains or valid witnesses.
    """

    def __init__(self, *, max_records_per_type=4096):
        if type(max_records_per_type) is not int or not 1 <= max_records_per_type <= 65536:
            raise ValueError('dependency-evidence-capacity-invalid')
        self.max_records_per_type = max_records_per_type
        self._records = {kind: {} for kind in EVIDENCE_TYPES}

    def append(self, record):
        if not isinstance(record, DependencyEvidence):
            raise ValueError('dependency-evidence-record-required')
        # Recheck typed records at this trust boundary as callers can bypass
        # frozen dataclasses with object.__setattr__.
        record = DependencyEvidence.from_document(record.document())
        group = self._records[record.evidence_type]
        if record.evidence_id in group:
            return False
        if len(group) >= self.max_records_per_type:
            raise ValueError('dependency-evidence-capacity-exceeded')
        if record.declaration_ref is not None:
            declaration = self._records['declared'].get(record.declaration_ref)
            if declaration is None or (
                    declaration.relation, declaration.source, declaration.target) != (
                    record.relation, record.source, record.target):
                raise ValueError('dependency-evidence-declaration-mismatch')
        group[record.evidence_id] = record
        return True

    def document(self):
        return {'schema_version': LEDGER_SCHEMA,
                'max_records_per_type': self.max_records_per_type,
                'proof_scope': 'classified_records_only',
                'record_counts': {k: len(v) for k, v in self._records.items()},
                'records': {k: [row.document() for row in v.values()]
                            for k, v in self._records.items()}}

    @classmethod
    def from_document(cls, document):
        if (type(document) is not dict or set(document) != {
                'schema_version', 'max_records_per_type', 'proof_scope', 'record_counts', 'records'}
                or document['schema_version'] != LEDGER_SCHEMA
                or document['proof_scope'] != 'classified_records_only'
                or type(document['records']) is not dict
                or set(document['records']) != set(EVIDENCE_TYPES)
                or type(document['record_counts']) is not dict
                or set(document['record_counts']) != set(EVIDENCE_TYPES)):
            raise ValueError('dependency-evidence-ledger-schema-invalid')
        ledger = cls(max_records_per_type=document['max_records_per_type'])
        for kind in EVIDENCE_TYPES:
            rows = document['records'][kind]
            count = document['record_counts'][kind]
            if (type(rows) is not list or len(rows) > ledger.max_records_per_type
                    or type(count) is not int or count != len(rows)):
                raise ValueError('dependency-evidence-ledger-count-invalid')
            for row in rows:
                record = DependencyEvidence.from_document(row)
                if record.evidence_type != kind or not ledger.append(record):
                    raise ValueError('dependency-evidence-ledger-category-invalid')
        return ledger

    def save(self, path):
        # Snapshots are explicit caller-selected artifacts; no topology or
        # raw journal is rewritten, and no runtime event is created.
        Path(path).write_bytes(_canonical(self.document()) + b'\n')

    @classmethod
    def load(cls, path):
        return cls.from_document(json.loads(Path(path).read_bytes()))

    @classmethod
    def from_prepared_contract(cls, prepared, **bounds):
        from .runtime_path_contract import PreparedRuntimePathContract
        if not isinstance(prepared, PreparedRuntimePathContract):
            raise ValueError('dependency-evidence-prepared-contract-required')
        document = prepared.document()
        relations = {(row['rule_index'], row['prerequisite_index']): row
                     for row in document['contract']['edges']}
        ledger = cls(**bounds)
        seen = set()
        contract_id = prepared.contract.identity_sha256
        for selection in document['selections']:
            for edge in selection['edges']:
                key = edge['rule_index'], edge['prerequisite_index']
                if key in seen or key not in relations:
                    continue
                seen.add(key)
                ledger.append(DependencyEvidence(
                    evidence_type='declared', relation=relations[key]['relation'],
                    source=edge['prerequisite'], target=edge['target'], scope='declared_topology',
                    evidence_refs=(f'contract:{contract_id}/edge:{key[0]}:{key[1]}',),
                    rule_id='runtime_path_contract', rule_version='1', epochs=()))
        return ledger
