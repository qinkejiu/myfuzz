"""Classify actual host RAM commit-to-read byte versions in the D1 ledger.

Private one-shot callback tokens come from the installed authorities. Saved
labels cannot enroll a callback. Records are historical and grant no active
prerequisite, CPU retirement or source-origin credit.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import re

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger
from .ledger import TransactionKey
from .memory_commit_authority import MemoryCommitAuthority
from .memory_read_authority import MemoryReadAuthority


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _bounded_key(value):
    fields = {'execution_id', 'testcase_id', 'source_component', 'source_epoch',
              'channel_id', 'source_sequence'}
    return (type(value) is dict and set(value) == fields
            and all(type(value[n]) is str and 0 < len(value[n]) <= 512
                    for n in fields - {'source_epoch', 'source_sequence'})
            and all(type(value[n]) is int and 0 <= value[n] < 1 << 64
                    for n in ('source_epoch', 'source_sequence')))


class MemoryDependencyEvidenceConsumer:
    def __init__(self, *, memory_commit_authority, memory_read_authority,
                 runtime_contract_sha256, max_records=256,
                 max_writer_versions=4096, max_event_gap=4096,
                 authority_consumer='default'):
        if (type(memory_commit_authority) is not MemoryCommitAuthority
                or type(memory_read_authority) is not MemoryReadAuthority
                or type(runtime_contract_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', runtime_contract_sha256) is None
                or any(type(n) is not int or not 1 <= n <= 65536
                       for n in (max_records, max_writer_versions, max_event_gap))):
            raise ValueError('invalid memory dependency evidence configuration')
        if (type(authority_consumer) is not str
                or authority_consumer not in memory_commit_authority._consumers
                or authority_consumer not in memory_read_authority._consumers):
            raise ValueError('registered write and read authority consumer required')
        writes, reads = memory_commit_authority._installed, memory_read_authority._installed
        if (set(writes) != set(reads) or any(writes[c][:3] != reads[c]
                                           for c in writes)):
            raise ValueError('same installed write and read services required')
        declaration_count = sum(len(v[3]) for v in writes.values())
        if (declaration_count > 256 or any(len(c) > 256 or any(len(m) > 256 for m in v[3])
                                           for c, v in writes.items())):
            raise ValueError('installed memory declaration bounds exceeded')
        self._commit_authority = memory_commit_authority
        self._read_authority = memory_read_authority
        self._authority_consumer = authority_consumer
        self._runtime = runtime_contract_sha256
        self._bounds = dict(max_records=max_records, max_writer_versions=max_writer_versions,
                            max_event_gap=max_event_gap, max_declared_resources=256,
                            max_transaction_text=512, max_writer_reference_text=4096)
        self._ledger = DependencyEvidenceLedger(
            max_records_per_type=max(max_records, declaration_count))
        self._declarations = {}
        for component, (_, _, memory, ids) in writes.items():
            for memory_id in ids:
                declaration = DependencyEvidence('declared', 'persistent_state',
                    f'{component}:{memory_id}:write', f'{component}:{memory_id}:read',
                    'declared_topology', (f'runtime:{self._runtime}',),
                    'installed_host_memory_byte_version', '1', ())
                self._ledger.append(declaration)
                self._declarations[component, memory_id] = declaration
        self._writers = OrderedDict()
        self._digests = OrderedDict()
        self._certificates = []
        self._last_id = 0
        self._integrity = True
        self._status = 'unknown'
        self._reason = 'no_authenticated_snapshot'

    def _fail(self, reason):
        self._integrity = False
        self._writers.clear()
        self._status, self._reason = 'incomplete', reason

    def consume(self, event, *, commit_token=None, read_token=None):
        # Retire supplied tokens even after a certainty barrier, so installed
        # producers cannot repeatedly drain an unusable issuance.
        commit = self._commit_authority.resolve(commit_token, consumer=self._authority_consumer) if commit_token is not None else None
        read = self._read_authority.resolve(read_token, consumer=self._authority_consumer) if read_token is not None else None
        try:
            if type(event) is not dict or type(event.get('event_id')) is not int:
                raise ValueError('malformed journal')
            event_id = event['event_id']
            digest = hashlib.sha256(_wire(event)).hexdigest()
            if event_id <= self._last_id:
                if self._digests.get(event_id) != digest or commit_token is not None or read_token is not None:
                    self._fail('conflicting_or_reissued_journal_event')
                return
            if event_id != self._last_id + 1:
                self._fail('journal_gap')
            self._last_id = event_id
            self._digests[event_id] = digest
            while len(self._digests) > self._bounds['max_event_gap']:
                self._digests.popitem(last=False)
            while self._writers:
                identity, writer = next(iter(self._writers.items()))
                if event_id - writer['event_id'] <= self._bounds['max_event_gap']:
                    break
                del self._writers[identity]
            if not self._integrity:
                return
            kind = event.get('kind')
            if commit_token is not None and kind != 'memory_write_commit' or read_token is not None and kind != 'memory_read_issuance':
                self._fail('authority_token_kind_mismatch')
            elif kind == 'memory_write_commit':
                self._write(event, commit)
            elif kind == 'memory_read_issuance':
                self._read(event, read)
        except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
            self._fail('malformed_or_inconsistent_memory_evidence')

    def _write(self, event, certificate):
        if certificate is None:
            self._fail('missing_live_commit_authority')
            return
        if not _bounded_key(certificate.get('fullkey')):
            self._fail('transaction_detail_bounds_exceeded')
            return
        if (event.get('schema_version') != 'memory_write_commit.v1'
                or event.get('component') != certificate['component']
                or _wire(event.get('transaction')) != _wire(certificate['fullkey'])
                or any(_wire(event.get(name)) != _wire(certificate[name])
                       for name in ('commit_document', 'commit_id', 'service_commit_sequence'))):
            self._fail('commit_authority_conflict')
            return
        document = certificate['commit_document']
        component, memory_id = certificate['component'], document['memory_id']
        if (component, memory_id) not in self._declarations:
            self._fail('undeclared_installed_memory')
            return
        writer_id = str(TransactionKey(**certificate['fullkey']))
        if len(writer_id) > self._bounds['max_writer_reference_text']:
            self._fail('writer_reference_bounds_exceeded')
            return
        for cell in document['enabled_byte_cells']:
            identity = (component, memory_id, document['generation'], cell['byte_offset'],
                        tuple(cell['version']), cell['writer_event_id'])
            if cell['writer_event_id'] != writer_id or cell['writer_kind'] != 'STORE':
                self._fail('commit_cell_writer_conflict')
                return
            self._writers[identity] = dict(event_id=event['event_id'], value=cell['value'],
                commit_id=certificate['commit_id'], fullkey=deepcopy(certificate['fullkey']))
            self._writers.move_to_end(identity)
            while len(self._writers) > self._bounds['max_writer_versions']:
                self._writers.popitem(last=False)

    def _read(self, event, document):
        if document is None:
            self._fail('missing_live_read_authority')
            return
        if (not _bounded_key(document.get('fullkey'))
                or any(len(ref) > self._bounds['max_writer_reference_text']
                       for ref in document['writer_event_ids'])):
            self._fail('transaction_detail_bounds_exceeded')
            return
        if (event.get('status') != 'accepted'
                or event.get('component') != document['fullkey']['source_component']
                or any(_wire(event.get(name)) != _wire(value) for name, value in document.items())):
            self._fail('read_authority_conflict')
            return
        component, memory_id = event['component'], document['memory_id']
        declaration = self._declarations.get((component, memory_id))
        if declaration is None:
            self._fail('undeclared_installed_memory')
            return
        missing = 0
        for lane, version in enumerate(document['versions']):
            offset = document['byte_offset'] + lane
            writer_id = document['writer_event_ids'][lane]
            identity = (component, memory_id, document['generation'], offset, tuple(version), writer_id)
            writer = self._writers.get(identity)
            value = document['value'] >> (8 * lane) & 255
            if (writer is None or document['writer_kinds'][lane] != 'STORE'
                    or writer['value'] != value or writer['event_id'] >= event['event_id']):
                missing += 1
                continue
            if len(self._certificates) >= self._bounds['max_records']:
                self._status, self._reason = 'incomplete', 'historical_record_capacity'
                return
            record = DependencyEvidence('verified', 'persistent_state', declaration.source,
                declaration.target, 'memory_byte_version',
                (f"journal:{writer['event_id']}", f"journal:{event['event_id']}",
                 f"commit:{writer['commit_id']}", f'byte:{offset}', f'runtime:{self._runtime}'),
                declaration.rule_id, declaration.rule_version,
                ((f'{component}:{memory_id}', document['generation']),),
                declaration_ref=declaration.evidence_id, validity='historical')
            try:
                appended = self._ledger.append(record)
            except ValueError:
                self._status, self._reason = 'incomplete', 'historical_record_capacity'
                return
            if appended:
                self._certificates.append(dict(evidence_id=record.evidence_id,
                    proof_scope='memory_byte_version', validity='historical',
                    memory_kind='modeled_host_persistent_memory', source_origin='unknown',
                    component=component, memory_id=memory_id, generation=document['generation'],
                    byte_offset=offset, byte_version=list(version), value=value,
                    writer_event_id=writer_id, write_event_id=writer['event_id'],
                    read_event_id=event['event_id'], write_transaction=writer['fullkey'],
                    read_transaction=deepcopy(document['fullkey'])))
        self._status = 'incomplete' if missing else 'verified'
        self._reason = 'unobserved_or_expired_byte_writer' if missing else None

    def report(self):
        return deepcopy(dict(schema_version='memory_dependency_evidence_report.v1',
            proof_scope='historical_host_memory_byte_versions_only', grants_prerequisites=False,
            runtime_contract_sha256=self._runtime, bounds=self._bounds,
            journal_integrity=self._integrity, last_event_id=self._last_id,
            status=self._status, reason=self._reason,
            retained_writer_versions=len(self._writers),
            counts=dict(verified=len(self._certificates)), certificates=self._certificates,
            ledger=self._ledger.document()))
