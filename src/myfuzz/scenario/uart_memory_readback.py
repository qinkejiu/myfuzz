"""Restricted live host RAM low-byte writer to later retired LW readback.

Owns the raw Store join and accepts only one-shot live read issuance from an
installed service wrapper. Saved read snapshots alone have no authority.
"""
from copy import deepcopy
from dataclasses import asdict
import json

from .cpu_retirement import CpuRetirementMatcher
from .ledger import TransactionKey
from .memory_read_authority import MemoryReadAuthority
from .memory_commit_authority import MemoryCommitAuthority
from .uart_store_memory import UartStoreMemoryJoin, _key


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class UartMemoryReadbackJoin:
    def __init__(self, *, memory_commit_authority, memory_read_authority,
                 admission_registry, ownership, edge_index,
                 max_writer_versions=256, max_pending_reads=256,
                 max_instruction_witnesses=2048):
        if (type(memory_commit_authority) is not MemoryCommitAuthority
                or type(memory_read_authority) is not MemoryReadAuthority):
            raise ValueError('installed write and read authorities required')
        if any(type(n) is not int or n < 1 for n in
               (max_writer_versions, max_pending_reads, max_instruction_witnesses)):
            raise ValueError('invalid memory readback capacity')
        self._store = UartStoreMemoryJoin(
            memory_commit_authority=memory_commit_authority,
            admission_registry=admission_registry, ownership=ownership,
            edge_index=edge_index, max_instruction_witnesses=max_instruction_witnesses)
        self._read_authority = memory_read_authority
        self._retire = CpuRetirementMatcher(max_pending=max_instruction_witnesses)
        self._writers = {}
        self._pending_reads = {}
        self.max_writer_versions = max_writer_versions
        self.max_pending_reads = max_pending_reads
        self._bad = False

    @property
    def degraded(self):
        return self._bad or self._store.degraded or self._read_authority.degraded

    @property
    def pending_count(self):
        return len(self._pending_reads)

    def consume(self, event, *, commit_token=None, read_token=None):
        if type(event) is not dict:
            self._bad = True
            return ()
        if self.degraded and event.get('kind') != 'cpu_reset':
            # The installed read callback has already happened. Retire its
            # one-shot authority even while the join cannot certify a load;
            # otherwise the runner drains and logs this same token forever.
            if event.get('kind') == 'memory_read_issuance' and read_token is not None:
                document = self._read_authority.resolve(read_token)
                if (document is None or event.get('status') != 'accepted'
                        or any(_wire(event.get(name)) != _wire(value)
                               for name, value in document.items())):
                    self._bad = True
            return ()
        kind = event.get('kind')
        store_reports = self._store.consume(event, commit_token=commit_token)
        if self._store.degraded:
            self._bad = True
            return tuple(store_reports)
        if kind == 'memory_read_issuance':
            if read_token is None:
                return tuple(store_reports)
            document = self._read_authority.resolve(read_token)
            if document is None:
                self._bad = True
                return tuple(store_reports)
            names = tuple(document)
            if (event.get('status') != 'accepted'
                    or any(_wire(event.get(name)) != _wire(document[name]) for name in names)):
                self._bad = True
                return tuple(store_reports)
            key = _key(document['fullkey'])
            if key is None or key in self._pending_reads or len(self._pending_reads) >= self.max_pending_reads:
                self._bad = True
                return tuple(store_reports)
            self._pending_reads[key] = deepcopy(document)
            return tuple(store_reports)
        if kind == 'cpu_reset':
            self._pending_reads.clear()
            # Host memory survives warm CPU reset. The exact writer version
            # remains addressable until a later cold memory generation.
        cpu_kinds = ('instr_response', 'data_accept', 'data_response',
                     'cpu_retire', 'cpu_reset', 'cpu_flush')
        matches = self._retire.consume(event) if kind in cpu_kinds else ()
        if any(report.get('status') == 'incomplete' for report in matches):
            self._bad = True
            return tuple(store_reports)
        if kind == 'cpu_flush':
            self._pending_reads.clear()
        for report in store_reports:
            if (report.get('kind') != 'uart_store_memory_match'
                    or report.get('status') != 'accepted'):
                continue
            if not self._remember_writer(report):
                return tuple(store_reports)
        output = list(store_reports)
        for match in matches:
            if (kind != 'cpu_retire' or match.get('status') != 'accepted'
                    or type(match.get('insn')) is not int or match['insn'] & 0x707f != 0x2003):
                continue
            keys = match.get('transaction_keys')
            key = _key(keys[0]) if type(keys) is list and len(keys) == 1 else None
            if key is None:
                self._bad = True
                return tuple(output)
            issued = self._pending_reads.pop(key, None)
            if issued is None:
                continue
            proof = self._join(event, match, issued)
            if proof is False:
                continue
            if proof is None:
                self._bad = True
                return tuple(output)
            output.append(proof)
        return tuple(deepcopy(output))

    @staticmethod
    def _writer_identity(record):
        if type(record) is not dict:
            return None
        version = record.get('byte_version')
        if (type(record.get('memory_id')) is not str
                or not record['memory_id']
                or type(record.get('generation')) is not int or record['generation'] < 0
                or type(record.get('byte_offset')) is not int or record['byte_offset'] < 0
                or type(version) is not list or len(version) != 2
                or any(type(value) is not int or value < 0 for value in version)
                or version[0] != record['generation']
                or type(record.get('writer_event_id')) is not str
                or not record['writer_event_id']):
            return None
        return (record['memory_id'], record['generation'],
                record['byte_offset'], tuple(version), record['writer_event_id'])

    def _protected_writer_versions(self):
        """Versions in live issued or already drained reads may retire later."""
        protected = set()
        for record in (*self._read_authority._pending.values(),
                       *self._pending_reads.values()):
            if (type(record) is not dict or type(record.get('versions')) is not list
                    or len(record['versions']) != 4
                    or type(record.get('writer_event_ids')) is not list
                    or len(record['writer_event_ids']) != 4):
                self._bad = True
                return None
            identity = self._writer_identity(dict(
                memory_id=record.get('memory_id'), generation=record.get('generation'),
                byte_offset=record.get('byte_offset'),
                byte_version=record['versions'][0],
                writer_event_id=record['writer_event_ids'][0]))
            if identity is None:
                self._bad = True
                return None
            protected.add(identity)
        return protected

    def _reclaim_obsolete_writers(self):
        """Reclaim only versions absent from current RAM and all live reads.

        Current state is used solely to *remove* stale history; it never
        creates or upgrades a source certificate. Missing installation or
        malformed pending reads keeps history and raises a certainty barrier.
        """
        protected = self._protected_writer_versions()
        if protected is None:
            return 0
        reclaimed = 0
        for identity, writer in tuple(self._writers.items()):
            if identity in protected:
                continue
            fullkey = writer.get('store_fullkey')
            component = fullkey.get('source_component') if type(fullkey) is dict else None
            installed = self._read_authority._installed.get(component)
            if installed is None:
                self._bad = True
                return reclaimed
            service, ledger, memory = installed
            if service.ledger is not ledger or service.memory is not memory:
                self._bad = True
                return reclaimed
            memory_id, generation, offset, version, writer_id = identity
            cell = (memory._bytes.get((memory_id, offset))
                    if memory.generation == generation else None)
            current = (cell is not None and cell.version == version
                       and cell.writer_event_id == writer_id
                       and cell.writer_kind == 'STORE'
                       and cell.value == writer.get('byte_value'))
            if not current:
                del self._writers[identity]
                reclaimed += 1
        return reclaimed

    def _remember_writer(self, report):
        """Store only a privately generated Store certificate within budget."""
        identity = self._writer_identity(report)
        if self.degraded or identity is None or identity in self._writers:
            self._bad = True
            return False
        if len(self._writers) >= self.max_writer_versions:
            self._reclaim_obsolete_writers()
        if self.degraded or len(self._writers) >= self.max_writer_versions:
            self._bad = True
            return False
        self._writers[identity] = deepcopy(report)
        return True

    def _join(self, raw, match, issued):
        key = _key(issued.get('fullkey'))
        beats = match.get('data_beats')
        if (key is None or type(beats) is not list or len(beats) != 1
                or type(raw.get('rd_addr')) is not int or raw['rd_addr'] == 0
                or raw.get('mode') != 3 or raw.get('trap') != 0
                or any(raw.get(name) != 0 for name in
                       ('ext_rf_wr_suppress', 'mem_is_cap', 'mem_rcap', 'rd_wcap'))):
            return None
        beat = beats[0]
        response = beat.get('response')
        if (type(response) is not dict or _key(beat.get('transaction')) != key
                or _key(response.get('transaction')) != key
                or beat.get('write') != 0 or beat.get('be') != 15
                or beat.get('raw_address') != issued.get('address')
                or response.get('rdata') != issued.get('value')
                or raw.get('mem_addr') != issued.get('address')
                or raw.get('mem_rdata') != issued.get('value')
                or raw.get('rd_wdata') != issued.get('value')):
            return None
        snapshot = response.get('snapshot')
        if type(snapshot) is not dict:
            return None
        for field in ('memory_id', 'generation', 'byte_offset', 'data_hex',
                      'versions', 'writer_event_ids', 'writer_kinds', 'value'):
            if _wire(snapshot.get(field)) != _wire(issued.get(field)):
                return None
        if (snapshot.get('transaction_id') != str(TransactionKey(**issued['fullkey']))
                or issued.get('width_bytes') != 4
                or type(issued.get('versions')) is not list or len(issued['versions']) != 4
                or type(issued.get('writer_event_ids')) is not list or len(issued['writer_event_ids']) != 4
                or type(issued.get('writer_kinds')) is not list or len(issued['writer_kinds']) != 4):
            return None
        identity = (issued['memory_id'], issued['generation'], issued['byte_offset'],
                    tuple(issued['versions'][0]), issued['writer_event_ids'][0])
        writer = self._writers.get(identity)
        if writer is None:
            return False
        if (issued['writer_kinds'][0] != 'STORE'
                or issued['data_hex'][:2] != f"{writer['byte_value']:02x}"
                or writer['byte_version'] != issued['versions'][0]):
            return None
        provenance = raw.get('provenance')
        observed_case = provenance.get('observed_case') if type(provenance) is dict else None
        if (type(observed_case) is not dict
                or type(observed_case.get('case_id')) is not str
                or type(observed_case.get('case_index')) is not int):
            observed_case = None
        return dict(kind='uart_memory_readback', schema_version='uart_memory_readback.v1',
            status='accepted', proof_scope='uart_host_ram_low_byte_retired_load_readback',
            memory_kind='modeled_host_persistent_memory',
            store_fullkey=deepcopy(writer['store_fullkey']),
            store_retirement_event_id=writer['store_retirement_event_id'],
            store_byte_version=deepcopy(writer['byte_version']),
            store_commit_id=writer['commit_id'],
            source_case_id=writer['source_admission'].get('case_id'),
            load_observed_case=deepcopy(observed_case),
            load_fullkey=deepcopy(issued['fullkey']),
            load_retirement_event_id=raw.get('event_id'), load_order=raw.get('order'),
            loaded_register=raw['rd_addr'], memory_id=issued['memory_id'],
            generation=issued['generation'], byte_offset=issued['byte_offset'],
            byte_value=writer['byte_value'], influenced_bits=[0, 8],
            upper_bits_origin='unknown', rtl_ram_origin='unknown',
            whole_word_origin='unknown', generic_isr_origin='unknown')
