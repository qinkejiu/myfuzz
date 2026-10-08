"""Restricted UART operand to modeled host RAM low-byte writer certificate.

Only raw CPU/UART evidence and a live installed MemoryService callback can
authorize this join. The certificate says nothing about RTL RAM or upper bits.
"""
from copy import deepcopy
from .cpu_retirement import CpuRetirementMatcher
from .ledger import TransactionLedger
from .memory_commit_authority import MemoryCommitAuthority
from .uart_operand_use import UartOperandUseTracker


def _key(document):
    names = ('execution_id', 'testcase_id', 'source_component', 'source_epoch',
             'channel_id', 'source_sequence')
    if type(document) is not dict or set(document) != set(names):
        return None
    if any(type(document[name]) is not str or not document[name]
           for name in names[:3] + ('channel_id',)):
        return None
    if any(type(document[name]) is not int or not 0 <= document[name] < 1 << 64
           for name in ('source_epoch', 'source_sequence')):
        return None
    return tuple(document[name] for name in names)


class UartRamCommitJoin:
    def __init__(self, *, admission_registry, ownership, edge_index, services,
                 max_pending=256, max_instruction_witnesses=2048):
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError('invalid UART RAM join capacity')
        self._uses = UartOperandUseTracker(admission_registry=admission_registry,
            ownership=ownership, edge_index=edge_index,
            max_instruction_witnesses=max_instruction_witnesses)
        self._retire = CpuRetirementMatcher(max_pending=max_instruction_witnesses)
        self._authority = MemoryCommitAuthority(services=services, max_pending=max_pending)
        self._services = dict(services)
        self._commits = {}
        self._matches = {}
        self._uses_by_retirement = {}
        self._bad = False
        self.max_pending = max_pending

    @property
    def degraded(self):
        return self._bad or self._authority.degraded

    def stage_commit(self, component, service, ledger, key, receipt):
        """Pin one actual unacknowledged callback before producer stream ack."""
        if self.degraded:
            return False
        token = self._authority.stage(component, service, ledger, key, receipt)
        if token is None:
            return False
        certificate = self._authority.resolve(token)
        if certificate is None:
            self._bad = True
            return False
        identity = _key(certificate['fullkey'])
        if identity is None or identity in self._commits or len(self._commits) >= self.max_pending:
            self._bad = True
            return False
        self._commits[identity] = certificate
        return True

    def consume(self, event):
        """Consume raw facts in order; saved accepted labels are ignored."""
        if self.degraded:
            return ()
        if type(event) is not dict:
            self._bad = True
            return ()
        kind = event.get('kind')
        # Both engines independently validate raw evidence. Their output is
        # private; detached journal certificates cannot enter either engine.
        uses = self._uses.consume(event)
        matches = self._retire.consume(event)
        if any(report.get('status') == 'incomplete' for report in uses) or any(
                report.get('status') == 'incomplete' for report in matches):
            self._bad = True
            return ()
        if kind in ('cpu_reset', 'cpu_flush'):
            self._matches.clear()
            self._uses_by_retirement.clear()
            self._commits.clear()
            return ()
        for report in uses:
            if report.get('status') == 'accepted':
                self._remember(self._uses_by_retirement,
                               report.get('operand_retirement_event_id'), report)
        for report in matches:
            if report.get('status') != 'accepted' or kind != 'cpu_retire':
                continue
            keys = report.get('transaction_keys')
            if (type(keys) is not list or len(keys) != 1
                    or type(report.get('insn')) is not int
                    or report['insn'] & 0x707f != 0x2023):
                continue
            retirement_id = event.get('event_id')
            if (retirement_id in self._uses_by_retirement
                    or retirement_id in self._uses._pending):
                self._remember(self._matches, retirement_id, report)
            else:
                # A proven unrelated SW consumed its callback, so its pending
                # commit cannot accumulate through a long online session.
                identity = _key(keys[0])
                if identity is not None:
                    self._commits.pop(identity, None)
        if self.degraded:
            return ()
        output = []
        for retirement_id in tuple(self._matches.keys() & self._uses_by_retirement.keys()):
            match = self._matches.pop(retirement_id)
            use = self._uses_by_retirement.pop(retirement_id)
            certificate = self._join(match, use)
            if certificate is not None:
                output.append(certificate)
        return tuple(deepcopy(output))

    def _remember(self, table, identity, report):
        if type(identity) not in (int, str) or identity in table or len(table) >= self.max_pending:
            self._bad = True
            return
        table[identity] = report

    def _join(self, match, use):
        keys = match.get('transaction_keys')
        if type(keys) is not list or len(keys) != 1:
            return None
        identity = _key(keys[0])
        if identity is None:
            return None
        commit = self._commits.pop(identity, None)
        if commit is None:
            return None
        document = commit['commit_document']
        address = use.get('measured_mem_addr')
        value = use.get('operand_value')
        if (type(address) is not int or not 0 <= address < 1 << 32
                or type(value) is not int or not 0 <= value < 1 << 32
                or use.get('measured_mem_wmask') != 15
                or match.get('cpu_scope') != use.get('cpu_scope')
                or match.get('order') != use.get('operand_order')
                or match.get('insn') != use.get('decoded_insn')
                or keys[0] != document.get('fullkey')):
            return None
        expected_payload = dict(op='write', address=address, value=value,
                                width_bytes=4, byte_enable=15)
        if document.get('payload_sha256') != TransactionLedger._digest(expected_payload):
            return None
        service = self._services.get(identity[2])
        if service is None:
            return None
        try:
            memory_id, _, offset = service.memory.resolve_span(address, 4, write=True)
        except (ValueError, TypeError):
            return None
        cells = document.get('enabled_byte_cells')
        if (document.get('memory_id') != memory_id or document.get('byte_offset') != offset
                or document.get('width_bytes') != 4 or document.get('byte_enable') != 15
                or type(cells) is not list or len(cells) != 4):
            return None
        version = document.get('version')
        for lane, cell in enumerate(cells):
            if (type(cell) is not dict or cell.get('byte_offset') != offset + lane
                    or cell.get('value') != (value >> (8 * lane)) & 255
                    or cell.get('version') != version or cell.get('writer_kind') != 'STORE'):
                return None
        low = cells[0]
        return dict(kind='uart_ram_commit_join', schema_version='uart_ram_commit_join.v1',
                    status='accepted', proof_scope='uart_seed_operand_host_ram_byte_writer',
                    fullkey=deepcopy(keys[0]), operand_retirement_event_id=use['operand_retirement_event_id'],
                    source_register_version_key=deepcopy(use['source_register_version_key']),
                    source_seed_certificate_ref=use['source_seed_certificate_ref'],
                    source_admission=deepcopy(use['source_admission']),
                    memory_kind='modeled_host_persistent_memory', memory_id=memory_id,
                    generation=document['generation'], byte_offset=low['byte_offset'],
                    byte_value=low['value'], byte_version=deepcopy(low['version']),
                    commit_id=commit['commit_id'], influenced_bits=[0, 8],
                    upper_bits_origin='unknown', rtl_ram_origin='unknown',
                    generic_isr_origin='unknown')
