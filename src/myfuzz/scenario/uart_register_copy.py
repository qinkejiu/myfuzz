"""Bounded, raw-RVFI UART register provenance through ADDI rd, rs1, 0.

The source seed is independently reconstructed from raw UART/read receipts.
Only the measured low eight bits are attributed; higher bits remain unknown.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
from types import SimpleNamespace

from .uart_operand_seed import UartOperandSeedTracker, _uint, _wire
from .uart_retired_read import UartRetiredReadLinker


class UartRegisterCopyTracker:
    def __init__(self, *, admission_registry=None, ownership=None, edge_index=None,
                 max_pending_copies=256, **seed_limits):
        if type(max_pending_copies) is not int or max_pending_copies < 1:
            raise ValueError('invalid register-copy capacity')
        self._seed = UartOperandSeedTracker(admission_registry=admission_registry,
            ownership=ownership, edge_index=edge_index, **seed_limits)
        self.max_pending_copies = max_pending_copies
        self._pending = OrderedDict()
        self._certificates = {}
        self._native = {}
        self._bad = set()
        self._global_bad = False

    @property
    def pending_count(self):
        return len(self._pending)

    def _report(self, event, *, status='incomplete', reason=None, **fields):
        return deepcopy(dict(kind='uart_register_copy', schema_version='uart_register_copy.v1',
            status=status, reason=reason, proof_scope='uart_seed_addi_register_copy',
            observation_event_id=event.get('event_id'), upper_bits_origin='unknown',
            generic_isr_origin='unknown', whole_word_origin='unknown', **fields))

    def _fail(self, event, reason):
        component = event.get('source_component', event.get('component'))
        epoch = event.get('source_epoch', event.get('reset_epoch'))
        if type(component) is str and _uint(epoch) and not self._global_bad:
            if (component, epoch) in self._bad or len(self._bad) < self._seed.max_components:
                self._bad.add((component, epoch))
            else:
                self._global_bad = True
        else:
            self._global_bad = True
        return [self._report(event, reason=reason)]

    @staticmethod
    def _valid_copy(event):
        insn = event.get('insn')
        if not _uint(insn, 32) or insn & 0x707f != 0x13 or insn >> 20:
            return False
        widths = dict(rs1_addr=5, rd_addr=5, rs1_rdata=32, rd_wdata=32,
            rs2_addr=5, mem_addr=32, mem_rmask=4, mem_wmask=4,
            mem_rdata=32, mem_wdata=32, trap=1, ext_rf_wr_suppress=1,
            rd_wcap=1, rs1_rcap=1, rs2_rcap=1, mem_is_cap=1, mem_wcap=1, mode=2)
        if any(not _uint(event.get(k), width) for k, width in widths.items()):
            return False
        return (event['rs1_addr'] == (insn >> 15) & 31
            and event['rd_addr'] == (insn >> 7) & 31
            and event['rs1_addr'] != 0 and event['rd_addr'] != 0
            and event['rd_wdata'] == event['rs1_rdata']
            and event['mode'] == 3
            and all(event[k] == 0 for k in ('mem_rmask', 'mem_wmask', 'mem_rdata',
                'mem_wdata', 'trap', 'ext_rf_wr_suppress', 'rd_wcap', 'rs1_rcap',
                'rs2_rcap', 'mem_is_cap', 'mem_wcap')))

    def _resolved(self, raw, source_key, source_proof):
        destination_key = [raw['source_component'], raw['source_epoch'], raw['order'], raw['rd_addr']]
        return self._report(raw, status='accepted', reason='matched_retired_addi_register_copy',
            cpu_scope=source_proof['cpu_scope'], source_register_version_key=source_key,
            destination_register_version_key=destination_key,
            source_certificate_ref=hashlib.sha256(_wire(source_proof).encode()).hexdigest(),
            source_seed_register_version_key=source_proof.get('source_seed_register_version_key')
                or source_proof.get('register_version_key'), source_admission=source_proof['source_admission'],
            source_entry_id=source_proof.get('source_entry_id') or source_proof.get('entry_id'),
            actual_post_ref=raw['actual_post_ref'],
            retirement_event_id=raw['event_id'], order=raw['order'], decoded_insn=raw['insn'],
            source_register=raw['rs1_addr'], destination_register=raw['rd_addr'],
            measured_rs1_rdata=raw['rs1_rdata'], measured_rd_wdata=raw['rd_wdata'],
            influenced_bits=[0, 8], graph_path_certified=source_proof['graph_path_certified'],
            path_id=source_proof['path_id'])

    def _drain(self):
        reports = []
        changed = True
        while changed:
            changed = False
            for event_id, pending in list(self._pending.items()):
                raw, source_key = pending
                if (self._global_bad or (raw['source_component'], raw['source_epoch']) in self._bad
                        or self._seed._global_bad or self._seed._states.get(raw['source_component'], {}).get('bad')):
                    continue
                source_proof = self._certificates.get(tuple(source_key))
                if source_proof is None:
                    continue
                proof = self._resolved(raw, source_key, source_proof)
                dest_key = tuple(proof['destination_register_version_key'])
                self._certificates[dest_key] = proof
                del self._pending[event_id]
                reports.append(proof)
                changed = True
        return reports

    def _collect(self):
        live = {tuple(version['register_version_key'])
            for state in self._seed._states.values() for version in state['registers'].values()}
        live.update(tuple(source_key) for _, source_key in self._pending.values())
        self._certificates = {key: proof for key, proof in self._certificates.items() if key in live}

    def consume(self, event):
        if type(event) is not dict:
            return tuple(self._fail({}, 'malformed_register_copy_event'))
        kind = event.get('kind')
        if kind is not None and type(kind) is not str:
            return tuple(self._fail(event, 'malformed_register_copy_kind'))
        if kind == 'uart_consumption_match' and event.get('proof_scope') not in (
                'uart_fifo_retention', 'uart_fifo_read_consumption'):
            return ()
        if kind not in {'cpu_retire', 'cpu_reset', 'cpu_flush', 'instr_response',
                'data_accept', 'data_response', 'cpu_retirement_match',
                'uart_tick_observation', 'uart_frame_validation', 'uart_rdata_access',
                'uart_reset', 'uart_consumption_match'}:
            return ()
        try:
            import json
            raw = json.loads(_wire(event))
        except (TypeError, ValueError, RecursionError):
            return tuple(self._fail({}, 'malformed_register_copy_event'))
        component, epoch = raw.get('source_component'), raw.get('source_epoch')
        event_id = raw.get('event_id')
        repeated = type(event_id) in (int, str) and event_id in self._seed._seen
        prior = None
        if kind == 'cpu_retire' and type(component) is str and _uint(epoch) and _uint(raw.get('rs1_addr'), 5):
            prior = self._seed.register_at(component, epoch, raw['rs1_addr'])
        seed_reports = self._seed.consume(raw)
        reports = []
        if any(p.get('status') == 'incomplete' for p in seed_reports):
            reports.extend(self._fail(raw, 'raw_register_copy_certainty_barrier'))
        if kind == 'cpu_reset':
            state = self._seed._states.get(raw.get('component', component))
            if state and state['epoch'] == raw.get('reset_epoch') and not state['bad'] and not reports:
                c = raw.get('component', component)
                self._bad = {key for key in self._bad if key[0] != c}
                self._pending = OrderedDict((k, v) for k, v in self._pending.items()
                    if v[0]['source_component'] != c)
                self._certificates = {k: v for k, v in self._certificates.items() if k[0] != c}
                self._native = {k: v for k, v in self._native.items() if k[1] != c}
            return tuple(reports)
        if kind == 'cpu_flush':
            reports.extend(self._fail(raw, 'register_copy_flush_certainty_barrier'))
        if kind == 'cpu_retire' and not repeated and not reports:
            if type(component) is not str or not _uint(epoch) or self._global_bad or (component, epoch) in self._bad:
                return tuple(reports)
            if not UartRetiredReadLinker._native_retire(SimpleNamespace(_native=self._native), raw):
                return tuple(self._fail(raw, 'unproven_register_copy_retirement'))
            if (_uint(raw.get('insn'), 32) and raw['insn'] & 0x707f == 0x13
                    and raw['insn'] >> 20 == 0 and (raw['insn'] >> 7) & 31):
                if not self._valid_copy(raw):
                    return tuple(self._fail(raw, 'invalid_retired_addi_copy'))
                if prior is not None:
                    if prior['measured_value'] != raw['rs1_rdata']:
                        return tuple(self._fail(raw, 'register_copy_source_value_conflict'))
                    source_key = prior['register_version_key']
                    if (tuple(source_key) in self._certificates
                            or prior['retirement_event_id'] in self._seed._pending
                            or any((v[0]['source_component'], v[0]['source_epoch'], v[0]['order'], v[0]['rd_addr'])
                                == tuple(source_key) for v in self._pending.values())):
                        if len(self._pending) >= self.max_pending_copies:
                            return tuple(self._fail(raw, 'register_copy_pending_capacity'))
                        self._pending[raw['event_id']] = (raw, source_key)
        for proof in seed_reports:
            if proof.get('status') == 'accepted':
                self._certificates[tuple(proof['register_version_key'])] = proof
        reports.extend(self._drain())
        self._collect()
        return tuple(deepcopy(reports))
