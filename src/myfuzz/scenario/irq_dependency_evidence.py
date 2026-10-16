"""D1 historical IRQ boundaries from existing native and serial consumers.

The optional provider covers native UART watermark binding and measured Ibex
receipts. It does not infer unknown IP causes, ISR effects or prerequisites.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import re

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger
from .irq_serial_certificates import IrqSerialCertificates
from .uart_irq_consumption import UartNativeIrqJoin


_FIELDS = frozenset('event_id kind schema_version component source_component source_epoch '
    'reset_epoch local_tick tick execution_id producer_event_id command_scope receipt_id '
    'receipt_ticks phase observation_contract pre post observation_event_id irq_class '
    'pre_output post_output pre_event pre_state post_state pre_enable pre_test pre_test_qe '
    'pre_watermark_test post_watermark_test watermark_threshold watermark_level pre_depth '
    'pre_entry_ids source_local_tick source_phase source_output_key source_observation_event_id '
    'source_receipt_ref source_port target_component target_epoch target_port width '
    'source_bit_offset target_bit_offset value target_value dataflow_delivery_event_id '
    'binding_delivery_event_id input_context expected_input actual_pre_input actual_post_input '
    'irq_masked_pre irq_taken_pre sample_event_id sample_ref take_key irq_serial_observation '
    'valid intr order pc_rdata insn physical_reset reason'.split())
_NATIVE_KINDS = frozenset(('uart_tick_observation', 'uart_irq_update',
    'native_irq_binding_delivery', 'cpu_external_irq_sample', 'cpu_external_irq_taken',
    'uart_reset', 'cpu_reset'))


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _bounded(value, depth=0):
    if depth > 12: return False
    if type(value) is dict:
        return len(value) <= 256 and all(type(k) is str and len(k) <= 1024
            and _bounded(v, depth + 1) for k, v in value.items())
    if type(value) is list:
        return len(value) <= 128 and all(_bounded(v, depth + 1) for v in value)
    return value is None or type(value) is bool or (
        type(value) is str and len(value) <= 1024) or (
        type(value) is int and -(1 << 64) < value < 1 << 64)


class IrqDependencyEvidenceConsumer:
    def __init__(self, *, ownership, admission_registry, source_component,
                 target_component, runtime_contract_sha256, max_records=256,
                 max_pending=256, max_event_gap=4096):
        if (any(type(n) is not int or not 1 <= n <= 65536
                for n in (max_records, max_pending, max_event_gap))
                or any(type(c) is not str or not 0 < len(c) <= 256 or c.strip() != c
                       for c in (source_component, target_component))
                or source_component == target_component
                or type(runtime_contract_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', runtime_contract_sha256) is None):
            raise ValueError('invalid IRQ evidence configuration')
        if ownership.binding_producer(target_component, 'irq', 0, 1) != source_component + '.uart_rx_watermark':
            raise ValueError('explicit native IRQ ownership binding required')
        self._source, self._target, self._runtime = source_component, target_component, runtime_contract_sha256
        self._bounds = dict(max_records=max_records, max_pending=max_pending,
                            max_event_gap=max_event_gap, max_projected_bytes=65536)
        self._native = UartNativeIrqJoin(ownership=ownership, admission_registry=admission_registry,
            max_components=2, max_entry_refs=max_pending, enable_boundary_evidence=True)
        self._serial = IrqSerialCertificates(max_pending=max_pending, max_event_gap=max_event_gap)
        self._ledger = DependencyEvidenceLedger(max_records_per_type=max(3, max_records))
        self._declarations = {}
        for scope, relation, source, target in (
                ('irq_delivery', 'direct_binding', f'{source_component}:irq_output', f'{target_component}:irq_sample'),
                ('irq_acceptance', 'causal_order', f'{target_component}:irq_sample', f'{target_component}:irq_take'),
                ('cpu_retirement', 'causal_order', f'{target_component}:irq_take', f'{target_component}:irq_retire')):
            record = DependencyEvidence('declared', relation, source, target, 'declared_topology',
                (f'runtime:{self._runtime}',), 'native_irq_boundary_' + scope, '1', ())
            self._ledger.append(record); self._declarations[scope] = record
        self._last_id, self._integrity = 0, True
        self._digests, self._acceptances = OrderedDict(), OrderedDict()
        self._certificates = []
        self._reset_markers, self._reset_floors = {}, {}
        self._barrier_waiting = set()
        self._status, self._reason = 'unknown', 'no_observed_irq_boundary'

    def _fail(self, reason):
        self._integrity = False
        self._acceptances.clear()
        self._status, self._reason = 'incomplete', reason

    def consume(self, event):
        try:
            if type(event) is not dict or type(event.get('event_id')) is not int:
                raise ValueError('malformed journal')
            event_id = event['event_id']; digest = hashlib.sha256(_wire(event)).hexdigest()
            if event_id <= self._last_id:
                if self._digests.get(event_id) != digest: self._fail('journal_identity_conflict')
                return
            if event_id != self._last_id + 1: self._fail('journal_gap')
            self._last_id = event_id; self._digests[event_id] = digest
            while len(self._digests) > self._bounds['max_event_gap']: self._digests.popitem(last=False)
            while self._acceptances and event_id - next(iter(self._acceptances)) > self._bounds['max_event_gap']:
                self._acceptances.popitem(last=False)
            if not self._integrity: return
            kind = event.get('kind')
            if kind == 'reset_barrier':
                self._acceptances.clear()
                self._barrier_waiting = {self._source, self._target} - set(self._reset_markers)
                for component, states in ((self._source, self._native._sources),
                                          (self._target, self._native._cpus)):
                    self._reset_floors[component] = states.get(component, {}).get('epoch', 0)
                self._reset_markers.clear()
                self._status, self._reason = 'incomplete', 'reset_requires_measured_native_receipts'
                self._advance_serial(dict(event_id=event_id, kind='reset_barrier'))
                return
            relevant = kind in _NATIVE_KINDS or kind == 'cpu_retire'
            if not relevant:
                self._advance_serial({'event_id': event_id}); return
            component = event.get('component')
            if kind == 'native_irq_binding_delivery':
                if (event.get('source_component'), event.get('target_component')) != (self._source, self._target):
                    self._advance_serial({'event_id': event_id}); return
            elif component not in (self._source, self._target):
                self._advance_serial({'event_id': event_id}); return
            if self._barrier_waiting and kind not in ('uart_reset', 'cpu_reset'):
                self._advance_serial({'event_id': event_id}); return
            projected = {k: v for k, v in event.items() if k in _FIELDS}
            if kind == 'uart_tick_observation':
                from myfuzz.local_harness.opentitan_uart_fifo_contract import UART_FIFO_PROBES
                probes = {'probe_uart_' + k for k in UART_FIFO_PROBES} | {'intr_rx_watermark_o', 'uart_rx_watermark'}
                for phase in ('pre', 'post'):
                    if type(projected.get(phase)) is dict:
                        projected[phase] = {k: v for k, v in projected[phase].items() if k in probes}
            if not _bounded(projected) or len(_wire(projected)) > self._bounds['max_projected_bytes']:
                self._fail('native_irq_projection_bounds'); return
            if kind in ('uart_reset', 'cpu_reset'): self._acceptances.clear()
            native = self._native.consume(projected) if kind in _NATIVE_KINDS else ()
            if kind in ('uart_reset', 'cpu_reset'):
                if any(r.get('kind') == 'native_irq_reset' for r in native):
                    epoch = projected['reset_epoch']
                    if component not in self._barrier_waiting or epoch > self._reset_floors[component]:
                        self._barrier_waiting.discard(component)
                        self._reset_markers[component] = epoch
                self._advance_serial(dict(event_id=event_id, kind='reset_barrier'))
                return
            if component in (self._source, self._target):
                self._reset_markers.pop(component, None)
            if any(r.get('status') == 'incomplete' for r in native):
                self._status, self._reason = 'incomplete', 'native_irq_evidence_incomplete'
            for boundary in self._native.drain_boundary_evidence():
                appended = self._append(boundary['proof_scope'], boundary)
                if appended and boundary['proof_scope'] == 'irq_acceptance':
                    self._acceptances[boundary['take_event_id']] = boundary
                    while len(self._acceptances) > self._bounds['max_pending']: self._acceptances.popitem(last=False)
            self._advance_serial(projected)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            self._fail('malformed_or_inconsistent_irq_evidence')

    def _advance_serial(self, event):
        # Compact projections preserve each actual journal ID, including rows
        # with no supported IRQ fields; they carry no inferred source facts.
        for serial in self._serial.ingest((event,)):
            acceptance = self._acceptances.pop(serial['take_identity_event_id'], None)
            if (acceptance is None or serial['component'] != self._target
                    or acceptance.get('serial_decision_consistent') is not True
                    or serial['reset_epoch'] != acceptance['target_epoch']
                    or serial['take_identity'].get('take_key') != acceptance['take_key']):
                self._status, self._reason = 'incomplete', 'retirement_without_exact_native_acceptance'
                continue
            self._append('cpu_retirement', {**acceptance,
                'proof_scope': 'cpu_retirement', 'serial_certificate': serial,
                'retirement_event_id': serial['retirement_event_id']})

    def _append(self, scope, boundary):
        if len(self._certificates) >= self._bounds['max_records']:
            self._status, self._reason = 'incomplete', 'historical_record_capacity'; return False
        declaration = self._declarations[scope]
        ids = [boundary['source_observation_event_id'], boundary['binding_delivery_event_id'], boundary['sample_event_id']]
        if 'take_event_id' in boundary: ids.append(boundary['take_event_id'])
        if 'retirement_event_id' in boundary: ids.append(boundary['retirement_event_id'])
        if any(type(i) is not int or not 1 <= i <= self._last_id
               or self._last_id - i > self._bounds['max_event_gap'] for i in ids):
            self._status, self._reason = 'incomplete', 'expired_native_irq_evidence'; return False
        record = DependencyEvidence('verified', declaration.relation, declaration.source,
            declaration.target, scope, tuple(f'journal:{i}' for i in dict.fromkeys(ids)) + (f'runtime:{self._runtime}',),
            declaration.rule_id, declaration.rule_version,
            ((self._source, boundary['source_epoch']), (self._target, boundary['target_epoch'])),
            declaration_ref=declaration.evidence_id, validity='historical')
        if self._ledger.append(record):
            self._certificates.append(dict(evidence_id=record.evidence_id, **deepcopy(boundary)))
        self._status, self._reason = 'verified', None
        return True

    def report(self):
        counts = {scope: 0 for scope in self._declarations}
        for certificate in self._certificates: counts[certificate['proof_scope']] += 1
        return deepcopy(dict(schema_version='irq_dependency_evidence_report.v1',
            proof_scope='historical_native_irq_boundaries_only', provider='native_uart_ibex_irq.v1',
            runtime_contract_sha256=self._runtime, bounds=self._bounds,
            journal_integrity=self._integrity, last_event_id=self._last_id,
            status=self._status, reason=self._reason, counts=counts,
            awaiting_native_reset_components=sorted(self._barrier_waiting),
            grants_prerequisites=False, certificates=self._certificates, ledger=self._ledger.document()))
