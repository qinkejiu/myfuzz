"""Append-time evidence metadata; input declarations never imply DUT causality."""
from __future__ import annotations

from copy import deepcopy
from .runtime_edge_index import RuntimeEdgeIndex
from .source_provenance import AdmissionRegistry


class EventProvenance:
    def __init__(self, edge_index: RuntimeEdgeIndex):
        if not isinstance(edge_index, RuntimeEdgeIndex):
            raise ValueError('provenance requires a compiled runtime edge index')
        self.edge_index = edge_index
        self.registry = AdmissionRegistry()
        self.observed_case = None
        self.configuration = {
            'schema_version': 'source_provenance_configuration.v1',
            'edge_index': edge_index.document(),
            'edge_index_sha256': edge_index.identity_sha256}

    def decorate(self, record: dict) -> dict:
        """Total for ordinary JSON output records, including malformed witnesses.

        Facts from a failed local command remain in the log. Unknown writer
        references stay unknown; neither current case nor transport candidates
        may manufacture a causal origin. The supplied record is never modified.
        """
        result = deepcopy(record)
        kind = record.get('kind')
        refs = []
        resource = None
        scope = 'observation_only'
        if kind == 'source_admission':
            document = record.get('admission')
            if isinstance(document, dict):
                refs = [document.get('action_id')]
            scope = 'authorized_attempt'
        elif kind in ('source_injection', 'instruction_source'):
            refs = [record.get('action_id' if kind == 'source_injection' else 'source_event_id')]
            scope = 'source_action'
        elif kind in ('uart_source_frame_admission', 'uart_source_frame_begin',
                      'uart_source_frame_end', 'uart_source_frame_cancel'):
            refs = [record.get('action_id')]
            scope = 'uart_pin_drive' if kind in ('uart_source_frame_begin', 'uart_source_frame_end') else 'source_action'
        elif kind == 'memory_read':
            raw = record.get('writer_event_ids')
            refs = list(raw) if isinstance(raw, (list, tuple)) else []
            scope = 'memory_writer_snapshot'
        elif kind == 'cpu_retirement_match' and record.get('status') == 'accepted':
            raw = record.get('source_refs')
            refs = list(raw) if isinstance(raw, (list, tuple)) else []
            scope = 'retired_instruction_origin'
        if kind in ('memory_read', 'memory_write', 'memory_initialization', 'instruction_source'):
            resource = {}
            for name in ('memory_id', 'generation', 'byte_offset', 'address',
                         'width_bytes', 'byte_enable', 'transaction', 'version',
                         'versions', 'writer_event_id', 'writer_event_ids', 'writer_kinds'):
                if name in record:
                    value = record[name]
                    resource[name] = list(deepcopy(value)) if isinstance(value, tuple) else deepcopy(value)
        known, unknown = {}, []
        invalid_refs = 0
        writer_kinds = record.get('writer_kinds')
        for offset, ref in enumerate(refs):
            if type(ref) is not str or not ref.strip():
                invalid_refs += 1
                continue
            admission = self.registry.get(ref)
            if kind in ('uart_source_frame_admission', 'uart_source_frame_begin',
                        'uart_source_frame_end', 'uart_source_frame_cancel',
                        'cpu_retirement_match') and admission is not None:
                expected_kind = 'instruction' if kind == 'cpu_retirement_match' else 'source_event'
                if admission.input_kind != expected_kind or admission.component != record.get('component'):
                    admission = None
                if kind == 'cpu_retirement_match':
                    cpu_scope = record.get('cpu_scope')
                    if (not isinstance(cpu_scope, dict) or
                            cpu_scope.get('source_component') != record.get('component')):
                        admission = None
            if kind == 'memory_read' and (
                    not isinstance(writer_kinds, (list, tuple))
                    or offset >= len(writer_kinds)
                    or writer_kinds[offset] != 'INSTRUCTION_SOURCE'
                    or admission is not None and admission.input_kind != 'instruction'):
                admission = None
            if admission is None:
                if ref not in unknown:
                    unknown.append(ref)
            else:
                known[admission.admission_id] = admission
        candidates = list(self.edge_index.match_event(record))
        if candidates and scope == 'observation_only':
            scope = 'transport_candidates_only'
        result['provenance'] = {
            'schema_version': 'event_source_provenance.v1',
            'observed_case': deepcopy(self.observed_case),
            'origin_admission_ids': sorted(known),
            'origin_status': 'partial' if known and (unknown or invalid_refs) else 'known' if known else 'unknown',
            'unknown_writer_ids': unknown,
            'invalid_origin_references': invalid_refs,
            'proof_scope': scope,
            'edge_candidates': candidates,
            'resource': resource}
        return result
