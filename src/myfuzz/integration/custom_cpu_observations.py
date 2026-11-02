"""Bounded, observation-only Wishbone CPU facts for a shared custom slot."""
from copy import deepcopy

from .compiled_wishbone_f4 import wishbone_native_beats


class CustomCpuCaseObserver:
    """Collect case-local facts incrementally without reconstructing transactions."""
    names = ('wishbone_samples', 'memory_reads', 'memory_writes',
             'mmio_acceptances', 'mmio_deliveries')

    def __init__(self, *, cpu_id, flow, limit=32):
        if flow not in ('F1', 'F2', 'F3', 'F4'):
            raise ValueError('custom-CPU-observation-flow')
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError('custom-CPU-observation-limit')
        self.cpu_id, self.flow, self.limit = cpu_id, flow, limit
        self.facts = {name: [] for name in self.names}
        self.counts = dict.fromkeys(self.names, 0)

    def _add(self, name, row):
        self.counts[name] += 1
        if len(self.facts[name]) < self.limit:
            self.facts[name].append(deepcopy(row))

    def observe(self, event):
        if not isinstance(event, dict) or event.get('component') != self.cpu_id:
            return
        outputs = event.get('outputs')
        if (isinstance(outputs, dict) and isinstance(outputs.get('driver_samples'), (list, tuple))
                and any(outputs.get(field) == 1 for field in ('instr_req_accepted', 'instr_rsp_consumed',
                                                               'data_req_accepted', 'data_rsp_consumed'))):
            self._add('wishbone_samples', event)
        kind = event.get('kind')
        name = {'memory_read': 'memory_reads', 'memory_read_issuance': 'memory_reads',
                'memory_write': 'memory_writes', 'memory_write_commit': 'memory_writes',
                'mmio_acceptance': 'mmio_acceptances', 'mmio_delivery': 'mmio_deliveries'}.get(kind)
        if name:
            self._add(name, event)

    @property
    def result(self):
        return dict(schema_version='custom_cpu_case_observations.v1', flow=self.flow,
            facts=deepcopy(self.facts), counts=dict(self.counts),
            truncated={name: self.counts[name] > self.limit for name in self.names},
            scope='raw_case_events_no_cross_case_join', case_causality='unknown',
            source_attribution='unknown', retirement='unknown', certificate='not_granted',
            reward_eligible=False)


def project_custom_cpu_case_events(events, *, cpu_id, flow, limit=32):
    """Keep raw case-local samples without reconstructing cross-case beats."""
    observer = CustomCpuCaseObserver(cpu_id=cpu_id, flow=flow, limit=limit)
    for event in events:
        observer.observe(event)
    return observer.result


def project_custom_cpu_events(events, *, cpu_id, traces, event_start, event_end, flow, limit=32):
    """Project actual CPU bus and host-memory/MMIO facts in one case interval.

    ``events`` is the whole journal prefix, needed to reconstruct Wishbone
    sequence ownership when a request straddles a case boundary. Bounds are
    zero-based and end-exclusive, matching OnlineCaseReceipt. These facts do
    not assert instruction retirement, a source-to-consumer join or reward.
    """
    if flow not in ('F1', 'F2', 'F3', 'F4'):
        raise ValueError('custom-CPU-observation-flow')
    if (type(event_start) is not int or type(event_end) is not int
            or not 0 <= event_start <= event_end <= len(events)):
        raise ValueError('custom-CPU-observation-case-bounds')
    if type(limit) is not int or not 1 <= limit <= 256:
        raise ValueError('custom-CPU-observation-limit')
    names = ('wishbone_acceptances', 'wishbone_responses', 'memory_reads',
             'memory_writes', 'mmio_acceptances', 'mmio_deliveries')
    facts = {name: [] for name in names}
    counts = dict.fromkeys(names, 0)
    def add(name, value):
        counts[name] += 1
        if len(facts[name]) < limit:
            facts[name].append(deepcopy(value))

    case_ids = set()
    for event in events[event_start:event_end]:
        if not isinstance(event, dict):
            continue
        case_ids.add(event.get('event_id'))
        if event.get('component') != cpu_id:
            continue
        kind = event.get('kind')
        name = {'memory_read': 'memory_reads', 'memory_read_issuance': 'memory_reads',
                'memory_write': 'memory_writes', 'memory_write_commit': 'memory_writes',
                'mmio_acceptance': 'mmio_acceptances', 'mmio_delivery': 'mmio_deliveries'}.get(kind)
        if name:
            add(name, event)
    for beat in wishbone_native_beats(events, cpu_id, traces, require_resolved=False):
        if beat['event_id'] in case_ids:
            add('wishbone_acceptances' if beat['kind'] == 'acceptance' else 'wishbone_responses', beat)
    return dict(schema_version='custom_cpu_case_observations.v1', flow=flow,
        facts=facts, counts=counts, truncated={name: counts[name] > limit for name in names},
        scope='raw_case_events_and_validated_wishbone_samples',
        case_causality='unknown', source_attribution='unknown', retirement='unknown',
        certificate='not_granted', reward_eligible=False)
