"""Optional exact native sync0 -> sync1 version consumption observations.

This proves an enabled internal synchronizer edge consumed an observed stage
version. It proves neither external action origin, IRQ acceptance nor overall
operation success. No annotation, equal value or protocol acceptance suffices.
"""
from copy import deepcopy
import hashlib

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger
from .gpio_consumption import _ref
from .gpio_register_evidence import GpioRegisterEvidenceConsumer, _canonical


class GpioSyncConsumptionEvidenceConsumer(GpioRegisterEvidenceConsumer):
    def __init__(self, *, component, bit_lo, width, runtime_contract_sha256,
                 max_records=4096, max_event_gap=4096, max_accesses=256):
        self._sources = {}
        self._functional_status = 'unknown'
        super().__init__(component=component, register='sync0', bit_lo=bit_lo,
            width=width, runtime_contract_sha256=runtime_contract_sha256,
            max_records=max_records, max_event_gap=max_event_gap, max_accesses=max_accesses)
        self._contract_hash = hashlib.sha256(_canonical(dict(
            native_contract=self._contract_hash, rule='gpio_sync_consumption.v1',
            source='sync0', target='sync1'))).hexdigest()
        self._source = f'{component}:sync0[{bit_lo}:{width}]:produced'
        self._target = f'{component}:sync1[{bit_lo}:{width}]:consumed'
        self._declaration = DependencyEvidence('declared', 'causal_order',
            self._source, self._target, 'declared_topology',
            ('observation_contract:' + self._contract_hash,
             'runtime_contract:' + self._runtime_hash), 'gpio_sync_consumption', '1', ())
        self._ledger = DependencyEvidenceLedger(max_records_per_type=max_records)
        self._ledger.append(self._declaration)
        self._reason = 'missing_observed_stage_consumption'

    def _clear_additional_resources(self):
        self._sources.clear()
        self._functional_status = 'unknown'

    def _fail(self, reason):
        super()._fail(reason)
        self._functional_status = 'incomplete'

    def _process_records(self, records, raw, event_id):
        for record in records:
            if record.get('kind') != 'gpio_input_sample' or record.get('status') != 'observed':
                continue
            consumed = record['stages']['sync1'][self._bit_lo:self._bit_lo+self._width]
            sources = [self._sources.get(bit) for bit in
                       range(self._bit_lo, self._bit_lo+self._width)]
            if all(source is not None and target['observation_event_id'] == event_id
                   and target['local_tick'] > source['local_tick']
                   and 0 < event_id-source['observation_event_id'] <= self._max_gap
                   and target['dependencies'] == [_ref(source)]
                   and target['value'] == source['value']
                   for source, target in zip(sources, consumed)):
                self._certify(sources, consumed, event_id)
            else:
                self._functional_status = ('incomplete' if any(
                    source is not None for source in sources) else 'unknown')
                self._reason = 'missing_or_expired_actual_stage_consumption'
            # Only an actual enabled update establishes a produced version.
            # Baselines and held same values do not establish stage production.
            for bit in range(self._bit_lo, self._bit_lo+self._width):
                resource = record['stages']['sync0'][bit]
                if (record['enabled_mask'] & (1 << bit)
                        and resource['observation_event_id'] == event_id):
                    self._sources[bit] = deepcopy(resource)

    def _certify(self, sources, consumed, event_id):
        if len(self._certificates) >= self._max_records:
            self._functional_status = 'incomplete'
            self._reason = 'record_capacity_exceeded'
            return
        source_ids = sorted({source['observation_event_id'] for source in sources})
        evidence = DependencyEvidence('verified', 'causal_order', self._source,
            self._target, 'functional_consumption', tuple(
                ['journal:' + str(v) for v in source_ids + [event_id]] +
                ['observation_contract:' + self._contract_hash,
                 'runtime_contract:' + self._runtime_hash]),
            'gpio_sync_consumption', '1', ((self._component, self._epoch),),
            declaration_ref=self._declaration.evidence_id, validity='historical')
        if not self._ledger.append(evidence):
            return
        self._certificates.append(dict(evidence_id=evidence.evidence_id,
            proof_scope='sync0_to_sync1_version_consumption', component=self._component,
            reset_epoch=self._epoch, bit_lo=self._bit_lo, width=self._width,
            source_event_ids=source_ids, consumer_event_id=event_id,
            source_resources=deepcopy(sources), consumer_resources=deepcopy(consumed)))
        self._functional_status = 'verified'
        self._reason = 'actual_prior_stage_version_consumed'

    def report(self):
        result = super().report()
        result.update(schema_version='gpio_sync_consumption_evidence_report.v1',
            proof_scope='internal_stage_consumption_only', register_status='unknown',
            functional_status=self._functional_status)
        return result
