"""Read-only capability bridge for descriptor record campaigns.

Installed RAM certificates prove historical modeled-host byte consumption.
They neither identify the selected instruction's origin nor grant live state,
case attribution, or policy rewards. Absent providers remain unknown.
"""
from copy import deepcopy
from hashlib import sha256

from myfuzz.scenario.classified_feedback import ClassifiedEvidenceFeedback
from .model import canonical, identifier


class RecordConsumptionFeedback:
    def __init__(self, runner, *, max_records=4096):
        self._consumer = ClassifiedEvidenceFeedback(runner, max_records=max_records)
        self._seen = set()
        self._cases = 0
        self._prepared = False

    def prepare_case(self):
        self._consumer.prepare_case()
        self._prepared = True

    def observe_case(self, *, case_id, flow):
        identifier(case_id)
        if flow not in ('F1', 'F2', 'F3', 'F4', 'F5') or not self._prepared:
            raise ValueError('prepared descriptor case required')
        verified = self._consumer.observe_case()['verified_dependency']
        records = [row for row in verified['new_records']
                   if row['scope'] == 'memory_byte_version']
        features = set()
        for row in records:
            # Resource/declaration identities are finite semantic keys. Event,
            # epoch, version, testcase IDs and random payloads are not novelty.
            resource_refs = [ref for ref in row['evidence_refs'] if ref.startswith('byte:')]
            feature = 'historical-host-memory:' + sha256(canonical(dict(
                relation=row['relation'], source=row['source'], target=row['target'],
                scope=row['scope'], rule_id=row['rule_id'], rule_version=row['rule_version'],
                resource_refs=resource_refs))).hexdigest()
            if feature not in self._seen:
                features.add(feature)
        self._seen.update(features)
        self._cases += 1
        self._prepared = False
        return deepcopy(dict(schema_version='descriptor_record_consumption_feedback.v1',
            case_id=case_id, flow_id=flow,
            provider_status=verified['provider_statuses']['memory'],
            consumption_observation='historical_observed' if records else 'unknown',
            state_observation='unknown', cross_testcase='unknown', irq_consumption='unknown',
            memory_kind='modeled_host_persistent_memory', source_origin='unknown',
            proof_scope='historical_installed_host_memory_byte_versions_only',
            reward_eligible=False, native_authority=False, grants_prerequisites=False,
            policy_features={}, new_historical_records=records,
            new_semantic_features=sorted(features)))

    def snapshot(self):
        self._consumer.validate()
        return dict(schema_version='descriptor_record_consumption_state.v1',
            case_count=self._cases, semantic_feature_count=len(self._seen),
            provider_configuration=self._consumer.configuration(),
            state_observation='unknown', reward_eligible=False,
            grants_prerequisites=False)
