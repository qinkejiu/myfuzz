"""Historical verified feedback from installed Runner authorities only.

This reporting adapter cannot install providers, promote candidates, restore
saved scoring state, or grant live prerequisites.
"""
from copy import deepcopy
import hashlib
import json

from .dependency_evidence import DependencyEvidence, DependencyEvidenceLedger


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _functional_unknown():
    return dict(category='functional_coverage',
        schema_version='stage2_functional_coverage_feedback.v1', status='unknown',
        reason='no_stage2_functional_provider', new_features=[],
        proof_scope='no_functional_proof', grants_prerequisites=False)


def _certified_record(name, provider, report, record, certificates):
    """A ledger document is not proof; its digest must bind an issued certificate."""
    certificate = certificates.get(record.evidence_id)
    if certificate is None:
        raise ValueError('classified-feedback-certificate-mismatch')
    try:
        if name == 'memory':
            component, memory_id = certificate['component'], certificate['memory_id']
            declaration = provider._declarations[(component, memory_id)]
            # The native certificate's evidence_id binds the full record,
            # including the commit reference absent from its compact facts.
            refs = (f"journal:{certificate['write_event_id']}",
                    f"journal:{certificate['read_event_id']}", record.evidence_refs[2],
                    f"byte:{certificate['byte_offset']}",
                    f"runtime:{report['runtime_contract_sha256']}")
            if (certificate['proof_scope'] != 'memory_byte_version'
                    or certificate['validity'] != 'historical'
                    or not record.evidence_refs[2].startswith('commit:')):
                raise ValueError('certificate facts')
            epochs = ((f'{component}:{memory_id}', certificate['generation']),)
            scope = 'memory_byte_version'
        else:
            scope = certificate['proof_scope']
            declaration = provider._declarations[scope]
            ids = [certificate['source_observation_event_id'],
                   certificate['binding_delivery_event_id'], certificate['sample_event_id']]
            if 'take_event_id' in certificate: ids.append(certificate['take_event_id'])
            if 'retirement_event_id' in certificate: ids.append(certificate['retirement_event_id'])
            refs = tuple(f'journal:{i}' for i in dict.fromkeys(ids)) + (
                f"runtime:{report['runtime_contract_sha256']}",)
            epochs = ((provider._source, certificate['source_epoch']),
                      (provider._target, certificate['target_epoch']))
        expected = DependencyEvidence('verified', declaration.relation,
            declaration.source, declaration.target, scope, refs,
            declaration.rule_id, declaration.rule_version, epochs,
            declaration_ref=declaration.evidence_id, validity='historical')
        if _bytes(expected.document()) != _bytes(record.document()):
            raise ValueError('certificate projection')
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise ValueError('classified-feedback-certificate-mismatch') from exc


class ClassifiedEvidenceFeedback:
    def __init__(self, runner, max_records=4096):
        from .runner import ScenarioRunner
        from .memory_dependency_evidence import MemoryDependencyEvidenceConsumer
        from .irq_dependency_evidence import IrqDependencyEvidenceConsumer
        if (not isinstance(runner, ScenarioRunner) or type(max_records) is not int
                or not 1 <= max_records <= 65536):
            raise ValueError('classified-feedback-configuration-invalid')
        self._runner, self._max_records = runner, max_records
        self._providers = {}
        for name, expected in (('memory', MemoryDependencyEvidenceConsumer),
                               ('irq', IrqDependencyEvidenceConsumer)):
            provider = getattr(runner, '_' + name + '_dependency_consumer')
            config = getattr(runner, '_' + name + '_dependency_configuration')
            if ((provider is None) != (config is None)
                    or provider is not None and type(provider) is not expected):
                raise ValueError('classified-feedback-installed-provider-required')
            self._providers[name] = (provider, _bytes(config))
        self._configuration = dict(schema_version='classified_evidence_feedback_config.v1',
            max_records=max_records, providers={name: json.loads(config)
                for name, (_, config) in self._providers.items()},
            policy='installed_verified_history_session_dedup_no_restoration.v1',
            functional_provider=None, grants_prerequisites=False)
        self._hash = hashlib.sha256(_bytes(self._configuration)).hexdigest()
        self._seen, self._count = set(), 0

    def configuration(self):
        return deepcopy(self._configuration)

    def validate(self):
        for name, (provider, config) in self._providers.items():
            if (getattr(self._runner, '_' + name + '_dependency_consumer') is not provider
                    or _bytes(getattr(self._runner, '_' + name + '_dependency_configuration')) != config):
                raise ValueError('classified-feedback-provider-configuration-changed')
            if provider is not None:
                report = type(provider).report(provider)
                document = json.loads(config)
                if (report['runtime_contract_sha256'] != document['runtime_contract_sha256']
                        or any(type(value) is not int or not 1 <= value <= 65536
                            or type(report['bounds'][key]) is not int
                            or report['bounds'][key] != value
                            for key, value in document.items() if key.startswith('max_'))):
                    raise ValueError('classified-feedback-provider-configuration-changed')

    def _consume(self, credit):
        self.validate()
        records, statuses = {}, {}
        for name, (provider, _) in self._providers.items():
            if provider is None:
                statuses[name] = 'not_configured'
                continue
            report = type(provider).report(provider)
            # Loading checks the entire classified ledger; only verified rows
            # from this exact installed provider may enter feedback.
            ledger = DependencyEvidenceLedger.from_document(report['ledger']).document()
            certificates = {}
            for certificate in report['certificates']:
                evidence_id = certificate['evidence_id']
                if evidence_id in certificates:
                    raise ValueError('classified-feedback-certificate-duplicate')
                certificates[evidence_id] = certificate
            statuses[name] = report['status']
            for row in ledger['records']['verified']:
                record = DependencyEvidence.from_document(row)
                if record.evidence_type != 'verified':
                    raise ValueError('classified-feedback-verified-record-required')
                _certified_record(name, provider, report, record, certificates)
                if record.evidence_id not in self._seen:
                    records[record.evidence_id] = record.document()
        if len(self._seen) + len(records) > self._max_records:
            raise ValueError('classified-feedback-capacity-exceeded')
        self._seen.update(records)
        if credit:
            self._count = min(65536, self._count + len(records))
        return records if credit else {}, statuses

    def prepare_case(self):
        self._consume(False)

    def observe_case(self):
        records, statuses = self._consume(True)
        return deepcopy(dict(
            verified_dependency=dict(category='verified_dependency',
                schema_version='classified_verified_dependency_feedback.v1',
                status='observed' if records else 'no_new_records',
                provider_statuses=statuses, new_records=[records[k] for k in sorted(records)],
                counts=dict(new=len(records), total=self._count),
                proof_scope='historical_installed_provider_verified_records_only',
                grants_prerequisites=False),
            functional_coverage=_functional_unknown()))

    def snapshot(self):
        self.validate()
        return deepcopy(dict(schema_version='classified_evidence_feedback_state.v1',
            configuration=self._configuration, configuration_sha256=self._hash,
            seen_evidence_ids=sorted(self._seen), counts=dict(verified=self._count),
            functional_coverage=_functional_unknown(),
            proof_scope='historical_feedback_only', grants_prerequisites=False))
