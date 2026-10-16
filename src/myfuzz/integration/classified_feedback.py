"""Independent classified evidence reporting for online executions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from myfuzz.scenario.classified_feedback import ClassifiedEvidenceFeedback


_SOURCE_FILES = (
    'src/myfuzz/integration/classified_feedback.py',
    'src/myfuzz/scenario/classified_feedback.py',
    'src/myfuzz/scenario/dependency_evidence.py',
    'src/myfuzz/scenario/memory_dependency_evidence.py',
    'src/myfuzz/scenario/irq_dependency_evidence.py',
    'src/myfuzz/integration/candidate_exploration.py',
    'src/myfuzz/scenario/ip_base_coverage.py',
    'src/myfuzz/scenario/ip_base_events.py',
    'src/myfuzz/scenario/ip_protocol_events.py',
    'src/myfuzz/scenario/ip_protocol_checker.py',
    'src/myfuzz/local_harness/native_physical_observation.py',
)


def classified_source_identity():
    root = Path(__file__).resolve().parents[3]
    return [dict(path=p, sha256=hashlib.sha256((root/p).read_bytes()).hexdigest()) for p in _SOURCE_FILES]


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


class OnlineClassifiedFeedback:
    def __init__(self, executor, *, max_records=4096):
        if executor.online_decoder is None or executor.session is None:
            raise ValueError('classified feedback requires an actual online session')
        self._executor, self._runner = executor, executor.session.runner
        self.explicit_enabled = executor.classified_feedback
        self.consumer = ClassifiedEvidenceFeedback(self._runner, max_records=max_records)
        self._observed, self._base = {}, {}
        self._cursor = 0
        if self.explicit_enabled:
            from .candidate_exploration import (_observation_configuration,
                _projector_configuration, _protocol_configuration)
            from myfuzz.local_harness.native_physical_observation import physical_observation_parameters
            from myfuzz.scenario.ip_base_events import IpBaseEventNormalizer
            from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
            from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
            from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer
            for component, local in self._runner.sessions.items():
                artifact = getattr(local, 'artifact', None)
                if artifact is None or artifact.runtime_document.get('base_event_schema_version') != 'ip_base_event.v1':
                    continue
                physical = self._runner._ip_base_event_normalizer(component, local)
                protocol = self._runner._ip_protocol_event_normalizer(component, local)
                checker = self._runner._ip_protocol_checker(component, local)
                if physical is None:
                    raise ValueError('classified base observation unavailable')
                profile = artifact.plan.profile
                fresh = IpBaseEventNormalizer(component_id=profile.component_id,
                    instance_id=artifact.plan.request.instance_id, **physical_observation_parameters(artifact))
                trace = artifact.runtime_document.get('base_protocol_trace')
                kwargs = dict(component_id=profile.component_id, instance_id=artifact.plan.request.instance_id, protocol_trace=trace)
                fresh_protocol = IpProtocolEventNormalizer(**kwargs) if trace is not None else None
                fresh_checker = IpProtocolChecker(**kwargs) if trace is not None else None
                if (_bytes(_projector_configuration(physical)) != _bytes(_projector_configuration(fresh))
                        or _bytes(_protocol_configuration(protocol)) != _bytes(_protocol_configuration(fresh_protocol))
                        or _bytes(_protocol_configuration(checker)) != _bytes(_protocol_configuration(fresh_checker))):
                    raise ValueError('classified cached observation differs from actual artifact')
                config = _bytes(_observation_configuration(local, physical, protocol, checker))
                self._observed[component] = (local, physical, protocol, checker, config)
                self._base[component] = IpBaseCoverageConsumer(component_id=physical.component_id,
                    instance_id=physical.instance_id, physical_exports=physical._exports,
                    endpoint_protocols={protocol.endpoint_id: protocol.protocol} if protocol else {})
        self._configuration = dict(observations={k: json.loads(row[4]) for k,row in self._observed.items()},schema_version='online_classified_feedback_config.v1',
            enabled=True, explicit_requested=self.explicit_enabled, evidence=self.consumer.configuration(),
            source_files=classified_source_identity(),
            outside_case_policy='consume_without_scoring',
            proof_scope='historical_classified_feedback_only', grants_prerequisites=False)
        self._hash = hashlib.sha256(json.dumps(self._configuration, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        self._cases = 0

    def validate(self):
        if self._executor.session.runner is not self._runner:
            raise ValueError('classified feedback runner changed')
        if type(self._executor.classified_feedback) is not bool or self._executor.classified_feedback is not self.explicit_enabled:
            raise ValueError('classified feedback switch changed')
        self.consumer.validate()
        from .candidate_exploration import _observation_configuration
        from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
        for component, (local, physical, protocol, checker, config) in self._observed.items():
            verify_native_physical_observation(local.artifact)
            if (self._runner.sessions.get(component) is not local
                    or self._runner._ip_base_event_normalizers.get(component) is not physical
                    or self._runner._ip_protocol_event_normalizers.get(component) is not protocol
                    or self._runner._ip_protocol_checkers.get(component) is not checker
                    or _bytes(_observation_configuration(local, physical, protocol, checker)) != config):
                raise ValueError('classified base observation configuration changed')

    def _consume_base(self):
        events = self._runner.events_since(self._cursor)
        for consumer in self._base.values():
            consumer.consume(events, start_cursor=self._cursor)
        self._cursor += len(events)

    def base_coverage(self):
        return dict(category='base_coverage', schema_version='online_base_coverage.v1',
            status='observed' if self._base else 'unknown',
            instances={k:v.snapshot() for k,v in sorted(self._base.items())})

    def prepare_case(self):
        self.validate(); self.consumer.prepare_case(); self._consume_base()

    def observe_case(self):
        self.validate()
        result = self.consumer.observe_case()
        self._consume_base()
        if self.explicit_enabled:
            result['base_coverage'] = self.base_coverage()
            if self._executor._candidate_exploration is None:
                result['candidate_novelty'] = dict(category='candidate_novelty',
                    schema_version='disabled_candidate_feedback.v1', status='disabled',
                    candidate_novelty=0, candidate_energy=0, grants_prerequisites=False)
        self._cases += 1
        return result

    def state(self):
        self.validate()
        return deepcopy(dict(schema_version='online_classified_feedback_state.v1',
            configuration=self._configuration, configuration_sha256=self._hash,
            cases=self._cases, evidence=self.consumer.snapshot(), base_coverage=self.base_coverage(),
            proof_scope='historical_classified_feedback_only', grants_prerequisites=False))
