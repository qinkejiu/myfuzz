"""D8 exploration from the online runner's declared, observable legal paths.

This adapter owns fresh discovery/scoring state. Saved records are never
enrolled as evidence and correlation never grants a prerequisite.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from myfuzz.scenario.candidate_exploration import CandidateExplorationBudget
from myfuzz.scenario.dependency_candidates import (
    CandidateRelation, CandidateSignal, DependencyCandidateConsumer)
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer
from myfuzz.scenario.ip_base_events import IpBaseEventNormalizer
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.local_harness.native_physical_observation import (
    physical_observation_parameters, verify_native_physical_observation)


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE_PATHS = (
    'src/myfuzz/integration/candidate_exploration.py',
    'src/myfuzz/integration/classified_feedback.py',
    'src/myfuzz/scenario/candidate_exploration.py',
    'src/myfuzz/scenario/dependency_candidates.py',
    'src/myfuzz/scenario/dependency_evidence.py',
    'src/myfuzz/scenario/classified_feedback.py',
    'src/myfuzz/scenario/memory_dependency_evidence.py',
    'src/myfuzz/scenario/irq_dependency_evidence.py',
    'src/myfuzz/scenario/ip_base_events.py',
    'src/myfuzz/scenario/ip_base_coverage.py',
    'src/myfuzz/scenario/ip_protocol_events.py',
    'src/myfuzz/scenario/ip_protocol_checker.py',
    'src/myfuzz/local_harness/native_physical_observation.py',
)


def candidate_source_identity():
    return [dict(path=path, sha256=hashlib.sha256((_ROOT / path).read_bytes()).hexdigest())
            for path in _SOURCE_PATHS]


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _artifact_configuration(session):
    artifact = session.artifact
    profile, request = artifact.plan.profile, artifact.plan.request
    return dict(runtime=artifact.runtime_document, request=request.document(),
        profile=dict(component_id=profile.component_id, endpoints=[
            dict(endpoint_id=e.endpoint_id, clock=e.clock) for e in profile.endpoints]))


def _projector_configuration(normalizer):
    return dict(component_id=normalizer.component_id, instance_id=normalizer.instance_id,
                exports=normalizer._exports, bound_inputs=normalizer._bound_inputs,
                bound_exports=normalizer._bound_exports)


def _protocol_configuration(normalizer):
    if normalizer is None:
        return None
    if type(normalizer) not in (IpProtocolEventNormalizer, IpProtocolChecker):
        raise ValueError('candidate protocol projector type is unsupported')
    return dict(component_id=normalizer.component_id, instance_id=normalizer.instance_id,
        protocol=normalizer.protocol, endpoint_id=normalizer.endpoint_id,
        clock_domain=normalizer.clock_domain, max_wait_cycles=normalizer.max_wait_cycles,
        signals=normalizer._signals,
        **({'signal_widths': normalizer._widths} if type(normalizer) is IpProtocolChecker else {}))


def _observation_configuration(session, normalizer, protocol=None, checker=None):
    return dict(artifact=_artifact_configuration(session),
                projector=_projector_configuration(normalizer),
                protocol_projector=_protocol_configuration(protocol),
                protocol_checker=_protocol_configuration(checker))


class OnlineCandidateExploration:
    def __init__(self, executor, *, max_cases=65536):
        decoder, runner = executor.online_decoder, executor.session.runner
        prepared = executor._prepared_runtime_paths
        if prepared is None:
            raise ValueError('candidate exploration requires trusted runtime paths')
        # Actual topology binding checks ownership, routes and edge contracts
        # without starting a harness or issuing commands.
        self._compiled = prepared.bind(runner)
        self._executor, self._decoder = executor, decoder
        self._source_document = _bytes([asdict(s) for s in decoder.sources])
        nodes = {node.node_id: node for node in decoder.runtime_contract.nodes}
        declarations = {edge.key: edge for edge in decoder.runtime_contract.edges}
        signals, relations, feature_sources, observed = {}, [], {}, {}
        protocols = {}
        checkers = {}
        for direction, path in decoder.runtime_paths:
            legal = [s for s in decoder.sources if s.direction == direction
                     and s.path_id == path.target and s.source_id in path.source_ids]
            for edge in path.edges:
                declaration = declarations.get((edge.rule_index, edge.prerequisite_index))
                if declaration is None:
                    continue
                pair = (nodes[edge.prerequisite], nodes[edge.target])
                if any(node.kind != 'physical' for node in pair):
                    continue
                for node in pair:
                    if node.node_id in signals:
                        continue
                    local = runner.sessions[node.component]
                    if not callable(getattr(local, 'drain_tick_samples', None)):
                        raise ValueError('candidate physical observations unavailable')
                    try:
                        normalizer = runner._ip_base_event_normalizer(node.component, local)
                    except (ValueError, AttributeError, TypeError) as exc:
                        raise ValueError('candidate physical observation contract invalid') from exc
                    if normalizer is None:
                        raise ValueError('candidate physical observations unavailable')
                    artifact = local.artifact
                    document, profile = artifact.runtime_document, artifact.plan.profile
                    fresh = IpBaseEventNormalizer(component_id=profile.component_id,
                        instance_id=artifact.plan.request.instance_id,
                        **physical_observation_parameters(artifact))
                    if _bytes(_projector_configuration(fresh)) != _bytes(_projector_configuration(normalizer)):
                        raise ValueError('candidate cached projector differs from actual artifact')
                    native = verify_native_physical_observation(artifact)
                    port = node.port
                    if native:
                        aliases = document['native_physical_observation_mapping']['aliases']
                        port = next((a['physical_port'] for a in aliases if a['port'] == port), port)
                    exports = [row for row in normalizer._exports
                               if row['physical_port'] == port and (
                                   row['bit_lo'] <= node.bit_offset
                                   and node.bit_offset + node.width <= row['bit_lo'] + row['width']
                                   if native else (row['bit_lo'], row['width'])
                                   == (node.bit_offset, node.width))]
                    if (len(exports) != 1 or exports[0]['clock_domain'] is None
                            or exports[0]['direction'] != (
                                'input' if (node.component, node.port) in runner.ownership._bits
                                else 'output')):
                        raise ValueError('candidate physical export does not match runtime node')
                    row = exports[0]
                    signals[node.node_id] = CandidateSignal(node.node_id,
                        normalizer.component_id, normalizer.instance_id,
                        row['endpoint_id'], row['role'], row['physical_port'],
                        row['direction'], node.bit_offset, node.width,
                        **({'observation_bit_lo': row['bit_lo'],
                            'observation_width': row['width']} if native else {}))
                    if node.component not in observed:
                        try:
                            protocol = runner._ip_protocol_event_normalizer(node.component, local)
                            checker = runner._ip_protocol_checker(node.component, local)
                            trace = document.get('base_protocol_trace')
                            fresh_protocol = (IpProtocolEventNormalizer(
                                component_id=profile.component_id,
                                instance_id=artifact.plan.request.instance_id, protocol_trace=trace)
                                if trace is not None else None)
                            if _bytes(_protocol_configuration(protocol)) != _bytes(_protocol_configuration(fresh_protocol)):
                                raise ValueError('candidate cached protocol projector differs from artifact')
                            fresh_checker = (IpProtocolChecker(component_id=profile.component_id,
                                instance_id=artifact.plan.request.instance_id, protocol_trace=trace)
                                if trace is not None else None)
                            if _bytes(_protocol_configuration(checker)) != _bytes(_protocol_configuration(fresh_checker)):
                                raise ValueError('candidate cached protocol checker differs from artifact')
                        except (ValueError, AttributeError, TypeError, KeyError) as exc:
                            raise ValueError('candidate protocol observation contract invalid') from exc
                        protocols[node.component] = protocol
                        checkers[node.component] = checker
                        observed[node.component] = (local, normalizer,
                            _bytes(_observation_configuration(local, normalizer, protocol, checker)))
                for source in legal:
                    relation_id = hashlib.sha256(_bytes(dict(
                        path_id=decoder.path_identifier(path, direction=direction),
                        source_id=source.source_id, edge=edge.document()))).hexdigest()
                    relations.append(CandidateRelation(relation_id, pair[0].node_id,
                        pair[1].node_id, declaration.relation,
                        declaration_ref=decoder.runtime_contract.identity_sha256))
                    for rule in ('value_match', 'receipt_window'):
                        feature_sources[relation_id + ':' + rule] = source.source_id
        if not relations:
            raise ValueError('candidate exploration has no observable declared physical relation')
        # Same selected path can appear through multiple sources. Keep its
        # identical relation once without creating another novelty identity.
        relations = tuple({r.relation_id: r for r in relations}.values())
        self._observed = observed
        self._protocols = protocols
        self._checkers = checkers
        self._base = {component: IpBaseCoverageConsumer(
            component_id=normalizer.component_id, instance_id=normalizer.instance_id,
            endpoint_protocols=({protocols[component].endpoint_id: protocols[component].protocol}
                                if protocols[component] is not None else {}),
            physical_exports=normalizer._exports)
            for component, (_, normalizer, _) in observed.items()}
        contexts = tuple(sorted(json.dumps([base.component_id, base.instance_id, feature],
            separators=(',', ':'), ensure_ascii=False)
            for base in self._base.values() for feature in base.feature_universe
            if feature.startswith('port_change:') or feature.endswith((
                ':transaction_request', ':transaction_accept', ':transaction_response'))))[:64]
        for relation in relations:
            source_id = feature_sources[relation.relation_id + ':value_match']
            for feature in contexts:
                feature_sources[relation.relation_id + ':coverage_context:' + feature] = source_id
        self._discovery = DependencyCandidateConsumer(signals=tuple(signals.values()),
            relations=relations, allow_signal_aliases=True, coverage_features=contexts,
            base_coverage=tuple(self._base.values()))
        self._budget = CandidateExplorationBudget(
            legal_sources=tuple(s.source_id for s in decoder.sources),
            feature_sources=feature_sources, enabled=True, max_cases=max_cases)
        self._classified_feedback = executor._classified_feedback.consumer
        self._configuration = dict(classified_feedback=self._classified_feedback.configuration(), schema_version='online_candidate_exploration_config.v1',
            enabled=True, source_files=candidate_source_identity(), runtime_paths=prepared.document(),
            sources=[asdict(s) for s in decoder.sources],
            observations={component: json.loads(config)
                          for component, (_, _, config) in sorted(observed.items())},
            discovery=dict(signals=[asdict(s) for s in signals.values()],
                relations=[asdict(r) for r in relations],
                allow_signal_aliases=True,
                coverage_features=list(contexts),
                coverage_context_selection='lexicographic_first64_port_changes_and_protocol_boundaries.v1',
                bounds=self._discovery.snapshot()['bounds']),
            budget=self._budget.configuration(),
            energy_rule='positive_credited_weight_delta_fixed_hits_and_uses.v1',
            outside_case_policy='consume_without_scoring',
            proof_scope='legal_source_exploration_only', grants_prerequisites=False)
        self._configuration_sha256 = hashlib.sha256(_bytes(self._configuration)).hexdigest()
        self._max_cases = max_cases
        self._cases = self._novelty = self._energy = 0
        self.prepare_case()

    def validate(self):
        executor = self._executor
        self._compiled.validate_topology()
        self._classified_feedback.validate()
        if (executor.online_decoder is not self._decoder
                or _bytes([asdict(s) for s in self._decoder.sources]) != self._source_document):
            raise ValueError('candidate online sources changed')
        for path_id in executor._prepared_runtime_paths.path_ids:
            executor._validate_runtime_source_owners(path_id, executor.session.runner, self._decoder)
        for component, (local, normalizer, config) in self._observed.items():
            try:
                verify_native_physical_observation(local.artifact)
            except (ValueError, AttributeError, KeyError, TypeError) as exc:
                raise ValueError('candidate observation contract changed') from exc
            protocol = self._protocols[component]
            if (executor.session.runner._ip_protocol_event_normalizers.get(component) is not protocol
                    or _bytes(_protocol_configuration(protocol))
                    != _bytes(json.loads(config)['protocol_projector'])):
                raise ValueError('candidate protocol observation configuration changed')
            checker = self._checkers[component]
            if (executor.session.runner._ip_protocol_checkers.get(component) is not checker
                    or _bytes(_protocol_configuration(checker))
                    != _bytes(json.loads(config)['protocol_checker'])):
                raise ValueError('candidate protocol checker configuration changed')
            if (executor.session.runner.sessions.get(component) is not local
                    or executor.session.runner._ip_base_event_normalizers.get(component) is not normalizer
                    or _bytes(_observation_configuration(local, normalizer, protocol, checker)) != config):
                raise ValueError('candidate observation configuration changed')

    def _consume(self, events):
        cursor = self._discovery.cursor
        self._discovery.consume(events, start_cursor=cursor)
        for consumer in self._base.values():
            consumer.consume(events, start_cursor=cursor)

    def prepare_case(self):
        self.validate()
        if self._cases >= self._max_cases:
            raise ValueError('candidate exploration case capacity exceeded')
        # Bootstrap and between-case reset events never receive case energy.
        self._consume(self._executor.session.runner.events_since(self._discovery.cursor))

    def apply_weights(self, weights):
        self.validate()
        return self._budget.apply_weights(weights)

    def observe_case(self, result, *, non_candidate_new_energy, weights):
        self.validate()
        if (result.event_start != self._discovery.cursor
                or result.event_end - result.event_start != len(result.events)):
            raise ValueError('candidate case journal is not contiguous')
        before = set(self._discovery.snapshot()['feature_counts'])
        self._consume(result.events)
        new = tuple(sorted(set(self._discovery.snapshot()['feature_counts']) - before))
        feedback = self._budget.observe_case(case_id=result.case_id,
            new_features=new, non_candidate_new_energy=min(65536, non_candidate_new_energy),
            weights=weights)
        self._cases += 1
        self._novelty += feedback['candidate_novelty']
        self._energy += feedback['candidate_energy']
        return feedback

    def base_coverage(self):
        return dict(category='base_coverage', schema_version='online_base_coverage.v1',
                    instances={k: v.snapshot() for k, v in sorted(self._base.items())})

    def state(self):
        return deepcopy(dict(schema_version='online_candidate_exploration_state.v1',
            configuration=self._configuration, configuration_sha256=self._configuration_sha256,
            cases=self._cases, candidate_novelty=self._novelty, candidate_energy=self._energy,
            discovery=self._discovery.snapshot(), base_coverage=self.base_coverage(),
            classified_feedback=self._classified_feedback.snapshot(),
            proof_scope='legal_source_exploration_only', grants_prerequisites=False))
