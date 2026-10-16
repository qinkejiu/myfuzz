"""Bounded D8 scoring of prevalidated legal sources, never dependency proof.

The production caller must preflight ownership/routes/protocols and supply
new features from its frozen discovery configuration. This budget does not
perform those checks, enroll witnesses, or import saved scoring state.
"""
from copy import deepcopy
import hashlib
import json


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _text(value):
    return type(value) is str and 0 < len(value) <= 1024 and value.strip() == value


class CandidateExplorationBudget:
    def __init__(self, *, legal_sources, feature_sources, enabled=False, max_cases=65536):
        if (type(enabled) is not bool or type(max_cases) is not int
                or not 1 <= max_cases <= 65536
                or type(legal_sources) is not tuple or not 1 <= len(legal_sources) <= 4096
                or any(not _text(source) for source in legal_sources)
                or len(set(legal_sources)) != len(legal_sources)
                or type(feature_sources) is not dict or not 1 <= len(feature_sources) <= 65536
                or any(not _text(feature) or not _text(source) or source not in legal_sources
                       for feature, source in feature_sources.items())):
            raise ValueError('invalid candidate exploration configuration')
        self._config = dict(schema_version='candidate_exploration_budget.v1', enabled=enabled,
            legal_sources=sorted(legal_sources), feature_sources=dict(sorted(feature_sources.items())),
            max_cases=max_cases, novelty_units_per_case=1, energy_per_unit=1,
            max_energy_numerator=1, max_energy_denominator=10,
            proof_scope='legal_source_exploration_only', grants_prerequisites=False)
        self._configuration_sha256 = hashlib.sha256(_canonical(self._config)).hexdigest()
        self._seen = set()
        self._cases = {}
        self._energy = dict.fromkeys(legal_sources, 0)

    @property
    def configuration_sha256(self):
        return self._configuration_sha256

    def configuration(self):
        return deepcopy(self._config)

    def _weights(self, weights):
        if (type(weights) is not dict or set(weights) != set(self._energy)
                or any(type(value) is not int or not 1 <= value <= 65536
                       for value in weights.values())):
            raise ValueError('candidate weights must name exactly the prevalidated legal sources')

    def apply_weights(self, weights):
        """Add accumulated candidate energy to a baseline excluding candidates."""
        self._weights(weights)
        return {source: min(65536, weight + self._energy[source])
                for source, weight in weights.items()}

    def observe_case(self, *, case_id, new_features, non_candidate_new_energy, weights):
        """Budget one case using non-candidate energy and baseline weights.

        ``weights`` excludes this policy's accumulated candidate delta. The
        caller supplies actual non-candidate energy credited in this case,
        never total session weights or the count of candidate records.
        """
        self._weights(weights)
        if (not _text(case_id) or type(new_features) is not tuple
                or len(new_features) > len(self._config['feature_sources'])
                or any(not _text(feature) or feature not in self._config['feature_sources']
                       for feature in new_features)
                or len(set(new_features)) != len(new_features)
                or type(non_candidate_new_energy) is not int
                or not 0 <= non_candidate_new_energy <= 65536):
            raise ValueError('invalid candidate exploration case')
        features = sorted(new_features)
        digest = hashlib.sha256(_canonical(dict(features=features,
            non_candidate_new_energy=non_candidate_new_energy, weights=weights))).hexdigest()
        old = self._cases.get(case_id)
        if old is not None:
            if old[0] != digest:
                raise ValueError('candidate case identity reused with changed content')
            return deepcopy(old[1])
        if len(self._cases) >= self._config['max_cases']:
            raise ValueError('candidate exploration case capacity exceeded')
        novel = [feature for feature in features if feature not in self._seen]
        feature = novel[0] if self._config['enabled'] and novel else None
        source = self._config['feature_sources'][feature] if feature is not None else None
        energy = int(source is not None and non_candidate_new_energy >= 10
                     and self.apply_weights(weights)[source] < 65536)
        answer = dict(schema_version='candidate_exploration_case.v1', case_id=case_id,
            configuration_sha256=self.configuration_sha256,
            candidate_novelty=int(feature is not None), candidate_energy=energy,
            credited_feature=feature, credited_source=source,
            non_candidate_new_energy=non_candidate_new_energy,
            proof_scope='legal_source_exploration_only', grants_prerequisites=False)
        # Spend every observed feature, including those beyond this case's one
        # unit. No eviction/reset operation can renew the session identities.
        self._seen.update(features)
        if energy:
            self._energy[source] += energy
        self._cases[case_id] = digest, answer
        return deepcopy(answer)
