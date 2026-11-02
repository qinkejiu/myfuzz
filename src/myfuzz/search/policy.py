"""Bounded frontier-conditioned scheduling and documentary delayed reward."""
from collections import deque
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
import random

from .actions import Catalog, Decision, context_key
from .frontier import frontier
from .model import canonical


class Policy:
    def __init__(self, *, seed, epsilon=0.10, max_contexts=4096,
                 max_decisions=65536, max_features=65536, mode="state"):
        if (type(seed) is not int or type(epsilon) not in (int, float)
                or not 0 <= epsilon <= 1 or type(max_contexts) is not int
                or not 1 <= max_contexts <= 4096
                or type(max_decisions) is not int or not 1 <= max_decisions <= 65536
                or type(max_features) is not int or not 1 <= max_features <= 65536
                or mode not in ("state", "uniform", "legacy")):
            raise ValueError("invalid bounded policy configuration")
        self.seed, self.epsilon = seed, epsilon
        self.max_contexts, self.max_decisions, self.max_features = max_contexts, max_decisions, max_features
        self._rng = random.Random(seed)
        self._contexts, self._arms, self._pending, self._settled = set(), {}, {}, {}
        self._seen = set()
        self._final_costs = {}
        self._completed_participants = {}
        self._late_relations = {}
        self._sequence = 0
        self._saturated = self._features_saturated = False
        self._catalog_identity = None
        self.mode = mode
        self._source_uses, self._source_gains, self._source_hits = {}, {}, {}

    def choose(self, goal, snapshot, catalog: Catalog):
        if self._sequence >= self.max_decisions or len(self._pending) >= 128:
            raise ValueError("decision or outstanding action capacity exhausted")
        if self._catalog_identity not in (None, catalog.identity):
            raise ValueError("action catalog drift")
        eligible = tuple(sorted(catalog.eligible(snapshot), key=lambda a: a.id))
        if not eligible:
            raise ValueError("no eligible action; state remains unknown or unavailable")
        front = frontier(goal, snapshot)
        context = context_key(goal, snapshot, front, tuple(a.id for a in eligible))
        bucket = context
        if context not in self._contexts:
            if len(self._contexts) >= self.max_contexts:
                bucket = "overflow"
                self._saturated = True
            else:
                self._contexts.add(context)
        focused = tuple(a for a in eligible if set(a.produces).intersection(front))
        pool = focused or eligible
        entropy = self._rng.getrandbits(128)
        if self.mode == "uniform":
            selected = eligible[(entropy >> 64) % len(eligible)]
            reason = "uniform"
        elif self.mode == "legacy":
            # Adapt the shipped formula to the SAME typed catalog. This does
            # not reproduce the old raw-byte path selector or native corpus.
            sources = sorted({a.source_id for a in eligible})
            weights = {}
            for source in sources:
                uses = self._source_uses.get(source, 0)
                gains = self._source_gains.get(source, 0)
                targets = {effect for a in catalog.actions if a.source_id == source for effect in a.produces}
                gap = bool(targets - self._source_hits.get(source, set()))
                weights[source] = max(1, min(65536, round(
                    8 + 64 * gap + 32 / (uses + 1) + 16 * gains / (uses + 1))))
            draw = (entropy & ((1 << 64) - 1)) % sum(weights.values())
            for source in sources:
                if draw < weights[source]:
                    break
                draw -= weights[source]
            choices = tuple(a for a in eligible if a.source_id == source)
            selected = choices[(entropy >> 64) % len(choices)]
            reason = "legacy-weight-adaptation"
        elif (entropy & ((1 << 64) - 1)) / (1 << 64) < self.epsilon:
            pool, reason = eligible, "explore"
            selected = pool[(entropy >> 64) % len(pool)]
        else:
            untried = [a for a in pool if (goal.identity, bucket, a.id) not in self._arms]
            reason = "frontier" if focused else "fallback"
            if untried:
                selected = untried[0]
            else:
                def rate(action):
                    rows = self._arms[(goal.identity, bucket, action.id)]
                    return Fraction(sum(r for _, r, _ in rows), max(1, sum(c for _, _, c in rows)))
                selected = max(pool, key=lambda a: (rate(a), -pool.index(a)))
        decision = Decision(self._sequence, goal.id, context, selected.id,
                            selected.values[(entropy >> 32) % len(selected.values)],
                            reason, entropy)
        arm = (goal.identity, bucket, selected.id)
        self._pending[decision.id] = (arm, selected.source_id)
        self._arms.setdefault(arm, deque(maxlen=128))
        self._source_uses[selected.source_id] = self._source_uses.get(selected.source_id, 0) + 1
        self._catalog_identity = catalog.identity
        self._sequence += 1
        return decision

    def settle(self, decision_id, features, cost_ns, *, censored=False):
        return self.settle_group((decision_id,), features, {decision_id: cost_ns}, censored=censored)[0]

    def settle_group(self, decision_ids, features, costs_ns, *, censored=False):
        """Split one semantic reward once among explicitly joined contributors.

        Participant joins are supplied by the execution adapter; this method
        never asserts that the join represents native evidence or causality.
        All participants and costs are validated before consuming any novelty.
        """
        if (type(features) is not dict or set(features) - {"relation", "frontier", "coverage"}
                or type(censored) is not bool or type(decision_ids) is not tuple
                or not 1 <= len(decision_ids) <= 128
                or any(type(key) is not str for key in decision_ids)
                or len(set(decision_ids)) != len(decision_ids)
                or type(costs_ns) is not dict or set(costs_ns) != set(decision_ids)
                or any(type(v) is not int or v <= 0 for v in costs_ns.values())):
            raise ValueError("invalid settlement")
        if any(key in self._final_costs and costs_ns[key] != self._final_costs[key]
               for key in decision_ids):
            raise ValueError('settlement conflicts with final cost')
        decision_ids = tuple(sorted(decision_ids))
        normalized = {}
        for kind, values in features.items():
            if (type(values) is not tuple or len(values) > 128
                    or any(type(v) is not str or not v or len(v) > 1024 for v in values)
                    or len(set(values)) != len(values)):
                raise ValueError("bounded unique semantic features required")
            normalized[kind] = tuple(sorted(values))
        fingerprint = sha256(canonical([decision_ids, normalized, costs_ns, censored])).hexdigest()
        if any(key in self._settled for key in decision_ids):
            if any(key not in self._settled or self._settled[key][0] != fingerprint for key in decision_ids):
                raise ValueError("conflicting settlement for existing decision")
            return [deepcopy(self._settled[key][1]) for key in decision_ids]
        if any(key not in self._pending for key in decision_ids):
            raise ValueError("unknown or expired decision")
        novel = [(kind, value) for kind, values in sorted(normalized.items())
                 for value in values if (kind, value) not in self._seen]
        reward = 0
        accepted = []
        if not censored:
            for item in novel:
                if len(self._seen) >= self.max_features:
                    self._features_saturated = True
                    continue
                self._seen.add(item)
                accepted.append(item)
                reward += 2 if item[0] == "relation" else 1
            reward = min(4, reward)
        answers = []
        share = Fraction(reward, len(decision_ids))
        for decision_id in decision_ids:
            arm, source = self._pending.pop(decision_id)
            self._completed_participants[decision_id] = (arm, source)
            if not censored:
                self._arms[arm].append((decision_id, share, costs_ns[decision_id]))
                self._source_gains[source] = self._source_gains.get(source, 0) + Fraction(len(accepted), len(decision_ids))
                self._source_hits.setdefault(source, set()).update(value for kind, value in accepted if kind == "frontier")
            answer = {"schema_version": "dependency_search_settlement.v1",
                      "decision_id": decision_id, "participants": list(decision_ids),
                      "reward": None if censored else float(share),
                      "reward_numerator": None if censored else share.numerator,
                      "reward_denominator": None if censored else share.denominator,
                      "cost_ns": costs_ns[decision_id], "censored": censored,
                      "novel_features": [list(item) for item in accepted],
                      "native_authority": False}
            self._settled[decision_id] = (fingerprint, deepcopy(answer))
            answers.append(deepcopy(answer))
        return answers

    def settle_relation_group(self, decision_ids, features, costs_ns):
        """Add a newly observed relation to retained trials, without re-entry.

        Exactly one pending consumer may join old, noncensored contributors
        whose original arm rows remain in the bounded window. Return ``None``
        for expired/censored participants, without consuming any novelty.
        Existing settle/settle_group idempotency documents remain unchanged;
        this method returns separate incremental credit records.
        """
        if (type(decision_ids) is not tuple or not 2 <= len(decision_ids) <= 128
                or len(set(decision_ids)) != len(decision_ids)
                or type(features) is not dict or set(features) != {'relation'}
                or type(costs_ns) is not dict or set(costs_ns) != set(decision_ids)
                or any(type(v) is not int or v <= 0 for v in costs_ns.values())):
            raise ValueError('invalid incremental relation settlement')
        decision_ids = tuple(sorted(decision_ids))
        if any(key in self._final_costs and costs_ns[key] != self._final_costs[key]
               for key in decision_ids):
            raise ValueError('incremental settlement conflicts with final cost')
        fingerprint = sha256(canonical([decision_ids, features, costs_ns])).hexdigest()
        if fingerprint in self._late_relations:
            return deepcopy(self._late_relations[fingerprint])
        pending = [key for key in decision_ids if key in self._pending]
        if len(pending) == len(decision_ids):
            return self.settle_group(decision_ids, features, costs_ns)
        if len(pending) != 1:
            return None
        consumer = pending[0]
        retained = {}
        for key in decision_ids:
            if key == consumer:
                continue
            previous = self._settled.get(key)
            if previous is None or previous[1]['censored']:
                return None
            arm, source = self._completed_participants[key]
            rows = self._arms[arm]
            match = [i for i, row in enumerate(rows) if row[0] == key]
            if not match:
                return None
            i = match[0]
            if rows[i][2] != costs_ns[key]:
                raise ValueError('incremental credit conflicts with retained cost')
            consumer_arm, _ = self._pending[consumer]
            if arm == consumer_arm and len(rows) == rows.maxlen and i == 0:
                return None  # The consumer would evict this contributor.
            retained[key] = (rows, key, source)
        # Normal settlement validates feature bounds and final cost before
        # novelty is consumed. Its consumer-only reward is redistributed below.
        answer = self.settle_group((consumer,), features, {consumer: costs_ns[consumer]})[0]
        total = Fraction(answer['reward_numerator'], answer['reward_denominator'])
        share = total / len(decision_ids)
        accepted_count = len(answer['novel_features'])
        arm, source = self._completed_participants[consumer]
        rows = self._arms[arm]
        for i, (key, reward, cost) in enumerate(rows):
            if key == consumer:
                rows[i] = (key, share, cost)
                break
        self._source_gains[source] -= Fraction(accepted_count * (len(decision_ids) - 1), len(decision_ids))
        records = []
        for key in decision_ids:
            if key in retained:
                rows, retained_id, old_source = retained[key]
                i = next(i for i, row in enumerate(rows) if row[0] == retained_id)
                identity, reward, cost = rows[i]
                rows[i] = (identity, reward + share, cost)
                self._source_gains[old_source] = self._source_gains.get(old_source, 0) + Fraction(accepted_count, len(decision_ids))
            record = dict(answer, schema_version='dependency_search_incremental_relation_credit.v1',
                decision_id=key, participants=list(decision_ids), reward=float(share),
                reward_numerator=share.numerator, reward_denominator=share.denominator,
                cost_ns=costs_ns[key], retained_trial=key != consumer)
            records.append(record)
        # Preserve the consumer's normal idempotent settlement with its share.
        old_fingerprint, _ = self._settled[consumer]
        consumer_answer = dict(answer, reward=float(share), reward_numerator=share.numerator,
                               reward_denominator=share.denominator)
        self._settled[consumer] = (old_fingerprint, consumer_answer)
        self._late_relations[fingerprint] = deepcopy(records)
        return records

    def finalize_cost(self, decision_id, cost_ns):
        """Update one measured denominator, never reward or novelty."""
        if (type(cost_ns) is not int or cost_ns <= 0
                or decision_id in self._final_costs
                or decision_id not in self._pending and decision_id not in self._settled):
            raise ValueError('invalid or repeated final cost')
        if decision_id in self._settled:
            fingerprint, answer = self._settled[decision_id]
            if cost_ns < answer['cost_ns']:
                raise ValueError('final cost precedes execution cost')
            self._settled[decision_id] = (fingerprint, dict(answer, cost_ns=cost_ns))
            for rows in self._arms.values():
                for i, (identity, reward, cost) in enumerate(rows):
                    if identity == decision_id:
                        rows[i] = (identity, reward, cost_ns)
        self._final_costs[decision_id] = cost_ns

    def statistics(self):
        return {"mode": self.mode, "contexts": len(self._contexts), "context_saturated": self._saturated,
                "features": len(self._seen), "features_saturated": self._features_saturated,
                "decisions": self._sequence, "pending": len(self._pending),
                "settled_trials": sum(len(rows) for rows in self._arms.values()),
                "arms": len(self._arms), "native_authority": False}
