"""Deterministic, bounded controller-side mutation policy for RawBits v4."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
import hashlib
from typing import Mapping

from .input_model import InputValidationError
from .rawbits_v4 import RawBitsV4Lane


_TRANSITION_EVENT_CAPACITY = 64


class MutationLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2


@dataclass(frozen=True)
class MutationConfig:
    stall_threshold: int = 32
    cooldown_tests: int = 8
    exploration_capacity: int = 128
    seed_capacity: int = 64
    max_sites: tuple[int, int, int] = (1, 4, 16)
    acceptance_denominator: int = 32
    acceptance_numerators: tuple[int, int, int] = (1, 4, 16)

    def __post_init__(self) -> None:
        try:
            max_sites = tuple(self.max_sites)
            acceptance_numerators = tuple(self.acceptance_numerators)
        except TypeError as exc:
            raise InputValidationError("mutation level tables must be sequences") from exc
        object.__setattr__(self, "max_sites", max_sites)
        object.__setattr__(self, "acceptance_numerators", acceptance_numerators)
        integer_scalars = (
            self.stall_threshold, self.cooldown_tests,
            self.exploration_capacity, self.seed_capacity,
            self.acceptance_denominator,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_scalars):
            raise InputValidationError("mutation configuration values must be integers")
        if self.stall_threshold <= 0 or self.cooldown_tests < 0:
            raise InputValidationError("mutation thresholds must be non-negative/positive")
        if self.exploration_capacity <= 0 or self.seed_capacity <= 0:
            raise InputValidationError("mutation corpus capacities must be positive")
        if len(self.max_sites) != 3 or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in self.max_sites
        ):
            raise InputValidationError("mutation max_sites must have three positive levels")
        if len(self.acceptance_numerators) != 3 or self.acceptance_denominator <= 0:
            raise InputValidationError("mutation acceptance table is invalid")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value > self.acceptance_denominator
            for value in self.acceptance_numerators
        ):
            raise InputValidationError("mutation acceptance numerator is out of range")


@dataclass(frozen=True)
class MutationState:
    level: MutationLevel = MutationLevel.L0
    stagnant: int = 0
    cooldown: int = 0
    testcase_index: int = 0


@dataclass(frozen=True)
class ProtocolCampaignPolicy:
    """Protocol-only policy; B is raw escape, C/D share the 80/20 scheduler."""

    name: str
    protocol_weight: int = 80
    adversarial_weight: int = 20
    feedback: bool = False
    mutation_level: MutationLevel = MutationLevel.L0

    def __post_init__(self) -> None:
        if self.name not in {"B", "C", "D"}:
            raise InputValidationError("protocol campaign policy must be B, C, or D")
        if self.protocol_weight <= 0 or self.adversarial_weight <= 0:
            raise InputValidationError("protocol campaign weights must be positive")
        if self.name == "B" and self.feedback:
            raise InputValidationError("B raw policy cannot use coverage feedback")
        if self.name == "C" and self.feedback:
            raise InputValidationError("C policy cannot use coverage feedback")


def protocol_campaign_policy(name: str) -> ProtocolCampaignPolicy:
    if name == "B":
        return ProtocolCampaignPolicy("B")
    if name == "C":
        return ProtocolCampaignPolicy("C")
    if name == "D":
        return ProtocolCampaignPolicy("D", feedback=True)
    raise InputValidationError("unknown protocol campaign policy")


class ProtocolLaneScheduler:
    """Choose the lane with the largest deficit from the frozen 80/20 target."""

    def __init__(self, policy: ProtocolCampaignPolicy) -> None:
        self.policy = policy
        self.dispatched = {
            RawBitsV4Lane.RAW_ESCAPE: 0,
            RawBitsV4Lane.PROTOCOL_WAVEFORM: 0,
            RawBitsV4Lane.ADVERSARIAL_MUTATION: 0,
        }

    def choose(self) -> RawBitsV4Lane:
        total = sum(self.dispatched.values())
        if self.policy.name == "B":
            lane = RawBitsV4Lane.RAW_ESCAPE
        else:
            protocol_deficit = self.policy.protocol_weight * (total + 1) - self.dispatched[RawBitsV4Lane.PROTOCOL_WAVEFORM] * 100
            adversarial_deficit = self.policy.adversarial_weight * (total + 1) - self.dispatched[RawBitsV4Lane.ADVERSARIAL_MUTATION] * 100
            lane = RawBitsV4Lane.PROTOCOL_WAVEFORM if protocol_deficit >= adversarial_deficit else RawBitsV4Lane.ADVERSARIAL_MUTATION
        self.dispatched[lane] += 1
        return lane


@dataclass(frozen=True)
class MutationCandidate:
    parent_digest: str
    operator: str
    position: int
    payload_digest: str
    level: MutationLevel
    mutation_sites: int
    generation: int = 0
    lane: str = "ADVERSARIAL_MUTATION"
    old_value: int | None = None
    new_value: int | None = None

    @property
    def structure_signature(self) -> str:
        return f"{self.lane}:{self.parent_digest}:{self.operator}:{self.position}:{self.payload_digest}"


@dataclass(frozen=True)
class ExplorationEntry:
    candidate: MutationCandidate
    insertion_index: int
    last_selected_index: int = 0


class AdaptiveMutationController:
    """State machine for D; C can use ``mutate_level`` without feedback calls."""

    def __init__(self, seed: int, config: MutationConfig | None = None) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise InputValidationError("mutation seed must be a non-negative integer")
        self.seed = seed
        self.config = config or MutationConfig()
        self.state = MutationState()
        self._counter = 0
        self._parent_selection_counter = 0
        self._permanent_selection_counter = 0
        self._insertion = 0
        self._seeds: dict[str, MutationCandidate] = {}
        self._primary: dict[str, MutationCandidate] = {}
        self._exploration: dict[str, ExplorationEntry] = {}
        self._diagnostics = self._diagnostic_defaults()
        self._transition_events: list[dict[str, object]] = []

    @property
    def level(self) -> MutationLevel:
        return self.state.level

    @property
    def primary(self) -> tuple[MutationCandidate, ...]:
        return tuple(self._primary.values())

    @property
    def seeds(self) -> tuple[MutationCandidate, ...]:
        return tuple(self._seeds.values())

    @property
    def exploration(self) -> tuple[ExplorationEntry, ...]:
        return tuple(sorted(self._exploration.values(), key=lambda item: item.insertion_index))

    def mutate_level(self, level: MutationLevel | None = None) -> MutationLevel:
        return self.state.level if level is None else MutationLevel(level)

    def observe_result(self, new_branch_count: int) -> MutationState:
        if isinstance(new_branch_count, bool) or not isinstance(new_branch_count, int) or new_branch_count < 0:
            raise InputValidationError("new_branch_count must be a non-negative integer")
        current = self.state
        self._diagnostics["observed_results"] += 1
        self._diagnostics["level_before_counts"][current.level.name] += 1
        candidate_stagnant = 0 if new_branch_count else current.stagnant + 1
        self._diagnostics["maximum_stagnant"] = max(
            self._diagnostics["maximum_stagnant"], candidate_stagnant,
        )
        if new_branch_count:
            self._diagnostics["new_branch_results"] += 1
            self._diagnostics["new_branch_total"] += new_branch_count
            next_level = MutationLevel(max(MutationLevel.L0, current.level - 1))
            self.state = MutationState(next_level, 0, self.config.cooldown_tests, current.testcase_index + 1)
        elif current.cooldown:
            self._diagnostics["no_new_branch_results"] += 1
            self._diagnostics["cooldown_results"] += 1
            self.state = MutationState(current.level, current.stagnant + 1, current.cooldown - 1, current.testcase_index + 1)
        else:
            self._diagnostics["no_new_branch_results"] += 1
            stagnant = current.stagnant + 1
            level = current.level
            if stagnant >= self.config.stall_threshold and level < MutationLevel.L2:
                level = MutationLevel(level + 1)
                stagnant = 0
            self.state = MutationState(level, stagnant, 0, current.testcase_index + 1)
        if self.state.level != current.level:
            direction = f"{current.level.name}_TO_{self.state.level.name}"
            self._diagnostics["transition_counts"][direction] += 1
            self._diagnostics["transition_event_count"] += 1
            self._transition_events.append({
                "testcase_index": self.state.testcase_index,
                "from_level": current.level.name,
                "to_level": self.state.level.name,
                "reason": "new_branch" if new_branch_count else "stagnation",
                "new_branch_count": new_branch_count,
            })
            if len(self._transition_events) > _TRANSITION_EVENT_CAPACITY:
                del self._transition_events[0]
                self._diagnostics["transition_events_truncated"] = True
        return self.state

    def accepts_non_new_branch(self, candidate: MutationCandidate) -> bool:
        level = int(candidate.level)
        threshold = self.config.acceptance_numerators[level]
        draw = self._draw(candidate.structure_signature)
        return draw % self.config.acceptance_denominator < threshold

    def record(
        self, candidate: MutationCandidate, *, new_branch: bool,
        initial_seed: bool = False,
    ) -> bool:
        if candidate.mutation_sites > self.config.max_sites[int(candidate.level)]:
            raise InputValidationError("candidate exceeds mutation level site bound")
        self._diagnostics["candidate_results"] += 1
        self._diagnostics["candidate_level_counts"][candidate.level.name] += 1
        operators = self._diagnostics["operator_counts"]
        operators[candidate.operator] = operators.get(candidate.operator, 0) + 1
        signature = candidate.structure_signature
        if initial_seed:
            if candidate.operator not in {"seed", "protocol_seed"} or candidate.parent_digest:
                raise InputValidationError("initial mutation corpus entry is not a root seed")
            retained = self.add_seed(candidate)
            if new_branch:
                self._diagnostics["candidate_new_branch_results"] += 1
            return retained
        if new_branch:
            self._diagnostics["candidate_new_branch_results"] += 1
            self._promote_ancestors(candidate.parent_digest)
            self._primary[signature] = candidate
            self._diagnostics["primary_insertions"] += 1
            return True
        if signature in self._primary or signature in self._exploration:
            self._diagnostics["duplicate_rejections"] += 1
            return False
        if not self.accepts_non_new_branch(candidate):
            self._diagnostics["exploration_probability_rejections"] += 1
            return False
        self._insertion += 1
        self._exploration[signature] = ExplorationEntry(candidate, self._insertion)
        self._diagnostics["exploration_insertions"] += 1
        self._evict_if_needed()
        return signature in self._exploration

    @property
    def has_seeds(self) -> bool:
        return bool(self._seeds)

    def add_seed(self, candidate: MutationCandidate) -> bool:
        """Add a completed protocol projection to the bounded permanent seed bank."""
        if candidate.operator not in {"seed", "protocol_seed"} or candidate.parent_digest:
            raise InputValidationError("mutation seed must be a root candidate")
        signature = candidate.structure_signature
        if signature in self._seeds:
            return True
        if len(self._seeds) >= self.config.seed_capacity:
            return False
        self._seeds[signature] = candidate
        self._diagnostics["seed_insertions"] += 1
        return True

    def record_protocol_seed(
        self, candidate: MutationCandidate, *, new_branch: bool,
    ) -> bool:
        """Retain a completed valid protocol projection for future mutation."""
        self._diagnostics["protocol_seed_results"] += 1
        if new_branch:
            signature = candidate.structure_signature
            self._primary[signature] = candidate
            self._diagnostics["protocol_seed_new_branch_results"] += 1
            self._diagnostics["primary_insertions"] += 1
            return True
        return self.add_seed(candidate)

    def choose_exploration(self) -> ExplorationEntry | None:
        if not self._exploration:
            return None
        entry = min(self._exploration.values(), key=lambda item: (int(item.candidate.level), item.last_selected_index, item.insertion_index, item.candidate.payload_digest))
        self._counter += 1
        self._diagnostics["exploration_selections"] += 1
        self._exploration[entry.candidate.structure_signature] = ExplorationEntry(entry.candidate, entry.insertion_index, self._counter)
        return self._exploration[entry.candidate.structure_signature]

    def choose_parent(self) -> MutationCandidate | None:
        """Choose deterministically across permanent and exploratory corpus entries."""
        if not self._seeds and not self._primary and not self._exploration:
            return None
        permanent = tuple(self._seeds.values()) + tuple(
            candidate for signature, candidate in self._primary.items()
            if signature not in self._seeds
        )
        choose_exploration = bool(self._exploration) and (
            not permanent or self._parent_selection_counter % 2 == 1
        )
        self._parent_selection_counter += 1
        if choose_exploration:
            entry = self.choose_exploration()
            return None if entry is None else entry.candidate
        seeds = tuple(self._seeds.values())
        primary = tuple(
            candidate for signature, candidate in self._primary.items()
            if signature not in self._seeds
        )
        if seeds and primary:
            selected_pool = primary if self._permanent_selection_counter % 2 == 0 else seeds
        else:
            selected_pool = primary or seeds
        self._permanent_selection_counter += 1
        values = sorted(
            selected_pool,
            key=lambda item: (item.generation, item.payload_digest, item.structure_signature),
        )
        candidate = values[(self._permanent_selection_counter - 1) % len(values)]
        if candidate.structure_signature in self._seeds:
            self._diagnostics["seed_selections"] += 1
        else:
            self._diagnostics["primary_selections"] += 1
        return candidate

    def retained_payload_digests(self) -> tuple[str, ...]:
        return tuple(sorted({
            candidate.payload_digest
            for candidate in self._seeds.values()
        } | {
            candidate.payload_digest
            for candidate in self._primary.values()
        } | {
            entry.candidate.payload_digest
            for entry in self._exploration.values()
        }))

    def diagnostics(self) -> Mapping[str, object]:
        return {
            "schema": "myfuzz.adaptive-mutation-diagnostics/v4",
            "history_complete": self._diagnostics["history_complete"],
            "observed_results": self._diagnostics["observed_results"],
            "new_branch_results": self._diagnostics["new_branch_results"],
            "new_branch_total": self._diagnostics["new_branch_total"],
            "no_new_branch_results": self._diagnostics["no_new_branch_results"],
            "cooldown_results": self._diagnostics["cooldown_results"],
            "level_before_counts": dict(self._diagnostics["level_before_counts"]),
            "transition_counts": dict(self._diagnostics["transition_counts"]),
            "maximum_stagnant": self._diagnostics["maximum_stagnant"],
            "primary_insertions": self._diagnostics["primary_insertions"],
            "exploration_insertions": self._diagnostics["exploration_insertions"],
            "exploration_probability_rejections": self._diagnostics["exploration_probability_rejections"],
            "duplicate_rejections": self._diagnostics["duplicate_rejections"],
            "exploration_selections": self._diagnostics["exploration_selections"],
            "primary_selections": self._diagnostics["primary_selections"],
            "seed_insertions": self._diagnostics["seed_insertions"],
            "seed_selections": self._diagnostics["seed_selections"],
            "promoted_ancestors": self._diagnostics["promoted_ancestors"],
            "candidate_results": self._diagnostics["candidate_results"],
            "candidate_new_branch_results": self._diagnostics["candidate_new_branch_results"],
            "protocol_seed_results": self._diagnostics["protocol_seed_results"],
            "protocol_seed_new_branch_results": self._diagnostics["protocol_seed_new_branch_results"],
            "candidate_level_counts": dict(self._diagnostics["candidate_level_counts"]),
            "operator_counts": dict(sorted(self._diagnostics["operator_counts"].items())),
            "evictions": self._diagnostics["evictions"],
            "transition_event_count": self._diagnostics["transition_event_count"],
            "transition_events_truncated": self._diagnostics["transition_events_truncated"],
            "recent_transition_events": [dict(item) for item in self._transition_events],
            "final_state": {**asdict(self.state), "level": self.state.level.name},
            "primary_size": len(self._primary),
            "seed_size": len(self._seeds),
            "exploration_size": len(self._exploration),
        }

    def checkpoint(self) -> Mapping[str, object]:
        def candidate(value: MutationCandidate) -> dict[str, object]:
            result = asdict(value)
            result["level"] = int(value.level)
            return result
        return {
            "schema": "myfuzz.adaptive-mutation-state/v4",
            "seed": self.seed,
            "config": asdict(self.config),
            "state": {**asdict(self.state), "level": int(self.state.level)},
            "rng_counter": self._counter,
            "parent_selection_counter": self._parent_selection_counter,
            "permanent_selection_counter": self._permanent_selection_counter,
            "insertion_counter": self._insertion,
            "primary": [candidate(value) for value in self._primary.values()],
            "seeds": [candidate(value) for value in self._seeds.values()],
            "exploration": [
                {"candidate": candidate(entry.candidate), "insertion_index": entry.insertion_index,
                 "last_selected_index": entry.last_selected_index}
                for entry in self.exploration
            ],
            "diagnostics": self.diagnostics(),
        }

    @classmethod
    def from_checkpoint(cls, value: Mapping[str, object]) -> "AdaptiveMutationController":
        if value.get("schema") != "myfuzz.adaptive-mutation-state/v4":
            raise InputValidationError("adaptive mutation checkpoint schema mismatch")
        try:
            config = MutationConfig(**dict(value["config"]))
            controller = cls(int(value["seed"]), config)
            state = dict(value["state"])
            controller.state = MutationState(
                MutationLevel(int(state["level"])), int(state["stagnant"]),
                int(state["cooldown"]), int(state["testcase_index"]),
            )
            controller._counter = int(value["rng_counter"])
            controller._parent_selection_counter = int(
                value.get("parent_selection_counter", 0)
            )
            controller._permanent_selection_counter = int(
                value.get("permanent_selection_counter", 0)
            )
            controller._insertion = int(value["insertion_counter"])
            def candidate(item):
                data = dict(item); data["level"] = MutationLevel(int(data["level"]))
                return MutationCandidate(**data)
            for item in value["primary"]:
                current = candidate(item)
                controller._primary[current.structure_signature] = current
            for item in value.get("seeds", ()):
                current = candidate(item)
                controller._seeds[current.structure_signature] = current
            for item in value["exploration"]:
                current = candidate(item["candidate"])
                controller._exploration[current.structure_signature] = ExplorationEntry(
                    current, int(item["insertion_index"]), int(item["last_selected_index"]),
                )
            raw_diagnostics = value.get("diagnostics")
            if raw_diagnostics is None:
                controller._diagnostics["history_complete"] = False
                controller._diagnostics["observed_results"] = controller.state.testcase_index
                controller._diagnostics["maximum_stagnant"] = controller.state.stagnant
            elif isinstance(raw_diagnostics, Mapping):
                controller._restore_diagnostics(raw_diagnostics)
            else:
                raise InputValidationError("adaptive mutation diagnostics are malformed")
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("adaptive mutation checkpoint is malformed") from exc
        return controller

    def _evict_if_needed(self) -> None:
        while len(self._exploration) > self.config.exploration_capacity:
            victim = max(self._exploration.values(), key=lambda item: (int(item.candidate.level), item.last_selected_index, item.insertion_index, item.candidate.payload_digest))
            del self._exploration[victim.candidate.structure_signature]
            self._diagnostics["evictions"] += 1

    def _promote_ancestors(self, parent_digest: str) -> None:
        while parent_digest:
            match = next((
                entry for entry in self._exploration.values()
                if entry.candidate.payload_digest == parent_digest
            ), None)
            if match is None:
                return
            signature = match.candidate.structure_signature
            del self._exploration[signature]
            self._primary[signature] = match.candidate
            self._diagnostics["promoted_ancestors"] += 1
            parent_digest = match.candidate.parent_digest

    def _draw(self, domain: str) -> int:
        raw = f"myfuzz-mutation-v4:{self.seed}:{self._counter}:{domain}".encode("utf-8")
        self._counter += 1
        return int.from_bytes(hashlib.sha256(raw).digest()[:8], "little")

    @staticmethod
    def _diagnostic_defaults() -> dict[str, object]:
        return {
            "history_complete": True,
            "observed_results": 0,
            "new_branch_results": 0,
            "new_branch_total": 0,
            "no_new_branch_results": 0,
            "cooldown_results": 0,
            "level_before_counts": {level.name: 0 for level in MutationLevel},
            "transition_counts": {
                "L0_TO_L1": 0, "L1_TO_L2": 0,
                "L2_TO_L1": 0, "L1_TO_L0": 0,
            },
            "maximum_stagnant": 0,
            "primary_insertions": 0,
            "exploration_insertions": 0,
            "exploration_probability_rejections": 0,
            "duplicate_rejections": 0,
            "exploration_selections": 0,
            "primary_selections": 0,
            "seed_insertions": 0,
            "seed_selections": 0,
            "promoted_ancestors": 0,
            "candidate_results": 0,
            "candidate_new_branch_results": 0,
            "protocol_seed_results": 0,
            "protocol_seed_new_branch_results": 0,
            "candidate_level_counts": {level.name: 0 for level in MutationLevel},
            "operator_counts": {},
            "evictions": 0,
            "transition_event_count": 0,
            "transition_events_truncated": False,
        }

    def _restore_diagnostics(self, value: Mapping[str, object]) -> None:
        if value.get("schema") != "myfuzz.adaptive-mutation-diagnostics/v4":
            raise InputValidationError("adaptive mutation diagnostics schema mismatch")
        restored = self._diagnostic_defaults()
        scalar_names = (
            "observed_results", "new_branch_results", "new_branch_total",
            "no_new_branch_results", "cooldown_results", "maximum_stagnant",
            "primary_insertions", "exploration_insertions",
            "exploration_probability_rejections", "duplicate_rejections",
            "exploration_selections", "evictions", "transition_event_count",
            "primary_selections", "promoted_ancestors",
            "seed_insertions", "seed_selections",
            "candidate_results", "candidate_new_branch_results",
            "protocol_seed_results", "protocol_seed_new_branch_results",
        )
        backward_optional = {
            "primary_selections", "promoted_ancestors", "candidate_results",
            "candidate_new_branch_results", "seed_insertions", "seed_selections",
            "protocol_seed_results", "protocol_seed_new_branch_results",
        }
        try:
            restored["history_complete"] = bool(value["history_complete"])
            for name in scalar_names:
                restored[name] = int(
                    value.get(name, 0) if name in backward_optional else value[name]
                )
                if restored[name] < 0:
                    raise ValueError
            restored["transition_events_truncated"] = bool(value["transition_events_truncated"])
            restored["level_before_counts"] = {
                level.name: int(value["level_before_counts"][level.name])
                for level in MutationLevel
            }
            restored["transition_counts"] = {
                name: int(value["transition_counts"][name])
                for name in restored["transition_counts"]
            }
            raw_candidate_levels = value.get("candidate_level_counts", {})
            restored["candidate_level_counts"] = {
                level.name: int(raw_candidate_levels.get(level.name, 0))
                for level in MutationLevel
            }
            raw_operators = value.get("operator_counts", {})
            if not isinstance(raw_operators, Mapping):
                raise ValueError
            restored["operator_counts"] = {
                str(name): int(count) for name, count in raw_operators.items()
            }
            if (
                any(count < 0 for count in restored["candidate_level_counts"].values())
                or any(not name or count < 0 for name, count in restored["operator_counts"].items())
                or sum(restored["candidate_level_counts"].values())
                != restored["candidate_results"]
                or sum(restored["operator_counts"].values())
                != restored["candidate_results"]
            ):
                raise ValueError
            events = value["recent_transition_events"]
            if not isinstance(events, list) or len(events) > _TRANSITION_EVENT_CAPACITY:
                raise ValueError
            self._transition_events = [dict(item) for item in events]
        except (KeyError, TypeError, ValueError) as exc:
            raise InputValidationError("adaptive mutation diagnostics are malformed") from exc
        self._diagnostics = restored


def mutation_manifest(config: MutationConfig) -> Mapping[str, object]:
    return {
        "schema": "myfuzz.adaptive-mutation/v4",
        "stall_threshold": config.stall_threshold,
        "cooldown_tests": config.cooldown_tests,
        "exploration_capacity": config.exploration_capacity,
        "max_sites": list(config.max_sites),
        "acceptance_denominator": config.acceptance_denominator,
        "acceptance_numerators": list(config.acceptance_numerators),
    }
