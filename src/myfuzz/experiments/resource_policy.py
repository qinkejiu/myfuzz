from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass


_MIB = 1024 * 1024


class ResourceProfileError(ValueError):
    """Raised when a low-resource profile cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    candidate_limit: int
    seed_limit: int
    budget_name: str
    build_concurrency: int
    waveforms: bool
    replay_queue_capacity: int
    event_ring_capacity: int
    field_groups_per_batch: int
    soft_memory_bytes: int
    hard_memory_bytes: int
    token_bytes: int

    def __post_init__(self) -> None:
        if not self.name:
            raise ResourceProfileError("profile name must not be empty")
        if not self.budget_name:
            raise ResourceProfileError("profile budget_name must not be empty")
        positive = (
            ("candidate_limit", self.candidate_limit),
            ("seed_limit", self.seed_limit),
            ("build_concurrency", self.build_concurrency),
            ("replay_queue_capacity", self.replay_queue_capacity),
            ("event_ring_capacity", self.event_ring_capacity),
            ("field_groups_per_batch", self.field_groups_per_batch),
            ("soft_memory_bytes", self.soft_memory_bytes),
            ("hard_memory_bytes", self.hard_memory_bytes),
            ("token_bytes", self.token_bytes),
        )
        for label, value in positive:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ResourceProfileError(f"{label} must be a positive integer")
        if self.build_concurrency != 1:
            raise ResourceProfileError("low-resource build_concurrency must be 1")
        if self.waveforms is not False:
            raise ResourceProfileError("low-resource waveforms must be false")
        if self.soft_memory_bytes >= self.hard_memory_bytes:
            raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
        if self.token_bytes > self.soft_memory_bytes:
            raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")


CONSERVATIVE_PROFILE = ResourceProfile(
    name="conservative",
    candidate_limit=1,
    seed_limit=1,
    budget_name="smoke",
    build_concurrency=1,
    waveforms=False,
    replay_queue_capacity=32,
    event_ring_capacity=512,
    field_groups_per_batch=16,
    soft_memory_bytes=512 * _MIB,
    hard_memory_bytes=768 * _MIB,
    token_bytes=64 * _MIB,
)


def apply_resource_profile(
    config: Mapping[str, object],
    profile: ResourceProfile = CONSERVATIVE_PROFILE,
) -> dict[str, object]:
    """Return a detached planner config constrained by one resource profile."""
    if not isinstance(config, Mapping):
        raise ResourceProfileError("config must be an object")
    if not isinstance(profile, ResourceProfile):
        raise ResourceProfileError("profile must be a ResourceProfile")

    detached = copy.deepcopy(dict(config))
    selection = detached.get("candidate_selection")
    pair = detached.get("candidate_pair")
    budgets = detached.get("budgets")
    if not isinstance(selection, Mapping):
        raise ResourceProfileError("candidate_selection must be an object")
    if not isinstance(pair, Mapping):
        raise ResourceProfileError("candidate_pair must be an object")
    candidate_count = selection.get("k")
    if isinstance(candidate_count, bool) or not isinstance(candidate_count, int) or candidate_count <= 0:
        raise ResourceProfileError("candidate_selection.k must be a positive integer")
    seeds = pair.get("seeds")
    if not isinstance(seeds, Sequence) or isinstance(seeds, (str, bytes, bytearray)) or not seeds:
        raise ResourceProfileError("candidate_pair.seeds must be a non-empty array")
    normalized_seeds: list[int] = []
    for seed in seeds:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ResourceProfileError("candidate_pair.seeds must contain non-negative integers")
        normalized_seeds.append(seed)
    if len(normalized_seeds) != len(set(normalized_seeds)):
        raise ResourceProfileError("candidate_pair.seeds must be unique")
    if not isinstance(budgets, Sequence) or isinstance(budgets, (str, bytes, bytearray)) or not budgets:
        raise ResourceProfileError("budgets must be a non-empty array")
    selected_budget: dict[str, object] | None = None
    names: set[str] = set()
    for item in budgets:
        if not isinstance(item, Mapping):
            raise ResourceProfileError("each budget must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ResourceProfileError("budget name must be a non-empty string")
        if name in names:
            raise ResourceProfileError("budget names must be unique")
        names.add(name)
        if name == profile.budget_name:
            selected_budget = copy.deepcopy(dict(item))
    if selected_budget is None:
        raise ResourceProfileError(f"required budget is missing: {profile.budget_name}")

    for item in (selected_budget,):
        kind = item.get("kind")
        value = item.get("value")
        if kind not in {"cycles", "seconds"}:
            raise ResourceProfileError("selected budget kind must be cycles or seconds")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError("selected budget value must be a positive integer")

    def positive_int(label: str) -> int:
        value = detached.get(label)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError(f"{label} must be a positive integer")
        return value

    input_soft = positive_int("soft_memory_bytes")
    input_hard = positive_int("hard_memory_bytes")
    input_token = positive_int("token_bytes")
    input_build_concurrency = positive_int("build_concurrency")
    if not isinstance(detached.get("waveforms"), bool):
        raise ResourceProfileError("waveforms must be boolean")
    if input_soft >= input_hard:
        raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
    if input_token > input_soft:
        raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")

    output_selection = dict(selection)
    output_selection["k"] = min(candidate_count, profile.candidate_limit)
    output_pair = dict(pair)
    output_pair["seeds"] = sorted(normalized_seeds)[: profile.seed_limit]
    detached["candidate_selection"] = output_selection
    detached["candidate_pair"] = output_pair
    detached["budgets"] = [selected_budget]
    detached["build_concurrency"] = min(input_build_concurrency, profile.build_concurrency)
    detached["waveforms"] = profile.waveforms
    detached["replay_queue_capacity"] = min(
        positive_int("replay_queue_capacity"), profile.replay_queue_capacity
    )
    detached["event_ring_capacity"] = min(
        positive_int("event_ring_capacity"), profile.event_ring_capacity
    )
    detached["field_groups_per_batch"] = min(
        positive_int("field_groups_per_batch"), profile.field_groups_per_batch
    )
    output_soft = min(input_soft, profile.soft_memory_bytes)
    output_hard = min(input_hard, profile.hard_memory_bytes)
    if output_soft >= output_hard:
        raise ResourceProfileError("profile would make soft_memory_bytes invalid")
    detached["soft_memory_bytes"] = output_soft
    detached["hard_memory_bytes"] = output_hard
    detached["token_bytes"] = min(input_token, profile.token_bytes, output_soft)
    return detached
