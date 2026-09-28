"""Select an upstream path from feedback and mutate only its declared source."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Mapping

from .dependency import DependencyGraph, DependencyPath
from .genome import ScenarioGenome
from .ownership import OwnershipMap


@dataclass(frozen=True)
class MutationPlan:
    direction: str
    target: str
    path: DependencyPath
    focus_source: str


_GENOME_TARGET_KINDS = frozenset(("genome_action", "initial_image"))
_RUNTIME_TARGET_KINDS = frozenset(("committed_ram", "read_snapshot",
                                   "real_response", "ip_output"))


@dataclass(frozen=True)
class MutationTarget:
    """The write target named by one mutation command.

    An empty action identifier selects the first matching Genome action, as
    the existing RFuzz/campaign operator does. Runtime targets are never
    writable, even when a caller also supplies a forged dependency source.
    """

    kind: str
    identifier: str = ""

    def __post_init__(self) -> None:
        if self.kind not in _GENOME_TARGET_KINDS | _RUNTIME_TARGET_KINDS:
            raise ValueError("unknown mutation target kind")
        if not isinstance(self.identifier, str):
            raise ValueError("mutation target identifier must be a string")
        if self.kind in _RUNTIME_TARGET_KINDS and not self.identifier:
            raise ValueError("runtime mutation target needs an identifier")


def choose_mutation(graph: DependencyGraph, target_weights: Mapping[str, int], *,
                    direction: str,
                    source_weights: Mapping[str, int] | None = None) -> MutationPlan:
    candidates: list[tuple[int, DependencyPath]] = []
    for target, weight in target_weights.items():
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
            raise ValueError("target weight must be nonnegative integer")
        for path in graph.paths_to(target, direction=direction):
            candidates.append((weight, path))
    if not candidates:
        raise ValueError("no reachable target has a fuzzable upstream source")
    weight, path = min(candidates, key=lambda item: (-item[0],
                                                      len(item[1].source_ids),
                                                      item[1].target,
                                                      item[1].source_ids))
    del weight
    if source_weights is None:
        source_weights = {}
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in source_weights.values()):
        raise ValueError("source weight must be nonnegative integer")
    focus = min(path.source_ids,
                key=lambda source_id: (-source_weights.get(source_id, 0), source_id))
    return MutationPlan(direction, path.target, path, focus)


def mutate_genome(genome: ScenarioGenome, plan: MutationPlan,
                  graph: DependencyGraph, ownership: OwnershipMap, *,
                  bit_index: int, action_id: str | None = None,
                  target: MutationTarget | None = None) -> ScenarioGenome:
    """Mutate a declared Genome source; reject runtime facts before execution.

    The default path used by RFuzz and Campaign also passes through this
    target-kind dispatch. An explicit target lets a caller name and test a
    forbidden runtime write without obtaining a writable runtime handle.
    """
    if target is not None and not isinstance(target, MutationTarget):
        raise ValueError("mutation target must be a MutationTarget")
    if target is not None and target.kind in _RUNTIME_TARGET_KINDS:
        raise ValueError("runtime mutation target is immutable")
    if (genome.direction != plan.direction
            or plan.target != plan.path.target
            or plan.path not in graph.paths_to(plan.target,
                                               direction=plan.direction)
            or plan.focus_source not in plan.path.source_ids):
        raise ValueError("mutation plan disagrees with genome path")
    source = graph.sources.get(plan.focus_source)
    if source is None:
        raise ValueError("mutation focus is not a declared source")
    if target is None:
        target = MutationTarget("initial_image", source.port) if (
            source.kind == "memory_image") else MutationTarget(
                "genome_action", action_id or "")
    if source.kind == "memory_image":
        if target.kind != "initial_image" or target.identifier != source.port:
            raise ValueError("mutation target does not match upstream source")
    elif target.kind != "genome_action" or (
            target.identifier and action_id is not None
            and target.identifier != action_id):
        raise ValueError("mutation target does not match upstream source")
    if target.kind == "genome_action" and target.identifier:
        action_id = target.identifier
    if (isinstance(bit_index, bool) or not isinstance(bit_index, int)
            or not 0 <= bit_index < source.width):
        raise ValueError("mutation bit is outside source width")
    absolute_bit = source.bit_offset + bit_index
    bit_owners = sum(
        candidate.kind == source.kind
        and candidate.component == source.component
        and candidate.port == source.port
        and candidate.bit_offset <= absolute_bit
        < candidate.bit_offset + candidate.width
        for candidate in graph.sources.values())
    if bit_owners != 1:
        raise ValueError("graph source ownership overlap")
    if source.kind == "memory_image":
        images = list(genome.initial_images)
        for index, image in enumerate(images):
            if image.image_id != source.port or image.component != source.component:
                continue
            if source.bit_offset + source.width > len(image.data) * 8:
                raise ValueError("mutation bit is outside memory image")
            data = bytearray(image.data)
            data[absolute_bit // 8] ^= 1 << (absolute_bit % 8)
            images[index] = replace(image, data_hex=bytes(data).hex())
            return replace(genome, initial_images=tuple(images))
        raise ValueError("genome has no image for selected upstream source")
    ownership.mutation_source(source.component, source.port,
                              source.bit_offset, source.width,
                              direction=plan.direction)
    actions = list(genome.actions)
    for index, action in enumerate(actions):
        if action_id is not None and action.action_id != action_id:
            continue
        action_width = (action.width if action.width is not None
                        else ownership.field_width(action.component, action.port))
        if (action.component == source.component and action.port == source.port
                and action.direction == plan.direction
                and action.bit_offset <= absolute_bit
                < action.bit_offset + action_width):
            local_bit = absolute_bit - action.bit_offset
            actions[index] = replace(action, value=action.value ^ (1 << local_bit))
            return replace(genome, actions=tuple(actions))
    raise ValueError("genome has no matching action for selected upstream source")
