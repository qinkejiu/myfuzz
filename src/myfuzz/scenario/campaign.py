"""Small reference campaign using dependency targets and fresh scenario RTL.

This is a local reference executor. It does not claim RFuzz transport support.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import random
from typing import Callable

from .dependency import DependencyGraph
from .feedback import CoverageTarget, observed_targets
from .genome import ScenarioGenome
from .mutation import MutationPlan, MutationTarget, choose_mutation, mutate_genome
from .ownership import OwnershipMap
from .replay import ScenarioTrace, record_scenario
from .runner import ScenarioRunner


@dataclass(frozen=True)
class CampaignExecution:
    genome: ScenarioGenome
    trace: ScenarioTrace
    observed_targets: tuple[str, ...]
    new_targets: tuple[str, ...]
    mutation_plan: MutationPlan | None


@dataclass(frozen=True)
class CampaignResult:
    executions: tuple[CampaignExecution, ...]
    covered_targets: tuple[str, ...]


class ScenarioCampaign:
    def __init__(self, *, graph: DependencyGraph, ownership: OwnershipMap,
                 targets: tuple[CoverageTarget, ...],
                 factory: Callable[[], ScenarioRunner], random_seed: int) -> None:
        if not isinstance(random_seed, int) or isinstance(random_seed, bool):
            raise ValueError("random_seed must be an integer")
        if len({target.target_id for target in targets}) != len(targets):
            raise ValueError("coverage target IDs must be unique")
        if not targets:
            raise ValueError("campaign needs at least one semantic target")
        self.graph = graph
        self.ownership = ownership
        self.targets = targets
        self.factory = factory
        self.random = random.Random(random_seed)

    def run(self, seed: ScenarioGenome, *, mutations: int) -> CampaignResult:
        if not isinstance(seed, ScenarioGenome):
            raise ValueError("seed genome is required")
        if isinstance(mutations, bool) or not isinstance(mutations, int) \
                or mutations < 0:
            raise ValueError("mutations must be a nonnegative integer")
        seen: set[str] = set()
        source_uses = {source_id: 0 for source_id in self.graph.sources}
        executions: list[CampaignExecution] = []

        def execute(genome: ScenarioGenome,
                    plan: MutationPlan | None) -> CampaignExecution:
            trace = record_scenario(genome, self.factory)
            hits = observed_targets(trace.events, self.targets)
            new = hits - seen
            seen.update(hits)
            execution = CampaignExecution(genome, trace, tuple(sorted(hits)),
                                          tuple(sorted(new)), plan)
            executions.append(execution)
            return execution

        parent = seed
        execute(seed, None)
        for index in range(mutations):
            weights = {target.target_id: (100 if target.target_id not in seen else 1)
                       for target in self.targets}
            high_watermark = max(source_uses.values(), default=0)
            source_weights = {source_id: high_watermark - uses + 1
                              for source_id, uses in source_uses.items()}
            plan = choose_mutation(self.graph, weights, direction=parent.direction,
                                   source_weights=source_weights)
            source_uses[plan.focus_source] += 1
            source = self.graph.sources[plan.focus_source]
            bit_index = self.random.randrange(source.width)
            action_id = None
            if source.kind == "source":
                absolute_bit = source.bit_offset + bit_index
                matching = [action.action_id for action in parent.actions
                            if action.component == source.component
                            and action.port == source.port
                            and action.bit_offset <= absolute_bit
                            < action.bit_offset + (action.width or self.ownership.field_width(
                                action.component, action.port))]
                if matching:
                    action_id = self.random.choice(matching)
            target = (MutationTarget("initial_image", source.port)
                      if source.kind == "memory_image" else
                      MutationTarget("genome_action", action_id or ""))
            candidate = mutate_genome(parent, plan, self.graph, self.ownership,
                                      bit_index=bit_index, action_id=action_id,
                                      target=target)
            candidate = replace(candidate,
                                testcase_id=f"{seed.testcase_id}-mutation-{index + 1}")
            result = execute(candidate, plan)
            if result.new_targets:
                parent = candidate
        return CampaignResult(tuple(executions), tuple(sorted(seen)))
