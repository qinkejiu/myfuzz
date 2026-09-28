"""Decode RFuzz records into one dependency aware, persistent testcase.

The RFuzz record count is a count of mutation decisions. It is never a DUT
cycle count. Only graph declared upstream sources can change the genome.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
                         FuzzableSource, SourceBinding, SourceBindings)
from .genome import GenomeCodec, ScenarioGenome
from .mutation import MutationPlan, MutationTarget, mutate_genome
from .ownership import InputField, InputOwner, OwnershipMap, compile_ownership


RECORD_BYTES = 8


@dataclass(frozen=True)
class DecoderTemplate:
    target_id: str
    genome: ScenarioGenome

    def __post_init__(self) -> None:
        if not self.target_id or not isinstance(self.genome, ScenarioGenome):
            raise ValueError("decoder template requires a target and genome")


class GenomeRecordDecoder:
    """A fixed RFuzz input format selects direction, path, source and action."""

    def __init__(self, *, graph: DependencyGraph, ownership: OwnershipMap,
                 templates: tuple[DecoderTemplate, ...],
                 max_records: int = 200, max_delay_ticks: int = 64,
                 source_bindings: SourceBindings | None = None) -> None:
        if not isinstance(templates, tuple) or not 1 <= len(templates) <= 256:
            raise ValueError("decoder requires 1..256 templates")
        if any(not isinstance(item, DecoderTemplate) for item in templates):
            raise ValueError("invalid decoder template")
        if not 1 <= max_records <= 200 or max_delay_ticks < 0:
            raise ValueError("decoder limits are invalid")
        self.graph = graph
        self.ownership = ownership
        self.templates = templates
        self.max_records = max_records
        self.max_delay_ticks = max_delay_ticks
        self.source_bindings = source_bindings
        self.trusted_for_search = source_bindings is not None
        self.from_document_replay_only = False
        if source_bindings is not None:
            source_bindings.validate(graph, ownership,
                                     tuple(item.genome for item in templates))
        for template in templates:
            if not graph.paths_to(template.target_id,
                                  direction=template.genome.direction):
                raise ValueError("template target lacks a reachable upstream path")

    def document(self) -> dict:
        """Record all decode inputs so raw RFuzz corpus can be interpreted later."""
        document = {
            "schema_version": ("scenario_rfuzz_decoder.v2"
                               if self.source_bindings is not None
                               else "scenario_rfuzz_decoder.v1"),
            "record_bytes": RECORD_BYTES,
            "max_records": self.max_records,
            "max_delay_ticks": self.max_delay_ticks,
            "record_fields": ["template", "path", "source", "bit_low",
                              "action", "operator", "delay", "bit_high"],
            "templates": [{"target_id": item.target_id,
                           "genome": json.loads(GenomeCodec.encode(item.genome))}
                          for item in self.templates],
            "sources": [asdict(item) for _, item in sorted(self.graph.sources.items())],
            "rules": [asdict(rule)
                      for _, rules in sorted(self.graph.rules.items()) for rule in rules],
            "ownership": self.ownership.document(),
        }
        if self.source_bindings is not None:
            document["source_bindings"] = [asdict(item) for item in
                                           self.source_bindings.entries]
        return document

    @classmethod
    def from_document(cls, document: dict, *,
                      source_bindings: SourceBindings | None = None) -> GenomeRecordDecoder:
        """Reconstruct the exact decoder needed for raw corpus replay."""
        if not isinstance(document, dict) or document.get("schema_version") \
                not in ("scenario_rfuzz_decoder.v1", "scenario_rfuzz_decoder.v2"):
            raise ValueError("unknown RFuzz scenario decoder manifest")
        try:
            recorded_bindings = None
            if document["schema_version"] == "scenario_rfuzz_decoder.v2":
                recorded_bindings = SourceBindings(tuple(
                    SourceBinding(**item) for item in document["source_bindings"]))
                if source_bindings is not None and source_bindings != recorded_bindings:
                    raise ValueError("decoder source bindings disagree with trusted binding")
            elif source_bindings is not None:
                raise ValueError("legacy decoder has no trusted source bindings")
            graph = DependencyGraph(
                sources=tuple(FuzzableSource(**{**item,
                                                "directions": tuple(item["directions"])})
                              for item in document["sources"]),
                rules=tuple(DependencyRule(**{**item,
                                              "prerequisites": tuple(item["prerequisites"])})
                            for item in document["rules"]))
            ownership_data = document["ownership"]
            ownership = compile_ownership(
                tuple(InputField(**item) for item in ownership_data["fields"]),
                tuple(InputOwner(**item) for item in ownership_data["owners"]))
            templates = tuple(DecoderTemplate(
                item["target_id"],
                GenomeCodec.decode(json.dumps(item["genome"], sort_keys=True,
                                              separators=(",", ":")).encode("utf-8")))
                for item in document["templates"])
            decoder = cls(graph=graph, ownership=ownership, templates=templates,
                          max_records=document["max_records"],
                          max_delay_ticks=document["max_delay_ticks"],
                          source_bindings=recorded_bindings)
            # The document does not pin its rules, templates or ownership to a
            # trusted profile, even when an external source map is supplied.
            decoder.trusted_for_search = False
            decoder.from_document_replay_only = True
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid RFuzz scenario decoder manifest") from exc
        if (json.dumps(decoder.document(), sort_keys=True, separators=(",", ":"))
                != json.dumps(document, sort_keys=True, separators=(",", ":"))):
            raise ValueError("RFuzz scenario decoder manifest is not canonical")
        return decoder

    def _choices(self, genome: ScenarioGenome,
                 source: FuzzableSource) -> tuple[tuple[int, tuple[str, ...]], ...]:
        if source.width > 8192:
            raise ValueError("source width exceeds decoder bound")
        if source.kind == "memory_image":
            image = next((item for item in genome.initial_images
                          if item.image_id == source.port
                          and item.component == source.component), None)
            if image is None:
                return ()
            return tuple((index, ()) for index in range(source.width)
                         if source.bit_offset + index < len(image.data) * 8)
        choices = []
        for index in range(source.width):
            absolute = source.bit_offset + index
            action_ids = tuple(action.action_id for action in genome.actions
                               if action.component == source.component
                               and action.port == source.port
                               and action.direction == genome.direction
                               and action.bit_offset <= absolute
                               < action.bit_offset + (action.width or
                                   self.ownership.field_width(action.component,
                                                              action.port)))
            if action_ids:
                self.ownership.mutation_source(source.component, source.port,
                                               absolute, 1,
                                               direction=genome.direction)
                choices.append((index, action_ids))
        return tuple(choices)

    def decode(self, records: tuple[bytes, ...]) -> ScenarioGenome:
        if self.source_bindings is not None:
            self.source_bindings.validate(
                self.graph, self.ownership,
                tuple(item.genome for item in self.templates))
        if (not isinstance(records, tuple) or not 1 <= len(records) <= self.max_records
                or any(not isinstance(record, bytes)
                       or len(record) != RECORD_BYTES for record in records)):
            raise ValueError("RFuzz testcase needs 1..max_records eight bytes records")
        selected = self.templates[records[0][0] % len(self.templates)]
        paths = self.graph.paths_to(selected.target_id,
                                    direction=selected.genome.direction)
        path = paths[records[0][1] % len(paths)]
        genome = selected.genome
        for record in records:
            operation = record[5] % 3
            if operation == 0:
                continue
            sources = tuple(self.graph.sources[source_id]
                            for source_id in path.source_ids)
            source = sources[record[2] % len(sources)]
            choices = self._choices(genome, source)
            if not choices:
                raise ValueError("selected upstream source has no mutable genome field")
            bit_selector = record[3] | record[7] << 8
            bit_index, action_ids = choices[bit_selector % len(choices)]
            action_id = (action_ids[record[4] % len(action_ids)]
                         if action_ids else None)
            if operation == 1:
                plan = MutationPlan(genome.direction, path.target, path,
                                    source.source_id)
                target = (MutationTarget("initial_image", source.port)
                          if source.kind == "memory_image" else
                          MutationTarget("genome_action", action_id or ""))
                genome = mutate_genome(genome, plan, self.graph, self.ownership,
                                       bit_index=bit_index, action_id=action_id,
                                       target=target)
            elif source.kind == "source" and action_id is not None:
                changed = tuple(replace(action,
                                        delay_ticks=min(self.max_delay_ticks,
                                                        action.delay_ticks + record[6]))
                                if action.action_id == action_id else action
                                for action in genome.actions)
                genome = replace(genome, actions=changed)
        digest = hashlib.sha256(b"".join(records)).hexdigest()[:24]
        return replace(genome, testcase_id=f"rfuzz-{digest}",
                       path_id=f"{selected.target_id}:{','.join(path.source_ids)}")
