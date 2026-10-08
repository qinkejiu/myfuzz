"""Decode RFuzz records into one dependency aware, persistent testcase.

The RFuzz record count is a count of mutation decisions. It is never a DUT
cycle count. Only graph declared upstream sources can change the genome.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from types import MappingProxyType

from .dependency import (DependencyGraph, DependencyPath, DependencyRule,
                         FuzzableSource, SourceBinding, SourceBindings)
from .genome import GenomeCodec, ScenarioGenome
from .mutation import MutationPlan, MutationTarget, mutate_genome, _compile_mutation_authorization
from .ownership import InputField, InputOwner, OwnershipMap, compile_ownership
from .runtime_path_contract import RuntimePathContract


RECORD_BYTES = 8


class _FrozenRules(list):
    def _deny(self, *args, **kwargs):
        raise TypeError('decoder rules are immutable')
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _deny


class _FrozenGraph(DependencyGraph):
    def __init__(self, original):
        super().__init__(sources=(), rules=original.ordered_rules)
        self.sources = MappingProxyType(dict(original.sources))
        self.rules = MappingProxyType({key: _FrozenRules(value) for key, value in self.rules.items()})
        self._indexed_rules = MappingProxyType(self._indexed_rules)
        self.edge_document()
        self._frozen = True

    def __setattr__(self, key, value):
        if getattr(self, '_frozen', False):
            raise AttributeError('decoder graph is immutable')
        super().__setattr__(key, value)


class _FrozenOwnership(OwnershipMap):
    def __init__(self, original):
        super().__init__(MappingProxyType({key: tuple(value) for key, value in original._bits.items()}))
        self._frozen = True

    def __setattr__(self, key, value):
        if getattr(self, '_frozen', False):
            raise AttributeError('decoder ownership is immutable')
        super().__setattr__(key, value)


class _RuntimePathCache:
    def _initialize_runtime_paths(self, graph, ownership, contract, targets):
        if not isinstance(contract, RuntimePathContract) or not isinstance(graph, DependencyGraph) or not isinstance(ownership, OwnershipMap):
            raise ValueError('runtime path contract is required')
        self._runtime_contract = contract
        self.graph, self.ownership = _FrozenGraph(graph), _FrozenOwnership(ownership)
        graph_digest = hashlib.sha256(json.dumps(self.graph.edge_document(), sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        if contract.graph_sha256 != graph_digest:
            raise ValueError('runtime contract graph digest differs')
        paths, lookup, ids = {}, {}, {}
        for direction, target in dict.fromkeys(targets):
            selected = self.graph.edge_paths_to(target, direction=direction)
            if not selected:
                raise ValueError('template target lacks a reachable upstream path')
            paths[(direction, target)] = selected
            for path in selected:
                identifier = self.graph.path_identity(path, direction=direction)
                lookup[identifier] = (direction, path)
                ids[(direction, path)] = identifier
        self._paths_by_key = MappingProxyType(paths)
        self._path_lookup = MappingProxyType(lookup)
        self._path_ids = MappingProxyType(ids)
        object.__setattr__(self.graph, '_decoder_path_proofs', frozenset(ids))

    @property
    def runtime_contract(self):
        return self._runtime_contract

    @property
    def runtime_paths(self):
        return tuple(self._path_lookup.values()) if self._runtime_contract is not None else ()

    def paths_for(self, target_id, *, direction):
        if self._runtime_contract is None:
            return self.graph.paths_to(target_id, direction=direction)
        return self._paths_by_key.get((direction, target_id), ())

    def resolve_path_id(self, path_id):
        if type(path_id) is not str or self._runtime_contract is None or path_id not in self._path_lookup:
            raise ValueError('unknown runtime path identity')
        return self._path_lookup[path_id]

    def path_identifier(self, path, *, direction):
        try:
            return self._path_ids[(direction, path)]
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError('unknown runtime path') from error

    def _path_mapping_document(self):
        return [{'direction': direction, 'path_id': identifier, 'target': path.target,
                 'source_ids': list(path.source_ids), 'edges': [edge.document() for edge in path.edges]}
                for identifier, (direction, path) in self._path_lookup.items()]


@dataclass(frozen=True)
class DecoderTemplate:
    target_id: str
    genome: ScenarioGenome

    def __post_init__(self) -> None:
        if not self.target_id or not isinstance(self.genome, ScenarioGenome):
            raise ValueError("decoder template requires a target and genome")


class GenomeRecordDecoder(_RuntimePathCache):
    """A fixed RFuzz input format selects direction, path, source and action."""

    def __init__(self, *, graph: DependencyGraph, ownership: OwnershipMap,
                 templates: tuple[DecoderTemplate, ...],
                 max_records: int = 200, max_delay_ticks: int = 64,
                 source_bindings: SourceBindings | None = None,
                 runtime_contract: RuntimePathContract | None = None) -> None:
        if not isinstance(templates, tuple) or not 1 <= len(templates) <= 256:
            raise ValueError("decoder requires 1..256 templates")
        if any(not isinstance(item, DecoderTemplate) for item in templates):
            raise ValueError("invalid decoder template")
        if not 1 <= max_records <= 200 or max_delay_ticks < 0:
            raise ValueError("decoder limits are invalid")
        if runtime_contract is not None and (type(max_records) is not int or type(max_delay_ticks) is not int):
            raise ValueError('runtime decoder limits must be integers')
        self._runtime_contract = None
        if runtime_contract is not None:
            self._initialize_runtime_paths(graph, ownership, runtime_contract,
                tuple((item.genome.direction, item.target_id) for item in templates))
            graph, ownership = self.graph, self.ownership
        else:
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
            if not self.paths_for(template.target_id, direction=template.genome.direction):
                raise ValueError("template target lacks a reachable upstream path")
        self._mutation_authorizations = {}
        if runtime_contract is not None:
            for direction, path in self.runtime_paths:
                for source_id in path.source_ids:
                    plan = MutationPlan(direction, path.target, path, source_id)
                    self._mutation_authorizations[(direction, path, source_id)] = _compile_mutation_authorization(plan, graph, ownership)

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
        if self.runtime_contract is not None:
            document['schema_version'] = 'scenario_rfuzz_decoder.v3'
            document.pop('sources')
            document.pop('rules')
            document['graph'] = self.graph.edge_document()
            document['runtime_contract'] = self.runtime_contract.document()
            document['path_mapping'] = self._path_mapping_document()
        return document

    @classmethod
    def from_document(cls, document: dict, *,
                      source_bindings: SourceBindings | None = None) -> GenomeRecordDecoder:
        """Reconstruct the exact decoder needed for raw corpus replay."""
        if not isinstance(document, dict) or document.get("schema_version") \
                not in ("scenario_rfuzz_decoder.v1", "scenario_rfuzz_decoder.v2", "scenario_rfuzz_decoder.v3"):
            raise ValueError("unknown RFuzz scenario decoder manifest")
        try:
            recorded_bindings = None
            if document["schema_version"] == "scenario_rfuzz_decoder.v2" or (document["schema_version"] == "scenario_rfuzz_decoder.v3" and 'source_bindings' in document):
                recorded_bindings = SourceBindings(tuple(
                    SourceBinding(**item) for item in document["source_bindings"]))
                if source_bindings is not None and source_bindings != recorded_bindings:
                    raise ValueError("decoder source bindings disagree with trusted binding")
            elif source_bindings is not None:
                raise ValueError("legacy decoder has no trusted source bindings")
            graph = DependencyGraph.from_edge_document(document['graph']) if document['schema_version'] == 'scenario_rfuzz_decoder.v3' else DependencyGraph(
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
                          source_bindings=recorded_bindings,
                          runtime_contract=(RuntimePathContract.from_document(document['runtime_contract'])
                              if document['schema_version'] == 'scenario_rfuzz_decoder.v3' else None))
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
        if self.source_bindings is not None and self.runtime_contract is None:
            self.source_bindings.validate(
                self.graph, self.ownership,
                tuple(item.genome for item in self.templates))
        if (not isinstance(records, tuple) or not 1 <= len(records) <= self.max_records
                or any(not isinstance(record, bytes)
                       or len(record) != RECORD_BYTES for record in records)):
            raise ValueError("RFuzz testcase needs 1..max_records eight bytes records")
        selected = self.templates[records[0][0] % len(self.templates)]
        paths = self.paths_for(selected.target_id, direction=selected.genome.direction)
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
                                       target=target,
                                       _authorization=self._mutation_authorizations.get((genome.direction, path, source.source_id)))
            elif source.kind == "source" and action_id is not None:
                changed = tuple(replace(action,
                                        delay_ticks=min(self.max_delay_ticks,
                                                        action.delay_ticks + record[6]))
                                if action.action_id == action_id else action
                                for action in genome.actions)
                genome = replace(genome, actions=changed)
        digest = hashlib.sha256(b"".join(records)).hexdigest()[:24]
        return replace(genome, testcase_id=f"rfuzz-{digest}",
                       path_id=(self.path_identifier(path, direction=genome.direction)
                                if self.runtime_contract is not None else
                                f"{selected.target_id}:{','.join(path.source_ids)}"))
