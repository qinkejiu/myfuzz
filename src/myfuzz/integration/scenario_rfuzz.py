"""RFuzz shared-buffer adapter for complete, persistent scenario testcases.

One RFuzz test (possibly several fixed records) is decoded before any RTL is
started. Its records are mutation decisions, not DUT cycles. Existing RFuzz
wire framing remains unchanged; this adapter is opt-in for scenario mode.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Callable

from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.feedback import CoverageTarget, observed_targets
from myfuzz.scenario.genome import GenomeCodec, ScenarioGenome
from myfuzz.scenario.replay import ScenarioTrace, record_scenario
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder, RECORD_BYTES
from myfuzz.scenario.runner import ScenarioRunner

from .rfuzz_shmem import OwnedSegment
from .rfuzz_wire import InputBatch, encode_coverage_buffer, parse_input_buffer


@dataclass(frozen=True)
class ScenarioRfuzzReceipt:
    run_id: str
    buffer_id: int
    slot: int
    raw_sha256: str
    genome_sha256: str | None
    semantic_sha256: str | None
    status: str
    total_local_ticks: int
    coverage_hex: str
    violations: tuple[str, ...]
    error: str | None
    trace: ScenarioTrace | None
    manifest_sha256: str | None = None
    local_ticks: dict[str, int] | None = None
    path_id: str | None = None
    applied_sources: tuple[str, ...] = ()
    applied_template: int | None = None
    applied_path: int | None = None
    applied_hint_sequence: int | None = None
    effective_genome_sha256: str | None = None
    wall_cut: dict | None = None
    # Raw selection is applied_sources; this is trace-proven consumption.
    applied_source_ids: tuple[str, ...] = ()


def _effective_genome_sha256(genome: ScenarioGenome) -> str:
    """Hash executable scenario content, excluding RFuzz identity labels."""
    document = json.loads(GenomeCodec.encode(genome))
    document.pop("testcase_id")
    document.pop("path_id")
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _trace_protocol_environment_error(trace: ScenarioTrace) -> bool:
    """Classify only a typed harness failure, never an arbitrary DUT symptom."""
    return trace.status == "uncertain_effect" and any(
        event.get("kind") == "harness_failure"
        and event.get("error_type") == "ProtocolEnvironmentError"
        for event in trace.events)


def _trace_wall_cut(trace: ScenarioTrace) -> dict | None:
    """Retain the real wall-budget cut for deterministic corpus replay."""
    cut = next((dict(event) for event in trace.events
                if event.get("kind") == "budget_exhausted"
                and event.get("limit") == "max_wall_time_ms"), None)
    if cut is None:
        return None
    prefix_count = cut.get("prefix_event_count", len(trace.events) - 1)
    if type(prefix_count) is not int or not 0 <= prefix_count < len(trace.events):
        raise ValueError("invalid wall-cut event prefix")
    encoded = json.dumps(trace.events[:prefix_count], sort_keys=True,
                         separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    cut["semantic_prefix_sha256"] = hashlib.sha256(encoded).hexdigest()
    return cut


class ScenarioRfuzzExecutor:
    def __init__(self, *, run_id: str, decoder: GenomeRecordDecoder,
                 factory: Callable[[], ScenarioRunner],
                 targets: tuple[CoverageTarget, ...],
                 checker: Callable[[ScenarioTrace], tuple[str, ...]] | None = None,
                 evidence_dir: Path | None = None,
                 replay_only: bool = False,
                 allow_legacy_search: bool = False) -> None:
        if not run_id:
            raise ValueError("run_id is required")
        if not targets or len(targets) > 4096:
            raise ValueError("RFuzz requires 1..4096 coverage targets")
        if len({target.target_id for target in targets}) != len(targets):
            raise ValueError("coverage target IDs must be unique")
        if not replay_only:
            if decoder.from_document_replay_only:
                raise ValueError("decoder documents are replay-only")
            if not decoder.trusted_for_search and not (
                    allow_legacy_search and decoder.source_bindings is None):
                raise ValueError("search requires trusted source bindings; "
                                 "legacy search needs explicit compatibility")
        self.run_id = run_id
        self.decoder = decoder
        self.replay_only = replay_only
        self.factory = factory
        self.targets = targets
        self.checker = checker
        self.evidence_dir = Path(evidence_dir) if evidence_dir is not None else None
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.receipts: list[ScenarioRfuzzReceipt] = []
        self.first_receipt_completed_at: float | None = None
        self._completed: dict[tuple[int, int], tuple[str, bytes]] = {}
        self._target_hits: set[str] = set()
        self._hint_source_uses = {source_id: 0 for source_id in decoder.graph.sources}
        self._hint_sequence = 0
        self._published_hints: list[dict] = []
        self._latest_completed_batch: tuple[ScenarioRfuzzReceipt, ...] = ()
        self._max_completed_buffer_id: int | None = None

    @property
    def counter_count(self) -> int:
        return len(self.targets)

    @property
    def applied_source_uses(self) -> dict[str, int]:
        return dict(self._hint_source_uses)

    def note_published_hint(self, hint: dict) -> None:
        """Record a successfully published sideband; publication is not use."""
        self._published_hints.append(dict(hint))

    def _raw_mutation_provenance(self, records: tuple[bytes, ...]):
        """Recover sources exercised by actual submitted records.

        The wire format does not carry the Rust hint sequence. Associate a
        sequence only when the observed selector uniquely identifies one
        published hint; otherwise leave it unknown rather than inventing it.
        """
        template_index = records[0][0] % len(self.decoder.templates)
        template = self.decoder.templates[template_index]
        paths = self.decoder.graph.paths_to(
            template.target_id, direction=template.genome.direction)
        path_index = records[0][1] % len(paths)
        path = paths[path_index]
        source_indices = []
        selected_targets: dict[str, set[int | tuple[str, int, str]]] = {}
        for record in records:
            operation = record[5] % 3
            if operation == 0 or (operation == 2 and record[6] == 0):
                continue
            source_index = record[2] % len(path.source_ids)
            source = self.decoder.graph.sources[path.source_ids[source_index]]
            if operation == 1 or source.kind == "source":
                source_indices.append(source_index)
                choices = self.decoder._choices(template.genome, source)
                if not choices:
                    continue
                bit_selector = record[3] | record[7] << 8
                bit_index, action_ids = choices[bit_selector % len(choices)]
                absolute_bit = source.bit_offset + bit_index
                target = (absolute_bit // 8 if source.kind == "memory_image" else
                          (action_ids[record[4] % len(action_ids)],
                           absolute_bit,
                           "value" if operation == 1 else "delay")
                          if action_ids else ("", absolute_bit, "value"))
                selected_targets.setdefault(source.source_id, set()).add(target)
        sources = tuple(dict.fromkeys(path.source_ids[index]
                                      for index in source_indices))
        matching = [hint["sequence"] for hint in self._published_hints
                    if hint.get("template") == template_index
                    and hint.get("path") == path_index
                    and hint.get("source") in source_indices]
        sequence = matching[0] if len(matching) == 1 else None
        return sources, template_index, path_index, sequence, selected_targets

    def _consumed_source_ids(self, selected_targets: dict,
                             template_index: int, genome: ScenarioGenome,
                             trace: ScenarioTrace) -> tuple[str, ...]:
        """Count only mutated source bytes/ports observed by an accepted local step.

        A source injection alone is insufficient: a later successful step must
        record the same input segment. An image preload alone is insufficient:
        an accepted memory read must return the selected initial-image byte.
        Address aliases without a directly matching read are conservatively
        excluded. Neither condition proves a downstream causal effect.
        """
        template = self.decoder.templates[template_index].genome
        template_images = {(item.component, item.image_id): item
                           for item in template.initial_images}
        template_actions = {item.action_id: item for item in template.actions}
        final_actions = {item.action_id: item for item in genome.actions}
        used = []
        events = trace.events
        for source_id, targets in selected_targets.items():
            source = self.decoder.graph.sources[source_id]
            if source.kind == "memory_image":
                image = next((item for item in genome.initial_images
                              if item.component == source.component
                              and item.image_id == source.port), None)
                original = template_images.get((source.component, source.port))
                if image is None or original is None:
                    continue
                changed_bytes = {byte for byte in targets if type(byte) is int
                                 and byte < len(image.data)
                                 and image.data[byte] != original.data[byte]}
                if not changed_bytes:
                    continue
                preload = next((event for event in events
                                if event.get("kind") == "initial_image"
                                and event.get("component") == source.component
                                and event.get("image_id") == source.port
                                and event.get("address") == image.address
                                and event.get("data_hex") == image.data_hex), None)
                if preload is None:
                    continue
                for event in events:
                    if (event.get("kind") != "memory_read"
                            or event.get("component") != source.component
                            or event.get("event_id", 0) <= preload.get("event_id", 0)):
                        continue
                    transaction = event.get("transaction")
                    # Ibex exposes an instruction channel; CVA6's local
                    # harness has one unified instruction/data port.
                    if (source.component == "cpu"
                            and (not isinstance(transaction, dict)
                                 or transaction.get("channel_id")
                                 not in ("instr", "unified"))):
                        continue
                    address = event.get("address")
                    data_hex = event.get("data_hex")
                    writers = event.get("writer_event_ids")
                    if (type(address) is not int or not isinstance(data_hex, str)
                            or not isinstance(writers, (tuple, list))):
                        continue
                    try:
                        data = bytes.fromhex(data_hex)
                    except ValueError:
                        continue
                    if len(data) != len(writers):
                        continue
                    if any(address <= image.address + byte < address + len(data)
                           and 0 <= byte < len(image.data)
                           and data[image.address + byte - address] == image.data[byte]
                           and writers[image.address + byte - address] == "initial-image"
                           for byte in changed_bytes):
                        used.append(source_id)
                        break
                continue
            changed_actions = set()
            for action_id, absolute_bit, kind in targets:
                original = template_actions.get(action_id)
                actual = final_actions.get(action_id)
                if original is None or actual is None:
                    continue
                if kind == "delay":
                    changed = actual.delay_ticks != original.delay_ticks
                else:
                    local_bit = absolute_bit - actual.bit_offset
                    changed = (local_bit >= 0
                               and bool((actual.value ^ original.value)
                                        & (1 << local_bit)))
                if changed:
                    changed_actions.add(action_id)
            if not changed_actions:
                continue
            mask = ((1 << source.width) - 1) << source.bit_offset
            owner_ref = self.decoder.ownership.mutation_source(
                source.component, source.port, source.bit_offset,
                source.width, direction=genome.direction)
            for index, event in enumerate(events):
                if (event.get("kind") != "source_injection"
                        or event.get("component") != source.component
                        or event.get("port") != source.port
                        or event.get("source_ref") != owner_ref
                        or event.get("direction") != genome.direction
                        or event.get("action_id") not in changed_actions):
                    continue
                offset, width, value = (event.get("bit_offset"),
                                        event.get("width"), event.get("value"))
                if (type(offset) is not int or type(width) is not int or width < 1
                        or type(value) is not int
                        or not (mask & (((1 << width) - 1) << offset))):
                    continue
                observed_mask = mask & (((1 << width) - 1) << offset)
                expected = (value << offset) & observed_mask
                for later in events[index + 1:]:
                    if (later.get("kind") == "source_injection"
                            and later.get("component") == source.component
                            and later.get("port") == source.port
                            and type(later.get("bit_offset")) is int
                            and type(later.get("width")) is int
                            and later["width"] > 0
                            and observed_mask & (((1 << later["width"]) - 1)
                                        << later["bit_offset"])):
                        break
                    inputs = later.get("inputs")
                    if (later.get("component") == source.component
                            and isinstance(inputs, dict)
                            and type(inputs.get(source.port)) is int
                            and inputs[source.port] & observed_mask == expected):
                        used.append(source_id)
                        break
                if source_id in used:
                    break
        return tuple(used)

    def _feedback_hint_fields(self) -> dict:
        """The completed batch identity is shared by every mutation policy."""
        return {
            "feedback_scope": "cumulative_run_feedback",
            "max_completed_buffer_id": self._max_completed_buffer_id,
            "latest_completed_batch": [
                {"run_id": receipt.run_id,
                 "buffer_id": receipt.buffer_id, "slot": receipt.slot,
                 "raw_sha256": receipt.raw_sha256,
                 "genome_sha256": receipt.genome_sha256,
                 "path_id": receipt.path_id,
                 "status": receipt.status}
                for receipt in self._latest_completed_batch],
        }

    def mutation_hint(self) -> dict:
        """Prefer an uncovered target and rotate the supporting upstream source."""
        if self.replay_only:
            raise ValueError("replay-only executor cannot provide mutation hints")
        target_ids = {target.target_id for target in self.targets}
        candidates = [(index, template) for index, template
                      in enumerate(self.decoder.templates)
                      if template.target_id in target_ids]
        if not candidates:
            raise ValueError("no RFuzz template maps to a coverage target")
        template_index, template = min(
            candidates, key=lambda item: (item[1].target_id in self._target_hits,
                                          item[0]))
        paths = self.decoder.graph.paths_to(
            template.target_id, direction=template.genome.direction)
        path_index, path = min(enumerate(paths),
                               key=lambda item: (sum(self._hint_source_uses[s]
                                                     for s in item[1].source_ids), item[0]))
        source_index = min(range(len(path.source_ids)),
                           key=lambda index: (self._hint_source_uses[
                               path.source_ids[index]], index))
        source_id = path.source_ids[source_index]
        self._hint_sequence += 1
        return {"schema_version": "scenario_mutation_hint.v1",
                "run_id": self.run_id, "sequence": self._hint_sequence,
                **self._feedback_hint_fields(),
                "target_id": template.target_id,
                "template": template_index, "path": path_index,
                "source": source_index,
                "energy": 64 if template.target_id not in self._target_hits else 8}

    def _save_evidence(self, *, receipt: ScenarioRfuzzReceipt,
                       records: tuple[bytes, ...], genome: ScenarioGenome) -> None:
        if self.evidence_dir is None:
            return
        run_hash = hashlib.sha256(self.run_id.encode("utf-8")).hexdigest()[:8]
        name = (f"{receipt.status}_{run_hash}_{receipt.buffer_id}_{receipt.slot}_"
                f"{receipt.raw_sha256[:16]}.json")
        document = {"run_id": self.run_id, "buffer_id": receipt.buffer_id,
                    "slot": receipt.slot, "raw_records_hex": [r.hex() for r in records],
                    "raw_sha256": receipt.raw_sha256,
                    "path_id": receipt.path_id,
                    "genome": json.loads(GenomeCodec.encode(genome)),
                    "genome_sha256": receipt.genome_sha256,
                    "status": receipt.status,
                    "violations": list(receipt.violations),
                    "trace": asdict(receipt.trace)}
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                                             dir=self.evidence_dir,
                                             prefix=".violation-") as handle:
                temporary_path = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.evidence_dir / name)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def execute_batch(self, batch: InputBatch, *,
                      on_receipt: Callable[[ScenarioRfuzzReceipt], None] | None = None
                      ) -> tuple[bytes, ...]:
        if not isinstance(batch, InputBatch) or batch.input_bytes != RECORD_BYTES:
            raise ValueError("scenario RFuzz input must use eight bytes records")
        coverages: list[bytes] = []
        before_batch = len(self.receipts)
        for slot, records in enumerate(batch.tests):
            raw_hash = hashlib.sha256(b"".join(records)).hexdigest()
            identity = (batch.buffer_id, slot)
            old = self._completed.get(identity)
            if old is not None:
                if old[0] != raw_hash:
                    raise ValueError("RFuzz slot identity reused with different input")
                coverages.append(old[1])
                continue
            empty_coverage = bytes(self.counter_count)
            try:
                genome = self.decoder.decode(records)
            except ValueError as exc:
                receipt = ScenarioRfuzzReceipt(
                    self.run_id, batch.buffer_id, slot, raw_hash, None,
                    None, "input_invalid", 0, empty_coverage.hex(),
                    (), str(exc), None)
                coverage = empty_coverage
            else:
                try:
                    (applied_sources, applied_template, applied_path,
                     applied_hint_sequence, selected_targets) = self._raw_mutation_provenance(records)
                    effective_genome_sha256 = _effective_genome_sha256(genome)
                    trace = record_scenario(genome, self.factory)
                    consumed_sources = self._consumed_source_ids(
                        selected_targets, applied_template, genome, trace)
                    wall_cut = _trace_wall_cut(trace)
                    protocol_environment_error = _trace_protocol_environment_error(trace)
                    checks_allowed = trace.status not in (
                        "uncertain_effect", "environment_error") and not protocol_environment_error
                    violations = (tuple(self.checker(trace))
                                  if self.checker and checks_allowed else ())
                    if any(not isinstance(item, str) or not item
                           for item in violations):
                        raise ValueError("checker returned invalid violation IDs")
                    hits = observed_targets(trace.events, self.targets)
                    self._target_hits.update(hits)
                    coverage = bytes(int(target.target_id in hits)
                                     for target in self.targets)
                    status = ("environment_error" if protocol_environment_error else
                              "dut_violation" if violations else trace.status)
                    receipt = ScenarioRfuzzReceipt(
                        self.run_id, batch.buffer_id, slot, raw_hash,
                        trace.genome_sha256, trace.semantic_sha256, status,
                        sum(trace.local_ticks.values()), coverage.hex(),
                        violations, None,
                        trace if violations or not checks_allowed or wall_cut else None,
                        trace.manifest_sha256, dict(trace.local_ticks),
                        genome.path_id, applied_sources, applied_template,
                        applied_path, applied_hint_sequence,
                        effective_genome_sha256, wall_cut, consumed_sources)
                except Exception as exc:
                    receipt = ScenarioRfuzzReceipt(
                        self.run_id, batch.buffer_id, slot, raw_hash, None,
                        None, "environment_error", 0, empty_coverage.hex(), (),
                        f"{type(exc).__name__}: {exc}", None)
                    coverage = empty_coverage
            if receipt.status in ("dut_violation", "uncertain_effect"):
                self._save_evidence(receipt=receipt, records=records,
                                    genome=genome)
            self.receipts.append(receipt)
            if receipt.genome_sha256 is not None:
                for source_id in receipt.applied_source_ids:
                    self._hint_source_uses[source_id] += 1
            self._max_completed_buffer_id = (batch.buffer_id if self._max_completed_buffer_id is None
                                             else max(self._max_completed_buffer_id,
                                                      batch.buffer_id))
            if self.first_receipt_completed_at is None:
                self.first_receipt_completed_at = time.monotonic()
            self._completed[identity] = (raw_hash, coverage)
            coverages.append(coverage)
            if on_receipt is not None:
                on_receipt(receipt)
        if len(self.receipts) > before_batch:
            self._latest_completed_batch = tuple(self.receipts[before_batch:])
        return tuple(coverages)

    def process_owned_pair(self, input_id: int, coverage_id: int, *,
                           creator_pid: int,
                           on_receipt: Callable[[ScenarioRfuzzReceipt], None] | None = None
                           ) -> tuple[int, int]:
        """Use existing RFuzz SysV framing with slot-aware execution identity."""
        if input_id == coverage_id:
            raise ValueError("input and coverage shared-memory IDs alias")
        with OwnedSegment(input_id, creator_pid=creator_pid) as inputs, \
                OwnedSegment(coverage_id, creator_pid=creator_pid,
                             writable=True) as outputs:
            batch = parse_input_buffer(inputs.read(), input_bytes=RECORD_BYTES,
                                       max_cycles=self.decoder.max_records)
            stride = ((self.counter_count + 2 + 7) // 8) * 8
            if 16 + stride * len(batch.tests) > outputs.size:
                raise ValueError("RFuzz coverage capacity is insufficient")
            coverages = (self.execute_batch(batch) if on_receipt is None
                         else self.execute_batch(batch, on_receipt=on_receipt))
            outputs.write(encode_coverage_buffer(
                batch, coverages, counter_count=self.counter_count,
                capacity=outputs.size))
        return coverage_id, input_id
