"""Read-only slot immutability gate over one saved online trace.

The plan forbids mutating program bytes that a real Store or fetch already
determined: "真实 Store/取指后的程序字节不能被后例变异".  Persistent memory
already refuses such a write at admission time and that refusal has its own
rejection code; this module answers the different, evidence-side question over
*saved* artifacts: did a later case ever submit a **different** value to a
program byte an earlier case had already materialized, or read back a different
value?

It is read-only by construction: it opens the run directory, reads
``online_events.jsonl`` (or an explicitly given event file) and the declared
instruction reservation of ``decoder_manifest.json``, and writes nothing inside
the run.  No RTL is compiled, rendered or started.

Evidence model
--------------
* program regions: the declared online instruction reservation
  ``[instruction_start, instruction_end)`` of the run's decoder manifest, plus
  every byte range a declared ``initial_image`` event installs.  Both are
  declarations of the run, so the checker never guesses where program bytes
  live; it refuses a run that declares no reservation.
* slot universe: every byte of those regions that at least one observed event
  materializes or reads.  Region bytes no event touches are reported as a
  count, never as a pass.
* materialization events: ``instruction_source`` (the decoded instruction bytes
  supplied to the CPU), ``initial_image`` and ``memory_initialization`` (program
  bytes installed before the session) and ``memory_write`` (a real CPU Store).
  A Store only materializes the lanes it enables *and* only when its own
  ``memory_write_commit`` receipt says ``commit_status == complete`` and
  ``performed_effect`` is true; disabled lanes stay unmaterialized, and a store
  without such a receipt (or with one that did not take effect) never counts as
  materialization.
* read evidence: ``memory_read`` and non-write, non-error ``instr_response``.
  Only the lanes the response actually carries are compared.  Retire-level
  instruction words are deliberately not used: ``cpu_retire.insn`` does not
  state the compressed-instruction length, so comparing four bytes there could
  invent a mismatch.
* a byte is a conflict when a later materialization writes a **different**
  value, or a later read returns a different value than the byte's established
  value.  Re-materializing the same value is recorded as a reassertion, not as
  a value conflict, and never makes a slot ``violated`` on its own.
* a byte is ``insufficient_evidence`` when it was read before it was
  materialized, when it was read but never materialized, or when a store that
  wrote it has no complete commit receipt, or when its record is malformed.
  Such a byte is never reported as ``immutable``.

Conclusions are per run and explicitly bounded: the report covers the events of
that one trace.  ``run_conclusion`` is ``violated`` when any slot is violated,
``insufficient_evidence`` when no slot is violated but one lacks evidence (or
no slot exists at all), and ``immutable`` only when at least one program byte
was materialized and no slot is violated or unevidenced.

Command line
------------
``PYTHONPATH=src python3 -m myfuzz.scenario.slot_immutability RUN_DIR [...]``
reads each run directory and exits ``0`` for ``immutable``, ``1`` for
``violated`` and ``2`` for ``insufficient_evidence``, so an unevidenced run
cannot be mistaken for a pass.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys


SLOT_IMMUTABILITY_SCHEMA_VERSION = "slot_immutability_report.v1"
#: Event kinds that can materialize program bytes.
MATERIALIZATION_KINDS = ("instruction_source", "initial_image",
                         "memory_initialization", "memory_write")
#: Event kinds used as read evidence, with the lanes they actually carry.
READ_KINDS = ("memory_read", "instr_response")
#: Slot verdicts; every slot has exactly one.
SLOT_VERDICTS = ("immutable", "violated", "insufficient_evidence")
#: Conflict identities, both about a *different* value.
CONFLICT_KINDS = ("later_materialization_different_value",
                  "later_read_different_value")
#: Why a slot carries no established value.  A record that cannot even state
#: which byte it wrote is not one of these: such an event is listed by id in
#: ``malformed_event_ids`` and never materializes anything.
INSUFFICIENT_REASONS = ("read_before_materialization",
                        "no_materialization_event",
                        "store_without_commit_receipt",
                        "store_not_committed",
                        "store_commit_disagrees_with_write")
#: Per-run conclusions and their command-line exit codes.
RUN_CONCLUSIONS = ("immutable", "violated", "insufficient_evidence")
EXIT_CODES = {"immutable": 0, "violated": 1, "insufficient_evidence": 2}
ARGUMENT_ERROR_EXIT_CODE = 3
EVENTS_FILE_NAME = "online_events.jsonl"
MANIFEST_FILE_NAME = "decoder_manifest.json"
RESERVATION_REGION_ID = "declared.online_instruction_reservation"
DEFAULT_MEMORY_ID = "ram"
_HAS_COMMIT = "complete"
_EFFECTING_COMMIT = "performed_effect"


class SlotImmutabilityError(ValueError):
    """The evidence scope itself cannot be established, so nothing is claimed."""


def _event_id(event: Mapping) -> int:
    value = event.get("event_id")
    if type(value) is not int:
        raise SlotImmutabilityError("every event needs an integer event_id")
    return value


def load_events(path: str | Path) -> tuple[dict, ...]:
    """Read one JSONL trace in event order; a malformed line fails closed."""
    events = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise SlotImmutabilityError(
                    f"{path}: line {number} is not JSON") from error
            if not isinstance(event, dict):
                raise SlotImmutabilityError(
                    f"{path}: line {number} is not a JSON object")
            _event_id(event)
            events.append(event)
    return tuple(events)


def program_range_from_run(directory: str | Path) -> tuple[tuple[int, int], str]:
    """Read the declared program reservation of one run directory.

    The range is a declaration of the run, so it is required: without it a
    checker cannot tell a program byte from a data byte and must refuse instead
    of guessing.
    """
    manifest_path = Path(directory) / MANIFEST_FILE_NAME
    if not manifest_path.is_file():
        raise SlotImmutabilityError(
            f"{directory} has no {MANIFEST_FILE_NAME} to declare the program range")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SlotImmutabilityError(f"{manifest_path} is not JSON") from error
    start = manifest.get("instruction_start")
    end = manifest.get("instruction_end")
    if (type(start) is not int or type(end) is not int or start < 0
            or end <= start):
        raise SlotImmutabilityError(
            f"{manifest_path} declares no usable instruction reservation")
    return (start, end), f"{MANIFEST_FILE_NAME}:instruction_start..instruction_end"


def _observed_case_id(event: Mapping) -> str | None:
    provenance = event.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    observed = provenance.get("observed_case")
    if not isinstance(observed, Mapping):
        return None
    case_id = observed.get("case_id")
    return case_id if isinstance(case_id, str) and case_id else None


def _hex_bytes(event: Mapping, kind: str) -> bytes:
    data_hex = event.get("data_hex")
    if not isinstance(data_hex, str):
        raise SlotImmutabilityError(f"{kind} record has no data_hex")
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as error:
        raise SlotImmutabilityError(f"{kind} data_hex is not hex") from error
    if not data:
        raise SlotImmutabilityError(f"{kind} record carries no bytes")
    return data


def _lane_bytes(value: int, width: int, enable: int) -> dict[int, int]:
    """Bytes one write actually determined, keyed by lane offset."""
    return {lane: (value >> (8 * lane)) & 0xFF for lane in range(width)
            if enable >> lane & 1}


def _commit_agrees(document: Mapping, write: Mapping,
                   written: Mapping[int, int]) -> bool:
    """Whether the per-byte commit receipt states exactly the written lanes."""
    cells = document.get("enabled_byte_cells")
    if not isinstance(cells, list) or not cells:
        return True
    byte_offset = document.get("byte_offset")
    if type(byte_offset) is not int:
        return False
    stated = {cell.get("byte_offset"): cell.get("value") for cell in cells
              if isinstance(cell, Mapping)}
    if set(stated) != {byte_offset + lane for lane in written}:
        return False
    return all(stated[byte_offset + lane] == value
               for lane, value in written.items())


def _read_bytes(event: Mapping) -> tuple[int, str, dict[int, int]]:
    """Return (address, kind, byte values) of one read event."""
    kind = str(event.get("kind"))
    if kind == "memory_read":
        address = event.get("address")
        if type(address) is not int:
            raise SlotImmutabilityError("memory_read record has no address")
        data = _hex_bytes(event, kind)
        return address, kind, dict(enumerate(data))
    address = event.get("aligned_address")
    if type(address) is not int:
        address = event.get("address")
    rdata, enable = event.get("rdata"), event.get("be")
    if type(address) is not int or type(rdata) is not int:
        raise SlotImmutabilityError("instr_response has no address/rdata")
    lanes = 0xF if type(enable) is not int else enable & 0xF
    return address, kind, _lane_bytes(rdata, 4, lanes)


@dataclass
class _Slot:
    """One program byte and every observed claim about its content."""

    memory_id: str
    address: int
    region_id: str
    value: int | None = None
    first_event_id: int | None = None
    first_kind: str | None = None
    first_case_id: str | None = None
    first_generation: int | None = None
    conflict_event_id: int | None = None
    conflict_kind: str | None = None
    conflict_value: int | None = None
    read_event_ids: list[int] = field(default_factory=list)
    reassertion_event_ids: list[int] = field(default_factory=list)
    early_read_event_id: int | None = None
    insufficient_reason: str | None = None

    def materialize(self, *, event_id: int, kind: str, value: int,
                    case_id: str | None, generation: int | None) -> None:
        if self.value is None:
            self.value = value
            self.first_event_id = event_id
            self.first_kind = kind
            self.first_case_id = case_id
            self.first_generation = generation
            return
        if value == self.value:
            self.reassertion_event_ids.append(event_id)
            return
        if self.conflict_event_id is None:
            self.conflict_event_id = event_id
            self.conflict_kind = "later_materialization_different_value"
            self.conflict_value = value

    def read(self, *, event_id: int, value: int) -> None:
        if self.value is None:
            # A read of a byte no materialization has determined yet: the byte
            # held a value this trace never explains, so its immutability is not
            # established.
            if self.early_read_event_id is None:
                self.early_read_event_id = event_id
            self.unmaterialized("read_before_materialization")
            return
        self.read_event_ids.append(event_id)
        if value != self.value and self.conflict_event_id is None:
            self.conflict_event_id = event_id
            self.conflict_kind = "later_read_different_value"
            self.conflict_value = value

    def unmaterialized(self, reason: str) -> None:
        if reason not in INSUFFICIENT_REASONS:
            raise SlotImmutabilityError(f"unknown insufficient reason {reason!r}")
        if self.insufficient_reason is None:
            self.insufficient_reason = reason

    @property
    def reason(self) -> str:
        if self.conflict_event_id is not None:
            return str(self.conflict_kind)
        if self.value is None:
            return self.insufficient_reason or "no_materialization_event"
        return self.insufficient_reason or "first_materialization_uncontradicted"

    @property
    def verdict(self) -> str:
        if self.conflict_event_id is not None:
            return "violated"
        if self.value is None or self.insufficient_reason is not None:
            return "insufficient_evidence"
        return "immutable"

    def document(self) -> dict:
        return {"memory_id": self.memory_id, "address": self.address,
                "region_id": self.region_id, "verdict": self.verdict,
                "reason": self.reason,
                "first_materialization_event_id": self.first_event_id,
                "first_materialization_kind": self.first_kind,
                "first_materialization_case_id": self.first_case_id,
                "first_materialization_generation": self.first_generation,
                "materialized_value": self.value,
                "conflicting_event_id": self.conflict_event_id,
                "conflict_kind": self.conflict_kind,
                "conflicting_value": self.conflict_value,
                "read_event_ids": list(self.read_event_ids),
                "reassertion_event_ids": list(self.reassertion_event_ids),
                "early_read_event_id": self.early_read_event_id}


@dataclass(frozen=True)
class ProgramRegion:
    """One declared byte range holding program bytes."""

    region_id: str
    memory_id: str
    start: int
    end: int
    source: str

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def document(self, slots: int) -> dict:
        return {"region_id": self.region_id, "memory_id": self.memory_id,
                "start": self.start, "end": self.end, "source": self.source,
                "bytes": self.end - self.start, "slots": slots}


def _memory_bases(events: Sequence[Mapping]) -> dict[str, int]:
    """Derive each memory's base address from events carrying both fields.

    The trace, not an outside assumption, states the mapping between a byte
    offset and an address; contradictory traces are refused.
    """
    bases: dict[str, int] = {}
    for event in events:
        memory_id, address, offset = (event.get("memory_id"),
                                     event.get("address"),
                                     event.get("byte_offset"))
        if (type(address) is not int or type(offset) is not int
                or not isinstance(memory_id, str)):
            continue
        base = address - offset
        previous = bases.setdefault(memory_id, base)
        if previous != base:
            raise SlotImmutabilityError(
                f"memory {memory_id!r} reports inconsistent base addresses "
                f"{previous} and {base}")
    return bases


def declared_regions(events: Sequence[Mapping],
                     program_range: tuple[int, int],
                     range_source: str) -> tuple[ProgramRegion, ...]:
    """The declared program regions: the reservation plus declared images."""
    regions = [ProgramRegion(RESERVATION_REGION_ID, DEFAULT_MEMORY_ID,
                             program_range[0], program_range[1], range_source)]
    seen: set[tuple[str, int, int]] = set()
    for event in events:
        if event.get("kind") != "initial_image":
            continue
        try:
            data = _hex_bytes(event, "initial_image")
        except SlotImmutabilityError:
            continue
        address, image_id = event.get("address"), event.get("image_id")
        if type(address) is not int or not isinstance(image_id, str) or not image_id:
            continue
        key = (image_id, address, len(data))
        if key in seen:
            continue
        seen.add(key)
        regions.append(ProgramRegion(f"initial_image:{image_id}",
                                     DEFAULT_MEMORY_ID, address,
                                     address + len(data),
                                     f"{EVENTS_FILE_NAME}:initial_image:{image_id}"))
    return tuple(regions)


@dataclass(frozen=True)
class SlotImmutabilityReport:
    """One run's slot verdicts, its declared scope and its conclusion."""

    program_range: tuple[int, int]
    range_source: str
    event_count: int
    slots: tuple[_Slot, ...]
    regions: tuple[ProgramRegion, ...]
    memory_bases: Mapping[str, int]
    materializations_by_kind: Mapping[str, int]
    reads_by_kind: Mapping[str, int]
    read_evidence_event_count: int
    ignored_event_kinds: Mapping[str, int]
    malformed_event_ids: tuple[int, ...]
    events_path: str | None = None
    run_directory: str | None = None

    # -- derived views -------------------------------------------------
    @property
    def counts(self) -> dict[str, int]:
        counts = {verdict: 0 for verdict in SLOT_VERDICTS}
        for slot in self.slots:
            counts[slot.verdict] += 1
        return counts

    @property
    def conflicts_by_kind(self) -> dict[str, int]:
        counts = {kind: 0 for kind in CONFLICT_KINDS}
        for slot in self.slots:
            if slot.conflict_kind is not None:
                counts[slot.conflict_kind] += 1
        return counts

    @property
    def insufficient_by_reason(self) -> dict[str, int]:
        reasons: dict[str, int] = {}
        for slot in self.slots:
            if slot.verdict == "insufficient_evidence":
                reasons[slot.reason] = reasons.get(slot.reason, 0) + 1
        return dict(sorted(reasons.items()))

    @property
    def reassertion_event_ids(self) -> tuple[int, ...]:
        return tuple(event_id for slot in self.slots
                     for event_id in slot.reassertion_event_ids)

    @property
    def violated_slots(self) -> tuple[_Slot, ...]:
        return tuple(slot for slot in self.slots if slot.verdict == "violated")

    @property
    def run_conclusion(self) -> str:
        counts = self.counts
        if counts["violated"]:
            return "violated"
        if counts["insufficient_evidence"] or not self.slots:
            return "insufficient_evidence"
        return "immutable"

    @property
    def unobserved_program_bytes(self) -> int:
        declared = {(region.memory_id, address)
                    for region in self.regions
                    for address in range(region.start, region.end)}
        observed = {(slot.memory_id, slot.address) for slot in self.slots}
        return len(declared - observed)

    def region_slot_counts(self) -> dict[str, int]:
        counts = {region.region_id: 0 for region in self.regions}
        for slot in self.slots:
            counts[slot.region_id] = counts.get(slot.region_id, 0) + 1
        return counts

    @property
    def conclusion_reason(self) -> str:
        counts = self.counts
        if not self.slots:
            return ("no materialization or read event touches a declared "
                    "program region, so no slot can be judged")
        if counts["violated"]:
            return (f"{counts['violated']} program byte(s) were later given or "
                    "read back a different value")
        if counts["insufficient_evidence"]:
            return (f"{counts['insufficient_evidence']} program byte(s) lack "
                    "materialization evidence and are not claimed immutable")
        return (f"{counts['immutable']} materialized program byte(s) were never "
                "given or read back a different value in this run")

    def summary(self) -> dict:
        return {
            "slot_count": len(self.slots),
            "immutable": self.counts["immutable"],
            "violated": self.counts["violated"],
            "insufficient_evidence": self.counts["insufficient_evidence"],
            "materializations_by_kind": dict(sorted(
                self.materializations_by_kind.items())),
            "reads_by_kind": dict(sorted(self.reads_by_kind.items())),
            "read_evidence_event_count": self.read_evidence_event_count,
            "conflicts_by_kind": self.conflicts_by_kind,
            "insufficient_by_reason": self.insufficient_by_reason,
            "reassertion_count": len(self.reassertion_event_ids),
            "reassertion_event_ids": list(self.reassertion_event_ids),
            "malformed_event_ids": list(self.malformed_event_ids),
            "ignored_event_kinds": dict(sorted(self.ignored_event_kinds.items())),
            "memory_bases": dict(sorted(self.memory_bases.items())),
            "region_slots": self.region_slot_counts(),
        }

    def document(self, *, include_slots: bool = True) -> dict:
        counts = self.region_slot_counts()
        document = {
            "schema_version": SLOT_IMMUTABILITY_SCHEMA_VERSION,
            "run_directory": self.run_directory,
            "events_path": self.events_path,
            "event_count": self.event_count,
            "program_range": {"start": self.program_range[0],
                              "end": self.program_range[1],
                              "source": self.range_source},
            "program_regions": [region.document(counts.get(region.region_id, 0))
                                for region in self.regions],
            "slot_universe": ("bytes of the declared program regions with at "
                              "least one observed materialization or read event"),
            "proof_scope": {
                "covers": "the online event trace of this run only",
                "rtl_executed_by_checker": False,
                "unobserved_program_bytes": self.unobserved_program_bytes,
                "materialization_kinds": list(MATERIALIZATION_KINDS),
                "read_kinds": list(READ_KINDS),
                "store_requires_complete_commit_receipt": True,
                "not_in_scope": ("data memory outside the declared program "
                                 "regions, and every byte of a region no event "
                                 "touches"),
            },
            "summary": self.summary(),
            "run_conclusion": self.run_conclusion,
            "conclusion_reason": self.conclusion_reason,
        }
        if include_slots:
            document["slots"] = {
                f"{slot.memory_id}@{slot.address}": slot.document()
                for slot in self.slots}
        return document

    def gate_line(self) -> str:
        summary = self.summary()
        target = self.run_directory or self.events_path or "<events>"
        return (f"{SLOT_IMMUTABILITY_SCHEMA_VERSION} {target}: "
                f"conclusion={self.run_conclusion} slots={summary['slot_count']} "
                f"immutable={summary['immutable']} "
                f"violated={summary['violated']} "
                f"insufficient_evidence={summary['insufficient_evidence']} "
                f"reads={summary['read_evidence_event_count']} "
                f"(scope: this run only; "
                f"{self.unobserved_program_bytes} untouched declared program "
                "byte(s) are outside the slot universe)")


def analyze_events(events: Iterable[Mapping], *,
                   program_range: tuple[int, int],
                   range_source: str = "declared by the caller",
                   include_initial_images: bool = True,
                   events_path: str | None = None,
                   run_directory: str | None = None) -> SlotImmutabilityReport:
    """Judge every declared program slot of one event trace, read-only."""
    start, end = program_range
    if (type(start) is not int or type(end) is not int or start < 0 or end <= start):
        raise SlotImmutabilityError("a declared program range is required")
    ordered = sorted(events, key=_event_id)
    bases = _memory_bases(ordered)
    regions = declared_regions(ordered, program_range, range_source)
    if not include_initial_images:
        regions = regions[:1]
    commits: dict[tuple, Mapping] = {}
    for event in ordered:
        if event.get("kind") == "memory_write_commit":
            document = event.get("commit_document")
            if isinstance(document, Mapping):
                commits[(event.get("producer_event_id"),
                         document.get("byte_offset"))] = document
    slots: dict[tuple[str, int], _Slot] = {}
    materializations: dict[str, int] = {}
    reads: dict[str, int] = {}
    ignored: dict[str, int] = {}
    read_event_count = 0
    malformed: list[int] = []

    def region_of(memory_id: str, address: int) -> ProgramRegion | None:
        for region in regions:
            if region.memory_id == memory_id and region.contains(address):
                return region
        return None

    def slot_for(memory_id: str, address: int) -> _Slot | None:
        region = region_of(memory_id, address)
        if region is None:
            return None
        return slots.setdefault((memory_id, address),
                                _Slot(memory_id=memory_id, address=address,
                                      region_id=region.region_id))

    for event in ordered:
        kind = str(event.get("kind"))
        event_id = _event_id(event)
        if kind == "memory_initialization":
            memory_id = str(event.get("memory_id", DEFAULT_MEMORY_ID))
            offset, value = event.get("byte_offset"), event.get("value")
            base = bases.get(memory_id)
            if (base is None or type(offset) is not int or type(value) is not int
                    or not 0 <= value <= 0xFF):
                malformed.append(event_id)
                continue
            slot = slot_for(memory_id, base + offset)
            if slot is not None:
                materializations[kind] = materializations.get(kind, 0) + 1
                slot.materialize(event_id=event_id, kind=kind, value=value,
                                 case_id=None, generation=event.get("generation"))
            continue
        if kind == "memory_write":
            memory_id = str(event.get("memory_id", DEFAULT_MEMORY_ID))
            address, value = event.get("address"), event.get("value")
            width, enable = event.get("width_bytes"), event.get("byte_enable")
            if (type(address) is not int or type(value) is not int
                    or type(width) is not int or not 0 < width <= 32
                    or type(enable) is not int):
                malformed.append(event_id)
                continue
            document = commits.get((event.get("producer_event_id"),
                                    event.get("byte_offset")))
            if document is None:
                reason, performed = "store_without_commit_receipt", False
            elif (document.get("commit_status") != _HAS_COMMIT
                  or document.get(_EFFECTING_COMMIT) is not True):
                reason, performed = "store_not_committed", False
            else:
                reason, performed = None, True
            written = _lane_bytes(value, width, enable)
            if performed and not _commit_agrees(document, event, written):
                # The per-byte receipt is the stronger evidence: when it states
                # different bytes than the write event, the store's effect on
                # these lanes is not established.
                reason, performed = "store_commit_disagrees_with_write", False
            counted = False
            for lane, lane_value in written.items():
                slot = slot_for(memory_id, address + lane)
                if slot is None:
                    continue
                if performed:
                    if not counted:
                        materializations["memory_write"] = (
                            materializations.get("memory_write", 0) + 1)
                        counted = True
                    slot.materialize(event_id=event_id, kind="memory_write",
                                     value=lane_value,
                                     case_id=_observed_case_id(event),
                                     generation=event.get("generation"))
                else:
                    # The lane was written but no complete receipt evidences the
                    # effect, so the byte stays unjudged.
                    slot.unmaterialized(str(reason))
            continue
        if kind in ("instruction_source", "initial_image"):
            memory_id = str(event.get("memory_id", DEFAULT_MEMORY_ID))
            address = event.get("address")
            try:
                data = _hex_bytes(event, kind)
            except SlotImmutabilityError:
                malformed.append(event_id)
                continue
            if type(address) is not int:
                malformed.append(event_id)
                continue
            counted = False
            for offset, value in enumerate(data):
                slot = slot_for(memory_id, address + offset)
                if slot is None:
                    continue
                if not counted:
                    materializations[kind] = materializations.get(kind, 0) + 1
                    counted = True
                slot.materialize(event_id=event_id, kind=kind, value=value,
                                 case_id=_observed_case_id(event),
                                 generation=event.get("generation"))
            continue
        if kind in READ_KINDS:
            if kind == "instr_response" and (event.get("write")
                                             or event.get("error")):
                # A write response or an errored response carries no read value.
                ignored[kind] = ignored.get(kind, 0) + 1
                continue
            memory_id = str(event.get("memory_id", DEFAULT_MEMORY_ID))
            try:
                address, kind, values = _read_bytes(event)
            except SlotImmutabilityError:
                malformed.append(event_id)
                continue
            read_event_count += 1
            reads[kind] = reads.get(kind, 0) + 1
            for offset, value in values.items():
                slot = slot_for(memory_id, address + offset)
                if slot is not None:
                    slot.read(event_id=event_id, value=value)
            continue
        ignored[kind] = ignored.get(kind, 0) + 1
    for slot in slots.values():
        if slot.value is None and slot.insufficient_reason is None:
            slot.unmaterialized("no_materialization_event")
    return SlotImmutabilityReport(
        program_range=(start, end), range_source=range_source,
        event_count=len(ordered),
        slots=tuple(sorted(slots.values(),
                           key=lambda item: (item.memory_id, item.address))),
        regions=regions, memory_bases=bases,
        materializations_by_kind=materializations, reads_by_kind=reads,
        read_evidence_event_count=read_event_count,
        ignored_event_kinds=ignored, malformed_event_ids=tuple(malformed),
        events_path=events_path, run_directory=run_directory)


def report_for_run(directory: str | Path, *,
                   events_file: str = EVENTS_FILE_NAME,
                   program_range: tuple[int, int] | None = None,
                   include_initial_images: bool = True
                   ) -> SlotImmutabilityReport:
    """Build the report of one saved run directory, read-only."""
    directory = Path(directory)
    if program_range is None:
        program_range, range_source = program_range_from_run(directory)
    else:
        range_source = "caller declaration"
    path = directory / events_file
    if not path.is_file():
        raise SlotImmutabilityError(f"{directory} has no {events_file}")
    return analyze_events(load_events(path), program_range=program_range,
                          range_source=range_source,
                          include_initial_images=include_initial_images,
                          events_path=str(path),
                          run_directory=str(directory))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m myfuzz.scenario.slot_immutability",
        description=("Read-only slot immutability gate over saved online traces: "
                     "did a later case submit or read back a different value for "
                     "a program byte an earlier case materialized?"))
    parser.add_argument("runs", nargs="+",
                        help="saved run directories holding an online trace")
    parser.add_argument("--events", default=EVENTS_FILE_NAME,
                        help=f"trace file name inside each run (default {EVENTS_FILE_NAME})")
    parser.add_argument("--json-out", default=None,
                        help="write the full slot_immutability_report.v1 JSON here")
    parser.add_argument("--no-slots", action="store_true",
                        help="omit the per-slot table from the JSON report")
    parser.add_argument("--reservation-only", action="store_true",
                        help="judge only the declared online reservation, not "
                             "declared initial images")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    reports = []
    for directory in arguments.runs:
        try:
            report = report_for_run(
                directory, events_file=arguments.events,
                include_initial_images=not arguments.reservation_only)
        except (SlotImmutabilityError, OSError) as error:
            print(f"slot_immutability: {directory}: {error}", file=sys.stderr)
            return ARGUMENT_ERROR_EXIT_CODE
        reports.append(report)
        print(report.gate_line())
        for slot in report.violated_slots:
            print(f"  violated {slot.memory_id}@{slot.address}: "
                  f"{slot.conflict_kind} at event {slot.conflict_event_id} "
                  f"(first materialization {slot.first_event_id}, value "
                  f"{slot.value}, conflicting value {slot.conflict_value})")
    # Severity order, not numeric order: one violated run outranks every
    # unevidenced run, and an unevidenced run never reads as a pass.
    conclusions = {report.run_conclusion for report in reports}
    exit_code = next(EXIT_CODES[conclusion] for conclusion in RUN_CONCLUSIONS
                     if conclusion in conclusions)
    if arguments.json_out:
        include_slots = not arguments.no_slots
        document = ([report.document(include_slots=include_slots)
                     for report in reports] if len(reports) > 1
                    else reports[0].document(include_slots=include_slots))
        Path(arguments.json_out).write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8")
    return exit_code


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
