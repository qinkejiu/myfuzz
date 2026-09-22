"""Turn raw instruction candidates into the memory image a composed SoC boots.

Step 6B of the assurance plan: the reference layer in
:mod:`myfuzz.composition.soc_instruction_stimulus` already knows how to consume
raw instruction fields, repair them to legal encodings for the declared ISA,
keep bytes consistent per address and report counters.  What was missing was a
production path: nothing called it, so the instruction raw segment was dead ABI.

This module closes that gap for the profile-driven flow:

* it appends one bounded ``instruction`` segment to the composition's raw layout
  (offer, address, data, byte enable) and records its identity;
* it materialises those candidates into a byte image with the reference layer,
  so the ISA repair, the alignment and window checks and the drop counters are
  the ones already tested;
* it proves the entry address is inside a declared executable region *before*
  any byte is written, and refuses an image that would land outside it;
* it declares the freeze point and states, explicitly, which lifecycle event
  restores what: ``test_begin`` re-materialises the frozen image, a DUT reset
  re-writes memory from the image the RTL already holds, and a driver reset does
  not touch memory at all.

Unmapped raw fields are reported rather than silently ignored, and the
environment never rewrites a byte after the freeze point.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .input_layout import InputLayout, LayoutField
from .soc_composition import CompositionPlan
from .soc_instruction_stimulus import (
    CpuInstructionCapabilities,
    SocInstructionStimulus,
    SocInstructionStimulusError,
)

IMAGE_SCHEMA = "soc_image.v1"
INSTRUCTION_FIELDS = ("init_offer", "init_address", "init_data", "init_be")
INSTRUCTION_WIDTHS = {"init_offer": 1, "init_address": 32, "init_data": 32, "init_be": 4}
INSTRUCTION_BITS = sum(INSTRUCTION_WIDTHS.values())
DATA_FIELDS = ("data_offer", "data_address", "data_value", "data_be")
DATA_WIDTHS = {"data_offer": 1, "data_address": 32, "data_value": 32, "data_be": 4}
DATA_BITS = sum(DATA_WIDTHS.values())
#: The maximum number of instruction candidates one sample may carry; the image
#: build is bounded so an oversized corpus fails instead of growing forever.
MAX_INSTRUCTION_CANDIDATES = 4096
#: A byte image is written to a hex file for `$readmemh`; bound its size.
MAX_IMAGE_BYTES = 1 << 20
#: How many candidate *slots* one image plan may declare per kind.  A slot is one
#: independently fuzzable (offer, address, data, byte-enable) block; the legacy
#: single-candidate layout is one slot per kind and names its segments
#: ``init_*`` / ``data_*``.  The bound is declared here so an oversized request
#: fails by name instead of building an astronomically wide raw layout, and it
#: is large enough for a declared program to exceed a 4 KiB branch range (1025
#: four-byte slots), which is the bound the target encoder checks.
MAX_CANDIDATE_SLOTS = 2048
#: The declared raw segment roles of one candidate slot, in bit order.  The
#: fourth instruction role is the instruction word (``data``); the fourth data
#: role is the data word (``value``), exactly as the legacy names say.
INSTRUCTION_ROLES = ("offer", "address", "data", "be")
DATA_ROLES = ("offer", "address", "value", "be")
_ROLE_WIDTHS = {("instruction", "offer"): 1, ("instruction", "address"): 32,
                ("instruction", "data"): 32, ("instruction", "be"): 4,
                ("data", "offer"): 1, ("data", "address"): 32,
                ("data", "value"): 32, ("data", "be"): 4}
#: How a test selects and uses the declared slots.  Recorded verbatim in the
#: plan document so the fuzz-side contract is stated, not implied.
CANDIDATE_SELECTION = (
    "one raw word per test cycle; a slot's offer bit selects that slot for this "
    "test; each slot may be offered by at most one word of one test; every "
    "offered slot is written into the memory model's initial_memory while the "
    "CPU is held in reset, so all offered candidates are frozen before release"
)
CANDIDATE_SCHEMA = "soc_image_candidates.v1"


def candidate_prefix(kind: str, index: int) -> str:
    """The declared segment prefix of one candidate slot.

    Slot 0 of each kind keeps the historical ``init`` / ``data`` prefix, so a
    one-slot plan is bit-for-bit the layout that existed before slots did.
    """
    base = "init" if kind == "instruction" else "data"
    return base if index == 0 else f"{base}{index}"


class SocImageError(ValueError):
    """The declared image cannot be materialised safely."""


def _error(reason: str) -> None:
    raise SocImageError(reason)


@dataclass(frozen=True, slots=True)
class ImageSegment:
    """One raw segment of the image plan."""

    name: str
    raw_lo: int
    raw_hi: int
    width: int

    def extract(self, raw_value: int) -> int:
        return (int(raw_value) >> self.raw_lo) & ((1 << self.width) - 1)

    def document(self) -> dict[str, object]:
        return {"name": self.name, "raw_lo": self.raw_lo, "raw_hi": self.raw_hi,
                "width": self.width}


@dataclass(frozen=True, slots=True)
class CandidateSlot:
    """One declared, independently fuzzable candidate slot of the image plan.

    The slot owns four raw segments (offer, address, word, byte enable), the
    address the composer places it at, and the declared region that address is
    inside.  The declared address is what the address policy projects a fuzzer's
    raw address onto (``repair``) or requires it to equal (``strict``); it is
    recorded in the plan document so the placement is declared, not inferred.
    """

    kind: str
    index: int
    prefix: str
    segments: tuple[ImageSegment, ...]
    declared_address: int
    alignment: int
    region_id: str
    region_base: int
    region_size: int

    def __post_init__(self) -> None:
        roles = INSTRUCTION_ROLES if self.kind == "instruction" else DATA_ROLES
        if self.kind not in ("instruction", "data") or self.index < 0:
            _error(f"candidate-slot-invalid:{self.kind}:{self.index}")
        if self.prefix != candidate_prefix(self.kind, self.index):
            _error(f"candidate-slot-prefix-mismatch:{self.prefix}")
        expected = tuple(f"{self.prefix}_{role}" for role in roles)
        if tuple(item.name for item in self.segments) != expected:
            _error(f"candidate-slot-segments-mismatch:{self.prefix}")
        if self.alignment <= 0 or self.declared_address % self.alignment:
            _error(f"candidate-slot-misaligned:{self.prefix}:0x{self.declared_address:x}")

    @property
    def name(self) -> str:
        return self.prefix

    def segment(self, role: str) -> ImageSegment:
        for item in self.segments:
            if item.name == f"{self.prefix}_{role}":
                return item
        raise SocImageError(f"unknown-candidate-segment:{self.prefix}:{role}")

    def document(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "index": self.index,
            "prefix": self.prefix,
            "declared_address": self.declared_address,
            "declared_address_hex": f"0x{self.declared_address:08x}",
            "alignment": self.alignment,
            "region_id": self.region_id,
            "region_base": self.region_base,
            "region_size": self.region_size,
            "segments": [item.document() for item in self.segments],
        }


@dataclass(frozen=True, slots=True)
class CandidateLayout:
    """The declared candidate slots of one image plan, per kind, in order."""

    instruction: tuple[CandidateSlot, ...] = ()
    data: tuple[CandidateSlot, ...] = ()

    @property
    def instruction_count(self) -> int:
        return len(self.instruction)

    @property
    def data_count(self) -> int:
        return len(self.data)

    def slots(self, kind: str | None = None) -> tuple[CandidateSlot, ...]:
        if kind is None:
            return self.instruction + self.data
        if kind == "instruction":
            return self.instruction
        if kind == "data":
            return self.data
        raise SocImageError(f"unknown-candidate-kind:{kind}")

    def slot(self, prefix: str) -> CandidateSlot:
        for item in self.slots():
            if item.prefix == prefix:
                return item
        raise SocImageError(f"unknown-candidate-slot:{prefix}")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": CANDIDATE_SCHEMA,
            "instruction_count": self.instruction_count,
            "data_count": self.data_count,
            "selection": CANDIDATE_SELECTION,
            "instruction": [item.document() for item in self.instruction],
            "data": [item.document() for item in self.data],
        }


@dataclass(frozen=True, slots=True)
class ImagePlan:
    """How a sample's raw instruction candidates become a boot image."""

    region_id: str
    base: int
    size: int
    entry_address: int
    segments: tuple[ImageSegment, ...]
    instruction_raw_lo: int
    data_region_id: str
    data_base: int
    data_size: int
    capabilities: CpuInstructionCapabilities
    isa_repair: bool
    freeze_policy: str
    lifecycle: Mapping[str, str]
    plan_hash: str
    layout_hash: str
    image_hash: str = ""
    candidates: CandidateLayout = field(default_factory=CandidateLayout)
    program: Mapping[str, object] | None = None
    diagnostics: tuple[str, ...] = ()
    _stimulus_factory: object = field(default=None, repr=False, compare=False)


    @property
    def raw_width(self) -> int:
        return max((item.raw_hi for item in self.segments), default=-1) + 1

    def segment(self, name: str) -> ImageSegment:
        for item in self.segments:
            if item.name == name:
                return item
        raise SocImageError(f"unknown-image-segment:{name}")

    def materialize(self, raw_value: int, *,
                    directed: Mapping[int, bytes] | None = None) -> "ImageResult":
        """Build the byte image for one candidate word."""
        return self.materialize_many((raw_value,), directed=directed)

    def materialize_many(self, raw_values: Sequence[int], *,
                         directed: Mapping[int, bytes] | None = None) -> "ImageResult":
        """Build one frozen code/data state from all candidate words of a test.

        RFuzz transports a sequence of raw words per test.  Buffering that
        sequence before reset lets the environment establish the complete
        initial state without recompiling RTL and without rewriting memory
        after the CPU has started.  Every declared candidate slot is extracted
        from every word; a slot whose offer bit is clear in every word of the
        test simply contributes nothing.
        """
        if (not isinstance(raw_values, Sequence) or isinstance(raw_values, (str, bytes))
                or not raw_values or len(raw_values) > MAX_INSTRUCTION_CANDIDATES):
            _error("invalid-raw-sample-sequence")
        for raw_value in raw_values:
            if isinstance(raw_value, bool) or not isinstance(raw_value, int) or raw_value < 0:
                _error("invalid-raw-sample")
            if raw_value >> self.raw_width:
                _error("raw-sample-exceeds-image-segment")
        stimulus = self._new_stimulus()
        if directed:
            stimulus.preload_directed(dict(directed), kind="boot")
        counters_before = dict(stimulus.counters)
        candidates: list[dict[str, int]] = []
        accepted = 0
        dropped: list[str] = []
        placed: list[dict[str, object]] = []
        data_bytes: dict[int, int] = {}
        data_records: list[dict[str, object]] = []
        # Two declared slots may not resolve to the same instruction word: the
        # plan declares one placement per slot, and a test that offers two
        # slots at one word would make the later overlay silently win.  That is
        # a refused layout violation, never a quiet overwrite.
        beats: dict[int, str] = {}
        for raw_value in raw_values:
            for slot in self.candidates.instruction:
                if not slot.segment("offer").extract(raw_value):
                    continue
                candidate = {
                    "init_offer": 1,
                    "init_address": slot.segment("address").extract(raw_value),
                    "init_data": slot.segment("data").extract(raw_value),
                    "init_be": slot.segment("be").extract(raw_value),
                }
                beat = candidate["init_address"] & ~0x3
                if candidate["init_be"] and beat in beats:
                    _error(f"candidate-slot-address-conflict:{beats[beat]}:"
                           f"{slot.prefix}:0x{beat:x}")
                if candidate["init_be"]:
                    beats[beat] = slot.prefix
                try:
                    outcome = stimulus.accept(candidate)
                except SocInstructionStimulusError as error:
                    raise SocImageError(f"instruction-candidate-rejected:{error}") from error
                ok = bool(outcome.get("accepted"))
                if ok:
                    accepted += 1
                else:
                    dropped.append(str(outcome.get("reason", "unknown")))
                candidates.append(candidate)
                placed.append({
                    "kind": "instruction", "slot": slot.prefix, "index": slot.index,
                    "declared_address": slot.declared_address,
                    "address": candidate["init_address"],
                    "byte_enable": candidate["init_be"], "accepted": ok,
                    "reason": "" if ok else str(outcome.get("reason", "unknown")),
                })
            for slot in self.candidates.data:
                if not slot.segment("offer").extract(raw_value):
                    continue
                address_value = slot.segment("address").extract(raw_value)
                value = slot.segment("value").extract(raw_value)
                enables = slot.segment("be").extract(raw_value)
                enabled = [index for index in range(4) if enables & (1 << index)]
                if not enabled:
                    dropped.append("data-byte-enable-empty")
                    placed.append({
                        "kind": "data", "slot": slot.prefix, "index": slot.index,
                        "declared_address": slot.declared_address,
                        "address": address_value, "byte_enable": enables,
                        "accepted": False, "reason": "data-byte-enable-empty",
                    })
                    continue
                if any(not self.data_base <= address_value + index
                       < self.data_base + self.data_size for index in enabled):
                    _error(f"data-address-unmapped:0x{address_value:x}")
                for index in enabled:
                    absolute = address_value + index
                    byte = (value >> (8 * index)) & 0xFF
                    previous = data_bytes.get(absolute)
                    if previous is not None and previous != byte:
                        _error(f"data-initialization-conflict:0x{absolute:x}")
                    data_bytes[absolute] = byte
                data_records.append({"slot": slot.prefix, "index": slot.index,
                                     "address": address_value, "value": value,
                                     "byte_enable": enables})
                placed.append({
                    "kind": "data", "slot": slot.prefix, "index": slot.index,
                    "declared_address": slot.declared_address,
                    "address": address_value, "byte_enable": enables,
                    "accepted": True, "reason": "",
                })
                accepted += 1
        committed = stimulus.flush()
        image_base, image_bytes = stimulus.byte_image()
        if image_bytes and not (self.base <= image_base
                                < self.base + self.size):
            _error(f"image-outside-region:0x{image_base:x}")
        if image_bytes and image_base + len(image_bytes) > self.base + self.size:
            _error(f"image-exceeds-region:{image_base + len(image_bytes):x}")
        # The memory model loads from the region base, so the artifact is the
        # region-anchored image with the leading gap materialised as zeroes.
        pad = image_base - self.base if image_bytes else 0
        image = bytes(pad) + image_bytes
        if len(image) > MAX_IMAGE_BYTES:
            _error(f"image-exceeds-bound:{len(image)}>{MAX_IMAGE_BYTES}")
        counters = dict(stimulus.counters)
        delta = {name: counters[name] - counters_before.get(name, 0)
                 for name in sorted(counters)}
        delta["data_initializations"] = len(data_records)
        data_image = bytearray()
        if data_bytes:
            last = max(data_bytes) - self.data_base
            if last + 1 > MAX_IMAGE_BYTES:
                _error(f"data-image-exceeds-bound:{last + 1}>{MAX_IMAGE_BYTES}")
            data_image = bytearray(last + 1)
            for absolute, byte in data_bytes.items():
                data_image[absolute - self.data_base] = byte
        if self.region_id == self.data_region_id:
            merged = bytearray(max(len(image), len(data_image)))
            merged[:len(image)] = image
            explicitly_initialized: set[int] = set()
            if directed:
                for start, payload in directed.items():
                    explicitly_initialized.update(range(int(start), int(start) + len(payload)))
            for record in stimulus.initialization_records:
                corrected = record.get("corrected_candidate") or {}
                start = int(corrected.get("address", -1))
                enables = int(corrected.get("be", 0))
                explicitly_initialized.update(
                    start + index for index in range(4) if enables & (1 << index))
            for absolute, byte in data_bytes.items():
                offset = absolute - self.base
                if absolute in explicitly_initialized and merged[offset] != byte:
                    _error(f"code-data-initialization-conflict:0x{absolute:x}")
                merged[offset] = byte
            region_images = {self.region_id: bytes(merged)}
        else:
            region_images = {self.region_id: image,
                             self.data_region_id: bytes(data_image)}
        return ImageResult(
            base=self.base, size=self.size, entry_address=self.entry_address,
            image=image, image_base=self.base, candidates=tuple(candidates), accepted=accepted,
            dropped=tuple(dropped), committed=committed, counters=delta,
            initialization_records=tuple(stimulus.initialization_records),
            data_initializations=tuple(data_records), region_images=region_images,
            content_hash="sha256:" + hashlib.sha256(image).hexdigest(),
            freeze_policy=self.freeze_policy, lifecycle=dict(self.lifecycle),
            slots=tuple(placed))

    def _new_stimulus(self) -> SocInstructionStimulus:
        factory = self._stimulus_factory
        if factory is None:
            _error("image-plan-without-stimulus-factory")
        return factory()  # type: ignore[operator]

    def write_hex(self, image: bytes, path: Path) -> Path:
        """Write the byte image as a `$readmemh` file, byte per line."""
        if not isinstance(image, bytes):
            _error("image-must-be-bytes")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{byte:02x}\n" for byte in image), encoding="utf-8")
        return target

    def document(self) -> dict[str, object]:
        return {
            "schema_version": IMAGE_SCHEMA,
            "region_id": self.region_id,
            "base": self.base,
            "size": self.size,
            "entry_address": self.entry_address,
            "segments": [item.document() for item in self.segments],
            "raw_width": self.raw_width,
            "instruction_raw_lo": self.instruction_raw_lo,
            "data_region": {"region_id": self.data_region_id, "base": self.data_base,
                            "size": self.data_size},
            "isa": {"xlen": self.capabilities.xlen,
                    "extensions": list(self.capabilities.extensions),
                    "privilege_modes": list(self.capabilities.privilege_modes),
                    "instruction_alignment": self.capabilities.instruction_alignment,
                    "provenance": self.capabilities.provenance},
            "isa_repair": self.isa_repair,
            "freeze_policy": self.freeze_policy,
            "lifecycle": dict(self.lifecycle),
            "candidates": self.candidates.document(),
            "program": dict(self.program) if self.program is not None else None,
            "plan_hash": self.plan_hash,
            "layout_hash": self.layout_hash,
            "image_hash": self.image_hash,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class ImageResult:
    base: int
    size: int
    entry_address: int
    image: bytes
    image_base: int
    candidates: tuple[Mapping[str, int], ...]
    accepted: int
    dropped: tuple[str, ...]
    committed: int
    counters: Mapping[str, int]
    initialization_records: tuple[Mapping[str, object], ...]
    data_initializations: tuple[Mapping[str, object], ...]
    region_images: Mapping[str, bytes]
    content_hash: str
    freeze_policy: str
    lifecycle: Mapping[str, str]
    #: One record per offered candidate slot: which slot, which address it was
    #: placed at, whether the reference layer accepted it and why not.
    slots: tuple[Mapping[str, object], ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "schema_version": IMAGE_SCHEMA,
            "base": self.base,
            "size": self.size,
            "entry_address": self.entry_address,
            "bytes": len(self.image),
            "image_base": self.image_base,
            "content_hash": self.content_hash,
            "accepted_candidates": self.accepted,
            "committed_beats": self.committed,
            "dropped": list(self.dropped),
            "counters": dict(sorted(self.counters.items())),
            "regions": {name: {"bytes": len(image),
                                "content_hash": "sha256:" + hashlib.sha256(image).hexdigest()}
                        for name, image in sorted(self.region_images.items())},
            "data_initializations": [dict(item) for item in self.data_initializations],
            "slots": [dict(item) for item in self.slots],
            "freeze_policy": self.freeze_policy,
            "lifecycle": dict(self.lifecycle),
        }


def _capabilities(plan: CompositionPlan) -> CpuInstructionCapabilities:
    cpu_instance = next((item for item in plan.instances if item.kind == "cpu"), None)
    if cpu_instance is None:
        _error("image-requires-a-cpu-instance")
    contract = cpu_instance.profile.cpu
    if contract is None:
        _error("image-requires-a-cpu-contract")
    if contract.family != "riscv":
        # The first phase only generates software for the RISC-V family, and a
        # profile that claims another family is a capability gap, not a boot
        # image this build can produce.
        _error(f"unsupported-isa-family:{contract.family}")
    alignment = 4
    parameters = {
        "reset_vector": int(contract.reset_vector),
        "boot_address_required": bool(contract.boot_address_required),
    }
    try:
        return CpuInstructionCapabilities(
            xlen=int(contract.xlen),
            extensions=tuple(str(item).upper() for item in contract.extensions),
            instruction_alignment=alignment,
            parameters=parameters,
            provenance=f"component_profile:{cpu_instance.component_id}",
        )
    except SocInstructionStimulusError as error:
        raise SocImageError(f"unsupported-cpu-execution:{error}") from error


def _stimulus_reserved_bits(plan: CompositionPlan) -> int:
    """Raw bits the compiled stimulus ABI reserves after the profile layout.

    The composition compiles one ``soc_stimulus.v1`` document whose raw layout
    spans the instruction, mmio and environment segments.  A synthetic master's
    request fields live inside that block at the document's own offsets, so the
    block is reserved as a whole and the image segments follow it.
    """
    if not plan.synthetic:
        return 0
    stimulus = plan.stimulus
    layout = stimulus.get("raw_layout") if isinstance(stimulus, Mapping) else None
    total = layout.get("total_bits") if isinstance(layout, Mapping) else None
    if not isinstance(total, int) or isinstance(total, bool) or total <= 0:
        _error("synthetic-master-without-compiled-stimulus-layout")
    return int(total)


def _executable_regions(plan: CompositionPlan) -> list[dict[str, object]]:
    regions = []
    for region in plan.plan["address_map"]["memory_regions"]:
        permissions = region.get("permissions") or {}
        if permissions.get("execute"):
            regions.append(dict(region))
    return regions


def _candidate_count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_CANDIDATE_SLOTS:
        _error(f"candidate-count-invalid:{label}:{value!r}")
    return int(value)


def _slot_address(slot_addresses: Mapping[str, int] | None, prefix: str, default: int,
                  *, alignment: int, region_base: int, region_size: int,
                  label: str) -> int:
    address = default if slot_addresses is None or prefix not in slot_addresses \
        else slot_addresses[prefix]
    if isinstance(address, bool) or not isinstance(address, int) or address < 0:
        _error(f"candidate-slot-address-invalid:{prefix}")
    if address % alignment:
        _error(f"candidate-slot-misaligned:{prefix}:0x{address:x}")
    if not region_base <= address or address + 4 > region_base + region_size:
        _error(f"candidate-slot-outside-region:{label}:{prefix}:0x{address:x}")
    return int(address)


def _candidate_layout(*, owner: Mapping[str, object],
                      data_owner: Mapping[str, object], entry: int,
                      capabilities: CpuInstructionCapabilities,
                      instruction_candidates: int, data_candidates: int,
                      slot_addresses: Mapping[str, int] | None,
                      cursor: int) -> tuple[list[ImageSegment], CandidateLayout, int]:
    """Declare every candidate slot and its raw segments.

    Every slot is placed at a declared address inside a declared region: slot 0
    at the declared entry (instructions) or the writable region base (data),
    slot k at a four-byte stride from there unless the caller declares explicit
    addresses.  A declaration that does not fit the region is refused by name,
    never clamped.
    """
    alignment = capabilities.instruction_alignment
    segments: list[ImageSegment] = []
    instruction_slots: list[CandidateSlot] = []
    data_slots: list[CandidateSlot] = []
    for kind, count, roles in (("instruction", instruction_candidates, INSTRUCTION_ROLES),
                               ("data", data_candidates, DATA_ROLES)):
        region = owner if kind == "instruction" else data_owner
        base = int(region["base"])
        size = int(region["size"])
        for index in range(count):
            prefix = candidate_prefix(kind, index)
            built: list[ImageSegment] = []
            for role in roles:
                width = _ROLE_WIDTHS[(kind, role)]
                built.append(ImageSegment(name=f"{prefix}_{role}", raw_lo=cursor,
                                          raw_hi=cursor + width - 1, width=width))
                cursor += width
            address = _slot_address(
                slot_addresses, prefix, entry + alignment * index if kind == "instruction"
                else base + alignment * index,
                alignment=alignment, region_base=base,
                region_size=size, label=f"{kind}-region")
            slot = CandidateSlot(kind=kind, index=index, prefix=prefix,
                                 segments=tuple(built), declared_address=address,
                                 alignment=alignment, region_id=str(region["region_id"]),
                                 region_base=base, region_size=size)
            segments.extend(built)
            (instruction_slots if kind == "instruction" else data_slots).append(slot)
    return segments, CandidateLayout(instruction=tuple(instruction_slots),
                                     data=tuple(data_slots)), cursor


def build_image_plan(plan: CompositionPlan, *, isa_repair: bool = True,
                     directed_seed: bytes | None = None,
                     instruction_candidates: int = 1, data_candidates: int = 1,
                     slot_addresses: Mapping[str, int] | None = None) -> ImagePlan:
    """Append the declared candidate segments and freeze the image contract.

    ``instruction_candidates`` / ``data_candidates`` declare how many
    independently fuzzable candidates one test may carry.  Both default to one,
    which is the historical single-candidate layout bit for bit; a larger count
    appends further (offer, address, word, byte enable) blocks at declared
    addresses and records them in the plan document.
    """
    if not isinstance(plan, CompositionPlan):
        _error("composition-plan-required")
    instruction_candidates = _candidate_count(instruction_candidates,
                                              "instruction_candidates")
    data_candidates = _candidate_count(data_candidates, "data_candidates")
    if slot_addresses is not None and not isinstance(slot_addresses, Mapping):
        _error("candidate-slot-addresses-invalid")
    capabilities = _capabilities(plan)
    regions = _executable_regions(plan)
    if not regions:
        _error("no-executable-region-declared")
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    contract = cpu_instance.profile.cpu
    assert contract is not None
    entry = int(contract.reset_vector)
    owner = next((region for region in regions
                  if int(region["base"]) <= entry < int(region["base"]) + int(region["size"])),
                 None)
    if owner is None:
        _error(f"entry-address-outside-executable-region:0x{entry:x}")
    if entry % capabilities.instruction_alignment:
        _error(f"entry-address-misaligned:0x{entry:x}")

    writable = [dict(region) for region in plan.plan["address_map"]["memory_regions"]
                if (region.get("permissions") or {}).get("write")]
    if not writable:
        _error("no-writable-data-region-declared")
    data_owner = min(writable, key=lambda item: (int(item["base"]), str(item["region_id"])))

    # The compiled stimulus document owns one contiguous raw block right after the
    # profile layout.  A composition with a synthetic master drives that master's
    # raw request fields from inside the block, so the image segments start after
    # it instead of overlapping the master's inputs.
    cursor = int(plan.raw_layout.get("raw_width", 0)) + _stimulus_reserved_bits(plan)
    instruction_raw_lo = cursor
    segments, candidates, cursor = _candidate_layout(
        owner=owner, data_owner=data_owner, entry=entry, capabilities=capabilities,
        instruction_candidates=instruction_candidates, data_candidates=data_candidates,
        slot_addresses=slot_addresses, cursor=cursor)

    def factory() -> SocInstructionStimulus:
        return SocInstructionStimulus(
            capabilities,
            instruction_windows=[(int(owner["base"]), int(owner["size"]))],
            isa_legal=isa_repair,
            mmio_reachability_bias=False)

    lifecycle = {
        "test_begin": "re-materialise the frozen image and reload it into the memory model",
        "dut_reset": "the memory model re-writes its array from the image it already holds; "
                     "the environment does not resupply bytes",
        "driver_reset": "driver state is cleared; memory is not touched",
        "after_freeze": "no byte may be rewritten by the environment",
    }
    diagnostics = [
        "unmapped raw fields are reported in the sample diagnostic, never silently zeroed",
        "the image is frozen before the CPU is released; a store by the CPU is not an "
        "image rewrite",
        f"{candidates.instruction_count} instruction and {candidates.data_count} data "
        f"candidate slots are declared at their plan addresses; {CANDIDATE_SELECTION}",
    ]
    payload = {
        "schema_version": IMAGE_SCHEMA,
        "region_id": str(owner["region_id"]),
        "base": int(owner["base"]),
        "size": int(owner["size"]),
        "entry_address": entry,
        "segments": [item.document() for item in segments],
        "data_region": {"region_id": str(data_owner["region_id"]),
                        "base": int(data_owner["base"]), "size": int(data_owner["size"])},
        "isa": {"xlen": capabilities.xlen,
                "extensions": list(capabilities.extensions)},
        "isa_repair": bool(isa_repair),
        "candidates": candidates.document(),
        "layout_hash": str(plan.raw_layout.get("layout_hash", "")),
        "plan_hash": plan.plan_hash,
    }
    image_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return ImagePlan(
        region_id=str(owner["region_id"]),
        base=int(owner["base"]),
        size=int(owner["size"]),
        entry_address=entry,
        segments=tuple(segments),
        instruction_raw_lo=instruction_raw_lo,
        data_region_id=str(data_owner["region_id"]),
        data_base=int(data_owner["base"]), data_size=int(data_owner["size"]),
        capabilities=capabilities,
        isa_repair=bool(isa_repair),
        freeze_policy="frozen_before_cpu_release",
        lifecycle=lifecycle,
        plan_hash=plan.plan_hash,
        layout_hash=str(plan.raw_layout.get("layout_hash", "")),
        image_hash=image_hash,
        candidates=candidates,
        diagnostics=tuple(diagnostics),
        _stimulus_factory=factory,
    )


def image_plan_document(plan: ImagePlan) -> dict[str, object]:
    return plan.document()


def combined_layout_hash(plan: CompositionPlan, image: ImagePlan) -> str:
    """The identity that binds the fuzz layout and the image segment together."""
    payload = {
        "schema_version": "soc_combined_layout.v1",
        "raw_layout_hash": str(plan.raw_layout.get("layout_hash", "")),
        "image_plan_hash": image.image_hash,
        "image_segments": [item.document() for item in image.segments],
        "instruction_raw_lo": image.instruction_raw_lo,
    }
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def combined_input_layout(plan: CompositionPlan, image: ImagePlan) -> InputLayout:
    """Return the actual RFuzz ABI containing special, instruction and data fields.

    A hash that mentions two independent layouts is not enough: the transport
    needs one concrete bit mapping.  This conversion preserves every existing
    profile field verbatim and appends the image fields at the offsets frozen
    by :func:`build_image_plan`.

    A composition whose drive profile declares a synthetic MMIO master also
    carries that master's raw stimulus fields, at exactly the offsets the profile
    runtime drives them from (``plan.synthetic["raw_ports"]``).  Without them the
    harness would leave the synthetic master's inputs at their idle value and
    every BFM transaction would be a zero offer; the image segments are placed
    after the reserved stimulus block by :func:`build_image_plan` so the two
    regions never overlap.  Attached peer models likewise contribute their
    per-cycle request ports after the image segment.  These fields are a raw
    ABI boundary, not an implicit peer event scheduler: the peer model observes
    the same cycle values the generated top receives.
    """
    if image.plan_hash != plan.plan_hash:
        _error("image-plan-composition-mismatch")
    fields: list[LayoutField] = []
    for item in plan.raw_layout.get("fields", []):
        if not isinstance(item, Mapping):
            _error("invalid-profile-layout-field")
        binding = item.get("binding") or {}
        provenance = item.get("provenance")
        fields.append(LayoutField(
            field_id=str(item["field_id"]), owner=str(item["owner"]),
            role=str(item["role"]), width=int(item["width"]),
            raw_lo=int(item["raw_lo"]), raw_hi=int(item["raw_hi"]),
            encoding=str(item.get("encoding", "bits")),
            constraint=dict(item.get("constraint") or {}),
            dependency_group=item.get("dependency_group"),
            port=str(binding.get("port", "")), signed=bool(binding.get("signed", False)),
            direction=str(binding.get("direction", "input")),
            provenance=dict(provenance) if isinstance(provenance, Mapping) else None,
            evidence=tuple(str(value) for value in item.get("evidence", ())),
            member_path=tuple(str(value) for value in binding.get("member_path", ())),
            port_raw_lo=binding.get("raw_lo"), port_raw_hi=binding.get("raw_hi"),
            port_width=binding.get("container_width"),
        ))
    stimulus_fields: list[LayoutField] = []
    raw_ports = list((plan.synthetic or {}).get("raw_ports", []))  # type: ignore[union-attr]
    if raw_ports:
        stimulus_base = int(plan.raw_layout.get("raw_width", 0))
        stimulus_end = stimulus_base + _stimulus_reserved_bits(plan)
        for item in raw_ports:
            # The synthetic master's raw request fields: the top-level port is
            # the request, so the transport drives it directly from the raw word.
            stimulus_fields.append(LayoutField(
                field_id=f"soc_stimulus:{item['port']}", owner="soc_stimulus",
                role=str(item["port"]), width=int(item["width"]),
                raw_lo=int(item["raw_lo"]), raw_hi=int(item["raw_hi"]),
                encoding="bits", constraint={}, port=str(item["name"]),
                direction="input",
                evidence=("soc_stimulus.v1#/raw_layout/segments/mmio",),
            ))
        # The compiled stimulus document reserves one contiguous block; the
        # segments this ABI does not drive (the instruction segment and the
        # environment segment) are recorded as explicit reserved fields so the
        # raw-bit mapping stays total and contiguous instead of silently
        # dropping bits.
        covered = sorted((field.raw_lo, field.raw_hi) for field in stimulus_fields)
        cursor = stimulus_base
        gaps: list[tuple[int, int]] = []
        for low, high in covered:
            if low > cursor:
                gaps.append((cursor, low - 1))
            cursor = max(cursor, high + 1)
        if cursor < stimulus_end:
            gaps.append((cursor, stimulus_end - 1))
        for index, (low, high) in enumerate(gaps):
            stimulus_fields.append(LayoutField(
                field_id=f"soc_stimulus:reserved_{index}", owner="soc_stimulus",
                role="reserved", width=high - low + 1, raw_lo=low, raw_hi=high,
                encoding="bits", constraint={}, port="", direction="input",
                evidence=("soc_stimulus.v1#/raw_layout/segments",),
            ))
        stimulus_fields.sort(key=lambda field: (field.raw_lo, field.field_id))
    fields.extend(stimulus_fields)
    raw_width = max([image.raw_width] + [field.raw_hi + 1 for field in fields])
    for slot in image.candidates.slots():
        declared = f"soc_image.candidate_slot.{slot.prefix}"
        for segment in slot.segments:
            instruction = segment.name in INSTRUCTION_FIELDS
            fields.append(LayoutField(
                field_id=f"soc_image:{segment.name}", owner="soc_image",
                role=segment.name, width=segment.width, raw_lo=segment.raw_lo,
                raw_hi=segment.raw_hi, encoding="bits", constraint={},
                port="", direction="input", evidence=(
                    declared,
                    "soc_image.instruction_plan" if instruction else "soc_image.data_plan",),
                provenance={"file": "soc_image.v1", "line": 1},
            ))
    # Attached peers are already instantiated by the profile renderer. Their
    # request ports must therefore be part of the concrete RFuzz ABI as well;
    # otherwise the persistent harness would leave every request at its idle
    # value even though the generated top exposes the port. Place this region
    # after the image so existing image offsets remain stable and a raw peer
    # value cannot be mistaken for an image candidate.
    peer_inputs: list[dict[str, object]] = []
    cursor = max([image.raw_width] + [field.raw_hi + 1 for field in fields])
    occupied_ports = {field.port for field in fields if field.port}
    for peer in sorted(plan.peers, key=lambda item: (item.instance_id, item.endpoint_id)):
        for slot in peer.slots:
            for signal in slot.signals:
                top_port = str(signal.top_port)
                if top_port in occupied_ports:
                    _error(f"peer-input-port-collision:{top_port}")
                occupied_ports.add(top_port)
                width = int(signal.width)
                if width <= 0:
                    _error(f"peer-input-width-invalid:{top_port}:{width}")
                field_id = f"soc_peer:{peer.instance_id}:{slot.slot}:{signal.peer_port}"
                field = LayoutField(
                    field_id=field_id,
                    owner="soc_peer",
                    role=f"{slot.slot}:{signal.peer_port}",
                    width=width,
                    raw_lo=cursor,
                    raw_hi=cursor + width - 1,
                    encoding="bits",
                    constraint={"randomizable": True},
                    port=top_port,
                    direction="input",
                    provenance={"file": "soc_peer_plan.v1", "line": 1,
                                "peer_instance": peer.instance_id,
                                "peer_id": peer.peer_id, "slot": slot.slot,
                                "source": signal.source,
                                "minimum_gap_cycles": slot.minimum_gap_cycles},
                    evidence=("soc_peer_plan.v1#/slots",),
                )
                fields.append(field)
                peer_inputs.append({
                    "field_id": field_id,
                    "instance_id": peer.instance_id,
                    "peer_id": peer.peer_id,
                    "slot": slot.slot,
                    "kind": slot.kind,
                    "peer_port": signal.peer_port,
                    "top_port": top_port,
                    "source": signal.source,
                    "width": width,
                    "raw_lo": cursor,
                    "raw_hi": cursor + width - 1,
                    "minimum_gap_cycles": slot.minimum_gap_cycles,
                })
                cursor += width
    raw_width = max(raw_width, cursor)
    document = {
        "schema_version": "soc_combined_input_layout.v1",
        "raw_width": raw_width,
        "fields": [{
            "field_id": field.field_id, "owner": field.owner, "role": field.role,
            "width": field.width, "raw_lo": field.raw_lo, "raw_hi": field.raw_hi,
            "encoding": field.encoding, "constraint": dict(field.constraint),
        } for field in fields],
        "profile_layout_hash": str(plan.raw_layout.get("layout_hash", "")),
        "image_plan_hash": image.image_hash,
        "candidates": image.candidates.document(),
        "stimulus_raw_base": int(plan.raw_layout.get("raw_width", 0)),
        "synthetic_master": (str(plan.synthetic["source_id"]) if plan.synthetic else None),
    }
    # Keep the no-peer document bit-for-bit compatible with the existing ABI;
    # attached peers get an explicit identity-bearing record for their ports.
    if peer_inputs:
        document["peer_inputs"] = peer_inputs
    return InputLayout(
        "soc_combined_input_layout.v1", raw_width, tuple(fields),
        hashlib.sha256(canonical_bytes(document)).hexdigest())


__all__ = [
    "IMAGE_SCHEMA",
    "DATA_BITS",
    "DATA_FIELDS",
    "DATA_WIDTHS",
    "INSTRUCTION_BITS",
    "INSTRUCTION_FIELDS",
    "INSTRUCTION_WIDTHS",
    "MAX_IMAGE_BYTES",
    "MAX_INSTRUCTION_CANDIDATES",
    "ImagePlan",
    "ImageResult",
    "ImageSegment",
    "SocImageError",
    "build_image_plan",
    "combined_layout_hash",
    "combined_input_layout",
    "image_plan_document",
]
