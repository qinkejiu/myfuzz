"""Build and run a profile-composed SoC.

The matrix path and the profile path share one idea: a generated top is compiled
with Verilator into a binary, and a generated testbench reads one raw input word
per cycle from its own stdin.  This module implements that contract for the
profile path, and adds what the later phases need:

* declared special inputs are driven from the raw layout, and the driver RTL
  inside the top applies the profile's drive strategy (the raw port stays a
  request, never the component input itself);
* when the plan declares a synthetic MMIO master, its six raw fields are driven
  from the compiled ``soc_stimulus.v1`` mmio-segment offsets (appended to the
  profile layout's own bits), its own counters are read through the hierarchy,
  and one counter per declared fabric source attributes every completion to the
  source id the arbiter reports;
* an explicit, bounded external-event plan drives non-MMIO pins at declared
  cycles, because a random bit flip on a UART receive line is not a legal event;
* a peer model attached to an external interface is driven by a second declared
  event plan whose entries carry a **payload** (a byte to transmit, an armed SPI
  byte, a GPIO drive/direction pair) instead of a single level, and every event
  the generated top really applied is reported back;
* a boot image reaches the memory model through the same
  ``+riscv_boot_image`` plusarg the RTL already implements;
* every run returns the per-cycle trace it actually applied, so a failure can be
  replayed from saved inputs instead of being re-guessed, and the peer models'
  own counters are read back with it.

The runtime never edits the DUT: the testbench only drives top-level inputs and
reads observations (including the memory model's own array) through
hierarchical references.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .soc_composition import CompositionPlan
from .soc_image import ImagePlan

RUNTIME_SCHEMA = "soc_runtime.v1"
TOP_MODULE = "myfuzz_soc_top"
TESTBENCH_MODULE = "myfuzz_profile_tb"

#: One request may not exceed this many simulated cycles; the bound exists so an
#: unresponsive DUT is a diagnosed timeout rather than an unbounded wait.
MAX_CYCLES = 65536
MAX_EVENTS = 256
MAX_PEER_EVENTS = 256
#: How many fabric completions one run keeps in its response capture.  The ring
#: keeps the most recent ones and the total is counted separately, so a long run
#: still reports how many transactions happened.
MAX_RESPONSE_CAPTURE = 32
MAX_REQUEST_CAPTURE = 256
MAX_OBSERVED_WORDS = 32
RESET_CYCLES = 8
CLOCK_HALF_PERIOD = 5


class SocRuntimeError(ValueError):
    """The runtime cannot be built or run as declared."""


def _error(reason: str) -> None:
    raise SocRuntimeError(reason)


@dataclass(frozen=True, slots=True)
class ExternalEvent:
    """One declared external-pin event, applied at an absolute cycle."""

    slot: str
    cycle: int
    value: int

    def document(self) -> dict[str, object]:
        return {"slot": self.slot, "cycle": self.cycle, "value": self.value}


@dataclass(frozen=True, slots=True)
class PeerStimulusEvent:
    """One declared peer-model stimulus event, applied at an absolute cycle.

    An external pin event carries a level; a peer event carries a *payload* the
    peer's own protocol consumes: one byte to transmit (UART), one byte to arm
    for the next selection (SPI), or one packed drive/drive-valid pair (GPIO).
    The slot names the plan-derived stimulus slot the event belongs to, so a
    slot the plan never declared cannot be scheduled.
    """

    slot: str
    cycle: int
    payload: int

    def document(self) -> dict[str, object]:
        return {"slot": self.slot, "cycle": self.cycle, "payload": self.payload}


@dataclass(frozen=True, slots=True)
class RuntimeSample:
    """One test: a request id, per-cycle raw inputs and the two event plans."""

    request_id: int
    raw: tuple[int, ...]
    events: tuple[ExternalEvent, ...] = ()
    peer_events: tuple[PeerStimulusEvent, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.request_id, bool) or not isinstance(self.request_id, int) \
                or self.request_id < 0:
            _error("invalid-request-id")
        if not self.raw:
            _error("sample-without-raw-input")
        if len(self.raw) > MAX_CYCLES:
            _error(f"sample-exceeds-cycle-bound:{len(self.raw)}>{MAX_CYCLES}")
        if len(self.events) > MAX_EVENTS:
            _error(f"event-plan-exceeds-bound:{len(self.events)}>{MAX_EVENTS}")
        if len(self.peer_events) > MAX_PEER_EVENTS:
            _error(f"peer-event-plan-exceeds-bound:"
                   f"{len(self.peer_events)}>{MAX_PEER_EVENTS}")
        for item in self.peer_events:
            if isinstance(item.cycle, bool) or not isinstance(item.cycle, int) \
                    or item.cycle < 0:
                _error(f"peer-event-cycle-invalid:{item.slot}:{item.cycle}")
            if isinstance(item.payload, bool) or not isinstance(item.payload, int) \
                    or item.payload < 0:
                _error(f"peer-event-payload-invalid:{item.slot}:{item.payload}")

    def payload(self) -> str:
        lines = [f"{self.request_id:016x} {len(self.raw)}"]
        lines.append(f"E {len(self.events)}")
        for event in self.events:
            lines.append(f"{event.slot} {event.cycle} {event.value}")
        # The peer plan follows the external plan and carries a payload per
        # entry.  The slot is the index of the plan-derived slot table, so the
        # testbench never matches a string and a stale slot number is refused by
        # the runtime before the simulator runs.
        lines.append(f"P {len(self.peer_events)}")
        for event in self.peer_events:
            lines.append(f"{event.slot} {event.cycle} {event.payload:x}")
        lines.extend(f"{value:x}" for value in self.raw)
        return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class RuntimeBuild:
    output_dir: Path
    top_path: Path
    testbench_path: Path
    executable: Path
    sources: tuple[str, ...]
    raw_width: int
    slots: tuple[dict[str, object], ...]
    observations: tuple[dict[str, object], ...]
    boot_image: Path | None
    boot_image_policy: str
    build_hash: str
    warnings: int = 0
    #: The plan's declared peer stimulus slots and observed peer outputs.  A
    #: sample may only schedule a slot in this table, and the counters a run
    #: reports are exactly the ones the plan declared as counters.
    peer_slots: tuple[dict[str, object], ...] = ()
    peer_observations: tuple[dict[str, object], ...] = ()
    peer_wires: tuple[dict[str, object], ...] = ()
    spi_wire_contracts: Mapping[str, object] = field(default_factory=dict)
    cpu_data_sources: tuple[int, ...] = ()
    source_hashes: Mapping[str, str] = field(default_factory=dict)

    def executable_resolution(self) -> str:
        """The executable's path relative to the build directory it lives in.

        The one canonical spelling of "where the binary is", so a record made
        here and a path derived from it cannot disagree.
        """
        try:
            return self.executable.relative_to(self.output_dir).as_posix()
        except ValueError:
            return self.executable.as_posix()

    def document(self) -> dict[str, object]:
        return {
            "schema_version": RUNTIME_SCHEMA,
            "output_dir": self.output_dir.as_posix(),
            "top": self.top_path.name,
            "testbench": self.testbench_path.name,
            # The path relative to ``output_dir``, not the bare basename: the
            # binary lives under ``obj_dir``, so a basename alone cannot be
            # resolved and every reconstruction from this record would silently
            # recompile (or point at a file that never exists).
            "executable": self.executable_resolution(),
            "sources": list(self.sources),
            "raw_width": self.raw_width,
            "slots": [dict(item) for item in self.slots],
            "observations": [dict(item) for item in self.observations],
            "peer_slots": [dict(item) for item in self.peer_slots],
            "peer_observations": [dict(item) for item in self.peer_observations],
            "peer_wires": [dict(item) for item in self.peer_wires],
            "spi_wire_contracts": dict(self.spi_wire_contracts),
            "cpu_data_sources": list(self.cpu_data_sources),
            "source_hashes": dict(self.source_hashes),
            "boot_image": None if self.boot_image is None else self.boot_image.name,
            "boot_image_policy": self.boot_image_policy,
            "build_hash": self.build_hash,
            "warnings": self.warnings,
        }


@dataclass(frozen=True, slots=True)
class RunResult:
    request_id: int
    cycles: int
    status: str
    counters: Mapping[str, int]
    observations: Mapping[str, int]
    trace: tuple[dict[str, int], ...]
    applied: tuple[dict[str, int], ...]
    stdout: str
    stderr: str
    reason: str = ""
    #: The peer stimulus the generated testbench reported applying, one record
    #: per applied event.  A replay that applies the same plan produces the same
    #: records, which is what makes the peer half of a run reproducible.
    peer_applied: tuple[dict[str, object], ...] = ()
    #: The fabric completions the run captured, oldest first: address, write
    #: flag, read data and the source the arbiter attributed the completion to.
    #: A register read back from a peripheral is attributed here to the address
    #: that produced it instead of to whichever observation came last.
    responses: tuple[dict[str, int], ...] = ()
    #: Independent peer-contract evidence.  Wire properties that the runtime
    #: cannot observe are retained as ``not_assessed`` by the oracle rather than
    #: inferred from a peer's own counters.
    peer_oracle: Mapping[str, object] | None = None
    peer_wire_trace: tuple[dict[str, object], ...] = ()
    peer_wire_status: tuple[dict[str, object], ...] = ()
    requests: tuple[dict[str, int], ...] = ()
    requests_truncated: bool = False
    #: The candidate-image placements the harness performed before releasing the
    #: CPU, one record per offered slot.  ``readback`` is the value the memory
    #: model's own array returned at the placed address, so the record is the
    #: harness's observation of the placement rather than a restatement of the
    #: raw field that asked for it.
    image_placements: tuple[dict[str, object], ...] = ()
    #: Addresses the harness refused to place because they left the declared
    #: region.  A refusal is recorded, never silently dropped.
    image_errors: tuple[dict[str, object], ...] = ()

    def document(self) -> dict[str, object]:
        document = {
            "request_id": self.request_id,
            "cycles": self.cycles,
            "status": self.status,
            "counters": dict(sorted(self.counters.items())),
            "observations": dict(sorted(self.observations.items())),
            "trace": [dict(item) for item in self.trace],
            "applied_trace": [dict(item) for item in self.applied],
            "peer_applied": [dict(item) for item in self.peer_applied],
            "peer_wire_trace": [dict(item) for item in self.peer_wire_trace],
            "peer_wire_status": [dict(item) for item in self.peer_wire_status],
            "fabric_requests": [dict(item) for item in self.requests],
            "fabric_requests_truncated": self.requests_truncated,
            "fabric_responses": [dict(item) for item in self.responses],
            "image_placements": [dict(item) for item in self.image_placements],
            "image_errors": [dict(item) for item in self.image_errors],
            "reason": self.reason,
        }
        if self.peer_oracle is not None:
            document["peer_oracle"] = dict(self.peer_oracle)
        return document


# ---------------------------------------------------------------------------
# testbench generation
# ---------------------------------------------------------------------------


def _sv_type(width: int) -> str:
    return "logic" if width == 1 else f"logic [{width - 1}:0]"


def _special_slots(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    records = plan.raw_layout.get("special_inputs")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        _error("runtime-requires-special-input-records")
    slots: list[dict[str, object]] = []
    for item in records:
        if not isinstance(item, Mapping):
            continue
        slots.append({
            "name": str(item["top_port"]),
            "width": int(item["width"]),
            "raw_lo": int(item["raw_lo"]),
            "raw_hi": int(item["raw_hi"]),
            "strategy": str(item["strategy"]),
            "instance_id": str(item["instance_id"]),
            "port": str(item["port"]),
        })
    slots.sort(key=lambda item: str(item["name"]))
    return tuple(slots)


def _peer_slots(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The plan's peer stimulus slots, indexed in the order a sample addresses them.

    The index is the slot's position in this table; a sample entry names the
    index, so the generated testbench never matches a string and a slot the plan
    did not declare is refused before the simulator starts.
    """
    records: list[dict[str, object]] = []
    for peer in plan.peers:
        for slot in peer.slots:
            records.append({
                "index": len(records),
                "slot": slot.slot,
                "kind": slot.kind,
                "width": slot.width,
                "instance_id": slot.instance_id,
                "peer_id": slot.peer_id,
                "peer_module": peer.module,
                "peer_source": peer.source,
                "peer_protocol": list(peer.protocol),
                "parameters": dict(peer.parameter_values),
                "minimum_gap_cycles": slot.minimum_gap_cycles,
                "signals": [{"peer_port": item.peer_port, "top_port": item.top_port,
                             "width": item.width, "source": item.source}
                            for item in slot.signals],
            })
    records.sort(key=lambda item: (str(item["instance_id"]), str(item["slot"])))
    for index, item in enumerate(records):
        item["index"] = index
    return tuple(records)


def _peer_stimulus_ports(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The top-level inputs a peer's stimulus slot drives."""
    records: list[dict[str, object]] = []
    for peer in plan.peers:
        for slot in peer.slots:
            for signal in slot.signals:
                records.append({"name": signal.top_port, "width": signal.width,
                                "instance_id": peer.instance_id, "slot": slot.slot,
                                "peer_port": signal.peer_port, "source": signal.source,
                                "kind": slot.kind})
    records.sort(key=lambda item: str(item["name"]))
    return tuple(records)


def _peer_observations(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The plan's observed peer outputs, counters first in the plan's own order."""
    records: list[dict[str, object]] = []
    for peer in plan.peers:
        for item in peer.observations:
            records.append({"name": item.top_port, "width": item.width,
                            "instance_id": peer.instance_id, "peer_id": peer.peer_id,
                            "peer_port": item.peer_port, "counter": item.counter,
                            "description": item.description})
    records.sort(key=lambda item: str(item["name"]))
    return tuple(records)


def _spi_wire_records(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """Resolve observation-only SPI nets from the already audited peer roles."""
    records: list[dict[str, object]] = []
    for peer in plan.peers:
        if peer.peer_id != "spi":
            continue
        roles = {role: f"dut.{peer.instance_id}__{peer.binding(role).component_port}"
                 for role in ("sck", "cs", "mosi", "miso")}
        records.append({"instance_id": peer.instance_id, "roles": roles,
                        "parameters": peer.parameter_values})
    return tuple(records)


def _fabric_widths(plan: CompositionPlan) -> tuple[int, int, int]:
    """The fabric widths the response capture is declared with.

    They are the plan's own fabric parameters, so the capture observes exactly
    the buses the rendered top has instead of a width this module assumed.
    """
    parameters = plan.plan["fabric"]["rtl"]["parameters"]
    address_width = int(parameters["ADDRESS_WIDTH"])
    data_width = int(parameters["DATA_WIDTH"])
    num_sources = int(parameters["NUM_SOURCES"])
    return address_width, data_width, max(1, (num_sources - 1).bit_length())


def _peer_raw_slots(plan: CompositionPlan, image_plan=None) -> tuple[dict[str, object], ...]:
    """The attached peers' request ports, at their combined-ABI raw offsets.

    A peer model's request ports are part of the concrete RFuzz ABI exactly the
    way the synthetic master's are: ``combined_input_layout`` appends them after
    the image segment, and the persistent harness must drive them from the raw
    word, or every request would stay at its idle value while the peer plan alone
    carried the stimulus.  The image plan is the only record of where that region
    starts, so nothing here re-derives an offset; without one the caller has a
    profile-only ABI and there is nothing to drive.

    ``source`` distinguishes a level-carrying request (``level_drive``) from a
    pulse request (``pulse``): a pulse is a one-cycle request the peer model
    latches itself, so the raw bit is consumed in the cycle it is raised.
    """
    if image_plan is None or not plan.peers:
        return ()
    cursor = int(image_plan.raw_width)
    slots: list[dict[str, object]] = []
    for peer in plan.peers:
        for slot in peer.slots:
            for signal in slot.signals:
                top_port = str(signal.top_port)
                width = int(signal.width)
                if width <= 0:
                    _error(f"runtime-peer-raw-width-invalid:{top_port}")
                slots.append({
                    "name": top_port,
                    "width": width,
                    "raw_lo": cursor,
                    "raw_hi": cursor + width - 1,
                    "source": str(signal.source),
                    "instance_id": str(peer.instance_id),
                    "slot": str(slot.slot),
                    "peer_port": str(signal.peer_port),
                })
                cursor += width
    return tuple(slots)


def _image_memory_targets(plan: CompositionPlan, image_plan) -> dict[str, tuple[str, int, int]]:
    """Where each image region really lives, from the plan's own fabric records.

    The overlay writes into the memory model's ``initial_memory`` array, which is
    anchored at its memory instance's base address.  Both the target index and
    the base/size come from the plan: a missing or ambiguous mapping is refused
    rather than guessed, because an overlay written at the wrong anchor would
    silently place a candidate somewhere the CPU never fetches.
    """
    fabric = plan.plan["fabric"]
    regions = {str(item["region_id"]): item
               for item in plan.plan["address_map"]["memory_regions"]}
    windows = fabric["decode"]["windows"]
    targets: dict[str, tuple[str, int, int]] = {}
    for region_id in {str(item.region_id) for item in image_plan.candidates.slots()}:
        region = regions.get(region_id)
        if region is None:
            _error(f"runtime-image-region-unknown:{region_id}")
        matches = [row for row in windows if str(row.get("window_id")) == region_id]
        if len(matches) != 1:
            _error(f"runtime-image-memory-target-ambiguous:{region_id}")
        index = int(matches[0]["target_index"])
        base = int(region["base"])
        size = int(region["size"])
        if int(matches[0]["base"]) != base or int(matches[0]["size"]) != size:
            _error(f"runtime-image-region-window-mismatch:{region_id}")
        targets[region_id] = (f"u_mem_{index}", base, size)
    return targets


def _synthetic_slots(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The synthetic master's raw fields, at the offsets the stimulus records.

    The offsets are the ``soc_stimulus.v1`` mmio-segment offsets shifted by the
    profile layout's own width, which is the frozen combined ABI this runtime
    feeds: bits [0, raw_layout.raw_width) are the declared special inputs, the
    stimulus segments follow.  Nothing here re-derives a field position.
    """
    synthetic = plan.synthetic
    if not synthetic:
        return ()
    base_bit = int(synthetic.get("raw_base_bit", 0))
    records = synthetic.get("raw_ports")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        _error("runtime-synthetic-record-without-raw-ports")
    slots: list[dict[str, object]] = []
    for item in records:
        if not isinstance(item, Mapping):
            continue
        if int(item["raw_lo"]) != base_bit + int(item["segment_bit_offset"]):
            _error(f"runtime-synthetic-offset-mismatch:{item['name']}")
        slots.append({
            "name": str(item["name"]),
            "width": int(item["width"]),
            "raw_lo": int(item["raw_lo"]),
            "raw_hi": int(item["raw_hi"]),
            "strategy": "raw_request",
            "instance_id": str(synthetic["instance_id"]),
            "port": str(item["port"]),
        })
    slots.sort(key=lambda item: str(item["name"]))
    return tuple(slots)


def _synthetic_observations(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The synthetic master's own counters, read through the hierarchy.

    They are internal state of the generated top, not top-level outputs, so they
    are read the same way the memory model's array is: by hierarchical reference
    from the testbench, never by adding a port to the DUT.
    """
    synthetic = plan.synthetic
    if not synthetic:
        return ()
    records = synthetic.get("observations")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return ()
    cell = f"u_{synthetic['instance_id']}"
    return tuple({"name": str(item["name"]), "cell": cell, "port": str(item["port"]),
                  "width": int(item["width"])}
                 for item in records if isinstance(item, Mapping))


def _fabric_sources(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """The plan's own fabric sources, in lane order, as response-attribution slots."""
    records: list[dict[str, object]] = []
    for source in plan.plan["fabric"]["sources"]:
        source_id = str(source["source_id"])
        if not source_id.isidentifier():
            _error(f"runtime-source-id-not-an-identifier:{source_id}")
        records.append({"index": int(source["index"]), "source_id": source_id,
                        "kind": str(source["kind"])})
    records.sort(key=lambda item: int(item["index"]))
    return tuple(records)


def _testbench_raw_width(plan: CompositionPlan, image_plan=None) -> int:
    """The raw word width the generated testbench really consumes.

    With an image plan this is the frozen combined ABI: the profile prefix, the
    stimulus block, the candidate image segments and the attached peers' request
    fields.  Without one it is the profile prefix plus the synthetic master's
    fields, exactly the width the earlier phases published.
    """
    width = int(plan.raw_layout["raw_width"])
    for slot in _special_slots(plan) + _synthetic_slots(plan):
        width = max(width, int(slot["raw_hi"]) + 1)
    if image_plan is not None:
        width = max(width, int(image_plan.raw_width))
    for slot in _peer_raw_slots(plan, image_plan):
        width = max(width, int(slot["raw_hi"]) + 1)
    return width


def _external_inputs(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """Top-level external *inputs* the environment owns through an event plan."""
    records: list[dict[str, object]] = []
    for instance in plan.instances:
        for entry in instance.dispositions:
            if entry.disposition != "external" or entry.direction != "input":
                continue
            span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
                f"_{entry.bit_hi}_{entry.bit_lo}"
            records.append({
                "name": f"{entry.instance_id}__{entry.port}{span}",
                "width": entry.bit_hi - entry.bit_lo + 1,
                "instance_id": entry.instance_id,
                "port": entry.port,
            })
    records.sort(key=lambda item: str(item["name"]))
    return tuple(records)


def _observations(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for instance in plan.instances:
        for entry in instance.dispositions:
            # An exported external *output* is a real observation of the run: the
            # component drives it and the SoC exports it.  External inputs are
            # driven by the event plan and are never observations.
            observed = entry.disposition == "observe" or (
                entry.disposition == "external" and entry.direction == "output")
            if not observed:
                continue
            span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
                f"_{entry.bit_hi}_{entry.bit_lo}"
            records.append({
                "name": f"{instance.instance_id}__{entry.port}{span}",
                "width": entry.bit_hi - entry.bit_lo + 1,
            })
    for slot in _special_slots(plan):
        # The driver's applied value is exported by the generated top, so a run
        # can report the timing it really produced instead of assuming it.
        records.append({
            "name": f"{slot['name']}__applied",
            "width": int(slot["width"]),
            "applied_for": str(slot["name"]),
        })
    for item in _peer_observations(plan):
        # A peer's counters and observations are top-level outputs of the
        # generated top, so the run reports them exactly like any other output.
        records.append({
            "name": str(item["name"]),
            "width": int(item["width"]),
            "peer_instance": str(item["instance_id"]),
            "peer_observed": str(item["peer_port"]),
            "peer_counter": bool(item["counter"]),
        })
    records.sort(key=lambda item: str(item["name"]))
    return tuple(records)


def _memory_slots(plan: CompositionPlan) -> tuple[dict[str, object], ...]:
    """Memory instances the testbench may read back through the hierarchy."""
    records: list[dict[str, object]] = []
    fabric = plan.plan["fabric"]
    for index, target in enumerate(fabric["targets"]):
        if target.get("backing_kind") != "memory":
            continue
        rows = [row for row in fabric["decode"]["windows"]
                if int(row["target_index"]) == int(target["index"])]
        if not rows:
            continue
        records.append({
            "instance": f"u_mem_{index}",
            "backing_id": str(target["backing_id"]),
            "base": int(rows[0]["base"]),
            "size": int(rows[0]["size"]),
        })
    return tuple(records)


def render_profile_testbench(plan: CompositionPlan, *,
                             boot_plusargs: Sequence[str] = (),
                             image_plan=None) -> str:
    slots = _special_slots(plan)
    synthetic_slots = _synthetic_slots(plan)
    # The attached peers' request ports.  Without an image plan this is empty and
    # the testbench is exactly the profile-only artifact earlier phases published.
    peer_raw_slots = _peer_raw_slots(plan, image_plan)
    image_targets = ({} if image_plan is None
                     else _image_memory_targets(plan, image_plan))
    synthetic_observations = _synthetic_observations(plan)
    # The per-source attribution counters are rendered only for a composition
    # that really has several sources, so the CPU-only testbench stays exactly
    # the artifact the earlier phases published.
    fabric_sources = _fabric_sources(plan) if plan.synthetic else ()
    externals = _external_inputs(plan)
    peer_stimulus = _peer_stimulus_ports(plan)
    peer_slots = _peer_slots(plan)
    spi_wires = _spi_wire_records(plan)
    fabric_address_width, fabric_data_width, fabric_source_width = _fabric_widths(plan)
    observations = _observations(plan)
    memory = _memory_slots(plan)
    raw_width = _testbench_raw_width(plan, image_plan)
    if raw_width <= 0:
        _error("runtime-requires-a-raw-input-layout")
    lines: list[str] = []
    add = lines.append
    add("// Generated by myfuzz profile runtime. Do not edit.")
    add(f"// plan: {plan.plan_hash}")
    add(f"// raw-input layout: {plan.raw_layout.get('layout_hash', '<none>')}")
    if image_plan is not None:
        add(f"// image plan: {image_plan.image_hash}")
    add(f"module {TESTBENCH_MODULE};")
    add(f"  localparam integer RAW_WIDTH = {raw_width};")

    add(f"  localparam integer MAX_EVENTS = {MAX_EVENTS};")
    add(f"  localparam integer MAX_CYCLES = {MAX_CYCLES};")
    add(f"  localparam integer RESET_CYCLES = {RESET_CYCLES};")
    add(f"  localparam integer EVENT_SLOTS = {max(1, len(externals))};")
    add(f"  localparam integer PEER_SLOTS = {max(1, len(peer_slots))};")
    add(f"  localparam integer PEER_EVENTS_MAX = {MAX_PEER_EVENTS};")
    add("  localparam integer PEER_WIRE_MAX = 8192;")
    add(f"  localparam integer REQ_CAPTURE = {MAX_REQUEST_CAPTURE};")
    add(f"  localparam integer MEMORY_SLOTS = {max(1, len(memory))};")
    add(f"  localparam integer OBSERVED_WORDS = {MAX_OBSERVED_WORDS};")
    add("")
    add("  logic clk_i = 1'b0;")
    # Power-on value is the released level so that the first driven edge is a
    # real assertion: an asynchronous-reset block only clears on a 1->0
    # transition, and a net that starts low never provides one.
    add("  logic rst_ni = 1'b1;")
    add("  logic [RAW_WIDTH-1:0] raw_bits = '0;")
    add("  always #%d clk_i = ~clk_i;" % CLOCK_HALF_PERIOD)
    add("")
    for slot in slots:
        add(f"  {_sv_type(int(slot['width']))} {slot['name']};")
        add(f"  assign {slot['name']} = raw_bits[{int(slot['raw_hi'])}:"
            f"{int(slot['raw_lo'])}];")
    if not slots:
        add("  // no declared special inputs in this composition")
    if synthetic_slots:
        add("")
        add("  // The synthetic master's raw fields.  These top-level ports *are* the")
        add("  // request: the master latches them itself, so no driver stage is inserted")
        add("  // in front of them.  Their bit offsets are the stimulus mmio segment's own")
        add("  // offsets, shifted by the profile layout width.")
        for slot in synthetic_slots:
            add(f"  {_sv_type(int(slot['width']))} {slot['name']};")
            add(f"  assign {slot['name']} = raw_bits[{int(slot['raw_hi'])}:"
                f"{int(slot['raw_lo'])}];")
    add("")
    for index, item in enumerate(externals):
        add(f"  {_sv_type(int(item['width']))} {item['name']}; // event slot {index}")
        add(f"  initial {item['name']} = '0;")
    if not externals:
        add("  // no external input pins in this composition")
    add("")
    peer_raw_by_port = {str(item["name"]): item for item in peer_raw_slots}
    if peer_stimulus:
        add("  // Peer-model stimulus ports.  Two declared sources can address one port,")
        add("  // and they are not interchangeable: the raw ABI carries a per-cycle")
        add("  // request (the peer model latches a pulse itself), while the peer event")
        add("  // plan carries a payload at a declared cycle.  The raw word is the")
        add("  // default level and a fired event overrides it, so both remain usable")
        add("  // and a test can tell which one it used.")
        for item in peer_stimulus:
            name = str(item["name"])
            raw = peer_raw_by_port.get(name)
            # A port that is continuously assigned must not carry *any* initial
            # value -- not a declaration initialiser and not a procedural
            # ``initial`` statement; Verilator refuses both with CONTASSINIT.
            # The level is defined from time zero anyway, because the expression
            # the port is assigned reads ``{name}__event`` (initialised to zero)
            # and, on the image path, ``raw_bits`` (initialised to zero).
            if raw is None:
                add(f"  {_sv_type(int(item['width']))} {name}; "
                    f"// {item['instance_id']} {item['slot']} -> {item['peer_port']}")
                add(f"  {_sv_type(int(item['width']))} {name}__event = '0;")
                add(f"  assign {name} = {name}__event;")
            else:
                add(f"  {_sv_type(int(item['width']))} {name}; "
                    f"// {item['instance_id']} {item['slot']} -> {item['peer_port']}")
                add(f"  {_sv_type(int(item['width']))} {name}__event = '0;")
                add(f"  logic {name}__event_active = 1'b0;")
                add(f"  assign {name} = {name}__event_active ? {name}__event : "
                    f"raw_bits[{int(raw['raw_hi'])}:{int(raw['raw_lo'])}];")
    if peer_raw_slots:
        add("")
        add("  // Attached peer request fields taken straight from the raw word.  Their")
        add("  // offsets come from the frozen combined ABI (after the image segment), so")
        add("  // a raw peer field really reaches the peer model's own port.")
    for item in observations:
        add(f"  logic [{int(item['width']) - 1}:0] obs_{item['name']};")
    for slot in slots:
        add(f"  logic [{int(slot['width']) - 1}:0] prev_applied_{slot['name']} = '0;")
    add("")
    add("  // Observation-only counters; the CPU and peripherals are never modified.")
    add("  integer cycles = 0;")
    add("  integer accepted = 0;")
    add("  integer completed = 0;")
    add("  integer errors = 0;")
    for index, item in enumerate(spi_wires):
        add(f"  integer peer_wire_count_{index} = 0;")
        add(f"  integer peer_wire_truncated_{index} = 0;")
        add(f"  logic [3:0] peer_wire_previous_{index} = 4'bxxxx;")
    add("  integer event_index = 0;")
    add("  integer event_slot [0:MAX_EVENTS-1];")
    add("  integer event_cycle [0:MAX_EVENTS-1];")
    add("  logic [63:0] event_value [0:MAX_EVENTS-1];")
    add("  integer event_count = 0;")
    add("  integer peer_event_index = 0;")
    add("  integer peer_event_slot [0:PEER_EVENTS_MAX-1];")
    add("  integer peer_event_cycle [0:PEER_EVENTS_MAX-1];")
    add("  logic [63:0] peer_event_value [0:PEER_EVENTS_MAX-1];")
    add("  integer peer_event_count = 0;")
    add("  integer request_id = 0;")
    add("  integer requested_cycles = 0;")
    add("  integer cycle_index = 0;")
    add("  integer memory_word [0:MEMORY_SLOTS*OBSERVED_WORDS-1];")
    add("  logic [63:0] boot_bytes;")
    add("  integer fd;")
    add("  integer code;")
    add("  integer scan_count;")
    # The raw word carries the profile layout and, for a BFM composition, the
    # whole stimulus layout after it, so it is as wide as RAW_WIDTH.
    add("  logic [RAW_WIDTH-1:0] raw_word;")
    add("  logic [63:0] memory_value;")
    if image_plan is not None:
        # One buffered raw word per cycle of the record: the overlay scans the
        # whole record for an offer, so a buffer sized by the number of declared
        # slots would be written past its end and corrupt the surrounding state.
        add("  logic [RAW_WIDTH-1:0] sample_words [0:MAX_CYCLES-1];")
        add("  integer image_lane = 0;")
        add("  logic [31:0] image_address = '0;")
        add("  logic [31:0] image_value = '0;")
        add("  logic [3:0] image_be = '0;")
        add("  logic [31:0] image_readback = '0;")
        for slot in image_plan.candidates.slots():
            add(f"  logic placed_{slot.prefix}_kind = 1'b0;")
            add(f"  logic [31:0] placed_{slot.prefix}_address = '0;")
            add(f"  logic [3:0] placed_{slot.prefix}_be = '0;")
    if fabric_sources:
        add("")
        add("  // Response attribution: the fabric's own rsp_source_id decides which")
        add("  // lane a completion belongs to.  These counters only observe it.")
        for index, item in enumerate(fabric_sources):
            add(f"  integer source_responses_{index} = 0; // lane {index}: {item['source_id']}")
    add("")
    add("  // Per-completion capture: every fabric response is recorded with the address")
    add("  // it answered, so a read value can be attributed to the window that produced")
    add("  // it instead of being inferred from the last observation.  The capture is a")
    add("  // bounded ring: the most recent completions are kept and the total counted.")
    add(f"  localparam integer RSP_CAPTURE = {MAX_RESPONSE_CAPTURE};")
    add("  integer rsp_total = 0;")
    add("  integer rsp_head = 0;")
    add("  integer req_total = 0;")
    add("  integer req_head = 0;")
    add("  integer req_cycle [0:REQ_CAPTURE-1];")
    add(f"  logic [{fabric_address_width - 1}:0] req_addr [0:REQ_CAPTURE-1];")
    add(f"  logic [{fabric_data_width - 1}:0] req_wdata [0:REQ_CAPTURE-1];")
    add(f"  logic [{fabric_data_width // 8 - 1}:0] req_be [0:REQ_CAPTURE-1];")
    add(f"  logic [{fabric_source_width - 1}:0] req_source [0:REQ_CAPTURE-1];")
    add("  integer rsp_seq [0:RSP_CAPTURE-1];")
    add(f"  logic [{fabric_address_width - 1}:0] rsp_addr [0:RSP_CAPTURE-1];")
    add(f"  logic [{fabric_data_width - 1}:0] rsp_rdata [0:RSP_CAPTURE-1];")
    add("  logic rsp_write [0:RSP_CAPTURE-1];")
    add(f"  logic [{fabric_source_width - 1}:0] rsp_source [0:RSP_CAPTURE-1];")
    add("  always @(posedge clk_i) begin")
    add("    if (dut.fabric_rsp_valid && dut.fabric_rsp_ready) begin")
    add("      rsp_seq[rsp_head] = rsp_total;")
    add("      rsp_addr[rsp_head] = dut.fabric_addr;")
    add("      rsp_rdata[rsp_head] = dut.fabric_rdata;")
    add("      rsp_write[rsp_head] = dut.fabric_write;")
    add("      rsp_source[rsp_head] = dut.fabric_rsp_source_id;")
    add("      rsp_head = (rsp_head + 1) % RSP_CAPTURE;")
    add("      rsp_total = rsp_total + 1;")
    add("    end")
    add("  end")
    add("  always @(posedge clk_i) begin")
    add("    if (dut.fabric_req_valid && dut.fabric_req_ready && dut.fabric_write) begin")
    add("      req_cycle[req_head] = cycles;")
    add("      req_addr[req_head] = dut.fabric_addr;")
    add("      req_wdata[req_head] = dut.fabric_wdata;")
    add("      req_be[req_head] = dut.fabric_be;")
    add("      req_source[req_head] = dut.fabric_source_id;")
    add("      req_head = (req_head + 1) % REQ_CAPTURE;")
    add("      req_total = req_total + 1;")
    add("    end")
    add("  end")
    add("")
    for index, item in enumerate(externals):
        add(f"  assign obs_event_slot_{index} = {item['name']};")
        add(f"  logic [{int(item['width']) - 1}:0] obs_event_slot_{index};")
    if not externals:
        add("  logic obs_event_slot_none;")
        add("  assign obs_event_slot_none = 1'b0;")
    add("")

    # The DUT.
    add(f"  {TOP_MODULE} dut (")
    connections = ["    .clk_i(clk_i)", "    .rst_ni(rst_ni)"]
    for slot in slots:
        connections.append(f"    .{slot['name']}({slot['name']})")
    for slot in synthetic_slots:
        connections.append(f"    .{slot['name']}({slot['name']})")
    for item in externals:
        connections.append(f"    .{item['name']}({item['name']})")
    for item in peer_stimulus:
        connections.append(f"    .{item['name']}({item['name']})")
    for item in observations:
        connections.append(f"    .{item['name']}(obs_{item['name']})")
    add(",\n".join(connections))
    add("  );")
    add("")
    for index, item in enumerate(spi_wires):
        roles = item["roles"]
        assert isinstance(roles, Mapping)
        packed = "{" + ", ".join(str(roles[role]) for role in
                                   ("sck", "cs", "mosi", "miso")) + "}"
        add("  // Sample after the active edge and all nonblocking updates settle.")
        add("  always @(negedge clk_i) begin")
        add(f"    if (rst_ni && cycles > 0 && cycles <= requested_cycles && "
            f"{packed} !== peer_wire_previous_{index}) begin")
        add(f"      peer_wire_previous_{index} = {packed};")
        add(f"      if (peer_wire_count_{index} < PEER_WIRE_MAX) begin")
        add(f"        $display(\"MYFUZZ_PEER_WIRE cycle=%0d instance={item['instance_id']} "
            "sck=%b cs=%b mosi=%b miso=%b\", cycles, " +
            ", ".join(str(roles[role]) for role in
                      ("sck", "cs", "mosi", "miso")) + ");")
        add(f"        peer_wire_count_{index} = peer_wire_count_{index} + 1;")
        add("      end else begin")
        add(f"        peer_wire_truncated_{index} = 1;")
        add("      end")
        add("    end")
        add("  end")
        add("")
    if fabric_sources:
        add("  // One counter per declared fabric source, incremented by the completion the")
        add("  // arbiter attributes to that source id.  The DUT is only observed.")
        add("  always @(posedge clk_i) begin")
        add("    if (dut.fabric_rsp_valid && dut.fabric_rsp_ready) begin")
        add("      case (dut.fabric_rsp_source_id)")
        for index, item in enumerate(fabric_sources):
            add(f"        {int(item['index'])}: source_responses_{index} = "
                f"source_responses_{index} + 1;")
        add("        default: ;")
        add("      endcase")
        add("    end")
        add("  end")
        add("")

    # Memory observation through the model's own array.
    for index, item in enumerate(memory):
        add(f"  // {item['backing_id']} at 0x{int(item['base']):08x} "
            f"size 0x{int(item['size']):x}")
        add(f"  task automatic read_memory_{index}(input integer byte_offset, "
            f"output logic [63:0] value);")
        add("    begin")
        add(f"      value = {{dut.{item['instance']}.memory[byte_offset+7],"
            f" dut.{item['instance']}.memory[byte_offset+6],")
        add(f"               dut.{item['instance']}.memory[byte_offset+5],"
            f" dut.{item['instance']}.memory[byte_offset+4],")
        add(f"               dut.{item['instance']}.memory[byte_offset+3],"
            f" dut.{item['instance']}.memory[byte_offset+2],")
        add(f"               dut.{item['instance']}.memory[byte_offset+1],"
            f" dut.{item['instance']}.memory[byte_offset]}};")
        add("    end")
        add("  endtask")
    if not memory:
        add("  // no memory backing in this composition")
    add("")

    # Event application.
    add("  always @(posedge clk_i) begin")
    add("    while (event_index < event_count && event_cycle[event_index] <= cycles) begin")
    add("      case (event_slot[event_index])")
    for index, item in enumerate(externals):
        add(f"        {index}: {item['name']} <= "
            f"event_value[event_index][{int(item['width']) - 1}:0];")
    if not externals:
        add("        0: ;")
    add("        default: ;")
    add("      endcase")
    add("      event_index = event_index + 1;")
    add("    end")
    add("  end")
    add("")
    if peer_stimulus:
        # A pulse slot is asserted for exactly the declared cycle, so every pulse
        # signal is cleared first and the event that fires this cycle sets it
        # again.  A level slot holds its payload until the next event, because a
        # drive state is not a pulse.
        add("  // Peer stimulus application.  A pulse slot is high for exactly one clk_i")
        add("  // cycle at its declared cycle; a level slot holds the payload it was given")
        add("  // until the next event of the same slot.  Every applied event is reported")
        add("  // so a run's peer stimulus is part of its saved evidence.")
        add("  always @(posedge clk_i) begin")
        for item in peer_stimulus:
            if str(item["source"]) == "pulse":
                add(f"    {item['name']}__event <= '0;")
        add("    while (peer_event_index < peer_event_count "
            "&& peer_event_cycle[peer_event_index] <= cycles) begin")
        add("      case (peer_event_slot[peer_event_index])")
        for index, slot in enumerate(peer_slots):
            add(f"        {index}: begin // {slot['slot']} ({slot['kind']})")
            for signal in slot["signals"]:  # type: ignore[union-attr]
                width = int(signal["width"])
                source = str(signal["source"])
                name = str(signal["top_port"])
                if source == "pulse":
                    expression = "1'b1"
                elif source in ("payload", "payload_low"):
                    expression = f"peer_event_value[peer_event_index][{width - 1}:0]"
                elif source == "payload_high":
                    expression = (f"peer_event_value[peer_event_index]"
                                  f"[{2 * width - 1}:{width}]")
                else:
                    _error(f"runtime-unsupported-peer-signal:{source}")
                add(f"          {name}__event <= {expression}; // {signal['peer_port']}")
                if name in peer_raw_by_port:
                    add(f"          {name}__event_active <= 1'b1;")
            add(f"          $display(\"MYFUZZ_PEER_APPLIED cycle=%0d "
                f"instance={slot['instance_id']} slot={slot['slot']} value=%0h\", "
                f"cycles, peer_event_value[peer_event_index]);")
            add("        end")
        add("        default: ;")
        add("      endcase")
        add("      peer_event_index = peer_event_index + 1;")
        add("    end")
        add("  end")
        add("")
        add("  // A pulse event is active for exactly the cycle it fired in.")
        for item in peer_stimulus:
            if str(item["source"]) == "pulse" and str(item["name"]) in peer_raw_by_port:
                add(f"  always @(negedge clk_i) {item['name']}__event_active <= 1'b0;")
        add("")

    # Main loop.
    add("  initial begin")
    plusargs = " ".join(f'"{item}"' for item in boot_plusargs)
    add("    fd = 32'h80000000;")
    add("    for (cycle_index = 0; cycle_index < RAW_WIDTH; cycle_index = cycle_index + 1) "
        "raw_bits[cycle_index] = 1'b0;")
    add("    scan_count = $fscanf(fd, \"%h %d\", boot_bytes, requested_cycles);")
    add("    if (scan_count != 2) begin")
    add("      $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=missing-header\");")
    add("      $finish;")
    add("    end")
    add("    request_id = boot_bytes[31:0];")
    add("    if (requested_cycles > MAX_CYCLES || requested_cycles < 1) begin")
    add("      $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=cycle-bound\");")
    add("      $finish;")
    add("    end")
    add("    scan_count = $fscanf(fd, \"E %d\", event_count);")
    add("    if (scan_count != 1 || event_count < 0 || event_count > MAX_EVENTS) begin")
    add("      $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=missing-event-plan\");")
    add("      $finish;")
    add("    end")
    add("    for (cycle_index = 0; cycle_index < event_count; cycle_index = cycle_index + 1) "
        "begin")
    add("      scan_count = $fscanf(fd, \"%d %d %h\", event_slot[cycle_index], "
        "event_cycle[cycle_index], event_value[cycle_index]);")
    add("      if (scan_count != 3) begin")
    add("        $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=short-event-plan\");")
    add("        $finish;")
    add("      end")
    add("    end")
    add("    for (cycle_index = 0; cycle_index < event_count; cycle_index = cycle_index + 1) "
        "begin")
    add("      if (event_slot[cycle_index] < 0 || event_slot[cycle_index] >= EVENT_SLOTS) begin")
    add("        $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=event-slot\");")
    add("        $finish;")
    add("      end")
    add("    end")
    add("    // Sort the event plan by cycle so the runner can apply it in order.")
    add("    begin : sort_events")
    add("      integer i; integer j; integer slot_tmp; integer cycle_tmp; logic [63:0] value_tmp;")
    add("      for (i = 0; i < event_count; i = i + 1)")
    add("        for (j = i + 1; j < event_count; j = j + 1)")
    add("          if (event_cycle[j] < event_cycle[i]) begin")
    add("            slot_tmp = event_slot[i]; cycle_tmp = event_cycle[i]; "
        "value_tmp = event_value[i];")
    add("            event_slot[i] = event_slot[j]; event_cycle[i] = event_cycle[j]; "
        "event_value[i] = event_value[j];")
    add("            event_slot[j] = slot_tmp; event_cycle[j] = cycle_tmp; "
        "event_value[j] = value_tmp;")
    add("          end")
    add("    end")
    add("    // The peer plan: one payload-carrying entry per declared stimulus event.")
    add("    scan_count = $fscanf(fd, \"P %d\", peer_event_count);")
    add("    if (scan_count != 1 || peer_event_count < 0 "
        "|| peer_event_count > PEER_EVENTS_MAX) begin")
    add("      $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=missing-peer-plan\");")
    add("      $finish;")
    add("    end")
    add("    for (cycle_index = 0; cycle_index < peer_event_count; cycle_index = cycle_index + 1) "
        "begin")
    add("      scan_count = $fscanf(fd, \"%d %d %h\", peer_event_slot[cycle_index], "
        "peer_event_cycle[cycle_index], peer_event_value[cycle_index]);")
    add("      if (scan_count != 3) begin")
    add("        $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=short-peer-plan\");")
    add("        $finish;")
    add("      end")
    add("      if (peer_event_slot[cycle_index] < 0 "
        "|| peer_event_slot[cycle_index] >= PEER_SLOTS) begin")
    add("        $display(\"MYFUZZ_SOC_RUN status=PROTOCOL_ERROR reason=peer-slot\");")
    add("        $finish;")
    add("      end")
    add("    end")
    add("    begin : sort_peer_events")
    add("      integer i; integer j; integer slot_tmp; integer cycle_tmp; logic [63:0] value_tmp;")
    add("      for (i = 0; i < peer_event_count; i = i + 1)")
    add("        for (j = i + 1; j < peer_event_count; j = j + 1)")
    add("          if (peer_event_cycle[j] < peer_event_cycle[i]) begin")
    add("            slot_tmp = peer_event_slot[i]; cycle_tmp = peer_event_cycle[i]; "
        "value_tmp = peer_event_value[i];")
    add("            peer_event_slot[i] = peer_event_slot[j]; "
        "peer_event_cycle[i] = peer_event_cycle[j]; peer_event_value[i] = peer_event_value[j];")
    add("            peer_event_slot[j] = slot_tmp; peer_event_cycle[j] = cycle_tmp; "
        "peer_event_value[j] = value_tmp;")
    add("          end")
    add("    end")
    add("")
    if image_plan is not None:
        add("    // Buffer the whole record before reset: the candidate image is a")
        add("    // pre-release overlay, so the CPU must still be held while it is placed,")
        add("    // and the per-cycle loop below replays the same buffered words.")
        add("    for (cycle_index = 0; cycle_index < requested_cycles; "
            "cycle_index = cycle_index + 1) begin")
        add("      scan_count = $fscanf(fd, \"%h\", raw_word);")
        add("      if (scan_count != 1) raw_word = '0;")
        add("      sample_words[cycle_index] = raw_word;")
        add("    end")
    add("    rst_ni = 1'b0;")
    add("    for (cycle_index = 0; cycle_index < RESET_CYCLES; cycle_index = cycle_index + 1) ")
    add("      @(posedge clk_i);")
    if image_plan is not None:
        # Reset is deasserted before the overlay is written so that the reset
        # window below is a real assertion, not a level that was already low.
        add("    rst_ni = 1'b1;")
        add("    repeat (2) @(posedge clk_i);")
    else:
        # Every build releases the CPU once, here.  The image-plan branch above
        # only defers the release so the candidates are placed while the CPU is
        # still held; the release itself is below and is unconditional.
        add("    rst_ni = 1'b1;")
    if image_plan is not None:
        add("    // Place every offered candidate slot into the memory model's own")
        add("    // initial_memory and read it back through the model's array.  This is the")
        add("    // pre-CPU-release half of the input ABI: the applied raw word is the only")
        add("    // thing that decides what is placed, and the reset assertion below is what")
        add("    // makes the placement the memory the CPU will fetch from.")
        for slot in image_plan.candidates.slots():
            kind = slot.kind
            prefix = slot.prefix
            value_name = "data" if kind == "instruction" else "value"
            instance, base, size = image_targets[str(slot.region_id)]
            offer = slot.segment("offer")
            address = slot.segment("address")
            payload = slot.segment(value_name)
            be = slot.segment("be")
            add(f"    for (cycle_index = 0; cycle_index < requested_cycles; "
                f"cycle_index = cycle_index + 1) begin")
            add(f"      if (sample_words[cycle_index][{offer.raw_hi}:{offer.raw_lo}]) begin")
            add(f"        image_address = sample_words[cycle_index]"
                f"[{address.raw_hi}:{address.raw_lo}];")
            add(f"        image_value = sample_words[cycle_index]"
                f"[{payload.raw_hi}:{payload.raw_lo}];")
            add(f"        image_be = sample_words[cycle_index][{be.raw_hi}:{be.raw_lo}];")
            add("        for (image_lane = 0; image_lane < 4; image_lane = image_lane + 1) begin")
            add("          if (image_be[image_lane]) begin")
            add(f"            if ({{1'b0,image_address}} + image_lane < 33'd{base} || "
                f"{{1'b0,image_address}} + image_lane >= 33'd{base + size}) begin")
            add('              $display("MYFUZZ_IMAGE_ERROR slot=%s reason=address", '
                f'"{prefix}");')
            add("            end else begin")
            add(f"              dut.{instance}.initial_memory[image_address - 32'd{base} "
                "+ image_lane] = image_value[image_lane*8 +: 8];")
            add("            end")
            add("          end")
            add("        end")
            add(f"        placed_{prefix}_address = image_address;")
            add(f"        placed_{prefix}_be = image_be;")
            add(f"        placed_{prefix}_kind = 1'b1;")
            add("      end")
            add("    end")
        # The overlay becomes the CPU's view only when the memory model refreshes
        # its working array from ``initial_memory``, which the model does on the
        # *falling* edge of reset.  Asserting reset once more copies the placed
        # candidates in; the release on the next line is the CPU start.  Place,
        # refresh and release therefore all happen before the first executed
        # cycle, which is what makes this a pre-release image load rather than a
        # post-release memory write.
        add("    rst_ni = 1'b0;")
        add("    repeat (2) @(posedge clk_i);")
        add("    rst_ni = 1'b1;")
        for slot in image_plan.candidates.slots():
            kind = slot.kind
            prefix = slot.prefix
            instance, base, size = image_targets[str(slot.region_id)]
            add(f"    if (placed_{prefix}_kind) begin")
            add(f"      image_readback = '0;")
            add("      for (image_lane = 0; image_lane < 4; image_lane = image_lane + 1) begin")
            add(f"        if (placed_{prefix}_be[image_lane]) "
                f"image_readback[image_lane*8 +: 8] = "
                f"dut.{instance}.memory[placed_{prefix}_address - 32'd{base} + image_lane];")
            add("      end")
            add(f'      $display("MYFUZZ_IMAGE kind={kind} addr=%08h value=%08h '
                f'reset=%0b slot={prefix}", placed_{prefix}_address, image_readback, rst_ni);')
            add("    end")
    add("    cycles = 0;")
    add("    accepted = 0; completed = 0; errors = 0;")
    add("    for (cycle_index = 0; cycle_index < requested_cycles; cycle_index = cycle_index + 1) "
        "begin")
    if image_plan is None:
        add("      scan_count = $fscanf(fd, \"%h\", raw_word);")
        add("      if (scan_count != 1) raw_word = '0;")
    else:
        add("      raw_word = sample_words[cycle_index];")
    add("      raw_bits = raw_word[RAW_WIDTH-1:0];")
    add("      @(posedge clk_i);")
    add("      cycles = cycles + 1;")
    for slot in slots:  # one line per applied-value change, so a run is replayable
        signal = f"obs_{slot['name']}__applied"
        add(f"      if ({signal} !== prev_applied_{slot['name']}) begin")
        add(f"        $display(\"MYFUZZ_APPLIED cycle=%0d port={slot['name']} value=%0h\", "
            f"cycles, {signal});")
        add(f"        prev_applied_{slot['name']} = {signal};")
        add("      end")
    add("    end")
    add("    $display(\"MYFUZZ_SOC_RUN status=OK cycles=%0d request=%0d\", cycles, request_id);")
    for index, item in enumerate(spi_wires):
        add(f"    $display(\"MYFUZZ_PEER_WIRE_SUMMARY instance={item['instance_id']} "
            f"count=%0d truncated=%0d\", peer_wire_count_{index}, "
            f"peer_wire_truncated_{index});")
    for index, item in enumerate(observations):
        add(f"    $display(\"MYFUZZ_OBS {item['name']}=%0h\", obs_{item['name']});")
    for index, item in enumerate(fabric_sources):
        add(f"    $display(\"MYFUZZ_OBS fabric_source_responses__{item['source_id']}=%0h\", "
            f"source_responses_{index});")
    if fabric_sources:
        # The arbiter's own protocol-error flag: a completion attributed to the
        # wrong source or transaction id is a DUT-visible anomaly, not a timing
        # detail, so every run reports it.
        add("    $display(\"MYFUZZ_OBS fabric_protocol_error=%0h\", "
            "dut.fabric_protocol_error);")
    add("    $display(\"MYFUZZ_OBS fabric_responses=%0h\", rsp_total);")
    add("    $display(\"MYFUZZ_REQ_SUMMARY total=%0d truncated=%0d\", "
        "req_total, req_total > REQ_CAPTURE);")
    add("    for (cycle_index = 0; cycle_index < REQ_CAPTURE "
        "&& cycle_index < req_total; cycle_index = cycle_index + 1) begin")
    add("      code = (req_head - 1 - cycle_index + 2*REQ_CAPTURE) % REQ_CAPTURE;")
    add("      $display(\"MYFUZZ_REQ cycle=%0d addr=%0h write=1 wdata=%0h "
        "be=%0h source=%0h\", req_cycle[code], req_addr[code], "
        "req_wdata[code], req_be[code], req_source[code]);")
    add("    end")
    add("    for (cycle_index = 0; cycle_index < RSP_CAPTURE "
        "&& cycle_index < rsp_total; cycle_index = cycle_index + 1) begin")
    add("      // Most recent completion first; the sequence number orders them.")
    add("      code = (rsp_head - 1 - cycle_index + 2*RSP_CAPTURE) % RSP_CAPTURE;")
    add("      $display(\"MYFUZZ_RSP seq=%0d addr=%0h write=%0d rdata=%0h source=%0h\",")
    add("               rsp_seq[code], rsp_addr[code], rsp_write[code], "
        "rsp_rdata[code], rsp_source[code]);")
    add("    end")
    for item in synthetic_observations:
        add(f"    // {item['name']}: the synthetic master's own counter, read through the")
        add("    // hierarchy; it is internal state, not a top-level output.")
        add(f"    $display(\"MYFUZZ_OBS {item['name']}=%0h\", "
            f"dut.{item['cell']}.{item['port']});")
    for index, item in enumerate(memory):
        add(f"    for (cycle_index = 0; cycle_index < OBSERVED_WORDS; cycle_index = cycle_index + 1) "
            "begin")
        add(f"      read_memory_{index}(cycle_index*8, memory_value);")
        add(f"      $display(\"MYFUZZ_MEM {item['instance']}[%0d]=%0h\", cycle_index, "
            "memory_value);")
        add("    end")
    add("    $finish;")
    add("  end")
    add("endmodule")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def _component_build_options(plan: CompositionPlan, *,
                             base_dir: Path) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Include roots and defines every component's build context declares.

    A real CPU is a multi-file closure with its own include directories and
    macros; compiling the generated top without them fails with missing includes
    even though the source list is complete.  Both come from the profile's own
    declared build context, so nothing is inferred from a component name.
    """
    include_dirs: list[str] = []
    defines: list[tuple[str, str]] = []
    for instance in plan.instances:
        source = instance.profile.source
        root = (base_dir / source.source_root).resolve()
        for item in source.include_roots:
            candidate = (root / item).resolve()
            if candidate.is_dir() and candidate.as_posix() not in include_dirs:
                include_dirs.append(candidate.as_posix())
        settings = source.elaboration
        if settings is not None:
            for name, value in settings.defines:
                if (name, value) not in defines:
                    defines.append((name, value))
    return tuple(include_dirs), tuple(defines)


def _requires_boot_image(plan: CompositionPlan) -> bool:
    """True when any memory region is rendered with LOAD_IMAGE enabled."""
    for region in plan.spec.get("memory_regions", []):
        if str(region.get("initialization_policy")) in ("preload", "rom"):
            return True
    return False


def _serialize_events(events: Sequence[ExternalEvent]) -> str:
    return "\n".join(f"{item.slot} {item.cycle} {item.value}" for item in events)


def build_profile_runtime(plan: CompositionPlan, *, output_dir: Path, base_dir: Path,
                          top_text: str, sources: Sequence[str],
                          boot_image: Path | None = None,
                          timeout_seconds: int = 1800,
                          verilator: str | None = None,
                          spi_wire_contracts: Mapping[str, object] | None = None,
                          image_plan: "ImagePlan | None" = None) -> RuntimeBuild:
    """Render the testbench, compile the SoC and return the runnable artifact."""
    if not isinstance(plan, CompositionPlan):
        _error("composition-plan-required")
    tool = verilator or shutil.which("verilator")
    if tool is None:
        _error("runtime-tool-missing")
    output = Path(output_dir)
    if output.exists() and any(output.iterdir()):
        _error(f"runtime-output-must-be-new:{output}")
    output.mkdir(parents=True, exist_ok=True)
    slots = _special_slots(plan) + _synthetic_slots(plan)
    externals = _external_inputs(plan)
    peer_slot_records = [dict(item) for item in _peer_slots(plan)]
    # The independent oracle records the exact peer source identity consumed by
    # this build.  A missing source is retained as ``None`` and remains a build
    # error in the normal source-closure path; the field is not fabricated.
    for item in peer_slot_records:
        source = Path(str(item.get("peer_source", "")))
        source_path = source if source.is_absolute() else Path(base_dir) / source
        if source_path.is_file():
            item["peer_source_hash"] = (
                "sha256:" + hashlib.sha256(source_path.read_bytes()).hexdigest())
        else:
            item["peer_source_hash"] = None
    peer_slots = tuple(peer_slot_records)
    peer_observations = _peer_observations(plan)
    peer_wires = _spi_wire_records(plan)
    cpu_data_sources = tuple(int(item["index"])
                             for item in plan.plan["fabric"]["sources"]
                             if str(item.get("kind")) == "cpu_data")
    contracts = dict(spi_wire_contracts or {})
    admitted_spi = {str(item["instance_id"]) for item in peer_wires}
    for instance_id, record in contracts.items():
        if instance_id not in admitted_spi or not isinstance(record, Mapping) or \
                not isinstance(record.get("txdata_address"), int) or \
                isinstance(record.get("txdata_address"), bool) or \
                int(record["txdata_address"]) < 0 or not str(record.get("basis", "")):
            _error(f"runtime-spi-wire-contract-invalid:{instance_id}")
    observations = _observations(plan)
    memory = _memory_slots(plan)
    required = _requires_boot_image(plan)
    if boot_image is None and required:
        # The memory model refuses to start without an image when a region
        # declares LOAD_IMAGE.  Writing an explicit empty image is honest: no
        # program is loaded, and the build record says so.
        boot_image = output / "no_program_loaded.hex"
        boot_image.write_text("00\n", encoding="utf-8")
        image_policy = "explicit_empty_image_no_program_loaded"
    elif boot_image is None:
        image_policy = "no_preloaded_region"
    else:
        image_policy = "external_image"
    plusargs = () if boot_image is None else (f"+riscv_boot_image={boot_image}",)
    if image_plan is not None and not isinstance(image_plan, ImagePlan):
        _error("runtime-image-plan-invalid")
    testbench = render_profile_testbench(plan, image_plan=image_plan)
    top_path = output / f"{TOP_MODULE}.sv"
    tb_path = output / "profile_tb.sv"
    top_path.write_text(top_text, encoding="utf-8")
    tb_path.write_text(testbench, encoding="utf-8")
    closure = [str(item) for item in sources]
    source_hashes = {}
    for item in closure:
        path = Path(item)
        resolved = path if path.is_absolute() else base_dir / path
        if not resolved.is_file():
            _error(f"runtime-source-missing:{item}")
        source_hashes[item] = "sha256:" + hashlib.sha256(resolved.read_bytes()).hexdigest()
    board = output / "sources.f"
    board.write_text("".join(f"{item}\n" for item in closure), encoding="utf-8")
    include_dirs, defines = _component_build_options(plan, base_dir=Path(base_dir))
    command = [tool, "--binary", "--timing", "-Wno-fatal", "-Wno-lint",
               "--top-module", TESTBENCH_MODULE,
               "-o", "myfuzz_profile_sim",
               "--Mdir", (output / "obj_dir").as_posix(),
               *(f"-I{item}" for item in include_dirs),
               *(f"-D{name}={value}" for name, value in defines),
               tb_path.as_posix(), top_path.as_posix(),
               *((base_dir / item).as_posix() if not Path(item).is_absolute() else item
                 for item in closure)]
    # The compiler output directory is emptied first: a failed compile that left
    # an older executable behind would otherwise be reported as a successful
    # build, and every run after it would silently execute the stale binary.
    executable = output / "obj_dir" / "myfuzz_profile_sim"
    if executable.is_file():
        executable.unlink()
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False,
                                timeout=timeout_seconds, cwd=base_dir.as_posix())
    except subprocess.TimeoutExpired as error:
        raise SocRuntimeError(f"runtime-build-timeout:{timeout_seconds}s") from error
    diagnostics = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise SocRuntimeError(f"runtime-build-failed:{diagnostics.strip()[-4000:]}")
    if not executable.is_file():
        raise SocRuntimeError("runtime-executable-missing")
    warnings = len([line for line in diagnostics.splitlines() if "%Warning" in line])
    payload = {
        "schema_version": RUNTIME_SCHEMA,
        "plan_hash": plan.plan_hash,
        "layout_hash": plan.raw_layout.get("layout_hash"),
        "top": hashlib.sha256(top_text.encode("utf-8")).hexdigest(),
        "testbench": hashlib.sha256(testbench.encode("utf-8")).hexdigest(),
        "sources": list(closure),
        "source_hashes": dict(sorted(source_hashes.items())),
        "include_dirs": list(include_dirs),
        "defines": [list(item) for item in defines],
        "boot_image": None if boot_image is None else
        hashlib.sha256(Path(boot_image).read_bytes()).hexdigest(),
        "boot_image_policy": image_policy,
        # The peer stimulus ABI and the observed peer outputs are part of what
        # the binary consumes and reports, so they identify the build.
        "peer_slots": [dict(item) for item in peer_slots],
        "peer_observations": [dict(item) for item in peer_observations],
        "peer_wires": [dict(item) for item in peer_wires],
        "spi_wire_contracts": contracts,
        "cpu_data_sources": list(cpu_data_sources),
    }
    return RuntimeBuild(
        output_dir=output, top_path=top_path, testbench_path=tb_path, executable=executable,
        sources=tuple(closure), raw_width=_testbench_raw_width(plan, image_plan),
        slots=slots, observations=observations, boot_image=boot_image,
        boot_image_policy=image_policy,
        build_hash="sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        warnings=warnings, peer_slots=peer_slots, peer_observations=peer_observations,
        peer_wires=peer_wires, spi_wire_contracts=contracts,
        cpu_data_sources=cpu_data_sources, source_hashes=source_hashes)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def validate_peer_events(build: RuntimeBuild, sample: RuntimeSample) -> None:
    """Refuse a peer stimulus plan this build cannot honour.

    A slot the plan never declared, a payload wider than the slot carries, or
    two pulse events closer than the peer model's declared minimum spacing are
    all refused here with a located reason: a peer that would drop the byte (or
    sample a half-driven line) must never be reported as a passing test.
    """
    # A build that declares no peer slots (an older generated build, or a caller's
    # own record) can only be driven with an empty peer plan.
    slots = tuple(getattr(build, "peer_slots", ()) or ())
    by_index = {int(item["index"]): item for item in slots}
    by_slot = {str(item["slot"]): item for item in slots}
    for item in sample.peer_events:
        record = by_index.get(int(item.slot))
        if record is None:
            _error(f"peer-event-unknown-slot:{item.slot}: the plan declares "
                   f"{sorted(by_index)}")
        if item.payload >= (1 << int(record["width"])):
            _error(f"peer-event-payload-out-of-range:{record['slot']}:{item.payload}"
                   f"!<{1 << int(record['width'])}")
    # The plan's own declared spacing: two events on one pulse slot that arrive
    # closer than the peer's minimum would be dropped by the peer's handshake.
    for record in slots:
        if str(record["kind"]) != "pulse_byte":
            continue
        cycles = sorted(item.cycle for item in sample.peer_events
                        if int(item.slot) == int(record["index"]))
        minimum = int(record["minimum_gap_cycles"])
        for earlier, later in zip(cycles, cycles[1:]):
            if later - earlier < minimum:
                _error(f"peer-event-too-close:{record['slot']}:{later}-{earlier}"
                       f"<{minimum} ({by_slot[str(record['slot'])]['instance_id']})")


def run_sample(build: RuntimeBuild, sample: RuntimeSample, *,
               timeout_seconds: int = 600) -> RunResult:
    """Run one sample and return the counters, observations and the trace."""
    validate_peer_events(build, sample)
    try:
        command = ["nice", "-n15", Path(build.executable).resolve().as_posix()]
        if build.boot_image is not None:
            # Resolve against the build directory: the recorded path may be
            # relative to the caller's working directory.
            image = Path(build.boot_image)
            if not image.is_absolute():
                image = (build.output_dir / image.name).resolve()
            command.append(f"+riscv_boot_image={image}")
        result = subprocess.run(
            command,
            input=sample.payload(), capture_output=True, text=True, check=False,
            timeout=timeout_seconds, cwd=build.output_dir.as_posix())
    except subprocess.TimeoutExpired as error:
        return RunResult(request_id=sample.request_id, cycles=0, status="timeout",
                         counters={}, observations={}, trace=(), applied=(), stdout="",
                         stderr="", reason=f"run-timeout:{timeout_seconds}s")
    stdout = result.stdout or ""
    observations: dict[str, int] = {}
    memory: dict[str, int] = {}
    applied: list[dict[str, int]] = []
    peer_applied: list[dict[str, object]] = []
    peer_wire_trace: list[dict[str, object]] = []
    peer_wire_status: list[dict[str, object]] = []
    responses: list[dict[str, int]] = []
    requests: list[dict[str, int]] = []
    requests_truncated = False
    image_placements: list[dict[str, object]] = []
    image_errors: list[dict[str, object]] = []
    status = "unknown"
    cycles = 0
    reason = ""
    for line in stdout.splitlines():
        if line.startswith("MYFUZZ_OBS "):
            name, _, value = line[len("MYFUZZ_OBS "):].partition("=")
            try:
                observations[name.strip()] = int(value.strip(), 16)
            except ValueError:
                continue
        elif line.startswith("MYFUZZ_APPLIED "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                applied.append({"cycle": int(fields["cycle"]),
                                "port": str(fields["port"]),
                                "value": int(fields["value"], 16)})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_PEER_APPLIED "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                peer_applied.append({"cycle": int(fields["cycle"]),
                                     "instance": str(fields["instance"]),
                                     "slot": str(fields["slot"]),
                                     "value": int(fields["value"], 16)})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_PEER_WIRE_SUMMARY "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                peer_wire_status.append({"instance_id": fields["instance"],
                                         "count": int(fields["count"]),
                                         "truncated": bool(int(fields["truncated"]))})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_PEER_WIRE "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                peer_wire_trace.append({"instance_id": fields["instance"],
                                        "cycle": int(fields["cycle"]),
                                        **{role: fields[role] for role in
                                           ("sck", "cs", "mosi", "miso")}})
            except KeyError:
                continue
        elif line.startswith("MYFUZZ_IMAGE_ERROR "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            image_errors.append({"slot": str(fields.get("slot", "")),
                                 "reason": str(fields.get("reason", ""))})
        elif line.startswith("MYFUZZ_IMAGE "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                image_placements.append({
                    "kind": str(fields["kind"]), "slot": str(fields["slot"]),
                    "addr": int(fields["addr"], 16),
                    "readback": int(fields["value"], 16),
                    "reset_held": bool(int(fields["reset"]))})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_RSP "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                responses.append({"seq": int(fields["seq"]),
                                  "addr": int(fields["addr"], 16),
                                  "write": int(fields["write"]),
                                  "rdata": int(fields["rdata"], 16),
                                  "source": int(fields["source"], 16)})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_REQ_SUMMARY "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                requests_truncated = bool(int(fields["truncated"]))
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_REQ "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            try:
                requests.append({"cycle": int(fields["cycle"]),
                                 "addr": int(fields["addr"], 16),
                                 "write": int(fields["write"]),
                                 "wdata": int(fields["wdata"], 16),
                                 "be": int(fields["be"], 16),
                                 "source": int(fields["source"], 16)})
            except (KeyError, ValueError):
                continue
        elif line.startswith("MYFUZZ_MEM "):
            name, _, value = line[len("MYFUZZ_MEM "):].partition("=")
            try:
                memory[name.strip()] = int(value.strip(), 16)
            except ValueError:
                continue
        elif line.startswith("MYFUZZ_SOC_RUN "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            status = fields.get("status", "unknown")
            reason = fields.get("reason", "")
            if "cycles" in fields:
                try:
                    cycles = int(fields["cycles"])
                except ValueError:
                    cycles = 0
    if result.returncode != 0 and status == "OK":
        status = "simulator-error"
        reason = f"returncode:{result.returncode}"
    counters = {
        "cycles": cycles,
        "observations": len(observations),
        "memory_words": len(memory),
        "applied_changes": len(applied),
        "peer_applied_events": len(peer_applied),
        "fabric_responses": len(responses),
    }
    # The plan's declared peer counters, keyed by peer and port: this is the
    # compact evidence a replay is compared against, and it is read from the
    # peer's own top-level outputs, never from the plan's expectation.
    for item in tuple(getattr(build, "peer_observations", ()) or ()):
        if not item.get("counter"):
            continue
        name = str(item["name"])
        if name in observations:
            counters[f"peer.{item['instance_id']}.{item['peer_port']}"] = \
                int(observations[name])
    all_observations = dict(observations)
    all_observations.update(memory)
    # One trace entry per applied cycle: the raw value and the driven fuzz ports.
    trace: list[dict[str, int]] = []
    for index, value in enumerate(sample.raw):
        entry = {"cycle": index, "raw": value}
        for slot in build.slots:
            width = int(slot["width"])
            entry[str(slot["name"])] = (value >> int(slot["raw_lo"])) & ((1 << width) - 1)
        trace.append(entry)
    run_result = RunResult(
        request_id=sample.request_id, cycles=cycles, status=status,
        counters=counters, observations=all_observations,
        trace=tuple(trace), applied=tuple(applied), stdout=stdout,
        stderr=result.stderr or "", reason=reason,
        peer_applied=tuple(sorted(peer_applied,
                                  key=lambda item: (int(item["cycle"]),
                                                    str(item["slot"]))
                                  )),
        responses=tuple(sorted(responses,
                               key=lambda item: int(item["seq"]))),
        peer_wire_trace=tuple(peer_wire_trace),
        peer_wire_status=tuple(peer_wire_status),
        requests=tuple(sorted(requests, key=lambda item: int(item["cycle"]))),
        requests_truncated=requests_truncated,
        image_placements=tuple(image_placements),
        image_errors=tuple(image_errors))
    if tuple(getattr(build, "peer_slots", ()) or ()):
        # Import locally so the pure oracle stays independent from the runtime
        # dataclasses and can be used by static evidence tests on its own.
        from .soc_peer_oracle import audit_peer_run
        run_result = replace(run_result,
                             peer_oracle=audit_peer_run(build, sample, run_result))
    return run_result


def run_samples(build: RuntimeBuild, samples: Sequence[RuntimeSample], *,
                timeout_seconds: int = 600) -> tuple[RunResult, ...]:
    return tuple(run_sample(build, sample, timeout_seconds=timeout_seconds)
                 for sample in samples)


def runtime_document(build: RuntimeBuild, results: Sequence[RunResult], *,
                     provenance: Mapping[str, object] | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": RUNTIME_SCHEMA,
        "build": build.document(),
        "runs": [item.document() for item in results],
        "summary": {
            "runs": len(results),
            "ok": sum(1 for item in results if item.status == "OK"),
            "failed": sum(1 for item in results if item.status not in ("OK",)),
        },
    }
    if provenance is not None:
        document["provenance"] = dict(provenance)
    return document


def run_sample_with_policy(build: RuntimeBuild, sample: RuntimeSample, *, policy: object,
                           timeout_seconds: int = 600) -> RunResult:
    """Validate identity and apply sample constraints before simulator execution.

    Only environment-owned raw input fields are projected. Events and request
    identity are preserved, and run_sample's trace describes the projected raw
    inputs. This does not implement online rules or modify any DUT output.

    ``RuntimeBuild`` has no ``layout_hash`` field, so the build's own identity is
    read from the generated testbench that ``build_profile_runtime`` wrote:
    :func:`render_profile_testbench` stamps it with ``// plan:`` and
    ``// raw-input layout:`` in its header.  Raises :class:`SocRuntimeError` when
    the policy carries no ``policy_hash``, when its layout or plan hash is
    missing, when either differs from that record, or when the record itself
    cannot be read: a mismatch is refused instead of being run silently.
    """
    def recorded_identity() -> tuple[str, str]:
        path = Path(build.testbench_path)
        if not path.is_file():
            _error(f"runtime-build-record-unreadable:{path}")
        plan_hash = ""
        layout_hash = ""
        for line in path.read_text(encoding="utf-8").splitlines():
            if not plan_hash and line.startswith("// plan: "):
                plan_hash = line[len("// plan: "):].strip()
            elif not layout_hash and line.startswith("// raw-input layout: "):
                layout_hash = line[len("// raw-input layout: "):].strip()
        if not plan_hash or not layout_hash:
            _error(f"runtime-build-record-without-identity:{path}")
        return plan_hash, layout_hash

    policy_hash = getattr(policy, "policy_hash", "")
    if not isinstance(policy_hash, str) or not policy_hash:
        _error("policy-hash-missing: the supplied policy carries no policy_hash")
    recorded_plan, recorded_layout = recorded_identity()
    policy_layout = str(getattr(policy, "layout_hash", "") or "")
    if not policy_layout:
        _error("policy-layout-hash-missing: the supplied policy carries no layout_hash")
    if policy_layout != recorded_layout:
        _error(f"policy-layout-mismatch:policy={policy_layout}:build={recorded_layout}")
    policy_plan = str(getattr(policy, "plan_hash", "") or "")
    if policy_plan != recorded_plan:
        _error(f"policy-plan-mismatch:policy={policy_plan}:build={recorded_plan}")
    from .input_constraints import project_sample_values
    projected = RuntimeSample(sample.request_id, tuple(
        project_sample_values(policy, raw, raw_width=build.raw_width)
        for raw in sample.raw), sample.events, sample.peer_events)
    return run_sample(build, projected, timeout_seconds=timeout_seconds)


__all__ = [
    "CLOCK_HALF_PERIOD",
    "MAX_CYCLES",
    "MAX_EVENTS",
    "MAX_OBSERVED_WORDS",
    "MAX_PEER_EVENTS",
    "MAX_RESPONSE_CAPTURE",
    "RESET_CYCLES",
    "RUNTIME_SCHEMA",
    "TESTBENCH_MODULE",
    "ExternalEvent",
    "PeerStimulusEvent",
    "RunResult",
    "RuntimeBuild",
    "RuntimeSample",
    "SocRuntimeError",
    "build_profile_runtime",
    "render_profile_testbench",
    "run_sample",
    "run_sample_with_policy",
    "run_samples",
    "runtime_document",
    "validate_peer_events",
]
