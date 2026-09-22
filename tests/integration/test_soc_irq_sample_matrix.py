"""Multi-sample interrupt matrix on one real two-source SoC: per-source evidence.

Why this module exists
----------------------
``tests/integration/test_soc_interrupt_lifecycle.py`` closes the interrupt loop
for one generated sample and ``tests/integration/test_soc_multi_latch_fault.py``
shows a connection fault dropping one source, but both decide *closure* from the
generated program's aggregate ledger (``interrupt_completions`` /
``all_sources_closed``).  The 2026-09-21 evidence review recorded that
``all_sources_closed`` can read 1 merely because two completions happened, so it
proves nothing about *which* physical source the controller handed out: with two
sources on one SoC an id permutation can still complete twice.

This module therefore drives one real Ibex + two novagpio SoC through four
distinct raw samples -- simultaneous arrival, staggered arrival, arrival while
one source is masked, and a condition already present when reset is released --
and asserts, per declared source, from the CPU's own transactions:

* the external cause: the raw special input the environment really applied is
  read back from ``RunResult.observations`` (``<instance>__pin_mode_i__applied``),
  and a pin-carried arrival is additionally evidenced by the source's own status
  register read over the bus before its declared clear;
* the controller's pending bit for **that** source before the claim;
* the claim id the CPU read -- recorded by the handler for the first entry, and
  for later entries the id the shared handler dispatched on (the value it read
  from CLAIM) plus the per-id dispatch the program document declares;
* the profile-declared clear really emptying **that** source's status register;
* COMPLETE retiring **that** source's pending bit.

``all_sources_closed`` is deliberately never asserted here; the aggregate count
is at most a cross-check that the ledger advanced, never the proof.

Where the evidence comes from (measured, not assumed)
-----------------------------------------------------
* ``RunResult.requests`` is the runtime's **write** capture (256 entries deep,
  complete for these runs).  The generated handler stores every value it read
  into the RAM report block, so one shared-handler entry is reconstructed as one
  record carrying the controller's pending word, the claim id, the peripheral
  status before and after the declared clear, the id written to COMPLETE and the
  pending word after COMPLETE, each with the cycle it was stored at.
* the fabric response capture is a 32-entry ring (``MAX_RESPONSE_CAPTURE``) and
  an interrupt entry contains instruction fetches between its MMIO accesses, so
  the ring cannot hold a whole entry.  Peripheral read *addresses* therefore come
  from the plan's per-id dispatch (asserted by the pure tests) while every
  *value* is the CPU's own recorded store.
* the runtime exports an applied-value observation only for the plan's declared
  special inputs; an external event pin driven by the event plan has **no**
  readback, so a pin-carried arrival is evidenced by its effect rather than by a
  driven-value record.
* the report block guards the first entry's peripheral-status fields
  (``cause_before_clear`` / ``status_raw_before_clear`` / ``pending_before_claim``):
  a second entry does not rewrite them.  The staggered sample is therefore
  ordered so the **higher** source id is served first, which gives every declared
  source a directly recorded status/clear in at least one sample; the second
  entry's clear is asserted from the controller's own post-COMPLETE pending word,
  which for a level source is the sampled value of that source's ``irq_o``.
* the profile runtime asserts reset for ``RESET_CYCLES`` posedges **before** it
  consumes any raw word or applies a post-release event, so "an event during
  reset" is only expressible as an event at cycle 0: the runtime applies it at
  the first reset edge and the pin is active for the whole reset window.

The tests are opt-in through ``MYFUZZ_SOC_REAL=1``.  When the flag is set
nothing skips: a missing Verilator, a missing profile or a render/build failure
is a *failure* naming that exact reason.  The four samples share one build, so a
behavioural difference can never come from a different executable.
"""
from __future__ import annotations

import json
import os
import shutil
import time
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_boot_program import (
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RESET_CYCLES,
    ExternalEvent,
    RunResult,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    render_profile_testbench,
    run_sample,
)

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"

#: One sample window for every case.  The generated programs schedule their
#: trigger around cycles 2048..4096 and a two-source SoC lengthens every
#: instruction fetch, so the window has to outlast the service by a wide margin;
#: it stays far inside the runtime's own MAX_CYCLES (65536).
CYCLES = 20000

RAM_BASE = 0x8000_0000

#: Raw special-input values used by the matrix.  The composition's frozen raw
#: layout is six bits: ``gpio0.pin_mode_i`` in bits [2:0] and ``gpio1.pin_mode_i``
#: in bits [5:3] (``novagpio.sv`` computes ``sampled = gpio_in_i ^ pin_mode_i``),
#: so a raw word is also a way to change a source's sampled pin vector.
SIMULTANEOUS_RAW = 0b000_000
STAGGERED_GPIO1_MODE = 0b010
MASKED_GPIO0_MODE = 0b000
MASKED_GPIO1_MODE = 0b111
RESET_GPIO0_MODE = 0b100
RESET_GPIO1_MODE = 0b001

#: The staggered sample's raw step cycle.  The special-input driver registers the
#: raw value it is offered, so the mode reaches the component one edge after the
#: raw word does (``soc_special_input_driver.sv``: ``value_q <= raw_i``).
STAGGERED_RAW_CYCLE = 2048


# ---------------------------------------------------------------------------
# case table
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MatrixCase:
    """One raw sample of the matrix: its stimulus, and what must be observed."""

    name: str
    program_key: str
    purpose: str
    #: ``(from_cycle, raw_word)`` steps; the raw word of a cycle is the value of
    #: the last step that starts at or before it.
    raw_steps: tuple[tuple[int, int], ...]
    #: The pin_mode value this sample offers each declared instance, which is what
    #: the run's applied-value readback has to show.
    modes: Mapping[str, int]
    events: tuple[ExternalEvent, ...]
    #: The declared source ids that must be claimed, in service order.
    claims: tuple[int, ...]
    #: Declared source id -> the cycle its condition appears in.
    arrivals: Mapping[int, int]
    #: Declared source ids that must never be claimed in this sample.
    unclaimed: tuple[int, ...] = ()

    def raw(self, cycles: int = CYCLES) -> tuple[int, ...]:
        """The per-cycle raw word stream this sample offers."""
        words: list[int] = []
        for cycle in range(cycles):
            word = 0
            for from_cycle, value in self.raw_steps:
                if cycle >= from_cycle:
                    word = value
            words.append(word)
        return tuple(words)


def declared_pin_plan(program) -> dict[str, dict[str, int]]:
    """The program's declared per-pin event pairs, keyed by the runtime slot name.

    The generated trigger plan drives each declared external input low first and
    all-ones afterwards, so a pair is one low event and one high event; both are
    read back from the program's own document instead of being hard-coded.
    """
    pins: dict[str, dict[str, int]] = {}
    for item in program.document["trigger"]["events"]:
        entry = pins.setdefault(str(item["name"]), {"slot": int(item["slot"])})
        value = int(item["value"])
        if value == 0:
            entry["low_cycle"] = int(item["cycle"])
            entry["low_value"] = value
        else:
            entry["high_cycle"] = int(item["cycle"])
            entry["high_value"] = value
    return pins


def matrix_cases(plan, programs: Mapping[str, object]) -> tuple[MatrixCase, ...]:
    """The four samples, derived from the plan's pins and the programs' own plans.

    Every case is a different raw sample *and* a different stimulus plan:

    * ``simultaneous``   - both declared pins change in the same cycle;
    * ``staggered``      - the higher source id arrives first through its declared
      special input and the lower id arrives 1024 cycles later on its pin;
    * ``masked``         - the program enables only the first source, and the second
      one arrives through its special input while the controller cannot claim it;
    * ``reset_boundary`` - both pins are already active during the reset window, so
      the condition exists from the first sampled edge after release.
    """
    sources = {int(item["source_id"]): str(item["instance_id"])
               for item in plan.interrupt_document["sources"]}
    multi = declared_pin_plan(programs["multi"])
    staggered = declared_pin_plan(programs["staggered"])
    single = declared_pin_plan(programs["single"])

    def pin(name: str, table: Mapping[str, Mapping[str, int]]) -> Mapping[str, int]:
        """The entry of ``table`` that belongs to the declared instance ``name``."""
        for key, entry in table.items():
            if key.startswith(name + "__"):
                return entry
        raise AssertionError(f"the program declares no external pin for {name}")

    first, second = sorted(sources)  # source ids are numbered in this order
    first_pin, second_pin = pin(sources[first], multi), pin(sources[second], multi)
    staggered_first = pin(sources[first], staggered)
    single_first = pin(sources[first], single)

    def pair(entry: Mapping[str, int], cycle: int | None = None) -> tuple[ExternalEvent, ...]:
        """One pin's declared low/high pair, optionally re-scheduled to ``cycle``."""
        low = int(entry["low_cycle"]) if cycle is None else cycle
        high = int(entry["high_cycle"]) if cycle is None else cycle
        return (ExternalEvent(slot=int(entry["slot"]), cycle=low,
                              value=int(entry["low_value"])),
                ExternalEvent(slot=int(entry["slot"]), cycle=high,
                              value=int(entry["high_value"])))

    return (
        MatrixCase(
            name="simultaneous",
            program_key="multi",
            purpose="both declared sources arrive in the same cycle; the controller "
                    "must pend both before the first claim and serve each id once",
            raw_steps=((0, SIMULTANEOUS_RAW),),
            modes={sources[first]: 0, sources[second]: 0},
            events=tuple(pair(first_pin)) + tuple(pair(second_pin)),
            claims=(first, second),
            arrivals={first: int(first_pin["high_cycle"]),
                      second: int(second_pin["high_cycle"])},
        ),
        MatrixCase(
            name="staggered",
            program_key="staggered",
            purpose="the higher source id arrives through its special input first and "
                    "the lower id arrives 1024 cycles later, so the two arrival "
                    "windows are distinct and the report's guarded first-entry "
                    "fields record the higher id's own status register",
            raw_steps=((0, SIMULTANEOUS_RAW),
                       (STAGGERED_RAW_CYCLE, STAGGERED_GPIO1_MODE << 3)),
            modes={sources[first]: 0, sources[second]: STAGGERED_GPIO1_MODE},
            # The higher id's declared pin pair is replaced by its special-input
            # arrival; the lower id's declared pair is applied unchanged.
            events=tuple(pair(staggered_first)),
            claims=(second, first),
            arrivals={second: STAGGERED_RAW_CYCLE,
                      first: int(staggered_first["high_cycle"])},
        ),
        MatrixCase(
            name="masked",
            program_key="single",
            purpose="the program enables only the first source (the single-source "
                    "lifecycle request); the second source arrives through its "
                    "special input, pends, and must never be claimed",
            raw_steps=((0, (MASKED_GPIO1_MODE << 3) | MASKED_GPIO0_MODE),),
            modes={sources[first]: MASKED_GPIO0_MODE, sources[second]: MASKED_GPIO1_MODE},
            # The masked source's arrival is a raw step, so the single-source
            # program's declared pin plan describes the enabled source exactly and
            # is applied unchanged.
            events=tuple(pair(single_first)),
            claims=(first,),
            arrivals={first: int(single_first["high_cycle"]), second: 0},
            unclaimed=(second,),
        ),
        MatrixCase(
            name="reset_boundary",
            program_key="multi",
            purpose="both pins are driven to their active level at cycle 0, inside the "
                    "reset window, so each source's status must latch on the first "
                    "sampled edge after release and both must be served before the "
                    "main flow stamps its prologue",
            raw_steps=((0, (RESET_GPIO1_MODE << 3) | RESET_GPIO0_MODE),),
            modes={sources[first]: RESET_GPIO0_MODE, sources[second]: RESET_GPIO1_MODE},
            # Same pins and values as the declared plan, re-scheduled into the
            # reset window: the runtime applies a cycle-0 event at the first reset
            # edge, so the level is already present when reset is released.
            events=(ExternalEvent(slot=int(first_pin["slot"]), cycle=0,
                                  value=int(first_pin["high_value"])),
                    ExternalEvent(slot=int(second_pin["slot"]), cycle=0,
                                  value=int(second_pin["high_value"]))),
            claims=(first, second),
            arrivals={first: 0, second: 0},
        ),
    )


# ---------------------------------------------------------------------------
# per-entry evidence extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClaimRound:
    """One shared-handler entry, rebuilt from the report-block stores it performed.

    ``values`` is keyed by the report field names the program's own layout
    declares.  A field the entry did not rewrite is simply absent, which is how
    the generated program distinguishes the first entry (whose peripheral-status
    fields it guards against a later entry overwriting them) from later ones.
    """

    start_cycle: int
    values: Mapping[str, int]

    @property
    def claim_id(self) -> int | None:
        """The id the CPU read from CLAIM, when this entry recorded it."""
        return self.values.get("claim_id")

    @property
    def complete_id(self) -> int:
        """The id the CPU wrote to COMPLETE (0 when the entry wrote none)."""
        return int(self.values.get("complete_id", 0))

    @property
    def complete_cycle(self) -> int:
        """The cycle of the COMPLETE write (0 when the entry wrote none)."""
        return int(self.values.get("complete_cycle", 0))

    def pending(self, source_id: int) -> int:
        """The controller's pending bit for one source before this entry's claim."""
        return int(self.values.get("pending_word_0_before_claim", 0)) & (1 << source_id)

    def pending_after(self, source_id: int) -> int:
        """The controller's pending bit for one source after this entry's COMPLETE."""
        return int(self.values.get("pending_word_after_complete", 0)) & (1 << source_id)


def claim_rounds(result: RunResult, *, layout: Mapping[str, int], report_address: int,
                 controller_base: int, complete_offset: int) -> tuple[ClaimRound, ...]:
    """One record per shared-handler entry, from the CPU's own write capture.

    A new entry starts at the store to ``handler_entries``; everything the entry
    stored into the report block afterwards belongs to it, and a write to the
    controller's COMPLETE register is the id that entry completed.  The write
    capture keeps 256 entries and a run performs well under 100, so no entry is
    lost; the report block in RAM only keeps the last value of each field, which
    is why the per-entry record is rebuilt from the capture instead of read back.
    """
    by_offset = {int(offset): str(name) for name, offset in layout.items()}
    entries: list[dict[str, int]] = []
    for request in sorted(result.requests, key=lambda item: int(item["cycle"])):
        address = int(request["addr"])
        if address == report_address + int(layout["handler_entries"]):
            entries.append({"handler_entries": int(request["wdata"]),
                            "start_cycle": int(request["cycle"])})
            continue
        if not entries:
            continue
        name = by_offset.get(address - report_address)
        if name is not None:
            entries[-1][name] = int(request["wdata"])
        if address == controller_base + complete_offset:
            entries[-1]["complete_id"] = int(request["wdata"])
            entries[-1]["complete_cycle"] = int(request["cycle"])
    return tuple(ClaimRound(start_cycle=int(item["start_cycle"]),
                            values={key: value for key, value in item.items()
                                    if key != "start_cycle"})
                 for item in entries)


class _FakeResult:
    """The one attribute ``claim_rounds`` needs, so the parser is testable purely."""

    def __init__(self, requests: Sequence[Mapping[str, int]]) -> None:
        self.requests = tuple(dict(item) for item in requests)


# ---------------------------------------------------------------------------
# plan building shared by the pure and the real tests
# ---------------------------------------------------------------------------


def request_document(reset_vector: int) -> dict:
    """The checked-in Ibex request with two novagpio instances at 0x4000_0000/1000.

    Two instances are the smallest composition in which the controller has to
    distinguish *which* physical source it serves: with one source an id-to-source
    mapping cannot be shown at all.  The ROM region is anchored at the CPU
    profile's own reset vector so the declared entry is the first byte of the
    region.
    """
    document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
    for region in document["memory"]:
        if region["region_id"] == "rom0":
            region["base"] = int(reset_vector)
    document["request_id"] = "ibex-two-novagpio-irq-sample-matrix"
    document["peripherals"] = [
        {"instance_id": "gpio0", "profile": GPIO_PROFILE, "parameters": {}},
        {"instance_id": "gpio1", "profile": GPIO_PROFILE, "parameters": {},
         "address": 0x4000_1000},
    ]
    return document


def profiles_for(document: Mapping[str, object]) -> dict:
    """Every component profile the request references, keyed by path and id."""
    profiles: dict = {}
    references = [document["cpu"]["profile"]] + [item["profile"]
                                                 for item in document["peripherals"]]
    for relative in sorted(set(references) | {IBEX_PROFILE, GPIO_PROFILE}):
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"missing component profile {relative}")
        profile = load_component_profile(path)
        profiles[relative] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


def build_matrix_plan():
    """Compose the two-source SoC from the checked-in request."""
    document = request_document(int(load_component_profile(ROOT / IBEX_PROFILE)
                                    .cpu.reset_vector))
    profiles = profiles_for(document)
    return build_composition(load_composition_request(document, profiles=profiles),
                             base_dir=ROOT)


def matrix_programs(plan) -> dict[str, object]:
    """The three generated programs the four samples are run against.

    ``verify_peripherals`` is off for all of them: the declared-register phase
    writes each writable register's declared reset value, and the novagpio
    profile declares ``IRQ_EN.reset_value = 0``, so leaving the phase enabled
    would clear the source's interrupt enable before a later arrival and make the
    sample measure that phase instead of the interrupt path.
    """
    return {
        "multi": build_boot_program(plan, request=ProgramRequest(
            exercise_all_sources=True, verify_peripherals=False)),
        "staggered": build_boot_program(plan, request=ProgramRequest(
            exercise_all_sources=True, stagger_sources=True,
            verify_peripherals=False)),
        "single": build_boot_program(plan, request=ProgramRequest(
            verify_peripherals=False)),
    }


def report_layout(program) -> dict[str, int]:
    """The program's own report-field offsets, never a hard-coded copy."""
    return {str(item["name"]): int(item["offset"])
            for item in program.document["report"]["layout"]}


def controller_offsets(plan) -> dict[str, int]:
    """The controller's declared register offsets from the plan's register map."""
    return {str(item["name"]): int(item["offset"])
            for item in plan.interrupt_document["controller"]["register_map"]}


def peripheral_base(plan, instance_id: str) -> int:
    """The MMIO window base the plan declares for one instance."""
    for record in plan.target_records:
        if record.get("instance_id") == instance_id:
            return int(record["window"]["base"])
    raise AssertionError(f"the plan declares no MMIO window for {instance_id}")


def raw_field_layout(plan) -> dict[str, tuple[int, int]]:
    """``top_port -> (raw_lo, raw_hi)`` for the plan's declared special inputs."""
    return {str(item["top_port"]): (int(item["raw_lo"]), int(item["raw_hi"]))
            for item in plan.raw_layout["special_inputs"]}


def ram_instance(plan) -> int:
    """The fabric target index (``u_mem_<index>``) that backs the RAM region."""
    for row in plan.plan["fabric"]["decode"]["windows"]:
        if str(row["window_id"]) == "ram0":
            return int(row["target_index"])
    raise AssertionError("the plan declares no decoded ram0 window")


def read32(result: RunResult, address: int, *, instance: int) -> int:
    """One 32-bit RAM word out of the runtime's hierarchical readback."""
    offset = int(address) - RAM_BASE
    index, lane = divmod(offset, 8)
    key = f"u_mem_{instance}[{index}]"
    if key not in result.observations:
        raise AssertionError(
            "the runtime read back no RAM word %d for address 0x%08x" % (index, address))
    return (int(result.observations[key]) >> (lane * 8)) & 0xFFFF_FFFF


# ---------------------------------------------------------------------------
# pure plan-level tests (no Verilator)
# ---------------------------------------------------------------------------


class IrqSampleMatrixPlanTests(unittest.TestCase):
    """Everything the matrix claims must already hold before any RTL is built.

    This tier builds no RTL and runs no sample; composing the plan does use the
    profile elaborator (Verilator's ``--json`` frontend), exactly like every other
    composition test in this repository.  A host without that tool skips the tier
    unless ``MYFUZZ_SOC_REAL=1`` is set, in which case nothing skips and the
    missing tool is named as a failure.
    """

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("verilator") is None and not OPT_IN:
            raise unittest.SkipTest(
                "the plan-level tier needs the profile elaborator; it builds and runs no RTL")
        cls.plan = build_matrix_plan()
        cls.programs = matrix_programs(cls.plan)
        cls.cases = matrix_cases(cls.plan, cls.programs)
        cls.offsets = controller_offsets(cls.plan)

    def test_the_composition_declares_the_two_level_sources_this_matrix_uses(self) -> None:
        sources = list(self.plan.interrupt_document["sources"])
        self.assertEqual(["gpio0", "gpio1"], [item["instance_id"] for item in sources])
        self.assertEqual([1, 2], [int(item["source_id"]) for item in sources])
        for item in sources:
            self.assertEqual("level", item["trigger"])
            self.assertEqual("direct", item["normalizer"]["kind"])
            # A level source's pending bit follows its input, so the controller's
            # post-COMPLETE pending word is a sampled view of that source's irq_o.
            self.assertEqual("follows-input-level", item["normalizer"]["pending"])
            self.assertIn("IRQ_STATUS[0] is set", str(item["hold"]))
        # The controller bit of a source is id-1 and bitmap bit k is source id k,
        # so a source's own pending bit is exactly 1 << source_id; a level source
        # must not be latched or its pending bit could not follow the clear.
        self.assertEqual(0, int(self.plan.interrupt_document["controller"]["latch_mask"]))
        self.assertEqual({"CLAIM": 0x00, "COMPLETE": 0x04, "IN_SERVICE": 0x08,
                          "SOURCE_COUNT": 0x0C, "PENDING0": 0x20, "ENABLE0": 0x24},
                         controller_offsets(self.plan))
        self.assertEqual(0x4000_0000, peripheral_base(self.plan, "gpio0"))
        self.assertEqual(0x4000_1000, peripheral_base(self.plan, "gpio1"))

    def test_the_peripherals_declare_the_clear_and_reset_facts_the_matrix_relies_on(self) -> None:
        profile = load_component_profile(ROOT / GPIO_PROFILE)
        registers = {str(item.name): item for item in profile.address.registers}
        self.assertEqual(0x08, int(registers["DATA_IN"].offset))
        self.assertEqual("read_clears", str(registers["DATA_IN"].side_effect))
        self.assertEqual("IRQ_STATUS", str(registers["DATA_IN"].clears_register))
        self.assertEqual(0x10, int(registers["IRQ_STATUS"].offset))
        self.assertEqual("ro", str(registers["IRQ_STATUS"].access))
        # The declared-register phase writes this value, which is why every matrix
        # program disables the phase.
        self.assertEqual(0, int(registers["IRQ_EN"].reset_value))
        self.assertEqual("rw", str(registers["IRQ_EN"].access))
        for program in self.programs.values():
            self.assertFalse(program.document["software"]["enabled"])

    def test_every_case_offers_a_distinct_raw_sample(self) -> None:
        streams = {case.name: case.raw() for case in self.cases}
        self.assertEqual(4, len(streams))
        for stream in streams.values():
            self.assertEqual(CYCLES, len(stream))
        names = sorted(streams)
        for index, name in enumerate(names):
            for other in names[index + 1:]:
                self.assertNotEqual(streams[name], streams[other],
                                    "%s and %s offer the same raw word stream"
                                    % (name, other))
        # Every word is inside the composition's frozen raw width, the stream is
        # exactly the declared steps, and the mode each case reports as applied is
        # the one its last step offers.
        layout = raw_field_layout(self.plan)
        self.assertEqual({"gpio0__pin_mode_i": (0, 2), "gpio1__pin_mode_i": (3, 5)}, layout)
        self.assertEqual(6, int(self.plan.raw_layout["raw_width"]))
        for case in self.cases:
            stream = case.raw()
            for index, (from_cycle, word) in enumerate(case.raw_steps):
                self.assertLess(word, 1 << 6)
                until = (case.raw_steps[index + 1][0]
                         if index + 1 < len(case.raw_steps) else CYCLES)
                self.assertTrue(all(item == word for item in stream[from_cycle:until]),
                                "%s: the step at cycle %d does not hold until cycle %d"
                                % (case.name, from_cycle, until))
            last = case.raw_steps[-1][1]
            self.assertTrue(all(item == 0 for item in stream[:case.raw_steps[0][0]]))
            for instance, mode in case.modes.items():
                lo, hi = layout[f"{instance}__pin_mode_i"]
                self.assertEqual(mode, (last >> lo) & ((1 << (hi - lo + 1)) - 1),
                                 "%s: the applied mode of %s is not the sample's last step"
                                 % (case.name, instance))

    def test_the_cases_arrive_in_the_windows_they_claim(self) -> None:
        by_name = {case.name: case for case in self.cases}
        simultaneous = by_name["simultaneous"]
        self.assertEqual(1, len(set(simultaneous.arrivals.values())),
                         "the simultaneous case must name one common arrival cycle")
        staggered = by_name["staggered"]
        arrivals = sorted(staggered.arrivals.values())
        self.assertGreater(arrivals[1] - arrivals[0], 1,
                           "a staggered arrival must be more than one cycle apart")
        order = [source_id for source_id, _ in
                 sorted(staggered.arrivals.items(), key=lambda item: item[1])]
        self.assertEqual(tuple(order), staggered.claims,
                         "the staggered sample must serve the earlier arrival first")
        boundary = by_name["reset_boundary"]
        for cycle in boundary.arrivals.values():
            self.assertLess(cycle, RESET_CYCLES,
                            "a reset-boundary event must be applied inside the reset window")
        for event in boundary.events:
            self.assertEqual(0, event.cycle)
            self.assertNotEqual(0, event.value)
        masked = by_name["masked"]
        self.assertEqual((1,), masked.claims)
        self.assertEqual((2,), masked.unclaimed)
        self.assertIn(2, masked.arrivals)
        self.assertTrue(masked.modes["gpio1"])

    def test_the_samples_only_drive_pins_and_special_inputs_the_plan_declares(self) -> None:
        slots = {int(item["slot"]): str(item["name"]) for item in
                 self.programs["multi"].document["trigger"]["events"]}
        self.assertEqual({0: "gpio0__gpio_in_i", 1: "gpio1__gpio_in_i"}, slots)
        for case in self.cases:
            self.assertTrue(case.events, "%s applies no event" % case.name)
            for event in case.events:
                self.assertIn(event.slot, slots)
                self.assertLess(event.cycle, CYCLES)
                self.assertLessEqual(event.value, 0xFF)
            for from_cycle, word in case.raw_steps:
                self.assertLess(from_cycle, CYCLES)
                self.assertLess(word, 1 << 6)
            for instance, mode in case.modes.items():
                self.assertLess(mode, 8)

    def test_the_programs_declare_the_dispatch_and_enable_set_each_case_needs(self) -> None:
        multi = self.programs["multi"].document
        entries = {int(item["source_id"]): item for item in multi["sources"]}
        self.assertEqual([1, 2], sorted(entries))
        for source in self.plan.interrupt_document["sources"]:
            source_id = int(source["source_id"])
            instance = str(source["instance_id"])
            entry = entries[source_id]
            self.assertEqual(instance, entry["instance_id"])
            # The per-id dispatch the shared handler performs is generated from
            # exactly these records: the source's own window, its declared status
            # register (whose cause bit the entry reads) and its declared clear.
            self.assertEqual(peripheral_base(self.plan, instance), int(entry["window_base"]))
            self.assertEqual("IRQ_STATUS", entry["status"]["register"])
            self.assertEqual(0x10, int(entry["status"]["offset"]))
            self.assertEqual(0, int(entry["status"]["cause_bit"]))
            self.assertEqual("read_clears", entry["clear"]["kind"])
            self.assertEqual("DATA_IN", entry["clear"]["register"])
            self.assertEqual(0x08, int(entry["clear"]["offset"]))
            self.assertEqual("IRQ_EN", entry["enable"]["register"])
            # A source's own controller enable bit is bit (id % 32) of the ENABLE
            # word, which is also the bit the handler masks its pending word with.
            self.assertEqual(1 << source_id, int(entry["controller_enable"]["mask"]))
            self.assertEqual(self.offsets["ENABLE0"],
                             int(entry["controller_enable"]["offset"]))
        steps = "\n".join(str(item) for item in multi["steps"])
        for source_id, entry in entries.items():
            self.assertIn("source %d (%s at 0x%08x)"
                          % (source_id, entry["instance_id"], int(entry["window_base"])), steps)
        self.assertIn("isr multi-source ledger", steps)
        self.assertIn("the declared-register phase is switched off by the request", steps)
        # The single-source program (the masked case) enables exactly one source and
        # drives exactly that source's pin; the multi program enables both.
        single = self.programs["single"].document
        self.assertEqual([1], [int(item["source_id"]) for item in single["sources"]
                               if item["controller_enable"]["enabled"]])
        self.assertEqual(1, len(single["trigger"]["pins"]))
        self.assertEqual([1, 2], [int(item["source_id"]) for item in multi["sources"]
                                  if item["controller_enable"]["enabled"]])
        self.assertEqual(2, len(multi["trigger"]["pins"]))
        self.assertTrue(self.programs["staggered"].document["trigger"]["staggered"])
        self.assertFalse(multi["trigger"]["staggered"])
        self.assertNotEqual([int(item["cycle"]) for item in multi["trigger"]["events"]],
                            [int(item["cycle"])
                             for item in self.programs["staggered"].document["trigger"]["events"]])
        # The staggered request changes only the declared trigger schedule, so the
        # two multi-source programs emit the same code and differ in their event
        # plan; the single-source program is a third, genuinely different image.
        images = {name: image_hex(program.image) for name, program in self.programs.items()}
        self.assertEqual(2, len(set(images.values())))
        self.assertEqual(images["multi"], images["staggered"])
        self.assertNotEqual(images["multi"], images["single"])

    def test_the_claim_round_extractor_rebuilds_one_record_per_handler_entry(self) -> None:
        layout = {"handler_entries": 0x04, "claim_id": 0x00,
                  "pending_word_0_before_claim": 0x28, "status_raw_before_clear": 0x20,
                  "cause_before_clear": 0x18, "status_raw_after_clear": 0x24,
                  "cause_after_clear": 0x1C, "pending_word_after_complete": 0x30,
                  "pending_before_claim": 0x14}
        report, controller = 0x8000_0010, 0x4000_2000
        requests = tuple({"cycle": cycle, "addr": addr, "wdata": data}
                         for cycle, addr, data in (
                             (100, report + 0x04, 1),          # entry 1 starts
                             (110, report + 0x28, 0b110),      # both sources pending
                             (120, report + 0x00, 1),          # CLAIM read back as 1
                             (125, report + 0x14, 0b010),      # masked pending bit
                             (130, report + 0x20, 1),          # peripheral status
                             (140, report + 0x18, 1),          # masked cause
                             (150, report + 0x24, 0),          # after the declared clear
                             (160, report + 0x1C, 0),
                             (170, controller + 0x04, 1),      # COMPLETE
                             (180, report + 0x30, 0b100),      # source 2 still pending
                             (200, report + 0x04, 2),          # entry 2 starts
                             (210, report + 0x28, 0b100),
                             (250, controller + 0x04, 2),
                             (260, report + 0x30, 0)))
        rounds = claim_rounds(_FakeResult(requests), layout=layout,
                              report_address=report, controller_base=controller,
                              complete_offset=0x04)
        self.assertEqual(2, len(rounds))
        first, second = rounds
        self.assertEqual(1, first.claim_id)
        self.assertEqual(1, first.complete_id)
        # ``pending`` returns the masked bit, so source 1 is 1 << 1 and source 2 is
        # 1 << 2, exactly as the controller's bitmap numbering defines them.
        self.assertEqual(1 << 1, first.pending(1))
        self.assertEqual(1 << 2, first.pending(2))
        self.assertEqual(0, first.pending_after(1))
        self.assertEqual(1 << 2, first.pending_after(2))
        self.assertEqual(0b110, first.values["pending_word_0_before_claim"])
        self.assertEqual(0b010, first.values["pending_before_claim"])
        # The second entry does not rewrite the guarded first-entry fields, so they
        # are absent rather than stale, and its own unguarded fields are present.
        self.assertIsNone(second.claim_id)
        self.assertEqual(2, second.complete_id)
        self.assertEqual(0, second.pending(1))
        self.assertEqual(1 << 2, second.pending(2))
        self.assertEqual(0, second.pending_after(2))
        self.assertNotIn("status_raw_before_clear", second.values)
        self.assertNotIn("pending_before_claim", second.values)

    def test_the_runtime_releases_reset_before_it_consumes_any_raw_word(self) -> None:
        text = render_profile_testbench(self.plan)
        hold = text.index("    rst_ni = 1'b0;")
        reset_loop = text.index("for (cycle_index = 0; cycle_index < RESET_CYCLES;")
        release = text.index("    rst_ni = 1'b1;")
        counter_clear = text.index("    cycles = 0;")
        raw_scan = text.index('$fscanf(fd, "%h", raw_word);')
        self.assertLess(hold, reset_loop)
        self.assertLess(reset_loop, release)
        self.assertLess(release, counter_clear)
        self.assertLess(counter_clear, raw_scan,
                        "the per-cycle raw loop must start after the reset window")
        self.assertLess(text.index("integer cycles = 0;"), reset_loop,
                        "the event plan is matched against a cycle count that is still 0 "
                        "while reset is asserted, which is what applies a cycle-0 event "
                        "inside the reset window")
        self.assertIn("while (event_index < event_count && event_cycle[event_index] <= cycles)",
                      text)
        # The applied-value readback exists only for the plan's declared special
        # inputs: a driven external event pin has no applied observation, which is
        # the observability boundary this module records.
        self.assertIn("obs_gpio0__pin_mode_i__applied", text)
        self.assertIn("obs_gpio1__pin_mode_i__applied", text)
        self.assertNotIn("obs_gpio0__gpio_in_i__applied", text)
        self.assertNotIn("obs_gpio1__gpio_in_i__applied", text)


# ---------------------------------------------------------------------------
# real RTL matrix
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real IRQ sample matrix")
class SocIrqSampleMatrixTests(unittest.TestCase):
    """One build, four raw samples, per-source evidence for every claim."""

    blocker: str | None = None
    plan = None
    programs: dict = {}
    cases: tuple[MatrixCase, ...] = ()
    results: dict = {}
    run_executables: dict = {}
    build = None
    timings: dict = {}
    notes: list = []

    @classmethod
    def setUpClass(cls) -> None:
        cls.started = time.monotonic()
        try:
            cls._prepare()
        except Exception as error:                 # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        for relative in (IBEX_PROFILE, GPIO_PROFILE, REQUEST_FILE):
            if not (ROOT / relative).is_file():
                raise AssertionError(f"missing composition input {relative}")
        verilator = shutil.which("verilator")
        if verilator is None:
            raise AssertionError("Verilator is required for the real IRQ sample matrix")

        started = time.monotonic()
        cls.plan = build_matrix_plan()
        cls.timings["compose_s"] = time.monotonic() - started
        controller = cls.plan.interrupt_document["controller"]
        if not controller.get("present"):
            raise AssertionError("the composed plan instantiates no interrupt controller")
        if [int(item["source_id"]) for item in cls.plan.interrupt_document["sources"]] != [1, 2]:
            raise AssertionError("expected the two declared novagpio sources 1 and 2")
        cls.source_ids = {int(item["source_id"]): str(item["instance_id"])
                          for item in cls.plan.interrupt_document["sources"]}
        cls.offsets = controller_offsets(cls.plan)
        cls.controller_base = int(controller["window"]["base"])
        cls.ram_instance = ram_instance(cls.plan)

        started = time.monotonic()
        cls.programs = matrix_programs(cls.plan)
        cls.cases = matrix_cases(cls.plan, cls.programs)
        cls.layouts = {name: report_layout(program)
                       for name, program in cls.programs.items()}
        cls.timings["program_s"] = time.monotonic() - started

        started = time.monotonic()
        cls.top_text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        records = source_list(cls.plan)
        cls.sources = [item["path"] for item in records if item["role"] != "include_root"]
        cls.include_roots = sorted({item["path"] for item in records
                                    if item["role"] == "include_root"})
        cls.timings["render_s"] = time.monotonic() - started

        cls._temporary = TemporaryDirectory(prefix=".myfuzz-irq-matrix-", dir=ROOT)
        scratch = Path(cls._temporary.name)
        cls.images = {}
        for name, program in cls.programs.items():
            path = scratch / f"boot-{name}.hex"
            path.write_text(image_hex(program.image), encoding="utf-8")
            cls.images[name] = path.resolve()

        # soc_runtime.build_profile_runtime does not pass the profile's declared
        # include roots or defines to Verilator, and a real CPU closure with
        # cross-directory includes cannot be compiled without them; the runtime
        # accepts the tool path, so the declared flags go through a wrapper.
        flags = [f"-I{ROOT / item}" for item in cls.include_roots]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        tool = verilator
        if flags:
            wrapper = scratch / "verilator_with_profile_flags.sh"
            wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n"
                               % (verilator, " ".join(flags)), encoding="utf-8")
            wrapper.chmod(0o755)
            tool = wrapper.as_posix()
            cls.notes.append("the build used the plan's declared include roots/defines")

        started = time.monotonic()
        cls.build = cls._build_runtime(scratch / "soc", cls.images["multi"], tool)
        cls.timings["build_s"] = time.monotonic() - started

        started = time.monotonic()
        for case in cls.cases:
            cls.results[case.name] = cls._run(case)
        cls.timings["runs_s"] = time.monotonic() - started

    @classmethod
    def _build_runtime(cls, output: Path, image: Path, tool: str):
        """Compile the composed SoC, retrying once on a transient tool failure.

        The runtime refuses a non-empty output directory, so each attempt starts
        from a fresh one.  A genuine RTL or compile error fails both attempts and
        is still reported with its (runtime-truncated) diagnostics; the retry
        exists because a concurrent heavy build on the same host can kill the C++
        stage, which says nothing about this composition.
        """
        last: Exception | None = None
        for attempt in (1, 2):
            if output.exists():
                shutil.rmtree(output)
            try:
                return build_profile_runtime(
                    cls.plan, output_dir=output, base_dir=ROOT, top_text=cls.top_text,
                    sources=cls.sources, boot_image=image, verilator=tool,
                    timeout_seconds=1800)
            except SocRuntimeError as error:
                last = error
                print("MYFUZZ_SOC_IRQ_MATRIX_NOTE build attempt %d failed: %s"
                      % (attempt, str(error)[:300]))
                if "runtime-build-failed" not in str(error):
                    raise
        raise last

    @classmethod
    def _run(cls, case: MatrixCase) -> RunResult:
        """Run one sample against the one build, swapping only the boot image."""
        sample = RuntimeSample(request_id=abs(hash(case.name)) % 60000,
                               raw=case.raw(), events=case.events)
        build = cls.build
        if build.boot_image != cls.images[case.program_key]:
            build = replace(build, boot_image=cls.images[case.program_key])
        started = time.monotonic()
        result = run_sample(build, sample, timeout_seconds=1800)
        elapsed = time.monotonic() - started
        cls.run_executables[case.name] = str(build.executable)
        print("MYFUZZ_SOC_IRQ_MATRIX_RUN case=%s program=%s status=%s cycles=%d wall_s=%.2f "
              "reason=%s" % (case.name, case.program_key, result.status, result.cycles,
                             elapsed, result.reason))
        for name, value in sorted(result.observations.items()):
            if name.endswith("__applied"):
                print("MYFUZZ_SOC_IRQ_MATRIX_APPLIED case=%s %s=%d"
                      % (case.name, name, value))
        return result

    @classmethod
    def tearDownClass(cls) -> None:
        total = time.monotonic() - cls.started
        if cls.blocker is None:
            print("\nMYFUZZ_SOC_IRQ_MATRIX_TIMING compose_s=%.1f program_s=%.1f "
                  "render_s=%.1f build_s=%.1f runs_s=%.1f wall_s=%.1f"
                  % (cls.timings.get("compose_s", 0.0), cls.timings.get("program_s", 0.0),
                     cls.timings.get("render_s", 0.0), cls.timings.get("build_s", 0.0),
                     cls.timings.get("runs_s", 0.0), total))
            if cls.notes:
                print("MYFUZZ_SOC_IRQ_MATRIX_NOTE %s" % "; ".join(cls.notes))
        else:
            print("\nMYFUZZ_SOC_IRQ_MATRIX_BLOCKED %s" % cls.blocker)
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail("the IRQ sample matrix could not be prepared: %s" % self.blocker)

    # -- helpers -----------------------------------------------------------

    def case(self, name: str) -> MatrixCase:
        for case in self.cases:
            if case.name == name:
                return case
        raise AssertionError(f"no matrix case {name}")

    def program(self, case: MatrixCase):
        return self.programs[case.program_key]

    def rounds(self, case: MatrixCase, result: RunResult) -> tuple[ClaimRound, ...]:
        program = self.program(case)
        return claim_rounds(result, layout=self.layouts[case.program_key],
                            report_address=int(program.report_address),
                            controller_base=self.controller_base,
                            complete_offset=self.offsets["COMPLETE"])

    def report(self, case: MatrixCase, result: RunResult, field: str) -> int:
        program = self.program(case)
        address = int(program.report_address) + self.layouts[case.program_key][field]
        return read32(result, address, instance=self.ram_instance)

    def assert_applied_modes(self, case: MatrixCase, result: RunResult) -> None:
        """The environment's own applied-value readback matches the sample's raw.

        This is the external-cause record for a raw-carried arrival: the value the
        component was really offered, reported by the generated top's own driver
        port, not a restatement of the raw word the test asked for.
        """
        for instance, mode in case.modes.items():
            name = f"{instance}__pin_mode_i__applied"
            self.assertIn(name, result.observations,
                          "%s: the run reports no applied value for %s" % (case.name, instance))
            self.assertEqual(mode, int(result.observations[name]),
                             "%s: the applied value of %s is not what the sample offered"
                             % (case.name, instance))

    def assert_source_chain(self, case: MatrixCase, result: RunResult,
                            record: ClaimRound, source_id: int) -> None:
        """Every per-source statement this matrix makes, from the CPU's records."""
        instance = self.source_ids[source_id]
        label = "%s: source %d (%s)" % (case.name, source_id, instance)
        cause_mask = 1  # novagpio's only declared interrupt cause is IRQ_STATUS[0]

        # (1) the claim id the CPU read: the handler stores the value it read from
        #     CLAIM for the first entry of a run, and for every entry it writes
        #     COMPLETE with the id it dispatched on -- the value it just read.
        if record.claim_id is not None:
            self.assertEqual(source_id, record.claim_id,
                             "%s: the id the CPU read from CLAIM" % label)
            self.assertEqual(record.claim_id, record.complete_id)
            # The report guards the masked pending bit to the first entry, so it is
            # only meaningful here; it is the claimed source's own bit.
            self.assertEqual(1 << source_id, int(record.values["pending_before_claim"]),
                             "%s: the recorded masked pending bit is not this source's"
                             % label)
        self.assertEqual(source_id, record.complete_id,
                         "%s: the id the CPU wrote to COMPLETE" % label)

        # (2) pending before the claim, for this source's own bit.
        word = int(record.values["pending_word_0_before_claim"])
        self.assertNotEqual(0, word & (1 << source_id),
                            "%s: the controller did not pend this source before its claim "
                            "(pending word 0x%x)" % (label, word))

        # (3) the profile-declared clear emptied this source's status register.
        before = record.values.get("status_raw_before_clear")
        if before is not None:
            self.assertNotEqual(0, before & cause_mask,
                                "%s: the peripheral status was not latched before the clear"
                                % label)
            self.assertEqual(cause_mask, int(record.values["cause_before_clear"]))
            self.assertEqual(0, int(record.values["status_raw_after_clear"]) & cause_mask,
                             "%s: the declared clear did not empty the status register"
                             % label)
            self.assertEqual(0, int(record.values["cause_after_clear"]))
        else:
            # The report keeps only the first entry's peripheral status, so a later
            # entry's clear is asserted from the controller's own post-COMPLETE
            # pending word: a level source's pending bit is the sampled value of
            # its irq_o, and the declared hold keeps irq_o high until IRQ_STATUS is
            # cleared, so a cleared bit after COMPLETE means the clear happened.
            self.assertEqual(0, record.pending_after(source_id),
                             "%s: the source still pends after its COMPLETE, so its irq_o "
                             "was never lowered" % label)

        # (4) COMPLETE retired exactly this source's pending bit.
        self.assertEqual(0, record.pending_after(source_id),
                         "%s: COMPLETE did not clear this source's pending bit" % label)
        self.assertEqual(1, int(record.values["complete_accepted"]),
                         "%s: the controller did not accept COMPLETE" % label)
        self.assertEqual(0, int(record.values["final_in_service"]),
                         "%s: the controller kept a source in service" % label)

    def assert_not_claimed(self, case: MatrixCase, result: RunResult, source_id: int) -> None:
        """A source that must not be claimed has no COMPLETE and no entry at all."""
        for record in self.rounds(case, result):
            self.assertNotEqual(source_id, record.complete_id,
                                "%s: source %d was completed although it must not be claimed"
                                % (case.name, source_id))
        for request in result.requests:
            if int(request["addr"]) == self.controller_base + self.offsets["COMPLETE"]:
                self.assertNotEqual(source_id, int(request["wdata"]),
                                    "%s: the CPU wrote COMPLETE for the unclaimed source %d"
                                    % (case.name, source_id))

    def assert_case(self, case: MatrixCase) -> RunResult:
        """Run-level assertions shared by every case, then the per-source chains."""
        result = self.results[case.name]
        self.assertEqual("OK", result.status,
                         "%s: the run must complete, not %s (%s)"
                         % (case.name, result.status, result.reason))
        self.assertEqual(CYCLES, result.cycles, "%s: the sample window was not run" % case.name)
        self.assertFalse(result.requests_truncated,
                         "%s: the write capture was truncated, so the per-entry record would "
                         "be incomplete" % case.name)
        self.assert_applied_modes(case, result)

        records = self.rounds(case, result)
        for index, record in enumerate(records, start=1):
            print("MYFUZZ_SOC_IRQ_MATRIX_ENTRY case=%s entry=%d start_cycle=%d claim_id=%s "
                  "complete_id=%d complete_cycle=%d pending_before=0x%x status_before=%s "
                  "status_after=%s pending_after=0x%x"
                  % (case.name, index, record.start_cycle, record.claim_id,
                     record.complete_id, record.complete_cycle,
                     int(record.values.get("pending_word_0_before_claim", 0)),
                     record.values.get("status_raw_before_clear"),
                     record.values.get("status_raw_after_clear"),
                     int(record.values.get("pending_word_after_complete", 0))))
        self.assertEqual(case.claims, tuple(record.complete_id for record in records),
                         "%s: the served source ids, in service order" % case.name)
        self.assertEqual(case.claims[0], self.report(case, result, "claim_id"),
                         "%s: the first id the CPU read from CLAIM" % case.name)
        self.assertEqual(len(case.claims), self.report(case, result, "handler_entries"))
        self.assertEqual(0, self.report(case, result, "unknown_claim"),
                         "%s: every claimed id was found in the plan's source table" % case.name)
        self.assertEqual(1 if len(case.claims) == 1 else 2,
                         self.report(case, result, "interrupt_completions"),
                         "%s: the handler's own completion count" % case.name)
        self.assertEqual(1, self.report(case, result, "main_completed"),
                         "%s: the CPU ran its main flow" % case.name)

        for source_id in case.claims:
            record = next(item for item in records if item.complete_id == source_id)
            self.assert_source_chain(case, result, record, source_id)
        for source_id in case.unclaimed:
            self.assert_not_claimed(case, result, source_id)
        return result

    # -- the matrix --------------------------------------------------------

    def test_simultaneous_arrival_pends_both_sources_before_the_first_claim(self) -> None:
        """Same-cycle arrival: one shared window, both bits pending, both served.

        ``all_sources_closed`` would be 1 here whatever ids the controller handed
        out, so the proof is the pending word the CPU itself read before the first
        claim (both bits) plus each entry's own id, status and COMPLETE.
        """
        case = self.case("simultaneous")
        result = self.assert_case(case)
        records = self.rounds(case, result)
        self.assertEqual(1, len(set(case.arrivals.values())),
                         "both declared pins must change in the same cycle")
        self.assertEqual(0b110, int(records[0].values["pending_word_0_before_claim"]),
                         "both sources must already be pending when the first is claimed")
        self.assertEqual(0b100, int(records[1].values["pending_word_0_before_claim"]),
                         "the first source's pending bit must be gone once it was claimed")
        # The first entry recorded its own peripheral status, so source 1's clear
        # is a directly read status register value; source 2's clear is the
        # controller's post-COMPLETE pending word.
        self.assertEqual(0, int(records[0].values["pending_word_after_complete"]) & 0b010)
        self.assertEqual(0, int(records[1].values["pending_word_after_complete"]))

    def test_staggered_arrival_serves_the_first_arrival_and_keeps_the_windows_distinct(
            self) -> None:
        """Distinct arrival windows: the pending words prove they never overlapped.

        The first arrival is the higher source id, so the report's guarded
        first-entry fields (masked pending bit, status before and after the
        declared clear) belong to that source and are asserted directly; the lower
        id then arrives in its own window and is served second.
        """
        case = self.case("staggered")
        result = self.assert_case(case)
        records = self.rounds(case, result)
        arrivals = sorted(case.arrivals.values())
        self.assertGreater(arrivals[1] - arrivals[0], 1)
        first, second = case.claims
        # Before the first claim only the first arrival is pending: the second
        # source's condition did not exist yet, which is what "staggered" means.
        self.assertEqual(1 << first, int(records[0].values["pending_word_0_before_claim"]))
        self.assertEqual(1 << second, int(records[1].values["pending_word_0_before_claim"]))
        self.assertEqual(first, records[0].claim_id,
                         "the CPU must read the first-arriving source's id from CLAIM")
        self.assertLess(records[0].complete_cycle, records[1].start_cycle,
                        "the two services must be distinct handler entries in time order")

    def test_a_source_arriving_while_masked_is_pending_and_never_claimed(self) -> None:
        """Arrival while masked: the source pends, the controller cannot claim it.

        The program enables only the first source, so the second one's own ENABLE
        bit stays at its reset value while the raw sample changes its sampled pin
        vector.  It must be visible as pending both before and after the other
        source's service, and it must never be claimed or completed.
        """
        case = self.case("masked")
        result = self.assert_case(case)
        records = self.rounds(case, result)
        self.assertEqual(1, len(records), "exactly one source may be served")
        masked = case.unclaimed[0]
        self.assertEqual(0b110, int(records[0].values["pending_word_0_before_claim"]),
                         "the masked source must be pending before the enabled source's claim")
        self.assertEqual(1 << masked,
                         int(records[0].values["pending_word_after_complete"]),
                         "the masked source must still be asking after the enabled source "
                         "completed, and nothing else may be pending")
        self.assertEqual(0, self.report(case, result, "final_in_service"))
        # The enabled source's own chain, including its declared clear.
        self.assertEqual(1, int(records[0].values["status_raw_before_clear"]) & 1)
        self.assertEqual(0, int(records[0].values["status_raw_after_clear"]) & 1)
        self.assertEqual(MASKED_GPIO1_MODE,
                         int(result.observations["gpio1__pin_mode_i__applied"]),
                         "the masked arrival must be the raw value the sample offered")

    def test_a_condition_present_when_reset_is_released_is_serviced_after_release(self) -> None:
        """Reset boundary: the pins are active during reset, both sources are served.

        The runtime applies a cycle-0 event at the first reset edge, so both pin
        levels are already active for the whole reset window.  The peripheral's
        change detector latches them on the first sampled edge after release, so
        the handler runs before the main flow has even stamped its prologue; both
        sources must then be claimed by their own declared ids.
        """
        case = self.case("reset_boundary")
        result = self.assert_case(case)
        records = self.rounds(case, result)
        for event in case.events:
            self.assertLess(event.cycle, RESET_CYCLES,
                            "the boundary sample must drive its pins inside the reset window")
        self.assertEqual(0b110, int(records[0].values["pending_word_0_before_claim"]),
                         "both sources must already be pending at the first claim")
        # The service preempted the main flow before it read its own mcycle stamp,
        # so the boundary condition was live from the first enabled instruction.
        prologue = self.report(case, result, "prologue_cycle")
        self.assertGreater(prologue, 0)
        self.assertLess(records[0].start_cycle, prologue,
                        "the boundary condition must be serviced before the main flow "
                        "stamps its prologue cycle")

    def test_the_four_samples_are_distinct_and_share_one_build(self) -> None:
        """One executable, four different samples: no case can come from another build."""
        self.assertEqual(4, len(self.cases))
        payloads = {RuntimeSample(request_id=1, raw=case.raw(), events=case.events).payload()
                    for case in self.cases}
        self.assertEqual(len(self.cases), len(payloads), "every case must be its own sample")
        streams = {case.raw() for case in self.cases}
        self.assertEqual(len(self.cases), len(streams),
                         "every case must offer its own raw word stream")
        executables = set(self.run_executables.values())
        self.assertEqual(1, len(executables),
                         "all four samples must run against the same executable")
        self.assertEqual({str(self.build.executable)}, executables)
        self.assertTrue(Path(str(self.build.executable)).is_file())
        for case in self.cases:
            self.assertEqual("OK", self.results[case.name].status,
                             "%s did not run to completion" % case.name)


if __name__ == "__main__":
    unittest.main()
