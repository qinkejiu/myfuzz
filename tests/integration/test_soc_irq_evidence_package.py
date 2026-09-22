"""Task 3: multi-sample IRQ evidence in one package, replay and reduction.

Phase 3 of the SoC roadmap asks for two things that this module proves together:

* the per-source interrupt record of *several* samples must enter the same
  ``EvidencePackage``/``replay_package`` entry point the RFuzz input uses, so the
  CPU's own claim/clear/COMPLETE evidence is bound to the plan, layout, policy,
  build, boot image, source closure and tool that produced it, and a replay
  compares it field by field instead of "ran again without crashing";
* a reduced counterexample must keep the *failure identity*: the same source ids
  the CPU served, the same event ordering and the same accepted transactions --
  asserted as a property of two real runs, not as "it still fails".

The per-source IRQ record is derived from the run's own document, never invented.
Every value names the field it came from: the claim id and the COMPLETE cycle are
the write data and cycle of the COMPLETE store in ``fabric_requests`` (a field
``replay_package`` compares as ``fabric_request[i].0x<addr>.<field>``), the
pending and cleared-cause words are the program's own RAM report as the runtime
read it back (``observation:u_mem_N[k]``), and the declared clear target is the
plan/program declaration the plan hash and boot-image hash cover.  Because the
record is a pure projection of those fields, a package whose stored record was
edited is caught by recomputation, and a package whose *run* was edited is caught
by replay with the field name.

Half of the tests need no simulator at all: the composition, the boot program, the
constraint policy and the interrupt plan are pure Python -- they *are* the real
two-source SoC -- and only the run is a deterministic model that applies the rules
the real runs were observed to follow (the event plan raises a source; only a
controller-ENABLEd source is claimed, lowest id first; a source is completed once
and never re-claimed after its declared clear took effect; the report records the
first claim's pending mask and the first served source's cleared status).  The
other half is the real thing: the same plan built twice with Verilator -- once as
composed, once with the edge source's controller latch bit removed -- compiled,
run, packaged, replayed and reduced.  The three samples are one simultaneous
arrival, one where the level source arrives first, and one where only the level
source arrives at all, so the per-source records carry two different service
orders and one explicitly unserved source.

``MYFUZZ_SOC_REAL=1`` gates the real build, following
``tests/integration/test_soc_interrupt_lifecycle.py``: when the flag is set
nothing here skips, and a missing dependency or a failed build is a failure
naming it.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
import unittest.mock
from collections.abc import Mapping, Sequence
from pathlib import Path

from myfuzz.composition import soc_failure_evidence as evidence_module
from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_boot_program import (
    COMPLETION_FLAG,
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_failure_evidence import (
    COMPOSITION_DEFECT,
    EVIDENCE_DOCUMENT,
    RAW_INPUT_DIRECTORY,
    RAW_INPUT_INDEX,
    REPLAY_AGREEMENT,
    REPLAY_DIVERGENCE,
    REPLAY_REFUSED,
    REQUIRED_IDENTITY,
    build_evidence_package,
    classify_boundary,
    minimize_sample,
    read_evidence_package,
    replay_package,
    write_evidence_package,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent,
    RunResult,
    RuntimeBuild,
    RuntimeSample,
    build_profile_runtime,
    run_sample,
)

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_dependency_replay import applied_legality

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
#: Scratch space for the patched profile; ``runs/`` is git-ignored like every
#: other test scratch directory.  The real builds live in a temporary directory so
#: a failed run leaves no 300 MB build behind.
SCRATCH = ROOT / "runs/soc-irq-evidence-package"
IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"
#: The two-source plan phase 3 freezes: an edge-shaped source (whose converter
#: emits a one-cycle pulse, so the controller must latch it) and a level-shaped
#: one (which the controller follows, so the declared peripheral clear is what
#: retires it).
EDGE_INSTANCE = "edge0"
LEVEL_INSTANCE = "level0"
#: Key of the per-sample per-source IRQ record inside ``package.attribution``.
IRQ_SERVICE_KEY = "irq_service"
IRQ_SERVICE_SCHEMA = "soc_irq_service_record.v1"

MEMORY_WORD = re.compile(r"^u_mem_(\d+)\[(\d+)\]$")
#: The two 32-bit bitmap words the controller's register ABI publishes.
PENDING_WORD_BITS = 32
#: Raw length of each sample of the package.  The declared trigger raises the pins
#: at 3072 (and 4096 when delayed), so every window covers the service with room
#: to spare; the different lengths also make the three raw inputs distinct.
SIMULTANEOUS_CYCLES = 6000
LEVEL_FIRST_CYCLES = 7000
SINGLE_CYCLES = 8000
#: The declared trigger drives each pin low first and high again one lead later,
#: so the edge-shaped source really sees the rising edge its converter decodes.
TRIGGER_LEAD = 1024
DECLARED_RAISE_CYCLE = 3072
DELAYED_RAISE_CYCLE = 4096


# ---------------------------------------------------------------------------
# the two-source composition: real composition, real program, no RTL
# ---------------------------------------------------------------------------


def _records(value: object) -> tuple[object, ...]:
    """One document field as a tuple, whatever shape it was saved in."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    if isinstance(value, Mapping):
        return (dict(value),)
    return (value,)


def _edge_profile_path() -> str:
    """The novagpio profile patched to a rising-edge interrupt, under ``runs/``."""
    document = json.loads((ROOT / GPIO_PROFILE).read_text(encoding="utf-8"))
    sources = document.get("interrupts")
    if not isinstance(sources, list) or not sources:
        raise AssertionError(f"{GPIO_PROFILE} declares no interrupt source")
    sources[0]["trigger"] = "rising_edge"
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / "novagpio-rising-edge.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path.relative_to(ROOT).as_posix()


@functools.lru_cache(maxsize=1)
def irq_plan():
    """The real Ibex + edge/level two-source composition.

    Composing, rendering and generating the boot program are pure Python, so both
    halves of this module describe the *same* SoC; only the runs differ (a
    deterministic model in the pure half, Verilator in the gated half).
    """
    document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
    reset_vector = int(load_component_profile(ROOT / IBEX_PROFILE).cpu.reset_vector)
    for region in document["memory"]:
        if region["region_id"] == "rom0":
            # The declared entry is the first byte of the region, exactly as the
            # memory model loads an image, so the boot image must start there.
            region["base"] = reset_vector
    document["request_id"] = "ibex-irq-evidence-package"
    document["peripherals"] = [
        {"instance_id": EDGE_INSTANCE, "profile": _edge_profile_path(), "parameters": {}},
        {"instance_id": LEVEL_INSTANCE, "profile": GPIO_PROFILE, "parameters": {}},
    ]
    profiles: dict = {}
    for reference in sorted({document["cpu"]["profile"], _edge_profile_path(),
                             GPIO_PROFILE}):
        profile = load_component_profile(ROOT / reference)
        profiles[reference] = profile
        profiles.setdefault(profile.component_id, profile)
    return build_composition(load_composition_request(document, profiles=profiles), base_dir=ROOT)


@functools.lru_cache(maxsize=1)
def irq_program():
    """The generated two-source program whose image the real builds boot."""
    return build_boot_program(irq_plan(), request=ProgramRequest(exercise_all_sources=True))


@functools.lru_cache(maxsize=1)
def irq_policy():
    """The compiled constraint policy of the same plan, as the policy identity."""
    return compile_input_constraints(irq_plan(), drive_profile="cpu_execute")


def declared_sources(plan) -> dict[int, Mapping[str, object]]:
    """The plan's own interrupt source table, keyed by declared source id."""
    return {int(item["source_id"]): item for item in plan.interrupt_document["sources"]}


def declared_ids(plan) -> tuple[int, int]:
    """The plan's numbering of the edge-shaped and the level-shaped source."""
    sources = declared_sources(plan)
    edge = next(source_id for source_id, item in sources.items()
                if str(item["instance_id"]) == EDGE_INSTANCE)
    level = next(source_id for source_id, item in sources.items()
                 if str(item["instance_id"]) == LEVEL_INSTANCE)
    return edge, level


def source_slot(program, instance_id: str) -> int:
    """The runtime's external input slot the plan gave one source's pin.

    The slot index is the position in the runtime's own slot table, so the
    declared trigger and a hand-written event plan address the same pin.
    """
    for item in program.document["trigger"]["events"]:
        if str(item["name"]).startswith(instance_id + "__"):
            return int(item["slot"])
    raise AssertionError(f"the program's trigger plan names no pin of {instance_id}")


def trigger_events(program, raise_cycles: Mapping[int, int], *,
                   lead: int = TRIGGER_LEAD) -> tuple[ExternalEvent, ...]:
    """A per-slot event plan: drive the pin low, then high one ``lead`` later.

    ``raise_cycles`` names, per runtime slot, the cycle the pin goes high.  A
    source whose slot is absent contributes nothing, which is how a sample
    exercises "this source was never raised" without changing the program.
    """
    events: list[ExternalEvent] = []
    for slot, cycle in sorted(raise_cycles.items()):
        events.append(ExternalEvent(slot=int(slot), cycle=int(cycle) - lead, value=0))
        events.append(ExternalEvent(slot=int(slot), cycle=int(cycle), value=0xFF))
    return tuple(sorted(events, key=lambda item: (item.cycle, item.slot)))


def irq_sample(request_id: int, cycles: int, events: Sequence[ExternalEvent]) -> RuntimeSample:
    """One IRQ sample: ``cycles`` raw words plus the pin event plan.

    The raw words hold every declared special input at ground for the whole run,
    which is the declared idle level ``applied_legality`` re-checks against the
    driver's own exported applied value; the interrupt cause is the event plan.
    """
    return RuntimeSample(request_id=int(request_id), raw=(0,) * int(cycles),
                         events=tuple(events))


def package_samples(program, request_prefix: int) -> tuple[list[RuntimeSample], dict[int, list[int]]]:
    """The three samples of one package and the service ledger each must show.

    Sample 0 raises both pins in one cycle (fixed lowest-id priority then serves
    the edge source first), sample 1 raises the level source first (so the level
    source is served first), sample 2 raises only the level source (so the edge
    source is an explicitly unserved record).  All three run against one build.
    """
    plan = irq_plan()
    edge_id, level_id = declared_ids(plan)
    edge_slot = source_slot(program, EDGE_INSTANCE)
    level_slot = source_slot(program, LEVEL_INSTANCE)
    samples = [
        irq_sample(request_prefix + 1, SIMULTANEOUS_CYCLES,
                   trigger_events(program, {edge_slot: DECLARED_RAISE_CYCLE,
                                            level_slot: DECLARED_RAISE_CYCLE})),
        irq_sample(request_prefix + 2, LEVEL_FIRST_CYCLES,
                   trigger_events(program, {edge_slot: DELAYED_RAISE_CYCLE,
                                            level_slot: DECLARED_RAISE_CYCLE})),
        irq_sample(request_prefix + 3, SINGLE_CYCLES,
                   trigger_events(program, {level_slot: DECLARED_RAISE_CYCLE})),
    ]
    ledgers = {0: [edge_id, level_id], 1: [level_id, edge_id], 2: [level_id]}
    return samples, ledgers


# ---------------------------------------------------------------------------
# what one run says about each declared source
# ---------------------------------------------------------------------------


def ram_index(plan, program) -> int:
    """The plan's fabric target index of the program's RAM region.

    The runtime reads each memory target back as ``u_mem_<its fabric index>``
    (``soc_runtime._memory_slots``), so the index is derived from the plan and not
    guessed from the observation names.
    """
    ram_region = str(program.document["memory"]["ram_region_id"])
    fabric = plan.plan["fabric"]
    wanted = None
    for row in fabric["decode"]["windows"]:
        if str(row.get("window_id")) == ram_region:
            wanted = int(row["target_index"])
            break
    if wanted is not None:
        for position, target in enumerate(fabric["targets"]):
            if (int(target.get("index", position)) == wanted
                    and target.get("backing_kind") == "memory"):
                return position
    raise AssertionError(f"the plan has no memory target backing region {ram_region!r}")


def ram_instance(plan, program, result_document: Mapping[str, object]) -> str:
    """The observed memory instance that carries the program's RAM report.

    The index comes from the plan, and the choice is then *checked* against the
    run: the word at the program's flag address must be the program's completion
    flag, or the word at ``source_count`` must be the program's declared source
    count.  A readback of a different build satisfies neither, so a report is
    never decoded out of the wrong memory.
    """
    index = ram_index(plan, program)
    observations = result_document.get("observations") or {}
    memory = program.document["memory"]
    anchors = (
        (int(memory["flag_address"]), COMPLETION_FLAG, "completion flag"),
        (report_address(program, "source_count"),
         len(program.document["sources"]), "declared source count"),
    )
    for address, expected, label in anchors:
        if _read_word(observations, int(memory["ram_base"]), int(address), index) == expected:
            return f"u_mem_{index}"
    raise AssertionError(
        f"the run's u_mem_{index} readback carries neither the completion flag nor the "
        f"declared source count, so it is not this program's RAM report")


def _read_word(observations: Mapping[str, object], base: int, address: int,
               index: int) -> int | None:
    offset = int(address) - int(base)
    if offset < 0:
        return None
    word_index, lane = divmod(offset, 8)
    word = observations.get(f"u_mem_{index}[{word_index}]")
    if word is None:
        return None
    return (int(word) >> (lane * 8)) & 0xFFFF_FFFF


def report_address(program, field: str) -> int:
    """The address the program's own report layout gives one field."""
    for item in program.document["report"]["layout"]:
        if str(item["name"]) == field:
            return int(item["address"])
    raise AssertionError(f"the program declares no report field {field!r}")


def report_word(plan, program, result_document: Mapping[str, object], field: str) -> int | None:
    """One 32-bit word of the program's RAM report, from the run's own readback."""
    observations = result_document.get("observations") or {}
    memory = program.document["memory"]
    index = ram_index(plan, program)
    return _read_word(observations, int(memory["ram_base"]), report_address(program, field),
                      index)


def claim_ledger(program, result_document: Mapping[str, object]) -> tuple[int, ...]:
    """The ids the CPU completed, in the order it completed them.

    The ISR writes the claimed id to the controller's COMPLETE register, so the
    write data of those stores is the CPU's own record of what it claimed; the
    field is compared by ``replay_package`` as
    ``fabric_request[i].0x<complete-address>.wdata``.
    """
    controller = program.document["controller"]
    complete_address = int(controller["base"]) + int(controller["registers_used"]["COMPLETE"])
    writes = [entry for entry in _records(result_document.get("fabric_requests"))
              if isinstance(entry, Mapping) and int(entry.get("write", 0)) == 1]
    completes = sorted((entry for entry in writes
                        if int(entry.get("addr", -1)) == complete_address),
                       key=lambda entry: int(entry["cycle"]))
    return tuple(int(entry["wdata"]) for entry in completes)


def irq_service_records(plan, program, result_document: Mapping[str, object]) \
        -> tuple[dict[str, object], ...]:
    """One record per declared source: the CPU's own service evidence for it.

    Invariants this function exists to keep testable:

    * the tuple has exactly one entry per source the *plan* declares, in the
      plan's numbering, so a source the run never served is an explicit record
      with ``service_round=None`` rather than a missing entry;
    * the tuple is a pure projection of the run document -- the claim id and
      COMPLETE store come from ``fabric_requests`` (compared by name on replay),
      the pending and cleared-cause words from the program's RAM report
      (compared as ``observation:u_mem_N[k]``), and the declared clear target and
      enable mask from the plan/program declaration covered by the plan hash and
      the boot-image hash.  Nothing here is an independent claim about the run;
    * the program's report keeps the *first* claim's pending sample and the first
      served source's cleared status only, so those two fields are attributed to
      the first-claimed source by comparing the recorded mask with that source's
      own enable mask; every other source is evidenced by its own COMPLETE store
      and by never being claimed a second time;
    * a truncated window (a reduced counterexample can end at the service
      boundary) may cut off the program's trailing bookkeeping, so the
      report-derived fields of such a run stay ``None`` rather than being guessed
      from a summary counter.  The claim/COMPLETE ledger is unaffected, which is
      why the failure property is read from it and not from a counter.
    """
    sources = declared_sources(plan)
    declared = tuple(program.document["sources"])
    controller = program.document["controller"]
    complete_address = int(controller["base"]) + int(controller["registers_used"]["COMPLETE"])
    requests = [entry for entry in _records(result_document.get("fabric_requests"))
                if isinstance(entry, Mapping)]
    completes = [entry for entry in requests
                 if int(entry.get("write", 0)) == 1
                 and int(entry.get("addr", -1)) == complete_address]
    completes.sort(key=lambda entry: int(entry["cycle"]))
    ledger = [int(entry["wdata"]) for entry in completes]
    first_pending = report_word(plan, program, result_document, "pending_before_claim")
    last_pending = report_word(plan, program, result_document, "pending_word_after_complete")
    cause_before = report_word(plan, program, result_document, "cause_before_clear")
    cause_after = report_word(plan, program, result_document, "cause_after_clear")
    status_after = report_word(plan, program, result_document, "status_raw_after_clear")
    records: list[dict[str, object]] = []
    for setup in declared:
        source_id = int(setup["source_id"])
        plan_source = sources.get(source_id)
        if plan_source is None:
            raise AssertionError(f"the program declares source id {source_id}, the plan does not")
        if str(plan_source["instance_id"]) != str(setup["instance_id"]):
            raise AssertionError(
                f"source id {source_id} is {plan_source['instance_id']} in the plan and "
                f"{setup['instance_id']} in the program")
        mask = int(setup["controller_enable"]["mask"])
        rounds = [index for index, claimed in enumerate(ledger) if claimed == source_id]
        round_index = rounds[0] if rounds else None
        # The program's own report names the first claim's pending sample and the
        # first served source's post-clear status; the mask identifies which
        # source those belong to instead of assuming the plan's order.
        first_claimed = bool(ledger) and ledger[0] == source_id and first_pending == mask
        record: dict[str, object] = {
            "source_id": source_id,
            "instance_id": str(setup["instance_id"]),
            "endpoint_id": str(plan_source["endpoint_id"]),
            "declared_trigger": str(plan_source["trigger"]),
            "normalizer": str(plan_source["normalizer"].get("kind")),
            "controller_bit": int(plan_source["controller_bit"]),
            "controller_enable_mask": mask,
            "clear_target": {
                "register": str(setup["clear"]["register"]),
                "kind": str(setup["clear"]["kind"]),
                "offset": int(setup["clear"]["offset"]),
                "address": int(setup["window_base"]) + int(setup["clear"]["offset"]),
            },
            "service_round": round_index,
            "service_count": len(rounds),
            "claim_id": ledger[round_index] if round_index is not None else None,
            "claim_matches_declared_id":
                None if round_index is None else bool(ledger[round_index] == source_id),
            "cleared_once": len(rounds) == 1,
            "complete": None,
            "complete_evidence": None,
            "pending_mask_at_first_claim": first_pending if first_claimed else None,
            "pending_bit_after_last_complete":
                None if last_pending is None else bool(last_pending & mask),
            "declared_cause_before_clear": cause_before if first_claimed else None,
            "declared_cause_after_clear": cause_after if first_claimed else None,
            "peripheral_status_after_clear": status_after if first_claimed else None,
        }
        if round_index is not None:
            entry = completes[round_index]
            record["complete"] = {"cycle": int(entry["cycle"]), "addr": int(entry["addr"]),
                                 "wdata": int(entry["wdata"])}
            record["complete_evidence"] = (
                f"fabric_request[{requests.index(entry)}].0x{int(entry['addr']):x}.wdata")
        records.append(record)
    return tuple(records)


def irq_service_document(plan, program, samples: Sequence[RuntimeSample],
                         results: Sequence[object]) -> dict[str, object]:
    """The per-sample per-source records a package carries in its attribution."""
    entries = []
    for position, result in enumerate(results):
        sample = samples[position]
        entries.append({
            "position": position,
            "request_id": int(sample.request_id),
            "event_plan": len(sample.events),
            "sources": [dict(record) for record in
                        irq_service_records(plan, program, _document(result))],
        })
    return {"schema_version": IRQ_SERVICE_SCHEMA, "samples": entries}


def irq_service_mismatches(plan, program, package) -> tuple[str, ...]:
    """Name every stored per-source record that disagrees with the run it describes.

    This is what keeps the stored record honest: it is not an independent claim
    but a projection of the compared fields, so recomputing it from
    ``package.results`` must reproduce it exactly.  A deleted record is reported
    as ``sample<i>:source<id>:record-missing``; an edited value is reported with
    the field it was edited in.
    """
    stored = package.attribution.get(IRQ_SERVICE_KEY) \
        if isinstance(package.attribution, Mapping) else None
    if not isinstance(stored, Mapping):
        return ("irq-service-record-missing",)
    entries = {int(item["position"]): item for item in _records(stored.get("samples"))
               if isinstance(item, Mapping) and "position" in item}
    problems: list[str] = []
    for position, result in enumerate(package.results):
        expected = {int(record["source_id"]): record
                    for record in irq_service_records(plan, program, result)}
        entry = entries.get(position)
        if entry is None:
            problems.append(f"sample{position}:record-missing")
            continue
        observed = {int(record["source_id"]): record
                    for record in _records(entry.get("sources")) if isinstance(record, Mapping)}
        for source_id, record in sorted(expected.items()):
            found = observed.get(source_id)
            if found is None:
                problems.append(f"sample{position}:source{source_id}:record-missing")
                continue
            for field in sorted(set(record) | set(found)):
                if record.get(field) != found.get(field):
                    problems.append(f"sample{position}:source{source_id}:{field}")
        for source_id in sorted(set(observed) - set(expected)):
            problems.append(f"sample{position}:source{source_id}:undeclared-record")
    return tuple(problems)


def first_request_divergence(saved: Mapping[str, object], replayed: Mapping[str, object]) -> str:
    """The request field label where a replay's request capture first differs.

    The label is spelled exactly as ``soc_failure_evidence._comparison_fields``
    spells it (``fabric_request[<index>].0x<address>.<field>``) and the field order
    is the order it inserts them, so the located field of a replay can be predicted
    from the two captures and asserted exactly instead of being accepted as
    "something diverged".
    """
    left = _records(saved.get("fabric_requests"))
    right = _records(replayed.get("fabric_requests"))
    for index in range(max(len(left), len(right))):
        before = left[index] if index < len(left) else {}
        after = right[index] if index < len(right) else {}
        assert isinstance(before, Mapping) and isinstance(after, Mapping)
        for field in ("cycle", "addr", "write", "wdata", "be", "source"):
            if before.get(field) != after.get(field):
                address = int(before.get("addr", after.get("addr", 0)))
                return f"fabric_request[{index}].0x{address:x}.{field}"
    raise AssertionError("the two captures have identical request records")


def complete_evidence_problems(result_document: Mapping[str, object],
                               record: Mapping[str, object]) -> tuple[str, ...]:
    """Whether a record's ``complete_evidence`` label names the store it claims.

    The label is a promise about where the value came from; this checks it against
    the run document itself, so a record whose label points at a different request
    (or at no request at all) is reported instead of being trusted.
    """
    label = str(record.get("complete_evidence", ""))
    match = re.match(r"^fabric_request\[(\d+)\]\.0x([0-9a-f]+)\.wdata$", label)
    if match is None:
        return (f"complete-evidence-label:{label}",)
    entries = _records(result_document.get("fabric_requests"))
    index = int(match.group(1))
    if index >= len(entries) or not isinstance(entries[index], Mapping):
        return (f"complete-evidence-index:{label}",)
    entry = entries[index]
    problems = []
    if int(entry.get("write", 0)) != 1:
        problems.append(f"complete-evidence-not-a-write:{label}")
    if int(entry.get("addr", -1)) != int(match.group(2), 16):
        problems.append(f"complete-evidence-address:{label}")
    complete = record.get("complete")
    if not isinstance(complete, Mapping):
        return tuple(problems + [f"complete-evidence-without-store:{label}"])
    for field in ("cycle", "addr", "wdata"):
        if int(complete.get(field, -1)) != int(entry.get(field, -2)):
            problems.append(f"complete-evidence-{field}:{label}")
    return tuple(problems)


def applied_trace_problems(result_document: Mapping[str, object]) -> tuple[str, ...]:
    """Whether one run's applied trace is the faithful change log of its own trace.

    The per-cycle trace carries the raw word and the value each declared special
    input was driven to; ``applied_trace`` is the driver's change log.  A package
    that saved a change log disagreeing with the trace it belongs to -- an entry
    for a value that never changed, a missing change, an order that is not the
    applied order -- is caught here.  A run whose raw words hold every slot at its
    reset value has an empty log, which is recorded as such rather than padded.
    """
    trace = [entry for entry in _records(result_document.get("trace"))
             if isinstance(entry, Mapping)]
    ports = sorted({str(name) for entry in trace for name in entry
                    if name not in ("cycle", "raw")})
    previous = {name: 0 for name in ports}
    expected: list[dict[str, int | str]] = []
    for entry in trace:
        for name in ports:
            value = int(entry.get(name, 0))
            if value != previous[name]:
                expected.append({"cycle": int(entry["cycle"]), "port": name, "value": value})
                previous[name] = value
    observed = [{"cycle": int(item["cycle"]), "port": str(item["port"]),
                 "value": int(item["value"])}
                for item in _records(result_document.get("applied_trace"))
                if isinstance(item, Mapping)]
    if expected != observed:
        return (f"applied-trace-mismatch:expected={len(expected)}:observed={len(observed)}",)
    return ()


def service_transactions(program, result_document: Mapping[str, object]) \
        -> tuple[tuple[int, int, int], ...]:
    """The accepted CPU writes that constitute the interrupt service.

    Everything the CPU accepted into the controller's window (the ENABLE setup
    write and one COMPLETE per service round) plus any write to a declared clear
    target, as ``(cycle, address, write data)``.  All of it lives in
    ``fabric_requests``, so a replay that accepted a different set of transactions
    is a divergence and not an interpretation.
    """
    controller = program.document["controller"]
    base = int(controller["base"])
    size = int(controller["size"])
    clears = {int(setup["window_base"]) + int(setup["clear"]["offset"])
              for setup in program.document["sources"]}
    transactions = []
    for entry in _records(result_document.get("fabric_requests")):
        if not isinstance(entry, Mapping) or int(entry.get("write", 0)) != 1:
            continue
        address = int(entry.get("addr", -1))
        if base <= address < base + size or address in clears:
            transactions.append((int(entry["cycle"]), address, int(entry["wdata"])))
    return tuple(sorted(transactions))


def event_ordering(sample: RuntimeSample) -> tuple[tuple[int, int, int], ...]:
    """A sample's external event plan as its own ordering: cycle, slot, value."""
    return tuple((int(item.cycle), int(item.slot), int(item.value))
                 for item in sorted(sample.events, key=lambda item: (item.cycle, item.slot)))


def irq_failure_property(plan, program, sample: RuntimeSample,
                         result_document: Mapping[str, object]) -> dict[str, object]:
    """The precise property a reduced counterexample must still exhibit.

    Four parts, all read from the run and its input, none of them a summary
    counter: which source ids the CPU completed and in what order, which declared
    ids it never completed, the accepted service transactions, and the event
    ordering of the input that produced them.
    """
    ledger = claim_ledger(program, result_document)
    return {
        "claimed_source_ids": list(ledger),
        "unserved_source_ids": [source_id for source_id in sorted(declared_sources(plan))
                                if source_id not in ledger],
        "service_transactions": [list(item) for item in
                                 service_transactions(program, result_document)],
        "event_ordering": [list(item) for item in event_ordering(sample)],
    }


def _document(result: object) -> Mapping[str, object]:
    """One run as its document, whether it was handed over as a result or a mapping."""
    if isinstance(result, RunResult):
        return result.document()
    if isinstance(result, Mapping):
        return result
    raise AssertionError(f"unsupported run result {type(result).__name__}")


def build_irq_package(plan, build, policy, samples: Sequence[RuntimeSample],
                      results: Sequence[object], *, attribution: Mapping[str, object] | None = None,
                      **overrides):
    """Build one package that carries the per-source IRQ record of every sample.

    ``attribution`` keeps any other caller evidence (a defect finding, say) and
    always gains the per-sample per-source record of ``IRQ_SERVICE_KEY``.
    """
    record = dict(attribution or {})
    if samples is not None:
        record[IRQ_SERVICE_KEY] = irq_service_document(plan, irq_program(), samples, results)
    arguments: dict[str, object] = {"kind": "irq_multisource_evidence", "attribution": record}
    if samples is not None:
        arguments["samples"] = list(samples)
    arguments.update(overrides)
    return build_evidence_package(plan, build, policy, list(results), **arguments)


# ---------------------------------------------------------------------------
# the deterministic run model the pure half uses
# ---------------------------------------------------------------------------


def pure_irq_run(build: RuntimeBuild, sample: RuntimeSample, *,
                 timeout_seconds: int = 600) -> RunResult:
    """A run of the two-source plan, modelled from what the real runs do.

    The model is not a second SoC: it applies the rules the real composition was
    observed to follow -- the event plan raises a source, an ENABLEd pending source
    is claimed lowest-id-first, the ISR samples the pending word, claims, reads the
    status, clears through the declared clear register, completes with the claimed
    id and reads IN_SERVICE -- and it writes the same RAM report the generated
    program writes (the first claim's pending mask, the first served source's
    cleared status, the post-COMPLETE pending bitmap).  It drives the packaging,
    replay and minimisation machinery, and every rule it applies is separately
    asserted against the real build in the gated half of this module.
    """
    plan = irq_plan()
    program = irq_program()
    declared = tuple(program.document["sources"])
    controller = program.document["controller"]
    base = int(controller["base"])
    registers = controller["registers_used"]
    slots = {source_slot(program, str(setup["instance_id"])): int(setup["source_id"])
             for setup in declared}
    setup_by_id = {int(setup["source_id"]): setup for setup in declared}
    # Which sources the event plan raises, in the order the events arrive.  A
    # source is raised once: a repeated drive of the same pin is the same
    # condition, exactly as a held level is.
    raised: list[tuple[int, int]] = []
    for event in sorted(sample.events, key=lambda item: (item.cycle, item.slot)):
        source_id = slots.get(int(event.slot))
        if source_id is None or int(event.value) == 0:
            continue
        if any(existing == source_id for _, existing in raised):
            continue
        raised.append((int(event.cycle), source_id))
    cycles = len(sample.raw)
    requests: list[dict[str, int]] = []
    responses: list[dict[str, int]] = []
    enable_cycle = 4
    if cycles > enable_cycle:
        enable_mask = 0
        for setup in declared:
            enable_mask |= int(setup["controller_enable"]["mask"])
        requests.append({"cycle": enable_cycle, "addr": base + int(registers["ENABLE0"]),
                         "write": 1, "wdata": enable_mask, "be": 0xF, "source": 1})
    served: list[int] = []
    sequence = 0
    for round_index, (raise_cycle, source_id) in enumerate(raised):
        claim_cycle = raise_cycle + 10 + 20 * round_index
        complete_cycle = claim_cycle + 4
        if complete_cycle >= cycles:
            # The raw stream ended before the CPU could finish this round: the
            # sample is too short, which is what makes the cycle window a real
            # dimension of the evidence rather than a constant.
            break
        setup = setup_by_id[source_id]
        served.append(source_id)
        clear_address = int(setup["window_base"]) + int(setup["clear"]["offset"])
        for address in (base + int(registers["PENDING0"]), base + int(registers["CLAIM"]),
                        int(setup["window_base"]) + int(setup["status"]["offset"]),
                        clear_address, base + int(registers["IN_SERVICE"])):
            responses.append({"seq": sequence, "addr": address, "write": 0,
                              "rdata": source_id if address == base + int(registers["CLAIM"])
                              else 0, "source": 1})
            sequence += 1
        requests.append({"cycle": complete_cycle, "addr": base + int(registers["COMPLETE"]),
                         "write": 1, "wdata": source_id, "be": 0xF, "source": 1})
    requests.sort(key=lambda entry: int(entry["cycle"]))
    responses.sort(key=lambda entry: int(entry["seq"]))
    # The pending bits still set at the last claim: every raised source that has
    # not been claimed yet.  The program samples this word on every entry and the
    # last write wins, exactly as the real report behaves.
    pending_at_last_claim = 0
    for _, source_id in raised[:len(served) + 1]:
        if source_id not in served:
            pending_at_last_claim |= int(setup_by_id[source_id]["controller_enable"]["mask"])
    pending_after_complete = 0
    for _, source_id in raised:
        if source_id not in served:
            pending_after_complete |= int(setup_by_id[source_id]["controller_enable"]["mask"])
    first = served[0] if served else None
    cause_mask = (1 << int(setup_by_id[first]["status"]["cause_bit"])) if first else 0
    report = {
        "claim_id": first or 0,
        "handler_entries": len(served),
        "complete_accepted": 1 if served else 0,
        "final_in_service": 0,
        "source_count": len(declared),
        "pending_before_claim": 0 if first is None
        else int(setup_by_id[first]["controller_enable"]["mask"]),
        "cause_before_clear": cause_mask,
        "cause_after_clear": 0,
        "status_raw_before_clear": cause_mask,
        "status_raw_after_clear": 0,
        "pending_word_0_before_claim": pending_at_last_claim,
        "pending_word_1_before_claim": 0,
        "pending_word_after_complete": pending_after_complete,
        "unknown_claim": 0,
        "loop_closed": 1 if len(served) == len(declared) else 0,
        "all_sources_closed": 1 if len(served) == len(declared) else 0,
        "main_completed": 1,
        "interrupt_completions": len(served),
    }
    memory = program.document["memory"]
    ram_base = int(memory["ram_base"])
    index = ram_index(plan, program)
    words: dict[int, int] = {}
    for field, value in report.items():
        offset = report_address(program, field) - ram_base
        word_index, lane = divmod(offset, 8)
        words[word_index] = words.get(word_index, 0) | (value << (lane * 8))
    if served:
        # The program stamps its completion flag into RAM after every completion.
        words[0] = words.get(0, 0) | COMPLETION_FLAG
    observations: dict[str, int] = {f"u_mem_{index}[{word_index}]": words.get(word_index, 0)
                                    for word_index in range(32)}
    # The driver's own exported applied value for every declared special input,
    # and the change log it produces, exactly as the generated top exports them.
    applied: list[dict[str, int]] = []
    # The driver logs a change only when the value it applies differs from the one
    # it last applied, and its register resets to 0: an all-zero run has an empty
    # change log (which is what the real runs of these samples produce).
    previous: dict[str, int] = {str(slot["name"]): 0 for slot in build.slots}
    for cycle, raw in enumerate(sample.raw):
        for slot in build.slots:
            width = int(slot["width"])
            value = (int(raw) >> int(slot["raw_lo"])) & ((1 << width) - 1)
            if previous.get(str(slot["name"])) != value:
                applied.append({"cycle": cycle, "port": str(slot["name"]), "value": value})
                previous[str(slot["name"])] = value
    for slot in build.slots:
        observations[f"{slot['name']}__applied"] = previous.get(str(slot["name"]), 0)
    trace = []
    for cycle, raw in enumerate(sample.raw):
        entry = {"cycle": cycle, "raw": int(raw)}
        for slot in build.slots:
            width = int(slot["width"])
            entry[str(slot["name"])] = (int(raw) >> int(slot["raw_lo"])) & ((1 << width) - 1)
        trace.append(entry)
    return RunResult(
        request_id=sample.request_id, cycles=cycles, status="OK",
        counters={"cycles": cycles, "observations": len(observations),
                  "applied_changes": len(applied)},
        observations=observations, trace=tuple(trace), applied=tuple(applied),
        stdout="", stderr="", reason="",
        requests=tuple(requests), responses=tuple(responses))


def pure_build(directory: Path, plan=None, program=None) -> RuntimeBuild:
    """A ``RuntimeBuild``-shaped record the package machinery accepts, without a compile.

    The generated-testbench record is what ``recorded_build_identity`` reads, so a
    two-line file carrying the plan's own hash and the plan's own raw-layout hash
    binds a package to this directory exactly as a compiled build would.  The top,
    the executable and the boot image are real files, so every identity hash the
    package records is a real content hash rather than ``missing``.
    """
    plan = plan if plan is not None else irq_plan()
    program = program if program is not None else irq_program()
    testbench = directory / "myfuzz_profile_tb.sv"
    testbench.write_text(
        "// Generated by myfuzz profile runtime. Do not edit.\n"
        f"// plan: {plan.plan_hash}\n"
        f"// raw-input layout: {plan.raw_layout['layout_hash']}\n"
        "module myfuzz_profile_tb; endmodule\n", encoding="utf-8")
    top = directory / "myfuzz_soc_top.sv"
    top.write_text("module myfuzz_soc_top; endmodule\n", encoding="utf-8")
    executable = directory / "myfuzz_profile_sim"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    boot_image = directory / "boot_program.hex"
    boot_image.write_text(image_hex(program.image), encoding="utf-8")
    slots = []
    raw_width = int(plan.raw_layout["raw_width"])
    for item in plan.raw_layout.get("special_inputs", ()):
        raw_width = max(raw_width, int(item["raw_hi"]) + 1)
        slots.append({"name": str(item["top_port"]), "width": int(item["width"]),
                      "raw_lo": int(item["raw_lo"]), "raw_hi": int(item["raw_hi"]),
                      "strategy": str(item["strategy"]), "instance_id": str(item["instance_id"]),
                      "port": str(item["port"])})
    slots.sort(key=lambda item: str(item["name"]))
    return RuntimeBuild(
        output_dir=directory, top_path=top, testbench_path=testbench, executable=executable,
        sources=("pure test double: no RTL is compiled",), raw_width=raw_width,
        slots=tuple(slots), observations=(), boot_image=boot_image,
        boot_image_policy="external_image", build_hash="sha256:" + "3" * 64, warnings=0)


# ---------------------------------------------------------------------------
# pure: the package, the replay, the tamper detection and the reduction
# ---------------------------------------------------------------------------


class PureIrqEvidencePackageTests(unittest.TestCase):
    """The packaging/replay contract, driven by a deterministic run model.

    The plan, the generated program, the constraint policy and the interrupt plan
    are the real ones; only the simulator is replaced, so a failure here is a
    failure of the evidence machinery and not of the RTL.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = irq_plan()
        cls.program = irq_program()
        cls.policy = irq_policy()
        cls.edge_id, cls.level_id = declared_ids(cls.plan)
        cls.setups = {int(setup["source_id"]): setup
                      for setup in cls.program.document["sources"]}

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-irq-evidence-", dir=ROOT)
        self.directory = Path(self._temporary.name)
        self.build = pure_build(self.directory)
        self.samples, self.ledgers = package_samples(self.program, 0x1A00)
        patcher = unittest.mock.patch.object(evidence_module, "run_sample", pure_irq_run)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.results = [pure_irq_run(self.build, sample) for sample in self.samples]

    def tearDown(self) -> None:
        self._temporary.cleanup()

    # -- fixtures and helpers ---------------------------------------------

    def package(self, **overrides):
        arguments = {
            "legality": applied_legality(self.build, self.samples[0], self.results[0]),
            "criteria": [{"criterion_id": "irq-source-service-ledger",
                          "statement": "every raised source is claimed by its own id, cleared "
                                       "through its declared register and completed",
                          "basis": "src/myfuzz/protocols/rtl/soc_irq_controller.sv service "
                                   "contract plus the profile's declared clear operation",
                          "independent": True}],
        }
        arguments.update(overrides)
        samples = arguments.pop("samples", self.samples)
        results = arguments.pop("results", self.results)
        return build_irq_package(self.plan, self.build, self.policy, samples, results,
                                 **arguments)

    def assert_service_record(self, result_document, record, ledger_position, *,
                              cause_mask: int, first_claim_mask: int | None) -> None:
        """One source's record must say exactly what the run did for it, field by field."""
        if ledger_position is None:
            self.assertIsNone(record["service_round"])
            self.assertIsNone(record["claim_id"])
            self.assertIsNone(record["claim_matches_declared_id"])
            self.assertIsNone(record["complete"])
            self.assertIsNone(record["complete_evidence"])
            self.assertFalse(record["cleared_once"])
            self.assertIsNone(record["pending_mask_at_first_claim"])
        else:
            self.assertEqual(ledger_position, record["service_round"])
            self.assertEqual(record["source_id"], record["claim_id"])
            self.assertTrue(record["claim_matches_declared_id"])
            self.assertTrue(record["cleared_once"],
                            "the source was claimed again: its declared clear did not take")
            # The evidence label must name the very COMPLETE store it was read from.
            self.assertEqual((), complete_evidence_problems(result_document, record))
            self.assertEqual(record["claim_id"], record["complete"]["wdata"])
        if record["pending_mask_at_first_claim"] is not None:
            self.assertEqual(record["pending_mask_at_first_claim"],
                             record["controller_enable_mask"],
                             "the first claim's pending sample must name this source's own bit")
            self.assertEqual(record["pending_mask_at_first_claim"], first_claim_mask)
            self.assertEqual(record["declared_cause_before_clear"], cause_mask)
            self.assertEqual(record["declared_cause_after_clear"], 0)
            self.assertEqual(record["peripheral_status_after_clear"], 0)
        else:
            self.assertIsNone(record["declared_cause_before_clear"])
            self.assertIsNone(record["declared_cause_after_clear"])
            self.assertIsNone(record["peripheral_status_after_clear"])
        self.assertFalse(record["pending_bit_after_last_complete"])
        self.assertTrue(str(record["clear_target"]["register"]))
        self.assertTrue(str(record["clear_target"]["kind"]))
        self.assertGreater(int(record["clear_target"]["offset"]), 0)

    def tampered_claim_package(self, package, position: int, *, forge: int):
        """The package with one source's COMPLETE record forged to another id.

        The forged value is written where the CPU's own claim really is -- the
        write data of the second COMPLETE store in ``fabric_requests`` -- so the
        package is internally consistent and only a replay against the real build
        can tell that the run it describes never happened.
        """
        controller = self.program.document["controller"]
        complete_address = int(controller["base"]) + int(
            controller["registers_used"]["COMPLETE"])
        results = [dict(result) for result in package.results]
        requests = [dict(entry) for entry in _records(results[position]["fabric_requests"])]
        completes = [index for index, entry in enumerate(requests)
                     if int(entry.get("write", 0)) == 1
                     and int(entry.get("addr", -1)) == complete_address]
        self.assertEqual(2, len(completes))
        index = completes[1]
        requests[index] = dict(requests[index], wdata=int(forge))
        results[position] = dict(results[position], fabric_requests=requests)
        return dataclasses.replace(package, results=tuple(results)), index

    # -- the package -------------------------------------------------------

    def test_one_package_carries_every_sample_and_the_full_identity(self) -> None:
        package = self.package()
        self.assertTrue(package.inputs_complete)
        self.assertEqual(3, len(package.samples))
        self.assertEqual(3, len(package.results))
        identity = package.identity
        for name in REQUIRED_IDENTITY:
            with self.subTest(field=name):
                self.assertTrue(identity.get(name), f"{name} is not bound")
        self.assertEqual(self.plan.plan_hash, identity["plan_hash"])
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]), identity["layout_hash"])
        self.assertEqual(self.policy.policy_hash, identity["policy_hash"])
        self.assertEqual(self.build.build_hash, identity["build_hash"])
        self.assertEqual({"novagpio", "ibex"}, set(identity["profile_hashes"]))
        self.assertTrue(str(identity["tool"]["executable_hash"]).startswith("sha256:"))
        self.assertNotEqual("missing", identity["boot_image_hash"])
        for position, sample in enumerate(self.samples):
            with self.subTest(sample=position):
                self.assertEqual(list(sample.raw), list(package.sample(position).raw))
                self.assertEqual(
                    event_ordering(sample),
                    tuple((int(item["cycle"]), int(item["slot"]), int(item["value"]))
                          for item in package.samples[position]["events"]))
                result = package.result(position)
                self.assertEqual(len(sample.raw), len(_records(result["trace"])))
                self.assertIn("applied_trace", result)
                self.assertEqual((), applied_trace_problems(result))
        # The applied trace is the driver's change log, and the legality record
        # compares it with the raw field that requested it.
        self.assertEqual("confirmed",
                         package.legality["environment_legality"], package.legality)

    def test_every_source_has_a_claim_clear_and_complete_record(self) -> None:
        package = self.package()
        source_ids = sorted(declared_sources(self.plan))
        for position, result in enumerate(package.results):
            records = irq_service_records(self.plan, self.program, result)
            ledger = list(claim_ledger(self.program, result))
            with self.subTest(sample=position):
                self.assertEqual(self.ledgers[position], ledger)
                self.assertEqual(source_ids, [record["source_id"] for record in records])
                self.assertEqual([self.edge_id, self.level_id],
                                 [int(record["source_id"]) for record in records])
                self.assertEqual((), applied_trace_problems(result))
                for record in records:
                    source_id = int(record["source_id"])
                    position_in_ledger = (ledger.index(source_id)
                                          if source_id in ledger else None)
                    first = ledger[0] if ledger else None
                    self.assert_service_record(
                        result, record, position_in_ledger,
                        cause_mask=(1 << int(self.setups[source_id]["status"]["cause_bit"])
                                    if position_in_ledger is not None else 0),
                        first_claim_mask=(int(record["controller_enable_mask"])
                                          if source_id == first else None))
                self.assertEqual(1, len([record for record in records
                                         if record["pending_mask_at_first_claim"] is not None]),
                                 "exactly the first-claimed source carries the report's "
                                 "first-claim pending sample")

    def test_the_relied_on_rules_are_the_ones_the_model_applies(self) -> None:
        """The invariants the real half asserts must hold in the model too."""
        package = self.package()
        for position, result in enumerate(package.results):
            with self.subTest(sample=position):
                ledger = list(claim_ledger(self.program, result))
                self.assertEqual(ledger, self.ledgers[position])
                self.assertEqual(len(ledger),
                                 report_word(self.plan, self.program, result,
                                             "interrupt_completions"))
                self.assertEqual(1 if len(ledger) == 2 else 0,
                                 report_word(self.plan, self.program, result,
                                             "all_sources_closed"))
                self.assertEqual(0, report_word(self.plan, self.program, result,
                                                "status_raw_after_clear"))
                self.assertEqual(0, report_word(self.plan, self.program, result,
                                                "pending_word_after_complete"))

    def test_the_stored_record_is_a_projection_of_the_compared_fields(self) -> None:
        package = self.package()
        self.assertEqual((), irq_service_mismatches(self.plan, self.program, package))
        stored = package.attribution[IRQ_SERVICE_KEY]
        self.assertEqual(IRQ_SERVICE_SCHEMA, stored["schema_version"])
        self.assertEqual(3, len(stored["samples"]))
        for position, result in enumerate(package.results):
            with self.subTest(sample=position):
                self.assertEqual(
                    [dict(item) for item in
                     irq_service_records(self.plan, self.program, result)],
                    stored["samples"][position]["sources"])
        # An edited copy of one source's record is named by field, not accepted.
        edited = dataclasses.replace(package, attribution={
            IRQ_SERVICE_KEY: {
                "schema_version": IRQ_SERVICE_SCHEMA,
                "samples": [dict(entry, sources=[
                    dict(record, claim_id=int(record["claim_id"]) + 1)
                    if record["claim_id"] is not None else dict(record)
                    for record in entry["sources"]]) for entry in stored["samples"]],
            },
        })
        problems = irq_service_mismatches(self.plan, self.program, edited)
        self.assertIn("sample0:source1:claim_id", problems)
        self.assertIn("sample0:source2:claim_id", problems)
        self.assertIn("sample2:source2:claim_id", problems)
        # A deleted record is named as missing rather than silently shrinking.
        deleted = dataclasses.replace(package, attribution={
            IRQ_SERVICE_KEY: {
                "schema_version": IRQ_SERVICE_SCHEMA,
                "samples": [dict(entry, sources=list(entry["sources"])[1:])
                            for entry in stored["samples"]],
            },
        })
        problems = irq_service_mismatches(self.plan, self.program, deleted)
        self.assertIn("sample0:source1:record-missing", problems)
        self.assertIn("sample2:source1:record-missing", problems)

    def test_replay_agrees_field_by_field_for_every_sample(self) -> None:
        package = self.package()
        document = write_evidence_package(package, self.directory)
        self.assertEqual(EVIDENCE_DOCUMENT, document.name)
        read_back = read_evidence_package(self.directory)
        self.assertEqual(package.document(), read_back.document())
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertTrue(replay.agreed)
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.mismatching_fields)
        self.assertEqual(3, len(replay.reruns))
        self.assertGreater(len(replay.checked_fields),
                           len(self.samples[0].raw) + len(self.samples[2].raw))
        for position, sample in enumerate(self.samples):
            self.assertIn(f"sample{position}:trace[0].raw", replay.matching_fields)
            self.assertIn(f"sample{position}:trace[{len(sample.raw) - 1}].raw",
                          replay.matching_fields)
        for position, rerun in enumerate(replay.reruns):
            with self.subTest(sample=position):
                self.assertEqual(
                    irq_service_records(self.plan, self.program, package.results[position]),
                    irq_service_records(self.plan, self.program, rerun),
                    "the per-source record of the replay differs from the saved one")

    def test_the_raw_archive_and_the_applied_trace_are_written_per_sample(self) -> None:
        package = self.package()
        write_evidence_package(package, self.directory)
        index = json.loads((self.directory / RAW_INPUT_INDEX).read_text(encoding="utf-8"))
        self.assertEqual(3, len(index["samples"]))
        applied = json.loads((self.directory / evidence_module.APPLIED_TRACE_DOCUMENT)
                             .read_text(encoding="utf-8"))
        for position, entry in enumerate(index["samples"]):
            with self.subTest(sample=position):
                payload = (self.directory / entry["file"]).read_text(encoding="utf-8")
                self.assertEqual(self.samples[position].payload(), payload)
                self.assertEqual(RAW_INPUT_DIRECTORY, Path(entry["file"]).parent.as_posix())
                self.assertEqual(len(self.samples[position].raw), entry["raw_words"])
                self.assertEqual(len(self.samples[position].events), entry["events"])
                self.assertEqual(len(self.samples[position].raw),
                                 len(applied["samples"][position]["trace"]))
                self.assertEqual(list(self.results[position].applied),
                                 applied["samples"][position]["applied_trace"])

    # -- tampering ---------------------------------------------------------

    def test_a_tampered_claim_id_is_located_by_field_name(self) -> None:
        package = self.package()
        altered, index = self.tampered_claim_package(package, 0, forge=self.edge_id)
        # The document round trip cannot see it: only the raw-input half of the
        # package is content-addressed, so the run half is bound by replay.
        write_evidence_package(altered, self.directory)
        read_back = read_evidence_package(self.directory)
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        self.assertIsNotNone(replay.divergence)
        controller = self.program.document["controller"]
        complete_address = int(controller["base"]) + int(
            controller["registers_used"]["COMPLETE"])
        label = f"sample0:fabric_request[{index}].0x{complete_address:x}.wdata"
        self.assertIn(label, replay.mismatching_fields)
        self.assertEqual(label, replay.divergence["label"])
        self.assertEqual(label[len("sample0:"):], replay.divergence["field"],
                         "the located field is the COMPLETE store of the tampered source")
        self.assertEqual("observed-fabric-request", replay.divergence["kind"])
        # The saved (tampered) run claims the edge id for the level source's round;
        # the replayed run claims the level id, which is the difference located.
        self.assertEqual(self.edge_id, replay.divergence["expected"])
        self.assertEqual(self.level_id, replay.divergence["observed"])
        self.assertEqual([label], list(replay.mismatching_fields),
                         "only the tampered claim may diverge")
        # The record derived from the tampered run shows which source lost its id.
        records = irq_service_records(self.plan, self.program, read_back.result(0))
        self.assertTrue(records[0]["claim_matches_declared_id"])
        self.assertFalse(records[1]["claim_matches_declared_id"],
                         "the forged claim id must not be accepted as the level source's")
        self.assertIn("sample0:source2:claim_id",
                      irq_service_mismatches(self.plan, self.program, altered))
        print("MYFUZZ_SOC_IRQ_TAMPER claim field=%s expected=%d observed=%d"
              % (replay.divergence["field"], replay.divergence["expected"],
                 replay.divergence["observed"]))

    def test_deleting_a_source_from_the_document_is_detected_by_the_archive(self) -> None:
        """A sample whose document lost a source's trigger no longer matches its archive."""
        package = self.package()
        document_path = write_evidence_package(package, self.directory)
        document = json.loads(document_path.read_text(encoding="utf-8"))
        events = [dict(event) for event in document["samples"][1]["events"]]
        self.assertTrue(events)
        document["samples"][1]["events"] = events[1:]
        document_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            read_evidence_package(self.directory)
        self.assertIn("raw-input-document-mismatch", str(caught.exception))

    def test_a_consistent_package_missing_one_source_diverges_at_a_named_field(self) -> None:
        """The same deletion, saved consistently: replay locates the missing service."""
        package = self.package()
        samples = list(package.samples)
        events = [dict(event) for event in samples[0]["events"]]
        dropped = [event for event in events
                   if not (int(event["slot"]) == source_slot(self.program, EDGE_INSTANCE)
                           and int(event["value"]) != 0)]
        self.assertEqual(len(events) - 1, len(dropped))
        samples[0] = dict(samples[0], events=dropped)
        truncated = dataclasses.replace(package, samples=tuple(samples))
        directory = self.directory / "consistent"
        write_evidence_package(truncated, directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(len(dropped), len(read_back.sample(0).events))
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        record_label = first_request_divergence(read_back.result(0), replay.reruns[0])
        self.assertEqual("sample0:" + record_label, replay.divergence["label"])
        self.assertEqual(record_label, replay.divergence["field"])
        self.assertEqual("observed-fabric-request", replay.divergence["kind"])
        records = irq_service_records(self.plan, self.program, replay.reruns[0])
        self.assertEqual([self.edge_id],
                         [record["source_id"] for record in records
                          if record["service_round"] is None],
                         "the replayed run served a source it never raised")
        self.assertTrue(
            [record for record in records if record["source_id"] == self.level_id][0]
            ["claim_matches_declared_id"])
        print("MYFUZZ_SOC_IRQ_TAMPER deleted_source field=%s label=%s"
              % (replay.divergence["field"], replay.divergence["label"]))

    def test_a_package_without_the_saved_event_plan_is_refused(self) -> None:
        """A trace has the raw words but not the event plan, so it cannot replay."""
        package = self.package(samples=None)
        self.assertFalse(package.inputs_complete)
        replay = replay_package(package, self.build)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("event plan is unknown", replay.reason)
        self.assertFalse(replay.reruns)

    def test_a_package_replayed_against_another_build_is_refused_by_field(self) -> None:
        package = self.package()
        other = dataclasses.replace(self.build, build_hash="sha256:" + "9" * 64)
        replay = replay_package(package, other)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("build_hash", replay.reason)

    # -- reduction ---------------------------------------------------------

    def test_the_reduction_keeps_the_source_ids_event_order_and_transactions(self) -> None:
        """A reduced counterexample must still be the same failure, not a smaller one."""
        failing = self.samples[2]
        failing_result = pure_irq_run(self.build, failing)
        original = irq_failure_property(self.plan, self.program, failing,
                                       failing_result.document())
        self.assertEqual([self.level_id], original["claimed_source_ids"])
        self.assertEqual([self.edge_id], original["unserved_source_ids"])
        self.assertTrue(original["service_transactions"])

        def predicate(result: RunResult) -> bool:
            return irq_failure_property(self.plan, self.program, failing,
                                        result.document()) == original

        minimal, log = minimize_sample(self.build, failing, predicate=predicate)
        self.assertTrue(log["preserved"], log["continuity"])
        self.assertIn(log["stopped"], ("fixed_point", "budget"))
        self.assertEqual(len(failing.events), log["events_preserved"])
        self.assertEqual(failing.events, minimal.events,
                         "the reduced sample changed the event plan that causes the failure")
        self.assertLess(len(minimal.raw), len(failing.raw))
        self.assertGreaterEqual(log["accepted"], 1)
        # The claim is re-checked on an independent run of the reduced sample, not
        # only inside the search that produced it.
        reduced_result = pure_irq_run(self.build, minimal)
        self.assertEqual(original, irq_failure_property(self.plan, self.program, minimal,
                                                        reduced_result.document()))
        self.assertEqual((self.level_id,),
                         claim_ledger(self.program, reduced_result.document()))
        records = irq_service_records(self.plan, self.program, reduced_result.document())
        self.assertEqual([None, 0], [record["service_round"] for record in records])
        self.assertEqual([False, True], [record["cleared_once"] for record in records])


# ---------------------------------------------------------------------------
# real RTL: the same plan, compiled, run, packaged, replayed and reduced
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real IRQ evidence package")
class RealIrqEvidencePackageTests(unittest.TestCase):
    """The real two-source SoC: package, replay, tamper detection and reduction.

    Two builds of one plan: as composed, and with the edge source's controller
    latch bit removed.  The first is where the multi-sample package comes from; the
    second is where the failing sample comes from, because a converter pulse the
    controller does not latch is a composition defect -- the level source is still
    served, so the failure is a missing source, not a missing run.
    """

    @classmethod
    def setUpClass(cls) -> None:
        tool = shutil.which("verilator")
        if tool is None:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires Verilator for the IRQ evidence package")
        cls.plan = irq_plan()
        cls.program = irq_program()
        cls.policy = irq_policy()
        cls.edge_id, cls.level_id = declared_ids(cls.plan)
        top = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        match = re.search(r"\.LATCH_MASK\((\d+)'b([01]+)\)", top)
        if match is None:
            raise AssertionError("the generated top has no controller LATCH_MASK")
        cls.latch_width = int(match.group(1))
        mask = int(match.group(2), 2)
        bit = 1 << (cls.edge_id - 1)
        if not mask & bit:
            raise AssertionError(f"the edge source was composed unlatched: {mask:b}")
        cls.mutated_top = (top[:match.start()]
                           + f".LATCH_MASK({cls.latch_width}'b"
                             f"{mask & ~bit:0{cls.latch_width}b})"
                           + top[match.end():])
        if cls.mutated_top == top:
            raise AssertionError("the latch mutation changed nothing")
        cls._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-irq-evidence-")
        cls.addClassCleanup(cls._temporary.cleanup)
        root = Path(cls._temporary.name)
        cls.image = root / "boot_program.hex"
        cls.image.write_text(image_hex(cls.program.image), encoding="utf-8")
        records = source_list(cls.plan)
        cls.sources = [item["path"] for item in records if item["role"] != "include_root"]
        include_roots = sorted({item["path"] for item in records
                                if item["role"] == "include_root"})
        # The runtime passes no profile include roots or defines to Verilator, and a
        # CPU closure with cross-directory includes cannot be compiled without
        # them, so the plan's declared flags go through a tiny wrapper.
        flags = [f"-I{ROOT / item}" for item in include_roots]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        cls.tool = tool
        if flags:
            wrapper = root / "verilator-with-profile-flags.sh"
            wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" % (tool, " ".join(flags)),
                               encoding="utf-8")
            wrapper.chmod(0o755)
            cls.tool = wrapper.as_posix()
        cls.builds = {
            label: build_profile_runtime(
                cls.plan, output_dir=root / label, base_dir=ROOT, top_text=text,
                sources=cls.sources, boot_image=cls.image, verilator=cls.tool,
                timeout_seconds=1800)
            for label, text in (("baseline", top), ("no_edge_latch", cls.mutated_top))}
        if cls.builds["baseline"].build_hash == cls.builds["no_edge_latch"].build_hash:
            raise AssertionError("the two builds are the same artifact")
        cls.samples, cls.ledgers = package_samples(cls.program, 0x2A00)
        cls.results = [run_sample(cls.builds["baseline"], sample, timeout_seconds=1800)
                       for sample in cls.samples]
        cls.failing_sample = cls.samples[0]
        cls.failing_result = run_sample(cls.builds["no_edge_latch"], cls.failing_sample,
                                        timeout_seconds=1800)

    # -- fixtures ----------------------------------------------------------

    def report(self, result, name: str) -> int | None:
        return report_word(self.plan, self.program, result.document(), name)

    def package(self, **overrides):
        arguments = {
            "legality": applied_legality(self.builds["baseline"], self.samples[0],
                                         self.results[0]),
            "criteria": [{"criterion_id": "irq-source-service-ledger",
                          "statement": "every raised source is claimed by its own id, cleared "
                                       "through its declared register and completed",
                          "basis": "src/myfuzz/protocols/rtl/soc_irq_controller.sv service "
                                   "contract plus the profile's declared clear operation",
                          "independent": True}],
        }
        arguments.update(overrides)
        samples = arguments.pop("samples", self.samples)
        results = arguments.pop("results", self.results)
        return build_irq_package(self.plan, self.builds["baseline"], self.policy,
                                 samples, results, **arguments)

    def reduced_witness(self):
        """The failing sample reduced once and cached: same witness everywhere."""
        cached = getattr(type(self), "_reduction", None)
        if cached is not None:
            return cached
        build = self.builds["no_edge_latch"]
        failing = self.failing_sample
        original = irq_failure_property(self.plan, self.program, failing,
                                       self.failing_result.document())

        def predicate(result: RunResult) -> bool:
            return irq_failure_property(self.plan, self.program, failing,
                                        result.document()) == original

        minimal, log = minimize_sample(build, failing, predicate=predicate,
                                      timeout_seconds=1800)
        result = run_sample(build, minimal, timeout_seconds=1800)
        cached = (minimal, log, result, original)
        type(self)._reduction = cached
        return cached

    # -- the real runs and the package -------------------------------------

    def test_the_real_runs_are_the_declared_experiment(self) -> None:
        for position, result in enumerate(self.results):
            with self.subTest(sample=position):
                self.assertEqual("OK", result.status, result.reason)
                self.assertEqual(len(self.samples[position].raw), result.cycles)
                self.assertEqual(
                    "confirmed",
                    applied_legality(self.builds["baseline"], self.samples[position],
                                     result)["environment_legality"])
                self.assertFalse(result.requests_truncated,
                                 "the request capture was truncated, so the ledger is partial")
                self.assertEqual(self.ledgers[position],
                                 list(claim_ledger(self.program, result.document())))
        self.assertEqual("confirmed",
                         applied_legality(self.builds["baseline"], self.samples[0],
                                          self.results[0])["environment_legality"])

    def test_one_package_carries_every_sample_and_the_full_identity(self) -> None:
        package = self.package()
        self.assertTrue(package.inputs_complete)
        self.assertEqual(3, len(package.samples))
        identity = package.identity
        for name in REQUIRED_IDENTITY:
            with self.subTest(field=name):
                self.assertTrue(identity.get(name), f"{name} is not bound")
        self.assertEqual(self.plan.plan_hash, identity["plan_hash"])
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]), identity["layout_hash"])
        self.assertEqual(self.policy.policy_hash, identity["policy_hash"])
        self.assertEqual(self.builds["baseline"].build_hash, identity["build_hash"])
        self.assertEqual({"novagpio", "ibex"}, set(identity["profile_hashes"]))
        runtime = identity["runtime"]
        self.assertEqual(sorted(self.sources), sorted(runtime["sources"]),
                         "the package must carry the source closure it was built from")
        self.assertEqual(set(self.sources), set(runtime["source_hashes"]))
        self.assertEqual("riscv", identity["isa"]["family"])
        self.assertEqual(32, identity["isa"]["xlen"])
        self.assertGreater(self.builds["baseline"].executable.stat().st_size, 0)
        self.assertEqual(identity["tool"]["executable_hash"],
                         runtime["executable_hash"])
        self.assertEqual(identity["boot_image_hash"],
                         "sha256:" + hashlib.sha256(self.image.read_bytes()).hexdigest())
        for position, sample in enumerate(self.samples):
            with self.subTest(sample=position):
                self.assertEqual(list(sample.raw), list(package.sample(position).raw))
                self.assertEqual(len(sample.raw),
                                 len(_records(package.result(position)["trace"])))

    def test_every_source_has_a_real_claim_clear_and_complete_record(self) -> None:
        package = self.package()
        source_ids = sorted(declared_sources(self.plan))
        for position, result in enumerate(package.results):
            records = irq_service_records(self.plan, self.program, result)
            ledger = list(self.ledgers[position])
            with self.subTest(sample=position):
                self.assertEqual(source_ids, [record["source_id"] for record in records])
                self.assertEqual(len(ledger), self.report(self.results[position],
                                                         "interrupt_completions"))
                self.assertEqual(len(ledger),
                                 len([record for record in records
                                      if record["cleared_once"]]))
                self.assertEqual((), applied_trace_problems(result))
                first = ledger[0]
                for record in records:
                    source_id = int(record["source_id"])
                    if source_id not in ledger:
                        self.assertIsNone(record["service_round"])
                        self.assertIsNone(record["claim_id"])
                        self.assertFalse(record["cleared_once"])
                        self.assertIsNone(record["pending_mask_at_first_claim"])
                        continue
                    self.assertEqual(ledger.index(source_id), record["service_round"])
                    self.assertEqual(source_id, record["claim_id"],
                                     "the CPU completed a different id than it served")
                    self.assertTrue(record["claim_matches_declared_id"])
                    self.assertTrue(record["cleared_once"],
                                    "the source was claimed twice: its declared clear failed")
                    self.assertGreater(int(record["complete"]["cycle"]), 0)
                    self.assertEqual(record["claim_id"], record["complete"]["wdata"])
                    self.assertEqual(
                        record["clear_target"]["address"],
                        int(next(setup for setup in self.program.document["sources"]
                                 if int(setup["source_id"]) == source_id)["window_base"])
                        + int(record["clear_target"]["offset"]))
                    self.assertFalse(record["pending_bit_after_last_complete"],
                                     "a source was still pending after the last COMPLETE")
                    if source_id == first:
                        self.assertEqual(int(record["controller_enable_mask"]),
                                         record["pending_mask_at_first_claim"],
                                         "the report's first-claim pending sample must name "
                                         "the first served source's own bit")
                        self.assertEqual(
                            report_word(self.plan, self.program, result,
                                        "pending_before_claim"),
                            record["pending_mask_at_first_claim"])
                        self.assertEqual(int(record["pending_mask_at_first_claim"]),
                                         1 << (source_id % PENDING_WORD_BITS))
                        self.assertEqual(1, record["declared_cause_before_clear"],
                                         "the declared cause bit was not set before the clear")
                        self.assertEqual(0, record["declared_cause_after_clear"],
                                         "the declared clear did not empty the cause")
                        self.assertEqual(0, record["peripheral_status_after_clear"])
                    else:
                        self.assertIsNone(record["pending_mask_at_first_claim"])
                    if source_id in ledger:
                        self.assertEqual((), complete_evidence_problems(result, record))
                # The aggregate report agrees with the ledger and, for the samples
                # that close, the declared clear emptied the served peripheral.
                self.assertEqual(1 if len(ledger) == 2 else 0,
                                 self.report(self.results[position], "all_sources_closed"))
                self.assertEqual(0, self.report(self.results[position],
                                                "pending_word_after_complete"))
                if len(ledger) == 2:
                    self.assertEqual(0, self.report(self.results[position],
                                                    "status_raw_after_clear"))
                    self.assertEqual(0, self.report(self.results[position],
                                                    "cause_after_clear"))
        self.assertEqual((), irq_service_mismatches(self.plan, self.program, package))

    def test_replay_agrees_field_by_field_for_every_sample(self) -> None:
        package = self.package()
        directory = Path(self._temporary.name) / "package"
        write_evidence_package(package, directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(package.document(), read_back.document())
        replay = replay_package(read_back, self.builds["baseline"], timeout_seconds=1800)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertTrue(replay.agreed)
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.mismatching_fields)
        self.assertEqual(3, len(replay.reruns))
        for position, sample in enumerate(self.samples):
            self.assertIn(f"sample{position}:trace[0].raw", replay.matching_fields)
            self.assertIn(f"sample{position}:trace[{len(sample.raw) - 1}].raw",
                          replay.matching_fields)
        for position, rerun in enumerate(replay.reruns):
            with self.subTest(sample=position):
                self.assertEqual(
                    irq_service_records(self.plan, self.program, package.results[position]),
                    irq_service_records(self.plan, self.program, rerun))
        self.assertEqual((), irq_service_mismatches(self.plan, self.program, read_back))

    # -- tampering ---------------------------------------------------------

    def test_a_tampered_claim_id_is_located_by_field_name(self) -> None:
        package = self.package()
        controller = self.program.document["controller"]
        complete_address = int(controller["base"]) + int(
            controller["registers_used"]["COMPLETE"])
        results = [dict(result) for result in package.results]
        requests = [dict(entry) for entry in _records(results[0]["fabric_requests"])]
        completes = [index for index, entry in enumerate(requests)
                     if int(entry.get("write", 0)) == 1
                     and int(entry.get("addr", -1)) == complete_address]
        self.assertEqual(2, len(completes), "the simultaneous sample must claim twice")
        index = completes[1]
        requests[index] = dict(requests[index], wdata=self.edge_id)
        results[0] = dict(results[0], fabric_requests=requests)
        altered = dataclasses.replace(package, results=tuple(results))
        directory = Path(self._temporary.name) / "tampered-claim"
        write_evidence_package(altered, directory)
        read_back = read_evidence_package(directory)
        replay = replay_package(read_back, self.builds["baseline"], timeout_seconds=1800)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        self.assertIsNotNone(replay.divergence)
        label = f"sample0:fabric_request[{index}].0x{complete_address:x}.wdata"
        self.assertIn(label, replay.mismatching_fields)
        self.assertEqual(label, replay.divergence["label"])
        self.assertEqual(label[len("sample0:"):], replay.divergence["field"],
                         "the located field is the COMPLETE store of the tampered source")
        self.assertEqual("observed-fabric-request", replay.divergence["kind"])
        # The saved (tampered) run claims the edge id for the level source's round;
        # the replayed run claims the level id, which is the difference located.
        self.assertEqual(self.edge_id, replay.divergence["expected"])
        self.assertEqual(self.level_id, replay.divergence["observed"])
        self.assertEqual([label], list(replay.mismatching_fields),
                         "only the tampered claim may diverge")
        records = irq_service_records(self.plan, self.program, read_back.result(0))
        self.assertTrue(records[0]["claim_matches_declared_id"])
        self.assertFalse(records[1]["claim_matches_declared_id"],
                         "the forged claim id must not be accepted as the level source's")
        self.assertIn("sample0:source2:claim_id",
                      irq_service_mismatches(self.plan, self.program, altered))
        print("MYFUZZ_SOC_IRQ_TAMPER claim field=%s expected=%d observed=%d"
              % (replay.divergence["field"], replay.divergence["expected"],
                 replay.divergence["observed"]))

    def test_deleting_a_source_from_the_document_is_detected_by_the_archive(self) -> None:
        package = self.package()
        directory = Path(self._temporary.name) / "archive-tamper"
        document_path = write_evidence_package(package, directory)
        document = json.loads(document_path.read_text(encoding="utf-8"))
        events = [dict(event) for event in document["samples"][1]["events"]]
        document["samples"][1]["events"] = events[1:]
        document_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            read_evidence_package(directory)
        self.assertIn("raw-input-document-mismatch", str(caught.exception))

    def test_a_consistent_package_missing_one_source_diverges_at_a_named_field(self) -> None:
        package = self.package()
        samples = list(package.samples)
        events = [dict(event) for event in samples[0]["events"]]
        dropped = [event for event in events
                   if not (int(event["slot"]) == source_slot(self.program, EDGE_INSTANCE)
                           and int(event["value"]) != 0)]
        self.assertEqual(len(events) - 1, len(dropped))
        samples[0] = dict(samples[0], events=dropped)
        truncated = dataclasses.replace(package, samples=tuple(samples))
        directory = Path(self._temporary.name) / "missing-source"
        write_evidence_package(truncated, directory)
        read_back = read_evidence_package(directory)
        replay = replay_package(read_back, self.builds["baseline"], timeout_seconds=1800)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status, replay.reason)
        record_label = first_request_divergence(read_back.result(0), replay.reruns[0])
        self.assertEqual("sample0:" + record_label, replay.divergence["label"])
        self.assertEqual(record_label, replay.divergence["field"])
        self.assertEqual("observed-fabric-request", replay.divergence["kind"])
        records = irq_service_records(self.plan, self.program, replay.reruns[0])
        self.assertEqual([self.edge_id],
                         [record["source_id"] for record in records
                          if record["service_round"] is None],
                         "the replayed run served a source it never raised")
        self.assertTrue(
            [record for record in records if record["source_id"] == self.level_id][0]
            ["claim_matches_declared_id"])
        print("MYFUZZ_SOC_IRQ_TAMPER deleted_source field=%s label=%s"
              % (replay.divergence["field"], replay.divergence["label"]))

    def test_a_package_without_the_saved_event_plan_is_refused(self) -> None:
        package = self.package(samples=None)
        self.assertFalse(package.inputs_complete)
        replay = replay_package(package, self.builds["baseline"], timeout_seconds=1800)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("event plan is unknown", replay.reason)
        self.assertFalse(replay.reruns)

    # -- the reduction keeps the failure identity --------------------------

    def test_the_latch_fault_sample_closes_on_one_build_and_fails_on_the_other(self) -> None:
        """The counterexample pair: same sample, same program, one latch bit apart."""
        self.assertEqual("OK", self.failing_result.status, self.failing_result.reason)
        self.assertEqual([self.level_id],
                         list(claim_ledger(self.program, self.failing_result.document())),
                         "the faulted build must still serve the level source")
        self.assertEqual(1, self.report(self.failing_result, "interrupt_completions"))
        self.assertEqual(0, self.report(self.failing_result, "all_sources_closed"),
                         "the faulted build must not report the loop as closed")
        self.assertEqual(self.ledgers[0],
                         list(claim_ledger(self.program, self.results[0].document())),
                         "the composed build must serve both sources for the same sample")
        records = irq_service_records(self.plan, self.program,
                                      self.failing_result.document())
        self.assertIsNone(records[0]["service_round"])
        self.assertTrue(records[1]["claim_matches_declared_id"])
        self.assertTrue(records[1]["cleared_once"])

    def test_the_reduced_counterexample_keeps_the_failure_property(self) -> None:
        """The reduced witness is the same failure, and only the transaction half proves it.

        The reduction stops at the service boundary: the window ends just after the
        CPU's accepted COMPLETE store, so the generated program's *trailing*
        bookkeeping -- its completion counter and its closed flag, written after the
        COMPLETE -- may be cut off, and a summary counter must not be what the
        reduced failure is read from.  The claim ledger, the unserved source and the
        accepted transactions are all in ``fabric_requests`` and are preserved
        exactly, which is what this test asserts (and why it does not assert
        ``all_sources_closed`` here).
        """
        minimal, log, reduced, original = self.reduced_witness()
        self.assertTrue(log["preserved"], log["continuity"])
        self.assertIn(log["stopped"], ("fixed_point", "budget"))
        self.assertEqual(len(self.failing_sample.events), log["events_preserved"])
        self.assertEqual(self.failing_sample.events, minimal.events,
                         "the reduced sample changed the event plan that causes the failure")
        self.assertLess(len(minimal.raw), len(self.failing_sample.raw),
                        "the reduction removed nothing")
        self.assertGreaterEqual(log["accepted"], 1)
        # The failure is a partial service: the level source is completed, the
        # latched-away edge source is not, and the composed build does serve both.
        self.assertEqual([self.level_id], original["claimed_source_ids"])
        self.assertEqual([self.edge_id], original["unserved_source_ids"])
        self.assertEqual(self.ledgers[0],
                         list(claim_ledger(self.program, self.results[0].document())))
        self.assertTrue(original["service_transactions"])
        # The kept property is re-measured on an independent run of the reduced
        # sample: the reduced counterexample is the same failure, one window shorter.
        self.assertEqual("OK", reduced.status, reduced.reason)
        self.assertEqual(original, irq_failure_property(self.plan, self.program, minimal,
                                                        reduced.document()))
        self.assertEqual([self.level_id],
                         list(claim_ledger(self.program, reduced.document())))
        records = irq_service_records(self.plan, self.program, reduced.document())
        self.assertIsNone(records[0]["service_round"])
        self.assertEqual(self.level_id, records[1]["claim_id"])
        self.assertTrue(records[1]["cleared_once"])
        # The accepted store is inside the reduced window and is named by the record.
        self.assertEqual((), complete_evidence_problems(reduced.document(), records[1]))
        self.assertLess(int(records[1]["complete"]["cycle"]), len(minimal.raw))
        self.assertLessEqual(len(minimal.raw) - int(records[1]["complete"]["cycle"]),
                             256, "the reduction must stop near the service boundary, not "
                                  "after a whole extra program phase")
        self.assertEqual(original["service_transactions"],
                         [list(item) for item in
                          service_transactions(self.program, reduced.document())],
                         "the reduced witness must keep exactly the accepted service")
        print("MYFUZZ_SOC_IRQ_REDUCTION original_words=%d minimal_words=%d stopped=%s "
              "complete_cycle=%d program_counter=%s"
              % (len(self.failing_sample.raw), len(minimal.raw), log["stopped"],
                 int(records[1]["complete"]["cycle"]),
                 self.report(reduced, "interrupt_completions")))

    def test_the_reduced_sample_packages_and_replays_as_a_composition_defect(self) -> None:
        minimal, _, result, _ = self.reduced_witness()
        build = self.builds["no_edge_latch"]
        package = build_irq_package(
            self.plan, build, self.policy, [minimal], [result],
            criteria=[{"criterion_id": "all-declared-sources-served",
                       "statement": "every declared source is claimed and completed by the "
                                    "CPU through the controller",
                       "basis": "src/myfuzz/protocols/rtl/soc_irq_controller.sv "
                                "source-id/latch contract, read independently of the "
                                "generated top",
                       "independent": True}],
            legality=applied_legality(build, minimal, result),
            anomaly={"present": True, "kind": "missing-source-service",
                     "criterion": "all-declared-sources-served",
                     "basis": "the controller's LATCH_MASK source-id contract, verified in "
                              "tests/protocols/test_soc_irq_controller_rtl.py",
                     "basis_independent": True, "reproducible": True,
                     "expected": self.ledgers[0],
                     "observed": list(claim_ledger(self.program, result.document())),
                     "first_divergence": {"cycle": DECLARED_RAISE_CYCLE,
                                          "field": "source-service", "kind": "observation"}},
            attribution={"composition_findings": [
                {"fault": "controller LATCH_MASK bit removed for the edge source",
                 "source_id": self.edge_id,
                 "composed_build_hash": self.builds["baseline"].build_hash,
                 "faulted_build_hash": self.builds["no_edge_latch"].build_hash}]})
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertEqual([self.edge_id],
                         [record["source_id"] for record in
                          irq_service_records(self.plan, self.program, result.document())
                          if record["service_round"] is None])
        self.assertEqual((), irq_service_mismatches(self.plan, self.program, package))
        replay = replay_package(package, build, timeout_seconds=1800)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)


if __name__ == "__main__":
    unittest.main()
