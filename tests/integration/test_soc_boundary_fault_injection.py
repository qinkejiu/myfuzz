"""Priority item 7: injected faults in every layer except the component RTL.

One deliberate fault is injected into each layer that can produce an anomaly in a
composed SoC -- the generator, an adapter, a component profile, the software /
stimulus program and the external model -- the *real* pipeline runs on the
mutated artifact, an evidence package is built from what the run really observed,
and the boundary classification of that package is asserted.  For every site the
three questions the programme asks are answered explicitly:

* **is it detected, and by which named check?**  The detection is a real audit
  finding (``soc_structure_audit`` re-elaborates the generated top with the
  Verilog frontend), a real runtime divergence against the clean baseline of the
  same composition (a DUT-visible observation), or a real RAM report field of the
  boot program the composition generated;
* **which boundary does the evidence point at?**  ``classify_boundary`` is
  asserted against the category the *evidence* supports (not bent to a guess);
* **is it ever a component bug?**  No injected fault is classified
  ``component_candidate``.

===================================  ==========================================
site                                 named detection
===================================  ==========================================
generator: interrupt source vector    ``audit_structure`` finding ``interrupt_paths``
swapped                               (FAIL) + controller source mis-attribution at
                                      runtime (handler re-entry storm, starved main
                                      flow)
generator: router ``WINDOW_TARGET``   the plan's decode table re-read from the
packing swapped                       rendered parameter + ``cpu0__trap_o`` /
                                      ``status_o`` divergence (the audit does *not*
                                      re-read the router packing: reported)
generator: special-input driver       the declared drive contract replayed against
instance dropped                      the driver's real applied waveform (the audit
                                      does not check it: reported)
adapter: APB bridge ``WINDOW_BASE``   ``audit_structure`` finding
corrupted                             ``adapter_parameters`` (FAIL) + runtime trap
profile: declared field width the     ``component_profile`` binding conflict
RTL does not have                     (``binding-width-conflict``): the composition
                                      is refused, never silently adapted
profile: declared clear operation     the generated program's own declared promise
the RTL does not implement            (``cause_after_clear == 0``) fails, and the
                                      profile/RTL binding conflict is named
software: the boot image's declared   the same promise fails on the patched image
clear step removed                    while the *same binary* clears correctly with
                                      the unpatched image (so the DUT is not at fault)
external model: a drive request the   the declared drive contract monitor
profile's declared timing contract    (``soc_special_input_driver`` reference model
forbids                               vs the real applied trace) reports a
                                      ``driver_violation``; the experiment is labelled
                                      deliberate-illegal and the violated constraint
                                      is preserved with the run
===================================  ==========================================

Nothing here edits a component under test.  The only artifacts mutated are
generated ones (the rendered top, the produced boot image, a profile document);
the DUT RTL, the audit and every existing check are untouched.

What this module deliberately does *not* claim
----------------------------------------------

* No real *component* defect is injected: that would require editing the DUT RTL,
  which the task forbids.  The positive control therefore asserts the
  ``component_candidate`` gate contract instead, on real packages: the evidence a
  package needs, branch by branch, and the demonstration that the gate is the only
  path to that category.
* A recompiled build in a *different directory* is refused by ``replay_package``
  because the compiled executable's content hash is part of the package identity
  and Verilator embeds its build path.  The refusal is asserted (it is the
  conservative behaviour), the identical artifact copied into a new directory is
  shown to replay with agreement, and the behavioural reproduction on the rebuilt
  binary is asserted field by field.  The identity check was *not* weakened.
* Two sites the brief names could not be exercised on this composition and are
  reported rather than faked: a width-adapter fault (the renderer refuses
  ``width_adapters`` outright: ``width-adapter-rendering-unsupported``) and the CPU
  adapter's own parameters (no audit check re-reads them).

``MYFUZZ_SOC_REAL=1`` opts in, following
``tests/integration/test_soc_interrupt_lifecycle.py``; when the flag is set
nothing skips -- a missing Verilator, a missing profile, a render or a build
failure fails the tests with that exact reason.  Real builds are cached under
``runs/soc-boundary-fault-injection/`` keyed by plan + rendered top + source list
+ boot image, and the cached identity is re-verified before it is reused.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import shutil
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.input_constraints import (
    InputConstraintPolicy,
    compile_input_constraints,
)
from myfuzz.composition.soc_boot_program import (
    COMPLETION_FLAG,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import CompositionPlan, build_composition
from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    DRIVER_VIOLATION,
    LEGALITY_CONFIRMED,
    LEGALITY_VIOLATED,
    PROFILE_DEFECT,
    REPLAY_AGREEMENT,
    REPLAY_REFUSED,
    REQUIRED_IDENTITY,
    REQUIRED_LEGALITY,
    SOFTWARE_OR_MODEL_DEFECT,
    UNDIAGNOSED,
    EvidencePackage,
    build_evidence_package,
    classify_boundary,
    component_candidate_ready,
    minimize_sample,
    missing_identity,
    profile_identities,
    read_evidence_package,
    recorded_build_identity,
    replay_package,
    write_evidence_package,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent,
    RuntimeBuild,
    RuntimeSample,
    build_profile_runtime,
    run_sample,
)
from myfuzz.composition.soc_structure_audit import FAIL, audit_structure
from myfuzz.contracts import canonical_bytes

from tests.composition.soc_generation_fixture import ROOT, example_plan, tools_available
from tests.integration.test_soc_dependency_replay import OPT_IN, runtime_build
from tests.integration.test_soc_interrupt_lifecycle import (
    CYCLES,
    GPIO_PROFILE,
    IBEX_PROFILE,
    REQUEST_FILE,
    read32,
)

CACHE_ROOT = ROOT / "runs/soc-boundary-fault-injection"
EVIDENCE_ROOT = CACHE_ROOT / "evidence"
IMAGE_ROOT = CACHE_ROOT / "images"

#: The layer a fault was injected into.  It is recorded in every package.
SITE_GENERATOR = "generator"
SITE_ADAPTER = "adapter"
SITE_PROFILE = "profile"
SITE_SOFTWARE = "software_or_stimulus_program"
SITE_EXTERNAL = "external_model"

#: How the *environment* behaved.  The assurance plan's 1.7.2 requires a legal
#: interaction and a deliberately illegal one to stay distinguishable, and the
#: violated constraint to be preserved with the run.
LEGAL_INTERACTION = "legal_interaction"
DELIBERATE_ILLEGAL = "deliberate_illegal"

#: The example composition's CPU states (examples/soc_generation/rtl/novacore.sv).
ST_POLL = 3
ST_TRAP = 5

#: The example composition's raw layout: cpu0.event_i is raw bits 0..3 and
#: gpio0.pin_mode_i raw bits 4..6 (asserted against the plan in ``_prepare``).
EVENT_PORT = "cpu0__event_i"
PIN_MODE_PORT = "gpio0__pin_mode_i"
PIN_MODE_SHIFT = 4

#: One request whose words differ per cycle, so an applied trace has a value per
#: cycle and the waveform monitors compare cycle by cycle.
WAVE_RAW = (0x00, 0x7F, 0x30, 0x00, 0x55, 0x11, 0x22, 0x00) * 8


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _top_text(plan: CompositionPlan) -> str:
    return render_composition(plan)["myfuzz_soc_top.sv"]


def _sources(plan: CompositionPlan) -> list[str]:
    return [str(item["path"]) for item in source_list(plan)
            if item["role"] != "include_root"]


def _include_roots(plan: CompositionPlan) -> list[str]:
    return [str(item["path"]) for item in source_list(plan)
            if item["role"] == "include_root"]


def _policy(plan: CompositionPlan) -> InputConstraintPolicy:
    return compile_input_constraints(plan, drive_profile=str(plan.drive_profile))


def report_layout(program) -> dict[str, int]:
    """``report field -> byte offset`` from the generated program's own document."""
    return {str(item["name"]): int(item["offset"])
            for item in program.document["report"]["layout"]}


def report_value(program, result, name: str) -> int:
    return read32(result, program.report_address + report_layout(program)[name])


# ---------------------------------------------------------------------------
# real builds, content-keyed and re-verified
# ---------------------------------------------------------------------------


_BUILDS: dict[tuple[str, str], RuntimeBuild] = {}


def _build_digest(plan: CompositionPlan, top_text: str, sources: Sequence[str],
                  boot_image: Path | None) -> str:
    payload = {
        "plan_hash": plan.plan_hash,
        "layout_hash": str(plan.raw_layout.get("layout_hash", "")),
        "top": _sha256_bytes(top_text.encode("utf-8")),
        "sources": list(sources),
        "include_roots": _include_roots(plan),
        "boot_image": "none" if boot_image is None else _sha256_file(boot_image),
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _resolve_boot_image(document: Mapping[str, object], output: Path,
                        requested: str | Path | None) -> Path | None:
    """The boot image a restored build must really run with.

    ``RuntimeBuild.document`` stores the image's basename (it is written next to
    the executable), so a restored build resolves it relative to its own output
    directory.  An explicit ``requested`` image always wins.
    """
    if requested is not None:
        return Path(requested)
    name = document.get("boot_image")
    if not name:
        return None
    return output / str(name)


def _runtime_from_document(document: Mapping[str, object], boot_image: Path | None,
                           *, executable_path: str | Path | None = None) -> RuntimeBuild:
    """Rebuild a ``RuntimeBuild`` from its own document.

    ``RuntimeBuild.document`` records the executable's *basename* only, while the
    real file lives in ``obj_dir`` (``soc_runtime.build_profile_runtime`` compiles
    with ``-o myfuzz_profile_sim`` into ``obj_dir``), so the executable path is
    passed in explicitly here -- from the cache record, or from the directory a
    build was copied to.  Without it a cached build can never be reconstructed and
    every run silently recompiles.
    """
    output = Path(str(document["output_dir"]))
    executable = Path(executable_path) if executable_path is not None \
        else output / "obj_dir" / str(document["executable"]) if (output / "obj_dir" / str(document["executable"])).exists() else output / str(document["executable"])
    # ``build_profile_runtime`` *invents* an empty boot image when the plan needs
    # one and the caller passed none (``no_program_loaded.hex``), and the run only
    # passes ``+riscv_boot_image`` when the build carries that path.  The record
    # therefore has to be read back as the authoritative boot image: restoring it
    # as ``None`` silently produces a cached build that aborts at time 0 with
    # "missing +riscv_boot_image", which is a harness defect and not a symptom of
    # whatever fault was injected.
    resolved = _resolve_boot_image(document, output, boot_image)
    return RuntimeBuild(
        output_dir=output,
        top_path=output / str(document["top"]),
        testbench_path=output / str(document["testbench"]),
        executable=executable,
        sources=tuple(str(item) for item in document.get("sources", ())),
        raw_width=int(document["raw_width"]),
        slots=tuple(dict(item) for item in document.get("slots", ())),
        observations=tuple(dict(item) for item in document.get("observations", ())),
        boot_image=resolved,
        boot_image_policy=str(document.get("boot_image_policy", "")),
        build_hash=str(document["build_hash"]),
        warnings=int(document.get("warnings", 0)))


def build_runtime(plan: CompositionPlan, label: str, *, top_text: str | None = None,
                  boot_image: Path | None = None, rebuild: bool = False) -> RuntimeBuild:
    """One real Verilator build, reused only while its identity still matches.

    The cache key covers the plan hash, the layout hash, the rendered top text,
    the published source list and the boot image bytes, and a cached directory is
    accepted only when the generated testbench still records this plan and layout
    and the top file still hashes to the requested text.  ``rebuild=True`` forces a
    fresh compile into its own directory (the cross-build test).
    """
    text = _top_text(plan) if top_text is None else top_text
    sources = _sources(plan)
    digest = _build_digest(plan, text, sources, boot_image)
    key = (label, digest)
    if not rebuild and key in _BUILDS:
        return _BUILDS[key]
    suffix = "-rebuild" if rebuild else f"-{digest[:12]}"
    directory = CACHE_ROOT / f"build-{label}{suffix}"
    record = directory / "runtime_build.json"
    if not rebuild and record.is_file():
        try:
            document = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            document = {}
        saved = document.get("build") if isinstance(document, Mapping) else None
        if isinstance(saved, Mapping) and document.get("digest") == digest:
            candidate = _runtime_from_document(
                saved, boot_image, executable_path=document.get("executable_path"))
            if candidate.executable.is_file() and candidate.top_path.is_file() \
                    and candidate.testbench_path.is_file() \
                    and (candidate.boot_image is None or candidate.boot_image.is_file()):
                recorded = recorded_build_identity(candidate)
                if recorded["plan_hash"] == plan.plan_hash \
                        and recorded["layout_hash"] == str(plan.raw_layout["layout_hash"]) \
                        and _sha256_file(candidate.top_path) == _sha256_bytes(
                            text.encode("utf-8")):
                    _BUILDS[key] = candidate
                    return candidate
    shutil.rmtree(directory, ignore_errors=True)
    build = build_profile_runtime(plan, output_dir=directory, base_dir=ROOT, top_text=text,
                                  sources=sources, boot_image=boot_image)
    record.write_text(json.dumps({
        "digest": digest,
        "plan_hash": plan.plan_hash,
        "layout_hash": str(plan.raw_layout.get("layout_hash", "")),
        "boot_image_path": None if build.boot_image is None
        else str(Path(build.boot_image).resolve()),
        "executable_path": str(build.executable),
        "build": build.document(),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _BUILDS[key] = build
    return build


def run_twice(build: RuntimeBuild, sample: RuntimeSample, *, label: str):
    """Run the same saved input twice and require identical documents.

    This is the real basis of every ``reproducible`` claim this module makes: a
    run whose observation is not stable is a failure here, not a caveat later.
    """
    first = run_sample(build, sample)
    second = run_sample(build, sample)
    if first.document() != second.document():
        raise AssertionError(f"{label}: the injected run is not reproducible:\n"
                             f"first={json.dumps(first.document())[:400]}\n"
                             f"second={json.dumps(second.document())[:400]}")
    return first, second


# ---------------------------------------------------------------------------
# plan fixtures
# ---------------------------------------------------------------------------


def novacore_plan() -> CompositionPlan:
    return example_plan()


def ibex_plan(*, mutate_profile: tuple[str, object] | None = None) -> CompositionPlan:
    """The real-CPU composition: Ibex + novagpio, as the lifecycle test composes it.

    ``mutate_profile`` replaces one declared profile with a mutated copy under a
    private key, so a mutation is a declared-fact change of *this* plan and never
    leaks into another test's cached fixtures.
    """
    document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
    profiles: dict[str, object] = {}
    references = sorted({str(document["cpu"]["profile"])}
                        | {str(item["profile"]) for item in document["peripherals"]}
                        | {IBEX_PROFILE, GPIO_PROFILE})
    for relative in references:
        profile = load_component_profile(ROOT / relative)
        profiles[relative] = profile
        profiles.setdefault(str(profile.component_id), profile)
    cpu_profile = profiles[str(document["cpu"]["profile"])]
    if getattr(cpu_profile, "cpu", None) is None:
        raise AssertionError(f"{IBEX_PROFILE}: no cpu contract")
    reset_vector = int(cpu_profile.cpu.reset_vector)
    for region in document["memory"]:
        if region["region_id"] == "rom0":
            region["base"] = reset_vector
    document["peripherals"] = [item for item in document["peripherals"]
                               if item["profile"] == GPIO_PROFILE
                               or item["instance_id"] != "gpio0"]
    if mutate_profile is not None:
        relative, mutate = mutate_profile
        profiles["fixture-mutated"] = mutate(profiles[relative])
        document["peripherals"] = [
            dict(item, profile="fixture-mutated") if item["profile"] == relative else item
            for item in document["peripherals"]]
    document["request_id"] = "ibex-novagpio-boundary-fault-injection"
    return build_composition(load_composition_request(document, profiles=profiles),
                             base_dir=ROOT)


def novacore_plan_without_uart1(plan: CompositionPlan) -> CompositionPlan:
    """A real second plan: the same composition minus uart1, so its hashes differ."""
    request = plan.request
    peripherals = tuple(item for item in request.peripherals
                        if item.instance_id != "uart1")
    return build_composition(dataclasses.replace(request, peripherals=peripherals),
                             base_dir=ROOT)


# ---------------------------------------------------------------------------
# generator mutations (text, on the rendered top)
# ---------------------------------------------------------------------------


def _router_decode(plan: CompositionPlan) -> list[dict]:
    return sorted((dict(row) for row in plan.plan["fabric"]["decode"]["windows"]),
                  key=lambda row: (int(row["base"]), str(row["window_id"])))


def _router_target_width(plan: CompositionPlan) -> int:
    targets = int(plan.plan["fabric"]["rtl"]["parameters"]["NUM_TARGETS"])
    return max(1, (targets - 1).bit_length())


def router_target_map(plan: CompositionPlan, top_text: str) -> dict[str, int]:
    """``window_id -> target_index`` as the rendered router parameter really packs it.

    The renderer packs ``WINDOW_TARGET`` most-significant-window-first over the
    decode table sorted by (base, window_id).  This is the re-read of the router's
    own parameters that the shipped audit does not perform; it is asserted against
    the plan's decode table on the pristine top before it is used as a check.
    """
    decode = _router_decode(plan)
    width = _router_target_width(plan)
    line = next(line for line in top_text.splitlines() if ".WINDOW_TARGET(" in line)
    match = re.search(r"\.WINDOW_TARGET\((\d+)'b([01]+)\)", line)
    if match is None:
        raise AssertionError(f"the rendered top has no readable WINDOW_TARGET: {line}")
    # The literal is sized: 18'b... is *eighteen bits* (six windows of a 3-bit
    # target id), not eighteen windows.  The window count comes from the plan.
    declared_bits, bits = int(match.group(1)), match.group(2)
    if declared_bits != len(bits) or declared_bits != len(decode) * width:
        raise AssertionError(f"router WINDOW_TARGET is {declared_bits} bits ({len(bits)} "
                             f"digits); the plan has {len(decode)} windows of {width} "
                             f"target-id bits")
    return {str(row["window_id"]): int(bits[(len(decode) - 1 - index) * width:
                                            (len(decode) - index) * width], 2)
            for index, row in enumerate(decode)}


def swap_router_window_targets(plan: CompositionPlan, top_text: str,
                               left: str, right: str) -> tuple[str, dict[str, object]]:
    """Swap two windows' target indices inside the rendered router parameter.

    This is one of the generator mutations the brief names.  The plan is
    untouched, so the built top contradicts the plan's own decode table.
    """
    decode = _router_decode(plan)
    width = _router_target_width(plan)
    index = {str(row["window_id"]): position for position, row in enumerate(decode)}
    if left not in index or right not in index:
        raise AssertionError(f"the plan has no window {left!r} or {right!r}")
    line = next(line for line in top_text.splitlines() if ".WINDOW_TARGET(" in line)
    match = re.search(r"\.WINDOW_TARGET\((\d+)'b([01]+)\)", line)
    assert match is not None
    declared_bits, bits = int(match.group(1)), match.group(2)
    slots = len(decode)
    if declared_bits != len(bits) or declared_bits != slots * width:
        raise AssertionError(f"router WINDOW_TARGET is {declared_bits} bits ({len(bits)} "
                             f"digits); the plan has {slots} windows of {width} "
                             f"target-id bits")
    chunks = [bits[(slots - 1 - position) * width:(slots - position) * width]
              for position in range(slots)]
    # ``chunks`` is in decode order; the rendered string is that order reversed
    # (the renderer packs ``reversed(values)`` most significant first), so the
    # swap is performed on the string order and joined back directly.
    packed = list(reversed(chunks))
    first, second = slots - 1 - index[left], slots - 1 - index[right]
    packed[first], packed[second] = packed[second], packed[first]
    swapped = line.replace(bits, "".join(packed))
    mutated = top_text.replace(line, swapped)
    if mutated == top_text:
        raise AssertionError("the router window swap changed nothing")
    plan_map = {str(row["window_id"]): int(row["target_index"]) for row in decode}
    return mutated, {
        "site": SITE_GENERATOR,
        "artifact": "rendered myfuzz_soc_top.sv (router parameter packing)",
        "mutation": "swap two windows' WINDOW_TARGET index",
        "windows": [left, right],
        "plan_decode": {left: plan_map[left], right: plan_map[right]},
        "rendered_after": {name: router_target_map(plan, mutated)[name]
                           for name in (left, right)},
        "line_before": line.strip(),
        "line_after": swapped.strip(),
    }


def swap_interrupt_source_vector(plan: CompositionPlan, top_text: str) -> tuple[str, dict]:
    """Swap the two lowest interrupt sources in the controller's source vector.

    The vector is rendered most-significant source id first and the controller reads
    ``source_i[k]`` as source id ``k+1`` (``soc_irq_controller.sv`` lines 1-6), so
    reordering entries re-labels which peripheral owns which controller bit -- a
    wiring fault the audit re-reads out of the elaborated netlist.
    """
    document = plan.interrupt_document
    if not document["controller"]["present"]:
        raise AssertionError("the plan declares no interrupt controller")
    sources = sorted(document["sources"], key=lambda item: int(item["source_id"]))
    if len(sources) < 2:
        raise AssertionError("the plan declares fewer than two interrupt sources")

    def signal(item: Mapping[str, object]) -> str:
        return f"{item['instance_id']}__{item['port']}"

    declared_lsb_first = [signal(item) for item in sources]
    declared_expression = "{" + ", ".join(reversed(declared_lsb_first)) + "}"
    line = next(line for line in top_text.splitlines() if ".source_i(" in line)
    if declared_expression not in line:
        raise AssertionError(f"the rendered source vector {line.strip()} is not the "
                             f"plan's own order {declared_expression}")
    swapped = list(declared_lsb_first)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    swapped_expression = "{" + ", ".join(reversed(swapped)) + "}"
    mutated = top_text.replace(declared_expression, swapped_expression)
    if mutated == top_text:
        raise AssertionError("the source-vector swap changed nothing")
    return mutated, {
        "site": SITE_GENERATOR,
        "artifact": "rendered myfuzz_soc_top.sv (interrupt controller source vector)",
        "mutation": "swap the two lowest-id entries of the source vector",
        "plan_vector_lsb_first": declared_lsb_first,
        "rendered_after_lsb_first": swapped,
        "source_ids": [int(item["source_id"]) for item in sources],
        "controller_bit_of_first_source": int(sources[0]["controller_bit"]),
        "line_before": line.strip(),
        "line_after": next(line for line in mutated.splitlines()
                           if ".source_i(" in line).strip(),
    }


def drop_special_input_driver(top_text: str, instance_id: str,
                              port: str) -> tuple[str, dict]:
    """Delete one rendered ``soc_special_input_driver`` instance and its export.

    This is the other generator mutation the brief names.  The component input is
    left undriven and the exported applied value stops following the request while
    the top-level port still exists, so the driver the plan declares is simply not
    in the built structure.
    """
    suffix = f"u_drive_{instance_id}__{port}"
    lines = top_text.splitlines()
    start = next((index for index, line in enumerate(lines) if suffix in line), None)
    if start is None:
        raise AssertionError(f"the rendered top has no driver {suffix}")
    end = next((index for index in range(start, len(lines))
                if lines[index].strip() == ");"), None)
    if end is None:
        raise AssertionError(f"driver {suffix} has no statement end")
    removed = list(lines[start:end + 1])
    rest = lines[:start] + lines[end + 1:]
    assign = next(index for index, line in enumerate(rest)
                  if f"assign {instance_id}__{port}__applied" in line)
    removed.append(rest[assign])
    rest = rest[:assign] + rest[assign + 1:]
    logic = next(index for index, line in enumerate(rest)
                 if re.match(rf"\s*logic(\s*\[\d+:\d+\])?\s+{re.escape(instance_id)}__"
                             rf"{re.escape(port)}__driven\s*;", line))
    removed.append(rest[logic])
    rest = rest[:logic] + rest[logic + 1:]
    mutated = "\n".join(rest) + "\n"
    if suffix in mutated:
        raise AssertionError("the driver instance is still in the rendered top")
    return mutated, {
        "site": SITE_GENERATOR,
        "artifact": "rendered myfuzz_soc_top.sv (special-input driver instance)",
        "mutation": f"drop the driver for {instance_id}.{port} and its applied export",
        "removed_lines": [line.strip() for line in removed],
        "drivers_remaining": mutated.count("soc_special_input_driver #("),
    }


# ---------------------------------------------------------------------------
# adapter mutation
# ---------------------------------------------------------------------------


def adapter_window_base(plan: CompositionPlan, instance_id: str) -> int:
    """The window base the plan resolved for one peripheral's bridge."""
    for record in plan.target_records:
        if record.get("instance_id") == instance_id:
            window = record.get("window")
            if isinstance(window, Mapping):
                return int(window["base"])
    raise AssertionError(f"the plan has no resolved window for {instance_id}")


def corrupt_adapter_window_base(plan: CompositionPlan, top_text: str, instance_id: str,
                                wrong_base: int) -> tuple[str, dict]:
    """Render one target bridge with another window base (the adapter fault).

    The adapter parameter is the declared contract between the router window and
    the peripheral's local address decode: with the wrong base, every access the
    window routes to that peripheral is translated to the wrong local offset (or
    refused), which is a decode fault of the composed wiring, not of the
    peripheral.
    """
    declared = adapter_window_base(plan, instance_id)
    lines = top_text.splitlines()
    index = next((position for position in range(len(lines))
                  if f"u_{instance_id}_adapter (" in lines[position]), None)
    if index is None:
        raise AssertionError(f"the rendered top has no adapter for {instance_id}")
    line = lines[index]
    bad = f".WINDOW_BASE({declared}), .WINDOW_SIZE("
    if bad not in line:
        raise AssertionError(f"adapter line does not carry the planned base {declared}: "
                             f"{line}")
    if wrong_base == declared:
        raise AssertionError("the injected window base equals the declared one")
    mutated = top_text.replace(line, line.replace(bad, f".WINDOW_BASE({wrong_base}), "
                                                       f".WINDOW_SIZE("))
    if mutated == top_text:
        raise AssertionError("the adapter window mutation changed nothing")
    return mutated, {
        "site": SITE_ADAPTER,
        "artifact": "rendered myfuzz_soc_top.sv (target bridge parameter)",
        "mutation": f"{instance_id}: .WINDOW_BASE({declared}) -> .WINDOW_BASE({wrong_base})",
        "declared_window_base": declared,
        "injected_window_base": wrong_base,
        "line_after": next(line for line in mutated.splitlines()
                           if f"u_{instance_id}_adapter (" in line).strip(),
    }


# ---------------------------------------------------------------------------
# profile mutations
# ---------------------------------------------------------------------------


def _replace_component_profile(plan: CompositionPlan, instance_id: str, mutate) -> CompositionPlan:
    request = plan.request
    peripherals = []
    matched = False
    for item in request.peripherals:
        if item.instance_id == instance_id:
            matched = True
            peripherals.append(dataclasses.replace(item, profile=mutate(item.profile)))
        else:
            peripherals.append(item)
    if not matched:
        raise AssertionError(f"the plan has no peripheral {instance_id}")
    return build_composition(dataclasses.replace(request, peripherals=tuple(peripherals)),
                             base_dir=ROOT)


def with_port_action_strategy(plan: CompositionPlan, instance_id: str, port: str,
                              strategy: str, drive: Mapping[str, int]) -> CompositionPlan:
    """The same composition with one declared special-input strategy changed."""
    def mutate(profile):
        actions = []
        found = False
        for action in profile.port_actions:
            if action.port == port:
                found = True
                actions.append(dataclasses.replace(action, strategy=strategy,
                                                   drive=dict(drive)))
            else:
                actions.append(action)
        if not found:
            raise AssertionError(f"{instance_id} declares no port action for {port}")
        return dataclasses.replace(profile, port_actions=tuple(actions))
    return _replace_component_profile(plan, instance_id, mutate)


def with_declared_clear(plan: CompositionPlan, instance_id: str, register: str,
                        side_effect: str, clear_text: str) -> CompositionPlan:
    """Declare a clear operation the component's RTL does not implement."""
    return _replace_component_profile(
        plan, instance_id,
        lambda profile: declared_clear_profile_mutation(profile, register=register,
                                                        side_effect=side_effect,
                                                        clear_text=clear_text))


def declared_clear_profile_mutation(profile, *, register: str = "IRQ_STATUS",
                                    side_effect: str = "write_1_to_clear",
                                    clear_text: str = (
                                        "Write 1 to IRQ_STATUS[0] (offset 0x10) to clear "
                                        "the interrupt latch.")):
    """The profile fault as a pure profile mutation (for the plan fixture hook).

    It declares one register read-write with a write-1-to-clear side effect and
    names it in the interrupt source's declared clear text, so the generated
    program performs exactly that declared operation.  ``novagpio.sv`` declares the
    same offset read-only and clears on a DATA_IN access, so the declaration
    contradicts the RTL.
    """
    registers = []
    found = False
    for entry in profile.address.registers:
        if entry.name == register:
            found = True
            registers.append(dataclasses.replace(entry, access="rw",
                                                 side_effect=side_effect))
        else:
            registers.append(entry)
    if not found:
        raise AssertionError(f"{profile.component_id} declares no register {register}")
    interrupts = tuple(dataclasses.replace(entry, clear=clear_text)
                       for entry in profile.interrupts)
    return dataclasses.replace(
        profile, address=dataclasses.replace(profile.address, registers=tuple(registers)),
        interrupts=interrupts)


def _mutate_endpoint_field(plan: CompositionPlan, instance_id: str, endpoint_id: str,
                           role: str, mutate) -> CompositionPlan:
    def profile_mutation(profile):
        endpoints = []
        found = False
        for endpoint in profile.endpoints:
            if endpoint.endpoint_id == endpoint_id:
                fields = []
                for field in endpoint.fields:
                    if field.role == role:
                        found = True
                        fields.append(mutate(field))
                    else:
                        fields.append(field)
                endpoint = dataclasses.replace(endpoint, fields=tuple(fields))
            endpoints.append(endpoint)
        if not found:
            raise AssertionError(f"{instance_id} declares no field {endpoint_id}:{role}")
        return dataclasses.replace(profile, endpoints=tuple(endpoints))
    return _replace_component_profile(plan, instance_id, profile_mutation)


def with_declared_field_width(plan: CompositionPlan, instance_id: str, endpoint_id: str,
                              role: str, width: int) -> CompositionPlan:
    """Declare a width the elaborated RTL port does not have."""
    return _mutate_endpoint_field(plan, instance_id, endpoint_id, role,
                                 lambda field: dataclasses.replace(field, width=width))


def with_declared_field_direction(plan: CompositionPlan, instance_id: str,
                                  endpoint_id: str, role: str,
                                  direction: str) -> CompositionPlan:
    """Declare a direction the endpoint's protocol function contradicts."""
    return _mutate_endpoint_field(plan, instance_id, endpoint_id, role,
                                 lambda field: dataclasses.replace(field,
                                                                   direction=direction))


def with_missing_port_alias(plan: CompositionPlan, instance_id: str, endpoint_id: str,
                            role: str, alias: str) -> CompositionPlan:
    """Bind a role to a port the elaborated RTL does not have."""
    return _mutate_endpoint_field(plan, instance_id, endpoint_id, role,
                                 lambda field: dataclasses.replace(field,
                                                                   aliases=(alias,)))


def rtl_field_width(plan: CompositionPlan, instance_id: str, endpoint_id: str,
                    role: str) -> int:
    """The width the elaborator really found for one declared role."""
    endpoint = plan.instance(instance_id).binding.endpoint(endpoint_id)
    return int(next(item for item in endpoint.fields if item.role == role).width)


# ---------------------------------------------------------------------------
# software mutation: patch the produced boot image at a named address
# ---------------------------------------------------------------------------


def listing_rows(program) -> list[dict[str, object]]:
    """The program's own listing: instruction rows and comment rows, in order.

    ``_Assembler.listing`` emits label rows, comment rows (``# ...``) and
    instruction rows; only the last two matter here, and both carry the address the
    row belongs to.
    """
    rows: list[dict[str, object]] = []
    for entry in program.document["listing"]:
        parts = str(entry).split()
        if len(parts) < 2 or not re.fullmatch(r"[0-9a-f]{8}", parts[0]):
            continue
        address = int(parts[0], 16)
        if re.fullmatch(r"[0-9a-f]{8}", parts[1]):
            rows.append({"kind": "instruction", "address": address,
                         "word": int(parts[1], 16), "text": " ".join(parts[2:])})
        else:
            rows.append({"kind": "comment", "address": address, "word": None,
                         "text": " ".join(parts[1:])})
    return rows


def declared_clear_instruction(program) -> dict[str, object]:
    """The instruction the generated program uses for its declared clear step.

    The listing's comment row is the program's own record of which declared
    operation it performs; the next instruction row at the same address is the word
    that implements it.
    """
    rows = listing_rows(program)
    for index, entry in enumerate(rows):
        if entry["kind"] != "comment" or "clear:" not in str(entry["text"]):
            continue
        for following in rows[index + 1:]:
            if following["kind"] != "instruction":
                continue
            if following["address"] != entry["address"]:
                raise AssertionError(f"the clear comment at 0x{entry['address']:08x} is "
                                     f"not followed by its instruction")
            return {"comment": str(entry["text"]),
                    "address": int(following["address"]),
                    "word": int(following["word"]),
                    "instruction": str(following["text"])}
    raise AssertionError("the program listing records no clear instruction")


def patch_image_word(program, address: int, word: int) -> dict[str, object]:
    """Replace one 32-bit word of the produced image at a named address."""
    rom_base = int(program.document["entry"]["rom_base"])
    offset = int(address) - rom_base
    if offset < 0 or offset + 4 > len(program.image):
        raise AssertionError(f"0x{address:08x} is outside the image")
    before = int.from_bytes(program.image[offset:offset + 4], "little")
    patched = bytearray(program.image)
    patched[offset:offset + 4] = int(word).to_bytes(4, "little")
    return {"address": int(address), "rom_base": rom_base, "image_offset": offset,
            "word_before": before, "word_after": int(word),
            "bytes_before": program.image[offset:offset + 4].hex(),
            "bytes_after": bytes(patched[offset:offset + 4]).hex(),
            "image": bytes(patched)}


def write_image(label: str, image: bytes) -> Path:
    IMAGE_ROOT.mkdir(parents=True, exist_ok=True)
    path = IMAGE_ROOT / f"{label}.hex"
    path.write_text(image_hex(image), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# the declared drive contract, monitored against the driver's real output
# ---------------------------------------------------------------------------


def declared_drive_contracts(plan: CompositionPlan,
                             policy: InputConstraintPolicy) -> dict[str, dict]:
    """The declared drive contract of every special input, with its provenance.

    The obligation (rule id, primitive, failure class, checker, category, raw-bit
    geometry) is the plan's compiled ``drive:`` rule -- the same document the
    package identity carries; the strategy parameters are the plan's own
    raw-layout record, which is exactly what the renderer writes into the
    ``soc_special_input_driver`` instance.  Both halves are declared facts of the
    plan, not of this test.
    """
    records = {str(item["top_port"]): item
               for item in plan.raw_layout.get("special_inputs", [])}
    declared: dict[str, dict] = {}
    for rule in policy.rules:
        if not rule.primitive.startswith("drive_"):
            continue
        port = str(rule.write_set[0])
        if port not in records:
            raise AssertionError(f"drive rule {rule.rule_id} names no declared special "
                                 f"input")
        record = records[port]
        declared[port] = {
            "rule_id": rule.rule_id, "primitive": rule.primitive,
            "failure_class": rule.failure_class, "checker": rule.checker,
            "category": rule.category, "owner": rule.owner, "phase": rule.phase,
            "top_port": port, "component_port": str(record["port"]),
            "instance_id": str(record["instance_id"]),
            "width": int(record["width"]), "raw_lo": int(record["raw_lo"]),
            "raw_hi": int(record["raw_hi"]), "strategy": str(record["strategy"]),
            "drive": dict(record.get("drive") or {}),
            "basis": str(record.get("basis", "")),
        }
    return declared


def applied_waveform(result, port: str, cycles: int) -> list[int]:
    """The value the driver really applied in each post-reset cycle.

    ``MYFUZZ_APPLIED`` is printed only when the applied value changes
    (``soc_runtime.render_profile_testbench``), so the per-cycle waveform is the
    last reported value at or before that cycle.  Cycle numbering restarts when the
    CPU is released: cycle 1 is the first post-reset edge and raw word 0 is what
    the driver samples for it.
    """
    changes = {int(item["cycle"]): int(item["value"]) for item in result.applied
               if str(item["port"]) == port}
    waveform: list[int] = []
    current = 0
    for cycle in range(1, cycles + 1):
        if cycle in changes:
            current = changes[cycle]
        waveform.append(current)
    return waveform


def monitor_drive_contract(declared: Mapping[str, object], sample: RuntimeSample,
                           result) -> dict[str, object]:
    """Replay one declared strategy against the driver's real applied waveform.

    The reference model is the contract ``soc_special_input_driver`` documents,
    with the parameters the profile declared.  Two outcomes are kept apart on
    purpose:

    * a request the declared strategy does not accept (a rising edge during an
      active pulse, or inside the declared minimum gap) is a **driver violation**:
      the environment offered a stimulus the declared contract forbids and the RTL
      was right to drop it;
    * a waveform the declared strategy cannot produce at all is a **structural
      finding**: the composition does not contain -- or does not behave as -- the
      driver the plan declares, so the environment is not to blame.
    """
    parameters = dict(declared.get("drive") or {})  # type: ignore[arg-type]
    strategy = str(declared["strategy"])
    pulse_cycles = int(parameters.get("pulse_cycles", 1))
    min_gap = int(parameters.get("min_gap_cycles", 0))
    hold_on_ready = bool(parameters.get("handshake"))
    port = str(declared["top_port"])
    low, high = int(declared["raw_lo"]), int(declared["raw_hi"])
    mask = (1 << (high - low + 1)) - 1
    requests = [(int(raw) >> low) & mask for raw in sample.raw]
    applied = applied_waveform(result, port, len(requests))
    violations: list[dict[str, object]] = []
    structural: list[dict[str, object]] = []
    predicted: list[int] = []
    value, pulse_left, payload, gap, raw_bit = 0, 0, 0, min_gap, 0
    for index, request in enumerate(requests):
        cycle = index + 1
        trigger = bool(request & 1) and not raw_bit
        raw_bit = request & 1
        if strategy in ("cycle_value", "hold"):
            # update_i and hold_ready_i are tied high by the renderer, so both
            # strategies apply every offered value on its own edge.
            value = request
        elif strategy == "reset_sampled":
            # Only the release edge writes; later requests are ignored *by
            # contract*, so a change after it is not a violation, it is a no-op.
            if cycle == 1:
                value = request
        elif strategy == "pulse":
            if pulse_left > 0:
                value = payload
                pulse_left -= 1
                gap = 0
                if trigger:
                    violations.append({"cycle": cycle, "reason": "a pulse is active",
                                       "pulse_left": pulse_left + 1,
                                       "requested": request})
            elif trigger and gap >= min_gap:
                value = payload = request
                pulse_left = pulse_cycles - 1
                gap = 0
            else:
                value = 0
                if trigger:
                    violations.append({"cycle": cycle,
                                       "reason": "declared minimum gap not met",
                                       "gap": gap, "min_gap_cycles": min_gap,
                                       "requested": request})
                if gap < min_gap:
                    gap += 1
        else:  # pragma: no cover - the compiler only emits the four strategies
            raise AssertionError(f"unsupported drive strategy {strategy}")
        predicted.append(value)
    for index, (want, got) in enumerate(zip(predicted, applied)):
        if want != got:
            structural.append({"cycle": index + 1, "declared": want, "applied": got})
    return {
        "port": port, "strategy": strategy,
        "declared_parameters": {"pulse_cycles": pulse_cycles, "min_gap_cycles": min_gap,
                                "handshake": hold_on_ready},
        "rule_id": str(declared["rule_id"]), "primitive": str(declared["primitive"]),
        "checker": str(declared["checker"]),
        "failure_class": str(declared["failure_class"]),
        "violations": violations, "structural": structural,
        "requests": requests, "applied": applied, "declared_waveform": predicted,
    }


def drive_legality_record(plan: CompositionPlan, policy: InputConstraintPolicy,
                          sample: RuntimeSample, result) -> dict[str, object]:
    """The environment-legality record of one run, from the declared drive contracts."""
    checks, violations, structural = [], [], []
    waveforms: dict[str, object] = {}
    for port, declared in sorted(declared_drive_contracts(plan, policy).items()):
        outcome = monitor_drive_contract(declared, sample, result)
        checks.append({"monitor": outcome["checker"], "rule_id": outcome["rule_id"],
                       "primitive": outcome["primitive"], "port": port,
                       "strategy": outcome["strategy"],
                       "declared_parameters": outcome["declared_parameters"],
                       "violations": outcome["violations"],
                       "structural": outcome["structural"],
                       "result": "fail" if (outcome["violations"]
                                            or outcome["structural"]) else "pass"})
        violations.extend(dict(item, rule_id=outcome["rule_id"], port=port,
                               strategy=outcome["strategy"],
                               primitive=outcome["primitive"],
                               failure_class=outcome["failure_class"],
                               checker=outcome["checker"],
                               declared=outcome["declared_parameters"])
                          for item in outcome["violations"])
        structural.extend(dict(item, rule_id=outcome["rule_id"], port=port,
                               strategy=outcome["strategy"])
                          for item in outcome["structural"])
        waveforms[port] = {"requests": outcome["requests"], "applied": outcome["applied"],
                           "declared_waveform": outcome["declared_waveform"]}
    return {"checks": checks, "violations": violations, "structural": structural,
            "waveforms": waveforms}


def legality_record(plan: CompositionPlan, policy: InputConstraintPolicy,
                    sample: RuntimeSample, result, *, interaction: str, site: str,
                    environment_broken: bool = False,
                    notes: Sequence[str] = ()) -> dict[str, object]:
    """One run's legality record in the shape the evidence package requires.

    ``environment_legality`` is ``violated`` only when the environment itself broke
    a declared precondition (``interaction`` is deliberately illegal and the
    monitor saw the request dropped).  A structural finding -- the declared driver
    is not in the composition -- stays in the record but does not mark the
    environment, which is what keeps a legal interaction from being blamed for a
    wiring fault.
    """
    monitored = drive_legality_record(plan, policy, sample, result)
    violations = monitored["violations"]
    structural = monitored["structural"]
    if environment_broken and not violations:
        raise AssertionError("the run was declared an environment violation but the "
                             "declared drive contracts all held")
    return {
        "environment_legality": LEGALITY_VIOLATED if violations else LEGALITY_CONFIRMED,
        "driver_violations": violations,
        "constraint_rejections": [],
        "monitor_results": monitored["checks"],
        "structural_findings": structural,
        "waveforms": monitored["waveforms"],
        "experiment": {
            "site": site,
            "interaction": interaction,
            "fault_injection": True,
            "environment_broken": bool(violations),
            "declared_contracts": [
                {key: item[key] for key in ("rule_id", "primitive", "checker",
                                            "failure_class", "top_port", "strategy",
                                            "drive", "width", "raw_lo", "raw_hi")}
                for _port, item in sorted(declared_drive_contracts(plan, policy).items())],
            "violated_constraint": violations[0] if violations else None,
        },
        "notes": list(notes),
    }


# ---------------------------------------------------------------------------
# evidence packages
# ---------------------------------------------------------------------------


def criterion(criterion_id: str, statement: str, basis: str) -> dict[str, object]:
    return {"criterion_id": criterion_id, "statement": statement, "basis": basis,
            "independent": True}


def injected_anomaly(*, kind: str, criterion_id: str, statement: str, basis: str,
                     expected: object, observed: object, field: str,
                     cycle: int | None = None) -> dict[str, object]:
    return {
        "present": True, "kind": kind, "criterion": criterion_id, "basis": basis,
        "statement": statement, "basis_independent": True, "reproducible": True,
        "expected": expected, "observed": observed,
        "first_divergence": {"cycle": cycle, "field": field,
                             "kind": "observation" if field.startswith("observation:")
                             else "applied-port-value"},
    }


def package_for(plan: CompositionPlan, build: RuntimeBuild, policy: InputConstraintPolicy,
                sample: RuntimeSample, result, *, kind: str, criterion_record: Mapping,
                anomaly: Mapping, legality: Mapping, findings: Mapping,
                injection: Mapping, notes: Sequence[str] = ()) -> EvidencePackage:
    """Build one package from a real run, its legality record and the findings."""
    attribution: dict[str, object] = {key: list(value) for key, value in findings.items()}
    attribution["injection"] = dict(injection)
    return build_evidence_package(plan, build, policy, [result], kind=kind, samples=[sample],
                                  criteria=[criterion_record], legality=legality,
                                  attribution=attribution, anomaly=anomaly,
                                  notes=list(notes))


def round_trip(package: EvidencePackage, label: str) -> tuple[EvidencePackage, Path]:
    """Write a package and read it back; the classification must survive."""
    directory = EVIDENCE_ROOT / label
    shutil.rmtree(directory, ignore_errors=True)
    document = write_evidence_package(package, directory)
    return read_evidence_package(directory), document


# ---------------------------------------------------------------------------
# the pure composition refusal (no build needed) -- runs in the default suite
# ---------------------------------------------------------------------------


@unittest.skipUnless(tools_available(), "verilator is required for the RTL frontend")
class ProfileBindingConflictTests(unittest.TestCase):
    """A profile that declares what the RTL contradicts is refused, by name."""

    def test_a_declared_width_the_rtl_does_not_have_names_the_binding_conflict(self) -> None:
        plan = novacore_plan()
        self.assertEqual(32, rtl_field_width(plan, "gpio0", "gpio.bus", "pwdata"))
        with self.assertRaises(ComponentProfileError) as caught:
            with_declared_field_width(plan, "gpio0", "gpio.bus", "pwdata", 16)
        message = str(caught.exception)
        # The failure names the component, the endpoint, the role, the elaborated
        # port and both widths -- it does not adapt the declaration to the RTL.
        self.assertIn("binding-width-conflict", message)
        self.assertIn("novagpio", message)
        self.assertIn("gpio.bus:pwdata", message)
        self.assertIn("pwdata_i:32!=16", message)

    def test_a_declared_direction_the_protocol_forbids_names_the_conflict(self) -> None:
        plan = novacore_plan()
        with self.assertRaises(ComponentProfileError) as caught:
            with_declared_field_direction(plan, "gpio0", "gpio.bus", "psel", "output")
        message = str(caught.exception)
        self.assertIn("field-direction-conflicts-with-function", message)
        self.assertIn("gpio.bus:psel:output!=input", message)

    def test_a_role_bound_to_a_port_the_rtl_lacks_is_refused_not_guessed(self) -> None:
        plan = novacore_plan()
        with self.assertRaises(ComponentProfileError) as caught:
            with_missing_port_alias(plan, "gpio0", "gpio.irq", "irq", "irq_absent_o")
        message = str(caught.exception)
        self.assertIn("port-missing", message)
        self.assertIn("irq_absent_o", message)


# ---------------------------------------------------------------------------
# the executed matrix
# ---------------------------------------------------------------------------


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the boundary fault-injection matrix")
class SocBoundaryFaultInjectionTests(unittest.TestCase):
    """Five injected layers, each detected, each attributed, none a component bug."""

    context: dict[str, object] | None = None
    preparation_error: str | None = None

    # -- preparation -------------------------------------------------------

    @classmethod
    def setUpClass(cls) -> None:
        if not tools_available():
            raise AssertionError("MYFUZZ_SOC_REAL=1 requires Verilator for the boundary "
                                 "fault-injection matrix")
        try:
            cls.context = cls._prepare()
        except Exception as error:  # noqa: BLE001 - reported verbatim
            cls.preparation_error = f"{type(error).__name__}: {error}"

    def setUp(self) -> None:
        if self.preparation_error is not None:
            self.fail("the fault-injection matrix could not be prepared: "
                      f"{self.preparation_error}")

    @classmethod
    def _prepare(cls) -> dict[str, object]:
        context: dict[str, object] = {}
        notes: list[str] = []

        plan = novacore_plan()
        policy = _policy(plan)
        top = _top_text(plan)
        declared = declared_drive_contracts(plan, policy)
        if set(declared) != {EVENT_PORT, PIN_MODE_PORT}:
            raise AssertionError("the example plan declares unexpected special inputs: "
                                 f"{sorted(declared)}")
        if int(declared[PIN_MODE_PORT]["raw_lo"]) != PIN_MODE_SHIFT:
            raise AssertionError("gpio0.pin_mode_i is not at raw bit 4")
        context.update(novacore_plan=plan, novacore_policy=policy, novacore_top=top,
                       novacore_declared_drives=declared)

        # The clean baseline: the same composition with no fault anywhere.  Every
        # divergence below is a divergence from *this* run on *this* machine.
        baseline_build = runtime_build()
        wave = RuntimeSample(request_id=0xB0, raw=WAVE_RAW)
        baseline_result, baseline_repeat = run_twice(baseline_build, wave,
                                                     label="clean baseline")
        if baseline_result.status != "OK":
            raise AssertionError(f"the clean baseline did not complete: "
                                 f"{baseline_result.status} {baseline_result.reason}")
        context.update(novacore_baseline_build=baseline_build,
                       novacore_baseline_sample=wave,
                       novacore_baseline_result=baseline_result,
                       novacore_baseline_repeat=baseline_repeat)
        notes.append(f"clean baseline: status={baseline_result.status} "
                     f"status_o={baseline_result.observations.get('cpu0__status_o')} "
                     f"trap_o={baseline_result.observations.get('cpu0__trap_o')}")

        # --- generator, router packing -------------------------------------
        pristine_map = router_target_map(plan, top)
        expected_map = {str(row["window_id"]): int(row["target_index"])
                        for row in _router_decode(plan)}
        if pristine_map != expected_map:
            raise AssertionError(f"the router-packing re-read disagrees with the plan on "
                                 f"the pristine top: {pristine_map} != {expected_map}")
        swapped_top, swap_record = swap_router_window_targets(plan, top, "rom0", "gpio0_win")
        context["router_swap"] = cls._runtime_case(
            plan, policy, "generator-router-swap", swapped_top, swap_record,
            RuntimeSample(request_id=0xB1, raw=WAVE_RAW), context,
            criterion_basis="the plan's own decode windows and the clean baseline run of "
                            "the same composition")

        # --- generator, dropped driver -------------------------------------
        dropped_top, drop_record = drop_special_input_driver(top, "cpu0", "event_i")
        context["driver_drop"] = cls._runtime_case(
            plan, policy, "generator-driver-drop", dropped_top, drop_record,
            RuntimeSample(request_id=0xB2, raw=WAVE_RAW), context,
            criterion_basis="the plan's declared special-input driver contract, replayed "
                            "against the run's applied-value observations",
            cpu_divergence=False)

        # --- adapter --------------------------------------------------------
        adapter_top, adapter_record = corrupt_adapter_window_base(
            plan, top, "gpio0", adapter_window_base(plan, "uart1"))
        context["adapter"] = cls._runtime_case(
            plan, policy, "adapter-window-base", adapter_top, adapter_record,
            RuntimeSample(request_id=0xB3, raw=WAVE_RAW), context,
            criterion_basis="the resolved adapter window parameters the plan binds to the "
                            "rendered bridge, and the clean baseline run")

        # --- external model: the declared timing contract of a GPIO stimulus
        pulse_plan = with_port_action_strategy(plan, "gpio0", "pin_mode_i", "pulse",
                                               {"pulse_cycles": 4, "min_gap_cycles": 8})
        pulse_policy = _policy(pulse_plan)
        pulse_top = _top_text(pulse_plan)
        if ".STRATEGY(2), .PULSE_CYCLES(4), .PULSE_MIN_GAP(8)" not in pulse_top:
            raise AssertionError("the declared pulse strategy was not rendered into the "
                                 "driver instance")
        pulse_build = build_runtime(pulse_plan, "external-pulse")
        context.update(
            pulse_plan=pulse_plan, pulse_policy=pulse_policy, pulse_top=pulse_top,
            pulse_build=pulse_build,
            # Two accepted requests: the pulse trigger is raw_i[0], so both requests
            # carry an odd payload (1 then 3) and the second rising edge is 13
            # cycles after the first pulse ended, past the declared minimum gap of 8.
            pulse_legal_raw=tuple([(1 << PIN_MODE_SHIFT)] + [0] * 12
                                  + [(3 << PIN_MODE_SHIFT)] + [0] * 20),
            pulse_illegal_active_raw=tuple([(1 << PIN_MODE_SHIFT), 0,
                                            (1 << PIN_MODE_SHIFT)] + [0] * 20),
            pulse_illegal_gap_raw=tuple([(1 << PIN_MODE_SHIFT)] + [0] * 5
                                        + [(1 << PIN_MODE_SHIFT)] + [0] * 20))
        notes.append("declared pulse contract on gpio0.pin_mode_i: PULSE_CYCLES=4, "
                     "PULSE_MIN_GAP=8 (profile port_actions -> rendered "
                     "soc_special_input_driver #(.STRATEGY(2), .PULSE_CYCLES(4), "
                     ".PULSE_MIN_GAP(8)))")

        # --- the real CPU composition (generator 1a, profile 3b, software 4) -
        context["ibex"] = cls._ibex_cases(notes)
        context["notes"] = notes
        return context

    @classmethod
    def _runtime_case(cls, plan: CompositionPlan, policy: InputConstraintPolicy, label: str,
                      top_text: str, record: Mapping[str, object], sample: RuntimeSample,
                      context: Mapping[str, object], *, criterion_basis: str,
                      cpu_divergence: bool = True) -> dict:
        """Audit one mutated top, build it, run it twice and package the result.

        ``cpu_divergence`` is False for a fault whose symptom is not a CPU
        observation: the dropped-driver fault leaves novacore's status untouched
        (the component only XOR-reduces ``event_i``), so its detection is the
        declared-drive-contract monitor's structural finding and that is what the
        guard requires instead.
        """
        audit = audit_structure(plan, top_text=top_text, source_files=_sources(plan),
                                base_dir=ROOT, include_roots=_include_roots(plan))
        build = build_runtime(plan, label, top_text=top_text)
        result, repeat = run_twice(build, sample, label=label)
        if result.status != "OK":
            raise AssertionError(f"{label}: the injected build did not run: "
                                 f"{result.status} {result.reason}")
        legality = legality_record(plan, policy, sample, result,
                                   interaction=LEGAL_INTERACTION, site=str(record["site"]),
                                   notes=["the raw stimulus obeys every declared drive "
                                          "contract; the fault is in the built artifact, "
                                          "not in the environment"])
        baseline = context["novacore_baseline_result"]
        observed = {"cpu0__status_o": result.observations.get("cpu0__status_o"),
                    "cpu0__trap_o": result.observations.get("cpu0__trap_o")}
        expected = {"cpu0__status_o": baseline.observations.get("cpu0__status_o"),
                    "cpu0__trap_o": baseline.observations.get("cpu0__trap_o")}
        if cpu_divergence:
            if observed == expected:
                raise AssertionError(f"{label}: the injected fault produced no observable "
                                     f"divergence from the clean baseline: {observed}")
            anomaly = injected_anomaly(
                kind="injected-artifact-divergence",
                criterion_id="declared-artifact-contract",
                statement="the composed CPU completes its boot fetch and holds ST_POLL "
                          "(status_o == 3) with trap_o == 0, exactly as the clean build of "
                          "the same plan does",
                basis=criterion_basis, expected=expected, observed=observed,
                field="observation:cpu0__trap_o")
        else:
            structural = legality["structural_findings"]
            if not structural:
                raise AssertionError(f"{label}: the injected fault is not detectable: the "
                                     f"declared drive contract monitor found neither a "
                                     f"violation nor a structural finding")
            first = structural[0]
            anomaly = injected_anomaly(
                kind="declared-driver-structure-missing",
                criterion_id="declared-driver-implements-its-strategy",
                statement="the rendered driver implements the strategy the plan declares "
                          "for every special input",
                basis=criterion_basis, expected={"declared": first["declared"]},
                observed={"applied": first["applied"]},
                field=f"applied[{first['port']}]", cycle=int(first["cycle"]))
        case = dict(record)
        case["record"] = dict(record)
        case.update({
            "audit": audit, "build": build, "sample": sample, "result": result,
            "repeat": repeat, "legality": legality, "anomaly": anomaly, "policy": policy,
            "plan": plan, "expected": expected, "observed": observed, "top_text": top_text,
            "audit_status": audit["summary"]["status"],
            "audit_findings": [{"check_id": item["check_id"], "status": item["status"],
                                "detail": item["detail"], "expected": item.get("expected"),
                                "actual": item.get("actual")}
                               for item in audit["findings"] if item["status"] != "pass"],
            "audit_unknown": [item["check_id"] for item in audit["unknown"]],
            "build_directory": str(build.output_dir), "build_hash": build.build_hash,
        })
        notes = context.get("notes")
        line = (f"{label}: audit={audit['summary']['status']} "
                f"findings={[item['check_id'] for item in case['audit_findings']]} "
                f"status_o={observed['cpu0__status_o']} trap_o={observed['cpu0__trap_o']} "
                f"(baseline {expected['cpu0__status_o']}/{expected['cpu0__trap_o']})")
        print(f"MYFUZZ_BOUNDARY {line}")
        if isinstance(notes, list):
            notes.append(line)
        return case

    @classmethod
    def _ibex_cases(cls, notes: list[str]) -> dict[str, object]:
        """The real-CPU composition: boot program, four real builds, real runs."""
        plan = ibex_plan()
        policy = _policy(plan)
        top = _top_text(plan)
        controller = plan.interrupt_document["controller"]
        if not controller.get("present"):
            raise AssertionError("the Ibex composition declares no interrupt controller")
        sources = sorted(plan.interrupt_document["sources"],
                         key=lambda item: int(item["source_id"]))
        if len(sources) < 2:
            raise AssertionError("the Ibex composition declares fewer than two sources")
        program = build_boot_program(plan)
        trigger = program.document["trigger"]
        if trigger is None or trigger["instance_id"] != "gpio0":
            raise AssertionError("the generated boot program triggers no gpio0 source")
        clear = declared_clear_instruction(program)
        image = write_image("ibex-positive", program.image)
        build = build_runtime(plan, "ibex-pristine", top_text=top, boot_image=image)
        sample = RuntimeSample(request_id=0x1BE, raw=(0,) * CYCLES,
                               events=tuple(
                                   ExternalEvent(slot=int(item["slot"]),
                                                 cycle=int(item["cycle"]),
                                                 value=int(item["value"]))
                                   for item in trigger["events"]))
        result, repeat = run_twice(build, sample, label="real-CPU baseline")
        if result.status != "OK":
            raise AssertionError(f"the real-CPU baseline did not run: {result.status}")
        if read32(result, program.flag_address) != COMPLETION_FLAG:
            raise AssertionError("the real-CPU baseline never wrote the completion flag")
        report = {name: report_value(program, result, name)
                  for name in report_layout(program)}
        for name, promised in program.observations.items():
            if name == "completion_flag":
                continue
            if report.get(name) != promised:
                raise AssertionError(f"the real-CPU baseline contradicts its own declared "
                                     f"promise {name}: promised {promised} read "
                                     f"{report.get(name)}")
        notes.append(f"real-CPU baseline: claim_id={report['claim_id']} "
                     f"handler_entries={report['handler_entries']} "
                     f"cause_after_clear={report['cause_after_clear']} "
                     f"source_count={report['source_count']} "
                     f"loop_closed={report['loop_closed']}")

        # --- generator: source vector --------------------------------------
        vector_top, vector_record = swap_interrupt_source_vector(plan, top)
        vector_audit = audit_structure(plan, top_text=vector_top, source_files=_sources(plan),
                                       base_dir=ROOT, include_roots=_include_roots(plan))
        vector_build = build_runtime(plan, "ibex-generator-vector", top_text=vector_top,
                                     boot_image=image)
        vector_result, vector_repeat = run_twice(vector_build, sample,
                                                 label="generator source vector")
        vector_report = {name: report_value(program, vector_result, name)
                         for name in report_layout(program)}
        vector_case = dict(vector_record)
        vector_case["record"] = dict(vector_record)
        vector_case.update({
            "audit": vector_audit, "build": vector_build, "sample": sample,
            "result": vector_result, "repeat": vector_repeat, "report": vector_report,
            "policy": policy, "plan": plan,
            "audit_findings": [{"check_id": item["check_id"], "status": item["status"],
                                "detail": item["detail"],
                                "expected": item.get("expected"),
                                "actual": item.get("actual")}
                               for item in vector_audit["findings"]
                               if item["status"] != "pass"],
            "audit_unknown": [item["check_id"] for item in vector_audit["unknown"]],
            "build_directory": str(vector_build.output_dir),
        })
        print(f"MYFUZZ_BOUNDARY generator source vector: audit="
              f"{vector_audit['summary']['status']} "
              f"findings={[item['check_id'] for item in vector_case['audit_findings']]} "
              f"handler_entries={vector_report['handler_entries']} "
              f"(baseline {report['handler_entries']}) "
              f"main_completed={vector_report['main_completed']} "
              f"(baseline {report['main_completed']}) "
              f"source_count={vector_report['source_count']} "
              f"(baseline {report['source_count']})")

        # --- software: the declared clear step removed ----------------------
        patched = patch_image_word(program, int(clear["address"]), 0x00000013)
        patched_image = write_image("ibex-software-no-clear", patched["image"])
        software_build = build_runtime(plan, "ibex-software-no-clear", top_text=top,
                                       boot_image=patched_image)
        software_result, software_repeat = run_twice(software_build, sample,
                                                     label="software missing clear")
        control = run_sample(build, sample)
        software_report = {name: report_value(program, software_result, name)
                           for name in report_layout(program)}
        print(f"MYFUZZ_BOUNDARY software patch: word 0x{int(clear['word']):08x} at "
              f"0x{int(clear['address']):08x} -> 0x00000013 (nop); "
              f"cause_after_clear={software_report['cause_after_clear']} "
              f"(same binary, generated image: "
              f"{report_value(program, control, 'cause_after_clear')}) "
              f"handler_entries={software_report['handler_entries']}")
        notes.append(f"software patch cause_after_clear="
                     f"{software_report['cause_after_clear']} (control "
                     f"{report_value(program, control, 'cause_after_clear')})")

        # --- profile: a declared clear the RTL does not implement ------------
        profile_plan = ibex_plan(mutate_profile=(GPIO_PROFILE,
                                                 declared_clear_profile_mutation))
        profile_policy = _policy(profile_plan)
        profile_top = _top_text(profile_plan)
        profile_program = build_boot_program(profile_plan)
        profile_source = next(item for item in profile_program.document["sources"]
                              if item["instance_id"] == "gpio0")
        if profile_source["clear"]["kind"] != "write_1_to_clear" \
                or profile_source["clear"]["register"] != "IRQ_STATUS":
            raise AssertionError("the mutated profile did not change the declared clear "
                                 f"operation: {profile_source['clear']}")
        profile_image = write_image("ibex-profile-clear", profile_program.image)
        profile_build = build_runtime(profile_plan, "ibex-profile-clear",
                                      top_text=profile_top, boot_image=profile_image)
        profile_trigger = profile_program.document["trigger"]
        profile_sample = RuntimeSample(
            request_id=0x1BF, raw=(0,) * CYCLES,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in profile_trigger["events"]))
        profile_result, profile_repeat = run_twice(profile_build, profile_sample,
                                                   label="profile declared clear")
        profile_report = {name: report_value(profile_program, profile_result, name)
                          for name in report_layout(profile_program)}
        print(f"MYFUZZ_BOUNDARY profile declared clear: "
              f"{profile_source['clear']['register']} "
              f"offset 0x{int(profile_source['clear']['offset']):02x} "
              f"({profile_source['clear']['kind']}); "
              f"cause_after_clear={profile_report['cause_after_clear']} "
              f"(promised {profile_program.observations['cause_after_clear']}) "
              f"handler_entries={profile_report['handler_entries']} "
              f"(baseline {report['handler_entries']})")
        notes.append(f"profile declared clear cause_after_clear="
                     f"{profile_report['cause_after_clear']} "
                     f"handler_entries={profile_report['handler_entries']}")
        return {
            "plan": plan, "policy": policy, "top": top, "sources": sources,
            "program": program, "clear": clear, "image": image, "build": build,
            "sample": sample, "result": result, "repeat": repeat, "report": report,
            "vector": vector_case,
            "software": {"patch": patched, "image": patched_image, "build": software_build,
                         "result": software_result, "repeat": software_repeat,
                         "control": control, "report": software_report},
            "profile": {"plan": profile_plan, "policy": profile_policy, "top": profile_top,
                        "program": profile_program, "build": profile_build,
                        "sample": profile_sample, "result": profile_result,
                        "repeat": profile_repeat, "report": profile_report,
                        "source": profile_source},
        }

    # -- small shared accessors -------------------------------------------

    def ctx(self) -> dict[str, object]:
        assert self.context is not None
        return self.context

    def ibex(self) -> dict[str, object]:
        return self.ctx()["ibex"]  # type: ignore[return-value]

    def print_note(self, text: str) -> None:
        print(f"MYFUZZ_BOUNDARY {text}")

    def _site_packages(self) -> dict[str, EvidencePackage]:
        """The package of every injected site, built once per test process."""
        if "site_packages" not in self.ctx():
            self.ctx()["site_packages"] = self._build_site_packages()
        return self.ctx()["site_packages"]  # type: ignore[return-value]

    def _build_site_packages(self) -> dict[str, EvidencePackage]:
        context = self.ctx()
        ibex = self.ibex()
        packages: dict[str, EvidencePackage] = {}

        vector = ibex["vector"]
        baseline = ibex["report"]
        report = vector["report"]
        packages["generator:source-vector"] = package_for(
            ibex["plan"], vector["build"], ibex["policy"], ibex["sample"],
            vector["result"], kind="fault_injection_generator_source_vector",
            criterion_record=criterion(
                "controller-source-vector-matches-the-plan",
                "each declared source id reaches the controller bit the plan recorded for "
                "it, so the ISR's source table identifies the peripheral it clears",
                "the plan's interrupt_document source table and the independent structural "
                "audit of the elaborated top (check interrupt_paths)"),
            anomaly=injected_anomaly(
                kind="injected-artifact-divergence",
                criterion_id="controller-source-vector-matches-the-plan",
                statement="the controller's source vector is the plan's recorded order",
                basis="the plan's interrupt_document and audit_structure check "
                      "interrupt_paths",
                expected={"handler_entries": baseline["handler_entries"],
                          "main_completed": baseline["main_completed"],
                          "source_count": baseline["source_count"]},
                observed={"handler_entries": report["handler_entries"],
                          "main_completed": report["main_completed"],
                          "source_count": report["source_count"]},
                field="observation:handler_entries"),
            legality=legality_record(ibex["plan"], ibex["policy"], ibex["sample"],
                                     vector["result"], interaction=LEGAL_INTERACTION,
                                     site=SITE_GENERATOR,
                                     notes=["the environment applied exactly the events "
                                            "the program declares"]),
            findings={"composition_findings": [
                "audit_structure check interrupt_paths failed: the elaborated source "
                "vector is not the plan's recorded order",
                f"the mis-attributed source changed the controller bookkeeping: "
                f"handler_entries {report['handler_entries']} vs "
                f"{baseline['handler_entries']}, main_completed "
                f"{report['main_completed']} vs {baseline['main_completed']}"]},
            injection=vector, notes=["injected: the interrupt source vector order in the "
                                     "rendered top; the plan is unchanged"])

        router = context["router_swap"]  # type: ignore[index]
        pristine_map = router_target_map(context["novacore_plan"], context["novacore_top"])
        packages["generator:router-window"] = package_for(
            router["plan"], router["build"], router["policy"], router["sample"],
            router["result"], kind="fault_injection_generator_router_window",
            criterion_record=criterion("router-window-targets-match-the-plan",
                                       str(router["anomaly"]["statement"]),
                                       str(router["anomaly"]["basis"])),
            anomaly=router["anomaly"], legality=router["legality"],
            findings={"composition_findings": [
                "the rendered router WINDOW_TARGET packing disagrees with the plan's "
                f"decode table: plan {router['record']['plan_decode']}, rendered "
                f"{router['record']['rendered_after']} (the audit re-reads the adapter "
                "parameters but not the router's own window parameters)",
                f"the run's CPU traps: status_o={router['observed']['cpu0__status_o']} "
                f"trap_o={router['observed']['cpu0__trap_o']} against the clean baseline "
                f"{router['expected']['cpu0__status_o']}/"
                f"{router['expected']['cpu0__trap_o']}"]},
            injection=router["record"],
            notes=["injected: the router WINDOW_TARGET packing in the rendered top; the "
                   "plan and every component are unchanged",
                   f"pristine router packing re-read: {pristine_map}"])

        dropped = context["driver_drop"]  # type: ignore[index]
        monitored = legality_record(dropped["plan"], dropped["policy"], dropped["sample"],
                                    dropped["result"], interaction=LEGAL_INTERACTION,
                                    site=SITE_GENERATOR)
        structural = monitored["structural_findings"][0]
        packages["generator:driver-dropped"] = package_for(
            dropped["plan"], dropped["build"], dropped["policy"], dropped["sample"],
            dropped["result"], kind="fault_injection_generator_driver_dropped",
            criterion_record=criterion("declared-driver-implements-its-strategy",
                                       "every declared special input is driven by the "
                                       "rendered driver under the profile's declared "
                                       "strategy",
                                       "the plan's compiled drive rule and the "
                                       "soc_special_input_driver contract it names"),
            anomaly=injected_anomaly(
                kind="declared-driver-structure-missing",
                criterion_id="declared-driver-implements-its-strategy",
                statement="the rendered driver implements the declared strategy",
                basis="the plan's compiled drive rule vs the run's applied waveform",
                expected={"declared": structural["declared"]},
                observed={"applied": structural["applied"]},
                field=f"applied[{EVENT_PORT}]", cycle=int(structural["cycle"])),
            legality=monitored,
            findings={"composition_findings": [
                f"the rendered top contains no soc_special_input_driver for {EVENT_PORT} "
                f"({dropped['record']['mutation']})",
                f"the declared drive strategy cannot explain the applied waveform: "
                f"{structural}"]},
            injection=dropped["record"],
            notes=["injected: the rendered top's driver instance; the plan still declares "
                   "the driver, so the built structure contradicts the plan"])

        adapter = context["adapter"]  # type: ignore[index]
        audit_finding = next(item for item in adapter["audit_findings"]
                             if item["check_id"] == "adapter_parameters")
        packages["adapter:window-base"] = package_for(
            adapter["plan"], adapter["build"], adapter["policy"], adapter["sample"],
            adapter["result"], kind="fault_injection_adapter_window_base",
            criterion_record=criterion("adapter-window-parameters-match-the-plan",
                                       str(adapter["anomaly"]["statement"]),
                                       str(adapter["anomaly"]["basis"])),
            anomaly=adapter["anomaly"], legality=adapter["legality"],
            findings={"composition_findings": [
                "audit_structure check adapter_parameters failed: the elaborated adapter "
                f"carries WINDOW_BASE "
                f"{audit_finding['actual'][0]['actual']['WINDOW_BASE']} while the plan "
                f"resolved {audit_finding['actual'][0]['expected']['WINDOW_BASE']}",
                f"the run's CPU traps: status_o={adapter['observed']['cpu0__status_o']} "
                f"trap_o={adapter['observed']['cpu0__trap_o']} against the clean baseline "
                f"{adapter['expected']['cpu0__status_o']}/"
                f"{adapter['expected']['cpu0__trap_o']}"]},
            injection=adapter["record"],
            notes=["injected: the rendered adapter's WINDOW_BASE parameter; the adapter "
                   "RTL and the peripheral are unchanged"])

        profile = ibex["profile"]
        packages["profile:declared-clear"] = package_for(
            profile["plan"], profile["build"], profile["policy"], profile["sample"],
            profile["result"], kind="fault_injection_profile_declared_clear",
            criterion_record=criterion(
                "profile-declared-clear-empties-the-source",
                "the declared clear operation ends the condition the profile's own hold "
                "text names",
                "the profile's declared register semantics checked against the component's "
                "RTL and against the same program on the profile the RTL implements"),
            anomaly=injected_anomaly(
                kind="declared-register-contract-violated",
                criterion_id="profile-declared-clear-empties-the-source",
                statement="the declared clear empties the source condition",
                basis="the profile's declared register map and clear text against the RTL",
                expected={"cause_after_clear": 0, "status_raw_after_clear": 0},
                observed={"cause_after_clear": profile["report"]["cause_after_clear"],
                          "status_raw_after_clear":
                              profile["report"]["status_raw_after_clear"]},
                field="observation:cause_after_clear"),
            legality=legality_record(profile["plan"], profile["policy"], profile["sample"],
                                     profile["result"], interaction=LEGAL_INTERACTION,
                                     site=SITE_PROFILE,
                                     notes=["the environment applied the declared trigger; "
                                            "the declared clear is what failed"]),
            findings={"profile_findings": [
                "the profile declares gpio0 IRQ_STATUS read-write with a "
                "write-1-to-clear side effect at offset 0x10 and names it in the source's "
                "clear text, while examples/soc_generation/rtl/novagpio.sv declares "
                "'0x10 IRQ_STAT ro   bit0 pin-event pending (cleared by writing DATA_IN)'",
                f"the generated program performed the declared write and the condition "
                f"stayed asserted: cause_after_clear="
                f"{profile['report']['cause_after_clear']} against its own promise "
                f"{profile['program'].observations['cause_after_clear']}"]},
            injection={"site": SITE_PROFILE, "artifact": GPIO_PROFILE,
                       "mutation": "IRQ_STATUS: ro/none -> rw/write_1_to_clear and "
                                   "the source clear text names IRQ_STATUS[0]",
                       "plan_hash": profile["plan"].plan_hash,
                       "declared_clear": dict(profile["source"]["clear"])},
            notes=["injected: the profile's declared register semantics; the component RTL "
                   "is unchanged and the same binary clears correctly with the profile the "
                   "RTL implements"])

        software = ibex["software"]
        clear = ibex["clear"]
        promised = ibex["program"].observations["cause_after_clear"]
        control = report_value(ibex["program"], software["control"], "cause_after_clear")
        packages["software:missing-clear"] = package_for(
            ibex["plan"], software["build"], ibex["policy"], ibex["sample"],
            software["result"], kind="fault_injection_software_missing_clear",
            criterion_record=criterion(
                "generated-program-meets-its-declared-promises",
                "the generated program's declared promise (cause_after_clear == 0 after "
                "the declared clear) holds in the run",
                "build_boot_program's own observations document, checked against the same "
                "compiled binary with the unpatched image"),
            anomaly=injected_anomaly(
                kind="stimulus-program-contradicts-its-declared-contract",
                criterion_id="generated-program-meets-its-declared-promises",
                statement="the declared clear promise holds in the run",
                basis="the program's own observations document and the unpatched image run "
                      "on the same binary",
                expected={"cause_after_clear": promised, "status_raw_after_clear": 0},
                observed={"cause_after_clear": software["report"]["cause_after_clear"],
                          "status_raw_after_clear":
                              software["report"]["status_raw_after_clear"]},
                field="observation:cause_after_clear"),
            legality=legality_record(ibex["plan"], ibex["policy"], ibex["sample"],
                                     software["result"], interaction=LEGAL_INTERACTION,
                                     site=SITE_SOFTWARE,
                                     notes=["the environment applied the declared trigger; "
                                            "the stimulus program contradicted its own "
                                            "declared register contract"]),
            findings={"software_or_model_findings": [
                f"the boot image's declared clear instruction "
                f"(0x{int(clear['word']):08x} at 0x{int(clear['address']):08x}, "
                f"'{clear['instruction']}', the listing's '{clear['comment']}') was "
                f"replaced with 0x00000013 (nop), so the declared clear step is absent",
                f"the program's own promise cause_after_clear={promised} is contradicted: "
                f"cause_after_clear={software['report']['cause_after_clear']}, "
                f"status_raw_after_clear="
                f"{software['report']['status_raw_after_clear']}; the same compiled binary "
                f"with the generated image reads cause_after_clear={control}"]},
            injection={"site": SITE_SOFTWARE,
                       "artifact": f"boot image word at 0x{int(clear['address']):08x} "
                                   f"(offset 0x{software['patch']['image_offset']:x})",
                       "mutation": f"0x{int(clear['word']):08x} -> 0x00000013 (nop)",
                       "declared_clear": dict(clear)},
            notes=["injected: the produced boot image only; the composition, the profiles "
                   "and every component are unchanged"])

        for label, raw in (("illegal-active-pulse", context["pulse_illegal_active_raw"]),
                           ("illegal-minimum-gap", context["pulse_illegal_gap_raw"])):
            sample = RuntimeSample(request_id=0xC1, raw=raw)
            result, _repeat = run_twice(context["pulse_build"], sample, label=label)
            record = legality_record(context["pulse_plan"], context["pulse_policy"], sample,
                                     result, interaction=DELIBERATE_ILLEGAL,
                                     site=SITE_EXTERNAL, environment_broken=True)
            violation = record["driver_violations"][0]
            packages[f"external:{label}"] = package_for(
                context["pulse_plan"], context["pulse_build"], context["pulse_policy"],
                sample, result, kind=f"fault_injection_external_{label.replace('-', '_')}",
                criterion_record=criterion(
                    "declared-drive-contract-is-honoured-by-the-environment",
                    "every external request the environment offers is one the profile's "
                    "declared drive strategy accepts",
                    "the plan's compiled drive_pulse rule with the declared "
                    "PULSE_CYCLES/PULSE_MIN_GAP against the driver's real applied waveform"),
                anomaly=injected_anomaly(
                    kind="illegal-external-stimulus",
                    criterion_id="declared-drive-contract-is-honoured-by-the-environment",
                    statement="the declared drive contract is honoured by the environment",
                    basis="the plan's compiled drive rule against the applied waveform",
                    expected={"accepted_requests":
                                  len(record["waveforms"][PIN_MODE_PORT]["requests"])},
                    observed={"dropped_request_cycle": violation["cycle"]},
                    field=f"applied[{PIN_MODE_PORT}]", cycle=int(violation["cycle"])),
                legality=record,
                findings={"driver_violations_preserved": [
                    f"{violation['rule_id']}: request at cycle {violation['cycle']} "
                    f"({violation['reason']})"]},
                injection={"site": SITE_EXTERNAL,
                           "artifact": "external request plan",
                           "mutation": f"{label}: {violation['reason']}",
                           "violated_constraint": violation},
                notes=["deliberately illegal experiment: the environment offered a request "
                       "the profile's declared timing contract forbids, so this run is a "
                       "fault-injection experiment, not a legal interaction"])
        return packages

    # ------------------------------------------------------------------
    # site 1: generator
    # ------------------------------------------------------------------

    def test_site1a_generator_source_vector_swap_is_a_named_audit_finding(self) -> None:
        """The generator's vector fault is caught by ``interrupt_paths`` -- and by a run.

        Detection: the independent structural audit re-reads the elaborated source
        vector and fails ``interrupt_paths``; the runtime shows what that means --
        the enabled controller bit now belongs to another peripheral, so the ISR's
        declared source table no longer matches the source it claims, the condition
        it clears is not the asserted one, and the interrupt re-pends: the handler
        re-enters while the main flow is starved.
        """
        vector = self.ibex()["vector"]
        findings = {item["check_id"]: item for item in vector["audit_findings"]}
        self.assertIn("interrupt_paths", findings)
        self.assertEqual(FAIL, findings["interrupt_paths"]["status"])
        self.assertNotEqual(vector["plan_vector_lsb_first"],
                            vector["rendered_after_lsb_first"])
        baseline = self.ibex()["report"]
        report = vector["report"]
        self.assertGreater(report["handler_entries"], baseline["handler_entries"])
        self.assertEqual(1, baseline["main_completed"])
        self.assertEqual(0, report["main_completed"],
                         "the mis-attributed interrupt re-entry storm starves the main "
                         "flow")
        self.assertNotEqual(baseline["source_count"], report["source_count"])
        self.print_note(f"site1a audit expected="
                        f"{json.dumps(findings['interrupt_paths']['expected'])[:120]} "
                        f"actual="
                        f"{json.dumps(findings['interrupt_paths']['actual'])[:120]}")

    def test_site1a_package_is_a_composition_defect(self) -> None:
        """The package built from that run points at the composition."""
        package = self._site_packages()["generator:source-vector"]
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertIn("interrupt_paths", reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)
        read_back, document = round_trip(package, "site1a-generator-source-vector")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site1a package={document} classification={classification} "
                        f"reason={reason[:200]}")

    def test_site1b_generator_router_window_swap_diverges_at_runtime(self) -> None:
        """The router-packing fault: the runtime catches what the audit does not.

        Detection: this module re-reads the rendered ``WINDOW_TARGET`` packing and
        compares it with the plan's decode table (the pristine top passes that
        check, so it is not vacuous), and the run diverges -- the boot fetch now
        routes to a peripheral window and the poll to the ROM target, so the CPU's
        own trap output asserts.
        """
        case = self.ctx()["router_swap"]
        record = case["record"]
        self.assertEqual({"rom0": 0, "gpio0_win": 2}, record["plan_decode"])
        self.assertEqual(2, record["rendered_after"]["rom0"])
        self.assertEqual(0, record["rendered_after"]["gpio0_win"])
        self.assertEqual("pass", case["audit_status"],
                         "the shipped audit does not re-read the router packing")
        self.assertEqual([], case["audit_findings"])
        self.assertTrue(case["audit_unknown"],
                        "the audit documents what it cannot prove")
        self.assertEqual(ST_TRAP, case["observed"]["cpu0__status_o"])
        self.assertEqual(1, case["observed"]["cpu0__trap_o"])
        self.assertEqual(ST_POLL, case["expected"]["cpu0__status_o"])
        self.assertEqual(0, case["expected"]["cpu0__trap_o"])

    def test_site1b_package_is_a_composition_defect(self) -> None:
        package = self._site_packages()["generator:router-window"]
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertIn("wiring/decode/adapter/controller", reason)
        read_back, document = round_trip(package, "site1b-generator-router-window")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site1b package={document} classification={classification} "
                        f"reason={reason[:200]}")

    def test_site1c_generator_dropped_driver_is_caught_by_the_applied_monitor(self) -> None:
        """The dropped-driver fault: the declared structure is not in the build.

        Detection: the plan declares a driver and the top-level port still exists,
        but the component input is no longer driven by it, so the declared strategy
        cannot explain the applied waveform.  The monitor reports a *structural*
        finding -- not a driver violation, because the environment offered a legal
        value -- and the package is a composition defect.
        """
        case = self.ctx()["driver_drop"]
        record = case["record"]
        self.assertEqual(2, len(self.ctx()["novacore_declared_drives"]),
                         "the plan declares two special-input drivers")
        self.assertEqual(1, record["drivers_remaining"],
                         "exactly one rendered driver is left after the drop")
        self.assertTrue(any("u_drive_cpu0__event_i" in line
                            for line in record["removed_lines"]))
        # Two independent detectors see this fault, and the test requires both
        # to be exactly the ones it names.  The audit's ``cpu_input_dispositions``
        # check re-reads the CPU pins against the plan and finds cpu0.event_i no
        # longer driven by its declared driver net; the applied-value monitor
        # below finds the declared strategy cannot explain the waveform.  A
        # *silent* audit is not required: if the audit fails, it must fail with
        # that one check and nothing else, so an unrelated audit regression
        # still fails this test.
        if case["audit_status"] != "pass":
            self.assertEqual({"cpu_input_dispositions"},
                             {item["check_id"] for item in case["audit_findings"]},
                             "the audit failed for a reason other than the dropped CPU "
                             "input driver")
            detail = case["audit_findings"][0]
            self.assertEqual(FAIL, detail["status"])
            # The audit names the *component* pin (u_cpu0.event_i), while
            # EVENT_PORT is the exported top-level port name (cpu0__event_i).
            self.assertIn(f"u_cpu0.{EVENT_PORT.split('__', 1)[1]}",
                          json.dumps(detail["actual"], sort_keys=True),
                          "the audit's disagreement does not name the CPU input that the "
                          "mutation undrove")
        self.assertTrue(case["result"].applied,
                        "the surviving driver still reports applied values")
        package = self._site_packages()["generator:driver-dropped"]
        monitored = package.legality
        self.assertEqual([], monitored["driver_violations"],
                         "a deleted driver is not an environment violation")
        self.assertEqual(LEGALITY_CONFIRMED, monitored["environment_legality"])
        structural = [item for item in monitored["structural_findings"]
                      if item["port"] == EVENT_PORT]
        self.assertTrue(structural)
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertNotEqual(DRIVER_VIOLATION, classification)
        read_back, document = round_trip(package, "site1c-generator-driver-dropped")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site1c package={document} classification={classification} "
                        f"structural={json.dumps(structural[0])}")

    # ------------------------------------------------------------------
    # site 2: adapter
    # ------------------------------------------------------------------

    def test_site2_adapter_window_base_is_a_named_audit_finding(self) -> None:
        """The adapter fault: the APB bridge's ``WINDOW_BASE`` is corrupted.

        Detection: the independent audit re-reads the elaborated adapter parameters
        and fails ``adapter_parameters``, naming the instance and both values; the
        run diverges the same way the router fault does, because the window's
        translated access now lands outside the peripheral's declared window.
        """
        case = self.ctx()["adapter"]
        record = case["record"]
        self.assertNotEqual(record["declared_window_base"], record["injected_window_base"])
        self.assertIn(f".WINDOW_BASE({record['injected_window_base']})",
                      record["line_after"])
        findings = {item["check_id"]: item for item in case["audit_findings"]}
        self.assertIn("adapter_parameters", findings)
        self.assertEqual(FAIL, findings["adapter_parameters"]["status"])
        actual = findings["adapter_parameters"]["actual"]
        self.assertEqual(record["declared_window_base"], actual[0]["expected"]["WINDOW_BASE"])
        self.assertEqual(record["injected_window_base"], actual[0]["actual"]["WINDOW_BASE"])
        self.assertEqual(ST_TRAP, case["observed"]["cpu0__status_o"])
        self.assertEqual(1, case["observed"]["cpu0__trap_o"])

    def test_site2_package_is_a_composition_defect(self) -> None:
        package = self._site_packages()["adapter:window-base"]
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        self.assertIn("adapter_parameters", reason)
        read_back, document = round_trip(package, "site2-adapter-window-base")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site2 package={document} classification={classification} "
                        f"reason={reason[:200]}")

    # ------------------------------------------------------------------
    # site 3: profile
    # ------------------------------------------------------------------

    def test_site3b_profile_declared_clear_is_a_profile_defect(self) -> None:
        """The profile fault: a clear operation the component's RTL does not implement.

        The mutated profile declares ``IRQ_STATUS`` read-write with a
        write-1-to-clear side effect and names it in the source's declared clear
        text, so the generated program performs exactly that declared operation --
        and the peripheral's condition stays asserted.  The program's own promised
        ``cause_after_clear == 0`` fails, while the same peripheral, driven by the
        program generated from the profile the RTL implements, clears it.
        """
        profile = self.ibex()["profile"]
        source = profile["source"]
        self.assertEqual("write_1_to_clear", source["clear"]["kind"])
        self.assertEqual("IRQ_STATUS", source["clear"]["register"])
        self.assertEqual(16, int(source["clear"]["offset"]))
        report = profile["report"]
        promised = profile["program"].observations["cause_after_clear"]
        baseline = self.ibex()["report"]
        self.assertEqual(0, promised)
        self.assertEqual(1, report["cause_after_clear"],
                         "the declared clear must not have cleared the RTL's latch")
        self.assertEqual(1, report["status_raw_after_clear"])
        self.assertEqual(0, baseline["cause_after_clear"])
        self.assertEqual(0, baseline["status_raw_after_clear"])
        self.assertGreater(report["handler_entries"], baseline["handler_entries"],
                           "the still-asserted source re-pends and re-enters the handler")
        # The RTL's own declaration is the other half of the binding conflict.
        rtl = (ROOT / "examples/soc_generation/rtl/novagpio.sv").read_text(encoding="utf-8")
        self.assertIn("IRQ_STAT ro", rtl)
        self.assertIn("cleared by writing DATA_IN", rtl)
        package = self._site_packages()["profile:declared-clear"]
        classification, reason = classify_boundary(package)
        self.assertEqual(PROFILE_DEFECT, classification, reason)
        self.assertIn("profile semantics", reason)
        # The package identity binds the faulty profile *transitively*, through the
        # plan hash: the mutated declaration changes the plan.  The per-component
        # ``profile_hashes`` records the elaborated binding and the component RTL
        # content, not the profile's declared register/address semantics, so those
        # two entries are unchanged -- recorded here as an identity-coverage gap,
        # not hidden.
        pristine_plan = self.ibex()["plan"]
        pristine = profile_identities(pristine_plan)["novagpio"]
        mutated = profile_identities(profile["plan"])["novagpio"]
        self.assertNotEqual(pristine_plan.plan_hash, profile["plan"].plan_hash)
        self.assertEqual(pristine["content_hash"], mutated["content_hash"],
                         "profile_hashes.content_hash covers the component RTL closure")
        self.assertEqual(pristine["binding_hashes"], mutated["binding_hashes"],
                         "profile_hashes.binding_hashes covers the elaborated binding")
        read_back, document = round_trip(package, "site3b-profile-declared-clear")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site3b package={document} classification={classification} "
                        f"cause_after_clear={report['cause_after_clear']} "
                        f"handler_entries={report['handler_entries']} "
                        f"plan_hash={package.identity['plan_hash'][:24]} "
                        f"(profile semantics bound transitively; profile_hashes "
                        f"unchanged)")

    # ------------------------------------------------------------------
    # site 4: software / stimulus program
    # ------------------------------------------------------------------

    def test_site4_software_without_the_declared_clear_step_is_a_software_defect(self) -> None:
        """The software fault: the boot program omits its declared clear step.

        The image is patched at the address of the instruction the program's own
        listing records for its declared clear.  The peripheral condition then stays
        asserted and the program's promised ``cause_after_clear`` fails -- while the
        *same compiled binary*, given the unpatched image, clears it.  The DUT is
        therefore not the suspect, and the package says so.
        """
        software = self.ibex()["software"]
        patch = software["patch"]
        clear = self.ibex()["clear"]
        program = self.ibex()["program"]
        self.assertEqual(int(clear["address"]), patch["address"])
        self.assertEqual(int(clear["word"]), patch["word_before"])
        self.assertEqual(0x00000013, patch["word_after"])
        self.assertEqual("13000000", patch["bytes_after"],
                         "the image is little-endian: the nop word's bytes in order")
        self.assertEqual("lw", str(clear["instruction"]).split()[0])
        self.assertIn("8(", str(clear["instruction"]))
        report = software["report"]
        promised = program.observations["cause_after_clear"]
        control = report_value(program, software["control"], "cause_after_clear")
        self.assertEqual(0, promised)
        self.assertEqual(1, report["cause_after_clear"],
                         "the source must stay asserted without the clear step")
        self.assertEqual(0, control,
                         "the same binary clears with the image the program generated")
        self.assertEqual(1, report["status_raw_after_clear"])
        baseline = self.ibex()["report"]
        self.assertGreater(report["handler_entries"], baseline["handler_entries"])
        package = self._site_packages()["software:missing-clear"]
        classification, reason = classify_boundary(package)
        self.assertEqual(SOFTWARE_OR_MODEL_DEFECT, classification, reason)
        self.assertIn("software/model/checker", reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)
        read_back, document = round_trip(package, "site4-software-missing-clear")
        self.assertEqual(classification, read_back.classification[0])
        self.print_note(f"site4 package={document} classification={classification} "
                        f"patched=0x{patch['address']:08x}:{patch['bytes_before']}->"
                        f"{patch['bytes_after']} cause_after_clear="
                        f"{report['cause_after_clear']} control={control} "
                        f"handler_entries={report['handler_entries']}")

    # ------------------------------------------------------------------
    # site 5: external model
    # ------------------------------------------------------------------

    def test_site5_a_legal_stimulus_is_confirmed_and_labelled_legal(self) -> None:
        """The legal control: every offered request obeys the declared contract."""
        context = self.ctx()
        plan, policy, build = context["pulse_plan"], context["pulse_policy"], \
            context["pulse_build"]
        sample = RuntimeSample(request_id=0xC0, raw=context["pulse_legal_raw"])
        result, repeat = run_twice(build, sample, label="legal pulse experiment")
        self.assertEqual("OK", result.status)
        record = legality_record(plan, policy, sample, result,
                                 interaction=LEGAL_INTERACTION, site=SITE_EXTERNAL)
        self.assertEqual([], record["driver_violations"])
        self.assertEqual([], record["structural_findings"])
        self.assertEqual(LEGALITY_CONFIRMED, record["environment_legality"])
        self.assertTrue(record["experiment"]["fault_injection"])
        self.assertFalse(record["experiment"]["environment_broken"])
        self.assertIsNone(record["experiment"]["violated_constraint"])
        waveform = record["waveforms"][PIN_MODE_PORT]
        self.assertEqual(waveform["declared_waveform"], waveform["applied"],
                         "the declared pulse strategy is what the driver really applied")
        self.assertNotEqual(waveform["requests"], waveform["applied"],
                            "a pulse stretches its request over the declared width: the "
                            "applied waveform is the contract, not the request stream")
        applied = applied_waveform(result, PIN_MODE_PORT,
                                   len(context["pulse_legal_raw"]))
        pulses = [(index + 1, applied[index]) for index in range(len(applied))
                  if applied[index] != 0 and (index == 0 or applied[index - 1] == 0)]
        self.assertEqual(2, len(pulses), f"two accepted pulses expected: {applied}")
        self.assertEqual([1, 3], [payload for _cycle, payload in pulses],
                         "both accepted requests were applied with their own payload")
        self.assertEqual(result.document(), repeat.document())
        self.print_note(f"site5 legal control: confirmed, pulses at {pulses}")

    def test_site5_an_illegal_external_stimulus_is_a_driver_violation(self) -> None:
        """The external-model fault: requests the declared timing contract forbids.

        Two deliberately illegal experiments on the same real build: a new request
        offered while a pulse is still active, and one offered before the declared
        minimum gap has elapsed.  The driver drops both (its documented behaviour),
        the monitor reports a driver violation preserving the violated constraint,
        and the experiment is labelled deliberate rather than a legal interaction.
        """
        context = self.ctx()
        plan, policy, build = context["pulse_plan"], context["pulse_policy"], \
            context["pulse_build"]
        legal_sample = RuntimeSample(request_id=0xC0, raw=context["pulse_legal_raw"])
        legal_record = legality_record(plan, policy, legal_sample,
                                       run_sample(build, legal_sample),
                                       interaction=LEGAL_INTERACTION, site=SITE_EXTERNAL)
        cases = (("illegal-active-pulse", context["pulse_illegal_active_raw"],
                  "a pulse is active", 3),
                 ("illegal-minimum-gap", context["pulse_illegal_gap_raw"],
                  "declared minimum gap not met", 7))
        for label, raw, reason, cycle in cases:
            with self.subTest(case=label):
                sample = RuntimeSample(request_id=0xC1, raw=raw)
                result, repeat = run_twice(build, sample, label=label)
                record = legality_record(plan, policy, sample, result,
                                         interaction=DELIBERATE_ILLEGAL,
                                         site=SITE_EXTERNAL, environment_broken=True)
                self.assertEqual(LEGALITY_VIOLATED, record["environment_legality"])
                self.assertEqual([], record["structural_findings"],
                                 "the declared driver really implements its strategy")
                violations = record["driver_violations"]
                self.assertEqual(1, len(violations), violations)
                violation = violations[0]
                self.assertEqual(reason, violation["reason"])
                self.assertEqual(cycle, violation["cycle"])
                self.assertEqual(PIN_MODE_PORT, violation["port"])
                self.assertEqual("drive_pulse", violation["primitive"])
                self.assertEqual("driver_violation", violation["failure_class"])
                self.assertEqual("soc_special_input_driver", violation["checker"])
                self.assertEqual({"pulse_cycles": 4, "min_gap_cycles": 8,
                                  "handshake": False},
                                 {key: violation["declared"][key] for key in
                                  ("pulse_cycles", "min_gap_cycles", "handshake")})
                experiment = record["experiment"]
                self.assertEqual(DELIBERATE_ILLEGAL, experiment["interaction"])
                self.assertTrue(experiment["fault_injection"])
                self.assertTrue(experiment["environment_broken"])
                self.assertEqual(violation, experiment["violated_constraint"],
                                 "the violated constraint is preserved with the run")
                self.assertNotEqual(legal_record["experiment"]["interaction"],
                                    experiment["interaction"],
                                    "legal and deliberately illegal experiments are "
                                    "labelled separately")
                # The same stimulus offered to a cycle_value port is legal: the
                # verdict follows the declared contract, not the monitor.
                pristine_sample = RuntimeSample(request_id=0xC2, raw=raw)
                pristine = legality_record(
                    context["novacore_plan"], context["novacore_policy"], pristine_sample,
                    run_sample(context["novacore_baseline_build"], pristine_sample),
                    interaction=LEGAL_INTERACTION, site=SITE_EXTERNAL)
                self.assertEqual([], pristine["driver_violations"],
                                 "the same requests are legal under cycle_value")
                self.assertEqual(LEGALITY_CONFIRMED, pristine["environment_legality"])
                self.assertEqual(result.document(), repeat.document())

        for label, _raw, _reason, _cycle in cases:
            package = self._site_packages()[f"external:{label}"]
            classification, reason_text = classify_boundary(package)
            self.assertEqual(DRIVER_VIOLATION, classification, reason_text)
            self.assertIn("the environment, not the DUT, broke the interface contract",
                          reason_text)
            self.assertEqual(LEGALITY_VIOLATED, package.legality["environment_legality"])
            ready, gate_reason = component_candidate_ready(package)
            self.assertFalse(ready, "an environment violation must close the component gate")
            self.assertIn("environment-legality-violated", gate_reason)
            read_back, document = round_trip(package, f"site5-external-{label}")
            self.assertEqual(classification, read_back.classification[0])
            self.assertTrue(read_back.legality["experiment"]["fault_injection"])
            self.print_note(f"site5 {label} package={document} "
                            f"classification={classification} violation="
                            f"{json.dumps(package.legality['driver_violations'][0])}")

    # ------------------------------------------------------------------
    # item 6: the positive control / component gate
    # ------------------------------------------------------------------

    def test_positive_control_the_component_gate_is_the_only_path(self) -> None:
        """What evidence a ``component_candidate`` package needs, and that the gate is it.

        No component defect is injected here: editing the DUT RTL is forbidden by
        the task, so this asserts the *gate contract* on real packages instead.  The
        gate passes on a real injected-fault package (complete identity, confirmed
        legality, a recorded criterion with an independent basis, real observations,
        a reproduced anomaly) -- and a recorded layer finding still decides the
        boundary, which is the precedence the plan requires.  The same real run with
        the layer findings withheld shows that ``component_candidate_ready`` is the
        only path to that category.
        """
        case = self.ctx()["adapter"]
        package = package_for(
            case["plan"], case["build"], case["policy"], case["sample"], case["result"],
            kind="gate_demonstration_component_candidate",
            criterion_record=criterion("adapter-window-parameters-match-the-plan",
                                       str(case["anomaly"]["statement"]),
                                       str(case["anomaly"]["basis"])),
            anomaly=case["anomaly"], legality=case["legality"], findings={},
            injection=case["record"],
            notes=["evidence-gate demonstration only: NO component defect was injected "
                   "(editing the DUT RTL is forbidden).  The injected fault is the adapter "
                   "WINDOW_BASE recorded in attribution.injection; the layer finding was "
                   "withheld from this package on purpose, to show that the gate -- and "
                   "only the gate -- opens component_candidate."])
        self.assertEqual((), missing_identity(package.identity))
        for field in REQUIRED_LEGALITY:
            with self.subTest(legality_field=field):
                self.assertIn(field, package.legality)
        self.assertEqual(LEGALITY_CONFIRMED, package.legality["environment_legality"])
        ready, reason = component_candidate_ready(package)
        self.assertTrue(ready, reason)
        self.assertEqual("", reason)
        classification, classify_reason = classify_boundary(package)
        self.assertEqual(COMPONENT_CANDIDATE, classification, classify_reason)
        self.assertIn("complete identity, confirmed environment legality", classify_reason)
        print("MYFUZZ_BOUNDARY component-candidate evidence required: "
              f"identity={list(REQUIRED_IDENTITY)} "
              f"legality={list(REQUIRED_LEGALITY)} criteria=at least one recorded "
              "criterion observations=at least one observed value "
              "anomaly=present+criterion+basis+reproducible+independent")
        # A recorded layer finding takes precedence over a passing gate.
        with_finding = package_for(
            case["plan"], case["build"], case["policy"], case["sample"], case["result"],
            kind="fault_injection_adapter_window_base",
            criterion_record=criterion("adapter-window-parameters-match-the-plan",
                                       str(case["anomaly"]["statement"]),
                                       str(case["anomaly"]["basis"])),
            anomaly=case["anomaly"], legality=case["legality"],
            findings={"composition_findings": [
                "audit adapter_parameters failed: the elaborated bridge window base is not "
                "the plan's resolved window base"]},
            injection=case["record"], notes=[])
        self.assertTrue(component_candidate_ready(with_finding)[0])
        self.assertEqual(COMPOSITION_DEFECT, classify_boundary(with_finding)[0])

    def test_positive_control_every_single_missing_prerequisite_closes_the_gate(self) -> None:
        """Branch by branch on a *real* package: one missing prerequisite is enough."""
        case = self.ctx()["adapter"]
        base = package_for(
            case["plan"], case["build"], case["policy"], case["sample"], case["result"],
            kind="gate_demonstration_component_candidate",
            criterion_record=criterion("adapter-window-parameters-match-the-plan",
                                       str(case["anomaly"]["statement"]),
                                       str(case["anomaly"]["basis"])),
            anomaly=case["anomaly"], legality=case["legality"], findings={},
            injection=case["record"], notes=[])
        self.assertTrue(component_candidate_ready(base)[0])
        variants: list[tuple[str, EvidencePackage]] = []
        for field in REQUIRED_IDENTITY:
            identity = {key: value for key, value in base.identity.items() if key != field}
            variants.append((f"identity:{field}",
                             dataclasses.replace(base, identity=identity)))
        for field in REQUIRED_LEGALITY:
            legality = {key: value for key, value in base.legality.items() if key != field}
            variants.append((f"legality:{field}",
                             dataclasses.replace(base, legality=legality)))
        variants.append(("no-criterion", dataclasses.replace(base, criteria=())))
        variants.append(("no-observation", dataclasses.replace(
            base, results=tuple(dict(item, observations={}) for item in base.results))))
        anomaly = dict(base.anomaly)
        variants.extend((
            ("no-anomaly", dataclasses.replace(base, anomaly=dict(anomaly, present=False))),
            ("anomaly-without-criterion", dataclasses.replace(
                base, anomaly=dict(anomaly, criterion=""))),
            ("anomaly-without-basis", dataclasses.replace(
                base, anomaly=dict(anomaly, basis=""))),
            ("anomaly-not-reproduced", dataclasses.replace(
                base, anomaly=dict(anomaly, reproducible=False))),
            ("anomaly-basis-not-independent", dataclasses.replace(
                base, anomaly=dict(anomaly, basis_independent=False))),
            ("legality-unavailable", dataclasses.replace(
                base, legality=dict(base.legality, environment_legality="unavailable"))),
            ("legality-violated", dataclasses.replace(
                base, legality=dict(base.legality, environment_legality=LEGALITY_VIOLATED,
                                    driver_violations=["injected for the gate branch"]))),
            ("identity-conflict", dataclasses.replace(
                base, identity=dict(base.identity, layout_hash="9" * 64))),
        ))
        for label, variant in variants:
            with self.subTest(missing=label):
                ready, reason = component_candidate_ready(variant)
                self.assertFalse(ready, f"{label} still passed the gate")
                self.assertTrue(reason)
                classification, _ = classify_boundary(variant)
                self.assertNotEqual(COMPONENT_CANDIDATE, classification,
                                    f"{label} was classified as a component defect")
        self.print_note(f"component gate: {len(variants)} single-prerequisite variants all "
                        f"closed the gate on a real package")

    def test_positive_control_a_clean_run_never_becomes_a_component_candidate(self) -> None:
        """A clean run is not an anomaly: it can never pass the gate."""
        context = self.ctx()
        sample = context["novacore_baseline_sample"]
        result = context["novacore_baseline_result"]
        legality = legality_record(context["novacore_plan"], context["novacore_policy"],
                                   sample, result, interaction=LEGAL_INTERACTION,
                                   site="clean_baseline")
        package = build_evidence_package(
            context["novacore_plan"], context["novacore_baseline_build"],
            context["novacore_policy"], [result], kind="clean_baseline_run",
            samples=[sample],
            criteria=[criterion("clean-run-matches-the-declared-artifact-contract",
                                "the composed CPU holds ST_POLL with no trap, as the clean "
                                "build of this plan does",
                                "the plan's declared decode windows and the novacore state "
                                "machine read independently of any injected artifact")],
            legality=legality, anomaly=None,
            notes=["no anomaly: nothing was injected and the run matches the baseline"])
        ready, reason = component_candidate_ready(package)
        self.assertFalse(ready)
        self.assertEqual("no-anomaly-recorded", reason)
        classification, classify_reason = classify_boundary(package)
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("no-anomaly-recorded", classify_reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)

    def test_no_injected_fault_is_ever_a_component_candidate(self) -> None:
        """The programme's item 7: five layers, five attributions, never the component."""
        expected = {
            "generator:source-vector": COMPOSITION_DEFECT,
            "generator:router-window": COMPOSITION_DEFECT,
            "generator:driver-dropped": COMPOSITION_DEFECT,
            "adapter:window-base": COMPOSITION_DEFECT,
            "profile:declared-clear": PROFILE_DEFECT,
            "software:missing-clear": SOFTWARE_OR_MODEL_DEFECT,
            "external:illegal-active-pulse": DRIVER_VIOLATION,
            "external:illegal-minimum-gap": DRIVER_VIOLATION,
        }
        table = self._site_packages()
        self.assertEqual(set(expected), set(table))
        for label, package in sorted(table.items()):
            with self.subTest(site=label):
                classification, reason = classify_boundary(package)
                self.assertEqual(expected[label], classification, reason)
                self.assertNotEqual(COMPONENT_CANDIDATE, classification)
                self.assertTrue(reason)
                self.assertEqual((), missing_identity(package.identity),
                                 "every injected-fault package carries complete identity")
                for field in REQUIRED_LEGALITY:
                    self.assertIn(field, package.legality)
                self.assertTrue(package.criteria)
                self.assertTrue(package.anomaly.get("present"))
                self.assertTrue(package.anomaly.get("reproducible"))
                self.assertTrue(package.anomaly.get("basis_independent"))
                if classification == DRIVER_VIOLATION:
                    ready, gate_reason = component_candidate_ready(package)
                    self.assertFalse(ready)
                    self.assertIn("environment-legality-violated", gate_reason)
        print("MYFUZZ_BOUNDARY matrix: "
              + "; ".join(f"{label}={classify_boundary(package)[0]}"
                          for label, package in sorted(table.items())))

    # ------------------------------------------------------------------
    # item 7: cross-build reproduction
    # ------------------------------------------------------------------

    def test_cross_build_the_divergence_reproduces_in_a_new_directory(self) -> None:
        """A rebuilt composition reproduces its identity, its divergence and its class.

        The plan/layout/top/testbench/build identity of the rebuild is byte-identical
        to the packaged one, and re-running the package's saved raw input on the
        rebuilt binary reproduces the recorded run exactly.  A *recompiled* binary in
        a new directory is refused by ``replay_package`` because the compiled
        executable's content hash is part of the package identity and Verilator
        embeds its build path; that refusal is asserted (the check was not weakened)
        and pinned to the binary content, because the *identical* artifact copied
        into a new directory replays with agreement.
        """
        case = self.ctx()["adapter"]
        package = self._site_packages()["adapter:window-base"]
        directory = EVIDENCE_ROOT / "cross-build-source"
        shutil.rmtree(directory, ignore_errors=True)
        write_evidence_package(package, directory)
        read_back = read_evidence_package(directory)

        # 1. the identical artifact in a new directory replays and agrees.
        copy = CACHE_ROOT / "build-cross-copy"
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(case["build"].output_dir, copy)
        copied = _runtime_from_document(
            dict(case["build"].document(), output_dir=copy.as_posix()),
            case["build"].boot_image,
            executable_path=copy / "obj_dir" / case["build"].executable.name)
        self.assertEqual(_sha256_file(case["build"].executable),
                         _sha256_file(copied.executable))
        replay_copy = replay_package(read_back, copied)
        self.assertEqual(REPLAY_AGREEMENT, replay_copy.status, replay_copy.reason)
        self.assertTrue(replay_copy.agreed)
        self.assertEqual(int(case["observed"]["cpu0__trap_o"]),
                         int(replay_copy.reruns[0]["observations"]["cpu0__trap_o"]))
        shutil.rmtree(copy, ignore_errors=True)

        # 2. a real rebuild of the same composition into a new directory: the
        #    composition identity is identical, the compiled binary is not.
        rebuild = build_runtime(case["plan"], "cross-build-rebuild",
                                top_text=case["top_text"], rebuild=True)
        saved = read_back.identity
        recorded = recorded_build_identity(rebuild)
        self.assertEqual(saved["plan_hash"], recorded["plan_hash"])
        self.assertEqual(saved["layout_hash"], recorded["layout_hash"])
        self.assertEqual(saved["rendered_top_hash"], _sha256_file(rebuild.top_path))
        self.assertEqual(saved["testbench_hash"], _sha256_file(rebuild.testbench_path))
        self.assertEqual(saved["build_hash"], rebuild.build_hash)
        self.assertNotEqual(saved["runtime"]["executable_hash"],
                            _sha256_file(rebuild.executable))
        refused = replay_package(read_back, rebuild)
        self.assertEqual(REPLAY_REFUSED, refused.status)
        self.assertIn("runtime.executable_hash", refused.reason)
        self.print_note(f"cross-build refusal (recompiled binary): {refused.reason[:220]}")

        # 3. the saved input re-runs on the rebuilt binary and diverges identically.
        rerun, rerun_repeat = run_twice(rebuild, read_back.sample(),
                                        label="cross-build rerun")
        self.assertEqual(case["result"].document(), rerun.document(),
                         "the rebuilt composition reproduces the recorded run exactly")
        rebuilt_package = package_for(
            case["plan"], rebuild, case["policy"], read_back.sample(), rerun,
            kind="fault_injection_adapter_window_base",
            criterion_record=criterion("adapter-window-parameters-match-the-plan",
                                       str(case["anomaly"]["statement"]),
                                       str(case["anomaly"]["basis"])),
            anomaly=case["anomaly"], legality=case["legality"],
            findings={"composition_findings": [
                "audit adapter_parameters failed: the elaborated bridge window base is not "
                "the plan's resolved window base"]},
            injection=case["record"], notes=["rebuilt into a new directory"])
        self.assertEqual(classify_boundary(read_back)[0],
                         classify_boundary(rebuilt_package)[0])
        self.assertEqual(COMPOSITION_DEFECT, classify_boundary(rebuilt_package)[0])
        self.print_note("cross-build: identical plan/layout/top/testbench/build hashes, "
                        "distinct executable; rerun observations identical; "
                        f"classification {classify_boundary(rebuilt_package)[0]}")

    def test_cross_build_a_package_from_a_different_plan_is_refused(self) -> None:
        """A plan hash that is not the package's is refused, never reinterpreted."""
        context = self.ctx()
        package = self._site_packages()["adapter:window-base"]
        other_plan = novacore_plan_without_uart1(context["novacore_plan"])
        self.assertNotEqual(context["novacore_plan"].plan_hash, other_plan.plan_hash)
        # The *raw layout* is the declared special inputs, which uart1 does not
        # contribute to: dropping it changes the plan, not the raw layout.  The
        # refusal therefore has to be decided by the plan hash, which it names.
        self.assertEqual(str(context["novacore_plan"].raw_layout["layout_hash"]),
                         str(other_plan.raw_layout["layout_hash"]))
        other_build = build_runtime(other_plan, "cross-build-other-plan")
        refused = replay_package(package, other_build)
        self.assertEqual(REPLAY_REFUSED, refused.status)
        self.assertIn("plan_hash", refused.reason)
        self.assertIn(other_plan.plan_hash, refused.reason)
        self.assertIsNone(refused.divergence)
        self.assertFalse(refused.reruns)
        self.assertEqual(COMPOSITION_DEFECT, classify_boundary(package)[0])
        self.print_note(f"different-plan refusal: {refused.reason[:240]}")

    # ------------------------------------------------------------------
    # item 8: minimisation of an injected fault
    # ------------------------------------------------------------------

    def test_minimisation_records_the_witness_and_the_stop_reason(self) -> None:
        """``minimize_sample`` on the injected external-model fault.

        The predicate is the injected fault's own nature: the declared drive
        contract is violated in a way the declared driver explains (a dropped
        request) with no structural finding.  The stop reason and the witness are
        asserted, and the witness is re-run for real.
        """
        context = self.ctx()
        plan, policy, build = context["pulse_plan"], context["pulse_policy"], \
            context["pulse_build"]
        raw = tuple(list(context["pulse_illegal_gap_raw"]) + [0] * 32)
        sample = RuntimeSample(request_id=0xC3, raw=raw)

        def predicate(result) -> bool:
            reconstructed = RuntimeSample(
                request_id=result.request_id,
                raw=tuple(int(item["raw"]) for item in result.trace),
                events=sample.events)
            record = drive_legality_record(plan, policy, reconstructed, result)
            return bool(record["violations"]) and not record["structural"]

        self.assertTrue(predicate(run_sample(build, sample)),
                        "the predicate must hold on the original sample")
        minimal, log = minimize_sample(build, sample, predicate=predicate)
        self.assertNotEqual(sample, minimal)
        self.assertLess(len(minimal.raw), len(sample.raw))
        self.assertEqual("fixed_point", log["stopped"])
        self.assertTrue(log["preserved"])
        self.assertEqual(len(sample.raw), log["original"]["words"])
        self.assertEqual(len(minimal.raw), log["minimal"]["words"])
        self.assertGreater(log["removed_words"], 0)
        self.assertGreaterEqual(log["candidates"], 1)
        witness = run_sample(build, minimal)
        self.assertTrue(predicate(witness), "the witness must still reproduce the fault")
        record = drive_legality_record(plan, policy, minimal, witness)
        self.assertTrue(record["violations"])
        self.assertEqual([], record["structural"])
        print(f"MYFUZZ_BOUNDARY minimisation: stopped={log['stopped']} "
              f"preserved={log['preserved']} original_words={len(sample.raw)} "
              f"minimal_words={len(minimal.raw)} removed={log['removed_words']} "
              f"witness={list(minimal.raw)} "
              f"violation={json.dumps(record['violations'][0])}")
        # The budget stop reason is recorded as well, on the same injected fault.
        budget_minimal, budget_log = minimize_sample(build, sample, predicate=predicate,
                                                     budget=1)
        self.assertEqual("budget", budget_log["stopped"])
        self.assertEqual(1, budget_log["candidates"])
        self.assertTrue(budget_log["preserved"])
        self.print_note(f"minimisation budget stop: stopped={budget_log['stopped']} "
                        f"candidates={budget_log['candidates']} "
                        f"words={len(budget_minimal.raw)}")


if __name__ == "__main__":
    unittest.main()
