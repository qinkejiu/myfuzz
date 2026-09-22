"""Item 5: interrupt trigger support, the edge converter, and its refusals.

The controller samples its input every clock, so the composer's trigger support
is a statement about *what a source's output means*:

* ``level`` is sampled directly and follows its input;
* ``pulse`` is a bounded same-domain pulse of at least one clock, which that
  sampling captures, and its declared ``pulse_width_cycles`` is the contract
  that makes the capture correct;
* ``rising_edge`` / ``falling_edge`` / ``both_edges`` describe a source that
  *holds* an edge-shaped condition, so ``soc_irq_edge_detect`` is inserted and
  the plan records exactly which converter parameters were rendered;
* anything else is refused by name, and a cross-domain source is refused
  whatever its trigger says.

This module checks the plan, the rendered top, the published source closure and
the independent audit for the accepted cases, and the exact error string for
every refused case.  The converter's own behaviour is verified separately in
``tests/protocols/test_soc_irq_edge_detect_rtl.py``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    load_component_profile,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_interrupt_plan import (
    CPU_IRQ_SEMANTICS_REFUSED,
    CPU_IRQ_SEMANTICS_SUPPORTED,
    EDGE_DETECT_MODULE,
    EDGE_DETECT_RTL_SOURCE,
    InterruptPlanError,
    build_interrupt_plan,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import FAIL, PASS, audit_structure

from .soc_generation_fixture import EXAMPLE, ROOT, example_profiles, tools_available
from .test_soc_interrupt_plan import _PlanFixture


GPIO_PROFILE = EXAMPLE / "profiles" / "novagpio.json"
REQUEST = EXAMPLE / "request.json"
#: Scratch profiles and rendered tops live under the workspace so the renderer's
#: relative source paths keep working; nothing here is a checked-in input.
SCRATCH = ROOT / "runs" / "irq-trigger-tests"


def _patched_gpio_profile(name: str, **changes) -> str:
    """Write a copy of the novagpio profile with its source declaration changed.

    ``name`` names the copy so each variant gets its own file.  The returned
    path is relative to the repository root, which is what a composition
    request stores.
    """
    document = json.loads(GPIO_PROFILE.read_text(encoding="utf-8"))
    sources = document.get("interrupts")
    if not isinstance(sources, list) or not sources:
        raise AssertionError("the novagpio example profile declares no interrupt source")
    for key, value in changes.items():
        if value is None:
            sources[0].pop(key, None)
        else:
            sources[0][key] = value
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path.relative_to(ROOT))


def _patched_request(name: str, **changes) -> dict:
    """The example request narrowed to cpu0 plus the trigger under test.

    The other peripherals are dropped so the rendered controller has exactly one
    source: that makes the source vector, the converter's position in it and the
    audit's expectations readable in the test rather than incidental.
    """
    document = json.loads(REQUEST.read_text(encoding="utf-8"))
    profile = _patched_gpio_profile(name, **changes)
    kept = []
    for item in document["peripherals"]:
        if item["instance_id"] == "gpio0":
            item["profile"] = profile
            kept.append(item)
    if not kept:
        raise AssertionError("the example request has no gpio0 peripheral")
    document["peripherals"] = kept
    document["request_id"] = f"irq-trigger-{name}"
    return document


def _composition(name: str, **changes):
    """One real composition whose gpio0 source carries the requested trigger."""
    from myfuzz.composition.component_profile import load_composition_request

    document = _patched_request(name, **changes)
    profiles = example_profiles()
    # The patched profile is a new file, so it has to be registered under the
    # reference the request now uses; the request loader never reads from disk.
    reference = next(item["profile"] for item in document["peripherals"]
                     if item["instance_id"] == "gpio0")
    profiles[reference] = load_component_profile(ROOT / reference)
    request = load_composition_request(document, profiles=profiles)
    return build_composition(request, base_dir=ROOT)


def _source(plan, instance_id: str = "gpio0") -> dict:
    for item in plan.interrupt_document["sources"]:
        if item["instance_id"] == instance_id:
            return item
    raise AssertionError(f"the plan has no interrupt source for {instance_id}")


def _audit(plan, top_text: str) -> dict:
    records = source_list(plan)
    return audit_structure(
        plan, top_text=top_text,
        source_files=[item["path"] for item in records if item["role"] != "include_root"],
        base_dir=ROOT,
        include_roots=sorted({item["path"] for item in records
                              if item["role"] == "include_root"}))


def _finding(audit: dict, check_id: str) -> dict:
    for item in audit["findings"]:
        if item["check_id"] == check_id:
            return item
    raise AssertionError(f"the audit has no {check_id!r} finding: "
                         f"{[item['check_id'] for item in audit['findings']]}")


class DirectTriggerTests(unittest.TestCase):
    """``level`` and ``pulse`` are wired straight into the controller."""

    def test_a_level_source_needs_no_converter(self) -> None:
        plan = _composition("level")
        source = _source(plan)
        self.assertEqual("level", source["trigger"])
        self.assertEqual({"kind": "direct", "capture": "controller-follows-level",
                          "pending": "follows-input-level",
                          "declared_idle_level": 0}, source["normalizer"])
        self.assertEqual(0, plan.interrupt_document["controller"]["latch_mask"],
                         "a level-only plan must render LATCH_MASK=0")
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        # The rendered comment block names the converter module, so the check is
        # on a real instantiation and on the converter nets, not on the word.
        self.assertNotIn(f"{EDGE_DETECT_MODULE} #(", top)
        self.assertNotIn("irq_src_", top)
        self.assertNotIn(EDGE_DETECT_RTL_SOURCE,
                         [item["path"] for item in source_list(plan)])

    def test_a_pulse_source_is_direct_and_records_its_capture_contract(self) -> None:
        plan = _composition("pulse", trigger="pulse", pulse_width_cycles=2)
        source = _source(plan)
        self.assertEqual("pulse", source["trigger"])
        self.assertEqual("direct", source["normalizer"]["kind"])
        self.assertEqual(2, source["normalizer"]["pulse_width_cycles"])
        self.assertEqual("controller-latches-every-high", source["normalizer"]["capture"])
        # A bounded pulse is a moment, not a state: the controller must latch it
        # or the event is gone before the CPU can claim it.
        self.assertEqual("latched-until-claim", source["normalizer"]["pending"])
        self.assertEqual(1, plan.interrupt_document["controller"]["latch_mask"])
        self.assertEqual("1'b1", plan.interrupt_document["controller"]["latch_mask_literal"])
        self.assertEqual([1], plan.interrupt_document["controller"]["latched_source_ids"])
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertNotIn(f"{EDGE_DETECT_MODULE} #(", top)
        self.assertNotIn("irq_src_", top)
        support = plan.interrupt_document["trigger_support"]
        self.assertEqual(["pulse"], support["direct"])
        self.assertEqual([], support["edge_detected"])
        self.assertNotIn("pulse", support["edge_detected"])


class EdgeTriggerTests(unittest.TestCase):
    """Each edge trigger renders a converter the audit re-reads."""

    CASES = (
        ("rising_edge", 0, "edge-rising"),
        ("falling_edge", 1, "edge-falling"),
        ("both_edges", 2, "edge-both"),
    )

    def test_each_edge_trigger_renders_its_planned_converter(self) -> None:
        for trigger, edge_parameter, name in self.CASES:
            with self.subTest(trigger=trigger):
                plan = _composition(name, trigger=trigger)
                source = _source(plan)
                self.assertEqual(trigger, source["trigger"])
                normalizer = source["normalizer"]
                self.assertEqual("edge_detect", normalizer["kind"])
                self.assertEqual(EDGE_DETECT_MODULE, normalizer["module"])
                self.assertEqual(edge_parameter, normalizer["edge_parameter"])
                self.assertEqual(1, normalizer["pulse_cycles"])
                self.assertEqual(0, normalizer["reset_level"])
                self.assertEqual("latched-until-claim", normalizer["pending"])
                top = render_composition(plan)["myfuzz_soc_top.sv"]
                self.assertIn(f"{EDGE_DETECT_MODULE} #(", top)
                self.assertIn(f".EDGE({edge_parameter}), .PULSE_CYCLES(1), "
                              f".RESET_LEVEL(0)) u_irq_src_1", top)
                self.assertIn(".raw_i(gpio0__irq_o), .irq_o(irq_src_1)", top)
                self.assertIn(".source_i(irq_src_1)", top)
                self.assertIn(".LATCH_MASK(1'b1)) u_irq_controller", top)
                controller = plan.interrupt_document["controller"]
                self.assertEqual(1, controller["latch_mask"])
                self.assertEqual([1], controller["latched_source_ids"])
                published = [item["path"] for item in source_list(plan)]
                self.assertIn(EDGE_DETECT_RTL_SOURCE, published)
                support = plan.interrupt_document["trigger_support"]
                self.assertEqual([trigger], support["edge_detected"])
                self.assertEqual(1, len(support["instances"]))
                self.assertEqual(1, support["instances"][0]["source_id"])

    def test_the_declared_detect_pulse_width_reaches_the_rendered_parameter(self) -> None:
        plan = _composition("edge-wide", trigger="rising_edge", detect_pulse_cycles=4)
        self.assertEqual(4, _source(plan)["normalizer"]["pulse_cycles"])
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn(".EDGE(0), .PULSE_CYCLES(4), .RESET_LEVEL(0)", top)

    def test_the_audit_passes_the_converter_check_on_the_pristine_top(self) -> None:
        if not tools_available():  # pragma: no cover - guarded by skipUnless
            self.skipTest("verilator is required for the independent audit")
        plan = _composition("edge-audited", trigger="rising_edge")
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        audit = _audit(plan, top)
        finding = _finding(audit, "interrupt_normalizers")
        self.assertEqual(PASS, finding["status"], finding)
        self.assertEqual(PASS, audit["summary"]["status"], audit["summary"])
        mmio = _finding(audit, "controller_mmio")
        self.assertEqual(PASS, mmio["status"], mmio)
        self.assertEqual(1, mmio["expected"]["LATCH_MASK"])
        self.assertEqual(1, mmio["actual"]["LATCH_MASK"])

    def test_the_audit_fails_when_the_converter_parameter_is_wrong(self) -> None:
        """The audit check is only evidence if it can fail.

        The rendered ``EDGE`` parameter is changed from rising to falling while
        the plan still says rising, exactly the generator mutation the brief
        names.  Everything else - the instance, its input net and its output net
        - is untouched, so a passing audit here would mean the check reads
        nothing.
        """
        if not tools_available():  # pragma: no cover - guarded by skipUnless
            self.skipTest("verilator is required for the independent audit")
        plan = _composition("edge-mutated", trigger="rising_edge")
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn(".EDGE(0)", top)
        mutated = top.replace(".EDGE(0), .PULSE_CYCLES(1), .RESET_LEVEL(0)",
                              ".EDGE(1), .PULSE_CYCLES(1), .RESET_LEVEL(0)", 1)
        self.assertNotEqual(top, mutated)
        audit = _audit(plan, mutated)
        finding = _finding(audit, "interrupt_normalizers")
        self.assertEqual(FAIL, finding["status"], finding)
        self.assertEqual(FAIL, audit["summary"]["status"], audit["summary"])

    def test_the_audit_fails_when_the_latch_mask_is_wrong(self) -> None:
        """A converted source rendered without its latch must not pass.

        This is the exact defect the real edge lifecycle run found: the
        converter emitted a pulse into a level-following pending bit, so the
        event was dropped.  Flipping only the rendered mask reproduces it, and
        the audit has to say so.
        """
        if not tools_available():  # pragma: no cover - guarded by skipUnless
            self.skipTest("verilator is required for the independent audit")
        plan = _composition("edge-latch-mutated", trigger="rising_edge")
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn(".LATCH_MASK(1'b1)) u_irq_controller", top)
        mutated = top.replace(".LATCH_MASK(1'b1)) u_irq_controller",
                              ".LATCH_MASK(1'b0)) u_irq_controller", 1)
        self.assertNotEqual(top, mutated)
        audit = _audit(plan, mutated)
        self.assertEqual(FAIL, _finding(audit, "controller_mmio")["status"])
        self.assertEqual(FAIL, audit["summary"]["status"], audit["summary"])

    def test_the_audit_fails_when_the_converter_output_is_unwired(self) -> None:
        """A converter that is instantiated but bypassed must not pass.

        The controller is re-fed the raw source net instead of the converter's
        output, which is the subtlest way to "support" an edge source while not
        actually converting anything.
        """
        if not tools_available():  # pragma: no cover - guarded by skipUnless
            self.skipTest("verilator is required for the independent audit")
        plan = _composition("edge-bypassed", trigger="rising_edge")
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn(".source_i(irq_src_1)", top)
        mutated = top.replace(".source_i(irq_src_1)", ".source_i(gpio0__irq_o)", 1)
        self.assertNotEqual(top, mutated)
        audit = _audit(plan, mutated)
        self.assertEqual(FAIL, _finding(audit, "interrupt_normalizers")["status"])
        self.assertEqual(FAIL, _finding(audit, "interrupt_paths")["status"])


class TriggerRefusalTests(unittest.TestCase):
    """Every unsupported trigger is refused by name at profile load or plan time."""

    def test_a_pulse_source_must_declare_its_width(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(ROOT / _patched_gpio_profile("pulse-no-width",
                                                               trigger="pulse"))
        self.assertIn("interrupt-pulse-width-required", str(error.exception))

    def test_a_pulse_width_on_a_non_pulse_trigger_is_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(
                ROOT / _patched_gpio_profile("level-with-width", trigger="level",
                                             pulse_width_cycles=2))
        self.assertIn("interrupt-pulse-width-only-for-pulse-trigger:level",
                      str(error.exception))

    def test_a_detect_width_on_a_non_edge_trigger_is_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(
                ROOT / _patched_gpio_profile("level-with-detect", trigger="level",
                                             detect_pulse_cycles=2))
        self.assertIn("interrupt-detect-pulse-width-only-for-edge-trigger:level",
                      str(error.exception))

    def test_a_zero_pulse_width_is_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(
                ROOT / _patched_gpio_profile("pulse-zero", trigger="pulse",
                                             pulse_width_cycles=0))
        self.assertIn("invalid-interrupt-pulse-width", str(error.exception))

    def test_an_unknown_trigger_is_refused(self) -> None:
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(
                ROOT / _patched_gpio_profile("bogus", trigger="level_or_edge"))
        self.assertIn("unsupported-interrupt-trigger:level_or_edge", str(error.exception))


class CrossDomainRefusalTests(unittest.TestCase):
    """The converter is synchronous, so a cross-domain source stays refused."""

    def test_a_cross_domain_source_is_refused_for_every_trigger(self) -> None:
        fixture = _PlanFixture()
        for trigger, extra in (("level", {}), ("pulse", {"pulse_width_cycles": 1}),
                               ("rising_edge", {}), ("falling_edge", {}),
                               ("both_edges", {})):
            with self.subTest(trigger=trigger):
                sources = []
                for request, profile_source in fixture.sources():
                    if request.instance_id == "gpio0":
                        profile_source = replace(profile_source, clock_domain="other",
                                                 trigger=trigger, **extra)
                    sources.append((request, profile_source))
                with self.assertRaises(InterruptPlanError) as error:
                    fixture.build(sources)
                self.assertIn("cross-domain-interrupt-source:gpio0:other",
                              str(error.exception))

    def test_the_plan_records_cross_domain_as_refused(self) -> None:
        plan = _composition("edge-plan-doc", trigger="rising_edge")
        self.assertEqual("refused; the detector is synchronous and same-domain only",
                         plan.interrupt_document["trigger_support"]["cross_domain"])


class CpuEntryTests(unittest.TestCase):
    """CPU interrupt entry semantics: one accepted kind, every other refused."""

    def test_machine_external_is_the_supported_semantics(self) -> None:
        self.assertEqual(("machine_external",), CPU_IRQ_SEMANTICS_SUPPORTED)
        plan = _composition("entry-supported")
        entry = plan.interrupt_document["cpu_entry"]
        self.assertEqual("machine_external", entry["semantics"])
        support = plan.interrupt_document["cpu_entry_support"]
        self.assertEqual(["machine_external"], support["supported"])

    def test_every_other_declared_semantics_is_refused_with_its_reason(self) -> None:
        fixture = _PlanFixture()
        for semantics, reason in sorted(CPU_IRQ_SEMANTICS_REFUSED.items()):
            with self.subTest(semantics=semantics):
                cpu = replace(fixture.cpu_profile,
                              cpu=replace(fixture.cpu_profile.cpu, irq_semantics=semantics))
                with self.assertRaises(InterruptPlanError) as error:
                    fixture.build(cpu_profile=cpu)
                self.assertEqual(f"unsupported-cpu-interrupt-semantics:{semantics}:{reason}",
                                 str(error.exception))

    def test_an_unknown_semantics_is_refused_and_lists_what_is_supported(self) -> None:
        fixture = _PlanFixture()
        cpu = replace(fixture.cpu_profile,
                      cpu=replace(fixture.cpu_profile.cpu, irq_semantics="hypervisor"))
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build(cpu_profile=cpu)
        self.assertEqual("unsupported-cpu-interrupt-semantics:hypervisor:unknown-semantics:"
                         "supported=machine_external", str(error.exception))

    def test_a_cpu_without_an_interrupt_entry_is_still_refused(self) -> None:
        fixture = _PlanFixture()
        cpu = replace(fixture.cpu_profile, cpu=None)
        with self.assertRaises(InterruptPlanError) as error:
            fixture.build(cpu_profile=cpu)
        self.assertIn("cpu-contract-missing", str(error.exception))


class MultiSourceTriggerTests(unittest.TestCase):
    """A plan can mix direct and converted sources in one controller."""

    def test_a_level_and_an_edge_source_share_one_controller(self) -> None:
        from myfuzz.composition.soc_interrupt_plan import interrupt_plan_document

        fixture = _PlanFixture()
        sources = []
        for request, profile_source in fixture.sources():
            if request.instance_id == "gpio0":
                profile_source = replace(profile_source, trigger="rising_edge")
            sources.append((request, profile_source))
        plan = fixture.build(sources)
        recorded = interrupt_plan_document(plan, window_base=0x40000000)
        support = recorded["trigger_support"]
        self.assertEqual(["level"], support["direct"])
        self.assertEqual(["rising_edge"], support["edge_detected"])
        # Numbering is by stable instance id, so gpio0 (source 1) and uart0
        # (source 2) keep the order the plan documents; the converter instances
        # are listed by the same numbering.
        self.assertEqual([1], [item["source_id"] for item in support["instances"]])
        self.assertEqual({1: "gpio0", 2: "uart0"},
                         {int(item["source_id"]): str(item["instance_id"])
                          for item in recorded["sources"]})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
