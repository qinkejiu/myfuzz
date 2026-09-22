"""Real two-source latch fault is a composition failure, not a GPIO bug."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile, load_composition_request
from myfuzz.composition.soc_boot_program import ProgramRequest, build_boot_program
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_defect_confirmation import confirm_component_defect
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_failure_evidence import (
    COMPOSITION_DEFECT, build_evidence_package,
    classify_boundary, replay_package,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import audit_structure
from myfuzz.composition.soc_runtime import ExternalEvent, RuntimeSample, build_profile_runtime, run_sample

from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_irq_edge_lifecycle import read32
from tests.integration.test_soc_dependency_replay import applied_legality


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for real multi-source latch fault")
class MultiSourceLatchFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tool = shutil.which("verilator")
        if tool is None:
            raise AssertionError("Verilator is required")
        cls._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-multi-latch-")
        root = Path(cls._temporary.name)
        edge = json.loads((ROOT / "examples/soc_generation/profiles/novagpio.json")
                          .read_text(encoding="utf-8"))
        edge["interrupts"][0]["trigger"] = "rising_edge"
        edge_path = root / "novagpio-edge.json"
        edge_path.write_text(json.dumps(edge), encoding="utf-8")
        request_doc = json.loads((ROOT / "examples/soc_generation/request-ibex.json")
                                 .read_text(encoding="utf-8"))
        request_doc["request_id"] = "ibex-multi-source-latch-fault"
        request_doc["peripherals"] = [
            {"instance_id": "edge0", "profile": edge_path.as_posix(), "parameters": {}},
            {"instance_id": "level0",
             "profile": "examples/soc_generation/profiles/novagpio.json", "parameters": {}},
        ]
        profiles = {}
        for reference in ("configs/cpus/ibex/component_profile.json",
                          edge_path.as_posix(),
                          "examples/soc_generation/profiles/novagpio.json"):
            profile = load_component_profile(Path(reference) if Path(reference).is_absolute()
                                             else ROOT / reference)
            profiles[reference] = profile
            profiles.setdefault(profile.component_id, profile)
        request = load_composition_request(request_doc, profiles=profiles)
        cls.plan = build_composition(request, base_dir=ROOT)
        cls.program = build_boot_program(cls.plan,
                                         request=ProgramRequest(exercise_all_sources=True))
        cls.layout = {str(item["name"]): int(item["offset"])
                      for item in cls.program.document["report"]["layout"]}
        top = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        match = re.search(r"\.LATCH_MASK\((\d+)'b([01]+)\)", top)
        if match is None:
            raise AssertionError("generated top lacks LATCH_MASK")
        cls.edge_id = next(int(item["source_id"])
                           for item in cls.plan.interrupt_document["sources"]
                           if item["instance_id"] == "edge0")
        cls.level_id = next(int(item["source_id"])
                            for item in cls.plan.interrupt_document["sources"]
                            if item["instance_id"] == "level0")
        mask = int(match.group(2), 2)
        bit = 1 << (cls.edge_id - 1)
        if not mask & bit or mask & (1 << (cls.level_id - 1)):
            raise AssertionError(f"unexpected latch mask {mask:b}")
        mutated = top[:match.start()] + f".LATCH_MASK({match.group(1)}'b{mask & ~bit:0{int(match.group(1))}b})" + top[match.end():]
        source_match = re.search(r"\.source_i\(\{([^,{}]+), ([^,{}]+)\}\)", top)
        if source_match is None:
            raise AssertionError("generated top lacks two-source controller vector")
        swapped = (top[:source_match.start()] +
                   f".source_i({{{source_match.group(2)}, {source_match.group(1)}}})" +
                   top[source_match.end():])
        cls.top_hashes = {name: "sha256:" + hashlib.sha256(value.encode()).hexdigest()
                          for name, value in (("baseline", top),
                                              ("missing_edge_latch", mutated),
                                              ("swapped_source_ids", swapped))}
        image = root / "boot.hex"
        image.write_text("".join(f"{value:02x}\n" for value in cls.program.image),
                         encoding="utf-8")
        source_records = source_list(cls.plan)
        sources = [item["path"] for item in source_records if item["role"] != "include_root"]
        cls.sources = sources
        cls.include_roots = [item["path"] for item in source_records
                             if item["role"] == "include_root"]
        flags = [f"-I{ROOT / item['path']}" for item in source_records
                 if item["role"] == "include_root"]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        wrapper = root / "verilator-with-profile-flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" %
                           (tool, " ".join(flags)), encoding="utf-8")
        wrapper.chmod(0o755)
        cls.builds = {
            name: build_profile_runtime(
                cls.plan, output_dir=root / name, base_dir=ROOT,
                top_text=value, sources=sources, boot_image=image,
                verilator=wrapper.as_posix(), timeout_seconds=1800)
            for name, value in (("baseline", top),
                                ("missing_edge_latch", mutated),
                                ("swapped_source_ids", swapped))}
        trigger = cls.program.document["trigger"]
        sample = RuntimeSample(
            request_id=13, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]))
        cls.sample = sample
        cls.results = {name: run_sample(build, sample, timeout_seconds=1800)
                       for name, build in cls.builds.items()}

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def report(self, label: str, field: str) -> int:
        return read32(self.results[label],
                      self.program.report_address + self.layout[field])

    def test_baseline_closes_both_sources(self) -> None:
        self.assertEqual("OK", self.results["baseline"].status)
        self.assertEqual(2, self.report("baseline", "interrupt_completions"))
        self.assertEqual(1, self.report("baseline", "all_sources_closed"))

    def test_missing_one_latch_drops_only_that_source(self) -> None:
        self.assertNotEqual(self.top_hashes["baseline"],
                            self.top_hashes["missing_edge_latch"])
        self.assertEqual("OK", self.results["missing_edge_latch"].status)
        self.assertEqual(1, self.report("missing_edge_latch", "interrupt_completions"))
        self.assertEqual(0, self.report("missing_edge_latch", "all_sources_closed"))
        pending = self.report("missing_edge_latch", "pending_word_0_before_claim")
        self.assertEqual(0, pending & (1 << self.edge_id))
        self.assertNotEqual(0, pending & (1 << self.level_id))

    def test_swapped_source_ids_do_not_close_the_declared_loop(self) -> None:
        self.assertNotEqual(self.top_hashes["baseline"],
                            self.top_hashes["swapped_source_ids"])
        self.assertEqual("OK", self.results["swapped_source_ids"].status)
        audit = audit_structure(
            self.plan,
            top_text=self.builds["swapped_source_ids"].top_path.read_text(),
            source_files=self.sources, base_dir=ROOT,
            include_roots=self.include_roots)
        self.assertEqual("fail", audit["summary"]["status"])
        self.assertTrue(any(item["check_id"] == "interrupt_paths" and
                            item["status"] == "fail" for item in audit["findings"]))
        # With simultaneous events, a mere completion count can look closed
        # even when both physical sources are assigned the wrong IDs.  Distinct
        # arrival windows make the edge pulse disappear on the unlatched lane.
        staggered = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True,
                                              stagger_sources=True))
        image = Path(self._temporary.name) / "staggered-boot.hex"
        image.write_text("".join(f"{value:02x}\n" for value in staggered.image),
                         encoding="utf-8")
        trigger = staggered.document["trigger"]
        sample = RuntimeSample(
            request_id=14, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]),
                                       cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]))
        result = run_sample(replace(self.builds["swapped_source_ids"],
                                    boot_image=image), sample, timeout_seconds=1800)
        self.assertEqual("OK", result.status)
        self.assertEqual(0, read32(result, staggered.report_address +
                                   self.layout["all_sources_closed"]))

    def test_masked_cpu_never_claims_either_source(self) -> None:
        disabled = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True,
                                              enable_interrupts=False))
        image = Path(self._temporary.name) / "masked-boot.hex"
        image.write_text("".join(f"{value:02x}\n" for value in disabled.image),
                         encoding="utf-8")
        result = run_sample(replace(self.builds["baseline"], boot_image=image),
                            self.sample, timeout_seconds=1800)
        self.assertEqual("OK", result.status)
        self.assertEqual(0, read32(result,
                                   disabled.report_address + self.layout["interrupt_completions"]))

    def test_latch_fault_replays_and_is_classified_as_composition(self) -> None:
        build = self.builds["missing_edge_latch"]
        result = self.results["missing_edge_latch"]
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        package = build_evidence_package(
            self.plan, build, policy, [result], samples=[self.sample],
            kind="injected_connection_fault",
            criteria=[{"criterion_id": "all-sources-complete",
                       "description": "both declared sources must be claimed and completed"}],
            legality=applied_legality(build, self.sample, result),
            anomaly={"present": True, "criterion": "all-sources-complete",
                     "basis": "independent controller LATCH_MASK source-ID contract",
                     "basis_independent": True, "reproducible": True,
                     "expected": 1, "observed": 0},
            attribution={"composition_findings": [
                {"fault": "source-specific LATCH_MASK bit removed",
                 "source_id": self.edge_id,
                 "baseline_top_hash": self.top_hashes["baseline"],
                 "mutated_top_hash": self.top_hashes["missing_edge_latch"]}]})
        classification, reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, classification, reason)
        confirmed_class, _ = confirm_component_defect(
            package, isolation={}, criterion={})
        self.assertEqual(COMPOSITION_DEFECT, confirmed_class)
        self.assertEqual("agreement", replay_package(package, build,
                                                     timeout_seconds=1800).status)


if __name__ == "__main__":
    unittest.main()
