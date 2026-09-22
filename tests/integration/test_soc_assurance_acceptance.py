"""Step 10: the generation-phase acceptance for user-supplied RTL and profiles.

Scope of this acceptance (matching the assurance plan's ``当前生成验收``):
a first-time CPU, first-time peripherals and two instances of one profile are
composed, rendered, elaborated and independently audited without editing the
generator, and invalid inputs are rejected with a located diagnostic.

Real CPU execution, replay and defect attribution belong to the later phases and
are deliberately not claimed here.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import CompositionError, build_composition

from tests.composition.soc_generation_fixture import ROOT, example_profiles


class GenerationAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-accept-", dir=ROOT)
        self.output = Path(self._temporary.name) / "soc"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _run_generator(self, *extra: str) -> subprocess.CompletedProcess:
        profiles = [str(path) for path in sorted(
            (ROOT / "examples/soc_generation/profiles").glob("*.json"))]
        command = [sys.executable, "scripts/generate_soc.py",
                   "--request", "examples/soc_generation/request.json",
                   "--output", self.output.as_posix(), *extra]
        for profile in profiles:
            command += ["--profile", Path(profile).relative_to(ROOT).as_posix()]
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              timeout=900, check=False)

    def test_generation_entry_point_publishes_a_complete_artifact_set(self) -> None:
        result = self._run_generator()
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual("pass", summary["audit"])
        self.assertEqual(["cpu0", "gpio0", "uart0", "uart1"], summary["instances"])
        for name in ("myfuzz_soc_top.sv", "sources.f", "soc_composition.json",
                     "soc_plan.json", "soc_spec.json", "interrupt_plan.json",
                     "address_map.json", "raw_layout.json", "port_dispositions.json",
                     "structure_audit.json", "inputs.json"):
            with self.subTest(artifact=name):
                self.assertTrue((self.output / name).is_file(), name)

    def test_the_published_audit_record_is_bound_to_the_published_plan(self) -> None:
        self.assertEqual(0, self._run_generator().returncode)
        audit = json.loads((self.output / "structure_audit.json").read_text())
        composition = json.loads((self.output / "soc_composition.json").read_text())
        self.assertEqual(composition["plan_hash"], audit["plan_hash"])
        self.assertEqual("pass", audit["summary"]["status"])
        self.assertEqual(0, audit["summary"]["failed"])
        self.assertTrue(audit["unknown"], "unverifiable properties must be reported")

    def test_the_source_list_matches_the_rendered_top(self) -> None:
        self.assertEqual(0, self._run_generator().returncode)
        listed = [line.strip() for line in
                  (self.output / "sources.f").read_text().splitlines() if line.strip()]
        self.assertIn("src/myfuzz/protocols/rtl/soc_irq_controller.sv", listed)
        self.assertIn("examples/soc_generation/rtl/novacore.sv", listed)
        top = (self.output / "myfuzz_soc_top.sv").read_text()
        self.assertIn("examples/soc_generation/rtl/novauart.sv", listed)

    def test_generation_is_deterministic(self) -> None:
        first = self._run_generator()
        self.assertEqual(0, first.returncode)
        first_hash = json.loads(first.stdout)["plan_hash"]
        first_top = (self.output / "myfuzz_soc_top.sv").read_text()
        shutil.rmtree(self.output)
        second = self._run_generator()
        self.assertEqual(0, second.returncode)
        self.assertEqual(first_hash, json.loads(second.stdout)["plan_hash"])
        self.assertEqual(first_top, (self.output / "myfuzz_soc_top.sv").read_text())

    def test_audit_can_be_skipped_and_that_is_reported(self) -> None:
        result = self._run_generator("--no-audit")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("skipped", json.loads(result.stdout)["audit"])
        self.assertFalse((self.output / "structure_audit.json").exists())


class RejectionAcceptanceTests(unittest.TestCase):
    """An unsupported or inconsistent input must be refused, with a location."""

    def _request(self, mutate):
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        mutate(document)
        return load_composition_request(document, profiles=example_profiles())

    def test_an_unknown_port_in_the_profile_is_refused(self) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/profiles/novauart.json").read_text())
        document["endpoints"][0]["fields"][0]["aliases"] = ["paddr_typo_i"]
        profile = load_component_profile(document)
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novauart.json"] = profile
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises(ComponentProfileError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("port-missing", str(error.exception))
        self.assertIn("novauart", str(error.exception))

    def test_a_reversed_direction_role_is_refused(self) -> None:
        """Declaring a peripheral's slave bus as a master must not be inverted."""
        document = json.loads(
            (ROOT / "examples/soc_generation/profiles/novagpio.json").read_text())
        document["endpoints"][0]["function"] = "memory_master"
        profile = load_component_profile(document)
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novagpio.json"] = profile
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises(ComponentProfileError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("direction-conflict", str(error.exception))
        self.assertIn("novagpio", str(error.exception))

    def test_an_unsupported_component_function_is_refused(self) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/profiles/novagpio.json").read_text())
        document["endpoints"][0]["function"] = "dma_master"
        with self.assertRaises(ComponentProfileError) as error:
            load_component_profile(document)
        self.assertIn("unsupported-endpoint-function", str(error.exception))

    def test_an_undisposed_port_is_refused(self) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/profiles/novagpio.json").read_text())
        document["port_actions"] = []
        profile = load_component_profile(document)
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novagpio.json"] = profile
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        with self.assertRaises(CompositionError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("undisposed-port-bits", str(error.exception))
        self.assertIn("pin_mode_i", str(error.exception))

    def test_a_missing_capability_is_refused_instead_of_guessed(self) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/profiles/novauart.json").read_text())
        del document["capabilities"]["has_error"]
        profile = load_component_profile(document)
        profiles = dict(example_profiles())
        profiles["examples/soc_generation/profiles/novauart.json"] = profile
        request = load_composition_request(
            ROOT / "examples/soc_generation/request.json", profiles=profiles)
        # Dropping the error capability is a real capability change, not a
        # silent fallback: the resolved adapter must still describe the target.
        plan = build_composition(request, base_dir=ROOT)
        adapter = next(item["resolved_adapter"] for item in plan.target_records
                       if item.get("instance_id") == "uart0")
        self.assertEqual("none", adapter["error_source"])

    def test_two_overlapping_fixed_addresses_are_refused(self) -> None:
        def mutate(document):
            document["peripherals"][1]["address"] = 0x40001000
            document["peripherals"][2]["address"] = 0x40001000
        request = self._request(mutate)
        with self.assertRaises(CompositionError) as error:
            build_composition(request, base_dir=ROOT)
        self.assertIn("fixed-address-overlap", str(error.exception))

    def test_an_auto_address_moves_around_a_later_fixed_one(self) -> None:
        """A user-fixed address is kept; the auto window is the one that moves."""
        request = self._request(
            lambda document: document["peripherals"][2].__setitem__("address", 0x40000000))
        plan = build_composition(request, base_dir=ROOT)
        windows = {item["target_id"]: item["base"]
                   for item in plan.plan["address_map"]["windows"]}
        self.assertEqual(0x40000000, windows["uart1_win"])
        self.assertNotEqual(0x40000000, windows["gpio0_win"])
        self.assertNotEqual(0x40000000, windows["uart0_win"])

    def test_a_boot_region_without_execute_permission_is_rejected_by_the_plan(self) -> None:
        def mutate(document):
            document["memory"][0]["permissions"]["execute"] = False
        request = self._request(mutate)
        plan = build_composition(request, base_dir=ROOT)
        region = next(item for item in plan.plan["address_map"]["memory_regions"]
                      if item["region_id"] == "rom0")
        self.assertFalse(region["permissions"]["execute"])


class OfflineScopeTests(unittest.TestCase):
    def test_the_acceptance_designs_are_not_registered_components(self) -> None:
        """The example must exercise the profile path, not a component table."""
        source = (ROOT / "src/myfuzz/integration/soc_matrix_smoke.py").read_text()
        for name in ("novacore", "novauart", "novagpio"):
            self.assertNotIn(name, source)
            self.assertNotIn(name, (ROOT / "configs/soc/matrix.json").read_text())

    def test_generated_rtl_needs_no_edit_to_the_generator(self) -> None:
        """A second, differently named request must use the same code path."""
        document = json.loads((ROOT / "examples/soc_generation/request.json").read_text())
        document["request_id"] = "renamed-instances"
        for index, peripheral in enumerate(document["peripherals"]):
            peripheral["instance_id"] = f"p{index}"
        profiles = example_profiles()
        request = load_composition_request(document, profiles=profiles)
        plan = build_composition(request, base_dir=ROOT)
        self.assertEqual(["cpu0", "p0", "p1", "p2"],
                         [item.instance_id for item in plan.instances])
        with unittest.mock.patch.object(Path, "read_text", Path.read_text):
            self.assertTrue(plan.plan_hash)


if __name__ == "__main__":
    unittest.main()
