"""Preflight contracts for a persistent, independently driven scenario."""

import json
import hashlib
from pathlib import Path
import unittest

from myfuzz.scenario.contracts import ResourceBudget, ResourceUsage, ScenarioManifest
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.host_identity import host_source_identity


_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_REAL_IDENTITY = _FIXTURES / "runner_identity_ibex_two_gpio_v5.json"
_REAL_GENOME = _FIXTURES / "genome_ibex_two_gpio_multiround.json"


def _real_identity():
    """Keep the saved identity shape while using current local wrapper bytes."""
    identity = json.loads(_REAL_IDENTITY.read_text())
    root = Path(__file__).resolve().parents[2]
    for session in identity["sessions"].values():
        for source in session["identity"]["sources"]["files"]:
            if source["path"].endswith("_main.cpp"):
                source["sha256"] = hashlib.sha256(
                    (root / source["path"]).read_bytes()).hexdigest()
    return identity


def manifest_document():
    return {
        "schema_version": "scenario_manifest.v1",
        "scenario_id": "cpu_gpio",
        "components": [
            {"component_id": "cpu", "harness_kind": "independent_rtl",
             "source_sha256": "a" * 64, "harness_sha256": "b" * 64,
             "profile_sha256": "c" * 64},
            {"component_id": "gpio", "harness_kind": "independent_rtl",
             "source_sha256": "d" * 64, "harness_sha256": "e" * 64,
             "profile_sha256": "f" * 64},
        ],
        "toolchain": {"verilator": "5.000", "compiler": "g++ 13",
                      "rfuzz": "local", "identity_sha256": "1" * 64},
        "ownership": {
            "fields": [{"component_id": "gpio", "port": "pins", "width": 2}],
            "owners": [
                {"component_id": "gpio", "port": "pins", "bit_offset": 0,
                 "width": 1, "kind": "source", "producer_ref": "gpio_env"},
                {"component_id": "gpio", "port": "pins", "bit_offset": 1,
                 "width": 1, "kind": "bound", "producer_ref": "cpu.pin_out"},
            ],
        },
        "bindings": [{"producer_ref": "cpu.pin_out", "target_component": "gpio",
                      "target_port": "pins", "bit_offset": 1, "width": 1}],
        "schedule_order": ["cpu", "gpio"],
        "scheduler_policy_id": "stable-local-v1",
        "reset_policy": {"initial": "cold_all", "allowed": ["warm_all", "cold_all"],
                         "scope": "all", "hold_cycles": 2, "release_cycles": 1},
        "initializer_id": "sha256-byte-v1",
        "address_map": [{"memory_id": "ram", "base": 0, "size": 4096,
                         "permissions": "rwx", "owner_component": "cpu"}],
        "budget": ResourceBudget().to_document(),
    }


class ContractTests(unittest.TestCase):
    def test_canonical_manifest_identity_and_roundtrip(self):
        document = manifest_document()
        manifest = ScenarioManifest.from_document(document)
        self.assertEqual(manifest.to_document(), document)
        self.assertEqual(ScenarioManifest.from_bytes(manifest.canonical_bytes()), manifest)
        self.assertEqual(len(manifest.sha256), 64)
        self.assertEqual(manifest.component_epoch(0, 2), ("cpu", 2))
        self.assertEqual(manifest.memory_generation("ram", 0), ("ram", 0))

    def test_rejects_noncanonical_and_unknown_fields(self):
        manifest = ScenarioManifest.from_document(manifest_document())
        with self.assertRaisesRegex(ValueError, "canonical"):
            ScenarioManifest.from_bytes(json.dumps(manifest.to_document()).encode())
        document = manifest_document()
        document["unknown"] = 1
        with self.assertRaisesRegex(ValueError, "unknown"):
            ScenarioManifest.from_document(document)

    def test_ownership_and_binding_must_match(self):
        document = manifest_document()
        document["ownership"]["owners"][1]["bit_offset"] = 0
        with self.assertRaisesRegex(ValueError, "overlap"):
            ScenarioManifest.from_document(document)
        document = manifest_document()
        document["bindings"][0]["producer_ref"] = "wrong"
        with self.assertRaisesRegex(ValueError, "binding"):
            ScenarioManifest.from_document(document)

    def test_rejects_partial_and_unknown_reset_policies(self):
        for scope in ("cpu", "ip"):
            with self.subTest(scope=scope):
                document = manifest_document()
                document["reset_policy"]["scope"] = scope
                with self.assertRaisesRegex(ValueError, "unsupported_reset_scope"):
                    ScenarioManifest.from_document(document)
        document = manifest_document()
        document["reset_policy"]["allowed"] = ["warm_all", "soft_cpu"]
        with self.assertRaisesRegex(ValueError, "reset_policy"):
            ScenarioManifest.from_document(document)

    def test_budget_preflight_checks_actions_steps_and_source_bits(self):
        manifest = ScenarioManifest.from_document(manifest_document())
        genome = ScenarioGenome(
            testcase_id="case", direction="CPU_TO_IP", path_id="path",
            schedule_order=("cpu", "gpio"), max_steps=3,
            actions=(Action("a", "gpio", "pins", 1, "CPU_TO_IP",
                            Trigger("START"), bit_offset=0, width=1),))
        manifest.preflight_genome(genome)
        invalid = ScenarioGenome(
            testcase_id="case", direction="CPU_TO_IP", path_id="path",
            schedule_order=("cpu", "gpio"), max_steps=3,
            actions=(Action("a", "gpio", "pins", 1, "CPU_TO_IP",
                            Trigger("START"), bit_offset=1, width=1),))
        with self.assertRaisesRegex(ValueError, "bound input"):
            manifest.preflight_genome(invalid)
        smaller = manifest_document()
        smaller["budget"]["max_scheduler_steps"] = 2
        with self.assertRaisesRegex(ValueError, "max_scheduler_steps"):
            ScenarioManifest.from_document(smaller).preflight_genome(genome)

    def test_schema_artifacts_are_parseable_and_versioned(self):
        root = Path(__file__).resolve().parents[2] / "schemas"
        for name in ("scenario_manifest.v1.json", "scenario_runtime_manifest.v1.json",
                     "scenario_genome.v1.json", "scenario_result.v1.json"):
            schema = json.loads((root / name).read_text())
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["type"], "object")

    def test_resource_usage_reports_first_exceeded_limit(self):
        budget = ResourceBudget()
        usage = ResourceUsage(local_cycles={"cpu": 4}, materialized_bytes={"ram": 3},
                              scheduler_steps=5, source_actions=1, transactions=2,
                              semantic_records=6, evidence_bytes=10, wall_time_ms=15,
                              quiesce_steps=0)
        budget.check_usage(usage)
        oversized = ResourceUsage(**{**usage.to_document(),
                                     "evidence_bytes": budget.max_evidence_bytes
                                     - budget.evidence_termination_reserve_bytes + 1})
        with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
            budget.check_usage(oversized)
        self.assertTrue(ResourceBudget(build_workers=2, waveform_enabled=True).waveform_enabled)

    def test_image_preflight_uses_aggregate_bytes_and_address_map(self):
        document = manifest_document()
        document["budget"]["max_materialized_bytes_per_memory"] = 2
        manifest = ScenarioManifest.from_document(document)
        genome = ScenarioGenome(
            testcase_id="case", direction="CPU_TO_IP", path_id="path",
            schedule_order=("cpu", "gpio"), max_steps=3, actions=(),
            initial_images=(MemoryImage("one", "cpu", 0, "aabb"),
                            MemoryImage("two", "cpu", 2, "cc")))
        with self.assertRaisesRegex(ValueError, "max_materialized_bytes_per_memory"):
            manifest.preflight_genome(genome)
        outside = ScenarioGenome(
            testcase_id="case", direction="CPU_TO_IP", path_id="path",
            schedule_order=("cpu", "gpio"), max_steps=3, actions=(),
            initial_images=(MemoryImage("bad", "cpu", 4096, "aa"),))
        with self.assertRaisesRegex(ValueError, "address_map"):
            manifest.preflight_genome(outside)

    def test_action_direction_cannot_override_genome_direction(self):
        manifest = ScenarioManifest.from_document(manifest_document())
        genome = ScenarioGenome(
            testcase_id="case", direction="CPU_TO_IP", path_id="path",
            schedule_order=("cpu", "gpio"), max_steps=3,
            actions=(Action("a", "gpio", "pins", 1, "IP_TO_CPU",
                            Trigger("START"), bit_offset=0, width=1),))
        with self.assertRaisesRegex(ValueError, "direction"):
            manifest.preflight_genome(genome)

    def test_real_runner_identity_requires_explicit_per_harness_reset_timing(self):
        identity = _real_identity()
        with self.assertRaisesRegex(ValueError, "reset_timings"):
            ScenarioManifest.from_runner_identity(
                identity, scenario_id="ibex_two_gpio_multiround",
                schedule_order=("cpu", "gpio_a", "gpio_b"),
                scheduler_policy_id="stable-local-v1", budget=ResourceBudget())

    def test_runtime_reset_timing_must_match_hashed_harness_source(self):
        identity = _real_identity()
        timings = {}
        for component, hold, release, source_path in (
                ("cpu", 10, 0, "src/myfuzz/scenario/rtl/local_ibex_cpu_main.cpp"),
                ("gpio_a", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp"),
                ("gpio_b", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp")):
            files = identity["sessions"][component]["identity"]["sources"]["files"]
            timings[component] = {
                "hold_cycles": hold, "release_cycles": release,
                "source_path": source_path,
                "source_sha256": next(item["sha256"] for item in files
                                      if item["path"] == source_path),
            }
        timings["cpu"]["hold_cycles"] = 11
        with self.assertRaisesRegex(ValueError, "reset_timings.cpu.hold_cycles"):
            ScenarioManifest.from_runner_identity(
                identity, scenario_id="reset-audit",
                schedule_order=("cpu", "gpio_a", "gpio_b"),
                scheduler_policy_id="stable-local-v1",
                reset_timings=timings, budget=ResourceBudget())
        timings["cpu"]["hold_cycles"] = 10
        timings["gpio_a"]["release_cycles"] = 7
        with self.assertRaisesRegex(ValueError, "reset_timings.gpio_a.release_cycles"):
            ScenarioManifest.from_runner_identity(
                identity, scenario_id="reset-audit",
                schedule_order=("cpu", "gpio_a", "gpio_b"),
                scheduler_policy_id="stable-local-v1",
                reset_timings=timings, budget=ResourceBudget())

    def test_real_runner_identity_roundtrip_preserves_all_source_facts(self):
        identity = _real_identity()
        self.assertEqual(identity["bindings"][0]["width"], 8)
        genome_document = json.loads(_REAL_GENOME.read_text())
        genome = ScenarioGenome(**{
            **genome_document,
            "schedule_order": ("cpu", "gpio_a", "gpio_b"),
            "actions": (),
            "initial_images": tuple(MemoryImage(**item)
                                    for item in genome_document["initial_images"]),
        })
        timings = {}
        for component, hold, release, path in (
                ("cpu", 10, 0, "src/myfuzz/scenario/rtl/local_ibex_cpu_main.cpp"),
                ("gpio_a", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp"),
                ("gpio_b", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp")):
            files = identity["sessions"][component]["identity"]["sources"]["files"]
            digest = next(item["sha256"] for item in files if item["path"] == path)
            timings[component] = {"hold_cycles": hold, "release_cycles": release,
                                  "source_path": path, "source_sha256": digest}
        manifest = ScenarioManifest.from_runner_identity(
            identity, scenario_id="ibex_two_gpio_multiround",
            schedule_order=genome.schedule_order,
            scheduler_policy_id="stable-local-v1",
            reset_timings=timings,
            budget=ResourceBudget(max_materialized_bytes_per_memory=131072))
        self.assertEqual(manifest.to_document()["runner_identity"], identity)
        self.assertEqual(ScenarioManifest.from_bytes(manifest.canonical_bytes()), manifest)
        manifest.preflight_genome(genome)
        timings["cpu"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reset_timings.cpu.source_sha256"):
            ScenarioManifest.from_runner_identity(
                identity, scenario_id="ibex_two_gpio_multiround",
                schedule_order=genome.schedule_order,
                scheduler_policy_id="stable-local-v1", reset_timings=timings,
                budget=ResourceBudget(max_materialized_bytes_per_memory=131072))

    def test_runtime_manifest_accepts_and_checks_host_source_closure(self):
        identity = _real_identity()
        identity["host_sources"] = host_source_identity()
        timings = {}
        for component, hold, release, path in (
                ("cpu", 10, 0, "src/myfuzz/scenario/rtl/local_ibex_cpu_main.cpp"),
                ("gpio_a", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp"),
                ("gpio_b", 8, 8, "src/myfuzz/scenario/rtl/local_opentitan_gpio_main.cpp")):
            files = identity["sessions"][component]["identity"]["sources"]["files"]
            timings[component] = {
                "hold_cycles": hold, "release_cycles": release,
                "source_path": path,
                "source_sha256": next(item["sha256"] for item in files
                                      if item["path"] == path),
            }
        manifest = ScenarioManifest.from_runner_identity(
            identity, scenario_id="ibex_two_gpio_multiround",
            schedule_order=("cpu", "gpio_a", "gpio_b"),
            scheduler_policy_id="stable-local-v1", reset_timings=timings,
            budget=ResourceBudget(max_materialized_bytes_per_memory=131072))
        self.assertEqual(identity["host_sources"],
                         manifest.to_document()["runner_identity"]["host_sources"])
        identity["host_sources"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "host source sha256"):
            ScenarioManifest.from_runner_identity(
                identity, scenario_id="ibex_two_gpio_multiround",
                schedule_order=("cpu", "gpio_a", "gpio_b"),
                scheduler_policy_id="stable-local-v1", reset_timings=timings,
                budget=ResourceBudget(max_materialized_bytes_per_memory=131072))


if __name__ == "__main__":
    unittest.main()
