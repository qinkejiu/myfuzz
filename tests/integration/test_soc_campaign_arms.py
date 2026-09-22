"""Item 6: the three-arm campaign really executes all three arms.

The arms - ``direct_input``, ``constrained_baseline`` and ``dependency_repair`` -
share one build, one source closure, one coverage identity, one budget and one
seed; only the input projection differs.  These tests assert the execution
properties that a comparison function alone cannot provide:

* the shared corpus is a deterministic function of the compiled layout and the
  seed, and is identical for every arm;
* an unknown arm, a missing real-run opt-in, a reused output directory and an
  artifact without arm projectors are all refused;
* a fabricated identity difference between arms is refused, so "same SoC" is a
  checked fact rather than a formatting claim;
* with Verilator present, the three arms really execute the corpus through the
  real RTL simulator, persist a corpus that replays byte-for-byte, and show the
  projection differences the plan expects: the constrained baseline rejects the
  dependency-bearing candidates, the repair arm accepts them and counts its
  address repairs, and the direct arm feeds raw candidates that the harness
  itself refuses.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.integration.soc_comparison import (
    ARM_NAMES,
    SocComparisonError,
    build_seed_corpus,
    execute_soc_campaign_arms,
)

from tests.composition.soc_generation_fixture import (
    ROOT,
    example_plan,
    profile_paths,
    request_path,
    profile_tools_available,
)


def _config(**overrides):
    value = {
        "root": str(ROOT),
        "config_id": "arms-test",
        "composition_request": str(request_path()),
        "component_profiles": [str(path) for path in profile_paths()],
        "drive_profile": "cpu_execute",
        "mode": "cpu_only",
        "seed": 7,
        "seed_cycles": 3,
        "duration_seconds": 120,
        "corpus_entries": 4,
        "corpus_cycles": 2,
    }
    value.update(overrides)
    return value


class _Projector:
    """A projector stub with the fields the arm runner reports."""

    instruction_mode = "test-arm"
    constraint_hash = "sha256:test"

    def __init__(self, name):
        self.name = name
        self.repair_counts = {"address_repair": 0}

    def project(self, raw):
        return raw


def _fake_artifact():
    build = {
        "composition_hash": "sha256:composition",
        "layout_hash": "sha256:layout",
        "policy_hash": "sha256:policy",
        "constraint_hash": "sha256:constraint",
        "image_hash": "sha256:image",
        "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
        "drive_profile": "cpu_execute",
        "mode": "cpu_only",
        "sources": {"source_count": 1, "source_files": [{"path": "dut.sv"}]},
        "structure_audit": {"status": "pass", "summary": {"status": "pass"}},
    }
    return SimpleNamespace(build_document=build,
                           projection_arms={name: _Projector(name) for name in ARM_NAMES})


def _report(arm, **overrides):
    report = {
        "arm": arm,
        "status": "completed",
        "final_status": "passed",
        "artifact": {
            "composition_hash": "sha256:composition",
            "layout_hash": "sha256:layout",
            "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
            "policy_hash": "sha256:policy",
            "constraint_hash": "sha256:constraint",
            "structure_audit": {"status": "pass"},
            "source_closure_hash": "sha256:closure",
        },
        "rtl_execution": {"tests": 1, "coverage_records": 1,
                          "execution_totals": {"cycles": 1}},
        "corpus": {"status": "verified", "entries": 1},
        "input_projection": {"accepted_entries": 1, "rejected_entries": 0,
                             "anomaly_entries": 0, "repair_counts": {}},
        "client_result": {"binary_sha256": "sha256:binary"},
        "seed": 7,
        "budget_seconds": 120.0,
    }
    report.update(overrides)
    return report


class CorpusTests(unittest.TestCase):
    def test_the_corpus_is_deterministic_and_arm_independent(self) -> None:
        plan = example_plan()
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from myfuzz.integration.soc_builder import build_projection_arms
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        arms = build_projection_arms(layout=layout, constraint_hash="sha256:t",
                                     special_width=int(plan.raw_layout["raw_width"]),
                                     policy=policy, image=image)
        first = build_seed_corpus(SimpleNamespace(layout=layout), seed=11, entries=6, cycles=3,
                                  image_plan=image.document())
        second = build_seed_corpus(SimpleNamespace(layout=layout), seed=11, entries=6, cycles=3,
                                   image_plan=image.document())
        other = build_seed_corpus(SimpleNamespace(layout=layout), seed=12, entries=6, cycles=3,
                                  image_plan=image.document())
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(["candidate", "special"] * 3, [entry["kind"] for entry in first])
        self.assertTrue(all(len(entry["raw"]) == 3 for entry in first))
        # A candidate raises each image offer in exactly one cycle: the image
        # projection refuses a test with several candidates.
        offer = next(field for field in layout.fields if field.role == "init_offer")
        for entry in first:
            if entry["kind"] != "candidate":
                continue
            raised = sum((word >> offer.raw_lo) & 1 for word in entry["raw"])
            self.assertEqual(1, raised)
        # The special entries leave every dependency bit at zero.
        dependency_low = min(field.raw_lo for field in layout.fields
                             if str(field.owner) in ("soc_image", "soc_stimulus"))
        for entry in first:
            if entry["kind"] == "special":
                self.assertTrue(all(word >> dependency_low == 0 for word in entry["raw"]))

    def test_the_arm_semantics_differ_on_the_shared_corpus(self) -> None:
        """The three projectors really apply three different policies."""
        plan = example_plan()
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from myfuzz.integration.soc_builder import SocBuildError, build_projection_arms
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        arms = build_projection_arms(layout=layout, constraint_hash="sha256:t",
                                     special_width=int(plan.raw_layout["raw_width"]),
                                     policy=policy, image=image)
        corpus = build_seed_corpus(SimpleNamespace(layout=layout), seed=7, entries=6, cycles=3,
                                   image_plan=image.document())
        outcomes: dict[str, int] = {}
        for name, projector in arms.items():
            accepted = 0
            for entry in corpus:
                records = list(entry["raw"])
                project_records = getattr(projector, "project_records", None)
                try:
                    if project_records is not None:
                        project_records(records)
                    else:
                        for value in records:
                            projector.project(value)
                    accepted += 1
                except SocBuildError:
                    continue
            outcomes[name] = accepted
        # Dependency-bearing candidates: the constrained baseline cannot serve
        # them, the repair arm can, and the identity arm accepts everything.
        self.assertEqual(len(corpus), outcomes["direct_input"])
        self.assertLess(outcomes["constrained_baseline"], outcomes["direct_input"])
        self.assertEqual(len(corpus), outcomes["dependency_repair"])
        self.assertGreater(arms["dependency_repair"].repair_counts.get("address_repair", 0), 0)


class ExecutionContractTests(unittest.TestCase):
    """Argument and identity handling, without building anything."""

    def test_an_unknown_arm_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SocComparisonError, "arms:unknown-arm"):
                execute_soc_campaign_arms(_config(), Path(directory) / "out",
                                          arms=("direct_input", "something_else"),
                                          environment={"MYFUZZ_SOC_REAL": "1"})

    def test_the_real_opt_in_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SocComparisonError, "real-opt-in-required"):
                execute_soc_campaign_arms(_config(), Path(directory) / "out",
                                          environment={})

    def test_an_existing_output_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            output.mkdir()
            with self.assertRaisesRegex(SocComparisonError, "arms-output-must-be-new"):
                execute_soc_campaign_arms(_config(), output,
                                          environment={"MYFUZZ_SOC_REAL": "1"})

    def test_an_artifact_without_arm_projectors_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plain = SimpleNamespace(build_document={"structure_audit": {"status": "pass"}})
            with self.assertRaisesRegex(SocComparisonError, "artifact-without-arm-projectors"):
                execute_soc_campaign_arms(
                    _config(), Path(directory) / "out",
                    builder=lambda config, build_dir: plain,
                    corpus=({"index": 0, "kind": "special", "raw": (0,)},),
                    environment={"MYFUZZ_SOC_REAL": "1"})

    def test_a_fabricated_identity_difference_between_arms_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            def runner(artifact, arm, corpus, **options):
                report = _report(arm)
                if arm == "dependency_repair":
                    report["artifact"] = dict(report["artifact"],
                                              source_closure_hash="sha256:other")
                return report
            with patch("myfuzz.integration.soc_comparison._run_arm", side_effect=runner):
                with self.assertRaisesRegex(SocComparisonError,
                                            "identity-not-shared:source_closure_hash"):
                    execute_soc_campaign_arms(
                        _config(), Path(directory) / "out",
                        builder=lambda config, build_dir: _fake_artifact(),
                        corpus=({"index": 0, "kind": "special", "raw": (0,)},),
                        environment={"MYFUZZ_SOC_REAL": "1"})

    def test_every_arm_receives_the_same_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            seen = []

            def runner(artifact, arm, corpus, **options):
                seen.append((arm, tuple(corpus)))
                return _report(arm)

            corpus = ({"index": 0, "kind": "special", "raw": (0,)},
                      {"index": 1, "kind": "candidate", "raw": (1, 2)})
            with patch("myfuzz.integration.soc_comparison._run_arm", side_effect=runner):
                document = execute_soc_campaign_arms(
                    _config(), Path(directory) / "out",
                    builder=lambda config, build_dir: _fake_artifact(),
                    corpus=corpus, environment={"MYFUZZ_SOC_REAL": "1"})
            self.assertEqual(sorted(ARM_NAMES), sorted(arm for arm, _ in seen))
            self.assertEqual(1, len({repr(payload) for _, payload in seen}))
            self.assertEqual("valid", document["comparison"]["comparison"]["status"])
            self.assertTrue(document["shared"]["identity_shared"])
            self.assertTrue((Path(directory) / "out" / "arms_report.json").is_file())
            self.assertTrue((Path(directory) / "out" / "comparison.json").is_file())


@unittest.skipUnless(profile_tools_available(),
                     "bundled RFuzz Verilator 5.020 required for the real arm campaign")
class ArmsExecutionTests(unittest.TestCase):
    """The three arms really execute one build and replay their own corpus."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        image = cls.directory / "boot.hex"
        image.write_text("13\n00\n00\n00\n")
        cls.config = _config(
            external_input_defaults={"gpio0__gpio_in_i": 0, "uart0__uart_rx_i": 0,
                                     "uart1__uart_rx_i": 0},
            boot_image=str(image), corpus_entries=6, corpus_cycles=3)
        cls.output = cls.directory / "arms"
        cls.document = execute_soc_campaign_arms(
            cls.config, cls.output, environment={"MYFUZZ_SOC_REAL": "1"})
        cls.reports = {
            arm: json.loads((cls.output / path).read_text(encoding="utf-8"))
            for arm, path in cls.document["arm_reports"].items()}

    def test_all_three_arms_executed_under_one_identity(self) -> None:
        shared = self.document["shared"]
        self.assertTrue(shared["identity_shared"])
        self.assertEqual(7, shared["seed"])
        self.assertEqual(6, shared["corpus_entries"])
        self.assertEqual(3, shared["corpus_cycles"])
        self.assertEqual(set(ARM_NAMES), set(self.document["arms"]))
        self.assertEqual("valid", self.document["comparison"]["comparison"]["status"])
        self.assertEqual("not-claimed",
                         self.document["comparison"]["comparison"]["component_bug_claim"])
        for arm, report in self.reports.items():
            with self.subTest(arm=arm):
                self.assertEqual("completed", report["status"], report["evidence_missing"])
                self.assertGreater(report["rtl_execution"]["tests"], 0)
                self.assertEqual("verified", report["corpus"]["status"])
                self.assertEqual("passed", report["replay"]["status"])
                self.assertEqual(report["corpus"]["entries"], report["replay"]["entries"])
                self.assertEqual(shared["executable_sha256"],
                                 report["client_result"]["binary_sha256"])

    def test_the_arms_differ_only_in_their_projection(self) -> None:
        direct = self.reports["direct_input"]
        constrained = self.reports["constrained_baseline"]
        repair = self.reports["dependency_repair"]
        # The constrained baseline cannot serve the dependency candidates.
        self.assertGreater(constrained["input_projection"]["rejected_entries"], 0)
        self.assertTrue(any("dynamic-image-loading-unsupported" in reason
                            for reason in constrained["input_projection"]["rejection_reasons"]))
        # The repair arm accepts every entry and records its address repairs.
        self.assertEqual(0, repair["input_projection"]["rejected_entries"])
        self.assertEqual(0, repair["input_projection"]["anomaly_entries"])
        self.assertGreater(repair["input_projection"]["repair_counts"]["address_repair"], 0)
        self.assertEqual(0, constrained["input_projection"]["repair_counts"]["address_repair"])
        # The identity arm hands the raw candidate to the harness, which refuses
        # an out-of-window image address itself: a replayable anomaly, not a
        # silent rejection.
        self.assertGreater(direct["input_projection"]["anomaly_entries"], 0)
        anomalies = [entry for entry in direct["entries"] if entry["status"] == "anomaly"]
        self.assertTrue(any("image address" in " ".join(entry.get("diagnostics", []))
                            for entry in anomalies), anomalies)
        # Coverage is DUT coverage: the repaired arm reached more RTL feedback
        # than the baseline without changing the coverage identity.
        self.assertGreater(repair["rtl_execution"]["coverage_records"],
                           constrained["rtl_execution"]["coverage_records"])
        self.assertEqual(constrained["artifact"]["coverage_kind"],
                         repair["artifact"]["coverage_kind"])

    def test_the_saved_corpus_is_replayable_and_identity_bound(self) -> None:
        for arm, report in self.reports.items():
            with self.subTest(arm=arm):
                manifest = report["corpus"]["manifest"]
                self.assertEqual("rfuzz_corpus_manifest.v1", manifest["schema_version"])
                self.assertEqual(report["artifact"]["layout_hash"], manifest["layout_hash"])
                for entry in manifest["replays"]:
                    self.assertTrue(entry["coverage_verified"])
                    self.assertTrue((self.output / "arms" / arm / "corpus"
                                     / entry["file"]).is_file())


if __name__ == "__main__":
    unittest.main()
