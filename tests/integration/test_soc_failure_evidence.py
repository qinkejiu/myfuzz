"""Step 9: boundary classification and counterexample minimisation.

Two halves:

* the classification branches, tested branch by branch on packages assembled
  from the same documents a real run produces.  Every named category of the plan
  is exercised, and the gate that guards ``component_candidate`` is tested
  against one deliberately missing prerequisite at a time -- including the case
  the plan calls out explicitly: a DUT-looking anomaly whose environment
  legality evidence is missing must not become a component defect.
* the minimiser, tested on the real example build with synthetic predicates: a
  sixteen-cycle input must shrink to its one-cycle witness, a one-step budget
  must stop the search and say so, and a predicate the original does not satisfy
  must be reported instead of silently "minimising" something else.

``MYFUZZ_SOC_REAL=1`` gates the real build (following
``tests/integration/test_soc_matrix_runtime.py``); when the flag is set nothing
here skips.  The real build is shared with
``tests/integration/test_soc_dependency_replay.py`` and cached under ``runs/``.
"""
from __future__ import annotations

import dataclasses
import shutil
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_failure_evidence import (
    BOUNDARY_CLASSES,
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    DRIVER_VIOLATION,
    EVIDENCE_SCHEMA,
    LEGALITY_CONFIRMED,
    LEGALITY_UNAVAILABLE,
    OBSERVATION_INSUFFICIENT,
    PROFILE_DEFECT,
    REQUIRED_IDENTITY,
    REQUIRED_LEGALITY,
    SOFTWARE_OR_MODEL_DEFECT,
    UNDIAGNOSED,
    EvidencePackage,
    SocFailureEvidenceError,
    build_evidence_package,
    classify_boundary,
    component_candidate_ready,
    minimize_sample,
    read_evidence_package,
    write_evidence_package,
)
from myfuzz.composition.soc_runtime import RuntimeSample, run_sample

from tests.composition.soc_generation_fixture import ROOT, example_plan
from tests.integration.test_soc_dependency_replay import (
    OPT_IN,
    applied_legality,
    runtime_build,
)


def _digest(seed: str) -> str:
    return "sha256:" + (seed * 64)[:64]


_CRITERION = {
    "criterion_id": "poll-transaction-completes-in-window",
    "statement": "the composed CPU completes its boot fetch and reaches the poll state "
                 "within the declared cycle window",
    "basis": "examples/soc_generation/rtl/novacore.sv state machine read independently "
             "of the generated software",
    "independent": True,
}


def _identity(**overrides) -> dict[str, object]:
    identity: dict[str, object] = {
        "plan_hash": _digest("a"),
        "layout_hash": "b" * 64,
        "profile_hashes": {
            "novacore": {"component_id": "novacore", "top_module": "novacore",
                         "content_hash": _digest("c"),
                         "binding_hashes": {"cpu0": _digest("d")},
                         "instances": ["cpu0"]},
        },
        "policy_hash": _digest("e"),
        "policy_drive_profile": "cpu_execute",
        "policy": {"policy_hash": _digest("e"), "drive_profile": "cpu_execute",
                   "profile_version": 1, "layout_hash": "b" * 64,
                   "plan_hash": _digest("a"), "rule_count": 1,
                   "rules": [{"rule_id": "drive:cpu0__event_i", "category": "environment_hard",
                              "owner": "environment", "primitive": "drive_cycle_value",
                              "phase": "runtime", "failure_class": "driver_violation",
                              "checker": "soc_special_input_driver"}],
                   "gaps": ["one outstanding transaction"]},
        "rendered_top_hash": _digest("f"),
        "testbench_hash": _digest("0"),
        "build_hash": _digest("1"),
        "boot_image_hash": _digest("2"),
        "boot_image_policy": "external_image",
        "isa": {"family": "riscv", "xlen": 32, "extensions": ["I"],
                "reset_vector": 65536},
        "runtime": {"schema_version": "soc_runtime.v1", "top_module": "myfuzz_soc_top",
                    "testbench_module": "myfuzz_profile_tb", "raw_width": 7,
                    "executable_hash": _digest("3"), "warnings": 0,
                    "boot_image_policy": "external_image", "sources": []},
        "tool": {"simulator": "verilator", "verilator": "Verilator 5.051",
                 "runtime_schema": "soc_runtime.v1", "executable_hash": _digest("3"),
                 "provenance": "probe"},
        "recorded_build_identity": {"plan_hash": _digest("a"), "layout_hash": "b" * 64},
    }
    identity.update(overrides)
    return identity


def _result(*, observations: dict[str, int] | None = None) -> dict[str, object]:
    observed = {"cpu0__status_o": 3, "cpu0__trap_o": 0} if observations is None \
        else dict(observations)
    return {
        "request_id": 1,
        "status": "OK",
        "cycles": 3,
        "counters": {"cycles": 3, "observations": len(observed)},
        "observations": observed,
        "trace": [{"cycle": 0, "raw": 0, "cpu0__event_i": 0},
                  {"cycle": 1, "raw": 1, "cpu0__event_i": 1}],
        "applied_trace": [{"cycle": 1, "port": "cpu0__event_i", "value": 1}],
        "reason": "",
    }


def _legality(*, state: str = LEGALITY_CONFIRMED, violations: tuple[str, ...] = ()) \
        -> dict[str, object]:
    return {
        "environment_legality": state,
        "driver_violations": list(violations),
        "constraint_rejections": [],
        "monitor_results": [{"monitor": "special-input-hold", "result": "pass"}],
        "notes": [],
    }


def _anomaly(*, present: bool = True, reproducible: bool = True,
             basis_independent: bool = True, criterion: str = "criterion-1",
             basis: str = "independent specification",
             divergence: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "present": present,
        "kind": "observation-mismatch",
        "criterion": criterion,
        "basis": basis,
        "basis_independent": basis_independent,
        "reproducible": reproducible,
        "expected": 3,
        "observed": 2,
        "first_divergence": divergence or {"cycle": 7, "field": "raw",
                                           "kind": "applied-stimulus"},
    }


def _package(**overrides) -> EvidencePackage:
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA,
        "kind": "synthetic",
        "identity": _identity(),
        "samples": ({"request_id": 1, "raw": [0, 1, 2], "events": []},),
        "results": (_result(),),
        "inputs_complete": True,
        "criteria": (_CRITERION,),
        "legality": _legality(),
        "attribution": {},
        "anomaly": _anomaly(),
        "classification": (UNDIAGNOSED, "unclassified"),
        "notes": (),
    }
    fields.update(overrides)
    package = EvidencePackage(**fields)  # type: ignore[arg-type]
    if "classification" in overrides:
        return package
    # Like build_evidence_package, a package carries the classification its own
    # evidence supports; the stored-classification test overrides it on purpose.
    return dataclasses.replace(package, classification=classify_boundary(package))


def _without(document: dict[str, object], name: str) -> dict[str, object]:
    return {key: value for key, value in document.items() if key != name}


#: One case per branch the plan names.  The table is asserted to cover every
#: member of :data:`BOUNDARY_CLASSES`, so a category cannot be added to the
#: module without a case that reaches it.
CASES: tuple[tuple[str, dict[str, object], str], ...] = (
    ("component-candidate", {}, COMPONENT_CANDIDATE),
    ("driver-violation-state",
     {"legality": _legality(state="violated", violations=("hold broken at cycle 4",))},
     DRIVER_VIOLATION),
    ("driver-violation-recorded",
     {"legality": _legality(violations=("request dropped before ready",))},
     DRIVER_VIOLATION),
    ("profile-defect",
     {"attribution": {"profile_findings": (
         "write-1-to-clear described as read-clear in the profile register table",)}},
     PROFILE_DEFECT),
    ("profile-defect-despite-self-consistency",
     {"attribution": {"profile_findings": ("profile semantics conflict with the RTL",),
                      "self_consistency_only": True}},
     PROFILE_DEFECT),
    ("composition-defect",
     {"attribution": {"composition_findings": (
         "generated bridge drops paddr[12] for the second instance",)}},
     COMPOSITION_DEFECT),
    ("software-or-model-defect",
     {"attribution": {"software_or_model_findings": (
         "the checker reads the wrong register offset",)}},
     SOFTWARE_OR_MODEL_DEFECT),
    ("observation-insufficient-no-criterion", {"criteria": ()},
     OBSERVATION_INSUFFICIENT),
    ("observation-insufficient-no-observation",
     {"results": (_result(observations={}),)}, OBSERVATION_INSUFFICIENT),
    ("undiagnosed-missing-identity",
     {"identity": _identity(rendered_top_hash="")}, UNDIAGNOSED),
    ("undiagnosed-missing-tool-identity",
     {"identity": _identity(tool={"simulator": "verilator",
                                  "executable_hash": "missing"})}, UNDIAGNOSED),
    ("undiagnosed-missing-boot-image-hash",
     {"identity": _identity(boot_image_hash="none")}, UNDIAGNOSED),
    ("undiagnosed-missing-legality-field",
     {"legality": _without(_legality(), "monitor_results")}, UNDIAGNOSED),
    ("undiagnosed-legality-unavailable",
     {"legality": _legality(state=LEGALITY_UNAVAILABLE)}, UNDIAGNOSED),
    ("undiagnosed-identity-conflict",
     {"identity": _identity(layout_hash="9" * 64)}, UNDIAGNOSED),
    ("undiagnosed-policy-layout-conflict",
     {"identity": _identity(policy={"policy_hash": _digest("e"), "drive_profile": "cpu_execute",
                                    "profile_version": 1, "layout_hash": "9" * 64,
                                    "plan_hash": _digest("a"), "rule_count": 1, "rules": []})},
     UNDIAGNOSED),
    ("undiagnosed-no-anomaly", {"anomaly": _anomaly(present=False)}, UNDIAGNOSED),
    ("undiagnosed-not-reproduced", {"anomaly": _anomaly(reproducible=False)},
     UNDIAGNOSED),
    ("undiagnosed-basis-not-independent",
     {"anomaly": _anomaly(basis_independent=False)}, UNDIAGNOSED),
    ("undiagnosed-self-consistency-only",
     {"attribution": {"self_consistency_only": True}}, UNDIAGNOSED),
)

#: Every way the component gate can be starved, one at a time.
INCOMPLETE: tuple[tuple[str, dict[str, object]], ...] = (
    *((f"identity:{name}", {"identity": _without(_identity(), name)})
      for name in REQUIRED_IDENTITY),
    *((f"legality:{name}", {"legality": _without(_legality(), name)})
      for name in REQUIRED_LEGALITY),
    ("criterion-absent", {"criteria": ()}),
    ("observation-absent", {"results": (_result(observations={}),)}),
    ("anomaly-absent", {"anomaly": _anomaly(present=False)}),
    ("anomaly-without-criterion", {"anomaly": _anomaly(criterion="")}),
    ("anomaly-without-basis", {"anomaly": _anomaly(basis="")}),
    ("anomaly-not-reproduced", {"anomaly": _anomaly(reproducible=False)}),
    ("anomaly-basis-not-independent", {"anomaly": _anomaly(basis_independent=False)}),
    ("self-consistency-only", {"attribution": {"self_consistency_only": True}}),
    ("legality-violated", {"legality": _legality(state="violated")}),
    ("legality-unavailable", {"legality": _legality(state=LEGALITY_UNAVAILABLE)}),
    ("identity-conflict", {"identity": _identity(layout_hash="9" * 64)}),
    ("policy-identity-conflict",
     {"identity": _identity(policy={"policy_hash": _digest("e"), "drive_profile": "cpu_execute",
                                    "profile_version": 1, "layout_hash": "9" * 64,
                                    "plan_hash": _digest("a"), "rule_count": 1, "rules": []})}),
)


class BoundaryClassificationTests(unittest.TestCase):
    """Every branch of the classification, and the gate that guards it."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-evidence-", dir=ROOT)
        self.directory = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_every_documented_branch_classifies_as_the_plan_names_it(self) -> None:
        for label, overrides, expected in CASES:
            with self.subTest(case=label):
                package = _package(**overrides)
                classification, reason = classify_boundary(package)
                self.assertEqual(expected, classification, reason)
                self.assertIn(classification, BOUNDARY_CLASSES)
                self.assertTrue(reason, "every classification states its reason")

    def test_the_case_table_covers_every_boundary_class(self) -> None:
        self.assertEqual(set(BOUNDARY_CLASSES),
                         {expected for _, _, expected in CASES})

    def test_a_complete_package_passes_the_component_gate(self) -> None:
        ready, reason = component_candidate_ready(_package())
        self.assertTrue(ready, reason)
        self.assertEqual("", reason)

    def test_the_component_gate_rejects_every_single_missing_prerequisite(self) -> None:
        for label, overrides in INCOMPLETE:
            with self.subTest(missing=label):
                package = _package(**overrides)
                ready, reason = component_candidate_ready(package)
                self.assertFalse(ready, f"{label} still passed the gate")
                self.assertTrue(reason)
                classification, _ = classify_boundary(package)
                self.assertNotEqual(COMPONENT_CANDIDATE, classification,
                                    f"{label} was classified as a component defect")

    def test_a_dut_looking_anomaly_without_legality_evidence_is_not_a_defect(self) -> None:
        """The plan's ``通过条件``: missing legality evidence cannot confirm a bug."""
        package = _package(legality=_legality(state=LEGALITY_UNAVAILABLE))
        classification, reason = classify_boundary(package)
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("environment-legality-unavailable", reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)

    def test_an_identity_conflict_names_the_field_it_conflicts_on(self) -> None:
        package = _package(identity=_identity(layout_hash="9" * 64))
        classification, reason = classify_boundary(package)
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("layout_hash", reason)

    def test_a_stored_classification_cannot_override_the_evidence(self) -> None:
        package = _package(legality=_legality(state=LEGALITY_UNAVAILABLE),
                           classification=(COMPONENT_CANDIDATE, "trust me"))
        write_evidence_package(package, self.directory)
        read_back = read_evidence_package(self.directory)
        self.assertEqual(UNDIAGNOSED, read_back.classification[0])
        self.assertIn("legality", read_back.classification[1])

    def test_the_package_round_trips_through_its_document(self) -> None:
        package = _package()
        write_evidence_package(package, self.directory)
        read_back = read_evidence_package(self.directory)
        self.assertEqual(package.document(), read_back.document())
        self.assertEqual(package.samples[0]["raw"], list(read_back.sample().raw))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real evidence build")
class FailureEvidenceRealBuildTests(unittest.TestCase):
    """The real example build: attribution gate and counterexample shrinking."""

    #: Sixteen cycles where only the last one requests the two applied values, so
    #: the only one-cycle witness of "event_i = 0xf and pin_mode_i = 0x7 applied"
    #: is the single word 0x7f.
    MINIMIZE_RAW = tuple([0x00] * 15 + [0x7F])
    ONE_CYCLE_RAW = (0x7F,)

    @classmethod
    def setUpClass(cls):
        if shutil.which("verilator") is None:
            raise AssertionError("MYFUZZ_SOC_REAL=1 requires Verilator for the evidence build")
        cls.plan = example_plan()
        cls.build = runtime_build()
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.sample = RuntimeSample(request_id=0x5A17, raw=cls.ONE_CYCLE_RAW)
        cls.result = run_sample(cls.build, cls.sample)
        # A second real run of the same saved input: this is what backs the
        # "reproducible" claim below, and it is asserted rather than assumed.
        cls.repeat = run_sample(cls.build, cls.sample)

    def test_a_dut_looking_anomaly_keeps_its_boundary_without_legality_evidence(self) -> None:
        """The same anomaly, with and without the environment's legality record.

        No fault is injected anywhere: the observed value is the real observation
        of the real run, and the criterion is the caller's declared expectation
        (the CPU reaching the poll state inside a one-cycle window), which the
        run does not meet.  What is under test is the evidence gate, not a
        manufactured DUT bug.
        """
        self.assertEqual(self.result.document(), self.repeat.document())
        observed = self.result.observations["cpu0__status_o"]
        self.assertNotEqual(3, observed)
        anomaly = {
            "present": True,
            "kind": "declared-expectation-mismatch",
            "criterion": "cpu0 reaches ST_POLL (status_o == 3) within one cycle",
            "basis": "examples/soc_generation/rtl/novacore.sv boot state machine, read "
                     "independently of the generated software",
            "basis_independent": True,
            "reproducible": True,
            "expected": 3,
            "observed": observed,
            "first_divergence": {"cycle": 0, "field": "observation:cpu0__status_o",
                                 "kind": "observation"},
        }
        bare = build_evidence_package(self.plan, self.build, self.policy, [self.result],
                                      kind="dut_anomaly", samples=[self.sample],
                                      criteria=[_CRITERION], anomaly=anomaly)
        classification, reason = classify_boundary(bare)
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("environment-legality-unavailable", reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)

        legality = applied_legality(self.build, self.sample, self.result)
        self.assertEqual("confirmed", legality["environment_legality"], legality)
        confirmed = build_evidence_package(self.plan, self.build, self.policy, [self.result],
                                           kind="dut_anomaly", samples=[self.sample],
                                           criteria=[_CRITERION], legality=legality,
                                           anomaly=anomaly)
        classification, reason = classify_boundary(confirmed)
        self.assertEqual(COMPONENT_CANDIDATE, classification, reason)
        self.assertIn("cycle=0", reason)

    def test_a_legality_violation_is_attributed_to_the_driver_not_the_dut(self) -> None:
        legality = applied_legality(self.build, self.sample, self.result)
        legality["driver_violations"] = ["special-input-hold: value changed without a request"]
        package = build_evidence_package(self.plan, self.build, self.policy, [self.result],
                                         kind="driver_anomaly", samples=[self.sample],
                                         criteria=[_CRITERION], legality=legality,
                                         anomaly=_anomaly())
        classification, reason = classify_boundary(package)
        self.assertEqual(DRIVER_VIOLATION, classification)
        self.assertIn("special-input-hold", reason)

    def test_the_minimizer_shrinks_to_the_one_cycle_witness(self) -> None:
        sample = RuntimeSample(request_id=0x5A18, raw=self.MINIMIZE_RAW)

        def predicate(result) -> bool:
            return (result.status == "OK"
                    and result.observations.get("cpu0__event_i__applied") == 0x0F
                    and result.observations.get("gpio0__pin_mode_i__applied") == 0x07)

        minimal, log = minimize_sample(self.build, sample, predicate=predicate)
        self.assertEqual(self.ONE_CYCLE_RAW, minimal.raw)
        self.assertEqual("fixed_point", log["stopped"])
        self.assertTrue(log["preserved"])
        self.assertEqual(len(self.MINIMIZE_RAW), log["original"]["words"])
        self.assertEqual(1, log["minimal"]["words"])
        self.assertEqual(len(self.MINIMIZE_RAW) - 1, log["removed_words"])
        self.assertGreaterEqual(log["candidates"], 1)
        self.assertGreaterEqual(log["accepted"], 1)
        self.assertEqual(log["steps"], len(log["history"]))
        self.assertFalse(log["history_truncated"])
        # The recorded final replay is a real run of the minimal witness.
        again = run_sample(self.build, minimal)
        self.assertEqual(0x0F, again.observations["cpu0__event_i__applied"])
        self.assertEqual(0x07, again.observations["gpio0__pin_mode_i__applied"])
        self.assertEqual({str(key): int(value) for key, value in again.observations.items()},
                         {str(key): int(value)
                          for key, value in log["final_replay"]["observations"].items()})

    def test_the_minimizer_stops_at_the_budget_and_says_so(self) -> None:
        sample = RuntimeSample(request_id=0x5A19, raw=self.MINIMIZE_RAW)

        def predicate(result) -> bool:
            return result.observations.get("cpu0__event_i__applied") == 0x0F

        minimal, log = minimize_sample(self.build, sample, predicate=predicate, budget=1)
        self.assertEqual("budget", log["stopped"])
        self.assertEqual(1, log["candidates"])
        # original check + one search candidate + the final verification run
        self.assertEqual(3, log["steps"])
        self.assertLess(len(minimal.raw), len(self.MINIMIZE_RAW))
        self.assertGreater(len(minimal.raw), 1)
        self.assertTrue(log["preserved"])

    def test_a_predicate_the_original_does_not_satisfy_is_reported(self) -> None:
        sample = RuntimeSample(request_id=0x5A1A, raw=self.MINIMIZE_RAW)
        minimal, log = minimize_sample(self.build, sample, predicate=lambda result: False)
        self.assertEqual(sample, minimal)
        self.assertEqual("predicate-false-on-original", log["stopped"])
        self.assertFalse(log["preserved"])
        self.assertEqual(0, log["candidates"])
        self.assertEqual(1, log["steps"])

    def test_a_predicate_that_stops_holding_is_reported_not_hidden(self) -> None:
        sample = RuntimeSample(request_id=0x5A1C, raw=self.ONE_CYCLE_RAW)
        calls = {"count": 0}

        def predicate(result) -> bool:
            calls["count"] += 1
            return calls["count"] <= 1

        minimal, log = minimize_sample(self.build, sample, predicate=predicate)
        self.assertFalse(log["preserved"],
                         "an unstable predicate must not be presented as preserved")
        self.assertEqual(self.ONE_CYCLE_RAW, minimal.raw)
        self.assertEqual(3, log["steps"])  # original check, one zeroing try, final check

    def test_the_minimizer_validates_its_caller(self) -> None:
        sample = RuntimeSample(request_id=0x5A1B, raw=self.MINIMIZE_RAW)
        with self.assertRaises(SocFailureEvidenceError) as caught:
            minimize_sample(self.build, sample, predicate=lambda result: True, budget=0)
        self.assertIn("minimize-budget-out-of-bounds", str(caught.exception))
        with self.assertRaises(SocFailureEvidenceError) as caught:
            minimize_sample(self.build, sample, predicate="not-callable")  # type: ignore[arg-type]
        self.assertIn("minimize-requires-a-callable-predicate", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
