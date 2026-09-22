"""Step 6C replay: a saved raw input really re-runs, and divergence is located.

The dependency replay this phase requires is not "run it again and see whether it
exits zero".  The package carries the identity of the plan, the layout, every
component profile, the compiled constraint policy, the rendered top, the
testbench, the build, the boot image and the runtime/tool that produced the
observation; the replay re-runs the *saved* raw words through the same
executable and compares the applied stimulus cycle by cycle, then the
observations.  A deliberately altered saved word must be reported at the cycle
and field it was altered in, a package saved under an older layout must be
refused instead of silently re-interpreted, and ``run_sample_with_policy`` must
refuse a rule set whose layout/plan identity is not the one the build recorded.

``MYFUZZ_SOC_REAL=1`` gates the real build (Verilator + the example
composition), following ``tests/integration/test_soc_matrix_runtime.py``: when
the flag is set nothing here skips, and a missing dependency is a failure naming
it.  The build is cached under ``runs/soc-dependency-replay/<plan-prefix>/`` so a
repeated run re-executes the binary instead of recompiling it.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from myfuzz.composition.input_constraints import (
    compile_input_constraints,
    compile_rules,
)
from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    EVIDENCE_DOCUMENT,
    RAW_INPUT_DIRECTORY,
    RAW_INPUT_INDEX,
    REPLAY_AGREEMENT,
    REPLAY_DIVERGENCE,
    REPLAY_REFUSED,
    UNDIAGNOSED,
    build_evidence_package,
    classify_boundary,
    read_evidence_package,
    recorded_build_identity,
    replay_package,
    tool_identity,
    write_evidence_package,
)
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RuntimeBuild,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
    run_sample_with_policy,
)

from tests.composition.soc_generation_fixture import ROOT, example_plan

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
CACHE_ROOT = ROOT / "runs/soc-dependency-replay"

#: One request whose words differ per cycle, so the applied trace has a value per
#: cycle and a mutated word is visible at a named cycle.
SAMPLE_REQUEST_ID = 0x6C0DE
SAMPLE_RAW = (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B)
MUTATED_CYCLE = 5
MUTATED_VALUE = 0x7F

#: The judgement basis a criterion needs.  It is *not* the profile that generated
#: the stimulus alone: the driver's own RTL is cited as the independent half.
CRITERION = {
    "criterion_id": "special-input-applied-within-one-cycle",
    "statement": "a declared special input is applied to the component within one "
                 "cycle of its request and holds until the next request",
    "basis": "src/myfuzz/protocols/rtl/soc_special_input_driver.sv (independent RTL) "
             "checked against examples/soc_generation/rtl/novacore.sv",
    "independent": True,
}

_BUILD_CACHE: dict[str, RuntimeBuild] = {}


def _recorded_path(output: Path, value: object) -> Path:
    """Resolve one path from a build record against the build directory.

    The record stores paths relative to ``output_dir`` (the executable lives
    under ``obj_dir``), so joining is enough.  A record written by an older
    revision stored the bare basename of a binary that is really in ``obj_dir``;
    that form is only accepted when the plain join does not exist, so a legacy
    record cannot make this cache silently replay nothing.
    """
    candidate = output / str(value)
    if candidate.exists():
        return candidate
    nested = output / "obj_dir" / str(value)
    return nested if nested.exists() else candidate


def _build_from_document(document: dict) -> RuntimeBuild:
    output = Path(document["output_dir"])
    boot = document.get("boot_image")
    return RuntimeBuild(
        output_dir=output,
        top_path=_recorded_path(output, document["top"]),
        testbench_path=_recorded_path(output, document["testbench"]),
        executable=_recorded_path(output, document["executable"]),
        sources=tuple(str(item) for item in document.get("sources", ())),
        raw_width=int(document["raw_width"]),
        slots=tuple(dict(item) for item in document.get("slots", ())),
        observations=tuple(dict(item) for item in document.get("observations", ())),
        boot_image=None if boot is None else output / str(boot),
        boot_image_policy=str(document.get("boot_image_policy", "")),
        build_hash=str(document["build_hash"]),
        warnings=int(document.get("warnings", 0)),
    )


def runtime_build() -> RuntimeBuild:
    """The real example-composition runtime, built once and then re-used.

    The cache directory is keyed by the plan hash, and the cached record is only
    accepted when its plan hash, its recorded layout hash and its executable all
    still match; anything else is rebuilt from scratch instead of being replayed
    against a stale binary.
    """
    plan = example_plan()
    key = str(plan.plan_hash).split(":", 1)[-1][:12]
    if key in _BUILD_CACHE:
        return _BUILD_CACHE[key]
    directory = CACHE_ROOT / key
    record = directory / "runtime_build.json"
    if record.is_file():
        try:
            document = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            document = {}
        build_document = document.get("build")
        if isinstance(build_document, dict) and document.get("plan_hash") == plan.plan_hash:
            build = _build_from_document(build_document)
            if build.executable.is_file() and build.top_path.is_file() \
                    and build.testbench_path.is_file():
                recorded = recorded_build_identity(build)
                if recorded["plan_hash"] == plan.plan_hash \
                        and recorded["layout_hash"] == str(plan.raw_layout["layout_hash"]):
                    _BUILD_CACHE[key] = build
                    return build
    if directory.exists():
        shutil.rmtree(directory)
    files = render_composition(plan)
    sources = [str(item["path"]) for item in source_list(plan)]
    build = build_profile_runtime(plan, output_dir=directory, base_dir=ROOT,
                                  top_text=files["myfuzz_soc_top.sv"], sources=sources)
    record.write_text(json.dumps({"plan_hash": plan.plan_hash, "build": build.document()},
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _BUILD_CACHE[key] = build
    return build


def applied_legality(build: RuntimeBuild, sample: RuntimeSample,
                     result) -> dict[str, object]:
    """Confirm, from the run itself, that the environment applied what it asked.

    The generated top exports ``<slot>__applied`` for every declared special
    input, so the driver's real output can be compared with the raw field that
    requested it instead of being assumed.  A mismatch is recorded as a driver
    violation, which is what keeps it out of the component's column.
    """
    final = int(sample.raw[-1])
    checks = []
    violations = []
    for slot in build.slots:
        width = int(slot["width"])
        requested = (final >> int(slot["raw_lo"])) & ((1 << width) - 1)
        observed = result.observations.get(f"{slot['name']}__applied")
        held = observed == requested
        checks.append({"monitor": "applied-special-input-matches-request",
                       "port": str(slot["name"]), "cycle": len(sample.raw) - 1,
                       "requested": requested, "observed": observed,
                       "result": "pass" if held else "fail"})
        if not held:
            violations.append(f"{slot['name']}: requested {requested} observed {observed}")
    return {
        "environment_legality": "confirmed" if not violations else "violated",
        "driver_violations": violations,
        "constraint_rejections": [],
        "monitor_results": checks,
        "notes": ["checked against the applied value the DUT exported for the last cycle"],
    }


class RuntimePolicyBindingTests(unittest.TestCase):
    """The policy/build identity check, without needing Verilator.

    A build's recorded identity lives in the generated testbench it wrote, so the
    refusal paths can be exercised with a two-line record instead of a compile.
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-policy-", dir=ROOT)
        self.directory = Path(self._temporary.name)
        self.plan_hash = "sha256:" + "1" * 64
        self.layout_hash = "2" * 64
        self.build = self._fake_build(plan_hash=self.plan_hash, layout_hash=self.layout_hash)
        self.policy = compile_rules([], drive_profile="cpu_execute",
                                    layout_hash=self.layout_hash, plan_hash=self.plan_hash)
        self.sample = RuntimeSample(request_id=1, raw=SAMPLE_RAW)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _fake_build(self, *, plan_hash: str, layout_hash: str) -> RuntimeBuild:
        testbench = self.directory / "profile_tb.sv"
        testbench.write_text(
            "// Generated by myfuzz profile runtime. Do not edit.\n"
            f"// plan: {plan_hash}\n"
            f"// raw-input layout: {layout_hash}\n"
            "module myfuzz_profile_tb;\nendmodule\n", encoding="utf-8")
        return RuntimeBuild(
            output_dir=self.directory,
            top_path=self.directory / "myfuzz_soc_top.sv",
            testbench_path=testbench,
            executable=self.directory / "myfuzz_profile_sim",
            sources=(), raw_width=7, slots=(), observations=(),
            boot_image=None, boot_image_policy="no_preloaded_region",
            build_hash="sha256:" + "3" * 64, warnings=0)

    def test_the_build_record_is_read_from_the_generated_testbench(self) -> None:
        recorded = recorded_build_identity(self.build)
        self.assertEqual(self.plan_hash, recorded["plan_hash"])
        self.assertEqual(self.layout_hash, recorded["layout_hash"])

    def test_a_policy_without_a_policy_hash_is_refused(self) -> None:
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(self.build, self.sample,
                                   policy=dataclasses.replace(self.policy, policy_hash=""))
        self.assertIn("policy-hash-missing", str(caught.exception))

    def test_a_policy_from_an_older_layout_is_refused(self) -> None:
        stale = compile_rules([], drive_profile="cpu_execute",
                              layout_hash="f" * 64, plan_hash=self.plan_hash)
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(self.build, self.sample, policy=stale)
        message = str(caught.exception)
        self.assertIn("policy-layout-mismatch", message)
        self.assertIn("f" * 64, message)
        self.assertIn(self.layout_hash, message)

    def test_a_policy_from_an_older_plan_is_refused(self) -> None:
        stale = compile_rules([], drive_profile="cpu_execute",
                              layout_hash=self.layout_hash, plan_hash="sha256:" + "e" * 64)
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(self.build, self.sample, policy=stale)
        self.assertIn("policy-plan-mismatch", str(caught.exception))

    def test_a_build_without_a_readable_record_is_refused(self) -> None:
        broken = dataclasses.replace(self.build, testbench_path=self.directory / "absent.sv")
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(broken, self.sample, policy=self.policy)
        self.assertIn("runtime-build-record-unreadable", str(caught.exception))

    def test_the_tool_identity_records_an_unavailable_probe_honestly(self) -> None:
        record = tool_identity(self.build, probe=False)
        self.assertEqual("verilator", record["simulator"])
        self.assertEqual("unavailable", record["verilator"])
        self.assertIn("unavailable", str(record["provenance"]))
        # The fake build has no compiled binary, and the record says so rather
        # than claiming an identity it cannot produce.
        self.assertEqual("missing", record["executable_hash"])

    def test_a_failing_tool_probe_is_recorded_as_unavailable(self) -> None:
        bin_dir = self.directory / "bin"
        bin_dir.mkdir()
        probe = bin_dir / "verilator"
        probe.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        probe.chmod(0o755)
        with unittest.mock.patch.dict(os.environ, {"PATH": bin_dir.as_posix()}):
            record = tool_identity(self.build)
        self.assertEqual("unavailable", record["verilator"])
        self.assertIn("probe-returncode=1", str(record["provenance"]))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real dependency replay")
class DependencyReplayTests(unittest.TestCase):
    """Real replay of one saved sample on the example composition."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("verilator") is None:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires Verilator for the dependency replay")
        cls.plan = example_plan()
        cls.build = runtime_build()
        cls.policy = compile_input_constraints(cls.plan, drive_profile="cpu_execute")
        cls.sample = RuntimeSample(request_id=SAMPLE_REQUEST_ID, raw=SAMPLE_RAW)
        cls.result = run_sample(cls.build, cls.sample)
        cls.temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-soc-replay-", dir=ROOT)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)

    def package(self, **overrides):
        arguments = {
            "kind": "dependency_replay",
            "samples": [self.sample],
            "criteria": [CRITERION],
            "legality": applied_legality(self.build, self.sample, self.result),
        }
        results = overrides.pop("results", [self.result])
        arguments.update(overrides)
        return build_evidence_package(self.plan, self.build, self.policy,
                                      results, **arguments)

    # -- identity ---------------------------------------------------------

    def test_the_package_binds_every_identity_step_9_requires(self) -> None:
        package = self.package()
        identity = package.identity
        for name in ("plan_hash", "layout_hash", "profile_hashes", "policy_hash",
                     "rendered_top_hash", "testbench_hash", "build_hash",
                     "boot_image_hash", "isa", "runtime", "tool"):
            with self.subTest(field=name):
                self.assertTrue(identity.get(name), f"{name} is not bound")
        self.assertEqual(self.plan.plan_hash, identity["plan_hash"])
        self.assertEqual(str(self.plan.raw_layout["layout_hash"]), identity["layout_hash"])
        self.assertEqual(self.policy.policy_hash, identity["policy_hash"])
        self.assertEqual(self.build.build_hash, identity["build_hash"])
        # Every profile that produced this plan is identified by content, not by
        # the file name it happened to be loaded from.
        self.assertEqual({"novacore", "novagpio", "novauart"},
                         set(identity["profile_hashes"]))
        for record in identity["profile_hashes"].values():
            self.assertTrue(record["content_hash"])
            self.assertTrue(record["binding_hashes"])
        self.assertEqual("riscv", identity["isa"]["family"])
        self.assertEqual(32, identity["isa"]["xlen"])
        self.assertEqual(self.build.build_hash, identity["build_hash"])
        self.assertNotEqual("missing", identity["runtime"]["executable_hash"])
        self.assertTrue(identity["tool"]["simulator"])

    def test_the_package_saves_the_compiled_constraint_list(self) -> None:
        package = self.package()
        record = package.identity["policy"]
        self.assertEqual(self.policy.policy_hash, record["policy_hash"])
        self.assertEqual(len(self.policy.rules), record["rule_count"])
        self.assertEqual([rule.rule_id for rule in self.policy.rules],
                         [item["rule_id"] for item in record["rules"]])
        self.assertEqual(sorted({rule.category for rule in self.policy.rules}),
                         sorted({item["category"] for item in record["rules"]}))
        self.assertTrue(any(item["category"] == "environment_hard"
                            for item in record["rules"]))
        self.assertTrue(all(item["checker"] for item in record["rules"]))
        # The capability gaps the policy reports are part of the record too, so
        # a package never implies more coverage than the rules can give.
        self.assertEqual(list(self.policy.gaps), record["gaps"])
        self.assertTrue(record["gaps"])

    def test_a_saved_run_replays_and_agrees_twice(self) -> None:
        package = self.package()
        document = write_evidence_package(package, self.directory)
        self.assertTrue(document.is_file())
        self.assertEqual(EVIDENCE_DOCUMENT, document.name)
        read_back = read_evidence_package(self.directory)
        self.assertEqual(package.document(), read_back.document())
        self.assertEqual(SAMPLE_RAW, tuple(read_back.sample().raw))
        first = replay_package(package, self.build)
        second = replay_package(read_back, self.build)
        for label, replay in (("in-memory", first), ("read-back", second)):
            with self.subTest(package=label):
                self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
                self.assertTrue(replay.agreed)
                self.assertIsNone(replay.divergence)
                self.assertFalse(replay.mismatching_fields)
                self.assertEqual(1, len(replay.reruns))
                self.assertIn("observation:cpu0__status_o", replay.matching_fields)
                self.assertIn("trace[0].raw", replay.matching_fields)

    def test_a_document_that_disagrees_with_its_raw_archive_is_detected(self) -> None:
        package = self.package()
        document_path = write_evidence_package(package, self.directory)
        document = json.loads(document_path.read_text(encoding="utf-8"))
        document["samples"][0]["raw"][MUTATED_CYCLE] = MUTATED_VALUE
        document_path.write_text(json.dumps(document), encoding="utf-8")
        # The archive file itself is untouched, so its hash still matches the
        # index; only the document disagrees, and that must be caught too.
        with self.assertRaises(ValueError) as caught:
            read_evidence_package(self.directory)
        self.assertIn("raw-input-document-mismatch", str(caught.exception))

    def test_two_samples_replay_with_per_sample_labels(self) -> None:
        second = RuntimeSample(request_id=SAMPLE_REQUEST_ID + 1, raw=(0x7F, 0x00, 0x11))
        second_result = run_sample(self.build, second)
        # No legality record here on purpose: this test is about the comparison
        # being per sample, and legality would have to cover both samples.
        package = self.package(samples=[self.sample, second],
                               results=[self.result, second_result], legality=None)
        replay = replay_package(package, self.build)
        self.assertEqual(REPLAY_AGREEMENT, replay.status, replay.reason)
        self.assertIn("sample0:trace[0].raw", replay.matching_fields)
        self.assertIn("sample1:trace[2].raw", replay.matching_fields)
        self.assertEqual(2, len(replay.reruns))

    def test_a_deliberately_altered_saved_input_diverges_at_a_named_cycle(self) -> None:
        package = self.package()
        samples = list(package.samples)
        raw = list(samples[0]["raw"])
        self.assertEqual(0x05, raw[MUTATED_CYCLE])
        raw[MUTATED_CYCLE] = MUTATED_VALUE
        samples[0] = dict(samples[0], raw=raw)
        altered = dataclasses.replace(package, samples=tuple(samples))
        directory = self.directory / "altered"
        write_evidence_package(altered, directory)
        read_back = read_evidence_package(directory)
        self.assertEqual(MUTATED_VALUE, read_back.sample().raw[MUTATED_CYCLE])
        replay = replay_package(read_back, self.build)
        self.assertEqual(REPLAY_DIVERGENCE, replay.status)
        self.assertIsNotNone(replay.divergence)
        self.assertEqual(MUTATED_CYCLE, replay.divergence["cycle"])
        self.assertEqual("raw", replay.divergence["field"])
        self.assertEqual("applied-stimulus", replay.divergence["kind"])
        self.assertEqual(0x05, replay.divergence["expected"])
        self.assertEqual(MUTATED_VALUE, replay.divergence["observed"])
        self.assertIn("trace[5].raw", replay.mismatching_fields)
        self.assertNotIn("trace[4].raw", replay.mismatching_fields)
        self.assertEqual(1, len(replay.reruns))

    def test_a_package_saved_under_an_older_layout_is_refused(self) -> None:
        """Step 6C's legacy negative: old layout/rule versions must be refused."""
        package = self.package()
        legacy = dataclasses.replace(package, identity=dict(
            package.identity, layout_hash="3" * 64,
            policy=dict(package.identity["policy"], layout_hash="3" * 64)))
        directory = self.directory / "legacy"
        write_evidence_package(legacy, directory)
        replay = replay_package(read_evidence_package(directory), self.build)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("layout_hash", replay.reason)
        self.assertIn("3" * 64, replay.reason)
        self.assertIsNone(replay.divergence)
        self.assertFalse(replay.reruns)
        classification, reason = classify_boundary(read_evidence_package(directory))
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("identity-conflict:layout_hash", reason)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)

    def test_a_build_that_is_not_the_one_saved_is_refused(self) -> None:
        package = self.package()
        other = dataclasses.replace(self.build, build_hash="sha256:" + "9" * 64)
        replay = replay_package(package, other)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("build_hash", replay.reason)

    def test_the_raw_input_archive_is_byte_exact_and_tamper_evident(self) -> None:
        package = self.package()
        write_evidence_package(package, self.directory)
        index = json.loads((self.directory / RAW_INPUT_INDEX).read_text(encoding="utf-8"))
        entry = index["samples"][0]
        payload = (self.directory / entry["file"]).read_text(encoding="utf-8")
        self.assertEqual(self.sample.payload(), payload)
        self.assertEqual(RAW_INPUT_DIRECTORY, Path(entry["file"]).parent.as_posix())
        # A hand-edited archive must be detected, not replayed.
        tampered = Path(entry["file"])
        text = (self.directory / tampered).read_text(encoding="utf-8")
        edited = text.replace("\n5\n", "\n7f\n")
        self.assertNotEqual(text, edited)
        (self.directory / tampered).write_text(edited, encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            read_evidence_package(self.directory)
        self.assertIn("tampered", str(caught.exception))

    def test_a_package_without_the_saved_event_plan_is_refused(self) -> None:
        """A trace has the raw words but not the event plan, so it cannot replay."""
        package = self.package(samples=None)
        self.assertFalse(package.inputs_complete)
        self.assertEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB],
                         list(package.sample().raw))
        replay = replay_package(package, self.build)
        self.assertEqual(REPLAY_REFUSED, replay.status)
        self.assertIn("event plan is unknown", replay.reason)
        self.assertFalse(replay.reruns)

    def test_a_clean_run_is_never_a_component_candidate(self) -> None:
        package = self.package()
        classification, reason = classify_boundary(package)
        self.assertNotEqual(COMPONENT_CANDIDATE, classification)
        self.assertEqual(UNDIAGNOSED, classification)
        self.assertIn("no-anomaly-recorded", reason)

    def test_run_sample_with_policy_applies_sample_constraints_to_raw_trace(self) -> None:
        slot = self.build.slots[0]
        lo, hi = int(slot["raw_lo"]), int(slot["raw_hi"])
        rule = {"rule_id": "value:sample", "category": "environment_hard",
                "owner": "environment", "primitive": "value_enum", "phase": "sample",
                "fields": [str(slot["name"])], "write_set": [str(slot["name"])],
                "raw_bits": [[lo, hi]], "parameters": [["values", [1]]]}
        policy = compile_rules([rule], drive_profile="cpu_execute",
                               layout_hash=self.policy.layout_hash, plan_hash=self.plan.plan_hash)
        bound = run_sample_with_policy(self.build, self.sample, policy=policy)
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        expected = tuple((value & ~mask) | (1 << lo) for value in self.sample.raw)
        self.assertEqual(expected, tuple(item["raw"] for item in bound.trace))
        self.assertNotEqual(self.sample.raw, expected)

    def test_run_sample_with_policy_refuses_a_stale_rule_set(self) -> None:
        stale = compile_rules([], drive_profile="cpu_execute",
                              layout_hash="4" * 64, plan_hash=self.plan.plan_hash)
        with self.assertRaises(SocRuntimeError) as caught:
            run_sample_with_policy(self.build, self.sample, policy=stale)
        self.assertIn("policy-layout-mismatch", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
