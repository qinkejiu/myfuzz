"""File-identity binding for the offline component confirmation entry point."""
from __future__ import annotations

import dataclasses
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    classify_boundary,
)
from myfuzz.composition.soc_runtime import RuntimeBuild
from myfuzz.composition.soc_runtime import RunResult
from myfuzz.composition.soc_failure_evidence import ReplayResult

from tests.integration.test_soc_failure_evidence import _package
from tests.composition.soc_generation_fixture import example_plan


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class OfflineBuildBindingTests(unittest.TestCase):
    def _criterion(self) -> dict[str, object]:
        text = "independent SPI wire-level requirement"
        return {"criterion_id": "spi-mosi-byte", "expected": [3], "observed": [2],
                "independent_of_profile": True, "specification_text": text,
                "specification_hash": "sha256:" +
                hashlib.sha256(text.encode("utf-8")).hexdigest()}

    def _build(self, root: Path, name: str, *, component: bytes,
               extra: bytes = b"module peer; endmodule\n") -> RuntimeBuild:
        directory = root / name
        directory.mkdir()
        top = directory / "top.sv"
        testbench = directory / "tb.sv"
        boot = directory / "boot.hex"
        executable = directory / "sim"
        source = directory / "component.sv"
        peer = directory / "peer.sv"
        top.write_bytes(b"module top; endmodule\n")
        testbench.write_text("// plan: sha256:" + "a" * 64 + "\n"
                            "// raw-input layout: " + "b" * 64 + "\n",
                            encoding="utf-8")
        boot.write_bytes(b"00\n")
        executable.write_bytes(b"simulator\n")
        source.write_bytes(component)
        peer.write_bytes(extra)
        sources = (source.relative_to(root).as_posix(), peer.relative_to(root).as_posix())
        return RuntimeBuild(
            output_dir=directory, top_path=top, testbench_path=testbench,
            executable=executable, sources=sources, raw_width=7, slots=(),
            observations=(), boot_image=boot, boot_image_policy="external_image",
            build_hash="sha256:" + "1" * 64,
            source_hashes={item: _hash(root / item) for item in sources},
        )

    def _candidate(self, mutant: RuntimeBuild):
        package = _package()
        identity = dict(package.identity)
        identity.update({
            "rendered_top_hash": _hash(mutant.top_path),
            "testbench_hash": _hash(mutant.testbench_path),
            "boot_image_hash": _hash(mutant.boot_image),
            "build_hash": mutant.build_hash,
            "recorded_build_identity": {"plan_hash": "sha256:" + "a" * 64,
                                        "layout_hash": "b" * 64},
        })
        runtime = dict(identity["runtime"])
        runtime.update({"raw_width": mutant.raw_width,
                        "executable_hash": _hash(mutant.executable),
                        "sources": list(mutant.sources),
                        "source_hashes": dict(mutant.source_hashes)})
        identity["runtime"] = runtime
        anomaly = dict(package.anomaly)
        anomaly.update({"criterion": "spi-mosi-byte", "expected": [3], "observed": [2]})
        return dataclasses.replace(package, identity=identity, anomaly=anomaly)

    def _plan(self):
        # These legacy gate tests deliberately use synthetic hashes and files.
        # The real plan derivation is exercised separately below and in real RTL.
        validation = patch("myfuzz.composition.soc_offline_defect_confirmation._derived_plan_problem",
                           return_value=None)
        validation.start()
        self.addCleanup(validation.stop)
        plan = example_plan()
        return dataclasses.replace(plan, plan_hash="sha256:" + "a" * 64,
                                   raw_layout={**plan.raw_layout, "layout_hash": "b" * 64})

    def test_audit_plan_fields_are_rederived_even_when_stored_hashes_match(self):
        from myfuzz.composition.soc_offline_defect_confirmation import _plan_identity_problem

        plan = example_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            for build in (baseline, mutant):
                build.testbench_path.write_text(
                    f"// plan: {plan.plan_hash}\n"
                    f"// raw-input layout: {plan.raw_layout['layout_hash']}\n")
            package = self._candidate(mutant)
            package = dataclasses.replace(package, identity={
                **package.identity, "plan_hash": plan.plan_hash,
                "layout_hash": plan.raw_layout["layout_hash"]})
            self.assertIsNone(_plan_identity_problem(plan, baseline, mutant, package))
            for field, value in (("target_records", ()), ("cpu_inputs", ()),
                                 ("cpu_adapter", {}), ("interrupt_document", {}),
                                 ("interrupt_plan", None),
                                 ("instances", ()), ("plan", {}), ("spec", {}),
                                 ("synthetic", {"forged": True}),
                                 ("peers", ("forged",))):
                with self.subTest(field=field):
                    forged = dataclasses.replace(plan, **{field: value})
                    self.assertNotEqual(getattr(plan, field), value)
                    self.assertEqual("derived-plan:" + field,
                                     _plan_identity_problem(forged, baseline, mutant, package))

    def test_rebuild_preserves_automatic_empty_boot_policy(self):
        from myfuzz.composition.soc_offline_defect_confirmation import _rebuild_pair
        from myfuzz.composition.soc_runtime import build_profile_runtime

        plan = example_plan()
        root_dir = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "verilator"
            tool.write_text("fake compiler")

            # Only compilation is replaced: policy selection and metadata use the real API.
            def compile_fake(command, **kwargs):
                output = Path(command[command.index("--Mdir") + 1])
                output.mkdir(parents=True, exist_ok=True)
                (output / "myfuzz_profile_sim").write_text("fake executable")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("myfuzz.composition.soc_runtime.subprocess.run", side_effect=compile_fake):
                original = build_profile_runtime(
                    plan, output_dir=root / "original", base_dir=root_dir,
                    top_text="module myfuzz_soc_top; endmodule", sources=(),
                    verilator=str(tool))
                self.assertEqual("explicit_empty_image_no_program_loaded", original.boot_image_policy)
                baseline, mutant, _ = _rebuild_pair(
                    plan, original, original, base_dir=root_dir,
                    output_dir=root / "rebuilt", timeout_seconds=10, verilator=str(tool))
            for rebuilt in (baseline, mutant):
                self.assertEqual(original.boot_image_policy, rebuilt.boot_image_policy)
                self.assertEqual(original.build_hash, rebuilt.build_hash)
                self.assertEqual(_hash(original.boot_image), _hash(rebuilt.boot_image))

    def test_include_closure_drift_is_rejected_between_rebuilds(self):
        from myfuzz.composition.soc_offline_defect_confirmation import _rebuild_pair

        for change in ("modify", "add", "delete", "symlink"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                include = root / "includes"
                include.mkdir()
                header = include / "constants.svh"
                header.write_text("`define VALUE 1\n")
                plan = example_plan()
                instance = plan.instances[0]
                source = dataclasses.replace(instance.profile.source, source_root=str(root),
                                             include_roots=("includes",))
                instance = dataclasses.replace(instance, profile=dataclasses.replace(
                    instance.profile, source=source))
                plan = dataclasses.replace(plan, instances=(instance,))
                baseline = self._build(root, "baseline", component=b"baseline")
                mutant = self._build(root, "mutant", component=b"mutant")
                tool = root / "verilator"
                tool.write_text("fake compiler")

                calls = []

                def build_fake(*args, **kwargs):
                    calls.append(kwargs)
                    if len(calls) > 1:
                        return mutant
                    if change == "modify":
                        header.write_text("`define VALUE 2\n")
                    elif change == "add":
                        (include / "new.svh").write_text("added")
                    elif change == "delete":
                        header.unlink()
                    else:
                        (include / "escape").symlink_to(root, target_is_directory=True)
                    return baseline

                with patch("myfuzz.composition.soc_offline_defect_confirmation.build_profile_runtime",
                           side_effect=build_fake) as build:
                    with self.assertRaisesRegex(ValueError, "include-"):
                        _rebuild_pair(plan, baseline, mutant, base_dir=root,
                                      output_dir=root / "rebuilt", timeout_seconds=10,
                                      verilator=str(tool))
                    self.assertEqual(1, build.call_count)

    def test_explicit_include_roots_are_checked_between_and_during_mutant_build(self):
        from myfuzz.composition import soc_offline_defect_confirmation as offline

        for timing in ("between", "mutant", "stable"):
            with self.subTest(timing=timing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                include = root / "wrapper-includes"
                include.mkdir()
                header = include / "not-in-sources.svh"
                header.write_text("original")
                baseline = self._build(root, "baseline", component=b"baseline")
                mutant = self._build(root, "mutant", component=b"mutant")
                plan = dataclasses.replace(example_plan(), instances=())
                tool = root / "verilator"
                tool.write_text("fake compiler")
                source_checks = []
                real_source_bytes = offline._source_bytes

                def source_check(*args):
                    result = real_source_bytes(*args)
                    source_checks.append(args)
                    if timing == "between" and len(source_checks) == 2:
                        header.write_text("changed after baseline post-build inventory")
                    return result

                def build_fake(*args, **kwargs):
                    if kwargs["output_dir"].name == "mutant":
                        if timing == "mutant":
                            header.write_text("changed during mutant compilation")
                        return mutant
                    return baseline

                with patch.object(offline, "_source_bytes", side_effect=source_check), \
                        patch.object(offline, "build_profile_runtime", side_effect=build_fake) as build:
                    options = dict(base_dir=root, output_dir=root / "rebuilt",
                                   timeout_seconds=10, verilator=str(tool),
                                   include_roots=("wrapper-includes",))
                    if timing == "stable":
                        _, _, record = offline._rebuild_pair(plan, baseline, mutant, **options)
                        self.assertEqual([str(include)], record["include_manifest"]["roots"])
                        self.assertEqual(2, record["include_manifest"]["entries"])
                    else:
                        with self.assertRaisesRegex(ValueError, "mutant-include-input-drift"):
                            offline._rebuild_pair(plan, baseline, mutant, **options)
                    self.assertEqual(1 if timing == "between" else 2, build.call_count)

    def test_include_manifest_rejects_symlinks_special_files_and_missing_roots(self):
        from myfuzz.composition.soc_offline_defect_confirmation import _include_manifest
        import os

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declared = root / "declared"
            declared.mkdir()
            with self.assertRaisesRegex(ValueError, "include-root-missing"):
                _include_manifest((root / "missing",))
            link = declared / "escape"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "include-symlink"):
                _include_manifest((declared,))
            with self.assertRaisesRegex(ValueError, "include-symlink"):
                _include_manifest((link,))
            link.unlink()
            os.mkfifo(declared / "fifo")
            with self.assertRaisesRegex(ValueError, "include-symlink-or-special-file"):
                _include_manifest((declared,))

    def test_non_candidate_is_returned_unchanged(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = dataclasses.replace(
                self._candidate(mutant),
                attribution={"composition_findings": ["bad connection"]},
            )
            confirmation = confirm_component_offline(
                package, plan=object(), baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        expected_status, expected_reason = classify_boundary(package)
        self.assertEqual(COMPOSITION_DEFECT, expected_status)
        self.assertEqual(expected_status, confirmation.status)
        self.assertEqual(expected_reason, confirmation.reason)

    def test_build_differential_uses_fresh_file_bytes(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import build_differential

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            expected_removed = _hash(root / "baseline" / "component.sv")
            baseline = dataclasses.replace(
                baseline,
                source_hashes={name: "sha256:" + "0" * 64 for name in baseline.sources},
            )
            differential = build_differential(baseline, mutant, base_dir=root)
        self.assertTrue(differential["top_equal"])
        self.assertTrue(differential["testbench_equal"])
        self.assertTrue(differential["boot_equal"])
        self.assertIn(expected_removed, differential["removed_source_hashes"])
        self.assertEqual(1, len(differential["removed_source_hashes"]))
        self.assertEqual(1, len(differential["added_source_hashes"]))

    def test_mismatched_mutant_top_hash_is_undiagnosed_with_exact_reason(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            identity = dict(package.identity)
            identity["rendered_top_hash"] = "sha256:" + "f" * 64
            expected_reason = (
                "mutant-identity:rendered_top_hash:saved=sha256:" + "f" * 64
                + ":build=" + _hash(mutant.top_path)
            )
            confirmation = confirm_component_offline(
                dataclasses.replace(package, identity=identity),
                plan=object(), baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertEqual("undiagnosed", confirmation.status)
        self.assertEqual(expected_reason, confirmation.reason)

    def test_two_changed_sources_remain_component_candidates_with_exact_reason(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline", extra=b"old peer")
            mutant = self._build(root, "mutant", component=b"mutant", extra=b"new peer")
            confirmation = confirm_component_offline(
                self._candidate(mutant), plan=object(), baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertEqual(COMPONENT_CANDIDATE, confirmation.status)
        self.assertEqual("source-differential-not-single", confirmation.reason)

    def test_forged_runtime_raw_width_is_undiagnosed(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            identity = dict(package.identity)
            runtime = dict(identity["runtime"])
            runtime["raw_width"] = mutant.raw_width + 1
            identity["runtime"] = runtime
            confirmation = confirm_component_offline(
                dataclasses.replace(package, identity=identity), plan=object(),
                baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertEqual("undiagnosed", confirmation.status)
        self.assertEqual(
            f"mutant-identity:runtime.raw_width:saved={mutant.raw_width + 1}:"
            f"build={mutant.raw_width}",
            confirmation.reason,
        )

    def test_forged_runtime_source_hashes_are_undiagnosed(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            identity = dict(package.identity)
            runtime = dict(identity["runtime"])
            hashes = dict(runtime["source_hashes"])
            hashes[mutant.sources[0]] = "sha256:" + "f" * 64
            runtime["source_hashes"] = hashes
            identity["runtime"] = runtime
            confirmation = confirm_component_offline(
                dataclasses.replace(package, identity=identity), plan=object(),
                baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertEqual("undiagnosed", confirmation.status)
        self.assertEqual("mutant-identity:runtime.source_hashes:mismatch", confirmation.reason)

    def test_unknown_criterion_cannot_confirm(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            package = dataclasses.replace(package, anomaly={**package.anomaly,
                                                               "criterion": "criterion-1"})
            result = confirm_component_offline(
                package, plan=object(), baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component"),
                criterion={**self._criterion(), "criterion_id": "criterion-1"}, base_dir=root)
        self.assertEqual(COMPONENT_CANDIDATE, result.status)
        self.assertEqual("unsupported-criterion:criterion-1", result.reason)

    def test_plan_hash_and_layout_must_match_recorded_builds(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            criterion = self._criterion()
            base_plan = self._plan()
            for plan, reason in (
                (dataclasses.replace(base_plan, plan_hash="sha256:" + "c" * 64),
                 "plan-identity:plan_hash"),
                (dataclasses.replace(base_plan,
                                     raw_layout={**base_plan.raw_layout,
                                                 "layout_hash": "c" * 64}),
                 "plan-identity:layout_hash"),
            ):
                with self.subTest(reason=reason):
                    result = confirm_component_offline(
                        package, plan=plan, baseline=baseline, mutant=mutant,
                        fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component"),
                        criterion=criterion, base_dir=root)
                    self.assertEqual("undiagnosed", result.status)
                    self.assertEqual(reason, result.reason)

    def test_non_string_source_hash_key_is_rejected(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            identity = dict(package.identity)
            runtime = dict(identity["runtime"])
            runtime["source_hashes"] = {1: next(iter(mutant.source_hashes.values()))}
            identity["runtime"] = runtime
            result = confirm_component_offline(
                dataclasses.replace(package, identity=identity), plan=object(),
                baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component"),
                criterion=self._criterion(), base_dir=root)
        self.assertEqual("undiagnosed", result.status)
        self.assertEqual("mutant-identity:runtime.source_hashes:malformed", result.reason)

    def test_saved_runtime_fields_are_individually_bound(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            for field, forged in (("schema_version", "legacy"),
                                  ("sources", ["forged.sv"]),
                                  ("boot_image_policy", "forged")):
                with self.subTest(field=field):
                    identity = dict(package.identity)
                    runtime = dict(identity["runtime"])
                    runtime[field] = forged
                    identity["runtime"] = runtime
                    result = confirm_component_offline(
                        dataclasses.replace(package, identity=identity), plan=self._plan(),
                        baseline=baseline, mutant=mutant,
                        fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component"),
                        criterion=self._criterion(), base_dir=root)
                    self.assertEqual("undiagnosed", result.status)
                    self.assertEqual(f"mutant-identity:runtime.{field}:mismatch", result.reason)

    def test_rebuilt_runtime_interpretation_fields_are_individually_bound(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import _build_metadata_problem
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._build(root, "original", component=b"component")
            for field, forged in (
                ("raw_width", 8), ("slots", ({"name": "forged"},)),
                ("observations", ({"name": "forged"},)),
                ("peer_slots", ({"slot": "forged"},)),
                ("peer_observations", ({"name": "forged"},)),
                ("peer_wires", ({"name": "forged"},)),
                ("spi_wire_contracts", {"spi0": {"txdata_address": 0}}),
                ("cpu_data_sources", (7,)),
                ("build_hash", "sha256:" + "f" * 64),
            ):
                with self.subTest(field=field):
                    rebuilt = dataclasses.replace(original, **{field: forged})
                    self.assertEqual(f"baseline-rebuilt-{field}-mismatch",
                                     _build_metadata_problem(original, rebuilt, "baseline"))

    def test_missing_runtime_source_identity_is_undiagnosed(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            identity = dict(package.identity)
            runtime = dict(identity["runtime"])
            del runtime["source_hashes"]
            identity["runtime"] = runtime
            confirmation = confirm_component_offline(
                dataclasses.replace(package, identity=identity), plan=object(),
                baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertEqual("undiagnosed", confirmation.status)
        self.assertEqual("mutant-identity:runtime.source_hashes:missing", confirmation.reason)

    def test_reruns_and_independent_spi_gates_reject_each_invalid_evidence_kind(self) -> None:
        """Task-2 gates must derive every conclusion from fresh tool results."""
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )

        def result(*, wire_status: str, observed: object, truncated: bool = False) -> RunResult:
            return RunResult(
                request_id=1, cycles=4, status="OK", counters={}, observations={"observed": 1},
                trace=(), applied=(), stdout="", stderr="",
                peer_applied=({"cycle": 0, "instance": "spi0", "slot": "spi.arm_byte",
                               "value": 3},),
                peer_wire_trace=({"cycle": 1, "instance_id": "spi0", "mosi": "1"},),
                peer_wire_status=({"instance_id": "spi0", "count": 1,
                                   "truncated": truncated},),
                requests=({"cycle": 0, "addr": 0x1008, "write": 1, "wdata": 3,
                           "be": 15, "source": 0},), requests_truncated=truncated,
                peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                          "status": wire_status,
                                          "expected": {"mosi": [3], "miso": [0]},
                                          "observed": {"mosi": observed, "miso": [0]}},)},
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            package = self._candidate(mutant)
            fixture = IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv")
            agreement = ReplayResult(status="agreement", reason="same saved input")
            audit_pass = {"summary": {"status": "pass", "passed": 2, "failed": 0}}

            cases = (
                ("replay-divergence", ReplayResult(status="divergence", reason="changed"),
                 result(wire_status="pass", observed=[3]), result(wire_status="mismatch", observed=[2]),
                 audit_pass, audit_pass, "replay-not-agreement"),
                ("audit-failure", agreement, result(wire_status="pass", observed=[3]),
                 result(wire_status="mismatch", observed=[2]),
                 {"summary": {"status": "fail", "passed": 1, "failed": 1}}, audit_pass,
                 "baseline-structure-audit-failed"),
                ("audit-invalid", agreement, result(wire_status="pass", observed=[3]),
                 result(wire_status="mismatch", observed=[2]), {}, audit_pass,
                 "baseline-structure-audit-invalid"),
                ("baseline-spi-mismatch", agreement, result(wire_status="mismatch", observed=[3]),
                 result(wire_status="mismatch", observed=[2]), audit_pass, audit_pass,
                 "baseline-spi-wire:mismatch"),
                ("mutant-spi-pass", agreement, result(wire_status="pass", observed=[3]),
                 result(wire_status="pass", observed=[2]), audit_pass, audit_pass,
                 "mutant-spi-wire:pass"),
                ("truncated", agreement, result(wire_status="pass", observed=[3], truncated=True),
                 result(wire_status="mismatch", observed=[2]), audit_pass, audit_pass,
                 "baseline-run-incomplete"),
                ("wrong-mosi", agreement, result(wire_status="pass", observed=[3]),
                 result(wire_status="mismatch", observed=[1]), audit_pass, audit_pass,
                 "mutant-spi-observed"),
            )
            for name, replay, baseline_result, mutant_result, baseline_audit, mutant_audit, reason in cases:
                with self.subTest(name=name), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.replay_package",
                           return_value=replay), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.run_sample",
                           side_effect=(baseline_result, mutant_result)), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.audit_structure",
                           side_effect=(baseline_audit, mutant_audit)), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation._rebuild_pair",
                           return_value=(baseline, mutant, {"sha256": "test-tool"})):
                    confirmation = confirm_component_offline(
                        dataclasses.replace(package, results=(mutant_result.document(),)),
                        plan=self._plan(), baseline=baseline, mutant=mutant,
                        fixture=fixture, criterion=self._criterion(), base_dir=root,
                    )
                expected_status = (COMPOSITION_DEFECT if name == "audit-failure" else
                                   "undiagnosed" if name == "audit-invalid" else
                                   COMPONENT_CANDIDATE)
                self.assertEqual(expected_status, confirmation.status)
                self.assertEqual(reason, confirmation.reason)

    def test_rebuilt_mutant_must_match_every_saved_replay_field(self) -> None:
        from myfuzz.composition import soc_offline_defect_confirmation as offline

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            fixture = root / "fixture.sv"
            fixture.write_text("module tb; endmodule")
            baseline_result = RunResult(1, 4, "OK", {}, {"observed": 999}, (), (), "", "",
                peer_oracle={"status": "pass", "oracle_hash": "baseline-oracle",
                             "checks": [{"check_id": "spi-transfer-wire", "status": "pass",
                                         "expected": {"mosi": [3], "miso": [0]},
                                         "observed": {"mosi": [3], "miso": [0]}}]})
            mutant_result = dataclasses.replace(baseline_result, peer_oracle={
                "status": "mismatch", "oracle_hash": "mutant-oracle",
                "checks": [{"check_id": "spi-transfer-wire", "status": "mismatch",
                            "expected": {"mosi": [3], "miso": [0]},
                            "observed": {"mosi": [2], "miso": [0]}}]})
            cases = (
                ("observations", {"observed": 1}, "observation:observed"),
                ("trace", [{"cycle": 0, "raw": 1}], "trace[0].raw"),
                ("applied_trace", [{"cycle": 0, "port": "pin", "value": 1}], "applied[0].pin"),
                ("peer_applied", [{"cycle": 0, "instance": "spi0", "slot": "arm", "value": 3}],
                 "peer_applied[0].spi0.arm.value"),
                ("peer_wire_trace", [{"cycle": 0, "instance_id": "spi0", "sck": 1,
                                      "cs": 0, "mosi": 1, "miso": 0}], "peer_wire[0].spi0.sck"),
                ("peer_wire_status", [{"instance_id": "spi0", "count": 1, "truncated": False}],
                 "peer_wire_status:spi0:count"),
                ("fabric_requests", [{"cycle": 0, "addr": 4096, "write": 1, "wdata": 3,
                                      "be": 15, "source": 0}], "fabric_request[0].0x1000.wdata"),
                ("fabric_requests_truncated", True, "fabric_requests_truncated"),
                ("image_placements", [{"slot": "boot", "kind": "ram", "addr": 0,
                                       "readback": 1, "reset_held": True}], "image_placement[ram].boot.readback"),
                ("image_errors", [{"slot": "boot", "reason": "refused"}], "image_error[0].boot"),
                ("counters", {"irq": 1}, "counter:irq"),
                ("peer_oracle", {**mutant_result.peer_oracle, "oracle_hash": "different"}, "peer_oracle:hash"),
                ("peer_oracle", {**mutant_result.peer_oracle, "status": "different"}, "peer_oracle:status"),
                ("status", "TIMEOUT", "status"), ("cycles", 5, "cycles"),
            )
            for field, value, label in cases:
                package = dataclasses.replace(self._candidate(mutant), results=(
                    {**mutant_result.document(), field: value},))
                with self.subTest(field=label), \
                        patch.object(offline, "replay_package", return_value=ReplayResult("agreement", "original agrees")), \
                        patch.object(offline, "_rebuild_pair", return_value=(baseline, mutant, {})), \
                        patch.object(offline, "run_sample", side_effect=(baseline_result, mutant_result)), \
                        patch.object(offline, "audit_structure", return_value={"summary": {"status": "pass"}}), \
                        patch.object(offline, "run_isolation", return_value={
                            "fixture_hash": _hash(fixture),
                            "baseline_source_hash": baseline.source_hashes[baseline.sources[0]],
                            "mutant_source_hash": mutant.source_hashes[mutant.sources[0]],
                            "baseline": {"observation": {"bits": 8, "mosi": 3}},
                            "mutant": {"observation": {"bits": 8, "mosi": 2}}}) as isolation:
                    result = offline.confirm_component_offline(
                        package, plan=self._plan(), baseline=baseline, mutant=mutant,
                        fixture=offline.IsolationFixture(fixture, "tb", "OBS", "component"),
                        criterion=self._criterion(), base_dir=root)
                    self.assertEqual(COMPONENT_CANDIDATE, result.status)
                    self.assertEqual("rebuilt-mutant-replay-not-agreement", result.reason)
                    comparison = result.evidence["rebuilt_mutant_replay"]
                    self.assertIn(label, comparison["mismatching_fields"])
                    self.assertIsNotNone(comparison["divergence"])
                    if field == "observations":
                        self.assertEqual(1, comparison["divergence"]["expected"])
                        self.assertEqual(999, comparison["divergence"]["observed"])
                    if field == "peer_wire_trace":
                        for wire in ("sck", "cs", "mosi", "miso"):
                            self.assertIn(f"peer_wire[0].spi0.{wire}",
                                          comparison["mismatching_fields"])
                    isolation.assert_not_called()

    def test_positive_reruns_are_real_and_record_audits_and_hashes(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            fixture_path = root / "fixture.sv"
            def fresh_copy(original: RuntimeBuild, side: str) -> RuntimeBuild:
                directory = root / f"rebuilt-{side}"
                directory.mkdir()
                for path in (original.top_path, original.testbench_path, original.boot_image):
                    shutil.copy2(path, directory / path.name)
                executable = directory / "sim"
                executable.write_bytes(f"fresh-{side}".encode())
                return dataclasses.replace(
                    original, output_dir=directory, top_path=directory / original.top_path.name,
                    testbench_path=directory / original.testbench_path.name,
                    boot_image=directory / original.boot_image.name, executable=executable)
            fresh_baseline = fresh_copy(baseline, "baseline")
            fresh_mutant = fresh_copy(mutant, "mutant")
            baseline.executable.write_bytes(b"substituted-original-baseline")
            substituted_baseline_hash = _hash(baseline.executable)
            fixture_path.write_text("module tb; endmodule\n", encoding="utf-8")
            fixture_hash = _hash(fixture_path)
            replacement_fixture_hash = "sha256:" + hashlib.sha256(
                b"module tb; // replacement\nendmodule\n").hexdigest()
            baseline_top_hash = _hash(baseline.top_path)
            mutant_top_hash = _hash(mutant.top_path)
            baseline_top_text = baseline.top_path.read_text(encoding="utf-8")
            mutant_top_text = mutant.top_path.read_text(encoding="utf-8")
            package = self._candidate(mutant)
            baseline_result = RunResult(1, 4, "OK", {}, {"observed": 1}, (), (), "", "",
                peer_applied=({"cycle": 0, "instance": "spi0", "slot": "spi.arm_byte", "value": 3},),
                peer_wire_trace=({"cycle": 1, "instance_id": "spi0", "mosi": "1"},),
                peer_wire_status=({"instance_id": "spi0", "count": 1, "truncated": False},),
                requests=({"cycle": 0, "addr": 0x1008, "write": 1, "wdata": 3, "be": 15, "source": 0},),
                peer_oracle={"checks": ({"check_id": "spi-transfer-wire", "status": "pass",
                                          "expected": {"mosi": [3], "miso": [0]},
                                          "observed": {"mosi": [3], "miso": [0]}},)})
            mutant_result = dataclasses.replace(
                baseline_result, peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                                            "status": "mismatch",
                                                            "expected": {"mosi": [3], "miso": [0]},
                                                            "observed": {"mosi": [2], "miso": [0]}},)})
            package = dataclasses.replace(package, results=(mutant_result.document(),))
            audit = {"summary": {"status": "pass", "passed": 2, "failed": 0}}
            def isolated(bits: int, baseline_mosi: int, mutant_mosi: int) -> dict[str, object]:
                return {"fixture_hash": fixture_hash,
                        "baseline_source_hash": baseline.source_hashes[baseline.sources[0]],
                        "mutant_source_hash": mutant.source_hashes[mutant.sources[0]],
                        "baseline": {"observation": {"bits": bits, "mosi": baseline_mosi}},
                        "mutant": {"observation": {"bits": bits, "mosi": mutant_mosi}}}
            with patch("myfuzz.composition.soc_offline_defect_confirmation.replay_package",
                       return_value=ReplayResult(status="agreement", reason="same")) as replay, \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.run_sample",
                       side_effect=(baseline_result, mutant_result) * 5) as rerun, \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.audit_structure",
                       side_effect=(audit, audit) * 5) as structural, \
                 patch("myfuzz.composition.soc_offline_defect_confirmation._rebuild_pair",
                       return_value=(fresh_baseline, fresh_mutant,
                                     {"sha256": "test-tool"})), \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.run_isolation",
                       side_effect=(
                           isolated(8, 3, 2), isolated(7, 3, 2), isolated(9, 3, 2),
                           isolated(8, 2, 2),
                           {**isolated(8, 3, 2), "fixture_hash": replacement_fixture_hash},
                       )) as isolation:
                plan = self._plan()
                include_roots = ("include-a", "include-b")
                confirmation = confirm_component_offline(
                    package, plan=plan, baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(fixture_path, "tb", "OBS", "component"),
                    criterion=self._criterion(), base_dir=root, include_roots=include_roots,
                    timeout_seconds=17,
                )
                seven_bits = confirm_component_offline(
                    package, plan=plan, baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(fixture_path, "tb", "OBS", "component"),
                    criterion=self._criterion(), base_dir=root, include_roots=include_roots,
                    timeout_seconds=17,
                )
                nine_bits = confirm_component_offline(
                    package, plan=plan, baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(fixture_path, "tb", "OBS", "component"),
                    criterion=self._criterion(), base_dir=root, include_roots=include_roots,
                    timeout_seconds=17,
                )
                wrong_both_sides = confirm_component_offline(
                    package, plan=plan, baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(fixture_path, "tb", "OBS", "component"),
                    criterion=self._criterion(), base_dir=root, include_roots=include_roots,
                    timeout_seconds=17,
                )
                fixture_path.write_text("module tb; // replacement\nendmodule\n", encoding="utf-8")
                changed_confirmation = confirm_component_offline(
                    package, plan=plan, baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(fixture_path, "tb", "OBS", "component"),
                    criterion=self._criterion(), base_dir=root, include_roots=include_roots,
                    timeout_seconds=17,
                )
        self.assertEqual("component_confirmed", confirmation.status)
        self.assertEqual("offline-isolation-confirmed", confirmation.reason)
        self.assertEqual("agreement", confirmation.evidence["rebuilt_mutant_replay"]["status"])
        self.assertEqual(self._criterion(), confirmation.evidence["criterion"])
        for side in ("baseline", "mutant"):
            self.assertIn(side + "_build_hashes", confirmation.evidence)
            hashes = confirmation.evidence[side + "_build_hashes"]
            self.assertEqual({"top", "testbench", "boot_image", "executable"}, set(hashes))
            self.assertTrue(all(value.startswith("sha256:") or value == "none"
                                for value in hashes.values()))
            self.assertIn(side + "_source_hashes", confirmation.evidence)
        self.assertEqual("isolation-bits-invalid", seven_bits.reason)
        self.assertEqual("isolation-bits-invalid", nine_bits.reason)
        self.assertEqual("isolation-baseline-observation", wrong_both_sides.reason)
        self.assertEqual(10, rerun.call_count)
        self.assertEqual(10, structural.call_count)
        self.assertEqual(5, replay.call_count)
        self.assertEqual(((fresh_baseline, package.sample()), {"timeout_seconds": 17}),
                         rerun.call_args_list[0])
        self.assertEqual(((fresh_mutant, package.sample()), {"timeout_seconds": 17}),
                         rerun.call_args_list[1])
        self.assertNotEqual(baseline.executable, fresh_baseline.executable)
        self.assertNotEqual(substituted_baseline_hash,
                            confirmation.evidence["rebuilt_baseline_build_hashes"]["executable"])
        self.assertEqual("unverified-not-used-for-differential",
                         confirmation.evidence.get("original_baseline_executable_provenance"))
        self.assertEqual(((plan,), {"top_text": baseline_top_text,
                                    "source_files": baseline.sources, "base_dir": root,
                                    "include_roots": include_roots}), structural.call_args_list[0])
        self.assertEqual(((plan,), {"top_text": mutant_top_text,
                                    "source_files": mutant.sources, "base_dir": root,
                                    "include_roots": include_roots}), structural.call_args_list[1])
        self.assertEqual(baseline_top_hash, confirmation.evidence["baseline_top_hash"])
        self.assertEqual(mutant_top_hash, confirmation.evidence["mutant_top_hash"])
        self.assertEqual(fixture_hash, confirmation.evidence["fixture_hash"])
        self.assertNotEqual(fixture_hash, changed_confirmation.evidence["fixture_hash"])
        self.assertEqual(5, isolation.call_count)
        args, kwargs = isolation.call_args_list[0]
        self.assertEqual((IsolationFixture(fixture_path, "tb", "OBS", "component"),), args)
        self.assertEqual(root / baseline.sources[0], kwargs["baseline_source"])
        self.assertEqual(root / mutant.sources[0], kwargs["mutant_source"])
        self.assertEqual(17, kwargs["timeout_seconds"])
        self.assertEqual("isolation", kwargs["output_dir"].name)

    def test_spi_wire_verdict_requires_one_independent_check(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import spi_wire_verdict
        clean = RunResult(1, 1, "OK", {}, {}, (), (), "", "",
                          peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                                    "status": "pass",
                                                    "expected": {"mosi": [1], "miso": [0]},
                                                    "observed": {"mosi": [1], "miso": [0]}},)})
        self.assertEqual(("pass", [1], [1]), spi_wire_verdict(clean))
        self.assertEqual(("not_assessed", None, None),
                         spi_wire_verdict(dataclasses.replace(clean, peer_oracle={"checks": ()})))
        for malformed in ({"checks": "not-a-sequence"},
                          {"checks": ["not-a-check"]},
                          {"checks": [{"check_id": "spi-transfer-wire",
                                       "expected": "not-a-mapping", "observed": {}}]}):
            with self.subTest(malformed=malformed):
                self.assertEqual(("not_assessed", None, None),
                                 spi_wire_verdict(dataclasses.replace(clean,
                                                                       peer_oracle=malformed)))

    def test_tool_failure_has_stable_reason_and_keeps_details_in_evidence(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            with patch("myfuzz.composition.soc_offline_defect_confirmation.replay_package",
                       side_effect=TimeoutError("simulator host detail")):
                confirmation = confirm_component_offline(
                    self._candidate(mutant), plan=self._plan(), baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                    criterion=self._criterion(), base_dir=root,
                )
        self.assertEqual("undiagnosed", confirmation.status)
        self.assertEqual("offline-rerun-tool-failure", confirmation.reason)
        self.assertEqual({"type": "TimeoutError", "detail": "simulator host detail"},
                         confirmation.evidence["offline_rerun_error"])

    def test_isolation_runner_compiles_immutable_input_snapshots(self) -> None:
        """Both compiler invocations must consume the bytes named by evidence."""
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, run_isolation,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bench = root / "fixture.sv"
            baseline = root / "baseline.sv"
            mutant = root / "mutant.sv"
            original_fixture = b"original fixture\n"
            original_baseline = b"original baseline\n"
            original_mutant = b"original mutant\n"
            bench.write_bytes(original_fixture)
            baseline.write_bytes(original_baseline)
            mutant.write_bytes(original_mutant)
            compiler_inputs: list[tuple[bytes, bytes]] = []

            def fake_run(argv, **_kwargs):
                if argv[0] == "/tools/iverilog":
                    compiler_inputs.append((Path(argv[-2]).read_bytes(), Path(argv[-1]).read_bytes()))
                    if len(compiler_inputs) == 1:
                        bench.write_bytes(b"replaced fixture\n")
                        mutant.write_bytes(b"replaced mutant\n")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                output = "MYFUZZ_FIXTURE bits=8 mosi=" + ("3" if "baseline" in argv[1] else "2")
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch("myfuzz.composition.soc_offline_defect_confirmation.shutil.which",
                       side_effect=("/tools/iverilog", "/tools/vvp")), \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.subprocess.run",
                       side_effect=fake_run):
                result = run_isolation(
                    IsolationFixture(bench, "fixture_tb", "MYFUZZ_FIXTURE", "component"),
                    baseline_source=baseline, mutant_source=mutant,
                    output_dir=root / "output", timeout_seconds=10)
        self.assertEqual([(original_fixture, original_baseline),
                          (original_fixture, original_mutant)], compiler_inputs)
        self.assertEqual("sha256:" + hashlib.sha256(original_fixture).hexdigest(),
                         result["fixture_hash"])

    def test_isolation_observation_rejects_malformed_numeric_fields(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import _isolation_observation

        for line in ("OBS bits=8 mosi=wat", "OBS bits=eight mosi=3"):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "isolation-baseline-marker-malformed"):
                    _isolation_observation(line, "OBS", "baseline")


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"),
                     "Icarus Verilog and vvp are required")
class IsolationFixtureTests(unittest.TestCase):
    def _fixture_files(self, root: Path, *, baseline_value: int = 3,
                       mutant_value: int = 2, marker: str = "MYFUZZ_FIXTURE"):
        bench = root / "fixture.sv"
        baseline = root / "component-baseline.sv"
        mutant = root / "component-mutant.sv"
        bench.write_text(
            "module fixture_tb; integer value; initial begin value = component_value(); "
            f'$display("{marker} bits=8 mosi=%0h", value); $finish; end endmodule\n',
            encoding="utf-8")
        baseline.write_text(f"function integer component_value; component_value = {baseline_value}; endfunction\n",
                            encoding="utf-8")
        mutant.write_text(f"function integer component_value; component_value = {mutant_value}; endfunction\n",
                          encoding="utf-8")
        return bench, baseline, mutant

    def test_runner_recompiles_sources_and_parses_one_marker(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, run_isolation,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bench, baseline, mutant = self._fixture_files(root)
            result = run_isolation(
                IsolationFixture(bench, "fixture_tb", "MYFUZZ_FIXTURE", "component"),
                baseline_source=baseline, mutant_source=mutant, output_dir=root / "output",
                timeout_seconds=10)
        self.assertEqual({"bits": 8, "mosi": 3}, result["baseline"]["observation"])
        self.assertEqual({"bits": 8, "mosi": 2}, result["mutant"]["observation"])

    def test_runner_rejects_missing_or_duplicate_marker_compile_failure_and_timeout(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, run_isolation,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bench, baseline, mutant = self._fixture_files(root)
            fixture = IsolationFixture(bench, "fixture_tb", "MYFUZZ_FIXTURE", "component")
            for name, text, expected in (
                ("missing", "module fixture_tb; initial begin $finish; end endmodule\n", "marker-missing"),
                ("duplicate", "module fixture_tb; initial begin $display(\"MYFUZZ_FIXTURE bits=8 mosi=3\"); $display(\"MYFUZZ_FIXTURE bits=8 mosi=3\"); $finish; end endmodule\n", "marker-duplicate"),
                ("compile", "not valid verilog", "compile-failed"),
            ):
                bench.write_text(text, encoding="utf-8")
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ValueError, expected):
                        run_isolation(fixture, baseline_source=baseline, mutant_source=mutant,
                                      output_dir=root / name, timeout_seconds=10)
            bench.write_text("module fixture_tb; initial begin #100; $finish; end endmodule\n",
                            encoding="utf-8")
            with self.assertRaisesRegex(TimeoutError, "isolation-baseline-timeout"):
                run_isolation(fixture, baseline_source=baseline, mutant_source=mutant,
                              output_dir=root / "timeout", timeout_seconds=0.001)


if __name__ == "__main__":
    unittest.main()
