"""File-identity binding for the offline component confirmation entry point."""
from __future__ import annotations

import dataclasses
import hashlib
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


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class OfflineBuildBindingTests(unittest.TestCase):
    def _criterion(self) -> dict[str, object]:
        text = "independent SPI wire-level requirement"
        return {"criterion_id": "criterion-1", "expected": 3, "observed": 2,
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
                        "source_hashes": dict(mutant.source_hashes)})
        identity["runtime"] = runtime
        return dataclasses.replace(package, identity=identity)

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
                request_id=1, cycles=4, status="OK", counters={}, observations={},
                trace=(), applied=(), stdout="", stderr="",
                peer_applied=({"cycle": 0, "instance": "spi0", "slot": "spi.arm_byte",
                               "value": 3},),
                peer_wire_trace=({"cycle": 1, "instance_id": "spi0", "mosi": "1"},),
                peer_wire_status=({"instance_id": "spi0", "count": 1,
                                   "truncated": truncated},),
                requests=({"cycle": 0, "addr": 0x1008, "write": 1, "wdata": 3,
                           "be": 15, "source": 0},), requests_truncated=truncated,
                peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                          "status": wire_status, "expected": 3,
                                          "observed": observed},)},
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
                 result(wire_status="pass", observed=3), result(wire_status="mismatch", observed=2),
                 audit_pass, audit_pass, "replay-not-agreement"),
                ("audit-failure", agreement, result(wire_status="pass", observed=3),
                 result(wire_status="mismatch", observed=2),
                 {"summary": {"status": "fail", "passed": 1, "failed": 1}}, audit_pass,
                 "baseline-structure-audit-failed"),
                ("audit-invalid", agreement, result(wire_status="pass", observed=3),
                 result(wire_status="mismatch", observed=2), {}, audit_pass,
                 "baseline-structure-audit-invalid"),
                ("baseline-spi-mismatch", agreement, result(wire_status="mismatch", observed=3),
                 result(wire_status="mismatch", observed=2), audit_pass, audit_pass,
                 "baseline-spi-wire:mismatch"),
                ("mutant-spi-pass", agreement, result(wire_status="pass", observed=3),
                 result(wire_status="pass", observed=2), audit_pass, audit_pass,
                 "mutant-spi-wire:pass"),
                ("truncated", agreement, result(wire_status="pass", observed=3, truncated=True),
                 result(wire_status="mismatch", observed=2), audit_pass, audit_pass,
                 "baseline-run-incomplete"),
                ("wrong-mosi", agreement, result(wire_status="pass", observed=3),
                 result(wire_status="mismatch", observed=1), audit_pass, audit_pass,
                 "mutant-spi-observed"),
            )
            for name, replay, baseline_result, mutant_result, baseline_audit, mutant_audit, reason in cases:
                with self.subTest(name=name), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.replay_package",
                           return_value=replay), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.run_sample",
                           side_effect=(baseline_result, mutant_result)), \
                     patch("myfuzz.composition.soc_offline_defect_confirmation.audit_structure",
                           side_effect=(baseline_audit, mutant_audit)):
                    confirmation = confirm_component_offline(
                        package, plan=object(), baseline=baseline, mutant=mutant,
                        fixture=fixture, criterion=self._criterion(), base_dir=root,
                    )
                expected_status = (COMPOSITION_DEFECT if name == "audit-failure" else
                                   "undiagnosed" if name == "audit-invalid" else
                                   COMPONENT_CANDIDATE)
                self.assertEqual(expected_status, confirmation.status)
                self.assertEqual(reason, confirmation.reason)

    def test_positive_reruns_are_real_and_record_audits_and_hashes(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import (
            IsolationFixture, confirm_component_offline,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = self._build(root, "baseline", component=b"baseline")
            mutant = self._build(root, "mutant", component=b"mutant")
            baseline_top_hash = _hash(baseline.top_path)
            mutant_top_hash = _hash(mutant.top_path)
            package = self._candidate(mutant)
            baseline_result = RunResult(1, 4, "OK", {}, {}, (), (), "", "",
                peer_applied=({"cycle": 0, "instance": "spi0", "slot": "spi.arm_byte", "value": 3},),
                peer_wire_trace=({"cycle": 1, "instance_id": "spi0", "mosi": "1"},),
                peer_wire_status=({"instance_id": "spi0", "count": 1, "truncated": False},),
                requests=({"cycle": 0, "addr": 0x1008, "write": 1, "wdata": 3, "be": 15, "source": 0},),
                peer_oracle={"checks": ({"check_id": "spi-transfer-wire", "status": "pass",
                                          "expected": 3, "observed": 3},)})
            mutant_result = dataclasses.replace(
                baseline_result, peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                                            "status": "mismatch", "expected": 3,
                                                            "observed": 2},)})
            audit = {"summary": {"status": "pass", "passed": 2, "failed": 0}}
            with patch("myfuzz.composition.soc_offline_defect_confirmation.replay_package",
                       return_value=ReplayResult(status="agreement", reason="same")), \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.run_sample",
                       side_effect=(baseline_result, mutant_result)) as rerun, \
                 patch("myfuzz.composition.soc_offline_defect_confirmation.audit_structure",
                       side_effect=(audit, audit)) as structural:
                confirmation = confirm_component_offline(
                    package, plan=object(), baseline=baseline, mutant=mutant,
                    fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                    criterion=self._criterion(), base_dir=root,
                )
        self.assertEqual(COMPONENT_CANDIDATE, confirmation.status)
        self.assertEqual("offline-rerun-complete", confirmation.reason)
        self.assertEqual(2, rerun.call_count)
        self.assertEqual(2, structural.call_count)
        self.assertEqual(baseline_top_hash, confirmation.evidence["baseline_top_hash"])
        self.assertEqual(mutant_top_hash, confirmation.evidence["mutant_top_hash"])

    def test_spi_wire_verdict_requires_one_independent_check(self) -> None:
        from myfuzz.composition.soc_offline_defect_confirmation import spi_wire_verdict
        clean = RunResult(1, 1, "OK", {}, {}, (), (), "", "",
                          peer_oracle={"checks": ({"check_id": "spi-transfer-wire",
                                                    "status": "pass", "expected": 1,
                                                    "observed": 1},)})
        self.assertEqual(("pass", 1, 1), spi_wire_verdict(clean))
        self.assertEqual(("not_assessed", None, None),
                         spi_wire_verdict(dataclasses.replace(clean, peer_oracle={"checks": ()})))


if __name__ == "__main__":
    unittest.main()
