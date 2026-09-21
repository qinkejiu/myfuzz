"""File-identity binding for the offline component confirmation entry point."""
from __future__ import annotations

import dataclasses
import hashlib
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.soc_failure_evidence import (
    COMPONENT_CANDIDATE,
    COMPOSITION_DEFECT,
    classify_boundary,
)
from myfuzz.composition.soc_runtime import RuntimeBuild

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

    def test_mismatched_mutant_top_hash_does_not_confirm(self) -> None:
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
            confirmation = confirm_component_offline(
                dataclasses.replace(package, identity=identity),
                plan=object(), baseline=baseline, mutant=mutant,
                fixture=IsolationFixture(Path("fixture.sv"), "tb", "OBS", "component.sv"),
                criterion=self._criterion(), base_dir=root,
            )
        self.assertNotEqual("component_confirmed", confirmation.status)
        self.assertIn("rendered_top_hash", confirmation.reason)

    def test_two_changed_sources_do_not_confirm(self) -> None:
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
        self.assertNotEqual("component_confirmed", confirmation.status)
        self.assertIn("source", confirmation.reason)


if __name__ == "__main__":
    unittest.main()
