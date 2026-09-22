"""Replay every recorded input-dependency-repair artifact.

``test_soc_input_repair.py`` records one artifact per capability under
``runs/soc-input-repair/<name>/``: the declarative case (its spec, with every
address resolved), the composed program document, the repaired test document and
the frozen image as a ``$readmemh`` hex file.  This module does what a replay
must do -- it rebuilds each case from the *saved* spec alone and compares the
result with the saved record -- so a change in the composer, the plan, the
reference ISA repair or the address policy is reported as a divergence at the
artifact it changed, not as a silent difference in a later run.

Nothing here is allowed to pass by skipping: a missing or unreadable artifact is
a failure naming the file.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from .soc_input_repair_cases import ARTIFACT_ROOT, read_case, record_case, run_case
from .test_soc_input_repair import CASES


class ReplayTests(unittest.TestCase):
    """The saved record alone reproduces the recorded run."""

    @classmethod
    def setUpClass(cls) -> None:
        # Recording is idempotent and deterministic; running it here keeps the
        # replay self-contained instead of depending on test order.
        for spec in CASES:
            record_case(spec)

    def test_every_artifact_is_readable_and_named_by_its_case(self) -> None:
        for spec in CASES:
            with self.subTest(case=spec["name"]):
                path = ARTIFACT_ROOT / spec["name"] / "case.json"
                self.assertTrue(path.is_file(), f"missing artifact {path}")
                record = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual("soc_input_repair_case.v1", record["schema_version"])
                self.assertEqual(spec["name"], record["name"])
                self.assertEqual(spec["item"], record["item"])

    def test_every_case_replays_to_the_same_document(self) -> None:
        for spec in CASES:
            with self.subTest(case=spec["name"]):
                recorded = read_case(spec["name"])
                recomputed = run_case(recorded["spec"])
                self.assertEqual(recorded.get("error"), recomputed.get("error"),
                                 f"{spec['name']}: refusal diverged")
                self.assertEqual(recorded["spec"], recomputed["spec"])
                if "expect_error" in spec:
                    self.assertNotIn("test", recorded)
                    continue
                self.assertEqual(recorded["program"], recomputed["program"])
                self.assertEqual(recorded["test"], recomputed["test"])
                self.assertEqual(recorded["image_hash"], recomputed["image_hash"])
                self.assertEqual(recorded["region_hashes"], recomputed["region_hashes"])
                self.assertEqual(recorded["request"], recomputed["request"])

    def test_every_recorded_hex_file_is_the_replayed_image(self) -> None:
        for spec in CASES:
            if "expect_error" in spec:
                continue
            with self.subTest(case=spec["name"]):
                recorded = read_case(spec["name"])
                text = (ARTIFACT_ROOT / spec["name"] / "boot.hex").read_text(
                    encoding="utf-8")
                self.assertEqual(str(recorded["boot_hex"]), text)
                recomputed = run_case(recorded["spec"])
                self.assertEqual(recomputed["boot_hex"], text,
                                 f"{spec['name']}: the frozen image changed")

    def test_a_recorded_artifact_that_disagrees_with_its_spec_is_detected(self) -> None:
        """The replay compares documents, so a hand-edited record is caught."""
        recorded = read_case(CASES[0]["name"])
        altered = json.loads(json.dumps(recorded))
        altered["test"]["counters"]["address_repair"] += 1
        recomputed = run_case(recorded["spec"])
        self.assertNotEqual(altered["test"], recomputed["test"])

    def test_a_spec_whose_plan_changed_is_refused_rather_than_reinterpreted(self) -> None:
        """A saved case from an older extension set must not silently pass."""
        recorded = read_case("item7-m-profile-accepted")
        stale = json.loads(json.dumps(recorded["spec"]))
        stale["contract_extensions"] = ["i", "f"]
        recomputed = run_case(stale)
        self.assertEqual("candidate-isa-extension-unsupported:f",
                         recomputed.get("error"))


if __name__ == "__main__":
    unittest.main()
