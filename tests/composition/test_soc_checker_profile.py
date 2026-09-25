"""Contracts for the reserved Ibex/PULP checker feedback ABI."""

from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError

from myfuzz.composition.soc_checker_profile import (
    CheckerProfileError,
    load_checker_profile,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition
from myfuzz.composition.soc_runtime import render_profile_testbench
from myfuzz.composition.soc_image import build_image_plan
from myfuzz.integration.rfuzz_simulator import checker_feedback_observations
from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_ibex_pulp_dual_profile import load_dual_request


MANIFEST = ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json"


def checker_document():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def composition_plan():
    return build_composition(load_dual_request(), base_dir=ROOT,
                             drive_profile="cpu_execute")


class CheckerProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = composition_plan()

    def test_reserved_properties_are_immutable_ordered_and_hash_stable(self):
        first = load_checker_profile(checker_document(), self.plan)
        second = load_checker_profile(checker_document(), self.plan)
        self.assertEqual(first.profile_hash, second.profile_hash)
        self.assertEqual(list(range(50)), [item.bit for item in first.properties])
        self.assertEqual("OBI.INSTR.STALL_STABLE", first.properties[0].property_id)
        self.assertEqual("SPI.FIFO_DEPTH_BOUND", first.properties[-1].property_id)
        self.assertTrue(first.profile_hash.startswith("sha256:"))
        self.assertEqual(71, len(first.profile_hash))
        with self.assertRaises(FrozenInstanceError):
            first.properties[0].status = "active"
        changed = checker_document()
        changed["properties"][0]["property_id"] += ".V2"
        self.assertNotEqual(first.profile_hash,
                            load_checker_profile(changed, self.plan).profile_hash)

    def test_rejects_duplicate_ids(self):
        document = checker_document()
        document["properties"][1]["property_id"] = document["properties"][0]["property_id"]
        with self.assertRaisesRegex(CheckerProfileError, "property-id-duplicate"):
            load_checker_profile(document, self.plan)

    def test_rejects_duplicate_and_non_contiguous_bits(self):
        document = checker_document()
        document["properties"][1]["bit"] = 0
        with self.assertRaisesRegex(CheckerProfileError, "property-bit-duplicate"):
            load_checker_profile(document, self.plan)
        document["properties"][1]["bit"] = 51
        with self.assertRaisesRegex(CheckerProfileError, "property-bits-not-contiguous"):
            load_checker_profile(document, self.plan)

    def test_rejects_missing_record_and_wrong_bus_width(self):
        document = checker_document()
        document["properties"].pop()
        with self.assertRaisesRegex(CheckerProfileError, "property-count"):
            load_checker_profile(document, self.plan)
        for field in ("eval_width", "fail_width"):
            document = checker_document()
            document["feedback"][field] = 49
            with self.subTest(field=field), self.assertRaisesRegex(
                    CheckerProfileError, "checker-bus-width"):
                load_checker_profile(document, self.plan)

    def test_rejects_unknown_request_target_and_basis_kind(self):
        for field, value, reason in (
                ("request_id", "other", "request-id"),
                ("owner", "stranger", "property-owner"),
                ("basis_kind", "guess", "basis-kind")):
            document = checker_document()
            if field == "request_id":
                document[field] = value
            else:
                document["properties"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                    CheckerProfileError, reason):
                load_checker_profile(document, self.plan)

    def test_active_requires_real_binding_and_evidence(self):
        document = checker_document()
        record = document["properties"][0]
        record.update(status="active", binding="obi_instr_stall_eval",
                      basis_kind="standard", basis="OBI request hold until grant",
                      reason=None)
        self.assertEqual("active", load_checker_profile(document, self.plan).properties[0].status)
        record["binding"] = ""
        with self.assertRaisesRegex(CheckerProfileError, "active-binding"):
            load_checker_profile(document, self.plan)
        record["binding"] = "obi_instr_stall_eval"
        record["basis"] = ""
        with self.assertRaisesRegex(CheckerProfileError, "active-basis"):
            load_checker_profile(document, self.plan)

    def test_not_assessed_reserves_id_without_claim(self):
        document = checker_document()
        item = load_checker_profile(document, self.plan).properties[2]
        self.assertEqual("not_assessed", item.status)
        self.assertTrue(item.reason)
        self.assertIsNone(item.binding)
        document["properties"][2]["binding"] = "fake"
        with self.assertRaisesRegex(CheckerProfileError, "not-assessed-binding"):
            load_checker_profile(document, self.plan)
        document = checker_document()
        document["properties"][2]["reason"] = ""
        with self.assertRaisesRegex(CheckerProfileError, "not-assessed-reason"):
            load_checker_profile(document, self.plan)

    def test_rendered_protocol_monitors_feed_reserved_vectors(self):
        top = render_composition(self.plan)["myfuzz_soc_top.sv"]
        self.assertIn("output logic [49:0] checker_eval_o", top)
        self.assertIn("output logic [49:0] checker_fail_o", top)
        self.assertIn("checker_eval_o[0] = checker_obi_instr_eval[0]", top)
        self.assertIn("checker_fail_o[15] = checker_fabric_fail[1]", top)
        self.assertNotIn("checker_eval_o[2] =", top)
        bench = render_profile_testbench(self.plan,
                                         image_plan=build_image_plan(self.plan))
        self.assertIn(".checker_eval_o(obs_checker_eval_o)", bench)
        self.assertIn(".checker_fail_o(obs_checker_fail_o)", bench)

    def test_changed_property_id_changes_rendered_artifact_identity(self):
        original = load_checker_profile(checker_document(), self.plan)
        changed_document = checker_document()
        changed_document["properties"][0]["property_id"] += ".V2"
        changed = load_checker_profile(changed_document, self.plan)
        original_top = render_composition(self.plan, checker_profile=original)[
            "myfuzz_soc_top.sv"]
        changed_top = render_composition(self.plan, checker_profile=changed)[
            "myfuzz_soc_top.sv"]
        self.assertIn(original.profile_hash, original_top)
        self.assertIn(changed.profile_hash, changed_top)
        self.assertNotEqual(original_top, changed_top)

    def test_checker_observation_map_is_separate_and_width_checked(self):
        ports = (
            {"name": "checker_eval_o", "direction": "output", "width": 50},
            {"name": "checker_fail_o", "direction": "output", "width": 50},
        )
        observations = checker_feedback_observations(ports)
        self.assertEqual(100, len(observations))
        self.assertEqual(("checker_eval_o", 0), observations[0])
        self.assertEqual(("checker_eval_o", 49), observations[49])
        self.assertEqual(("checker_fail_o", 0), observations[50])
        self.assertEqual(("checker_fail_o", 49), observations[-1])
        bad = (dict(ports[0], width=49), ports[1])
        with self.assertRaisesRegex(ValueError, "checker-bus-width"):
            checker_feedback_observations(bad)


if __name__ == "__main__":
    unittest.main()
