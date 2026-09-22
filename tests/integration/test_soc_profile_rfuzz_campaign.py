"""Opt-in acceptance for the production profile -> kfuzz campaign path.

The class is skipped only when the explicit real-run opt-in is absent.  Once
``MYFUZZ_SOC_REAL=1`` is supplied, missing pinned dependencies raise a failure
with a concrete diagnostic instead of being converted into a passing skip.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.soc_campaign import run_soc_campaign
from tests.composition.soc_generation_fixture import ROOT, example_plan, profile_paths, request_path, profile_tools_available


def _client() -> Path:
    return Path(os.environ.get(
        "MYFUZZ_RFuzz_CLIENT",
        str(ROOT / "runs/rfuzz_client_native_build/target/debug/kfuzz"),
    )).resolve()


def _config(root: Path, boot: Path) -> dict[str, object]:
    plan = example_plan()
    defaults = {}
    for instance in plan.instances:
        for entry in instance.dispositions:
            if (entry.disposition == "external" and entry.direction == "input"):
                suffix = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) \
                    else f"_{entry.bit_hi}_{entry.bit_lo}"
                defaults[f"{entry.instance_id}__{entry.port}{suffix}"] = 0
    return {
        "root": str(root),
        "config_id": "profile-rfuzz-campaign-acceptance",
        "composition_request": str(request_path()),
        "component_profiles": [str(path) for path in profile_paths()],
        "drive_profile": "cpu_execute",
        "mode": "cpu_only",
        "seed": 20260921,
        "duration_seconds": 5,
        # Each fuzz test is this many cycles long.  A 3-cycle test is one fabric
        # request deep, so the fabric never has time to *complete* it and the
        # reported target-side transaction count is legitimately zero; the
        # campaign's acceptance requires both sides observed, which needs a test
        # long enough for a request to be answered.
        "seed_cycles": 32,
        "boot_image": str(boot),
        "external_input_defaults": defaults,
        "client_binary": str(_client()),
        "verilator": "bundled",
        "reset_contract": {"driver": True, "memory": True, "cpu": True,
                           "peripherals": True, "irq": True, "coverage": True},
    }


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for the real profile RFuzz campaign")
class ProfileRfuzzCampaignAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = []
        if not profile_tools_available():
            missing.append("bundled RFuzz Verilator 5.020")
        client = _client()
        if not client.is_file() or not client.stat().st_mode & 0o111:
            missing.append(str(client))
        if missing:
            raise AssertionError(
                "MYFUZZ_SOC_REAL=1 requires the production RFuzz dependencies; missing: "
                + ", ".join(missing))
        cls.temporary = tempfile.TemporaryDirectory(prefix="profile-rfuzz-campaign-")
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        boot = root / "boot.hex"
        boot.write_text("13\n00\n00\n00\n", encoding="utf-8")
        cls.output = root / "run"
        cls.config = _config(ROOT, boot)
        environment = dict(os.environ)
        environment["MYFUZZ_SOC_REAL"] = "1"
        environment["MYFUZZ_RFuzz_CLIENT"] = str(client)
        cls.result = run_soc_campaign(
            cls.config, cls.output, root=ROOT, environment=environment)

    def test_official_campaign_has_complete_profile_evidence(self):
        # A duration-bounded official run ends by interrupting the client, and the
        # interrupted-run policy accepts that outcome only when every piece of
        # evidence is present.  The status therefore names the termination; a
        # plain "completed" would mean the client stopped on its own, which this
        # campaign configuration does not ask for.
        self.assertEqual("completed_with_client_termination", self.result["status"])
        self.assertEqual("passed_with_client_termination", self.result["final_status"])
        # The policy must have been *applied*, not merely not-failed: it records
        # that nothing was missing and no error was seen.
        self.assertEqual([], self.result["evidence_missing"])
        self.assertEqual("official_rfuzz_source_backed_soc",
                         self.result["execution_kind"])
        self.assertTrue(self.result["preflight"]["toolchain"]["ready"])
        self.assertEqual("verified", self.result["corpus"]["status"])
        self.assertGreater(self.result["corpus"]["entries"], 0)
        self.assertEqual("passed", self.result["replay"]["status"])
        self.assertEqual("clean", self.result["cleanup"]["status"])
        self.assertTrue(self.result["fifo_reply_receipts"])
        self.assertTrue(self.result["artifact"]["tool_identity"])
        # Both sides of the fabric boundary were really observed, which is what
        # makes "the SoC executed" a measurement rather than an assumption.
        transactions = self.result["source_target_transactions"]
        self.assertEqual("observed", transactions["status"])
        self.assertGreater(transactions["source"]["transactions"], 0)
        self.assertGreater(transactions["target"]["transactions"], 0)
        self.assertGreater(self.result["rtl_execution"]["execution_totals"]["cycles"], 0)


if __name__ == "__main__":
    unittest.main()
