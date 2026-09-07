from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.generic_rtl_campaign import select_combinations, prepare_demo, run_demo_campaign
from myfuzz.integration import campaign


class GenericRtlCampaignTests(unittest.TestCase):
    @unittest.skipUnless(all(shutil.which(t) for t in ("iverilog", "vvp", "verilator")), "RTL toolchain required")
    def test_checkpoint_failure_cannot_pass_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(campaign, "write_checkpoint", side_effect=campaign.CampaignReportError("injected checkpoint failure")):
                result = run_demo_campaign(Path(directory) / "campaign", seed=1, count=1, seconds=1)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["results"][0]["passed"])
            self.assertTrue(result["results"][0]["result"]["error"])

    @unittest.skipUnless(all(shutil.which(t) for t in ("iverilog", "vvp", "verilator")), "RTL toolchain required")
    def test_one_stalled_endpoint_fails_even_when_other_endpoint_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fault"
            plan, executable = prepare_demo(root, ("apb3_register", "wishbone_register"))
            source = root / "source/traffic.sv"
            # Deliberate post-publication DUT fault, compiled below for the oracle test.
            source.write_text(source.read_text().replace("state_0 <= 1;", "state_0 <= 0;"))
            compiled = subprocess.run(["iverilog", "-g2012", "-s", "campaign_tb", "-o", str(executable),
                                       *(str(root / p) for p in plan.source_files),
                                       str(root / "generated/generic_composition_top.sv"), str(root / "campaign_tb.sv")],
                                      capture_output=True, text=True, timeout=15)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(["vvp", str(executable), "+batches=1"], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("endpoint 0 scoreboard/progress failure", result.stdout)

    def test_rss_sampling_handles_exit_to_zombie_between_stat_and_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "123").mkdir()
            (root / "124").mkdir()
            with patch.object(campaign, "_PROC_ROOT", root), \
                 patch.object(campaign, "_read_process_group_and_state", side_effect=[(42, "R"), (42, "Z"), (42, "R")]), \
                 patch.object(campaign, "read_rss_bytes", side_effect=[campaign.CampaignError("no VmRSS"), 4096]):
                self.assertEqual(campaign.read_process_group_rss_bytes(42), 4096)

    def test_rss_failure_of_still_live_process_remains_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "123").mkdir()
            with patch.object(campaign, "_PROC_ROOT", root), \
                 patch.object(campaign, "_read_process_group_and_state", return_value=(42, "R")), \
                 patch.object(campaign, "read_rss_bytes", side_effect=campaign.CampaignError("no VmRSS")):
                with self.assertRaises(campaign.CampaignError):
                    campaign.read_process_group_rss_bytes(42)

    def test_selection_is_unique_and_replayable(self):
        selected = select_combinations(20260907)
        self.assertEqual(selected, select_combinations(20260907))
        self.assertEqual(len(set(selected)), 3)
        self.assertTrue(all(len(item) >= 2 for item in selected))
        for seed, count in ((-1, 3), (True, 3), (1, 0), (1, 5)):
            with self.assertRaises(ValueError):
                select_combinations(seed, count)

    @unittest.skipUnless(all(shutil.which(t) for t in ("iverilog", "vvp", "verilator")), "RTL toolchain required")
    def test_all_pool_combinations_execute_scoreboard_with_shared_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            for index, selected in enumerate(select_combinations(1, 4)):
                with self.subTest(combination=selected):
                    plan, executable = prepare_demo(Path(directory) / str(index), selected)
                    self.assertEqual(len(plan.ir["adapters"]), len(selected))
                    for endpoint in plan.annotations["endpoints"]:
                        roles = {field["role"] for field in endpoint["fields"]}
                        for observation in endpoint["timing"]:
                            self.assertTrue(set(observation["fields"]) <= roles)
                    result = subprocess.run(["vvp", str(executable), "+seed=81273", "+batches=3"], capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    row = next(line for line in result.stdout.splitlines() if line.startswith("RESULT ")).split()
                    self.assertGreater(int(row[1]), 100)
                    self.assertEqual(int(row[2]), 0)
                    rows = [line.split() for line in result.stdout.splitlines() if line.startswith("RESULT ")]
                    self.assertEqual(len(rows), 3)
                    self.assertGreater(int(rows[-1][1]), int(rows[0][1]))
