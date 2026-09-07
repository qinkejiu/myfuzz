from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.integration.generic_rtl_campaign import select_combinations, prepare_demo


class GenericRtlCampaignTests(unittest.TestCase):
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
                    result = subprocess.run(["vvp", str(executable), "+seed=81273"], capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    row = next(line for line in result.stdout.splitlines() if line.startswith("RESULT ")).split()
                    self.assertGreater(int(row[1]), 100)
                    self.assertEqual(int(row[2]), 0)

