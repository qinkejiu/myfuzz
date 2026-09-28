"""Real OpenTitan GPIO in its own harness, without any CPU or SoC fabric."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/peripherals/opentitan_gpio/component_profile.json"
HARNESS = ROOT / "src/myfuzz/scenario/rtl/local_opentitan_gpio_tb.sv"


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class LocalOpenTitanGpioTests(unittest.TestCase):
    def test_gpio_register_and_external_edge_from_real_rtl(self):
        self.assertTrue(HARNESS.is_file(), "independent GPIO harness is missing")
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "Verilator is required")
        profile = json.loads(PROFILE.read_text())
        source = profile["source"]
        root = ROOT / source["root"]
        files = [root / item for item in source["files"]]
        self.assertTrue(all(item.is_file() for item in files))
        includes = [root / item for item in source["include_roots"]]
        with tempfile.TemporaryDirectory() as directory:
            obj = Path(directory) / "obj_dir"
            cmd = [verilator, "--binary", "--timing", "-j", "1", "--Mdir", str(obj),
                   "--top-module", "local_opentitan_gpio_tb", "-Wno-fatal",
                   "-Wno-WIDTH", "-Wno-PINMISSING", "-Wno-UNOPTFLAT"]
            cmd.extend("-I" + str(item) for item in includes)
            cmd.extend(str(item) for item in files)
            cmd.extend((str(ROOT / "src/myfuzz/protocols/rtl/beat_to_tlul.sv"),
                        str(ROOT / "src/myfuzz/composition/rtl/soc_opentitan_gpio_target.sv"),
                        str(HARNESS)))
            built = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                                   timeout=300)
            self.assertEqual(0, built.returncode, (built.stdout + built.stderr)[-5000:])
            binary = obj / "Vlocal_opentitan_gpio_tb"
            result = subprocess.run((str(binary),), cwd=ROOT, capture_output=True,
                                    text=True, timeout=30)
            output = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, output)
            self.assertIn("OT_GPIO_LOCAL_OK", output)
            self.assertIn("out=000000a5", output)
            self.assertIn("irq=1", output)


if __name__ == "__main__":
    unittest.main()
