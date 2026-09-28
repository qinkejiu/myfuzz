"""Pinned independent OpenTitan SPI Device RTL closure."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.source_crawler import source_tree_hash

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/peripherals/opentitan_spi_device/component_profile.json"
CLOSURE = ROOT / "configs/soc/closures/opentitan_spi_device.json"
LOCK = ROOT / "configs/soc/sources.lock.json"


class SpiDeviceClosureTests(unittest.TestCase):
    def test_independent_source_and_exact_read_set(self):
        self.assertEqual("opentitan_spi_device", load_component_profile(PROFILE).component_id)
        profile = json.loads(PROFILE.read_text())
        closure = json.loads(CLOSURE.read_text())
        lock = json.loads(LOCK.read_text())
        source = profile["source"]
        self.assertEqual("opentitan_spi_device", profile["component_id"])
        self.assertEqual("git:fca045df919a26c47e71616b9dac917b1ea4fd07", source["revision"])
        self.assertEqual("spi_device", source["top_module"])
        self.assertEqual(source["files"], closure["source_files"])
        self.assertEqual(source["include_roots"], closure["include_roots"])
        self.assertEqual("spi_device", closure["top_module"])
        self.assertFalse(closure["boundary"]["generated_soc_fabric"])
        self.assertEqual(0, closure["lint"]["exit_code"])
        self.assertEqual(0, closure["lint"]["errors"])
        self.assertIn("hw/ip/spi_device/rtl/spi_device.sv", source["files"])
        self.assertFalse(any("/spi_host/rtl/" in item for item in source["files"]))
        component = next(c for c in lock["components"] if c["id"] == "opentitan_spi_device")
        self.assertEqual(source["files"], component["source"]["files"])
        self.assertEqual(source_tree_hash(ROOT / source["root"],
                                          [ROOT / source["root"] / path for path in source["files"]]),
                         component["selected_content_hash"])
        self.assertEqual(hashlib.sha256(CLOSURE.read_bytes()).hexdigest(),
                         component["elaboration"]["evidence_sha256"])
        pinned = {(entry["root"], entry["path"]): entry["sha256"]
                  for entry in closure["closure_files"]}
        self.assertEqual(len(pinned), len(closure["closure_files"]))
        artifacts = {entry["path"]: entry["sha256"] for entry in component["artifacts"]}
        for relative in source["files"]:
            path = ROOT / source["root"] / relative
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, pinned[(source["root"], relative)])
            self.assertEqual(digest, artifacts[relative])
        for entry in closure["closure_files"]:
            path = ROOT / entry["root"] / entry["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
        wrapper_path = ROOT / profile["elaboration_boundary"]["wrapper"]
        wrapper = wrapper_path.read_text()
        self.assertIn("spi_device", wrapper)
        for port in ("tl_i", "tl_o", "sck_i", "csb_i", "sd_i", "sd_o", "sd_en_o"):
            self.assertIn(port, wrapper)
        self.assertEqual(hashlib.sha256(wrapper_path.read_bytes()).hexdigest(),
                         profile["elaboration_boundary"]["wrapper_sha256"])


    def test_verilator_replays_exact_vendor_read_set(self):
        closure = json.loads(CLOSURE.read_text())
        command = list(closure["command"])
        with tempfile.TemporaryDirectory(prefix="spi_device_closure_") as build_dir:
            command[command.index("--Mdir") + 1] = build_dir
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("%Error-", result.stderr)
            depfile = Path(build_dir) / "Vspi_device__ver.d"
            self.assertTrue(depfile.is_file())
            vendor_prefix = "third_party/soc-opentitan/"
            actual = {word[len(vendor_prefix):] for word in depfile.read_text().split()
                      if word.startswith(vendor_prefix)}
            expected = {entry["path"] for entry in closure["closure_files"]}
            self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
