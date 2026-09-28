"""Source identity and independent elaboration contract for OpenTitan SPI Host."""

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "third_party/soc-opentitan"
PROFILE = ROOT / "configs/peripherals/opentitan_spi_host/component_profile.json"
CLOSURE = ROOT / "configs/soc/closures/opentitan_spi_host.json"
SOURCE_LOCK = ROOT / "configs/soc/sources.lock.json"


class SpiHostClosureTests(unittest.TestCase):
    def test_pinned_compilation_closure_covers_core_dependencies(self):
        profile = json.loads(PROFILE.read_text())
        closure = json.loads(CLOSURE.read_text())
        lock = json.loads(SOURCE_LOCK.read_text())
        source = profile["source"]
        files = source["files"]
        self.assertEqual("git:fca045df919a26c47e71616b9dac917b1ea4fd07",
                         source["revision"])
        self.assertEqual("spi_host", source["top_module"])
        self.assertEqual(len(files), len(set(files)), "duplicate compilation file")
        core = (VENDOR / "hw/ip/spi_host/spi_host.core").read_text()
        for dependency in ("lowrisc:ip:spi_device_pkg", "lowrisc:ip:tlul",
                           "lowrisc:prim:all", "lowrisc:prim:flop_en",
                           "lowrisc:prim:racl_error_arb"):
            self.assertIn(dependency, core)
        for relative in ("hw/ip/spi_device/rtl/spi_device_pkg.sv",
                         "hw/ip/tlul/rtl/tlul_socket_1n.sv",
                         "hw/ip/tlul/rtl/tlul_adapter_sram_racl.sv",
                         "hw/ip/tlul/rtl/tlul_adapter_reg_racl.sv",
                         "hw/ip/prim/rtl/prim_packer_fifo.sv",
                         "hw/ip/prim_generic/rtl/prim_flop_en.sv"):
            self.assertIn(relative, files)
        for rtl in (VENDOR / "hw/ip/spi_host/rtl").glob("*.sv"):
            self.assertIn(str(rtl.relative_to(VENDOR)), files)
        self.assertEqual(files, closure["source_files"])
        self.assertEqual(source["include_roots"], closure["include_roots"])
        self.assertEqual("spi_host", closure["top_module"])
        self.assertEqual(0, closure["lint"]["errors"])
        self.assertEqual(0, closure["lint"]["exit_code"])
        self.assertFalse(closure["boundary"]["generated_soc_fabric"])
        wrapper = ROOT / profile["elaboration_boundary"]["wrapper"]
        self.assertEqual(hashlib.sha256(wrapper.read_bytes()).hexdigest(),
                         profile["elaboration_boundary"]["wrapper_sha256"])
        self.assertEqual(hashlib.sha256(wrapper.read_bytes()).hexdigest(),
                         closure["wrapper_elaboration"]["sha256"])
        for module in ("crossbar", "plic", "soc_bus"):
            self.assertNotIn(module, wrapper.read_text().lower())
        component = next(c for c in lock["components"]
                         if c["id"] == "opentitan_spi_host")
        self.assertEqual(files, component["source"]["files"])
        pinned = {(item["root"], item["path"]): item["sha256"]
                  for item in closure["closure_files"]}
        self.assertEqual(len(closure["closure_files"]), len(pinned),
                         "duplicate closure file")
        artifacts = {item["path"]: item["sha256"]
                     for item in component["artifacts"]}
        for relative in files:
            path = VENDOR / relative
            self.assertTrue(path.is_file(), relative)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, pinned[(source["root"], relative)], relative)
            self.assertEqual(digest, artifacts[relative], relative)
        for item in closure["closure_files"]:
            path = ROOT / item["root"] / item["path"]
            self.assertTrue(path.is_file(), str(path))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                             item["sha256"], str(path))


if __name__ == "__main__":
    unittest.main()
