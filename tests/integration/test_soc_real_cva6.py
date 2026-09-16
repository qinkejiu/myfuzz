"""CVA6 source-bound boundary and opt-in runtime acceptance checks."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition.cva6_source_closure import (
    Cva6SourceClosureError,
    resolve_cva6_source_closure,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/soc/cva6-pulp.json"
INTERFACE = ROOT / "configs/cpus/cva6/official_core_interface_description.json"
CVA6_RUNTIME_SOURCES = (
    "src/myfuzz/composition/rtl/soc_cva6_pulp_core.sv",
    "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv",
    "src/myfuzz/protocols/rtl/processor_memory_backend.sv",
    "src/myfuzz/protocols/rtl/soc_arbiter.sv",
    "src/myfuzz/protocols/rtl/soc_router.sv",
    "src/myfuzz/protocols/rtl/mmio_width_adapter.sv",
    "src/myfuzz/protocols/rtl/processor_apb_bridge.sv",
    "src/myfuzz/integration/rtl/riscv_boot_memory.sv",
    "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    "third_party/soc-pulp-apb-spi/spi_master_apb_if.sv",
    "third_party/soc-pulp-axi-spi/spi_master_clkgen.sv",
    "third_party/soc-pulp-axi-spi/spi_master_controller.sv",
    "third_party/soc-pulp-axi-spi/spi_master_fifo.sv",
    "third_party/soc-pulp-axi-spi/spi_master_rx.sv",
    "third_party/soc-pulp-axi-spi/spi_master_tx.sv",
)


class Cva6BoundaryTests(unittest.TestCase):
    def test_profile_is_rv64_axi4_and_declares_supported_fetch_bursts(self):
        profile = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(profile["cpu"]["xlen"], 64)
        self.assertEqual(profile["cpu"]["protocol"], ["axi4", "1"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["container_request"], "noc_req_o")
        self.assertTrue(profile["cpu"]["memory_boundary"]["packed_members_compiler_proven"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["burst_policy"],
                         "support_two_beat_reads")
        self.assertTrue(profile["cpu"]["memory_boundary"]["fetch_burst_required"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["max_read_beats"], 2)
        self.assertEqual(profile["cpu"]["memory_boundary"]["max_write_beats"], 1)

    def test_official_interface_keeps_all_packed_axi_fields_on_declared_containers(self):
        document = json.loads(INTERFACE.read_text(encoding="utf-8"))
        memory = next(endpoint for endpoint in document["endpoints"]
                      if endpoint.get("function") == "memory_master")
        packed = [field for field in memory["fields"] if "physical" in field]
        self.assertEqual(len(packed), 45)
        self.assertEqual({field["physical"]["port"] for field in packed},
                         {"noc_req_o", "noc_resp_i"})
        self.assertTrue(all(field["physical"].get("member_path") for field in packed))
        self.assertEqual({field["physical"]["port"] for field in packed
                          if (field["role"].startswith("aw") and field["role"] != "awready")
                          or field["role"] in {"wdata", "wstrb", "wlast", "wvalid", "wuser"}},
                         {"noc_req_o"})

    def test_mmio_profiles_explicitly_reject_unsupported_wide_crossing(self):
        profile = json.loads(CONFIG.read_text(encoding="utf-8"))
        for peripheral in profile["peripherals"]:
            self.assertEqual(peripheral["data_width"], 32)
            self.assertEqual(peripheral["width_conversion"],
                             {"spanning_write": "reject", "spanning_read": "reject"})
        self.assertEqual(profile["acceptance"]["environment"], "MYFUZZ_SOC_REAL=1")
        self.assertTrue(profile["acceptance"]["requires_runtime"])


@unittest.skipUnless(
    (ROOT / "third_party/cva6_upstream_reference").is_dir(),
    "the pinned CVA6 checkout is not materialized",
)
class Cva6SourceClosureTests(unittest.TestCase):
    def test_flattened_closure_is_pinned_and_package_ordered(self):
        closure = resolve_cva6_source_closure(ROOT)
        self.assertEqual(closure["top_module"], "cva6")
        self.assertEqual(closure["target_cfg"], "cv64a6_imafdc_sv39")
        self.assertEqual(
            closure["root_revision"],
            "git:2e1336dcff3d1a0b49fbe6282b97802f32ea32af",
        )
        self.assertGreater(len(closure["source_files"]), 200)
        self.assertIn(
            "third_party/cva6_upstream_reference/core/cva6.sv",
            closure["source_files"],
        )
        self.assertLess(
            closure["source_files"].index(
                "third_party/cva6_upstream_reference/core/include/cv64a6_imafdc_sv39_config_pkg.sv"
            ),
            closure["source_files"].index(
                "third_party/cva6_upstream_reference/core/cva6.sv"
            ),
        )
        self.assertIn(
            "third_party/cva6_upstream_reference/core/include",
            closure["include_dirs"],
        )
        self.assertEqual(
            closure["nested_repositories"],
            [
                {
                    "path": "core/cache_subsystem/hpdcache",
                    "revision": "git:f404e7ebbda8baa4af3729535f520a6b12a06d03",
                },
                {
                    "path": "core/cvfpu",
                    "revision": "git:3eb6afeab2cb33f7d8689222955d0171aeb3a801",
                },
                {
                    "path": "core/cvfpu/src/fpu_div_sqrt_mvp",
                    "revision": "git:86e1f558b3c95e91577c41b2fc452c86b04e85ac",
                },
            ],
        )
        self.assertTrue(all((ROOT / path).is_file() for path in closure["source_files"]))
        self.assertEqual(len(closure["source_files"]), len(set(closure["source_files"])))

    def test_missing_nested_pin_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "configs/soc").mkdir(parents=True)
            (root / "configs/soc/sources.lock.json").write_text(
                json.dumps({"schema_version": "soc_sources.v1", "components": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(Cva6SourceClosureError, "cva6-source-lock"):
                resolve_cva6_source_closure(root)

    def test_duplicate_nested_pin_is_fail_closed(self):
        document = json.loads(
            (ROOT / "configs/soc/sources.lock.json").read_text(encoding="utf-8")
        )
        record = next(item for item in document["components"] if item["id"] == "cva6")
        record["source"]["repositories"].append(
            dict(record["source"]["repositories"][0])
        )
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "sources.lock.json"
            lock.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(Cva6SourceClosureError, "nested-duplicate"):
                resolve_cva6_source_closure(ROOT, lock_path=lock)


@unittest.skipUnless(
    os.environ.get("MYFUZZ_SOC_REAL") == "1",
    "set MYFUZZ_SOC_REAL=1 for the source-backed CVA6 elaboration boundary",
)
class RealCva6OptInTests(unittest.TestCase):
    def test_source_bound_cva6_closure_elaborates(self):
        closure = resolve_cva6_source_closure(ROOT)
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "Verilator is required for CVA6 elaboration")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            filelist = root / "cva6.f"
            filelist.write_text(
                "\n".join(
                    [*(f"+incdir+{item}" for item in closure["include_dirs"]),
                     *closure["source_files"]]
                ) + "\n",
                encoding="utf-8",
            )
            command = [
                str(verilator), "--lint-only", "--language", "1800-2012",
                "--Mdir", str(root / "obj_dir"), "--top-module", "cva6",
                "-f", str(filelist), "-Wno-fatal", "-Wno-DECLFILENAME",
                "-Wno-UNUSED", "-Wno-UNOPTFLAT", "-Wno-IMPLICIT",
                "-Wno-PINMISSING", "-Wno-CASEWITHX", "-Wno-WIDTH",
            ]
            result = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=180,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_source_bound_cva6_pulp_runtime_smoke(self):
        """Run the pinned CVA6 through the real generic fabric and PULP GPIO."""
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "Verilator is required for CVA6 runtime")
        closure = resolve_cva6_source_closure(ROOT)
        closure_sources = [ROOT / item for item in closure["source_files"]]
        runtime_sources = [ROOT / item for item in CVA6_RUNTIME_SOURCES]
        testbench = ROOT / "tests/integration/rtl/soc_cva6_pulp_tb.sv"
        boot_image = ROOT / "tests/fixtures/soc_cva6_pulp_boot.hex"
        self.assertTrue(all(path.is_file() for path in closure_sources),
                        "CVA6 closure contains a missing source")
        self.assertTrue(all(path.is_file() for path in runtime_sources),
                        "CVA6 runtime closure contains a missing source")
        self.assertTrue(testbench.is_file())
        self.assertTrue(boot_image.is_file())
        include_dirs = [ROOT / item for item in closure["include_dirs"]]
        include_dirs.extend([
            ROOT / "third_party/soc-pulp-apb-gpio/rtl",
            ROOT / "third_party/soc-pulp-apb-spi",
            ROOT / "third_party/soc-pulp-axi-spi",
            ROOT / "src/myfuzz/composition/rtl",
            ROOT / "src/myfuzz/protocols/rtl",
            ROOT / "src/myfuzz/integration/rtl",
        ])
        warnings = [
            "-Wno-fatal", "-Wno-DECLFILENAME", "-Wno-UNUSED",
            "-Wno-UNOPTFLAT", "-Wno-IMPLICIT", "-Wno-PINMISSING",
            "-Wno-CASEWITHX", "-Wno-WIDTH",
        ]
        with tempfile.TemporaryDirectory() as directory:
            obj_dir = Path(directory) / "obj_dir"
            command = [
                str(verilator), "--binary", "--timing", "--language", "1800-2012",
                "--top-module", "soc_cva6_pulp_tb", "-j", "2",
                "--Mdir", str(obj_dir), *warnings,
            ]
            command.extend("-I" + str(path) for path in include_dirs)
            command.extend(str(path) for path in closure_sources)
            command.extend(str(path) for path in runtime_sources)
            command.append(str(testbench))
            compiled = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=240,
            )
            self.assertEqual(0, compiled.returncode,
                             compiled.stdout + compiled.stderr)
            binary = obj_dir / "Vsoc_cva6_pulp_tb"
            self.assertTrue(binary.is_file(), "Verilator did not emit CVA6 smoke binary")
            result = subprocess.run(
                [str(binary), "+riscv_boot_image=" + str(boot_image)],
                cwd=ROOT, text=True, capture_output=True, timeout=30,
            )
            output = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, output)
            self.assertRegex(
                output,
                r"SOC_CVA6_PULP_REAL_OK cpu_tx=\d+ cpu_done=\d+ gpio=000000a5",
            )


if __name__ == "__main__":
    unittest.main()
