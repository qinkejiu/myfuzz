"""CVA6 source-bound boundary checks; runtime remains unverified and opt-in."""
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


class Cva6BoundaryTests(unittest.TestCase):
    def test_profile_is_rv64_axi4_and_rejects_unproven_fetch_bursts(self):
        profile = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(profile["cpu"]["xlen"], 64)
        self.assertEqual(profile["cpu"]["protocol"], ["axi4", "1"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["container_request"], "noc_req_o")
        self.assertTrue(profile["cpu"]["memory_boundary"]["packed_members_compiler_proven"])
        self.assertEqual(profile["cpu"]["memory_boundary"]["burst_policy"], "reject_non_single_beat")
        self.assertFalse(profile["cpu"]["memory_boundary"]["fetch_burst_required"])

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


if __name__ == "__main__":
    unittest.main()
