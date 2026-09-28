"""Ibex candidate instructions must retire and feed RFuzz-visible coverage."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.soc_candidate_program import build_candidate_program
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_structure_audit import audit_structure
from tests.composition.soc_generation_fixture import ROOT, profile_tools_available
from tests.integration.test_soc_ibex_pulp_dual_profile import load_dual_request
from myfuzz.composition.soc_composition import build_composition
from myfuzz.integration.rfuzz_live import _ibex_instruction_coverage_document


MANIFEST = ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json"
PROFILE = ROOT / "configs/cpus/ibex/component_profile.json"
RVFI_CHECKER = "src/myfuzz/protocols/rtl/soc_ibex_rvfi_checker.sv"
RVFI_BENCH = ROOT / "tests/integration/rtl/soc_ibex_rvfi_checker_tb.sv"


class IbexRvfiCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = build_composition(load_dual_request(), base_dir=ROOT,
                                     drive_profile="cpu_execute")

    def test_profile_enables_and_exports_minimal_rvfi_trace(self):
        profile = load_component_profile(PROFILE)
        self.assertIn(("RVFI", "1"), profile.source.elaboration.defines)
        actions = {item.port: item.action for item in profile.port_actions}
        for port in ("rvfi_valid", "rvfi_order", "rvfi_insn", "rvfi_trap",
                     "rvfi_pc_rdata"):
            self.assertEqual("observe", actions.get(port), port)

    def test_retirement_order_is_active_and_instruction_opcode_bins_are_exported(self):
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        properties = document["properties"]
        self.assertEqual("active", properties[16]["status"])
        self.assertEqual("u_checker_ibex_rvfi", properties[16]["binding"])
        for bit in range(17, 21):
            self.assertEqual("not_assessed", properties[bit]["status"])

        rendered = render_composition(self.plan)["myfuzz_soc_top.sv"]
        self.assertIn("rvfi_opcode_coverage_o", rendered)
        self.assertIn("soc_ibex_rvfi_checker u_checker_ibex_rvfi", rendered)
        self.assertIn(".we_i(1'b0)", rendered)
        self.assertIn(".wdata_i('0)", rendered)
        self.assertIn(".be_i('0)", rendered)
        self.assertIn("checker_eval_o[16] = checker_ibex_rvfi_eval", rendered)
        self.assertIn("checker_fail_o[16] = checker_ibex_rvfi_fail", rendered)
        self.assertIn({"path": RVFI_CHECKER, "role": "checker_monitor",
                       "owner": "soc_top"}, source_list(self.plan))
        records = source_list(self.plan)
        audit = audit_structure(
            self.plan, top_text=rendered,
            source_files=[item["path"] for item in records
                          if item["role"] != "include_root"],
            include_roots=[item["path"] for item in records
                           if item["role"] == "include_root"],
            base_dir=ROOT)
        self.assertEqual("pass", audit["summary"]["status"])

    def test_candidate_instruction_program_has_a_safe_postlude(self):
        program = build_candidate_program(self.plan, instruction_candidates=4)
        image = program.static_image()
        program_end = program.program_base + program.program_size
        image_offset = program_end - program.image.base
        self.assertEqual((0x0000006F).to_bytes(4, "little"),
                         image[image_offset:image_offset + 4])
        self.assertEqual(image_offset + 4, len(image))

    def test_rfuzz_report_decodes_all_twelve_instruction_class_counters(self):
        bins = ["LUI", "AUIPC", "JAL", "JALR", "BRANCH", "LOAD", "STORE",
                "OP_IMM", "OP", "RV32M", "FENCE", "SYSTEM"]
        observations = [["rvfi_opcode_coverage_o", bit] for bit in range(12)]
        artifact = type("Artifact", (), {
            "coverage_ports": tuple([("source_coverage_o", 0)]
                                    + [tuple(item) for item in observations]),
            "build_document": {
                "ibex_instruction_coverage": {
                    "source": "Ibex RVFI valid, non-trapping retirement records",
                    "semantic_oracle": "not_assessed",
                    "bins": bins,
                    "observations": observations,
                },
            },
        })()
        maxima = [0, 2, 0, 1, 0, 0, 3, 1, 0, 5, 0, 0, 0]

        result = _ibex_instruction_coverage_document(artifact, maxima)

        self.assertEqual("observed", result["status"])
        self.assertEqual(5, result["covered_bins"])
        self.assertEqual(12, result["total_bins"])
        self.assertFalse(result["all_bins_covered"])
        self.assertTrue(result["bins"]["LUI"]["covered"])
        self.assertFalse(result["bins"]["AUIPC"]["covered"])
        self.assertEqual(5, result["bins"]["RV32M"]["counter_maximum"])

    @unittest.skipUnless(profile_tools_available(), "bundled RFuzz Verilator required")
    def test_checker_order_failures_are_sticky_and_opcode_bins_are_real(self):
        from myfuzz.rfuzz_compat import resolve_rfuzz_verilator

        with tempfile.TemporaryDirectory() as tmp:
            obj = Path(tmp) / "obj_dir"
            built = subprocess.run(
                [str(resolve_rfuzz_verilator(ROOT, environment={})), "--binary",
                 "--timing", "-Wno-fatal", "-Wno-lint", "--top-module",
                 "soc_ibex_rvfi_checker_tb", "--Mdir", str(obj),
                 str(ROOT / RVFI_CHECKER), str(RVFI_BENCH)],
                cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(0, built.returncode, built.stdout)
            result = subprocess.run(
                [str(obj / "Vsoc_ibex_rvfi_checker_tb")], cwd=ROOT,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("IBEX_RVFI_CHECKER_ALL_PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
