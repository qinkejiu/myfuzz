import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "configs" / "designs" / "rvx_multicomponent"


class RvxMulticomponentTargetTest(unittest.TestCase):
    def test_both_schemes_use_the_same_real_rvx_target(self) -> None:
        configs = [
            json.loads((TARGET / name / "config.json").read_text())
            for name in ("baseline_direct_slice", "depaware_projection")
        ]
        self.assertEqual([config["top"] for config in configs], ["rvx", "rvx"])
        self.assertEqual(configs[0]["flist"], configs[1]["flist"])
        self.assertEqual(configs[0]["instrumentation"], configs[1]["instrumentation"])
        self.assertNotEqual(
            configs[0]["harness"]["manual_harness_module"],
            configs[1]["harness"]["manual_harness_module"],
        )

    def test_filelist_uses_the_pinned_rvx_submodule(self) -> None:
        outer = (TARGET / "rtl" / "sources.f").read_text()
        self.assertIn("-F configs/designs/rvx_multicomponent/rtl/rvx_sources.f", outer)
        sources = (TARGET / "rtl" / "rvx_sources.f").read_text()
        for module in ("rvx", "rvx_core", "rvx_bus", "rvx_ram", "rvx_uart", "rvx_mtimer", "rvx_gpio", "rvx_spi"):
            self.assertIn(f"../../../../external_designs/rvx/hardware/{module}.v", sources)

    def test_harnesses_use_equal_raw_width_and_no_dut_feedback(self) -> None:
        baseline = (TARGET / "harness" / "rvx_baseline_direct_slice_harness.sv").read_text()
        depaware = (TARGET / "harness" / "rvx_depaware_projection_harness.sv").read_text()
        for source in (baseline, depaware):
            self.assertIn("logic [511:0] rfuzz_input_bits", source)
            self.assertIn("rvx #(", source)
            self.assertIn(".__vi_coverage(__vi_coverage)", source)
        self.assertIn(".halt(rfuzz_input_bits[0])", baseline)
        self.assertIn("wire halt_event", depaware)
        self.assertNotIn("wire uart_tx", depaware)


if __name__ == "__main__":
    unittest.main()
