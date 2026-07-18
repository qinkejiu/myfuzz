import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.axi_lite_fabric_v4 import (  # noqa: E402
    AxiLiteFabricV4Capability, AxiLiteFabricV4Input, AxiLiteFabricV4Model,
    AxiLiteTargetFeedbackV4,
    emit_axi_lite_fabric_v4,
)


def feedback(n, *, aw=(), w=(), b=(), bresp=(), ar=(), r=(), rdata=(), rresp=()):
    flags = lambda selected: tuple(index in selected for index in range(n))
    values = lambda source: tuple(source[index] if index < len(source) else 0 for index in range(n))
    return AxiLiteTargetFeedbackV4(flags(aw), flags(w), flags(b), values(bresp), flags(ar), flags(r), values(rdata), values(rresp))


class AxiLiteFabricV4Test(unittest.TestCase):
    def test_emitted_fabric_compiles(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fabric.sv"
            output = Path(directory) / "fabric.out"
            source.write_text(emit_axi_lite_fabric_v4(self.capability))
            result = subprocess.run(["iverilog", "-g2012", "-s", "myfuzz_axi_lite_fabric_v4", "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_optional_protection_bits_compile_and_reach_target_side(self):
        capability = AxiLiteFabricV4Capability(
            16, 32, 1, (0x100,), (0x100,), awprot_present=True, arprot_present=True,
        )
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fabric.sv"
            output = Path(directory) / "fabric.out"
            source.write_text(emit_axi_lite_fabric_v4(capability))
            result = subprocess.run(["iverilog", "-g2012", "-s", "myfuzz_axi_lite_fabric_v4", "-o", str(output), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_emitted_response_sequence_counters_wrap_with_stored_tags(self):
        rtl = emit_axi_lite_fabric_v4(self.capability)
        self.assertIn(
            "logic [1:0] w_alloc_seq, w_next_seq, r_alloc_seq, r_next_seq",
            rtl,
        )
        self.assertNotIn("integer w_alloc_seq", rtl)

    def setUp(self):
        self.capability = AxiLiteFabricV4Capability(16, 32, 2, (0x100, 0x400), (0x100, 0x100), 2, 2, 2, 2, 2)
        self.model = AxiLiteFabricV4Model(self.capability)

    def test_aw_w_pair_by_acceptance_order_and_read_advances_independently(self):
        idle = AxiLiteTargetFeedbackV4.idle(2)
        self.model.step(AxiLiteFabricV4Input(awvalid=True, awaddr=0x120, arvalid=True, araddr=0x410), idle)
        self.model.step(AxiLiteFabricV4Input(wvalid=True, wdata=0x11, wstrb=0xF), idle)
        driven = self.model.step(AxiLiteFabricV4Input(), feedback(2, aw=(0,), w=(0,), ar=(1,)))
        self.assertTrue(driven.slave_awvalid[0])
        self.assertEqual(driven.slave_wdata[0], 0x11)
        self.assertTrue(driven.slave_arvalid[1])

    def test_out_of_order_target_completion_returns_in_acceptance_order(self):
        idle = AxiLiteTargetFeedbackV4.idle(2)
        for address, data in ((0x120, 1), (0x410, 2)):
            self.model.step(AxiLiteFabricV4Input(awvalid=True, awaddr=address, wvalid=True, wdata=data, wstrb=15), idle)
        self.model.step(AxiLiteFabricV4Input(), feedback(2, aw=(0, 1), w=(0, 1)))
        later = self.model.step(AxiLiteFabricV4Input(), feedback(2, b=(1,), bresp=(0, 2)))
        self.assertFalse(later.bvalid)
        self.model.step(AxiLiteFabricV4Input(), feedback(2, b=(0,), bresp=(1, 0)))
        head = self.model.step(AxiLiteFabricV4Input(), idle)
        self.assertTrue(head.bvalid)
        self.assertEqual(head.bresp, 1)
        second = self.model.step(AxiLiteFabricV4Input(bready=True), idle)
        self.assertTrue(second.bvalid)
        self.assertEqual(self.model.step(AxiLiteFabricV4Input(), idle).bresp, 2)

    def test_b_backpressure_does_not_block_r(self):
        idle = AxiLiteTargetFeedbackV4.idle(2)
        self.model.step(AxiLiteFabricV4Input(awvalid=True, awaddr=0x120, wvalid=True, wdata=1, wstrb=15, arvalid=True, araddr=0x410), idle)
        self.model.step(AxiLiteFabricV4Input(), feedback(2, aw=(0,), w=(0,), ar=(1,)))
        self.model.step(AxiLiteFabricV4Input(), feedback(2, b=(0,), r=(1,), rdata=(0, 0x55)))
        both = self.model.step(AxiLiteFabricV4Input(), idle)
        self.assertTrue(both.bvalid)
        self.assertTrue(both.rvalid)
        self.assertEqual(both.rdata, 0x55)

    def test_manifest_reports_real_bounded_capability(self):
        manifest = self.capability.manifest()
        self.assertEqual(manifest["write_pairing"], "nth_aw_with_nth_w")
        self.assertEqual(manifest["read_write_progress"], "independent")
        self.assertEqual(manifest["target_issue_limits"], {"write": 1, "read": 1})


if __name__ == "__main__":
    unittest.main()
