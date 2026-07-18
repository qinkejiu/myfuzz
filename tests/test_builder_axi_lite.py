import sys
import subprocess
import tempfile
import random
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AXI_LITE_STATE_TABLE, AxiLiteCycle, AxiLiteFabricConfig, AxiLiteReferenceModel,
    InputValidationError, emit_axi_lite_assertions, emit_axi_lite_fabric,
)
from myfuzz.instrumentation.source_branch_instrumenter import instrument_project  # noqa: E402


class AxiLiteBackendTest(unittest.TestCase):
    def test_cycle_state_table_and_assertions_are_locked(self):
        self.assertEqual({item["state"] for item in AXI_LITE_STATE_TABLE}, {
            "write_collect", "write_issue", "write_response", "read_issue", "read_response", "reset",
        })
        assertions = emit_axi_lite_assertions()
        self.assertIn("p_b_stable", assertions)
        self.assertIn("p_r_stable", assertions)
        self.assertIn("p_reset_quiet", assertions)

    def test_config_rejects_width_and_overlap_errors(self):
        with self.assertRaisesRegex(InputValidationError, "multiple of 8"):
            AxiLiteFabricConfig(16, 12, 1, (0,), (256,))
        with self.assertRaisesRegex(InputValidationError, "overlap"):
            AxiLiteFabricConfig(16, 32, 2, (0, 128), (256, 256))

    def test_reference_model_pairs_aw_and_w_and_persists_b(self):
        model = AxiLiteReferenceModel(AxiLiteFabricConfig(16, 32, 1, (0x100,), (0x100,)))
        model.step(AxiLiteCycle(awvalid=True, awaddr=0x104))
        response = model.step(AxiLiteCycle(wvalid=True, wdata=7, wstrb=0xF))
        self.assertFalse(response.bvalid)
        response = model.step(AxiLiteCycle())
        self.assertTrue(response.bvalid)
        self.assertEqual(response.bresp, 0)
        self.assertTrue(model.step(AxiLiteCycle()).bvalid)
        model.step(AxiLiteCycle(bready=True))
        self.assertFalse(model.step(AxiLiteCycle()).bvalid)

    def test_reference_model_returns_decerr_for_unmapped_access(self):
        model = AxiLiteReferenceModel(AxiLiteFabricConfig(16, 32, 1, (0x100,), (0x100,)))
        response = model.step(AxiLiteCycle(arvalid=True, araddr=0x900))
        self.assertFalse(response.rvalid)
        response = model.step(AxiLiteCycle())
        self.assertTrue(response.rvalid)
        self.assertEqual(response.rresp, 3)

    def test_reference_model_has_one_logical_outstanding_and_write_priority(self):
        model = AxiLiteReferenceModel(AxiLiteFabricConfig(16, 32, 1, (0x100,), (0x100,)))
        simultaneous = model.step(AxiLiteCycle(
            awvalid=True, awaddr=0x104, arvalid=True, araddr=0x120,
        ))
        self.assertTrue(simultaneous.awready)
        self.assertFalse(simultaneous.arready)
        locked = model.step(AxiLiteCycle(arvalid=True, araddr=0x120))
        self.assertTrue(locked.wready)
        self.assertFalse(locked.arready)
        model.step(AxiLiteCycle(wvalid=True, wdata=1, wstrb=15))
        self.assertFalse(model.step(AxiLiteCycle(arvalid=True, araddr=0x120)).arready)

    def test_reference_model_holds_read_response_under_backpressure(self):
        model = AxiLiteReferenceModel(AxiLiteFabricConfig(16, 32, 1, (0x100,), (0x100,)))
        model.step(AxiLiteCycle(arvalid=True, araddr=0x120))
        response = model.step(AxiLiteCycle())
        self.assertTrue(response.rvalid)
        self.assertFalse(model.step(AxiLiteCycle()).rvalid is False)
        self.assertTrue(model.step(AxiLiteCycle(rready=True)).rvalid)
        self.assertFalse(model.step(AxiLiteCycle()).rvalid)

    def test_emitter_is_deterministic_and_has_flattened_channels(self):
        config = AxiLiteFabricConfig(16, 32, 2, (0x100, 0x400), (0x100, 0x80))
        first = emit_axi_lite_fabric(config)
        self.assertEqual(first, emit_axi_lite_fabric(config))
        self.assertIn("m_awvalid", first)
        self.assertIn("m_bready", first)
        self.assertIn("m_rvalid", first)
        self.assertIn("s_awvalid", first)
        self.assertIn("s_bready", first)
        self.assertIn("m_bresp=s_bresp", first)
        self.assertIn("aw_reg-BASE_0", first)

    def test_generated_fabric_is_instrumented_and_recompiles(self):
        config = AxiLiteFabricConfig(16, 32, 2, (0x100, 0x400), (0x100, 0x80))
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as output:
            root = Path(project)
            destination = Path(output)
            (root / "fabric.sv").write_text(emit_axi_lite_fabric(config))
            manifest = instrument_project(
                root, destination, top_module="myfuzz_axi_lite_fabric", force=True,
            )
            self.assertGreater(manifest["coverage_point_count"], 0)
            result = subprocess.run(
                ["iverilog", "-g2012", "-s", "myfuzz_axi_lite_fabric", "-o",
                 str(destination / "a.out"), str(destination / "fabric.sv")],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_random_interleavings_preserve_backpressured_responses(self):
        rng = random.Random(7)
        model = AxiLiteReferenceModel(AxiLiteFabricConfig(16, 32, 2, (0x100, 0x400), (0x100, 0x80)))
        previous = None
        previous_cycle = None
        for _ in range(1000):
            cycle = AxiLiteCycle(
                awvalid=bool(rng.getrandbits(1)), awaddr=rng.randrange(0x500),
                wvalid=bool(rng.getrandbits(1)), wdata=rng.getrandbits(32), wstrb=rng.getrandbits(4),
                bready=bool(rng.getrandbits(1)), arvalid=bool(rng.getrandbits(1)),
                araddr=rng.randrange(0x500), rready=bool(rng.getrandbits(1)),
            )
            response = model.step(cycle)
            if previous and previous.bvalid and not previous_cycle.bready:
                self.assertTrue(response.bvalid)
                self.assertEqual(response.bresp, previous.bresp)
            if previous and previous.rvalid and not previous_cycle.rready:
                self.assertTrue(response.rvalid)
                self.assertEqual((response.rdata, response.rresp), (previous.rdata, previous.rresp))
            previous = response
            previous_cycle = cycle


if __name__ == "__main__":
    unittest.main()
