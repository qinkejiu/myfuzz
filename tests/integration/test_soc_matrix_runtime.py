"""P12 runtime half: eight composition cells x three stimulus modes.

Every cell in configs/soc/matrix.json is rendered from its own config (and the
base profile it declares), elaborated, built with 'verilator --binary --timing'
and executed in cpu_only, mmio_only and mixed.  The generated testbench prints
one machine-readable observation line per run and this module asserts the
mode-specific facts PROJECT_GOALS section 5 requires:

* cpu_only  - the real CPU executes and issues a real MMIO transaction whose
  side effect is visible on the real peripheral, and the completion flag the
  generated boot program writes into RAM shows the register read back;
* mmio_only - the CPU is held in reset for the whole test while the peripherals
  leave reset and the independent synthetic fuzz_mmio_master completes the
  equivalent MMIO program with the same side effect;
* mixed     - the CPU and the synthetic master both have accepted and completed
  transactions, attributed by the fabric to the right source id.

The tests are opt-in through MYFUZZ_SOC_REAL=1.  When the flag is set nothing
may skip: a missing closure file, CPU source, Verilator or a missing port is a
failure naming that exact structural reason (never a behavioural substitute).
Builds are cached under runs/soc-matrix-runtime/<cell>/<mode>/ so a repeated run
only re-executes the binary, and the whole test run is timed and reported (per
cell/mode and in total).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import time
import unittest

from myfuzz.integration.soc_matrix_smoke import (
    FLAG_OK,
    MODES,
    SocMatrixSmokeError,
    cell_documents,
    load_matrix,
    run_cell_mode,
    validate_closure_files,
    validate_top_requirements,
)

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "configs/soc/matrix.json"
OUTPUT_ROOT = ROOT / "runs/soc-matrix-runtime"
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"

#: Reported wall-clock budget for one full run of this test (24 runs plus the
#: repeat runs that must hit the compile cache).  Every build and simulation
#: step has its own hard timeout in the smoke module; this bound is reported so
#: the acceptance run states its runtime instead of hiding it.
RUNTIME_BUDGET_S = int(os.environ.get("MYFUZZ_SOC_MATRIX_BUDGET_S", "7200"))

#: The generated testbench drives and observes exactly these ports/wires of the
#: rendered top; a rendering that does not expose one of them cannot be run.
TB_REQUIRED_PORTS = (
    "clk_i", "reset_i", "stim_offer_i", "stim_target_selector_i",
    "stim_offset_i", "stim_write_i", "stim_wdata_i", "stim_be_i",
    "env_offer_i", "env_data_i", "gpio_in_i", "spi_sck_i", "spi_cs_i",
    "irq_claim_i", "irq_complete_i", "cpu_mmio_transaction_o",
    "fuzz_mmio_transaction_o", "cpu_transaction_count_o",
    "fuzz_transaction_count_o", "cpu_completion_count_o",
    "fuzz_completion_count_o", "fabric_protocol_error_o", "gpio_out_o",
    "uart_rx_o", "spi_miso_o", "irq_o",
)
TB_REQUIRED_WIRES = (
    "fabric_addr", "fabric_source_id", "fabric_rsp_source_id", "fabric_rdata",
    "fabric_req_valid", "fabric_req_ready", "fabric_rsp_valid",
    "fabric_rsp_ready",
)


def _canonical(result: dict) -> dict:
    """The deterministic part of one run: identity + observations."""
    return {
        "cell_id": result["cell_id"],
        "mode": result["mode"],
        "seed": result["seed"],
        "plan_hash": result["identity"]["plan_hash"],
        "render_hash": result["identity"]["render_hash"],
        "layout_hash": result["identity"]["layout_hash"],
        "program_hash": result["program"]["program_hash"],
        "observations": result["observations"],
        "observation_line": result["observation_line"],
    }


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real SoC matrix runtime")
class SocMatrixRuntimeTests(unittest.TestCase):
    """Real runtime smoke for all eight cells in all three modes."""

    @classmethod
    def setUpClass(cls):
        cls.cells = list(load_matrix(MATRIX)["cells"])
        cls.started = time.monotonic()
        cls.timings = []

    @classmethod
    def tearDownClass(cls):
        total = time.monotonic() - cls.started
        build = sum(item["build_s"] for item in cls.timings)
        elapsed = sum(item["run_s"] for item in cls.timings)
        budget = RUNTIME_BUDGET_S
        print("\nMYFUZZ_SOC_MATRIX_TIMING runs=%d wall_s=%.1f build_s=%.1f "
              "simulation_s=%.1f budget_s=%d within_budget=%s"
              % (len(cls.timings), total, build, elapsed, budget,
                 total <= budget))
        for item in cls.timings:
            print("MYFUZZ_SOC_MATRIX_TIMING cell=%s mode=%s elaborate_s=%.1f "
                  "build_s=%.1f simulation_s=%.2f wall_s=%.1f cache_hit=%s"
                  % (item["cell"], item["mode"], item["elaborate_s"],
                     item["build_s"], item["run_s"], item["wall_s"],
                     item["cache_hit"]))
        cells = sorted({item["cell"] for item in cls.timings})
        for cell_id in cells:
            walls = [item["wall_s"] for item in cls.timings if item["cell"] == cell_id]
            print("MYFUZZ_SOC_MATRIX_TIMING cell=%s wall_s=%.1f modes=%d"
                  % (cell_id, sum(walls), len(walls)))

    # -- shared assertions -------------------------------------------------

    def assert_mode_observations(self, result: dict) -> None:
        obs = result["observations"]
        exp = result["expectations"]
        mode = result["mode"]
        label = "%s/%s" % (result["cell_id"], mode)
        self.assertEqual("OK", obs["status"],
                         "%s: testbench status %s" % (label, obs["status"]))
        self.assertEqual(0, obs["fabric_error"], "%s: fabric error" % label)
        self.assertEqual(exp["cpu_source_id"], obs["cpu_source_id"])
        self.assertEqual(exp["fuzz_source_id"], obs["fuzz_source_id"])

        if mode == "cpu_only":
            self.assertGreaterEqual(obs["cpu_tx"], 2,
                                    "%s: CPU issued no real MMIO transaction" % label)
            self.assertGreater(obs["cpu_done"], 0,
                               "%s: CPU transaction never completed" % label)
            self.assertEqual(0, obs["fuzz_tx"], "%s: fuzz source accepted" % label)
            self.assertEqual(0, obs["fuzz_done"], "%s: fuzz source completed" % label)
            self.assertGreaterEqual(obs["window_done_cpu"], 1,
                                    "%s: no CPU-attributed window transaction" % label)
            self.assertEqual(0, obs["window_done_fuzz"],
                             "%s: fuzz-attributed window transaction in cpu_only" % label)
            self.assertEqual(FLAG_OK, obs["cpu_flag"],
                             "%s: CPU completion flag %08x" % (label, obs["cpu_flag"]))
        elif mode == "mmio_only":
            self.assertEqual(0, obs["cpu_tx"],
                             "%s: CPU held in reset issued a transaction" % label)
            self.assertEqual(0, obs["cpu_done"],
                             "%s: CPU held in reset completed a transaction" % label)
            self.assertEqual(0, obs["cpu_flag"],
                             "%s: CPU wrote a completion flag while held in reset" % label)
            self.assertEqual(exp["fuzz_transactions"], obs["fuzz_tx"],
                             "%s: fuzz accepted count" % label)
            self.assertEqual(exp["fuzz_completions"], obs["fuzz_done"],
                             "%s: fuzz completed count" % label)
            self.assertGreaterEqual(obs["window_done_fuzz"], 1,
                                    "%s: no fuzz-attributed window transaction" % label)
            self.assertEqual(0, obs["window_done_cpu"],
                             "%s: CPU-attributed transaction in mmio_only" % label)
        else:
            self.assertGreaterEqual(obs["cpu_tx"], 2,
                                    "%s: CPU issued no real MMIO transaction" % label)
            self.assertGreater(obs["cpu_done"], 0,
                               "%s: CPU transaction never completed" % label)
            self.assertEqual(exp["fuzz_transactions"], obs["fuzz_tx"],
                             "%s: fuzz accepted count" % label)
            self.assertEqual(exp["fuzz_completions"], obs["fuzz_done"],
                             "%s: fuzz completed count" % label)
            self.assertEqual(FLAG_OK, obs["cpu_flag"],
                             "%s: CPU completion flag" % label)
            self.assertGreaterEqual(obs["window_done_cpu"], 1,
                                    "%s: no CPU-attributed window transaction" % label)
            self.assertGreaterEqual(obs["window_done_fuzz"], 1,
                                    "%s: no fuzz-attributed window transaction" % label)

        # The real peripheral side effect, observed on the pinned IP output.
        side_effect = exp["side_effect"]
        key = side_effect["key"]
        self.assertIn(key, obs, "%s: missing side-effect observation %s" % (label, key))
        if side_effect["kind"] == "gpio_out_register":
            self.assertEqual(side_effect["expected"], obs[key],
                             "%s: real %s output register"
                             % (label, side_effect["peripheral_id"]))
        elif side_effect["kind"] == "uart_tx_activity":
            self.assertGreaterEqual(obs[key], 2,
                                    "%s: real %s TX line showed no frame"
                                    % (label, side_effect["peripheral_id"]))
        elif side_effect["kind"] == "timer_readback":
            self.assertGreater(obs[key], 0)
            self.assertLessEqual(obs[key], side_effect["expected"])
        elif side_effect["kind"] == "register_write_readback":
            # The pinned zipcpu wrapper ties the wbuart CTS input so its
            # transmitter never leaves IDLE (see the smoke module's evidence);
            # the observed side effect is the real IP register round trip.
            self.assertEqual(side_effect["expected"], obs[key],
                             "%s: real %s register 0x%08x"
                             % (label, side_effect["peripheral_id"], obs[key]))

        # The register the program reads back really came from the pinned IP.
        if exp["readback_expected"] is not None:
            if mode in ("cpu_only", "mixed"):
                self.assertEqual(exp["readback_expected"], obs["cpu_readback"],
                                 "%s: CPU-read register value" % label)
            if mode in ("mmio_only", "mixed"):
                self.assertEqual(exp["readback_expected"], obs["fuzz_rdata"],
                                 "%s: synthetic-master register value" % label)

    def run_cell(self, cell: dict) -> None:
        cell_id = cell["cell_id"]
        config_path = ROOT / cell["config"]
        self.assertTrue(config_path.is_file(), "missing cell config %s" % config_path)
        for mode in MODES:
            output_dir = OUTPUT_ROOT / cell_id / mode
            started = time.monotonic()
            result = run_cell_mode(config_path, mode, output_dir)
            self.assertEqual(cell_id, result["cell_id"])
            self.assertEqual(mode, result["mode"])
            self.assertIn("MYFUZZ_SOC_MATRIX_RUN", result["observation_line"])
            self.assert_mode_observations(result)
            # Same cell + mode + seed rebuilds nothing and repeats exactly.
            again = run_cell_mode(config_path, mode, output_dir)
            self.assertTrue(again["artifacts"]["cache_hit"],
                            "%s/%s: second run rebuilt instead of using the cache"
                            % (cell_id, mode))
            self.assertEqual(_canonical(result), _canonical(again),
                             "%s/%s: run is not deterministic" % (cell_id, mode))
            self.timings.append({
                "cell": cell_id, "mode": mode,
                "build_s": result["timings"]["build_s"],
                "elaborate_s": result["timings"]["elaborate_s"],
                "run_s": result["timings"]["run_s"],
                "wall_s": time.monotonic() - started,
                "cache_hit": result["artifacts"]["cache_hit"],
            })
            print(result["observation_line"])

    # -- one test per matrix cell -----------------------------------------

    def test_cell_cva6_mixed(self):
        self.run_cell(self.cell("cva6-mixed"))

    def test_cell_cva6_opentitan(self):
        self.run_cell(self.cell("cva6-opentitan"))

    def test_cell_cva6_pulp(self):
        self.run_cell(self.cell("cva6-pulp"))

    def test_cell_cva6_zipcpu(self):
        self.run_cell(self.cell("cva6-zipcpu"))

    def test_cell_ibex_mixed(self):
        self.run_cell(self.cell("ibex-mixed"))

    def test_cell_ibex_opentitan(self):
        self.run_cell(self.cell("ibex-opentitan"))

    def test_cell_ibex_pulp(self):
        self.run_cell(self.cell("ibex-pulp"))

    def test_cell_ibex_zipcpu(self):
        self.run_cell(self.cell("ibex-zipcpu"))

    def cell(self, cell_id: str) -> dict:
        for entry in self.cells:
            if entry["cell_id"] == cell_id:
                return entry
        raise AssertionError("matrix does not declare cell %s" % cell_id)


class SocMatrixStructureTests(unittest.TestCase):
    """Always-runnable structural checks of the runtime smoke module."""

    def test_matrix_declares_eight_cells_and_three_modes(self):
        matrix = load_matrix(MATRIX)
        self.assertEqual(sorted(matrix["modes"]), sorted(MODES))
        self.assertEqual(8, len(matrix["cells"]))
        self.assertEqual(8, len({cell["cell_id"] for cell in matrix["cells"]}))

    def test_generated_boot_program_comes_from_the_cell_address_map(self):
        for cell in load_matrix(MATRIX)["cells"]:
            config = ROOT / cell["config"]
            with self.subTest(cell=cell["cell_id"]):
                first = cell_documents(config, "mixed")
                second = cell_documents(config, "mixed")
                target = first["target"]
                program = first["program"]
                self.assertIn("%08x" % target["window_base"],
                              program["assembly"] + "\n".join(program["listing"]))
                # The program is a pure function of the plan: same plan, same
                # words and same image.
                self.assertEqual(program["hex"], second["program"]["hex"])
                self.assertEqual(program["assembly"], second["program"]["assembly"])
                self.assertGreater(program["words"], 4)
                self.assertIn(target["peripheral_id"], program["assembly"])

    def test_cell_documents_share_the_renderer_source_closure(self):
        """The runtime plan must render from the renderer half's real sources.

        The runtime plan additionally declares the read/write capability of
        every pinned peripheral, because the P3 planner turns a target's
        declared capability into the router's window permissions: without it
        every MMIO window decodes as read=false/write=false and the router
        answers error without ever touching the real IP.  The source closure,
        the address map and the fabric topology must be identical to the
        renderer half's.
        """
        from myfuzz.composition.soc_renderer import render_soc
        from tests.integration.test_soc_renderer_cells import (
            cell_documents as renderer_documents,
        )
        for cell in load_matrix(MATRIX)["cells"]:
            with self.subTest(cell=cell["cell_id"]):
                mine = cell_documents(ROOT / cell["config"], "mixed")
                plan, stimulus, config = renderer_documents(cell)
                self.assertEqual(config["cell_id"], mine["config"]["cell_id"])
                theirs = json.loads(render_soc(plan, stimulus)["soc_manifest.json"])
                rendered = render_soc(mine["plan"], mine["stimulus"])
                ours = json.loads(rendered["soc_manifest.json"])
                # The generated testbench drives exactly these ports and
                # observes exactly these internal wires of the rendered top.
                validate_top_requirements(rendered["soc_top.sv"],
                                          ports=TB_REQUIRED_PORTS,
                                          wires=TB_REQUIRED_WIRES)
                for field in ("source_files", "include_dirs", "defines"):
                    self.assertEqual(theirs["real_elaboration"][field],
                                     ours["real_elaboration"][field])
                self.assertEqual(sorted(theirs["peripherals"]), sorted(ours["peripherals"]))
                self.assertEqual(
                    sorted((w["target_id"], w["window"]["base"], w["window"]["size"])
                           for w in plan["address_map"]["windows"]),
                    sorted((w["target_id"], w["window"]["base"], w["window"]["size"])
                           for w in mine["plan"]["address_map"]["windows"]))
                self.assertEqual([s["source_id"] for s in plan["fabric"]["sources"]],
                                 [s["source_id"] for s in mine["plan"]["fabric"]["sources"]])
                # The runtime plan must permit the accesses the smoke performs.
                probe = mine["target"]["window_target_id"]
                capabilities = mine["plan"]["target_capabilities"][probe]["capabilities"]
                self.assertTrue(capabilities["read"],
                                "%s: probe window is not readable" % probe)
                self.assertTrue(capabilities["write"],
                                "%s: probe window is not writable" % probe)

    def test_missing_closure_source_fails_with_the_exact_path(self):
        manifest = {
            "real_elaboration": {
                "source_files": ["third_party/does_not_exist/rtl/missing.sv"],
                "include_dirs": [], "defines": [],
                "cpu_core": "soc_ibex_beat_core",
            },
            "real_cpu": {"core_source": "src/myfuzz/does_not_exist_core.sv"},
            "peripherals": {},
        }
        with self.assertRaises(SocMatrixSmokeError) as caught:
            validate_closure_files(ROOT, manifest)
        message = str(caught.exception)
        self.assertIn("third_party/does_not_exist/rtl/missing.sv", message)
        self.assertIn("src/myfuzz/does_not_exist_core.sv", message)

    def test_missing_top_port_or_wire_fails_with_its_name(self):
        with self.assertRaises(SocMatrixSmokeError) as caught:
            validate_top_requirements("module myfuzz_soc_top(input logic clk_i);",
                                      ports=("clk_i", "stim_offer_i"),
                                      wires=("fabric_source_id",))
        message = str(caught.exception)
        self.assertIn("stim_offer_i", message)
        self.assertIn("fabric_source_id", message)

    def test_verilator_is_required_when_opted_in(self):
        if not OPT_IN:
            self.skipTest("opt-in only")
        self.assertIsNotNone(shutil.which("verilator"),
                             "Verilator is required for the real SoC matrix runtime")


if __name__ == "__main__":
    unittest.main()
