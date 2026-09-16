from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "configs" / "designs" / "ibex_opentitan_real_ip"
PREPARE_SCRIPT = TARGET / "scripts" / "prepare_sources.py"
PILOT_SCRIPT = ROOT / "scripts" / "runs" / "run_ibex_opentitan_real_ip_pilot.py"
EXPECTED_OPENTITAN_REVISION = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"


def load_prepare_module():
    spec = importlib.util.spec_from_file_location("ibex_ot_prepare_sources", PREPARE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PREPARE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_pilot_module():
    spec = importlib.util.spec_from_file_location("ibex_ot_pilot", PILOT_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PILOT_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IbexOpenTitanRealIpTargetTest(unittest.TestCase):
    def load_config(self, variant: str) -> dict:
        path = TARGET / variant / "config.json"
        self.assertTrue(path.is_file(), path)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_real_target_uses_pinned_official_ip_sources(self) -> None:
        source_list = TARGET / "rtl" / "opentitan_sources.f"
        self.assertTrue(source_list.is_file(), source_list)
        sources = source_list.read_text(encoding="utf-8")
        for path in (
            "external_designs/opentitan/hw/ip/uart/rtl/uart.sv",
            "external_designs/opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio.sv",
            "external_designs/opentitan/hw/ip/rv_timer/rtl/rv_timer.sv",
        ):
            self.assertIn(path, sources)
        self.assertIn("external_designs/opentitan/hw/ip/prim/", sources)
        self.assertIn("external_designs/opentitan/hw/ip/prim_generic/", sources)
        self.assertIn("external_designs/opentitan/hw/ip/tlul/", sources)
        self.assertIn(
            "+incdir+external_designs/opentitan/hw/dv/sv/dv_utils", sources
        )
        self.assertNotIn("ibex_mcip_", sources)

    def test_prepare_sources_rejects_wrong_revision(self) -> None:
        self.assertTrue(PREPARE_SCRIPT.is_file(), PREPARE_SCRIPT)
        module = load_prepare_module()
        with self.assertRaisesRegex(RuntimeError, "OpenTitan revision"):
            module.prepare_sources(ROOT, revision_reader=lambda _: "0" * 40)

    def test_prepare_sources_pins_expected_revision(self) -> None:
        self.assertTrue(PREPARE_SCRIPT.is_file(), PREPARE_SCRIPT)
        module = load_prepare_module()
        self.assertEqual(module.EXPECTED_OPENTITAN_REVISION, EXPECTED_OPENTITAN_REVISION)

    def test_system_top_instantiates_only_official_peripheral_tops(self) -> None:
        top_path = TARGET / "rtl" / "ibex_opentitan_real_ip_top.sv"
        self.assertTrue(top_path.is_file(), top_path)
        top = top_path.read_text(encoding="utf-8")
        for declaration in ("uart u_uart", "gpio u_gpio", "rv_timer u_rv_timer"):
            self.assertIn(declaration, top)
        self.assertNotIn("ibex_mcip_", top)

    def test_mmio_exerciser_touches_all_regions(self) -> None:
        assembly_path = TARGET / "programs" / "mmio_exerciser.S"
        self.assertTrue(assembly_path.is_file(), assembly_path)
        assembly = assembly_path.read_text(encoding="utf-8")
        for address in ("0x40000000", "0x40010000", "0x40020000"):
            self.assertIn(address, assembly)
        image = TARGET / "programs" / "mmio_exerciser.hex"
        self.assertTrue(image.is_file(), image)
        self.assertGreater(image.stat().st_size, 0)

    def test_firmware_matches_ibex_reset_entry(self) -> None:
        link = (TARGET / "programs" / "link.ld").read_text(encoding="ascii")
        self.assertIn(". = 0x80;", link)
        words = (TARGET / "programs" / "mmio_exerciser.hex").read_text(
            encoding="ascii"
        ).splitlines()
        self.assertGreaterEqual(len(words), 33)
        self.assertEqual(words[:32], ["00000013"] * 32)
        self.assertNotEqual(words[32], "00000013")

    def test_depaware_debug_event_is_reachable_within_server_budget(self) -> None:
        source = (TARGET / "harness" / "ibex_ot_depaware_projection_harness.sv").read_text(
            encoding="ascii"
        )
        self.assertIn("cycle_q[7:0] == {2'b00, rfuzz_input_bits[247:242]}", source)
        self.assertNotIn("8'hff", source)

    def test_outer_filelist_contains_shared_top_and_upstream_ibex(self) -> None:
        sources = (TARGET / "rtl" / "sources.f").read_text(encoding="utf-8")
        official_sources = (TARGET / "rtl" / "opentitan_sources.f").read_text(
            encoding="utf-8"
        )
        for ibex_source in ("ibex_top.sv", "ibex_core.sv"):
            self.assertIn(
                "external_designs/opentitan/hw/vendor/lowrisc_ibex/rtl/"
                + ibex_source,
                official_sources,
            )
        self.assertIn(
            "configs/designs/ibex_opentitan_real_ip/rtl/ibex_opentitan_real_ip_top.sv",
            sources,
        )
        self.assertIn(
            "-f configs/designs/ibex_opentitan_real_ip/rtl/opentitan_sources.f",
            sources,
        )

    def test_harnesses_share_top_width_and_instrumentation(self) -> None:
        variants = ("baseline_direct_slice", "depaware_projection")
        configs = [self.load_config(variant) for variant in variants]
        for key in ("top", "flist", "instrumentation"):
            self.assertEqual(configs[0][key], configs[1][key])
        self.assertEqual(configs[0]["top"], "ibex_opentitan_real_ip_top")

        for config in configs:
            harness_path = ROOT / config["harness"]["manual_harness"]
            source = harness_path.read_text(encoding="utf-8")
            self.assertIn("logic [511:0] rfuzz_input_bits", source)
            self.assertIn("ibex_opentitan_real_ip_top dut", source)

    def test_depaware_projection_has_no_dut_output_feedback(self) -> None:
        config = self.load_config("depaware_projection")
        source = (ROOT / config["harness"]["manual_harness"]).read_text(
            encoding="utf-8"
        )
        self.assertIsNone(re.search(r"assign\s+\w+\s*=.*dut\.", source))
        self.assertNotIn("dut.", source)

    def test_instrumenter_honors_verilator_lowercase_f_paths(self) -> None:
        from scripts.source_branch_instrumenter import parse_flist

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "lists").mkdir()
            (project / "rtl").mkdir()
            top = project / "rtl" / "top.sv"
            child = project / "rtl" / "child.sv"
            top.write_text("module top; endmodule\n", encoding="ascii")
            child.write_text("module child; endmodule\n", encoding="ascii")
            (project / "nested.f").write_text("rtl/child.sv\n", encoding="ascii")
            outer = project / "lists" / "sources.f"
            outer.write_text("-f nested.f\nrtl/top.sv\n", encoding="ascii")

            result = parse_flist(outer, project)
            self.assertEqual(set(result.files), {top.resolve(), child.resolve()})

    def test_pilot_rejects_different_coverage_universes(self) -> None:
        pilot = load_pilot_module()
        with self.assertRaisesRegex(RuntimeError, "coverage universe"):
            pilot.validate_pair(
                {"coverage_width": 10, "coverage_identity": "a"},
                {"coverage_width": 10, "coverage_identity": "b"},
            )

    def test_pilot_summary_names_real_opentitan_revision(self) -> None:
        pilot = load_pilot_module()
        result = {"coverage_width": 10, "coverage_identity": "same"}
        summary = pilot.build_summary(result, result)
        self.assertEqual(summary["target"], "ibex_opentitan_real_ip")
        self.assertEqual(
            summary["opentitan_revision"], EXPECTED_OPENTITAN_REVISION
        )


if __name__ == "__main__":
    unittest.main()
