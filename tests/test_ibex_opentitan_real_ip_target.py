from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "configs" / "designs" / "ibex_opentitan_real_ip"
PREPARE_SCRIPT = TARGET / "scripts" / "prepare_sources.py"
EXPECTED_OPENTITAN_REVISION = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"


def load_prepare_module():
    spec = importlib.util.spec_from_file_location("ibex_ot_prepare_sources", PREPARE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PREPARE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IbexOpenTitanRealIpTargetTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
