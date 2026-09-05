"""Public runtime protocol API and RTL source inventory checks."""

from __future__ import annotations

from pathlib import Path
import unittest

import myfuzz.protocols as protocols


_RTL_DIR = Path(__file__).resolve().parents[2] / "src" / "myfuzz" / "protocols" / "rtl"
_RTL_SOURCES = (
    "apb4_mmio_bridge.sv",
    "apb4_mmio_target.sv",
    "axi4_lite_mmio_bridge.sv",
    "axi4_lite_mmio_target.sv",
    "tl_ul_mmio_bridge.sv",
    "tl_ul_mmio_target.sv",
)


class RuntimeProtocolApiTest(unittest.TestCase):
    def test_runtime_models_and_compiler_are_public(self) -> None:
        for symbol in (
            "Apb4BridgeModel",
            "Axi4LiteBridgeModel",
            "TileLinkUlBridgeModel",
            "compile_runtime_protocol",
        ):
            self.assertIn(symbol, protocols.__all__)
            self.assertTrue(callable(getattr(protocols, symbol)))

    def test_rtl_sources_are_bounded_and_deterministic(self) -> None:
        for source_name in _RTL_SOURCES:
            source = _RTL_DIR / source_name
            self.assertTrue(source.is_file(), source_name)
            contents = source.read_text(encoding="utf-8")
            self.assertIn("MAX_WAIT_CYCLES", contents, source_name)
            self.assertNotIn("$random", contents, source_name)

    def test_rtl_readme_describes_runtime_contract(self) -> None:
        readme = (_RTL_DIR / "README.md").read_text(encoding="utf-8")
        for phrase in (
            "MMIO",
            "APB4",
            "AXI4-Lite",
            "TL-UL",
            "16",
            "backpressure",
            "error",
            "resource",
        ):
            self.assertIn(phrase, readme)


if __name__ == "__main__":
    unittest.main()
