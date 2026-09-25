"""Real PULP RTL regression for the SPI peer's mode-0 output timing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.composition.soc_generation_fixture import ROOT


SOURCES = (
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    "third_party/soc-pulp-apb-spi/spi_master_apb_if.sv",
    "third_party/soc-pulp-axi-spi/spi_master_clkgen.sv",
    "third_party/soc-pulp-axi-spi/spi_master_controller.sv",
    "third_party/soc-pulp-axi-spi/spi_master_fifo.sv",
    "third_party/soc-pulp-axi-spi/spi_master_rx.sv",
    "third_party/soc-pulp-axi-spi/spi_master_tx.sv",
    "src/myfuzz/protocols/rtl/soc_pulp_spi_peer.sv",
    "tests/integration/rtl/soc_pulp_spi_peer_timing_tb.sv",
)


@unittest.skipUnless(shutil.which("verilator"), "Verilator required")
class PulpSpiPeerTimingTests(unittest.TestCase):
    def test_literal_32_bit_rx_at_divider_zero_and_one(self):
        for source in SOURCES:
            self.assertTrue((ROOT / source).is_file(), source)
        with tempfile.TemporaryDirectory() as tmp:
            command = [
                "verilator", "--binary", "--timing", "--top-module",
                "soc_pulp_spi_peer_timing_tb", "-Wno-fatal", "-Wno-lint",
                "--Mdir", tmp, *(str(ROOT / source) for source in SOURCES),
            ]
            built = subprocess.run(command, cwd=ROOT, text=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=False)
            self.assertEqual(0, built.returncode, built.stdout)
            result = subprocess.run(
                [str(Path(tmp) / "Vsoc_pulp_spi_peer_timing_tb")], cwd=ROOT,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("spi_peer_timing_pass divider=0 rx=a5c396f0", result.stdout.lower())
            self.assertIn("spi_peer_timing_pass divider=1 rx=a5c396f0", result.stdout.lower())
            for divider in (0, 1):
                self.assertIn(
                    f"spi_rx_samples divider={divider} count=32 word=a5c396f0",
                    result.stdout.lower(),
                )
                fall_window = 1 if divider == 0 else 0
                self.assertIn(
                    "spi_rx_sample div={} index=0 sck_pre=0 miso=1 "
                    "peer_head=10 peer_fall={}".format(divider, fall_window),
                    result.stdout.lower(),
                )
            self.assertIn("SPI_PEER_TIMING_ALL_PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
