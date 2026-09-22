"""SPI wire monitors must follow resolved role bindings, not port guesses."""
from __future__ import annotations

import unittest

from myfuzz.composition.soc_runtime import _spi_wire_records, render_profile_testbench
from tests.composition.test_soc_peer_interrupt_plan import SpiInterruptPlanTests


class SpiWireCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SpiInterruptPlanTests.setUpClass()
        cls.plan = SpiInterruptPlanTests.plan

    def test_monitor_uses_four_bound_roles(self) -> None:
        peer = self.plan.peer("spi0")
        records = _spi_wire_records(self.plan)
        self.assertEqual(1, len(records))
        record = records[0]
        self.assertEqual("spi0", record["instance_id"])
        self.assertEqual(
            {role: f"dut.{peer.instance_id}__{peer.binding(role).component_port}"
             for role in ("sck", "cs", "mosi", "miso")},
            record["roles"])
        bench = render_profile_testbench(self.plan)
        self.assertIn("MYFUZZ_PEER_WIRE", bench)
        for signal in record["roles"].values():
            self.assertIn(signal, bench)


if __name__ == "__main__":
    unittest.main()
