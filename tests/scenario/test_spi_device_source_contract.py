"""SPI Device source adapter never accepts fabricated RTL feedback."""

import unittest
from unittest.mock import patch

from myfuzz.scenario.ibex_spi_device_example import _FuzzableSpiDeviceSession
from myfuzz.scenario.spi_device_session import OpenTitanSpiDeviceSession


class SpiDeviceSourceContractTests(unittest.TestCase):
    def test_two_pending_frames_are_sent_on_separate_local_steps(self):
        device = _FuzzableSpiDeviceSession()
        pending = {"frame_1": 0x0012345a, "frame_2": 0x005678a6}
        with patch.object(OpenTitanSpiDeviceSession, "step_local",
                          return_value={"irq": 0}), \
                patch.object(device, "transfer_bytes", return_value=b"") as transfer:
            device.step_local(pending)
            self.assertEqual(1, transfer.call_count)
            device.step_local(pending)
            self.assertEqual(2, transfer.call_count)

    def test_irq_and_mmio_response_cannot_be_supplied_as_sources(self):
        device = _FuzzableSpiDeviceSession()
        for port in ("irq", "rdata", "jedec_read"):
            with self.subTest(port=port), self.assertRaisesRegex(ValueError, "undeclared"):
                device.step_local({port: 1})


if __name__ == "__main__":
    unittest.main()
