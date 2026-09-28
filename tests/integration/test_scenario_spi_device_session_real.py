"""Pinned OpenTitan SPI Device executes TL configuration and external SPI."""

from __future__ import annotations

import os
import unittest


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealSpiDeviceSessionTests(unittest.TestCase):
    def test_explicit_reset_starts_new_rtl_epoch_with_monotonic_local_ticks(self):
        from myfuzz.scenario.spi_device_session import OpenTitanSpiDeviceSession

        device = OpenTitanSpiDeviceSession()
        device.begin_case("spi-device-explicit-reset")
        try:
            device.write_register(0x30, 0x00A11234)
            previous_ticks = device.local_ticks
            device.reset_local()
            device.step_local({})
            self.assertGreater(device.local_ticks, previous_ticks)
            self.assertNotEqual(0x00A11234, device.read_register(0x30))
        finally:
            device.end_case()

    def test_duplicate_local_command_returns_cached_result(self):
        from myfuzz.scenario.spi_device_session import OpenTitanSpiDeviceSession

        device = OpenTitanSpiDeviceSession()
        device.begin_case("spi-device-command-retry")
        try:
            proc = device._process
            assert proc is not None and proc.stdin is not None and proc.stdout is not None
            command = (f"CMD {device._wire_execution} 1 0 1 0 1 1 "
                       "40000010 10 f 1\n")
            proc.stdin.write(command)
            proc.stdin.flush()
            first = proc.stdout.readline()
            proc.stdin.write(command)
            proc.stdin.flush()
            repeated = proc.stdout.readline()
            self.assertEqual(first, repeated)
            self.assertTrue(first.startswith("RESULT "), first)
        finally:
            device.end_case()

    def test_source_adapter_reuses_one_session_across_cases(self):
        from myfuzz.scenario.ibex_spi_device_example import _FuzzableSpiDeviceSession

        device = _FuzzableSpiDeviceSession()
        for case_id in ("spi-device-case-a", "spi-device-case-b"):
            device.begin_case(case_id)
            try:
                device.write_register(0x10, 1 << 4)
                device.write_register(0xA8, 0x81010202)
                device.step_local({"frame_1": 0x0012345A})
                self.assertEqual(0x02, device.read_register(0x44) & 0xff)
            finally:
                device.end_case()

    def test_jedec_response_comes_from_configured_rtl(self):
        from myfuzz.scenario.spi_device_session import OpenTitanSpiDeviceSession

        device = OpenTitanSpiDeviceSession()
        device.begin_case("spi-device-jedec")
        try:
            device.write_register(0x10, 1 << 4)  # FlashMode
            device.write_register(0x30, 0x00A11234)
            device.write_register(0x88, 0x8012009F)
            self.assertEqual(0x00A11234, device.read_register(0x30))
            self.assertEqual(bytes((0xA1, 0x34, 0x12)),
                             device.transfer_bytes(bytes((0x9F,)), read_count=3))
            # A second transfer uses the same RTL instance and CSR state.
            self.assertEqual(bytes((0xA1, 0x34, 0x12)),
                             device.transfer_bytes(bytes((0x9F,)), read_count=3))
        finally:
            device.end_case()

    def test_external_upload_is_visible_in_real_fifo(self):
        from myfuzz.scenario.spi_device_session import OpenTitanSpiDeviceSession

        device = OpenTitanSpiDeviceSession()
        device.begin_case("spi-device-upload")
        try:
            device.write_register(0x10, 1 << 4)
            device.write_register(0xA8, 0x81010202)
            device.write_register(0x04, 1)  # upload command FIFO IRQ enable
            device.transfer_bytes(bytes((0x02, 0x00, 0x12, 0x34, 0x5A)))
            for _ in range(100):
                result = device.step_local({})
                if result["irq"] & 1:
                    break
            self.assertEqual(1, result["irq"] & 1)
            self.assertEqual(0x02, device.read_register(0x44) & 0xff)
            self.assertEqual(0x001234, device.read_register(0x48) & 0xffffff)
            self.assertEqual(0x5A, device.read_register(0x1e00) & 0xff)
        finally:
            device.end_case()


if __name__ == "__main__":
    unittest.main()
