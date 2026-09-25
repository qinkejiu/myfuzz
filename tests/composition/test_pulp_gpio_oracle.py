"""Literal-vector tests for the independent PULP GPIO oracle."""

import unittest

from myfuzz.composition.pulp_gpio_oracle import (
    PulpGpioOracle,
    PulpGpioOracleError,
)


class PulpGpioOracleRegisterTests(unittest.TestCase):
    def setUp(self):
        self.oracle = PulpGpioOracle(pins=32)

    def test_reset_state_is_all_zero(self):
        pins = self.oracle.sample_pins(0)
        self.assertEqual({
            "gpio_out": 0,
            "gpio_dir": 0,
            "gpio_padcfg": 0,
            "gpio_in_sync": 0,
        }, pins)
        self.assertEqual(0, self.oracle.apb_access(address=0x00, write=False, wdata=0))
        self.assertEqual(0, self.oracle.apb_access(address=0x04, write=False, wdata=0))
        self.assertEqual(0, self.oracle.apb_access(address=0x0C, write=False, wdata=0))

    def test_padout_write_and_read(self):
        self.assertIsNone(self.oracle.apb_access(address=0x0C, write=True, wdata=0x12345678))
        self.assertEqual(0x12345678, self.oracle.apb_access(address=0x0C, write=False, wdata=0))
        self.assertEqual(0x12345678, self.oracle.sample_pins(0)["gpio_out"])

    def test_padoutset_sets_only_one_bits(self):
        self.oracle.apb_access(address=0x0C, write=True, wdata=0xA0)
        self.oracle.apb_access(address=0x10, write=True, wdata=0x05)
        self.assertEqual(0xA5, self.oracle.apb_access(address=0x0C, write=False, wdata=0))

    def test_padoutclr_clears_only_one_bits(self):
        self.oracle.apb_access(address=0x0C, write=True, wdata=0xFF)
        self.oracle.apb_access(address=0x14, write=True, wdata=0x24)
        self.assertEqual(0xDB, self.oracle.apb_access(address=0x0C, write=False, wdata=0))

    def test_paddir_and_gpioen_are_independent_registers(self):
        self.oracle.apb_access(address=0x00, write=True, wdata=0x80000011)
        self.oracle.apb_access(address=0x04, write=True, wdata=0x000000F0)
        self.assertEqual(0x80000011, self.oracle.apb_access(address=0x00, write=False, wdata=0))
        self.assertEqual(0x000000F0, self.oracle.apb_access(address=0x04, write=False, wdata=0))
        self.assertEqual(0x80000011, self.oracle.sample_pins(0)["gpio_dir"])

    def test_padcfg_words_are_preserved_and_packed_by_pad(self):
        self.oracle.apb_access(address=0x28, write=True, wdata=0x76543210)
        self.oracle.apb_access(address=0x2C, write=True, wdata=0xFEDCBA98)
        self.assertEqual(0x76543210, self.oracle.apb_access(address=0x28, write=False, wdata=0))
        self.assertEqual(0xFEDCBA98, self.oracle.apb_access(address=0x2C, write=False, wdata=0))
        self.assertEqual(0xFEDCBA9876543210, self.oracle.sample_pins(0)["gpio_padcfg"])


class PulpGpioOracleSamplingTests(unittest.TestCase):
    def test_input_pipeline_has_literal_three_sample_timing(self):
        oracle = PulpGpioOracle(pins=32)
        oracle.apb_access(address=0x04, write=True, wdata=0x00000001)
        expected = [
            {"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
             "gpio_in_sync": 0},
            {"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
             "gpio_in_sync": 1},
            {"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
             "gpio_in_sync": 0},
            {"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
             "gpio_in_sync": 0},
        ]
        actual = [oracle.sample_pins(value) for value in (1, 0, 0)]
        self.assertEqual(expected[:3], actual)
        self.assertEqual(1, oracle.apb_access(address=0x08, write=False, wdata=0))
        self.assertEqual(expected[3], oracle.sample_pins(0))

    def test_group_sampling_enabled_by_any_gpioen_bit_in_each_quad(self):
        oracle = PulpGpioOracle(pins=32)
        oracle.apb_access(address=0x04, write=True, wdata=0x00000008)
        self.assertEqual(0, oracle.sample_pins(0x00000001)["gpio_in_sync"])
        self.assertEqual(0x00000001, oracle.sample_pins(0x00000001)["gpio_in_sync"])

    def test_disabled_neighboring_group_does_not_sample_when_another_group_is_enabled(self):
        oracle = PulpGpioOracle(pins=32)
        oracle.apb_access(address=0x04, write=True, wdata=0x00000008)

        # Pad 4 toggles while only group 0 has an enable bit. Its whole
        # 4-pad group must remain held despite group 0 being active.
        self.assertEqual(0, oracle.sample_pins(0x00000010)["gpio_in_sync"])
        self.assertEqual(0, oracle.sample_pins(0x00000000)["gpio_in_sync"])
        self.assertEqual(0, oracle.sample_pins(0x00000010)["gpio_in_sync"])

        # Enabling group 1 starts its pipeline; the first stage-2 observation
        # is delayed by one sample, then reflects pad 4.
        oracle.apb_access(address=0x04, write=True, wdata=0x00000018)
        self.assertEqual(0, oracle.sample_pins(0x00000010)["gpio_in_sync"])
        self.assertEqual(0x00000010, oracle.sample_pins(0x00000010)["gpio_in_sync"])

    def test_disabled_group_holds_all_stages(self):
        oracle = PulpGpioOracle(pins=32)
        oracle.apb_access(address=0x04, write=True, wdata=0x00000001)
        oracle.sample_pins(1)
        oracle.apb_access(address=0x04, write=True, wdata=0)
        held = {"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
                "gpio_in_sync": 0}
        self.assertEqual(held, oracle.sample_pins(0))
        self.assertEqual(held, oracle.sample_pins(0))


class PulpGpioOracleRefusalTests(unittest.TestCase):
    def assert_refused(self, operation, reason):
        with self.assertRaises(PulpGpioOracleError) as caught:
            operation()
        self.assertEqual(reason, caught.exception.reason)

    def test_reset_clears_registers_and_input_history(self):
        oracle = PulpGpioOracle(pins=32)
        oracle.apb_access(address=0x04, write=True, wdata=1)
        oracle.apb_access(address=0x0C, write=True, wdata=0xA5)
        oracle.sample_pins(1)
        oracle.reset()
        self.assertEqual(0, oracle.apb_access(address=0x04, write=False, wdata=0))
        self.assertEqual(0, oracle.apb_access(address=0x0C, write=False, wdata=0))
        self.assertEqual({"gpio_out": 0, "gpio_dir": 0, "gpio_padcfg": 0,
                          "gpio_in_sync": 0}, oracle.sample_pins(0))

    def test_only_supported_pin_parameterization_is_accepted(self):
        self.assert_refused(lambda: PulpGpioOracle(pins=8), "unsupported-pin-width")

    def test_unaligned_access_is_refused(self):
        oracle = PulpGpioOracle(pins=32)
        self.assert_refused(lambda: oracle.apb_access(address=0x0D, write=False, wdata=0),
                            "unaligned-access")

    def test_unmapped_offset_is_refused(self):
        oracle = PulpGpioOracle(pins=32)
        self.assert_refused(lambda: oracle.apb_access(address=0x80, write=False, wdata=0),
                            "unsupported-offset")

    def test_interrupt_and_status_semantics_are_not_assessed(self):
        oracle = PulpGpioOracle(pins=32)
        for address in (0x18, 0x1C, 0x20, 0x24):
            self.assert_refused(
                lambda address=address: oracle.apb_access(address=address, write=False, wdata=0),
                "not-assessed-interrupt-status-semantics",
            )

    def test_read_only_padin_cannot_be_written(self):
        oracle = PulpGpioOracle(pins=32)
        self.assert_refused(lambda: oracle.apb_access(address=0x08, write=True, wdata=1),
                            "write-to-read-only-register")

    def test_data_must_be_unsigned_32_bit(self):
        oracle = PulpGpioOracle(pins=32)
        self.assert_refused(lambda: oracle.apb_access(address=0x0C, write=True, wdata=1 << 32),
                            "invalid-write-data")

    def test_pin_sample_must_match_supported_width(self):
        oracle = PulpGpioOracle(pins=32)
        self.assert_refused(lambda: oracle.sample_pins(1 << 32), "invalid-pin-sample")


if __name__ == "__main__":
    unittest.main()
