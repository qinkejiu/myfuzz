"""A PULP I2C command remains pending until native completion IRQ."""
import unittest

from myfuzz.local_harness.i2c_session import GeneratedPulpI2cSession


class I2cPendingTests(unittest.TestCase):
    def test_address_and_read_commands_wait_for_real_irq(self):
        self.assertTrue(callable(getattr(GeneratedPulpI2cSession, 'begin_quiesce', None)))
        session = object.__new__(GeneratedPulpI2cSession)
        for stage in (4, 6):
            with self.subTest(stage=stage):
                session._write_stage = stage
                session._irq_level = 0
                self.assertEqual(1, session.pending_events)
                session._irq_level = 1
                self.assertEqual(0, session.pending_events)


if __name__ == '__main__':
    unittest.main()
