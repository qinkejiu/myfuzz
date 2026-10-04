"""A generated PULP I2C peer has one testcase-owned response byte."""
import unittest

from myfuzz.local_harness.i2c_session import GeneratedPulpI2cSession


class I2cSourceTests(unittest.TestCase):
    def test_peer_response_is_installed_once_and_remains_stable(self):
        session = object.__new__(GeneratedPulpI2cSession)
        session._peer_response = None
        calls = []
        session.command = lambda operation, fields: calls.append((operation, fields)) or object()
        session._take = lambda reply: {'observations': {'interrupt_o': 0,
            'scl_pad_i': 1, 'scl_padoen_o': 1, 'sda_pad_i': 1,
            'sda_padoen_o': 1}}
        session.configure_peer_response(0x5a)
        self.assertEqual([('SOURCE_I2C', (0x5a,))], calls)
        session.step_local({'peer_response': 0x5a})
        self.assertEqual([('SOURCE_I2C', (0x5a,)), ('STEP_I2C', (0,))], calls)
        with self.assertRaisesRegex(ValueError, 'single response byte'):
            session.step_local({'peer_response': 0xa6})
        self.assertEqual(2, len(calls))

    def test_response_must_be_selected_before_step_and_is_bounded(self):
        session = object.__new__(GeneratedPulpI2cSession)
        session._peer_response = None
        with self.assertRaisesRegex(ValueError, 'peer_response'):
            session.step_local({})
        for value in (-1, 256, True):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'response byte'):
                session.configure_peer_response(value)

    def test_apb_transaction_cannot_start_before_source_selection(self):
        session = object.__new__(GeneratedPulpI2cSession)
        session._peer_response = None
        session._write_stage = 0
        session._irq_level = 0
        with self.assertRaisesRegex(ValueError, 'peer_response'):
            session.write_register(0, 2)


if __name__ == '__main__':
    unittest.main()
