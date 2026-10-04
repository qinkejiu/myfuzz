"""The serial data source is owned once before a controller read command."""
import unittest

from myfuzz.local_harness.opentitan_i2c_session import GeneratedOpentitanI2cSession


class OpenTitanI2cSourceTests(unittest.TestCase):
    def test_fdata_is_blocked_until_external_response_source_is_selected(self):
        session = object.__new__(GeneratedOpentitanI2cSession)
        session._peer_response = None
        session.command = lambda *_: self.fail('FDATA reached RTL without source')
        with self.assertRaisesRegex(ValueError, 'source required'):
            session.write_register(0x1c, 0x1a1)

    def test_peer_response_is_latched_once_and_bound_pads_are_not_actions(self):
        session = object.__new__(GeneratedOpentitanI2cSession)
        session._peer_response = None
        calls = []
        session.command = lambda operation, fields: calls.append((operation, fields)) or object()
        session._take = lambda reply: {'observations': {}}
        session.configure_peer_response(0x5a)
        session.configure_peer_response(0x5a)
        self.assertEqual([('SOURCE_TLUL_I2C', (0x5a,))], calls)
        with self.assertRaisesRegex(ValueError, 'one response byte'):
            session.configure_peer_response(0xa6)
        with self.assertRaisesRegex(ValueError, 'bound'):
            session.step_local({'sda_i': 0})
        self.assertEqual(1, len(calls))


if __name__ == '__main__':
    unittest.main()
