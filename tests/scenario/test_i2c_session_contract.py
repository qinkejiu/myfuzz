"""Contract for an independent, persistent OpenTitan I2C RTL session."""

import unittest
from io import StringIO
from types import SimpleNamespace


class I2cSessionContractTests(unittest.TestCase):
    def test_i2c_session_rejects_fabricated_irq_and_rdata(self):
        from myfuzz.scenario.i2c_session import OpenTitanI2cSession

        session = OpenTitanI2cSession()
        with self.assertRaisesRegex(ValueError, "undeclared I2C inputs"):
            session.step_local({"irq": 1, "rdata": 0x55})

    def test_bound_peer_owns_open_drain_lines(self):
        from myfuzz.scenario.i2c_session import OpenTitanI2cSession

        class Peer:
            scl_i = 1
            sda_i = 1

            def observe(self, *, scl_en, sda_en):
                pass

        session = OpenTitanI2cSession()
        session.attach_peer(Peer())
        with self.assertRaisesRegex(ValueError, "bound I2C lines"):
            session.step_local({"sda_i": 0})

    def test_unbound_open_drain_line_rises_when_host_releases(self):
        from myfuzz.scenario.i2c_session import OpenTitanI2cSession

        session = OpenTitanI2cSession()
        proc = SimpleNamespace(stdin=StringIO())
        session._observe_tick(["TICK", "1", "0", "0", "1"], proc)
        self.assertEqual(0, session._scl_i)
        session._observe_tick(["TICK", "0", "0", "0", "2"], proc)
        self.assertEqual(1, session._scl_i)

    def test_pending_event_follows_real_controller_status(self):
        from myfuzz.scenario.i2c_session import OpenTitanI2cSession

        session = OpenTitanI2cSession()
        proc = SimpleNamespace(stdin=StringIO())
        session._observe_tick(["TICK", "0", "0", "1", "1"], proc)
        self.assertEqual(1, session.pending_events)
        session._observe_tick(["TICK", "0", "0", "0", "2"], proc)
        self.assertEqual(0, session.pending_events)


if __name__ == "__main__":
    unittest.main()
