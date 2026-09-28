"""Contract checks for the independent OpenTitan SPI Host session."""

import unittest
from io import StringIO
from types import SimpleNamespace


class SpiHostSessionContractTests(unittest.TestCase):
    def test_session_rejects_undeclared_environment_inputs(self):
        from myfuzz.scenario.spi_host_session import OpenTitanSpiHostSession

        session = OpenTitanSpiHostSession()
        with self.assertRaisesRegex(ValueError, "undeclared SPI Host inputs"):
            session.step_local({"irq_event": 1})

    def test_session_exposes_persistent_case_lifecycle(self):
        from myfuzz.scenario.spi_host_session import OpenTitanSpiHostSession

        session = OpenTitanSpiHostSession()
        self.assertEqual(0, session.local_ticks)
        self.assertEqual(0, session.pending_responses)
        self.assertTrue(callable(session.begin_case))
        self.assertTrue(callable(session.reset_local))
        self.assertTrue(callable(session.end_case))

    def test_attached_peer_owns_miso_input(self):
        from myfuzz.scenario.spi_host_session import OpenTitanSpiHostSession
        from myfuzz.scenario.spi_peer import SpiPeer

        session = OpenTitanSpiHostSession()
        session.attach_peer(SpiPeer(b"\x5a"))
        with self.assertRaisesRegex(ValueError, "bound SPI Host MISO"):
            session.step_local({"spi_sd_i": 0})

    def test_disabled_output_pads_cannot_clock_external_peer(self):
        from myfuzz.scenario.spi_host_session import OpenTitanSpiHostSession
        from myfuzz.scenario.spi_peer import SpiPeer

        session = OpenTitanSpiHostSession()
        peer = SpiPeer(b"\x80")
        session.attach_peer(peer)
        proc = SimpleNamespace(stdin=StringIO())
        session._observe_tick(["TICK", "0", "0", "0", "0", "0", "0", "0", "1"], proc)
        session._observe_tick(["TICK", "1", "0", "0", "0", "0", "0", "0", "2"], proc)
        self.assertEqual(0, peer.sample_count)


if __name__ == "__main__":
    unittest.main()
