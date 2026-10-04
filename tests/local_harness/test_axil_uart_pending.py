"""A deferred UART RX read remains pending until it really executes."""
from types import SimpleNamespace
import unittest

from myfuzz.local_harness.axil_uart_session import GeneratedAxiLiteUartSession


class AxilUartPendingTests(unittest.TestCase):
    def test_genome_source_is_pending_before_first_tick(self):
        session = object.__new__(GeneratedAxiLiteUartSession)
        session._started = False
        session.startup_writes = ()
        session.source = None
        session.source_mode = 'genome'
        self.assertEqual(1, session.pending_events)

    def test_pending_read_survives_serial_end_and_idle_gap(self):
        session = object.__new__(GeneratedAxiLiteUartSession)
        session._started = True
        session.startup_writes = ()
        session.source = b'Z'
        session.source_mode = 'constructor'
        session.read_rx_after_source = True
        session._rx_read = False
        session.peer = SimpleNamespace(source_end_tick=100)
        session.local_ticks = 125
        self.assertGreater(session.pending_events, 0)
        session._rx_read = True
        self.assertEqual(0, session.pending_events)


if __name__ == '__main__':
    unittest.main()
