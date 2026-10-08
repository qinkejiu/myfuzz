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

    def test_cpu_routed_rx_read_remains_pending_after_serial_frame(self):
        session = object.__new__(GeneratedAxiLiteUartSession)
        session._started = True
        session.startup_writes = ()
        session.source = None
        session.source_mode = 'genome'
        session.read_rx_after_source = False
        session.cpu_routed_mode = True
        session._rx_read = False
        session.peer = SimpleNamespace(source_end_tick=100)
        session.local_ticks = 125

        self.assertEqual(1, session.pending_events)
        session._rx_read = True
        self.assertEqual(0, session.pending_events)

    def test_cpu_routed_pending_clears_only_after_successful_rxreg_access(self):
        session = object.__new__(GeneratedAxiLiteUartSession)
        session._started = True
        session.startup_writes = ()
        session.source = None
        session.source_mode = 'genome'
        session.read_rx_after_source = False
        session.cpu_routed_mode = True
        session._rx_read = False
        session._rx_word = 0
        session.peer = SimpleNamespace(source_end_tick=100)
        session.local_ticks = 125

        def fail_access(write, offset, value, be):
            raise RuntimeError('simulated AXI read failure')

        session._access = fail_access
        with self.assertRaisesRegex(RuntimeError, 'simulated AXI read failure'):
            session.read_register(8)
        self.assertFalse(session._rx_read)
        self.assertEqual(1, session.pending_events)

        session._access = lambda write, offset, value, be: 0x12345678
        self.assertEqual(0x12345678, session.read_register(4))
        self.assertFalse(session._rx_read)
        self.assertEqual(1, session.pending_events)

        self.assertEqual(0x12345678, session.read_register(8))
        self.assertTrue(session._rx_read)
        self.assertEqual(0x12345678, session._rx_word)
        self.assertEqual(0, session.pending_events)


if __name__ == '__main__':
    unittest.main()
