"""UART source actions can be queued across testcase boundaries without reset."""

import unittest

from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.scenario.uart_peer import Uart8N1Peer


class OpentitanUartRearmTests(unittest.TestCase):
    def test_same_byte_can_be_queued_twice_without_restarting_peer(self):
        session = object.__new__(GeneratedOpentitanUartSession)
        session.peer = Uart8N1Peer(b'\x5a', clocks_per_bit=32)
        session.peer.start_source(100)
        session.source_mode = 'genome'
        session.read_rx_after_source = False
        session._started = True
        session._rx_read = False
        session._selected_source_byte = 0x5a
        session.local_ticks = 420
        session.enqueue_rx_byte(0x5a)
        second_start = session.peer.source_end_tick - 10 * 32
        self.assertGreaterEqual(second_start, 420 + 17 * 32)
        self.assertEqual(0, session.peer.drive_rx(second_start))
        self.assertEqual(1, session.peer.drive_rx(second_start - 1))
        session.local_ticks = session.peer.source_end_tick
        session.enqueue_rx_byte(0x5a)
        self.assertGreater(session.peer.source_end_tick, second_start + 320)

    def test_changed_genome_byte_is_accepted_after_explicit_rearm(self):
        session = object.__new__(GeneratedOpentitanUartSession)
        session.peer = Uart8N1Peer(b'\x5a', clocks_per_bit=32)
        session.peer.start_source(100)
        session.source_mode = 'genome'
        session.read_rx_after_source = False
        session._started = True
        session._rx_read = False
        session._rx_word = 0
        session._selected_source_byte = 0x5a
        session.local_ticks = 420
        session.enqueue_rx_byte(0xa6)
        session.command = lambda *args: None
        session._take = lambda *args, **kwargs: {'observations': {}}
        self.assertEqual(0, session.step_local({'uart_rx_byte': 0xa6})['serial_rx_read'])
        with self.assertRaisesRegex(ValueError, 'cannot change'):
            session.step_local({'uart_rx_byte': 0x11})

    def test_changed_genome_byte_after_completed_frame_rearms_automatically(self):
        session = object.__new__(GeneratedOpentitanUartSession)
        session.peer = Uart8N1Peer(b'\x5a', clocks_per_bit=32)
        session.peer.start_source(100)
        session.source_mode = 'genome'
        session.read_rx_after_source = False
        session._started = True
        session._rx_read = False
        session._rx_word = 0
        session._selected_source_byte = 0x5a
        session.local_ticks = 420
        session.command = lambda *args: None
        session._take = lambda *args, **kwargs: {'observations': {}}
        session.step_local({'uart_rx_byte': 0xa6})
        self.assertEqual(0xa6, session._selected_source_byte)
        self.assertGreater(session.peer.source_end_tick, 420)

    def test_source_rearm_rejects_bad_byte_and_prestart(self):
        session = object.__new__(GeneratedOpentitanUartSession)
        session.peer = Uart8N1Peer(b'', clocks_per_bit=32)
        session.source_mode = 'genome'
        session._started = False
        session.local_ticks = 0
        with self.assertRaises(ValueError):
            session.enqueue_rx_byte(0x100)
        with self.assertRaises(RuntimeError):
            session.enqueue_rx_byte(0x5a)

    def test_mmio_access_allowed_in_idle_gap_but_not_across_next_start(self):
        session = object.__new__(GeneratedOpentitanUartSession)
        session.peer = Uart8N1Peer(b'\x5a', clocks_per_bit=16)
        session.peer.start_source(100)
        session.peer.append_source(b'\xa6', 300)
        session.max_local_ticks_per_register_access = 12
        session.local_ticks = 260
        session.command = lambda *args: None
        session._take = lambda *args, **kwargs: {
            'samples': [{'pre': {'backend': {
                'uart_req_valid': 1, 'uart_req_ready': 1}}}],
            'rdata': 0x5a, 'error': 0}
        self.assertEqual(0x5a, session._access(False, 0x18, 0, 15))
        session.local_ticks = 290
        with self.assertRaisesRegex(RuntimeError, 'during serial source waveform'):
            session._access(False, 0x18, 0, 15)


if __name__ == '__main__':
    unittest.main()
