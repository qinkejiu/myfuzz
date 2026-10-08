"""Reset-free UART RX scheduling leaves TX observation and earlier frames intact."""

import unittest

from myfuzz.scenario.uart_peer import Uart8N1Peer


class UartPeerQueueTests(unittest.TestCase):
    def test_two_frames_and_idle_gap(self):
        peer = Uart8N1Peer(b'\x5a', clocks_per_bit=16)
        peer.start_source(100)
        peer.append_source(b'\xa6', 300)
        self.assertEqual(100, peer.source_start_tick)
        self.assertEqual(460, peer.source_end_tick)
        self.assertTrue(peer.source_active(100))
        self.assertFalse(peer.source_active(260))
        self.assertTrue(peer.source_active(300))
        self.assertFalse(peer.source_overlaps(260, 280))
        self.assertTrue(peer.source_overlaps(280, 301))
        self.assertEqual(1, peer.drive_rx(299))
        for start, byte in ((100, 0x5a), (300, 0xa6)):
            self.assertEqual(0, peer.drive_rx(start))
            for bit in range(8):
                self.assertEqual((byte >> bit) & 1,
                                 peer.drive_rx(start + (bit + 1) * 16))
            self.assertEqual(1, peer.drive_rx(start + 9 * 16))

    def test_reject_overlapping_frames_and_reset_queue(self):
        peer = Uart8N1Peer(b'\x11', clocks_per_bit=16)
        peer.start_source(100)
        with self.assertRaises(ValueError):
            peer.append_source(b'\x22', 250)
        peer.append_source(b'\x22', 276)
        peer.reset_case()
        self.assertIsNone(peer.source_start_tick)
        self.assertEqual(0, peer.source_end_tick)
        self.assertEqual(1, peer.drive_rx(300))


if __name__ == '__main__':
    unittest.main()
