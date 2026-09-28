"""Pin-level behavior of the OpenTitan SPI Host's external mode-0 peer."""

import unittest

from myfuzz.scenario.spi_peer import SpiPeer


def clock_byte(peer: SpiPeer, mosi: int = 0) -> list[int]:
    sampled = []
    for shift in range(7, -1, -1):
        peer.observe(sck=0, csb=0, mosi=(mosi >> shift) & 1)
        sampled.append((peer.sd_i >> 1) & 1)
        peer.observe(sck=1, csb=0, mosi=(mosi >> shift) & 1)
        peer.observe(sck=0, csb=0, mosi=(mosi >> shift) & 1)
    return sampled


class SpiPeerTests(unittest.TestCase):
    def test_real_rising_edges_sample_four_payload_bytes_in_order(self):
        peer = SpiPeer(bytes((0xA5, 0x3C, 0xE1, 0x72)))
        peer.observe(sck=0, csb=0, mosi=0)
        bits = []
        for _ in range(4):
            bits.extend(clock_byte(peer))
        self.assertEqual(32, peer.sample_count)
        self.assertEqual(bytes((0xA5, 0x3C, 0xE1, 0x72)),
                         bytes(sum(bits[index:index + 8][bit] << (7 - bit)
                                   for bit in range(8))
                               for index in range(0, 32, 8)))
        self.assertEqual(0, peer.bit_index)

    def test_held_sck_and_deselected_edges_do_not_consume_payload(self):
        peer = SpiPeer(b"\x80")
        peer.observe(sck=0, csb=1, mosi=0)
        peer.observe(sck=1, csb=1, mosi=0)
        peer.observe(sck=0, csb=1, mosi=0)
        self.assertEqual(0, peer.sd_i)
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual(2, peer.sd_i)
        for _ in range(8):
            peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual(0, peer.sample_count)
        self.assertEqual(0, peer.bit_index)
        peer.observe(sck=1, csb=0, mosi=0)
        for _ in range(8):
            peer.observe(sck=1, csb=0, mosi=0)
        self.assertEqual(1, peer.sample_count)
        self.assertEqual(1, peer.bit_index)
        self.assertEqual(2, peer.sd_i, "mode-0 MISO stays stable until falling SCK")
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual(0, peer.sd_i)

    def test_completed_frames_and_payload_survive_transaction_boundary(self):
        peer = SpiPeer(b"\x96")
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual([1, 0, 0, 1, 0, 1, 1, 0], clock_byte(peer, 0xD2))
        peer.observe(sck=0, csb=1, mosi=0)
        self.assertEqual((b"\xD2",), peer.completed_frames)
        self.assertEqual(1, peer.payload_index)
        peer.queue_payload(b"\x5A")
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual([0, 1, 0, 1, 1, 0, 1, 0], clock_byte(peer, 0x37))
        peer.observe(sck=0, csb=1, mosi=0)
        self.assertEqual((b"\xD2", b"\x37"), peer.completed_frames)
        self.assertEqual(2, peer.payload_index)
        self.assertEqual(16, peer.sample_count)

    def test_partial_byte_does_not_complete_or_consume_queued_byte(self):
        peer = SpiPeer(b"\xA5")
        peer.observe(sck=0, csb=0, mosi=0)
        peer.observe(sck=1, csb=0, mosi=1)
        peer.observe(sck=0, csb=0, mosi=1)
        peer.observe(sck=0, csb=1, mosi=0)
        self.assertEqual(0, peer.payload_index)
        self.assertEqual(1, peer.incomplete_frame_count)
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual(2, peer.sd_i)
        self.assertEqual([1, 0, 1, 0, 0, 1, 0, 1], clock_byte(peer))

    def test_unsupported_mode_and_invalid_pin_are_rejected(self):
        with self.assertRaises(ValueError):
            SpiPeer(b"\x00", cpol=1)
        with self.assertRaises(ValueError):
            SpiPeer(b"\x00", cpha=1)
        with self.assertRaises(ValueError):
            SpiPeer(b"\x00").observe(sck=2, csb=0, mosi=0)

    def test_explicit_case_reset_replays_payload_from_first_byte(self):
        peer = SpiPeer(b"\xC0")
        peer.observe(sck=0, csb=0, mosi=0)
        clock_byte(peer, 0x83)
        peer.observe(sck=0, csb=1, mosi=0)
        peer.reset_case()
        self.assertEqual(0, peer.payload_index)
        self.assertEqual(0, peer.sample_count)
        self.assertEqual((), peer.completed_frames)
        peer.observe(sck=0, csb=0, mosi=0)
        self.assertEqual([1, 1, 0, 0, 0, 0, 0, 0], clock_byte(peer))


if __name__ == "__main__":
    unittest.main()
