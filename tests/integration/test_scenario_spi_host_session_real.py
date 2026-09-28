"""Source-backed OpenTitan SPI Host local session and external peer."""

import os
import unittest

from myfuzz.scenario.spi_host_session import OpenTitanSpiHostSession
from myfuzz.scenario.spi_peer import SpiPeer
from myfuzz.scenario.protocol_io import read_local_reply, write_local_command


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealSpiHostSessionTests(unittest.TestCase):
    def test_csaat_held_chip_select_remains_pending(self):
        peer = SpiPeer(b"\x12\x34\x56\x78")
        session = OpenTitanSpiHostSession()
        session.attach_peer(peer)
        session.begin_case("spi-held-cs")
        try:
            session.write_register(0x10, (1 << 31) | (1 << 29) | 1)
            session.write_register(0x18, 8)
            session.write_register(0x20, 0x69)  # four bytes, CSAAT=1
            for _ in range(800):
                observed = session.step_local({})
                if peer.sample_count == 32 and observed["csb"] == 0 \
                        and not (observed["native_pending"] and observed["sck"]):
                    # Allow the RTL to settle after the final sampled edge.
                    for _ in range(20):
                        observed = session.step_local({})
                    break
            else:
                self.fail("real SPI Host did not hold CS after CSAAT")
            self.assertEqual(0, observed["csb"])
            self.assertEqual(1, session.pending_events)
            peer.queue_payload(b"\x9a\xbc\xde\xf0")
            session.write_register(0x20, 0x68)  # second segment releases CS
            for _ in range(800):
                observed = session.step_local({})
                if peer.sample_count >= 64 and observed["csb"] == 1 \
                        and not session.pending_events:
                    break
            else:
                self.fail("follow-up segment did not release the held CS")
            self.assertEqual(64, peer.sample_count)
        finally:
            session.end_case()

    def test_disabled_output_pads_do_not_leave_phantom_peer_transfer(self):
        peer = SpiPeer(b"\xaa\xbb\xcc\xdd")
        session = OpenTitanSpiHostSession()
        session.attach_peer(peer)
        session.begin_case("spi-disabled-pads")
        try:
            session.write_register(0x10, (1 << 31) | 1)  # SPIEN, OUTPUT_EN=0
            session.write_register(0x18, 8)
            session.write_register(0x20, 0x68)
            for _ in range(800):
                session.step_local({})
                if not session.pending_events:
                    break
            else:
                self.fail("completed native command left a phantom pending event")
            self.assertEqual(0, peer.sample_count)
        finally:
            session.end_case()

    def test_duplicate_local_command_reuses_reply_without_clocking_rtl(self):
        session = OpenTitanSpiHostSession()
        session.begin_case("spi-host-command-replay")
        try:
            session.step_local({"spi_sd_i": 0})
            tick_after_first = session.local_ticks
            proc = session._process
            duplicate = (f"CMD {session._wire_execution} 1 0 0 0 0 0 f 1\n")
            write_local_command(proc.stdin, duplicate)
            reply = read_local_reply(session, proc.stdout)
            self.assertTrue(reply.startswith(f"RESULT {session._wire_execution} 1 "))
            self.assertEqual(tick_after_first, session.local_ticks)
            # If the command ran again, the next unique local reply would
            # report an extra RTL tick rather than two total ticks.
            session.step_local({"spi_sd_i": 0})
            self.assertEqual(tick_after_first + 1, session.local_ticks)
        finally:
            session.end_case()

    def test_two_rx_commands_keep_rtl_fifo_peer_and_irq_state(self):
        first = bytes.fromhex("12 34 56 78")
        second = bytes.fromhex("a5 5a 0f f0")
        peer = SpiPeer(first)
        session = OpenTitanSpiHostSession()
        session.attach_peer(peer)
        session.begin_case("spi-host-two-rounds")
        try:
            # Real CONTROL, CONFIGOPTS, EVENT_ENABLE and INTR_ENABLE writes.
            # RX watermark=1 prevents a fabricated IRQ before RX FIFO data.
            session.write_register(0x10, (1 << 31) | (1 << 29) | 1)
            session.write_register(0x18, 8)
            session.write_register(0x34, 4, be=1)
            session.write_register(0x04, 2)
            self.assertEqual(4, session.read_register(0x34))
            self.assertEqual(0, session.read_register(0x00) & 2)

            values = []
            previous_ticks = session.local_ticks
            for round_index, payload in enumerate((first, second)):
                if round_index:
                    peer.queue_payload(payload)
                # STATUS.READY is a real RTL read; do not inject a command
                # while the previous one remains busy.
                self.assertTrue(session.read_register(0x14) & (1 << 28))
                session.write_register(0x20, 0x68)  # four-byte standard read
                self.assertEqual(1, session.pending_events)
                target_edges = 32 * (round_index + 1)
                saw_selected = False
                saw_event = False
                for _ in range(1000):
                    observed = session.step_local({})
                    saw_selected |= observed["csb"] == 0
                    saw_event |= bool(observed["irq_event"])
                    if peer.sample_count == target_edges and observed["csb"] == 1:
                        break
                else:
                    self.fail("real SPI Host did not complete 32 sampled edges")
                self.assertTrue(saw_selected)
                self.assertTrue(saw_event)
                self.assertEqual(0, observed["irq_error"])
                for _ in range(20):
                    if not session.pending_events:
                        break
                    session.step_local({})
                self.assertEqual(0, session.pending_events)
                self.assertGreater(session.local_ticks, previous_ticks)
                previous_ticks = session.local_ticks
                self.assertEqual(2, session.read_register(0x00) & 2)
                values.append(session.read_register(0x24))
                self.assertEqual(0, session.step_local({})["irq_event"])
            self.assertEqual([0x78563412, 0xf00f5aa5], values)
            self.assertEqual(64, peer.sample_count)
            self.assertEqual(8, peer.payload_index)
            self.assertEqual(0, peer.incomplete_frame_count)
        finally:
            session.end_case()


if __name__ == "__main__":
    unittest.main()
