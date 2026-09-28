"""Two persistent OpenTitan I2C Controller read transfers with a real peer."""

import os
import unittest

from myfuzz.scenario.i2c_peer import I2cPeer
from myfuzz.scenario.i2c_session import OpenTitanI2cSession


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealI2cSessionTests(unittest.TestCase):
    def test_two_reads_keep_real_rtl_fifo_irq_and_peer_state(self):
        peer = I2cPeer(b"\x5a")
        session = OpenTitanI2cSession()
        session.attach_peer(peer)
        session.begin_case("i2c-two-rounds")
        try:
            for offset, value in ((0x3c, 0x00100010), (0x40, 0x00020002),
                                  (0x44, 0x00080008), (0x48, 0x00040004),
                                  (0x4c, 0x00080008), (0x04, 0x202),
                                  (0x10, 1)):
                session.write_register(offset, value)
            self.assertEqual(0, session.read_register(0x00) & 0x202)
            values = []
            previous_ticks = session.local_ticks
            for round_index, value in enumerate((0x5a, 0xa6)):
                if round_index:
                    peer.queue_payload(bytes((value,)))
                session.write_register(0x1c, 0x1a1)  # START + address 0x50/read
                session.write_register(0x1c, 0x601)  # READB one byte + STOP
                self.assertEqual(1, session.pending_events)
                saw_scl_low = False
                saw_sda_low = False
                for _ in range(1500):
                    observed = session.step_local({})
                    saw_scl_low |= observed["scl_en"] == 1
                    saw_sda_low |= observed["sda_en"] == 1
                    if peer.stop_count == round_index + 1:
                        break
                else:
                    self.fail("real I2C Host did not produce STOP")
                self.assertTrue(saw_scl_low)
                self.assertTrue(saw_sda_low)
                self.assertGreater(session.local_ticks, previous_ticks)
                previous_ticks = session.local_ticks
                for _ in range(20):
                    if not session.pending_events:
                        break
                    session.step_local({})
                self.assertEqual(0, session.pending_events)
                self.assertTrue(session.read_register(0x00) & 0x202)
                values.append(session.read_register(0x18) & 0xff)
                session.write_register(0x00, 0x200)  # real W1C cmd_complete
                self.assertEqual(0, session.read_register(0x00) & 0x202)
            self.assertEqual([0x5a, 0xa6], values)
            self.assertEqual(2, peer.start_count)
            self.assertEqual(2, peer.stop_count)
            self.assertEqual(2, peer.ack_count)
            self.assertEqual(2, peer.payload_index)
        finally:
            session.end_case()


if __name__ == "__main__":
    unittest.main()
