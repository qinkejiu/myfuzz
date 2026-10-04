"""A PULP native pin peer changes state only from selected real SCK edges."""
import importlib
import unittest


def peer(payload=b'', **kwargs):
    module = importlib.import_module('myfuzz.scenario.pulp_spi_peer')
    return module.PulpSpiMode0Peer(payload, **kwargs)


def pins(*, sck=0, cs=15, mosi=0, mode=0, events=0):
    return {'spi_clk': sck, 'spi_csn0': cs & 1, 'spi_csn1': (cs >> 1) & 1,
            'spi_csn2': (cs >> 2) & 1, 'spi_csn3': (cs >> 3) & 1,
            'spi_mode': mode, 'spi_sdo0': mosi, 'events_o': events}


class PulpSpiPeerTests(unittest.TestCase):
    def test_sdi1_is_miso_and_only_selected_edges_shift(self):
        spi = peer(b'\xa5')
        spi.observe(pins(cs=14), local_tick=1, phase='post')
        self.assertEqual({'spi_sdi0': 0, 'spi_sdi1': 1,
                          'spi_sdi2': 0, 'spi_sdi3': 0}, spi.drive_inputs())
        observed = 0
        for index in range(8):
            observed = (observed << 1) | spi.drive_inputs()['spi_sdi1']
            spi.observe(pins(sck=1, cs=14, mosi=(0x3c >> (7-index)) & 1),
                        local_tick=2+index*2, phase='post')
            spi.observe(pins(sck=0, cs=14), local_tick=3+index*2, phase='post')
        spi.observe(pins(), local_tick=18, phase='post')
        self.assertEqual(0xa5, observed)
        self.assertEqual((b'\x3c',), spi.completed_frames)
        self.assertEqual(8, spi.sample_count)

    def test_idle_reset_width_mode_is_not_cpol_cpha(self):
        spi = peer(b'\xff')
        spi.observe(pins(mode=2), local_tick=1, phase='pre')
        self.assertEqual(0, spi.sample_count)
        spi.observe(pins(cs=14, mode=0), local_tick=1, phase='post')
        with self.assertRaisesRegex(ValueError, 'single-line'):
            spi.observe(pins(cs=14, mode=1), local_tick=2, phase='post')

    def test_real_cs_setup_mode_two_transient_drives_zero_until_standard_mode(self):
        spi = peer(b'\x80')
        spi.observe(pins(cs=14, mode=2), local_tick=1, phase='post')
        self.assertEqual(0, spi.drive_inputs()['spi_sdi1'])
        spi.observe(pins(cs=14, mode=0), local_tick=2, phase='post')
        self.assertEqual(1, spi.drive_inputs()['spi_sdi1'])
        self.assertEqual(0, spi.sample_count)
        with self.assertRaisesRegex(ValueError, 'single-line'):
            spi.observe(pins(cs=14, mode=2, sck=1), local_tick=3, phase='post')

    def test_multiple_or_wrong_chip_selection_fails_closed(self):
        for cs in (12, 13):
            with self.subTest(cs=cs), self.assertRaises(ValueError):
                peer().observe(pins(cs=cs), local_tick=1, phase='post')
        spi = peer(chip_select=2)
        spi.observe(pins(cs=11), local_tick=1, phase='post')

    def test_pause_and_duplicate_pin_phases_do_not_advance_payload(self):
        spi = peer(b'\x80')
        spi.observe(pins(cs=14), local_tick=1, phase='post')
        for tick in range(2, 20):
            spi.observe(pins(cs=14), local_tick=tick, phase='pre')
            spi.observe(pins(cs=14), local_tick=tick, phase='post')
        self.assertEqual(0, spi.sample_count)
        self.assertEqual(1, spi.drive_inputs()['spi_sdi1'])

    def test_incomplete_frame_restarts_byte_and_completed_frames_persist(self):
        spi = peer(b'\x80')
        spi.observe(pins(cs=14), local_tick=1, phase='post')
        spi.observe(pins(cs=14, sck=1), local_tick=2, phase='post')
        spi.observe(pins(), local_tick=3, phase='post')
        self.assertEqual(1, spi.incomplete_frame_count)
        spi.observe(pins(cs=14), local_tick=4, phase='post')
        self.assertEqual(1, spi.drive_inputs()['spi_sdi1'])
        self.assertEqual(0, spi.payload_index)

    def test_native_event_bits_are_observed_independently_without_inventing_irq(self):
        spi = peer()
        for tick, events in enumerate((0, 1, 0, 2, 0), start=1):
            spi.observe(pins(events=events), local_tick=tick, phase='post')
        self.assertEqual([(0, 2, 1), (0, 3, 0), (1, 4, 1), (1, 5, 0)],
                         [(e['bit'], e['local_tick'], e['level']) for e in spi.events])
        self.assertEqual(0, spi.sample_count)
        self.assertEqual((), spi.completed_frames)

    def test_missing_invalid_or_backwards_receipt_refused(self):
        for bad in ({}, pins(events=4), pins(sck=True)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                peer().observe(bad, local_tick=1, phase='post')
        spi = peer()
        spi.observe(pins(), local_tick=2, phase='post')
        with self.assertRaises(ValueError):
            spi.observe(pins(), local_tick=1, phase='post')
        with self.assertRaises(ValueError):
            spi.observe(pins(), local_tick=2, phase='pre')

    def test_explicit_reset_clears_native_event_state_and_peer_transfer(self):
        spi = peer(b'\xff')
        spi.observe(pins(cs=14, events=1), local_tick=1, phase='post')
        spi.reset_case(b'\x00')
        spi.observe(pins(cs=14), local_tick=1, phase='post')
        self.assertEqual([], spi.events)
        self.assertEqual(0, spi.drive_inputs()['spi_sdi1'])


if __name__ == '__main__':
    unittest.main()
