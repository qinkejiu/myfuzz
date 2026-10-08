"""Pinned real UART proves source pin drive identity, with FIFO origin unknown."""
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanUartSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1', 'requires pinned RTL')
class UartSourceFramesRealTests(unittest.TestCase):
    def test_two_equal_bytes_have_distinct_action_ids_and_real_pin_witnesses(self):
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_uart_local/component_profile.json',
            instance_id='uart_source', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        runtime = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        artifact = render_local_driver(runtime, base_dir=ROOT)
        with tempfile.TemporaryDirectory(prefix='myfuzz-uart-frame-') as work:
            uart = GeneratedOpentitanUartSession(artifact, base_dir=ROOT,
                cache_dir=Path(work), source=None,
                startup_writes=((0x10, 0x80000003, 15),))
            uart.enable_source_provenance()
            uart.begin_case('real-source-frames')
            try:
                uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0,
                    width=8, action_id='same-byte-first')
                uart.step_local({'uart_rx_byte': 0x5a})
                uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0,
                    width=8, action_id='same-byte-second')
                while uart.local_ticks < uart.peer.source_end_tick:
                    uart.step_local({'uart_rx_byte': 0x5a})
                ends = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end']
                self.assertEqual(['same-byte-first', 'same-byte-second'], [e['action_id'] for e in ends])
                self.assertEqual(2, len({e['frame_id'] for e in ends}))
                samples = {s['local_tick']: s for s in uart.drain_tick_samples()}
                for end in ends:
                    self.assertTrue(end['waveform_matched'])
                    self.assertEqual(320, end['sample_count'])
                    self.assertEqual('unknown', end['fifo_origin'])
                    for bit in end['bit_witness']:
                        actual = samples[bit['local_tick']]['pre']['physical'][uart._rx_physical_name]
                        self.assertEqual(actual, bit['actual_pre_level'])
                        self.assertEqual(bit['expected_level'], actual)
                        self.assertTrue(bit['receipt']['execution'])
                        self.assertGreater(bit['receipt']['sequence'], 0)
                start = uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0,
                    width=8, action_id='unfinished-before-reset')
                while uart.local_ticks < start + 12:
                    uart.step_local({'uart_rx_byte': 0x5a})
                uart.reset_local()
                cancel = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_cancel'][-1]
                self.assertEqual('unfinished-before-reset', cancel['action_id'])
                self.assertEqual(13, cancel['sample_count'])
                self.assertEqual('reset', cancel['reason'])
                self.assertEqual(2, len([e for e in uart.source_events
                    if e['kind'] == 'uart_source_frame_end']))
                uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0,
                    width=8, action_id='after-reset')
                uart.step_local({'uart_rx_byte': 0x5a})
                while uart.local_ticks < uart.peer.source_end_tick:
                    uart.step_local({'uart_rx_byte': 0x5a})
                last = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][-1]
                self.assertTrue(last['waveform_matched'])
                self.assertEqual('after-reset', last['action_id'])
                self.assertEqual(1, last['reset_epoch'])
                self.assertGreater(last['start_tick'], cancel['local_tick'])
            finally:
                uart.end_case()
