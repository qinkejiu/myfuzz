"""Source identities describe measured pin drive, never UART FIFO acceptance."""
from collections import deque
from types import SimpleNamespace
import unittest

from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.scenario.uart_peer import Uart8N1Peer


def session():
    uart = object.__new__(GeneratedOpentitanUartSession)
    uart.peer = Uart8N1Peer(b'', clocks_per_bit=32)
    uart.source_mode = 'genome'
    uart.source = None
    uart.startup_writes = ()
    uart.read_rx_after_source = False
    uart.cpu_routed_mode = False
    uart._started = False
    uart._rx_read = False
    uart._rx_word = 0
    uart._selected_source_byte = None
    uart.local_ticks = 0
    uart._tick_base = 0
    uart._case_id = 'case-a'
    uart.reset_epoch = 0
    uart._samples = deque()
    uart.max_local_ticks_per_register_access = 37
    uart._artifact_document = {'physical_exports': [dict(physical_port='cio_rx_i', runtime_name='rx_pin')]}
    uart.enable_source_provenance()
    def command(operation, fields):
        uart.local_ticks += 1
        snapshot = dict(uart_tx=1, physical={'rx_pin': fields[0]})
        return SimpleNamespace(status='result', payload={'samples': [dict(
            local_tick=uart.local_ticks, pre=snapshot, post=snapshot)], 'observations': {}})
    uart.command = command
    return uart


class UartSourceProvenanceTests(unittest.TestCase):
    def test_first_and_same_byte_queued_action_have_distinct_measured_frames(self):
        uart = session()
        self.assertIsNone(uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='first'))
        uart.step_local({'uart_rx_byte': 0x5a})
        second = uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='second')
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0x5a})
        admissions = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_admission']
        ends = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end']
        self.assertEqual(['first', 'second'], [e['action_id'] for e in admissions])
        self.assertEqual(2, len({e['frame_id'] for e in admissions}))
        self.assertEqual(second, admissions[1]['start_tick'])
        self.assertEqual(2, len(ends))
        for event in ends:
            self.assertTrue(event['waveform_matched'])
            self.assertEqual(320, event['sample_count'])
            self.assertEqual(10, len(event['bit_witness']))
            self.assertEqual('unknown', event['fifo_origin'])

    def test_schedule_sample_mismatch_does_not_claim_completed_waveform(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='first')
        uart.step_local({'uart_rx_byte': 0x5a})
        original = uart.command
        def corrupt(operation, fields):
            reply = original(operation, fields)
            if uart.local_ticks == uart.peer.source_start_tick:
                reply.payload['samples'][0]['post']['physical']['rx_pin'] = 1
            return reply
        uart.command = corrupt
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0x5a})
        end = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        self.assertFalse(end['waveform_matched'])
        self.assertGreater(end['mismatch_count'], 0)

    def test_reset_cancels_pending_frames_without_erasing_prior_evidence(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='old')
        uart.step_local({'uart_rx_byte': 0x5a})
        # The lifecycle cancellation helper is also used before process reset.
        uart._cancel_source_frames('reset')
        self.assertEqual('uart_source_frame_cancel', uart.source_events[-1]['kind'])
        self.assertEqual('old', uart.source_events[-1]['action_id'])
        self.assertEqual('unknown', uart.source_events[-1]['fifo_origin'])
        self.assertEqual('uart_source_frame_admission', uart.source_events[0]['kind'])

    def test_bad_raw_source_and_duplicate_action_rejected(self):
        uart = session()
        for byte in (-1, 256, True):
            with self.assertRaises(ValueError):
                uart.admit_source_event('uart_rx_byte', byte, bit_offset=0, width=8, action_id='bad')
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='one')
        with self.assertRaises(ValueError):
            uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='one')

    def test_cross_case_queue_keeps_origin_and_global_tick_coordinates(self):
        uart = session()
        uart._tick_base = 1000
        uart.local_ticks = 1000
        # The real driver returns case-relative ticks; simulate that receipt here.
        def command(operation, fields):
            uart.local_ticks += 1
            snap = dict(uart_tx=1, physical={'rx_pin': fields[0]})
            return SimpleNamespace(status='result', payload={'samples': [dict(
                local_tick=uart.local_ticks - uart._tick_base, pre=snap, post=snap)],
                'observations': {}})
        uart.command = command
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='a')
        uart.step_local({'uart_rx_byte': 0x5a})
        uart._case_id = 'case-b'
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='b')
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0x5a})
        ends = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end']
        self.assertEqual(['case-a', 'case-b'], [e['session_case_id'] for e in ends])
        self.assertTrue(all(e['waveform_matched'] for e in ends))
        self.assertGreater(ends[0]['bit_witness'][0]['local_tick'], 1000)

    def test_reset_local_cancels_partially_driven_and_queued_frames(self):
        from unittest.mock import patch
        from myfuzz.local_harness.session import GeneratedLocalSession
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='active')
        uart.step_local({'uart_rx_byte': 0x5a})
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='queued')
        while uart.local_ticks < uart.peer.source_start_tick + 32:
            uart.step_local({'uart_rx_byte': 0x5a})
        with patch.object(GeneratedLocalSession, 'reset_local', return_value={'cancelled_responses': 0}):
            uart.reset_local()
        cancelled = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_cancel']
        self.assertEqual(['active', 'queued'], [e['action_id'] for e in cancelled])
        self.assertEqual([33, 0], [e['sample_count'] for e in cancelled])
        self.assertFalse(any(e['kind'] == 'uart_source_frame_end' for e in uart.source_events))
        self.assertEqual(1, uart.peer.drive_rx(uart.local_ticks + 1))
        self.assertTrue(any(e['kind'] == 'uart_source_frame_begin' for e in uart.source_events))

    def test_multiple_prestart_admissions_preserve_frame_order(self):
        uart = session()
        for action, byte in (('one', 0x5a), ('two', 0xa6)):
            uart.admit_source_event('uart_rx_byte', byte, bit_offset=0, width=8, action_id=action)
        uart.step_local({'uart_rx_byte': 0xa6})
        admission = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_admission']
        self.assertEqual(['one', 'two'], [e['action_id'] for e in admission])
        self.assertEqual([0x5a, 0xa6], [e['byte'] for e in admission])
        self.assertGreater(admission[1]['start_tick'], admission[0]['end_tick'])

    def test_missing_actual_pin_and_missing_ticks_are_not_waveform_evidence(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='zero')
        uart.step_local({'uart_rx_byte': 0})
        original = uart.command
        def missing(operation, fields):
            reply = original(operation, fields)
            if uart.local_ticks == uart.peer.source_start_tick:
                reply.payload['samples'][0]['pre']['physical'].clear()
            return reply
        uart.command = missing
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0})
        event = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        self.assertFalse(event['waveform_matched'])
        self.assertIsNone(event['bit_witness'][0]['actual_pre_level'])

    def test_provenance_direct_queue_requires_explicit_action_identity(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='zero')
        uart.step_local({'uart_rx_byte': 0})
        before = uart.peer.source_end_tick
        with self.assertRaisesRegex(ValueError, 'action identity'):
            uart.enqueue_rx_byte(0)
        self.assertEqual(before, uart.peer.source_end_tick)

    def test_bit_witness_binds_actual_driver_receipt(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='zero')
        original = uart.command
        def identified(operation, fields):
            reply = original(operation, fields)
            reply.execution = 'execution-a'
            reply.sequence = uart.local_ticks
            return reply
        uart.command = identified
        uart.step_local({'uart_rx_byte': 0})
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0})
        event = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        witness = event['bit_witness'][0]
        self.assertEqual('execution-a', witness['receipt']['execution'])
        self.assertEqual(event['start_tick'], witness['receipt']['sequence'])

    def test_end_case_marks_unscheduled_admission_pending_cancelled(self):
        from unittest.mock import patch
        from myfuzz.local_harness.session import GeneratedLocalSession
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='pending')
        with patch.object(GeneratedLocalSession, 'end_case'):
            uart.end_case()
        cancel = uart.source_events[-1]
        self.assertEqual('uart_source_frame_cancel', cancel['kind'])
        self.assertEqual('pending', cancel['action_id'])
        self.assertEqual('pending', cancel['schedule_status'])
        self.assertEqual('end_case', cancel['reason'])
        self.assertIsNone(cancel['frame_id'])

    def test_readback_backpressure_rejects_second_pending_action_before_scheduling(self):
        uart = session()
        uart.read_rx_after_source = True
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='first')
        with self.assertRaisesRegex(RuntimeError, 'not been read'):
            uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='second')
        self.assertEqual([(0, 'first')], uart._pending_source_actions)

    def test_missing_tick_coverage_prevents_matched_waveform_even_with_legal_levels(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='zero')
        uart.step_local({'uart_rx_byte': 0})
        original = uart.command
        def skip_tick(operation, fields):
            if uart.local_ticks == uart.peer.source_start_tick + 31:
                uart.local_ticks += 1
            return original(operation, fields)
        uart.command = skip_tick
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0})
        event = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        self.assertEqual(319, event['sample_count'])
        self.assertEqual(0, event['mismatch_count'])
        self.assertFalse(event['waveform_matched'])

    def test_rejected_begin_case_does_not_cancel_live_frame(self):
        from unittest.mock import patch
        from myfuzz.local_harness.session import GeneratedLocalSession
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0, bit_offset=0, width=8, action_id='active')
        uart.step_local({'uart_rx_byte': 0})
        before = list(uart.source_events)
        with patch.object(GeneratedLocalSession, 'begin_case', side_effect=ValueError('already running')):
            with self.assertRaises(ValueError):
                uart.begin_case('invalid-restart')
        self.assertEqual(before, uart.source_events)
        self.assertEqual(1, len(uart._source_frames))

    def test_constructor_waveform_cannot_claim_genome_action_identity(self):
        uart = session()
        uart.source_mode = 'constructor'
        uart.source = b'\x11'
        uart.peer.source = uart.source
        with self.assertRaisesRegex(ValueError, 'genome-owned source'):
            uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='incorrect')
        self.assertEqual([], uart._pending_source_actions)

    def test_mutated_peer_schedule_cannot_certify_admitted_frame_payload(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='admitted-5a')
        uart.step_local({'uart_rx_byte': 0x5a})
        # Driver receives peer.drive_rx exactly, but this altered schedule is no
        # longer the admitted action's payload and must not certify that origin.
        uart.peer._source_segments[0] = b'\xa6'
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0x5a})
        event = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        self.assertEqual(0x5a, event['byte'])
        self.assertFalse(event['waveform_matched'])
        self.assertGreater(event['mismatch_count'], 0)
        for witness in event['bit_witness'][1:9]:
            self.assertEqual((0x5a >> (witness['bit_index'] - 1)) & 1,
                             witness['expected_level'])

    def test_mutated_peer_clock_cannot_change_frozen_admission_schedule(self):
        uart = session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='fixed-clock')
        uart.step_local({'uart_rx_byte': 0x5a})
        frozen_end = uart.peer.source_end_tick
        uart.peer.clocks_per_bit = 16
        while uart.local_ticks < frozen_end:
            uart.step_local({'uart_rx_byte': 0x5a})
        event = [e for e in uart.source_events if e['kind'] == 'uart_source_frame_end'][0]
        self.assertFalse(event['waveform_matched'])
        self.assertEqual(10, len(event['bit_witness']))
        self.assertEqual(32, event['bit_witness'][1]['local_tick'] - event['start_tick'])
