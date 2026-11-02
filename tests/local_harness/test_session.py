"""Persistent generated RTL process transport, using a deterministic fake driver."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from myfuzz.local_harness.session import GeneratedLocalSession


DIGEST = 'a' * 64


class GeneratedSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.document = {'schema_version': 'local_runtime_artifact.v1',
                         'driver_schema_version': 'local_driver_generation.v1',
                         'status': 'driver_generated', 'driver_status': 'generated',
                         'artifact_digest': DIGEST, 'kind': 'apb_gpio',
                         'driver_reset': {'schema_version': 'generated_local_reset.v1',
                                          'reset_assert_ticks': 8,
                                          'reset_release_ticks': 4}}
        self.artifact = type('Artifact', (), {'runtime_document': self.document})()

    def driver(self, mode='valid'):
        path = self.root / 'driver.py'
        body = textwrap.dedent(f'''\
            #!/usr/bin/env python3
            import json, sys, time
            digest = {DIGEST!r}
            mode = {mode!r}
            kind = {self.document['kind']!r}
            if mode == 'wrong_ready': digest = 'b' * 64
            print('READY local_driver.v1 ' + digest + ' 8 4', flush=True)
            tick = 0
            for line in sys.stdin:
                if line == 'END\\n': break
                parts = line.strip().split(' ')
                if parts[0] == 'ACK':
                    print('ACKED ' + parts[1] + ' ' + parts[2] + ' ' +
                          format(tick,'x'), flush=True)
                    continue
                if mode == 'eof': break
                if mode == 'stall':
                    sys.stdout.write('RESULT ')
                    sys.stdout.flush()
                    time.sleep(5)
                    continue
                if mode == 'bad_tick' or (mode == 'bad_tick_after_one' and tick >= 1): before = tick + 1
                else: before = tick
                tick += 1
                payload = {{'schema_version':'local_driver_result.v1','kind':kind,
                           'samples':[{{'local_tick':tick,'pre':{{}},'post':{{}}}}],
                           'observations':{{'gpio_out':tick}},'pre_backend':{{}},
                           'rdata':0,'error':0}}
                if mode == 'native_valid_taps':
                    taps = {{'cpu_native_trace_valid':1, 'cpu_native_trace_addr':0,
                            'cpu_native_trace_wdata':0, 'cpu_native_trace_wstrb':0,
                            'cpu_native_trace_ready':0, 'cpu_native_trace_rdata':0}}
                    for phase in ('pre', 'post'):
                        payload['samples'][0][phase]['protocol_taps'] = dict(taps)
                encoded = json.dumps(payload,sort_keys=True,separators=(',',':')).encode().hex()
                print('RESULT ' + parts[1] + ' ' + parts[2] + ' ' +
                      format(before,'x') + ' ' + format(tick,'x') + ' ' + encoded,
                      flush=True)
            ''')
        path.write_text(body)
        path.chmod(0o755)
        return path

    def make_session(self, mode='valid', **kwargs):
        binary = self.driver(mode)
        session = GeneratedLocalSession(self.artifact, base_dir=self.root,
                                        cache_dir=self.root / 'cache', **kwargs)
        patcher = patch('myfuzz.local_harness.session.build_local_harness',
                        return_value=binary)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(session.end_case)
        return session

    def enable_native_taps(self):
        self.document['kind'] = 'native_memory_cpu'
        self.document['native_completion_observation'] = {'schema_version':
            'native_completion_observation.v1'}
        self.document['protocol_tap_ports'] = [
            {'name': name, 'width': width} for name, width in (
                ('cpu_native_trace_valid', 1), ('cpu_native_trace_addr', 32),
                ('cpu_native_trace_wdata', 32), ('cpu_native_trace_wstrb', 4),
                ('cpu_native_trace_ready', 1), ('cpu_native_trace_rdata', 32))]

    def test_opted_in_native_receipt_requires_taps_before_command_commit(self):
        self.enable_native_taps()
        session = self.make_session(mode='valid')
        session.prepare_local()
        session.begin_case('native-case')
        with self.assertRaises(ValueError):
            session.command('STEP_MEMORY', (0, 0, 0, 0))
        self.assertEqual((0, 0), (session._sequence, session.local_ticks))
        self.assertIsNone(session.process)

    def test_opted_in_native_receipt_forwards_exact_tap_contract(self):
        self.enable_native_taps()
        session = self.make_session(mode='native_valid_taps')
        session.prepare_local()
        session.begin_case('native-case')
        receipt = session.command('STEP_MEMORY', (0, 0, 0, 0))
        self.assertEqual((1, 1), (session._sequence, session.local_ticks))
        self.assertEqual(1, receipt.payload['samples'][0]['pre']
                         ['protocol_taps']['cpu_native_trace_valid'])

    def test_native_without_observation_accepts_legacy_receipt(self):
        self.document['kind'] = 'native_memory_cpu'
        session = self.make_session(mode='valid')
        session.prepare_local()
        session.begin_case('legacy-native-case')
        receipt = session.command('STEP_MEMORY', (0, 0, 0, 0))
        self.assertEqual((1, 1), (session._sequence, receipt.tick_after))

    def test_process_stays_alive_across_commands_and_ticks_are_monotone(self):
        session = self.make_session()
        session.prepare_local()
        session.begin_case('case-1')
        first = session.command('STEP_GPIO', (0,))
        second = session.command('STEP_GPIO', (1,))
        self.assertEqual((1, 2), (first.tick_after, second.tick_after))
        self.assertEqual(2, session.local_ticks)
        self.assertEqual(1, first.payload['observations']['gpio_out'])
        self.assertEqual(2, second.payload['observations']['gpio_out'])

    def test_host_acknowledges_only_parsed_prefix_before_seventeenth_command(self):
        session = self.make_session()
        session.begin_case('long-case')
        for index in range(16):
            self.assertEqual(index + 1,
                             session.command('STEP_GPIO', (index,)).tick_after)
        self.assertEqual(0, session._acknowledged)
        self.assertEqual(17, session.command('STEP_GPIO', (16,)).tick_after)
        self.assertEqual(16, session._acknowledged)
        self.assertEqual(17, session.local_ticks)

    def test_opt_in_trace_keeps_actual_commands_and_replies_across_ack(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session()
        with record_local_commands() as trace:
            session.begin_case('captured-case')
            for index in range(17):
                session.command('STEP_GPIO', (index,))
            session.end_case()
        records = trace.for_session(session)
        self.assertEqual(17, len(records))
        self.assertEqual(list(range(1, 18)), [r['sequence'] for r in records])
        self.assertEqual([format(index, 'x') for index in range(17)],
                         [r['command'].split()[-1] for r in records])
        self.assertTrue(all(r['reply'].startswith('RESULT ') for r in records))
        self.assertEqual((0, 17), (records[0]['tick_before'], records[-1]['tick_after']))
        self.assertTrue(trace.complete_for(session))

    def test_export_distinguishes_restarted_same_component_sessions(self):
        from types import SimpleNamespace
        import hashlib
        from myfuzz.local_harness.session import record_local_commands
        self.artifact.plan = SimpleNamespace(request=SimpleNamespace(instance_id='gpio_b'))
        session = self.make_session()
        with record_local_commands() as trace:
            session.begin_case('first')
            first_pid = session.process.pid
            first_nonce = session._execution
            session.command('STEP_GPIO', (1,))
            session.end_case()
            session.begin_case('second')
            second_pid = session.process.pid
            second_nonce = session._execution
            session.command('STEP_GPIO', (2,))
            session.end_case()
        rows = trace.export_sessions()
        self.assertEqual(2, len(rows))
        self.assertEqual(['gpio_b','gpio_b'], [row['component'] for row in rows])
        self.assertEqual([first_nonce, second_nonce], [row['identity']['execution_nonce'] for row in rows])
        self.assertEqual([first_pid, second_pid], [row['identity']['pid'] for row in rows])
        self.assertEqual(hashlib.sha256(session._binary.read_bytes()).hexdigest(), rows[0]['identity']['binary_sha256'])
        self.assertEqual([1, 1], [len(row['records']) for row in rows])
        self.assertTrue(all(row['complete'] for row in rows))
        rows[0]['records'].clear()
        self.assertEqual(1, len(trace.export_sessions()[0]['records']))

    def test_mid_session_capture_is_incomplete(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session()
        session.begin_case('late-capture')
        session.command('STEP_GPIO', (0,))
        with record_local_commands() as trace:
            session.command('STEP_GPIO', (1,))
        self.assertFalse(trace.complete_for(session))
        self.assertFalse(trace.export_sessions()[0]['complete'])

    def test_first_failed_command_is_exported_as_incomplete(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session('bad_tick')
        session.begin_case('first-command-fails')
        pid = session.process.pid
        with record_local_commands() as trace:
            with self.assertRaises(ValueError):
                session.command('STEP_GPIO', (0,))
        row, = trace.export_sessions()
        self.assertFalse(row['complete'])
        self.assertEqual([], row['records'])
        self.assertEqual(pid, row['identity']['pid'])

    def test_command_trace_keeps_reply_even_if_timing_observer_changes_last_reply(self):
        from myfuzz.local_harness.session import observe_local_command_timings, record_local_commands
        session = self.make_session()
        session.begin_case('timed-capture')
        def observer(_operation, _elapsed):
            session._last_wire_reply = 'replaced by observer'
        with record_local_commands() as trace, observe_local_command_timings(observer):
            session.command('STEP_GPIO', (0,))
        self.assertTrue(trace.for_session(session)[0]['reply'].startswith('RESULT '))

    def test_full_command_trace_is_marked_incomplete_without_stopping_rtl(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session()
        session.begin_case('bounded-capture')
        with record_local_commands(max_commands=1) as trace:
            session.command('STEP_GPIO', (0,))
            second = session.command('STEP_GPIO', (1,))
        self.assertEqual(second.tick_after, 2)
        self.assertEqual(len(trace.for_session(session)), 1)
        self.assertFalse(trace.complete_for(session))

    def test_command_trace_byte_budget_does_not_stop_live_session(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session()
        session.begin_case('byte-bound-capture')
        with record_local_commands(max_bytes=1) as trace:
            receipt = session.command('STEP_GPIO', (0,))
        self.assertEqual(receipt.tick_after, 1)
        self.assertFalse(trace.complete_for(session))

    def test_failed_driver_reply_marks_prior_command_trace_incomplete(self):
        from myfuzz.local_harness.session import record_local_commands
        session = self.make_session('bad_tick_after_one')
        session.begin_case('failed-capture')
        with record_local_commands() as trace:
            session.command('STEP_GPIO', (0,))
            with self.assertRaises(ValueError):
                session.command('STEP_GPIO', (1,))
        self.assertEqual(len(trace.for_session(session)), 1)
        self.assertFalse(trace.complete_for(session))

    def test_wrong_ready_is_rejected_and_process_closed(self):
        session = self.make_session('wrong_ready')
        with self.assertRaisesRegex(ValueError, 'identity'):
            session.begin_case('case-1')
        self.assertIsNone(session.process)

    def test_eof_and_stalled_partial_reply_are_bounded(self):
        for mode in ('eof', 'stall'):
            with self.subTest(mode=mode):
                session = self.make_session(mode, command_timeout_seconds=0.1)
                session.begin_case('case-' + mode)
                with self.assertRaises((RuntimeError, TimeoutError)):
                    session.command('STEP_GPIO', (0,))
                self.assertIsNone(session.process)

    def test_stalled_reply_identifies_command_and_limiting_deadline(self):
        import time
        from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded, command_deadline
        session = self.make_session('stall', command_timeout_seconds=0.1)
        session.begin_case('local-deadline')
        with self.assertRaises(LocalCommandDeadlineExceeded) as failure:
            session.command('STEP_GPIO', (0,))
        details = failure.exception.timeout_diagnostic
        self.assertEqual(details['operation'], 'STEP_GPIO')
        self.assertEqual(details['limiting_deadline'], 'local_command')
        self.assertIsNone(details['outer_remaining_seconds'])

        session = self.make_session('stall', command_timeout_seconds=1.0)
        session.begin_case('session-deadline')
        with command_deadline(time.monotonic() + 0.1):
            with self.assertRaises(LocalCommandDeadlineExceeded) as failure:
                session.command('STEP_GPIO', (0,))
        details = failure.exception.timeout_diagnostic
        self.assertEqual(details['operation'], 'STEP_GPIO')
        self.assertEqual(details['limiting_deadline'], 'outer_deadline')
        self.assertLessEqual(details['outer_remaining_seconds'], 0)

    def test_bad_tick_is_rejected(self):
        session = self.make_session('bad_tick')
        session.begin_case('case-1')
        with self.assertRaisesRegex(ValueError, 'tick'):
            session.command('STEP_GPIO', (0,))
        self.assertIsNone(session.process)

    def test_invalid_fields_rejected_before_process_effect(self):
        session = self.make_session()
        session.begin_case('case-1')
        with self.assertRaises(ValueError):
            session.command('STEP_GPIO', (1 << 32,))
        self.assertEqual(0, session.local_ticks)
        self.assertEqual(1, session.command('STEP_GPIO', (0,)).tick_after)

    def test_explicit_reset_starts_fresh_process_with_monotone_lifetime_ticks(self):
        session = self.make_session()
        session.begin_case('case-1')
        session.command('STEP_GPIO', (0,))
        self.assertEqual({'cancelled_responses': 0}, session.reset_local())
        self.assertEqual(1, session.local_ticks)
        self.assertEqual(1, session.command('STEP_GPIO', (1,)).tick_after)
        self.assertEqual(2, session.local_ticks)

    def test_artifact_document_mutation_after_creation_is_refused(self):
        session = self.make_session()
        self.document['artifact_digest'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'changed'):
            session.begin_case('case-1')

    def test_session_identity_includes_authenticated_build_inputs(self):
        session = self.make_session()
        expected = {'schema_version': 'local_harness_build_identity.v1',
                    'build_digest': 'c' * 64}
        with patch('myfuzz.local_harness.session.local_build_identity',
                   return_value=expected) as build_identity:
            identity = session.identity_document()
        self.assertEqual(expected, identity['build_identity'])
        build_identity.assert_called_once_with(self.artifact, base_dir=self.root)


if __name__ == '__main__':
    unittest.main()
