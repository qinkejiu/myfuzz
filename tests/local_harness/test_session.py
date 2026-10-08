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
                if mode == 'bad_tick': before = tick + 1
                else: before = tick
                tick += 1
                payload = {{'schema_version':'local_driver_result.v1','kind':'apb_gpio',
                           'samples':[{{'local_tick':tick,'pre':{{}},'post':{{}}}}],
                           'observations':{{'gpio_out':tick}},'pre_backend':{{}},
                           'rdata':0,'error':0}}
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
