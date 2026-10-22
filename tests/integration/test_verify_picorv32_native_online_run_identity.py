import importlib.util
import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / 'scripts' / 'verify_picorv32_native_online.py'
SPEC = importlib.util.spec_from_file_location(
    '_verify_picorv32_native_online_run_identity', SCRIPT_PATH)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NativeOnlineGateRunIdentityTests(unittest.TestCase):
    def test_cli_requires_a_64_character_lowercase_hex_run_id(self):
        parser = GATE.build_parser()
        required = ['--output', '/tmp/out', '--cache-dir', '/tmp/cache',
                    '--heavy-lock', '/tmp/lock']
        with self.assertRaises(SystemExit):
            parser.parse_args(required)

        run_id = '0123456789abcdef' * 4
        args = parser.parse_args(required + ['--gate-run-id', run_id])
        self.assertEqual(args.gate_run_id, run_id)

    def test_cli_rejects_noncanonical_run_id(self):
        parser = GATE.build_parser()
        required = ['--output', '/tmp/out', '--cache-dir', '/tmp/cache',
                    '--heavy-lock', '/tmp/lock']
        for run_id in (
                'a' * 63,
                'a' * 65,
                'A' * 64,
                'g' * 64,
                'a' * 63 + '\n'):
            with self.subTest(run_id=repr(run_id)), self.assertRaises(SystemExit):
                parser.parse_args(required + ['--gate-run-id', run_id])

    def test_branch_result_identity_is_explicit_and_names_a_gate_branch(self):
        run_id = 'b' * 64
        for branch in ('positive', 'controlled-response', 'native-source-refusal'):
            with self.subTest(branch=branch):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = Path(temp_dir) / 'result.json.gz'
                    GATE.save_gate_result(path, {'status': 'failed'}, run_id, branch)
                    document = json.loads(gzip.decompress(path.read_bytes()))
                self.assertEqual(document['gate_run_id'], run_id)
                self.assertEqual(document['gate_branch'], branch)
                self.assertEqual(document['gate_pid'], os.getpid())

    def test_branch_result_identity_rejects_unknown_branch(self):
        with self.assertRaises(ValueError):
            GATE.gate_result_identity('b' * 64, 'unexpected')

    def test_summary_identity_uses_same_run_id_and_gate_process(self):
        run_id = 'c' * 64
        identity = GATE.gate_summary_identity(run_id)
        self.assertEqual(identity, {'gate_run_id': run_id, 'gate_pid': os.getpid()})

    def test_argument_validation_rejects_each_native_option_dependency(self):
        cases = (
            ({'native_source_binding': True},
             'native-source-binding requires native-completion-observation'),
            ({'native_source_completion': True, 'native_completion_observation': True},
             'native-source-completion requires native-source-binding'),
            ({'native_source_completion': True, 'native_source_binding': True},
             'native-source-completion requires native-completion-observation'),
        )
        for options, expected_message in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temp_dir:
                outside = Path(temp_dir)
                stderr = StringIO()
                with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    self._run_main(outside / 'out', outside / 'cache', outside / 'lock',
                                   options=self._cli_options(options))
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(expected_message, stderr.getvalue())

    def test_argument_validation_rejects_output_inside_source_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            source_root = Path(temp_dir)
            outside = source_root.parent / (source_root.name + '-outside')
            stderr = StringIO()
            with patch.object(GATE, 'ROOT', source_root), redirect_stderr(stderr), \
                    self.assertRaises(SystemExit) as raised:
                self._run_main(source_root / 'runs' / 'candidate', outside / 'cache',
                               outside / 'lock')
            self.assertEqual(raised.exception.code, 2)
            self.assertIn('output must be outside frozen source', stderr.getvalue())

    @staticmethod
    def _cli_options(options):
        mapping = dict(native_completion_observation='--native-completion-observation',
                       native_source_binding='--native-source-binding',
                       native_source_completion='--native-source-completion')
        return [mapping[name] for name, enabled in options.items() if enabled]

    @staticmethod
    def _run_main(output, cache_dir, heavy_lock, *, options=()):
        argv = ['verify_picorv32_native_online.py', '--output', str(output),
                '--cache-dir', str(cache_dir), '--heavy-lock', str(heavy_lock),
                '--gate-run-id', 'd' * 64, *options]
        with patch('sys.argv', argv):
            GATE.main()


if __name__ == '__main__':
    unittest.main()
