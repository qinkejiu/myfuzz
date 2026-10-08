"""Current commands share their scripts' parsers and execution behavior."""
from contextlib import redirect_stdout, redirect_stderr
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.__main__ import ROOT, main


COMMANDS = (
    (('harness', 'generate'), 'generate_local_harness',
     ['--request', 'request.json', '--output', 'out']),
    (('scenario', 'record'), 'record_scenario',
     ['--genome', 'genome.json', '--factory', 'invalid', '--output', 'out']),
    (('scenario', 'replay'), 'replay_scenario',
     ['--evidence', 'out', '--factory', 'invalid']),
    (('scenario', 'campaign'), 'run_scenario_campaign',
     ['--manifest', 'missing.json', '--output', 'out']),
)


class CurrentCliTests(unittest.TestCase):
    def invoke(self, entry, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                status = entry(argv)
            except SystemExit as exc:
                status = exc.code
        return status, stdout.getvalue(), stderr.getvalue()

    def test_help_exposes_each_current_command_and_script_options(self):
        for command, script, _ in COMMANDS:
            with self.subTest(command=command):
                status, stdout, _ = self.invoke(main, [*command, '--help'])
                self.assertEqual(0, status)
                module = importlib.import_module('scripts.' + script)
                with patch.object(sys, 'argv', [script, '--help']):
                    script_status, script_help, _ = self.invoke(lambda _: module.main(), [])
                self.assertEqual(0, script_status)
                for option in ('--output', '--factory', '--request', '--provider',
                               '--resume', '--reverse-chain-values', '--seed'):
                    if option in script_help:
                        self.assertIn(option, stdout)

    def test_invalid_input_preserves_script_status_and_validation(self):
        for command, script, argv in COMMANDS[1:]:
            with self.subTest(command=command):
                module = importlib.import_module('scripts.' + script)
                with patch.object(sys, 'argv', [script, *argv]):
                    expected = self.invoke(lambda _: module.main(), [])
                actual = self.invoke(main, [*command, *argv])
                self.assertEqual(expected[:2], actual[:2])
                self.assertEqual(expected[2].splitlines()[-1].split('error: ')[-1],
                                 actual[2].splitlines()[-1].split('error: ')[-1])

    def test_generation_calls_same_implementation_with_same_arguments(self):
        module = importlib.import_module('scripts.generate_local_harness')
        argv = ['--request', 'request.json', '--output', 'out', '--build-cache', 'cache']
        with patch.object(module, 'generate', return_value={'status': 'driver_generated'}) as generate:
            with patch.object(sys, 'argv', ['generate_local_harness.py', *argv]):
                expected = self.invoke(lambda _: module.main(), [])
            expected_call = generate.call_args
            generate.reset_mock()
            actual = self.invoke(main, ['harness', 'generate', *argv])
            self.assertEqual(expected, actual)
            self.assertEqual(expected_call, generate.call_args)

    def test_record_produces_same_trace_through_both_entries(self):
        from myfuzz.scenario.genome import ScenarioGenome, Action, Trigger, GenomeCodec
        module = importlib.import_module('scripts.record_scenario')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            genome = ScenarioGenome(
                testcase_id='cli-record', direction='IP_TO_IP', path_id='pin',
                schedule_order=('gpio',), max_steps=3,
                actions=(Action('edge', 'gpio', 'pin', 1, 'IP_TO_IP', Trigger('START')),))
            path = root / 'genome.bin'
            path.write_bytes(GenomeCodec.encode(genome))
            argv = ['--genome', str(path), '--factory',
                    'tests.scenario.evidence_cli_fixture:make_runner']
            with patch.object(sys, 'argv', ['record_scenario.py', *argv, '--output', str(root / 'script')]):
                expected = self.invoke(lambda _: module.main(), [])
            actual = self.invoke(main, ['scenario', 'record', *argv, '--output', str(root / 'module')])
            self.assertEqual(0, expected[0], expected[2])
            self.assertEqual(expected, actual)
            self.assertEqual((root / 'script' / 'trace.json').read_bytes(),
                             (root / 'module' / 'trace.json').read_bytes())
            self.assertEqual((root / 'script' / 'run_identity.json').read_bytes(),
                             (root / 'module' / 'run_identity.json').read_bytes())

    def test_campaign_preserves_blocked_status_defaults_and_report(self):
        module = importlib.import_module('scripts.run_scenario_campaign')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / 'manifest.json'
            manifest.write_text('{}\n')
            argv = ['--manifest', str(manifest)]
            with patch.object(sys, 'argv', ['run_scenario_campaign.py', *argv, '--output', str(root / 'script')]):
                expected = self.invoke(lambda _: module.main(), [])
            actual = self.invoke(main, ['scenario', 'campaign', *argv, '--output', str(root / 'module')])
            self.assertEqual(2, expected[0], expected[2])
            self.assertEqual(expected[0], actual[0])
            expected_json, actual_json = json.loads(expected[1]), json.loads(actual[1])
            expected_json.pop('report')
            actual_json.pop('report')
            self.assertEqual(expected_json, actual_json)
            reports = [json.loads((root / entry / 'campaign_report.json').read_text())
                       for entry in ('script', 'module')]
            self.assertEqual(reports[0], reports[1])
            self.assertEqual((root / 'script' / 'campaign_run_identity.json').read_bytes(),
                             (root / 'module' / 'campaign_run_identity.json').read_bytes())

    def test_replay_subprocess_matches_script_result(self):
        from myfuzz.scenario.evidence import save_evidence_bundle
        from myfuzz.scenario.genome import ScenarioGenome, Action, Trigger
        from tests.scenario.evidence_cli_fixture import make_runner
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'evidence'
            save_evidence_bundle(ScenarioGenome(
                testcase_id='cli-parity', direction='IP_TO_IP', path_id='pin',
                schedule_order=('gpio',), max_steps=3,
                actions=(Action('edge', 'gpio', 'pin', 1, 'IP_TO_IP',
                                Trigger('START')),)), make_runner, bundle)
            argv = ['--evidence', str(bundle), '--factory',
                    'tests.scenario.evidence_cli_fixture:make_runner', '--rebuild', '--compare-trace']
            results = []
            for entry in ([sys.executable, str(ROOT / 'scripts/replay_scenario.py')],
                          [sys.executable, '-m', 'myfuzz', 'scenario', 'replay']):
                results.append(subprocess.run([*entry, *argv], cwd=ROOT,
                    env={**os.environ, 'PYTHONPATH': str(ROOT / 'src') + os.pathsep + str(ROOT)},
                    capture_output=True, text=True, timeout=30, check=False))
            self.assertEqual(0, results[0].returncode, results[0].stderr)
            self.assertEqual(0, results[1].returncode, results[1].stderr)
            self.assertEqual(json.loads(results[0].stdout), json.loads(results[1].stdout))

    def test_old_matrix_parameters_require_explicit_compatibility_command(self):
        for command in ('check', 'preflight', 'run'):
            with self.subTest(command=command):
                with patch('myfuzz.__main__._check', return_value=0):
                    status, _, stderr = self.invoke(main, [command])
                self.assertEqual(2, status)
                self.assertIn('invalid choice', stderr)

    def test_compat_soc_preflight_dispatches_with_historical_arguments(self):
        argv = ['compat', 'soc', 'preflight', '--matrix', 'matrix.json',
                '--output', 'out', '--seconds', '42', '--seed', '9']
        expected = {'status': 'preflight-only', 'tasks_planned': 32,
                    'effective_budget_seconds': 42}
        with patch('myfuzz.__main__.run_matrix', return_value=expected) as run_matrix:
            status, stdout, stderr = self.invoke(main, argv)
        self.assertEqual(0, status, stderr)
        self.assertEqual({
            'status': 'preflight-only', 'tasks': 32,
            'effective_seconds': 42,
        }, json.loads(stdout))
        run_matrix.assert_called_once_with(
            Path('matrix.json'), Path('out'), seconds=42, seed=9,
            preflight_only=True, root=ROOT, client=None)

    def test_compat_soc_run_requires_the_historical_opt_in(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch('myfuzz.__main__.run_matrix') as run_matrix:
                status, _, stderr = self.invoke(
                    main, ['compat', 'soc', 'run', '--output', 'out',
                           '--client', 'rfuzz'])
        self.assertEqual(2, status)
        self.assertIn('run requires MYFUZZ_SOC_REAL=1', stderr)
        run_matrix.assert_not_called()
