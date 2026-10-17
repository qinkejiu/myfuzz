"""New-process gate for the non-Ibex, non-GPIO controlled protocol error.

The existing sibling acceptance test
``test_cv32e40p_opentitan_uart_controlled_error_real.py`` proves, inside one
Python process, that the unmodified CV32E40P + OpenTitan UART chain is silent
while the same chain with one controlled UART RXDATA response flipped from
``0x5a`` to ``0x5b`` is caught by ``IbexUartOnlineChecker``.  This test closes
the remaining replay claim: the control run, the fault run, both fresh RTL
replays and the checker recheck are executed by **separate OS processes**, in
that order, and the same named violation is reproduced at the same local tick,
event and data value while the control stays silent.

Each phase is one ``python3`` invocation of
``non_ibex_non_gpio_controlled_error_process.py``:

1. ``run --group control``   real RTL, unmodified factory, full evidence bundle
2. ``run --group fault``     real RTL, one-shot RDATA response flip, bundle
3. ``replay --group control`` fresh RTL sessions, complete trace comparison
4. ``replay --group fault``   fresh RTL sessions, same comparison and violation
5. ``check``                  no RTL: fresh checker on the four saved traces

The boundary is unchanged from the sibling test: the perturbation lives at
``target_register_read_response_copy``, is computed from the RTL's own returned
value, marks ``rtl_internal_fault=False`` and is calibration only.  Nothing
here is a natural DUT defect, an RTL-internal fault, a synthetic CPU/DMA output
or a relaxed checker invariant.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name(
    'non_ibex_non_gpio_controlled_error_process.py')
EXPECTED_VIOLATION = 'uart_rxdata_source_mismatch'
SOURCE_BYTE = 0x5a
INJECTED_BYTE = SOURCE_BYTE ^ 1
RDATA_OFFSET = 0x18
TIMEOUT_SECONDS = 1800


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _driver_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment['MYFUZZ_SCENARIO_REAL'] = '1'
    parts = [str(ROOT / 'src'), str(ROOT)]
    if environment.get('PYTHONPATH'):
        parts.append(environment['PYTHONPATH'])
    environment['PYTHONPATH'] = os.pathsep.join(parts)
    return environment


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P and '
                     'OpenTitan RTL')
class NonIbexNonGpioFreshProcessControlledErrorTests(unittest.TestCase):
    """The controlled error survives real, separate-process replay."""

    def test_control_run_fault_run_and_fresh_replays_are_separate_processes(self):
        override = os.environ.get('MYFUZZ_CONTROLLED_ERROR_OUTPUT')
        cleanup = None
        if override:
            work = Path(override)
            work.mkdir(parents=True, exist_ok=True)
        else:
            cleanup = tempfile.TemporaryDirectory(
                prefix='myfuzz-p6-non-ibex-non-gpio-fresh-process-')
            work = Path(cleanup.name)
        try:
            case = work / f'fresh-process-{os.getpid()}'
            case.mkdir(parents=True, exist_ok=False)
            self._run_case(case)
        finally:
            if cleanup is not None:
                cleanup.cleanup()

    def _step(self, case: Path, label: str, *arguments: str) -> dict:
        command = [sys.executable, str(DRIVER), *map(str, arguments)]
        started = time.time_ns()
        completed = subprocess.run(
            command, cwd=ROOT, env=_driver_environment(),
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
        finished = time.time_ns()
        stdout_path = case / f'{label}.stdout.log'
        stderr_path = case / f'{label}.stderr.log'
        stdout_path.write_text(completed.stdout, encoding='utf-8')
        stderr_path.write_text(completed.stderr, encoding='utf-8')
        record = {
            'label': label,
            'argv': command,
            'returncode': completed.returncode,
            'started_unix_ns': started,
            'finished_unix_ns': finished,
            'stdout': str(stdout_path.resolve()),
            'stdout_sha256': _sha256(stdout_path),
            'stderr': str(stderr_path.resolve()),
            'stderr_sha256': _sha256(stderr_path),
        }
        if completed.returncode != 0:
            self.fail(
                f'{label} exited {completed.returncode}\n'
                f'command: {command}\n'
                f'stdout tail:\n{completed.stdout[-4000:]}\n'
                f'stderr tail:\n{completed.stderr[-4000:]}')
        return record

    def _read(self, path: Path) -> dict:
        return json.loads(Path(path).read_text(encoding='utf-8'))

    def _run_case(self, case: Path) -> None:
        cache = case / 'cache'
        control_bundle = case / 'control-bundle'
        fault_bundle = case / 'fault-bundle'
        control_replay_trace = case / 'control-replay-trace.json'
        fault_replay_trace = case / 'fault-replay-trace.json'
        steps = []

        # The normal group runs first, in its own process.
        steps.append(self._step(
            case, '01-control-run', 'run', '--group', 'control',
            '--bundle', control_bundle, '--cache', cache,
            '--observation', case / 'control-run.json'))
        control_run = self._read(case / 'control-run.json')

        # The fault group is a separate process over the identical scenario.
        steps.append(self._step(
            case, '02-fault-run', 'run', '--group', 'fault',
            '--bundle', fault_bundle, '--cache', cache,
            '--observation', case / 'fault-run.json'))
        fault_run = self._read(case / 'fault-run.json')

        # Fresh RTL replays: each process loads a saved bundle and constructs
        # brand-new sessions; nothing is fed back from the original process.
        steps.append(self._step(
            case, '03-control-replay', 'replay', '--group', 'control',
            '--bundle', control_bundle, '--cache', cache,
            '--trace-out', control_replay_trace,
            '--observation', case / 'control-replay.json'))
        control_replay = self._read(case / 'control-replay.json')

        steps.append(self._step(
            case, '04-fault-replay', 'replay', '--group', 'fault',
            '--bundle', fault_bundle, '--cache', cache,
            '--trace-out', fault_replay_trace,
            '--observation', case / 'fault-replay.json'))
        fault_replay = self._read(case / 'fault-replay.json')

        # A checker-only process, with no RTL runnable path, re-derives all
        # four verdicts from the saved trace JSON.
        steps.append(self._step(
            case, '05-check', 'check', '--group', 'fault',
            '--trace', f'control-run={control_bundle / "trace.json"}',
            '--trace', f'fault-run={fault_bundle / "trace.json"}',
            '--trace', f'control-replay={control_replay_trace}',
            '--trace', f'fault-replay={fault_replay_trace}',
            '--observation', case / 'checker.json'))
        checker = self._read(case / 'checker.json')

        # -- the two groups declared the same system identity ---------------
        self.assertEqual([], control_run['findings'])
        self.assertEqual([EXPECTED_VIOLATION], fault_run['findings'])
        self.assertEqual(control_run['manifest_sha256'],
                         fault_run['manifest_sha256'])
        self.assertEqual(control_run['chain'], fault_run['chain'])
        self.assertEqual(control_run['checker'], fault_run['checker'])

        # -- the RTL really produced 0x5a; only the response copy changed ----
        control_evidence = control_run['evidence']
        fault_evidence = fault_run['evidence']
        self.assertEqual(SOURCE_BYTE,
                         control_evidence['real_rtl_uart_rsp_rdata'])
        self.assertEqual(SOURCE_BYTE,
                         fault_evidence['real_rtl_uart_rsp_rdata'])
        self.assertEqual(SOURCE_BYTE,
                         control_evidence['rdata_delivery_read_value'])
        self.assertEqual(INJECTED_BYTE,
                         fault_evidence['rdata_delivery_read_value'])
        # The RTL's raw response sample, its event and local tick are the same
        # in both groups; the perturbation is not an RTL change.
        self.assertEqual(control_evidence['real_rtl_uart_rsp_sample_event_id'],
                         fault_evidence['real_rtl_uart_rsp_sample_event_id'])
        self.assertEqual(control_evidence['real_rtl_uart_rsp_local_tick'],
                         fault_evidence['real_rtl_uart_rsp_local_tick'])
        self.assertEqual(control_evidence['rdata_delivery_event_id'],
                         fault_evidence['rdata_delivery_event_id'])
        self.assertEqual(SOURCE_BYTE, control_run['persistent_ram_rdata'])
        self.assertEqual(INJECTED_BYTE, fault_run['persistent_ram_rdata'])
        self.assertEqual([], control_evidence['findings'])
        self.assertEqual([EXPECTED_VIOLATION], fault_evidence['findings'])

        fault_document = fault_run['fault_document']
        self.assertIsNotNone(fault_document,
                             'the controlled perturbation never fired')
        self.assertEqual('controlled_target_response_fault.v1',
                         fault_document['schema_version'])
        self.assertTrue(fault_document['calibration_only'])
        self.assertFalse(fault_document['rtl_internal_fault'])
        self.assertEqual('target_register_read_response_copy',
                         fault_document['observation_boundary'])
        self.assertTrue(fault_document['injected_once'])
        self.assertEqual('uart', fault_document['target_instance'])
        self.assertEqual(RDATA_OFFSET, fault_document['offset'])
        self.assertFalse(fault_document['write'])
        self.assertEqual(SOURCE_BYTE, fault_document['real_rtl_rdata'])
        self.assertEqual(INJECTED_BYTE, fault_document['delivered_rdata'])
        self.assertIsNone(control_run['fault_document'])

        # -- both fresh RTL replays matched the saved complete traces ---------
        for name, document in (('control', control_replay),
                               ('fault', fault_replay)):
            self.assertTrue(document['replay']['matches'],
                            f'{name} replay did not match')
            self.assertIsNone(document['replay']['first_difference'])
            self.assertEqual('full',
                             document['replay']['verification_scope'])
            self.assertEqual(control_run['manifest_sha256'],
                             document['manifest_sha256'])
        self.assertEqual([], control_replay['findings'])
        self.assertEqual([EXPECTED_VIOLATION], fault_replay['findings'])
        self.assertEqual(control_evidence, control_replay['evidence'])
        self.assertEqual(fault_evidence, fault_replay['evidence'])
        self.assertEqual(control_run['semantic_sha256'],
                         control_replay['semantic_sha256'])
        self.assertEqual(fault_run['semantic_sha256'],
                         fault_replay['semantic_sha256'])
        self.assertEqual(SOURCE_BYTE, control_replay['persistent_ram_rdata'])
        self.assertEqual(INJECTED_BYTE, fault_replay['persistent_ram_rdata'])
        self.assertIsNotNone(fault_replay['fault_document'])
        self.assertEqual(fault_document, fault_replay['fault_document'])
        self.assertEqual(fault_run['bundle_trace_json_sha256'],
                         fault_replay['source_bundle_trace_json_sha256'])

        # -- the checker decisions were independently re-derived -------------
        results = checker['results']
        self.assertEqual([], results['control-run']['findings'])
        self.assertEqual([EXPECTED_VIOLATION], results['fault-run']['findings'])
        self.assertEqual([], results['control-replay']['findings'])
        self.assertEqual([EXPECTED_VIOLATION],
                         results['fault-replay']['findings'])
        self.assertEqual(EXPECTED_VIOLATION, checker['expected_violation'])
        self.assertNotEqual(control_run['process']['pid'],
                            fault_run['process']['pid'])
        self.assertNotEqual(fault_run['process']['pid'],
                            fault_replay['process']['pid'])
        self.assertEqual(fault_run['bundle_trace_json_sha256'],
                         results['fault-run']['trace_json_sha256'])
        self.assertEqual(control_run['bundle_trace_json_sha256'],
                         results['control-run']['trace_json_sha256'])
        self.assertEqual(fault_replay['replay_trace_json_sha256'],
                         results['fault-replay']['trace_json_sha256'])
        self.assertEqual(control_replay['replay_trace_json_sha256'],
                         results['control-replay']['trace_json_sha256'])

        # -- five genuinely separate processes, run sequentially -------------
        process_documents = (control_run, fault_run, control_replay,
                             fault_replay, checker)
        pids = [document['process']['pid'] for document in process_documents]
        self.assertEqual(5, len(set(pids)), pids)
        self.assertNotIn(os.getpid(), pids)
        for document in process_documents:
            self.assertEqual(os.getpid(),
                             document['process']['parent_pid'])
        phases = [
            (control_run['process']['started_unix_ns'],
             control_run['process']['finished_unix_ns']),
            (fault_run['process']['started_unix_ns'],
             fault_run['process']['finished_unix_ns']),
            (control_replay['process']['started_unix_ns'],
             control_replay['process']['finished_unix_ns']),
            (fault_replay['process']['started_unix_ns'],
             fault_replay['process']['finished_unix_ns']),
            (checker['process']['started_unix_ns'],
             checker['process']['finished_unix_ns']),
        ]
        for index in range(len(phases) - 1):
            self.assertLess(phases[index][1], phases[index + 1][0],
                            f'phase {index} and {index + 1} overlapped')

        report = {
            'schema_version':
                'p6_non_ibex_non_gpio_fresh_process_report.v1',
            'chain': control_run['chain'],
            'expected_violation': EXPECTED_VIOLATION,
            'source_byte': SOURCE_BYTE,
            'injected_byte': INJECTED_BYTE,
            'control': control_run,
            'fault': fault_run,
            'control_replay': control_replay,
            'fault_replay': fault_replay,
            'checker': checker,
            'steps': steps,
            'process_ids': pids,
            'control_bundle': str(control_bundle.resolve()),
            'fault_bundle': str(fault_bundle.resolve()),
            'control_bundle_trace_sha256':
                control_run['bundle_trace_json_sha256'],
            'fault_bundle_trace_sha256':
                fault_run['bundle_trace_json_sha256'],
        }
        report_path = case / 'fresh-process-report.json'
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True,
                       ensure_ascii=False) + '\n', encoding='utf-8')
        self.assertTrue(report_path.is_file())


if __name__ == '__main__':
    unittest.main()
