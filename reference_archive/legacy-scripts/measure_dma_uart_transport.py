#!/usr/bin/env python3
"""Measure existing scalar continuous RX command calls; execution starts in main."""
from __future__ import annotations

import argparse
from collections import Counter
import fcntl
import gzip
import hashlib
import json
import math
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def _bytes(value):
    try:
        values = tuple(int(part.strip(), 0) for part in value.split(','))
    except ValueError as exc:
        raise argparse.ArgumentTypeError('use comma-separated integer bytes') from exc
    if not 1 <= len(values) <= 16 or any(not 0 <= byte <= 255 for byte in values):
        raise argparse.ArgumentTypeError('provide 1..16 bytes in 0..255')
    return values


class CommandTimings:
    """Bounded aggregates of the existing (operation, elapsed_seconds) callback."""

    def __init__(self):
        self.operations = {}
        self.invalid_callbacks = 0
        self.overflow_callbacks = 0

    def __call__(self, operation, seconds):
        if (type(operation) is not str or not 1 <= len(operation) <= 128
                or type(seconds) not in (float, int)
                or not math.isfinite(seconds) or seconds < 0):
            self.invalid_callbacks += 1
            return
        row = self.operations.get(operation)
        if row is None:
            if len(self.operations) >= 64:
                self.overflow_callbacks += 1
                return
            row = self.operations[operation] = dict(calls=0, seconds=0.0,
                                                   max_seconds=0.0)
        row['calls'] += 1
        row['seconds'] += seconds
        row['max_seconds'] = max(row['max_seconds'], seconds)

    def document(self):
        return dict(by_operation=self.operations,
            observed_command_calls=sum(row['calls'] for row in self.operations.values()),
            observed_command_seconds=sum(row['seconds'] for row in self.operations.values()),
            invalid_callbacks=self.invalid_callbacks,
            overflow_callbacks=self.overflow_callbacks,
            semantics='GeneratedLocalSession.command finally callback after initial owner guard; excludes that guard and includes _command_impl failures/prewire attempts; not a wire-command counter')


def _cpu_times():
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return dict(python_process_seconds=time.process_time(),
                waited_descendants_cpu_seconds=children.ru_utime + children.ru_stime)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory')
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--heavy-lock', type=Path, required=True,
                        help='root must supply the canonical shared nonblocking worker lock')
    parser.add_argument('--source-bytes', type=_bytes, default=(0x5a, 0, 0xa5, 0xa5))
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    operation = dict(schema_version='dma_scalar_measurement_operation.v1',
        stage='created', lock_acquired=False, project_import_completed=False,
        runtime_call_entered=False, runtime_returned=False)
    try:
        code = _measure_locked(args, operation)
    except BaseException as primary:
        operation.update(status='failed', failure=_bounded_error(primary))
        try:
            _save_operation(args.output, operation)
        except BaseException as secondary:
            # Receipt failure must not replace the original lock/import/runtime error.
            try:
                print('operation receipt write failed: ' + str(_bounded_error(secondary)),
                      file=sys.stderr)
            except BaseException:
                pass
        raise
    operation.update(status='completed' if code == 0 else 'failed', exit_code=code)
    _save_operation(args.output, operation)
    return code


def _bounded_error(error):
    try:
        message = str(error)[:2048]
    except BaseException:
        message = '<exception string unavailable>'
    return dict(type=type(error).__name__[:128], message=message)


def _save_operation(output, operation):
    (output / 'operation.json').write_text(json.dumps(operation, indent=2,
        sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')


def _measure_locked(args, operation):
    # No project import, constructor, build or model launch until lock admission.
    # Existing canonical lock parent must already exist; do not create a new lock tree.
    operation['stage'] = 'lock_open'
    with args.heavy_lock.open('a+') as lock:
        operation['stage'] = 'lock_acquire'
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operation['lock_acquired'] = True
        operation['stage'] = 'project_import'
        sys.path.insert(0, str(ROOT / 'src'))
        import_started = time.monotonic()
        from myfuzz.local_harness.session import observe_local_command_timings
        from myfuzz.integration.dma_uart_rx_runtime import (
            ContinuousRxFailure, run_continuous_uart_rx)
        import_seconds = time.monotonic() - import_started
        operation['project_import_completed'] = True
        operation['stage'] = 'measurement_setup'
        timings = CommandTimings()
        result = None
        failure = None
        cpu_before = _cpu_times()
        started = time.monotonic()
        operation['stage'] = 'runtime'
        operation['runtime_call_entered'] = True
        try:
            with observe_local_command_timings(timings):
                result = run_continuous_uart_rx(args.source_bytes,
                                               cache_dir=args.cache_dir)
        except ContinuousRxFailure as exc:
            result = exc.result
            failure = _bounded_error(exc)
        except Exception as exc:
            failure = _bounded_error(exc)
        operation['runtime_returned'] = True
        operation['runtime_failure'] = failure
        elapsed = time.monotonic() - started
        cpu_after = _cpu_times()
        operation['stage'] = 'result_write'
        counts = None
        bundle = None
        if result is not None:
            # Write the runtime's original document without timing fields or normalization.
            original = json.dumps(result.to_document(), sort_keys=True,
                                  allow_nan=False).encode()
            path = args.output / 'scalar-result.json.gz'
            path.write_bytes(gzip.compress(original, mtime=0))
            bundle = dict(path=path.name, uncompressed_sha256=hashlib.sha256(original).hexdigest(),
                          compressed_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            kinds = Counter(event.get('kind') for event in result.events)
            phases = Counter(event.get('phase') for event in result.events
                if event.get('kind') == 'local_tick_sample'
                and event.get('component') == 'uart')
            commands = result.plan.commands
            counts = dict(logical_plan_commands=len(commands), events=len(result.events),
                completed_cases=len(result.cases), local_ticks=dict(result.local_ticks),
                uart_raw_tick_sample_events=dict(phases),
                uart_tick_observation_events=kinds['uart_tick_observation'],
                phase=result.phase, error=result.error,
                trace_status=result.trace.status if result.trace is not None else None)
        report = dict(schema_version='dma_scalar_transport_timing.v1',
            script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            project_root=str(ROOT), cache_dir=str(args.cache_dir.resolve()),
            heavy_lock=str(args.heavy_lock.resolve()), source_bytes=list(args.source_bytes),
            resource_budget='unchanged runtime default: max_wall_time_ms=300000',
            import_seconds=import_seconds, whole_runtime_wall_seconds=elapsed,
            cpu_deltas={name: cpu_after[name] - value for name, value in cpu_before.items()},
            timings=timings.document(), saved_event_counts=counts,
            original_bundle=bundle, failure=failure,
            unavailable=dict(actual_wire_command_count='callback lacks write/reply identity',
                ack_count='ACKs execute inside _command_impl, no callback per ACK',
                wire_bytes='callback exposes only operation and elapsed seconds',
                build_startup_seconds='runtime wrapper does not expose phase timings; included in whole runtime wall',
                steady_state_wall_seconds='unavailable without separate phase instrumentation',
                native_only_cpu_seconds='waited-descendant delta may include compiler/build children',
                effective_search_seconds='directed continuous run, not RFuzz search',
                fresh_comparison='not run by measurement script'),
            interpretation='command duration includes guard/ACK/transport/parse work; sum is not isolated pipe cost or an achievable speedup')
        operation['stage'] = 'timing_write'
        (args.output / 'timing.json').write_text(json.dumps(report, indent=2,
            sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')
        operation['stage'] = 'measurement_finished'
        return 1 if failure is not None or timings.invalid_callbacks or timings.overflow_callbacks else 0


if __name__ == '__main__':
    raise SystemExit(main())
