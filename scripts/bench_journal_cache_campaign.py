#!/usr/bin/env python3
"""Memory-lean same-workload campaign A/B for the EventJournal chunk cache.

Runs a fixed sequence of the real shared all-flow descriptor in ``original``
mode with ``execution_mode='search'`` (the campaign and its evidence export,
no within-invocation replay), so the two compared runs differ only in
``MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE``.  The replay is deliberately excluded
because this host cannot hold the full eight-case prefix and replay together;
the journal cache is exercised by the campaign steps themselves.

The work is identical on both sides and the report keeps the executed work
(case/flow counts, local ticks, journal event count and per-kind counts, native
eval counts when enabled) so a timing difference cannot come from doing less.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

DEFAULT_RECORDS = ('F6:0110c00008000000', 'F6:0110c00008000000')


class FixedWitness:
    """A selector that only returns the declared sequence, in order."""

    def __init__(self, records):
        self.records = tuple(records)

    def attach_runtime(self, runtime):
        self.runtime = runtime
        self.done = 0

    def choose(self):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows = flow_records(self.runtime)
        if len(rows) != self.done or any(row['status'] != 'passed' for row in rows):
            raise ValueError('online choice requires prior actual completion')
        if self.done >= len(self.records):
            raise ValueError('declared sequence complete')
        return self.records[self.done]

    def settle(self, record):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows = flow_records(self.runtime)
        if len(rows) != self.done + 1 or rows[-1]['flow'] + ':' + rows[-1]['raw_hex'] != record:
            raise ValueError('selected source was not actually consumed')
        self.done += 1


def _native_eval(prefix, native_dir):
    """Aggregate the per-process dut timing documents exactly like the benchmark."""
    identities = prefix.get('original_execution_audit', {}).get('identities', {})
    rows = {}
    for component, identity in identities.items():
        pid = identity.get('pid')
        path = Path(native_dir) / f'dut-timing-{pid}.json'
        if type(pid) is not int or not path.is_file():
            rows[component] = dict(status='unavailable', reason='counter not emitted')
            continue
        document = json.loads(path.read_text())
        if document.get('schema_version') != 'dut_eval_timing.v1' or document.get('pid') != pid:
            raise ValueError('native eval counter/process identity mismatch')
        rows[component] = dict(status='observed', **document)
    return {'original': rows}


def _aggregate(output):
    """Recompute native_eval for an already completed campaign-only output."""
    performance = output / 'performance.json'
    prefix = output / 'workload' / 'original' / 'prefix.json'
    if not performance.is_file() or not prefix.is_file():
        raise ValueError('completed campaign output required')
    report = json.loads(performance.read_text())
    report['native_eval'] = _native_eval(json.loads(prefix.read_text()), output / 'native-eval')
    performance.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + '\n')
    print(json.dumps({'aggregated': str(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=None)
    parser.add_argument('--records', default=','.join(DEFAULT_RECORDS),
                        help='comma-separated FLOW:hex sequence (default: two F6 cases)')
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--dut-eval', action='store_true')
    parser.add_argument('--aggregate-only', action='store_true',
                        help='recompute native_eval from an existing output directory')
    args = parser.parse_args()
    base = ROOT
    if args.aggregate_only:
        _aggregate(args.output)
        return 0
    records = [row for row in args.records.split(',') if row]
    if not records or any(':' not in row for row in records):
        raise ValueError('bounded FLOW:hex sequence required')
    if args.output.exists():
        raise ValueError('benchmark output must not exist')
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.runtime_benchmark import RuntimeTimings, workload_identity
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from scripts.run_shared_f6_slots import OnlineWitnessSequence

    args.output.mkdir(parents=True)
    native_dir = args.output / 'native-eval'
    prior = os.environ.get('MYFUZZ_DUT_TIMING_DIR')
    if args.dut_eval:
        native_dir.mkdir()
        os.environ['MYFUZZ_DUT_TIMING_DIR'] = str(native_dir.resolve())
    descriptor = load_descriptor(
        base / 'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json',
        base_dir=base)
    timing = RuntimeTimings()
    targets = dict(preparation=create_preparation, construct=CompiledF6Runtime.__init__,
                   begin=CompiledF6Runtime.begin, submit=CompiledF6Runtime.submit,
                   finish=CompiledF6Runtime.finish, fresh_replay=CompiledF6Runtime.replay,
                   selector_settle=OnlineWitnessSequence.settle)
    started = time.monotonic()
    failure = None
    summary = None
    try:
        with timing.observe(targets):
            summary = run_descriptor(
                descriptor, flow='mixed', mode='original',
                case_root=args.output / 'workload', base_dir=base,
                cache_dir=args.cache, sequence=records,
                record_selector=FixedWitness(records), selected_count=len(records),
                execution_case_capacity=len(records), execution_mode='search')
    except BaseException as error:  # keep the failure in the report, then re-raise
        failure = dict(type=type(error).__name__, reason=str(error))
        raise
    finally:
        wall = time.monotonic() - started
        if args.dut_eval:
            if prior is None:
                os.environ.pop('MYFUZZ_DUT_TIMING_DIR', None)
            else:
                os.environ['MYFUZZ_DUT_TIMING_DIR'] = prior
        report = timing.document(wall_seconds=wall)
        report.update(
            status='failed' if failure else 'complete', failure=failure,
            summary=summary, requested_records=records,
            replay_skipped=True, execution_mode='search',
            journal_cache_capacity=os.environ.get('MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE', 'default'),
            peak_rss_kb=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            native_eval_timers_enabled=args.dut_eval)
        prefix_path = args.output / 'workload' / 'original' / 'prefix.json'
        if prefix_path.is_file():
            prefix = json.loads(prefix_path.read_text(encoding='utf-8'))
            report['workload_identity'] = workload_identity(prefix)
            if args.dut_eval:
                report['native_eval'] = _native_eval(prefix, args.output / 'native-eval')
        (args.output / 'performance.json').write_text(
            json.dumps(report, indent=2, sort_keys=True, default=str) + '\n')
    print(json.dumps(dict(status=report['status'], wall_seconds=wall,
                          execution_seconds=(summary or {}).get('execution_seconds'),
                          records=len(records),
                          peak_rss_kb=report['peak_rss_kb'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
