#!/usr/bin/env python3
"""Same-workload A/B driver for the shared all-flow runtime.

One invocation runs an explicit FLOW:hex sequence through the checked-in
``compiled-f1-f6-ibex-gpio-dma-shared`` descriptor and records the phase spans,
peak RSS and byte identities of every exported document.  ``--replay`` keeps the
within-invocation fresh replay (``execution_mode`` unset -> the legacy default),
without it the run is campaign-only (``execution_mode='search'``) and never
starts a second session.  The two modes are separate workloads and their walls
must not be compared with each other.

The workload is fixed by the caller so both sides of an A/B execute exactly the
same case sequence; ``workload_identity`` (events, local ticks, native eval
counts) is recomputed from the saved prefix exactly like
``scripts/bench_journal_cache_campaign.py`` does.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

DEFAULT_DESCRIPTOR = ('configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/'
                      'generic_scenario.json')


class SequenceWitness:
    """Return the declared sequence in order, only after real prior completion."""

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
        if (len(rows) != self.done + 1
                or rows[-1]['flow'] + ':' + rows[-1]['raw_hex'] != record):
            raise ValueError('selected source was not actually consumed')
        from scripts.run_shared_f6_slots import require_f5_irq_witness
        require_f5_irq_witness(rows[-1])
        self.done += 1


def _sha256(path, chunk=1 << 22):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _canonical_sha(value):
    if value is None:
        return None
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         allow_nan=False, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _native_eval(prefix, native_dir):
    identities = prefix.get('original_execution_audit', {}).get('identities', {})
    rows = {}
    for component, identity in identities.items():
        pid = identity.get('pid')
        path = Path(native_dir) / f'dut-timing-{pid}.json'
        if type(pid) is not int or not path.is_file():
            rows[component] = dict(status='unavailable', reason='counter not emitted')
            continue
        document = json.loads(path.read_text())
        if (document.get('schema_version') != 'dut_eval_timing.v1'
                or document.get('pid') != pid):
            raise ValueError('native eval counter/process identity mismatch')
        rows[component] = dict(status='observed', **document)
    return rows


def _runtime_eval_seconds(native_eval):
    seconds = 0.0
    count = 0
    for row in native_eval.values():
        if row.get('status') != 'observed':
            continue
        for scope in ('runtime', 'startup'):
            seconds += row.get(f'{scope}_eval_ns', 0) / 1e9
            count += row.get(f'{scope}_eval_count', 0)
    return seconds, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=None)
    parser.add_argument('--descriptor', default=DEFAULT_DESCRIPTOR)
    parser.add_argument('--records', required=True,
                        help='comma-separated FLOW:hex sequence actually executed')
    parser.add_argument('--replay', action='store_true',
                        help='extension of the workload by the within-invocation fresh replay')
    parser.add_argument('--dut-eval', action='store_true')
    parser.add_argument('--base-root', type=Path, default=ROOT)
    parser.add_argument('--label', default='')
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.cache is not None:
        args.cache = args.cache.resolve()
    base = args.base_root.resolve()
    if args.output.exists():
        raise ValueError('benchmark output must not exist')
    records = [row for row in args.records.split(',') if row]
    if not records or any(':' not in row for row in records):
        raise ValueError('bounded FLOW:hex sequence required')
    sys.path.insert(0, str(base / 'src'))
    sys.path.insert(0, str(base))
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.integration.runtime_benchmark import RuntimeTimings, workload_identity
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
    from myfuzz.runtime.preparation import create_preparation

    args.output.mkdir(parents=True)
    native_dir = args.output / 'native-eval'
    prior = os.environ.get('MYFUZZ_DUT_TIMING_DIR')
    if args.dut_eval:
        native_dir.mkdir()
        os.environ['MYFUZZ_DUT_TIMING_DIR'] = str(native_dir.resolve())
    descriptor = load_descriptor(base / args.descriptor, base_dir=base)
    witness = SequenceWitness(records)
    timing = RuntimeTimings()
    targets = dict(preparation=create_preparation,
                   construct=CompiledF6Runtime.__init__,
                   begin=CompiledF6Runtime.begin,
                   submit=CompiledF6Runtime.submit,
                   finish=CompiledF6Runtime.finish,
                   fresh_replay=CompiledF6Runtime.replay,
                   selector_settle=SequenceWitness.settle)
    started = time.monotonic()
    failure = None
    summary = None
    rss_before_analysis = None
    try:
        with timing.observe(targets):
            summary = run_descriptor(
                descriptor, flow='mixed', mode='original',
                case_root=args.output / 'workload', base_dir=base,
                cache_dir=args.cache, sequence=records,
                record_selector=witness, selected_count=len(records),
                execution_case_capacity=len(records),
                execution_mode=None if args.replay else 'search')
    except BaseException as error:
        failure = dict(type=type(error).__name__, reason=str(error))
        raise
    finally:
        wall = time.monotonic() - started
        rss_before_analysis = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if args.dut_eval:
            if prior is None:
                os.environ.pop('MYFUZZ_DUT_TIMING_DIR', None)
            else:
                os.environ['MYFUZZ_DUT_TIMING_DIR'] = prior
        report = timing.document(wall_seconds=wall)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        report.update(status='failed' if failure else 'complete', failure=failure,
                      summary=summary, requested_records=records,
                      label=args.label, replay_included=bool(args.replay),
                      execution_mode=None if args.replay else 'search',
                      peak_rss_kb=rss_before_analysis,
                      host_cpu_seconds=dict(
                          self=round(usage.ru_utime + usage.ru_stime, 3),
                          children=round(
                              resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime
                              + resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime, 3)),
                      native_eval_timers_enabled=args.dut_eval,
                      descriptor_relative=args.descriptor,
                      base_root=str(base))
        evidence = args.output / 'workload' / 'original'
        for name in ('prefix.json', 'compiled_f6_prefix.json', 'recording.json'):
            path = evidence / name
            if path.is_file():
                report.setdefault('documents', {})[name] = dict(
                    bytes=path.stat().st_size, sha256=_sha256(path))
        replay_path = evidence / 'replay.json'
        if replay_path.is_file():
            report.setdefault('documents', {})['replay.json'] = dict(
                bytes=replay_path.stat().st_size, sha256=_sha256(replay_path))
        prefix_path = evidence / 'prefix.json'
        if prefix_path.is_file():
            prefix = json.loads(prefix_path.read_text(encoding='utf-8'))
            report['workload_identity'] = workload_identity(prefix)
            # Work-only identities: the prefix also pins this checkout's host
            # source digests, which differ across the compared source variants
            # even when every executed case, event and tick is identical.  The
            # hashes below cover only what the DUT and controllers actually did.
            report['work_hashes'] = {
                'actual_events_sha256': _canonical_sha(prefix.get('actual_events')),
                'assertion_material_sha256': _canonical_sha(
                    prefix.get('assertion_material')),
                'flow_records_sha256': _canonical_sha(prefix.get('flow_records')),
                'trace_local_ticks_sha256': _canonical_sha(
                    prefix.get('trace_local_ticks')),
                'trace_events_sha256': _canonical_sha(prefix.get('trace_events')),
            }
            # Cross-process work identity: the raw journal and the certificates
            # embed the real process nonces, so only the normalized prefix is
            # comparable between two invocations (exactly what the runtime's own
            # replay comparison uses).
            from myfuzz.integration.compiled_f6 import (_digest,
                _normalized_f6_prefix)
            report['normalized_prefix_sha256'] = _digest(
                _normalized_f6_prefix(prefix))
            if args.dut_eval:
                native_eval = _native_eval(prefix, args.output / 'native-eval')
                report['native_eval'] = native_eval
                seconds, count = _runtime_eval_seconds(native_eval)
                report['dut_eval_seconds'] = seconds
                report['dut_eval_count'] = count
            allowed = set(records)
            executed = {f"{row['flow']}:{row['raw_hex']}"
                        for row in prefix.get('flow_records', [])}
            report['record_mismatch'] = sorted(executed ^ allowed)
        report['peak_rss_with_analysis_kb'] = (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        (args.output / 'performance.json').write_text(
            json.dumps(report, indent=2, sort_keys=True, default=str) + '\n')
    print(json.dumps(dict(status=report['status'], wall_seconds=wall,
                          replay=bool(args.replay), records=len(records),
                          peak_rss_kb=report['peak_rss_kb'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
