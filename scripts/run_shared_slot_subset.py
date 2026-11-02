#!/usr/bin/env python3
"""Run an explicit typed subset of the shared-slot flows in one real session.

This is the same public descriptor runtime as ``run_shared_all_flows.py``: the
only difference is the record list, so a subset never gets a private executor or
a weaker admission.  A subset run proves only the flows it actually executed;
it never stands in for the canonical six-flow acceptance.
"""
import argparse
from contextlib import nullcontext
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from scripts.run_shared_f6_slots import OnlineWitnessSequence, require_f5_irq_witness


class SubsetWitness(OnlineWitnessSequence):
    def __init__(self, records):
        super().__init__()
        self.records = tuple(records)

    def choose(self):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows = flow_records(self.runtime)
        if len(rows) != self.done or any(row['status'] != 'passed' for row in rows):
            raise ValueError('online choice requires prior actual completion')
        if self.done >= len(self.records):
            raise ValueError('online sequence complete')
        return self.records[self.done]

    def settle(self, record):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows = flow_records(self.runtime)
        if rows:
            require_f5_irq_witness(rows[-1])
        super().settle(record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--descriptor', type=Path, required=True)
    parser.add_argument('--mode', choices=('original', 'fresh'), default='original')
    parser.add_argument('--records', required=True,
        help='comma-separated FLOW:hex records, in execution order')
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--record-local-commands', action='store_true',
        help='save bounded per-component recorded commands (local_commands.json, '
             'fresh_local_commands.json) for offline coverage replay')
    args = parser.parse_args()
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
    records = [row for row in args.records.split(',') if row]
    if not records or any(':' not in row for row in records):
        raise ValueError('explicit FLOW:hex records required')
    for record in records:
        flow, raw = record.split(':', 1)
        if flow not in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6'):
            raise ValueError('unsupported flow: ' + flow)
        bytes.fromhex(raw)
    descriptor = load_descriptor(args.descriptor, base_dir=ROOT)
    recording = (record_local_commands() if args.record_local_commands
                 else nullcontext(None))
    with recording as command_trace:
        summary = run_descriptor(descriptor, flow='mixed', mode=args.mode,
            case_root=args.output, base_dir=ROOT, cache_dir=args.cache,
            sequence=records, record_selector=SubsetWitness(records),
            selected_count=len(records), execution_case_capacity=len(records),
            command_trace=command_trace)
    counts = {flow: summary['flow_case_counts'].get(flow, 0)
              for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    print({'case_count': summary['case_count'], 'flow_case_counts': counts,
           'replay_matches': summary['replay_matches'], 'evidence_dir': summary['evidence_dir']})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
