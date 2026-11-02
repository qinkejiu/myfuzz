#!/usr/bin/env python3
"""Exercise the public descriptor with one online storage/DMA choice at a time."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))


def require_f5_irq_witness(row):
    if row.get('flow') != 'F5':
        return
    certificate = row.get('certificate', {})
    if certificate.get('schema_version') == 'compiled_shared_declared_F5_slot_case.v1':
        observed = certificate.get('observation', {})
        valid = (certificate.get('status') == 'certified'
            and observed.get('status') == 'verified'
            and observed.get('irq_consumption') == 'verified'
            and observed.get('transport', {}).get('status') == 'observed'
            and observed.get('transport', {}).get('attribution') == 'unique'
            and observed.get('consumption', {}).get('status') == 'verified'
            and observed.get('consumption', {}).get('irq_consumption') == 'verified')
    else:
        valid = certificate.get('irq_isr', {}).get('status') == 'verified'
    if not valid:
        raise ValueError('actual native IRQ ISR chain must be verified')


class OnlineWitnessSequence:
    def attach_runtime(self, runtime):
        self.runtime = runtime
        self.done = 0

    def choose(self):
        from myfuzz.integration.shared_f6_slots import flow_records
        records = flow_records(self.runtime)
        if len(records) != self.done or any(row['status'] != 'passed' for row in records):
            raise ValueError('online choice requires prior actual completion')
        if not records:
            return 'F4:55000000'
        if records[-1]['flow'] == 'F4':
            expected = 85 if self.done == 1 else 170
            if records[-1]['certificate']['value'] != expected:
                raise ValueError('actual storage value differs from online prerequisite')
            return 'F6:0110c00008000000'
        if self.done == 2:
            return 'F4:aa000000'
        raise ValueError('online sequence complete')

    def settle(self, record):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows = flow_records(self.runtime)
        if len(rows) != self.done+1 or rows[-1]['flow']+':'+rows[-1]['raw_hex'] != record:
            raise ValueError('online selected source was not actually consumed')
        self.done += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--native', action='store_true', required=True)
    args = parser.parse_args()
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
    descriptor = load_descriptor(ROOT/'configs/scenarios/compiled-f6-ibex-wbdmac-storage/generic_shared_slots.json', base_dir=ROOT)
    summary = run_descriptor(descriptor, flow='mixed', mode='original',
        case_root=args.output, base_dir=ROOT, cache_dir=args.cache,
        sequence=['F4:55000000','F4:aa000000','F6:0110c00008000000'],
        record_selector=OnlineWitnessSequence(), selected_count=4, execution_case_capacity=4)
    if summary['case_count'] != 4 or summary['f6_case_count'] != 2 or summary['replay_matches'] is not True:
        raise RuntimeError('complete mixed original/fresh evidence required')
    print(summary)


if __name__ == '__main__':
    main()
