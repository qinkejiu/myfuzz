#!/usr/bin/env python3
"""Run six flows online in one real CPU/RAM/DMA/GPIO session and replay it."""
import argparse
from contextlib import nullcontext
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from scripts.run_shared_f6_slots import OnlineWitnessSequence, require_f5_irq_witness

RECORDS=('F3:55000000','F1:03200000','F4:0001000000','F5:0000000100000000',
         'F2:08100040','F6:0110c00008000000','F5:0000000000000000','F6:0110c00008000000')


class AllFlowWitness(OnlineWitnessSequence):
    def choose(self):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows=flow_records(self.runtime)
        if len(rows)!=self.done or any(row['status']!='passed' for row in rows):
            raise ValueError('online choice requires prior actual completion')
        if self.done>=len(RECORDS):raise ValueError('online sequence complete')
        return RECORDS[self.done]

    def settle(self,record):
        from myfuzz.integration.shared_f6_slots import flow_records
        rows=flow_records(self.runtime)
        if rows:
            require_f5_irq_witness(rows[-1])
        super().settle(record)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path)
    parser.add_argument('--descriptor',type=Path,default=ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json')
    parser.add_argument('--mode',choices=('original','fresh'),default='original')
    parser.add_argument('--records',default=','.join(RECORDS),
        help='comma-separated FLOW:hex sequence; defaults to the canonical eight')
    parser.add_argument('--native',action='store_true',required=True)
    parser.add_argument('--record-local-commands',action='store_true',
        help='save bounded per-component recorded commands (local_commands.json, '
             'fresh_local_commands.json) for offline coverage replay')
    args=parser.parse_args()
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.runtime.generic_campaign import load_descriptor,run_descriptor
    descriptor=load_descriptor(args.descriptor,base_dir=ROOT)
    records=[row for row in args.records.split(',') if row]
    if list(records)!=list(RECORDS):
        # Only the canonical eight-record witness is accepted: an edited
        # sequence would change the workload being certified.
        raise ValueError('shared-all-flows-canonical-records-required')
    recording=(record_local_commands() if args.record_local_commands
               else nullcontext(None))
    with recording as command_trace:
        summary=run_descriptor(descriptor,flow='mixed',mode=args.mode,case_root=args.output,
            base_dir=ROOT,cache_dir=args.cache,sequence=list(RECORDS),record_selector=AllFlowWitness(),
            selected_count=len(RECORDS),execution_case_capacity=len(RECORDS),
            command_trace=command_trace)
    if (summary['case_count']!=len(RECORDS) or summary['f6_case_count']!=2
            or set(summary['flow_case_counts'])!={'F1','F2','F3','F4','F5','F6'}
            or any(count<1 for count in summary['flow_case_counts'].values())
            or summary['replay_matches'] is not True):
        raise RuntimeError('all six actual flows and full fresh replay required')
    print(summary)


if __name__=='__main__':main()
