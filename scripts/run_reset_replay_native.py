#!/usr/bin/env python3
"""Run a completed reset shared-slot campaign and its fresh replay."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

from scripts.run_reset_recovery_native import (DEFAULT_CACHE, DEFAULT_DESCRIPTOR,
    ResetRecoverySelector, ResetProbeComplete, save)


class ContinuingResetSelector(ResetRecoverySelector):
    """Continue the campaign only after the real reset diagnostics verify."""
    def _reset_probe(self):
        try:
            super()._reset_probe()
        except ResetProbeComplete:
            if self.outcome != 'verified':
                raise ValueError('reset-recovery-not-verified: ' + str(self.outcome_detail))
            self.reset_report['terminal_probe'] = False
            self.reset_report['normal_campaign_completion'] = False
            self._export()
            save(self.recovery_dir / 'result.json', self.result())
            return
        raise ValueError('reset-recovery-probe-not-completed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=ROOT / DEFAULT_CACHE)
    parser.add_argument('--descriptor', type=Path, default=ROOT / DEFAULT_DESCRIPTOR)
    parser.add_argument('--rounds', type=int, default=1024)
    parser.add_argument('--reset-policy', choices=('warm_all','cold_all'), default='warm_all')
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    if args.rounds < 1:
        parser.error('rounds must be positive')
    from myfuzz.runtime.generic_campaign import load_descriptor, run_descriptor
    selector = ContinuingResetSelector('reset-ram',
        output=args.output / 'original' / 'consumption-diagnostic.json',
        reset_policy=args.reset_policy, recovery_dir=args.output)
    try:
        descriptor = load_descriptor(args.descriptor, base_dir=ROOT)
        summary = run_descriptor(descriptor, flow='mixed', mode='original',
            case_root=args.output, base_dir=ROOT, cache_dir=args.cache,
            sequence=list(selector.plan), record_selector=selector,
            selected_count=len(selector.plan), execution_case_capacity=8,
            rounds=args.rounds, execution_mode='acceptance')
        if selector.outcome != 'verified' or summary.get('replay_matches') is not True:
            raise ValueError('reset-replay-not-verified')
        summary['reset_policy'] = args.reset_policy
        summary['selected_case_count'] = summary['case_count']
        summary['executed_flow_case_count'] = sum(summary['flow_case_counts'].values())
        save(args.output / 'original' / 'summary.json', summary)
    except Exception as error:
        print(json.dumps({'status':'failed', 'error_type':type(error).__name__,
                          'error':str(error), 'output':str(args.output)}))
        return 1
    print(json.dumps({'status':'verified', 'output':str(args.output),
                      'reset_policy':args.reset_policy,
                      'selected_case_count':summary['selected_case_count'],
                      'executed_flow_case_count':summary['executed_flow_case_count'],
                      'replay_matches':True}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
