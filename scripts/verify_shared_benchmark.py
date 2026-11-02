#!/usr/bin/env python3
"""Check full same-source execution equivalence before comparing wall times."""
import argparse
import json
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--varying-axis',choices=('fetch_scan','topology_validation'),default='fetch_scan')
    args=parser.parse_args()
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
    from myfuzz.integration.runtime_benchmark_equivalence import compare_benchmarks
    def read(root,name):return json.loads((root/name).read_text())
    report=compare_benchmarks(read(args.baseline,'performance.json'),read(args.candidate,'performance.json'),
        read(args.baseline,'workload/original/prefix.json'),read(args.candidate,'workload/original/prefix.json'),
        varying_axis=args.varying_axis)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'equivalent':report['equivalent'],'report':str(args.output)}))
    return 0 if report['equivalent'] else 1


if __name__=='__main__':raise SystemExit(main())
