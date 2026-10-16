#!/usr/bin/env python3
"""Run explicitly declared experimental compiled dataflow records and fresh replay."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from myfuzz.integration.compiled_execution_files import run_compiled_execution_files


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose',type=Path,required=True)
    parser.add_argument('--ip-capability',type=Path,action='append',required=True)
    parser.add_argument('--supplement',type=Path,required=True)
    parser.add_argument('--records',type=Path,required=True,
                        help='JSON array of explicit 16-digit hex records (eight bytes each)')
    parser.add_argument('--executor',required=True,help='explicit executor selection; unsupported names refuse')
    parser.add_argument('--output',type=Path,required=True,help='must be a new directory')
    parser.add_argument('--cache-dir',type=Path,required=True)
    parser.add_argument('--heavy-lock',type=Path,
                        help='canonical shared project lock; default repository .superpowers/heavy-worker.lock')
    parser.add_argument('--run-id',default='compiled-dataflow')
    parser.add_argument('--rounds-per-case',type=int,default=128)
    parser.add_argument('--max-cases',type=int,default=64)
    parser.add_argument('--replays',type=int,default=1)
    args=parser.parse_args(argv)
    try:
        result=run_compiled_execution_files(base_dir=ROOT,compose_path=args.compose,
            capability_paths=args.ip_capability,supplement_path=args.supplement,
            records_path=args.records,output_dir=args.output,cache_dir=args.cache_dir,
            executor=args.executor,run_id=args.run_id,rounds_per_case=args.rounds_per_case,
            max_cases=args.max_cases,replay_count=args.replays,heavy_lock=args.heavy_lock)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (ValueError,OSError,RuntimeError,TimeoutError,KeyError,TypeError) as error:
        print(f'compiled-dataflow-refused: {error}',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
