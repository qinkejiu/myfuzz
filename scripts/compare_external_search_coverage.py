#!/usr/bin/env python3
"""Compare independently searched traces measured by the same Verilator coverage method.

The left side is a local-harness measurement and build cache. The right side can
also be another tool's raw Verilator coverage.dat and a DUT source tree. Each
side needs a JSON document: {"tool": str, "version": str, "seed": int,
"budget_seconds": number, "elapsed_seconds": number,
"end_reason": "budget_exhausted"}. Search metadata and external build information
are self-reported; local coverage replay is outside the search budget.
"""
import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))
from scripts.compare_local_harness_coverage import load_run
from myfuzz.local_harness.coverage import parse_verilator_coverage


def _metadata(row):
    if not isinstance(row,dict) or any(not isinstance(row.get(k),str) or not row[k]
                                       for k in ('tool','version','end_reason')):
        raise ValueError('tool, version and end_reason must be nonempty strings')
    for key in ('budget_seconds','elapsed_seconds'):
        value=row.get(key)
        if type(value) not in (int,float) or not math.isfinite(value) or value<=0:
            raise ValueError(key+' must be positive and finite')
    if type(row.get('seed')) is not int or row['seed']<0:
        raise ValueError('seed must be a nonnegative integer')
    return {k:row[k] for k in ('tool','version','seed','budget_seconds','elapsed_seconds','end_reason')}


def compare_search_runs(left,right,left_metadata,right_metadata):
    """Compare points, permitting different independently generated command traces."""
    metadata=[_metadata(left_metadata),_metadata(right_metadata)]
    reasons=[]
    if left.get('coverage_kind')!='verilator-line-block' or right.get('coverage_kind')!='verilator-line-block':
        reasons.append('coverage_method_mismatch')
    if any(not row.get('cache_verified') and row.get('coverage_provenance') != 'external_self_reported_build'
           for row in (left, right)):
        reasons.append('cache_unverified')
    if (not left.get('dut_sources') or left.get('dut_sources')!=right.get('dut_sources')
            or not left.get('dut_source_sha256') or left.get('dut_source_sha256')!=right.get('dut_source_sha256')):
        reasons.append('dut_sources_mismatch')
    lp,rp=left.get('dut_points'),right.get('dut_points')
    if not isinstance(lp,dict) or not lp or not isinstance(rp,dict) or set(lp)!=set(rp):
        reasons.append('point_set_mismatch')
    if metadata[0]['budget_seconds']!=metadata[1]['budget_seconds']:
        reasons.append('search_budget_mismatch')
    if any(m['end_reason']!='budget_exhausted' or m['elapsed_seconds']<m['budget_seconds'] for m in metadata):
        reasons.append('search_budget_not_exhausted')
    coverage=None
    if not reasons:
        lh={p for p,n in lp.items() if n>0};rh={p for p,n in rp.items() if n>0}
        coverage=dict(left_covered=len(lh),right_covered=len(rh),total=len(lp),
            right_minus_left=len(rh)-len(lh),left_only=len(lh-rh),right_only=len(rh-lh))
    return dict(schema_version='external_search_coverage_comparison.v1',
        status='not_comparable' if reasons else 'comparable',reasons=reasons,coverage=coverage,
        search_budget_evidence='self_reported',
        runs=[dict(**m,commands=r['commands']['count'],local_ticks=r['commands']['local_ticks'],
                   coverage_provenance=r.get('coverage_provenance','local_cache_verified'),
                   verilator_version=r.get('verilator_version'),
                   build_description=r.get('build_description'),
                   coverage_data_sha256=r.get('coverage_data_sha256'))
              for m,r in zip(metadata,(left,right))],
        limitations=['Budget, elapsed time and tool identities are self-reported.',
            'External Verilator version, build flags and coverage collection scope are self-reported.',
            'Local coverage is an offline Verilator line/block replay, including startup/reset.',
            'Local coverage replay cost is outside the search budget.',
            'A single pair does not establish statistical significance or tool superiority.'])


def _load(path,cache,max_commands):
    row=load_run(path,cache=cache,max_commands=max_commands)
    inputs=path/'inputs'
    row['dut_source_sha256']={name:sha256((inputs/name).read_bytes()).hexdigest()
                                for name in row['dut_sources']}
    return row


def load_external_verilator(data, *, source_root, dut_sources, verilator_version, build_description):
    """Decode external raw points against the local run's declared DUT sources.

    Source bytes and the complete point set are compared by the caller. Build
    flags and version are reported by the external tool, not verified here.
    """
    if not verilator_version or not build_description:
        raise ValueError('external-verilator-version-and-build-required')
    root=Path(source_root).resolve()
    sources={name:sha256((root/name).read_bytes()).hexdigest() for name in dut_sources}
    selected=set(dut_sources)
    points={}
    raw=Path(data).read_bytes()
    for point in parse_verilator_coverage(raw.decode('utf-8')):
        fields=dict(point['fields'])
        path=Path(fields['f'])
        path=(path if path.is_absolute() else root/path).resolve()
        try:
            relative=path.relative_to(root).as_posix()
        except ValueError:
            continue
        if relative not in selected:
            continue
        fields['f']=relative
        identity=json.dumps(fields,sort_keys=True,separators=(',',':'))
        if identity in points:
            raise ValueError('duplicate-normalized-point')
        points[identity]=point['count']
    return dict(coverage_kind='verilator-line-block',cache_verified=False,
        coverage_provenance='external_self_reported_build',dut_sources=list(dut_sources),
        dut_source_sha256=sources,dut_points=points,commands=dict(count=None,local_ticks=None),
        verilator_version=verilator_version,build_description=build_description,
        coverage_data_sha256=sha256(raw).hexdigest())


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--left',type=Path,required=True,help='saved local coverage directory')
    parser.add_argument('--left-cache',type=Path,required=True)
    right=parser.add_mutually_exclusive_group(required=True)
    right.add_argument('--right',type=Path,help='saved local coverage directory')
    right.add_argument('--right-coverage-file',type=Path,help='external raw Verilator coverage.dat')
    parser.add_argument('--right-cache',type=Path)
    parser.add_argument('--right-source-root',type=Path)
    parser.add_argument('--right-verilator-version')
    parser.add_argument('--right-build-description')
    for side in ('left','right'):
        parser.add_argument('--'+side+'-search',type=Path,required=True,help='search metadata JSON')
    parser.add_argument('--max-commands',type=int,default=2048)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        left=_load(args.left,args.left_cache,args.max_commands)
        if args.right:
            if args.right_cache is None:raise ValueError('right-cache-required')
            right=_load(args.right,args.right_cache,args.max_commands)
        else:
            if args.right_source_root is None:raise ValueError('right-source-root-required')
            right=load_external_verilator(args.right_coverage_file,source_root=args.right_source_root,
                dut_sources=left['dut_sources'],verilator_version=args.right_verilator_version,
                build_description=args.right_build_description)
        result=compare_search_runs(left,right,json.loads(args.left_search.read_text()),json.loads(args.right_search.read_text()))
    except (ValueError,TypeError,KeyError,OSError,RuntimeError) as error:
        print(json.dumps(dict(status='unavailable',reason=str(error))))
        return 1
    rendered=json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n'
    if args.output:args.output.write_text(rendered)
    print(rendered,end='')
    return 0 if result['status']=='comparable' else 2


if __name__=='__main__':
    raise SystemExit(main())
