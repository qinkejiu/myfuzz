"""Production entry point for finite dependency searches."""
import argparse
from hashlib import sha256
import json
import time
from pathlib import Path
from .config import identity, load_scenario

ROOT = Path(__file__).resolve().parents[3]

def source_identity():
    paths=sorted((ROOT/'src/myfuzz/search').glob('*.py'))
    paths += [ROOT/'scripts/run_dependency_search.py'] + sorted((ROOT/'configs/search').glob('*.json'))
    return identity({str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in paths})

def parser():
    p=argparse.ArgumentParser(description='Finite dependency search. Without --scenario the default scope is the Ibex dual GPIO live search only.')
    p.add_argument('--scenario', type=Path, help='versioned JSON scenario (paths inside it are project-relative)')
    p.add_argument('--preflight','--plan-only',dest='preflight',action='store_true', help='inspect configuration and capabilities without native build or execution')
    p.add_argument('--mode',choices=('original','fresh'))
    p.add_argument('--execution-mode', choices=('develop','search','acceptance'), default='search',
                   help='develop: one-case smoke; search: boundary validation without unconditional replay; acceptance: full replay')
    p.add_argument('--elaboration-mode', choices=('direct','supervised'),
                   help='pin the GPIO frontend mode used by original/fresh')
    p.add_argument('--policy',choices=('state','uniform','legacy'),default='state')
    p.add_argument('--cases',type=int)
    p.add_argument('--seconds',type=float)
    p.add_argument('--seed',type=int)
    p.add_argument('--output',type=Path)
    p.add_argument('--cache',type=Path)
    p.add_argument('--original',type=Path)
    p.add_argument('--record-local-commands',action='store_true')
    p.add_argument('--ablation',choices=('none','frontier','state','credit','cost'),default='none')
    return p

def main(argv=None):
    started = time.monotonic()
    p=parser(); args=p.parse_args(argv)
    try:
        config=load_scenario(args.scenario, ROOT) if args.scenario else {'schema_version':'dependency_search_scenario.v1','name':'ibex-dual-gpio-default','backend':'gpio','goal':{'id':'gpio:configuration-consumption'}}
        provenance={'scenario_identity':identity(config),'scenario_configuration':config,'source_sha':source_identity(),'goal_semantics':'backend-defined objective; goal.id is a human label only'}
        provenance['execution_mode'] = args.execution_mode
        if args.elaboration_mode is not None and config['backend'] != 'gpio':
            p.error('--elaboration-mode is supported by the GPIO backend')
        if args.preflight:
            if config['backend']=='gpio':
                detail={'backend':'gpio','capabilities':{'live_state_provider':True,'native_started':False},'shared_catalog_identity':None,'catalog_identity_scope':'pending-runtime-binding','catalog_materialized':False}
            else:
                from .descriptor_search import preflight_scenario
                detail=preflight_scenario(config, ROOT)
            print(json.dumps({**detail,**provenance},sort_keys=True)); return 0
        if args.execution_mode == 'develop':
            if args.cases is None:
                args.cases = 1
            if args.cases != 1:
                p.error('develop mode requires exactly one smoke case')
        missing=[key for key in (('mode','cases','seconds','seed','output','cache') if config['backend']=='gpio' else ('mode','cases','seed','output','cache')) if getattr(args,key) is None]
        if missing: p.error('required for execution: '+', '.join('--'+key for key in missing))
        if args.cases < 1 or (args.seconds is not None and not 0 < args.seconds < float('inf')): p.error('cases and seconds must be positive and finite')
        campaign_output=args.output
        provenance_output=campaign_output/args.mode if args.scenario else campaign_output
        if args.scenario:
            expected_original=campaign_output/'original'
            if args.original is not None and args.original.resolve()!=expected_original.resolve():
                p.error('--original must equal OUTPUT/original for scenario campaigns')
            if args.mode=='fresh':
                reference=json.loads((expected_original/'search-configuration.json').read_text())
                if any(reference.get(k)!=provenance[k] for k in ('scenario_identity','source_sha')):
                    p.error('fresh scenario or source identity mismatch')
        if config['backend']=='gpio':
            if args.scenario:
                args.output=provenance_output
                if args.mode=='fresh': args.original=campaign_output/'original'
            from .gpio_search import main as gpio_main
            forwarded=[]
            for key in ('mode','execution_mode','elaboration_mode','policy','cases','seconds','seed','output','cache','original','ablation'):
                value=getattr(args,key)
                if value is not None: forwarded += ['--'+key.replace('_','-'),str(value)]
            if args.record_local_commands: forwarded.append('--record-local-commands')
            from contextlib import redirect_stdout
            from io import StringIO
            with redirect_stdout(StringIO()):
                exit_code = gpio_main(forwarded)
            if exit_code:
                raise ValueError('GPIO execution failed')
            summary = provenance_output / 'search-summary.json'
            result = json.loads(summary.read_text())
        else:
            if args.ablation != 'none':
                p.error('--ablation is supported by the default GPIO backend only')
            if args.original is not None and args.original.resolve() != (args.output/'original').resolve():
                p.error('descriptor fresh mode requires --original to equal OUTPUT/original')
            from .descriptor_search import execute
            from myfuzz.local_harness.build import host_source_discovery_scope
            with host_source_discovery_scope(reuse_nested=True):
                result=execute(descriptor_path=ROOT/config['descriptor'],base_dir=ROOT,mode=args.mode,policy=args.policy,cases=args.cases,seconds=args.seconds,seed=args.seed,output=args.output,cache=args.cache,flow=config['flow'],rounds=config.get('rounds'),records=config['records'],record_local_commands=args.record_local_commands,execution_mode=args.execution_mode)
        provenance_output.mkdir(parents=True,exist_ok=True)
        (provenance_output/'search-configuration.json').write_text(json.dumps(provenance,indent=2)+'\n')
        if isinstance(result, dict):
            result['command_wall_seconds'] = time.monotonic() - started
            (provenance_output/'search-summary.json').write_text(json.dumps(result,indent=2)+'\n')
        if isinstance(result,dict): print(json.dumps(result,default=str))
        return result if isinstance(result,int) else 0
    except (ValueError,FileNotFoundError) as exc:
        p.error(str(exc))

if __name__=='__main__':
    raise SystemExit(main())
