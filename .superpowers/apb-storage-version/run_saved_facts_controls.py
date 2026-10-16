"""Explicit software ABI/tool fixtures; rejects frontend/compiler/native launch."""
import json,os,subprocess,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT))
os.environ.pop('MYFUZZ_GPIO_VERSION_REAL',None)
from myfuzz.composition import component_profile as profiles
from myfuzz.composition.source_crawler import ElaboratedPortFact
with tarfile.open(ROOT/'docs/reports/evidence/compiled-f4-ibex-current-20261017/evidence.tar.gz') as archive:
    rows={}
    for name in ('processor','peripheral'):
        doc=json.load(archive.extractfile('outputs/ibex/generated/'+name+'/artifact.json'))
        rows[doc['source_verification']['top_module'] if 'top_module' in doc['source_verification'] else ('ibex_top' if name=='processor' else 'apb_gpio')]=sorted({(r['port'],r['direction'],r['port_width']) for r in doc['plan']['ports']})

def saved_facts(profile,**kwargs):
    ports=rows.get(profile.source.top_module)
    if ports is None:raise AssertionError('undeclared software ABI fixture '+profile.source.top_module)
    return profiles.PhysicalFacts(top_module=profile.source.top_module,ports=tuple(ElaboratedPortFact(name=n,direction=d,width=w,signed=False,source_file=profile.source.files[0],line=1,column=1) for n,d,w in ports),content_hash='software_saved_ports_not_frontend',revision=profile.source.revision,files=profile.source.files,include_roots=profile.source.include_roots)
profiles.elaborate_profile=saved_facts
# Keep actual Popen/wire mechanics but seal an explicitly guarded Python method
# before session import; this is never an eligible native build issuance.
original_init=subprocess.Popen.__init__
commands=[]
def guarded_init(self,argv,*args,**kwargs):
    command=list(argv) if not isinstance(argv,str) else [argv]
    executable=Path(command[0])
    if executable.name!='git' and executable.name not in ('wire-worker.py','mechanical-apb-peer.py'):
        raise AssertionError('frontend/compiler/model/tool command forbidden '+str(command))
    commands.append(command)
    original_init(self,argv,*args,**kwargs)
subprocess.Popen.__init__=guarded_init
from myfuzz.local_harness import plan,runtime_renderer,build
plan.elaborate_profile=saved_facts;runtime_renderer.elaborate_profile=saved_facts
build._toolchain=lambda:dict(verilator=dict(path='software_verilator'),cxx=dict(path='software_cxx'),ar=dict(path='software_ar'))
import pytest
selectors=sys.argv[1:] or ['tests/local_harness/test_native_reset_observation.py','tests/local_harness/test_native_reset_observation_boundaries.py','tests/local_harness/test_gpio_register_version.py']
status=int(pytest.main(['-q',*selectors]))
receipt=Path(os.environ.get('MYFUZZ_PURE_RECEIPT',str(ROOT/'.superpowers/apb-storage-version/pure-final-process-receipt.json')))
with receipt.open('x') as out:json.dump(dict(pid=os.getpid(),returncode=status,selectors=selectors,subprocess_commands=commands,software_fixture_only=True),out,indent=2)
raise SystemExit(status)
