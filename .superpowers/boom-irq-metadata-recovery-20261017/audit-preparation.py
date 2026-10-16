"""Read-only source/import/origin audit. Does not call recovery or a model."""
import configparser,hashlib,importlib,json,os
from pathlib import Path
from myfuzz.local_harness.boom_irq_recovery import ARCHIVES,SCOPES,_tree_files,load_origin,_tool_identity
BASE=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017')
SOURCE=BASE/'source'
OLD=Path('/root/fanzehui/boom-irq-verification-20261017')
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
expected=json.loads((BASE/'source-destination.json').read_text())['files']
actual={str(file.relative_to(SOURCE)):digest(file) for scope in SCOPES for file in _tree_files(SOURCE/scope)}
assert actual==expected,'remote source mismatch'
assert all((SOURCE/name).stat().st_nlink==1 for name in expected)
shared=[name for name in expected if (OLD/'project'/name).is_file() and os.path.samestat((SOURCE/name).stat(),(OLD/'project'/name).stat())]
assert not shared,shared
pins=json.loads((BASE/'owned-source-pins.json').read_text())
for name,value in pins.items():assert actual[name]==value,name
assert digest(BASE/'source.tar.gz')==json.loads((BASE/'local-preparation.json').read_text())['source_archive_sha256']
git=SOURCE/'third_party/soc-pulp-apb-gpio/.git'
assert git.is_dir() and not git.is_symlink()
assert not (git/'commondir').exists() and not (git/'objects/info/alternates').exists()
config=configparser.ConfigParser();config.read(git/'config')
assert not config.has_option('core','worktree'),'external git worktree not supported'
imports={}
for name in ('myfuzz.local_harness.boom_irq_recovery','myfuzz.local_harness.boom_irq_generation',
             'myfuzz.local_harness.boom_irq_cpu_session','myfuzz.local_harness.boom_irq_scenario_session',
             'myfuzz.scenario.boom_gpio_irq_runner'):
    module=importlib.import_module(name);path=Path(module.__file__).resolve();assert path.is_relative_to(SOURCE)
    imports[name]={'path':str(path.relative_to(SOURCE)),'sha256':digest(path)}
from myfuzz.local_harness.build import _discover_host_sources
host=_discover_host_sources()
assert 'scripts/verify_soc_sources.py' in host
assert all(name in expected and hashlib.sha256(data).hexdigest()==expected[name] for name,data in host.items())
files,origin=load_origin(BASE/'archives')
original={name.removeprefix('artifact/'):digest(OLD/name) for name in files if name.startswith('artifact/')}
wanted={name.removeprefix('artifact/'):hashlib.sha256(data).hexdigest() for name,data in files.items() if name.startswith('artifact/')}
assert original==wanted,'original artifact changed'
_tool_identity(origin['tool_identity'])
for name in ('project-finalized','artifact-finalized'):assert not (BASE/name).exists()
assert not (BASE/'state/PID').exists()
report={'status':'prepared_not_executed','source_files':len(actual),'owned_pins_checked':len(pins),
 'source_matches_manifest':True,'shared_old_source_inodes':shared,'all_source_links_one':True,
 'pulp_git_is_directory':True,'pulp_git_files':sum(name.startswith('third_party/soc-pulp-apb-gpio/.git/') for name in actual),
 'pulp_git_external_references_absent':True,'host_discovery_files':len(host),'imports':imports,
 'original_artifact_files_pinned':len(original),'original_artifact_unchanged':True,
 'tool_hashes_match_actual_build':True,'future_destinations_absent':True,'pid_absent':True,
 'recovery_executed':False,'model_executed':False,'clean_checkout_claim':False,'source_authority':False}
(BASE/'state/preparation.json').write_text(json.dumps(report,indent=2)+'\n')
(BASE/'state/original-artifact-preparation-pins.json').write_text(json.dumps(original,indent=2)+'\n')
(BASE/'state/tool-preparation.json').write_text(json.dumps(origin['tool_identity'],indent=2)+'\n')
print(json.dumps(report,indent=2))
