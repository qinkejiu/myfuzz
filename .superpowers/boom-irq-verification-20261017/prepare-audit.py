import hashlib,importlib,json,os
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-verification-20261017')
root=base/'project'; old=Path('/root/fanzehui/boom-verification-20261017/project')
owned=json.loads((root/'.superpowers/boom-irq-verification-20261017/source-pins.json').read_text())
for name,expected in owned.items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected,name
scopes=('src','configs','tests','third_party/soc-pulp-apb-gpio')
files={}; shared=[]
for scope in scopes:
    for file in sorted((root/scope).rglob('*')):
        if not file.is_file() or '__pycache__' in file.parts or file.suffix=='.pyc': continue
        relative=str(file.relative_to(root))
        files[relative]=hashlib.sha256(file.read_bytes()).hexdigest()
        previous=old/relative
        if previous.exists() and os.path.samestat(file.stat(),previous.stat()): shared.append(relative)
assert not shared,shared
imports={}
for name in ('boom_irq_contract','boom_irq_generation','boom_irq_cpu_session','boom_irq_scenario_session'):
    module=importlib.import_module('myfuzz.local_harness.'+name)
    path=Path(module.__file__).resolve()
    assert path.is_relative_to(root),str(path)
    imports[module.__name__]={'path':str(path.relative_to(root)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
module=importlib.import_module('myfuzz.scenario.boom_gpio_irq_runner')
path=Path(module.__file__).resolve()
assert path.is_relative_to(root)
imports[module.__name__]={'path':str(path.relative_to(root)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
# Generate static instruction bytes only: no session/factory/build invocation.
program=module.boom_gpio_irq_program()
assert len(program)==1280
assert (base/'artifact').is_dir() and not any((base/'artifact').iterdir())
manifest={'schema_version':'boom_irq_prepared_source_snapshot.v1','scope':scopes,'files':files}
(base/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
report={'stage':'prepared_not_launched','owned_pins_checked':len(owned),'source_files':len(files),
        'shared_source_file_inodes':shared,'imports':imports,'artifact_empty':True,
        'program_sha256':hashlib.sha256(program).hexdigest(),
        'baseline_snapshot':str(old),'copy_method':'cp -a, independent destination; owned frozen overlay only',
        'no_native_build_elaboration_probe_execution':True}
(base/'attempt2/state/preparation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
