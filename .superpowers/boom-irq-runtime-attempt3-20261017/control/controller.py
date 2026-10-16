"""One authorized BOOM IRQ runtime operation; import/default are source-only."""
import hashlib,importlib,json,os,shutil,subprocess,sys,traceback
from pathlib import Path
BASE=Path('/root/fanzehui/boom-irq-runtime-attempt3-20261017')
PROJECT=BASE/'project'
OUTPUT=BASE/'gate-output'
CACHE=BASE/'gpio-cache'
ORIGINAL_SOURCE=Path('/root/fanzehui/boom-irq-factory-fix-20261017/project-finalized')
ARTIFACT=Path('/root/fanzehui/boom-irq-factory-fix-20261017/artifact-finalized')
HEAVY_LOCK=Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock')
MODULES=('myfuzz.scenario.boom_gpio_irq_verification','myfuzz.scenario.boom_gpio_irq_runner',
 'myfuzz.local_harness.boom_irq_scenario_session','myfuzz.local_harness.boom_irq_cpu_session',
 'myfuzz.local_harness.boom_irq_generation','myfuzz.local_harness.boom_irq_recovery',
 'myfuzz.local_harness.boom_irq_contract','myfuzz.local_harness.gpio_session',
 'myfuzz.local_harness.build','myfuzz.scenario.runner','myfuzz.scenario.router',
 'myfuzz.scenario.ledger','myfuzz.scenario.irq','myfuzz.scenario.protocol_io')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(name,value):
    if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('unsafe receipt path')
    with check_path(BASE/'state'/name).open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')

def stage(value):
    with check_path(BASE/'state/stage').open('w') as stream:stream.write(value)

def fresh_text(path,value):
    with check_path(path).open('x') as stream:stream.write(value)
def check_path(path):
    path=Path(path).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('symlink path')
    if path.exists() and path.is_file() and path.stat().st_nlink!=1:raise ValueError('shared file inode')
    return path.resolve()
def inventory(root):
    root=check_path(root);result={}
    for path in sorted(root.rglob('*')):
        check_path(path)
        if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':
            result[path.relative_to(root).as_posix()]=digest(path)
    return result


def copy_independent(source,target):
    source=check_path(source);target=check_path(target)
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):raise ValueError('copy destination exists/overlaps')
    before=inventory(source);target.mkdir(parents=True,exist_ok=False)
    for name in before:
        original=source/name;copied=target/name
        copied.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(original,copied)
        if (copied.stat().st_nlink!=1 or original.stat().st_nlink!=1
            or os.path.samestat(original.stat(),copied.stat())):raise ValueError('shared copy inode')
    if inventory(source)!=before or inventory(target)!=before:raise ValueError('independent copy bytes differ')
    return before


def tool_inventory(receipt):
    result={'which_verilator':shutil.which('verilator'),'files':{}}
    for name,info in receipt['tools'].items():
        path=Path(info['path'])
        if not path.resolve().is_relative_to('/root/fanzehui'):raise ValueError('tool outside allowed root')
        row=dict(path=str(path),resolved_path=str(path.resolve()),sha256=digest(path))
        if row!={k:info[k] for k in ('path','resolved_path','sha256')}:raise ValueError('actual tool identity differs')
        result['files'][name]=row
    if result['which_verilator']!=receipt['tools']['verilator']['path']:raise ValueError('tool selection differs')
    return result


def claim():
    state=BASE/'state'
    conflicts=[state/name for name in ('PID','launcher-PID','worker.exit','operation.claim','native-PID','native.exit','stage','imports.json','failure.json')]+[OUTPUT,CACHE]
    if any(p.exists() or p.is_symlink() for p in conflicts):raise ValueError('runtime operation already claimed or used; no state changed')
    check_path(state)
    with check_path(state/'operation.claim').open('x') as stream:stream.write(json.dumps(dict(pid=os.getpid(),argv=sys.argv))+'\n')


def checked_imports(expected):
    result={}
    for name in MODULES:
        module=importlib.import_module(name);path=Path(module.__file__).resolve()
        if not path.is_relative_to(PROJECT):raise ValueError('import origin outside runtime snapshot')
        relative=path.relative_to(PROJECT).as_posix()
        if digest(path)!=expected.get(relative):raise ValueError('import source hash differs')
        result[name]=dict(path=relative,sha256=digest(path))
    save('imports.json',result)
    return importlib.import_module(MODULES[0])


def audit_inputs(ready):
    expected=json.loads((BASE/'project-files.json').read_text())['files']
    original=json.loads((BASE/'original-source-files.json').read_text())['files']
    artifact=json.loads((BASE/'original-artifact-files.json').read_text())['files']
    actual=inventory(PROJECT);old=inventory(ORIGINAL_SOURCE);built=inventory(ARTIFACT)
    if actual!=expected or old!=original or built!=artifact:raise ValueError('source/artifact audit differs')
    if digest(ARTIFACT/'irq-session-artifact.json')!=ready['artifact_sha256']:raise ValueError('manifest pin differs')
    shared=[name for name in original if os.path.samestat((PROJECT/name).stat(),(ORIGINAL_SOURCE/name).stat())]
    if shared or any((PROJECT/name).stat().st_nlink!=1 for name in actual) or any((ORIGINAL_SOURCE/name).stat().st_nlink!=1 for name in original) or any((ARTIFACT/name).stat().st_nlink!=1 for name in artifact):raise ValueError('source copy inode drift')
    return dict(project_files=actual,original_source_files=old,original_artifact_files=built,shared_source_inodes=shared)


def main():
    try:claim()
    except (ValueError,FileExistsError) as error:
        print(str(error),file=sys.stderr);return 125
    with check_path(BASE/'state/PID').open('x') as stream:stream.write(str(os.getpid())+'\n')
    stage('live-input-check\n')
    status=1;ready=None;tools_before=None;child=None
    try:
        ready=json.loads((BASE/'ready.json').read_text())
        for name,expected in ready['control_hashes'].items():
            if digest(check_path(BASE/name))!=expected:raise ValueError('control drift: '+name)
        save('before.json',audit_inputs(ready))
        expected=json.loads((BASE/'project-files.json').read_text())['files']
        gate=checked_imports(expected)
        freeze=json.loads((BASE/'source-freeze.json').read_text());gate.verify_freeze(PROJECT,freeze)
        manifest=json.loads((ARTIFACT/'irq-session-artifact.json').read_text())
        tools_before=tool_inventory(manifest['build_origin']['tool_identity']);save('tools-before.json',tools_before)
        argv=[sys.executable,'-u','-m','myfuzz.scenario.boom_gpio_irq_verification','--run-native',
            '--repo',str(PROJECT),'--cpu-output',str(ARTIFACT),'--cache-dir',str(CACHE),'--output',str(OUTPUT),
            '--freeze-path',str(BASE/'source-freeze.json'),'--freeze-sha256',ready['freeze_sha256'],
            '--artifact-sha256',ready['artifact_sha256'],'--heavy-lock',str(HEAVY_LOCK)]
        save('invocation.json',dict(controller_pid=os.getpid(),controller_argv=getattr(sys,'orig_argv',sys.argv),
            native_argv=argv,cwd=str(PROJECT),python=sys.executable,python_version=sys.version,
            env={name:os.environ.get(name) for name in ('PYTHONPATH','TMPDIR','PYTHONDONTWRITEBYTECODE')},
            historical_origin=manifest['build_origin'],metadata_finalization=manifest['metadata_finalization']))
        stage('native-child-starting\n')
        with check_path(BASE/'logs/native.log').open('x') as log:
            child=subprocess.Popen(argv,cwd=PROJECT,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
            with check_path(BASE/'state/native-PID').open('x') as stream:stream.write(str(child.pid)+'\n')
            stage('native-child-live\n')
            code=child.wait()
        fresh_text(BASE/'state/native.exit',str(code)+'\n')
        save('child.json',dict(pid=child.pid,args=child.args,exit=code,poll=child.poll()))
        if code!=0:raise ValueError('actual native gate child failed')
        summary=json.loads((OUTPUT/'summary.json').read_text())
        if summary['status']!='pass' or summary['source_authority'] is not False or summary['isa_retirement_authority'] is not False:
            raise ValueError('actual gate summary missing/pass authority differs')
        status=0
    except BaseException as error:
        save('failure.json',dict(type=type(error).__name__,detail=str(error)));traceback.print_exc()
    finally:
        try:
            if child is not None and child.poll() is None:
                # Do not kill or restart an actual native child on collection failure.
                code=child.wait();fresh_text(BASE/'state/native.exit',str(code)+'\n')
                save('child.json',dict(pid=child.pid,args=child.args,exit=code,poll=child.poll()))
            if ready is not None:
                save('after.json',audit_inputs(ready))
                manifest=json.loads((ARTIFACT/'irq-session-artifact.json').read_text())
                after=tool_inventory(manifest['build_origin']['tool_identity'])
                save('tools-after.json',dict(actual=after,equal_before=after==tools_before))
                if tools_before is not None and after!=tools_before:raise ValueError('tool post-audit drift')
        except BaseException as error:
            save('after-audit-failure.json',dict(type=type(error).__name__,detail=str(error)));status=1
        fresh_text(BASE/'state/worker.exit',str(status)+'\n');stage('terminal\n')
    return status


if __name__=='__main__':
    if sys.argv[1:]!=['--run-native-once']:
        print(json.dumps(dict(native='not_executed',exact_go_required=True)));sys.exit(0)
    sys.exit(main())
