"""Metadata recovery controller; prepared only, exact parent GO required to run."""
import hashlib,importlib,json,os,shutil,sys,traceback
from pathlib import Path
SCOPES=('src','configs','tests','scripts','third_party/soc-pulp-apb-gpio')
BASE=Path('/root/fanzehui/boom-irq-factory-fix-20261017')
SOURCE=BASE/'source'
ORIGINAL=Path('/root/fanzehui/boom-irq-verification-20261017/artifact')
PROJECT=BASE/'project-finalized'
OUTPUT=BASE/'artifact-finalized'
OLD_METADATA=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017/artifact-finalized')
OLD_PROJECT=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017/project-finalized')
FAILED_PROJECT=Path('/root/fanzehui/boom-irq-runtime-gate-20261017/project')
FAILED_FIRST=Path('/root/fanzehui/boom-irq-runtime-gate-20261017/gate-output/first.json.gz')
FACTORY='src/myfuzz/scenario/boom_gpio_irq_runner.py'
OLD_FACTORY='1de87df95d1f10b44dd5848cc19afd9432527cf3b088103fa67f0883db8b0e09'
NEW_FACTORY='0af5037e8282c232c672a0251e2c8f579d4f1f6edde793bc51e20854f8f1e77e'
HELPER='a6bbd17117a0973e4e67bc599b0e4cd7daa277449d4be9de3dfea0db294db3a8'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def checked_path(path):
    path=Path(path).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('control path symlink')
    if path.exists() and path.is_file() and path.stat().st_nlink!=1:raise ValueError('control path shared inode')
    return path

def save(name,value):
    if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('unsafe receipt path')
    with checked_path(BASE/'state'/name).open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')

def stage(value):
    path=checked_path(BASE/'state/stage')
    with path.open('w') as stream:stream.write(value)

def fresh_text(path,value):
    with checked_path(path).open('x') as stream:stream.write(value)
def source_inventory(root):
    result={}
    for scope in SCOPES:
        directory=root/scope
        for file in (directory,*directory.rglob('*')):
            if any(path.is_symlink() for path in (file,*file.parents)):
                raise ValueError('source symlink')
            if file.is_file() and '__pycache__' not in file.parts and file.suffix!='.pyc':
                result[str(file.relative_to(root))]=digest(file)
    return result
def original_inventory(files):
    result={}
    for path in ORIGINAL.rglob('*'):
        if any(part.is_symlink() for part in (path,*path.parents)):raise ValueError('original symlink')
        if path.is_file():result[str(path.relative_to(ORIGINAL))]=digest(path)
    return result
def tools(receipt):
    result={'which_verilator':shutil.which('verilator'),'files':{}}
    for name,info in receipt['tools'].items():
        path=Path(info['path'])
        if not path.resolve().is_relative_to('/root/fanzehui'):
            raise ValueError('manual tool read outside permitted root')
        result['files'][name]={'path':str(path),'resolved_path':str(path.resolve()),'sha256':digest(path)}
    return result


def claim():
    state=BASE/'state'
    checked_path(state)
    conflicts=(state/'stage',state/'result.json',state/'failure.json',state/'imports.json',state/'PID',state/'launcher-PID',state/'worker.exit',state/'operation.claim',PROJECT,OUTPUT)
    if any(path.exists() or path.is_symlink() for path in conflicts):
        raise ValueError('metadata operation already claimed or used; no state changed')
    with checked_path(state/'operation.claim').open('x') as stream:
        stream.write(json.dumps({'pid':os.getpid(),'argv':sys.argv})+'\n')


def checked_imports(expected):
    result={}
    for name in ('myfuzz.local_harness.boom_irq_recovery',
                 'myfuzz.local_harness.boom_irq_generation',
                 'myfuzz.local_harness.boom_irq_cpu_session'):
        module=importlib.import_module(name)
        path=Path(module.__file__).resolve()
        if not path.is_relative_to(SOURCE):raise ValueError('BOOM import origin outside snapshot')
        relative=str(path.relative_to(SOURCE))
        if digest(path)!=expected.get(relative):raise ValueError('BOOM import source hash differs')
        result[name]={'path':relative,'sha256':digest(path)}
    save('imports.json',result)
    return importlib.import_module('myfuzz.local_harness.boom_irq_recovery')


def protected_inventory():
    def tree(root):
        result={}
        for path in root.rglob('*'):
            if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('protected input symlink')
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':
                result[path.relative_to(root).as_posix()]=digest(path)
        return result
    return {'old_metadata':tree(OLD_METADATA),'old_finalized_project':source_inventory(OLD_PROJECT),
            'failed_runtime_project':source_inventory(FAILED_PROJECT),'failed_first_sha256':digest(FAILED_FIRST)}


def host_factory_contract(old_artifact):
    new=(SOURCE/FACTORY).read_bytes();old=(FAILED_PROJECT/FACTORY).read_bytes()
    if (digest(SOURCE/FACTORY)!=NEW_FACTORY or digest(FAILED_PROJECT/FACTORY)!=OLD_FACTORY
        or new.replace(b"'bound','gpio.irq'",b"'bound','gpio_irq'")!=old):
        raise ValueError('factory change is not exact owner producer correction')
    if digest(SOURCE/'src/myfuzz/local_harness/boom_irq_recovery.py')!=HELPER:
        raise ValueError('recovery helper changed')
    if old_artifact['scenario_factory_sha256']!=OLD_FACTORY:raise ValueError('old factory identity differs')
    for name,value in old_artifact['implementation_source_hashes'].items():
        if digest(SOURCE/'src/myfuzz/local_harness'/name)!=value:raise ValueError('native implementation identity changed')


def main():
    state=BASE/'state'
    try:claim()
    except (ValueError,FileExistsError) as error:
        print(str(error),file=sys.stderr)
        return 125
    with checked_path(state/'PID').open('x') as stream:stream.write(str(os.getpid())+'\n')
    stage('live-source-origin-check\n')
    files=origin=None
    before=tools_before=result=None
    protected_before=None
    status=1
    artifact_created=False
    try:
        save('invocation.json',{'argv':getattr(sys,'orig_argv',sys.argv),'script_argv':sys.argv,'pid':os.getpid(),'python':sys.executable,
            'python_version':sys.version,'cwd':str(Path.cwd()),'runtime_gate':False,
            'function_arguments':{'repo':str(SOURCE),'original_output':str(ORIGINAL),
                'project_destination':str(PROJECT),'output_destination':str(OUTPUT),'archives':str(BASE/'archives')}})
        ready=json.loads((BASE/'ready.json').read_text())
        for name,expected in ready['control_hashes'].items():
            if digest(BASE/name)!=expected:raise ValueError('control file drift: '+name)
        expected=json.loads((BASE/'source-destination.json').read_text())['files']
        actual=source_inventory(SOURCE)
        save('source-before.json',{'files':actual,'match_prepared':actual==expected})
        if actual!=expected:raise ValueError('prepared source drift')
        if PROJECT.exists() or OUTPUT.exists():raise ValueError('future destination no longer absent')
        protected_before=protected_inventory();save('protected-before.json',protected_before)
        if protected_before!=json.loads((BASE/'protected-preparation-pins.json').read_text()):raise ValueError('protected input drift')
        old_artifact=json.loads((OLD_METADATA/'irq-session-artifact.json').read_text())
        host_factory_contract(old_artifact)
        api=checked_imports(expected)
        files,origin=api.load_origin(BASE/'archives')
        save('archive-origin.json',origin)
        before=original_inventory(files)
        wanted={name.removeprefix('artifact/'):hashlib.sha256(data).hexdigest()
                for name,data in files.items() if name.startswith('artifact/')}
        matches=all(before.get(name)==value for name,value in wanted.items())
        save('original-before.json',{'files':before,'pinned_subset':wanted,'match_pinned':matches})
        if not matches:raise ValueError('original artifact drift')
        tools_before=tools(origin['tool_identity'])
        save('tools-before.json',tools_before)
        stage('metadata-only-independent-copy-and-finalize\n')
        artifact=api.recover_metadata(repo=SOURCE,original_output=ORIGINAL,
            project_destination=PROJECT,output_destination=OUTPUT,archives=BASE/'archives')
        artifact_created=True
        if artifact['scenario_factory_sha256']!=NEW_FACTORY or artifact['implementation_source_hashes']!=old_artifact['implementation_source_hashes']:
            raise ValueError('new metadata factory/native identity contract differs')
        if any(artifact['session_files'][name]!=value for name,value in origin['effective_inputs'].items()):
            raise ValueError('effective compiled inputs changed')
        save('host-factory-change.json',dict(old_factory_sha256=OLD_FACTORY,new_factory_sha256=NEW_FACTORY,
            factory_only_exact_producer_delta=True,effective_inputs=origin['effective_inputs'],
            implementation_source_hashes_unchanged=artifact['implementation_source_hashes'],
            original_binary_sha256=artifact['session_files']['obj/VBoomTile'],
            new_cpp_build=False,source_authority=False,runtime_verified=False))
        copied=source_inventory(PROJECT)
        save('copied-source.json',{'files':copied,'match_prepared':copied==expected})
        if copied!=expected:
            checked_path(OUTPUT/'.recovery-incomplete.json').write_text('control copied-source audit failed\n')
            raise ValueError('copied source mismatch')
        shared=[name for name in expected if os.path.samestat((SOURCE/name).stat(),(PROJECT/name).stat())]
        if shared:raise ValueError('shared source inode')
        artifact_shared=[name for name in before if os.path.samestat((ORIGINAL/name).stat(),(OUTPUT/name).stat())]
        if artifact_shared:raise ValueError('shared original artifact inode')
        api.validate_recovery_origin(OUTPUT,artifact)
        result={'metadata_only_recovery_audit_pass':True,'runtime_verified':False,
            'source_authority':False,'new_cpp_build':False,'native_model_executed':False,
            'historical_build_exit':origin['build_exit'],'historical_probe_exit':origin['probe_exit'],
            'historical_failed_stage_exit':origin['failed_stage_exit'],'copied_source_files':len(copied),
            'original_artifact_file_count':len(before),
            'shared_source_inodes':shared,'shared_artifact_inodes':artifact_shared,'binary_sha256':digest(OUTPUT/'obj/VBoomTile'),
            'final_manifest_sha256':digest(OUTPUT/'irq-session-artifact.json')}
        status=0
    except BaseException as error:
        save('failure.json',{'type':type(error).__name__,'error':str(error),'runtime_gate':False})
        traceback.print_exc()
    finally:
        try:
            if protected_before is not None:
                protected_after=protected_inventory()
                save('protected-after.json',dict(actual=protected_after,equal_before=protected_after==protected_before))
                if protected_after!=protected_before:status=1
            if files is not None:
                after=original_inventory(files)
                save('original-after.json',{'files':after,'equal_before':after==before})
                if before is not None and after!=before:status=1
            if origin is not None:
                tools_after=tools(origin['tool_identity'])
                save('tools-after.json',{'actual':tools_after,'equal_before':tools_after==tools_before})
                if tools_before is not None and tools_after!=tools_before:status=1
            expected=json.loads((BASE/'source-destination.json').read_text())['files']
            after_source=source_inventory(SOURCE)
            save('source-after.json',{'files':after_source,'match_prepared':after_source==expected})
            if after_source!=expected:status=1
        except BaseException as audit_error:
            save('after-audit-failure.json',{'error':str(audit_error)})
            status=1
        if result is not None:
            result['metadata_only_recovery_audit_pass']=status==0
            result['worker_exit']=status
            save('result.json',result)
        if status and artifact_created:
            checked_path(OUTPUT/'.recovery-incomplete.json').write_text('controller audit incomplete or failed\n')
        fresh_text(state/'worker.exit',str(status)+'\n')
        stage('terminal\n')
    return status


if __name__=='__main__':
    if sys.argv[1:]!=['--metadata-only-once']:
        print(json.dumps(dict(metadata_operation='not_executed',exact_go_required=True)));sys.exit(0)
    sys.exit(main())
