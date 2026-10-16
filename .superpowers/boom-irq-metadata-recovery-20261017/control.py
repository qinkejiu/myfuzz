"""Metadata recovery controller; prepared only, exact parent GO required to run."""
import hashlib,importlib,json,os,shutil,sys,traceback
from pathlib import Path
SCOPES=('src','configs','tests','scripts','third_party/soc-pulp-apb-gpio')
BASE=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017')
SOURCE=BASE/'source'
ORIGINAL=Path('/root/fanzehui/boom-irq-verification-20261017/artifact')
PROJECT=BASE/'project-finalized'
OUTPUT=BASE/'artifact-finalized'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name,value):(BASE/'state'/name).write_text(json.dumps(value,indent=2)+'\n')
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
    conflicts=(state/'PID',state/'launcher-PID',state/'worker.exit',state/'operation.claim',PROJECT,OUTPUT)
    if any(path.exists() or path.is_symlink() for path in conflicts):
        raise ValueError('metadata operation already claimed or used; no state changed')
    with (state/'operation.claim').open('x') as stream:
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


def main():
    state=BASE/'state'
    try:claim()
    except (ValueError,FileExistsError) as error:
        print(str(error),file=sys.stderr)
        return 125
    with (state/'PID').open('x') as stream:stream.write(str(os.getpid())+'\n')
    (state/'stage').write_text('live-source-origin-check\n')
    files=origin=None
    before=tools_before=result=None
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
        (state/'stage').write_text('metadata-only-independent-copy-and-finalize\n')
        artifact=api.recover_metadata(repo=SOURCE,original_output=ORIGINAL,
            project_destination=PROJECT,output_destination=OUTPUT,archives=BASE/'archives')
        artifact_created=True
        copied=source_inventory(PROJECT)
        save('copied-source.json',{'files':copied,'match_prepared':copied==expected})
        if copied!=expected:
            (OUTPUT/'.recovery-incomplete.json').write_text('control copied-source audit failed\n')
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
            (OUTPUT/'.recovery-incomplete.json').write_text('controller audit incomplete or failed\n')
        (state/'worker.exit').write_text(str(status)+'\n')
        (state/'stage').write_text('terminal\n')
    return status


if __name__=='__main__':sys.exit(main())
