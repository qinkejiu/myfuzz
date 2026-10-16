"""Independent read-only source/artifact audit; freezes unused native controls."""
import hashlib,importlib.util,json,os,shutil
from pathlib import Path
BASE=Path('/root/fanzehui/boom-irq-runtime-gate-20261017')
spec=importlib.util.spec_from_file_location('boom_irq_control_audit',BASE/'control/controller.py')
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)


def main():
    initial=BASE/'ready.json'
    if control.digest(initial)!='a3e5194f5b1a7defa684d87407c45dbe5f33ad38e72921a2b2dc9193f519daf8':raise ValueError('initial unused ready changed')
    forbidden=[BASE/'state'/n for n in ('PID','operation.claim','worker.exit','native-PID','native.exit')]+[control.OUTPUT,control.CACHE,BASE/'state/post-preparation-audit.json']
    if any(p.exists() or p.is_symlink() for p in forbidden):raise ValueError('native state used or audit already completed')
    pins=json.loads((BASE/'final-control-pins.json').read_text())['files']
    for name,value in pins.items():
        if control.digest(control.check_path(BASE/name))!=value:raise ValueError('final control source drift')
    ready=json.loads(initial.read_text())
    for name,value in ready['control_hashes'].items():
        if name=='control/test_control.py':continue
        if control.digest(control.check_path(BASE/name))!=value:raise ValueError('original preparation receipt drift')
    audit=control.audit_inputs(ready)
    def save(name,value):
        with (BASE/name).open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')
    save('state/protected-source-after.json',dict(files=audit['original_source_files'],equal_baseline=True))
    save('state/protected-artifact-after.json',dict(files=audit['original_artifact_files'],equal_baseline=True))
    save('state/project-after.json',dict(files=audit['project_files'],equal_prepared=True,shared_source_inodes=audit['shared_source_inodes']))
    save('state/post-preparation-audit.json',dict(status='prepared_not_executed',native_state_absent=True,
        protected_source_files=len(audit['original_source_files']),protected_artifact_files=len(audit['original_artifact_files']),
        runtime_source_files=len(audit['project_files']),zero_shared_inodes=True,constructor_executed=False,model_executed=False))
    shutil.copy2(initial,BASE/'preparation-ready.initial.json')
    names=[*pins,'final-control-pins.json','state/protected-source-after.json','state/protected-artifact-after.json',
           'state/project-after.json','state/post-preparation-audit.json','preparation-ready.initial.json']
    for name in names:ready['control_hashes'][name]=control.digest(BASE/name)
    ready['control_hashes']['control/test_control.py']=control.digest(BASE/'control/test_control.py')
    ready['preparation_only_actual_pid']=264582
    ready['preparation_only_actual_exit']=0
    ready['operation_status']='unused_awaiting_exact_native_go'
    temporary=BASE/'ready.final.pending'
    with temporary.open('x') as stream:
        stream.write(json.dumps(ready,indent=2)+'\n');stream.flush();os.fsync(stream.fileno())
    temporary.replace(initial)
    print(json.dumps(dict(ready_sha256=control.digest(initial),native_executed=False,post_audit=True)))


if __name__=='__main__':main()
