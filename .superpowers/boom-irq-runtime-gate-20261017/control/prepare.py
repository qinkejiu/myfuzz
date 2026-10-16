"""Pure copies/hash/import/source-freeze preparation. Never invokes a model/tool."""
import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('boom_irq_runtime_control',Path(__file__).with_name('controller.py'))
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
BASE=control.BASE
ADDITIONS=('src/myfuzz/scenario/boom_gpio_irq_verification.py','tests/local_harness/test_boom_irq_verification.py')


def prepare_snapshot(*,source,artifact,baseline,artifact_files,overlay,destination):
    source=control.check_path(source);artifact=control.check_path(artifact)
    destination=control.check_path(destination);staging=destination.with_name(destination.name+'.preparing')
    if destination.exists() or staging.exists():raise ValueError('new runtime snapshot already exists')
    if any(destination.is_relative_to(p) or p.is_relative_to(destination) or staging.is_relative_to(p) for p in (source,artifact)):
        raise ValueError('runtime copy overlaps protected original')
    before=control.inventory(source);built=control.inventory(artifact)
    if before!=baseline or built!=artifact_files:raise ValueError('finalized source/artifact differs before copy')
    additions=control.inventory(overlay)
    if set(additions)!=set(ADDITIONS) or set(additions)&set(before):raise ValueError('overlay must add exact two new gate files')
    control.copy_independent(source,staging)
    for name in ADDITIONS:
        src=overlay/name;dst=staging/name
        dst.parent.mkdir(parents=True,exist_ok=True)
        control.shutil.copy2(src,dst)
        if dst.stat().st_nlink!=1 or os.path.samestat(src.stat(),dst.stat()):raise ValueError('overlay copy is shared')
    expected={**before,**additions}
    if control.inventory(staging)!=expected or control.inventory(source)!=before or control.inventory(artifact)!=built:
        raise ValueError('copied source or protected original drift')
    staging.rename(destination)
    return expected


def main():
    state=BASE/'state'
    conflicts=[BASE/'project',BASE/'project.preparing',state/'preparation.claim',state/'preparation.json',state/'operation.claim',state/'PID',BASE/'gate-output',BASE/'gpio-cache']
    if any(p.exists() or p.is_symlink() for p in conflicts):raise ValueError('preparation already used')
    control.check_path(state)
    with (state/'preparation.claim').open('x') as stream:stream.write(str(os.getpid())+'\n')
    baseline=json.loads((BASE/'baseline-source-files.json').read_text())['files']
    artifact_files=json.loads((BASE/'baseline-artifact-files.json').read_text())['files']
    frozen=json.loads((BASE/'overlay-files.json').read_text())['files']
    if control.inventory(BASE/'overlay')!=frozen:raise ValueError('frozen overlay differs')
    expected=prepare_snapshot(source=control.ORIGINAL_SOURCE,artifact=control.ARTIFACT,baseline=baseline,
        artifact_files=artifact_files,overlay=BASE/'overlay',destination=control.PROJECT)
    save=lambda name,value:(BASE/name).write_text(json.dumps(value,indent=2)+'\n')
    save('project-files.json',dict(files=expected));save('original-source-files.json',dict(files=baseline))
    save('original-artifact-files.json',dict(files=artifact_files))
    sys.path[:0]=[str(control.PROJECT/'src'),str(control.PROJECT)]
    gate=control.checked_imports(expected)
    freeze=gate.prepare_freeze(control.PROJECT)
    if any(expected.get(name)!=value for name,value in freeze['files'].items()):raise ValueError('source-freeze dependency outside prepared closure')
    save('source-freeze.json',freeze)
    protected_source=control.inventory(control.ORIGINAL_SOURCE);protected_artifact=control.inventory(control.ARTIFACT)
    if protected_source!=baseline or protected_artifact!=artifact_files:raise ValueError('protected original changed')
    shared=[name for name in baseline if os.path.samestat((control.PROJECT/name).stat(),(control.ORIGINAL_SOURCE/name).stat())]
    if shared or any((control.PROJECT/name).stat().st_nlink!=1 for name in expected):raise ValueError('copy inode audit failed')
    git=control.PROJECT/'third_party/soc-pulp-apb-gpio/.git'
    if not git.is_dir() or (git/'commondir').exists() or (git/'objects/info/alternates').exists():raise ValueError('PULP Git closure external')
    if 'worktree' in (git/'config').read_text().lower():raise ValueError('PULP Git worktree reference')
    manifest=json.loads((control.ARTIFACT/'irq-session-artifact.json').read_text())
    tools=control.tool_inventory(manifest['build_origin']['tool_identity'])
    save('state/preparation.json',dict(status='prepared_not_executed',files=len(expected),baseline_source_files=len(baseline),
        protected_artifact_files=len(artifact_files),added_files=list(ADDITIONS),shared_source_inodes=shared,
        all_links_one=True,original_source_unchanged=True,original_artifact_unchanged=True,
        pulp_git_is_directory=True,pulp_git_files=len(control.inventory(git)),source_freeze_files=len(freeze['files']),
        tools=tools,constructor_executed=False,model_executed=False,build_executed=False,describe_executed=False,
        whole_head_reviewed=False,source_authority=False))
    controls=['control/controller.py','control/launch.sh','control/prepare.py','control/test_control.py',
        'baseline-source-files.json','baseline-artifact-files.json','overlay-files.json','project-files.json',
        'original-source-files.json','original-artifact-files.json','source-freeze.json','state/imports.json','state/preparation.json']
    ready=dict(schema_version='boom_irq_runtime_ready.v1',native_executed=False,exact_go_required=True,
        gate_source_commit='70fdbcb',independent_review_commit='869c70b',metadata_evidence_commit='9557281',
        artifact_path=str(control.ARTIFACT),artifact_sha256=control.digest(control.ARTIFACT/'irq-session-artifact.json'),
        freeze_sha256=control.digest(BASE/'source-freeze.json'),
        control_hashes={name:control.digest(BASE/name) for name in controls})
    with (BASE/'ready.json').open('x') as stream:stream.write(json.dumps(ready,indent=2)+'\n')
    print(json.dumps(dict(prepared=True,ready_sha256=control.digest(BASE/'ready.json'),source_files=len(expected),native_executed=False)))


if __name__=='__main__':main()
