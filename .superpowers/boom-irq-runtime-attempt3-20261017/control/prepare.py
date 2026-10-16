"""Pure copies/hash/import/source-freeze preparation. Never invokes a model/tool."""
import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('boom_irq_runtime_control',Path(__file__).with_name('controller.py'))
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
BASE=control.BASE
ADDITIONS=('src/myfuzz/scenario/boom_gpio_irq_verification.py','tests/local_harness/test_boom_irq_verification.py')
EXPECTED_ARTIFACT_SHA='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'


def prepare_snapshot(source,destination,expected,overlay,overlay_expected):
    source=control.check_path(source);destination=control.check_path(destination)
    staging=control.check_path(destination.with_name(destination.name+'.preparing'))
    if destination.exists() or staging.exists():raise ValueError('new runtime snapshot already exists')
    if (destination.is_relative_to(source) or source.is_relative_to(destination)
        or staging.is_relative_to(source) or source.is_relative_to(staging)):
        raise ValueError('runtime copy overlaps protected original')
    if control.inventory(source)!=expected:raise ValueError('finalized source differs before copy')
    overlay=control.check_path(overlay)
    if (set(overlay_expected)!=set(ADDITIONS) or not set(ADDITIONS)<=set(expected)
        or control.inventory(overlay)!=overlay_expected):raise ValueError('reviewed replacement overlay differs')
    if any(p.is_relative_to(q) or q.is_relative_to(p) for p in (destination,staging) for q in (overlay,)):
        raise ValueError('overlay overlaps copy destination')
    control.copy_independent(source,staging)
    for name in ADDITIONS:
        original=overlay/name;copied=staging/name
        control.shutil.copy2(original,copied)
        if copied.stat().st_nlink!=1 or os.path.samestat(original.stat(),copied.stat()):raise ValueError('overlay copy inode shared')
    combined={**expected,**overlay_expected}
    if control.inventory(staging)!=combined or control.inventory(source)!=expected or control.inventory(overlay)!=overlay_expected:
        raise ValueError('copied source or protected original drift')
    staging.rename(destination)
    return combined


def main():
    state=BASE/'state'
    conflicts=[BASE/'project',BASE/'project.preparing',state/'preparation.claim',state/'preparation.json',state/'operation.claim',state/'PID',BASE/'gate-output',BASE/'gpio-cache']
    if any(p.exists() or p.is_symlink() for p in conflicts):raise ValueError('preparation already used')
    control.check_path(state)
    with (state/'preparation.claim').open('x') as stream:stream.write(str(os.getpid())+'\n')
    baseline=json.loads((BASE/'baseline-source-files.json').read_text())['files']
    artifact_files=json.loads((BASE/'baseline-artifact-files.json').read_text())['files']
    if control.inventory(control.ARTIFACT)!=artifact_files:raise ValueError('artifact differs before copy')
    if control.digest(control.ARTIFACT/'irq-session-artifact.json')!=EXPECTED_ARTIFACT_SHA:raise ValueError('artifact manifest differs')
    overlay=json.loads((BASE/'overlay-files.json').read_text())['files']
    expected=prepare_snapshot(control.ORIGINAL_SOURCE,control.PROJECT,baseline,BASE/'overlay',overlay)
    def save(name,value):
        with control.check_path(BASE/name).open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')
    save('project-files.json',dict(files=expected));save('original-source-files.json',dict(files=baseline))
    save('original-artifact-files.json',dict(files=artifact_files))
    sys.path[:0]=[str(control.PROJECT/'src'),str(control.PROJECT)]
    gate=control.checked_imports(expected)
    (state/'imports.json').rename(state/'preparation-imports.json')
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
        protected_artifact_files=len(artifact_files),added_files=[],replaced_files=list(ADDITIONS),overlay_before=overlay,overlay_after=control.inventory(BASE/'overlay'),shared_source_inodes=shared,
        all_links_one=True,original_source_unchanged=True,original_artifact_unchanged=True,
        pulp_git_is_directory=True,pulp_git_files=len(control.inventory(git)),source_freeze_files=len(freeze['files']),
        tools=tools,constructor_executed=False,model_executed=False,build_executed=False,describe_executed=False,
        whole_head_reviewed=False,source_authority=False))
    controls=['control/controller.py','control/launch.sh','control/prepare.py','control/test_control.py',
        'control/test_prepare.py','overlay-files.json','implementation-input-proof.json','baseline-source-files.json','baseline-artifact-files.json','project-files.json',
        'original-source-files.json','original-artifact-files.json','source-freeze.json','state/preparation-imports.json','state/preparation.json']
    controls.extend('overlay/'+name for name in ADDITIONS)
    ready=dict(schema_version='boom_irq_runtime_ready.v1',native_executed=False,exact_go_required=True,
        gate_source_commit='2c28758',baseline_gate_review_commit='869c70b',budget_fix_review_commit='pending_source_review',metadata_evidence_commit='64026db',factory_fix_commit='15bc4cb',
        artifact_path=str(control.ARTIFACT),artifact_sha256=control.digest(control.ARTIFACT/'irq-session-artifact.json'),
        freeze_sha256=control.digest(BASE/'source-freeze.json'),
        control_hashes={name:control.digest(BASE/name) for name in controls})
    with (BASE/'ready.json').open('x') as stream:stream.write(json.dumps(ready,indent=2)+'\n')
    print(json.dumps(dict(prepared=True,ready_sha256=control.digest(BASE/'ready.json'),source_files=len(expected),native_executed=False)))


if __name__=='__main__':main()
