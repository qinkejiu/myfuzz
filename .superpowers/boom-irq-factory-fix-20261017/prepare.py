"""Copies/hash-only preparation. Does NOT execute recover_metadata/generate/tool."""
import importlib.util,json,os,shutil,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('factory_metadata_control',Path(__file__).with_name('control.py'))
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
BASE=control.BASE
NEW_TEST='tests/local_harness/test_boom_irq_factory_binding.py'


def validate_delta(old,new,overlay):
    if set(overlay)!={control.FACTORY,NEW_TEST} or overlay[control.FACTORY]!=control.NEW_FACTORY:
        raise ValueError('overlay identity differs')
    if old.get(control.FACTORY)!=control.OLD_FACTORY or NEW_TEST in old:raise ValueError('baseline factory differs')
    if new!={**old,**overlay}:raise ValueError('snapshot delta includes other changes')


def main():
    state=BASE/'state';control.checked_path(state)
    if any(p.exists() or p.is_symlink() for p in (BASE/'source',BASE/'source.preparing',BASE/'project-finalized',BASE/'artifact-finalized',state/'preparation.claim',state/'PID',state/'operation.claim')):
        raise ValueError('preparation already used')
    control.fresh_text(state/'preparation.claim',str(os.getpid())+'\n')
    pins=json.loads((BASE/'preparation-input-pins.json').read_text())['files']
    for name,want in pins.items():
        if control.digest(control.checked_path(BASE/name))!=want:raise ValueError('preparation source pin drift')
    old=json.loads((BASE/'old-runtime-source-files.json').read_text())['files']
    overlay=json.loads((BASE/'overlay-files.json').read_text())['files']
    if control.source_inventory(control.FAILED_PROJECT)!=old:raise ValueError('failed source changed')
    protected=control.protected_inventory()
    if protected!=json.loads((BASE/'protected-expected.json').read_text()):raise ValueError('protected original changed')
    build_before=control.original_inventory(None)
    if build_before!=json.loads((BASE/'original-build-pins.json').read_text())['files']:raise ValueError('original build drift')
    for name,want in overlay.items():
        if control.digest(control.checked_path(BASE/'overlay'/name))!=want:raise ValueError('overlay hash differs')
    expected={**old,**overlay};validate_delta(old,expected,overlay)
    staging=BASE/'source.preparing';staging.mkdir()
    for name in old:
        source=control.checked_path(control.FAILED_PROJECT/name);target=staging/name
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        if source.stat().st_nlink!=1 or target.stat().st_nlink!=1 or os.path.samestat(source.stat(),target.stat()):raise ValueError('baseline copy shared')
    for name in overlay:
        source=control.checked_path(BASE/'overlay'/name);target=staging/name
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
        if target.stat().st_nlink!=1 or os.path.samestat(source.stat(),target.stat()):raise ValueError('overlay copy shared')
    if control.source_inventory(staging)!=expected:raise ValueError('new source bytes differ')
    staging.rename(control.SOURCE)
    sys.path[:0]=[str(control.SOURCE/'src'),str(control.SOURCE)]
    api=control.checked_imports(expected)
    (state/'imports.json').rename(state/'preparation-imports.json')
    archives=BASE/'archives';archives.mkdir()
    for name,want in api.ARCHIVES.items():
        source=control.checked_path(control.OLD_METADATA/'recovery-receipts'/name);target=archives/name
        if control.digest(source)!=want:raise ValueError('historical archive changed')
        shutil.copy2(source,target)
        if target.stat().st_nlink!=1 or os.path.samestat(source.stat(),target.stat()):raise ValueError('archive copy shared')
    _,origin=api.load_origin(BASE/'archives')  # fixed archive validation only, no generation/tool query.
    old_artifact=json.loads((control.OLD_METADATA/'irq-session-artifact.json').read_text());control.host_factory_contract(old_artifact)
    after=control.protected_inventory();build_after=control.original_inventory(None)
    if after!=protected or build_after!=build_before:raise ValueError('protected input changed during copy')
    shared=[n for n in old if os.path.samestat((control.SOURCE/n).stat(),(control.FAILED_PROJECT/n).stat())]
    if shared or any((control.SOURCE/n).stat().st_nlink!=1 for n in expected):raise ValueError('source inode audit failed')
    git=control.SOURCE/'third_party/soc-pulp-apb-gpio/.git'
    if not git.is_dir() or (git/'commondir').exists() or (git/'objects/info/alternates').exists():raise ValueError('PULP Git not standalone')
    tools=control.tools(origin['tool_identity'])
    for name,info in origin['tool_identity']['tools'].items():
        if tools['files'][name]!={k:info[k] for k in ('path','resolved_path','sha256')}:raise ValueError('actual tool hash/path differs')
    if tools['which_verilator']!=origin['tool_identity']['tools']['verilator']['path']:raise ValueError('tool selection differs')
    def save(name,value):
        with control.checked_path(BASE/name).open('x') as stream:stream.write(json.dumps(value,indent=2)+'\n')
    save('source-destination.json',dict(files=expected));save('protected-preparation-pins.json',protected)
    save('state/protected-after-preparation.json',dict(actual=after,equal_before=True))
    save('state/original-build-preparation.json',dict(before=build_before,after=build_after,equal_before=True))
    save('state/preparation.json',dict(status='prepared_not_executed',pid=os.getpid(),source_files=len(expected),
        original_runtime_source_files=len(old),changed_existing_files=[control.FACTORY],added_files=[NEW_TEST],
        shared_source_inodes=shared,all_links_one=True,pulp_git_is_directory=True,
        pulp_git_files=sum(1 for p in git.rglob('*') if p.is_file()),tools=tools,
        constructor_executed=False,model_executed=False,generator_executed=False,tool_query_executed=False,
        future_metadata_stage_version_query_required=True,source_authority=False))
    names=[*pins,'preparation-input-pins.json','source-destination.json','protected-preparation-pins.json',
           'state/preparation-imports.json','state/protected-after-preparation.json','state/original-build-preparation.json','state/preparation.json']
    names+=['archives/'+n for n in api.ARCHIVES]
    ready=dict(schema_version='boom_irq_factory_fix_metadata_ready.v1',operation_executed=False,exact_go_required=True,
        old_factory_sha256=control.OLD_FACTORY,new_factory_sha256=control.NEW_FACTORY,
        helper_sha256=control.HELPER,unchanged_effective_input_count=len(api.INPUTS),
        future_stage='metadata_only_with_actual_version_query_no_build_or_model',
        control_hashes={n:control.digest(BASE/n) for n in names})
    save('ready.json',ready)
    print(json.dumps(dict(ready_sha256=control.digest(BASE/'ready.json'),source_files=len(expected),metadata_operation_executed=False)))


if __name__=='__main__':main()
