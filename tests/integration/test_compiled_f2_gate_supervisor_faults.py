"""Supervisor capture/scratch controls use short Python children, never RTL."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = ROOT/'.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/gates/run_gate.py'


def supervisor():
    spec = importlib.util.spec_from_file_location('f2_supervisor_fault_control', SUPERVISOR)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def fake_root(tmp_path, monkeypatch):
    mod = supervisor()
    for name in ('src/myfuzz','scripts','tests','configs','templates','third_party/native'):
        (tmp_path/name).mkdir(parents=True)
    gates = tmp_path/'.superpowers/sdd/compiled-f2-rfuzz-entry-20261023/gates'
    (gates/'inputs').mkdir(parents=True)
    (gates/'inputs/control-matrix.json').write_text(json.dumps({'allowed_software_skip_fragments':['MYFUZZ_RUN_NATIVE_F2_RFUZZ=1']}))
    (tmp_path/'agent.md').write_text('software fixture')
    plan = tmp_path/'docs/superpowers/plans/2026-10-23-compiled-f2-rfuzz-entry.md'
    plan.parent.mkdir(parents=True); plan.write_text('software fixture')
    native = tmp_path/'third_party/native'
    (native/'rtl.sv').write_text('module actual_input; endmodule\n')
    profile = {'schema_version':'component_profile.v1','source':{'root':'third_party/native','files':['rtl.sv','.myfuzz-elaboration-static/keep.sv'],'include_roots':[]}}
    (tmp_path/'configs/component_profile.json').write_text(json.dumps(profile))
    static = native/'.myfuzz-elaboration-static'; static.mkdir(); (static/'keep.sv').write_text('registered source\n')
    monkeypatch.setattr(mod,'ROOT',tmp_path);monkeypatch.setattr(mod,'GATES',gates)
    monkeypatch.setattr(mod,'BASE',tmp_path/'evidence')
    monkeypatch.setattr(mod,'CACHE',tmp_path/'unused-cache')
    monkeypatch.setattr(mod,'CLIENT',Path(sys.executable))
    monkeypatch.setattr(mod,'executables',lambda:{'python':{'path':sys.executable,'sha256':mod.digest(sys.executable)}})
    return mod,native


def test_scratch_is_pruned_before_descent_and_changing_siblings_do_not_drift(tmp_path, monkeypatch):
    mod,native = fake_root(tmp_path,monkeypatch)
    scratch=native/'.myfuzz-elaboration-owned';scratch.mkdir();(scratch/'evidence.json').write_text('{}')
    walked=[];real_walk=os.walk
    def tracked(*args,**kwargs):
        for directory,dirs,files in real_walk(*args,**kwargs):
            walked.append(Path(directory))
            yield directory,dirs,files
            if Path(directory)==native and scratch.exists():
                # The consumer must prune before os.walk resumes recursion.
                assert scratch.name not in dirs
                shutil.rmtree(scratch)
    monkeypatch.setattr(mod.os,'walk',tracked)
    before=mod.snapshot()
    assert not any('.myfuzz-elaboration-owned' in name for name in before)
    assert scratch not in walked
    another=native/'.myfuzz-elaboration-next';another.mkdir();(another/'new.json').write_text('{}')
    after=mod.snapshot()
    assert before==after
    assert 'third_party/native/rtl.sv' in before


def test_hidden_declared_prefixed_inputs_and_symlinks_remain_frozen(tmp_path,monkeypatch):
    mod,native=fake_root(tmp_path,monkeypatch)
    hidden=native/'.ordinary-hidden';hidden.mkdir();(hidden/'defs.vh').write_text('real header')
    (native/'.myfuzz-elaboration-source.sv').write_text('real prefix file')
    link=native/'.myfuzz-elaboration-link.sv';link.symlink_to('rtl.sv')
    nested=native/'ordinary';nested.mkdir();ordinary=nested/'.myfuzz-elaboration-not-owned';ordinary.mkdir();(ordinary/'keep.sv').write_text('ordinary nested input')
    # A static declaration with the owned prefix is retained explicitly.
    snapshot=mod.snapshot()
    expected={'third_party/native/.ordinary-hidden/defs.vh',
        'third_party/native/.myfuzz-elaboration-source.sv',
        'third_party/native/.myfuzz-elaboration-link.sv',
        'third_party/native/.myfuzz-elaboration-static/keep.sv',
        'third_party/native/ordinary/.myfuzz-elaboration-not-owned/keep.sv'}
    assert expected<=set(snapshot)
    assert mod.source_origins(snapshot)['third_party/native/.myfuzz-elaboration-link.sv']['is_symlink'] is True


def test_software_optins_are_code_owned_and_native_stays_disabled(monkeypatch,tmp_path):
    mod=supervisor()
    monkeypatch.setenv('MYFUZZ_SCENARIO_RFUZZ_LIVE','0')
    monkeypatch.setenv('MYFUZZ_RUN_NATIVE_F2_RFUZZ','1')
    _,env,_,expected=mod.command(SimpleNamespace(mode='software'),tmp_path/'out')
    assert env['MYFUZZ_SCENARIO_RFUZZ_LIVE']=='1'
    assert env['MYFUZZ_RUN_NATIVE_F2_RFUZZ']=='0' and expected==0


def setup_short_child(tmp_path,monkeypatch,*,bad_junit=False,remove_source=False,expected=0,alias_state=None,junit_xml=None,native_names=None):
    mod,native=fake_root(tmp_path,monkeypatch)
    if alias_state is not None:
        (native/'alias.sv').symlink_to('rtl.sv' if alias_state=='available' else 'future.sv')
    if native_names is not None:
        path=tmp_path/mod.NATIVE;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# not executed')
        matrix=mod.GATES/'inputs/control-matrix.json';doc=json.loads(matrix.read_bytes())
        doc.update(native_control_nodes=[mod.NATIVE+'::'+name for name in native_names],expected_selected_native_controls=5)
        matrix.write_text(json.dumps(doc))
    if expected:
        (tmp_path/'scripts/verify_compiled_f2_rfuzz.py').write_text(
            "def verify_refusal_material(*args,**kwargs):raise RuntimeError('controlled-refusal-capture')\n")
    freeze=tmp_path/'freeze';mod.archive_inputs(freeze,mod.snapshot())
    out=mod.BASE/'software-attempt1';done=out/'child-done.json'
    script=("from pathlib import Path;import sys;out=Path(sys.argv[1]);"
        "(out/'child-done.json').write_text('{}');"
        "(out/'pytest-results.xml').write_text(sys.argv[2]);"
        +("Path(sys.argv[3]).unlink();" if remove_source else '')
        +("(Path(sys.argv[3]).parent/'future.sv').write_text('target appears');" if alias_state=='missing' else ''))
    xml=junit_xml if junit_xml is not None else ('malformed junit' if bad_junit else '<testsuite><testcase name="short-child"/></testsuite>')
    monkeypatch.setattr(mod,'command',lambda args,target:([sys.executable,'-c',script,str(target),xml,str(native/'rtl.sv')],{},5,expected))
    monkeypatch.setattr(sys,'argv',['run_gate.py','software','--freeze',str(freeze),'--attempt','1'])
    return mod,out,done


@pytest.mark.parametrize('fault',['source-after','source-origins-after','output-initial','output-final','skip-reasons','junit','real-input-missing','archive-hash','terminal-export'])
def test_post_child_failure_retains_actual_exit_and_attempts_remaining_captures(tmp_path,monkeypatch,fault):
    mod,out,done=setup_short_child(tmp_path,monkeypatch,bad_junit=fault=='junit',remove_source=fault=='real-input-missing')
    originals={name:getattr(mod,name) for name in ('snapshot','source_origins','output_map','write','digest')}
    attempts=[];fired=[];output_calls=[]
    def wrap(name):
        def call(*args,**kwargs):
            post=done.is_file();stage=None
            if name=='snapshot' and post:stage='source-after'
            if name=='source_origins' and post:stage='source-origins-after'
            if name=='output_map' and post:
                output_calls.append(True);stage='output-initial' if len(output_calls)==1 else 'output-final'
            if name=='write' and post:
                if Path(args[0]).name=='skip-reasons.json':stage='skip-reasons'
                if Path(args[0]).name=='terminal.json':stage='terminal-export'
            if name=='digest' and post and Path(args[0]).name=='executed-inputs.tar.gz':stage='archive-hash'
            if stage:attempts.append(stage)
            if stage==fault and not fired:
                fired.append(stage);raise OSError('controlled-'+fault)
            return originals[name](*args,**kwargs)
        return call
    for name in originals:monkeypatch.setattr(mod,name,wrap(name))
    assert mod.main()==1
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True and terminal['timed_out'] is False
    assert terminal['supervisor_error'] is not None and terminal['capture_errors']
    assert (out/'invocation/skip-reasons.json').exists()
    assert 'output-final' in attempts
    if fault in ('source-after','real-input-missing'):assert terminal['inputs_unchanged'] is False
    if fault=='source-origins-after':assert terminal['source_origins_unchanged'] is False
    if fault in ('output-initial','output-final'):assert terminal['outputs_unchanged'] is False


def test_primary_process_receipt_error_survives_later_capture_failures(tmp_path,monkeypatch):
    mod,out,done=setup_short_child(tmp_path,monkeypatch)
    write=mod.write;snapshot=mod.snapshot
    def fail_write(path,value):
        if Path(path).name=='process.json':
            time.sleep(0.1)  # Let the actual short child exit before receipt export fails.
            raise RuntimeError('primary-process-receipt-fault')
        return write(path,value)
    def fail_snapshot():
        if done.exists():raise OSError('secondary-after-source-fault')
        return snapshot()
    monkeypatch.setattr(mod,'write',fail_write);monkeypatch.setattr(mod,'snapshot',fail_snapshot)
    assert mod.main()==1
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True
    assert 'primary-process-receipt-fault' in terminal['supervisor_error']
    assert any('secondary-after-source-fault' in row['error'] for row in terminal['capture_errors'])


def test_absent_optional_top_is_empty_but_listed_source_disappearance_is_error(tmp_path,monkeypatch):
    mod,native=fake_root(tmp_path,monkeypatch)
    (tmp_path/'templates').rmdir()
    assert 'third_party/native/rtl.sv' in mod.snapshot()
    real_walk=os.walk
    def remove_listed(*args,**kwargs):
        for directory,dirs,files in real_walk(*args,**kwargs):
            if Path(directory)==native and 'rtl.sv' in files:
                (native/'rtl.sv').unlink()
            yield directory,dirs,files
    monkeypatch.setattr(mod.os,'walk',remove_listed)
    with pytest.raises(FileNotFoundError):mod.snapshot()


def test_actual_repository_enumeration_accepts_its_optional_missing_top():
    mod=supervisor()
    selected=set(mod.enumerate_inputs())
    assert ROOT/'src/myfuzz/composition/component_profile.py' in selected
    assert SUPERVISOR in selected
    assert Path(__file__).resolve() in selected


def test_unavailable_symlink_provenance_is_frozen_and_reappearance_is_drift(tmp_path,monkeypatch):
    mod,native=fake_root(tmp_path,monkeypatch)
    link=native/'.myfuzz-elaboration-missing.sv';link.symlink_to('missing-target.sv')
    available=mod.snapshot()
    missing=mod.unavailable_symlinks()
    key='third_party/native/.myfuzz-elaboration-missing.sv'
    assert key not in available
    assert missing[key]['is_symlink'] is True
    assert missing[key]['content_sha256'] is None and missing[key]['declared_source_file'] is False
    assert missing[key]['link_target']=='missing-target.sv'
    freeze=tmp_path/'freeze-with-missing-alias';mod.archive_inputs(freeze,available)
    assert json.loads((freeze/'unavailable-symlinks.json').read_bytes())==missing
    (native/'missing-target.sv').write_text('target appears')
    assert key in mod.snapshot() and mod.unavailable_symlinks()!=missing


def test_declared_source_with_unavailable_symlink_refuses(tmp_path,monkeypatch):
    mod,native=fake_root(tmp_path,monkeypatch)
    link=native/'explicit.sv';link.symlink_to('absent.sv')
    profile=tmp_path/'configs/component_profile.json';document=json.loads(profile.read_bytes())
    document['source']['files'].append('explicit.sv');profile.write_text(json.dumps(document))
    with pytest.raises(ValueError,match='declared source symlink'):
        mod.snapshot()


@pytest.mark.parametrize('change',['missing-native-skip','wrong-skip-module'])
def test_software_accepts_only_exact_five_declared_native_skips(tmp_path,monkeypatch,change):
    names=[f'test_native_control_{i}' for i in range(5)]
    selected=names[:-1] if change=='missing-native-skip' else names
    classname='tests.integration.test_compiled_f2_rfuzz_native' if change=='missing-native-skip' else 'tests.integration.unrelated'
    xml='<testsuite>'+''.join(f'<testcase classname="{classname}" name="{name}"><skipped message="MYFUZZ_RUN_NATIVE_F2_RFUZZ=1"/></testcase>' for name in selected)+'</testsuite>'
    mod,out,_=setup_short_child(tmp_path,monkeypatch,junit_xml=xml,native_names=names)
    assert mod.main()==1
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True and terminal['skip_policy_ok'] is False


def test_clean_short_child_is_accepted_with_no_native_module(tmp_path,monkeypatch):
    mod,out,_=setup_short_child(tmp_path,monkeypatch)
    assert mod.main()==0
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True and terminal['capture_errors']==[]
    assert terminal['inputs_unchanged'] and terminal['outputs_unchanged'] and terminal['unavailable_symlinks_unchanged']


@pytest.mark.parametrize('state',['available','missing'])
def test_actual_child_target_loss_or_reappearance_is_failed_provenance(tmp_path,monkeypatch,state):
    mod,out,_=setup_short_child(tmp_path,monkeypatch,alias_state=state,remove_source=state=='available')
    assert mod.main()==1
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True
    assert terminal['inputs_unchanged'] is False and terminal['unavailable_symlinks_unchanged'] is False
    assert any(row['stage']=='unavailable-symlink-drift' for row in terminal['capture_errors'])
    before=json.loads((out/'invocation/unavailable-symlinks-before.json').read_bytes())
    after=json.loads((out/'invocation/unavailable-symlinks-after.json').read_bytes())
    assert before!=after


def test_refusal_capture_failure_keeps_child_receipt_and_other_exports(tmp_path,monkeypatch):
    mod,out,_=setup_short_child(tmp_path,monkeypatch,expected=1)
    assert mod.main()==1
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['exit_code']==0 and terminal['reaped'] is True
    assert terminal['expected_refusal_validated'] is False
    assert any(row['stage']=='expected-refusal' and 'controlled-refusal-capture' in row['error'] for row in terminal['capture_errors'])
    assert (out/'invocation/output-final.json').exists() and (out/'invocation/skip-reasons.json').exists()


def test_exact_five_native_skips_are_accepted_in_software(tmp_path,monkeypatch):
    names=[f'test_native_control_{i}' for i in range(5)]
    xml='<testsuite>'+''.join(f'<testcase classname="tests.integration.test_compiled_f2_rfuzz_native" name="{name}"><skipped message="real RTL requires MYFUZZ_RUN_NATIVE_F2_RFUZZ=1"/></testcase>' for name in names)+'</testsuite>'
    mod,out,_=setup_short_child(tmp_path,monkeypatch,junit_xml=xml,native_names=names)
    assert mod.main()==0
    terminal=json.loads((out/'invocation/terminal.json').read_bytes())
    assert terminal['skip_policy_ok'] is True and terminal['skip_count']==5


def test_declared_external_design_and_include_neighbor_are_bounded_inputs(tmp_path,monkeypatch):
    mod,_=fake_root(tmp_path,monkeypatch)
    external=tmp_path/'external_designs/rvx/hardware';(external/'include').mkdir(parents=True)
    (external/'rvx_core.v').write_text('module registered_rvx; endmodule')
    (external/'include/defs.vh').write_text('registered include neighbor')
    (tmp_path/'configs/rvx_profile.json').write_text(json.dumps({
        'schema_version':'component_profile.v1','source':{'root':'external_designs/rvx/hardware',
            'files':['rvx_core.v'],'include_roots':['include']}}))
    (tmp_path/'configs/broad_unselected_profile.json').write_text(json.dumps({
        'schema_version':'component_profile.v1','source':{'root':'.','files':[],'include_roots':['.']}}))
    (tmp_path/'unbounded-cwd').mkdir();(tmp_path/'unbounded-cwd/not-an-input.sv').write_text('not a declared root')
    (tmp_path/'.superpowers/cache').mkdir();(tmp_path/'.superpowers/cache/not-an-input.sv').write_text('cache output')
    selected=mod.snapshot()
    assert {'external_designs/rvx/hardware/rvx_core.v','external_designs/rvx/hardware/include/defs.vh'}<=set(selected)
    assert 'unbounded-cwd/not-an-input.sv' not in selected and '.superpowers/cache/not-an-input.sv' not in selected


@pytest.mark.parametrize('relative_root',['src/myfuzz/protocols/rtl','src/myfuzz/integration/rtl'])
def test_profileless_generator_root_prunes_only_owned_scratch(tmp_path,monkeypatch,relative_root):
    mod,_=fake_root(tmp_path,monkeypatch)
    generated_root=tmp_path/relative_root;generated_root.mkdir(parents=True)
    (generated_root/'keep.sv').write_text('real generator source')
    hidden=generated_root/'.ordinary-hidden';hidden.mkdir();(hidden/'defs.vh').write_text('real hidden header')
    (generated_root/'.myfuzz-elaboration-source.sv').write_text('real prefixed file')
    (generated_root/'.myfuzz-elaboration-link.sv').symlink_to('keep.sv')
    static=generated_root/'.myfuzz-elaboration-static';static.mkdir();(static/'declared.sv').write_text('declared static source')
    # The profile declares a static input using source.root='.'; it does not
    # grant generator ownership to the module directory or recurse over ROOT.
    (tmp_path/'configs/static_generator_input.json').write_text(json.dumps({
        'schema_version':'component_profile.v1','source':{'root':'.',
            'files':[relative_root+'/.myfuzz-elaboration-static/declared.sv'],'include_roots':[]}}))
    scratch=generated_root/'.myfuzz-elaboration-generated';scratch.mkdir();(scratch/'manifest.json').write_text('{}')
    selected=mod.snapshot()
    assert relative_root+'/.myfuzz-elaboration-generated/manifest.json' not in selected
    assert {relative_root+'/'+name for name in ('keep.sv','.ordinary-hidden/defs.vh',
        '.myfuzz-elaboration-source.sv','.myfuzz-elaboration-link.sv',
        '.myfuzz-elaboration-static/declared.sv')}<=set(selected)
    shutil.rmtree(scratch)
    assert mod.snapshot()==selected


def test_actual_all_existing_declared_native_files_are_selected():
    mod=supervisor();selected=set(mod.enumerate_inputs())
    _,_,declared=mod._source_directory_policy()
    existing={path for path in declared if path.is_file() and path.is_relative_to(ROOT)}
    assert len(existing)>=521
    assert existing<=selected, sorted(str(p.relative_to(ROOT)) for p in existing-selected)
    assert ROOT/'external_designs/rvx/hardware/rvx_core.v' in selected
    assert ROOT/'src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv' in selected
    assert ROOT/'src/myfuzz/integration/rtl/riscv_boot_memory.sv' in selected
