"""Finalize-only contracts. All native/generation work is forbidden or mocked."""
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'.superpowers/boom-irq-verification-20261017'


def test_actual_origin_receipts_keep_failed_stage_and_successful_build_separate():
    from myfuzz.local_harness.boom_irq_recovery import load_origin
    files,origin=load_origin(BASE)
    assert origin['build_exit']==0 and origin['probe_exit']==0
    assert origin['failed_stage_exit']==1
    assert origin['binary_sha256']=='6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90'
    assert len(origin['inventory'])==16


def test_command_contract_changes_only_declared_output_slots():
    from myfuzz.local_harness.boom_irq_recovery import build_argv, check_command
    command=build_argv(Path('/new-output'))
    check_command(command,Path('/new-output'))
    for index,value in ((0,'another-verilator'),(7,'OtherTop'),(command.index('2'),'4')):
        bad=list(command);bad[index]=value
        with pytest.raises(ValueError): check_command(bad,Path('/new-output'))


@pytest.fixture
def origin_fixture(tmp_path,monkeypatch):
    from myfuzz.local_harness import boom_irq_recovery as recovery
    from myfuzz.local_harness import boom_irq_generation as generation
    files,origin=recovery.load_origin(BASE)
    original=tmp_path/'original';original.mkdir()
    for name,data in files.items():
        if name.startswith('artifact/'):
            path=original/name.removeprefix('artifact/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    repo=tmp_path/'source'
    for scope in recovery.SCOPES:
        path=repo/scope;path.mkdir(parents=True,exist_ok=True);(path/'fixture.txt').write_text('software fixture')
    def canonical(repo,destination):
        destination.mkdir(parents=True,exist_ok=True)
        for name in recovery.INPUTS: (destination/name).write_bytes(files['artifact/'+name])
        return {'command':recovery.build_argv(destination),'simulator':origin['tool_identity']['version'],
            'implementation_source_hashes':{'boom_irq_generation.py':'new-generation-fixture','boom_irq_cpu_session.py':'new-session-fixture'}}
    monkeypatch.setattr(generation,'generate_irq',canonical)
    monkeypatch.setattr(recovery,'_tool_identity',lambda receipt:None)
    monkeypatch.setattr(generation.subprocess,'run',lambda *a,**k:pytest.fail('native/build invoked'))
    return recovery,repo,original,tmp_path/'new-project',tmp_path/'new-output',files,origin


def invoke(fixture):
    module,repo,original,project,output,*_=fixture
    return module.recover_metadata(repo=repo,original_output=original,
        project_destination=project,output_destination=output,archives=BASE)


def test_metadata_only_positive_with_actual_receipts_and_mocked_source_tool_auth(origin_fixture):
    import os
    recovery,repo,original,project,output,files,origin=origin_fixture
    artifact=invoke(origin_fixture)
    assert artifact['build_origin']['failed_stage_exit']==1
    assert artifact['metadata_finalization']['new_cpp_build'] is False
    assert artifact['runtime_verified'] is False and artifact['source_authority'] is False
    assert not (output/'.recovery-incomplete.json').exists()
    assert not (original/'irq-session-artifact.json').exists()
    assert not os.path.samestat((original/'obj/VBoomTile').stat(),(output/'obj/VBoomTile').stat())
    assert recovery.validate_recovery_origin(output,artifact)


@pytest.mark.parametrize('name',['driver.cpp','EICG_wrapper.v','irq-profile.json','passive_probes.vlt',
    'obj/VBoomTile','generated-probes.json','probe-describe.stdout','build.exit','probe-describe.exit',
    'obj/VBoomTile__Syms__Slow.cpp','obj/VBoomTile_classes.mk','obj/VBoomTile__Syms__Slow.d'])
def test_changed_original_is_refused_with_incomplete_marker(origin_fixture,name):
    recovery,repo,original,project,output,*_=origin_fixture
    (original/name).write_bytes(b'changed historical input/receipt')
    with pytest.raises(ValueError,match='original build'):
        invoke(origin_fixture)
    assert (output/'.recovery-incomplete.json').exists()
    assert not (output/'irq-session-artifact.json').exists()
    assert not project.exists()


def test_existing_destination_and_ancestor_symlink_rejected_before_mutation(origin_fixture,tmp_path):
    recovery,repo,original,project,output,*_=origin_fixture
    output.mkdir();(output/'history').write_text('keep')
    with pytest.raises(ValueError,match='new'): invoke(origin_fixture)
    assert (output/'history').read_text()=='keep'
    link=tmp_path/'alias';link.symlink_to(repo,target_is_directory=True)
    with pytest.raises(ValueError,match='symlink'):
        recovery.recover_metadata(repo=link,original_output=original,
            project_destination=project,output_destination=tmp_path/'other-output',archives=BASE)


def test_linked_copy_is_rejected_before_manifest(origin_fixture,monkeypatch):
    import os
    recovery,repo,original,project,output,*_=origin_fixture
    monkeypatch.setattr(recovery.shutil,'copy2',lambda source,target:os.link(source,target))
    with pytest.raises(ValueError,match='shared'):invoke(origin_fixture)
    assert (output/'.recovery-incomplete.json').exists()
    assert not (output/'irq-session-artifact.json').exists()


def test_wrong_effective_flags_refused_before_manifest(origin_fixture,monkeypatch):
    from myfuzz.local_harness import boom_irq_generation as generation
    recovery,repo,original,project,output,*_=origin_fixture
    canonical=generation.generate_irq
    def changed(*args):
        artifact=canonical(*args);artifact['command'][7]='WrongTop';return artifact
    monkeypatch.setattr(generation,'generate_irq',changed)
    with pytest.raises(ValueError,match='flags'):invoke(origin_fixture)
    assert (output/'.recovery-incomplete.json').exists()
    assert not (output/'irq-session-artifact.json').exists()


@pytest.mark.parametrize('mutation',['stage_exit','new_cpp','runtime','old_python','inventory','receipt_hash','binary'])
def test_constructor_origin_contract_rejects_rehashed_or_unknown_claims(origin_fixture,mutation):
    import copy
    recovery,repo,original,project,output,*_=origin_fixture
    artifact=copy.deepcopy(invoke(origin_fixture))
    if mutation=='stage_exit':artifact['build_origin']['failed_stage_exit']=0
    if mutation=='new_cpp':artifact['metadata_finalization']['new_cpp_build']=True
    if mutation=='runtime':artifact['runtime_verified']=True
    if mutation=='old_python':
        artifact['implementation_source_hashes']['boom_irq_generation.py']=artifact['build_origin']['original_python_hashes']['src/myfuzz/local_harness/boom_irq_generation.py']
    if mutation=='inventory':artifact['generated_probes'][0]['width']=2
    if mutation=='receipt_hash':artifact['session_files']['recovery-receipts/attempt2-evidence.tar.gz']='changed'
    if mutation=='binary':
        (output/'obj/VBoomTile').write_bytes(b'changed');artifact['session_files']['obj/VBoomTile']=recovery.sha(b'changed')
    with pytest.raises(ValueError):recovery.validate_recovery_origin(output,artifact)


def test_atomic_publication_does_not_overwrite_existing_manifest(origin_fixture,monkeypatch):
    recovery,repo,original,project,output,*_=origin_fixture
    real_link=recovery.os.link
    def collision(source,target):
        target.write_text('concurrent historical manifest')
        return real_link(source,target)
    monkeypatch.setattr(recovery.os,'link',collision)
    with pytest.raises(FileExistsError):invoke(origin_fixture)
    assert (output/'irq-session-artifact.json').read_text()=='concurrent historical manifest'
    assert (output/'.recovery-incomplete.json').exists()


def test_real_current_source_authentication_matches_saved_compiled_inputs(origin_fixture,monkeypatch):
    # Only tool path/version are mocked because no Verilator is installed locally.
    # Actual current source/port/profile authentication and every effective input
    # comparison run. No compiler/model command may execute.
    from myfuzz.local_harness import boom_irq_generation as generation
    from myfuzz.local_harness import tilelink_coherent_cpu_session as baseline
    recovery,repo,original,project,output,files,origin=origin_fixture
    import importlib
    real_generate=importlib.reload(generation).generate_irq
    monkeypatch.setattr(generation,'generate_irq',real_generate)
    monkeypatch.setattr(baseline.subprocess,'check_output',lambda *a,**k:origin['tool_identity']['version'])
    artifact=recovery.recover_metadata(repo=ROOT,original_output=original,
        project_destination=project,output_destination=output,archives=BASE)
    assert artifact['implementation_source_hashes']['boom_irq_recovery.py']==recovery.sha(Path(recovery.__file__).read_bytes())
    assert artifact['build_origin']['effective_inputs']['driver.cpp']==artifact['driver_sha256']
    assert recovery.validate_recovery_origin(output,artifact)
    # The real constructor must reject changed origin before process launch.
    import json
    from myfuzz.local_harness import boom_irq_cpu_session as native
    bad=json.loads((output/'irq-session-artifact.json').read_text())
    bad['build_origin']['failed_stage_exit']=0
    (output/'irq-session-artifact.json').write_text(json.dumps(bad))
    monkeypatch.setattr(native.subprocess,'Popen',lambda *a,**k:pytest.fail('bad origin launched model'))
    with pytest.raises(ValueError,match='origin/metadata'):
        native.GeneratedBoomIrqCpuSession(output,repo=project)


@pytest.mark.parametrize('name',['driver.cpp','tl_ram.h','EICG_wrapper.v','irq-profile.json',
                                 'passive_probes.vlt','boom_irq_probe_specs.h'])
def test_changed_current_effective_input_refuses_binary_reuse(origin_fixture,monkeypatch,name):
    from myfuzz.local_harness import boom_irq_generation as generation
    recovery,repo,original,project,output,*_=origin_fixture
    canonical=generation.generate_irq
    def changed(repo,destination):
        artifact=canonical(repo,destination);(destination/name).write_bytes(b'new compiled input');return artifact
    monkeypatch.setattr(generation,'generate_irq',changed)
    with pytest.raises(ValueError,match='compiled input'):invoke(origin_fixture)
    assert (output/'.recovery-incomplete.json').exists()
    assert not (output/'irq-session-artifact.json').exists()


def test_different_tool_version_refuses_metadata_reuse(origin_fixture,monkeypatch):
    from myfuzz.local_harness import boom_irq_generation as generation
    recovery,repo,original,project,output,*_=origin_fixture
    canonical=generation.generate_irq
    def changed(*args):
        artifact=canonical(*args);artifact['simulator']='different tool';return artifact
    monkeypatch.setattr(generation,'generate_irq',changed)
    with pytest.raises(ValueError,match='version'):invoke(origin_fixture)
    assert not (output/'irq-session-artifact.json').exists()


def test_tool_wrapper_path_mismatch_refused_before_tool_read(monkeypatch):
    from myfuzz.local_harness import boom_irq_recovery as recovery
    files,origin=recovery.load_origin(BASE)
    monkeypatch.setattr(recovery.shutil,'which',lambda name:'/other/tool')
    with pytest.raises(ValueError,match='path'):recovery._tool_identity(origin['tool_identity'])


def test_pinned_archive_tamper_refused_without_model(tmp_path):
    from myfuzz.local_harness import boom_irq_recovery as recovery
    (tmp_path/'attempt2-evidence.tar.gz').write_bytes(b'forged')
    with pytest.raises(ValueError,match='archive'):recovery.load_origin(tmp_path)
