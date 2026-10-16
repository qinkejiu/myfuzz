"""Software fixtures only: no actual native/recovery/source constructor."""
import hashlib,importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest


def load(tmp_path):
    path=Path(__file__).with_name('controller.py')
    if not path.exists():pytest.fail('runtime controller missing')
    spec=importlib.util.spec_from_file_location('isolated_boom_irq_control',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.BASE=tmp_path/'operation';module.BASE.mkdir();(module.BASE/'state').mkdir()
    module.PROJECT=module.BASE/'project';module.OUTPUT=module.BASE/'gate-output';module.CACHE=module.BASE/'gpio-cache'
    module.ORIGINAL_SOURCE=tmp_path/'finalized-source';module.ARTIFACT=tmp_path/'finalized-artifact'
    return module


def snapshot(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('name',['PID','launcher-PID','worker.exit','operation.claim','native-PID','native.exit','gate-output','gpio-cache'])
def test_reuse_refuses_without_modifying_history(tmp_path,name):
    module=load(tmp_path)
    path=module.BASE/name if name in ('gate-output','gpio-cache') else module.BASE/'state'/name
    if name in ('gate-output','gpio-cache'):path.mkdir();(path/'old').write_text('preserve')
    else:path.write_text('old state')
    before=snapshot(module.BASE)
    assert module.main()==125
    assert snapshot(module.BASE)==before


def test_exclusive_claim(tmp_path):
    module=load(tmp_path);module.claim();before=snapshot(module.BASE)
    with pytest.raises((ValueError,FileExistsError)):module.claim()
    assert snapshot(module.BASE)==before


def test_origin_and_hash_checked_before_returning_native_api(tmp_path,monkeypatch):
    module=load(tmp_path)
    for path,expected in [(tmp_path/'elsewhere/module.py',{}),(module.PROJECT/'src/module.py',{'src/module.py':'bad'})]:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
        monkeypatch.setattr(module.importlib,'import_module',lambda name:SimpleNamespace(__file__=str(path)))
        with pytest.raises(ValueError):module.checked_imports(expected)


def test_inventory_rejects_symlinks_and_preserves_hashes(tmp_path):
    module=load(tmp_path);root=tmp_path/'source';root.mkdir();(root/'a').write_text('value')
    assert module.inventory(root)=={'a':hashlib.sha256(b'value').hexdigest()}
    (root/'link').symlink_to(root/'a')
    with pytest.raises(ValueError):module.inventory(root)


def test_launcher_is_source_first_and_has_no_build_or_overwriting_pid():
    path=Path(__file__).with_name('launch.sh')
    if not path.exists():pytest.fail('runtime launcher missing')
    text=path.read_text()
    assert '$base/project/src:$base/project:/root/fanzehui/system-20261016/pythonlib' in text
    assert '> "$base/state/launcher-PID"' not in text
    assert '--build' not in text and '--describe-probes' not in text


def test_copy_is_independent_and_exact(tmp_path):
    module=load(tmp_path);source=tmp_path/'source';source.mkdir();(source/'file').write_text('fixture')
    target=tmp_path/'target'
    module.copy_independent(source,target)
    assert module.inventory(source)==module.inventory(target)
    assert (target/'file').stat().st_nlink==1
    assert (source/'file').stat().st_ino!=(target/'file').stat().st_ino
    with pytest.raises(ValueError):module.copy_independent(source,target)


def test_tool_hash_scope_does_not_read_outside_allowed_root(tmp_path):
    module=load(tmp_path)
    with pytest.raises(ValueError):module.tool_inventory({'tools':{'outside':{'path':'/usr/bin/python3'}}})



def test_receipt_symlink_refused_without_touching_old_data(tmp_path):
    module=load(tmp_path);old=tmp_path/'old';old.write_text('preserve')
    (module.BASE/'state/before.json').symlink_to(old)
    with pytest.raises((ValueError,FileExistsError)):module.save('before.json',{'new':1})
    assert old.read_text()=='preserve'


def test_receipts_are_exclusive_and_state_parent_symlink_refused(tmp_path):
    module=load(tmp_path);module.save('receipt.json',{'old':1})
    with pytest.raises(FileExistsError):module.save('receipt.json',{'new':1})
    old=tmp_path/'old-tree';old.mkdir();(old/'sentinel').write_text('preserve')
    (module.BASE/'state/receipt.json').unlink();(module.BASE/'state').rmdir();(module.BASE/'state').symlink_to(old,target_is_directory=True)
    before=snapshot(old)
    assert module.main()==125
    assert snapshot(old)==before


@pytest.mark.parametrize('child_exit',[0,1])
def test_controller_collects_actual_child_fixture_exit_and_after_audit(tmp_path,monkeypatch,child_exit):
    """Fake process fixture; explicitly no model/subprocess construction."""
    import json
    module=load(tmp_path);(module.BASE/'logs').mkdir();module.PROJECT.mkdir();module.ARTIFACT.mkdir()
    (module.ARTIFACT/'irq-session-artifact.json').write_text(json.dumps({'build_origin':{'tool_identity':{}},'metadata_finalization':{'fixture':True}}))
    (module.BASE/'project-files.json').write_text(json.dumps({'files':{}}))
    (module.BASE/'source-freeze.json').write_text('{}')
    (module.BASE/'ready.json').write_text(json.dumps({'control_hashes':{},'freeze_sha256':'fixture','artifact_sha256':'fixture'}))
    audits=[]
    def audit(ready):audits.append('checked');return {'software_fixture':True}
    monkeypatch.setattr(module,'audit_inputs',audit)
    monkeypatch.setattr(module,'checked_imports',lambda expected:SimpleNamespace(verify_freeze=lambda *a:None))
    monkeypatch.setattr(module,'tool_inventory',lambda receipt:{'software_fixture':True})
    class Process:
        pid=123456
        def __init__(self,args,**kwargs):
            self.args=args;self.exit=None
            module.OUTPUT.mkdir();(module.OUTPUT/'summary.json').write_text(json.dumps({'status':'pass','source_authority':False,'isa_retirement_authority':False}))
        def wait(self):self.exit=child_exit;return self.exit
        def poll(self):return self.exit
    monkeypatch.setattr(module.subprocess,'Popen',Process)
    assert module.main()==child_exit
    assert (module.BASE/'state/native-PID').read_text().strip()=='123456'
    assert (module.BASE/'state/native.exit').read_text().strip()==str(child_exit)
    assert (module.BASE/'state/worker.exit').read_text().strip()==str(child_exit)
    assert audits==['checked','checked']
    assert json.loads((module.BASE/'state/child.json').read_text())['exit']==child_exit
