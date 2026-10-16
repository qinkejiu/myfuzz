"""Controller filesystem/software controls; never operational recovery or model."""
import hashlib,importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest


def load(tmp_path):
    path=Path(__file__).with_name('control.py')
    spec=importlib.util.spec_from_file_location('isolated_metadata_control',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.BASE=tmp_path/'operation';module.BASE.mkdir();(module.BASE/'state').mkdir()
    module.SOURCE=module.BASE/'source';module.ORIGINAL=module.BASE/'original'
    module.PROJECT=module.BASE/'project-finalized';module.OUTPUT=module.BASE/'artifact-finalized'
    return module


def snapshot(root):
    return {str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*') if path.is_file()}


@pytest.mark.parametrize('existing',['PID','launcher-PID','worker.exit','operation.claim','project-finalized','artifact-finalized'])
def test_reuse_refused_without_mutating_any_prior_state_or_output(tmp_path,existing):
    module=load(tmp_path)
    if existing.endswith('finalized'):
        path=module.BASE/existing;path.mkdir();(path/'history').write_text('preserve')
    else:(module.BASE/'state'/existing).write_text('prior operation')
    before=snapshot(module.BASE)
    assert module.main()==125
    assert snapshot(module.BASE)==before


def test_claim_is_exclusive_and_second_claim_does_not_rewrite(tmp_path):
    module=load(tmp_path)
    module.claim()
    before=snapshot(module.BASE)
    with pytest.raises((ValueError,FileExistsError)):module.claim()
    assert snapshot(module.BASE)==before


def test_wrong_import_origin_refuses_before_recovery(tmp_path,monkeypatch):
    module=load(tmp_path)
    fake=SimpleNamespace(__file__=str(tmp_path/'wrong-library/helper.py'))
    monkeypatch.setattr(module.importlib,'import_module',lambda name:fake)
    with pytest.raises(ValueError,match='import origin'):
        module.checked_imports({})


def test_launcher_prioritizes_snapshot_and_does_not_overwrite_pid():
    text=Path(__file__).with_name('run-control.sh').read_text()
    line=next(line for line in text.splitlines() if line.startswith('export PYTHONPATH='))
    assert line.index('$base/source/src') < line.index('/root/fanzehui/system-20261016/pythonlib')
    assert '> "$base/state/launcher-PID"' not in text


def test_import_inside_snapshot_with_wrong_hash_refused(tmp_path,monkeypatch):
    module=load(tmp_path)
    file=module.SOURCE/'src/myfuzz/local_harness/boom_irq_recovery.py'
    file.parent.mkdir(parents=True);file.write_text('changed source')
    monkeypatch.setattr(module.importlib,'import_module',lambda name:SimpleNamespace(__file__=str(file)))
    with pytest.raises(ValueError,match='source hash'):
        module.checked_imports({str(file.relative_to(module.SOURCE)):'wrong hash'})


def test_host_factory_delta_and_native_implementation_contract(tmp_path):
    module=load(tmp_path)
    module.FAILED_PROJECT=tmp_path/'failed-project'
    old=module.FAILED_PROJECT/module.FACTORY;old.parent.mkdir(parents=True);old.write_bytes(b"fixture 'bound','gpio_irq' tail")
    new=module.SOURCE/module.FACTORY;new.parent.mkdir(parents=True);new.write_bytes(old.read_bytes().replace(b"'bound','gpio_irq'",b"'bound','gpio.irq'"))
    module.OLD_FACTORY=module.digest(old);module.NEW_FACTORY=module.digest(new)
    helper=module.SOURCE/'src/myfuzz/local_harness/boom_irq_recovery.py';helper.parent.mkdir(parents=True);helper.write_text('unchanged helper fixture')
    module.HELPER=module.digest(helper)
    native=helper.with_name('native.py');native.write_text('unchanged native fixture')
    artifact={'scenario_factory_sha256':module.OLD_FACTORY,'implementation_source_hashes':{'native.py':module.digest(native)}}
    module.host_factory_contract(artifact)
    native.write_text('changed native')
    with pytest.raises(ValueError,match='implementation'):module.host_factory_contract(artifact)
    native.write_text('unchanged native fixture');new.write_bytes(new.read_bytes()+b' extra behavior')
    with pytest.raises(ValueError,match='exact owner'):module.host_factory_contract(artifact)


def test_state_symlink_refused_before_any_history_write(tmp_path):
    module=load(tmp_path);old=tmp_path/'old-history';old.mkdir();(old/'receipt').write_text('preserve')
    (module.BASE/'state').rmdir();(module.BASE/'state').symlink_to(old,target_is_directory=True)
    before=snapshot(old)
    assert module.main()==125
    assert snapshot(old)==before


def test_receipt_symlink_or_existing_file_is_not_overwritten(tmp_path):
    module=load(tmp_path);old=tmp_path/'old-receipt';old.write_text('preserve')
    target=module.BASE/'state/source-before.json';target.symlink_to(old)
    with pytest.raises((ValueError,FileExistsError)):module.save('source-before.json',{'new':1})
    assert old.read_text()=='preserve'
    target.unlink();target.write_text('first receipt')
    with pytest.raises(FileExistsError):module.save('source-before.json',{'new':2})
    assert target.read_text()=='first receipt'
