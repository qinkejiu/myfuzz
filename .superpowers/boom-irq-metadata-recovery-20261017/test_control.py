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
