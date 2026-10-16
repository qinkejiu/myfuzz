import importlib.util
from pathlib import Path
import pytest


def module():
    path=Path(__file__).with_name('prepare.py')
    if not path.exists():pytest.fail('attempt2 preparation source missing')
    spec=importlib.util.spec_from_file_location('pure_irq_attempt2_prepare',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def test_copy_requires_exact_new_finalized_source_no_overlay(tmp_path):
    m=module();source=tmp_path/'finalized';source.mkdir();(source/'file').write_text('frozen source')
    expected=m.control.inventory(source);target=tmp_path/'project'
    m.prepare_snapshot(source,target,expected)
    assert m.control.inventory(target)==expected and m.control.inventory(source)==expected
    assert (source/'file').stat().st_ino!=(target/'file').stat().st_ino
    with pytest.raises(ValueError):m.prepare_snapshot(source,target,expected)


def test_wrong_source_rejected_without_creating_project(tmp_path):
    m=module();source=tmp_path/'source';source.mkdir();(source/'file').write_text('different')
    target=tmp_path/'project'
    with pytest.raises(ValueError):m.prepare_snapshot(source,target,{})
    assert not target.exists() and not target.with_name('project.preparing').exists()


def test_symlink_destination_parent_refused_without_protected_write(tmp_path):
    m=module();source=tmp_path/'source';source.mkdir();(source/'file').write_text('source')
    protected=tmp_path/'protected';protected.mkdir();link=tmp_path/'link';link.symlink_to(protected,target_is_directory=True)
    with pytest.raises(ValueError):m.prepare_snapshot(source,link/'project',m.control.inventory(source))
    assert list(protected.iterdir())==[]
