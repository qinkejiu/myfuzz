import importlib.util
from pathlib import Path
import pytest


def module():
    path=Path(__file__).with_name('prepare.py');spec=importlib.util.spec_from_file_location('irq_attempt3_prepare',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def inputs(tmp_path,m):
    source=tmp_path/'source';overlay=tmp_path/'overlay';source.mkdir();overlay.mkdir()
    for name in m.ADDITIONS:
        for root,text in [(source,'old'),(overlay,'reviewed')]:
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    (source/'other').write_text('protected')
    return source,overlay


def test_exact_reviewed_two_file_replacement_preserves_finalized_source(tmp_path):
    m=module();source,overlay=inputs(tmp_path,m);before=m.control.inventory(source)
    overlay_map=m.control.inventory(overlay);target=tmp_path/'project'
    result=m.prepare_snapshot(source,target,before,overlay,overlay_map)
    assert result=={**before,**overlay_map} and len(result)==len(before)
    assert m.control.inventory(source)==before and m.control.inventory(target)==result
    assert all((source/n).stat().st_ino!=(target/n).stat().st_ino for n in before)
    with pytest.raises(ValueError):m.prepare_snapshot(source,target,before,overlay,overlay_map)


@pytest.mark.parametrize('fault',['extra','missing','changed','source','symlink'])
def test_overlay_fault_refuses_before_project_creation(tmp_path,fault):
    m=module();source,overlay=inputs(tmp_path,m);before=m.control.inventory(source);pin=m.control.inventory(overlay)
    first=overlay/m.ADDITIONS[0]
    if fault=='extra':(overlay/'extra').write_text('unreviewed')
    if fault=='missing':first.unlink()
    if fault=='changed':first.write_text('changed after freeze')
    if fault=='source':(source/'other').write_text('drift')
    if fault=='symlink':first.unlink();first.symlink_to(source/m.ADDITIONS[0])
    with pytest.raises(ValueError):m.prepare_snapshot(source,tmp_path/'project',before,overlay,pin)
    assert not (tmp_path/'project').exists() and not (tmp_path/'project.preparing').exists()


def test_ready_template_binds_actual_independent_budget_review():
    text=Path(__file__).with_name('prepare.py').read_text()
    assert "budget_fix_review_commit='5d3f290'" in text
    assert 'pending_source_review' not in text
