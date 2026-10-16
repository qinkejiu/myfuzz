"""Filelist/header source pin closure before any native process."""
import json
from unittest.mock import patch
import pytest
from tests.integration.test_compiled_execution_files import inputs
from myfuzz.integration.compiled_execution_files import _source_paths,_hashes,_unchanged


def declared(tmp_path):
    arguments=inputs(tmp_path);root=tmp_path/'native'
    (root/'inc').mkdir();(root/'inc/config.svh').write_text('`define VALUE 1\n')
    (root/'nested.f').write_text('+incdir+inc\n${RTL}/core.sv\n')
    (root/'main.f').write_text('-f nested.f\n')
    source=dict(root='native',revision='git:'+'0'*40,top_module='core',filelist='main.f',
        filelist_variables=[dict(name='RTL',value='.')])
    (tmp_path/'profile.json').write_text(json.dumps({'source':source}))
    return arguments


def test_nested_filelists_variables_and_headers_are_pinned(tmp_path):
    arguments=declared(tmp_path)
    with patch('subprocess.Popen',side_effect=AssertionError('source enumeration is pure')):
        paths=_source_paths(*arguments)
    assert {tmp_path/'native'/name for name in ('main.f','nested.f','core.sv','inc/config.svh')}<=set(paths)


@pytest.mark.parametrize('change',['nested','header','new-header','symlink'])
def test_filelist_closure_changes_refused_before_execution(tmp_path,change):
    arguments=declared(tmp_path);paths=_source_paths(*arguments);hashes=_hashes(paths)
    root=tmp_path/'native'
    if change=='nested':(root/'nested.f').write_text('+incdir+inc\ncore.sv\n// changed\n')
    elif change=='header':(root/'inc/config.svh').write_text('`define VALUE 2\n')
    elif change=='new-header':(root/'inc/new.inc').write_text('new header\n')
    else:
        (root/'copy.f').write_bytes((root/'nested.f').read_bytes());(root/'nested.f').unlink()
        (root/'nested.f').symlink_to('copy.f')
    with patch('subprocess.Popen',side_effect=AssertionError('no process')):
        with pytest.raises(ValueError):_unchanged(paths,hashes,arguments)


def test_actual_original_cv32_declaration_enumerates_without_processes():
    from pathlib import Path
    root=Path(__file__).resolve().parents[2];config=root/'configs/scenarios/compiled-f4-obi-apb'
    with patch('subprocess.Popen',side_effect=AssertionError('no source frontend/native')):
        paths=_source_paths(root,config/'compose.json',(config/'test_capability.json',),
            config/'execution_supplement.json',config/'example_records.json')
    assert root/'external_designs/cv32e40p/cv32e40p_manifest.flist' in paths
    assert root/'external_designs/cv32e40p/rtl/cv32e40p_core.sv' in paths


def test_boundary_source_failure_preserves_explicit_no_native_report(tmp_path):
    from types import SimpleNamespace
    from scripts.check_compiled_obi_no_error_boundary import run
    output=tmp_path/'new-evidence'
    args=SimpleNamespace(base_dir=tmp_path,output_dir=output,compose=tmp_path/'missing.json',
        ip_capability=[],supplement=tmp_path/'missing.json',heavy_lock=tmp_path/'lock')
    with patch('subprocess.Popen',side_effect=AssertionError('no native')):
        with pytest.raises(FileNotFoundError):run(args)
    report=json.loads((output/'report.json').read_text())
    assert report['native_executed'] is False and report['status']=='incomplete'
    assert report['error_type']=='FileNotFoundError'
    assert (output/'.incomplete').exists()
