"""File identity refusals before any generated or native execution."""
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from myfuzz.integration.compiled_execution_files import (
    _source_paths, _hashes, _unchanged, run_compiled_execution_files,
)


def inputs(tmp_path):
    (tmp_path/'src/myfuzz').mkdir(parents=True)
    (tmp_path/'src/myfuzz/marker.py').write_text('# pinned\n')
    (tmp_path/'scripts').mkdir()
    (tmp_path/'scripts/run_compiled_dataflow.py').write_text('# pinned\n')
    (tmp_path/'native').mkdir()
    (tmp_path/'native/core.sv').write_text('module core; endmodule\n')
    profile=tmp_path/'profile.json'
    profile.write_text(json.dumps({'source':{'root':'native','files':['core.sv']}}))
    request=tmp_path/'request.json';request.write_text(json.dumps({'profile_path':'profile.json'}))
    compose=tmp_path/'compose.json'
    compose.write_text(json.dumps({'cpu':{'request':'request.json'},'devices':[]}))
    supplement=tmp_path/'supplement.json';supplement.write_text('{}')
    records=tmp_path/'records.json';records.write_text('["5500000078563412"]')
    return (tmp_path,compose,(),supplement,records)


@pytest.mark.parametrize('name',['compose.json','supplement.json','request.json','profile.json','native/core.sv'])
def test_retargeted_source_symlink_refused_before_execution(tmp_path,name):
    arguments=inputs(tmp_path);paths=_source_paths(*arguments);expected=_hashes(paths)
    original=tmp_path/name;alternate=tmp_path/('alternate-'+original.name)
    alternate.write_bytes(original.read_bytes())
    original.unlink();original.symlink_to(alternate)
    with pytest.raises(ValueError,match='source-symlink-refused'):
        _unchanged(paths,expected,arguments)


def test_added_declared_native_dependency_refused(tmp_path):
    arguments=inputs(tmp_path);paths=_source_paths(*arguments);expected=_hashes(paths)
    (tmp_path/'native/extra.sv').write_text('module extra; endmodule\n')
    (tmp_path/'profile.json').write_text(json.dumps({'source':{'root':'native','files':['core.sv','extra.sv']}}))
    with pytest.raises(ValueError,match='source-input-changed'):
        _unchanged(paths,expected,arguments)


def test_unsupported_executor_retains_incomplete_report_and_explicit_lock(tmp_path):
    output=tmp_path/'evidence';lock=tmp_path/'canonical-project/heavy.lock'
    with patch('myfuzz.integration.compiled_execution_files.create_compiled_execution',
               side_effect=AssertionError('must refuse before startup')):
        with pytest.raises(ValueError,match='executor-unsupported'):
            run_compiled_execution_files(base_dir=tmp_path,compose_path=tmp_path/'missing',
                capability_paths=(),supplement_path=tmp_path/'missing',records_path=tmp_path/'missing',
                output_dir=output,cache_dir=tmp_path/'cache',executor='unsupported',heavy_lock=lock)
    report=json.loads((output/'report.json').read_text())
    assert report['status']=='refused'
    assert report['heavy_lock']==str(lock.resolve())
    assert report['runtime_admitted'] is False
    assert (output/'.incomplete').is_file()
    assert not lock.exists()
