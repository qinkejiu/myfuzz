import importlib.util
import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]


def module():
    path = ROOT/'scripts/attach_search_coverage.py'
    assert path.exists(), 'coverage attachment implementation missing'
    spec = importlib.util.spec_from_file_location('attach_search_coverage', path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def make_inputs(tmp_path, monkeypatch):
    m = module()
    digest, binary, nonce = 'a'*64, 'b'*64, 'c'*32
    search, measurement, cache = tmp_path/'search', tmp_path/'measurement', tmp_path/digest
    search.mkdir(); measurement.mkdir(); cache.mkdir()
    command = f'CMD {nonce} 1 STEP_GPIO 0'
    reply = f'RESULT {nonce} 1 0 1 ab'
    (search/'summary.json').write_text(json.dumps({'native_authority':False,'metrics':{},
                                                 'budget_overrun_seconds':2}))
    trace = {'schema_version':'local_command_trace.v1', 'sessions':{'gpio_b': {
        'complete':True, 'identity': {'component':'gpio_b','build_digest':digest,
                                     'binary_sha256':binary,'execution_nonce':nonce},
        'records':[{'sequence':1,'reset_epoch':0,'command':command,'reply':reply}]}}}
    (search/'local-commands.json').write_text(json.dumps(trace))
    (measurement/'coverage.dat').write_bytes(b'verified by reused validator')
    (measurement/'commands.txt').write_text(command+'\nEND\n')
    (measurement/'replies.txt').write_text('READY ignored\n'+reply+'\n')
    validated = {'build_digest':digest,'binary_sha256':binary,'cache_verified':True,
                 'dut_points':{'point-a':0,'point-b':3}, 'coverage_kind':'verilator-line-block'}
    def load_run(path, *, cache):
        if Path(cache).name != digest:
            raise ValueError('original-build-identity-mismatch')
        return validated
    monkeypatch.setattr(m, 'load_run', load_run)
    return m,search,measurement,cache,trace


def args(search, measurement, cache, output, component='gpio_b'):
    return ['--search',str(search),'--measurement',str(measurement),'--cache',str(cache),
            '--component',component,'--output',str(output)]


def test_attach_verified_points_to_new_summary(tmp_path, monkeypatch):
    m,search,measurement,cache,_ = make_inputs(tmp_path, monkeypatch)
    original = (search/'summary.json').read_bytes()
    output = tmp_path/'attached.json'
    assert m.main(args(search,measurement,cache,output)) == 0
    row = json.loads(output.read_text())
    assert row['coverage']['covered'] == 1
    assert row['coverage']['total'] == 2
    assert row['coverage']['metric'] == 'verilator-line-block:gpio_b:dut'
    assert row['coverage']['online'] is False
    assert row['coverage']['includes_budget_overrun'] is True
    assert row['native_authority'] is False
    assert row['metrics']['coverage'] == row['coverage']
    assert (search/'summary.json').read_bytes() == original
    assert m.main(args(search,measurement,cache,output)) == 2


def test_reject_component_cache_and_trace_mismatches(tmp_path, monkeypatch):
    m,search,measurement,cache,trace = make_inputs(tmp_path, monkeypatch)
    output = tmp_path/'not-created.json'
    assert m.main(args(search,measurement,cache,output,'gpio_a')) == 2
    assert m.main(args(search,measurement,tmp_path/'wrong-cache',output)) == 2
    trace['sessions']['gpio_b']['records'][0]['command'] += ' changed'
    (search/'local-commands.json').write_text(json.dumps(trace))
    assert m.main(args(search,measurement,cache,output)) == 2
    trace['sessions']['gpio_b']['records'][0]['command'] = (measurement/'commands.txt').read_text().splitlines()[0]
    trace['sessions']['gpio_b']['records'][0]['reply'] += ' changed'
    (search/'local-commands.json').write_text(json.dumps(trace))
    assert m.main(args(search,measurement,cache,output)) == 2
    assert not output.exists()


def test_standard_sidecar_and_underscore_commands_preserve_unknown_metrics(tmp_path, monkeypatch):
    m,search,measurement,cache,_ = make_inputs(tmp_path, monkeypatch)
    (search/'search-summary.json').write_text(json.dumps({'metrics':{'certified_events':None},
        'identity':{'coverage_metric':None},'status':'completed'}))
    (search/'local-commands.json').rename(search/'local_commands.json')
    row = m.attach(search,'gpio_b',measurement,cache)
    assert row['metrics']['certified_events'] is None
    assert row['coverage']['attestation'] == 'recorded-prefix-replay.v1'
    assert Path(row['coverage']['search_summary']).name == 'search-summary.json'
    assert row['identity']['coverage_metric'] is None
