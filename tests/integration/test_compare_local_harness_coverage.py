"""Synthetic unit controls; these are not measurements of a real harness."""
from copy import deepcopy
from hashlib import sha256
import json

import pytest

from scripts.compare_local_harness_coverage import compare_runs, load_run, parse_commands
from myfuzz.local_harness.coverage import parse_verilator_coverage


def evidence():
    return {
        'build_digest': 'a' * 64,
        'binary_sha256': 'b' * 64,
        'coverage_kind': 'verilator-line-block',
        'build_argv': ['verilator', '--coverage-line', '{RUN}/inputs/design.sv'],
        'source_sha256': {'design.sv': 'c' * 64},
        'points': {'point-1': 1, 'point-2': 0},
        'dut_points': {'point-1': 1},
        'dut_sources': ['design.sv'],
        'commands': {'count': 2, 'lengths_bytes': [12, 13], 'local_ticks': 3},
    }


def test_full_point_universe_includes_zero_counts_and_unknown_budgets():
    left = evidence()
    right = deepcopy(left)
    right['points'] = {'point-1': 0, 'point-2': 4}
    right['commands']['count'] = 3
    result = compare_runs(left, right)
    assert result['status'] == 'comparable_points'
    assert result['coverage']['total_points'] == 2
    assert result['coverage']['left_hit_points'] == 1
    assert result['coverage']['right_hit_points'] == 1
    assert result['dut_coverage']['total_points'] == 1
    assert result['dut_coverage']['left_hit_points'] == 1
    assert result['conditions']['same_command_count'] is False
    assert result['conditions']['seed'] == 'unknown'
    assert result['conditions']['time_budget'] == 'unknown'
    assert result['conditions']['fairness'] == 'unknown'
    assert result['conditions']['process_independence'] == 'unknown'


@pytest.mark.parametrize('field', ['build_digest', 'binary_sha256', 'coverage_kind',
                                   'build_argv', 'source_sha256', 'points'])
def test_different_identity_or_point_universe_refuses(field):
    left = evidence()
    right = deepcopy(left)
    if field == 'points':
        del right['points']['point-2']
    else:
        right[field] = 'different'
    result = compare_runs(left, right)
    assert result['status'] == 'incomparable'
    assert result['coverage'] is None
    assert field in result['reasons']


def test_command_count_comes_from_actual_sequential_records():
    nonce = '0' * 32
    text = f'CMD {nonce} 1 READ 0\nCMD {nonce} 2 READ 1\nEND\n'
    rows = parse_commands(text)
    assert len(rows) == 2
    assert [row[2] for row in rows] == ['1', '2']
    with pytest.raises(ValueError):
        parse_commands(text.replace(' 2 READ', ' 3 READ'))
    with pytest.raises(ValueError):
        parse_commands(text.replace('END\n', ''))


def test_command_parser_accepts_full_session_across_ack_boundary():
    execution = 'a' * 32
    text = ''.join(f'CMD {execution} {index:x} STEP_WB_REG\n'
                   for index in range(1, 18)) + 'END\n'
    assert len(parse_commands(text)) == 17


def synthetic_run(root):
    """Create a synthetic wire and coverage record for parser controls only."""
    (root / 'inputs/generated').mkdir(parents=True)
    (root / 'obj').mkdir()
    source = root / 'inputs/generated/example.sv'
    source.write_text('module example; endmodule\n')
    (root / 'inputs/generated/driver.cpp').write_text('synthetic driver\n')
    (root / 'obj/harness').write_bytes(b'synthetic binary')
    artifact = {'artifact_digest': 'd' * 64, 'driver_reset': {
        'reset_assert_ticks': 1, 'reset_release_ticks': 1}, 'kind': 'example'}
    (root / 'inputs/generated/artifact.json').write_text(json.dumps(artifact))
    fields = {'f': str(source), 'l': '2', 'n': '1', 't': 'line',
              'page': 'v_line/example', 'o': 'block', 'h': 'TOP.example'}
    point = ''.join('\x01' + key + '\x02' + value for key, value in fields.items())
    (root / 'coverage.dat').write_text("# SystemC::Coverage-3\nC '" + point + "' 0\n")
    nonce = '0' * 32
    (root / 'commands.txt').write_text(f'CMD {nonce} 1 READ 0\nEND\n')
    payload = {'schema_version': 'local_driver_result.v1', 'kind': 'example',
               'samples': [], 'observations': {}, 'pre_backend': {}, 'rdata': 0, 'error': 0}
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode().hex()
    (root / 'replies.txt').write_text(f"READY local_driver.v1 {'d'*64} 1 1\nRESULT {nonce} 1 0 0 {encoded}\n")
    digest = lambda path: sha256(path.read_bytes()).hexdigest()
    metadata = {'schema_version': 'local_harness_verilator_coverage.v1',
        'coverage_kind': 'verilator-line-block', 'original_build_digest': 'a' * 64,
        'original_binary_sha256': 'b' * 64,
        'coverage_data_sha256': digest(root / 'coverage.dat'),
        'coverage_binary_sha256': digest(root / 'obj/harness'),
        'instrumented_driver_sha256': digest(root / 'inputs/generated/driver.cpp'),
        'build_argv': ['verilator', '--coverage-line', str(source)],
        'replay': {'identical_stdout': True, 'result_count': 1, 'local_ticks': 0}}
    (root / 'coverage.json').write_text(json.dumps(metadata))


def test_saved_files_are_parsed_and_changed_coverage_is_refused(tmp_path):
    synthetic_run(tmp_path)
    run = load_run(tmp_path)
    assert list(run['points'].values()) == [0]
    assert run['commands']['count'] == 1
    (tmp_path / 'coverage.dat').write_text('changed')
    with pytest.raises(ValueError, match='file-hash-mismatch'):
        load_run(tmp_path)


def test_actual_command_count_must_match_recorded_replay(tmp_path):
    synthetic_run(tmp_path)
    metadata_path = tmp_path / 'coverage.json'
    metadata = json.loads(metadata_path.read_text())
    metadata['replay']['result_count'] = 2
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match='recorded-replay-mismatch'):
        load_run(tmp_path)


def test_different_dut_source_sets_are_not_comparable():
    left = evidence()
    right = deepcopy(left)
    right['dut_sources'] = ['other.sv']
    result = compare_runs(left, right)
    assert result['status'] == 'incomparable'
    assert 'dut_sources' in result['reasons']
    assert result['dut_coverage'] is None


def test_rejects_rehashed_derived_points_that_disagree_with_raw_data(tmp_path):
    synthetic_run(tmp_path)
    row = parse_verilator_coverage((tmp_path / 'coverage.dat').read_text())[0]
    row.update(normalized_source='generated/example.sv', source_sha256=sha256(
        (tmp_path / 'inputs/generated/example.sv').read_bytes()).hexdigest())
    document = {'schema_version': 'local_verilator_points.v1', 'all_points': [row],
                'selected_source_files': [], 'dut_points': []}
    path = tmp_path / 'coverage-points.json'
    path.write_text(json.dumps(document))
    metadata_path = tmp_path / 'coverage.json'
    meta = json.loads(metadata_path.read_text())
    meta['coverage_points_sha256'] = sha256(path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(meta))
    assert list(load_run(tmp_path)['points'].values()) == [0]
    document['all_points'][0]['count'] = 10
    path.write_text(json.dumps(document))
    meta['coverage_points_sha256'] = sha256(path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(meta))
    with pytest.raises(ValueError, match='saved-coverage-points-mismatch'):
        load_run(tmp_path)


def test_long_command_file_needs_explicit_budget_without_truncation():
    text=''.join(f"CMD {'a'*32} {i:x} STEP_WB_REG\n" for i in range(1,514))+'END\n'
    with pytest.raises(ValueError,match='command-count'):parse_commands(text)
    assert len(parse_commands(text,max_commands=600))==513


def test_saved_budget_cannot_authorize_more_than_requested(tmp_path):
    synthetic_run(tmp_path)
    meta=json.loads((tmp_path/'coverage.json').read_text())
    meta['replay_budget']={'max_commands':600,'max_input_bytes':64*1024*1024,
        'max_output_bytes':64*1024*1024,'max_wall_seconds':300}
    meta['replay_seconds']={'plain':120,'instrumented':120}
    (tmp_path/'coverage.json').write_text(json.dumps(meta))
    with pytest.raises(ValueError,match='wall-budget'):load_run(tmp_path)
    assert load_run(tmp_path,max_wall_seconds=300)['commands']['count']==1
    with pytest.raises(ValueError,match='output-byte-budget'):
        load_run(tmp_path,max_wall_seconds=300,max_output_bytes=10)
    meta['replay_budget']['max_commands']=65537
    (tmp_path/'coverage.json').write_text(json.dumps(meta))
    with pytest.raises(ValueError,match='max_commands'):load_run(tmp_path,max_wall_seconds=300)
