"""Pure-Python coverage of the Step E phase measurement; no RTL, no Verilator.

Every fact these tests touch is one of: the compact line format the three
in-process loops print, the JSON documents the entries write, the byte
inventory of an output directory, the wall-clock anchors taken from file
mtimes, or the A/B comparison that must ignore measured durations.  Nothing
here builds a model or starts a spike.
"""
import json
import os
import time
from pathlib import Path

import pytest

from scripts import measure_inprocess_phases as measure

FIVE_LOG = (
    'NEED_RECORD 0 tick 0\n'
    'CASE_INSTALLED 0\n'
    'mmio 49 write 40001004 0\n'
    'irq_source 72\n'
    'irq_take 77\n'
    'case 0 observations_passed irq_sources 1 takes 1 result 0\n'
    'NEED_RECORD 1 tick 134\n'
    'case 1 observations_passed irq_sources 1 takes 1 result 31\n'
    'NEED_RECORD 2 tick 231\n'
    'summary observations_passed cases 2 ticks 231 irqs 1 takes 1 writes 3 reads 1'
    ' result 31 apb_transfers 4 mret 1 successor 1 runtime_seconds 0.00256222\n'
)

F1F4_LOG = (
    'NEED_RECORD 0 tick 0\n'
    'retire 160 0x0001106c 0xf9dff06f\n'
    'case 0 observations_passed flow F1 record F1:2ab00693 ticks 47 seconds 0.000119303'
    ' i_fetches 24 d_reads 1 d_writes 1 apb_reads 0 apb_writes 0 fetch 0x12000'
    ' retire_pc 0x12000 retire_insn 0x2ab00693 successor_pc 0x12004\n'
    'case 1 observations_passed flow F4 record F4:40001008:0fffffff ticks 36'
    ' seconds 0.000103182 i_fetches 15 d_reads 2 d_writes 2 apb_reads 0 apb_writes 1'
    ' mmio_addr 0x40001008 mmio_value 0x0fffffff apb_offset 0x00000008'
    ' apb_pwdata 0x0fffffff apb_pready 1\n'
    'summary observations_passed cases 2 ticks 193 instruction_fetches 91 ram_reads 12'
    ' ram_writes 8 apb_transfers 2 apb_reads 1 apb_writes 1 ip_irq_high_ticks 0'
    ' irq_delivery unknown instruction_fetch_evidence observed retirement_evidence observed'
    ' runtime_seconds 0.003456646\n'
)


def _row(**overrides):
    """One recorded run, shaped exactly like ``run_class`` returns it."""
    row = dict(class_name='F5', label='F5 example', flow='F5', mode='hot',
               repetition=1, input_count=2, output='/nonexistent',
               returncode=0, wall_seconds=11.5, cpu_seconds=9.0, maxrss_kb=150000,
               artifact_bytes=497245,
               open_errors=[],
               delegate=dict(status='observations_passed'),
               log=dict(cases=2, summary_status='observations_passed'),
               phases=dict(wall=11.5, python_prepare=0.3, product_prepare=1.5,
                           link=0.02, run=0.006, write_and_exit=5.7,
                           body_span_seconds=5.5, body_minus_total=0.0,
                           closure_residual=0.0),
               inventory=dict(files=[], total_bytes=0, by_category={}),
               model_init=dict(seconds=None, bound_seconds=None, reason='not printed'),
               status=dict(status='observations_passed', reasons=[]))
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- #
# Compact log parsing
# --------------------------------------------------------------------------- #
def test_parse_run_log_reads_f5_case_and_summary_rows():
    parsed = measure.parse_run_log(FIVE_LOG)
    assert len(parsed['cases']) == 2
    assert parsed['cases'][0]['takes'] == 1
    assert parsed['cases'][1]['result'] == 31
    assert parsed['summary']['ticks'] == 231
    assert parsed['summary']['runtime_seconds'] == pytest.approx(0.00256222)
    assert parsed['requests'] == 3
    assert parsed['summary']['status'] == 'observations_passed'


def test_parse_run_log_reads_f1f4_rows_with_hex_and_seconds():
    parsed = measure.parse_run_log(F1F4_LOG)
    assert [row['flow'] for row in parsed['cases']] == ['F1', 'F4']
    assert parsed['cases'][0]['seconds'] == pytest.approx(0.000119303)
    assert parsed['cases'][0]['fetch'] == 0x12000
    assert parsed['cases'][1]['mmio_addr'] == 0x40001008
    assert parsed['cases'][1]['apb_pready'] == 1
    assert parsed['summary']['runtime_seconds'] == pytest.approx(0.003456646)


def test_parse_run_log_keeps_transport_lines_out_of_the_numbers():
    parsed = measure.parse_run_log(FIVE_LOG)
    assert 'mmio' not in json.dumps(parsed['cases'])
    assert 'CASE_INSTALLED' not in json.dumps(parsed)


def test_parse_run_log_rejects_a_duplicate_summary_line():
    with pytest.raises(ValueError):
        measure.parse_run_log('summary observations_passed cases 1\n'
                             'summary observations_passed cases 1\n')


def test_parse_run_log_requires_text():
    with pytest.raises(ValueError):
        measure.parse_run_log(None)


def test_parse_run_log_tolerates_blank_and_odd_lines():
    parsed = measure.parse_run_log('\n   \nsummary failed cases\n')
    assert parsed['cases'] == []
    assert parsed['summary']['cases'] is None
    assert parsed['summary']['status'] == 'failed'


def test_value_parses_hex_float_integer_and_text():
    assert measure._value('231') == 231
    assert measure._value('0x0fffffff') == 0x0fffffff
    assert measure._value('-0x10') == -16
    assert measure._value('0.0025') == pytest.approx(0.0025)
    assert measure._value('observations_passed') == 'observations_passed'


def test_pairs_maps_a_trailing_key_to_none():
    assert measure._pairs(['a', '1', 'b']) == {'a': 1, 'b': None}


# --------------------------------------------------------------------------- #
# F1-F4 case seconds and the model-init bound
# --------------------------------------------------------------------------- #
def test_case_seconds_keeps_unknown_rows_as_none():
    document = {'cases': [{'seconds': 0.001}, {'ticks': 4}, {'seconds': 0.002}]}
    assert measure.case_seconds(document) == [0.001, None, 0.002]
    assert measure.case_seconds({}) == []


def test_model_init_bound_subtracts_the_measured_case_spans():
    assert measure.model_init_bound(0.0034, [0.0001, 0.0001]) == pytest.approx(0.0032)


def test_model_init_bound_is_unknown_without_per_case_spans():
    assert measure.model_init_bound(0.0025, []) is None
    assert measure.model_init_bound(0.0025, [0.001, None]) is None
    assert measure.model_init_bound(None, [0.001]) is None


def test_model_init_bound_never_returns_a_negative_bound():
    assert measure.model_init_bound(0.001, [0.002, 0.002]) == 0.0


# --------------------------------------------------------------------------- #
# Phase split
# --------------------------------------------------------------------------- #
def test_phase_segments_closes_back_to_the_measured_wall():
    phases = measure.phase_segments(wall=11.5, launch_to_first=0.3, body=5.5, tail=5.7,
                                    total_seconds=5.5, link_seconds=0.02, run_seconds=0.006)
    assert phases['python_prepare'] == pytest.approx(0.3)
    assert phases['product_prepare'] == pytest.approx(5.474)
    assert phases['link'] == pytest.approx(0.02)
    assert phases['run'] == pytest.approx(0.006)
    assert phases['write_and_exit'] == pytest.approx(5.7)
    assert phases['closure_residual'] == pytest.approx(0.0, abs=1e-9)


def test_phase_segments_leave_missing_inputs_unknown_instead_of_guessing():
    phases = measure.phase_segments(wall=11.5, launch_to_first=0.3, body=None, tail=5.7,
                                    total_seconds=None, link_seconds=None,
                                    run_seconds=None)
    assert phases['product_prepare'] is None
    assert phases['link'] is None
    assert phases['run'] is None
    assert phases['closure_residual'] is None


def test_phase_segments_keeps_the_body_and_total_cross_check():
    phases = measure.phase_segments(wall=6.0, launch_to_first=0.3, body=5.5, tail=0.2,
                                    total_seconds=5.4, link_seconds=0.02, run_seconds=0.006)
    assert phases['body_minus_total'] == pytest.approx(0.1)


# --------------------------------------------------------------------------- #
# Artifact inventory
# --------------------------------------------------------------------------- #
def test_artifact_inventory_reports_categories_and_exact_bytes(tmp_path):
    (tmp_path / 'summary.json').write_text('{"a": 1}\n')
    (tmp_path / 'flow_summary.json').write_text('{}\n')
    (tmp_path / 'run.log').write_text('summary observations_passed\n')
    (tmp_path / 'firmware.txt').write_text('10000 00\n')
    (tmp_path / 'spike_config.h').write_text('#define X 1\n')
    (tmp_path / 'cpu_request.json').write_text('{}\n')
    (tmp_path / 'inprocess-spike').write_bytes(b'\x7fELF' + bytes(60))
    inventory = measure.artifact_inventory(tmp_path)
    assert set(inventory['by_category']) == {
        'summary', 'flow_summary', 'run_log', 'firmware', 'binding', 'request', 'executable'}
    assert inventory['total_bytes'] == sum(row['bytes'] for row in inventory['files'])
    assert inventory['by_category']['executable'] == 64


def test_file_category_maps_the_five_asked_for_artifacts():
    assert measure.file_category('summary.json') == 'summary'
    assert measure.file_category('flow_summary.json') == 'flow_summary'
    assert measure.file_category('run.log') == 'run_log'
    assert measure.file_category('firmware.txt') == 'firmware'
    assert measure.file_category('f6_binding.h') == 'binding'
    assert measure.file_category('source_request.json') == 'request'
    assert measure.file_category('mystery.bin') == 'other'


# --------------------------------------------------------------------------- #
# Wall-clock anchors from file mtimes
# --------------------------------------------------------------------------- #
def test_mtime_anchors_split_python_prep_body_and_tail(tmp_path):
    now = time.time()
    first = tmp_path / 'cpu_request.json'
    first.write_text('{}')
    summary = tmp_path / 'summary.json'
    summary.write_text('{}')
    flow = tmp_path / 'flow_summary.json'
    flow.write_text('{}')
    os.utime(first, (now + 0.30, now + 0.30))
    os.utime(summary, (now + 5.30, now + 5.30))
    os.utime(flow, (now + 11.40, now + 11.40))
    anchors = measure.mtime_anchors(tmp_path, started_wall=now, ended_wall=now + 11.5)
    assert anchors['first_file'] == 'cpu_request.json'
    assert anchors['launch_to_first'] == pytest.approx(0.30, abs=0.01)
    assert anchors['body'] == pytest.approx(5.00, abs=0.01)
    assert anchors['tail'] == pytest.approx(6.20, abs=0.01)
    assert anchors['tail_from_flow'] == pytest.approx(0.10, abs=0.01)


def test_mtime_anchors_do_not_treat_flow_summary_as_the_first_file(tmp_path):
    now = time.time()
    first = tmp_path / 'source_request.json'
    first.write_text('{}')
    log = tmp_path / 'run.log'
    log.write_text('summary\n')
    flow = tmp_path / 'flow_summary.json'
    flow.write_text('{}')
    os.utime(first, (now + 0.2, now + 0.2))
    os.utime(log, (now + 5.0, now + 5.0))
    os.utime(flow, (now + 9.0, now + 9.0))
    anchors = measure.mtime_anchors(tmp_path, started_wall=now, ended_wall=now + 9.1)
    assert anchors['first_file'] == 'source_request.json'
    assert anchors['flow_summary_wall'] == pytest.approx(now + 9.0, abs=0.01)


def test_mtime_anchors_report_unknown_for_an_empty_directory(tmp_path):
    anchors = measure.mtime_anchors(tmp_path, started_wall=time.time(),
                                    ended_wall=time.time())
    assert anchors['launch_to_first'] is None
    assert anchors['body'] is None
    assert anchors['tail'] is None


# --------------------------------------------------------------------------- #
# Command lines: the entries are called exactly as documented
# --------------------------------------------------------------------------- #
def test_entry_argv_for_f5_online_and_f6_preloaded():
    f5 = measure.entry_argv(measure.CLASSES['F5'], cache='c', output='o', python='py')
    assert f5[:2] == ['py', str(measure.ROOT / 'scripts/run_inprocess_flow.py')]
    assert f5[f5.index('--flow') + 1] == 'F5'
    assert '--online' in f5 and '--records' not in f5
    f6 = measure.entry_argv(measure.CLASSES['F6'], cache='c', output='o', python='py')
    assert f6[f6.index('--flow') + 1] == 'F6'
    assert f6[f6.index('--records') + 1] == '0110c00008000000,0530c00110000000'
    assert '--online' not in f6 and '--assume-lockstep' in f6


def test_entry_argv_for_f1f4_passes_two_records_to_its_own_entry():
    argv = measure.entry_argv(measure.CLASSES['F1F4'], cache='c', output='o', python='py')
    assert argv[1].endswith('scripts/run_inprocess_f1f4.py')
    assert argv[argv.index('--records') + 1] == 'F1:2ab00693,F4:40001008:0fffffff'
    assert '--flow' not in argv


def test_stdin_payload_only_exists_for_the_online_loop():
    assert measure.stdin_payload(measure.CLASSES['F5']) == (
        b'0,0,0xffffffff\n1,0,0xfffffffe\nEND\n')
    assert measure.stdin_payload(measure.CLASSES['F6']) is None
    assert measure.stdin_payload(measure.CLASSES['F1F4']) is None


def test_spike_stdin_formats_the_online_case_lines():
    assert measure.spike_stdin(measure.CLASSES['F5']) == (
        b'CASE 00000000 00000000 ffffffff\nCASE 00000001 00000000 fffffffe\n')
    assert measure.spike_stdin(measure.CLASSES['F6']) is None


def test_delegate_argv_targets_the_real_loop_and_refuses_the_thin_entry():
    argv = measure.delegate_argv(measure.CLASSES['F5'], cache='c', output='o', python='py')
    assert argv[1].endswith('scripts/run_inprocess_irq.py')
    assert argv[argv.index('--max-ticks') + 1] == '3000'
    argv = measure.delegate_argv(measure.CLASSES['F6'], cache='c', output='o', python='py')
    assert argv[1].endswith('scripts/run_inprocess_f6.py')
    with pytest.raises(ValueError):
        measure.delegate_argv(dict(measure.CLASSES['F5'],
                                  delegate='scripts/run_inprocess_flow.py'),
                              cache='c', output='o')


def test_class_inputs_are_exactly_two_cases_per_class():
    for name, spec in measure.CLASSES.items():
        assert len(spec['inputs']) == 2, name


# --------------------------------------------------------------------------- #
# Status and grouping
# --------------------------------------------------------------------------- #
def test_run_status_requires_a_case_line_per_input():
    row = _row()
    assert measure._run_status(row)['status'] == 'observations_passed'
    row['log'] = dict(cases=1, summary_status='observations_passed')
    verdict = measure._run_status(row)
    assert verdict['status'] == 'failed'
    assert 'case lines' in verdict['reasons'][0]


def test_run_status_reports_every_observed_problem():
    row = _row(returncode=1, open_errors=[('summary.json', 'missing')],
               delegate=dict(status=None), log=dict(cases=0, summary_status='failed'))
    reasons = measure._run_status(row)['reasons']
    assert len(reasons) == 5


def test_group_runs_splits_by_class_and_cache_state():
    grouped = measure.group_runs([_row(mode='cold'), _row(mode='hot'),
                                  _row(class_name='F6', mode='hot')])
    assert sorted(grouped) == [('F5', 'cold'), ('F5', 'hot'), ('F6', 'hot')]


def test_median_row_ignores_unknown_values():
    rows = [_row(wall_seconds=10.0), _row(wall_seconds=12.0), _row(wall_seconds=None)]
    assert measure.median_row(rows, 'wall_seconds') == pytest.approx(11.0)
    assert measure.median_row(rows, 'maxrss_kb') == 150000


def test_rows_round_trip_through_measurements_json(tmp_path):
    runs = [_row(class_name='F5', mode='cold')]
    path = measure.save_rows(tmp_path, runs)
    assert path.is_file()
    document = json.loads(path.read_text())
    assert document['schema_version'] == 'inprocess_phase_measurement.v1'
    assert measure.load_rows(tmp_path) == runs
    assert measure.load_rows(tmp_path / 'missing') == []


# --------------------------------------------------------------------------- #
# A/B comparison: durations are the only allowed difference
# --------------------------------------------------------------------------- #
def test_without_timings_strips_seconds_recursively():
    document = {'link_seconds': 1.0, 'cases': [{'seconds': 0.1, 'ticks': 47}],
                'nested': {'preparation_seconds': 3.0, 'status': 'ok'}}
    assert measure.without_timings(document) == {
        'cases': [{'ticks': 47}], 'nested': {'status': 'ok'}}


def test_document_differences_names_every_changed_path():
    left = {'a': 1, 'b': [1, 2], 'c': {'d': 'x'}}
    right = {'a': 2, 'b': [1, 2, 3], 'c': {'d': 'x'}}
    paths = [row[0] for row in measure.document_differences(left, right)]
    assert '$/a' in paths
    assert '$/b' in paths
    assert measure.document_differences(left, left) == []


def test_normalize_run_log_drops_only_measured_durations():
    text = 'case 0 observations_passed ticks 47 seconds 0.0001\nsummary ok runtime_seconds 0.003\n'
    normalized = measure.normalize_run_log(text)
    assert '0.0001' not in normalized
    assert '0.003' not in normalized
    assert 'ticks 47' in normalized
    assert 'case 0 observations_passed' in normalized


def test_work_differences_ignores_timings_but_sees_a_real_change(tmp_path):
    baseline, candidate = tmp_path / 'a', tmp_path / 'b'
    for directory, runtime, result in ((baseline, 0.0021, 31), (candidate, 0.0026, 31)):
        directory.mkdir()
        (directory / 'summary.json').write_text(json.dumps(
            {'status': 'observations_passed', 'link_seconds': 0.02,
             'builds': [{'preparation_seconds': runtime}]}))
        (directory / 'run.log').write_text(
            'case 0 observations_passed takes 1 result %d\n'
            'summary observations_passed cases 1 runtime_seconds %s\n' % (result, runtime))
    assert measure.work_differences(baseline, candidate) == []
    (candidate / 'run.log').write_text(
        'case 0 observations_passed takes 1 result 30\n'
        'summary observations_passed cases 1 runtime_seconds 0.0026\n')
    paths = [row[0] for row in measure.work_differences(baseline, candidate)]
    assert '$/run.log/cases[0]/result' in paths


def test_policies_cover_the_default_and_the_entry_only_candidate():
    assert measure.POLICIES['entry-and-exit'] is True
    assert measure.POLICIES['entry-only'] is False


def test_observed_work_separates_observations_from_durations(tmp_path):
    output = tmp_path / 'run'
    output.mkdir()
    (output / 'summary.json').write_text(json.dumps({'status': 'observations_passed',
                                                     'total_seconds': 5.5}))
    (output / 'run.log').write_text('case 0 observations_passed ticks 47\n'
                                    'summary observations_passed cases 1 ticks 47\n')
    work = measure.observed_work(output)
    assert work['cases'] == 1
    assert work['ticks'] == 47
    assert work['status'] == 'observations_passed'


# --------------------------------------------------------------------------- #
# Output-write re-measurement and the report renderer
# --------------------------------------------------------------------------- #
def test_remeasure_writes_reproduces_the_json_bytes_exactly(tmp_path):
    output = tmp_path / 'run'
    output.mkdir()
    document = {'status': 'observations_passed', 'cases': [{'seconds': 0.1}]}
    (output / 'summary.json').write_text(json.dumps(document, indent=2) + '\n')
    (output / 'run.log').write_text('summary observations_passed\n')
    run = _row(output=str(output), inventory=measure.artifact_inventory(output))
    result = measure.remeasure_writes(run, scratch=tmp_path / 'scratch')
    rows = {row['name']: row for row in result['files']}
    assert rows['summary.json']['compact'] is True
    assert rows['summary.json']['parse_seconds'] is not None
    assert rows['summary.json']['render_seconds'] is not None
    assert rows['run.log']['compact'] is None
    assert result['total']['timing_seconds'] > 0


def test_remeasure_writes_skips_a_missing_output_directory(tmp_path):
    run = _row(output=str(tmp_path / 'gone'), inventory={'files': [
        dict(name='summary.json', bytes=1, category='summary')], 'total_bytes': 1,
        'by_category': {'summary': 1}})
    result = measure.remeasure_writes(run, scratch=tmp_path / 'scratch')
    assert result['files'] == []
    assert result['total']['timing_seconds'] == 0.0


def test_report_markdown_carries_the_phase_table_and_every_run():
    document = dict(observation_scope='compact', environment=dict(
        cpu_model='x', cpu_count=8, python='3.12.3'),
        runs=[_row(mode='cold'), _row(mode='hot'), _row(class_name='F6', mode='hot')],
        attribution=[dict(class_name='F5', events={
            'execution_validation_scope[exit]': dict(count=1, sum=5.6, max=5.6)})],
        ab_policy=[dict(class_name='F5', repetition=1, identical_work=True,
                        identical_run_log=True, wall_saving_seconds=5.4,
                        arms={'entry-and-exit': dict(wall_seconds=11.5),
                              'entry-only': dict(wall_seconds=6.1)})],
        write_inventory=[dict(class_name='F5', mode='hot', result=dict(
            files=[dict()], total=dict(bytes=497245, parse_seconds=0.1,
                                       render_seconds=0.2, write_seconds=0.3)))])
    report = measure.report_markdown(document)
    assert '| class | cache | wall |' in report
    assert '| F1F4 |' not in report  # only the classes that were actually run
    phase_rows = [line for line in report.splitlines()
                  if line.startswith('| F5 | cold |') and 'observations_passed' in line]
    assert len(phase_rows) == 1
    assert '| unknown |' in phase_rows[0]   # the model-init column stays unknown
    assert 'DUT detail' in report and 'model init' in report
    assert 'execution_validation_scope[exit]' in report
    assert 'entry-only' in report


def test_main_requires_an_action(tmp_path):
    with pytest.raises(SystemExit):
        measure.main(['--workdir', str(tmp_path)])


def test_main_rejects_an_unknown_class(tmp_path):
    with pytest.raises(SystemExit):
        measure.main(['--workdir', str(tmp_path), '--mode', 'hot', '--classes', 'F9'])


def test_main_refuses_a_hot_run_without_the_cold_cache(tmp_path):
    with pytest.raises(SystemExit) as error:
        measure.main(['--workdir', str(tmp_path), '--mode', 'hot', '--classes', 'F5'])
    assert 'cold cache' in str(error.value.code)


def test_collect_does_not_fail_a_class_that_writes_no_flow_summary(tmp_path):
    """F1-F4 has its own entry and never writes flow_summary.json."""
    output = tmp_path / 'F1F4-hot-r1'
    output.mkdir()
    (output / 'summary.json').write_text(json.dumps({
        'status': 'observations_passed', 'returncode': 0, 'link_seconds': 0.02,
        'run_seconds': 0.005, 'total_seconds': 5.4,
        'cases': [{'seconds': 0.0001}, {'seconds': 0.0001}]}))
    (output / 'run.log').write_text(
        'case 0 observations_passed flow F1 ticks 47 seconds 0.0001\n'
        'case 1 observations_passed flow F4 ticks 46 seconds 0.0001\n'
        'summary observations_passed cases 2 ticks 92 runtime_seconds 0.0015\n')
    row = dict(class_name='F1F4', mode='hot', output=str(output), wall_seconds=9.0,
               returncode=0, input_count=2, anchors=measure.mtime_anchors(
                   output, started_wall=time.time() - 9, ended_wall=time.time()),
               cache=str(tmp_path / 'cache'), cache_state='hot',
               flow_summary_required=False)
    collected = measure.collect(row)
    assert collected['open_errors'] == []
    assert measure._run_status(collected)['status'] == 'observations_passed'
    assert collected['log']['case_seconds_sum'] == pytest.approx(0.0002)
    assert collected['model_init']['bound_seconds'] == pytest.approx(0.0013)


def test_collect_still_fails_the_thin_entry_without_a_flow_summary(tmp_path):
    output = tmp_path / 'F5-hot-r1'
    output.mkdir()
    (output / 'summary.json').write_text(json.dumps({
        'status': 'observations_passed', 'returncode': 0, 'link_seconds': 0.02,
        'run_seconds': 0.005, 'total_seconds': 5.4}))
    (output / 'run.log').write_text('case 0 observations_passed ticks 47\n'
                                    'summary observations_passed cases 1 ticks 47\n')
    row = dict(class_name='F5', mode='hot', output=str(output), wall_seconds=9.0,
               returncode=0, input_count=2, anchors=measure.mtime_anchors(
                   output, started_wall=time.time() - 9, ended_wall=time.time()),
               cache=str(tmp_path / 'cache'), cache_state='hot',
               flow_summary_required=True)
    collected = measure.collect(row)
    assert collected['open_errors'] == [('flow_summary.json', 'missing')]
    assert measure._run_status(collected)['status'] == 'failed'


def test_phase_segments_anchor_product_prepare_on_the_measured_span():
    """F6 spends ~1.5 s before its first artifact; anchoring keeps it additive."""
    phases = measure.phase_segments(wall=24.1, launch_to_first=1.8, body=16.7,
                                    tail=5.6, total_seconds=18.2, link_seconds=5.1,
                                    run_seconds=0.005)
    assert phases['product_prepare'] == pytest.approx(11.595)
    assert phases['delegate_clock_gap'] == pytest.approx(1.5)
    assert phases['closure_residual'] == pytest.approx(0.0, abs=1e-9)


def test_recompute_phases_uses_the_stored_anchors_only():
    row = _row(anchors=dict(launch_to_first=0.3, body=5.5, tail=5.7),
               delegate=dict(status='observations_passed', total_seconds=5.5,
                             link_seconds=0.02, run_seconds=0.006))
    recomputed = measure.recompute_phases(row)
    assert recomputed['phases']['python_prepare'] == pytest.approx(0.3)
    assert recomputed['phases']['product_prepare'] == pytest.approx(5.474)
    assert recomputed['phases']['closure_residual'] == pytest.approx(0.0, abs=1e-9)


def test_mtime_anchors_ignore_a_file_copied_with_its_old_timestamp(tmp_path):
    """``shutil.copy2`` keeps the cache binary's timestamp on a warm run."""
    now = time.time()
    binary = tmp_path / 'inprocess-spike'
    binary.write_bytes(b'\x7fELF')
    os.utime(binary, (now - 900.0, now - 900.0))
    first = tmp_path / 'source_request.json'
    first.write_text('{}')
    summary = tmp_path / 'summary.json'
    summary.write_text('{}')
    os.utime(first, (now + 0.3, now + 0.3))
    os.utime(summary, (now + 5.3, now + 5.3))
    anchors = measure.mtime_anchors(tmp_path, started_wall=now, ended_wall=now + 11.5)
    assert anchors['first_file'] == 'source_request.json'
    assert anchors['launch_to_first'] == pytest.approx(0.3, abs=0.01)
    assert anchors['body'] == pytest.approx(5.0, abs=0.01)
    assert anchors['ignored_old_files'] == ['inprocess-spike']


def test_recompute_row_refreshes_the_anchors_of_a_live_directory(tmp_path):
    now = time.time()
    output = tmp_path / 'run'
    output.mkdir()
    (output / 'cpu_request.json').write_text('{}')
    os.utime(output / 'cpu_request.json', (now + 0.3, now + 0.3))
    (output / 'summary.json').write_text('{"total_seconds": 5.0}')
    os.utime(output / 'summary.json', (now + 5.3, now + 5.3))
    row = _row(output=str(output), started_wall=now, ended_wall=now + 11.5,
               anchors=dict(launch_to_first=0.0, body=999.0, tail=0.0),
               delegate=dict(status='observations_passed', total_seconds=5.0,
                             link_seconds=0.02, run_seconds=0.005))
    refreshed = measure.recompute_phases(measure.recompute_row(row))
    assert refreshed['phases']['python_prepare'] == pytest.approx(0.3, abs=0.01)
    assert refreshed['phases']['product_prepare'] == pytest.approx(4.975, abs=0.01)


def test_mtime_anchors_flag_a_realtime_clock_step(tmp_path):
    """The host clock steps ~0.8 s now and then; the split must stay additive."""
    now = time.time()
    first = tmp_path / 'source_request.json'
    first.write_text('{}')
    summary = tmp_path / 'summary.json'
    summary.write_text('{}')
    os.utime(first, (now + 0.3, now + 0.3))
    os.utime(summary, (now + 5.3, now + 5.3))
    # monotonic says the run took 6.1 s, realtime only 5.3 s: a -0.8 s step
    anchors = measure.mtime_anchors(tmp_path, started_wall=now, ended_wall=now + 5.3,
                                    wall_seconds=6.1)
    assert anchors['clock_step_seconds'] == pytest.approx(-0.8, abs=0.01)
    assert anchors['anchors_trusted'] is False
    assert anchors['body'] == pytest.approx(6.1 - 0.3 - (5.3 - 5.3), abs=0.01)


def test_mtime_anchors_are_trusted_without_a_step(tmp_path):
    now = time.time()
    (tmp_path / 'cpu_request.json').write_text('{}')
    (tmp_path / 'summary.json').write_text('{}')
    os.utime(tmp_path / 'cpu_request.json', (now + 0.3, now + 0.3))
    os.utime(tmp_path / 'summary.json', (now + 5.3, now + 5.3))
    anchors = measure.mtime_anchors(tmp_path, started_wall=now, ended_wall=now + 11.5,
                                    wall_seconds=11.5)
    assert anchors['clock_step_seconds'] == pytest.approx(0.0, abs=1e-6)
    assert anchors['anchors_trusted'] is True
    assert anchors['body'] == pytest.approx(5.0, abs=0.01)


def test_replace_flag_is_accepted_for_a_repeated_run(tmp_path):
    parser = measure._parser()
    args = parser.parse_args(['--workdir', str(tmp_path), '--mode', 'cold', '--replace'])
    assert args.replace is True
    assert parser.parse_args(['--workdir', str(tmp_path)]).replace is False


def test_retries_default_and_replace_flag_are_parsed(tmp_path):
    parser = measure._parser()
    args = parser.parse_args(['--workdir', str(tmp_path), '--mode', 'hot'])
    assert args.retries == 2
    assert args.replace is False


def test_cold_retry_rebuilds_the_cache(tmp_path, monkeypatch):
    """A repeated cold run must delete the cache the first attempt created."""
    calls = []
    monkeypatch.setattr(measure, 'run_class',
                        lambda name, *, workdir, cache, cache_state, output, repetition,
                        python=None: _fake_cold_run(cache, output, calls))
    cache = tmp_path / 'cache-F5'
    cache.mkdir()
    (cache / 'model.bin').write_text('built')
    measure.main(['--workdir', str(tmp_path), '--mode', 'cold', '--classes', 'F5',
                  '--replace', '--retries', '1'])
    # attempt 1 deleted the pre-existing cache, attempt 2 rebuilt and then deleted it
    assert len(calls) == 2
    assert calls[0]['cache_present'] is False
    assert calls[1]['cache_present'] is False


def _fake_cold_run(cache, output, calls):
    cache = Path(cache)
    calls.append(dict(cache_present=cache.exists()))
    cache.mkdir(parents=True, exist_ok=True)
    (cache / 'model.bin').write_text('built')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').write_text('{"status": "observations_passed"}')
    trusted = len(calls) > 1
    return dict(class_name='F5', mode='cold', repetition=1, output=str(output),
                wall_seconds=1.0, cpu_seconds=0.5, maxrss_kb=1000, artifact_bytes=1,
                returncode=0, input_count=2, open_errors=[],
                delegate=dict(status='observations_passed', link_seconds=0.1,
                              run_seconds=0.01, total_seconds=0.2),
                log=dict(cases=2, summary_status='observations_passed'),
                anchors=dict(launch_to_first=0.1, body=0.2, tail=0.7,
                             clock_step_seconds=None if trusted else -0.8,
                             anchors_trusted=trusted),
                phases=measure.phase_segments(wall=1.0, launch_to_first=0.1, body=0.2,
                                              tail=0.7, total_seconds=0.2,
                                              link_seconds=0.1, run_seconds=0.01),
                inventory=dict(files=[], total_bytes=0, by_category={}),
                cache=dict(path=str(cache), state='cold', bytes=0),
                model_init=dict(seconds=None, bound_seconds=None, reason='not printed'),
               status=dict(status='observations_passed', reasons=[]))


def test_source_state_changes_when_a_dependency_changes():
    first = measure.source_state()
    assert isinstance(first, str) and len(first) == 64
    assert measure.source_state() == first


def test_observed_cache_reports_what_the_build_receipts_say():
    observed = measure.observed_cache({
        'link_cache_hit': True,
        'builds': [{'preparation_seconds': 2.931}, {'preparation_seconds': 0.36}]})
    assert observed['link_cache_hit'] is True
    assert observed['models'] == 2
    assert observed['build_preparation_seconds'] == [2.931, 0.36]
    assert measure.observed_cache({}) == dict(link_cache_hit=None, models=0,
                                              build_preparation_seconds=[])


def test_recompute_row_refreshes_the_log_and_the_model_init_bound(tmp_path):
    output = tmp_path / 'run'
    output.mkdir()
    (output / 'summary.json').write_text(json.dumps({
        'status': 'observations_passed',
        'cases': [{'seconds': 0.0001}, {'seconds': 0.0001}]}))
    (output / 'run.log').write_text(
        'case 0 observations_passed flow F1 ticks 47 seconds 0.0001\n'
        'case 1 observations_passed flow F4 ticks 46 seconds 0.0001\n'
        'summary observations_passed cases 2 ticks 92 runtime_seconds 0.0015\n')
    row = _row(class_name='F1F4', output=str(output), input_count=2,
               log=dict(cases=None, summary_status=None),
               model_init=dict(seconds=None, bound_seconds=None, reason='stale'))
    refreshed = measure.recompute_row(row)
    assert refreshed['log']['ticks'] == 92
    assert refreshed['log']['case_seconds_sum'] == pytest.approx(0.0002)
    assert refreshed['model_init']['bound_seconds'] == pytest.approx(0.0013)


def test_report_states_that_proposals_are_not_applied():
    report = measure.report_markdown(dict(runs=[_row()], environment={},
                                          observation_scope='compact'))
    assert 'Proposals (measured, not applied' in report
    assert 'Comparability record' in report
    assert 'execution_validation_scope(revalidate=False)' in report.replace('`', '')
