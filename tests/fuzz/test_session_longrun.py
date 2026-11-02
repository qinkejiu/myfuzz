"""Long-run tests for the fuzz session driver: no RTL, no Verilator.

A fake Python host speaks the same ``NEED_RECORD``/``case``/``summary``
protocol as the C++ host, so the session's long-run behaviour is exercised
without a model: a 10k or 50k case batch must keep the retained rows bounded
while the rolling aggregates stay exact; a host that stops talking must be
reported as stalled instead of hanging the run; a time budget must end even
when the host is slow or silent; the buffered log must still contain every line
after the session closes; and the fake host must be the same process for the
whole batch.
"""
import json
import time

from myfuzz.fuzz.corpus import Corpus
from myfuzz.fuzz.feedback import FeedbackState
from myfuzz.fuzz.session import (DEFAULT_LOG_FLUSH_SECONDS,
                                 DEFAULT_MAX_CASES_RECORDED,
                                 DEFAULT_MAX_FINDINGS,
                                 DEFAULT_MAX_SUBMITTED_RECORDED,
                                 DEFAULT_STALL_SECONDS, SessionBudget,
                                 run_session)
from myfuzz.fuzz.strategy import Input
from scripts.run_inprocess_f1f6 import parse_case_line, parse_summary_line

HOST = '''\
import os
import sys
import time

cases = int(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else 'normal'
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0

sys.stdout.write('hostpid %d\\n' % os.getpid())
sys.stdout.flush()

if mode == 'silent':
    time.sleep(3600)
    raise SystemExit(0)

if mode == 'nosummary':
    print('NEED_RECORD 0 tick 0', flush=True)
    raise SystemExit(1)

if mode == 'stuck_case':
    print('NEED_RECORD 0 tick 0', flush=True)
    sys.stdin.readline()
    print('CASE_INSTALLED 0', flush=True)
    time.sleep(3600)
    raise SystemExit(0)

if mode == 'needonly':
    for index in range(1_000_000):
        print('NEED_RECORD %d tick %d' % (index, index), flush=True)
        line = sys.stdin.readline()
        if not line or line.strip() == 'END':
            break
    print('summary observations_passed cases 0', flush=True)
    raise SystemExit(0)

if mode == 'lastcase':
    print('NEED_RECORD 0 tick 0', flush=True)
    sys.stdin.readline()
    sys.stdout.write(
        'CASE_INSTALLED 0\\n'
        'case 0 observations_passed flow F2 record F2:00014000 '
        'read_addr 0x00014000 read_value 0x00000000 echo_value 0x00000000 '
        'read_from ram target_reads 0 i_fetches 1 d_reads 1 d_writes 0 '
        'apb_reads 0 apb_writes 0 retires 1 ticks 3 seconds 0.001\\n')
    sys.stdout.flush()
    raise SystemExit(0)

for index in range(cases):
    if delay and index:
        time.sleep(delay)
    print('NEED_RECORD %d tick %d' % (index, index * 10), flush=True)
    line = sys.stdin.readline()
    if not line or line.strip() == 'END':
        break
    status = ('failed'
              if mode == 'failall' or index % 3 == 0
              else 'observations_passed')
    sys.stdout.write(
        'CASE_INSTALLED %d\\n' % index +
        'case %d %s flow F2 record F2:000140%02x '
        'read_addr 0x00014000 read_value 0x00000000 echo_value 0x00000000 '
        'read_from ram target_reads 0 i_fetches 1 d_reads 1 d_writes 0 '
        'apb_reads 0 apb_writes 0 retires 1 ticks 7 seconds 0.001\\n'
        % (index, status, index % 100))
    sys.stdout.flush()
print('summary %s cases %d' % (
    'failed' if mode == 'failall' or cases % 3 == 0 else 'observations_passed',
    cases), flush=True)
if mode == 'failall':
    raise SystemExit(1)
'''


class StubStrategy:
    flows = ('F2',)

    def __init__(self):
        self.generated = 0

    def seed_inputs(self):
        return []

    def next_input(self):
        self.generated += 1
        address = 0x14000 + 4 * (self.generated % 4)
        text = 'F2:%08x' % address
        return Input(flow='F2', fields=(address,), text=text,
                     message='CASE F2 %08x' % address)


def host_command(tmp_path, cases, mode='normal', delay=0.0):
    path = tmp_path / 'host.py'
    path.write_text(HOST)
    return ['python3', str(path), str(cases), mode, str(delay)]


def run(tmp_path, *, host_cases, mode='normal', delay=0.0, budget=None,
        strategy=None, stall_seconds=None, log_flush_seconds=None, **options):
    """Run one fake batch; the default budget is exactly ``host_cases``."""
    log = tmp_path / 'run.log'
    settings = dict(stall_seconds=DEFAULT_STALL_SECONDS,
                    log_flush_seconds=DEFAULT_LOG_FLUSH_SECONDS)
    if stall_seconds is not None:
        settings['stall_seconds'] = stall_seconds
    if log_flush_seconds is not None:
        settings['log_flush_seconds'] = log_flush_seconds
    result = run_session(
        host_command(tmp_path, host_cases, mode, delay),
        log_path=log, strategy=strategy or StubStrategy(),
        feedback=FeedbackState(), corpus=Corpus(max_entries=64),
        case_parser=parse_case_line, summary_parser=parse_summary_line,
        budget=budget if budget is not None else SessionBudget(cases=host_cases),
        **settings, **options)
    return result, log


def test_ten_thousand_cases_keep_a_bounded_case_sample(tmp_path):
    total = 10_000
    result, _ = run(tmp_path, host_cases=total)
    assert result.status == 'completed'
    assert result.cases_total == total
    assert result.stats.executed == total
    assert len(result.cases) == DEFAULT_MAX_CASES_RECORDED
    assert result.cases_dropped == total - DEFAULT_MAX_CASES_RECORDED
    assert result.cases_truncated == result.cases_dropped
    first_half = DEFAULT_MAX_CASES_RECORDED // 2
    indexes = [row['case']['index'] for row in result.cases]
    assert indexes[:first_half] == list(range(first_half))
    assert indexes[first_half:] == list(range(total - first_half, total))


def test_the_rolling_stats_are_exact_for_fifty_thousand_cases(tmp_path):
    total = 50_000
    failed = (total + 2) // 3
    passed = total - failed
    result, _ = run(tmp_path, host_cases=total, max_cases_recorded=8)
    stats = result.stats
    assert stats.executed == total
    assert stats.passed == passed and stats.failed == failed
    assert stats.ticks == 7 * total
    assert stats.flows == {'F2': {'executed': total, 'passed': passed,
                                  'failed': failed}}
    assert stats.status_counts == {'failed': failed,
                                   'observations_passed': passed}
    assert stats.findings == failed
    assert stats.first_case_index == 0
    assert stats.last_case_index == total - 1
    assert abs(stats.dut_seconds - 0.001 * total) < 1e-6
    assert stats.budget_reached == 'cases'
    assert len(result.cases) == 8
    document = result.document()
    assert document['stats']['executed'] == total
    assert document['stats']['ticks'] == 7 * total
    assert document['retention']['cases_total'] == total
    assert document['retention']['cases_retained'] == 8
    assert document['retention']['cases_dropped'] == total - 8


def test_findings_are_capped_but_none_are_lost_from_the_counts(tmp_path):
    total = 3_000
    result, _ = run(tmp_path, host_cases=total, mode='failall', max_findings=5)
    # A host that exits 1 after a summary with failed cases is a completed
    # batch with findings, not a host error.
    assert result.status == 'completed'
    assert result.stats.failed == total
    assert result.stats.findings == total
    assert len(result.findings) == 5
    assert result.retention['max_findings'] == 5
    assert result.retention['findings_total'] == total
    assert result.retention['findings_dropped'] == total - 5
    for finding in result.findings:
        assert finding['status'] == 'failed'
        assert finding['flow'] == 'F2'
        assert finding['input']['text'].startswith('F2:')
        assert finding['observation']['flow'] == 'F2'
        assert finding['observation']['ticks'] == 7


def test_submitted_inputs_are_bounded_with_an_exact_total(tmp_path):
    total = 4_000
    result, _ = run(tmp_path, host_cases=total, max_submitted_recorded=10)
    assert result.submitted_total == total
    assert len(result.submitted) == 10
    assert result.submitted_dropped == total - 10
    assert all(row['flow'] == 'F2' for row in result.submitted)
    assert all(len(row['words']) == 1 for row in result.submitted)
    assert {row['text'] for row in result.submitted} == {
        'F2:%08x' % (0x14000 + 4 * (index % 4))
        for index in range(4)}
    assert result.submitted[0]['text'] == 'F2:00014004'
    assert result.submitted[-1]['text'] == 'F2:00014000'
    assert result.document()['submitted_total'] == total


def test_a_silent_host_is_terminated_and_reported_as_stalled(tmp_path):
    started = time.monotonic()
    result, log = run(tmp_path, host_cases=10, mode='silent',
                      budget=SessionBudget(cases=1_000), stall_seconds=0.2)
    wall = time.monotonic() - started
    assert result.status == 'host_stalled'
    assert 'stall' in (result.error or '')
    assert result.stats.executed == 0
    assert result.summary is None
    assert result.stats.host_error == result.error
    assert wall < 10
    assert log.read_text().startswith('hostpid ')


def test_a_host_that_stops_in_the_middle_of_a_case_is_stalled(tmp_path):
    started = time.monotonic()
    result, _ = run(tmp_path, host_cases=5, mode='stuck_case', stall_seconds=0.2)
    wall = time.monotonic() - started
    assert result.status == 'host_stalled'
    assert result.stats.executed == 0
    assert result.stats.submitted == 1
    assert result.stats.budget_reached is None
    assert wall < 10


def test_a_host_that_never_reports_a_case_cannot_loop_forever(tmp_path):
    started = time.monotonic()
    result, _ = run(tmp_path, host_cases=1, mode='needonly', stall_seconds=5.0)
    wall = time.monotonic() - started
    assert result.stats.executed == 0
    assert result.stats.submitted > 1_000
    assert 'reported no case' in (result.error or '')
    assert result.status in ('completed_with_error', 'host_error')
    assert wall < 30


def test_a_time_budget_ends_on_time_while_the_host_is_slow(tmp_path):
    started = time.monotonic()
    result, _ = run(tmp_path, host_cases=1_000, delay=0.12,
                    budget=SessionBudget(seconds=0.5), stall_seconds=5.0)
    wall = time.monotonic() - started
    assert result.stats.budget_reached == 'seconds'
    assert result.status == 'completed'
    assert result.stats.executed >= 1
    assert result.summary is not None
    assert wall < 10


def test_a_time_budget_ends_when_the_host_never_speaks(tmp_path):
    started = time.monotonic()
    result, _ = run(tmp_path, host_cases=10, mode='silent',
                    budget=SessionBudget(seconds=0.2), stall_seconds=0.3)
    wall = time.monotonic() - started
    assert result.stats.budget_reached == 'seconds'
    assert result.status == 'host_stalled'
    assert 'after END' in (result.error or '')
    assert wall < 10


def test_a_time_budget_alone_ends_the_batch(tmp_path):
    started = time.monotonic()
    result, _ = run(tmp_path, host_cases=100_000,
                    budget=SessionBudget(seconds=0.4), stall_seconds=5.0)
    wall = time.monotonic() - started
    assert result.stats.budget_reached == 'seconds'
    assert result.status == 'completed'
    assert result.stats.executed >= 1
    assert wall < 10


def test_a_case_budget_alone_stops_exactly(tmp_path):
    result, _ = run(tmp_path, host_cases=20, budget=SessionBudget(cases=20))
    assert result.stats.budget_reached == 'cases'
    assert result.stats.executed == 20
    assert len(result.cases) == 20
    assert result.cases_dropped == 0
    assert result.cases[-1]['case']['index'] == 19


def test_both_budgets_stop_at_the_case_count(tmp_path):
    result, _ = run(tmp_path, host_cases=300,
                    budget=SessionBudget(cases=50, seconds=30),
                    stall_seconds=10.0)
    assert result.stats.budget_reached == 'cases'
    assert result.stats.executed == 50
    assert len(result.cases) == 50
    assert result.cases_total == 50
    assert result.status == 'completed'


def test_the_log_contains_every_line_of_a_normal_run(tmp_path):
    total = 200
    result, log = run(tmp_path, host_cases=total, log_flush_seconds=1.0)
    text = log.read_text()
    assert text.count('NEED_RECORD ') == total
    assert text.count('CASE_INSTALLED ') == total
    assert sum(1 for line in text.splitlines()
               if line.startswith('case ')) == total
    assert text.count('summary ') == 1
    assert text.splitlines()[-1].startswith('summary ')
    assert result.log_lines == text.count('\n')
    assert result.log_bytes == len(text)
    # The per-case chatter is buffered: only protocol/finding lines flush.
    assert result.log_flushes < result.log_lines


def test_the_buffered_tail_is_written_when_the_session_ends(tmp_path):
    result, log = run(tmp_path, host_cases=1, mode='lastcase',
                      log_flush_seconds=3_600.0)
    text = log.read_text()
    assert 'NEED_RECORD 0' in text
    assert 'CASE_INSTALLED 0' in text
    assert 'case 0 observations_passed' in text
    assert 'summary' not in text
    assert result.stats.executed == 1
    assert result.status == 'host_error'
    assert 'summary' in (result.error or '')


def test_a_generation_failure_still_ends_with_its_reason(tmp_path):
    class Broken(StubStrategy):
        def next_input(self):
            raise ValueError('no legal input for this flow')

    result, log = run(tmp_path, host_cases=3, strategy=Broken())
    assert result.stats.executed == 0
    assert result.stats.submitted == 0
    # The old driver reported this as completed_with_error or host_error
    # depending on whether the host answered the END it was sent; both are
    # unchanged semantics, and the reason is always stated.
    assert result.status in ('completed_with_error', 'host_error')
    assert 'no legal input' in (result.error or '')
    assert result.summary is not None
    assert result.stats.budget_reached is None


def test_an_early_exit_without_a_summary_is_a_host_error(tmp_path):
    result, log = run(tmp_path, host_cases=1, mode='nosummary')
    assert result.status == 'host_error'
    assert 'summary' in (result.error or '')
    assert result.stats.host_error == result.error
    assert result.summary is None
    assert log.read_text().startswith('hostpid ')


def test_the_host_is_one_process_for_the_whole_batch(tmp_path):
    total = 300
    result, log = run(tmp_path, host_cases=total)
    pids = [line.split()[1] for line in log.read_text().splitlines()
            if line.startswith('hostpid ')]
    assert len(pids) == 1
    assert int(pids[0]) == result.host_pid
    assert result.stats.executed == total


def test_odd_retention_limits_keep_only_the_declared_rows(tmp_path):
    result, _ = run(tmp_path, host_cases=5, max_cases_recorded=1)
    assert result.cases_total == 5
    assert len(result.cases) == 1
    assert result.cases[0]['case']['index'] == 4
    assert result.cases_dropped == 4
    result, _ = run(tmp_path, host_cases=5, max_cases_recorded=0)
    assert result.cases_total == 5
    assert result.cases == []
    assert result.cases_dropped == 5
    assert result.stats.executed == 5


def test_the_retained_sample_is_the_first_and_last_rows(tmp_path):
    total = 100
    result, _ = run(tmp_path, host_cases=total, max_cases_recorded=8)
    assert [row['case']['index'] for row in result.cases] == [0, 1, 2, 3,
                                                              96, 97, 98, 99]
    assert [row['input'] for row in result.cases[:1]] == ['F2:00014004']


def test_the_document_stays_small_for_many_cases(tmp_path):
    total = 20_000
    result, _ = run(tmp_path, host_cases=total)
    document = result.document()
    text = json.dumps(document)
    assert document['schema_version'] == 'inprocess_fuzz_session.v1'
    assert set(document) >= {'status', 'error', 'stats', 'summary', 'cases',
                             'submitted', 'findings', 'corpus', 'feedback',
                             'retention'}
    assert document['cases_total'] == total
    assert document['cases_dropped'] == total - DEFAULT_MAX_CASES_RECORDED
    assert document['retention']['cases_dropped'] == total - DEFAULT_MAX_CASES_RECORDED
    assert document['retention']['max_cases_recorded'] == DEFAULT_MAX_CASES_RECORDED
    assert document['retention']['max_submitted_recorded'] == (
        DEFAULT_MAX_SUBMITTED_RECORDED)
    assert document['retention']['max_findings'] == DEFAULT_MAX_FINDINGS
    assert len(document['cases']) == DEFAULT_MAX_CASES_RECORDED
    assert document['cases'][-1]['case']['index'] == total - 1
    assert len(text) < 200_000
