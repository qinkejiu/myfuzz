"""Per-case correspondence and log-mode options for the session driver."""
import json
from pathlib import Path

from myfuzz.fuzz.corpus import Corpus
from myfuzz.fuzz.feedback import FeedbackState
from myfuzz.fuzz.session import SessionBudget, run_session
from myfuzz.fuzz.strategy import Input
from scripts.run_inprocess_f1f6 import parse_case_line, parse_summary_line

HOST = '''\
import sys
n = int(sys.argv[1])
for i in range(n):
    print('NEED_RECORD %d tick %d' % (i, i), flush=True)
    line = sys.stdin.readline()
    if not line or line.strip() == 'END':
        break
    print('CASE_INSTALLED %d' % i, flush=True)
    print('case %d observations_passed flow F2 record F2:%08x read_addr 0x%08x '
          'read_value 0x%08x echo_value 0x%08x read_from ram target_reads 0 '
          'i_fetches 1 d_reads 1 d_writes 0 apb_reads 0 apb_writes 0 retires 1 '
          'seconds 0.001' % (i, 0x14000 + 4*i, 0x14000 + 4*i, i, i), flush=True)
print('summary observations_passed cases %d' % n, flush=True)
'''


class Strategy:
    flows = ('F2',)

    def __init__(self):
        self.i = 0

    def seed_inputs(self):
        return [Input('F2', (0x14000,), 'F2:00014000', 'CASE F2 00014000')]

    def next_input(self):
        self.i += 1
        a = 0x14000 + 4 * (self.i % 8)
        return Input('F2', (a,), 'F2:%08x' % a, 'CASE F2 %08x' % a)


def run(tmp_path, *, cases=6, case_check=None, log_case_lines=True):
    path = tmp_path / 'host.py'
    path.write_text(HOST)
    return run_session(['python3', str(path), str(cases)],
                       log_path=tmp_path / 'run.log', strategy=Strategy(),
                       feedback=FeedbackState(), corpus=Corpus(),
                       case_parser=parse_case_line,
                       summary_parser=parse_summary_line,
                       budget=SessionBudget(cases=cases),
                       case_check=case_check,
                       log_case_lines=log_case_lines)


def test_every_case_is_checked_not_only_the_retained_sample(tmp_path):
    seen = []

    def check(input_, case):
        seen.append((input_.text if input_ else None, case['record']))
        return None

    result = run(tmp_path, cases=500, case_check=check)
    assert result.stats.executed == 500
    assert len(seen) == 500
    assert result.stats.correspondence_checked == 500
    assert result.stats.correspondence_mismatched == 0
    assert len(result.cases) < 500  # rows are still bounded


def test_mismatches_are_counted_completely_and_sampled_boundedly(tmp_path):
    def check(input_, case):
        return 'synthetic mismatch' if case['index'] % 7 == 0 else None

    result = run(tmp_path, cases=200, case_check=check)
    expected = len([i for i in range(200) if i % 7 == 0])
    assert result.stats.correspondence_mismatched == expected
    assert len(result.correspondence_mismatches) <= 32
    assert result.correspondence_mismatches[0]['reason'] == 'synthetic mismatch'


def test_a_case_check_exception_is_counted_as_a_mismatch(tmp_path):
    def check(input_, case):
        raise ValueError('boom')

    result = run(tmp_path, cases=3, case_check=check)
    assert result.stats.correspondence_mismatched == 3
    assert 'boom' in result.correspondence_mismatches[0]['reason']


def test_a_summary_only_log_omits_per_case_chatter(tmp_path):
    result = run(tmp_path, cases=20, log_case_lines=False)
    log = (tmp_path / 'run.log').read_text()
    assert 'case ' not in log
    assert 'NEED_RECORD' not in log
    assert 'summary observations_passed' in log
    assert result.stats.executed == 20
    document = result.document()
    assert document['retention']['log_case_lines'] is False
    json.dumps(document)


def test_a_case_log_keeps_per_case_lines(tmp_path):
    run(tmp_path, cases=3, log_case_lines=True)
    log = (tmp_path / 'run.log').read_text()
    assert log.count('case ') == 3
    assert 'NEED_RECORD' in log
