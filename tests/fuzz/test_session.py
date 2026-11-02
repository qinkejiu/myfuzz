"""Pure-Python tests for the fuzz session driver: no RTL, no Verilator.

A tiny Python child speaks the same ``NEED_RECORD``/``case``/``summary`` protocol
as the C++ host, so the driver's budget, corpus updates, findings and incomplete
batch detection are exercised without a model.
"""
import json
from pathlib import Path

import pytest

from myfuzz.fuzz.corpus import Corpus
from myfuzz.fuzz.feedback import FeedbackState
from myfuzz.fuzz.session import SessionBudget, run_session
from myfuzz.fuzz.strategy import Input
from scripts.run_inprocess_f1f6 import parse_case_line, parse_summary_line

ROOT = Path(__file__).resolve().parents[2]

HOST = '''\
import sys
cases = int(sys.argv[1])
unfinished = len(sys.argv) > 2 and sys.argv[2] == 'truncate'
for index in range(cases):
    print('NEED_RECORD %d tick %d' % (index, index * 10), flush=True)
    line = sys.stdin.readline()
    if not line or line.strip() == 'END':
        break
    print('CASE_INSTALLED %d' % index, flush=True)
    status = 'observations_passed' if index % 3 else 'failed'
    print('case %d %s flow F2 record F2:00014000 read_addr 0x00014000 '
          'read_value 0x%08x echo_value 0x%08x read_from ram target_reads 0 '
          'i_fetches %d d_reads 1 d_writes 0 apb_reads 0 apb_writes 0 retires %d '
          'seconds 0.001' % (index, status, index + 1, index + 1, index, index),
          flush=True)
print('summary %s cases %d' % ('failed' if not unfinished else 'observations_passed',
                               cases if not unfinished else cases - 1), flush=True)
'''


class StubStrategy:
    flows = ('F2',)

    def __init__(self, seed_inputs=None):
        self._seeds = list(seed_inputs or [])
        self._index = 0

    def seed_inputs(self):
        return list(self._seeds)

    def next_input(self):
        self._index += 1
        address = 0x14000 + 4 * (self._index % 4)
        text = 'F2:%08x' % address
        return Input(flow='F2', fields=(address,), text=text,
                     message='CASE F2 %08x' % address)


def host(tmp_path, cases, *flags):
    path = tmp_path / 'host.py'
    path.write_text(HOST)
    return ['python3', str(path), str(cases), *flags]


def run(tmp_path, *, cases=5, budget_cases=None, budget_seconds=None, strategy=None,
        host_cases=None, flags=()):
    log = tmp_path / 'run.log'
    corpus = Corpus(max_entries=32)
    feedback = FeedbackState()
    result = run_session(
        host(tmp_path, host_cases if host_cases is not None else cases, *flags),
        log_path=log, strategy=strategy or StubStrategy(), feedback=feedback,
        corpus=corpus, case_parser=parse_case_line,
        summary_parser=parse_summary_line,
        budget=SessionBudget(cases=budget_cases if budget_cases is not None else cases,
                             seconds=budget_seconds))
    return result, log, corpus, feedback


def test_a_complete_batch_runs_every_case_and_stops_on_the_budget(tmp_path):
    result, log, corpus, feedback = run(tmp_path, cases=5)
    assert result.status == 'completed'
    assert result.stats.executed == 5
    assert result.stats.passed == 3 and result.stats.failed == 2
    assert result.stats.budget_reached == 'cases'
    assert result.summary is not None
    assert len(result.cases) == 5
    assert len(result.findings) == 2
    assert result.findings[0]['flow'] == 'F2'
    assert 'read_value' in result.findings[0]['observation']
    assert corpus.entries and feedback.discovered
    assert log.read_text().count('case ') == 5


def test_an_interesting_case_enters_the_corpus_with_its_input(tmp_path):
    result, _, corpus, feedback = run(tmp_path, cases=4)
    entries = {(row.flow, row.record_text) for row in corpus.entries}
    assert ('F2', 'F2:00014004') in entries
    assert all(row.discoveries >= 0 for row in corpus.entries)
    assert result.cases[0]['new']  # the first case is all-new


def test_a_failed_case_is_a_finding_not_a_broken_batch(tmp_path):
    result, _, _, _ = run(tmp_path, cases=3)
    assert result.status == 'completed'
    assert result.stats.failed == 1
    assert len(result.findings) == 1
    assert result.findings[0]['status'] == 'failed'


def test_a_host_that_stops_before_the_budget_is_a_host_error(tmp_path):
    result, _, _, _ = run(tmp_path, cases=5, host_cases=2)
    assert result.status == 'host_error'
    assert result.stats.executed == 2
    assert 'without the session ending it' in (result.error or '')


def test_a_host_without_a_summary_line_is_a_host_error(tmp_path):
    path = tmp_path / 'silent.py'
    path.write_text('print("NEED_RECORD 0 tick 0", flush=True)\n'
                    'raise SystemExit(1)\n')
    result = run_session([*host(tmp_path, 1)][:2] + [str(path)],
                         log_path=tmp_path / 'r.log', strategy=StubStrategy(),
                         feedback=FeedbackState(), corpus=Corpus(),
                         case_parser=parse_case_line,
                         summary_parser=parse_summary_line,
                         budget=SessionBudget(cases=1))
    assert result.status == 'host_error'
    assert 'summary' in (result.error or '')


def test_a_time_budget_ends_the_batch_after_the_current_case(tmp_path):
    result, _, _, _ = run(tmp_path, cases=1000, budget_cases=None,
                          budget_seconds=0.5, host_cases=1000)
    assert result.stats.budget_reached in ('seconds', 'cases')
    assert result.stats.executed >= 1


def test_the_session_document_is_json_serialisable(tmp_path):
    result, _, _, _ = run(tmp_path, cases=2)
    document = result.document()
    text = json.dumps(document)
    assert '"schema_version": "inprocess_fuzz_session.v1"' in text
    assert document['stats']['executed'] == 2


def test_a_generation_failure_ends_the_batch_with_its_reason(tmp_path):
    class Broken(StubStrategy):
        def next_input(self):
            raise ValueError('no legal input for this flow')

    result, _, _, _ = run(tmp_path, cases=3, strategy=Broken())
    assert result.stats.executed == 0
    assert result.status in ('completed_with_error', 'host_error')
    assert 'no legal input' in (result.error or '')
