"""Drive one long-lived in-process host with a real execute/observe/mutate loop.

The host prints ``NEED_RECORD`` when it is ready for another input and one
compact ``case`` line per executed input.  This module owns that conversation:
it writes the next legal input, reads the case line, asks the feedback and
corpus collaborators what it means, and decides when the declared budget is
spent.  It never restarts, resets or rebuilds a model; the caller built it once
and passes the same command for the whole batch.

A long run must not grow, so the result is a *sample plus aggregates*:

* the case rows and the submitted inputs are kept as the first half and the
  last half of at most ``max_cases_recorded`` / ``max_submitted_recorded``
  rows, with ``cases_total`` / ``submitted_total`` and the dropped counts
  stated beside them;
* :class:`SessionStats` carries the rolling aggregates -- counts, per-flow and
  per-status counts, ticks, DUT seconds and the loop timings -- so nothing that
  matters is only available through the retained sample;
* findings are capped by ``max_findings`` and each finding keeps its input and
  its full parsed case, so the cap, not the case count, bounds them.

A run must also not hang, so the host's stdout is read by a background thread
into a bounded queue and the main loop waits with a deadline.  A host that says
nothing for ``stall_seconds`` is terminated and reported as ``host_stalled``;
a case/time budget still ends on time even if the host is slow.  The log is
written through for every line, but it is flushed only on protocol lines, on
findings and on a ``log_flush_seconds`` deadline instead of on every line.

No coverage, certificate or replay is claimed here.  The feedback is exactly the
observed case fields, and every input was accepted by the entry's own gate.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import queue
import subprocess
import threading
import time

__all__ = [
    'DEFAULT_LOG_FLUSH_SECONDS', 'DEFAULT_MAX_CASES_RECORDED',
    'DEFAULT_MAX_FINDINGS', 'DEFAULT_MAX_SUBMITTED_RECORDED',
    'DEFAULT_STALL_SECONDS', 'SessionBudget', 'SessionResult', 'SessionStats',
    'run_session',
]

#: How many executed case rows a result keeps by default (first half, last half).
DEFAULT_MAX_CASES_RECORDED = 64
#: How many submitted inputs a result keeps by default.
DEFAULT_MAX_SUBMITTED_RECORDED = 64
#: How many findings a result keeps by default.
DEFAULT_MAX_FINDINGS = 128
#: How long the host may stay silent before the session calls it stalled.
DEFAULT_STALL_SECONDS = 30.0
#: How often a buffered log is flushed when no protocol line forces a flush.
DEFAULT_LOG_FLUSH_SECONDS = 0.5

#: The per-case chatter of a quiet run; every other line forces a log flush.
_CHATTER = frozenset(('case', 'CASE_INSTALLED'))
#: How many host lines may wait for the main loop before the reader blocks.
_QUEUE_LINES = 4096
#: How long a host that already closed stdout may take to exit.
_EXIT_GRACE_SECONDS = 10.0
#: How long a terminated host may take to die before it is killed.
_KILL_GRACE_SECONDS = 5.0
#: How long cleanup waits for the reader thread to reach its end of stream.
_READER_GRACE_SECONDS = 5.0
#: How many inputs a host may accept without reporting one case before the
#: session treats the conversation as broken instead of looping on it forever.
_MAX_UNANSWERED_SUBMISSIONS = 4096

_EOF = object()


@dataclass(frozen=True, slots=True)
class SessionBudget:
    """When the batch stops: a case count, a wall-clock budget, or both."""

    cases: int | None = None
    seconds: float | None = None

    def __post_init__(self):
        if self.cases is None and self.seconds is None:
            raise ValueError('a fuzz budget needs a case count or a time limit')
        if self.cases is not None and (type(self.cases) is not int or self.cases < 1):
            raise ValueError('cases must be a positive integer or None')
        if self.seconds is not None and (type(self.seconds) not in (int, float)
                                         or self.seconds <= 0):
            raise ValueError('seconds must be a positive number or None')


@dataclass
class SessionStats:
    """Rolling aggregates of one batch, independent of the retained sample."""

    executed: int = 0
    passed: int = 0
    failed: int = 0
    submitted: int = 0
    ticks: int = 0
    findings: int = 0
    first_case_index: int | None = None
    last_case_index: int | None = None
    flows: dict = field(default_factory=dict)
    status_counts: dict = field(default_factory=dict)
    generation_seconds: float = 0.0
    parse_seconds: float = 0.0
    feedback_seconds: float = 0.0
    round_trip_seconds: float = 0.0
    dut_seconds: float = 0.0
    max_round_trip_seconds: float = 0.0
    budget_reached: str | None = None
    host_error: str | None = None
    correspondence_checked: int = 0
    correspondence_mismatched: int = 0

    def document(self):
        return {
            'executed': self.executed, 'passed': self.passed,
            'failed': self.failed, 'submitted': self.submitted,
            'ticks': self.ticks, 'findings': self.findings,
            'first_case_index': self.first_case_index,
            'last_case_index': self.last_case_index,
            'flows': {flow: dict(row) for flow, row in sorted(self.flows.items())},
            'statuses': dict(sorted(self.status_counts.items())),
            'budget_reached': self.budget_reached,
            'host_error': self.host_error,
            'correspondence_checked': self.correspondence_checked,
            'correspondence_mismatched': self.correspondence_mismatched,
            'generation_seconds': round(self.generation_seconds, 6),
            'parse_seconds': round(self.parse_seconds, 6),
            'feedback_seconds': round(self.feedback_seconds, 6),
            'round_trip_seconds': round(self.round_trip_seconds, 6),
            'dut_seconds': round(self.dut_seconds, 6),
            'max_round_trip_seconds': round(self.max_round_trip_seconds, 6),
        }


@dataclass
class SessionResult:
    """Everything one batch produced, and the honest status of the batch."""

    status: str
    stats: SessionStats = field(default_factory=SessionStats)
    summary: dict | None = None
    cases: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    correspondence_mismatches: list = field(default_factory=list)
    submitted: list = field(default_factory=list)
    corpus: dict | None = None
    feedback: dict | None = None
    error: str | None = None
    cases_total: int = 0
    cases_dropped: int = 0
    cases_truncated: int = 0
    submitted_total: int = 0
    submitted_dropped: int = 0
    retention: dict = field(default_factory=dict)
    host_pid: int | None = None
    log_lines: int = 0
    log_flushes: int = 0
    log_bytes: int = 0
    wall_seconds: float = 0.0

    def document(self):
        return {
            'schema_version': 'inprocess_fuzz_session.v1',
            'status': self.status,
            'error': self.error,
            'wall_seconds': round(self.wall_seconds, 6),
            'host_pid': self.host_pid,
            'stats': self.stats.document(),
            'summary': self.summary,
            'cases': self.cases,
            'cases_total': self.cases_total,
            'cases_dropped': self.cases_dropped,
            'cases_truncated': self.cases_truncated,
            'findings': self.findings,
            'correspondence_mismatches': self.correspondence_mismatches,
            'submitted': self.submitted,
            'submitted_total': self.submitted_total,
            'submitted_dropped': self.submitted_dropped,
            'corpus': self.corpus,
            'feedback': self.feedback,
            'retention': self.retention,
            'log': {'lines': self.log_lines, 'flushes': self.log_flushes,
                    'bytes': self.log_bytes},
        }


class _BoundedRows:
    """The first and last rows of a stream that must not grow without bound.

    ``limit`` rows are kept -- the first ``limit // 2`` and the last
    ``limit - limit // 2`` -- and ``total`` counts every appended row, so the
    dropped count is always exact.
    """

    __slots__ = ('limit', 'total', '_head', '_head_size', '_tail')

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.total = 0
        self._head_size = limit // 2
        self._head: list = []
        self._tail: deque = deque(maxlen=limit - self._head_size)

    def append(self, value) -> None:
        self.total += 1
        if len(self._head) < self._head_size:
            self._head.append(value)
        elif self.limit:
            self._tail.append(value)

    def rows(self) -> list:
        return self._head + list(self._tail)

    @property
    def dropped(self) -> int:
        return self.total - len(self._head) - len(self._tail)


class _SessionLog:
    """A log that is written through on every line and flushed on schedule."""

    __slots__ = ('handle', 'interval', 'lines', 'flushes', 'bytes', 'last',
                 'suppressed')

    def __init__(self, handle, interval: float, suppressed=()) -> None:
        self.handle = handle
        self.interval = interval
        self.lines = 0
        self.flushes = 0
        self.bytes = 0
        self.last = time.monotonic()
        self.suppressed = frozenset(suppressed)

    def write(self, text: str) -> None:
        # A model may print a line of its own (a passive monitor's banner is
        # one, and its trailing newline makes a blank line).  Such a line has no
        # first token, so it is neither suppressed nor a protocol line: it is
        # written through like any other diagnostic.
        tokens = text.split(None, 1)
        if tokens and tokens[0] in self.suppressed:
            return
        self.handle.write(text)
        self.lines += 1
        self.bytes += len(text)

    def flush(self) -> None:
        self.handle.flush()
        self.flushes += 1
        self.last = time.monotonic()

    def maybe_flush(self, now: float, *, force: bool = False) -> None:
        if (force or self.interval <= 0.0
                or now - self.last >= self.interval):
            self.flush()

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.handle.close()


def _pump_lines(stream, lines: 'queue.Queue') -> None:
    """Read the host's stdout into a bounded queue; the sentinel means EOF."""
    try:
        for line in stream:
            lines.put(line)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass
        try:
            lines.put(_EOF, timeout=1.0)
        except queue.Full:
            pass


def _drain(reader: threading.Thread, lines: 'queue.Queue',
           log: _SessionLog) -> None:
    """Collect the lines the main loop did not consume, then join the reader."""
    deadline = time.monotonic() + _READER_GRACE_SECONDS
    while True:
        try:
            item = lines.get_nowait()
        except queue.Empty:
            if not reader.is_alive() or time.monotonic() >= deadline:
                return
            reader.join(0.02)
            continue
        if item is not _EOF:
            log.write(item)
        elif not reader.is_alive():
            return


def _send(process, text: str) -> bool:
    """Write one protocol line to the host; False if the host already closed it."""
    try:
        process.stdin.write(text)
        process.stdin.flush()
        return True
    except (BrokenPipeError, OSError, ValueError):
        return False


def _close_stdin(process) -> None:
    try:
        process.stdin.close()
    except (BrokenPipeError, OSError, ValueError):
        pass


def _terminate(process) -> int | None:
    """Stop the host for good; returns its exit code when one is known."""
    if process.poll() is not None:
        return process.returncode
    try:
        process.terminate()
    except OSError:
        return process.poll()
    try:
        return process.wait(timeout=_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            return process.poll()
        try:
            return process.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return process.poll()


def _row_limit(name: str, value) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a non-negative integer: ' + repr(value))
    return value


def _positive_seconds(name: str, value) -> float:
    if type(value) not in (int, float) or not value > 0:
        raise ValueError(name + ' must be a positive number: ' + repr(value))
    return float(value)


def _non_negative_seconds(name: str, value) -> float:
    if type(value) not in (int, float) or value < 0:
        raise ValueError(name + ' must be a non-negative number: ' + repr(value))
    return float(value)


def _input_document(input_):
    return dict(flow=input_.flow, words=[format(word, '08x') for word in input_.fields],
                text=input_.text, origin=input_.origin, parent=input_.parent)


def _case_row(case, observed, input_text):
    return dict(index=case.get('index'),
                flow=case.get('flow'),
                record=case.get('record'),
                status=case.get('status'),
                summary=observed.summary,
                new=[[_jsonable(item) for item in feature]
                     for feature in observed.new],
                input=input_text,
                case=case)


def run_session(command, *, log_path, strategy, feedback, corpus, case_parser,
                summary_parser, budget,
                max_cases_recorded=DEFAULT_MAX_CASES_RECORDED,
                max_submitted_recorded=DEFAULT_MAX_SUBMITTED_RECORDED,
                max_findings=DEFAULT_MAX_FINDINGS,
                stall_seconds=DEFAULT_STALL_SECONDS,
                log_flush_seconds=DEFAULT_LOG_FLUSH_SECONDS,
                log_case_lines=True, case_check=None) -> SessionResult:
    """Run one batch over an already built host.

    ``case_parser`` and ``summary_parser`` are the entry's own parsers, so the
    session cannot disagree with the executor about what a case line means.
    The result keeps a bounded deterministic sample of the batch and exact
    aggregates; ``max_findings`` bounds the finding list, which is where the
    full parsed case and its input are kept.
    """
    if not isinstance(budget, SessionBudget):
        raise TypeError('budget must be a SessionBudget')
    if not command:
        raise ValueError('a host command is required')
    max_cases_recorded = _row_limit('max_cases_recorded', max_cases_recorded)
    max_submitted_recorded = _row_limit('max_submitted_recorded',
                                        max_submitted_recorded)
    max_findings = _row_limit('max_findings', max_findings)
    stall_seconds = _positive_seconds('stall_seconds', stall_seconds)
    log_flush_seconds = _non_negative_seconds('log_flush_seconds',
                                              log_flush_seconds)

    result = SessionResult(status='completed')
    stats = result.stats
    case_rows = _BoundedRows(max_cases_recorded)
    submitted_rows = _BoundedRows(max_submitted_recorded)
    started = time.monotonic()
    time_deadline = (None if budget.seconds is None
                     else started + budget.seconds)

    pending: list = []
    try:
        pending = list(strategy.seed_inputs())
    except ValueError as error:
        result.error = 'seed corpus: ' + str(error)
    for seed_input in pending:
        if corpus is not None:
            try:
                corpus.seed(seed_input.flow, seed_input.fields, seed_input.text)
            except ValueError as error:
                result.error = result.error or 'corpus seed: ' + str(error)

    stop_requested = False
    end_sent = False
    stalled = False
    last_input = None
    last_round_trip_start = started
    last_activity = started

    suppressed = () if log_case_lines else ('case', 'CASE_INSTALLED', 'NEED_RECORD')
    log = _SessionLog(open(log_path, 'w', encoding='utf-8'), log_flush_seconds,
                      suppressed=suppressed)
    try:
        process = subprocess.Popen([str(part) for part in command],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1)
    except BaseException:
        log.close()
        raise
    result.host_pid = process.pid
    lines: queue.Queue = queue.Queue(maxsize=_QUEUE_LINES)
    reader = threading.Thread(target=_pump_lines, args=(process.stdout, lines),
                              name='fuzz-session-reader', daemon=True)
    reader.start()
    returncode = None
    try:
        try:
            while True:
                now = time.monotonic()
                wait = stall_seconds - (now - last_activity)
                if time_deadline is not None and not stop_requested:
                    wait = min(wait, time_deadline - now)
                if log.interval > 0.0:
                    wait = min(wait, log.interval - (now - log.last))
                try:
                    item = lines.get(timeout=max(0.0, wait))
                except queue.Empty:
                    item = None
                if item is None:
                    now = time.monotonic()
                    log.maybe_flush(now)
                    if (time_deadline is not None and not stop_requested
                            and now >= time_deadline):
                        # The time budget is spent: ask a host that may still be
                        # computing to stop, and give it one stall window to say
                        # what it has.  Nothing here can block forever.
                        stop_requested = True
                        stats.budget_reached = 'seconds'
                        if not end_sent:
                            end_sent = True
                            if not _send(process, 'END\n'):
                                result.error = result.error or (
                                    'host input: the host closed stdin before END')
                        last_activity = now
                        log.maybe_flush(now, force=True)
                        continue
                    if now - last_activity >= stall_seconds:
                        stalled = True
                        result.error = _prepend(result.error, (
                            'the host produced no output for ' +
                            _seconds_text(stall_seconds) +
                            (' after END' if end_sent else '') +
                            ' (stall limit); the session terminated it'))
                        break
                    continue
                if item is _EOF:
                    break
                now = time.monotonic()
                last_activity = now
                log.write(item)
                tokens = item.split()
                if not tokens:
                    log.maybe_flush(now)
                    continue
                token = tokens[0]
                if token not in _CHATTER:
                    log.maybe_flush(now, force=True)
                if token == 'NEED_RECORD':
                    if stop_requested:
                        if not end_sent:
                            end_sent = True
                            last_activity = now
                            if not _send(process, 'END\n'):
                                result.error = result.error or (
                                    'host input: the host closed stdin before END')
                        continue
                    generated = time.monotonic()
                    try:
                        if pending:
                            input_ = pending.pop(0)
                        else:
                            input_ = strategy.next_input()
                    except ValueError as error:
                        result.error = 'input generation: ' + str(error)
                        stop_requested = True
                        if not end_sent:
                            end_sent = True
                            last_activity = time.monotonic()
                            if not _send(process, 'END\n'):
                                result.error = result.error or (
                                    'host input: the host closed stdin before END')
                        continue
                    stats.generation_seconds += time.monotonic() - generated
                    submitted_at = time.monotonic()
                    if not _send(process, input_.message + '\n'):
                        result.error = result.error or (
                            'host input: the host closed stdin before a case')
                        stop_requested = True
                        continue
                    stats.submitted += 1
                    submitted_rows.append(input_)
                    last_input = input_
                    last_round_trip_start = submitted_at
                    last_activity = submitted_at
                    if stats.submitted - stats.executed > _MAX_UNANSWERED_SUBMISSIONS:
                        # A host that keeps asking for inputs without ever
                        # reporting a case would otherwise loop forever: this is
                        # a broken conversation, not a slow one.
                        result.error = _prepend(result.error, (
                            'the host accepted ' + str(stats.submitted) +
                            ' inputs and reported no case for the last ' +
                            str(stats.submitted - stats.executed)))
                        stop_requested = True
                        if not end_sent:
                            end_sent = True
                            if not _send(process, 'END\n'):
                                result.error = _prepend(result.error, (
                                    'host input: the host closed stdin before END'))
                        continue
                if token == 'case':
                    parsed_at = time.monotonic()
                    try:
                        case = case_parser(item, flows=set(strategy.flows))
                    except ValueError as error:
                        result.error = 'unreadable case line: ' + str(error)
                        stop_requested = True
                        continue
                    stats.parse_seconds += time.monotonic() - parsed_at
                    observed_at = time.monotonic()
                    try:
                        observed = feedback.observe(case)
                    except ValueError as error:
                        result.error = 'unreadable case feedback: ' + str(error)
                        stop_requested = True
                        continue
                    stats.feedback_seconds += time.monotonic() - observed_at
                    if (case_check is not None
                            and case.get('status') == 'observations_passed'):
                        try:
                            mismatch = case_check(last_input, case)
                        except ValueError as error:
                            mismatch = 'correspondence check failed: ' + str(error)
                        stats.correspondence_checked += 1
                        if mismatch:
                            stats.correspondence_mismatched += 1
                            if len(result.correspondence_mismatches) < 32:
                                result.correspondence_mismatches.append(dict(
                                    index=case.get('index'),
                                    record=case.get('record'),
                                    reason=mismatch))
                    _note_case(stats, case)
                    dut_seconds = case.get('seconds')
                    if isinstance(dut_seconds, (int, float)):
                        stats.dut_seconds += float(dut_seconds)
                    round_trip = time.monotonic() - last_round_trip_start
                    stats.round_trip_seconds += round_trip
                    stats.max_round_trip_seconds = max(
                        stats.max_round_trip_seconds, round_trip)
                    if observed.new and corpus is not None and last_input is not None:
                        entry = corpus.add(last_input.flow, last_input.fields,
                                           last_input.text, parent=last_input.parent,
                                           origin=last_input.origin)
                        corpus.note_discovery(entry)
                    input_text = None if last_input is None else last_input.text
                    if case.get('status') != 'observations_passed':
                        stats.findings += 1
                        if len(result.findings) < max_findings:
                            finding = dict(summary=observed.summary,
                                           status=case.get('status'),
                                           flow=case.get('flow'),
                                           record=case.get('record'),
                                           features=[[_jsonable(item) for item in feature]
                                                     for feature in observed.new],
                                           observation=case)
                            if last_input is not None:
                                finding['input'] = _input_document(last_input)
                            result.findings.append(finding)
                            log.maybe_flush(time.monotonic(), force=True)
                    case_rows.append((case, observed, input_text))
                    now = time.monotonic()
                    if not stop_requested:
                        if budget.cases is not None and stats.executed >= budget.cases:
                            stop_requested = True
                            stats.budget_reached = 'cases'
                        elif time_deadline is not None and now >= time_deadline:
                            stop_requested = True
                            stats.budget_reached = 'seconds'
                    continue
                if token == 'summary':
                    try:
                        result.summary = summary_parser(item)
                    except ValueError as error:
                        result.error = 'unreadable summary line: ' + str(error)
                    continue
                # Everything else in a quiet run is a declaration or a host
                # error; it stays in the log.  Nothing is guessed from it.
            if stalled:
                _terminate(process)
            else:
                try:
                    returncode = process.wait(timeout=_EXIT_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    _terminate(process)
                    returncode = process.returncode
                    result.error = result.error or 'host did not exit after END'
        finally:
            _close_stdin(process)
            if stalled:
                _terminate(process)
            _drain(reader, lines, log)
            log.flush()
    finally:
        log.close()
        if process.poll() is None:
            _terminate(process)
    returncode = process.returncode if returncode is None else returncode

    result.wall_seconds = time.monotonic() - started
    result.cases_total = case_rows.total
    result.cases = [_case_row(*row) for row in case_rows.rows()]
    result.cases_dropped = case_rows.dropped
    result.cases_truncated = result.cases_dropped
    result.submitted_total = submitted_rows.total
    result.submitted = [_input_document(row) for row in submitted_rows.rows()]
    result.submitted_dropped = submitted_rows.dropped
    result.log_lines = log.lines
    result.log_flushes = log.flushes
    result.log_bytes = log.bytes
    result.retention = {
        'max_cases_recorded': max_cases_recorded,
        'max_submitted_recorded': max_submitted_recorded,
        'max_findings': max_findings,
        'stall_seconds': stall_seconds,
        'log_flush_seconds': log_flush_seconds,
        'log_case_lines': bool(log_case_lines),
        'case_check': callable(case_check),
        'cases_retained': len(result.cases),
        'cases_total': result.cases_total,
        'cases_dropped': result.cases_dropped,
        'submitted_retained': len(result.submitted),
        'submitted_total': result.submitted_total,
        'submitted_dropped': result.submitted_dropped,
        'findings_retained': len(result.findings),
        'findings_total': stats.findings,
        'findings_dropped': stats.findings - len(result.findings),
    }
    # A host exit code of 1 is expected when a *case* failed: that is a finding,
    # not a broken batch.  Only a missing summary line, or a host that stopped
    # before the declared case budget without the session ending it, is a host
    # error.  A host that said nothing for the stall window is its own status:
    # the session ended it, so the missing summary is not a surprise.
    if stalled:
        result.status = 'host_stalled'
    elif result.summary is None:
        result.status = 'host_error'
        result.error = _prepend(result.error, 'host exited without a summary line '
                                '(code ' + str(returncode) + ')')
    elif (budget.cases is not None and stats.executed < budget.cases
          and stats.budget_reached is None):
        result.status = 'host_error'
        result.error = _prepend(result.error, (
            'the host stopped after ' + str(stats.executed) + ' of ' +
            str(budget.cases) + ' cases without the session ending it '
            '(tick budget?)'))
    elif result.error is not None:
        result.status = 'completed_with_error'
    else:
        result.status = 'completed'
    if result.status in ('host_error', 'host_stalled'):
        stats.host_error = result.error
    result.corpus = None if corpus is None else corpus.document()
    result.feedback = None if feedback is None else feedback.document()
    return result


def _note_case(stats: SessionStats, case: dict) -> None:
    """Count one parsed case, whether or not its row is retained."""
    stats.executed += 1
    index = case.get('index')
    if type(index) is int:
        if stats.first_case_index is None:
            stats.first_case_index = index
        stats.last_case_index = index
    flow = case.get('flow')
    status = case.get('status')
    passed = status == 'observations_passed'
    if passed:
        stats.passed += 1
    else:
        stats.failed += 1
    status_name = status if isinstance(status, str) else 'unknown'
    stats.status_counts[status_name] = stats.status_counts.get(status_name, 0) + 1
    if isinstance(flow, str):
        row = stats.flows.get(flow)
        if row is None:
            row = stats.flows[flow] = {'executed': 0, 'passed': 0, 'failed': 0}
        row['executed'] += 1
        row['passed' if passed else 'failed'] += 1
    ticks = case.get('ticks')
    if type(ticks) is int:
        stats.ticks += ticks


def _seconds_text(value: float) -> str:
    return ('%g' % value) + ' s'


def _prepend(error: str | None, detail: str) -> str:
    return detail if error is None else detail + '; ' + error


def _jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    return str(value)
