#!/usr/bin/env python3
"""Measure the closed-loop fuzz entry: preparation vs DUT advance, per-case DUT
milliseconds, closed-loop throughput, and the event-layer A/B on fixed inputs.

What is measured (nothing is attributed that the product does not state)
-----------------------------------------------------------------------
``wall``            wall clock around the whole entry process (``os.wait4``)
``cpu``             ``ru_utime+ru_stime`` of that process (host CPU, not DUT)
``maxrss_kb``       ``ru_maxrss`` of that process (Linux: KiB)
``total_seconds``   the entry's own ``total_seconds`` (includes preparation/build)
``run_seconds``     the entry's own ``run_seconds`` (the host process span)
``preparation``     ``total_seconds - run_seconds``: entry startup and imports,
                    scope entry, profile/artifact preparation, cache lookup, link,
                    firmware and binding render, summary write
``link``            ``link_seconds`` from ``summary.json`` (cache lookup + link)
``session_wall``    ``fuzz.wall_seconds``: the closed loop itself
``dut_seconds``     ``fuzz.stats.dut_seconds``: sum of the per-case ``seconds``
                    the C++ host measured around DUT execution (the loop only, not
                    model construction/reset)
``round_trip``      ``fuzz.stats.round_trip_seconds``: input handover -> parsed
                    case line, per case; it *contains* ``dut_seconds``
``generation`` / ``parse`` / ``feedback``
                    the session's own Python-side spans, per case
``cases/s``         executed / session wall, and executed / ``total_seconds``
``DUT share``       ``dut_seconds / session wall`` and ``dut_seconds / total``
per-case DUT ms     median and p95 of ``fuzz.cases[].case.seconds`` (nearest-rank
                    p95; the value is the host's own DUT loop span)

The A/B runs the *same* fixed records through the same cache once per arm per
repetition (three repetitions by default): ``--online`` (default event layer) and
``--online --quiet``, interleaved.  It reports wall,
CPU, log bytes, log line counts by prefix, the per-case DUT seconds sum and
whether the case statuses are identical, and it never calls the difference a
speedup unless the wall difference exceeds the measured run-to-run range.

Only the files named on the command line are written: one new output directory
per measured run below ``--output`` (the entry refuses an existing one), the
process stdout/stderr below ``--output/_process``, ``measurements.json`` and
``REPORT.md``.  No entry, host, profile, config or ``src/`` file is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = 'scripts/run_inprocess_f1f6.py'
DEFAULT_CONFIG = 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json'
DEFAULT_AB_CONFIG = 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json'
DEFAULT_CACHE = 'runs/_probe/cache'
FRESH_CACHE = 'runs/fuzz-opt-cache'
DEFAULT_OUTPUT = 'runs/fuzz-opt-20261101'

#: The fixed-input A/B unit and how often it is repeated: 4 records * 25 = the
#: 100 records the fixed path is measured with.
FIXED_UNIT = 'F1:2ab00693,F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff'
FIXED_REPEAT = 25
DEFAULT_FIXED_RECORDS = ','.join([FIXED_UNIT] * FIXED_REPEAT)
DEFAULT_AB_MAX_TICKS = 200000

#: Only these two printed statuses mean the batch itself completed.  A failed
#: *case* is a finding of the loop and is allowed; a failed *batch* is not.
ALLOWED_FUZZ_STATUS = ('fuzz_completed', 'fuzz_completed_with_findings')

#: Log line classification the A/B reports.  ``irq_*`` and the prelude
#: declaration lines are deliberately folded into ``other``.
LOG_PREFIXES = ('case', 'ifetch', 'rvfi', 'retire', 'apb', 'cpu_*', 'dma_*', 'other')

FUZZ_METRICS = (
    'wall_seconds', 'cpu_seconds', 'maxrss_kb',
    'total_seconds', 'run_seconds', 'link_seconds', 'preparation_seconds',
    'prepare_other_seconds', 'wall_minus_total_seconds', 'session_wall_seconds',
    'cases_executed', 'cases_passed', 'cases_failed', 'ticks_total',
    'dut_seconds_sum', 'runtime_seconds',
    'cases_per_session_second', 'cases_per_total_second',
    'dut_share_of_session', 'dut_share_of_total',
    'generation_seconds', 'parse_seconds', 'feedback_seconds',
    'round_trip_seconds', 'unaccounted_session_seconds',
    'corpus_entries', 'distinct_features', 'findings',
    'case_ms_median', 'case_ms_p95', 'case_ms_min', 'case_ms_max',
    'case_ticks_median', 'case_rows_recorded', 'case_seconds_sum',
)

AB_METRICS = (
    'wall_seconds', 'cpu_seconds', 'maxrss_kb',
    'total_seconds', 'run_seconds', 'link_seconds', 'preparation_seconds',
    'dut_seconds_sum', 'ticks_total', 'log_bytes', 'log_lines',
)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def resolve(path):
    """Resolve one command-line path against the repository root."""
    candidate = Path(path)
    return candidate if candidate.is_absolute() else (ROOT / candidate)


def relative(path):
    """Repository-relative text for a path, for the reproducible commands."""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _terminate_group(pid):
    try:
        os.killpg(os.getpgid(pid), 9)
    except (ProcessLookupError, PermissionError):
        pass


def run_child(argv, *, cwd, stdout_path, stderr_path, timeout):
    """Run one child and measure around it with ``wait4`` (wall + rusage).

    ``subprocess.run`` reaps the child itself and loses the rusage, so the wait
    is explicit here: that is what makes the per-run CPU/maxrss rows possible.
    A child that outlives ``timeout`` is killed as a process group and reported
    as a timeout, never silently dropped.
    """
    stdout_path, stderr_path = Path(stdout_path), Path(stderr_path)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started, started_wall = time.monotonic(), time.time()
    timed_out = False
    with stdout_path.open('wb') as out_handle, stderr_path.open('wb') as err_handle:
        process = subprocess.Popen(
            [str(value) for value in argv], cwd=str(cwd),
            stdin=subprocess.DEVNULL, stdout=out_handle, stderr=err_handle,
            start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    _terminate_group(process.pid)
                    pid, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(0.02)
            returncode = os.waitstatus_to_exitcode(status)
            process.returncode = returncode
        except BaseException:
            _terminate_group(process.pid)
            raise
        finally:
            if process.returncode is None:
                process.returncode = -1
    ended, ended_wall = time.monotonic(), time.time()
    return dict(wall_seconds=ended - started, started_wall=started_wall,
                ended_wall=ended_wall, returncode=returncode, timed_out=timed_out,
                cpu_seconds=usage.ru_utime + usage.ru_stime,
                maxrss_kb=usage.ru_maxrss,
                stdout=str(stdout_path), stderr=str(stderr_path))


def read_json(path):
    """Return ``(document, error)``; a missing or broken file is not a pass."""
    path = Path(path)
    if not path.is_file():
        return None, 'missing'
    try:
        return json.loads(path.read_text()), None
    except (OSError, ValueError) as error:
        return None, 'unreadable: ' + str(error)


def printed_json(text):
    """The entry's final JSON line: the last decodable object that states a status."""
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            document = json.loads(line)
        except ValueError:
            continue
        if isinstance(document, dict) and 'status' in document:
            return document
    return None


def log_facts(path):
    """Bytes, lines and the prefix histogram of one run.log."""
    path = Path(path)
    if not path.is_file():
        return dict(bytes=None, lines=None, prefixes={name: None for name in LOG_PREFIXES},
                    exists=False)
    text = path.read_text(errors='replace')
    lines = text.splitlines()
    counts = {name: 0 for name in LOG_PREFIXES}
    for line in lines:
        tokens = line.split(None, 1)
        first = tokens[0] if tokens else ''
        if first in ('case', 'ifetch', 'rvfi', 'retire', 'apb'):
            counts[first] += 1
        elif first.startswith('cpu_'):
            counts['cpu_*'] += 1
        elif first.startswith('dma_'):
            counts['dma_*'] += 1
        else:
            counts['other'] += 1
    return dict(bytes=path.stat().st_size, lines=len(lines), prefixes=counts,
                exists=True)


def percentile(values, fraction):
    """Nearest-rank percentile; ``None`` for an empty sample."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def case_stats(seconds):
    """Median/p95/min/max of a per-case seconds list, in milliseconds."""
    if not seconds:
        return dict(count=0, median_ms=None, p95_ms=None, min_ms=None, max_ms=None)
    milliseconds = [value * 1000.0 for value in seconds]
    return dict(count=len(milliseconds),
                median_ms=statistics.median(milliseconds),
                p95_ms=percentile(milliseconds, 0.95),
                min_ms=min(milliseconds), max_ms=max(milliseconds))


def medians(rows, keys):
    """Median of every numeric metric across the recorded rows."""
    document = {}
    for key in keys:
        values = [row[key] for row in rows
                  if isinstance(row.get(key), (int, float))]
        document[key] = statistics.median(values) if values else None
    return document


def ranges(rows, keys):
    """Within-arm range (max-min) per metric: the measured run-to-run noise."""
    document = {}
    for key in keys:
        values = [row[key] for row in rows
                  if isinstance(row.get(key), (int, float))]
        document[key] = (max(values) - min(values)) if len(values) > 1 else None
    return document


def source_state(paths=('src/myfuzz', 'scripts', 'configs')):
    """Fingerprint of the files the measured work depends on.

    Other agents may edit this repository while a campaign runs; two rows are
    only comparable when this digest is equal, so it is recorded per run rather
    than assumed frozen.
    """
    entries = []
    for root in paths:
        directory = ROOT / root
        for path in sorted(directory.rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.h', '.hpp', '.cpp', '.json'):
                stat = path.stat()
                entries.append('%s\0%d\0%d' % (path.relative_to(ROOT), stat.st_size,
                                                stat.st_mtime_ns))
    return hashlib.sha256('\n'.join(entries).encode()).hexdigest()


def load_average():
    try:
        return list(os.getloadavg())
    except OSError:
        return None


def environment():
    try:
        cpu_model = next(line.split(':', 1)[1].strip() for line in
                         Path('/proc/cpuinfo').read_text().splitlines()
                         if line.startswith('model name'))
    except (OSError, StopIteration):
        cpu_model = 'unknown'
    return dict(python=sys.version.split()[0], platform=platform.platform(),
                cpu_model=cpu_model, cpu_count=os.cpu_count())


def count_records(text):
    return len([part for part in text.split(',') if part])


def failed_flow_counts(row):
    """Which flows the failed cases of one recorded run belong to.

    Derived from the recorded ``records``/``case_statuses`` lists, so it is also
    available for rows written before this field existed.
    """
    counts = {}
    for record, status in zip(row.get('records') or (), row.get('case_statuses') or ()):
        if status != 'observations_passed':
            flow = (record or '?').split(':')[0]
            counts[flow] = counts.get(flow, 0) + 1
    return counts


def derived_comparison(document):
    """Recompute the derived blocks from the raw rows (no new measurement).

    ``measurements.json`` keeps every raw row; the medians and comparisons are a
    pure function of them, so ``--report-only`` can refresh them after the
    harness itself changed instead of re-running RTL.
    """
    runs = document['runs']
    document['comparison'] = dict(
        fuzz_first_vs_steady=fuzz_comparison(runs['fuzz']),
        event_layer=event_layer_comparison(runs['ab']['online'], runs['ab']['quiet']))
    document['medians'] = dict(
        fuzz_all=medians(runs['fuzz'], FUZZ_METRICS),
        fuzz_steady=(medians(runs['fuzz'][1:], FUZZ_METRICS)
                     if len(runs['fuzz']) > 1 else None),
        ab_online=medians(runs['ab']['online'], AB_METRICS),
        ab_quiet=medians(runs['ab']['quiet'], AB_METRICS))
    return document


# --------------------------------------------------------------------------- #
# Measuring one fuzz repetition
# --------------------------------------------------------------------------- #
def measure_fuzz_run(number, *, config, cache, output, cases, seed, entry,
                     process_dir, timeout):
    """Run one closed-loop batch into a new directory and fold its files."""
    name = 'fuzz-r%d' % number
    directory = Path(output) / name
    argv = [sys.executable, str(entry),
            '--config', str(config), '--cache', str(cache),
            '--output', str(directory), '--fuzz',
            '--cases', str(cases), '--seed', str(seed)]
    child = run_child(argv, cwd=ROOT,
                      stdout_path=Path(process_dir) / (name + '.stdout'),
                      stderr_path=Path(process_dir) / (name + '.stderr'),
                      timeout=timeout)
    stdout_text = Path(child['stdout']).read_text(errors='replace')
    printed = printed_json(stdout_text)
    summary, summary_error = read_json(directory / 'summary.json')
    session, session_error = read_json(directory / 'fuzz.json')
    stats = (session or {}).get('stats') or {}
    session_summary = (session or {}).get('summary') or {}
    fuzz_result = (summary or {}).get('fuzz_result') or {}

    total = (summary or {}).get('total_seconds')
    run_seconds = (summary or {}).get('run_seconds')
    link = (summary or {}).get('link_seconds')
    preparation = None
    prepare_other = None
    if isinstance(total, (int, float)) and isinstance(run_seconds, (int, float)):
        preparation = total - run_seconds
        if isinstance(link, (int, float)):
            prepare_other = preparation - link

    session_wall = (session or {}).get('wall_seconds')
    executed = stats.get('executed')
    passed = stats.get('passed')
    failed = stats.get('failed')
    dut = stats.get('dut_seconds')
    generation = stats.get('generation_seconds')
    parse = stats.get('parse_seconds')
    feedback = stats.get('feedback_seconds')
    round_trip = stats.get('round_trip_seconds')
    unaccounted = None
    if isinstance(session_wall, (int, float)) and all(
            isinstance(value, (int, float))
            for value in (generation, parse, feedback, round_trip)):
        unaccounted = session_wall - (generation + parse + feedback + round_trip)

    def ratio(numerator, denominator):
        if not isinstance(numerator, (int, float)) or not isinstance(denominator,
                                                                      (int, float)):
            return None
        return numerator / denominator if denominator else None

    # Per-case DUT spans: ``fuzz.cases[].case.seconds`` is the host's own loop
    # span for that case; a recorded case without a numeric span is skipped.
    case_rows = (session or {}).get('cases') or []
    seconds = []
    tick_values = []
    flows = {}
    for row in case_rows:
        case = row.get('case') or {}
        value = case.get('seconds')
        if isinstance(value, (int, float)):
            seconds.append(float(value))
        ticks = case.get('ticks')
        if isinstance(ticks, (int, float)):
            tick_values.append(int(ticks))
        flow = row.get('flow') or case.get('flow')
        bucket = flows.setdefault(flow, dict(cases=0, seconds=[], ticks=[]))
        bucket['cases'] += 1
        if isinstance(value, (int, float)):
            bucket['seconds'].append(float(value))
        if isinstance(ticks, (int, float)):
            bucket['ticks'].append(int(ticks))
    per_flow = {}
    for flow, bucket in sorted(flows.items(), key=lambda item: str(item[0])):
        stats_flow = case_stats(bucket['seconds'])
        per_flow[str(flow)] = dict(
            cases=bucket['cases'], median_ms=stats_flow['median_ms'],
            p95_ms=stats_flow['p95_ms'],
            median_ticks=(statistics.median(bucket['ticks'])
                          if bucket['ticks'] else None))
    stats_cases = case_stats(seconds)

    corpus_entries = fuzz_result.get('corpus_entries')
    if corpus_entries is None:
        corpus_entries = len(((session or {}).get('corpus') or {}).get('entries') or ())
    distinct = fuzz_result.get('distinct_features')
    if distinct is None:
        distinct = ((session or {}).get('feedback') or {}).get('distinct')

    problems = []
    if child['timed_out']:
        problems.append('the entry exceeded the per-run timeout')
    if child['returncode'] != 0:
        problems.append('the entry exited %s' % child['returncode'])
    if printed is None:
        problems.append('the entry printed no JSON status line')
    elif printed.get('status') not in ALLOWED_FUZZ_STATUS:
        problems.append('printed status %r is not a completed fuzz batch'
                        % printed.get('status'))
    if summary_error is not None:
        problems.append('summary.json: ' + summary_error)
    elif printed is not None and (summary or {}).get('status') != printed.get('status'):
        problems.append('summary.json status %r disagrees with the printed %r'
                        % ((summary or {}).get('status'), printed.get('status')))
    if session_error is not None:
        problems.append('fuzz.json: ' + session_error)
    else:
        if (session or {}).get('schema_version') != 'inprocess_fuzz_session.v1':
            problems.append('fuzz.json has an unexpected schema')
        if (session or {}).get('status') != 'completed':
            problems.append('the fuzz session status is %r'
                            % (session or {}).get('status'))
        if isinstance(executed, int) and executed != cases:
            problems.append('executed %d of the %d declared cases' % (executed, cases))
        if isinstance(passed, int) and isinstance(failed, int) and isinstance(
                executed, int) and passed + failed != executed:
            problems.append('passed+failed does not equal executed')
    if printed is not None and isinstance(printed.get('cases'), int) and isinstance(
            executed, int) and printed['cases'] != executed:
        problems.append('the printed case count disagrees with the session')

    return dict(
        number=number, kind='fuzz', name=name, output=str(directory), argv=argv,
        config=str(config), cache=str(cache), cases_declared=cases, seed=seed,
        returncode=child['returncode'], timed_out=child['timed_out'],
        wall_seconds=child['wall_seconds'], cpu_seconds=child['cpu_seconds'],
        maxrss_kb=child['maxrss_kb'], started_wall=child['started_wall'],
        ended_wall=child['ended_wall'], stdout=child['stdout'], stderr=child['stderr'],
        printed=printed, status=(printed or {}).get('status'),
        summary_status=(summary or {}).get('status'),
        session_status=(session or {}).get('status'),
        link_cache_hit=(summary or {}).get('link_cache_hit'),
        source_state=source_state(), load_average=load_average(),
        total_seconds=total, run_seconds=run_seconds, link_seconds=link,
        preparation_seconds=preparation, prepare_other_seconds=prepare_other,
        wall_minus_total_seconds=(child['wall_seconds'] - total
                                  if isinstance(total, (int, float)) else None),
        session_wall_seconds=session_wall,
        cases_executed=executed, cases_passed=passed, cases_failed=failed,
        ticks_total=session_summary.get('ticks'),
        dut_seconds_sum=dut, runtime_seconds=session_summary.get('runtime_seconds'),
        cases_per_session_second=ratio(executed, session_wall),
        cases_per_total_second=ratio(executed, total),
        dut_share_of_session=ratio(dut, session_wall),
        dut_share_of_total=ratio(dut, total),
        generation_seconds=generation, parse_seconds=parse,
        feedback_seconds=feedback, round_trip_seconds=round_trip,
        max_round_trip_seconds=stats.get('max_round_trip_seconds'),
        unaccounted_session_seconds=unaccounted,
        corpus_entries=corpus_entries, distinct_features=distinct,
        findings=len((session or {}).get('findings') or ()),
        case_rows_recorded=len(case_rows),
        cases_truncated=(session or {}).get('cases_truncated'),
        case_ms_median=stats_cases['median_ms'], case_ms_p95=stats_cases['p95_ms'],
        case_ms_min=stats_cases['min_ms'], case_ms_max=stats_cases['max_ms'],
        case_ticks_median=(statistics.median(tick_values) if tick_values else None),
        case_seconds_sum=sum(seconds) if seconds else None,
        per_flow=per_flow,
        records=[row.get('record') for row in case_rows],
        case_statuses=[row.get('status') for row in case_rows],
        log=log_facts(directory / 'run.log'),
        problems=problems,
    )


# --------------------------------------------------------------------------- #
# Measuring one fixed-input arm
# --------------------------------------------------------------------------- #
def measure_ab_run(number, *, arm, config, cache, output, records, text,
                   max_ticks, entry, process_dir, timeout):
    """Run one fixed-input arm (``online`` or ``quiet``) and fold its files."""
    name = 'ab-%s-r%d' % (arm, number)
    directory = Path(output) / name
    argv = [sys.executable, str(entry),
            '--config', str(config), '--cache', str(cache),
            '--output', str(directory), '--records', text, '--online',
            '--max-ticks', str(max_ticks)]
    if arm == 'quiet':
        argv.append('--quiet')
    child = run_child(argv, cwd=ROOT,
                      stdout_path=Path(process_dir) / (name + '.stdout'),
                      stderr_path=Path(process_dir) / (name + '.stderr'),
                      timeout=timeout)
    printed = printed_json(Path(child['stdout']).read_text(errors='replace'))
    summary, summary_error = read_json(directory / 'summary.json')
    cases = (summary or {}).get('cases') or []
    case_rows = [dict(index=case.get('index'), record=case.get('record'),
                      status=case.get('status'), ticks=case.get('ticks'),
                      seconds=case.get('seconds')) for case in cases]
    seconds = [float(case['seconds']) for case in case_rows
               if isinstance(case.get('seconds'), (int, float))]
    ticks_total = ((summary or {}).get('run_summary') or {}).get('ticks')
    if ticks_total is None:
        ticks_total = sum(case['ticks'] for case in case_rows
                          if isinstance(case.get('ticks'), (int, float)))
    total = (summary or {}).get('total_seconds')
    run_seconds = (summary or {}).get('run_seconds')
    link = (summary or {}).get('link_seconds')
    preparation = None
    if isinstance(total, (int, float)) and isinstance(run_seconds, (int, float)):
        preparation = total - run_seconds

    problems = []
    if child['timed_out']:
        problems.append('%s: the entry exceeded the per-run timeout' % name)
    if child['returncode'] != 0:
        problems.append('%s: the entry exited %s' % (name, child['returncode']))
    if summary_error is not None:
        problems.append('%s: summary.json: %s' % (name, summary_error))
    else:
        if (summary or {}).get('status') != 'observations_passed':
            problems.append('%s: summary.json status is %r'
                            % (name, (summary or {}).get('status')))
        if len(case_rows) != records:
            problems.append('%s: %d cases recorded, %d records sent'
                            % (name, len(case_rows), records))
        if any(case['status'] != 'observations_passed' for case in case_rows):
            problems.append('%s: at least one fixed case did not pass' % name)
    if printed is not None and printed.get('status') != 'observations_passed':
        problems.append('%s: printed status is %r' % (name, printed.get('status')))

    log = log_facts(directory / 'run.log')
    return dict(
        number=number, kind='ab', arm=arm, name=name, output=str(directory),
        argv=argv, config=str(config), cache=str(cache), records=records,
        returncode=child['returncode'], timed_out=child['timed_out'],
        wall_seconds=child['wall_seconds'], cpu_seconds=child['cpu_seconds'],
        maxrss_kb=child['maxrss_kb'], started_wall=child['started_wall'],
        ended_wall=child['ended_wall'], stdout=child['stdout'], stderr=child['stderr'],
        printed=printed, status=(printed or {}).get('status'),
        summary_status=(summary or {}).get('status'),
        input_mode=(summary or {}).get('input_mode'),
        event_layer=(summary or {}).get('event_layer'),
        link_cache_hit=(summary or {}).get('link_cache_hit'),
        source_state=source_state(), load_average=load_average(),
        total_seconds=total, run_seconds=run_seconds, link_seconds=link,
        preparation_seconds=preparation,
        ticks_total=ticks_total,
        dut_seconds_sum=sum(seconds) if seconds else None,
        case_ms_median=case_stats(seconds)['median_ms'],
        case_rows=case_rows, log=log,
        log_bytes=log['bytes'], log_lines=log['lines'],
        problems=problems,
    )


# --------------------------------------------------------------------------- #
# Comparisons
# --------------------------------------------------------------------------- #
def fuzz_comparison(runs):
    """First repetition vs the steady-state median, and input identity."""
    first = runs[0] if runs else None
    steady = runs[1:] if len(runs) > 1 else []
    document = dict(
        first=dict(number=first['number'], wall_seconds=first['wall_seconds'],
                   total_seconds=first['total_seconds'],
                   run_seconds=first['run_seconds'],
                   preparation_seconds=first['preparation_seconds'],
                   session_wall_seconds=first['session_wall_seconds'],
                   cases_per_session_second=first['cases_per_session_second'],
                   dut_seconds_sum=first['dut_seconds_sum'],
                   link_cache_hit=first['link_cache_hit']) if first else None,
        steady_median=medians(steady, FUZZ_METRICS) if steady else None,
        all_median=medians(runs, FUZZ_METRICS),
        steady_sample_count=len(steady),
        inputs_identical=[run['records'] == runs[0]['records'] for run in runs],
        case_statuses_identical=[run['case_statuses'] == runs[0]['case_statuses']
                                 for run in runs],
        source_states=sorted({run['source_state'] for run in runs}),
    )
    if first is not None and steady:
        delta = {}
        for key in ('wall_seconds', 'total_seconds', 'run_seconds',
                    'preparation_seconds', 'session_wall_seconds',
                    'dut_seconds_sum'):
            steady_value = document['steady_median'].get(key)
            if isinstance(first.get(key), (int, float)) and isinstance(
                    steady_value, (int, float)):
                delta[key] = first[key] - steady_value
        document['first_minus_steady'] = delta
    return document


def event_layer_comparison(online, quiet):
    """The fixed-input A/B: medians, within-arm ranges, deltas and identity."""
    arm_documents = {}
    for label, rows in (('online', online), ('quiet', quiet)):
        arm_documents[label] = dict(
            samples=len(rows),
            wall_seconds=[row['wall_seconds'] for row in rows],
            run_seconds=[row['run_seconds'] for row in rows],
            cpu_seconds=[row['cpu_seconds'] for row in rows],
            dut_seconds=[row['dut_seconds_sum'] for row in rows],
            log_bytes=[row['log']['bytes'] for row in rows],
            log_lines=[row['log']['lines'] for row in rows],
            medians=medians(rows, AB_METRICS),
            ranges=ranges(rows, AB_METRICS),
            prefix_counts=[row['log']['prefixes'] for row in rows],
            prefix_counts_identical=all(row['log']['prefixes'] == rows[0]['log']['prefixes']
                                        for row in rows),
            case_statuses=[row['case_rows'] and
                           [(case['record'], case['status']) for case in row['case_rows']]
                           for row in rows],
            link_cache_hit=[row['link_cache_hit'] for row in rows],
            source_state=sorted({row['source_state'] for row in rows}),
        )
    delta = {}
    for key in ('wall_seconds', 'cpu_seconds', 'run_seconds', 'dut_seconds_sum',
                'total_seconds', 'preparation_seconds', 'log_bytes', 'log_lines'):
        before = arm_documents['online']['medians'].get(key)
        after = arm_documents['quiet']['medians'].get(key)
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            delta[key] = after - before
    noise = {}
    for key in ('wall_seconds', 'cpu_seconds', 'run_seconds'):
        values = [arm_documents[label]['ranges'].get(key) for label in ('online', 'quiet')]
        known = [value for value in values if isinstance(value, (int, float))]
        noise[key] = max(known) if known else None
    status_lists = [statuses for statuses in
                    (arm_documents['online']['case_statuses'] +
                     arm_documents['quiet']['case_statuses']) if statuses is not None]
    identical = bool(status_lists) and all(
        statuses == status_lists[0] for statuses in status_lists)
    resolvable = {}
    for key in ('wall_seconds', 'cpu_seconds', 'run_seconds'):
        value = delta.get(key)
        band = noise.get(key)
        resolvable[key] = None if value is None or band is None else abs(value) > band
    tick_values = [row['ticks_total'] for row in list(online) + list(quiet)
                   if isinstance(row.get('ticks_total'), (int, float))]
    suppressed_lines = None
    if isinstance(delta.get('log_lines'), (int, float)):
        suppressed_lines = abs(delta['log_lines'])
    return dict(
        records_sent=None if not online else online[0]['records'],
        arms=arm_documents, delta_quiet_minus_online=delta, noise_range=noise,
        difference_exceeds_noise=resolvable,
        case_statuses_identical=identical,
        ticks_identical=(len(set(tick_values)) <= 1 if tick_values else None),
        suppressed_log_lines=suppressed_lines,
        sample_count=min(arm_documents['online']['samples'],
                         arm_documents['quiet']['samples']),
        wall_delta_share=(abs(delta['wall_seconds']) /
                          arm_documents['online']['medians']['wall_seconds']
                          if isinstance(delta.get('wall_seconds'), (int, float))
                          and arm_documents['online']['medians'].get('wall_seconds')
                          else None),
        log_bytes_ratio=(delta['log_bytes'] /
                         arm_documents['online']['medians']['log_bytes']
                         if isinstance(delta.get('log_bytes'), (int, float))
                         and arm_documents['online']['medians'].get('log_bytes')
                         else None),
    )


# --------------------------------------------------------------------------- #
# Report rendering (Chinese, like the other reports in the repository)
# --------------------------------------------------------------------------- #
def fmt(value, digits=3):
    if not isinstance(value, (int, float)):
        return 'unknown'
    return ('%.' + str(digits) + 'f') % value


def pct(value):
    if not isinstance(value, (int, float)):
        return 'unknown'
    return '%.1f%%' % (value * 100.0)


def integer(value):
    return 'unknown' if not isinstance(value, (int, float)) else str(int(value))


def table(header, rows):
    lines = ['| ' + ' | '.join(header) + ' |',
             '| ' + ' | '.join('---' for _ in header) + ' |']
    for row in rows:
        lines.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
    return '\n'.join(lines)


def fixed_records_one_liner():
    return ("python3 - <<'PY'\n"
            "print(','.join(['" + FIXED_UNIT + "'] * " + str(FIXED_REPEAT) + "))\n"
            "PY")


def render_report(document):
    """Render ``REPORT.md`` from the recorded document (never from memory)."""
    settings = document['settings']
    runs = document['runs']['fuzz']
    steady = document['comparison']['fuzz_first_vs_steady']
    comparison = document['comparison']['event_layer']
    all_median = steady['all_median']
    steady_median = steady['steady_median'] or {}
    first = runs[0] if runs else None
    online = comparison['arms']['online']
    quiet = comparison['arms']['quiet']
    online_median = online['medians']
    quiet_median = quiet['medians']
    delta = comparison['delta_quiet_minus_online']
    noise = comparison['noise_range']
    resolvable = comparison['difference_exceeds_noise']
    wall_resolvable = resolvable.get('wall_seconds')
    run_resolvable = resolvable.get('run_seconds')

    total_reference = all_median.get('total_seconds')
    preparation = all_median.get('preparation_seconds')
    run_seconds = all_median.get('run_seconds')
    session_wall = all_median.get('session_wall_seconds')
    dut = all_median.get('dut_seconds_sum')
    cases = all_median.get('cases_executed')
    session_rate = all_median.get('cases_per_session_second')
    total_rate = all_median.get('cases_per_total_second')
    case_median = all_median.get('case_ms_median')
    case_p95 = all_median.get('case_ms_p95')

    def event_verdict():
        if not comparison['sample_count'] or comparison['sample_count'] < 2:
            return ('两个臂各只有 1 次样本，无法估计重复噪声；本次不把 wall 差异称为加速。')
        if wall_resolvable is False:
            return ('wall 差异 %s s 小于臂内极差（%s s），因此不能称为加速；'
                    '可分辨的是 run.log 体积与行数，以及事件层的固定开销本身。'
                    % (fmt(delta.get('wall_seconds')), fmt(noise.get('wall_seconds'))))
        if wall_resolvable is None:
            return 'wall 差异没有可比的噪声带，不能判定。'
        if delta.get('wall_seconds', 0.0) < 0:
            return ('quiet 臂 wall 中位数比默认事件层低 %s s（%s），超过臂内极差 %s s；'
                    '这只是一组固定输入、%d 次样本的对照，不能外推到 fuzz 闭环或别的组合。'
                    % (fmt(-delta['wall_seconds']),
                       pct(comparison['wall_delta_share']),
                       fmt(noise.get('wall_seconds')), comparison['sample_count']))
        return ('quiet 臂 wall 中位数反而高 %s s，超过臂内极差 %s s；'
                '该样本不支持"关事件更快"。'
                % (fmt(delta.get('wall_seconds')), fmt(noise.get('wall_seconds'))))

    phase_rows = []
    for run in runs:
        marker = '（首轮）' if run['number'] == 1 else ''
        phase_rows.append([
            'r%d%s' % (run['number'], marker), fmt(run['wall_seconds']),
            fmt(run['total_seconds']), fmt(run['run_seconds']),
            fmt(run['link_seconds']), fmt(run['preparation_seconds']),
            fmt(run['session_wall_seconds']),
            '%s（%s/%s）' % (integer(run['cases_executed']),
                           integer(run['cases_passed']), integer(run['cases_failed'])),
            integer(run['ticks_total']), fmt(run['dut_seconds_sum'], 6),
            fmt(run['cases_per_session_second'], 1),
            fmt(run['cases_per_total_second'], 1),
            pct(run['dut_share_of_session']), run['status'] or 'unknown'])
    if steady_median:
        phase_rows.append([
            ('稳态中位数（第 2–%d 次）' % len(runs) if len(runs) > 2
             else '第 2 次（唯一的稳态样本）'),
            fmt(steady_median.get('wall_seconds')),
            fmt(steady_median.get('total_seconds')),
            fmt(steady_median.get('run_seconds')),
            fmt(steady_median.get('link_seconds')),
            fmt(steady_median.get('preparation_seconds')),
            fmt(steady_median.get('session_wall_seconds')),
            '%s（%s/%s）' % (integer(steady_median.get('cases_executed')),
                           integer(steady_median.get('cases_passed')),
                           integer(steady_median.get('cases_failed'))),
            integer(steady_median.get('ticks_total')),
            fmt(steady_median.get('dut_seconds_sum'), 6),
            fmt(steady_median.get('cases_per_session_second'), 1),
            fmt(steady_median.get('cases_per_total_second'), 1),
            pct(steady_median.get('dut_share_of_session')), '—'])
    phase_rows.append([
        '全部 %d 次中位数' % len(runs), fmt(all_median.get('wall_seconds')),
        fmt(total_reference), fmt(run_seconds), fmt(all_median.get('link_seconds')),
        fmt(preparation), fmt(session_wall),
        '%s（%s/%s）' % (integer(cases), integer(all_median.get('cases_passed')),
                       integer(all_median.get('cases_failed'))),
        integer(all_median.get('ticks_total')), fmt(dut, 6),
        fmt(session_rate, 1), fmt(total_rate, 1),
        pct(all_median.get('dut_share_of_session')), '—'])

    case_rows = []
    for run in runs:
        case_rows.append([
            'r%d' % run['number'], fmt(run['case_ms_median']),
            fmt(run['case_ms_p95']), fmt(run['case_ms_min']),
            fmt(run['case_ms_max']), fmt(run['case_ticks_median'], 1),
            integer(run['case_rows_recorded']),
            fmt(run['case_seconds_sum'], 6),
            fmt(run['runtime_seconds'], 6)])
    case_rows.append(['全部中位数', fmt(case_median), fmt(case_p95),
                      fmt(all_median.get('case_ms_min')),
                      fmt(all_median.get('case_ms_max')),
                      fmt(all_median.get('case_ticks_median'), 1),
                      integer(all_median.get('case_rows_recorded')),
                      fmt(all_median.get('case_seconds_sum'), 6),
                      fmt(all_median.get('runtime_seconds'), 6)])

    flow_rows = []
    if first is not None:
        for flow, entry in sorted(first['per_flow'].items()):
            flow_rows.append([flow, integer(entry['cases']), fmt(entry['median_ms']),
                              fmt(entry['p95_ms']), fmt(entry['median_ticks'], 1)])

    composition_rows = [
        ['generation（输入生成/变异）', fmt(all_median.get('generation_seconds')),
         pct(None if not isinstance(session_wall, (int, float))
             or not isinstance(all_median.get('generation_seconds'), (int, float))
             else all_median['generation_seconds'] / session_wall)],
        ['parse（case 行解析）', fmt(all_median.get('parse_seconds')),
         pct(None if not isinstance(session_wall, (int, float))
             or not isinstance(all_median.get('parse_seconds'), (int, float))
             else all_median['parse_seconds'] / session_wall)],
        ['feedback（特征/语料更新）', fmt(all_median.get('feedback_seconds')),
         pct(None if not isinstance(session_wall, (int, float))
             or not isinstance(all_median.get('feedback_seconds'), (int, float))
             else all_median['feedback_seconds'] / session_wall)],
        ['round-trip（交接到 case 行，含 DUT）',
         fmt(all_median.get('round_trip_seconds')),
         pct(None if not isinstance(session_wall, (int, float))
             or not isinstance(all_median.get('round_trip_seconds'), (int, float))
             else all_median['round_trip_seconds'] / session_wall)],
        ['其中 DUT（host 侧每例 seconds 之和）', fmt(dut, 6),
         pct(all_median.get('dut_share_of_session'))],
        ['会话内未归因（session wall − 上述四项）',
         fmt(all_median.get('unaccounted_session_seconds')),
         pct(None if not isinstance(session_wall, (int, float))
             or not isinstance(all_median.get('unaccounted_session_seconds'),
                               (int, float))
             else all_median['unaccounted_session_seconds'] / session_wall)],
    ]

    ab_rows = []
    for label, arm in (('online（默认事件层）', online), ('online --quiet', quiet)):
        ab_rows.append([
            label, integer(arm['samples']), fmt(arm['medians'].get('wall_seconds')),
            fmt(arm['ranges'].get('wall_seconds')),
            fmt(arm['medians'].get('run_seconds')),
            fmt(arm['medians'].get('cpu_seconds')),
            integer(arm['medians'].get('log_bytes')),
            integer(arm['medians'].get('log_lines')),
            integer(arm['medians'].get('ticks_total')),
            fmt(arm['medians'].get('dut_seconds_sum'), 6),
            '是' if arm['prefix_counts_identical'] else '否'])

    prefix_header = ['臂'] + list(LOG_PREFIXES)
    prefix_rows = []
    for label, arm in (('online', online), ('quiet', quiet)):
        counts = arm['prefix_counts'][0]
        prefix_rows.append([label] + [integer(counts.get(name))
                                      for name in LOG_PREFIXES])

    failed_runs = document.get('failures') or []
    failure_text = ('无。' if not failed_runs else
                    '\n'.join('* %s：%s（目录 %s）' % (row.get('name'), row.get('problem'),
                                                      row.get('output'))
                              for row in failed_runs))

    lines = []
    lines.append('# 单进程 fuzz 闭环性能测量（%s）' % document['campaign_date'])
    lines.append('')
    lines.append('测量时间：%s；由 `scripts/measure_fuzz_phases.py` 从 `measurements.json` '
                 '渲染，表中每个数都来自该文件（`--report-only` 只重渲染、不重测）。'
                 % document['generated'])
    lines.append('')
    lines.append('## 短答')
    lines.append('')
    lines.append('- 本批 %s 例 fuzz：wall 中位数 %s s = 解释器启动/退出 %s s + '
                 '`total_seconds` %s s；其中准备（`total_seconds − run_seconds`）%s s、'
                 'host 进程段 `run_seconds` %s s。闭环会话（`fuzz.wall_seconds`）%s s，'
                 'DUT（host 侧每例 `seconds` 之和）%s s，占会话 %s、占总 wall %s。'
                 % (integer(cases), fmt(all_median.get('wall_seconds')),
                    fmt(all_median.get('wall_minus_total_seconds')),
                    fmt(all_median.get('total_seconds')), fmt(preparation),
                    fmt(run_seconds), fmt(session_wall), fmt(dut, 6),
                    pct(all_median.get('dut_share_of_session')),
                    pct(all_median.get('dut_share_of_total'))))
    lines.append('- 用例通过/失败：%s/%s；ticks 合计 %s；语料条目 %s、distinct features %s；'
                 '状态 %s。'
                 % (integer(all_median.get('cases_passed')),
                    integer(all_median.get('cases_failed')),
                    integer(all_median.get('ticks_total')),
                    integer(all_median.get('corpus_entries')),
                    integer(all_median.get('distinct_features')),
                    '、'.join(sorted({run['status'] or 'unknown' for run in runs}))))
    lines.append('- 闭环吞吐 %s 例/秒（会话口径）、%s 例/秒（`total_seconds` 口径）；'
                 '单例 DUT 中位数 %s ms，p95 %s ms。'
                 % (fmt(session_rate, 1), fmt(total_rate, 1), fmt(case_median),
                    fmt(case_p95)))
    lines.append('- 固定输入事件层 A/B（%d 条记录，每臂 %d 次）：run.log 由 %s 字节降到 %s 字节'
                 '（%s），两臂 case 状态逐条相同；wall 差异 %s s，臂内极差 %s s。%s'
                 % (settings['fixed_records']['count'], comparison['sample_count'],
                    integer(online_median.get('log_bytes')),
                    integer(quiet_median.get('log_bytes')),
                    ('%.0f%%' % (comparison['log_bytes_ratio'] * 100.0)
                     if isinstance(comparison.get('log_bytes_ratio'), (int, float))
                     else 'unknown'),
                    fmt(delta.get('wall_seconds')), fmt(noise.get('wall_seconds')),
                    event_verdict()))
    lines.append('')
    lines.append('## 1. 测量对象与口径')
    lines.append('')
    lines.append(table(
        ['项', '内容'],
        [['机器', '%s / %s CPUs / Python %s / %s'
          % (document['environment']['cpu_model'],
             document['environment']['cpu_count'],
             document['environment']['python'],
             document['environment']['platform'])],
         ['fuzz 配置', '`%s`' % relative(settings['config'])],
         ['A/B 配置', '`%s`（单字 F1 旧配置）' % relative(settings['ab_config'])],
         ['cache', '`%s`（每次运行的 link_cache_hit 见阶段表）' % relative(settings['cache'])],
         ['用例 / seed / 重复', '%d / %d / %d' % (settings['cases'], settings['seed'],
                                                   settings['repetitions'])],
         ['A/B 输入 / 每臂重复', '%d 条固定记录 / %d（`--max-ticks %d`）'
          % (settings['fixed_records']['count'], settings['ab_repetitions'],
             settings['ab_max_ticks'])],
         ['源码指纹（每次运行记录）',
          '、'.join(state[:12] for state in steady['source_states'])],
         ['口径', '`total_seconds` 含准备/构建；`run_seconds` 是 host 进程段；'
                  '`fuzz.stats.dut_seconds` 只含每例 DUT 循环；`case.seconds` 是 host '
                  '自己量的每例 DUT 段（不含模型构造/复位与用例间空隙）。']]))
    lines.append('')
    lines.append('## 2. 阶段表（fuzz，秒）')
    lines.append('')
    lines.append(table(['重复', '进程 wall', 'total', 'run', 'link', '准备（total−run）',
                        '会话 wall', '用例（过/败）', 'ticks', 'DUT 合计 (s)',
                        '例/秒（会话）', '例/秒（total）', 'DUT/会话', '状态'],
                       phase_rows))
    lines.append('')
    if first is not None and steady.get('steady_median'):
        delta_first = steady.get('first_minus_steady') or {}
        lines.append('首轮单独看：wall %s s，稳态中位数 %s s；首轮减稳态：total %s s、'
                     '`run_seconds` %s s、会话 wall %s s、DUT 合计 %s s。首轮 link 缓存%s。'
                     % (fmt(first['wall_seconds']),
                        fmt(steady['steady_median'].get('wall_seconds')),
                        fmt(delta_first.get('total_seconds')),
                        fmt(delta_first.get('run_seconds')),
                        fmt(delta_first.get('session_wall_seconds')),
                        fmt(delta_first.get('dut_seconds_sum'), 6),
                        '命中' if first['link_cache_hit'] else '未命中'))
        lines.append('')
    lines.append('准备段的构成：link 中位数 %s s，其余准备（导入、scope、模型请求、'
                 '固件/绑定渲染、summary 写出）%s s；准备占 wall 的 %s。'
                 % (fmt(all_median.get('link_seconds')),
                    fmt(all_median.get('prepare_other_seconds')),
                    pct(None if not isinstance(preparation, (int, float))
                        or not isinstance(all_median.get('wall_seconds'), (int, float))
                        else preparation / all_median['wall_seconds'])))
    lines.append('')
    lines.append('## 3. 每例 DUT 与闭环成分')
    lines.append('')
    lines.append(table(['重复', 'DUT ms 中位数', 'p95', '最小', '最大',
                        '每例 ticks 中位数', '记录例数', '每例 seconds 合计',
                        'host runtime'], case_rows))
    lines.append('')
    lines.append('每例 DUT 毫秒来自 `fuzz.json` 的 `cases[].case.seconds`，p95 用最近秩；'
                 '`runtime` 是 host summary 的 `runtime_seconds`（含模型构造/复位与用例间空隙），'
                 '所以 `runtime − Σcase.seconds` 才是模型初始化与空隙的上界，不能全算给 DUT。')
    lines.append('')
    if flow_rows:
        lines.append('按 flow 拆分（第 1 次重复；同一 seed 下各次重复的输入逐条相同：%s）：'
                     % ('是' if all(steady.get('inputs_identical') or [])
                        else '否'))
        lines.append('')
        lines.append(table(['flow', '用例数', 'DUT ms 中位数', 'p95', '每例 ticks 中位数'],
                           flow_rows))
        lines.append('')
    lines.append('闭环会话内部分解（全部重复的中位数；round-trip 含 DUT，故不与 generation/'
                 'parse/feedback 相加）：')
    lines.append('')
    lines.append(table(['阶段', '秒', '占会话 wall'], composition_rows))
    lines.append('')
    failed_flows = {}
    for run in runs:
        for flow, count in failed_flow_counts(run).items():
            failed_flows[flow] = max(failed_flows.get(flow, 0), count)
    lines.append('语料与特征：corpus 条目中位数 %s，distinct features 中位数 %s，'
                 'findings（失败用例）中位数 %s%s；本批状态 %s。失败用例是闭环自己的'
                 '观察结论（case 行判失败），不是测量脚本的失败。'
                 % (integer(all_median.get('corpus_entries')),
                    integer(all_median.get('distinct_features')),
                    integer(all_median.get('findings')),
                    ('（flow：%s）' % '、'.join('%s×%d' % item
                                              for item in sorted(failed_flows.items()))
                     if failed_flows else ''),
                    '、'.join(sorted({run['status'] or 'unknown' for run in runs}))))
    lines.append('')
    lines.append('## 4. 事件层 A/B（固定输入，%d 条记录，同一 cache）'
                 % settings['fixed_records']['count'])
    lines.append('')
    lines.append(table(['臂', '样本', 'wall 中位 (s)', 'wall 极差 (s)',
                        'run 中位 (s)', 'CPU 中位 (s)', 'log 字节', 'log 行',
                        'ticks 合计', 'DUT 合计 (s)', '臂内 log 稳定'], ab_rows))
    lines.append('')
    lines.append('run.log 行前缀计数（每个臂的第 1 次样本；`irq_*` 与声明前导行归入 other）：')
    lines.append('')
    lines.append(table(prefix_header, prefix_rows))
    lines.append('')
    lines.append('对照：')
    lines.append('')
    lines.append(table(
        ['量', 'quiet − online（中位数）', '臂内极差（噪声带）', '是否超过噪声'],
        [['wall (s)', fmt(delta.get('wall_seconds')), fmt(noise.get('wall_seconds')),
          ('不能判定' if resolvable.get('wall_seconds') is None else
           ('是' if resolvable.get('wall_seconds') else '否'))],
         ['CPU (s)', fmt(delta.get('cpu_seconds')), fmt(noise.get('cpu_seconds')),
          ('不能判定' if resolvable.get('cpu_seconds') is None else
           ('是' if resolvable.get('cpu_seconds') else '否'))],
         ['run_seconds (s)', fmt(delta.get('run_seconds')),
          fmt(noise.get('run_seconds')),
          ('不能判定' if resolvable.get('run_seconds') is None else
           ('是' if resolvable.get('run_seconds') else '否'))],
         ['DUT 合计 (s)', fmt(delta.get('dut_seconds_sum'), 6), '—', '—'],
         ['log 字节', integer(delta.get('log_bytes')), '—', '—'],
         ['log 行', integer(delta.get('log_lines')), '—', '—']]))
    lines.append('')
    lines.append('两臂 case 状态逐条一致：%s；两臂 ticks 合计相同：%s；样本数：每臂 %d。%s'
                 % ('是' if comparison['case_statuses_identical'] else '否',
                    '是' if comparison.get('ticks_identical') else '否',
                    comparison['sample_count'], event_verdict()))
    lines.append('')
    lines.append('注意：`online` 臂的 `case.seconds` 覆盖该例的 tick 循环**连同**逐拍事件'
                 '打印，而 `--quiet` 臂关掉了这些行，所以上表 `DUT 合计` 的 %s s 差主要是'
                 '事件打印成本（本批少了 %s 行），不能读成 RTL 推进变快。fuzz 模式固定带 '
                 '`--quiet`，它报的 `dut_seconds` 才接近纯循环。'
                 % (fmt(delta.get('dut_seconds_sum'), 6),
                    integer(comparison.get('suppressed_log_lines'))))
    lines.append('')
    lines.append('噪声带的定义就是每个臂自身 wall/CPU/`run_seconds` 的极差（max−min）；'
                 '每臂只有 %d 次样本时它是经验范围，不是置信区间，所以"没超过极差"'
                 '只说明这批样本分辨不出，并不证明真实差异为零。'
                 % comparison['sample_count'])
    if run_resolvable:
        run_before = online_median.get('run_seconds')
        run_after = quiet_median.get('run_seconds')
        wall_before = online_median.get('wall_seconds')
        lines.append('')
        lines.append('`run_seconds`（host 进程段，事件打印发生在这里）由 %s s 降到 %s s，'
                     '差 %s s，臂内极差 %s s，样本内可分辨；这只占 online 臂 wall 的 %s，'
                     '所以 wall 仍判不出差异，也不能据此声称端到端加速。'
                     % (fmt(run_before, 6), fmt(run_after, 6),
                        fmt(delta.get('run_seconds'), 6),
                        fmt(noise.get('run_seconds'), 6),
                        pct(None if not isinstance(delta.get('run_seconds'), (int, float))
                            or not wall_before
                            else abs(delta['run_seconds']) / wall_before)))
    lines.append('')
    lines.append('## 5. 这些数字能证明什么、不能证明什么')
    lines.append('')
    lines.append('能证明（本机、本配置、本 cache 状态、本批输入）：')
    lines.append('')
    lines.append('* 这批 %s 例的 wall 构成：解释器启动/退出 %s s + 准备 %s s + '
                 '`run_seconds` %s s（其中闭环会话 %s s、DUT 循环 %s s）；准备远大于 '
                 'DUT 推进，短批次里 wall 主要不是 DUT。'
                 % (integer(cases), fmt(all_median.get('wall_minus_total_seconds')),
                    fmt(preparation), fmt(run_seconds), fmt(session_wall),
                    fmt(dut, 6)))
    lines.append('* 闭环在会话口径下 %s 例/秒，单例 DUT 中位 %s ms、p95 %s ms；'
                 '会话内 generation/parse/feedback 都远小于 round-trip。fuzz 模式由入口'
                 '固定加 `--quiet`，所以这里的 DUT 秒数不含逐拍事件打印。'
                 % (fmt(session_rate, 1), fmt(case_median), fmt(case_p95)))
    lines.append('* 固定输入上 `--quiet` 把 run.log 从 %s 字节/%s 行降到 %s 字节/%s 行，'
                 '且两臂 %d 个 case 的状态逐条一致。'
                 % (integer(online_median.get('log_bytes')),
                    integer(online_median.get('log_lines')),
                    integer(quiet_median.get('log_bytes')),
                    integer(quiet_median.get('log_lines')),
                    settings['fixed_records']['count']))
    lines.append('* 首轮与稳态的差异（若表中存在）就是本机当前的启动/缓存波动量级。')
    lines.append('')
    lines.append('不能证明：')
    lines.append('')
    lines.append('* 事件层带来 wall 加速——%s'
                 % ('wall 差异没有超过臂内极差，样本内不能区分。'
                    if wall_resolvable is False else
                    '即使本次差异超过噪声，也只有一组固定输入、一台机器的样本，'
                    '不能外推。'))
    lines.append('* 别的 CPU/IP/DMA 组合、别的 seed、别的 cases 数有同样吞吐；'
                 '本文件只覆盖 `%s` 这一组合。' % relative(settings['config']))
    lines.append('* 长跑内存/泄漏趋势——本批只记录每次进程的 `maxrss_kb`（中位数 %s KiB），'
                 '没有长时间重复采样。' % integer(all_median.get('maxrss_kb')))
    lines.append('* 覆盖率、replay、certificate——fuzz 模式只做观察反馈，'
                 '`certificate` 为 `none`、`replay` 为 `not_performed`。')
    lines.append('* 与其它入口（`run_inprocess_flow.py`、`run_inprocess_f1f4.py` 等）的对比；'
                 '本文件不测它们。')
    loads = ['%s/%s/%s' % (fmt(run['load_average'][0], 2), fmt(run['load_average'][1], 2),
                           fmt(run['load_average'][2], 2))
             for run in runs if run.get('load_average')]
    lines.append('* 机器空闲时的绝对性能——每次运行的 1/5/15 分钟 load average 为 %s；'
                 '测量期间可能有其它 agent 的运行。' % ('、'.join(loads) or 'unknown'))
    lines.append('')
    lines.append('## 6. 复现命令')
    lines.append('')
    lines.append('在仓库根目录、单进程串行运行（同一时间只跑一个 RTL 运行）：')
    lines.append('')
    lines.append('```')
    lines.append('python3 scripts/measure_fuzz_phases.py \\')
    lines.append('  --config %s \\' % relative(settings['config']))
    lines.append('  --cache %s \\' % relative(settings['cache']))
    lines.append('  --output %s \\' % relative(settings['output']))
    lines.append('  --cases %d --seed %d --repetitions %d \\'
                 % (settings['cases'], settings['seed'], settings['repetitions']))
    lines.append('  --ab-config %s --ab-repetitions %d'
                 % (relative(settings['ab_config']), settings['ab_repetitions']))
    lines.append('```')
    lines.append('')
    if settings['fixed_records'].get('is_default'):
        lines.append('`--fixed-records` 的默认值就是 %d 条记录（4 条一组重复 %d 次），'
                     '可这样原样生成：'
                     % (settings['fixed_records']['count'],
                        settings['fixed_records']['repeat']))
        lines.append('')
        lines.append('```')
        lines.append(fixed_records_one_liner())
        lines.append('```')
    else:
        lines.append('本次使用的是自定义 `--fixed-records`（%d 条，sha256 %s），'
                     '原文保存在 `measurements.json` 的 `settings.fixed_records.text`。'
                     % (settings['fixed_records']['count'],
                        settings['fixed_records']['text_sha256']))
    lines.append('')
    lines.append('脚本为每次运行新建输出目录并调用现有入口（本次逐条 argv 记录在 '
                 '`measurements.json` 的 `runs.*[].argv`），例如首轮 fuzz 与 A/B 两臂：')
    lines.append('')
    first_fuzz = runs[0] if runs else None
    first_online = online['samples'] and document['runs']['ab']['online'][0]
    first_quiet = quiet['samples'] and document['runs']['ab']['quiet'][0]
    lines.append('```')
    for row in (first_fuzz, first_online, first_quiet):
        if row:
            lines.append(' '.join(relative(part) if os.path.isabs(part) else part
                                  for part in row['argv']))
    lines.append('```')
    lines.append('')
    lines.append('## 7. 失败或被排除的 run')
    lines.append('')
    lines.append(failure_text)
    lines.append('')
    return '\n'.join(lines)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', default=DEFAULT_CONFIG,
                        help='fuzz declaration (default: the 4-word F1 program slot)')
    parser.add_argument('--cache', default=(DEFAULT_CACHE if (ROOT / DEFAULT_CACHE).is_dir()
                                            else FRESH_CACHE),
                        help='build/link cache shared by every measured run')
    parser.add_argument('--output', default=DEFAULT_OUTPUT,
                        help='directory that holds the new per-run output directories')
    parser.add_argument('--cases', type=int, default=200, help='fuzz case budget')
    parser.add_argument('--seed', type=int, default=20261101, help='fuzz PRNG seed')
    parser.add_argument('--repetitions', type=int, default=2,
                        help='closed-loop repetitions (the first one is reported apart)')
    parser.add_argument('--fixed-records', default=DEFAULT_FIXED_RECORDS,
                        help='comma-separated records for the fixed-input A/B '
                             '(default: 100 records)')
    parser.add_argument('--ab-config', default=DEFAULT_AB_CONFIG,
                        help='declaration for the fixed-input A/B (single-word F1)')
    parser.add_argument('--ab-repetitions', type=int, default=3,
                        help='runs per A/B arm (two arms are interleaved)')
    parser.add_argument('--ab-max-ticks', type=int, default=DEFAULT_AB_MAX_TICKS,
                        help='process tick budget of each fixed-input arm')
    parser.add_argument('--timeout', type=float, default=600.0,
                        help='wall-clock limit of one measured entry process')
    parser.add_argument('--entry', default=ENTRY, help=argparse.SUPPRESS)
    parser.add_argument('--report-only', action='store_true',
                        help='rewrite REPORT.md from the existing measurements.json '
                             '(no run is started)')
    args = parser.parse_args(argv)
    if args.cases < 1:
        parser.error('--cases must be positive')
    if args.seed < 0:
        parser.error('--seed must be non-negative')
    if args.repetitions < 1:
        parser.error('--repetitions must be positive')
    if args.ab_repetitions < 1:
        parser.error('--ab-repetitions must be positive')
    if args.ab_max_ticks < 1:
        parser.error('--ab-max-ticks must be positive')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    if count_records(args.fixed_records) < 1:
        parser.error('--fixed-records must contain at least one record')
    return args


def main(argv=None):
    args = parse_args(argv)
    config = resolve(args.config)
    ab_config = resolve(args.ab_config)
    cache = resolve(args.cache)
    output = resolve(args.output)
    entry = resolve(args.entry)
    process_dir = output / '_process'
    for label, path in (('config', config), ('A/B config', ab_config)):
        if not path.is_file():
            print('error: %s does not exist: %s' % (label, path), file=sys.stderr)
            return 1
    if not entry.is_file():
        print('error: the entry does not exist: %s' % entry, file=sys.stderr)
        return 1
    if args.report_only:
        document, error = read_json(output / 'measurements.json')
        if error is not None:
            print('error: cannot read %s: %s' % (output / 'measurements.json', error),
                  file=sys.stderr)
            return 1
        if document.get('schema_version') != 'inprocess_fuzz_measurement.v1':
            print('error: unexpected measurements schema: %r'
                  % document.get('schema_version'), file=sys.stderr)
            return 1
        if document.get('status') != 'measured':
            print('error: the measurement status is %r; nothing to report'
                  % document.get('status'), file=sys.stderr)
            return 1
        derived_comparison(document)
        (output / 'measurements.json').write_text(json.dumps(document, indent=2) + '\n')
        (output / 'REPORT.md').write_text(render_report(document))
        print(json.dumps(dict(status='report', report=str(output / 'REPORT.md'))))
        return 0
    records = count_records(args.fixed_records)
    planned = ['fuzz-r%d' % number for number in range(1, args.repetitions + 1)]
    planned += ['ab-%s-r%d' % (arm, number)
                for number in range(1, args.ab_repetitions + 1)
                for arm in ('online', 'quiet')]
    existing = [name for name in planned if (output / name).exists()]
    if existing:
        print('error: the output directories already exist below %s: %s\n'
              'the entry refuses an existing output directory; choose a new --output'
              % (output, ', '.join(existing)), file=sys.stderr)
        return 1
    output.mkdir(parents=True, exist_ok=True)
    process_dir.mkdir(parents=True, exist_ok=True)

    runs = dict(fuzz=[], ab=dict(online=[], quiet=[]))
    failures = []
    total_runs = len(planned)

    def record_failure(row):
        messages = row.get('problems') or ['unknown failure']
        for message in messages:
            failures.append(dict(name=row['name'], output=row['output'],
                                 problem=message))
        print('FAILED %s: %s (output kept at %s)'
              % (row['name'], '; '.join(messages), row['output']), file=sys.stderr)

    def write_measurements(document):
        (output / 'measurements.json').write_text(json.dumps(document, indent=2) + '\n')

    document = dict(
        schema_version='inprocess_fuzz_measurement.v1',
        generated=time.strftime('%Y-%m-%d %H:%M:%S'),
        campaign_date=time.strftime('%Y-%m-%d'),
        environment=environment(),
        settings=dict(
            entry=relative(entry), config=str(config), ab_config=str(ab_config),
            cache=str(cache), output=str(output), cases=args.cases, seed=args.seed,
            repetitions=args.repetitions, ab_repetitions=args.ab_repetitions,
            ab_max_ticks=args.ab_max_ticks,
            fixed_records=dict(count=records, repeat=FIXED_REPEAT,
                               is_default=(args.fixed_records == DEFAULT_FIXED_RECORDS),
                               text_sha256=hashlib.sha256(
                                   args.fixed_records.encode()).hexdigest(),
                               text=args.fixed_records),
            timeout_seconds=args.timeout,
            harness_argv=[str(part) for part in (sys.argv if argv is None else argv)],
        ),
        runs=runs, comparison={}, failures=failures, status='running',
    )

    step = 0
    for number in range(1, args.repetitions + 1):
        step += 1
        print('[%d/%d] fuzz-r%d ...' % (step, total_runs, number), file=sys.stderr,
              flush=True)
        row = measure_fuzz_run(number, config=config, cache=cache, output=output,
                              cases=args.cases, seed=args.seed, entry=entry,
                              process_dir=process_dir, timeout=args.timeout)
        runs['fuzz'].append(row)
        if row['problems']:
            record_failure(row)
            document['status'] = 'failed'
            write_measurements(document)
            return 2
        print('[%d/%d] fuzz-r%d: wall %s s, run %s s, session %s s, %s cases, %s'
              % (step, total_runs, number, fmt(row['wall_seconds']),
                 fmt(row['run_seconds']), fmt(row['session_wall_seconds']),
                 integer(row['cases_executed']), row['status']), file=sys.stderr,
              flush=True)

    for number in range(1, args.ab_repetitions + 1):
        for arm in ('online', 'quiet'):
            step += 1
            print('[%d/%d] ab-%s-r%d ...' % (step, total_runs, arm, number),
                  file=sys.stderr, flush=True)
            row = measure_ab_run(number, arm=arm, config=ab_config, cache=cache,
                                 output=output, records=records,
                                 text=args.fixed_records,
                                 max_ticks=args.ab_max_ticks, entry=entry,
                                 process_dir=process_dir, timeout=args.timeout)
            runs['ab'][arm].append(row)
            if row['problems']:
                record_failure(row)
                document['status'] = 'failed'
                write_measurements(document)
                return 2
            print('[%d/%d] ab-%s-r%d: wall %s s, run %s s, log %s bytes, %s cases'
                  % (step, total_runs, arm, number, fmt(row['wall_seconds']),
                     fmt(row['run_seconds']), integer(row['log']['bytes']),
                     len(row['case_rows'])), file=sys.stderr, flush=True)

    comparison = event_layer_comparison(runs['ab']['online'], runs['ab']['quiet'])
    if not comparison['case_statuses_identical']:
        problem = ('the fixed arms do not agree on the case statuses '
                   '(records %d): online=%s quiet=%s'
                   % (records,
                      comparison['arms']['online']['case_statuses'][0],
                      comparison['arms']['quiet']['case_statuses'][0]))
        failures.append(dict(name='ab-online/ab-quiet', output=str(output),
                             problem=problem))
        document['comparison'] = dict(fuzz_first_vs_steady=fuzz_comparison(runs['fuzz']),
                                     event_layer=comparison)
        document['status'] = 'failed'
        write_measurements(document)
        print('FAILED fixed A/B: ' + problem, file=sys.stderr)
        return 2

    document['status'] = 'measured'
    derived_comparison(document)
    write_measurements(document)
    (output / 'REPORT.md').write_text(render_report(document))

    # A short console summary; the files carry every raw row.
    all_median = document['medians']['fuzz_all']
    print('')
    print('fuzz: %d run(s), wall median %s s = total %s s (run %s s, preparation %s s)'
          % (len(runs['fuzz']), fmt(all_median['wall_seconds']),
             fmt(all_median['total_seconds']), fmt(all_median['run_seconds']),
             fmt(all_median['preparation_seconds'])))
    print('      session %s s, DUT %s s (%.1f%% of session), %s cases/s, case DUT %s ms '
          'median / %s ms p95'
          % (fmt(all_median['session_wall_seconds']), fmt(all_median['dut_seconds_sum']),
             (all_median['dut_share_of_session'] or 0.0) * 100.0,
             fmt(all_median['cases_per_session_second'], 1),
             fmt(all_median['case_ms_median']), fmt(all_median['case_ms_p95'])))
    print('A/B: %d sample(s)/arm, log %s -> %s bytes, wall delta %s s (noise %s s), '
          'case statuses identical %s'
          % (comparison['sample_count'],
             integer(comparison['arms']['online']['medians']['log_bytes']),
             integer(comparison['arms']['quiet']['medians']['log_bytes']),
             fmt(comparison['delta_quiet_minus_online'].get('wall_seconds')),
             fmt(comparison['noise_range'].get('wall_seconds')),
             'yes' if comparison['case_statuses_identical'] else 'no'))
    print(json.dumps(dict(status=document['status'], measurements=str(output / 'measurements.json'),
                          report=str(output / 'REPORT.md'),
                          cases=args.cases, repetitions=args.repetitions,
                          ab_repetitions=args.ab_repetitions)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
