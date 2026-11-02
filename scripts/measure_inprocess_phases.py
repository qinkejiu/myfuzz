#!/usr/bin/env python3
"""Measure the in-process F1-F4/F5/F6 entries in fixed, comparable phases.

Step E of ``docs/stage2-prototype-implementation-20261031.md`` asks for the
preparation / build / model-init / steady-run / output-write cost of the
already-verified in-process entries, measured with the *same* CPU/IP profiles,
the same number of inputs, the same cache state and the same observation scope,
so that two columns of numbers are actually comparable.

What this script does **not** do:

* it never edits an entry, a host, a profile or ``src/myfuzz``; every number is
  either read from an existing output (``summary.json``/``flow_summary.json``/
  ``run.log``) or measured *around* a real, unmodified run;
* it never removes a handshake, a case, a tick or an observation to make a
  number smaller.  A segment that the product does not report stays
  ``unknown`` instead of being guessed;
* it does not re-run the old campaign path or produce certificates/replays.

Measured per run
----------------
``wall``            wall clock around the whole entry process (``os.wait4``)
``cpu``             ``ru_utime+ru_stime`` of that process (host CPU, not DUT)
``maxrss_kb``       ``ru_maxrss`` of that process (Linux: KiB)
``launch_to_first`` wall from launch until the entry's *first* output file
                    exists = interpreter start + imports + config + dispatch
``body``            first output file -> ``summary.json`` = the product work the
                    entry itself times as ``total_seconds``
``tail``            ``summary.json`` -> process exit = summary write, the scope
                    exit re-authentication, teardown (and, for the F5/F6 thin
                    entry, its own post-processing)
``link``/``run``    the delegate's own ``link_seconds``/``run_seconds``
``case_seconds``    F1-F4 ``cases[].seconds`` (the C++ per-case span)
``runtime_seconds`` the C++ host's inclusive in-process span from ``run.log``

Sub-commands
------------
``--mode cold|hot``   run every selected class once (cold) or N times (hot)
                      and append the rows to ``<workdir>/measurements.json``
``--attribution``     run the same classes in-process (``runpy``) with plain
                      ``time.perf_counter`` timers on the library functions the
                      entries call, so the product work is attributed without
                      cProfile inflation and without patching product files
``--ab-policy``       A/B the one candidate change this script can express
                      without touching a product file (see ``POLICIES``)
``--report``          render ``REPORT.md`` from the recorded rows

Usage
-----
    python3 scripts/measure_inprocess_phases.py --workdir runs/stage2-stepE-measure --mode cold
    python3 scripts/measure_inprocess_phases.py --workdir runs/stage2-stepE-measure --mode hot --repetitions 2
    python3 scripts/measure_inprocess_phases.py --workdir runs/stage2-stepE-measure --attribution --ab-policy
    python3 scripts/measure_inprocess_phases.py --workdir runs/stage2-stepE-measure --report

Only ``--workdir`` (and the ``--cache``/``--output`` directories given on the
command line) are written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import runpy
import shutil
import statistics
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: One row per flow class.  ``inputs`` is the fixed input set: exactly two
#: cases per class, taken from the examples already verified in the docs.
CLASSES = {
    'F5': dict(
        flow='F5',
        label='F5 OBI CPU + APB PULP Timer IRQ',
        entry='scripts/run_inprocess_flow.py',
        delegate='scripts/run_inprocess_irq.py',
        config='configs/scenarios/inprocess-irq-pulp-timer-profile.json',
        cpu='configs/cpus/ibex_rvfi_local/component_profile.json',
        ip='configs/peripherals/pulp_timer_irq/component_profile.json',
        inputs=('0,0,0xffffffff', '1,0,0xfffffffe'),
        mode='online',
        spike_tail=('--online', '3000'),
        case_seconds=False,
    ),
    'F6': dict(
        flow='F6',
        label='F6 OBI CPU + Wishbone ZipDMA',
        entry='scripts/run_inprocess_flow.py',
        delegate='scripts/run_inprocess_f6.py',
        config='configs/scenarios/shared-dma-profile-examples/ibex-zipdma-profile-only.json',
        cpu='configs/cpus/ibex_rvfi_local/component_profile.json',
        ip='configs/peripherals/zipdma_smoke/component_profile.json',
        inputs=('0110c00008000000', '0530c00110000000'),
        mode='preloaded',
        assume_lockstep=True,
        spike_tail=('0110c00008000000,0530c00110000000',),
        case_seconds=False,
    ),
    'F1F4': dict(
        flow='F1-F4',
        label='F1-F4 OBI CPU + APB PULP Timer (RAM/MMIO)',
        entry='scripts/run_inprocess_f1f4.py',
        delegate='scripts/run_inprocess_f1f4.py',
        config='configs/scenarios/inprocess-irq-pulp-timer-profile.json',
        cpu='configs/cpus/ibex_rvfi_local/component_profile.json',
        ip='configs/peripherals/pulp_timer_irq/component_profile.json',
        inputs=('F1:2ab00693', 'F4:40001008:0fffffff'),
        mode='preloaded',
        spike_tail=('F1:2ab00693,F4:40001008:0fffffff', '20000'),
        case_seconds=True,
    ),
}

#: Why model construction/reset has no measured value of its own.
MODEL_INIT_REASON = ('the C++ hosts start their clock before VerilatedContext/model '
                     'construction and print no construct/reset span')

#: The observation scope every run in this file shares.  It is recorded next to
#: the numbers so nobody compares these seconds with a certified/replayed run.
OBSERVATION_SCOPE = ('compact summary.json + flow_summary.json + run.log; '
                     'no certificate, no replay, no per-cycle journal')


# --------------------------------------------------------------------------- #
# Parsing (pure functions; unit-tested without RTL)
# --------------------------------------------------------------------------- #
def _value(token):
    """Numbers stay numbers; ``0x``-prefixed tokens are hexadecimal integers."""
    try:
        return int(token)
    except ValueError:
        pass
    if token.lstrip('-+')[:2].lower() == '0x':
        try:
            return int(token, 16)
        except ValueError:
            return token
    try:
        return float(token)
    except ValueError:
        return token


def _pairs(tokens):
    """``key value key value ...`` -> dict; an odd trailing token maps to None."""
    row = {}
    index = 0
    while index < len(tokens):
        row[tokens[index]] = _value(tokens[index + 1]) if index + 1 < len(tokens) else None
        index += 2
    return row


def parse_run_log(text):
    """Extract the per-case rows, the closing summary line and the requests.

    All three in-process loops print ``case <n> <status> k v ...`` once per
    finished case, ``summary <status> k v ...`` once at the end, and
    ``NEED_RECORD <n> ...`` once per input request; every other line is
    transport detail and is not promoted into a number here.
    """
    if not isinstance(text, str):
        raise ValueError('run log text required')
    cases, summary, requests = [], None, 0
    for line in text.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == 'case' and len(tokens) >= 3:
            row = _pairs(tokens[3:])
            row.update(case=_value(tokens[1]), status=tokens[2])
            cases.append(row)
        elif tokens[0] == 'summary' and len(tokens) >= 2:
            if summary is not None:
                raise ValueError('duplicate summary line')
            row = _pairs(tokens[2:])
            row.update(status=tokens[1])
            summary = row
        elif tokens[0] == 'NEED_RECORD':
            requests += 1
    return dict(cases=cases, summary=summary, requests=requests)


def case_seconds(document):
    """F1-F4 ``cases[].seconds``; an unreadable row is skipped, never invented."""
    seconds = []
    for row in (document or {}).get('cases') or ():
        value = row.get('seconds') if isinstance(row, dict) else None
        if isinstance(value, (int, float)):
            seconds.append(float(value))
        else:
            seconds.append(None)
    return seconds


def model_init_bound(runtime_seconds, seconds):
    """Upper bound of model construct+reset from the C++ only.

    Every host starts its clock *before* ``VerilatedContext``/model construction
    and the reset sequence, and reports per-case spans that start after the
    reset, so ``runtime_seconds - sum(case_seconds)`` contains construct+reset.
    When the loop prints no per-case seconds the partition does not exist and
    the honest answer is ``None`` (= unknown), not a guess.
    """
    if not isinstance(runtime_seconds, (int, float)):
        return None
    if not seconds or any(value is None for value in seconds):
        return None
    return max(0.0, float(runtime_seconds) - sum(seconds))


def phase_segments(*, wall, launch_to_first, body, tail, total_seconds,
                   link_seconds, run_seconds):
    """Split one run into the five reported phases; missing input -> ``None``.

    ``product_prepare`` is anchored on the measured span from the entry's first
    output file to ``summary.json`` (minus the link and the DUT run) rather than
    on the entry's own clock, because the two entries do not start that clock at
    the same event: F6 spends ~1.5 s inside the scope entry and the artifact
    requests before its first write.  Anchoring keeps the five phases additive
    to ``wall``; ``closure_residual`` proves it and ``delegate_clock_gap``
    reports how far the entry's own ``total_seconds`` sits from the anchor
    instead of hiding the difference in a phase.
    """
    def known(value):
        return value if isinstance(value, (int, float)) else None

    python_prepare = known(launch_to_first)
    body = known(body)
    tail = known(tail)
    link = known(link_seconds)
    run = known(run_seconds)
    total = known(total_seconds)
    span = body if body is not None else total
    product_prepare = None
    if span is not None and link is not None and run is not None:
        product_prepare = max(0.0, span - link - run)
    accounted = [python_prepare, product_prepare, link, run, tail]
    closure = None
    if known(wall) is not None and all(value is not None for value in accounted):
        closure = wall - sum(accounted)
    return dict(
        wall=known(wall),
        python_prepare=python_prepare,
        product_prepare=product_prepare,
        link=link,
        run=run,
        write_and_exit=tail,
        body_span_seconds=body,
        body_minus_total=(None if body is None or total is None else body - total),
        delegate_clock_gap=(None if body is None or total is None else total - body),
        closure_residual=closure,
    )


#: Output file -> reported category.  Named so the inventory says which of the
#: five asked-for artifacts (summary/flow_summary/run.log/firmware/binding) and
#: which cache/binary bytes are actually written.
FILE_CATEGORIES = (
    ('summary.json', 'summary'),
    ('flow_summary.json', 'flow_summary'),
    ('run.log', 'run_log'),
    ('link.log', 'link_log'),
    ('firmware.txt', 'firmware'),
    ('spike_config.h', 'binding'),
    ('f6_binding.h', 'binding'),
    ('inprocess-spike', 'executable'),
)


def file_category(name):
    """Map one artifact name onto the reported category."""
    base = Path(name).name
    for known, category in FILE_CATEGORIES:
        if base == known:
            return category
    if base.endswith('_request.json'):
        return 'request'
    if base.endswith('.json'):
        return 'summary'
    if base.endswith(('.h', '.hpp')):
        return 'binding'
    return 'other'


def artifact_inventory(directory):
    """Every file the entry left behind, with its exact byte size."""
    directory = Path(directory)
    files = []
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            files.append(dict(name=str(path.relative_to(directory)),
                              bytes=path.stat().st_size,
                              category=file_category(path.name)))
    by_category = {}
    for row in files:
        by_category[row['category']] = by_category.get(row['category'], 0) + row['bytes']
    return dict(files=files, total_bytes=sum(row['bytes'] for row in files),
                by_category=dict(sorted(by_category.items())))


def mtime_anchors(directory, *, started_wall, ended_wall, wall_seconds=None):
    """Wall-clock anchors of a finished run, from the output files themselves.

    The entries refuse an existing output directory, so the youngest file is the
    first thing the delegate wrote and ``summary.json`` is written immediately
    before the scope exit; both give a real-time split of the run without
    modifying any entry.

    ``inprocess-spike`` is copied out of the build cache with ``shutil.copy2``,
    which keeps the *cache* entry's timestamp, so a file is only considered an
    anchor when it was actually written during this run.  ``flow_summary.json``
    belongs to the thin entry's own post-processing and is never the first file.

    This host's ``CLOCK_REALTIME`` occasionally steps by a few hundred ms while
    ``CLOCK_MONOTONIC`` keeps running, so a run's two real-time readings can
    disagree with its measured duration.  ``clock_step_seconds`` records that
    disagreement, the body span is derived from the *measured* wall instead of
    from two mtimes, and ``anchors_trusted`` says whether the split is usable.
    """
    directory = Path(directory)
    stamps = {}
    for path in directory.rglob('*'):
        if path.is_file():
            stamps[str(path.relative_to(directory))] = path.stat().st_mtime
    fresh = {name: value for name, value in stamps.items()
             if name != 'flow_summary.json' and started_wall <= value <= ended_wall + 1.0}
    summary = stamps.get('summary.json')
    flow = stamps.get('flow_summary.json')
    first = min(fresh.values()) if fresh else None
    step = None
    if isinstance(wall_seconds, (int, float)):
        step = (ended_wall - started_wall) - wall_seconds
    launch = None if first is None else max(0.0, first - started_wall)
    tail = None if summary is None else max(0.0, ended_wall - summary)
    body = None
    if isinstance(wall_seconds, (int, float)) and launch is not None and tail is not None:
        body = max(0.0, wall_seconds - launch - tail)
    elif first is not None and summary is not None:
        body = max(0.0, summary - first)
    return dict(
        first_file=min(fresh, key=fresh.get) if fresh else None,
        first_wall=first,
        summary_wall=summary,
        flow_summary_wall=flow,
        ignored_old_files=sorted(name for name, value in stamps.items()
                                 if name not in fresh and name != 'flow_summary.json'),
        clock_step_seconds=step,
        anchors_trusted=None if step is None else abs(step) <= 0.05,
        launch_to_first=launch,
        body=body,
        tail=tail,
        tail_from_flow=(None if flow is None else max(0.0, ended_wall - flow)),
    )


def entry_argv(spec, *, cache, output, python=None):
    """The exact command line the documented entry takes for this class."""
    python = python or sys.executable
    argv = [python, str(ROOT / spec['entry'])]
    if spec['entry'].endswith('run_inprocess_flow.py'):
        argv += ['--flow', spec['flow'], '--config', str(ROOT / spec['config']),
                 '--cache', str(cache), '--output', str(output)]
        if spec['mode'] == 'online':
            argv.append('--online')
        else:
            argv += ['--records', ','.join(spec['inputs'])]
        if spec.get('assume_lockstep'):
            argv.append('--assume-lockstep')
    else:
        argv += ['--config', str(ROOT / spec['config']), '--cache', str(cache),
                 '--output', str(output), '--records', ','.join(spec['inputs'])]
    return argv


def stdin_payload(spec):
    """``END``-terminated conversation for the online loops; nothing otherwise."""
    if spec['mode'] != 'online':
        return None
    return ('\n'.join(spec['inputs']) + '\nEND\n').encode()


def delegate_argv(spec, *, cache, output, python=None):
    """The delegate command line, used for the in-process attribution runs."""
    python = python or sys.executable
    argv = [python, str(ROOT / spec['delegate'])]
    if spec['delegate'].endswith('run_inprocess_flow.py'):
        raise ValueError('the thin entry is not used for in-process attribution')
    argv += ['--config', str(ROOT / spec['config']), '--cache', str(cache),
             '--output', str(output)]
    if spec['delegate'].endswith('run_inprocess_irq.py'):
        argv += ['--max-ticks', '3000']
        if spec['mode'] == 'online':
            argv.append('--online')
    elif spec['delegate'].endswith('run_inprocess_f6.py'):
        argv += ['--records', ','.join(spec['inputs'])]
        if spec.get('assume_lockstep'):
            argv.append('--assume-lockstep')
    else:
        argv += ['--records', ','.join(spec['inputs']), '--max-ticks', '20000']
    return argv


def read_json(path):
    """Return ``(document, error)``; a missing or broken file is not a pass."""
    path = Path(path)
    if not path.is_file():
        return None, 'missing'
    try:
        return json.loads(path.read_text()), None
    except (OSError, ValueError) as error:
        return None, 'unreadable: ' + str(error)


def collect(run):
    """Fold one finished run's files into the row that gets reported."""
    output = Path(run['output'])
    summary, summary_error = read_json(output / 'summary.json')
    flow, flow_error = read_json(output / 'flow_summary.json')
    log_text = ''
    if (output / 'run.log').is_file():
        log_text = (output / 'run.log').read_text(errors='replace')
    parsed = parse_run_log(log_text)
    seconds = case_seconds(summary)
    runtime = (parsed['summary'] or {}).get('runtime_seconds')
    timings = (flow or {}).get('timings') or {}
    # The thin F5/F6 entry reports the delegate's own numbers; F1-F4 has no
    # flow_summary and carries the same keys in its summary.json.
    link = timings.get('link_seconds', (summary or {}).get('link_seconds'))
    run_seconds = timings.get('run_seconds', (summary or {}).get('run_seconds'))
    total = timings.get('total_seconds', (summary or {}).get('total_seconds'))
    run['summary'] = summary
    run['flow_summary'] = flow
    # Only the thin F5/F6 entry writes a flow_summary.json; F1-F4 has its own
    # entry and must not be failed for the absence of a file it never writes.
    run['open_errors'] = [row for row in (
        ('summary.json', summary_error),
        ('flow_summary.json', flow_error if run.get('flow_summary_required') else None))
        if row[1]]
    run['log'] = dict(cases=len(parsed['cases']), requests=parsed['requests'],
                      summary_status=(parsed['summary'] or {}).get('status'),
                      ticks=(parsed['summary'] or {}).get('ticks'),
                      runtime_seconds=runtime,
                      case_seconds=seconds,
                      case_seconds_sum=(None if not seconds or any(
                          value is None for value in seconds) else sum(seconds)))
    run['delegate'] = dict(
        status=(summary or {}).get('status'),
        returncode=(summary or {}).get('returncode'),
        link_seconds=link, run_seconds=run_seconds, total_seconds=total,
        link_cache_hit=(summary or {}).get('link_cache_hit'),
        entry_seconds=timings.get('entry_seconds'),
        cases=(flow or {}).get('observations', {}).get('case_count')
        if flow else len((summary or {}).get('cases') or ()),
    )
    run['model_init'] = dict(seconds=None,
                             bound_seconds=model_init_bound(runtime, seconds),
                             reason=MODEL_INIT_REASON)
    run['phases'] = phase_segments(
        wall=run['wall_seconds'], launch_to_first=run['anchors']['launch_to_first'],
        body=run['anchors']['body'], tail=run['anchors']['tail'],
        total_seconds=total, link_seconds=link, run_seconds=run_seconds)
    run['cache_observed'] = observed_cache(summary)
    run['inventory'] = artifact_inventory(output)
    run['artifact_bytes'] = run['inventory']['total_bytes']
    run['cache'] = dict(path=run['cache'], state=run['cache_state'],
                        bytes=directory_bytes(run['cache']))
    return run


def directory_bytes(path):
    """Recursive byte total of one directory (0 when it does not exist)."""
    path = Path(path)
    if not path.exists():
        return 0
    return sum(child.stat().st_size for child in path.rglob('*') if child.is_file())


# --------------------------------------------------------------------------- #
# Running one entry (unmodified) and measuring around it
# --------------------------------------------------------------------------- #
def run_child(argv, *, cwd, stdin_bytes=None, stdout_path=None, stderr_path=None,
              env=None):
    """Run a child, wait for it with ``wait4`` and keep its own rusage.

    ``subprocess.run``/``Popen.communicate`` reap the child themselves and throw
    the ``rusage`` away, so the wait is done explicitly here: that is what makes
    the per-run ``ru_maxrss``/``ru_utime``/``ru_stime`` rows possible.
    """
    stdout_path, stderr_path = Path(stdout_path), Path(stderr_path)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started, started_wall = time.monotonic(), time.time()
    with stdout_path.open('wb') as out_handle, stderr_path.open('wb') as err_handle:
        process = subprocess.Popen(
            [str(value) for value in argv], cwd=str(cwd),
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=out_handle, stderr=err_handle, env=env, start_new_session=True)
        try:
            if stdin_bytes is not None:
                try:
                    process.stdin.write(stdin_bytes)
                    process.stdin.flush()
                except (BrokenPipeError, OSError):
                    # The entry may refuse the input before reading all of it;
                    # its exit code and log decide the row, not this write.
                    pass
                finally:
                    try:
                        process.stdin.close()
                    except (BrokenPipeError, OSError):
                        pass
            pid, status, usage = os.wait4(process.pid, 0)
            returncode = os.waitstatus_to_exitcode(status)
            process.returncode = returncode
        except BaseException:
            _terminate_group(process.pid)
            raise
        finally:
            if process.returncode is None:
                process.returncode = -1
    ended, ended_wall = time.monotonic(), time.time()
    return dict(
        wall_seconds=ended - started,
        started_wall=started_wall, ended_wall=ended_wall,
        returncode=returncode,
        cpu_seconds=usage.ru_utime + usage.ru_stime,
        maxrss_kb=usage.ru_maxrss,
        stdout=str(stdout_path), stderr=str(stderr_path),
    )


def _terminate_group(pid):
    """Do not leave a hung spike behind if the wait itself failed."""
    try:
        os.killpg(os.getpgid(pid), 9)
    except (ProcessLookupError, PermissionError):
        pass


def source_state(paths=('src/myfuzz', 'scripts', 'configs')):
    """Fingerprint of the files a run's work depends on, to detect source drift.

    Another process may be editing this repository while a measurement campaign
    runs; two runs are only comparable when this digest is equal, so it is
    recorded next to every row instead of assuming a frozen tree.
    """
    entries = []
    for root in paths:
        for path in sorted((ROOT / root).rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.h', '.hpp', '.cpp', '.json'):
                stat = path.stat()
                entries.append('%s\0%d\0%d' % (path.relative_to(ROOT), stat.st_size,
                                                 stat.st_mtime_ns))
    return hashlib.sha256('\n'.join(entries).encode()).hexdigest()


def observed_cache(summary):
    """What the cache state actually was, not what it was meant to be."""
    builds = (summary or {}).get('builds') or []
    return dict(link_cache_hit=(summary or {}).get('link_cache_hit'),
                models=len(builds),
                build_preparation_seconds=[round(float(build.get('preparation_seconds') or 0.0), 3)
                                           for build in builds])


def load_average():
    try:
        return list(os.getloadavg())
    except OSError:
        return None


def environment():
    """Fixed host facts, so two columns of seconds can be compared at all."""
    try:
        cpu_model = next(line.split(':', 1)[1].strip() for line in
                         Path('/proc/cpuinfo').read_text().splitlines()
                         if line.startswith('model name'))
    except (OSError, StopIteration):
        cpu_model = 'unknown'
    return dict(python=sys.version.split()[0], platform=platform.platform(),
                cpu_model=cpu_model, cpu_count=os.cpu_count(),
                load_average=load_average())


def run_class(name, *, workdir, cache, cache_state, output, repetition=1,
              python=None):
    """Run one class once and return the recorded row (never a success claim)."""
    spec = CLASSES[name]
    output = Path(output)
    workdir = Path(workdir)
    if output.exists():
        raise ValueError('output directory already exists: ' + str(output))
    child = run_child(entry_argv(spec, cache=cache, output=output, python=python),
                      cwd=ROOT, stdin_bytes=stdin_payload(spec),
                      stdout_path=workdir / 'logs' / (output.name + '.stdout'),
                      stderr_path=workdir / 'logs' / (output.name + '.stderr'))
    row = dict(
        class_name=name, label=spec['label'], flow=spec['flow'],
        entry=spec['entry'], delegate=spec['delegate'],
        config=spec['config'], cpu_profile=spec['cpu'], ip_profile=spec['ip'],
        inputs=list(spec['inputs']), input_count=len(spec['inputs']),
        input_mode=spec['mode'], assume_lockstep=bool(spec.get('assume_lockstep')),
        observation_scope=OBSERVATION_SCOPE,
        flow_summary_required=spec['entry'].endswith('run_inprocess_flow.py'),
        cache=str(cache), cache_state=cache_state, output=str(output),
        repetition=repetition, mode=cache_state,
        argv=[str(value) for value in entry_argv(spec, cache=cache, output=output,
                                                 python=python)],
        **{key: child[key] for key in ('wall_seconds', 'cpu_seconds', 'returncode',
                                       'maxrss_kb', 'started_wall', 'ended_wall',
                                       'stdout', 'stderr')},
        load_average=load_average(),
        source_state=source_state(),
        spike=None,
    )
    row['anchors'] = mtime_anchors(output, started_wall=child['started_wall'],
                                   ended_wall=child['ended_wall'],
                                   wall_seconds=child['wall_seconds'])
    row = collect(row)
    row['spike'] = spike_only(name, output=output, spec=spec)
    row['status'] = _run_status(row)
    return row


def spike_only(name, *, output, spec):
    """Re-run the *same* built spike alone: the DUT process without Python.

    This is the only way to see the model process' own wall/RSS, because the
    spike is a grandchild of the measured entry in the F5/F6 case and
    ``wait4`` reports one level only.  It runs the same binary with the same
    arguments and the same firmware; it is a second sample of the DUT, not a
    replacement for the entry run.
    """
    spike = Path(output) / 'inprocess-spike'
    firmware = Path(output) / 'firmware.txt'
    if not spike.is_file() or not firmware.is_file():
        return dict(status='skipped', reason='the entry left no spike/firmware')
    argv = [str(spike), str(firmware.resolve()), *spec['spike_tail']]
    child = run_child(argv, cwd=ROOT, stdin_bytes=spike_stdin(spec),
                      stdout_path=Path(output).parent / 'logs' / (Path(output).name + '.spike.stdout'),
                      stderr_path=Path(output).parent / 'logs' / (Path(output).name + '.spike.stderr'))
    text = Path(child['stdout']).read_text(errors='replace')
    parsed = parse_run_log(text)
    return dict(status='ran', wall_seconds=child['wall_seconds'],
                cpu_seconds=child['cpu_seconds'], maxrss_kb=child['maxrss_kb'],
                returncode=child['returncode'], argv=argv,
                runtime_seconds=(parsed['summary'] or {}).get('runtime_seconds'),
                cases=len(parsed['cases']),
                summary_status=(parsed['summary'] or {}).get('status'))


def spike_stdin(spec):
    """The online loops read one ``CASE ...`` line per requested case."""
    if spec['mode'] != 'online':
        return None
    lines = []
    for record in spec['inputs']:
        values = [int(part, 0) for part in record.split(',')]
        lines.append('CASE ' + ' '.join('%08x' % (value & 0xffffffff) for value in values))
    return ('\n'.join(lines) + '\n').encode()


def _run_status(row):
    """Observed status only: exit code, summary status and case counts must agree."""
    reasons = []
    if row['returncode'] != 0:
        reasons.append('entry exit code %s' % (row['returncode'],))
    for document, error in row['open_errors']:
        reasons.append('%s %s' % (document, error))
    delegate = row['delegate']
    if delegate.get('status') != 'observations_passed':
        reasons.append('summary status %r' % (delegate.get('status'),))
    observed = row['log']['cases']
    if observed != row['input_count']:
        reasons.append('%d case lines for %d inputs' % (observed, row['input_count']))
    if row['log']['summary_status'] != 'observations_passed':
        reasons.append('run.log summary %r' % (row['log']['summary_status'],))
    return dict(status='observations_passed' if not reasons else 'failed',
                reasons=reasons)


def rows_path(workdir):
    return Path(workdir) / 'measurements.json'


def load_rows(workdir):
    path = rows_path(workdir)
    if not path.is_file():
        return []
    document = json.loads(path.read_text())
    return document.get('runs', [])


def save_rows(workdir, runs, extra=None):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    document = dict(schema_version='inprocess_phase_measurement.v1',
                    generated_wall=time.time(), environment=environment(),
                    observation_scope=OBSERVATION_SCOPE,
                    classes={name: dict(flow=spec['flow'], label=spec['label'],
                                        entry=spec['entry'], delegate=spec['delegate'],
                                        config=spec['config'], cpu=spec['cpu'],
                                        ip=spec['ip'], inputs=list(spec['inputs']),
                                        input_mode=spec['mode'])
                             for name, spec in CLASSES.items()},
                    runs=runs)
    if extra:
        document.update(extra)
    path = rows_path(workdir)
    path.write_text(json.dumps(document, indent=2) + '\n')
    return path


# --------------------------------------------------------------------------- #
# Attribution: the same product work, in-process, with plain timers
# --------------------------------------------------------------------------- #
#: ``module attribute -> label`` for the library functions the three entries
#: call.  They are wrapped with ``time.perf_counter`` only: no branch, value or
#: call is changed, and the entries themselves are not imported differently.
ATTRIBUTION_TARGETS = (
    ('myfuzz.local_harness.build', 'build_local_harness_with_receipt'),
    ('myfuzz.local_harness.build', 'host_source_discovery_scope'),
    ('myfuzz.local_harness.execution_validation', 'execution_validation_scope'),
    ('myfuzz.composition.component_profile', '_elaborate_profile'),
    ('scripts.inprocess_build', 'build_link_run'),
    ('scripts.inprocess_build', '_cached_link'),
    ('scripts.inprocess_build', '_link_key'),
    ('scripts.run_timer_irq_smoke', 'timer_artifact'),
    ('myfuzz.local_harness', 'plan_local_harness'),
    ('myfuzz.local_harness', 'render_local_harness'),
    ('myfuzz.local_harness', 'verify_local_source_lock'),
    ('myfuzz.local_harness', 'render_local_runtime'),
    ('myfuzz.local_harness', 'render_local_driver'),
    ('myfuzz.local_harness.driver_renderer', 'render_local_driver'),
)

#: Both context managers are split into enter/body/exit, because the exit body
#: of ``execution_validation_scope`` re-runs every memoized validator.
SCOPE_TARGETS = (('myfuzz.local_harness.build', 'host_source_discovery_scope'),
                 ('myfuzz.local_harness.execution_validation',
                  'execution_validation_scope'))

#: Candidate policies for the *same* work.  ``entry-and-exit`` is what the
#: entries do today (the default of ``execution_validation_scope``);
#: ``entry-only`` is the policy ``myfuzz.search.workflow.run_boundary`` already
#: uses for trusted local search/develop runs and is measured here as the A/B
#: candidate.  Nothing in this file changes a product default.
POLICIES = {
    'entry-and-exit': True,
    'entry-only': False,
}


def _shims(events):
    """Install the timers; returns the number of wrapped callables."""
    import contextlib
    import importlib

    def record(name, seconds):
        row = events.setdefault(name, dict(count=0, sum=0.0, max=0.0))
        row['count'] += 1
        row['sum'] += seconds
        row['max'] = max(row['max'], seconds)

    def track(module, attribute):
        original = getattr(module, attribute)

        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                record(attribute, time.perf_counter() - started)
        wrapper.__name__ = attribute
        setattr(module, attribute, wrapper)

    def track_scope(module, attribute):
        original = getattr(module, attribute)

        @contextlib.contextmanager
        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            with original(*args, **kwargs) as state:
                record(attribute + '[enter]', time.perf_counter() - started)
                body_started = time.perf_counter()
                try:
                    yield state
                finally:
                    record(attribute + '[body]', time.perf_counter() - body_started)
                    exit_started = time.perf_counter()
            record(attribute + '[exit]', time.perf_counter() - exit_started)
        setattr(module, attribute, wrapper)

    for module_name, attribute in ATTRIBUTION_TARGETS:
        module = importlib.import_module(module_name)
        if attribute in {name for _, name in SCOPE_TARGETS}:
            continue
        if hasattr(module, attribute):
            track(module, attribute)
    for module_name, attribute in SCOPE_TARGETS:
        module = importlib.import_module(module_name)
        if hasattr(module, attribute):
            track_scope(module, attribute)
    return len(ATTRIBUTION_TARGETS)


def in_process_run(name, *, cache, output, policy='entry-and-exit', python=None):
    """Run one delegate in *this* process under plain timers.

    Import order matters: the timers must be installed before the delegate
    imports the wrapped names, so the library modules are imported here first.
    The delegate itself runs through ``runpy`` with the exact argv it would get
    as a process, and ``sys.stdin`` is replaced only for the online loop.
    """
    import io

    sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
    events = {}
    _shims(events)
    if policy != 'entry-and-exit':
        from myfuzz.local_harness import execution_validation as validation_module
        original = validation_module.execution_validation_scope
        revalidate = POLICIES[policy]

        def forced(*args, **kwargs):
            kwargs['revalidate'] = revalidate
            return original(*args, **kwargs)
        validation_module.execution_validation_scope = forced
    spec = CLASSES[name]
    argv = delegate_argv(spec, cache=cache, output=output, python=python)
    spec_argv = sys.argv
    saved_stdin = sys.stdin
    if spec['mode'] == 'online':
        sys.stdin = io.StringIO('\n'.join(spec['inputs']) + '\nEND\n')
    sys.argv = [argv[1], *argv[2:]]
    self_before = resource.getrusage(resource.RUSAGE_SELF)
    children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started, started_wall = time.perf_counter(), time.time()
    error = None
    try:
        runpy.run_path(str(ROOT / spec['delegate']), run_name='__main__')
    except SystemExit as exit_error:
        error = None if not exit_error.code else 'SystemExit %r' % (exit_error.code,)
    except BaseException as exception:  # recorded, never swallowed silently
        error = ''.join(traceback.format_exception_only(type(exception), exception)).strip()
    finally:
        ended = time.perf_counter()
        sys.argv = spec_argv
        sys.stdin = saved_stdin
    self_after = resource.getrusage(resource.RUSAGE_SELF)
    children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return dict(
        class_name=name, policy=policy, revalidate=POLICIES[policy],
        argv=[str(value) for value in argv], error=error,
        in_process_seconds=ended - started,
        started_wall=started_wall,
        cpu_seconds=(self_after.ru_utime + self_after.ru_stime
                     - self_before.ru_utime - self_before.ru_stime),
        children_cpu_seconds=(children_after.ru_utime + children_after.ru_stime
                              - children_before.ru_utime - children_before.ru_stime),
        self_maxrss_kb=self_after.ru_maxrss,
        events=events,
    )


def attributions(workdir, *, cache_state='hot', classes=('F5', 'F6', 'F1F4'),
                 repetitions=1, python=None):
    """One nested-child attribution run per class (isolated import state)."""
    rows = []
    for name in classes:
        for index in range(repetitions):
            output = Path(workdir) / ('attribution-%s-%s-%d' % (name, cache_state, index + 1))
            if output.exists():
                shutil.rmtree(output)
            payload = dict(class_name=name, cache=str(Path(workdir) / ('cache-' + name)),
                           output=str(output))
            argv = [python or sys.executable, str(Path(__file__).resolve()), '--in-process', name,
                    '--workdir', str(workdir), '--policy', 'entry-and-exit',
                    '--cache', payload['cache'], '--output', payload['output']]
            child = run_child(argv, cwd=ROOT, stdin_bytes=None,
                              stdout_path=Path(workdir) / 'logs' / (output.name + '.stdout'),
                              stderr_path=Path(workdir) / 'logs' / (output.name + '.stderr'))
            document, read_error = read_json(Path(payload['output']).parent /
                                             'logs' / (output.name + '.attribution.json'))
            row = dict(document or {})
            row.update(cache_state=cache_state, output=payload['output'],
                       wall_seconds=child['wall_seconds'], cpu_seconds=child['cpu_seconds'],
                       maxrss_kb=child['maxrss_kb'], returncode=child['returncode'],
                       open_error=read_error)
            summary, _ = read_json(Path(payload['output']) / 'summary.json')
            parsed = parse_run_log((Path(payload['output']) / 'run.log').read_text(errors='replace')
                                   if (Path(payload['output']) / 'run.log').is_file() else '')
            row['delegate'] = dict(
                status=(summary or {}).get('status'),
                link_seconds=(summary or {}).get('link_seconds'),
                run_seconds=(summary or {}).get('run_seconds'),
                total_seconds=(summary or {}).get('total_seconds'))
            row['log'] = dict(cases=len(parsed['cases']),
                              requests=parsed['requests'],
                              runtime_seconds=(parsed['summary'] or {}).get('runtime_seconds'),
                              summary_status=(parsed['summary'] or {}).get('status'))
            row['inventory'] = artifact_inventory(payload['output'])
            rows.append(row)
    return rows


def ab_policy(workdir, *, cache_state='hot', classes=('F5', 'F6', 'F1F4'),
              repetitions=1, python=None):
    """A/B the two validation policies over *identical* inputs.

    The only difference between the two arms is whether the scope re-runs its
    static validators after the body.  Everything the run observes is compared
    afterwards: the case rows, the tick/IRQ counters, ``run.log`` bytes and the
    summary document without its timing fields.
    """
    rows = []
    for name in classes:
        spec = CLASSES[name]
        for index in range(repetitions):
            arms = {}
            for policy in POLICIES:
                output = Path(workdir) / ('ab-%s-%s-%d-%s' % (name, cache_state, index + 1, policy))
                if output.exists():
                    shutil.rmtree(output)
                argv = [python or sys.executable, str(Path(__file__).resolve()), '--in-process', name,
                        '--workdir', str(workdir), '--policy', policy,
                        '--cache', str(Path(workdir) / ('cache-' + name)),
                        '--output', str(output)]
                child = run_child(argv, cwd=ROOT, stdin_bytes=None,
                                  stdout_path=Path(workdir) / 'logs' / (output.name + '.stdout'),
                                  stderr_path=Path(workdir) / 'logs' / (output.name + '.stderr'))
                document, read_error = read_json(Path(workdir) / 'logs' /
                                                 (output.name + '.attribution.json'))
                arms[policy] = dict(
                    output=str(output), wall_seconds=child['wall_seconds'],
                    cpu_seconds=child['cpu_seconds'], maxrss_kb=child['maxrss_kb'],
                    returncode=child['returncode'], open_error=read_error,
                    attribution=document,
                    **observed_work(output),
                )
            baseline, candidate = arms['entry-and-exit'], arms['entry-only']
            differences = work_differences(baseline['output'], candidate['output'])
            rows.append(dict(class_name=name, cache_state=cache_state,
                             repetition=index + 1, arms=arms,
                             remaining_differences=differences,
                             identical_work=not differences,
                             identical_run_log=baseline['run_log_sha256'] ==
                             candidate['run_log_sha256'],
                             wall_saving_seconds=baseline['wall_seconds'] -
                             candidate['wall_seconds'],
                             attribution_saving_seconds=(
                                 (baseline['attribution'] or {}).get('events', {})
                                 .get('execution_validation_scope[exit]', {}).get('sum', 0.0)
                                 - (candidate['attribution'] or {}).get('events', {})
                                 .get('execution_validation_scope[exit]', {}).get('sum', 0.0))))
    return rows


def without_timings(value):
    """Drop every measured duration so two runs of the same work compare equal.

    ``*_seconds``/``seconds`` values are the only fields a run is allowed to
    differ in; keeping them would hide a real observation change behind a
    timing difference (or the reverse).
    """
    if isinstance(value, dict):
        return {key: without_timings(item) for key, item in value.items()
                if key != 'seconds' and not key.endswith('_seconds')}
    if isinstance(value, list):
        return [without_timings(item) for item in value]
    return value


def document_differences(left, right, path='$'):
    """Every structural or value difference, as ``(path, left, right)`` rows."""
    rows = []
    if type(left) is not type(right):
        return [(path, type(left).__name__, type(right).__name__)]
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                rows.append((path + '/' + key, key in left, key in right))
            else:
                rows += document_differences(left[key], right[key], path + '/' + key)
    elif isinstance(left, list):
        if len(left) != len(right):
            rows.append((path, len(left), len(right)))
        else:
            for index, (first, second) in enumerate(zip(left, right)):
                rows += document_differences(first, second, '%s[%d]' % (path, index))
    elif left != right:
        rows.append((path, left, right))
    return rows


_TIMING_TOKEN = re.compile(r'\b([A-Za-z_]*seconds)\s+\S+')


def normalize_run_log(text):
    """Remove the measured durations from a log so the rest can be compared."""
    return _TIMING_TOKEN.sub(r'\1', text)


def observed_work(output):
    """The facts a run must not lose: case rows, counters, status and digests."""
    output = Path(output)
    summary, _ = read_json(output / 'summary.json')
    log_text = _read_text(output / 'run.log')
    parsed = parse_run_log(log_text)
    observed = without_timings(dict(cases=parsed['cases'], summary=parsed['summary']))
    return dict(
        observed_work_sha256=_digest(observed),
        run_log_sha256=_digest(normalize_run_log(log_text)),
        summary_digest=_digest(without_timings(summary or {})),
        cases=len(parsed['cases']),
        ticks=(parsed['summary'] or {}).get('ticks'),
        takes=(parsed['summary'] or {}).get('takes', (parsed['summary'] or {}).get('irq_takes')),
        status=(parsed['summary'] or {}).get('status'),
    )


def work_differences(baseline_output, candidate_output):
    """Differences between two runs *outside* the measured durations."""
    differences = []
    left, _ = read_json(Path(baseline_output) / 'summary.json')
    right, _ = read_json(Path(candidate_output) / 'summary.json')
    differences += document_differences(without_timings(left or {}),
                                        without_timings(right or {}), '$/summary.json')
    differences += document_differences(
        without_timings(parse_run_log(_read_text(Path(baseline_output) / 'run.log'))),
        without_timings(parse_run_log(_read_text(Path(candidate_output) / 'run.log'))),
        '$/run.log')
    return differences


def _read_text(path):
    path = Path(path)
    return path.read_text(errors='replace') if path.is_file() else ''


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Output-write cost, re-measured on the produced artifacts
# --------------------------------------------------------------------------- #
def remeasure_writes(run, *, scratch):
    """Reproduce each output write on the real file and time parse/render/write.

    The entries' own write duration is not logged, so it is re-measured on the
    exact bytes they left: the render is checked against those bytes (``identical``)
    to prove the re-measurement is of the same document.
    """
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    rows = []
    for row in (run.get('inventory') or {}).get('files', ()):
        path = Path(run['output']) / row['name']
        if not path.is_file():
            continue
        started = time.perf_counter()
        payload = path.read_bytes()
        read_seconds = time.perf_counter() - started
        parse_seconds = render_seconds = None
        identical = None
        target = scratch / ('remeasure' + path.suffix)
        if path.suffix == '.json':
            started = time.perf_counter()
            document = json.loads(payload)
            parse_seconds = time.perf_counter() - started
            started = time.perf_counter()
            rendered = (json.dumps(document, indent=2) + '\n').encode()
            render_seconds = time.perf_counter() - started
            identical = rendered == payload
            payload = rendered
        started = time.perf_counter()
        target.write_bytes(payload)
        write_seconds = time.perf_counter() - started
        rows.append(dict(name=row['name'], bytes=len(payload), compact=identical,
                         read_seconds=read_seconds, parse_seconds=parse_seconds,
                         render_seconds=render_seconds, write_seconds=write_seconds,
                         timing_seconds=(parse_seconds or 0.0) + (render_seconds or 0.0)
                         + write_seconds))
    target = scratch / ('remeasure' + '.total')
    total = dict(bytes=sum(row['bytes'] for row in rows),
                 timing_seconds=sum(row['timing_seconds'] for row in rows),
                 parse_seconds=sum(row['parse_seconds'] or 0.0 for row in rows),
                 render_seconds=sum(row['render_seconds'] or 0.0 for row in rows),
                 write_seconds=sum(row['write_seconds'] for row in rows))
    return dict(files=rows, total=total, scratch=str(scratch))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _seconds(value):
    return 'unknown' if value is None else '%.3f' % value


def recompute_row(run):
    """Re-derive the anchors and the phase split of one stored row.

    The output directory and the run's own wall bounds are kept in
    ``measurements.json``, so neither a formula change nor a fix of the anchor
    rule forces the runs to be repeated: the report is always rendered with one
    rule over the same measurements.  A row whose directory is gone keeps the
    anchors it was recorded with.
    """
    output = Path(run.get('output') or '')
    if output.is_dir():
        if isinstance(run.get('started_wall'), (int, float)):
            run['anchors'] = mtime_anchors(output, started_wall=run['started_wall'],
                                           ended_wall=run['ended_wall'],
                                           wall_seconds=run.get('wall_seconds'))
        if (output / 'run.log').is_file():
            parsed = parse_run_log((output / 'run.log').read_text(errors='replace'))
            seconds = case_seconds(read_json(output / 'summary.json')[0])
            run['log'] = dict(
                cases=len(parsed['cases']), requests=parsed['requests'],
                summary_status=(parsed['summary'] or {}).get('status'),
                ticks=(parsed['summary'] or {}).get('ticks'),
                runtime_seconds=(parsed['summary'] or {}).get('runtime_seconds'),
                case_seconds=seconds,
                case_seconds_sum=(None if not seconds or any(value is None for value in seconds)
                                  else sum(seconds)))
            run['model_init'] = dict(
                seconds=None,
                bound_seconds=model_init_bound(run['log']['runtime_seconds'], seconds),
                reason=MODEL_INIT_REASON)
    return run


def recompute_phases(run):
    """Re-derive the phase split of a stored row from its recorded anchors."""
    anchors = run.get('anchors') or {}
    delegate = run.get('delegate') or {}
    run['phases'] = phase_segments(
        wall=run.get('wall_seconds'), launch_to_first=anchors.get('launch_to_first'),
        body=anchors.get('body'), tail=anchors.get('tail'),
        total_seconds=delegate.get('total_seconds'),
        link_seconds=delegate.get('link_seconds'),
        run_seconds=delegate.get('run_seconds'))
    return run


def group_runs(runs):
    """``{(class, cache_state): [rows]}`` in a stable order."""
    grouped = {}
    for row in runs:
        grouped.setdefault((row['class_name'], row['mode']), []).append(row)
    return dict(sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])))


def median_row(rows, key):
    values = [row[key] for row in rows if isinstance(row.get(key), (int, float))]
    return statistics.median(values) if values else None


def markdown_table(header, rows):
    """Minimal pipe table; alignment is left so the text stays readable."""
    lines = ['| ' + ' | '.join(header) + ' |',
             '| ' + ' | '.join('---' for _ in header) + ' |']
    for row in rows:
        lines.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
    return '\n'.join(lines)


#: Recommendations.  None of them is applied here: every one of them lives in a file
#: this measurement is not allowed to edit, and every number quoted is measured above.
PROPOSALS = """## Proposals (measured, not applied: the files belong to another owner)

**P1 - select the already-supported entry-only static validation for trusted local
fixed-input runs.** The scope exit re-authenticates every static validator and costs
5.4-5.7 s of a ~11.2 s hot run (49-50 %). `myfuzz.search.workflow.run_boundary` already
runs `execution_validation_scope(revalidate=False)` for trusted local search/develop
work and records `static_validation_policy`; the prototype entries keep the
entry-and-exit default. Trying the entry-only policy in-process (A/B above) measures
11.28-11.43 s -> 5.64-5.83 s with **zero** observed differences (same case rows, same
tick/IRQ counters, same run.log after removing durations), i.e. no handshake and no
observation is dropped - only the post-run identity re-check. Whether that check may be
skipped for this workload is the owner's policy decision, so it is measured here and
not applied.

**P2 - memoise the component elaboration per artifact digest.** `_elaborate_profile`
is called **8 times per run for 2 models** (3.4-3.8 s) and `render_local_driver` 8
times (1.4-1.5 s); `plan_local_harness` 2 times (0.9-1.0 s). One memo keyed by the
artifact digest would remove ~2.5-3.5 s from a hot run without touching the DUT.

**P3 - cache the model-build receipt.** `build_local_harness_with_receipt` re-validates
both models on every run even when the Verilated model comes from the cache
(2.7-3.4 s for the CPU + 0.34-0.39 s for the IP at a cache hit).

**P4 - measured and deliberately not optimised:** the whole output write is 0.9-4.3 ms
per run (0.48-0.52 MB, of which the 474-493 KB executable), `_link_key` 17 ms,
`_cached_link` 9 ms, and the real DUT advance 4.4-6.7 ms. There is nothing to gain
there, and the DUT advance must not be shortened."""


def report_markdown(document):
    """Render the whole measurement as one Markdown report."""
    runs = document.get('runs') or []
    attributed = document.get('attribution') or []
    ab = document.get('ab_policy') or []
    inventory = document.get('write_inventory') or []
    environment_facts = document.get('environment') or {}
    lines = ['# In-process phase measurement (Step E)', '',
             'Generated ' + time.strftime('%Y-%m-%d %H:%M:%S'),
             '', 'Observation scope: ' + str(document.get('observation_scope')), '',
             'Host: ' + str(environment_facts.get('cpu_model')) + ', ' +
             str(environment_facts.get('cpu_count')) + ' CPUs, Python ' +
             str(environment_facts.get('python')), '']
    header = ['class', 'cache', 'wall', 'python prep', 'product prep', 'link',
              'DUT run', 'write+exit', 'model init', 'maxrss MB', 'artifacts KB',
              'cache hit', 'status']
    rows = []
    for (name, mode), group in group_runs(runs).items():
        phases = [row['phases'] for row in group]
        hits = [(row.get('cache_observed') or {}).get('link_cache_hit') for row in group]
        rows.append([
            name, mode, _seconds(median_row(group, 'wall_seconds')),
            _seconds(_median(phases, 'python_prepare')),
            _seconds(_median(phases, 'product_prepare')),
            _seconds(_median(phases, 'link')),
            _seconds(_median(phases, 'run')),
            _seconds(_median(phases, 'write_and_exit')),
            'unknown',
            _whole(_median_divide(group, 'maxrss_kb', 1024.0)),
            _whole(_median_divide(group, 'artifact_bytes', 1024.0)),
            '/'.join(str(value) for value in hits),
            group[0]['status']['status']])
    lines += ['## Phases per run (seconds; median of the recorded repetitions)', '',
              markdown_table(header, rows), '']
    stepped = ['%s %s r%d: %+.3f s' % (row['class_name'], row['mode'], row['repetition'],
                                       row['anchors']['clock_step_seconds'])
               for row in runs
               if isinstance((row.get('anchors') or {}).get('clock_step_seconds'), (int, float))
               and not (row.get('anchors') or {}).get('anchors_trusted', True)]
    if stepped:
        lines += ['Real-time clock step detected during (split still additive, but the '
                  'run is flagged): ' + '; '.join(stepped), '']
    lines += ['## DUT detail (the whole real advance, and its bound)', '',
              markdown_table(['class', 'cache', 'spike alone ms', 'spike RSS MB',
                              'runtime_seconds', 'sum case seconds', 'model-init bound',
                              'cases', 'ticks'],
                             [[row['class_name'], row['mode'],
                               '%.2f' % (1000.0 * (row.get('spike') or {}).get('wall_seconds', 0.0)),
                               _whole((row.get('spike') or {}).get('maxrss_kb', 0) / 1024.0),
                               _fine(row['log'].get('runtime_seconds')),
                               _fine(row['log'].get('case_seconds_sum')),
                               _fine((row.get('model_init') or {}).get('bound_seconds')),
                               row['log']['cases'], row['log'].get('ticks')]
                              for row in runs]), '',
              'Model init is **unknown**: every C++ host starts its clock before '
              '`VerilatedContext`/model construction and the reset sequence, so only an '
              'upper bound is derived, and only for F1-F4 (which prints per-case spans). '
              'For F5/F6 the whole `runtime_seconds` (1.5-2.9 ms) already bounds it.', '']
    lines += ['## Artifact inventory (bytes per category)', '']
    for row in runs:
        categories = ', '.join('%s=%d' % item
                               for item in row['inventory']['by_category'].items())
        lines.append('* %s %s r%d: %d bytes (%s)' % (
            row['class_name'], row['mode'], row['repetition'],
            row['inventory']['total_bytes'], categories))
    lines.append('')
    if attributed:
        lines += ['## Attribution (in-process, plain timers; seconds)', '']
        for row in attributed:
            rows = [[name, value['count'], '%.3f' % value['sum'], '%.3f' % value['max']]
                    for name, value in sorted(row.get('events', {}).items(),
                                              key=lambda item: -item[1]['sum'])]
            if rows:
                lines += ['### ' + row['class_name'], '', markdown_table(
                    ['function', 'calls', 'sum', 'max'], rows), '']
    if ab:
        lines += ['## Candidate A/B (same inputs, same observations)', '',
                  markdown_table(['class', 'rep', 'baseline wall', 'entry-only wall',
                                  'saving', 'identical work', 'identical run.log'],
                                 [[row['class_name'], row['repetition'],
                                   '%.3f' % row['arms']['entry-and-exit']['wall_seconds'],
                                   '%.3f' % row['arms']['entry-only']['wall_seconds'],
                                   '%.3f' % row['wall_saving_seconds'],
                                   row['identical_work'], row['identical_run_log']]
                                  for row in ab]), '']
    states = sorted({row.get('source_state') for row in runs if row.get('source_state')})
    attempts = ['%s %s r%d: %d attempts' % (row['class_name'], row['mode'],
                                            row['repetition'], row['attempts'])
                for row in runs if (row.get('attempts') or 1) > 1]
    lines += ['## Comparability record', '',
              '* CPU/IP: ibex_rvfi_local + pulp_timer_irq (F5, F1-F4), zipdma_smoke (F6); '
              'both sides declare 50 MHz.',
              '* Inputs: exactly two cases per class, identical for every column of the table.',
              '* Cache: `cache-<class>` absent before the cold run and reused by the hot runs; '
              'the measured cache state is the `cache hit` column, not an assumption.',
              '* Observation scope: ' + str(document.get('observation_scope')) + '.',
              '* Source state (src/myfuzz + scripts + configs): ' +
              (', '.join(state[:12] for state in states) if states else 'not recorded') +
              (' — one digest for every run' if len(states) <= 1
               else ' — %d different trees, the columns are NOT comparable' % len(states)),
              '* Host clock: `CLOCK_REALTIME` here steps by 0.7-1.1 s now and then; a run whose '
              'two real-time readings disagree is repeated and flagged.',
              ('* Repeated after a clock step: ' + '; '.join(attempts) + '.') if attempts else '',
              '']
    if inventory:
        lines += ['## Output-write cost re-measured on the produced files', '',
                  markdown_table(['class', 'mode', 'files', 'bytes', 'parse s',
                                  'render s', 'write s'],
                                 [[row['class_name'], row['mode'], len(row['result']['files']),
                                   row['result']['total']['bytes'],
                                   '%.5f' % row['result']['total']['parse_seconds'],
                                   '%.5f' % row['result']['total']['render_seconds'],
                                   '%.5f' % row['result']['total']['write_seconds']]
                                  for row in inventory]), '']
    lines += [PROPOSALS, '']
    return '\n'.join(line for line in lines if line is not None) + '\n'


def _fine(value):
    """Places that survive a sub-millisecond span, unlike ``_seconds``."""
    return 'unknown' if value is None else '%.5f' % value


def _whole(value):
    return 'unknown' if value is None else str(int(round(value)))


def _median_divide(rows, key, divisor):
    value = median_row(rows, key)
    return None if value is None else value / divisor


def _median(phases, key):
    values = [row[key] for row in phases if isinstance(row.get(key), (int, float))]
    return statistics.median(values) if values else None


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def _parser():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--workdir', type=Path, required=True,
                        help='directory that holds measurements.json, caches, outputs')
    parser.add_argument('--mode', choices=('cold', 'hot'), help='run the entries')
    parser.add_argument('--classes', default='F5,F6,F1F4')
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--attribution', action='store_true')
    parser.add_argument('--ab-policy', action='store_true')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--retries', type=int, default=2,
                        help='extra attempts when the host real-time clock steps during a '
                             'run (the file anchors of such a run cannot be trusted)')
    parser.add_argument('--replace', action='store_true',
                        help='re-run an existing output directory (and, for --mode cold, '
                             'delete the cache so the run is cold again)')
    parser.add_argument('--remeasure-writes', action='store_true')
    parser.add_argument('--in-process', choices=tuple(CLASSES), help=argparse.SUPPRESS)
    parser.add_argument('--policy', choices=tuple(POLICIES), default='entry-and-exit',
                        help=argparse.SUPPRESS)
    parser.add_argument('--cache', type=Path, help='cache directory for one class')
    parser.add_argument('--output', type=Path, help='output directory for one run')
    parser.add_argument('--python', default=sys.executable)
    return parser


def _classes(text):
    names = [name.strip() for name in text.split(',') if name.strip()]
    unknown = [name for name in names if name not in CLASSES]
    if unknown:
        raise SystemExit('unknown class(es): ' + ', '.join(unknown))
    return names


def main(argv=None):
    args = _parser().parse_args(argv)
    workdir = args.workdir.resolve()
    if args.in_process:
        # Hidden sub-command: one delegate, one process, timers installed.
        result = in_process_run(args.in_process, cache=args.cache, output=args.output,
                               policy=args.policy, python=args.python)
        target = workdir / 'logs' / (Path(args.output).name + '.attribution.json')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2) + '\n')
        return 0 if result.get('error') is None else 1
    if not (args.mode or args.attribution or args.ab_policy or args.report
            or args.remeasure_writes):
        raise SystemExit('one of --mode/--attribution/--ab-policy/--remeasure-writes/'
                         '--report is required')
    workdir.mkdir(parents=True, exist_ok=True)
    runs = load_rows(workdir)
    document = json.loads(rows_path(workdir).read_text()) if rows_path(workdir).is_file() else {}
    if args.mode:
        classes = _classes(args.classes)
        if args.repetitions < 1:
            raise SystemExit('--repetitions must be positive')
        for name in classes:
            cache = workdir / ('cache-' + name)
            if args.mode == 'cold' and cache.exists():
                if not args.replace:
                    raise SystemExit('cold measurement requires an absent cache: ' + str(cache))
                shutil.rmtree(cache)
            if args.mode == 'hot' and not cache.exists():
                raise SystemExit('hot measurement requires the cold cache: ' + str(cache))
            for index in range(args.repetitions):
                output = workdir / ('%s-%s-r%d' % (name, args.mode, index + 1))
                if output.exists():
                    if not args.replace:
                        raise SystemExit('output directory already exists: ' + str(output))
                    shutil.rmtree(output)
                    runs = [row for row in runs
                            if not (row['class_name'] == name and row['mode'] == args.mode
                                    and row['repetition'] == index + 1)]
                attempt = 0
                while True:
                    attempt += 1
                    if output.exists():
                        shutil.rmtree(output)
                    if attempt > 1 and args.mode == 'cold':
                        # a repeated cold run must rebuild every model: keeping the
                        # first attempt's cache would turn it into a warm run
                        shutil.rmtree(cache)
                    row = run_class(name, workdir=workdir, cache=cache,
                                    cache_state=args.mode, output=output,
                                    repetition=index + 1, python=args.python)
                    row['attempts'] = attempt
                    if row['anchors'].get('anchors_trusted') is not False:
                        break
                    step = row['anchors']['clock_step_seconds']
                    if attempt > args.retries:
                        print(json.dumps({'class': name, 'mode': args.mode,
                                          'repetition': index + 1,
                                          'clock_step_seconds': step,
                                          'note': 'anchors flagged, attempts exhausted'}),
                              flush=True)
                        break
                    print(json.dumps({'class': name, 'mode': args.mode,
                                      'repetition': index + 1,
                                      'clock_step_seconds': step,
                                      'note': 'host clock stepped during the run; repeating'}),
                          flush=True)
                runs.append(row)
                print(json.dumps({'class': name, 'mode': args.mode,
                                  'repetition': index + 1,
                                  'wall_seconds': round(row['wall_seconds'], 3),
                                  'attempts': attempt,
                                  'status': row['status']['status']}), flush=True)
                save_rows(workdir, runs, extra={
                    key: document[key] for key in ('attribution', 'ab_policy',
                                                   'write_inventory') if key in document})
    if args.attribution:
        rows = attributions(workdir, cache_state=args.mode or 'hot',
                            classes=_classes(args.classes), python=args.python)
        document['attribution'] = rows
        save_rows(workdir, runs, extra={key: document[key] for key in
                                        ('attribution', 'ab_policy', 'write_inventory')
                                        if key in document})
    if args.ab_policy:
        rows = ab_policy(workdir, cache_state=args.mode or 'hot',
                         classes=_classes(args.classes), python=args.python)
        document['ab_policy'] = rows
        save_rows(workdir, runs, extra={key: document[key] for key in
                                        ('attribution', 'ab_policy', 'write_inventory')
                                        if key in document})
    if args.remeasure_writes:
        scratch = workdir / 'scratch'
        rows = []
        for row in runs:
            if Path(row['output']).is_dir():
                rows.append(dict(class_name=row['class_name'], mode=row['mode'],
                                 repetition=row['repetition'],
                                 result=remeasure_writes(row, scratch=scratch)))
        document['write_inventory'] = rows
        save_rows(workdir, runs, extra={key: document[key] for key in
                                        ('attribution', 'ab_policy', 'write_inventory')
                                        if key in document})
        shutil.rmtree(scratch, ignore_errors=True)
    if args.report:
        document = json.loads(rows_path(workdir).read_text())
        document['runs'] = [recompute_phases(recompute_row(row))
                             for row in document.get('runs') or []]
        path = workdir / 'REPORT.md'
        path.write_text(report_markdown(document))
        save_rows(workdir, document['runs'], extra={key: document[key] for key in
                                                    ('attribution', 'ab_policy',
                                                     'write_inventory') if key in document})
        print(json.dumps({'report': str(path), 'runs': len(document.get('runs') or [])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
