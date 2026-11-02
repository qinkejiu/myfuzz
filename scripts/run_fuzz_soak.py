"""Soak one long fuzz run and measure its memory, throughput and output size.

Two modes:

* the default **entry** mode runs ``scripts/run_inprocess_f1f6.py --fuzz`` as a
  subprocess into a NEW directory under the soak root, samples the entry
  process and its host child from ``/proc/<pid>/status`` every
  ``--sample-seconds`` seconds, and records wall time, cases, throughput,
  peak/median RSS, host restarts and the size of every produced file;
* ``--session-only`` runs :func:`myfuzz.fuzz.session.run_session` against a
  synthetic fast host (a few lines of Python that speak the same
  ``NEED_RECORD``/``case``/``summary`` protocol) for ``--cases`` cases, so the
  bounded-memory property of the session itself is measurable even before the
  entry integration keeps only the sample.

Both modes write ``<output>/soak.json`` (schema ``inprocess_fuzz_soak.v1``) and
a short Chinese ``<output>/REPORT.md`` rendered from that document.  The
``/proc`` sampling and the RSS slope are the measurement; nothing here restarts
the host, and a host restart is reported as a fact rather than hidden.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SOAK_ROOT = ROOT / 'runs' / 'fuzz-soak-20261101'
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

SCHEMA = 'inprocess_fuzz_soak.v1'
DEFAULT_CONFIG = (ROOT / 'configs/scenarios/'
                  'inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json')
DEFAULT_SESSION_CASES = 200_000
DEFAULT_ENTRY_CASES = 200
DEFAULT_SEED = 20261101

#: The synthetic host's case line keeps one bounded feature vocabulary: every
#: value is either constant or a bucket, so the feedback state cannot grow with
#: the case count and the measurement stays a session measurement.
SYNTHETIC_HOST = '''\
"""One fast synthetic fuzz host: the session protocol without a model."""
import os
import sys

cases = int(sys.argv[1])
sys.stdout.write('hostpid %d\\n' % os.getpid())
sys.stdout.flush()
for index in range(cases):
    print('NEED_RECORD %d tick %d' % (index, index * 10), flush=True)
    line = sys.stdin.readline()
    if not line or line.strip() == 'END':
        break
    sys.stdout.write(
        'CASE_INSTALLED %d\\n' % index +
        'case %d observations_passed flow F2 record F2:00014000 '
        'read_addr 0x00014000 read_value 0x00000000 echo_value 0x00000000 '
        'read_from ram target_reads 0 i_fetches 1 d_reads 1 d_writes 0 '
        'apb_reads 0 apb_writes 0 retires 1 ticks 7 seconds 0.0001\\n' % index)
    sys.stdout.flush()
print('summary observations_passed cases %d ticks %d' % (cases, 7 * cases),
      flush=True)
'''


# ---------------------------------------------------------------------------
# /proc sampling
# ---------------------------------------------------------------------------
def _rss_bytes(pid: int) -> int | None:
    """The resident set size of one process, from ``/proc/<pid>/status``."""
    try:
        with open('/proc/%d/status' % pid, 'r', encoding='utf-8',
                  errors='replace') as handle:
            for line in handle:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def _children_of(pid: int) -> list:
    """Every process whose parent is ``pid``, with its ``comm`` name."""
    children = []
    try:
        entries = os.listdir('/proc')
    except OSError:
        return children
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % entry, 'rb') as handle:
                data = handle.read()
        except OSError:
            continue
        open_paren = data.find(b'(')
        close = data.rfind(b')')
        if open_paren < 0 or close <= open_paren:
            continue
        name = data[open_paren + 1:close].decode('utf-8', 'replace')
        fields = data[close + 2:].split()
        if len(fields) < 2:
            continue
        try:
            parent = int(fields[1])
            child = int(entry)
        except ValueError:
            continue
        if parent == pid:
            children.append((child, name))
    return children


def _descendants(pid: int) -> list:
    """``[(pid, comm), ...]`` for the whole process tree below ``pid``."""
    found = []
    stack = [pid]
    while stack:
        parent = stack.pop()
        for child, name in _children_of(parent):
            found.append((child, name))
            stack.append(child)
    return found


def _sample_memory(pid: int) -> dict | None:
    """One sample: the entry, its host child and the whole process tree."""
    entry = _rss_bytes(pid)
    if entry is None:
        return None
    host = 0
    tree = entry
    host_pids = []
    for child, name in _descendants(pid):
        rss = _rss_bytes(child)
        if rss is None:
            continue
        tree += rss
        if 'spike' in name:
            host += rss
            host_pids.append(child)
    return dict(entry_bytes=entry, host_bytes=host,
                total_bytes=entry + host, tree_bytes=tree,
                host_pids=host_pids)


def _fit_slope(points) -> float | None:
    """Least-squares slope of RSS over elapsed seconds; None without two points."""
    points = [point for point in points if point[1] is not None]
    if len(points) < 2:
        return None
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator <= 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denominator


def _mib(value) -> float | None:
    return None if value is None else round(value / (1024 * 1024), 3)


def _mib_text(value) -> str:
    return '%.1f' % (0.0 if value is None else value)


def _rss_document(series, *, warmup, cases, wall) -> dict:
    """Summarise one ``[(elapsed, bytes), ...]`` RSS series."""
    values = [value for _, value in series if value is not None]
    warmup = max(0, min(warmup, len(series)))
    tail = series[warmup:]
    slope = _fit_slope(tail)
    throughput = (cases / wall) if cases and wall and wall > 0 else None
    per_case = (slope / throughput
                if slope is not None and throughput else None)
    return dict(
        samples=len(series),
        warmup_samples=warmup,
        first_bytes=values[0] if values else None,
        last_bytes=values[-1] if values else None,
        peak_bytes=max(values) if values else None,
        median_bytes=(int(statistics.median(values)) if values else None),
        first_after_warmup_bytes=(tail[0][1] if tail else None),
        last_after_warmup_bytes=(tail[-1][1] if tail else None),
        slope_bytes_per_second=(None if slope is None else round(slope, 3)),
        slope_bytes_per_case=(None if per_case is None else round(per_case, 3)),
        slope_mib_per_10k_cases=(None if per_case is None
                                 else round(per_case * 10_000 / (1024 * 1024), 4)),
        series=[[round(elapsed, 3), value] for elapsed, value in series],
    )


def _warmup_index(samples) -> int:
    """The first sample after interpreter/feature warm-up, with two points left."""
    warmup = max(1, len(samples) // 5)
    if len(samples) - warmup < 2:
        warmup = max(0, len(samples) - 2)
    return warmup


def _outputs(directory: Path) -> dict:
    """Every produced file's size, plus the total."""
    files = {}
    total = 0
    for path in sorted(directory.rglob('*')):
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        files[str(path.relative_to(directory))] = size
        total += size
    return dict(files=files, total_bytes=total)


# ---------------------------------------------------------------------------
# Session-only mode
# ---------------------------------------------------------------------------
class _StubStrategy:
    """A cheap input source: the measurement is the session, not the gate."""

    flows = ('F2',)

    def __init__(self) -> None:
        from myfuzz.fuzz.strategy import Input
        self._input = Input
        self.generated = 0

    def seed_inputs(self):
        return []

    def next_input(self):
        self.generated += 1
        address = 0x14000 + 4 * (self.generated % 4)
        return self._input(flow='F2', fields=(address,),
                           text='F2:%08x' % address,
                           message='CASE F2 %08x' % address)


def run_session_only(args, output: Path) -> dict:
    from myfuzz.fuzz.corpus import Corpus
    from myfuzz.fuzz.feedback import FeedbackState
    from myfuzz.fuzz.session import SessionBudget, run_session
    from scripts.run_inprocess_f1f6 import parse_case_line, parse_summary_line

    host_path = output / 'synthetic_host.py'
    host_path.write_text(SYNTHETIC_HOST)
    log_path = output / 'run.log'
    budget = SessionBudget(cases=args.cases, seconds=args.seconds)
    samples = []
    stop = threading.Event()
    started = time.monotonic()

    def sample() -> None:
        while not stop.is_set():
            samples.append((time.monotonic() - started,
                            _rss_bytes(os.getpid())))
            stop.wait(args.sample_seconds)

    sampler = threading.Thread(target=sample, name='soak-sampler', daemon=True)
    sampler.start()
    try:
        result = run_session(
            [sys.executable, str(host_path), str(args.cases)],
            log_path=log_path, strategy=_StubStrategy(),
            feedback=FeedbackState(), corpus=Corpus(max_entries=256),
            case_parser=parse_case_line, summary_parser=parse_summary_line,
            budget=budget)
        document = result.document()
    finally:
        stop.set()
        sampler.join(timeout=5)
        samples.append((time.monotonic() - started, _rss_bytes(os.getpid())))
    total_wall = time.monotonic() - started
    cases = result.stats.executed
    (output / 'session.json').write_text(json.dumps(document, indent=2) + '\n')
    host_pids = []
    if log_path.is_file():
        for line in log_path.read_text(errors='replace').splitlines():
            if line.startswith('hostpid '):
                host_pids.append(int(line.split()[1]))
    return dict(
        status='completed' if result.status in ('completed',
                                                'completed_with_error') else result.status,
        error=result.error,
        wall_seconds=round(total_wall, 3),
        session_wall_seconds=round(result.wall_seconds, 3),
        cases=cases,
        throughput_cases_per_second=(None if not cases or not result.wall_seconds
                                     else round(cases / result.wall_seconds, 1)),
        budget_reached=result.stats.budget_reached,
        session_status=result.status,
        session=dict(
            status=result.status,
            stats=result.stats.document(),
            retention=result.retention,
            cases_total=result.cases_total,
            cases_dropped=result.cases_dropped,
            findings=len(result.findings),
            log_lines=result.log_lines,
            log_flushes=result.log_flushes,
            log_bytes=result.log_bytes,
            document_bytes=len(json.dumps(document)),
            host_pid=result.host_pid,
        ),
        rss=_rss_document(samples, warmup=_warmup_index(samples),
                          cases=cases, wall=result.wall_seconds),
        host_pids=sorted(set(host_pids)),
        host_restarts=max(0, len(set(host_pids)) - 1),
    )


# ---------------------------------------------------------------------------
# Entry mode
# ---------------------------------------------------------------------------
def run_entry(args, output: Path) -> dict:
    entry_dir = output / 'entry'
    entry = ROOT / 'scripts' / 'run_inprocess_f1f6.py'
    argv = [sys.executable, str(entry), '--config', str(args.config),
            '--cache', str(args.cache), '--output', str(entry_dir),
            '--fuzz', '--cases', str(args.cases), '--seed', str(args.seed),
            '--retain-cases', str(args.retain_cases)]
    if not args.prefix:
        argv += ['--no-prefix']
    if args.seconds is not None:
        argv += ['--seconds', str(args.seconds)]
    stdout_path = output / 'entry.stdout'
    total_series, tree_series, entry_series, host_series, host_seen = (
        [], [], [], [], [])
    host_pids = set()
    started = time.monotonic()
    timed_out = False
    with stdout_path.open('wb') as handle:
        process = subprocess.Popen([str(value) for value in argv], cwd=str(ROOT),
                                   stdin=subprocess.DEVNULL, stdout=handle,
                                   stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            deadline = started + args.timeout
            while process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    break
                sample = _sample_memory(process.pid)
                if sample is not None:
                    elapsed = now - started
                    total_series.append((elapsed, sample['total_bytes']))
                    tree_series.append((elapsed, sample['tree_bytes']))
                    entry_series.append((elapsed, sample['entry_bytes']))
                    host_seen.append(bool(sample['host_pids']))
                    if sample['host_pids']:
                        host_series.append((elapsed, sample['host_bytes']))
                        host_pids.update(sample['host_pids'])
                time.sleep(min(args.sample_seconds,
                               max(0.01, deadline - time.monotonic())))
        finally:
            returncode = _ensure_exit(process)
    wall = time.monotonic() - started
    session, summary = _read_entry_documents(entry_dir)
    stats = (session or {}).get('stats') or {}
    result = (summary or {}).get('fuzz_result') or {}
    printed = _printed_json(stdout_path)
    cases = stats.get('executed')
    if not isinstance(cases, int):
        cases = result.get('executed')
    if not isinstance(cases, int):
        cases = 0
    session_wall = (session or {}).get('wall_seconds')
    conversion_wall = (session_wall if isinstance(session_wall, (int, float))
                       and session_wall > 0 else wall)
    warmup = 0
    for index, seen in enumerate(host_seen):
        if seen:
            warmup = index
            break
    return dict(
        status=('timeout' if timed_out else
                (printed or {}).get('status') or
                ('failed' if returncode else 'completed')),
        error=(None if returncode == 0 and not timed_out
               else ('the entry exceeded its timeout'
                     if timed_out else 'entry exit code ' + str(returncode))),
        returncode=returncode,
        timed_out=timed_out,
        wall_seconds=round(wall, 3),
        session_wall_seconds=session_wall,
        cases=cases,
        throughput_cases_per_second=(
            None if not cases or not conversion_wall
            else round(cases / conversion_wall, 1)),
        budget_reached=stats.get('budget_reached'),
        session_status=(session or {}).get('status'),
        session=dict(
            status=(session or {}).get('status'),
            stats=stats or None,
            retention=(session or {}).get('retention'),
            cases_total=(session or {}).get('cases_total'),
            cases_dropped=(session or {}).get('cases_dropped'),
            findings=len((session or {}).get('findings') or ()),
            document_bytes=len(json.dumps(session)) if session else None,
        ),
        rss=_rss_document(total_series, warmup=warmup, cases=cases,
                          wall=conversion_wall),
        tree_rss=_rss_document(tree_series, warmup=warmup, cases=cases,
                               wall=conversion_wall),
        entry_rss=_rss_document(entry_series, warmup=warmup, cases=cases,
                                wall=conversion_wall),
        host_rss=_rss_document(host_series, warmup=0, cases=cases,
                               wall=conversion_wall),
        host_pids=sorted(host_pids),
        host_restarts=max(0, len(host_pids) - 1),
    )


def _read_entry_documents(entry_dir: Path):
    documents = []
    for name in ('fuzz.json', 'summary.json'):
        try:
            documents.append(json.loads((entry_dir / name).read_text()))
        except (OSError, ValueError):
            documents.append(None)
    return documents


def _printed_json(path: Path):
    try:
        lines = path.read_text(errors='replace').splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _signal_group(pid: int, signal_number: int) -> None:
    try:
        os.killpg(pid, signal_number)
    except OSError:
        try:
            os.kill(pid, signal_number)
        except OSError:
            pass


def _ensure_exit(process) -> int | None:
    """Stop the entry and the host it started, never leaving one behind."""
    if process.poll() is not None:
        return process.returncode
    _signal_group(process.pid, 15)
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _signal_group(process.pid, 9)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return process.poll()


# ---------------------------------------------------------------------------
# Report and CLI
# ---------------------------------------------------------------------------
def _report(document: dict) -> str:
    settings = document['settings']
    rss = document['rss']
    session = document['session'] or {}
    session_stats = session.get('stats') or {}
    lines = ['# fuzz 长跑浸泡测量（2026-11-01）', '',
             '测量时间：`%s`；由 `scripts/run_fuzz_soak.py` 从 `soak.json` 渲染。'
             % document['started'], '', '## 短答', '']
    mode = ('会话（session-only）' if document['mode'] == 'session-only'
            else '入口（entry）')
    lines.append('- 模式：%s；预算 cases=%s seconds=%s seed=%s；实际执行 %d 例。'
                 % (mode, settings['cases'], settings['seconds'],
                    settings['seed'], document['cases']))
    lines.append('- 吞吐：%s 例/秒（会话口径）；进程总 wall %.3f s。'
                 % (document['throughput_cases_per_second'], document['wall_seconds']))
    if rss['samples']:
        lines.append(
            '- 常驻内存：峰值 %s MiB、中位 %s MiB；从第 %d 个采样点起 '
            '%s → %s MiB，斜率 %+.2f MiB/万例（%+.1f KiB/秒）。'
            % (_mib_text(_mib(rss['peak_bytes'])),
               _mib_text(_mib(rss['median_bytes'])), rss['warmup_samples'],
               _mib_text(_mib(rss['first_after_warmup_bytes'])),
               _mib_text(_mib(rss['last_after_warmup_bytes'])),
               rss['slope_mib_per_10k_cases'] or 0.0,
               (rss['slope_bytes_per_second'] or 0.0) / 1024.0))
    lines.append('- 预算退出：`budget_reached=%s`，会话状态 `%s`，host 错误 `%s`。'
                 % (document['budget_reached'], document['session_status'],
                    session_stats.get('host_error')))
    lines.append('- host 进程：%d 个 PID（%s），重启 %d 次（必须为 0）。'
                 % (len(document['host_pids']),
                    ', '.join(str(pid) for pid in document['host_pids']) or '未观测到',
                    document['host_restarts']))
    if document['mode'] == 'session-only':
        lines.append('- 会话文档：`session.json` %.1f KiB（有界，不随用例数增长）；'
                     '保留 %d 例 / 丢弃 %s 例；日志 %d 行、%.1f MiB。'
                     % ((session.get('document_bytes') or 0) / 1024.0,
                        (session.get('cases_total') or 0)
                        - (session.get('cases_dropped') or 0),
                        session.get('cases_dropped'),
                        session.get('log_lines') or 0,
                        (session.get('log_bytes') or 0) / (1024 * 1024)))
    else:
        entry_rss = document.get('entry_rss') or {}
        host_rss = document.get('host_rss') or {}
        lines.append('- RSS 拆分：入口进程峰值 %s MiB、host 峰值 %s MiB。'
                     % (_mib_text(_mib(entry_rss.get('peak_bytes'))),
                        _mib_text(_mib(host_rss.get('peak_bytes')))))
        lines.append('- 会话文档：`entry/fuzz.json` %.1f KiB；保留 %d 例 / 丢弃 %s 例。'
                     % ((session.get('document_bytes') or 0) / 1024.0,
                        (session.get('cases_total') or 0)
                        - (session.get('cases_dropped') or 0),
                        session.get('cases_dropped')))
    outputs = document['outputs']
    lines.append('- 输出：合计 %.1f MiB；%s。'
                 % (outputs['total_bytes'] / (1024 * 1024),
                    '、'.join('`%s` %.1f MiB' % (name, size / (1024 * 1024))
                             for name, size in sorted(
                                 outputs['files'].items(),
                                 key=lambda row: -row[1])[:3])))
    lines += ['', '## 表', '',
              '| 项 | 数值 |', '| --- | --- |',
              '| 模式 | %s |' % document['mode'],
              '| 用例 / seed | %d / %s |' % (document['cases'], settings['seed']),
              '| 会话 wall (s) | %s |' % document['session_wall_seconds'],
              '| 采样间隔 (s) / 采样点数 | %s / %d |'
              % (settings['sample_seconds'], rss['samples']),
              '| RSS 峰值 / 中位 (MiB) | %s / %s |'
              % (_mib_text(_mib(rss['peak_bytes'])),
                 _mib_text(_mib(rss['median_bytes']))),
              '| 预热后 RSS 斜率 (MiB/万例) | %s |'
              % rss['slope_mib_per_10k_cases'],
              '| host 重启 | %d |' % document['host_restarts'],
              '| 输出合计 (MiB) | %.1f |'
              % (outputs['total_bytes'] / (1024 * 1024)),
              '', '## 口径', '',
              '每 %s s 读一次 `/proc/<pid>/status` 的 VmRSS（字节）；入口模式同时'
              '对入口进程和它的整棵子进程树取样（host 以进程名含 `spike` 识别）。'
              '斜率是预热后 RSS 对时间的最近二乘斜率，再除以实测会话吞吐折算成'
              '每万例；会话模式预热取前 20%% 采样点，入口模式从首次看到 host 的'
              '采样点起算。`session-only` 的合成 host 只打印固定词表的 case 行，'
              '因此反馈特征与语料都是有界的，测量到的是会话本身的内存。'
              % settings['sample_seconds'], '']
    return '\n'.join(lines)


def _new_output(path, *, default: Path) -> Path:
    """Create a fresh output directory; an existing non-empty one is refused."""
    if path is None:
        candidate = default
        suffix = 2
        while candidate.exists() and any(candidate.iterdir()):
            candidate = default.with_name(default.name + '-r%d' % suffix)
            suffix += 1
        path = candidate
    path = Path(path)
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise SystemExit('output directory is not new: ' + str(path))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Soak one long fuzz run and measure RSS, throughput and '
                    'output size.')
    parser.add_argument('--session-only', action='store_true',
                        help='measure run_session against a synthetic host')
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG,
                        help='entry mode: scenario config to fuzz')
    parser.add_argument('--cache', type=Path, default=SOAK_ROOT / 'cache',
                        help='entry mode: build/link cache directory')
    parser.add_argument('--output', type=Path, default=None,
                        help='new directory for soak.json and REPORT.md')
    parser.add_argument('--cases', type=int, default=None,
                        help='case budget (default: 200000 session-only, 200 entry)')
    parser.add_argument('--seconds', type=float, default=None,
                        help='optional wall-clock budget')
    parser.add_argument('--seed', type=int, default=DEFAULT_SEED,
                        help='input seed')
    parser.add_argument('--prefix', action='store_true',
                        help='keep prefix.txt/observations.jsonl (default: off for soak)')
    parser.add_argument('--retain-cases', type=int, default=128,
                        help='entry --retain-cases for the soak run (default 128)')
    parser.add_argument('--sample-seconds', type=float, default=0.5,
                        help='RSS sampling interval in seconds')
    parser.add_argument('--timeout', type=float, default=1800.0,
                        help='entry mode: whole-process timeout in seconds')
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.cases is None:
        args.cases = (DEFAULT_SESSION_CASES if args.session_only
                      else DEFAULT_ENTRY_CASES)
    if args.cases < 1:
        raise SystemExit('--cases must be positive')
    if args.seconds is not None and args.seconds <= 0:
        raise SystemExit('--seconds must be positive')
    if args.sample_seconds <= 0:
        raise SystemExit('--sample-seconds must be positive')
    if not args.session_only:
        if not Path(args.config).is_file():
            raise SystemExit('config not found: ' + str(args.config))
        Path(args.cache).mkdir(parents=True, exist_ok=True)
    default = SOAK_ROOT / ('%s-%d' % ('session-only' if args.session_only
                                      else 'entry', args.cases))
    output = _new_output(args.output, default=default)
    document = dict(schema_version=SCHEMA,
                    mode='session-only' if args.session_only else 'entry',
                    started=time.strftime('%Y-%m-%d %H:%M:%S'),
                    settings=dict(cases=args.cases, seconds=args.seconds,
                                  seed=args.seed,
                                  sample_seconds=args.sample_seconds,
                                  output=str(output),
                                  config=(None if args.session_only
                                          else str(args.config)),
                                  cache=(None if args.session_only
                                         else str(args.cache))),
                    status='running', error=None,
                    wall_seconds=0.0, session_wall_seconds=None,
                    cases=0, throughput_cases_per_second=None,
                    budget_reached=None, session_status=None, session=None,
                    host_pids=[], host_restarts=0,
                    rss=_rss_document([], warmup=0, cases=0, wall=0.0),
                    tree_rss=_rss_document([], warmup=0, cases=0, wall=0.0),
                    outputs={})
    runner = run_session_only if args.session_only else run_entry
    exit_code = 0
    try:
        document.update(runner(args, output))
    except Exception as failure:
        document['status'] = 'failed'
        document['error'] = '%s: %s' % (type(failure).__name__, failure)
        exit_code = 1
    finally:
        document['outputs'] = _outputs(output)
        (output / 'soak.json').write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + '\n')
        (output / 'REPORT.md').write_text(_report(document))
        print(json.dumps({'mode': document['mode'], 'status': document['status'],
                          'cases': document['cases'],
                          'rss_peak_mib': _mib(document['rss']['peak_bytes']),
                          'output': str(output)}, ensure_ascii=False))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
