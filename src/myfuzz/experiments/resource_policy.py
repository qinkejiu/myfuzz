from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
import copy
import ctypes
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
import threading


_MIB = 1024 * 1024


class ResourceProfileError(ValueError):
    """Raised when a low-resource profile cannot be applied safely."""


def heavy_process_budget(available_bytes: int) -> int:
    """Admit a heavy task only after reserving 2 GiB for the host."""
    if type(available_bytes) is not int or available_bytes < 0:
        raise ResourceProfileError('available memory must be a non-negative integer')
    budget = min(4 * 1024**3, available_bytes - 2 * 1024**3)
    if budget < 1024**3:
        raise ResourceProfileError('insufficient memory for heavy task')
    return budget


def explicit_jvm_heap_bytes(command: Sequence[str], rss_limit_bytes: int) -> int | None:
    """Require a bounded explicit heap for direct Java/SBT/Mill task commands."""
    if (isinstance(command, (str, bytes, bytearray))
            or not isinstance(command, Sequence)
            or any(not isinstance(token, str) for token in command)):
        raise ResourceProfileError('heavy command must be an argument array')
    launcher = Path(command[0]).name.lower() if command else ''
    java_launchers = {'java', 'java.exe'}
    build_launchers = {'sbt', 'sbt.bat', 'mill', 'mill.bat'}
    if launcher not in java_launchers | build_launchers:
        return None

    def is_indirect_options_file(token: str) -> bool:
        if token.startswith('-J'):
            token = token[2:]
        return (token.startswith('@') or token == '-XX:VMOptionsFile'
                or token.startswith('-XX:VMOptionsFile='))

    option_tokens = []
    index = 1
    if launcher in java_launchers:
        takes_value = {
            '-cp', '-classpath', '--class-path', '--module-path', '-p',
            '--upgrade-module-path', '--add-modules', '--limit-modules',
            '--add-exports', '--add-opens', '--add-reads', '--patch-module',
            '--enable-native-access', '--module-source-path', '--source',
        }
        while index < len(command):
            token = command[index]
            if (token in {'-jar', '-m', '--module'}
                    or token.startswith('--module=')):
                break
            if is_indirect_options_file(token):
                raise ResourceProfileError(
                    'JVM argument files cannot be used with a bounded heap command')
            if token in takes_value:
                index += 2
                continue
            if not token.startswith('-'):
                break
            option_tokens.append(token)
            index += 1
    else:
        while index < len(command):
            token = command[index]
            if is_indirect_options_file(token):
                raise ResourceProfileError(
                    'JVM argument files cannot be used with a bounded heap command')
            if not token.startswith('-'):
                break
            option_tokens.append(token)
            index += 1

    def parse_heap(token: str, *, allow_sbt_prefix: bool = False) -> int | None:
        if allow_sbt_prefix and token.startswith('-J'):
            token = token[2:]
        match = re.fullmatch(r'(?:-Xmx|-XX:MaxHeapSize=)([1-9][0-9]*)([kKmMgG]?)', token)
        if match is None:
            return None
        suffix = match.group(2).lower()
        scale = {'': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}[suffix]
        return int(match.group(1)) * scale

    matches = [heap for token in option_tokens
               if (heap := parse_heap(token, allow_sbt_prefix=launcher in build_launchers))
               is not None]
    env_names = ['JDK_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS']
    if launcher in {'sbt', 'sbt.bat'}:
        env_names.extend(['SBT_OPTS', 'JAVA_OPTS'])
    elif launcher in {'mill', 'mill.bat'}:
        env_names.extend(['MILL_JVM_OPTS', 'JAVA_OPTS'])
    for name in env_names:
        value = os.environ.get(name)
        if not value:
            continue
        try:
            tokens = shlex.split(value)
        except ValueError as exc:
            raise ResourceProfileError(f'{name} contains malformed JVM options') from exc
        if any(is_indirect_options_file(token) for token in tokens):
            raise ResourceProfileError(f'{name} cannot include JVM argument files')
        if any(parse_heap(token, allow_sbt_prefix=True) is not None for token in tokens):
            raise ResourceProfileError(f'{name} cannot override the explicit JVM heap')
    if len(matches) != 1:
        raise ResourceProfileError('heavy JVM command requires one explicit JVM heap limit')
    if matches[0] > rss_limit_bytes:
        raise ResourceProfileError('explicit JVM heap exceeds process RSS budget')
    return matches[0]


def available_process_memory() -> int:
    """Linux MemAvailable, constrained by any enclosing cgroup v2 budget."""
    rows = Path('/proc/meminfo').read_text().splitlines()
    available = next(int(row.split()[1]) * 1024 for row in rows
                     if row.startswith('MemAvailable:'))
    cgroup_root = Path('/sys/fs/cgroup')
    directories = {cgroup_root}
    for row in Path('/proc/self/cgroup').read_text().splitlines():
        if row.startswith('0::'):
            candidate = (cgroup_root / row[3:].lstrip('/')).resolve()
            if candidate.is_relative_to(cgroup_root):
                directories.update([candidate, *candidate.parents])
    for directory in directories:
        if not directory.is_relative_to(cgroup_root):
            continue
        try:
            maximum = (directory / 'memory.max').read_text().strip()
            if maximum != 'max':
                current = int((directory / 'memory.current').read_text())
                available = min(available, max(0, int(maximum) - current))
        except FileNotFoundError:
            continue
    return available


def _process_snapshot() -> dict[int, tuple[int, int, int, int, int]]:
    """pid -> (parent, process group, session, birth ticks, resident bytes)."""
    result = {}
    page_size = os.sysconf('SC_PAGE_SIZE')
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
            result[int(path.name)] = (int(fields[1]), int(fields[2]),
                                     int(fields[3]), int(fields[19]),
                                     max(0, int(fields[21])) * page_size)
        except (OSError, ValueError, IndexError):
            # Processes may disappear between enumeration and stat.
            continue
    return result


def _process_tree(pid: int, tracked: dict[int, int], snapshot: dict,
                  existing_children: set[int]) -> set[int]:
    live = {child for child, birth in tracked.items()
            if child in snapshot and snapshot[child][3] == birth}
    live.update(child for child, row in snapshot.items()
                if child == pid or row[1] == pid or row[2] == pid
                or (row[0] == os.getpid() and child not in existing_children))
    while True:
        descendants = {child for child, row in snapshot.items() if row[0] in live}
        if descendants <= live:
            break
        live.update(descendants)
    tracked.update({child: snapshot[child][3] for child in live})
    return live


def _stop_process_tree(process: subprocess.Popen, tracked: dict[int, int],
                       existing_children: set[int]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        snapshot = _process_snapshot()
        children = _process_tree(process.pid, tracked, snapshot, existing_children)
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        for child in children:
            try:
                os.kill(child, sig)
            except ProcessLookupError:
                pass
        if sig == signal.SIGTERM and children:
            time.sleep(.05)
    process.wait(timeout=2)
    # Reap adopted orphans as well as the direct child. A session-detached
    # compiler must not escape cleanup when its intermediate parent dies.
    deadline = time.monotonic() + 1
    pending = set(tracked) - {process.pid}
    while pending and time.monotonic() < deadline:
        for child in list(pending):
            try:
                waited, _ = os.waitpid(child, os.WNOHANG)
                if waited:
                    pending.remove(child)
            except ChildProcessError:
                pending.remove(child)
        if pending:
            time.sleep(.01)


@contextmanager
def _worker_lifecycle():
    """Adopt escaping grandchildren and turn termination into cleanup."""
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise ResourceProfileError('heavy supervisor requires a single-threaded main process')
    existing_children = {pid for pid, row in _process_snapshot().items()
                         if row[0] == os.getpid()}
    if existing_children:
        # A pre-existing child can fork and exit during supervision. Its newly
        # adopted descendants cannot be distinguished from the worker's tree.
        raise ResourceProfileError('heavy supervisor refuses existing child processes')
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) or libc.prctl(36, 1, 0, 0, 0):
        raise ResourceProfileError('cannot establish Linux child subreaper')
    interrupted = [None]
    def on_signal(signum, frame):
        interrupted[0] = signum
    handlers = {sig: signal.getsignal(sig) for sig in
                (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        for sig in handlers:
            signal.signal(sig, on_signal)
        yield existing_children, interrupted
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        libc.prctl(36, previous.value, 0, 0, 0)


def run_budgeted_process(command: Sequence[str], *, lock_path: Path,
                         available_bytes: int | None = None,
                         rss_limit_bytes: int | None = None,
                         timeout_seconds: float | None = None) -> subprocess.CompletedProcess:
    """Run one heavy worker; measure its tree and clean it on every exit path.

    RSS is sampled every 50 ms, so the cap is a termination threshold rather
    than an allocation limit. A budget stop is an infrastructure result.
    """
    if timeout_seconds is not None and (type(timeout_seconds) not in (int, float)
                                       or not 0 < timeout_seconds < float('inf')):
        raise ResourceProfileError('invalid wall timeout')
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ResourceProfileError('heavy worker busy') from exc
        available = available_process_memory() if available_bytes is None else available_bytes
        try:
            limit = heavy_process_budget(available)
        except ResourceProfileError as exc:
            exc.resource_receipt = {
                'schema_version': 'heavy_process_resource_receipt.v1',
                'status': 'startup_refused', 'workers': 1,
                'available_at_start_bytes': available, 'peak_tree_rss_bytes': None,
                'rss_limit_bytes': max(0, min(4 * 1024**3, available - 2 * 1024**3)),
                'elapsed_seconds': None, 'dut_finding': False}
            raise
        if rss_limit_bytes is not None:
            if type(rss_limit_bytes) is not int or not 0 < rss_limit_bytes <= limit:
                raise ResourceProfileError('invalid RSS limit')
            limit = rss_limit_bytes
        heap_limit = explicit_jvm_heap_bytes(command, limit)
        return _supervise_process(command, available, limit, timeout_seconds, heap_limit)


def _supervise_process(command, available, limit, timeout_seconds, heap_limit):
    with _worker_lifecycle() as (existing_children, interrupted):
        started = time.monotonic()
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
        except OSError as exc:
            error = ResourceProfileError(f'cannot launch heavy command: {exc}')
            error.resource_receipt = {
                'schema_version': 'heavy_process_resource_receipt.v1',
                'status': 'launch_failed', 'workers': 1,
                'available_at_start_bytes': available, 'rss_limit_bytes': limit,
                'peak_tree_rss_bytes': None, 'elapsed_seconds': None,
                'sampling_interval_seconds': .05, 'dut_finding': False,
                'jvm_heap_limit_bytes': heap_limit}
            raise error from exc
        tracked = {}
        peak = 0
        status = 'complete'
        try:
            while True:
                snapshot = _process_snapshot()
                tree = _process_tree(process.pid, tracked, snapshot, existing_children)
                peak = max(peak, sum(snapshot[child][4] for child in tree))
                if interrupted[0] is not None:
                    status = 'interrupted'
                    break
                if peak > limit:
                    status = 'budget_terminated'
                    break
                if timeout_seconds is not None and time.monotonic() - started >= timeout_seconds:
                    status = 'wall_timeout'
                    break
                if process.poll() is not None:
                    status = 'complete' if process.returncode == 0 else 'command_failed'
                    break
                try:
                    process.communicate(timeout=.05)
                except subprocess.TimeoutExpired:
                    continue
            _stop_process_tree(process, tracked, existing_children)
            stdout, stderr = process.communicate(timeout=2)
            exit_code = (128 + interrupted[0] if status == 'interrupted' else
                         124 if status in ('budget_terminated', 'wall_timeout')
                         else process.returncode)
            result = subprocess.CompletedProcess(command, exit_code, stdout, stderr)
            result.resource_receipt = {
                'schema_version': 'heavy_process_resource_receipt.v1',
                'status': status, 'workers': 1, 'available_at_start_bytes': available,
                'rss_limit_bytes': limit, 'peak_tree_rss_bytes': peak,
                'elapsed_seconds': time.monotonic() - started,
                'sampling_interval_seconds': .05, 'dut_finding': False,
                'jvm_heap_limit_bytes': heap_limit}
            return result
        finally:
            _stop_process_tree(process, tracked, existing_children)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    candidate_limit: int
    seed_limit: int
    budget_name: str
    build_concurrency: int
    waveforms: bool
    replay_queue_capacity: int
    event_ring_capacity: int
    field_groups_per_batch: int
    soft_memory_bytes: int
    hard_memory_bytes: int
    token_bytes: int
    frontend_concurrency: int = 1

    def __post_init__(self) -> None:
        if not self.name:
            raise ResourceProfileError("profile name must not be empty")
        if not self.budget_name:
            raise ResourceProfileError("profile budget_name must not be empty")
        positive = (
            ("candidate_limit", self.candidate_limit),
            ("seed_limit", self.seed_limit),
            ("build_concurrency", self.build_concurrency),
            ("replay_queue_capacity", self.replay_queue_capacity),
            ("event_ring_capacity", self.event_ring_capacity),
            ("field_groups_per_batch", self.field_groups_per_batch),
            ("soft_memory_bytes", self.soft_memory_bytes),
            ("hard_memory_bytes", self.hard_memory_bytes),
            ("token_bytes", self.token_bytes),
            ("frontend_concurrency", self.frontend_concurrency),
        )
        for label, value in positive:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ResourceProfileError(f"{label} must be a positive integer")
        if self.build_concurrency != 1:
            raise ResourceProfileError("low-resource build_concurrency must be 1")
        if self.frontend_concurrency != 1:
            raise ResourceProfileError("low-resource frontend_concurrency must be 1")
        if self.waveforms is not False:
            raise ResourceProfileError("low-resource waveforms must be false")
        if self.soft_memory_bytes >= self.hard_memory_bytes:
            raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
        if self.token_bytes > self.soft_memory_bytes:
            raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")


CONSERVATIVE_PROFILE = ResourceProfile(
    name="conservative",
    candidate_limit=1,
    seed_limit=1,
    budget_name="smoke",
    build_concurrency=1,
    waveforms=False,
    replay_queue_capacity=32,
    event_ring_capacity=512,
    field_groups_per_batch=16,
    soft_memory_bytes=512 * _MIB,
    hard_memory_bytes=768 * _MIB,
    token_bytes=64 * _MIB,
)


def apply_resource_profile(
    config: Mapping[str, object],
    profile: ResourceProfile = CONSERVATIVE_PROFILE,
) -> dict[str, object]:
    """Return a detached planner config constrained by one resource profile."""
    if not isinstance(config, Mapping):
        raise ResourceProfileError("config must be an object")
    if not isinstance(profile, ResourceProfile):
        raise ResourceProfileError("profile must be a ResourceProfile")

    detached = copy.deepcopy(dict(config))
    selection = detached.get("candidate_selection")
    pair = detached.get("candidate_pair")
    budgets = detached.get("budgets")
    if not isinstance(selection, Mapping):
        raise ResourceProfileError("candidate_selection must be an object")
    if not isinstance(pair, Mapping):
        raise ResourceProfileError("candidate_pair must be an object")
    candidate_count = selection.get("k")
    if isinstance(candidate_count, bool) or not isinstance(candidate_count, int) or candidate_count <= 0:
        raise ResourceProfileError("candidate_selection.k must be a positive integer")
    seeds = pair.get("seeds")
    if not isinstance(seeds, Sequence) or isinstance(seeds, (str, bytes, bytearray)) or not seeds:
        raise ResourceProfileError("candidate_pair.seeds must be a non-empty array")
    normalized_seeds: list[int] = []
    for seed in seeds:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ResourceProfileError("candidate_pair.seeds must contain non-negative integers")
        normalized_seeds.append(seed)
    if len(normalized_seeds) != len(set(normalized_seeds)):
        raise ResourceProfileError("candidate_pair.seeds must be unique")
    if not isinstance(budgets, Sequence) or isinstance(budgets, (str, bytes, bytearray)) or not budgets:
        raise ResourceProfileError("budgets must be a non-empty array")
    selected_budget: dict[str, object] | None = None
    names: set[str] = set()
    for item in budgets:
        if not isinstance(item, Mapping):
            raise ResourceProfileError("each budget must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ResourceProfileError("budget name must be a non-empty string")
        if name in names:
            raise ResourceProfileError("budget names must be unique")
        names.add(name)
        budget_label = "selected budget" if name == profile.budget_name else "budget"
        kind = item.get("kind")
        if not isinstance(kind, str) or kind not in {"cycles", "seconds"}:
            raise ResourceProfileError(f"{budget_label} kind must be cycles or seconds")
        value = item.get("value")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError(f"{budget_label} value must be a positive integer")
        if name == profile.budget_name:
            selected_budget = copy.deepcopy(dict(item))
    if selected_budget is None:
        raise ResourceProfileError(f"required budget is missing: {profile.budget_name}")

    def positive_int(label: str) -> int:
        value = detached.get(label)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError(f"{label} must be a positive integer")
        return value

    input_soft = positive_int("soft_memory_bytes")
    input_hard = positive_int("hard_memory_bytes")
    input_token = positive_int("token_bytes")
    input_build_concurrency = positive_int("build_concurrency")
    input_frontend_concurrency = detached.get("frontend_concurrency", 1)
    if (
        isinstance(input_frontend_concurrency, bool)
        or not isinstance(input_frontend_concurrency, int)
        or input_frontend_concurrency <= 0
    ):
        raise ResourceProfileError("frontend_concurrency must be a positive integer")
    if not isinstance(detached.get("waveforms"), bool):
        raise ResourceProfileError("waveforms must be boolean")
    if input_soft >= input_hard:
        raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
    if input_token > input_soft:
        raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")

    output_selection = dict(selection)
    output_selection["k"] = min(candidate_count, profile.candidate_limit)
    output_pair = dict(pair)
    output_pair["seeds"] = sorted(normalized_seeds)[: profile.seed_limit]
    detached["candidate_selection"] = output_selection
    detached["candidate_pair"] = output_pair
    detached["budgets"] = [selected_budget]
    detached["build_concurrency"] = min(input_build_concurrency, profile.build_concurrency)
    detached["frontend_concurrency"] = min(
        input_frontend_concurrency, profile.frontend_concurrency
    )
    detached["waveforms"] = profile.waveforms
    detached["replay_queue_capacity"] = min(
        positive_int("replay_queue_capacity"), profile.replay_queue_capacity
    )
    detached["event_ring_capacity"] = min(
        positive_int("event_ring_capacity"), profile.event_ring_capacity
    )
    detached["field_groups_per_batch"] = min(
        positive_int("field_groups_per_batch"), profile.field_groups_per_batch
    )
    output_soft = min(input_soft, profile.soft_memory_bytes)
    output_hard = min(input_hard, profile.hard_memory_bytes)
    if output_soft >= output_hard:
        raise ResourceProfileError("profile would make soft_memory_bytes invalid")
    detached["soft_memory_bytes"] = output_soft
    detached["hard_memory_bytes"] = output_hard
    detached["token_bytes"] = min(input_token, profile.token_bytes, output_soft)
    return detached
