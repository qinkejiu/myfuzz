#!/usr/bin/env python3
"""Linux subreaper used by ReferenceAdapter to contain evaluator descendants."""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import signal
import sys
import time


_PR_SET_CHILD_SUBREAPER = 36
_TERM_SECONDS = 0.25
_KILL_SECONDS = 0.75
_CLEANUP_FAILURE = 125
_INTERRUPTED = 124
_termination_requested = False


def _request_termination(_signal_number: int, _frame: object) -> None:
    global _termination_requested
    _termination_requested = True


def _enable_subreaper() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc").is_dir():
        raise RuntimeError("reference evaluator supervision requires Linux procfs")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _process_table() -> dict[int, tuple[int, str]]:
    table: dict[int, tuple[int, str]] = {}
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return table
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()
            table[int(entry.name)] = (int(fields[1]), fields[0])
        except (IndexError, OSError, ValueError):
            continue
    return table


def _live_descendants(root_pid: int) -> set[int]:
    table = _process_table()
    frontier = [root_pid]
    descendants: set[int] = set()
    while frontier:
        parent = frontier.pop()
        for pid, (parent_pid, state) in table.items():
            if parent_pid != parent or pid in descendants:
                continue
            frontier.append(pid)
            if state != "Z":
                descendants.add(pid)
    return descendants


def _reap_children() -> None:
    while True:
        try:
            child, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if child == 0:
            return


def _signal_descendants(root_pid: int, signal_number: int) -> None:
    for pid in _live_descendants(root_pid):
        try:
            os.kill(pid, signal_number)
        except ProcessLookupError:
            continue
        except PermissionError as error:
            raise RuntimeError(f"cannot signal evaluator descendant {pid}") from error


def _wait_for_descendants(root_pid: int, timeout: float, signal_number: int) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        _signal_descendants(root_pid, signal_number)
        _reap_children()
        if not _live_descendants(root_pid):
            _reap_children()
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _cleanup_descendants() -> bool:
    root_pid = os.getpid()
    if _wait_for_descendants(root_pid, _TERM_SECONDS, signal.SIGTERM):
        return True
    return _wait_for_descendants(root_pid, _KILL_SECONDS, signal.SIGKILL)


def _exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return _CLEANUP_FAILURE


def _report_cleanup(descriptor: int, succeeded: bool) -> None:
    try:
        os.write(descriptor, b"1" if succeeded else b"0")
    except OSError:
        pass
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _arguments(argv: list[str]) -> tuple[int, list[str]] | None:
    try:
        option = argv.index("--status-fd")
        separator = argv.index("--", option + 2)
        descriptor = int(argv[option + 1])
    except (IndexError, ValueError):
        return None
    command = argv[separator + 1 :]
    if descriptor < 0 or not command:
        return None
    return descriptor, command


def main(argv: list[str]) -> int:
    parsed = _arguments(argv)
    if parsed is None:
        return _CLEANUP_FAILURE
    status_descriptor, command = parsed

    try:
        _enable_subreaper()
    except (OSError, RuntimeError) as error:
        print(f"reference supervisor unavailable: {error}", file=sys.stderr)
        _report_cleanup(status_descriptor, False)
        return _CLEANUP_FAILURE

    signal.signal(signal.SIGTERM, _request_termination)
    signal.signal(signal.SIGINT, _request_termination)
    evaluator_pid = os.fork()
    if evaluator_pid == 0:
        os.close(status_descriptor)
        try:
            os.execve(command[0], command, dict(os.environ))
        except OSError as error:
            print(f"reference evaluator exec failed: {error}", file=sys.stderr)
            os._exit(126 if error.errno != errno.ENOENT else 127)

    status: int | None = None
    while status is None and not _termination_requested:
        try:
            waited, child_status = os.waitpid(evaluator_pid, os.WNOHANG)
        except ChildProcessError:
            break
        if waited == evaluator_pid:
            status = child_status
            break
        time.sleep(0.01)

    cleanup_succeeded = _cleanup_descendants()
    _report_cleanup(status_descriptor, cleanup_succeeded)
    if not cleanup_succeeded:
        print("reference supervisor could not terminate all descendants", file=sys.stderr)
        return _CLEANUP_FAILURE
    if _termination_requested:
        return _INTERRUPTED
    return _exit_code(status) if status is not None else _CLEANUP_FAILURE


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
