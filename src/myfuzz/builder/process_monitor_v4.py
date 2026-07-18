"""Single-process polling for bounded v4 target execution."""

from __future__ import annotations

from pathlib import Path
import subprocess
import time
from typing import Callable, Sequence

from .input_model import InputValidationError


class TargetProcessTimeoutV4(InputValidationError):
    """A target exceeded its per-testcase execution or internal guard bound."""


def run_polled_process_v4(
    command: Sequence[str | Path],
    *,
    cwd: str | Path,
    timeout_seconds: float,
    poll_interval_seconds: float = 1.0,
    poll_callback: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one child process, polling it from the owning thread only."""
    for name, value in (
        ("timeout_seconds", timeout_seconds),
        ("poll_interval_seconds", poll_interval_seconds),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise InputValidationError(f"v4 process {name} must be positive")
    normalized = [str(item) for item in command]
    process = subprocess.Popen(
        normalized, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    next_poll = started
    try:
        while True:
            now = time.monotonic()
            if poll_callback is not None and now >= next_poll:
                poll_callback()
                next_poll = now + float(poll_interval_seconds)
            remaining = float(timeout_seconds) - (time.monotonic() - started)
            if remaining <= 0:
                process.kill()
                stdout, stderr = process.communicate()
                raise subprocess.TimeoutExpired(
                    normalized, timeout_seconds, output=stdout, stderr=stderr,
                )
            wait = remaining
            if poll_callback is not None:
                wait = min(wait, max(0.001, next_poll - time.monotonic()))
            try:
                stdout, stderr = process.communicate(timeout=wait)
            except subprocess.TimeoutExpired:
                continue
            return subprocess.CompletedProcess(
                normalized, process.returncode, stdout, stderr,
            )
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.communicate()
        raise
