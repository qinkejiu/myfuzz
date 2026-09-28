"""Bounded line reads for independent local RTL command channels."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import io
import os
import select
import subprocess
import time
from typing import Iterator, TextIO


class LocalCommandDeadlineExceeded(TimeoutError):
    """A command was issued but its complete local reply was not observed."""


_deadline: ContextVar[float | None] = ContextVar("scenario_command_deadline", default=None)
DEFAULT_READY_TIMEOUT_SECONDS = 10.0
DEFAULT_COMMAND_WRITE_TIMEOUT_SECONDS = 10.0
DEFAULT_END_TIMEOUT_SECONDS = 3.0


@contextmanager
def command_deadline(deadline: float | None) -> Iterator[None]:
    token = _deadline.set(deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


class BoundedLineReader:
    """Read complete ASCII replies without blocking on a partial line."""

    def __init__(self, *, max_line_bytes: int = 65_536) -> None:
        if type(max_line_bytes) is not int or max_line_bytes < 1:
            raise ValueError("max_line_bytes must be positive")
        self.max_line_bytes = max_line_bytes
        self._buffer = bytearray()

    def reset(self) -> None:
        self._buffer.clear()

    def readline(self, stream: TextIO) -> str:
        deadline = _deadline.get()
        if deadline is None:
            return stream.readline()
        try:
            descriptor = stream.fileno()
        except (AttributeError, OSError) as exc:
            raise RuntimeError("timed local reply requires a file descriptor") from exc
        while True:
            newline = self._buffer.find(b"\n")
            first_line_bytes = newline + 1 if newline >= 0 else len(self._buffer)
            if first_line_bytes > self.max_line_bytes:
                raise RuntimeError("local reply line exceeds declared bound")
            if newline >= 0:
                line = bytes(self._buffer[:newline + 1])
                del self._buffer[:newline + 1]
                return line.decode("ascii")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LocalCommandDeadlineExceeded("max_wall_time_ms: local reply deadline")
            ready, _, _ = select.select((descriptor,), (), (), remaining)
            if not ready:
                raise LocalCommandDeadlineExceeded("max_wall_time_ms: local reply deadline")
            chunk = os.read(descriptor, 4096)
            if not chunk:
                line = bytes(self._buffer)
                self._buffer.clear()
                return line.decode("ascii")
            self._buffer.extend(chunk)


def read_local_reply(owner: object, stream: TextIO) -> str:
    """Use the session reader, including lightweight protocol test fixtures."""
    reader = getattr(owner, "_line_reader", None)
    if reader is None:
        reader = BoundedLineReader()
        setattr(owner, "_line_reader", reader)
    return reader.readline(stream)


def read_startup_ready(reader: BoundedLineReader, stream: TextIO) -> str:
    """Bound READY by its startup limit and any enclosing testcase deadline."""
    deadline = time.monotonic() + DEFAULT_READY_TIMEOUT_SECONDS
    enclosing = _deadline.get()
    if enclosing is not None:
        deadline = min(deadline, enclosing)
    with command_deadline(deadline):
        return reader.readline(stream).strip()


def _write_before(stream: TextIO, line: str, deadline: float) -> None:
    """Write a whole command without blocking on a child that stopped reading."""
    if type(stream) is io.StringIO:
        # Protocol fixtures use an in-memory stream with no pipe descriptor.
        # Real subprocess stdin always takes the deadline-bound fd path below.
        if time.monotonic() >= deadline:
            raise LocalCommandDeadlineExceeded(
                "max_wall_time_ms: local command write deadline")
        stream.write(line)
        return
    descriptor = stream.fileno()
    blocking = os.get_blocking(descriptor)
    payload = line.encode("ascii")
    offset = 0
    try:
        os.set_blocking(descriptor, False)
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LocalCommandDeadlineExceeded("max_wall_time_ms: local command write deadline")
            _, writable, _ = select.select((), (descriptor,), (), remaining)
            if not writable:
                raise LocalCommandDeadlineExceeded("max_wall_time_ms: local command write deadline")
            try:
                written = os.write(descriptor, payload[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise RuntimeError("local command pipe made no progress")
            offset += written
    finally:
        os.set_blocking(descriptor, blocking)


def write_local_command(stream: TextIO, line: str) -> None:
    """Use the testcase deadline or an independent bound for a CMD write."""
    deadline = time.monotonic() + DEFAULT_COMMAND_WRITE_TIMEOUT_SECONDS
    enclosing = _deadline.get()
    if enclosing is not None:
        deadline = min(deadline, enclosing)
    _write_before(stream, line, deadline)


def end_local_process(process: subprocess.Popen[str]) -> None:
    """Send END when possible, then kill and reap a stalled local harness."""
    deadline = time.monotonic() + DEFAULT_END_TIMEOUT_SECONDS
    enclosing = _deadline.get()
    if enclosing is not None:
        deadline = min(deadline, enclosing)
    try:
        if process.poll() is None and process.stdin is not None:
            try:
                _write_before(process.stdin, "END\n", deadline)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, 0)
                process.wait(timeout=remaining)
            except (BrokenPipeError, OSError, LocalCommandDeadlineExceeded,
                    subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=1)
    finally:
        for handle in (process.stdin, process.stdout):
            if handle is not None:
                try:
                    handle.close()
                except BrokenPipeError:
                    pass
