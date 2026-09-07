"""Private Linux FIFO endpoint for the upstream RFuzz shared-memory channel."""
import os
import math
from pathlib import Path
import select
import stat
import struct
import tempfile


class FifoEndpoint:
    @staticmethod
    def _validate_timeout(timeout):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 60:
            raise ValueError("finite FIFO timeout in [0,60] required")

    def __init__(self, base=Path("/tmp/fpga")):
        base = Path(base)
        try:
            base.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = base.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("FIFO base must be an owned non-symlink directory")
        if info.st_mode & 0o022:
            raise ValueError("FIFO base must not be writable by other users")
        self.directory = Path(tempfile.mkdtemp(prefix="myfuzz_", dir=base))
        self.fds = {}
        self.paths = []
        self.pending = bytearray()
        try:
            for name in ("tx", "rx"):
                path = self.directory / (name + ".fifo")
                os.mkfifo(path, 0o600)
                self.paths.append(path)
                # Linux supports RDWR FIFOs. The owned keepalive avoids startup
                # open deadlocks; the caller must monitor its client PID for exit.
                self.fds[name] = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        except BaseException:
            self.close()
            raise

    def receive(self, *, timeout=.1):
        self._validate_timeout(timeout)
        if not self.fds:
            raise ValueError("closed FIFO endpoint")
        if len(self.pending) < 8:
            ready, _, _ = select.select([self.fds["rx"]], [], [], timeout)
            if not ready:
                return None
            self.pending.extend(os.read(self.fds["rx"], 8-len(self.pending)))
        if len(self.pending) < 8:
            return None
        token = struct.unpack("<II", self.pending)
        self.pending.clear()
        return token

    def reply(self, token, *, timeout=1):
        self._validate_timeout(timeout)
        if not self.fds:
            raise ValueError("closed FIFO endpoint")
        if not isinstance(token, tuple) or len(token) != 2 or any(type(v) is not int or not 0 <= v <= 0x7fffffff for v in token):
            raise ValueError("invalid shared-memory token")
        _, ready, _ = select.select([], [self.fds["tx"]], [], timeout)
        if not ready:
            raise TimeoutError("RFuzz reply FIFO full")
        if os.write(self.fds["tx"], struct.pack("<II", *token)) != 8:
            raise RuntimeError("RFuzz reply was not atomic")

    def close(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()
        for path in self.paths:
            path.unlink(missing_ok=True)
        self.paths.clear()
        if self.directory.exists():
            self.directory.rmdir()  # never recursive: unexpected files survive

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
