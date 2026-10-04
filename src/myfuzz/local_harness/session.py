"""Persistent, deadline-bound transport for one generated local RTL driver."""
from __future__ import annotations

import copy
import re
from pathlib import Path
import subprocess
import time
import uuid

from myfuzz.scenario.protocol_io import (
    BoundedLineReader, _deadline, command_deadline, end_local_process,
    read_startup_ready, write_local_command,
)
from .build import build_local_harness, local_build_identity
from .runtime_artifact import LocalRuntimeArtifact
from .wire import MAX_REPLY_LINE_BYTES, DriverReceipt, parse_driver_ready, parse_driver_receipt
from .axi4_fields import AXI_STEP_MAXIMA


_OPERATIONS = {
    'axi4_cpu': {'STEP_AXI4': AXI_STEP_MAXIMA},
    'native_memory_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    'wishbone_cpu': {'STEP_WISHBONE': (1, 0xffffffff)},
    'axi4_lite_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    'obi_cpu': {'STEP_CPU': (1, 1, 1, 0xffffffff, 1, 1, 1, 0xffffffff, 1)},
    'apb_gpio': {'STEP_GPIO': (0xffffffff,),
                 'ACCESS_GPIO': (0xffffffff, 1, 4092, 0xffffffff, 15)},
    'tlul_gpio': {'STEP_TLUL_GPIO': (0xffffffff, 1),
                  'ACCESS_TLUL_GPIO': (0xffffffff, 1, 1, 124, 0xffffffff, 15)},
    'apb_spi': {'STEP_SPI': (1,), 'ACCESS_SPI': (1, 4092, 0xffffffff, 15),
                'SOURCE_SPI': (3, 0xffffffff, 32)},
    'apb_timer': {'STEP_TIMER': (1,), 'ACCESS_TIMER': (1, 4092, 0xffffffff, 15)},
}
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


class GeneratedLocalSession:
    """Owns one RTL process for an entire testcase; every accepted command is ordered."""

    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path, command_timeout_seconds: float = 10.0):
        self.artifact = artifact
        self._artifact_document = copy.deepcopy(artifact.runtime_document)
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        if (type(command_timeout_seconds) not in (int, float)
                or not 0 < command_timeout_seconds <= 3600):
            raise ValueError('invalid generated command deadline')
        self.command_timeout_seconds = float(command_timeout_seconds)
        self._binary: Path | None = None
        self._process: subprocess.Popen[str] | None = None
        self._reader = BoundedLineReader(max_line_bytes=MAX_REPLY_LINE_BYTES)
        self._execution = ''
        self._sequence = 0
        self.local_ticks = 0
        self._tick_base = 0
        self.reset_epoch = 0
        self._case_id: str | None = None

    @property
    def process(self) -> subprocess.Popen[str] | None:
        return self._process

    def prepare_local(self) -> None:
        """Compile and admit the exact artifact before testcase wall accounting."""
        if self._process is not None:
            raise RuntimeError('cannot rebuild a running generated harness')
        self._binary = build_local_harness(self.artifact, base_dir=self.base_dir,
                                           cache_dir=self.cache_dir)

    def identity_document(self) -> dict[str, object]:
        self._check_artifact_stable()
        document = self._artifact_document
        return {'schema_version': 'generated_local_session_identity.v1',
                'runtime_artifact': copy.deepcopy(document),
                'build_identity': local_build_identity(self.artifact, base_dir=self.base_dir),
                'command_timeout_seconds': self.command_timeout_seconds}

    def _check_artifact_stable(self) -> None:
        if self.artifact.runtime_document != self._artifact_document:
            raise ValueError('generated driver artifact changed after session creation')

    def _expected_ready(self) -> tuple[str, int, int, str]:
        self._check_artifact_stable()
        document = self._artifact_document
        if (document.get('schema_version') != 'local_runtime_artifact.v1'
                or document.get('driver_schema_version') != 'local_driver_generation.v1'
                or document.get('status') != 'driver_generated'
                or document.get('driver_status') != 'generated'):
            raise ValueError('generated driver artifact is not admitted')
        digest = document.get('artifact_digest')
        kind = document.get('kind')
        reset = document.get('driver_reset')
        if (not isinstance(reset, dict)
                or reset.get('schema_version') != 'generated_local_reset.v1'):
            raise ValueError('invalid generated driver reset contract')
        asserted = reset.get('reset_assert_ticks')
        released = reset.get('reset_release_ticks')
        if (type(digest) is not str or _DIGEST.fullmatch(digest) is None
                or kind not in _OPERATIONS
                or type(asserted) is not int or asserted < 1
                or type(released) is not int or released < 1):
            raise ValueError('invalid generated driver reset or identity contract')
        return digest, asserted, released, kind

    def _abort(self) -> None:
        proc, self._process = self._process, None
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=1)
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    stream.close()

    def begin_case(self, testcase_id: str) -> None:
        if self._process is not None or type(testcase_id) is not str or not testcase_id:
            raise ValueError('generated testcase can begin exactly once')
        digest, asserted, released, _ = self._expected_ready()
        if self._binary is None:
            self.prepare_local()
        self._execution = uuid.uuid4().hex
        self._sequence = 0
        self._tick_base = self.local_ticks
        self._case_id = testcase_id
        self._reader.reset()
        self._process = subprocess.Popen((str(self._binary),), cwd=self.base_dir,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            if self._process.stdout is None:
                raise RuntimeError('generated driver stdout is unavailable')
            ready = read_startup_ready(self._reader, self._process.stdout)
            parse_driver_ready(ready, digest=digest, assert_ticks=asserted,
                               release_ticks=released)
        except BaseException:
            self._abort()
            raise

    def command(self, operation: str, fields: tuple[int, ...]) -> DriverReceipt:
        proc = self._process
        if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
            raise RuntimeError('generated local process is not running')
        _, _, _, kind = self._expected_ready()
        maxima = _OPERATIONS[kind].get(operation)
        if (maxima is None or type(fields) is not tuple or len(fields) != len(maxima)
                or any(type(value) is not int or not 0 <= value <= maximum
                       for value, maximum in zip(fields, maxima))
                or (operation == 'ACCESS_GPIO' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_GPIO' and fields[3] % 4)
                or (operation == 'ACCESS_SPI' and fields[1] % 4)
                or (operation == 'ACCESS_TIMER' and fields[1] % 4)
                or (operation == 'SOURCE_SPI' and fields[2] == 0)):
            raise ValueError('invalid generated driver command')
        sequence = self._sequence + 1
        line = (f'CMD {self._execution} {sequence:x} {operation} '
                + ' '.join(f'{value:x}' for value in fields) + '\n')
        deadline = time.monotonic() + self.command_timeout_seconds
        outer = _deadline.get()
        if outer is not None:
            deadline = min(deadline, outer)
        # Once writing begins, an absent or malformed reply may follow real RTL
        # effects. The process is terminated and this sequence is never retried.
        try:
            with command_deadline(deadline):
                write_local_command(proc.stdin, line)
                answer = self._reader.readline(proc.stdout)
            if not answer:
                raise RuntimeError('lost_reply: generated driver stdout EOF')
            receipt = parse_driver_receipt(answer.strip(), execution=self._execution,
                                           sequence=sequence,
                                           current_tick=self.local_ticks - self._tick_base,
                                           kind=kind)
        except BaseException:
            self._abort()
            raise
        self._sequence = sequence
        self.local_ticks = self._tick_base + receipt.tick_after
        return receipt

    def reset_local(self) -> dict[str, int]:
        if self._process is None or self._case_id is None:
            raise RuntimeError('generated local process is not running')
        testcase_id = self._case_id
        self.end_case()
        self.reset_epoch += 1
        self.begin_case(testcase_id)
        return {'cancelled_responses': 0}

    def end_case(self) -> None:
        proc, self._process = self._process, None
        if proc is not None:
            end_local_process(proc)
        self._case_id = None
