"""Persistent, deadline-bound transport for one generated local RTL driver."""
from __future__ import annotations

import copy
import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
import re
from pathlib import Path
import subprocess
import time
import uuid
from weakref import WeakKeyDictionary
from types import MappingProxyType
from typing import Callable, Iterator

from myfuzz.scenario.protocol_io import (
    BoundedLineReader, _deadline, command_deadline, end_local_process,
    read_startup_ready, write_local_command,
)
from .build import build_local_harness, local_build_identity
from .runtime_artifact import LocalRuntimeArtifact
from .wire import (MAX_REPLY_LINE_BYTES, DriverReceipt, parse_driver_ack,
                   parse_driver_ready, parse_driver_receipt)
from .axi4_fields import AXI_STEP_MAXIMA
from .cva6_axi4_fields import CVA6_AXI_STEP_MAXIMA


_command_timing_observer: ContextVar[Callable[[str, float], None] | None] = (
    ContextVar('local_command_timing_observer', default=None))


@contextmanager
def observe_local_command_timings(observer: Callable[[str, float], None]
                                  ) -> Iterator[None]:
    """Observe driver command round trips in this execution context only."""
    if not callable(observer):
        raise ValueError('command timing observer must be callable')
    token = _command_timing_observer.set(observer)
    try:
        yield
    finally:
        _command_timing_observer.reset(token)


_OPERATIONS = {
    'axi4_cpu': {'STEP_AXI4': AXI_STEP_MAXIMA},
    'cva6_packed_axi4_cpu': {'STEP_CVA6_AXI4': CVA6_AXI_STEP_MAXIMA},
    'native_memory_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    'rvx_memory_cpu': {'STEP_RVX_MEMORY': (1, 1, 0xffffffff)},
    'wishbone_cpu': {'STEP_WISHBONE': (1, 0xffffffff),
                     'STEP_WISHBONE_IRQ': (1, 0xffffffff, 0xffffffff)},
    'axi4_lite_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    # AHB-Lite CPU (CVW): the same four-field beat step (req_ready, rsp_valid,
    # rsp_rdata, rsp_error) as the other memory CPUs.
    'ahb_lite_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    'obi_cpu': {'STEP_CPU': (1, 1, 1, 0xffffffff, 1, 1, 1, 0xffffffff, 1)},
    'apb_gpio': {'STEP_GPIO': (0xffffffff,),
                 'ACCESS_GPIO': (0xffffffff, 1, 4092, 0xffffffff, 15)},
    'tlul_gpio': {'STEP_TLUL_GPIO': (0xffffffff, 1),
                  'ACCESS_TLUL_GPIO': (0xffffffff, 1, 1, 124, 0xffffffff, 15)},
    'tlul_spi_host': {'STEP_TLUL_SPI_HOST': (15,),
                      'ACCESS_TLUL_SPI_HOST': (15, 1, 4092, 0xffffffff, 15)},
    'tlul_timer': {'STEP_TLUL_TIMER': (),
                   'ACCESS_TLUL_TIMER': (1, 4092, 0xffffffff, 15)},
    'tlul_uart': {'STEP_TLUL_UART': (1,),
                  'ACCESS_TLUL_UART': (1, 1, 4092, 0xffffffff, 15)},
    'tlul_i2c': {'STEP_TLUL_I2C': (),
                 'ACCESS_TLUL_I2C': (1, 124, 0xffffffff, 15),
                 'SOURCE_TLUL_I2C': (255,)},
    'tlul_register_observe': {'STEP_TLUL_REG': (),
                              'ACCESS_TLUL_REG': (1, 8188, 0xffffffff, 15),
                              'SOURCE_TLUL_REG': (63, 0xffffffffffffffff),
                              'BIND_TLUL_REG': (63, 0xffffffffffffffff)},
    'apb3_register_observe': {'STEP_APB3_REG': (),
                              'ACCESS_APB3_REG': (1, 4092, 0xffffffff, 15),
                              'SOURCE_APB3_REG': (63, 0xffffffffffffffff),
                              'BIND_APB3_REG': (63, 0xffffffffffffffff)},
    'wishbone_register_observe': {'STEP_WB_REG': (),
                                  'ACCESS_WB_REG': (1, 4092, 0xffffffff, 15)},
    # AXI4-Lite register observation shares the beat-facing register shape, so
    # its operation maxima are the same as the other generic register kinds.
    'axi4lite_register_observe': {'STEP_AXIL_REG': (),
                                  'ACCESS_AXIL_REG': (1, 4092, 0xffffffff, 15),
                                  'SOURCE_AXIL_REG': (63, 0xffffffffffffffff),
                                  'BIND_AXIL_REG': (63, 0xffffffffffffffff)},
    'tlul_spi_device': {'STEP_TLUL_SPI_DEVICE': (1, 1, 1, 15),
                        'ACCESS_TLUL_SPI_DEVICE': (1, 1, 1, 15, 1, 8188, 0xffffffff, 15)},
    'wishbone_timer': {'STEP_WB_TIMER': (),
                       'ACCESS_WB_TIMER': (1, 0, 0xffffffff, 15)},
    'wishbone_uart': {'STEP_WB_UART': (1, 1),
                      'ACCESS_WB_UART': (1, 1, 1, 12, 0xffffffff, 15)},
    'apb_spi': {'STEP_SPI': (1,), 'ACCESS_SPI': (1, 4092, 0xffffffff, 15),
                'SOURCE_SPI': (3, 0xffffffff, 32)},
    'apb_timer': {'STEP_TIMER': (1,), 'ACCESS_TIMER': (1, 4092, 0xffffffff, 15)},
    'axi4_lite_uart': {'STEP_AXIL_UART': (1, 1),
                       'ACCESS_AXIL_UART': (1, 1, 1, 12, 0xffffffff, 15)},
    'apb_i2c': {'STEP_I2C': (1,), 'ACCESS_I2C': (1, 4092, 0xffffffff, 15),
                'SOURCE_I2C': (255,)},
}


#: Every driver command a session kind is allowed to send, derived from the
#: registry above rather than restated per consumer. A kind whose table omits
#: SOURCE_/BIND_ (Wishbone register observation) therefore genuinely does not
#: offer those operations, instead of relying on a hand-kept list agreeing.
def registered_operations(kind: str) -> frozenset[str]:
    return frozenset(_OPERATIONS.get(kind, {}))
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
        self._acknowledged = 0
        self.local_ticks = 0
        self._tick_base = 0
        self.reset_epoch = 0
        self._case_id: str | None = None
        self._native_reset_observation = None
        self._native_reset_build_issuance = None

    @property
    def process(self) -> subprocess.Popen[str] | None:
        return self._process

    def prepare_local(self) -> None:
        """Compile and admit the exact artifact before testcase wall accounting."""
        if self._process is not None:
            raise RuntimeError('cannot rebuild a running generated harness')
        if self._native_reset_observation is not None:
            _NATIVE_RESET_CHECK_PRODUCERS[0](self)
        self._binary = build_local_harness(self.artifact, base_dir=self.base_dir,
                                           cache_dir=self.cache_dir)
        if self._native_reset_observation is not None:
            _NATIVE_RESET_CHECK_PRODUCERS[0](self)
            identity = local_build_identity(self.artifact, base_dir=self.base_dir)
            verified = _NATIVE_RESET_BUILD_FUNCTIONS['_validate_cache'][0](self._binary.parent, identity)
            if verified != self._binary:
                raise ValueError('native reset actual build result differs')
            self._native_reset_build_issuance = (object(), self, self.artifact, self._binary,
                hashlib.sha256(self._binary.read_bytes()).hexdigest(), json.dumps(identity,sort_keys=True,separators=(',',':')))
            _NATIVE_RESET_BUILD_ISSUANCES[self] = self._native_reset_build_issuance
            self._native_reset_observation._prepared(self)

    def configure_native_reset_observation(self, *, max_lifecycles=256, max_commands=4096):
        from .native_reset_observation import NativeResetObservation
        observer = NativeResetObservation(self, max_lifecycles=max_lifecycles, max_commands=max_commands)
        self._native_reset_observation = observer
        try:
            _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
            return observer.configuration()
        except BaseException:
            self._native_reset_observation = None
            raise

    @property
    def native_reset_observation_enabled(self):
        return self._native_reset_observation is not None

    def native_reset_observation_configuration(self):
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        return None if self._native_reset_observation is None else self._native_reset_observation.configuration()

    def native_reset_observation_snapshot(self):
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        return None if self._native_reset_observation is None else self._native_reset_observation.snapshot()

    def native_reset_observation_lifecycles(self):
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        return () if self._native_reset_observation is None else self._native_reset_observation.lifecycles()

    def native_reset_observation_commands(self):
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        return () if self._native_reset_observation is None else self._native_reset_observation.commands()

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
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
            finally:
                if self._native_reset_observation is not None:
                    self._native_reset_observation._closed(self, proc, aborted=True)
                for stream in (proc.stdin, proc.stdout):
                    if stream is not None:
                        stream.close()

    def begin_case(self, testcase_id: str) -> None:
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
        if self._process is not None or type(testcase_id) is not str or not testcase_id:
            raise ValueError('generated testcase can begin exactly once')
        if self._native_reset_observation is not None:
            self._native_reset_observation._before_begin(self)
        digest, asserted, released, _ = self._expected_ready()
        if self._binary is None:
            self.prepare_local()
        if self._native_reset_observation is not None:
            try:
                _NATIVE_RESET_NATIVE_ELIGIBLE[0](self)
            except BaseException:
                self._native_reset_observation._consumer_failed(self, 'prelaunch_build_drift')
                raise
        self._execution = uuid.uuid4().hex
        self._sequence = 0
        self._acknowledged = 0
        self._tick_base = self.local_ticks
        self._case_id = testcase_id
        self._reader.reset()
        try:
            self._process = subprocess.Popen((str(self._binary),), cwd=self.base_dir,
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, text=True, bufsize=1)
            if self._native_reset_observation is not None:
                self._native_reset_observation._launched(self)
            if self._process.stdout is None:
                raise RuntimeError('generated driver stdout is unavailable')
            ready = read_startup_ready(self._reader, self._process.stdout)
            parsed_ready = parse_driver_ready(ready, digest=digest, assert_ticks=asserted,
                               release_ticks=released)
            if self._native_reset_observation is not None:
                self._native_reset_observation._ready(self, parsed_ready)
        except BaseException:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'startup_failed')
            self._abort()
            raise

    def command(self, operation: str, fields: tuple[int, ...]) -> DriverReceipt:
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
        observer = _command_timing_observer.get()
        if observer is None:
            return self._command_impl(operation, fields)
        started = time.monotonic()
        try:
            return self._command_impl(operation, fields)
        finally:
            # The measurement must never replace a driver receipt or failure.
            elapsed = time.monotonic() - started
            try:
                observer(operation, elapsed)
            except Exception:
                pass

    def _command_impl(self, operation: str, fields: tuple[int, ...]) -> DriverReceipt:
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
        proc = self._process
        try:
            if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
                raise RuntimeError('generated local process is not running')
        except BaseException:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'command_process_not_running')
            raise
        _, _, _, kind = self._expected_ready()
        maxima = _OPERATIONS[kind].get(operation)
        if (maxima is None or type(fields) is not tuple or len(fields) != len(maxima)
                or any(type(value) is not int or not 0 <= value <= maximum
                       for value, maximum in zip(fields, maxima))
                or (operation == 'ACCESS_GPIO' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_GPIO' and fields[3] % 4)
                or (operation == 'ACCESS_TLUL_SPI_HOST' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_TIMER' and fields[1] % 4)
                or (operation == 'ACCESS_TLUL_REG' and
                    (fields[1] % 4 or fields[1] >= self.artifact.plan.profile.address.window_size))
                or (operation == 'ACCESS_APB3_REG' and
                    (fields[1] % 4 or fields[1] >= self.artifact.plan.profile.address.window_size
                     or fields[3] != 15))
                or (operation == 'ACCESS_WB_UART' and fields[3] % 4)
                or (operation == 'ACCESS_TLUL_UART' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_I2C' and fields[1] % 4)
                or (operation == 'ACCESS_TLUL_SPI_DEVICE' and fields[5] % 4)
                or (operation == 'ACCESS_SPI' and fields[1] % 4)
                or (operation == 'ACCESS_TIMER' and fields[1] % 4)
                or (operation == 'ACCESS_I2C' and fields[1] % 4)
                or (operation == 'SOURCE_SPI' and fields[2] == 0)):
            raise ValueError('invalid generated driver command')
        observer = self._native_reset_observation
        attempt = observer._begin_actual_command(self, operation, fields) if observer is not None else None
        sequence = self._sequence + 1
        # ACK only receipts that the host already parsed completely. A later
        # retry of a retired sequence is rejected by the driver's floor.
        # Sixteen maximal replies fit comfortably below the 64 MiB cache.
        if self._sequence - self._acknowledged >= 16:
            try:
                with command_deadline(time.monotonic() + self.command_timeout_seconds):
                    write_local_command(proc.stdin,
                                        f'ACK {self._execution} {self._sequence:x}\n')
                    acknowledgement = self._reader.readline(proc.stdout)
                if not acknowledgement:
                    raise RuntimeError('lost_ack: generated driver stdout EOF')
                parse_driver_ack(acknowledgement.strip(), execution=self._execution,
                                 sequence=self._sequence,
                                 current_tick=self.local_ticks - self._tick_base)
            except BaseException:
                self._abort()
                raise
            self._acknowledged = self._sequence
        line = (f'CMD {self._execution} {sequence:x} {operation}'
                + ('' if not fields else ' ' + ' '.join(f'{value:x}' for value in fields))
                + '\n')
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
                                           kind=kind,
                                           clock_schedule=self._artifact_document.get('clock_schedule'))
        except BaseException:
            self._abort()
            raise
        if observer is not None:
            observer._complete_actual_command(self, attempt, receipt)
        self._sequence = sequence
        self.local_ticks = self._tick_base + receipt.tick_after
        return receipt

    def reset_local(self) -> dict[str, int]:
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
        if self._process is None or self._case_id is None:
            raise RuntimeError('generated local process is not running')
        if self._native_reset_observation is not None:
            self._native_reset_observation._before_reset(self)
        testcase_id = self._case_id
        self.end_case()
        self.reset_epoch += 1
        self.begin_case(testcase_id)
        return {'cancelled_responses': 0}

    def end_case(self) -> None:
        guard_error = None
        try:
            _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        except BaseException as error:
            # A poisoned evidence ledger must not prevent teardown of the real
            # child process. Preserve the failure and never issue a close fact
            # from an observer that failed its integrity guard.
            guard_error = error
        proc, self._process = self._process, None
        try:
            if proc is not None:
                end_local_process(proc)
                if self._native_reset_observation is not None and guard_error is None:
                    self._native_reset_observation._closed(self, proc)
        except BaseException:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'end_or_reap_failed')
            if guard_error is None:
                raise
        finally:
            self._case_id = None
        if guard_error is not None:
            raise guard_error

# Import-time producer references: a replaced method cannot become a new baseline.
from . import build as _native_reset_build_module
_NATIVE_RESET_SESSION_FUNCTIONS = {name: (getattr(GeneratedLocalSession, name),
    getattr(GeneratedLocalSession, name).__code__) for name in
    ('prepare_local', '_expected_ready', '_check_artifact_stable', 'begin_case',
     '_command_impl', 'command', '_abort', 'reset_local', 'end_case')}
_NATIVE_RESET_BUILD_FUNCTIONS = {name: (getattr(_native_reset_build_module,name),
    getattr(_native_reset_build_module,name).__code__) for name in
    ('build_local_harness','local_build_identity','_prepare','_prepared_if_current','_validate_cache','_host_sources')}
_NATIVE_RESET_BUILD_ISSUANCES = WeakKeyDictionary()
_NATIVE_RESET_BUILD_REGISTRY_PIN = _NATIVE_RESET_BUILD_ISSUANCES
_NATIVE_RESET_OPERATIONS = (_OPERATIONS, json.dumps(_OPERATIONS, sort_keys=True))
_NATIVE_RESET_POPEN = subprocess.Popen
_NATIVE_RESET_POPEN_METHODS = {name:(getattr(subprocess.Popen,name),getattr(subprocess.Popen,name).__code__)
    for name in ('__init__','poll','wait','kill')}
_NATIVE_RESET_WIRE_FUNCTIONS = {name: (globals()[name], globals()[name].__code__) for name in
    ('parse_driver_ready','parse_driver_receipt','parse_driver_ack','end_local_process','write_local_command','read_startup_ready')}
from . import native_reset_observation as _NATIVE_RESET_OBSERVER_MODULE
_NATIVE_RESET_OBSERVER_FUNCTIONS = MappingProxyType({name:(getattr(_NATIVE_RESET_OBSERVER_MODULE,name),
    getattr(_NATIVE_RESET_OBSERVER_MODULE,name).__code__) for name in
    ('_actual_producer_frame','_actual_fact_origin','_check_observer_methods')})
_NATIVE_RESET_OBSERVER_FUNCTIONS_PIN = _NATIVE_RESET_OBSERVER_FUNCTIONS
_NATIVE_RESET_OBSERVER_MODULE_PIN = _NATIVE_RESET_OBSERVER_MODULE

def _native_reset_check_producers(owner):
    from .gpio_session import GeneratedPulpGpioSession, _NATIVE_RESET_GPIO_FUNCTIONS, _NATIVE_RESET_GPIO_FUNCTIONS_PIN
    if (_native_reset_check_producers is not _NATIVE_RESET_CHECK_PRODUCERS[0]
            or _native_reset_check_producers.__code__ is not _NATIVE_RESET_CHECK_PRODUCERS[1]
            or _native_reset_native_eligible is not _NATIVE_RESET_NATIVE_ELIGIBLE[0]
            or _native_reset_native_eligible.__code__ is not _NATIVE_RESET_NATIVE_ELIGIBLE[1]
            or _NATIVE_RESET_OBSERVER_FUNCTIONS is not _NATIVE_RESET_OBSERVER_FUNCTIONS_PIN
            or _NATIVE_RESET_OBSERVER_MODULE is not _NATIVE_RESET_OBSERVER_MODULE_PIN
            or _NATIVE_RESET_OWNER_GUARD is not _NATIVE_RESET_OWNER_GUARD_PIN
            or _NATIVE_RESET_OWNER_GUARD_PIN[0] is not _native_reset_owner_guard
            or _NATIVE_RESET_OWNER_GUARD_PIN[1] is not _native_reset_owner_guard.__code__
            or any(getattr(_NATIVE_RESET_OBSERVER_MODULE,name) is not function
                   or function.__code__ is not code
                   for name,(function,code) in _NATIVE_RESET_OBSERVER_FUNCTIONS.items())
            or any(globals()[name] is not table for name,table in _NATIVE_RESET_PIN_TABLES.items())):
        raise ValueError('native reset immutable producer pin drift')
    if _NATIVE_RESET_BUILD_ISSUANCES is not _NATIVE_RESET_BUILD_REGISTRY_PIN:
        raise ValueError('native reset build registry drift')
    if _NATIVE_RESET_GPIO_FUNCTIONS is not _NATIVE_RESET_GPIO_FUNCTIONS_PIN:
        raise ValueError('native reset GPIO pin table drift')
    if type(owner) is not GeneratedPulpGpioSession:
        raise ValueError('native reset requires actual GPIO producer')
    for name,(method,code) in _NATIVE_RESET_SESSION_FUNCTIONS.items():
        if (getattr(GeneratedLocalSession,name) is not method or method.__code__ is not code
                or name in vars(owner) or name != 'reset_local' and getattr(type(owner),name) is not method):
            raise ValueError('native reset producer method drift:'+name)
    for name,(method,code) in _NATIVE_RESET_GPIO_FUNCTIONS.items():
        if getattr(GeneratedPulpGpioSession,name) is not method or method.__code__ is not code or name in vars(owner):
            raise ValueError('native reset GPIO producer method drift:'+name)
    for name,(function,code) in _NATIVE_RESET_BUILD_FUNCTIONS.items():
        if getattr(_native_reset_build_module,name) is not function or function.__code__ is not code:
            raise ValueError('native reset build function drift:'+name)
    if build_local_harness is not _NATIVE_RESET_BUILD_FUNCTIONS['build_local_harness'][0] or local_build_identity is not _NATIVE_RESET_BUILD_FUNCTIONS['local_build_identity'][0]:
        raise ValueError('native reset build facade drift')
    if _OPERATIONS is not _NATIVE_RESET_OPERATIONS[0] or json.dumps(_OPERATIONS,sort_keys=True) != _NATIVE_RESET_OPERATIONS[1]:
        raise ValueError('native reset operation domain drift')
    if owner._native_reset_observation is not None:
        _NATIVE_RESET_OBSERVER_FUNCTIONS['_check_observer_methods'][0](owner._native_reset_observation)
    if subprocess.Popen is not _NATIVE_RESET_POPEN:
        raise ValueError('native reset process producer drift')
    for name,(method,code) in _NATIVE_RESET_POPEN_METHODS.items():
        if getattr(subprocess.Popen,name) is not method or method.__code__ is not code:
            raise ValueError('native reset process method drift:'+name)
    for name,(function,code) in _NATIVE_RESET_WIRE_FUNCTIONS.items():
        if globals()[name] is not function or function.__code__ is not code:
            raise ValueError('native reset wire producer drift:'+name)

def _native_reset_native_eligible(owner):
    _NATIVE_RESET_CHECK_PRODUCERS[0](owner)
    issuance=owner._native_reset_build_issuance
    if issuance is None and _NATIVE_RESET_BUILD_ISSUANCES.get(owner) is None:
        return False,None
    if issuance is not _NATIVE_RESET_BUILD_ISSUANCES.get(owner):
        raise ValueError('native reset forged build issuance')
    token,session,artifact,binary,digest,identity_json=issuance
    identity=json.loads(identity_json)
    if (session is not owner or artifact is not owner.artifact or binary!=owner._binary
            or hashlib.sha256(binary.read_bytes()).hexdigest()!=digest
            or local_build_identity(owner.artifact,base_dir=owner.base_dir)!=identity
            or _NATIVE_RESET_BUILD_FUNCTIONS['_validate_cache'][0](binary.parent,identity)!=binary):
        raise ValueError('native reset actual build issuance drift')
    return True,hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()

_NATIVE_RESET_CHECK_PRODUCERS=(_native_reset_check_producers,_native_reset_check_producers.__code__)
_NATIVE_RESET_NATIVE_ELIGIBLE=(_native_reset_native_eligible,_native_reset_native_eligible.__code__)
_NATIVE_RESET_SESSION_FUNCTIONS=MappingProxyType(_NATIVE_RESET_SESSION_FUNCTIONS)
_NATIVE_RESET_BUILD_FUNCTIONS=MappingProxyType(_NATIVE_RESET_BUILD_FUNCTIONS)
_NATIVE_RESET_WIRE_FUNCTIONS=MappingProxyType(_NATIVE_RESET_WIRE_FUNCTIONS)
_NATIVE_RESET_POPEN_METHODS=MappingProxyType(_NATIVE_RESET_POPEN_METHODS)
_NATIVE_RESET_PIN_TABLES=MappingProxyType({name:globals()[name] for name in
    ('_NATIVE_RESET_SESSION_FUNCTIONS','_NATIVE_RESET_BUILD_FUNCTIONS','_NATIVE_RESET_WIRE_FUNCTIONS',
     '_NATIVE_RESET_POPEN_METHODS','_NATIVE_RESET_OBSERVER_FUNCTIONS','_NATIVE_RESET_OBSERVER_MODULE')})

def _native_reset_owner_guard(owner, *, allow_incomplete=False):
    observer=owner._native_reset_observation
    if observer is None:
        return
    if (_NATIVE_RESET_OWNER_GUARD is not _NATIVE_RESET_OWNER_GUARD_PIN
            or _NATIVE_RESET_OWNER_GUARD_PIN[0] is not _native_reset_owner_guard
            or _NATIVE_RESET_OWNER_GUARD_PIN[1] is not _native_reset_owner_guard.__code__):
        if observer._status!='incomplete':
            observer._status='incomplete';observer._reason='owner_guard_dispatch_drift'
        raise ValueError('native reset owner guard dispatch drift')
    try:
        _NATIVE_RESET_CHECK_PRODUCERS[0](owner)
        observer.validate(allow_incomplete=allow_incomplete)
    except BaseException:
        if observer._status!='incomplete':
            observer._status='incomplete';observer._reason='producer_or_binding_drift'
        raise

_NATIVE_RESET_OWNER_GUARD=(_native_reset_owner_guard,_native_reset_owner_guard.__code__)
_NATIVE_RESET_OWNER_GUARD_PIN=_NATIVE_RESET_OWNER_GUARD
