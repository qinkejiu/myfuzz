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
    BoundedLineReader, LocalCommandDeadlineExceeded, _deadline, command_deadline, end_local_process,
    read_startup_ready, write_local_command,
)
from .build import build_local_harness, local_build_identity, build_local_harness_with_receipt
from .runtime_artifact import LocalRuntimeArtifact
from .wire import (MAX_REPLY_LINE_BYTES, DriverReceipt, parse_driver_ack,
                   parse_driver_ready, parse_driver_receipt)
from .wishbone_dma_fields import DMA_STEP_MAXIMA, DMA_SELECTED_STEP_MAXIMA
from .axi4_fields import AXI_STEP_MAXIMA
from .cva6_axi4_fields import CVA6_AXI_STEP_MAXIMA
from .vexii_axi_fields import (IRQ_STEP_MAXIMA as REDUCED_AXI_IRQ_STEP_MAXIMA,
                              STEP_MAXIMA as REDUCED_AXI_STEP_MAXIMA)


_BUILT_SESSION_PINS = WeakKeyDictionary()
_BUILT_OPTED_SESSIONS = WeakKeyDictionary()
_BUILT_REGISTRY_PINS = (_BUILT_SESSION_PINS, _BUILT_OPTED_SESSIONS)


_command_timing_observer: ContextVar[Callable[[str, float], None] | None] = (
    ContextVar('local_command_timing_observer', default=None))
_local_command_trace: ContextVar[object | None] = ContextVar(
    'local_command_trace', default=None)


class LocalCommandTrace:
    """Bounded record of commands accepted by each actual local session."""

    def __init__(self, max_commands: int, max_bytes: int, capture_records: bool = True):
        if type(max_commands) is not int or not 1 <= max_commands <= 4096:
            raise ValueError('invalid command trace capacity')
        if type(max_bytes) is not int or not 1 <= max_bytes <= 256 * 1024 * 1024:
            raise ValueError('invalid command trace byte capacity')
        if type(capture_records) is not bool:
            raise ValueError("invalid capture_records flag")
        self._capture_records = capture_records
        self._processes = {}
        self._max_commands = max_commands
        self._max_bytes = max_bytes
        self._sessions = {}
        self._sizes = {}
        self._incomplete = set()
        self._identities = {}

    def _key(self, session):
        return session, session._execution

    def _observe(self, session):
        key = self._key(session)
        if key in self._identities:
            return
        component = getattr(getattr(getattr(session.artifact, 'plan', None),
                                    'request', None), 'instance_id', None)
        binary = session._binary
        binary_sha256 = manifest_sha256 = build_digest = None
        if isinstance(binary, Path):
            try:
                with binary.open('rb') as stream:
                    binary_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
                if binary.name == 'harness' and re.fullmatch(r'[0-9a-f]{64}', binary.parent.name):
                    build_digest = binary.parent.name
                    manifest = binary.parent / 'manifest.json'
                    if manifest.is_file():
                        with manifest.open('rb') as stream:
                            manifest_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
            except OSError:
                pass
        proc = session.process
        self._processes[key] = proc
        self._identities[key] = {'component': component,
            'execution_nonce': session._execution,
            'pid': proc.pid if proc is not None else None,
            'artifact_digest': session._artifact_document.get('artifact_digest'),
            'build_digest': build_digest, 'binary_sha256': binary_sha256,
            'binary_path': str(binary) if binary is not None else None,
            'manifest_sha256': manifest_sha256}
        self._sessions.setdefault(key, [])
        if not self._capture_records or session._sequence != 0:
            self._incomplete.add(key)

    def _mark_incomplete(self, session):
        self._incomplete.add(self._key(session))

    def _record(self, session, operation, fields, receipt, reply):
        if not self._capture_records:
            return
        key = self._key(session)
        rows = self._sessions.setdefault(key, [])
        if len(rows) >= self._max_commands or not isinstance(reply, str):
            self._incomplete.add(key)
            return
        command = (f'CMD {receipt.execution} {receipt.sequence:x} {operation}'
                   + ('' if not fields else ' ' + ' '.join(f'{value:x}' for value in fields)))
        size = self._sizes.get(key, 0) + len(command) + len(reply)
        if size > self._max_bytes:
            self._incomplete.add(key)
            return
        if receipt.execution != key[1] or receipt.sequence != len(rows) + 1:
            self._incomplete.add(key)
        self._sizes[key] = size
        rows.append({'command': command, 'reply': reply.strip(),
                     'sequence': receipt.sequence, 'tick_before': receipt.tick_before,
                     'tick_after': receipt.tick_after, 'reset_epoch': session.reset_epoch})

    def for_session(self, session) -> tuple[dict, ...]:
        keys = [key for key in self._sessions if key[0] is session]
        if len(keys) > 1:
            raise ValueError('multiple traced executions for session')
        return tuple(copy.deepcopy(self._sessions[keys[0]] if keys else ()))

    def complete_for(self, session) -> bool:
        keys = [key for key in self._sessions if key[0] is session]
        return len(keys) == 1 and bool(self._sessions[keys[0]]) and keys[0] not in self._incomplete

    def export_executions(self) -> tuple[dict, ...]:
        """Snapshot observed identities and actual process exits; no audit authority."""
        rows = []
        for key, identity in self._identities.items():
            process = self._processes.get(key)
            code = process.poll() if process is not None else None
            rows.append(copy.deepcopy(identity) | {
                'reaped': type(code) is int,
                'exit_code': code if type(code) is int else None})
        return tuple(rows)

    def export_sessions(self) -> tuple[dict, ...]:
        """Return distinct execution snapshots, without asserting audit authority."""
        return tuple({'component': self._identities[key]['component'],
                      'identity': copy.deepcopy(self._identities[key]),
                      'complete': bool(rows) and key not in self._incomplete,
                      'records': copy.deepcopy(rows)}
                     for key, rows in self._sessions.items() if key in self._identities)


@contextmanager
def record_local_commands(max_commands: int = 4096,
                          max_bytes: int = 64 * 1024 * 1024, *,
                          capture_records: bool = True) -> Iterator[LocalCommandTrace]:
    """Capture successful commands and original replies without changing RTL inputs."""
    if _local_command_trace.get() is not None:
        raise ValueError('nested local command recording is unsupported')
    trace = LocalCommandTrace(max_commands, max_bytes, capture_records=capture_records)
    token = _local_command_trace.set(trace)
    try:
        yield trace
    finally:
        _local_command_trace.reset(token)


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
    'wishbone_dma': {'STEP_WB_DMA': DMA_STEP_MAXIMA},
    'axi4_cpu': {'STEP_AXI4': AXI_STEP_MAXIMA},
    'reduced_dual_axi_cpu': {'STEP_REDUCED_AXI': REDUCED_AXI_STEP_MAXIMA},
    # The derived IRQ variant adds the core's real external interrupt input as
    # the first step field; every remaining field is the same reduced AXI set.
    'reduced_dual_axi_irq_cpu': {'STEP_REDUCED_AXI_IRQ': REDUCED_AXI_IRQ_STEP_MAXIMA},
    'cva6_packed_axi4_cpu': {'STEP_CVA6_AXI4': CVA6_AXI_STEP_MAXIMA},
    'native_memory_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    'rvx_memory_cpu': {'STEP_RVX_MEMORY': (1, 1, 0xffffffff)},
    'wishbone_cpu': {'STEP_WISHBONE': (1, 0xffffffff),
                     'STEP_WISHBONE_IRQ': (1, 0xffffffff, 0xffffffff)},
    'axi4_lite_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1)},
    # AHB-Lite CPU (CVW): the same four-field beat step (req_ready, rsp_valid,
    # rsp_rdata, rsp_error) as the other memory CPUs.
    'ahb_lite_cpu': {'STEP_MEMORY': (1, 1, 0xffffffff, 1), 'READ_AHB_STARTUP': (63,)},
    'obi_cpu': {'STEP_CPU': (1, 1, 1, 0xffffffff, 1, 1, 1, 0xffffffff, 1)},
    # TileLink coherent client: the same four-field backend beat step as the
    # other memory CPUs, but the payload is one 8-byte word (rsp_rdata is 64
    # bits), because the client's beat really is 8 bytes wide.
    'tilelink_coherent_cpu': {'STEP_TL_COHERENT': (1, 1, 0xffffffffffffffff, 1)},
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
    'ahb_lite_register_observe': {'STEP_AHB_REG': (),
        'ACCESS_AHB_REG': (1, 4092, 0xffffffff, 15),
        'SOURCE_AHB_REG': (63, 0xffffffffffffffff),
        'BIND_AHB_REG': (63, 0xffffffffffffffff)},
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
#: A2-only retrieval command. It is never merged into the standard registry,
#: so old callers of `registered_operations(kind)` keep the exact same set.
_STORAGE_STARTUP_OPERATIONS = {'READ_APB_STORAGE_STARTUP': (63,)}
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
        self._prepare_attempted = False
        self._start_attempted = False
        self._built_launches = []
        self._built_preparation_failure = None
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
        # Exact unparsed last reply, retained for host consumers that must keep
        # the original wire context even after a parse/identity failure.
        self._last_wire_reply: str | None = None

    @property
    def process(self) -> subprocess.Popen[str] | None:
        return self._process

    def prepare_local(self) -> None:
        """Compile and admit the exact artifact before testcase wall accounting."""
        self._check_built_mode()
        if self._process is not None:
            raise RuntimeError('cannot rebuild a running generated harness')
        if self._native_reset_observation is not None:
            _NATIVE_RESET_CHECK_PRODUCERS[0](self)
        self._prepare_attempted = True
        if self in _BUILT_SESSION_PINS:
            pin = _BUILT_SESSION_PINS[self]
            if pin is None:
                self._check_artifact_stable()
                try:
                    result = build_local_harness_with_receipt(self.artifact,
                        base_dir=self.base_dir, cache_dir=self.cache_dir)
                except BaseException as error:
                    self._built_preparation_failure = copy.deepcopy(
                        getattr(error, 'preparation_observation', None))
                    raise
                self._binary = result.binary_path
                pin = (result, result.receipt_document(),
                    result.receipt_sha256, result.observation_document(), self.artifact)
                _BUILT_SESSION_PINS[self] = pin
                _BUILT_OPTED_SESSIONS[self] = pin
                self.validate_built_executable_receipt()
            else:
                self.validate_built_executable_receipt()
        else:
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

    def _check_built_mode(self) -> None:
        if (_BUILT_SESSION_PINS is not _BUILT_REGISTRY_PINS[0]
                or _BUILT_OPTED_SESSIONS is not _BUILT_REGISTRY_PINS[1]
                or (self in _BUILT_OPTED_SESSIONS) != (self in _BUILT_SESSION_PINS)):
            raise ValueError('built executable receipt pin registry drift')
        if (self in _BUILT_OPTED_SESSIONS
                and _BUILT_OPTED_SESSIONS[self] is not _BUILT_SESSION_PINS[self]):
            raise ValueError('fixed built executable receipt pin replaced')

    def configure_built_executable_receipt(self) -> None:
        self._check_built_mode()
        if self._prepare_attempted or self._start_attempted or self._process is not None or self in _BUILT_SESSION_PINS:
            raise ValueError('built executable receipt must be configured once before preparation')
        _BUILT_OPTED_SESSIONS[self] = None
        _BUILT_SESSION_PINS[self] = None

    def _built_pin(self):
        self._check_built_mode()
        pin = _BUILT_SESSION_PINS.get(self)
        if pin is None:
            raise ValueError('built executable receipt has not been prepared')
        return pin

    def built_executable_receipt_document(self) -> dict:
        return copy.deepcopy(self._built_pin()[1])

    def build_preparation_observation_document(self) -> dict:
        self._check_built_mode()
        if self._built_preparation_failure is not None:
            return copy.deepcopy(self._built_preparation_failure)
        return copy.deepcopy(self._built_pin()[3])

    def built_executable_launch_observations(self) -> tuple[dict, ...]:
        self._check_built_mode()
        return tuple(copy.deepcopy(self._built_launches))

    def _built_executable_launch_diagnostics(self) -> tuple[dict, ...]:
        """Retained facts only; this accessor never validates launch authority."""
        return tuple(copy.deepcopy(self._built_launches))

    def validate_built_executable_receipt(self) -> dict:
        result, receipt, digest, observation, artifact = self._built_pin()
        self._check_artifact_stable()
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
        if (self.artifact is not artifact or self._binary != result.binary_path
                or canonical(result.receipt_document()) != canonical(receipt)
                or result.receipt_sha256 != digest):
            raise ValueError('fixed built executable receipt or binary path changed')
        if (self._binary.is_symlink() or not self._binary.is_file()
                or hashlib.sha256(self._binary.read_bytes()).hexdigest() != receipt['binary_sha256']):
            raise ValueError('fixed built executable binary changed')
        if result.validate_current(self.artifact, base_dir=self.base_dir,
                                  cache_dir=self.cache_dir) != self._binary:
            raise ValueError('validated built executable path changed')
        return copy.deepcopy(receipt)

    def _built_closed(self, proc, *, aborted=False, error=None):
        if self not in _BUILT_REGISTRY_PINS[1] or not self._built_launches:
            return
        row = self._built_launches[-1]
        if row['pid'] != proc.pid:
            return
        row.update(returncode=proc.returncode, reaped=proc.returncode is not None,
                   aborted=aborted)
        if error is not None:
            row['cleanup_error'] = repr(error)
            if row['failure_stage'] is None:
                row['failure_stage'] = 'end_or_reap'

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
        self._check_built_mode()
        self._check_artifact_stable()
        document = self._artifact_document
        identity = {'schema_version': 'generated_local_session_identity.v1',
                'runtime_artifact': copy.deepcopy(document),
                'build_identity': local_build_identity(self.artifact, base_dir=self.base_dir),
                'command_timeout_seconds': self.command_timeout_seconds}
        if self in _BUILT_SESSION_PINS:
            identity['built_executable_receipt'] = self.validate_built_executable_receipt()
        return identity

    def _check_artifact_stable(self) -> None:
        if json.dumps(self.artifact.runtime_document, sort_keys=True, separators=(',', ':')) != json.dumps(self._artifact_document, sort_keys=True, separators=(',', ':')):
            raise ValueError('generated driver artifact changed after session creation')

    def _expected_ready(self) -> tuple[str, int, int, str]:
        self._check_artifact_stable()
        document = self._artifact_document
        kind = document.get('kind')
        ahb_startup = kind == 'ahb_lite_cpu'
        storage_markers = ('storage_startup_selection' in document
                           or 'storage_startup_capture' in document)
        # Only the exact generic-APB A2 document may take the storage branch.
        # Any marker on another runtime kind, or a partial/unknown capture, is
        # refused instead of silently degrading to the ordinary v1 schema.
        if kind != 'apb3_register_observe' and storage_markers:
            raise ValueError('storage startup contract on another runtime kind')
        storage_startup = (kind == 'apb3_register_observe' and (
            storage_markers
            or document.get('driver_schema_version') ==
            'local_driver_generation.apb_storage_startup.v2'))
        driver_schema = ('local_driver_generation.ahb_startup.v2' if ahb_startup
                         else 'local_driver_generation.apb_storage_startup.v2'
                         if storage_startup else 'local_driver_generation.v1')
        if (document.get('schema_version') != 'local_runtime_artifact.v1'
                or document.get('driver_schema_version') != driver_schema
                or document.get('status') != 'driver_generated'
                or document.get('driver_status') != 'generated'):
            raise ValueError('generated driver artifact is not admitted')
        if ahb_startup:
            from .ahb_startup import contract_from_document
            contract_from_document(document)
        elif 'ahb_startup_contract' in document:
            raise ValueError('AHB startup contract on another runtime kind')
        elif storage_startup:
            from .apb_storage_startup import contract_from_document
            try:
                contract_from_document(document)
            except (KeyError, TypeError) as error:
                raise ValueError('invalid storage startup contract') from error
        digest = document.get('artifact_digest')
        reset = document.get('driver_reset')
        if (not isinstance(reset, dict)
                or reset.get('schema_version') != 'generated_local_reset.v1'):
            raise ValueError('invalid generated driver reset contract')
        asserted = reset.get('reset_assert_ticks')
        released = reset.get('reset_release_ticks')
        if (type(digest) is not str or _DIGEST.fullmatch(digest) is None
                or kind not in _OPERATIONS
                or type(asserted) is not int or asserted < 1
                or type(released) is not int
                or released < (0 if ahb_startup or storage_startup else 1)):
            raise ValueError('invalid generated driver reset or identity contract')
        return digest, asserted, released, kind

    def _abort(self) -> None:
        revoke_error = None
        try:
            _revoke_storage_versions(self)
        except BaseException as error:
            revoke_error = error
        proc, self._process = self._process, None
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=1)
            except BaseException as error:
                self._built_closed(proc, aborted=True, error=error)
                raise
            finally:
                self._built_closed(proc, aborted=True)
                if self._native_reset_observation is not None:
                    self._native_reset_observation._closed(self, proc, aborted=True)
                for stream in (proc.stdin, proc.stdout):
                    if stream is not None:
                        stream.close()
        if revoke_error is not None:
            raise revoke_error

    def _abort_failed_operation(self, primary, stage):
        if self._built_launches and self._process is not None:
            row = self._built_launches[-1]
            if row['pid'] == self._process.pid:
                row['failure_stage'] = stage
                row['error'] = repr(primary)
        try:
            self._abort()
        except BaseException as cleanup:
            primary.add_note(stage + ' cleanup failure: ' + repr(cleanup))

    def begin_case(self, testcase_id: str) -> None:
        self._check_built_mode()
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
        if self in _BUILT_SESSION_PINS:
            self.validate_built_executable_receipt()
        self._execution = uuid.uuid4().hex
        self._sequence = 0
        self._acknowledged = 0
        self._tick_base = self.local_ticks
        self._case_id = testcase_id
        self._reader.reset()
        launch_row = None
        if self in _BUILT_SESSION_PINS:
            receipt = self._built_pin()[1]
            launch_row = dict(pid=None, execution_nonce=self._execution,
                argv=[str(self._binary)], built_receipt_sha256=self._built_pin()[2],
                artifact_digest=receipt['artifact_digest'], build_digest=receipt['build_digest'],
                binary_sha256=receipt['binary_sha256'], observed_executable_sha256=None,
                ready_artifact_digest=None, failure_stage=None, returncode=None,
                reaped=False, aborted=False)
        failure_stage = 'popen'
        self._start_attempted = True
        try:
            self._process = subprocess.Popen((str(self._binary),), cwd=self.base_dir,
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, text=True, bufsize=1)
            trace = _local_command_trace.get()
            if trace is not None:
                try:
                    trace._observe(self)
                except Exception:
                    trace._mark_incomplete(self)
            if launch_row is not None:
                launch_row['pid'] = self._process.pid
                self._built_launches.append(launch_row)
                failure_stage = 'live_executable'
                if self._process.poll() is not None:
                    raise ValueError('built executable exited before live validation')
                with Path(f'/proc/{self._process.pid}/exe').open('rb') as executable:
                    observed = hashlib.file_digest(executable, 'sha256').hexdigest()
                launch_row['observed_executable_sha256'] = observed
                if observed != receipt['binary_sha256'] or self._process.poll() is not None:
                    raise ValueError('live executable differs from built executable receipt')
            failure_stage = 'ready'
            if self._native_reset_observation is not None:
                self._native_reset_observation._launched(self)
            if self._process.stdout is None:
                raise RuntimeError('generated driver stdout is unavailable')
            ready = read_startup_ready(self._reader, self._process.stdout)
            parsed_ready = parse_driver_ready(ready, digest=digest, assert_ticks=asserted,
                               release_ticks=released)
            if launch_row is not None:
                launch_row['ready_artifact_digest'] = digest
            if self._native_reset_observation is not None:
                self._native_reset_observation._ready(self, parsed_ready)
        except BaseException as primary:
            if launch_row is not None:
                launch_row['failure_stage'] = failure_stage
                launch_row['error'] = repr(primary)
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'startup_failed')
            try:
                self._abort()
            except BaseException as cleanup:
                primary.add_note('startup cleanup failure: ' + repr(cleanup))
            raise

    def command(self, operation: str, fields: tuple[int, ...]) -> DriverReceipt:
        trace = _local_command_trace.get()
        if trace is not None:
            try:
                trace._observe(self)
            except Exception:
                trace._mark_incomplete(self)
        try:
            self._check_built_mode()
            _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
            observer = _command_timing_observer.get()
            if observer is None:
                receipt = self._command_impl(operation, fields)
                recorded_reply = self._last_wire_reply
            else:
                started = time.monotonic()
                try:
                    receipt = self._command_impl(operation, fields)
                    recorded_reply = self._last_wire_reply
                finally:
                    # The measurement must never replace a driver receipt or failure.
                    elapsed = time.monotonic() - started
                    try:
                        observer(operation, elapsed)
                    except Exception:
                        pass
        except BaseException:
            if trace is not None:
                trace._mark_incomplete(self)
            raise
        if trace is not None:
            try:
                trace._record(self, operation, fields, receipt, recorded_reply)
            except Exception:
                trace._mark_incomplete(self)
        return receipt

    def _command_impl(self, operation: str, fields: tuple[int, ...]) -> DriverReceipt:
        _NATIVE_RESET_OWNER_GUARD_PIN[0](self)
        self._last_wire_reply = None
        storage_authority = _storage_version_authority(self)
        if storage_authority is not None:
            storage_authority._actual_begin(self, operation, fields)
        proc = self._process
        try:
            if proc is None or proc.poll() is not None or proc.stdin is None or proc.stdout is None:
                raise RuntimeError('generated local process is not running')
        except BaseException:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'command_process_not_running')
            raise
        _, _, _, kind = self._expected_ready()
        native_taps = None
        if 'native_completion_observation' in self._artifact_document:
            if kind != 'native_memory_cpu':
                raise ValueError('native tap contract on another runtime kind')
            rows = self._artifact_document.get('protocol_tap_ports')
            if (type(rows) is not list or len(rows) != 6
                    or any(type(row) is not dict or type(row.get('name')) is not str
                           or type(row.get('width')) is not int for row in rows)):
                raise ValueError('invalid admitted native tap contract')
            native_taps = {row['name']: row['width'] for row in rows}
            if len(native_taps) != len(rows):
                raise ValueError('duplicate admitted native tap')
        maxima = _OPERATIONS[kind].get(operation)
        if kind == 'wishbone_dma' and operation in ('STEP_WB_DMA','STEP_WB_DMA_SEL',
                                                   'STEP_WB_DMA_WIDE','STEP_WB_DMA_SEL_WIDE'):
            from .wishbone_dma_fields import dma_profile_edge_contract
            expected = dma_profile_edge_contract(self.artifact.plan.profile.capabilities)
            maxima = (tuple(expected['input_maxima']) if expected['operation'] == operation
                and self._artifact_document.get('dma_edge_contract') == expected else None)
        if maxima is None and kind == 'apb3_register_observe':
            document = self._artifact_document
            # Merge the private retrieval allowance only after the exact A2
            # document was admitted by _expected_ready above.
            if (document.get('driver_schema_version') ==
                    'local_driver_generation.apb_storage_startup.v2'
                    and 'storage_startup_selection' in document
                    and 'storage_startup_capture' in document):
                maxima = _STORAGE_STARTUP_OPERATIONS.get(operation)
        if (maxima is None or type(fields) is not tuple or len(fields) != len(maxima)
                or any(type(value) is not int or not 0 <= value <= maximum
                       for value, maximum in zip(fields, maxima))
                or (operation == 'ACCESS_GPIO' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_GPIO' and fields[3] % 4)
                or (operation == 'ACCESS_TLUL_SPI_HOST' and fields[2] % 4)
                or (operation == 'ACCESS_TLUL_TIMER' and fields[1] % 4)
                or (operation == 'ACCESS_TLUL_REG' and
                    (fields[1] % 4 or fields[1] >= self.artifact.plan.profile.address.window_size))
                or (operation in ('ACCESS_APB3_REG', 'ACCESS_AHB_REG') and
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
            except BaseException as primary:
                self._abort_failed_operation(primary, 'ack')
                raise
            self._acknowledged = self._sequence
        line = (f'CMD {self._execution} {sequence:x} {operation}'
                + ('' if not fields else ' ' + ' '.join(f'{value:x}' for value in fields))
                + '\n')
        command_started = time.monotonic()
        local_deadline = command_started + self.command_timeout_seconds
        deadline = local_deadline
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
            self._last_wire_reply = answer
            receipt = parse_driver_receipt(answer.strip(), execution=self._execution,
                                           sequence=sequence,
                                           current_tick=self.local_ticks - self._tick_base,
                                           kind=kind,
                                           clock_schedule=self._artifact_document.get('clock_schedule'),
                                           native_taps=native_taps)
        except BaseException as primary:
            if isinstance(primary, LocalCommandDeadlineExceeded):
                now = time.monotonic()
                primary.timeout_diagnostic = dict(
                    operation=operation,
                    command_elapsed_seconds=now-command_started,
                    command_timeout_seconds=self.command_timeout_seconds,
                    outer_remaining_seconds=None if outer is None else outer-now,
                    limiting_deadline='outer_deadline' if outer is not None and outer <= local_deadline
                        else 'local_command')
            self._abort_failed_operation(primary, 'command')
            raise
        if observer is not None:
            observer._complete_actual_command(self, attempt, receipt)
        from myfuzz.scenario.gpio_register_version import _AUTHORITIES
        register_authority = _AUTHORITIES.get(self)
        if register_authority is not None:
            try:
                register_authority._actual_command(self, operation, fields, receipt)
            except BaseException as primary:
                self._abort_failed_operation(primary, 'consumer')
                raise
        if storage_authority is not None:
            try:
                storage_authority._actual_command(self, operation, fields, receipt)
            except BaseException as primary:
                self._abort_failed_operation(primary, 'consumer')
                raise
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
            _revoke_storage_versions(self)
            _NATIVE_RESET_OWNER_GUARD_PIN[0](self, allow_incomplete=True)
        except BaseException as error:
            # A poisoned evidence ledger must not prevent teardown of the real
            # child process. Preserve the failure and never issue a close fact
            # from an observer that failed its integrity guard.
            guard_error = error
        proc, self._process = self._process, None
        try:
            if proc is not None:
                try:
                    end_local_process(proc)
                except BaseException as error:
                    self._built_closed(proc, error=error)
                    raise
                self._built_closed(proc)
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
    ('build_local_harness','local_build_identity','_prepare','_prepared_if_current','_validate_cache','_validate_cache_current','_receipt_cache','_receipt_cache_current',
     'static_validation','strict_validation_active','_host_sources')}
_NATIVE_RESET_BUILD_ISSUANCES = WeakKeyDictionary()
_NATIVE_RESET_BUILD_REGISTRY_PIN = _NATIVE_RESET_BUILD_ISSUANCES
_NATIVE_RESET_OPERATIONS = (_OPERATIONS, json.dumps(_OPERATIONS, sort_keys=True),
    _STORAGE_STARTUP_OPERATIONS, json.dumps(_STORAGE_STARTUP_OPERATIONS, sort_keys=True))
_STORAGE_STARTUP_OPERATIONS_PIN = _STORAGE_STARTUP_OPERATIONS
_NATIVE_RESET_POPEN = subprocess.Popen
_NATIVE_RESET_POPEN_METHODS = {name:(getattr(subprocess.Popen,name),getattr(subprocess.Popen,name).__code__)
    for name in ('__init__','poll','wait','kill')}
_NATIVE_RESET_WIRE_FUNCTIONS = {name: (globals()[name], globals()[name].__code__) for name in
    ('parse_driver_ready','parse_driver_receipt','parse_driver_ack','end_local_process','write_local_command','read_startup_ready')}
from . import native_reset_observation as _NATIVE_RESET_OBSERVER_MODULE
_NATIVE_RESET_OBSERVER_FUNCTIONS = MappingProxyType({name:(getattr(_NATIVE_RESET_OBSERVER_MODULE,name),
    getattr(_NATIVE_RESET_OBSERVER_MODULE,name).__code__) for name in
    ('_actual_producer_frame','_actual_fact_origin','_check_observer_methods','static_validation')})
_NATIVE_RESET_OBSERVER_FUNCTIONS_PIN = _NATIVE_RESET_OBSERVER_FUNCTIONS
_NATIVE_RESET_OBSERVER_MODULE_PIN = _NATIVE_RESET_OBSERVER_MODULE

from . import native_reset_producer_contract as _NATIVE_RESET_PRODUCER_MODULE
_NATIVE_RESET_PRODUCER_PIN = (_NATIVE_RESET_PRODUCER_MODULE,
    _NATIVE_RESET_PRODUCER_MODULE.check_producer, _NATIVE_RESET_PRODUCER_MODULE.check_producer.__code__,
    _NATIVE_RESET_PRODUCER_MODULE._check_origin, _NATIVE_RESET_PRODUCER_MODULE._check_origin.__code__,
    _NATIVE_RESET_PRODUCER_MODULE._CHECK_ORIGIN, _NATIVE_RESET_PRODUCER_MODULE._DEPENDENCIES)

def _validate_producer_static():
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
            or any(globals()[name] is not table for name,table in _NATIVE_RESET_PIN_TABLES.items())
            or any(globals()[name] is not function or function.__code__ is not code
                   for name,(function,code) in _STORAGE_VERSION_LOOKUP_PINS.items())):
        raise ValueError('native reset immutable producer pin drift')
    if _NATIVE_RESET_BUILD_ISSUANCES is not _NATIVE_RESET_BUILD_REGISTRY_PIN:
        raise ValueError('native reset build registry drift')
    if _NATIVE_RESET_GPIO_FUNCTIONS is not _NATIVE_RESET_GPIO_FUNCTIONS_PIN:
        raise ValueError('native reset GPIO pin table drift')
    if (_NATIVE_RESET_PRODUCER_MODULE is not _NATIVE_RESET_PRODUCER_PIN[0]
            or _NATIVE_RESET_PRODUCER_MODULE.check_producer is not _NATIVE_RESET_PRODUCER_PIN[1]
            or _NATIVE_RESET_PRODUCER_MODULE.check_producer.__code__ is not _NATIVE_RESET_PRODUCER_PIN[2]
            or _NATIVE_RESET_PRODUCER_MODULE._check_origin is not _NATIVE_RESET_PRODUCER_PIN[3]
            or _NATIVE_RESET_PRODUCER_MODULE._check_origin.__code__ is not _NATIVE_RESET_PRODUCER_PIN[4]
            or _NATIVE_RESET_PRODUCER_MODULE._CHECK_ORIGIN is not _NATIVE_RESET_PRODUCER_PIN[5]
            or _NATIVE_RESET_PRODUCER_MODULE._DEPENDENCIES is not _NATIVE_RESET_PRODUCER_PIN[6]):
        raise ValueError('native reset producer registry drift')
    if _NATIVE_RESET_PRODUCER_MODULE.static_validation is not _NATIVE_RESET_BUILD_FUNCTIONS['static_validation'][0]:
        raise ValueError('native reset static validation producer drift')
    for name,(method,code) in _NATIVE_RESET_SESSION_FUNCTIONS.items():
        if (getattr(GeneratedLocalSession,name) is not method or method.__code__ is not code):
            raise ValueError('native reset producer method drift:'+name)
    for name,(method,code) in _NATIVE_RESET_GPIO_FUNCTIONS.items():
        if getattr(GeneratedPulpGpioSession,name) is not method or method.__code__ is not code:
            raise ValueError('native reset GPIO producer method drift:'+name)
    for name,(function,code) in _NATIVE_RESET_BUILD_FUNCTIONS.items():
        if getattr(_native_reset_build_module,name) is not function or function.__code__ is not code:
            raise ValueError('native reset build function drift:'+name)
    if build_local_harness is not _NATIVE_RESET_BUILD_FUNCTIONS['build_local_harness'][0] or local_build_identity is not _NATIVE_RESET_BUILD_FUNCTIONS['local_build_identity'][0]:
        raise ValueError('native reset build facade drift')
    if (_OPERATIONS is not _NATIVE_RESET_OPERATIONS[0]
            or json.dumps(_OPERATIONS,sort_keys=True) != _NATIVE_RESET_OPERATIONS[1]
            or _STORAGE_STARTUP_OPERATIONS is not _NATIVE_RESET_OPERATIONS[2]
            or json.dumps(_STORAGE_STARTUP_OPERATIONS,sort_keys=True) != _NATIVE_RESET_OPERATIONS[3]):
        raise ValueError('native reset operation domain drift')
    if subprocess.Popen is not _NATIVE_RESET_POPEN:
        raise ValueError('native reset process producer drift')
    for name,(method,code) in _NATIVE_RESET_POPEN_METHODS.items():
        if getattr(subprocess.Popen,name) is not method or method.__code__ is not code:
            raise ValueError('native reset process method drift:'+name)
    for name,(function,code) in _NATIVE_RESET_WIRE_FUNCTIONS.items():
        if globals()[name] is not function or function.__code__ is not code:
            raise ValueError('native reset wire producer drift:'+name)
    return True


def _native_reset_check_producers(owner):
    _NATIVE_RESET_BUILD_FUNCTIONS['static_validation'][0](('native-reset-producer-code',), _validate_producer_static)
    producer_kind = _NATIVE_RESET_PRODUCER_PIN[1](owner)
    if producer_kind == 'apb_storage':
        _storage_version_authority(owner)
    for name in _NATIVE_RESET_SESSION_FUNCTIONS:
        if name in vars(owner):
            raise ValueError('native reset producer method drift:'+name)
    if producer_kind == 'gpio':
        from .gpio_session import _NATIVE_RESET_GPIO_FUNCTIONS
        for name in _NATIVE_RESET_GPIO_FUNCTIONS:
            if name in vars(owner):
                raise ValueError('native reset GPIO producer method drift:'+name)
    locations = (str(Path(owner.base_dir).resolve()), str(Path(owner.cache_dir).resolve()))
    admitted_locations = _NATIVE_RESET_BUILD_FUNCTIONS['static_validation'][0](
        ('session_locations', owner),
        lambda: (str(Path(owner.base_dir).resolve()), str(Path(owner.cache_dir).resolve())))
    if locations != admitted_locations:
        raise ValueError('native reset session root or cache drift')
    from .execution_validation import static_validation_matches
    if not static_validation_matches(('session_artifact', owner),
                                     lambda: owner.artifact, owner.artifact):
        raise ValueError('native reset complete artifact drift')
    if owner._native_reset_observation is not None:
        _NATIVE_RESET_OBSERVER_FUNCTIONS['_check_observer_methods'][0](owner._native_reset_observation)

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
     '_NATIVE_RESET_POPEN_METHODS','_NATIVE_RESET_OBSERVER_FUNCTIONS','_NATIVE_RESET_OBSERVER_MODULE',
     '_NATIVE_RESET_PRODUCER_PIN')})

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

# Independent issuer origins: JSON and mutable module aliases cannot replace them.
from myfuzz.scenario import apb_storage_register_version as _STORAGE_VERSION_MODULE
_STORAGE_VERSION_PIN = (_STORAGE_VERSION_MODULE, _STORAGE_VERSION_MODULE._AUTHORITIES,
    _STORAGE_VERSION_MODULE._LIVE, _STORAGE_VERSION_MODULE._TOKENS,
    _STORAGE_VERSION_MODULE._TYPE, _STORAGE_VERSION_MODULE._METHODS,
    MappingProxyType({name:getattr(_STORAGE_VERSION_MODULE,name) for name in
        ('_WIDTHS','_REGISTRIES','_REDUCER','_ROUTED_VALIDATOR','_SCOPE_VALIDATOR','_GETFRAME')}))


def _storage_version_authority(owner):
    module,registry,live,tokens,cls,methods,facts = _STORAGE_VERSION_PIN
    if (module is not _STORAGE_VERSION_MODULE or module._AUTHORITIES is not registry
            or module._LIVE is not live or module._TOKENS is not tokens
            or module._TYPE is not cls or module._METHODS is not methods
            or any(getattr(module,name) is not value for name,value in facts.items())):
        raise ValueError('storage-version-dispatch-registry-drift')
    authority=registry.get(owner)
    if authority is not None and (type(authority) is not cls or any(
            name in vars(authority) or getattr(cls,name) is not method or method.__code__ is not code
            for name,(method,code) in methods.items())):
        raise ValueError('storage-version-dispatch-method-drift')
    return authority


def _revoke_storage_versions(owner):
    # Teardown must still reap a child even if another evidence consumer drifted.
    module,registry,live,tokens,cls,methods,facts = _STORAGE_VERSION_PIN
    authority=registry.get(owner)
    if authority is not None:
        if authority in tokens:tokens[authority].clear()
        if authority in live:live[authority]['bad']=True

_STORAGE_VERSION_LOOKUP_PINS=MappingProxyType({name:(globals()[name],globals()[name].__code__)
    for name in ('_storage_version_authority','_revoke_storage_versions')})
_NATIVE_RESET_PIN_TABLES=MappingProxyType({**_NATIVE_RESET_PIN_TABLES,
    '_STORAGE_VERSION_PIN':_STORAGE_VERSION_PIN,'_STORAGE_VERSION_LOOKUP_PINS':_STORAGE_VERSION_LOOKUP_PINS})
