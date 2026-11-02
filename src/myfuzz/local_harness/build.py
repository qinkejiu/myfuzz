"""Identity-keyed, bounded builds from authenticated runtime artifact bytes."""
from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, field
from contextlib import contextmanager
from contextvars import ContextVar
import errno
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

from .execution_validation import (file_digest_now, identity_memo, identity_of,
                                   static_validation, static_validation_matches,
                                   strict_validation_active)
from .renderer import _sha
from .runtime_artifact import LocalRuntimeArtifact
from .runtime_renderer import render_local_runtime
from .source_lock import verify_local_source_lock

BUILD_TIMEOUT_SECONDS = 300
CXX_STANDARD = 'c++17'
_REQUIRED_HEADERS = ('src/myfuzz/local_harness/rtl/local_driver_v1.h',
                     'src/myfuzz/scenario/rtl/local_command_replay.h')
_DRIVER_KEYS = {'driver_schema_version', 'driver_header_sources', 'driver_reset',
                'driver_limits', 'driver_field_map'}
_DRIVER_CHANGES = {'status', 'driver_status', 'cpp_sha256', 'artifact_digest'}
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_IMPLEMENTATION_ROOT = Path(__file__).resolve().parents[3]
_PREPARED_CACHE: dict[int, tuple] = {}
_PREPARED_CACHE_LIMIT = 16

#: Verilator arguments that keep generated-model assertions compiled in.
#: ``--assert`` is Verilator's default, but the assertion state of a model is evidence
#: and is therefore stated explicitly instead of inherited from a tool default.
ASSERTION_VERILATOR_FLAGS = ('--assert',)


def assertion_build_flags(*, rtl_assertions: bool = False) -> tuple[str, ...]:
    """Return the generic Verilator flags for an assertion-instrumented model.

    ``rtl_assertions`` also selects the upstream SystemVerilog assertion macros for
    cores whose ``prim_assert`` headers choose *dummy* macros whenever the tool
    predefines ``VERILATOR`` (Ibex, CVE2, CV32E40P).  That selection undefines the
    tool macro for the Verilator run; it never edits a pinned source byte.  Callers
    that only need Verilator's own SVA support use the default ``False``.
    """
    if type(rtl_assertions) is not bool:
        raise ValueError('rtl-assertions-bool-required')
    return (*ASSERTION_VERILATOR_FLAGS, '-UVERILATOR') if rtl_assertions else ASSERTION_VERILATOR_FLAGS


def _build_jobs() -> int:
    """Verilator/make parallelism for generated-harness builds.

    Throughput knob only: it changes the build schedule, not the pinned input
    bytes or the generated sources. Old caches miss once and are rebuilt.
    """
    raw = os.environ.get('MYFUZZ_BUILD_JOBS')
    if raw is not None:
        try:
            value = int(raw)
        except ValueError:
            raise LocalHarnessBuildError('invalid-myfuzz-build-jobs') from None
        if not 1 <= value <= 64:
            raise LocalHarnessBuildError('invalid-myfuzz-build-jobs')
        return value
    return max(1, min(8, os.cpu_count() or 1))


class LocalHarnessBuildError(RuntimeError):
    """Admission, build, timeout or cache integrity failed."""

    def __init__(self, *args, preparation_observation=None):
        super().__init__(*args)
        self._preparation_observation = copy.deepcopy(preparation_observation)

    @property
    def preparation_observation(self):
        return copy.deepcopy(self._preparation_observation)



def _selected_timing_mode(profile):
    """The Verilator timing mode the profile selects, or ``None``.

    A profile that publishes no ``capabilities`` table selects no timing
    mode: that is exactly the answer a profile whose ``capabilities`` names no
    ``verilator_timing_mode`` gives, so an artifact built from a real profile
    takes its present branch and nothing is invented on behalf of the absent
    table.
    """
    capabilities = getattr(profile, 'capabilities', None)
    getter = getattr(capabilities, 'get', None)
    return getter('verilator_timing_mode') if callable(getter) else None


def _verilator_timing_flags(profile):
    mode = _selected_timing_mode(profile)
    if mode is None:
        return ()
    if mode == 'no_timing':
        return ('--no-timing',)
    if mode == 'timing':
        return ('--timing', '--timescale', '1ns/1ps')
    raise LocalHarnessBuildError('unsupported-local-verilator-timing-mode')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _path(root, name):
    if not isinstance(name, str) or not name or '\\' in name or Path(name).is_absolute() or any(
            part in ('.', '..') for part in name.split('/')) or Path(name).as_posix() != name:
        raise LocalHarnessBuildError('invalid-build-input-path')
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise LocalHarnessBuildError('build-input-outside-or-missing:' + name)
    return path


def _environment():
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}


def _toolchain():
    result = {}
    for label, command in (('verilator', 'verilator'), ('cxx', 'c++'), ('make', 'make'), ('ar', 'ar')):
        executable = shutil.which(command)
        if executable is None:
            raise LocalHarnessBuildError('build-tool-missing:' + command)
        executable = str(Path(executable).resolve())
        version = subprocess.run([executable, '--version'], capture_output=True, text=True,
                                 check=True, timeout=10, env=_environment())
        result[label] = dict(path=executable, version=version.stdout.strip(),
                             executable_sha256=_digest(Path(executable).read_bytes()))
    verilator = Path(result['verilator']['path'])
    backend = verilator.parent / 'verilator_bin'
    if not backend.is_file():
        raise LocalHarnessBuildError('verilator-backend-missing')
    result['verilator']['backend_sha256'] = _digest(backend.read_bytes())
    details = subprocess.run([str(verilator), '-V'], capture_output=True, text=True,
                             check=True, timeout=10, env=_environment()).stdout
    roots = re.findall(r'^\s*VERILATOR_ROOT\s*=\s*(.+)$', details, re.M)
    if not roots:
        raise LocalHarnessBuildError('verilator-runtime-root-missing')
    runtime = Path(roots[-1].strip()).resolve()
    include = runtime / 'include'
    if not include.is_dir():
        raise LocalHarnessBuildError('verilator-runtime-headers-missing')
    result['verilator']['runtime_root'] = str(runtime)
    result['verilator']['runtime_files'] = [
        dict(path=path.relative_to(runtime).as_posix(), sha256=_digest(path.read_bytes()))
        for path in sorted(include.rglob('*')) if path.is_file()]
    return result


# --------------------------------------------------------------------------- #
# Content identity of the gates this module reuses
# --------------------------------------------------------------------------- #
#: Input rows a preparation/verification actually read, learned from its own
#: accepted result and re-observed by fresh digest afterwards.  Learning the
#: rows from the result is what keeps the identity complete: it covers exactly
#: the files that authentication captured (source closure, lock and evidence,
#: driver headers, adapter and protocol sources, host closure, toolchain bytes)
#: without a second hand-maintained list.
_BUILD_ROWS: dict[tuple, tuple[tuple[str, str], ...]] = {}
_LOCK_ROWS: dict[tuple, tuple[tuple[str, str], ...]] = {}
_ROWS_LIMIT = 32


def _remember_rows(table, key, rows) -> None:
    if key is None or not rows:
        return
    if len(table) >= _ROWS_LIMIT:
        table.pop(next(iter(table)))
    table[key] = tuple(rows)


def _observe_rows(rows):
    """Re-read every recorded row; ``None`` as soon as one byte differs."""
    observed = []
    for name, digest in rows:
        current = file_digest_now(name)
        if current is None or current != digest:
            return None
        observed.append((name, current))
    return observed


def _document_input_rows(document, root: Path) -> tuple[tuple[str, str], ...]:
    """Every ``(path, sha256)`` row a verification document publishes."""
    rows: list[tuple[str, str]] = []

    def visit(value):
        if isinstance(value, dict):
            path, digest = value.get('path'), value.get('sha256')
            if isinstance(path, str) and isinstance(digest, str) and _HEX.fullmatch(digest):
                rows.append((path, digest))
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)
    for path, digest in zip(document.get('wrapper_paths') or (),
                            document.get('wrapper_sha256') or ()):
        if isinstance(path, str) and isinstance(digest, str) and _HEX.fullmatch(digest):
            rows.append((path, digest))
    if document.get('schema_version') == 'zipdma_selected_profile_contract.v1':
        sources = document.get('sources')
        if isinstance(sources, dict):
            for name, digest in sources.items():
                if isinstance(name, str) and isinstance(digest, str) and _HEX.fullmatch(digest):
                    rows.append(((root / name).as_posix(), digest))
    return tuple(rows)


def _artifact_identity_key(artifact, root: Path):
    try:
        return (artifact_input_identity(artifact.plan, artifact), str(root))
    except Exception:
        return None


def _lock_identity_key(profile, root: Path, allow_source_only: bool):
    fingerprint = getattr(profile, 'profile_fingerprint', None)
    if not isinstance(fingerprint, str):
        return None
    return (fingerprint, str(root), bool(allow_source_only))


def _toolchain_rows() -> tuple[tuple[str, str], ...] | None:
    """Fresh digest of the tool bytes one build executes."""
    try:
        tools = _toolchain_paths()
    except LocalHarnessBuildError:
        return None
    rows = []
    for label, path in tools:
        digest = file_digest_now(path)
        if digest is None:
            return None
        rows.append((path, digest))
    include = _verilator_runtime_include()
    if include is not None:
        try:
            runtime = sorted(include.rglob('*'))
        except OSError:
            return None
        for path in runtime:
            if path.is_symlink() or not path.is_file():
                continue
            digest = file_digest_now(path)
            if digest is None:
                return None
            rows.append((str(path), digest))
    return tuple(rows)


def _verilator_runtime_include():
    """The Verilator runtime headers one build compiles against, if locatable.

    ``_toolchain`` asks ``verilator -V`` for ``VERILATOR_ROOT``; the standard
    install keeps it beside the executable, so re-observing the headers does not
    need a subprocess.  A layout that does not match contributes no headers
    here, and the preparation still authenticates them through ``_toolchain``.
    """
    try:
        tools = dict(_toolchain_paths())
    except LocalHarnessBuildError:
        return None
    candidate = Path(tools['verilator']).parent.parent / 'share/verilator/include'
    return candidate if candidate.is_dir() else None


_TOOLCHAIN_PATHS: list[tuple[str, str]] | None = None


def _toolchain_paths():
    """Resolved tool executables (no version subprocesses) for re-observation."""
    global _TOOLCHAIN_PATHS
    if _TOOLCHAIN_PATHS is not None:
        return list(_TOOLCHAIN_PATHS)
    rows = []
    for label, command in (('verilator', 'verilator'), ('cxx', 'c++'),
                           ('make', 'make'), ('ar', 'ar')):
        executable = shutil.which(command)
        if executable is None:
            raise LocalHarnessBuildError('build-tool-missing:' + command)
        executable = str(Path(executable).resolve())
        rows.append((label, executable))
        if label == 'verilator':
            backend = Path(executable).parent / 'verilator_bin'
            if not backend.is_file():
                raise LocalHarnessBuildError('verilator-backend-missing')
            rows.append(('verilator_bin', str(backend)))
    _TOOLCHAIN_PATHS = rows
    return list(rows)


def artifact_input_identity(plan, artifact) -> str:
    """Content identity of one generated artifact and the plan it came from."""
    doc = artifact.runtime_document
    return identity_of(
        'local-harness-artifact-inputs', _sha(doc),
        doc.get('artifact_digest'), _digest(artifact.cpp_text.encode()),
        _digest(artifact.runtime_sv.encode()),
        _digest(artifact.structural.wrapper_sv.encode()),
        _sha(artifact.structural.abi_document),
        _sha(plan.document()))


def _identity_or_none(compute):
    """Observe one identity, or ``None`` when the object cannot be observed.

    An unobservable identity is never a match: the caller then recomputes every
    time (and the exit boundary re-authenticates), which is the strict
    direction.
    """
    try:
        return compute()
    except Exception:
        return None


def verified_source_lock(profile, *, base_dir: Path, allow_source_only: bool = False,
                         profile_path=None):
    """The pinned-source gate, accepted once per observed input content.

    The gate records the exact rows it authenticated (profile file, declared
    source closure, lock document, verifier, elaboration evidence and every
    input its own contract publishes), and a later caller re-reads those rows.
    Same bytes: the accepted verification is reused.  Any changed byte: the gate
    runs again from scratch.
    """
    root = Path(base_dir).resolve()
    fingerprint = getattr(profile, 'profile_fingerprint', None)
    if not isinstance(fingerprint, str):
        fingerprint = ('profile-object', id(profile))
    key = _lock_identity_key(profile, root, allow_source_only)

    def observe():
        rows = _LOCK_ROWS.get(key) if key is not None else None
        if rows is None:
            return None
        return _identity_or_none(lambda: identity_of(
            'local-source-lock-rows', fingerprint, str(root), allow_source_only,
            id(verify_local_source_lock), _observe_rows(rows)))

    def validate():
        def compute():
            result = verify_local_source_lock(profile, base_dir=root,
                                              allow_source_only=allow_source_only)
            rows = []
            try:
                from myfuzz.composition.component_profile import source_lock_input_rows

                rows.extend(source_lock_input_rows(
                    profile, base_dir=root, allow_source_only=allow_source_only,
                    profile_path=profile_path, fresh=True) or ())
                rows.extend(_document_input_rows(result, root))
            except Exception:
                # An input this gate cannot describe is never reused: the
                # accepted result carries no rows, so the next caller verifies
                # again.
                rows = []
            _remember_rows(_LOCK_ROWS, key, rows)
            return result

        return identity_memo(
            ('local-source-lock', fingerprint, str(root), allow_source_only),
            observe(), compute, discover=observe)

    return static_validation(
        ('local-source-lock-verified', fingerprint, str(root), allow_source_only),
        validate, identity=observe, observe_after=True)


def _structural_identity(structural) -> str:
    return identity_of('local-structural-harness-inputs',
                       _digest(structural.wrapper_sv.encode()),
                       _sha(structural.abi_document))


def _gate_identity(profile, *, root: Path, extra) -> str | None:
    """Content identity of the pinned-source gate plus one gate-specific part."""
    from myfuzz.composition.component_profile import source_lock_input_identity

    lock = source_lock_input_identity(
        profile, base_dir=root,
        allow_source_only=getattr(profile, 'component_id', '') == 'rvx_core')
    if lock is None:
        lock = _LOCK_ROWS.get(_lock_identity_key(profile, root, False))
        if lock is None:
            return None
    return identity_of('local-harness-gate-inputs', lock, _sha(extra))


def render_generated_runtime(plan, structural, verified, *, base_dir: Path):
    """Render the admitted runtime top once per observed input content.

    ``render_local_runtime`` re-authenticates the profile, its pinned sources,
    its lock and its structural harness before it emits anything, so the entry,
    the builder and the exit re-authentication would each pay that admission
    for the same bytes.  The identity observes those bytes, so the second and
    later callers reuse the accepted top and a changed byte renders again.
    """
    root = Path(base_dir).resolve()

    def compute():
        return render_local_runtime(plan, structural, verified, base_dir=root)

    identity = _identity_or_none(lambda: identity_of(
        'local-runtime-render-inputs', str(root), plan.profile.profile_fingerprint,
        _preparation_stamp(),
        _gate_identity(plan.profile, root=root, extra=[
            plan.document(), _structural_identity(structural), _sha(verified)])))
    # Scope-local on purpose: the accepted top is shared by every caller in the
    # run that produced it, and the exit boundary re-observes its inputs.  A
    # later preparation renders its own artifact rather than inheriting a live
    # object owned by an earlier one.
    return static_validation(
        ('local-runtime-render', str(root),
         getattr(plan.profile, 'profile_fingerprint', 'unknown'),
         _identity_or_none(lambda: _sha(plan.document())) or 'unknown'),
        compute, identity=lambda: identity)


def render_generated_driver(artifact, *, base_dir: Path):
    """Render the bounded C++ driver once per observed artifact identity."""
    root = Path(base_dir).resolve()
    plan = artifact.plan

    def compute():
        module = importlib.import_module('myfuzz.local_harness.driver_renderer')
        renderer = getattr(module, 'render_local_driver', None)
        if not callable(renderer):
            raise LocalHarnessBuildError('driver-generator-unavailable')
        return renderer(artifact, base_dir=root)

    identity = _identity_or_none(lambda: identity_of(
        'local-driver-render-inputs', str(root), _preparation_stamp(),
        _gate_identity(plan.profile, root=root,
                       extra=[artifact_input_identity(plan, artifact)])))
    return static_validation(
        ('local-driver-render', str(root),
         getattr(plan.profile, 'profile_fingerprint', 'unknown'),
         artifact.runtime_document.get('artifact_digest')), compute,
        identity=lambda: identity)


def build_input_identity(artifact, root: Path):
    """Content identity of every row one build preparation authenticated."""
    rows = _BUILD_ROWS.get(_artifact_identity_key(artifact, root))
    if rows is None:
        return None
    return _identity_or_none(lambda: identity_of(
        'local-harness-build-inputs', str(root), _preparation_stamp(),
        _observe_rows(rows)))


def _remember_build_rows(artifact, root: Path, identity) -> None:
    """Learn the rows a preparation just authenticated, in observation order."""
    if not isinstance(identity, dict):
        return
    rows = []
    for item in identity.get('inputs', ()):
        if isinstance(item, dict):
            rows.append((str(root / item.get('path', '')), item.get('sha256')))
    for item in (identity.get('host_sources') or {}).get('files', ()):
        if isinstance(item, dict):
            rows.append((str(root / item.get('path', '')), item.get('sha256')))
    tools = identity.get('toolchain')
    if isinstance(tools, dict):
        for label in ('verilator', 'cxx', 'make', 'ar'):
            entry = tools.get(label)
            if isinstance(entry, dict):
                rows.append((entry.get('path'), entry.get('executable_sha256')))
        verilator = tools.get('verilator')
        if isinstance(verilator, dict):
            backend = Path(str(verilator.get('path'))).parent / 'verilator_bin'
            rows.append((str(backend), verilator.get('backend_sha256')))
            runtime = verilator.get('runtime_root')
            for item in verilator.get('runtime_files') or ():
                if isinstance(item, dict):
                    rows.append((str(Path(str(runtime)) / str(item.get('path'))),
                                 item.get('sha256')))
    clean = [(name, digest) for name, digest in rows
             if isinstance(name, str) and isinstance(digest, str) and _HEX.fullmatch(digest)]
    _remember_rows(_BUILD_ROWS, _artifact_identity_key(artifact, root), clean)


def _prepared_build(artifact, root: Path):
    """``_prepare`` once per observed input content, at each boundary.

    The identity is the re-observation of the exact input rows the preparation
    recorded plus the build-schedule constants that shape its argv.  It is
    observed *after* the preparation (``observe_after``): a row that changed
    while it ran leaves no identity, so the exit boundary runs it again.
    """
    def observe():
        return build_input_identity(artifact, root)

    def validate():
        def compute():
            identity, snapshots = _prepare(artifact, root)
            _remember_build_rows(artifact, root, identity)
            return identity, snapshots

        return identity_memo(('build_identity', id(artifact), str(root)),
                             observe(), compute, discover=observe)

    return static_validation(('build_identity', id(artifact), str(root)), validate,
                             identity=observe, observe_after=True)


def _cache_input_identity(directory, identity):
    """Fresh content identity of the published cache files (never a stamp).

    ``_validate_cache_current`` re-reads these exact bytes, including a
    same-size, restored-mtime edit, so the identity re-reads them too.
    """
    directory = Path(directory)
    rows = []
    try:
        rows.append(('manifest.json', file_digest_now(directory / 'manifest.json')))
        rows.append(('harness', file_digest_now(directory / 'harness')))
        for item in identity.get('inputs', ()):
            name = item.get('path')
            if not isinstance(name, str):
                return None
            rows.append((name, file_digest_now(directory / 'inputs' / name)))
    except (OSError, TypeError, AttributeError):
        return None
    if any(digest is None for _, digest in rows):
        return None
    return identity_of('local-harness-cache-files', str(directory.resolve()), rows)


def _discover_host_sources(probes=None):
    """Discover the actual Python import closure; leave legacy v1 unchanged."""
    root = _IMPLEMENTATION_ROOT
    def exists(name):
        present=(root/name).is_file()
        if probes is not None:
            if name in probes and probes[name] != present:
                raise LocalHarnessBuildError('host-source-probe-drift:'+name)
            probes[name]=present
        return present
    pending = ['src/myfuzz/scenario/uart_consumption.py',
               'src/myfuzz/local_harness/build.py', 'src/myfuzz/local_harness/driver_renderer.py',
               'src/myfuzz/local_harness/wire.py',
               'src/myfuzz/local_harness/native_session.py', 'scripts/verify_soc_sources.py']
    for name in ('session', 'cpu_session', 'gpio_session',
                 'wishbone_cpu_session', 'wishbone_dma_fields', 'wishbone_dma_template',
                 'wishbone_dma_session', 'wishbone_dma_scenario_session',
                 'axi_lite_session', 'axi4_cpu_session', 'vexii_axi_session',
                 'ahb_lite_session',
                 'cva6_axi4_session',
                 'spi_session', 'timer_session', 'axil_uart_session', 'i2c_session',
                 'rvx_memory_session',
                 'opentitan_spi_host_session', 'opentitan_i2c_session',
                 'opentitan_spi_device_session', 'opentitan_sysrst_ctrl_session'):
        path = f'src/myfuzz/local_harness/{name}.py'
        if exists(path):
            pending.append(path)
    contents = {}
    visited_imports = set()
    while pending:
        name = pending.pop()
        if name in contents:
            continue
        path = _path(root, name)
        raw = path.read_bytes()
        contents[name] = raw
        module = name.removeprefix('src/').removesuffix('.py').replace('/', '.')
        package = module if module.endswith('__init__') else module.rpartition('.')[0]
        if module.endswith('__init__'):
            package = module.removesuffix('.__init__')
        for node in ast.walk(ast.parse(raw, filename=name)):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = '.' * node.level + (node.module or '')
                try:
                    modules = [importlib.util.resolve_name(imported, package) if node.level else imported]
                except (ImportError, ValueError):
                    raise LocalHarnessBuildError('host-import-resolution:' + name)
                # Explicit package imports may resolve to a submodule even
                # when the parent package existed before this invocation.
                modules += [modules[0] + '.' + alias.name for alias in node.names
                            if alias.name != '*']
            for imported in modules:
                if imported == 'myfuzz' or imported.startswith('myfuzz.'):
                    parts = imported.split('.')
                    for index in range(1, len(parts)+1):
                        stem = 'src/' + '/'.join(parts[:index])
                        if stem in visited_imports:
                            continue
                        visited_imports.add(stem)
                        candidates = [stem + '.py', stem + '/__init__.py']
                        for candidate in candidates:
                            if exists(candidate) and candidate not in contents:
                                pending.append(candidate)
    return contents


_HOST_SOURCE_SCOPE = ContextVar('myfuzz_host_source_discovery', default=None)
_HOST_SCOPE_BATCH = ContextVar('myfuzz_host_scope_batch', default=False)


def _host_source_dependency_guard():
    actual=(_discover_host_sources,_host_sources,_path,ast.parse,ast.walk,importlib.util.resolve_name,
            _host_source_dependency_guard,_HOST_SOURCE_ACCESS,_HOST_SOURCE_SCOPE,_HOST_SOURCE_CONTEXT)
    if any(left is not right for left,right in zip(actual,_HOST_SOURCE_METHOD_PINS)):
        raise LocalHarnessBuildError('host-source-method-drift')


def _host_sources(_context=_HOST_SOURCE_SCOPE):
    current=_context.get()
    if current is None:return _discover_host_sources()
    _host_source_dependency_guard()
    return current()


@contextmanager
def host_source_discovery_scope(reuse_nested: bool = False):
    """Reuse code-owned AST discovery only; reread every byte and probe each use.

    ``reuse_nested=True`` marks a batch scope: nested scopes entered while it
    is active delegate to this scope instead of re-running the AST walk. Every
    use still re-reads every byte, so content drift is still refused. The
    default (strict) behaviour keeps nested scopes isolated, as tests require.
    """
    _host_source_dependency_guard()
    if _HOST_SCOPE_BATCH.get() and _HOST_SOURCE_SCOPE.get() is not None:
        yield
        return
    batch_token = _HOST_SCOPE_BATCH.set(True) if reuse_nested else None
    root=_IMPLEMENTATION_ROOT
    contents=None;probes=None
    def current():
        nonlocal contents,probes
        _host_source_dependency_guard()
        if _IMPLEMENTATION_ROOT is not root:
            raise LocalHarnessBuildError('host-source-root-drift')
        if contents is None:
            discovered={};raw=_discover_host_sources(discovered)
            contents=tuple(raw.items());probes=tuple(discovered.items())
        for name,expected in probes:
            if (root/name).is_file() != expected:
                raise LocalHarnessBuildError('host-source-probe-drift:'+name)
        fresh={}
        for name,expected in contents:
            raw=_path(root,name).read_bytes()
            if raw != expected:
                raise LocalHarnessBuildError('host-source-content-drift:'+name)
            fresh[name]=raw
        return fresh
    token=_HOST_SOURCE_SCOPE.set(current)
    try:yield
    finally:
        _HOST_SOURCE_SCOPE.reset(token)
        if batch_token is not None:
            _HOST_SCOPE_BATCH.reset(batch_token)


_HOST_SOURCE_ACCESS=_host_sources
_HOST_SOURCE_CONTEXT=_HOST_SOURCE_SCOPE
_HOST_SOURCE_METHOD_PINS=(_discover_host_sources,_host_sources,_path,ast.parse,ast.walk,
                         importlib.util.resolve_name,_host_source_dependency_guard,
                         _HOST_SOURCE_ACCESS,_HOST_SOURCE_CONTEXT,_HOST_SOURCE_CONTEXT)


def _check_headers(cpp, headers):
    def resolve(include, owner):
        if include == 'verilated.h' or re.fullmatch(r'V[A-Za-z_][A-Za-z0-9_$]*\.h', include):
            return None
        if owner:
            candidate = (Path(owner).parent / include).as_posix()
            normalized = os.path.normpath(candidate).replace(os.sep, '/')
            if normalized in headers:
                return normalized
        matches = [name for name in headers if name == include or Path(name).name == include]
        if len(matches) != 1:
            raise LocalHarnessBuildError('undeclared-driver-include:' + include)
        return matches[0]
    for owner, raw in [(None, cpp.encode()), *headers.items()]:
        text = raw.decode('utf-8')
        for include in re.findall(r'^\s*#\s*include\s*"([^"]+)"', text, re.M):
            resolve(include, owner)


def _driver_shape(artifact):
    doc = artifact.runtime_document
    reset = doc.get('driver_reset')
    expected_reset = dict(schema_version='generated_local_reset.v1',
                         reset_assert_ticks=artifact.plan.request.reset_assert_ticks,
                         reset_release_ticks=artifact.plan.request.reset_release_ticks)
    if reset != expected_reset or any(type(reset[name]) is not int for name in ('reset_assert_ticks', 'reset_release_ticks')):
        raise LocalHarnessBuildError('driver-reset-schema-mismatch')
    limits = doc.get('driver_limits')
    keys = {'max_command_bytes', 'max_payload_json_bytes', 'max_reply_line_bytes',
            'max_cached_bytes', 'reply_reservation_bytes', 'max_samples_per_command'}
    if not isinstance(limits, dict) or set(limits) != keys or any(type(value) is not int or value <= 0 for value in limits.values()):
        raise LocalHarnessBuildError('driver-limits-schema-mismatch')
    if limits['reply_reservation_bytes'] > limits['max_cached_bytes']:
        raise LocalHarnessBuildError('driver-reply-reservation-outside-capacity')
    fields = doc.get('driver_field_map')
    ports = {row['name'] for row in doc['runtime_ports']}
    if not isinstance(fields, dict) or any(not isinstance(key, str) or not key or not isinstance(value, str) or value not in ports for key, value in fields.items()):
        raise LocalHarnessBuildError('driver-field-map-schema-mismatch')


def _verify_generated_driver(artifact, baseline, root):
    path = _IMPLEMENTATION_ROOT / 'src/myfuzz/local_harness/driver_renderer.py'
    if not path.is_file():
        raise LocalHarnessBuildError('driver-generator-unavailable')
    # The bytes are a function of the artifact, not of who asks: reuse the one
    # accepted generation instead of rendering the same driver again.
    generated = render_generated_driver(baseline, base_dir=root)
    if (generated.cpp_text != artifact.cpp_text or generated.runtime_document != artifact.runtime_document
            or generated.runtime_sv != artifact.runtime_sv or generated.structural != artifact.structural):
        raise LocalHarnessBuildError('generated-driver-identity-mismatch')


def _preparation_stamp() -> tuple:
    """Include mutable in-process admission hooks in the fast-path key."""
    renderer = importlib.import_module('myfuzz.local_harness.driver_renderer')
    return (CXX_STANDARD, BUILD_TIMEOUT_SECONDS, _REQUIRED_HEADERS,
            frozenset(_DRIVER_KEYS), frozenset(_DRIVER_CHANGES),
            _build_jobs(),
            id(render_local_runtime), id(verify_local_source_lock),
            id(_verify_generated_driver), id(getattr(renderer, 'render_local_driver', None)),
            str(_IMPLEMENTATION_ROOT.resolve()))


def _prepared_if_current(artifact, root):
    if strict_validation_active():
        return None
    entry = _PREPARED_CACHE.get(id(artifact))
    if entry is None:
        return None
    original, frozen, saved_root, stamp, identity, snapshots = entry
    if (original is not artifact or saved_root != root
            or stamp != _preparation_stamp() or artifact != frozen):
        _PREPARED_CACHE.pop(id(artifact), None)
        return None
    if (type(identity) is not dict or type(snapshots) is not dict
            or type(identity.get('host_sources')) is not dict
            or type(identity['host_sources'].get('files')) is not list):
        _PREPARED_CACHE.pop(id(artifact), None)
        return None
    # Optional seeds and package aliases can appear without any old file
    # changing. Compare the whole current code-owned host closure as well.
    try:
        _host_source_dependency_guard()
        host = _HOST_SOURCE_ACCESS()
        expected = [dict(path=name, sha256=_digest(raw)) for name, raw in sorted(host.items())]
        if (_canonical(identity.get('host_sources', {}).get('files')) != _canonical(expected)
                or any(snapshots.get(name) != raw for name, raw in host.items())):
            _PREPARED_CACHE.pop(id(artifact), None)
            return None
        if _toolchain() != identity['toolchain']:
            return None
        for name, raw in snapshots.items():
            if not name.startswith('generated/') and _path(root, name).read_bytes() != raw:
                return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return copy.deepcopy(identity), snapshots.copy()


_HARNESS_VALIDATION_SCOPE = ContextVar('myfuzz_harness_validation_scope', default=None)


@contextmanager
def harness_validation_scope():
    """Reuse one prepared identity inside a batch run while stat stamps match.

    Within this scope repeated admissions compare input mtime/size instead of
    re-hashing every byte. Normal edits are still detected; tests and
    single-shot admissions do not enter this scope, so their stricter byte
    checks remain unchanged.
    """
    token = _HARNESS_VALIDATION_SCOPE.set({})
    try:
        yield
    finally:
        _HARNESS_VALIDATION_SCOPE.reset(token)


def _validation_stamp(identity, root):
    rows = []
    for item in identity['inputs']:
        name = item['path']
        if name.startswith('generated/'):
            continue
        info = (root / name).stat()
        rows.append((name, info.st_mtime_ns, info.st_size))
    for item in identity['host_sources']['files']:
        info = (root / item['path']).stat()
        rows.append((item['path'], info.st_mtime_ns, info.st_size))
    toolchain = identity['toolchain']
    for label in ('verilator', 'cxx', 'make', 'ar'):
        path = Path(toolchain[label]['path'])
        info = path.stat()
        rows.append((str(path), info.st_mtime_ns, info.st_size))
    verilator = toolchain['verilator']
    backend = Path(verilator['path']).parent / 'verilator_bin'
    info = backend.stat()
    rows.append((str(backend), info.st_mtime_ns, info.st_size))
    runtime = Path(verilator['runtime_root'])
    for item in verilator.get('runtime_files', []):
        path = runtime / item['path']
        info = path.stat()
        rows.append((str(path), info.st_mtime_ns, info.st_size))
    return tuple(rows)


def _prepare(artifact, base_dir, _host_context=_HOST_SOURCE_SCOPE):
    if (not isinstance(artifact, LocalRuntimeArtifact) or not isinstance(artifact.cpp_text, str)
            or not artifact.cpp_text.strip()):
        raise LocalHarnessBuildError('generated-driver-required')
    doc = artifact.runtime_document
    if not isinstance(doc, dict) or not isinstance(artifact.runtime_sv, str):
        raise LocalHarnessBuildError('invalid-runtime-artifact')
    ahb_startup = doc.get('kind') == 'ahb_lite_cpu'
    storage_startup = 'storage_startup_selection' in doc
    driver_schema = ('local_driver_generation.ahb_startup.v2' if ahb_startup
                     else 'local_driver_generation.apb_storage_startup.v2' if storage_startup
                     else 'local_driver_generation.v1')
    if (doc.get('status'), doc.get('driver_status'), doc.get('driver_schema_version')) != (
            'driver_generated', 'generated', driver_schema):
        raise LocalHarnessBuildError('generated-driver-schema-required')
    driver_keys = _DRIVER_KEYS
    if ahb_startup:
        from .ahb_startup import contract_from_document
        try:
            contract_from_document(doc)
        except (ValueError, KeyError, TypeError) as error:
            raise LocalHarnessBuildError('ahb-startup-contract-required') from error
        driver_keys = _DRIVER_KEYS | {'ahb_startup_contract'}
    elif 'ahb_startup_contract' in doc:
        raise LocalHarnessBuildError('ahb-startup-contract-wrong-runtime')
    if storage_startup:
        from .apb_storage_startup import contract_from_document
        try:contract_from_document(doc)
        except (ValueError,KeyError,TypeError) as error:
            raise LocalHarnessBuildError('storage-startup-contract-required') from error
        driver_keys=driver_keys | {'storage_startup_capture'}
    elif 'storage_startup_capture' in doc:
        raise LocalHarnessBuildError('storage-startup-contract-wrong-runtime')
    if _selected_timing_mode(getattr(getattr(artifact, 'plan', None), 'profile', None)) == 'timing':
        from .driver_renderer import _timed_clock_contract
        expected_timing = _timed_clock_contract(artifact.plan.profile, doc.get('clock_schedule', {}))
        if doc.get('driver_timing') != expected_timing:
            raise LocalHarnessBuildError('driver-timing-contract-mismatch')
        driver_keys = driver_keys | {'driver_timing'}
    elif 'driver_timing' in doc:
        raise LocalHarnessBuildError('driver-timing-not-selected-by-profile')
    if doc.get('cpp_sha256') != _digest(artifact.cpp_text.encode()) or doc.get('runtime_sv_sha256') != _digest(artifact.runtime_sv.encode()):
        raise LocalHarnessBuildError('artifact-text-hash-mismatch')
    unsigned = {key: value for key, value in doc.items() if key != 'artifact_digest'}
    if doc.get('artifact_digest') != _sha(unsigned):
        raise LocalHarnessBuildError('artifact-digest-mismatch')
    root = Path(base_dir).resolve()
    scope = _HARNESS_VALIDATION_SCOPE.get()
    if scope is not None and not strict_validation_active() and root == _IMPLEMENTATION_ROOT.resolve():
        entry = scope.get(id(artifact))
        if entry is not None:
            saved_artifact, saved_root, saved_key, saved_stamp, identity, snapshots = entry
            if (saved_artifact is artifact and saved_root == root
                    and saved_key == _preparation_stamp()):
                try:
                    if _validation_stamp(identity, root) == saved_stamp:
                        return copy.deepcopy(identity), snapshots.copy()
                except OSError:
                    scope.pop(id(artifact), None)
    if _host_context.get() is not None:
        _host_source_dependency_guard()
    if root == _IMPLEMENTATION_ROOT.resolve():
        current = _prepared_if_current(artifact, root)
        if current is not None:
            return current
    if _host_context.get() is not None:
        _HOST_SOURCE_ACCESS()
    verified = verified_source_lock(
        artifact.plan.profile, base_dir=root,
        allow_source_only=artifact.plan.profile.component_id == 'rvx_core',
        profile_path=root / artifact.plan.request.profile_path)
    if verified != artifact.source_verification:
        raise LocalHarnessBuildError('artifact-source-verification-mismatch')
    baseline = render_generated_runtime(artifact.plan, artifact.structural, verified,
                                       base_dir=root)
    if (artifact.runtime_sv != baseline.runtime_sv or set(doc) != set(baseline.runtime_document) | driver_keys
            or any(doc[key] != value for key, value in baseline.runtime_document.items() if key not in _DRIVER_CHANGES)):
        raise LocalHarnessBuildError('artifact-runtime-identity-mismatch')
    _driver_shape(artifact)
    _verify_generated_driver(artifact, baseline, root)
    snapshots = {}
    def capture(name, expected=None):
        raw = _path(root, name).read_bytes()
        if expected is not None and _digest(raw) != expected:
            raise LocalHarnessBuildError('build-input-hash-mismatch:' + name)
        if name in snapshots and snapshots[name] != raw:
            raise LocalHarnessBuildError('build-input-changed:' + name)
        snapshots[name] = raw
    capture(artifact.plan.request.profile_path, artifact.plan.profile_sha256)
    manifest = artifact.plan.profile.evidence.get('local_source_manifest')
    if manifest is None:
        capture('configs/soc/sources.lock.json', verified['lock_sha256'])
        lock = json.loads(snapshots['configs/soc/sources.lock.json'])
    else:
        # This manifest is embedded in the profile bytes just captured above.
        # Use the source verifier's exact canonical encoding for its identity;
        # it is not the hash of the unrelated central sources.lock.json.
        manifest_raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'),
                                  allow_nan=False).encode()
        if _digest(manifest_raw) != verified['lock_sha256']:
            raise LocalHarnessBuildError('profile-source-manifest-hash-mismatch')
        lock = manifest
    if verified.get('schema_version') == 'zipdma_selected_profile_contract.v1':
        for name, digest in verified['sources'].items():
            capture(artifact.plan.profile.source.source_root + '/' + name, digest)
        capture('configs/peripherals/zipdma_smoke/profile.json')
    else:
        record_id = ({'opentitan_gpio_local': 'opentitan_gpio',
                      'opentitan_rv_timer_local': 'opentitan_rv_timer',
                      'opentitan_sysrst_ctrl_local': 'opentitan_sysrst_ctrl',
                      'opentitan_spi_host_local': 'opentitan_spi_host',
                      'opentitan_uart_local': 'opentitan_uart',
                      'opentitan_i2c_local': 'opentitan_i2c',
                      'opentitan_spi_device_local': 'opentitan_spi_device'}
                     .get(artifact.plan.profile.component_id, artifact.plan.profile.component_id))
        record = verified.get('closure_record')
        if record is None:
            record = next(record for record in lock['components'] if record['id'] == record_id)
        elaboration = record.get('elaboration')
        if elaboration is None:
            if (artifact.plan.profile.component_id != 'rvx_core'
                    or verified.get('elaboration_status') != 'elaboration_unverified'
                    or record.get('source', {}).get('root') != 'external_designs/rvx'
                    or record.get('source', {}).get('top_module') != 'rvx_core'
                    or record.get('source', {}).get('files') != ['hardware/rvx_core.v']):
                raise LocalHarnessBuildError('source-only-build-scope-mismatch')
            source_hashes = {item['path']: item['sha256'] for item in record['artifacts']
                             if item['kind'] == 'source'}
            for name in record['source']['files']:
                if name not in source_hashes:
                    raise LocalHarnessBuildError('source-only-build-file-unpinned:' + name)
                capture(record['source']['root'] + '/' + name, source_hashes[name])
        else:
            evidence = elaboration['evidence']
            inline = lock.get('elaboration_closures', {}).get(record['id']) if manifest is not None else None
            if inline is None:
                capture(evidence, elaboration['evidence_sha256'])
                closure = json.loads(snapshots[evidence])
            else:
                raw = json.dumps(inline, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                if _digest(raw) != elaboration['evidence_sha256']:
                    raise LocalHarnessBuildError('profile-inline-closure-hash-mismatch')
                closure = inline
            for item in closure['closure_files']:
                item_root = item.get('root')
                if item_root is None:
                    # Repository-wide generated closures already record each path
                    # relative to the checkout and declare that convention once.
                    if closure.get('root') != '.':
                        raise LocalHarnessBuildError('closure-file-root-missing')
                    item_root = '.'
                name = item['path'] if item_root == '.' else item_root + '/' + item['path']
                capture(name, item['sha256'])
    for item in verified.get('authenticated_inputs', []):
        capture(item['path'], item['sha256'])
    if artifact.plan.profile.component_id in ('opentitan_gpio_local', 'opentitan_rv_timer_local',
                                              'opentitan_uart_local', 'opentitan_i2c_local',
                                              'opentitan_spi_device_local',
                                              'opentitan_sysrst_ctrl_local'):
        capture(verified['wrapper_path'], verified['wrapper_sha256'])
    if artifact.plan.profile.component_id == 'opentitan_spi_host_local':
        for path, digest in zip(verified['wrapper_paths'], verified['wrapper_sha256']):
            capture(path, digest)
    if artifact.plan.profile.component_id == 'opentitan_gpio_local':
        capture('configs/peripherals/opentitan_gpio/component_profile.json',
                verified['upstream_profile_sha256'])
    if artifact.plan.profile.component_id == 'opentitan_i2c_local':
        capture('configs/peripherals/opentitan_i2c/component_profile.json',
                verified['upstream_profile_sha256'])
    if artifact.plan.profile.component_id == 'opentitan_spi_device_local':
        capture('configs/peripherals/opentitan_spi_device/component_profile.json',
                verified['upstream_profile_sha256'])
    if artifact.plan.profile.component_id == 'opentitan_sysrst_ctrl_local':
        capture('configs/peripherals/opentitan_sysrst_ctrl/component_profile.json',
                verified['upstream_profile_sha256'])
    # Protocol declarations affect DMA field ownership/handshake admission and
    # must be retained with the executable snapshot, separately from RTL inputs.
    for item in (*doc['adapter_sources'], *doc.get('protocol_sources', [])):
        capture(item['path'], item['sha256'])
    rows = doc['driver_header_sources']
    if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) != {'path', 'sha256'} for row in rows):
        raise LocalHarnessBuildError('invalid-driver-header-sources')
    header_paths = [row['path'] for row in rows]
    if len(set(header_paths)) != len(header_paths) or not set(_REQUIRED_HEADERS).issubset(header_paths):
        raise LocalHarnessBuildError('required-driver-headers-missing-or-duplicated')
    for row in rows:
        if not isinstance(row['sha256'], str) or not _HEX.fullmatch(row['sha256']):
            raise LocalHarnessBuildError('invalid-driver-header-hash')
        capture(row['path'], row['sha256'])
    _check_headers(artifact.cpp_text, {name: snapshots[name] for name in header_paths})
    host = _HOST_SOURCE_ACCESS()
    for name, raw in host.items():
        if name in snapshots and snapshots[name] != raw:
            raise LocalHarnessBuildError('executing-host-source-mismatch:' + name)
        snapshots[name] = raw
    snapshots['generated/structural.sv'] = artifact.structural.wrapper_sv.encode()
    snapshots['generated/runtime.sv'] = artifact.runtime_sv.encode()
    snapshots['generated/driver.cpp'] = artifact.cpp_text.encode()
    snapshots['generated/artifact.json'] = _canonical(doc)
    tools = _toolchain()
    module = doc['module_name']
    build = artifact.structural.build_document
    timing_flags = _verilator_timing_flags(artifact.plan.profile)
    cpp_flags = (f'-std={CXX_STANDARD} ' + shlex.quote('-I{BUILD}/inputs/src/myfuzz/local_harness/rtl') + ' '
                 f'-DMYFUZZ_ARTIFACT_DIGEST={doc["artifact_digest"]}')
    argv = [tools['verilator']['path'], '--cc', '--exe', '--build', '-j', str(_build_jobs()), '-Wno-fatal',
            *timing_flags,
            '--top-module', module, '--Mdir', '{BUILD}/obj', '-o', 'harness',
            '-CFLAGS', cpp_flags, '-MAKEFLAGS', 'CXX=' + tools['cxx']['path'] +
            ' LINK=' + tools['cxx']['path'] + ' AR=' + tools['ar']['path'],
            *('-I{BUILD}/inputs/' + name for name in build['include_roots']),
            *('-D' + name for name in build['defines']),
            *('{BUILD}/inputs/' + name for name in build['source_files']),
            *('{BUILD}/inputs/' + row['path'] for row in doc['adapter_sources']),
            '{BUILD}/inputs/generated/structural.sv', '{BUILD}/inputs/generated/runtime.sv',
            '{BUILD}/inputs/generated/driver.cpp']
    identity = dict(schema_version='local_harness_build_identity.v1', artifact_digest=doc['artifact_digest'],
                    workers=1, build_jobs=_build_jobs(), timeout_seconds=BUILD_TIMEOUT_SECONDS, waveforms=False,
                    toolchain=tools, build_argv=argv,
                    inputs=[dict(path=name, sha256=_digest(raw)) for name, raw in sorted(snapshots.items())],
                    host_sources=dict(schema_version='local_harness_host_sources.v1',
                                      files=[dict(path=name, sha256=_digest(raw)) for name, raw in sorted(host.items())]))
    identity['build_digest'] = _sha(identity)
    if scope is not None and not strict_validation_active() and root == _IMPLEMENTATION_ROOT.resolve():
        try:
            stamp = _validation_stamp(identity, root)
        except OSError:
            stamp = None
        if stamp is not None:
            scope[id(artifact)] = (artifact, root, _preparation_stamp(), stamp,
                                   copy.deepcopy(identity), snapshots.copy())
    if root == _IMPLEMENTATION_ROOT.resolve():
        if len(_PREPARED_CACHE) >= _PREPARED_CACHE_LIMIT:
            _PREPARED_CACHE.pop(next(iter(_PREPARED_CACHE)))
        _PREPARED_CACHE[id(artifact)] = (
            artifact, copy.deepcopy(artifact), root, _preparation_stamp(),
            copy.deepcopy(identity), snapshots.copy())
    return identity, snapshots


def local_build_identity(artifact: LocalRuntimeArtifact, *, base_dir: Path) -> dict[str, object]:
    """Authenticate current input bytes and return their canonical build identity."""
    try:
        key = (id(artifact), str(Path(base_dir).resolve()))
        if not static_validation_matches(('build_artifact', *key), lambda: artifact, artifact):
            raise LocalHarnessBuildError('execution-artifact-drift')
        return _prepared_build(artifact, Path(base_dir).resolve())[0]
    except LocalHarnessBuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ImportError) as error:
        raise LocalHarnessBuildError('build-admission-failed:' + str(error)) from error


def _validate_cache(directory, identity):
    # Staging directories are renamed or discarded by the build transaction.
    # Only a published identity directory can survive an execution boundary.
    if Path(directory).name != identity.get('build_digest'):
        return _validate_cache_current(directory, identity)
    return static_validation(('build_cache', str(Path(directory).resolve()), _sha(identity)),
                             lambda: _validate_cache_current(directory, identity),
                             identity=lambda: _cache_input_identity(directory, identity))


def _validate_cache_current(directory, identity):
    try:
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        if _canonical(manifest['identity']) != _canonical(identity):
            raise ValueError('identity differs')
        binary = directory / 'harness'
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK) or _digest(binary.read_bytes()) != manifest['binary_sha256']:
            raise ValueError('binary differs')
        for item in identity['inputs']:
            path = directory / 'inputs' / item['path']
            if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()) or _digest(path.read_bytes()) != item['sha256']:
                raise ValueError('materialized input differs')
        return binary
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise LocalHarnessBuildError('cache-integrity-failed:' + str(error)) from error


def _compile(argv, directory):
    env = _environment()
    process = subprocess.Popen(argv, cwd=directory, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=BUILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)
        raise LocalHarnessBuildError('build-timeout') from error
    (directory / 'build.log').write_text(stdout + stderr)
    if process.returncode:
        raise LocalHarnessBuildError('verilator-build-failed:' + (stdout + stderr)[-6000:])


def _build_local_harness(artifact, *, base_dir, cache_dir, observation=None):
    """Build a snapshot with one worker; atomically publish only verified output."""
    try:
        if observation is not None:
            observation['failure_stage'] = 'admission'
        identity, snapshots = _prepared_build(artifact, Path(base_dir).resolve())
        if observation is not None:
            observation['failure_stage'] = 'cache_directory_preparation'
        cache = Path(cache_dir).resolve()
        cache.mkdir(parents=True, exist_ok=True)
        final = cache / identity['build_digest']
        if observation is not None:
            observation['failure_stage'] = 'cache_validation'
        if observation is not None and final.is_symlink():
            raise LocalHarnessBuildError('receipt-cache-integrity-failed:cache directory symlink')
        if final.exists():
            if observation is not None:
                manifest_path = final / 'manifest.json'
                observation['manifest_path'] = str(manifest_path)
                if manifest_path.is_file():
                    observation['manifest_sha256'] = _digest(manifest_path.read_bytes())
            binary = _validate_cache(final, identity)
            if observation is not None:
                observation['outcome'] = 'cache_hit'
            return binary, identity
        if observation is not None:
            observation['failure_stage'] = 'staging'
        stage = Path(tempfile.mkdtemp(prefix='.' + identity['build_digest'] + '-', dir=cache))
        try:
            if observation is not None:
                observation['failure_stage'] = 'materialization'
            for name, raw in snapshots.items():
                path = stage / 'inputs' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            argv = [token.replace('{BUILD}', str(stage)) for token in identity['build_argv']]
            if observation is not None:
                observation.update(failure_stage='compile', compiled_this_invocation=True,
                                   actual_build_argv=argv, compile_seconds_reason=None)
            compile_started = time.monotonic()
            try:
                _compile(argv, stage)
            finally:
                if observation is not None:
                    observation['compile_seconds'] = time.monotonic() - compile_started
            if observation is not None:
                observation['failure_stage'] = 'output_validation'
            binary = stage / 'obj/harness'
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise LocalHarnessBuildError('build-executable-missing')
            shutil.copy2(binary, stage / 'harness')
            manifest = dict(schema_version='local_harness_build_cache.v1', identity=identity,
                            binary_sha256=_digest((stage / 'harness').read_bytes()), actual_build_argv=argv)
            (stage / 'manifest.json').write_bytes(_canonical(manifest))
            if observation is not None:
                observation['failure_stage'] = 'identity_revalidation'
            if local_build_identity(artifact, base_dir=base_dir) != identity:
                raise LocalHarnessBuildError('build-inputs-changed-during-build')
            if observation is not None:
                observation['failure_stage'] = 'staged_cache_validation'
            _validate_cache(stage, identity)
            if observation is not None:
                observation['failure_stage'] = 'publication'
            try:
                stage.rename(final)
            except OSError as error:
                if error.errno not in (errno.EEXIST, errno.ENOTEMPTY) or not final.exists():
                    raise
                if observation is not None:
                    observation['failure_stage'] = 'winning_cache_validation'
                binary = _validate_cache(final, identity)
                if observation is not None:
                    observation['outcome'] = 'compiled_race_reused'
                return binary, identity
            if observation is not None:
                observation['failure_stage'] = 'published_cache_validation'
            binary = _validate_cache(final, identity)
            if observation is not None:
                observation['outcome'] = 'compiled_published'
            return binary, identity
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    except LocalHarnessBuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ImportError) as error:
        raise LocalHarnessBuildError('local-build-failed:' + str(error)) from error


def build_local_harness(artifact: LocalRuntimeArtifact, *, base_dir: Path, cache_dir: Path) -> Path:
    """Build with the existing Path contract and cache compatibility."""
    return _build_local_harness(artifact, base_dir=base_dir, cache_dir=cache_dir)[0]


def _receipt_cache(binary, identity, cache_dir):
    return static_validation(('receipt_cache', str(binary), str(Path(cache_dir).resolve()), _sha(identity)),
                             lambda: _receipt_cache_current(binary, identity, cache_dir),
                             identity=lambda: _cache_input_identity(Path(binary).parent, identity))


def _receipt_cache_current(binary, identity, cache_dir):
    """Validate the stricter receipt cache contract without altering legacy caches."""
    try:
        cache = Path(cache_dir).resolve()
        expected = cache / identity['build_digest'] / 'harness'
        if binary != expected or binary.parent.is_symlink() or binary.resolve() != expected:
            raise ValueError('unexpected executable path')
        directory = binary.parent
        manifest_path = directory / 'manifest.json'
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError('manifest path differs')
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        if (type(manifest) is not dict
                or manifest.get('schema_version') != 'local_harness_build_cache.v1'
                or type(manifest.get('identity')) is not dict
                or type(manifest.get('binary_sha256')) is not str
                or not _HEX.fullmatch(manifest['binary_sha256'])
                or type(manifest.get('actual_build_argv')) is not list
                or not manifest['actual_build_argv']
                or any(type(token) is not str for token in manifest['actual_build_argv'])):
            raise ValueError('unexpected cache manifest schema')
        if (identity.get('schema_version') != 'local_harness_build_identity.v1'
                or identity.get('build_digest') != _digest(_canonical(
                    {key: value for key, value in identity.items() if key != 'build_digest'}))):
            raise ValueError('unexpected build identity schema')
        for item in identity['inputs']:
            materialized = directory / 'inputs' / item['path']
            if any(parent.is_symlink() for parent in
                   (materialized, *materialized.parents[:len(materialized.parts) - len(directory.parts)])):
                raise ValueError('materialized input symlink')
        _validate_cache(directory, identity)
        # Pin the same bytes which were parsed and validated, refusing concurrent changes.
        if manifest_path.read_bytes() != raw:
            raise ValueError('manifest changed during validation')
        return manifest, raw
    except LocalHarnessBuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise LocalHarnessBuildError('receipt-cache-integrity-failed:' + str(error)) from error


@dataclass(frozen=True)
class LocalHarnessBuildResult:
    """A pinned preparation; saved receipts alone cannot authorize a launch."""

    binary_path: Path
    _receipt_bytes: bytes = field(repr=False)
    _observation_bytes: bytes = field(repr=False)
    _manifest_sha256: str = field(repr=False)

    @property
    def receipt_sha256(self) -> str:
        return _digest(self._receipt_bytes)

    def receipt_document(self) -> dict:
        return json.loads(self._receipt_bytes)

    def observation_document(self) -> dict:
        return json.loads(self._observation_bytes)

    def validate_current(self, artifact, *, base_dir, cache_dir) -> Path:
        identity = local_build_identity(artifact, base_dir=base_dir)
        try:
            receipt = self.receipt_document()
            if (type(receipt) is not dict
                    or set(receipt) != {'schema_version', 'artifact_digest', 'build_digest',
                                       'build_identity', 'binary_sha256'}
                    or receipt['schema_version'] != 'local_harness_built_receipt.v1'
                    or type(receipt['build_identity']) is not dict
                    or any(type(receipt[key]) is not str or not _HEX.fullmatch(receipt[key])
                           for key in ('artifact_digest', 'build_digest', 'binary_sha256'))
                    or self._receipt_bytes != _canonical(receipt)):
                raise ValueError('unexpected built receipt schema')
        except (ValueError, KeyError, TypeError) as error:
            raise LocalHarnessBuildError('built-receipt-schema-mismatch:' + str(error)) from error
        if (_canonical(identity) != _canonical(receipt['build_identity'])
                or identity['artifact_digest'] != receipt['artifact_digest']
                or identity['build_digest'] != receipt['build_digest']):
            raise LocalHarnessBuildError('built-receipt-current-identity-mismatch')
        manifest, raw = _receipt_cache(self.binary_path, identity, cache_dir)
        if (_digest(raw) != self._manifest_sha256
                or manifest['binary_sha256'] != receipt['binary_sha256']):
            raise LocalHarnessBuildError('built-receipt-pinned-cache-mismatch')
        return self.binary_path


def build_local_harness_with_receipt(artifact, *, base_dir, cache_dir) -> LocalHarnessBuildResult:
    """Prepare and pin a validated executable, retaining actual branch diagnostics."""
    started = time.monotonic()
    observation = dict(schema_version='local_harness_build_preparation.v1',
                       outcome=None, compiled_this_invocation=False,
                       compile_seconds=None, compile_seconds_reason='not_compiled_this_invocation',
                       actual_build_argv=None, failure_stage='admission')
    try:
        binary, identity = _build_local_harness(artifact, base_dir=base_dir, cache_dir=cache_dir,
                                                observation=observation)
        observation['failure_stage'] = 'receipt_validation'
        manifest, raw = _receipt_cache(binary, identity, cache_dir)
        receipt = dict(schema_version='local_harness_built_receipt.v1',
                       artifact_digest=identity['artifact_digest'], build_digest=identity['build_digest'],
                       build_identity=identity, binary_sha256=manifest['binary_sha256'])
        observation.update(manifest_path=str(binary.parent / 'manifest.json'),
                           manifest_sha256=_digest(raw), failure_stage=None,
                           preparation_seconds=time.monotonic() - started)
        return LocalHarnessBuildResult(binary, _canonical(receipt), _canonical(observation), _digest(raw))
    except (LocalHarnessBuildError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, ImportError) as error:
        observation.update(preparation_seconds=time.monotonic() - started, error=str(error))
        raise LocalHarnessBuildError(str(error), preparation_observation=observation) from error
