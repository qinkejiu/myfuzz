"""Identity-keyed, bounded builds from authenticated runtime artifact bytes."""
from __future__ import annotations

import ast
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


class LocalHarnessBuildError(RuntimeError):
    """Admission, build, timeout or cache integrity failed."""


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


def _host_sources():
    """Discover the actual Python import closure; leave legacy v1 unchanged."""
    root = _IMPLEMENTATION_ROOT
    pending = ['src/myfuzz/local_harness/build.py', 'src/myfuzz/local_harness/driver_renderer.py',
               'src/myfuzz/local_harness/wire.py',
               'src/myfuzz/local_harness/native_session.py', 'scripts/verify_soc_sources.py']
    for name in ('session', 'cpu_session', 'gpio_session'):
        path = f'src/myfuzz/local_harness/{name}.py'
        if (root / path).is_file():
            pending.append(path)
    contents = {}
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
                if node.module is None:
                    modules += [modules[0] + '.' + alias.name for alias in node.names]
            for imported in modules:
                if imported == 'myfuzz' or imported.startswith('myfuzz.'):
                    parts = imported.split('.')
                    for index in range(1, len(parts)+1):
                        stem = 'src/' + '/'.join(parts[:index])
                        candidates = [stem + '.py', stem + '/__init__.py']
                        for candidate in candidates:
                            if (root / candidate).is_file() and candidate not in contents:
                                pending.append(candidate)
    return contents


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
    module = importlib.import_module('myfuzz.local_harness.driver_renderer')
    renderer = getattr(module, 'render_local_driver', None)
    if not callable(renderer):
        raise LocalHarnessBuildError('driver-generator-unavailable')
    generated = renderer(baseline, base_dir=root)
    if (generated.cpp_text != artifact.cpp_text or generated.runtime_document != artifact.runtime_document
            or generated.runtime_sv != artifact.runtime_sv or generated.structural != artifact.structural):
        raise LocalHarnessBuildError('generated-driver-identity-mismatch')


def _prepare(artifact, base_dir):
    if (not isinstance(artifact, LocalRuntimeArtifact) or not isinstance(artifact.cpp_text, str)
            or not artifact.cpp_text.strip()):
        raise LocalHarnessBuildError('generated-driver-required')
    doc = artifact.runtime_document
    if not isinstance(doc, dict) or not isinstance(artifact.runtime_sv, str):
        raise LocalHarnessBuildError('invalid-runtime-artifact')
    if (doc.get('status'), doc.get('driver_status'), doc.get('driver_schema_version')) != (
            'driver_generated', 'generated', 'local_driver_generation.v1'):
        raise LocalHarnessBuildError('generated-driver-schema-required')
    if doc.get('cpp_sha256') != _digest(artifact.cpp_text.encode()) or doc.get('runtime_sv_sha256') != _digest(artifact.runtime_sv.encode()):
        raise LocalHarnessBuildError('artifact-text-hash-mismatch')
    unsigned = {key: value for key, value in doc.items() if key != 'artifact_digest'}
    if doc.get('artifact_digest') != _sha(unsigned):
        raise LocalHarnessBuildError('artifact-digest-mismatch')
    root = Path(base_dir).resolve()
    verified = verify_local_source_lock(artifact.plan.profile, base_dir=root)
    if verified != artifact.source_verification:
        raise LocalHarnessBuildError('artifact-source-verification-mismatch')
    baseline = render_local_runtime(artifact.plan, artifact.structural, verified, base_dir=root)
    if (artifact.runtime_sv != baseline.runtime_sv or set(doc) != set(baseline.runtime_document) | _DRIVER_KEYS
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
    capture('configs/soc/sources.lock.json', verified['lock_sha256'])
    lock = json.loads(snapshots['configs/soc/sources.lock.json'])
    record = next(record for record in lock['components'] if record['id'] == artifact.plan.profile.component_id)
    evidence = record['elaboration']['evidence']
    capture(evidence, record['elaboration']['evidence_sha256'])
    closure = json.loads(snapshots[evidence])
    for item in closure['closure_files']:
        capture(item['root'] + '/' + item['path'], item['sha256'])
    for item in doc['adapter_sources']:
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
    host = _host_sources()
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
    cpp_flags = (f'-std={CXX_STANDARD} ' + shlex.quote('-I{BUILD}/inputs/src/myfuzz/local_harness/rtl') + ' '
                 f'-DMYFUZZ_ARTIFACT_DIGEST={doc["artifact_digest"]}')
    argv = [tools['verilator']['path'], '--cc', '--exe', '--build', '-j', '1', '-Wno-fatal',
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
                    workers=1, timeout_seconds=BUILD_TIMEOUT_SECONDS, waveforms=False,
                    toolchain=tools, build_argv=argv,
                    inputs=[dict(path=name, sha256=_digest(raw)) for name, raw in sorted(snapshots.items())],
                    host_sources=dict(schema_version='local_harness_host_sources.v1',
                                      files=[dict(path=name, sha256=_digest(raw)) for name, raw in sorted(host.items())]))
    identity['build_digest'] = _sha(identity)
    return identity, snapshots


def local_build_identity(artifact: LocalRuntimeArtifact, *, base_dir: Path) -> dict[str, object]:
    """Authenticate current input bytes and return their canonical build identity."""
    try:
        return _prepare(artifact, base_dir)[0]
    except LocalHarnessBuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ImportError) as error:
        raise LocalHarnessBuildError('build-admission-failed:' + str(error)) from error


def _validate_cache(directory, identity):
    try:
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        if manifest['identity'] != identity:
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


def build_local_harness(artifact: LocalRuntimeArtifact, *, base_dir: Path, cache_dir: Path) -> Path:
    """Build a snapshot with one worker; atomically publish only verified output."""
    try:
        identity, snapshots = _prepare(artifact, base_dir)
        cache = Path(cache_dir).resolve()
        cache.mkdir(parents=True, exist_ok=True)
        final = cache / identity['build_digest']
        if final.exists():
            return _validate_cache(final, identity)
        stage = Path(tempfile.mkdtemp(prefix='.' + identity['build_digest'] + '-', dir=cache))
        try:
            for name, raw in snapshots.items():
                path = stage / 'inputs' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            argv = [token.replace('{BUILD}', str(stage)) for token in identity['build_argv']]
            _compile(argv, stage)
            binary = stage / 'obj/harness'
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise LocalHarnessBuildError('build-executable-missing')
            shutil.copy2(binary, stage / 'harness')
            manifest = dict(schema_version='local_harness_build_cache.v1', identity=identity,
                            binary_sha256=_digest((stage / 'harness').read_bytes()), actual_build_argv=argv)
            (stage / 'manifest.json').write_bytes(_canonical(manifest))
            if local_build_identity(artifact, base_dir=base_dir) != identity:
                raise LocalHarnessBuildError('build-inputs-changed-during-build')
            _validate_cache(stage, identity)
            try:
                stage.rename(final)
            except OSError as error:
                if error.errno not in (errno.EEXIST, errno.ENOTEMPTY) or not final.exists():
                    raise
                return _validate_cache(final, identity)
            return _validate_cache(final, identity)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    except LocalHarnessBuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ImportError) as error:
        raise LocalHarnessBuildError('local-build-failed:' + str(error)) from error
