"""Reconstruct P7 generated artifacts from copied requests and verify their bytes.

This loader never executes persisted binaries/C++ or trusts artifact.json as an
object constructor. Returned artifacts come from the current trusted renderer
and source-lock verifier. Runtime consumption and compiled semantic admission
are separate steps; loading alone grants no execution capability.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import (load_local_harness_request, plan_local_harness, render_local_driver,
               render_local_harness, render_local_runtime, verify_local_source_lock)
from .build import host_source_discovery_scope
from .runtime_artifact import LocalRuntimeArtifact


class GeneratedArtifactRefused(ValueError):
    def __init__(self, code, pointer, detail=None):
        self.code, self.pointer, self.detail = code, pointer, detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code, pointer, detail=None):
    raise GeneratedArtifactRefused(code, pointer, detail)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def _artifact_files(artifact):
    return {
        'wrapper.sv': artifact.structural.wrapper_sv.encode('utf-8'),
        'runtime.sv': artifact.runtime_sv.encode('utf-8'),
        'driver.cpp': artifact.cpp_text.encode('utf-8'),
        'artifact.json': _json_bytes(artifact.runtime_document),
        'abi.json': _json_bytes(artifact.structural.abi_document),
        'source_verification.json': _json_bytes(artifact.source_verification),
    }


def _read(path, pointer):
    if path.is_symlink() or not path.is_file():
        _refuse('generated-artifact-file-invalid', pointer, {'file': str(path)})
    try:
        return path.read_bytes()
    except OSError as error:
        _refuse('generated-artifact-file-unreadable', pointer, str(error))


def _document(path, pointer):
    raw = _read(path, pointer)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        _refuse('generated-artifact-json-invalid', pointer, str(error))
    if type(value) is not dict:
        _refuse('generated-artifact-document-required', pointer)
    return value


def _reconstruct(document, *, base_dir):
    request = load_local_harness_request(document)
    plan = plan_local_harness(request, base_dir=base_dir)
    verified = verify_local_source_lock(plan.profile, base_dir=base_dir)
    structural = render_local_harness(plan)
    runtime = render_local_runtime(plan, structural, verified, base_dir=base_dir)
    return render_local_driver(runtime, base_dir=base_dir)


def load_generated_artifacts(*, generated_root: Path,
                             base_dir: Path) -> dict[str, LocalRuntimeArtifact]:
    """Load the exact persisted harness set, failing closed on stale/changed data.

    Older generated sets without copied request.json need regeneration. The
    mutable original composition's request path is deliberately never consulted.
    Build-cache paths in harness_set.json are declarations, never executed here.
    """
    directory = Path(generated_root)
    if directory.is_symlink() or not directory.is_dir():
        _refuse('generated-artifact-directory-invalid', '/generated')
    document = _document(directory / 'harness_set.json', '/harness_set')
    rows = document.get('components')
    if (document.get('schema_version') != 'harness_set.v1'
            or type(rows) is not list or not rows):
        _refuse('generated-artifact-set-invalid', '/harness_set')
    result = {}
    with host_source_discovery_scope():
        for index, row in enumerate(rows):
            pointer = f'/components/{index}'
            if type(row) is not dict:
                _refuse('generated-artifact-component-invalid', pointer)
            instance = row.get('instance_id')
            if type(instance) is not str or not instance or instance in ('.', '..'):
                _refuse('generated-artifact-instance-invalid', pointer + '/instance_id')
            if instance in result:
                _refuse('generated-artifact-instance-duplicate', pointer + '/instance_id')
            name = row.get('harness')
            if (type(name) is not str or name != instance
                    or Path(name).name != name or '/' in name or '\\' in name):
                _refuse('generated-artifact-directory-invalid', pointer + '/harness')
            component = directory / name
            if component.is_symlink() or not component.is_dir():
                _refuse('generated-artifact-directory-invalid', pointer + '/harness')
            request = _document(component / 'request.json', pointer + '/request')
            if request.get('instance_id') != instance:
                _refuse('generated-artifact-instance-mismatch', pointer + '/request/instance_id')
            try:
                artifact = _reconstruct(request, base_dir=Path(base_dir).resolve())
            except (ValueError, OSError, RuntimeError) as error:
                _refuse('generated-artifact-reconstruction-refused', pointer + '/request', str(error))
            if artifact.plan.request.instance_id != instance:
                _refuse('generated-artifact-instance-mismatch', pointer + '/request/instance_id')
            for field in ('kind', 'artifact_digest'):
                if row.get(field) != artifact.runtime_document[field]:
                    code = ('generated-artifact-kind-mismatch' if field == 'kind'
                            else 'generated-artifact-digest-mismatch')
                    _refuse(code, pointer + '/' + field)
            for filename, expected in _artifact_files(artifact).items():
                file_pointer = pointer + '/harness/' + filename
                if _read(component / filename, file_pointer) != expected:
                    _refuse('generated-artifact-bytes-mismatch', file_pointer)
            result[instance] = artifact
    return result
