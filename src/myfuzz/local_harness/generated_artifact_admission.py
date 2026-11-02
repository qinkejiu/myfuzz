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
                             base_dir: Path, flow=None) -> dict[str, LocalRuntimeArtifact]:
    """Load the exact persisted harness set, failing closed on stale/changed data.

    Older generated sets without copied request.json need regeneration. The
    mutable original composition's request path is deliberately never consulted.
    Build-cache paths in harness_set.json are declarations, never executed here.
    """
    directory = Path(generated_root)
    if directory.is_symlink() or not directory.is_dir():
        _refuse('generated-artifact-directory-invalid', '/generated')
    document = _document(directory / 'harness_set.json', '/harness_set')
    schema = document.get('schema_version')
    wiring = document.get('wiring')
    route_bearing = (
        (isinstance(wiring, dict)
            and (wiring.get('schema_version') == 'wiring_contract.v2'
                 or 'dma_master_routes' in wiring))
        or 'dma_master_routes' in document
    )
    if flow not in (None,'F6'):
        _refuse('generated-artifact-flow-unsupported','/flow')
    if route_bearing and flow!='F6':
        _refuse('generated-artifact-route-intent-unsupported',
                '/wiring/dma_master_routes')
    rows = document.get('components')
    if (schema != ('harness_set.v2' if flow=='F6' else 'harness_set.v1')
            or (flow=='F6' and not route_bearing)
            or type(rows) is not list or not rows):
        _refuse('generated-artifact-set-invalid', '/harness_set')
    result = {}
    credentials={}
    loaded_pins={}
    initiator=None
    if flow=='F6':
        from .dma_artifact_endpoint_links import PROVIDER_ID
        from myfuzz.scenario.compiled_paths import load_path_wiring
        parsed=load_path_wiring(wiring)
        initiators={route.initiator_instance for route in parsed.dma_master_routes}
        if len(initiators)!=1:
            _refuse('generated-artifact-f6-initiator-required','/wiring/dma_master_routes')
        initiator=next(iter(initiators))
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
                if flow=='F6' and instance==initiator:
                    linked=_reconstruct_f6_linked(request,base_dir=Path(base_dir).resolve())
                    artifact=linked.artifact
                    expected=linked.endpoint_links_document()
                    metadata=dict(filename='dma_endpoint_links.v1.json',provider_id=PROVIDER_ID,
                        identity_sha256=expected['identity_sha256'])
                    if row.get('dma_endpoint_links')!=metadata:
                        _refuse('generated-artifact-f6-provider-identity-mismatch',pointer+'/dma_endpoint_links')
                    sidecar=_document(component/'dma_endpoint_links.v1.json',pointer+'/dma_endpoint_links')
                    from .dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
                    validated=validate_dma_artifact_endpoint_links(sidecar,artifact).document()
                    if (_read(component/'dma_endpoint_links.v1.json',pointer+'/dma_endpoint_links')!=_json_bytes(expected)
                            or validated!=expected):
                        _refuse('generated-artifact-f6-provider-bytes-mismatch',pointer+'/dma_endpoint_links')
                    credentials[instance]=validated
                    from hashlib import sha256
                    loaded_pins[str(component/'dma_endpoint_links.v1.json')]=sha256(_json_bytes(expected)).hexdigest()
                else:
                    if flow=='F6' and ('dma_endpoint_links' in row or (component/'dma_endpoint_links.v1.json').exists()):
                        _refuse('generated-artifact-f6-provider-instance-mismatch',pointer+'/dma_endpoint_links')
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
            if flow=='F6':
                from hashlib import sha256
                for filename,payload in dict(_artifact_files(artifact),**{'request.json':_json_bytes(request)}).items():
                    loaded_pins[str(component/filename)]=sha256(payload).hexdigest()
            result[instance] = artifact
    if flow=='F6':
        if set(credentials)!={initiator}:
            _refuse('generated-artifact-f6-provider-required','/components')
        from hashlib import sha256
        loaded_pins[str(directory/'harness_set.json')]=sha256(_json_bytes(document)).hexdigest()
        _retain_f6_provider_credentials(result,credentials,loaded_pins)
    return result


def _reconstruct_f6_linked(document,*,base_dir):
    from .dma_artifact_endpoint_links import render_dma_linked_runtime,PROVIDER_ID
    request=load_local_harness_request(document)
    plan=plan_local_harness(request,base_dir=base_dir)
    verified=verify_local_source_lock(plan.profile,base_dir=base_dir)
    structural=render_local_harness(plan)
    return render_dma_linked_runtime(plan,structural,verified,base_dir=base_dir,provider_id=PROVIDER_ID)


def _f6_provider_registry():
    from threading import RLock
    records={}
    lock=RLock()
    def retain(artifacts,credentials,pins):
        identities=tuple(sorted(artifacts))
        references=tuple(artifacts[name] for name in identities)
        with lock:
            records[id(artifacts)]=(artifacts,identities,references,_json_bytes(credentials),dict(pins))
    def checked(artifacts,include_files):
        row=records.get(id(artifacts))
        if row is None or row[0] is not artifacts or row[1]!=tuple(sorted(artifacts)) or any(
                reference is not artifacts[name] for name,reference in zip(row[1],row[2])):
            _refuse('generated-artifact-f6-same-call-provider-required','/artifacts')
        from .dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
        from hashlib import sha256
        for filename,digest in row[4].items():
            path=Path(filename)
            if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest()!=digest:
                _refuse('generated-artifact-f6-loaded-bytes-changed','/artifacts',{'file':filename})
        documents=json.loads(row[3])
        for name,document in documents.items():
            validate_dma_artifact_endpoint_links(document,artifacts[name])
        return {'credentials':documents,'file_pins':dict(row[4])} if include_files else documents
    def capture(artifacts,*,include_files=False):
        with lock:return checked(artifacts,include_files)
    def release(artifacts):
        with lock:
            row=records.get(id(artifacts))
            if row is not None and row[0] is artifacts:records.pop(id(artifacts))
    return retain,capture,release

_retain_f6_provider_credentials,validated_f6_provider_credentials,release_f6_provider_credentials=_f6_provider_registry()
