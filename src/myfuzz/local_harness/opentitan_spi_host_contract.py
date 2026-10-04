"""Authenticate the pinned OpenTitan SPI Host scalar TL-UL boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_PROFILE = 'configs/peripherals/opentitan_spi_host_local/component_profile.json'
_PROFILE_SHA = '65a5f5ee4f1bb950b042e86a729645f304789f84d2adefb2edce2ffb72bc523e'
_SCALAR = 'src/myfuzz/composition/rtl/soc_opentitan_spi_host_local_target.sv'
_SCALAR_SHA = '50b78c41f06cbff38773c4071728fdaf6644fbaa6f160f7c39b6e7597a49faa9'
_CLOSURE = 'configs/peripherals/opentitan_spi_host/closure_wrapper.sv'
_CLOSURE_SHA = 'cb6d50cb5f149aaf6bb244ef77aef6a7b2fe65a03dcb808f4b0c06e5cddd9d35'
_UNION_REVISION = 'sha256:24675362f3be641518b8f6f0ba8009df3e3dd49454bfad2316134a6ea3214952'


def verify_opentitan_spi_host_source_contract(profile: ComponentProfile, *,
                                              base_dir: Path) -> dict[str, object]:
    root = Path(base_dir).resolve()
    raw_profile = (root / _PROFILE).read_bytes()
    if hashlib.sha256(raw_profile).hexdigest() != _PROFILE_SHA:
        raise ValueError('opentitan-spi-host-profile-changed')
    if load_component_profile(json.loads(raw_profile)) != profile:
        raise ValueError('opentitan-spi-host-profile-object-mismatch')
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_spi_host_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-spi-host-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components']
                   if row['id'] == 'opentitan_spi_host'), None)
    if record is None or (record['source_status'], record['elaboration_status'],
                          record['closure_status']) != (
                              'source_verified', 'elaboration_verified', 'selected'):
        raise ValueError('opentitan-spi-host-upstream-lock')
    upstream = verifier.verify_record(record, root,
        owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_spi_host'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-spi-host-upstream-closure-changed')
    prefix = 'third_party/soc-opentitan/'
    files = [prefix + name for name in record['source']['files']] + [_CLOSURE, _SCALAR]
    includes = [prefix + name for name in record['source']['include_roots']]
    source = profile.source_document
    if (profile.component_id != 'opentitan_spi_host_local'
            or source.get('root') != '.' or source.get('top_module') !=
            'soc_opentitan_spi_host_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('revision') != _UNION_REVISION
            or source.get('files') != files or source.get('include_roots') != includes
            or source.get('filelist') or source.get('repositories')
            or source.get('filelist_variables')
            or source.get('elaboration') != {
                'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-spi-host-union-source-mismatch')
    for name, expected in ((_SCALAR, _SCALAR_SHA), (_CLOSURE, _CLOSURE_SHA)):
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('opentitan-spi-host-wrapper-changed:' + name)
    selected = {name: (root / name).read_bytes() for name in files}
    for directory in includes:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-spi-host-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-spi-host-union-changed')
    return {'schema_version': 'local_source_lock_verification.v1',
            'source_status': 'source_verified',
            'elaboration_status': 'elaboration_verified',
            'upstream_record': upstream,
            'wrapper_paths': [_CLOSURE, _SCALAR],
            'wrapper_sha256': [_CLOSURE_SHA, _SCALAR_SHA],
            'profile_sha256': _PROFILE_SHA,
            'profile_union_revision': _UNION_REVISION,
            'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
            'lock_sha256': hashlib.sha256(raw_lock).hexdigest()}
