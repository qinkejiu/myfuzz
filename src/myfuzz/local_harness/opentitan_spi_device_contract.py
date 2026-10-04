"""Pinned upstream OpenTitan SPI Device and complete scalar local boundary gate."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_spi_device_local_target.sv'
_WRAPPER_SHA256 = '21f27f0ff8dde9ee0ea7f61d88d60ca418d319f94e3253c7ac402c75328bdf5f'
_UNION_REVISION = 'sha256:b4f1fc98ecdbe8b9cde3666a6f667542a05eaa64b6e20cecd8ad95cfe31c78cf'
_PROFILE_SHA256 = '62cd24b2505558d9e94153ec0af242179f266c5e137545359e786e8f92dac6da'
_UPSTREAM_PROFILE_SHA256 = '34e2a3d2098261e06b93ce96c9b84cbc8360daf07bd256736d3a65d92333b0f1'


def verify_opentitan_spi_device_source_contract(profile: ComponentProfile, *,
                                          base_dir: Path) -> dict[str, object]:
    root = Path(base_dir).resolve()
    local_raw = (root / 'configs/peripherals/opentitan_spi_device_local/component_profile.json').read_bytes()
    upstream_raw = (root / 'configs/peripherals/opentitan_spi_device/component_profile.json').read_bytes()
    if (hashlib.sha256(local_raw).hexdigest() != _PROFILE_SHA256
            or hashlib.sha256(upstream_raw).hexdigest() != _UPSTREAM_PROFILE_SHA256
            or load_component_profile(json.loads(local_raw)) != profile):
        raise ValueError('opentitan-spi_device-profile-changed')
    upstream = json.loads(upstream_raw)
    lock_raw = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(lock_raw)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_spi_device_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-spi_device-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components'] if row['id'] == 'opentitan_spi_device'), None)
    if record is None or tuple(record[name] for name in
            ('closure_status', 'source_status', 'elaboration_status')) != (
            'selected', 'source_verified', 'elaboration_verified'):
        raise ValueError('opentitan-spi_device-upstream-lock')
    upstream_verified = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_spi_device'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-spi_device-upstream-closure-changed')
    closure = json.loads(closure_raw)
    source_upstream = upstream['source']
    if (source_upstream['root'] != record['source']['root']
            or source_upstream['revision'] != record['source']['revision']
            or source_upstream['top_module'] != record['source']['top_module']
            or source_upstream['files'] != record['source']['files']
            or not set(source_upstream['files']) <= {
                row['path'] for row in closure['closure_files']}):
        raise ValueError('opentitan-spi_device-upstream-profile-mismatch')
    expected_files = ['third_party/soc-opentitan/' + name for name in
                      source_upstream['files']] + [_WRAPPER]
    expected_includes = ['third_party/soc-opentitan/' + name for name in
                         source_upstream['include_roots']]
    source = profile.source_document
    if (profile.component_id != 'opentitan_spi_device_local'
            or source.get('root') != '.'
            or source.get('revision') != _UNION_REVISION
            or source.get('top_module') != 'soc_opentitan_spi_device_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('files') != expected_files
            or source.get('include_roots') != expected_includes
            or source.get('filelist') or source.get('repositories')
            or source.get('filelist_variables')
            or source.get('elaboration') != {
                'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-spi_device-union-source-mismatch')
    wrapper_path = (root / _WRAPPER).resolve()
    if (wrapper_path != root / _WRAPPER
            or hashlib.sha256(wrapper_path.read_bytes()).hexdigest() != _WRAPPER_SHA256):
        raise ValueError('opentitan-spi_device-wrapper-changed')
    selected = {name: (root / name).read_bytes() for name in expected_files}
    for directory in expected_includes:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-spi_device-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-spi_device-union-changed')
    return {
        'schema_version': 'local_source_lock_verification.v1',
        'source_status': 'source_verified',
        'elaboration_status': 'elaboration_verified',
        'upstream_record': upstream_verified,
        'wrapper_path': _WRAPPER,
        'wrapper_sha256': _WRAPPER_SHA256,
        'upstream_profile_sha256': _UPSTREAM_PROFILE_SHA256,
        'profile_union_revision': _UNION_REVISION,
        'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
        'lock_sha256': hashlib.sha256(lock_raw).hexdigest(),
    }
