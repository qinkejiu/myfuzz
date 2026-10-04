"""Pinned upstream OpenTitan I2C and complete scalar local boundary gate."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_i2c_local_target.sv'
_WRAPPER_SHA256 = 'a9b9ff2d6caf2c357b6b292f80fe84b935b0c2a6b89fc4353a2a3cc94b782e0f'
_UNION_REVISION = 'sha256:ef1288a9a92140502b41559bac90eaf3a378baa449ddaaf435531d9f5845f405'
_PROFILE_SHA256 = 'b422b44c9011804ac7d4af47d1afe85860da6c2a7bfe055c956dc4782301317b'
_UPSTREAM_PROFILE_SHA256 = '27617164535c5f1e7033a06bae68ffcd0575d1b263070168e82fd8c008da1567'


def verify_opentitan_i2c_source_contract(profile: ComponentProfile, *,
                                          base_dir: Path) -> dict[str, object]:
    root = Path(base_dir).resolve()
    local_raw = (root / 'configs/peripherals/opentitan_i2c_local/component_profile.json').read_bytes()
    upstream_raw = (root / 'configs/peripherals/opentitan_i2c/component_profile.json').read_bytes()
    if (hashlib.sha256(local_raw).hexdigest() != _PROFILE_SHA256
            or hashlib.sha256(upstream_raw).hexdigest() != _UPSTREAM_PROFILE_SHA256
            or load_component_profile(json.loads(local_raw)) != profile):
        raise ValueError('opentitan-i2c-profile-changed')
    upstream = json.loads(upstream_raw)
    lock_raw = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(lock_raw)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_i2c_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-i2c-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components'] if row['id'] == 'opentitan_i2c'), None)
    if record is None or tuple(record[name] for name in
            ('closure_status', 'source_status', 'elaboration_status')) != (
            'selected', 'source_verified', 'elaboration_verified'):
        raise ValueError('opentitan-i2c-upstream-lock')
    upstream_verified = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_i2c'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-i2c-upstream-closure-changed')
    closure = json.loads(closure_raw)
    source_upstream = upstream['source']
    if (source_upstream['root'] != record['source']['root']
            or source_upstream['revision'] != record['source']['revision']
            or source_upstream['top_module'] != record['source']['top_module']
            or source_upstream['files'] != record['source']['files']
            or not set(source_upstream['files']) <= {
                row['path'] for row in closure['closure_files']}):
        raise ValueError('opentitan-i2c-upstream-profile-mismatch')
    expected_files = ['third_party/soc-opentitan/' + name for name in
                      source_upstream['files']] + [_WRAPPER]
    expected_includes = ['third_party/soc-opentitan/' + name for name in
                         source_upstream['include_roots']]
    source = profile.source_document
    if (profile.component_id != 'opentitan_i2c_local'
            or source.get('root') != '.'
            or source.get('revision') != _UNION_REVISION
            or source.get('top_module') != 'soc_opentitan_i2c_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('files') != expected_files
            or source.get('include_roots') != expected_includes
            or source.get('filelist') or source.get('repositories')
            or source.get('filelist_variables')
            or source.get('elaboration') != {
                'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-i2c-union-source-mismatch')
    wrapper_path = (root / _WRAPPER).resolve()
    if (wrapper_path != root / _WRAPPER
            or hashlib.sha256(wrapper_path.read_bytes()).hexdigest() != _WRAPPER_SHA256):
        raise ValueError('opentitan-i2c-wrapper-changed')
    selected = {name: (root / name).read_bytes() for name in expected_files}
    for directory in expected_includes:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-i2c-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-i2c-union-changed')
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
