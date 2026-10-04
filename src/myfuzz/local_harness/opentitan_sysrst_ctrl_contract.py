"""Pinned source and scalar-boundary contract for OpenTitan sysrst_ctrl."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_sysrst_ctrl_local_target.sv'
_WRAPPER_SHA256 = 'a9d0bdcf6099a973506bdb3a0b2a37c9844a85283f5842fe1c42d67796bd51c2'
_PROFILE_SHA256 = '13ec68a71a3f7783a3c845400f1bc478c61d8fea33bcd81ab9d3011b077e00cd'
_UPSTREAM_PROFILE_SHA256 = 'cfa210c707f148915080a20b6183cc922b0cb6744dea8712bfdb6e5ed5a4a8d7'
_UNION_REVISION = 'sha256:8d7697c7ddb2c435e71e5899630f9da926eac3ca8dce785e7464d1803ae33a42'


def verify_opentitan_sysrst_ctrl_source_contract(
        profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    """Authenticate the pinned upstream closure and local scalar wrapper."""
    root = Path(base_dir).resolve()
    upstream_path = root / 'configs/peripherals/opentitan_sysrst_ctrl/component_profile.json'
    local_path = root / 'configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json'
    upstream_raw = upstream_path.read_bytes()
    local_raw = local_path.read_bytes()
    if (hashlib.sha256(upstream_raw).hexdigest() != _UPSTREAM_PROFILE_SHA256
            or hashlib.sha256(local_raw).hexdigest() != _PROFILE_SHA256):
        raise ValueError('opentitan-sysrst-ctrl-profile-changed')
    if load_component_profile(json.loads(local_raw)) != profile:
        raise ValueError('opentitan-sysrst-ctrl-profile-object-mismatch')
    upstream = load_component_profile(json.loads(upstream_raw))

    lock_raw = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(lock_raw)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_sysrst_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-sysrst-ctrl-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components']
                   if row['id'] == 'opentitan_sysrst_ctrl'), None)
    if record is None or (record['source_status'], record['elaboration_status'],
                          record['closure_status']) != (
            'source_verified', 'elaboration_verified', 'selected'):
        raise ValueError('opentitan-sysrst-ctrl-upstream-lock')
    upstream_verified = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_sysrst_ctrl'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-sysrst-ctrl-closure-changed')
    closure = json.loads(closure_raw)
    closure_paths = {row['path'] for row in closure['closure_files']
                     if row['root'] == 'third_party/soc-opentitan'}
    if (upstream.source.revision != record['source']['revision']
            or upstream.source.top_module != record['source']['top_module']
            or not set(upstream.source.files) <= closure_paths):
        raise ValueError('opentitan-sysrst-ctrl-upstream-profile-mismatch')

    source = profile.source_document
    upstream_source = upstream.source_document
    expected_files = [
        'third_party/soc-opentitan/' + name for name in upstream_source['files']
    ] + [_WRAPPER]
    expected_includes = [
        'third_party/soc-opentitan/' + name for name in upstream_source['include_roots']
    ]
    if (profile.component_id != 'opentitan_sysrst_ctrl_local'
            or source.get('root') != '.'
            or source.get('top_module') != 'soc_opentitan_sysrst_ctrl_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('revision') != _UNION_REVISION
            or source.get('files') != expected_files
            or source.get('include_roots') != expected_includes
            or source.get('filelist') or source.get('repositories')
            or source.get('filelist_variables')
            or source.get('elaboration') != {
                'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-sysrst-ctrl-union-source-mismatch')

    wrapper = (root / _WRAPPER).resolve()
    if wrapper != root / _WRAPPER or not wrapper.is_file():
        raise ValueError('opentitan-sysrst-ctrl-wrapper-path')
    wrapper_sha = hashlib.sha256(wrapper.read_bytes()).hexdigest()
    if wrapper_sha != _WRAPPER_SHA256:
        raise ValueError('opentitan-sysrst-ctrl-wrapper-changed')
    wrapper_text = wrapper.read_text()
    if (not re.search(r'\.rst_req_o\s*,', wrapper_text)
            or re.search(r'\.rst_(?:aon_)?ni\s*\(\s*rst_req_o\s*\)', wrapper_text)
            or re.search(r'assign\s+rst_(?:aon_)?ni\s*=\s*rst_req_o', wrapper_text)):
        raise ValueError('opentitan-sysrst-ctrl-reset-feedback')

    selected = {name: (root / name).read_bytes() for name in expected_files}
    for directory in expected_includes:
        for path in (root / directory).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            if not path.resolve().is_relative_to(root):
                raise ValueError('opentitan-sysrst-ctrl-include-path')
            selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-sysrst-ctrl-union-changed')

    return {
        'schema_version': 'local_source_lock_verification.v1',
        'source_status': 'source_verified',
        'elaboration_status': 'elaboration_verified',
        'upstream_record': upstream_verified,
        'wrapper_path': _WRAPPER,
        'wrapper_sha256': wrapper_sha,
        'upstream_profile_sha256': _UPSTREAM_PROFILE_SHA256,
        'profile_union_revision': _UNION_REVISION,
        'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
        'lock_sha256': hashlib.sha256(lock_raw).hexdigest(),
    }
