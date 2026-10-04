"""Strict two-owner source gate for the local OpenTitan GPIO scalar boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_gpio_local_target.sv'
_WRAPPER_SHA256 = '8046bc87b17a50e4bc5e6effb1c7d3bd8a588a9099b0ca7d28e07ed231101443'
_UNION_REVISION = 'sha256:05655bc876b9a2ee767c0fb482b6cc10353de98302349b145708d4576c632a35'
_PROFILE_SHA256 = '8d60dcab7f1c02989ca2e1cae66217dc77b066b07804df03c852df035cd9b58c'
_UPSTREAM_PROFILE_SHA256 = '3327d4aaa4fda5376cc014fb10d306256eec7109ef77b3168bf698db5141c46d'


def verify_opentitan_gpio_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    """Authenticate upstream lock and immutable local wrapper before runtime admission."""
    root = Path(base_dir).resolve()
    upstream_path = root / 'configs/peripherals/opentitan_gpio/component_profile.json'
    profile_raw = (root / 'configs/peripherals/opentitan_gpio_local/component_profile.json').read_bytes()
    upstream_raw = upstream_path.read_bytes()
    if (hashlib.sha256(profile_raw).hexdigest() != _PROFILE_SHA256
            or hashlib.sha256(upstream_raw).hexdigest() != _UPSTREAM_PROFILE_SHA256):
        raise ValueError('opentitan-gpio-profile-changed')
    if load_component_profile(json.loads(profile_raw)) != profile:
        raise ValueError('opentitan-gpio-profile-object-mismatch')
    upstream = load_component_profile(json.loads(upstream_raw))
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_gpio_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-gpio-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components'] if row['id'] == 'opentitan_gpio'), None)
    if record is None or (record['source_status'], record['elaboration_status'], record['closure_status']) != (
            'source_verified', 'elaboration_verified', 'selected'):
        raise ValueError('opentitan-gpio-upstream-lock')
    upstream_verified = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_gpio'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-gpio-upstream-closure-changed')
    closure = json.loads(closure_raw)
    if (upstream.source.revision != record['source']['revision']
            or upstream.source.top_module != record['source']['top_module']
            or not set(upstream.source.files) <= {row['path'] for row in closure['closure_files']}):
        raise ValueError('opentitan-gpio-upstream-profile-mismatch')
    source = profile.source_document
    source_upstream = upstream.source_document
    expected_files = ['third_party/soc-opentitan/' + name for name in source_upstream['files']] + [_WRAPPER]
    expected_includes = ['third_party/soc-opentitan/' + name for name in source_upstream['include_roots']]
    if (profile.component_id != 'opentitan_gpio_local' or source.get('root') != '.'
            or source.get('top_module') != 'soc_opentitan_gpio_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('revision') != _UNION_REVISION
            or source.get('files') != expected_files
            or source.get('include_roots') != expected_includes
            or source.get('filelist') or source.get('repositories') or source.get('filelist_variables')
            or source.get('elaboration') != {'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-gpio-union-source-mismatch')
    wrapper_path = (root / _WRAPPER).resolve()
    if wrapper_path != root / _WRAPPER or not wrapper_path.is_file():
        raise ValueError('opentitan-gpio-wrapper-path')
    wrapper_sha = hashlib.sha256(wrapper_path.read_bytes()).hexdigest()
    if wrapper_sha != _WRAPPER_SHA256:
        raise ValueError('opentitan-gpio-wrapper-changed')
    # SourceCrawler hashes all declared source files and the included roots.
    # Recompute the same union here, so the local owner cannot be replaced while
    # an upstream lock record alone remains valid.
    selected = {name: (root / name).read_bytes() for name in expected_files}
    for directory in expected_includes:
        for path in (root / directory).rglob('*'):
            if path.is_file():
                if path.is_symlink():
                    continue
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-gpio-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-gpio-union-changed')
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
        'lock_sha256': hashlib.sha256(raw_lock).hexdigest(),
    }
