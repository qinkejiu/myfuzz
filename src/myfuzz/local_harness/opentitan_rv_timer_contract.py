"""Authenticate the complete scalar OpenTitan RV Timer TL-UL boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_rv_timer_local_target.sv'
_WRAPPER_SHA256 = 'bc71b23cd6e963e997b765666cb5fb61082871622ca31a5a645ef35838ff4a0c'
_UNION_REVISION = 'sha256:ebaf906367810bbd1924a792dd8d7be43314c0ea02faa81c9999c01842a83c74'
_PROFILE_SHA256 = '6517e20c07dd56b99ad097291f12a2b0e0d311fd62fce7ff5b93828f20e7c677'


def verify_opentitan_rv_timer_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    root = Path(base_dir).resolve()
    profile_raw = (root / 'configs/peripherals/opentitan_rv_timer_local/component_profile.json').read_bytes()
    if hashlib.sha256(profile_raw).hexdigest() != _PROFILE_SHA256:
        raise ValueError('opentitan-rv-timer-profile-changed')
    if load_component_profile(json.loads(profile_raw)) != profile:
        raise ValueError('opentitan-rv-timer-profile-object-mismatch')
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_rv_timer_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-rv-timer-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components'] if row['id'] == 'opentitan_rv_timer'), None)
    if record is None or (record['source_status'], record['elaboration_status'], record['closure_status']) != (
            'source_verified', 'elaboration_verified', 'selected'):
        raise ValueError('opentitan-rv-timer-upstream-lock')
    upstream = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_rv_timer'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-rv-timer-upstream-closure-changed')
    source = profile.source_document
    locked = record['source']
    files = ['third_party/soc-opentitan/' + name for name in locked['files']] + [_WRAPPER]
    includes = ['third_party/soc-opentitan/' + name for name in locked['include_roots']]
    if (profile.component_id != 'opentitan_rv_timer_local' or source.get('root') != '.'
            or source.get('top_module') != 'soc_opentitan_rv_timer_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('revision') != _UNION_REVISION
            or source.get('files') != files or source.get('include_roots') != includes
            or source.get('filelist') or source.get('repositories') or source.get('filelist_variables')
            or source.get('elaboration') != {'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-rv-timer-union-source-mismatch')
    wrapper = (root / _WRAPPER).resolve()
    if wrapper != root / _WRAPPER or not wrapper.is_file():
        raise ValueError('opentitan-rv-timer-wrapper-path')
    if hashlib.sha256(wrapper.read_bytes()).hexdigest() != _WRAPPER_SHA256:
        raise ValueError('opentitan-rv-timer-wrapper-changed')
    selected = {name: (root / name).read_bytes() for name in files}
    for directory in includes:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-rv-timer-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-rv-timer-union-changed')
    return {'schema_version': 'local_source_lock_verification.v1',
            'source_status': 'source_verified',
            'elaboration_status': 'elaboration_verified',
            'upstream_record': upstream,
            'wrapper_path': _WRAPPER,
            'wrapper_sha256': _WRAPPER_SHA256,
            'profile_sha256': _PROFILE_SHA256,
            'profile_union_revision': _UNION_REVISION,
            'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
            'lock_sha256': hashlib.sha256(raw_lock).hexdigest()}
