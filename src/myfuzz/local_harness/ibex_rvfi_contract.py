"""Authenticate version 1 complete RVFI wrapper and its actual upstream pin."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.source_crawler import _content_hash

_PROFILE_SHA256 = 'aa73e0a5dd6052a50368eb8078199f3ec9f8f50e2de1ae27fc1ce04423e8d514'
_WRAPPER_SHA256 = 'e9bfa7595201a4205204afc23eff2b904428d2fb53f7f8200743ce4932cbf6c3'
_SIDEBAND_PATH = 'src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv'
_SIDEBAND_SHA256 = '516c51bce5a9434e7ea018fe437dc36570677d80c3e3c89b669387e144b65120'
_CLOSURE_SHA256 = 'd52dfecda5ac3d0e5fafec95822f68c8f69d5daaa3adf9840621e6666dce065e'

def verify_ibex_rvfi_source_contract(profile, *, base_dir: Path) -> dict:
    from .source_lock import verify_local_source_lock
    root = Path(base_dir).resolve()
    raw = (root / 'configs/cpus/ibex_rvfi_local/component_profile.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != _PROFILE_SHA256 or load_component_profile(json.loads(raw)) != profile:
        raise ValueError('ibex-rvfi-profile-changed')
    upstream = verify_local_source_lock(load_component_profile(root / 'configs/cpus/ibex_obi_local/component_profile.json'), base_dir=root)
    closure_raw = (root / 'configs/soc/closures/ibex_rvfi_local.json').read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != _CLOSURE_SHA256:
        raise ValueError('ibex-rvfi-closure-changed')
    closure = json.loads(closure_raw)
    if closure['lint']['exit_code'] != 0:
        raise ValueError('ibex-rvfi-elaboration-unverified')
    wrapper = root / closure['wrapper']
    if wrapper.is_symlink() or hashlib.sha256(wrapper.read_bytes()).hexdigest() != _WRAPPER_SHA256:
        raise ValueError('ibex-rvfi-wrapper-changed')
    sideband = root / _SIDEBAND_PATH
    if sideband.is_symlink() or hashlib.sha256(sideband.read_bytes()).hexdigest() != _SIDEBAND_SHA256:
        raise ValueError('ibex-rvfi-sideband-changed')
    local_rtl = {item['path']: item['sha256'] for item in closure['files']
                 if isinstance(item, dict) and not str(item.get('path', '')).startswith('third_party/')}
    if (local_rtl.get(closure['wrapper']) != _WRAPPER_SHA256
            or local_rtl.get(_SIDEBAND_PATH) != _SIDEBAND_SHA256):
        raise ValueError('ibex-rvfi-local-rtl-record-changed')
    selected = {}
    for name in profile.source_document['files']:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('ibex-rvfi-source-path')
        selected[name] = path.read_bytes()
    for directory in profile.source_document['include_roots']:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('ibex-rvfi-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != profile.source.revision:
        raise ValueError('ibex-rvfi-union-changed')
    lock = json.loads((root / 'configs/soc/sources.lock.json').read_bytes())
    upstream_record = next(row for row in lock['components'] if row['id'] == 'ibex_obi_local')
    authenticated_inputs = [
        {'path': closure['wrapper'], 'sha256': _WRAPPER_SHA256},
        {'path': _SIDEBAND_PATH, 'sha256': _SIDEBAND_SHA256},
        {'path': 'configs/soc/closures/ibex_rvfi_local.json', 'sha256': _CLOSURE_SHA256},
        {'path': 'configs/cpus/ibex_obi_local/component_profile.json',
         'sha256': hashlib.sha256((root / 'configs/cpus/ibex_obi_local/component_profile.json').read_bytes()).hexdigest()}]
    return {'closure_record': upstream_record, 'authenticated_inputs': authenticated_inputs,
            'schema_version': 'local_source_lock_verification.v1',
            'source_status': 'source_verified', 'elaboration_status': 'elaboration_verified',
            'upstream_record': upstream, 'official_revision': closure['official_revision'],
            'wrapper_path': closure['wrapper'], 'wrapper_sha256': _WRAPPER_SHA256,
            'profile_sha256': _PROFILE_SHA256, 'profile_union_revision': profile.source.revision,
            'closure_sha256': _CLOSURE_SHA256, 'lock_sha256': upstream['lock_sha256']}
