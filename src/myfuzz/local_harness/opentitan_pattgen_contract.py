"""Authenticate pattgen's fixed scalar profile and local elaboration closure."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_DIRECTORY = 'configs/peripherals/opentitan_pattgen_local/'
_PROFILE = _DIRECTORY + 'component_profile.json'
_CLOSURE = _DIRECTORY + 'closure.json'
_CLOSURE_SHA256 = '19dc868a02eb65454f0dea54a477b93dd418b6ad0dacb5d7d2c78df49281a291'


def verify_opentitan_pattgen_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    """Accept exactly the reviewed profile, include union and successful lint.

    pattgen has no entry in the existing SoC source lock. Its independent closure
    is pinned here and can be snapshotted by the same generated build pipeline.
    The global lock hash remains part of the existing build receipt identity.
    """
    root = Path(base_dir).resolve()

    def read(name):
        path = root / name
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            raise ValueError('opentitan-pattgen-source-path:' + name)
        return path.read_bytes()

    closure_raw = read(_CLOSURE)
    if hashlib.sha256(closure_raw).hexdigest() != _CLOSURE_SHA256:
        raise ValueError('opentitan-pattgen-closure-changed')
    closure = json.loads(closure_raw)
    profile_raw = read(_PROFILE)
    if load_component_profile(json.loads(profile_raw)) != profile:
        raise ValueError('opentitan-pattgen-profile-object-mismatch')
    if hashlib.sha256(profile_raw).hexdigest() != closure['profile_sha256']:
        raise ValueError('opentitan-pattgen-profile-changed')
    source = profile.source_document
    command = ['verilator', '--lint-only', '-Wno-fatal', '--top-module', source['top_module'],
               *('-I' + name for name in source['include_roots']), *source['files']]
    if (closure['schema_version'] != 'pinned_local_source_closure.v1'
            or closure['component_id'] != profile.component_id
            or closure['source_revision'] != source['revision']
            or closure['top_module'] != source['top_module']
            or closure['command'] != command or closure['returncode'] != 0):
        raise ValueError('opentitan-pattgen-elaboration-mismatch')
    selected = {}
    for row in closure['closure_files']:
        raw = read(row['path'])
        if row['root'] != '.' or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('opentitan-pattgen-source-changed:' + row['path'])
        selected[row['path']] = raw
    paths = set(source['files'])
    for directory in source['include_roots']:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                paths.add(path.relative_to(root).as_posix())
    if set(selected) != paths or _content_hash(selected) != source['revision']:
        raise ValueError('opentitan-pattgen-union-changed')
    if hashlib.sha256(read(closure['log_path'])).hexdigest() != closure['log_sha256']:
        raise ValueError('opentitan-pattgen-elaboration-log-changed')
    lock_raw = read('configs/soc/sources.lock.json')
    return {'schema_version': 'local_source_lock_verification.v1',
            'source_status': 'source_verified', 'elaboration_status': 'elaboration_verified',
            'profile_union_revision': source['revision'],
            'closure_sha256': _CLOSURE_SHA256,
            'lock_sha256': hashlib.sha256(lock_raw).hexdigest(),
            'closure_record': {'id': profile.component_id, 'elaboration': {
                'evidence': _CLOSURE, 'evidence_sha256': _CLOSURE_SHA256}},
            'authenticated_inputs': [{'path': closure['log_path'],
                                      'sha256': closure['log_sha256']}]}
