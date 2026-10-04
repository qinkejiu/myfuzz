"""Authenticate the complete scalar OpenTitan UART TL-UL boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, load_component_profile
from myfuzz.composition.source_crawler import _content_hash


_WRAPPER = 'src/myfuzz/composition/rtl/soc_opentitan_uart_local_target.sv'
_WRAPPER_SHA256 = '5991b251cf20be9a447cd4ecab0ed0643b36f4f768451a21649e9a5fe687f68b'
_UNION_REVISION = 'sha256:3c7fb0a65426581eb7e8650048b548496ef741b670933a8beacd544b2bdb4d4f'
_PROFILE_SHA256 = '759f864771b860c8d29b9005bf93ebb3b4381ec4472545de3c3e782b8697efce'


def verify_opentitan_uart_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    root = Path(base_dir).resolve()
    profile_raw = (root / 'configs/peripherals/opentitan_uart_local/component_profile.json').read_bytes()
    if hashlib.sha256(profile_raw).hexdigest() != _PROFILE_SHA256:
        raise ValueError('opentitan-uart-profile-changed')
    if load_component_profile(json.loads(profile_raw)) != profile:
        raise ValueError('opentitan-uart-profile-object-mismatch')
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_ot_uart_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('opentitan-uart-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    record = next((row for row in lock['components'] if row['id'] == 'opentitan_uart'), None)
    if record is None or (record['source_status'], record['elaboration_status'], record['closure_status']) != (
            'source_verified', 'elaboration_verified', 'selected'):
        raise ValueError('opentitan-uart-upstream-lock')
    upstream = verifier.verify_record(
        record, root, owners=verifier.document_owners(lock, root),
        allowed_roots=verifier.document_roots(lock)['opentitan_uart'], replay=False)
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('opentitan-uart-upstream-closure-changed')
    closure = json.loads(closure_raw)
    files = [arg for arg in closure['command'] if arg.startswith('third_party/soc-opentitan/')
             and arg.endswith('.sv')] + [_WRAPPER]
    includes = ['third_party/soc-opentitan/' + name for name in closure['include_roots']]
    source = profile.source_document
    if (profile.component_id != 'opentitan_uart_local' or source.get('root') != '.'
            or source.get('top_module') != 'soc_opentitan_uart_local_target'
            or source.get('top_port_selection') != 'all'
            or source.get('revision') != _UNION_REVISION
            or source.get('files') != files or source.get('include_roots') != includes
            or source.get('filelist') or source.get('repositories') or source.get('filelist_variables')
            or source.get('elaboration') != {'frontend': 'verilator-json', 'warning_policy': 'recorded-nonfatal'}):
        raise ValueError('opentitan-uart-union-source-mismatch')
    if not set('third_party/soc-opentitan/' + name for name in record['source']['files']) <= set(files):
        raise ValueError('opentitan-uart-closure-omits-top')
    wrapper = (root / _WRAPPER).resolve()
    if wrapper != root / _WRAPPER or not wrapper.is_file():
        raise ValueError('opentitan-uart-wrapper-path')
    if hashlib.sha256(wrapper.read_bytes()).hexdigest() != _WRAPPER_SHA256:
        raise ValueError('opentitan-uart-wrapper-changed')
    selected = {name: (root / name).read_bytes() for name in files}
    for directory in includes:
        for path in (root / directory).rglob('*'):
            if path.is_file() and not path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError('opentitan-uart-include-path')
                selected[path.relative_to(root).as_posix()] = path.read_bytes()
    if _content_hash(selected) != _UNION_REVISION:
        raise ValueError('opentitan-uart-union-changed')
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
