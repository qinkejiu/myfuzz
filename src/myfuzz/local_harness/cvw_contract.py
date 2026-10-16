"""Authenticate the CVW local profile, its typed top and its closure.

CVW is a *local* component in the same sense as ``ibex_rvfi_local`` and the
``opentitan_*_local`` profiles: its declared source root is the repository itself
(``root: "."``) with a content-hash pin, so it cannot be a record in
``configs/soc/sources.lock.json`` - that lock requires every closure root to be
owned by a ``git:`` revision (``scripts/verify_soc_sources.py``:
``unpinned-closure-root``).  Local components therefore authenticate through a
verifier like this one, which pins the repository-authored bytes by hash and lets
the *upstream* half be proven by an existing git-pinned record.

For CVW the split is:

* ``third_party/cvw_upstream_reference`` is a git checkout of the pinned CORE-V
  Wally revision.  Each file this profile reads from it is checked against the
  closure's recorded hash, and the checkout's revision is checked directly.
* ``configs/cpus/cvw/cvw_ahb_cpu_top.sv`` is **repository-authored**: it exists
  because ``wallypipelinedsoc`` takes ``#(parameter cvw_t P)``, a struct-typed
  localparam that no command line can supply.  It is pinned by hash here.
* ``configs/cpus/cvw/config_extmem/config.vh`` is **derived** from the pinned
  upstream configuration by ``scripts/derive_cvw_config.py``: it switches on
  ``EXT_MEM_SUPPORTED`` and moves the external-memory region off
  ``UNCORE_RAM_BASE``.  Upstream leaves ``EXT_MEM_SUPPORTED = 0`` in *every*
  committed configuration, so without this the AHB-Lite port is unreachable no
  matter what the core drives (``adrdec``:
  ``Sel = Match & Supported & AccessValid & SizeValid``).  It is pinned here, and
  the profile's content pin covers its 243-file read set, so it cannot drift
  silently.
* ``configs/cpus/cvw/component_profile.json`` and
  ``configs/soc/closures/cvw.json`` are pinned by hash so neither can drift
  without this module being updated deliberately.

Why the closed vocabulary of pinned hashes rather than trusting the profile: a
verifier that reads its expectations from the artifact it is verifying proves
nothing.  The three constants below are the whole point of this module.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.source_crawler import _content_hash

_PROFILE_PATH = 'configs/cpus/cvw/component_profile.json'
_CLOSURE_PATH = 'configs/soc/closures/cvw.json'
_WRAPPER_PATH = 'configs/cpus/cvw/cvw_ahb_cpu_top.sv'
_CONFIG_PATH = 'configs/cpus/cvw/config_extmem/config.vh'
_UPSTREAM_ROOT = 'third_party/cvw_upstream_reference'

_PROFILE_SHA256 = 'b3c784db4e5de83e0def8948e19c179217a42fd002403d5c9d36a438a0cfae59'
_CLOSURE_SHA256 = 'fca21c680d48ae6647931adb430a6fe7756f563105ee5a59d486e0e7fa7c0bc9'
_WRAPPER_SHA256 = '792f2d6a8ff71b959253b8e36c9fcb7c728c0702500d09550915762e55ebdba8'
_CONFIG_SHA256 = '69d7d6e05ad64dd09df8640fc5bf8b82bc401aab29d5e57de229656c9d8edf76'

#: The upstream revision the closure's non-local entries must belong to.
_UPSTREAM_REVISION = '2f2ddfd4c3c7f5d3a655e4488831d9277673105a'


def _read_pinned(root: Path, relative: str, expected: str, code: str) -> bytes:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(code + '-missing')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(code + '-changed')
    return raw


def verify_cvw_source_contract(profile, *, base_dir: Path) -> dict:
    """Authenticate the CVW profile, wrapper and closure, then the union pin."""
    root = Path(base_dir).resolve()
    raw = _read_pinned(root, _PROFILE_PATH, _PROFILE_SHA256, 'cvw-profile')
    if load_component_profile(json.loads(raw)) != profile:
        raise ValueError('cvw-profile-object-mismatch')
    closure_raw = _read_pinned(root, _CLOSURE_PATH, _CLOSURE_SHA256, 'cvw-closure')
    _read_pinned(root, _WRAPPER_PATH, _WRAPPER_SHA256, 'cvw-wrapper')
    config_raw = _read_pinned(root, _CONFIG_PATH, _CONFIG_SHA256, 'cvw-config').decode('utf-8')
    # The pinned bytes must still say what the derivation promised: a hash alone
    # would happily pin a configuration that had switched the feature back off.
    if 'localparam logic EXT_MEM_SUPPORTED = 1;' not in config_raw:
        raise ValueError('cvw-config-external-memory-disabled')
    if "localparam logic [63:0] EXT_MEM_BASE     = 64'hC0000000;" not in config_raw:
        raise ValueError('cvw-config-external-memory-base')
    if 'DERIVED FILE - DO NOT EDIT BY HAND' not in config_raw:
        raise ValueError('cvw-config-not-derived')
    closure = json.loads(closure_raw)
    if closure.get('status') != 'elaboration_verified':
        raise ValueError('cvw-elaboration-unverified')
    lint = closure.get('lint') or {}
    if lint.get('exit_code') != 0 or lint.get('errors') != 0:
        raise ValueError('cvw-elaboration-lint-failed')
    if closure.get('top_module') != profile.source.top_module:
        raise ValueError('cvw-top-module-mismatch')

    # Every file this profile reads must be recorded in the closure with that
    # hash, and every upstream entry must live under the pinned checkout.
    recorded = {}
    for item in closure.get('closure_files') or []:
        if not isinstance(item, dict):
            raise ValueError('cvw-closure-entry-invalid')
        recorded[item.get('path')] = item.get('sha256')
    # The pin covers what elaboration actually read, not "every file under the
    # include roots": config/ also holds non-HDL files (act/*.yaml, README,
    # imperas*.ic) that no compiler opens, and ibex_rvfi_local's union happened to
    # coincide with its read set while CVW's does not.  Re-running the elaboration
    # is the only way to know the read set rather than guess it.
    import tempfile

    from myfuzz.composition.source_elaboration import run_verilator_elaboration

    settings = profile.source.elaboration
    if settings is None:
        raise ValueError('cvw-elaboration-settings-missing')
    files = tuple(profile.source_document['files'])
    include_roots = tuple(profile.source_document['include_roots'])
    with tempfile.TemporaryDirectory(prefix='.cvw-verify-', dir=root) as temporary:
        run_verilator_elaboration(
            source_root=root, top_module=profile.source.top_module,
            source_files=files, include_roots=include_roots,
            defines=settings.defines, parameters=settings.parameters,
            warning_policy=settings.warning_policy, selected_top_ports=None,
            output_dir=Path(temporary) / 'evidence')
        manifest = json.loads(
            (Path(temporary) / 'evidence' / 'manifest.json').read_text(encoding='utf-8'))
    selected = {}
    labels = set()
    for record in manifest.get('sources') or []:
        label = record.get('file')
        if not isinstance(label, str) or label in labels:
            raise ValueError('cvw-elaboration-manifest-invalid')
        labels.add(label)
        path = root / label
        if path.is_symlink() or not path.is_file():
            raise ValueError('cvw-elaboration-source-missing:' + label)
        if recorded.get(label) != hashlib.sha256(path.read_bytes()).hexdigest():
            # Upstream files must be recorded in the closure; the authored wrapper
            # is recorded there too, and both are checked above.
            raise ValueError('cvw-elaboration-source-not-in-closure:' + label)
        selected[label] = path.read_bytes()
    if _content_hash(selected) != profile.source.revision:
        raise ValueError('cvw-union-changed')

    # The upstream half is proven by its git identity, not only by hashes: a
    # checkout that has moved off the pinned revision must be visible here.
    import subprocess

    head = subprocess.run(['git', '-C', str(root / _UPSTREAM_ROOT),
                           'rev-parse', 'HEAD'],
                          capture_output=True, text=True, check=False)
    if head.returncode != 0 or head.stdout.strip() != _UPSTREAM_REVISION:
        raise ValueError('cvw-upstream-revision-mismatch')

    # The lock's own bytes are reported by hash even though CVW has no record in
    # it: the lock is a real artifact this verification depends on, and callers
    # expect this key (see source_lock.verify_local_source_lock's return shape).
    elaboration_block = {
        'status': 'elaboration_verified',
        'top_module': profile.source.top_module,
        'tool': dict(closure.get('tool') or {}),
        'evidence': _CLOSURE_PATH,
        'evidence_sha256': _CLOSURE_SHA256,
    }
    lock_raw = (root / 'configs/soc/sources.lock.json').read_bytes()
    return {
        'schema_version': 'local_source_lock_verification.v1',
        'lock_sha256': hashlib.sha256(lock_raw).hexdigest(),
        'source_records': [{'path': item['path'], 'sha256': item['sha256']}
                           for item in [{'path': _WRAPPER_PATH,
                                         'sha256': _WRAPPER_SHA256}]],
        # The build gate reads this record's elaboration evidence, so the record
        # must carry the same block the lock format expects.  CVW has no lock
        # record of its own (the lock requires git-pinned closure roots), so the
        # block is supplied here from the closure this verifier just pinned.
        'closure_record': {
            'id': profile.component_id,
            'source': dict(profile.source_document),
            'elaboration': dict(elaboration_block),
        },
        'source_status': 'source_verified',
        'elaboration_status': 'elaboration_verified',
        'component_id': profile.component_id,
        'profile_sha256': _PROFILE_SHA256,
        'profile_union_revision': profile.source.revision,
        'wrapper_path': _WRAPPER_PATH,
        'wrapper_sha256': _WRAPPER_SHA256,
        'closure_sha256': _CLOSURE_SHA256,
        'upstream_root': _UPSTREAM_ROOT,
        'upstream_revision': _UPSTREAM_REVISION,
        'derived_config_path': _CONFIG_PATH,
        'derived_config_sha256': _CONFIG_SHA256,
        'authenticated_inputs': [
            {'path': _CONFIG_PATH, 'sha256': _CONFIG_SHA256},
            {'path': _PROFILE_PATH, 'sha256': _PROFILE_SHA256},
            {'path': _WRAPPER_PATH, 'sha256': _WRAPPER_SHA256},
            {'path': _CLOSURE_PATH, 'sha256': _CLOSURE_SHA256},
        ],
        'selected_files': len(selected),
    }
