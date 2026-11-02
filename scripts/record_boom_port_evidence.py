"""Record BOOM's pinned elaboration closure and its port evidence.

Why this script exists
----------------------
The derived ``BoomTile`` top is 17.96 MB.  A *lint* of it is cheap (Verilator
parses it in seconds), but the bounded JSON walker that turns a Verilator syntax
tree into port facts refuses it by policy
(``myfuzz.composition.source_elaboration._MAX_AST_NODES``).  The derivation
already publishes the structured port artifact
(``configs/cpus/boom/generated/source_manifest.json`` ->
``../evidence/derived-20261017/physical_ports.json``), so the closure this script
writes records BOTH:

* the ordinary frontend fact every other component records - the exact
  ``verilator --lint-only`` command, its tool version, its warning/error counts
  and the digest of every file it read;
* a ``port_evidence`` section carrying the published port rows, and the digests
  of the artifact and of the manifest that declares it.

``scripts/verify_soc_sources.py`` then re-derives the top module's declared
ports from the *pinned bytes* with the bounded text parser the crawler already
uses and requires an exact match, so the stored artifact is authenticated rather
than trusted.  The generation source pin itself is checked here by
``myfuzz.composition.stored_elaboration`` - the same code the D2 path uses - so
there is exactly one implementation of that rule.

Idempotent: re-running rewrites the same bytes for unchanged sources.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

_ROOT = Path(__file__).resolve().parents[1]
CLOSURE = Path('configs/soc/closures/boom.json')
COMPONENT = 'boom'
PROFILE = Path('configs/cpus/boom/component_profile.json')
SOURCE_ROOT = Path('configs/cpus/boom/generated')
LICENSE = Path('configs/cpus/boom/generated/LICENSE')


def _digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _verifier_module():
    """Load the trusted verifier beside this script, never from base_dir."""
    path = Path(__file__).with_name('verify_soc_sources.py')
    spec = importlib.util.spec_from_file_location('_myfuzz_boom_closure', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(_ROOT / PROFILE)


def _lint(root: Path, files: list[str], top_module: str) -> tuple[list[str], dict]:
    version = subprocess.run(['verilator', '--version'], capture_output=True,
                             text=True, check=False)
    if version.returncode != 0:
        raise SystemExit('verilator is required to record the closure')
    command = ['verilator', '--lint-only', '-Wno-fatal', '--top-module', top_module,
               *files]
    result = subprocess.run(command, cwd=str(root), capture_output=True, text=True,
                            check=False)
    diagnostics = (result.stdout or '') + (result.stderr or '')
    errors = diagnostics.count('%Error')
    warnings = diagnostics.count('%Warning')
    if result.returncode != 0 or errors:
        raise SystemExit('lint failed:\n' + diagnostics[-2000:])
    return command, {'name': 'verilator', 'version': version.stdout.strip(),
                     'frontend': 'verilator-lint'}, {
        'errors': errors, 'warnings': warnings, 'exit_code': result.returncode}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--write', action='store_true',
                        help='write the closure file (default: print it)')
    args = parser.parse_args(argv)
    sys.path.insert(0, str(_ROOT / 'src'))
    from myfuzz.composition.stored_elaboration import stored_elaboration_facts
    from myfuzz.composition.source_crawler import source_tree_hash

    profile = _profile()
    facts = stored_elaboration_facts(profile, base_dir=_ROOT)
    if facts is None:
        raise SystemExit('the component publishes no stored port evidence')
    verifier = _verifier_module()
    source_root = (_ROOT / SOURCE_ROOT).resolve()
    manifest_path = source_root / 'source_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    # ``physical_ports`` is declared relative to the manifest's own directory
    # (``generated/../evidence/...``), exactly as the manifest is written.
    artifact_path = (source_root / Path(manifest['physical_ports'])).resolve()
    artifact_raw = artifact_path.read_bytes()
    if _digest(artifact_raw) != manifest['physical_ports_sha256']:
        raise SystemExit('stored port artifact digest does not match its manifest')

    declared = [row['path'] for row in manifest['files']]
    if declared != list(profile.source.files):
        raise SystemExit('manifest file order differs from the profile declaration')
    files = [f'{SOURCE_ROOT.as_posix()}/{name}' for name in declared]
    command, tool, lint = _lint(_ROOT, files, profile.source.top_module)
    selected = source_tree_hash(source_root, [source_root / name for name in declared])

    rows = sorted([port.name, port.direction, port.width] for port in facts.ports)
    closure = {
        'schema_version': 'soc_elaboration_closure.v1',
        'component': COMPONENT,
        'root': SOURCE_ROOT.as_posix(),
        'top_module': profile.source.top_module,
        'tool': tool,
        'command': command,
        'include_roots': [],
        'defines': [],
        'parameters': [],
        'closure_files': [{'root': SOURCE_ROOT.as_posix(), 'path': name,
                           'sha256': _digest((source_root / name).read_bytes())}
                          for name in declared],
        'status': 'elaboration_verified',
        'lint': lint,
        'port_evidence': {
            'top_module': profile.source.top_module,
            'source_revision': profile.source.revision,
            'artifact': {'path': artifact_path.relative_to(_ROOT).as_posix(),
                         'sha256': _digest(artifact_raw)},
            'manifest': {'path': manifest_path.relative_to(_ROOT).as_posix(),
                         'sha256': _digest(manifest_path.read_bytes())},
            'ports': [{'name': name, 'direction': direction, 'width': width}
                      for name, direction, width in rows],
            'ports_sha256': verifier._ports_digest(rows),
            'derivation': 'stored-port-evidence-reverified-against-pinned-text',
            'not_claimed': ['frontend_port_extraction',
                            'source_elaboration_json_tree'],
        },
    }
    payload = json.dumps(closure, indent=2, sort_keys=True) + '\n'
    record = {
        'id': COMPONENT,
        'source': {
            'root': SOURCE_ROOT.as_posix(),
            'revision': profile.source.revision,
            'top_module': profile.source.top_module,
            'files': declared,
            'include_roots': [],
            'repositories': [],
        },
        'artifacts': [
            *({'path': name, 'sha256': _digest((source_root / name).read_bytes()),
               'kind': 'source'} for name in declared),
            {'path': 'LICENSE', 'sha256': _digest((_ROOT / LICENSE).read_bytes()),
             'kind': 'license'},
        ],
        'selected_content_hash': selected,
        'closure_status': 'selected',
        'source_status': 'source_verified',
        'elaboration_status': 'elaboration_verified',
        'runtime_status': 'runtime_unverified',
        'defines': [],
        'typed_parameters': [],
        'dependencies': [],
        'elaboration': {
            'status': 'elaboration_verified',
            'top_module': profile.source.top_module,
            'tool': tool,
            'evidence': CLOSURE.as_posix(),
            'evidence_sha256': _digest(payload.encode()),
            'closure_files': len(declared),
            'lint': lint,
        },
    }
    if args.write:
        target = _ROOT / CLOSURE
        target.write_bytes(payload.encode())
        print(f'wrote {CLOSURE.as_posix()} ({len(payload)} bytes, '
              f'evidence_sha256={record["elaboration"]["evidence_sha256"]})')
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
