#!/usr/bin/env python3
"""Generate one source-locked, independent RTL harness from a JSON request."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness import (  # noqa: E402
    build_local_harness, load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock,
)


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON field: ' + name)
        result[name] = value
    return result


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2,
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def generate(request_path: Path, output: Path, *, build_cache: Path | None = None):
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists')
    if not output.parent.is_dir():
        raise ValueError('output parent directory does not exist')
    document = json.loads(request_path.read_text(encoding='utf-8'),
                          object_pairs_hook=_unique_object)
    request = load_local_harness_request(document)
    plan = plan_local_harness(request, base_dir=ROOT)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    structural = render_local_harness(plan)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    artifact = render_local_driver(runtime, base_dir=ROOT)
    binary = None
    if build_cache is not None:
        binary = build_local_harness(artifact, base_dir=ROOT,
                                     cache_dir=build_cache.resolve())
    files = {
        'wrapper.sv': structural.wrapper_sv.encode('utf-8'),
        'runtime.sv': artifact.runtime_sv.encode('utf-8'),
        'driver.cpp': artifact.cpp_text.encode('utf-8'),
        'artifact.json': _json_bytes(artifact.runtime_document),
        'abi.json': _json_bytes(structural.abi_document),
        'source_verification.json': _json_bytes(verified),
    }
    staging = Path(tempfile.mkdtemp(prefix='.' + output.name + '.', dir=output.parent))
    try:
        for name, data in files.items():
            (staging / name).write_bytes(data)
        if output.exists() or output.is_symlink():
            raise ValueError('output already exists')
        os.rename(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    result = {'output': str(output),
              'kind': artifact.runtime_document['kind'],
              'artifact_digest': artifact.runtime_document['artifact_digest'],
              'status': 'binary_built' if binary is not None else 'driver_generated'}
    if binary is not None:
        result['binary'] = str(binary)
    return result


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--request', type=Path, required=True,
                        help='local_harness.v1 JSON request')
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory for generated files')
    parser.add_argument('--build-cache', type=Path,
                        help='also compile the authenticated RTL into this cache')


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    result = generate(args.request, args.output,
                      build_cache=args.build_cache)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == '__main__':
    raise SystemExit(main())
