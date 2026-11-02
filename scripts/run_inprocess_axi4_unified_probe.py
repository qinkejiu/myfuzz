#!/usr/bin/env python3
"""Build and run the native probe for ``scripts/inprocess_axi4_host.h``.

The probe links three real artifacts in one process:

  * the generated packed CVA6 runtime model (``local_runtime_processor``) from
    the current compiled-flow cache entry, after that entry's own generated
    artifact is checked (kind, module, 45 AXI4 backend ports, boot contract,
    no RVFI pin, runtime.sv digest);
  * the repository's existing full-AXI4 CPU-side adapter
    (``src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv``), Verilated
    once with the CVA6 widths (64/64/ID 4/USER 64) and cached under the output
    directory;
  * host RAM owned by the probe.

Nothing under ``src/`` or any shared scenario config is written.  Every build
product goes to ``<output>/build`` and every log to ``<output>/logs``.

Usage:
  python3 scripts/run_inprocess_axi4_unified_probe.py [--max-ticks 4000]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_RTL = ROOT / 'src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv'
PROBE_SOURCE = ROOT / 'tests/native/inprocess_axi4_unified_probe.cpp'
HOST_HEADER = ROOT / 'scripts/inprocess_axi4_host.h'
IDENTITY_HEADER = ROOT / 'scripts/inprocess_axi4_identity.h'
CACHE = ROOT / ('runs/round1-cva6-cache/'
                '8f5fdf6e6bd59397b89434a384ddb8a1199cfaf98b7f4887f8976339229925d1')
ADAPTER_MODULE = 'axi4_processor_memory_adapter'
ADAPTER_PARAMS = ['-GADDRESS_WIDTH=64', '-GDATA_WIDTH=64', '-GID_WIDTH=4',
                  '-GUSER_WIDTH=64']
AXI4_BACKEND_PORTS = 45


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], *, log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('w') as stream:
        stream.write('$ ' + ' '.join(str(part) for part in argv) + '\n')
        stream.flush()
        completed = subprocess.run(argv, cwd=ROOT, stdout=stream,
                                   stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        raise SystemExit(f'command failed ({completed.returncode}); see {log}')


def verilator_include() -> Path:
    override = os.environ.get('MYFUZZ_VERILATOR_INCLUDE')
    if override:
        return Path(override)
    try:
        sys.path.insert(0, str(ROOT / 'src'))
        from myfuzz.local_harness.build import _toolchain
        return Path(_toolchain()['verilator']['runtime_root']) / 'include'
    except Exception:
        candidates = sorted(Path.home().glob('.local/verilator-*/share/verilator/include'))
        if candidates:
            return candidates[-1]
        raise SystemExit('Verilator include directory not found; set MYFUZZ_VERILATOR_INCLUDE')


def check_cache(cache: Path) -> dict[str, object]:
    """Check that the cache entry is the model its own generated artifact describes."""
    archive = cache / 'obj/Vlocal_runtime_processor__ALL.a'
    artifact_path = cache / 'inputs/generated/artifact.json'
    runtime_path = cache / 'inputs/generated/runtime.sv'
    if not archive.is_file():
        raise SystemExit(f'missing CPU archive: {archive}')
    if not artifact_path.is_file() or not runtime_path.is_file():
        raise SystemExit(f'cache entry has no generated artifact: {artifact_path}')
    artifact = json.loads(artifact_path.read_text())
    if artifact.get('kind') != 'cva6_packed_axi4_cpu':
        raise SystemExit(f"unexpected artifact kind: {artifact.get('kind')}")
    if artifact.get('module_name') != 'local_runtime_processor':
        raise SystemExit(f"unexpected module name: {artifact.get('module_name')}")
    runtime_sha = sha256(runtime_path)
    if runtime_sha != artifact.get('runtime_sv_sha256'):
        raise SystemExit('runtime.sv no longer matches the artifact digest it was built with')
    ports = {row['name']: row for row in artifact.get('runtime_ports', [])}
    missing = [name for name in ('axi_arvalid', 'axi_awvalid', 'axi_rdata', 'axi_bid')
               if name not in ports]
    if missing:
        raise SystemExit('archive model lacks AXI4 pins: ' + ','.join(missing))
    if any('rvfi' in name for name in ports):
        raise SystemExit('archive unexpectedly exports RVFI; update the probe claim')
    backend = artifact.get('backend_ports', [])
    axi = [row for row in backend if row.get('channel') == 'axi']
    if len(backend) != AXI4_BACKEND_PORTS or len(axi) != AXI4_BACKEND_PORTS:
        raise SystemExit(f'backend is not the 45-role packed AXI4 port: '
                         f'{len(backend)} ports, {len(axi)} on channel axi')
    boot = artifact.get('boot_contract', {}).get('configured_boot_base')
    if boot != 0x10000:
        raise SystemExit(f'unexpected configured boot base: {boot!r}')
    unconnected = [row for row in artifact.get('structural_abi', {}).get('dispositions', [])
                   if row.get('port') == 'rvfi_probes_o']
    if len(unconnected) != 1 or unconnected[0].get('disposition') != 'unconnected':
        raise SystemExit('RVFI disposition is not the recorded unconnected one')
    return {
        'cache': str(cache.relative_to(ROOT)),
        'archive': str(archive.relative_to(ROOT)),
        'archive_sha256': sha256(archive),
        'artifact_kind': artifact['kind'],
        'artifact_digest': artifact.get('artifact_digest'),
        'runtime_sv_sha256': runtime_sha,
        'boot_base': boot,
        'backend_ports': len(backend),
        'axi_backend_ports': len(axi),
        'rvfi_bundle_bits': unconnected[0]['bits']['hi'] + 1,
        'rvfi_disposition': unconnected[0]['disposition'],
        'source_status': artifact.get('source_verification', {}).get('source_status'),
    }


def build_adapter(build: Path, logs: Path) -> Path:
    directory = build / 'adapter-cva6'
    archive = directory / f'V{ADAPTER_MODULE}__ALL.a'
    stamp_path = directory / 'adapter.stamp.json'
    stamp = {'rtl_sha256': sha256(ADAPTER_RTL), 'module': ADAPTER_MODULE,
             'params': ADAPTER_PARAMS}
    if archive.is_file() and stamp_path.is_file():
        try:
            if json.loads(stamp_path.read_text()) == stamp:
                (logs / 'adapter-build.log').write_text(
                    'adapter build cache hit: ' + stamp['rtl_sha256'] + '\n')
                return archive
        except json.JSONDecodeError:
            pass
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    dummy = build / 'adapter-dummy-main.cpp'
    dummy.write_text('int main() { return 0; }\n')
    verilator = shutil.which('verilator')
    if verilator is None:
        verilator = str(Path.home() / '.local/verilator-5.051-e413e67/bin/verilator')
    if not Path(verilator).is_file():
        raise SystemExit('verilator executable not found')
    run([verilator, '--cc', '--exe', '--build', '-j', '2',
         '--top-module', ADAPTER_MODULE, '-Wno-fatal', *ADAPTER_PARAMS,
         '--Mdir', str(directory), '-o', 'adapter-dummy',
         str(ADAPTER_RTL), str(dummy)], log=logs / 'adapter-build.log')
    stamp_path.write_text(json.dumps(stamp, indent=1, sort_keys=True) + '\n')
    return archive


def build_runtime_objects(build: Path, logs: Path, include: Path) -> list[Path]:
    objects = []
    for name in ('verilated.cpp', 'verilated_threads.cpp'):
        target = build / (name.rsplit('.', 1)[0] + '.o')
        source = include / name
        if not target.is_file() or target.stat().st_mtime < source.stat().st_mtime:
            run(['g++', '-std=c++17', '-O2', '-w', '-isystem', str(include),
                 '-c', str(source), '-o', str(target)],
                log=logs / f'{name}.build.log')
        objects.append(target)
    return objects


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--max-ticks', type=int, default=4000)
    parser.add_argument('--output', type=Path, default=ROOT / 'runs/round1-axi4')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--rebuild-adapter', action='store_true')
    options = parser.parse_args(argv)

    output = options.output if options.output.is_absolute() else ROOT / options.output
    build = output / 'build'
    logs = output / 'logs'
    build.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    identity = check_cache(CACHE)
    include = verilator_include()
    if not (include / 'verilated.h').is_file():
        raise SystemExit(f'Verilator include directory incomplete: {include}')

    probe_binary = build / 'inprocess_axi4_unified_probe'
    if options.skip_build and not probe_binary.is_file():
        raise SystemExit(f'--skip-build but no probe binary at {probe_binary}')
    if not options.skip_build:
        if options.rebuild_adapter:
            shutil.rmtree(build / 'adapter-cva6', ignore_errors=True)
        adapter_archive = build_adapter(build, logs)
        objects = build_runtime_objects(build, logs, include)
        probe_object = build / 'probe.o'
        run(['g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
             '-I', str(ROOT / 'scripts'),
             '-isystem', str(CACHE / 'obj'),
             '-isystem', str(adapter_archive.parent),
             '-isystem', str(include), '-isystem', str(include / 'vltstd'),
             '-c', str(PROBE_SOURCE), '-o', str(probe_object)],
            log=logs / 'probe-compile.log')
        run(['g++', '-std=c++17', '-O2', str(probe_object),
             *(str(path) for path in objects),
             str(CACHE / 'obj/Vlocal_runtime_processor__ALL.a'), str(adapter_archive),
             '-pthread', '-latomic', '-o', str(probe_binary)],
            log=logs / 'probe-link.log')

    identity['probe_source_sha256'] = sha256(PROBE_SOURCE)
    identity['host_header_sha256'] = sha256(HOST_HEADER)
    identity['identity_header_sha256'] = sha256(IDENTITY_HEADER)
    identity['adapter_rtl_sha256'] = sha256(ADAPTER_RTL)
    identity['verilator'] = subprocess.run(['verilator', '--version'],
                                           capture_output=True, text=True,
                                           check=True).stdout.strip()
    identity['compiler'] = subprocess.run(['g++', '--version'], capture_output=True,
                                          text=True, check=True).stdout.splitlines()[0]
    identity['max_ticks'] = options.max_ticks
    adapter_archive = build / 'adapter-cva6' / f'V{ADAPTER_MODULE}__ALL.a'
    if not adapter_archive.is_file():
        raise SystemExit(f'missing built adapter archive: {adapter_archive}')
    identity['adapter_archive'] = str(adapter_archive.relative_to(ROOT))
    identity['adapter_archive_sha256'] = sha256(adapter_archive)

    log = logs / 'probe-run.log'
    command = [str(probe_binary), '--max-ticks', str(options.max_ticks),
               '--identity', 'sha256:' + str(identity['archive_sha256'])]
    started = time.monotonic()
    with log.open('w') as stream:
        stream.write('$ ' + ' '.join(command) + '\n')
        stream.flush()
        completed = subprocess.run(command, cwd=ROOT, stdout=stream,
                                   stderr=subprocess.STDOUT)
    identity['probe_exit'] = completed.returncode
    identity['run_seconds'] = round(time.monotonic() - started, 3)
    (output / 'identity.json').write_text(json.dumps(identity, indent=1, sort_keys=True) + '\n')
    print(json.dumps(identity, indent=1, sort_keys=True))
    print(f'probe_exit={completed.returncode} log={log.relative_to(ROOT)}')
    return completed.returncode


if __name__ == '__main__':
    sys.exit(main())
