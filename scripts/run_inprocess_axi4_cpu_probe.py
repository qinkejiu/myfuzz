#!/usr/bin/env python3
"""Build and run the native CVA6 full-AXI4 probe against an existing CPU archive.

The probe links three real artifacts in one process:

  * the generated CVA6 runtime model (``local_runtime_processor``) from an
    existing compiled-flow cache entry, after its own source identity is checked;
  * the repository's existing full-AXI4 CPU-side adapter
    (``src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv``), Verilated
    here with the CVA6 widths (64/64/ID 4/USER 64);
  * host RAM owned by the probe.

Nothing under ``src/`` or any shared scenario config is written.  Every build
product goes to ``<output>/build`` and every log to ``<output>/logs``.

Usage:
  python3 scripts/run_inprocess_axi4_cpu_probe.py \
      --archive runs/cva6-f1f4-20261031/cache/20c5.../obj/Vlocal_runtime_processor__ALL.a \
      --output runs/stage2-axi4-cpu-20261101 [--max-ticks 12000]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_RTL = ROOT / 'src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv'
PROBE_SOURCE = ROOT / 'tests/native/inprocess_axi4_cva6_probe.cpp'
IDENTITY_HEADER = ROOT / 'scripts/inprocess_axi4_identity.h'
VERILATOR_INCLUDE = Path.home() / '.local/verilator-5.051-e413e67/share/verilator/include'
ADAPTER_MODULE = 'axi4_processor_memory_adapter'
ADAPTER_PARAMS = ['-GADDRESS_WIDTH=64', '-GDATA_WIDTH=64', '-GID_WIDTH=4', '-GUSER_WIDTH=64']


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], *, log: Path, cwd: Path = ROOT) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('w') as stream:
        stream.write('$ ' + ' '.join(str(part) for part in argv) + '\n')
        stream.flush()
        completed = subprocess.run(argv, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        raise SystemExit(f'command failed ({completed.returncode}); see {log}')


def check_archive(archive: Path) -> dict[str, object]:
    """Check that the archive is the model its own generated artifact describes."""
    obj_dir = archive.parent
    artifact_path = obj_dir.parent / 'inputs/generated/artifact.json'
    runtime_path = obj_dir.parent / 'inputs/generated/runtime.sv'
    if not artifact_path.is_file() or not runtime_path.is_file():
        raise SystemExit(f'archive has no generated artifact beside it: {artifact_path}')
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
    unconnected = [row for row in artifact.get('structural_abi', {}).get('dispositions', [])
                   if row.get('port') == 'rvfi_probes_o']
    if len(unconnected) != 1 or unconnected[0].get('disposition') != 'unconnected':
        raise SystemExit('RVFI disposition is not the recorded unconnected one')
    return {
        'archive': str(archive.relative_to(ROOT)),
        'archive_sha256': sha256(archive),
        'artifact_kind': artifact['kind'],
        'artifact_digest': artifact.get('artifact_digest'),
        'runtime_sv_sha256': runtime_sha,
        'rvfi_bundle_bits': unconnected[0]['bits']['hi'] + 1,
        'rvfi_disposition': unconnected[0]['disposition'],
        'source_status': artifact.get('source_verification', {}).get('source_status'),
        'source_lock_sha256': artifact.get('source_verification', {}).get('lock_sha256'),
        'runtime_status': artifact.get('source_verification', {}).get('runtime_status'),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'runs/stage2-axi4-cpu-20261101')
    parser.add_argument('--max-ticks', type=int, default=12000)
    parser.add_argument('--skip-build', action='store_true')
    options = parser.parse_args(argv)

    archive = options.archive if options.archive.is_absolute() else ROOT / options.archive
    output = options.output if options.output.is_absolute() else ROOT / options.output
    build = output / 'build'
    logs = output / 'logs'
    build.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    identity = check_archive(archive)
    if not VERILATOR_INCLUDE.is_dir():
        raise SystemExit(f'Verilator include directory missing: {VERILATOR_INCLUDE}')

    adapter_dir = build / 'adapter-cva6'
    probe_binary = build / 'inprocess_axi4_cva6_probe'
    if not options.skip_build:
        dummy = build / 'adapter-dummy-main.cpp'
        dummy.write_text('int main() { return 0; }\n')
        shutil.rmtree(adapter_dir, ignore_errors=True)
        adapter_dir.mkdir(parents=True)
        run(['verilator', '--cc', '--exe', '--build', '-j', '2',
             '--top-module', ADAPTER_MODULE, '-Wno-fatal', *ADAPTER_PARAMS,
             '--Mdir', str(adapter_dir), '-o', 'adapter-dummy',
             str(ADAPTER_RTL), str(dummy)], log=logs / 'adapter-build.log')
        objects = build / 'probe-obj'
        objects.mkdir(exist_ok=True)
        include = ['-isystem', str(archive.parent), '-isystem', str(adapter_dir),
                   '-isystem', str(VERILATOR_INCLUDE), '-isystem', str(VERILATOR_INCLUDE / 'vltstd')]
        run(['g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', *include,
             '-c', str(PROBE_SOURCE), '-o', str(objects / 'probe.o')],
            log=logs / 'probe-compile.log')
        for name in ('verilated.cpp', 'verilated_threads.cpp'):
            run(['g++', '-std=c++17', '-O2', '-w', '-isystem', str(VERILATOR_INCLUDE),
                 '-c', str(VERILATOR_INCLUDE / name),
                 '-o', str(objects / (name.rsplit('.', 1)[0] + '.o'))],
                log=logs / f'{name}.build.log')
        run(['g++', '-std=c++17', '-O2', str(objects / 'probe.o'),
             str(objects / 'verilated.o'), str(objects / 'verilated_threads.o'),
             str(archive), str(adapter_dir / f'V{ADAPTER_MODULE}__ALL.a'),
             '-pthread', '-latomic', '-o', str(probe_binary)],
            log=logs / 'probe-link.log')

    log = logs / 'probe-run.log'
    identity['probe_source_sha256'] = sha256(PROBE_SOURCE)
    identity['identity_header_sha256'] = sha256(IDENTITY_HEADER)
    identity['adapter_rtl_sha256'] = sha256(ADAPTER_RTL)
    identity['verilator'] = subprocess.run(['verilator', '--version'], capture_output=True,
                                           text=True, check=True).stdout.strip()
    identity['compiler'] = subprocess.run(['g++', '--version'], capture_output=True,
                                          text=True, check=True).stdout.splitlines()[0]
    identity['max_ticks'] = options.max_ticks
    with log.open('w') as stream:
        completed = subprocess.run([str(probe_binary), str(options.max_ticks),
                                    'sha256:' + identity['archive_sha256']],
                                   cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    identity['probe_exit'] = completed.returncode
    (output / 'identity.json').write_text(json.dumps(identity, indent=1, sort_keys=True) + '\n')
    print(json.dumps(identity, indent=1, sort_keys=True))
    return completed.returncode


if __name__ == '__main__':
    sys.exit(main())
