"""Generate an isolated coherent CPU/RAM harness from an authenticated physical profile.

This separate entry point does not claim admission to the generic MMIO router.
The manager has one coherent client and never emits probes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.source_crawler import source_tree_hash


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(repo: Path, output: Path) -> dict:
    repo, output = repo.resolve(), output.resolve()
    config = repo / 'configs/cpus/boom'
    profile = load_component_profile(config / 'component_profile.json')
    source = dict(profile.source_document)
    root = repo / source['root']
    spec = importlib.util.spec_from_file_location('_boom_materialize', root / 'materialize.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.materialize(root)
    if source_tree_hash(root, [root / name for name in source['files']]) != source['revision']:
        raise ValueError('coherent-cpu-source-union-mismatch')
    if source['revision'] != manifest['revision'] or source['top_module'] != 'BoomTile':
        raise ValueError('coherent-cpu-source-manifest-mismatch')
    port_record = root / manifest['physical_ports']
    if digest(port_record) != manifest['physical_ports_sha256']:
        raise ValueError('coherent-cpu-port-evidence-hash-mismatch')
    ports = json.loads(port_record.read_text())
    physical = ports['modules'][source['top_module']]['ports']
    rtl = (root / 'chipyard.TestHarness.SmallBoomConfig.top.v').read_text()
    header = re.search(r'\bmodule\s+BoomTile\s*\((.*?)\);', rtl, re.S)[1]
    actual = []
    for direction, packed, name in re.findall(r'^\s*(input|output|inout)\s+(?:wire\s+|reg\s+|logic\s+)?(\[\d+:\d+\])?\s*(\w+)', header, re.M):
        bounds = [int(v) for v in re.findall(r'\d+', packed)]
        actual.append((name, direction, abs(bounds[0]-bounds[1])+1 if bounds else 1))
    if actual != [(p['name'],p['direction'],p['width']) for p in physical]:
        raise ValueError('coherent-cpu-source-physical-ports-mismatch')
    document = json.loads((config / 'component_profile.json').read_text())
    endpoint, = document['endpoints']
    if endpoint['protocol'] != ['tilelink-coherent', '1']:
        raise ValueError('coherent-cpu-protocol-required')
    mappings = {field['role']: field['aliases'][0] for field in endpoint['fields']}
    bus = {p['name']: p for p in physical if p['name'].startswith('auto_tl_other_masters_out_')}
    if (len(mappings) != 39 or set(mappings.values()) != set(bus)
            or any(port != 'auto_tl_other_masters_out_' + role for role, port in mappings.items())):
        raise ValueError('coherent-cpu-physical-bus-mismatch')
    # The checked direct driver is the behavioral template. Every bus reference
    # becomes a concrete selected physical profile port in the emitted driver.
    driver = (config / 'runtime/boom_tile_ram.cpp').read_text()
    driver = re.sub(r'^#define TL\(name\).*\n', '', driver, flags=re.M)
    driver = re.sub(r'TL\((\w+)\)', lambda match: mappings[match[1]], driver)
    driver = driver.replace('  TlRam ram;', '  TlRam ram;\n  const bool fault = argc == 2 && std::string(argv[1]) == "--fault-read";\n  bool fault_injected = false;')
    needle = 'dut.auto_tl_other_masters_out_d_bits_data=ram.front_data();'
    replacement = needle + '\n        if(fault && ram.front().opcode==5 && ram.front().address==0x80001000 && ram.read64(0x80001000)==0x123) {dut.auto_tl_other_masters_out_d_bits_data ^= 1; fault_injected=true;}'
    if needle not in driver:
        raise ValueError('coherent-cpu-template-data-drive-missing')
    driver = driver.replace(needle, replacement)
    driver = driver.replace('  emit(lui(1,0x80001));', '  emit(0x0330000f); emit(lui(1,0x80001));')
    driver = driver.replace('<<ram.front_data()<<', '<<uint64_t(dut.auto_tl_other_masters_out_d_bits_data)<<')
    driver = driver.replace('<<ram.front().beat<<', '<<ram.front().beat<<",\\\"address\\\":"<<ram.front().address<<",\\\"fault_read\\\":"<<(fault && ram.front().opcode==5 && ram.front().address==0x80001000 && ram.read64(0x80001000)==0x123)<<')
    driver = driver.replace('cycle<250000', 'cycle<(fault ? 5000u : 250000u)')
    driver = driver.replace('std::cerr<<"timeout marker="', 'std::cerr<<"fault_injected="<<fault_injected<<" timeout marker="')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'driver.cpp').write_text(driver)
    shutil.copy2(config / 'runtime/tl_ram.h', output / 'tl_ram.h')
    inputs = []
    for name in source['files']:
        shutil.copy2(root / name, output / name)
        inputs.append(str(output / name))
    command = ['verilator', '--cc', '--exe', '--build', '--top-module', source['top_module'], '--Mdir', str(output / 'obj'), '-Wno-fatal', '--output-split', '20000', '--output-split-cfuncs', '20000', '-j', '2', '-CFLAGS', '-std=c++17 -O1', *inputs, str(output / 'driver.cpp')]
    artifact = {'schema_version':'generated_coherent_cpu_ram.v1', 'runtime_kind':'tilelink_coherent_cpu', 'derived_source':True, 'source_revision':source['revision'], 'source_manifest_sha256':digest(root / 'source_manifest.json'), 'profile_sha256':digest(config / 'component_profile.json'), 'driver_sha256':digest(output / 'driver.cpp'), 'manager_sha256':digest(output / 'tl_ram.h'), 'trace_verifier':str(config / 'runtime/verify_trace.py'), 'trace_verifier_sha256':digest(config / 'runtime/verify_trace.py'), 'simulator':subprocess.check_output(['verilator','--version'], text=True).strip(), 'physical_ports':47, 'coherent_fields':39, 'B_valid':0, 'external_probes_exercised':False, 'generic_router_admitted':False, 'command':command}
    (output / 'artifact.json').write_text(json.dumps(artifact, indent=2)+'\n')
    return artifact


def run_gates(output: Path, artifact: dict) -> dict:
    executable = output / 'obj/VBoomTile'
    verifier_path = Path(artifact['trace_verifier'])
    if digest(verifier_path) != artifact['trace_verifier_sha256']:
        raise ValueError('coherent-cpu-trace-verifier-mismatch')
    spec = importlib.util.spec_from_file_location('_coherent_trace_verifier', verifier_path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    runs = []
    for name, args in [('fresh1', []), ('fresh2', []), ('fault_read', ['--fault-read'])]:
        result = subprocess.run([str(executable), *args], capture_output=True)
        (output / (name+'.jsonl')).write_bytes(result.stdout)
        (output / (name+'.stderr')).write_bytes(result.stderr)
        (output / (name+'.exit')).write_text(str(result.returncode)+'\n')
        events = [json.loads(line) for line in result.stdout.splitlines()]
        runs.append({'name':name,'exit':result.returncode,'trace_sha256':hashlib.sha256(result.stdout).hexdigest(),'result':events[-1] if events else None,'stderr':result.stderr.decode()})
    if not all(r['exit']==0 and r['result'].get('result')=='pass' for r in runs[:2]):
        raise ValueError('coherent-cpu-fresh-run-failed')
    for run in runs[:2]:
        run['trace_verification'] = verifier.verify(output / (run['name']+'.jsonl'))
    if runs[0]['trace_sha256'] != runs[1]['trace_sha256']:
        raise ValueError('coherent-cpu-fresh-runs-differ')
    if runs[2]['exit']==0 or 'fault_injected=1' not in runs[2]['stderr'] or 'reload=290' not in runs[2]['stderr']:
        raise ValueError('coherent-cpu-fault-control-not-causal')
    fault_events = [json.loads(line) for line in (output / 'fault_read.jsonl').read_text().splitlines()]
    latest_a, releases, fault_beats = {}, [], []
    for index, event in enumerate(fault_events):
        if event.get('channel') == 'C' and event.get('address') == 0x80001000:
            releases.append({'event_index':index, **event})
        if event.get('channel') == 'A':
            latest_a[event['source']] = {'event_index':index, **event}
        if event.get('channel') == 'D' and event.get('fault_read'):
            request = latest_a[event['source']]
            if (request['address'] != 0x80001000 or request['opcode'] != 6
                    or request['size'] != event['size'] or len(releases) < 8
                    or releases[-1]['event_index'] >= request['event_index']):
                raise ValueError('coherent-cpu-fault-response-request-correlation-failed')
            fault_beats.append({'request':request,'response':{'event_index':index, **event}})
    marker = [event for event in fault_events if event.get('channel') == 'A' and event.get('address') == 0x4008 and event.get('opcode') == 0]
    if not fault_beats or not marker or marker[-1]['data'] & 0xffffffff != 290:
        raise ValueError('coherent-cpu-fault-marker-evidence-missing')
    fault_causality = {'released_line_beats':releases,'reacquire_and_replaced_D_beats':fault_beats,'CPU_reload_marker_A':marker[-1]}
    report = {'schema_version':'generated_coherent_cpu_ram_gate.v1','artifact':artifact,'executable_sha256':digest(executable),'two_fresh_matching':True,'fault_read_control':True,'fault_causality':fault_causality,'runs':runs}
    (output / 'gate.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-and-run', action='store_true')
    parser.add_argument('--heavy-lock', type=Path)
    args = parser.parse_args()
    artifact = generate(args.repo, args.output)
    if args.build_and_run:
        if args.heavy_lock is None:
            parser.error('--build-and-run requires the shared --heavy-lock')
        import fcntl
        with args.heavy_lock.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with (args.output / 'build.log').open('w') as log:
                subprocess.run(artifact['command'], stdout=log, stderr=subprocess.STDOUT, check=True)
            report = run_gates(args.output.resolve(), artifact)
        print(json.dumps({'two_fresh_matching':report['two_fresh_matching'],'fault_read_control':report['fault_read_control']}))
    else:
        print(json.dumps(artifact, indent=2))


if __name__ == '__main__':
    main()
