"""Separate opt-in IRQ artifact generation; baseline builder remains frozen."""
import fcntl
import json
import re
from pathlib import Path
import shutil
import subprocess

from myfuzz.composition.component_profile import load_component_profile
from .tilelink_coherent_cpu_session import generate, digest
from .boom_irq_contract import PROBES, validate_irq_profile, validate_probe_inventory

AUXILIARY = ('boom_irq_probes.h','boom_irq_probe_specs.h','passive_probes.vlt',
             'irq-profile.json','probe_contract.json','irq-interface.json')


def generate_irq(repo: Path, output: Path):
    repo, output = repo.resolve(), output.resolve()
    artifact = generate(repo, output)  # Authenticates unchanged four RTL files/47 ports.
    config = repo/'configs/cpus/boom_irq'
    baseline = json.loads((repo/'configs/cpus/boom/component_profile.json').read_text())
    variant = json.loads((config/'component_profile.json').read_text())
    validate_irq_profile(variant, baseline)
    load_component_profile(config/'component_profile.json')
    root = repo/'configs/cpus/boom/generated'
    manifest = json.loads((root/'source_manifest.json').read_text())
    ports = json.loads((root/manifest['physical_ports']).read_text())['modules']['BoomTile']['ports']
    meip = [row for row in ports if row['name']=='auto_int_local_in_2_0']
    if len(meip) != 1 or meip[0]['direction'] != 'input' or meip[0]['width'] != 1:
        raise ValueError('authenticated physical MEIP port mismatch')
    artifact['base_profile_sha256'] = artifact['profile_sha256']
    artifact['profile_sha256'] = digest(config/'component_profile.json')
    here = Path(__file__).parent
    shutil.copy2(here/'boom_irq_cpu_driver.cpp', output/'driver.cpp')
    shutil.copy2(here/'boom_irq_probes.h', output/'boom_irq_probes.h')
    for source, name in ((config/'component_profile.json','irq-profile.json'),
                         (config/'interface_description.json','irq-interface.json'),
                         (config/'passive_probes.vlt','passive_probes.vlt'),
                         (config/'probe_contract.json','probe_contract.json')):
        shutil.copy2(source, output/name)
    spec = 'inline std::vector<BoomProbe> boom_probe_specs() {return {\n'
    spec += ',\n'.join('{'+json.dumps(key)+','+json.dumps(path)+','+str(width)+'}' for key,(path,width) in PROBES.items())
    (output/'boom_irq_probe_specs.h').write_text(spec+'\n};}\n')
    contract = json.loads((config/'probe_contract.json').read_text())
    validate_probe_inventory(contract['probes'])
    artifact.update(schema_version='generated_boom_irq_session.v1',
        runtime_kind='tilelink_coherent_cpu_irq', driver_sha256=digest(output/'driver.cpp'),
        implementation_source_hashes={name:digest(here/name) for name in (
            'boom_irq_generation.py','boom_irq_contract.py','boom_irq_cpu_session.py',
            'boom_irq_cpu_driver.cpp','boom_irq_probes.h','boom_irq_scenario_session.py',
            'tilelink_coherent_cpu_session.py')},
        auxiliary_hashes={name:digest(output/name) for name in AUXILIARY},
        probes_runtime_confirmed=False, passive_probe_contract=contract,
        gpio_irq_policy='actual rising edge, fixed 64 CPU ticks, no extension')
    artifact['scenario_factory_sha256'] = digest(repo/'src/myfuzz/scenario/boom_gpio_irq_runner.py')
    command = artifact['command']
    index = command.index('--cc')
    command[index:index] = ['--vpi', str(output/'passive_probes.vlt')]
    artifact['command'] = command
    return artifact


def generated_symbol_files(output: Path):
    """Accept one of two explicit generated registry units, tied to make.

    This is local generated-file integrity, not signed toolchain provenance.
    Actual executed VPI descriptor/startup inventory remains independently required.
    """
    obj = output/'obj'
    layouts = ('VBoomTile__Syms.cpp','VBoomTile__Syms__Slow.cpp')
    if obj.is_symlink() or not obj.is_dir():
        raise ValueError('BOOM generated symbol directory missing/linked')
    candidates = [name for name in layouts if (obj/name).exists() or (obj/name).is_symlink()]
    unknown = [file.name for file in obj.iterdir()
               if file.name.startswith('VBoomTile__Syms') and file.suffix == '.cpp'
               and file.name not in layouts]
    if len(candidates) != 1 or unknown:
        raise ValueError('BOOM generated registry must use one unique supported layout')
    source = candidates[0]
    stem = Path(source).stem
    names = (source,'VBoomTile__Syms.h','VBoomTile_classes.mk',stem+'.d')
    for name in names:
        file = obj/name
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 1000000:
            raise ValueError('BOOM generated symbol closure missing/linked/oversized')
    make = (obj/'VBoomTile_classes.mk').read_text()
    blocks = re.findall(r'(?m)^VM_SUPPORT_(?:FAST|SLOW)\s*\+=\s*\\\n((?:[ \t]+[^\n]*\n)*)',make)
    units = [token for block in blocks for token in block.replace('\\',' ').split()]
    if units.count(stem) != 1 or any(Path(name).stem in units for name in layouts if name != source):
        raise ValueError('BOOM generated registry not uniquely selected by make support list')
    dependency = (obj/(stem+'.d')).read_text()
    if not dependency.startswith(stem+'.o: '+source+' '):
        raise ValueError('BOOM generated registry object dependency mismatch')
    return tuple('obj/'+name for name in names)


def _require_empty_output(output: Path):
    # Check before resolve so an empty-directory symlink is rejected too.
    if (output.is_symlink() or output.exists()
            and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError('IRQ output must be a new or empty directory')


def build_boom_irq_session(repo: Path, output: Path, *, heavy_lock: Path):
    _require_empty_output(output)
    output = output.resolve()
    if heavy_lock.resolve().is_relative_to(output):
        raise ValueError('IRQ lock must be outside the empty output directory')
    with heavy_lock.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _require_empty_output(output)
        artifact = generate_irq(repo, output)
        with (output/'build.log').open('w') as log:
            result = subprocess.run(artifact['command'], stdout=log, stderr=subprocess.STDOUT, check=False)
        (output/'build.exit').write_text(str(result.returncode)+'\n')
        result.check_returncode()
        # Actual generated VPI registry, no clock edge and no assumed C++ member.
        result = subprocess.run([str(output/'obj/VBoomTile'),'--describe-probes'],
                                capture_output=True, text=True, check=False, timeout=10)
        (output/'probe-describe.stdout').write_text(result.stdout)
        (output/'probe-describe.stderr').write_text(result.stderr)
        (output/'probe-describe.exit').write_text(str(result.returncode)+'\n')
        result.check_returncode()
        inventory = json.loads(result.stdout)
        validate_probe_inventory(inventory)
        (output/'generated-probes.json').write_text(json.dumps(inventory,indent=2)+'\n')
        artifact['generated_probes'] = inventory
        artifact['probes_runtime_confirmed'] = True
        symbol_files = generated_symbol_files(output)
        artifact['generated_symbol_files'] = symbol_files
        files = ['driver.cpp','tl_ram.h','obj/VBoomTile', *symbol_files,
                 'generated-probes.json', *AUXILIARY]
        files += [path.name for path in output.glob('*.v')]
        artifact['session_files'] = {name:digest(output/name) for name in files}
        (output/'irq-session-artifact.json').write_text(json.dumps(artifact,indent=2)+'\n')
    return artifact


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--heavy-lock', type=Path, required=True)
    args = parser.parse_args()
    build_boom_irq_session(args.repo, args.output, heavy_lock=args.heavy_lock)
