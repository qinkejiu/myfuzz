"""P7-B -> P7-C: a generated harness set must be able to reach an executable path.

P7-B generates harnesses plus a ``wiring_contract.v1``; P7-C compiles that
contract into F1..F6 paths.  Each module was green on its own while the chain
between them produced **zero** executable paths: the contract P7-B wrote carried
only ``cpu`` and ``windows``, so P7-C correctly refused every flow for want of a
declared program-image resource.

That is a real product gap, not a missing test, and this file pins both halves of
it:

* without a ``memory`` declaration the chain still refuses - the compiler must
  not invent an instruction image from an address range (the RED guard, so this
  file cannot pass vacuously by asserting "some path is executable" against a
  compiler that says yes to everything);
* with the declaration P7-B now writes, the same real profiles and the same real
  compiler yield executable paths.

Everything here uses real profiles and the real modules.  Nothing is mocked, and
no claim is made that the harnesses run: ``generate_harness_set`` only ever
reports the ``generated`` tier.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.local_harness.harness_set import (HarnessSetRefused,
                                              generate_harness_set, load_compose)
from myfuzz.scenario.compiled_paths import (compile_paths,
                                            load_path_compile_request)

ROOT = Path(__file__).resolve().parents[2]

CPU_PROFILE = 'configs/cpus/ibex_obi_local/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'
GPIO_CAPABILITY = 'configs/peripherals/pulp_gpio/test_capability.json'

#: The ROM the real Ibex profile's reset vector (0x10000) falls inside.  The
#: numbers match ``configs/soc/ibex-pulp.json``'s ``memory_regions``; the point of
#: the test is that a composition must *declare* them rather than inherit them.
ROM = {'resource_id': 'rom0', 'component_instance': 'cpu', 'base': 65536,
       'size': 32768, 'read': True, 'write': False, 'execute': True,
       'initialization_policy': 'preload'}
RAM = {'resource_id': 'ram0', 'component_instance': 'cpu', 'base': 2147483648,
       'size': 65536, 'read': True, 'write': True, 'execute': False,
       'initialization_policy': 'preload'}


def write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return path


def compose_document(directory: Path, *, memory=None) -> Path:
    """The real Ibex obi_local + PULP GPIO composition, with declared memory."""
    directory = Path(directory)
    write(directory / 'requests/cpu.json', {
        'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
        'instance_id': 'cpu', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
        'max_wait_cycles': 16})
    write(directory / 'requests/gpio.json', {
        'schema_version': 'local_harness.v1', 'profile_path': GPIO_PROFILE,
        'instance_id': 'gpio', 'reset_assert_ticks': 2, 'reset_release_ticks': 2,
        'max_wait_cycles': 16})
    document = {
        'schema_version': 'harness_compose.v1',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'request': 'requests/gpio.json',
                     'bus_endpoint': 'gpio.bus',
                     'base': 0x40000000, 'size': 0x1000}],
    }
    if memory is not None:
        document['memory'] = memory
    return write(directory / 'compose.json', document)


def generate(directory: Path, memory, *, output=None):
    """Run the real P7-B entry point over a real composition."""
    compose = load_compose(compose_document(directory, memory=memory), base_dir=ROOT)
    return generate_harness_set(compose, base_dir=ROOT, compose_base=directory,
                                output_root=output or (Path(directory) / 'out'))


def compile_request(directory: Path, wiring: Path) -> Path:
    """A ``path_compile_request.v1`` pointing at a generated wiring contract."""
    return write(Path(directory) / 'request.json', {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                'data_endpoint': 'processor.data',
                'instruction_endpoint': 'processor.instruction'},
        'devices': [{'device_id': 'gpio', 'instance_id': 'gpio',
                     'profile': GPIO_PROFILE, 'test_capability': GPIO_CAPABILITY}],
        'wiring': {'source': str(wiring)},
    })


def compiled_paths(directory: Path, wiring: Path) -> dict:
    """Feed a generated contract to the real P7-C compiler."""
    return compiled_request(compile_request(directory, wiring))


def compiled_request(request: Path) -> dict:
    """Compile an already-written ``path_compile_request.v1`` document."""
    document = compile_paths(load_path_compile_request(request, base_dir=ROOT))
    return {row['flow_id']: row for row in document['paths']}, document


def test_without_a_memory_declaration_the_chain_still_refuses(tmp_path):
    """The RED guard: an undeclared image must not become an executable F1."""
    generate(tmp_path, None)
    paths, document = compiled_paths(tmp_path, tmp_path / 'out' / 'wiring_contract.json')

    assert document['counts']['executable'] == 0, (
        'the compiler produced an executable path from a contract that declares '
        'no memory resource; it must have inferred an image it was never given')
    # Every flow is unsupported, and each says why in its own words.
    assert all(row['status'] == 'unsupported' for row in paths.values())
    assert all(row['reason']['code'] for row in paths.values())
    reasons = {row['reason']['code'] for row in paths.values()}
    assert 'instruction-image-resource-undeclared' in reasons
    assert document['runtime_path_contract'] is None


def test_a_declared_memory_resource_makes_the_chain_reach_executable(tmp_path):
    """GREEN: the declaration P7-B writes is the one P7-C needs."""
    document = generate(tmp_path, [ROM, RAM])

    wiring = json.loads((tmp_path / 'out' / 'wiring_contract.json')
                        .read_text(encoding='utf-8'))
    assert [row['resource_id'] for row in wiring['resources']] == ['rom0', 'ram0']
    # The two copies of the contract must agree, or a consumer could compile a
    # different declaration than the one the harness set reports.
    assert document['wiring'] == wiring

    paths, compiled = compiled_paths(tmp_path, tmp_path / 'out' / 'wiring_contract.json')
    assert compiled['identity']['wiring']['declared_sections'] == [
        'cpu', 'windows', 'resources']
    for flow in ('F1', 'F2', 'F3', 'F4'):
        assert paths[flow]['status'] == 'executable', (flow, paths[flow]['reason'])
        # Executable means nothing is missing; the reason shell carries no code.
        assert paths[flow]['reason']['code'] is None
        assert paths[flow]['reason']['missing'] == []
        assert paths[flow]['sources'], f'{flow} claims executable with no source'
    assert compiled['counts']['executable'] == 4
    # F5/F6 are refused for reasons this declaration does not address, and the
    # refusal must name them rather than quietly omitting the flows.
    assert paths['F5']['reason']['code'] == 'interrupt-delivery-missing'
    assert paths['F6']['reason']['code'] == 'dma-master-not-declared'


def test_the_program_image_source_is_the_declared_rom(tmp_path):
    """The image is the region the declared permissions qualify, not a name."""
    generate(tmp_path, [ROM, RAM])
    paths, _ = compiled_paths(tmp_path, tmp_path / 'out' / 'wiring_contract.json')

    source, = [row for row in paths['F1']['sources']
               if row.get('kind') == 'instruction_image']
    assert source['source_id'] == 'rom0.image'
    assert source['origin'] == 'fuzzable'
    # The region comes from the declaration, and the compiler says so.
    assert source['range'] == [ROM['base'], ROM['base'] + ROM['size'] - 1]
    assert source['origin_ref'] == 'wiring:wiring_contract.v1'
    assert 'read' in source['constraint_basis'] and 'execute' in source['constraint_basis']

    # RAM is readable but declares no execute permission, so it must not become
    # an instruction image even though it is the other declared region.
    assert [row['source_id'] for row in paths['F1']['sources']] == ['rom0.image']

    # Take away the execute permission and the ROM must stop qualifying, even
    # though it still contains the reset vector.
    other = tmp_path / 'no-execute'
    generate(other, [dict(ROM, execute=False)])
    paths, document = compiled_paths(other, other / 'out' / 'wiring_contract.json')
    assert paths['F1']['status'] == 'unsupported'
    assert paths['F1']['reason']['code'] == 'instruction-image-resource-undeclared'
    assert document['counts']['executable'] == 0


def test_memory_declarations_are_refused_by_name(tmp_path):
    """Leaving ownership or permissions unstated is refused, not defaulted."""
    def without(key):
        return {name: value for name, value in ROM.items() if name != key}

    cases = [
        ('compose-memory-owner-missing', '/memory/0/component_instance',
         [without('component_instance')]),
        ('compose-memory-owner-undeclared', '/memory/0/component_instance',
         [dict(ROM, component_instance='nobody')]),
        ('compose-memory-permission-missing', '/memory/0',
         [without('execute')]),
        ('compose-memory-permission-missing', '/memory/0', [without('read')]),
        ('compose-memory-permission-missing', '/memory/0', [without('write')]),
        ('compose-memory-field-invalid', '/memory/0/read', [dict(ROM, read='yes')]),
        ('compose-memory-empty', '/memory/0/size', [dict(ROM, size=0)]),
        ('compose-memory-id-duplicate', '/memory', [ROM, ROM]),
        ('compose-memory-object-required', '/memory/0', ['rom0']),
        ('compose-memory-array-required', '/memory', ROM),
    ]
    for index, (code, pointer, rows) in enumerate(cases):
        directory = tmp_path / f'case{index}'
        with pytest.raises(HarnessSetRefused) as raised:
            load_compose(compose_document(directory, memory=rows), base_dir=ROOT)
        assert raised.value.code == code, (index, raised.value.code)
        assert raised.value.pointer == pointer, (index, raised.value.pointer)


def test_an_unknown_memory_field_is_not_silently_ignored(tmp_path):
    """A misspelt optional field is refused, not dropped."""
    with pytest.raises(HarnessSetRefused) as raised:
        load_compose(compose_document(tmp_path, memory=[dict(ROM, execut=True)]),
                     base_dir=ROOT)
    assert raised.value.code == 'compose-field-unknown'
    assert raised.value.pointer == '/memory/0'


def test_a_supplement_that_contradicts_the_generated_contract_is_refused(tmp_path):
    """Two sources of the same fact must not silently disagree.

    A ``memory`` supplement may fill in a field the contract left out, but when
    both state a value they must be equal - otherwise the compiled path would
    describe a region the generated harness set never declared.
    """
    from myfuzz.scenario.compiled_paths import PathCompilationError

    generate(tmp_path, [ROM, RAM])
    wiring_path = tmp_path / 'out' / 'wiring_contract.json'
    request = compile_request(tmp_path, wiring_path)
    document = json.loads(request.read_text(encoding='utf-8'))
    document['memory'] = [{'resource_id': 'rom0', 'base': ROM['base'],
                           'size': ROM['size'] + 4096}]
    contradicting = write(tmp_path / 'contradicting.json', document)

    with pytest.raises(PathCompilationError) as raised:
        compile_paths(load_path_compile_request(contradicting, base_dir=ROOT))
    assert raised.value.code == 'wiring-resource-conflict'
    assert raised.value.pointer == '/memory/0/size'

    # A supplement that only fills a gap the contract left is accepted, so the
    # refusal above is about contradiction and not about supplements per se.
    # ROM here carries no initialization_policy, so the contract leaves the field
    # out and the supplement is the only source for it.
    other = tmp_path / 'gap'
    gap_rom = {name: value for name, value in ROM.items()
               if name != 'initialization_policy'}
    generate(other, [gap_rom])
    gap_wiring = other / 'out' / 'wiring_contract.json'
    wiring = json.loads(gap_wiring.read_text(encoding='utf-8'))
    assert 'initialization_policy' not in wiring['resources'][0], (
        'the contract stated a policy, so this case would contradict rather '
        'than fill')
    gap_request = compile_request(other, gap_wiring)
    gap_document = json.loads(gap_request.read_text(encoding='utf-8'))
    gap_document['memory'] = [{'resource_id': 'rom0',
                               'initialization_policy': 'commit-once'}]
    filled, _ = compiled_request(write(tmp_path / 'accepted.json', gap_document))
    baseline, _ = compiled_paths(other, gap_wiring)
    assert filled['F1']['status'] == 'executable'
    assert baseline['F1']['status'] == 'executable'


def test_the_cli_reports_the_same_chain(tmp_path):
    """The shipped entry point, not just the library call, reaches the contract."""
    compose = compose_document(tmp_path, memory=[ROM, RAM])
    output = tmp_path / 'cli-out'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    result = subprocess.run(
        [sys.executable, str(ROOT / 'scripts/generate_local_harness_set.py'),
         '--compose', str(compose), '--output', str(output),
         '--base-dir', str(ROOT)],
        cwd=ROOT, capture_output=True, text=True, env=environment)
    assert result.returncode == 0, result.stderr[-2000:]
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload['status'] == 'generated'
    assert payload['components'] == ['cpu', 'gpio']

    paths, document = compiled_paths(
        tmp_path, output / 'wiring_contract.json')
    assert document['counts']['executable'] == 4, (
        'the CLI produced a contract no path can be compiled from')
    assert paths['F1']['sources']
