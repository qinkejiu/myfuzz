"""P7-I2: input ownership is compiled from D3, never borrowed from a family.

The ownership map answers one question per physical environment input bit: is it
a fuzzable *source*, a *bound* delivery target, or a declared *fixed* constant?
The shipped runtime families answer it with a hand-written table; a generic path
must not copy that table, because the plan's rule is that no input is borrowed
from a family when the compiled document does not declare it.

These tests pin the compiled answer:

* a single-device composition compiles completely from D3 plus the wiring
  contract's ``fixed_inputs`` constants, and the result is admissible;
* the dual-GPIO composition's D3 declares no ``gpio_b.gpio_in[8]`` source, so the
  bit cannot be owned - the family's extra source is never borrowed, and offering
  it as a claim leaves it ``declared-not-compiled`` (which the existing admission
  refuses by name);
* an input that is neither source-, bound- nor fixed-declared refuses;
* fixed/source/bound conflicts, ranges outside their input, overlapping
  declarations and a non-representable source mask are all named refusals.

No test here starts RTL: D2 renders source only, D3 compiles declarations only.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.auto_harness_test import (build_path_compile_request,
                                                    load_composition)
from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
from myfuzz.scenario.compiled_ownership import (ORIGIN_D3_BOUND, ORIGIN_D3_SOURCE,
                                                ORIGIN_DECLARED, ORIGIN_FIXED,
                                                CompiledOwnershipRefused,
                                                compile_compiled_ownership,
                                                compiled_owner_document)
from myfuzz.scenario.compiled_paths import (PathCompilationError,
                                            compile_paths,
                                            load_path_compile_request,
                                            load_path_wiring)
from myfuzz.scenario.ownership import InputField, InputOwner

ROOT = Path(__file__).resolve().parents[2]

#: One CPU plus one PULP GPIO.  Its non-protocol inputs are the GPIO pins input
#: and the CPU's external-interrupt pin; both are environment inputs.
SOLO_COMPOSE = ROOT / 'configs' / 'scenarios' / 'ibex-pulp-gpio'
#: One CPU plus two instances of the same GPIO profile, the shape both shipped
#: runtime families wire.
DUAL_COMPOSE = ROOT / 'configs' / 'scenarios' / 'ibex-pulp-dual-gpio'
#: The generic F4 target composition (Ibex + PULP GPIO) whose D3 request is given
#: an ``environment_links`` width so one real ``external_pin`` source exists.
F4_COMPOSE = ROOT / 'configs' / 'scenarios' / 'compiled-f4-obi-apb-ibex'

ENVIRONMENT_LINKS = ({
    'link_id': 'pins', 'component_instance': 'peripheral',
    'endpoint_id': 'gpio.pins', 'width': 32, 'event_kind': 'pin_value'},)


def _generate(source_compose: Path, destination: Path, *, fixed_inputs=None,
              environment_links=(), ip_capabilities=()) -> dict:
    """D2 + D3 for one composition copy, with only declared additions."""
    shutil.copytree(source_compose, destination)
    compose_path = destination / 'compose.json'
    if fixed_inputs is not None:
        document = json.loads(compose_path.read_text(encoding='utf-8'))
        document['fixed_inputs'] = fixed_inputs
        compose_path.write_text(json.dumps(document, indent=2), encoding='utf-8')
    compose = load_compose(compose_path, base_dir=ROOT)
    generated = destination / 'generated'
    generate_harness_set(compose, base_dir=ROOT, compose_base=destination,
                         output_root=generated)
    composition = load_composition(compose_path, base_dir=ROOT)
    request_document, _ = build_path_compile_request(
        composition, wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=ip_capabilities)
    if environment_links:
        request_document['environment_links'] = [dict(row)
                                                 for row in environment_links]
    request = load_path_compile_request(request_document, base_dir=ROOT)
    compiled = compile_paths(request)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    wiring = json.loads((generated / 'wiring_contract.json').read_text(
        encoding='utf-8'))
    return {'compose': compose_path, 'generated': generated,
            'request': request, 'compiled': compiled,
            'artifacts': artifacts, 'wiring': wiring}


@pytest.fixture(scope='module')
def solo(tmp_path_factory):
    """A composition whose every non-protocol input is a declared constant."""
    destination = tmp_path_factory.mktemp('solo') / 'compose'
    return _generate(SOLO_COMPOSE, destination, fixed_inputs=[
        {'component_instance': 'gpio', 'port': 'gpio_in', 'bit_offset': 0,
         'width': 32, 'constant': 0},
        {'component_instance': 'cpu', 'port': 'irq_external_i', 'bit_offset': 0,
         'width': 1, 'constant': 0},
    ])


@pytest.fixture(scope='module')
def dual(tmp_path_factory):
    """The dual-GPIO composition: D3 declares no external pin source for it."""
    destination = tmp_path_factory.mktemp('dual') / 'compose'
    return _generate(DUAL_COMPOSE, destination)


@pytest.fixture(scope='module')
def gpio_f4(tmp_path_factory):
    """One composition with a real D3 ``external_pin`` source (width declared)."""
    destination = tmp_path_factory.mktemp('f4') / 'compose'
    return _generate(F4_COMPOSE, destination, environment_links=ENVIRONMENT_LINKS,
                     ip_capabilities=[F4_COMPOSE / 'test_capability.json'])


def _fixed(component, port, width, constant=0, offset=0):
    return {'component_instance': component, 'port': port, 'bit_offset': offset,
            'width': width, 'constant': constant}


def _dual_fixed_inputs():
    return [
        _fixed('cpu', 'irq_external_i', 1),
        _fixed('gpio_a', 'gpio_in', 32),
        _fixed('gpio_b', 'gpio_in', 8),
        _fixed('gpio_b', 'gpio_in', 23, offset=9),
    ]


def _admission(fixture, result):
    return admit_compiled_artifacts(
        artifacts=fixture['artifacts'], request=fixture['request'],
        compiled=fixture['compiled'], ownership=result.ownership,
        physical_port_map={(row['component_id'], row['port']): row['port']
                           for row in result.document['inputs']})


def _owners(document):
    return {(row['component_id'], row['port'], row['bit_offset'], row['width']): row
            for row in document['owners']}


# ---------------------------------------------------------------------------
# a complete compilation, and the admission it really feeds
# ---------------------------------------------------------------------------

def test_a_single_device_composition_compiles_completely(solo):
    """D3 + ``fixed_inputs`` own every non-protocol input bit, end to end."""
    # D2 wrote the declared section, and D3 read it back as declared.
    assert solo['wiring']['fixed_inputs'] == [
        {'component_instance': 'gpio', 'port': 'gpio_in', 'bit_offset': 0,
         'width': 32, 'constant': 0},
        {'component_instance': 'cpu', 'port': 'irq_external_i', 'bit_offset': 0,
         'width': 1, 'constant': 0},
    ]
    assert 'fixed_inputs' in solo['compiled']['identity']['wiring']['declared_sections']

    result = compile_compiled_ownership(
        artifacts=solo['artifacts'], compiled=solo['compiled'],
        fixed_inputs=solo['wiring']['fixed_inputs'])
    document = result.document
    assert document['status'] == 'compiled'
    inputs = {(row['component_id'], row['port']): row
              for row in document['inputs']}
    # The GPIO pins input and the CPU's interrupt pin are the whole surface.
    assert set(inputs) == {('cpu', 'irq_external_i'), ('gpio', 'gpio_in')}
    assert inputs[('gpio', 'gpio_in')]['width'] == 32
    assert inputs[('cpu', 'irq_external_i')]['width'] == 1
    owners = _owners(document)
    for key, row in owners.items():
        assert row['origin'] == ORIGIN_FIXED, (key, row)
        assert row['kind'] == 'fixed'
        assert row['producer_ref'] == 'constant_zero'
    assert set(owners) == {
        ('cpu', 'irq_external_i', 0, 1), ('gpio', 'gpio_in', 0, 32)}
    # Every bit is classified, so the existing admission accepts the exact map.
    admission = _admission(solo, result)
    assert admission['status'] == 'compatible', admission['refusals']


def test_a_declared_source_and_a_fixed_constant_compose_together(gpio_f4):
    """A real D3 source owns its bits; the rest of the surface is declared fixed."""
    compiled = gpio_f4['compiled']
    sources = [source for path in compiled['paths'] for source in path['sources']
               if source['kind'] == 'external_pin']
    assert len(sources) == 1, sources
    source = sources[0]
    assert (source['component'], source['port'], source['width']) == (
        'peripheral', 'gpio_in', 32)
    result = compile_compiled_ownership(
        artifacts=gpio_f4['artifacts'], compiled=compiled,
        fixed_inputs=[_fixed('processor', 'irq_external_i', 1)])
    owners = _owners(result.document)
    source_owner = owners[('peripheral', 'gpio_in', 0, 32)]
    assert source_owner['origin'] == ORIGIN_D3_SOURCE
    assert source_owner['kind'] == 'source'
    assert source_owner['producer_ref'] == source['source_id']
    fixed_owner = owners[('processor', 'irq_external_i', 0, 1)]
    assert fixed_owner['origin'] == ORIGIN_FIXED
    # The protocol bound inputs are recorded, but they are not pin owners.
    protocol_bound = {row['kind'] for row in result.document['d3_protocol_bound']}
    assert protocol_bound == {'ip_read_response', 'ip_register_commit'}
    assert not any(row['kind'] == 'bound' for row in result.document['owners'])
    assert _admission(gpio_f4, result)['status'] == 'compatible'


# ---------------------------------------------------------------------------
# the family's extra source is never borrowed
# ---------------------------------------------------------------------------

def test_the_family_extra_source_is_not_borrowed(dual):
    """D3 does not declare ``gpio_b.gpio_in[8]``; the compiler cannot own it.

    The shipped family declares that bit as the source ``external_b.pin8``.  The
    compiled ownership must not copy it: with the rest of the surface declared
    fixed, the bit is the one unowned bit and the compilation refuses by name.
    """
    compiled = dual['compiled']
    assert not [source for path in compiled['paths'] for source in path['sources']
                if source['kind'] == 'external_pin'], \
        'the dual composition has no declared external pin width'

    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(artifacts=dual['artifacts'], compiled=compiled,
                                   fixed_inputs=_dual_fixed_inputs())
    assert raised.value.code == 'compiled-input-owner-undeclared'
    assert raised.value.pointer == '/inputs/gpio_b/gpio_in'
    assert raised.value.detail['unowned_inputs'] == [
        {'component_id': 'gpio_b', 'port': 'gpio_in', 'unowned_bits': [[8, 8]]}]

    # Offering the family's table as claims keeps it visible, never compiled.
    claims = (
        (InputField('cpu', 'irq_external_i', 1),
         InputField('gpio_a', 'gpio_in', 32),
         InputField('gpio_b', 'gpio_in', 32)),
        (InputOwner('cpu', 'irq_external_i', 0, 1, 'bound', 'gpio_b.irq'),
         InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
         InputOwner('gpio_b', 'gpio_in', 0, 8, 'bound', 'gpio_a.gpio_out'),
         InputOwner('gpio_b', 'gpio_in', 8, 1, 'source', 'external_b.pin8'),
         InputOwner('gpio_b', 'gpio_in', 9, 23, 'fixed', 'constant_zero')),
    )
    result = compile_compiled_ownership(
        artifacts=dual['artifacts'], compiled=compiled, declared=claims)
    owners = _owners(result.document)
    source_owner = owners[('gpio_b', 'gpio_in', 8, 1)]
    assert (source_owner['kind'], source_owner['producer_ref'],
            source_owner['origin']) == (
        'source', 'external_b.pin8', ORIGIN_DECLARED)
    assert all(row['origin'] == ORIGIN_DECLARED
               for row in result.document['owners'])
    # The map is not a licence: the existing admission refuses the claim by name.
    admission = _admission(dual, result)
    assert admission['status'] == 'refused'
    assert 'ownership-source-uncompiled' in {row['code']
                                             for row in admission['refusals']}


def test_an_input_that_is_neither_source_bound_nor_fixed_refuses(dual):
    """No default owner exists: an undeclared input bit refuses the compilation."""
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(artifacts=dual['artifacts'],
                                   compiled=dual['compiled'])
    assert raised.value.code == 'compiled-input-owner-undeclared'
    listed = {(row['component_id'], row['port']): row['unowned_bits']
              for row in raised.value.detail['unowned_inputs']}
    assert listed == {
        ('cpu', 'irq_external_i'): [[0, 0]],
        ('gpio_a', 'gpio_in'): [[0, 31]],
        ('gpio_b', 'gpio_in'): [[0, 31]],
    }


# ---------------------------------------------------------------------------
# conflicts, widths and overlaps
# ---------------------------------------------------------------------------

def test_a_fixed_input_over_a_compiled_source_is_a_conflict(gpio_f4):
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=gpio_f4['artifacts'], compiled=gpio_f4['compiled'],
            fixed_inputs=[_fixed('processor', 'irq_external_i', 1),
                          _fixed('peripheral', 'gpio_in', 32)])
    assert raised.value.code == 'compiled-input-owner-conflict'
    assert raised.value.detail['conflicts']


def test_two_fixed_inputs_that_overlap_refuse(solo):
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=solo['artifacts'], compiled=solo['compiled'],
            fixed_inputs=[_fixed('cpu', 'irq_external_i', 1),
                          _fixed('gpio', 'gpio_in', 16),
                          _fixed('gpio', 'gpio_in', 16, offset=8)])
    assert raised.value.code == 'compiled-input-owner-conflict'
    assert raised.value.detail['conflicts'][0]['bit'] == 8


def test_a_fixed_input_outside_its_input_width_refuses(solo):
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=solo['artifacts'], compiled=solo['compiled'],
            fixed_inputs=[_fixed('cpu', 'irq_external_i', 1),
                          _fixed('gpio', 'gpio_in', 2, offset=31)])
    assert raised.value.code == 'compiled-fixed-input-range-exceeds-input'
    assert raised.value.detail['input_width'] == 32


def test_a_fixed_input_that_fits_its_width_is_accepted(solo):
    """The range rule is exact: 8 bits ending at bit 31 fit, 9 do not."""
    result = compile_compiled_ownership(
        artifacts=solo['artifacts'], compiled=solo['compiled'],
        fixed_inputs=[_fixed('cpu', 'irq_external_i', 1),
                      _fixed('gpio', 'gpio_in', 24),
                      _fixed('gpio', 'gpio_in', 8, constant=0xAB, offset=24)])
    owners = _owners(result.document)
    assert set(owners) == {('cpu', 'irq_external_i', 0, 1),
                           ('gpio', 'gpio_in', 0, 24),
                           ('gpio', 'gpio_in', 24, 8)}
    assert owners[('gpio', 'gpio_in', 24, 8)]['producer_ref'] == 'constant_0xab'


def test_a_source_outside_a_declared_abi_input_refuses(gpio_f4):
    altered = json.loads(json.dumps(gpio_f4['compiled']))
    source = next(row for path in altered['paths'] for row in path['sources']
                  if row['kind'] == 'external_pin')
    # The mask stays representable, so the range check is the one that fires.
    source['bit_offset'] = 8
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=gpio_f4['artifacts'], compiled=altered,
            fixed_inputs=[_fixed('processor', 'irq_external_i', 1)])
    assert raised.value.code == 'compiled-source-not-abi-input'


def test_a_source_with_a_non_representable_mask_refuses(gpio_f4):
    altered = json.loads(json.dumps(gpio_f4['compiled']))
    source = next(row for path in altered['paths'] for row in path['sources']
                  if row['kind'] == 'external_pin')
    source['mask'] = 1 << source['width']
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=gpio_f4['artifacts'], compiled=altered,
            fixed_inputs=[_fixed('processor', 'irq_external_i', 1)])
    assert raised.value.code == 'compiled-source-mask-not-representable'


def test_a_declared_claim_that_contradicts_d3_refuses(gpio_f4):
    claims = ((InputField('peripheral', 'gpio_in', 32),),
              (InputOwner('peripheral', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),))
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=gpio_f4['artifacts'], compiled=gpio_f4['compiled'],
            fixed_inputs=[_fixed('processor', 'irq_external_i', 1)],
            declared=claims)
    assert raised.value.code == 'compiled-owner-declaration-conflict'
    assert 'never reused' in raised.value.detail['requires']


def test_a_declared_claim_for_an_undeclared_input_refuses(solo):
    claims = ((InputField('gpio', 'not_a_port', 32),),
              (InputOwner('gpio', 'not_a_port', 0, 32, 'fixed', 'constant_zero'),))
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(
            artifacts=solo['artifacts'], compiled=solo['compiled'],
            fixed_inputs=solo['wiring']['fixed_inputs'], declared=claims)
    assert raised.value.code == 'declared-owner-not-physical'


# ---------------------------------------------------------------------------
# the wiring-contract section D3 must understand
# ---------------------------------------------------------------------------

def _wiring_contract(**fixed_inputs):
    return {
        'schema_version': 'wiring_contract.v1',
        'delivery': 'transaction_level_explicit',
        'global_interconnect': False,
        'cycle_accurate': False,
        'cpu': {'instance_id': 'cpu', 'endpoint_id': 'cpu.bus'},
        'windows': [],
        'fixed_inputs': list(fixed_inputs.get('rows', ())),
    }


def test_the_fixed_input_section_is_closed():
    document = _wiring_contract(rows=[_fixed('gpio', 'gpio_in', 8)])
    wiring = load_path_wiring(document)
    row, = wiring.fixed_inputs
    assert (row.component_instance, row.port, row.bit_offset, row.width,
            row.constant) == ('gpio', 'gpio_in', 0, 8, 0)
    assert 'fixed_inputs' in wiring.declared_sections

    unknown = _wiring_contract(rows=[{**_fixed('gpio', 'gpio_in', 8),
                                      'value': 1}])
    with pytest.raises(PathCompilationError) as raised:
        load_path_wiring(unknown)
    assert raised.value.code == 'wiring-fixed-input-field-unknown'

    missing = _wiring_contract(rows=[{'component_instance': 'gpio',
                                      'port': 'gpio_in', 'constant': 0}])
    with pytest.raises(PathCompilationError) as raised:
        load_path_wiring(missing)
    assert raised.value.code == 'wiring-fixed-input-field-missing'

    too_large = _wiring_contract(rows=[_fixed('gpio', 'gpio_in', 1, constant=2)])
    with pytest.raises(PathCompilationError) as raised:
        load_path_wiring(too_large)
    assert raised.value.code == 'wiring-fixed-input-constant-exceeds-width'


def test_a_contract_without_the_section_declares_no_constant(dual):
    """Old documents keep their bytes and their behaviour: no default constant."""
    assert 'fixed_inputs' not in dual['wiring']
    wiring = load_path_wiring(dual['wiring'])
    assert wiring.fixed_inputs == ()
    assert 'fixed_inputs' not in wiring.declared_sections


# ---------------------------------------------------------------------------
# the physical CPU IRQ bound end (the F5 shape no admitted composition reaches)
# ---------------------------------------------------------------------------

def _irq_artifact():
    """A minimal loaded-artifact shape: one CPU IRQ input, no protocol pins."""
    profile = SimpleNamespace(
        cpu=SimpleNamespace(irq_entry_endpoint='cpu.irq',
                            irq_entry_role='external'),
        endpoints=[SimpleNamespace(endpoint_id='cpu.irq', protocol=None,
                                   fields=[SimpleNamespace(
                                       role='external', aliases=['irq_i'])])])
    abi = {'ports': [{'physical_port': 'irq_i', 'direction': 'input',
                      'width': 1, 'bit_lo': 0, 'bit_hi': 0,
                      'endpoint_id': 'cpu.irq', 'role': 'external'}]}
    return SimpleNamespace(structural=SimpleNamespace(abi_document=abi),
                           plan=SimpleNamespace(profile=profile))


def _irq_compiled(*, with_producer=True):
    rows = [{'input_id': 'dev.irq.irq', 'kind': 'ip_irq', 'component': 'dev',
             'endpoint_id': 'dev.irq'}] if with_producer else []
    rows.append({'input_id': 'cpu.cpu.irq.external', 'kind': 'cpu_irq_input',
                 'component': 'cpu', 'endpoint_id': 'cpu.irq'})
    return {'schema_version': 'compiled_paths.v1',
            'paths': [{'path_id': 'F5:dev.irq', 'flow_id': 'F5',
                       'status': 'executable', 'sources': [],
                       'bound_inputs': rows}]}


def test_the_cpu_irq_bound_end_comes_from_the_paired_ip_producer():
    """A bound end is owned by the real IP output, never by a random source."""
    result = compile_compiled_ownership(artifacts={'cpu': _irq_artifact()},
                                        compiled=_irq_compiled())
    document = result.document
    owner, = document['owners']
    assert (owner['component_id'], owner['port'], owner['kind'],
            owner['producer_ref'], owner['origin']) == (
        'cpu', 'irq_i', 'bound', 'dev.irq.irq', ORIGIN_D3_BOUND)
    assert [row['kind'] for row in document['d3_producer_bound']] == ['ip_irq']

    without = _irq_compiled(with_producer=False)
    with pytest.raises(CompiledOwnershipRefused) as raised:
        compile_compiled_ownership(artifacts={'cpu': _irq_artifact()},
                                   compiled=without)
    assert raised.value.code == 'compiled-bound-producer-unknown'
    assert 'never a random source' in raised.value.detail['requires']


def test_the_audit_document_names_every_origin(solo):
    document = compiled_owner_document(
        artifacts=solo['artifacts'], compiled=solo['compiled'],
        fixed_inputs=solo['wiring']['fixed_inputs'])
    assert document['schema_version'] == 'compiled_ownership.v1'
    assert {row['origin'] for row in document['owners']} == {ORIGIN_FIXED}
    assert document['inputs_sha256'].startswith('sha256:')
    assert document['compiled_paths_sha256'].startswith('sha256:')
    assert 'declared-not-compiled' in ' '.join(document['not_claimed'])
