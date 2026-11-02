"""A short declaration builds reusable F2/F4 scenario files."""
import json
from pathlib import Path

import pytest

from scripts.generate_mmio_scenario import _select_name, generate_scenario
from myfuzz.local_harness.harness_set import load_compose
from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records

ROOT = Path(__file__).resolve().parents[2]


def test_cpu_and_apb_profiles_generate_all_four_paths_without_pair_request(tmp_path):
    cpu_path = 'configs/cpus/cv32e20_profile_irq_adapter/component_profile.json'
    ip_path = 'configs/peripherals/profile_only_idle_i2c/component_profile.json'
    cap_path = 'configs/peripherals/profile_only_idle_i2c/test_capability.json'
    cpu = json.loads((ROOT / cpu_path).read_text())
    ip = json.loads((ROOT / ip_path).read_text())
    capability = json.loads((ROOT / cap_path).read_text())
    capability.pop('component_id'); capability.pop('profile_fingerprint')
    ip['evidence']['embedded_test_capability'] = capability
    ip['evidence']['local_harness'] = {'reset_assert_ticks': 2, 'reset_release_ticks': 3, 'max_wait_cycles': 16}
    for path, doc in ((cpu_path, cpu), (ip_path, ip)):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc))
    out = tmp_path / 'generated'
    descriptor = generate_scenario(dict(name='profile-only', cpu_profile=cpu_path, ip_profile=ip_path,
        mmio_base=0x40001000, ram={'base': 65536, 'size': 196608},
        write_values=[0x55], memory_flows=True), base_dir=tmp_path, output=out)
    doc = json.loads(descriptor.read_text())
    assert set(doc['flow_ids']) == {'F1', 'F2', 'F3', 'F4'}
    assert set(doc['executors'].values()) == {'compiled_mmio'}
    compose = json.loads((out / 'compose.json').read_text())
    assert json.loads((out / compose['cpu']['request']).read_text())['profile_path'] == cpu_path
    request = json.loads((out / compose['devices'][0]['request']).read_text())
    assert request['profile_path'] == ip_path
    assert request['schema_version'] == 'local_harness.v2'
    assert request['tuning']['endpoint_policies'] == [dict(endpoint_id='i2c.bus',
        template_id='target.apb3', template_version='1', variant_id='full-word', max_outstanding=1)]
    assert (out / 'ip_test_capability.json').is_file()


def test_ambiguous_endpoint_or_register_requires_explicit_selection():
    with pytest.raises(ValueError, match='ambiguous'):
        _select_name({}, 'cpu_endpoint', ('cpu.a', 'cpu.b'), 'CPU data endpoint')
    assert _select_name({'cpu_endpoint': 'cpu.b'}, 'cpu_endpoint',
                        ('cpu.a', 'cpu.b'), 'CPU data endpoint') == 'cpu.b'
    with pytest.raises(ValueError, match='incompatible'):
        _select_name({'register': 'other'}, 'register', ('ctrl',), 'register')


@pytest.mark.parametrize('cpu_request,endpoint,ram,mmio_base', [
    ('configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/requests/processor.json', 'processor.data', {'base': 65536, 'size': 196608}, 0x40001000),
    ('configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/requests/cpu.json', 'processor.memory', {'base': 0, 'size': 65536}, 0x40001000),
    ('configs/scenarios/compiled-f4-obi-wb-uart-setup/requests/processor.json', 'processor.memory', {'base': 0, 'size': 196608}, 0x40001000),
    ('configs/scenarios/cvw-pulp-gpio/requests/cpu.json', 'cpu.external_bus', {'base': 0xc0000000, 'size': 65536}, 0xc0010000),
])
def test_spi_combinations_reuse_profiles_and_public_runtime(tmp_path, cpu_request, endpoint, ram, mmio_base):
    target = 'configs/scenarios/compiled-f2-f4-obi-apb-spi-mmio-ibex/requests/peripheral.json'
    capability = 'configs/scenarios/compiled-f2-f4-obi-apb-spi-mmio-ibex/test_capability.json'
    for relative in (cpu_request, target, capability):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    for request in (cpu_request, target):
        profile_path = json.loads((tmp_path / request).read_text())['profile_path']
        path = tmp_path / profile_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / profile_path).read_bytes())
    declaration = {'name': 'spi-smoke', 'cpu_request': cpu_request, 'ip_request': target,
                   'ip_capability': capability, 'cpu_endpoint': endpoint, 'ip_endpoint': 'spi.bus',
                   'mmio_base': mmio_base, 'register': 'SPICMD', 'register_offset': 8,
                   'ram': ram, 'write_values': [0x55, 0xaa]}
    with pytest.raises(ValueError, match='register'):
        generate_scenario({**declaration, 'register_offset': 0}, base_dir=tmp_path, output=tmp_path / 'bad-offset')
    with pytest.raises(ValueError, match='write_values'):
        generate_scenario({**declaration, 'write_values': [1 << 32]}, base_dir=tmp_path, output=tmp_path / 'bad-value')
    output = tmp_path / 'generated'
    descriptor_path = generate_scenario(declaration, base_dir=tmp_path, output=output)
    descriptor = load_descriptor(descriptor_path, base_dir=tmp_path)
    assert descriptor.executors == {'F2': 'compiled_mmio', 'F4': 'compiled_mmio'}
    rows = json.loads((output / 'acceptance_sequence.json').read_text())
    read_record = (mmio_base + 8).to_bytes(4, 'little').hex()
    assert rows == ['F4:55000000', 'F2:' + read_record, 'F4:aa000000', 'F2:' + read_record]
    assert select_case_records(descriptor, flow='mixed', records=rows) == tuple(tuple(r.split(':')) for r in rows)
    compose = load_compose(descriptor.compose, base_dir=tmp_path)
    assert compose['devices'][0]['bus_endpoint'] == 'spi.bus'
    # The component profiles already provide unambiguous endpoints and the
    # capability identifies the register; callers need not duplicate them.
    compact = {key: value for key, value in declaration.items()
               if key not in ('cpu_endpoint', 'ip_endpoint', 'register', 'register_offset')}
    compact_output = tmp_path / 'compact'
    compact_path = generate_scenario(compact, base_dir=tmp_path, output=compact_output)
    compact_descriptor = load_descriptor(compact_path, base_dir=tmp_path)
    compact_compose = json.loads(compact_descriptor.compose.read_text())
    assert compact_compose['cpu']['data_endpoint'] == endpoint
    assert compact_compose['devices'][0]['bus_endpoint'] == 'spi.bus'
    assert json.loads((compact_output / 'acceptance_sequence.json').read_text()) == rows


def test_reserved_bits_are_not_silently_written(tmp_path):
    paths = [
        'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/requests/processor.json',
        'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/requests/peripheral.json',
        'configs/scenarios/compiled-f2-f4-obi-apb-i2c-ibex/test_capability.json',
        'configs/cpus/ibex_obi_local/component_profile.json',
        'configs/peripherals/pulp_i2c/component_profile.json',
    ]
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    declaration = {'name': 'i2c-smoke', 'cpu_request': paths[0], 'ip_request': paths[1],
                   'ip_capability': paths[2], 'cpu_endpoint': 'processor.data', 'ip_endpoint': 'i2c.bus',
                   'mmio_base': 0x40001000, 'register': 'PRESCALER', 'register_offset': 0,
                   'ram': {'base': 65536, 'size': 196608}, 'write_values': [0x10000]}
    with pytest.raises(ValueError, match='write_values'):
        generate_scenario(declaration, base_dir=tmp_path, output=tmp_path / 'bad')
    declaration['write_values'] = [0x55, 0xaa]
    assert generate_scenario(declaration, base_dir=tmp_path, output=tmp_path / 'ok').is_file()


_TIMING = {'reset_assert_ticks': 2, 'reset_release_ticks': 3, 'max_wait_cycles': 16}
_UART_FILES = (
    'configs/cpus/picorv32_wb/component_profile.json',
    'configs/peripherals/zipcpu_uart/component_profile.json',
    'configs/peripherals/zipcpu_uart/test_capability.json',
)


def _uart_declaration(tmp_path):
    for relative in _UART_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    return {'name': 'uart-setup-side-effectful', 'cpu_profile': _UART_FILES[0],
            'cpu_timing': _TIMING, 'ip_profile': _UART_FILES[1], 'ip_timing': _TIMING,
            'ip_capability': _UART_FILES[2], 'register': 'SETUP',
            'allow_side_effectful_register': True, 'mmio_base': 0x60000000,
            'ram': {'base': 0, 'size': 196608}, 'write_values': [0x55]}


def test_side_effectful_masked_register_still_needs_the_write_policy(tmp_path):
    """``allow_side_effectful_register`` never replaces the declared policy.

    The reviewed SETUP word stores bits [30:0] and resets UART state on a write.
    Selecting it as side-effectful is a separate declaration from the masked
    full-word policy, so a missing ``write_policy`` is refused either way.
    """
    declaration = _uart_declaration(tmp_path)
    output = generate_scenario(declaration, base_dir=tmp_path, output=tmp_path / 'ok')
    assert json.loads((output.parent / 'acceptance_sequence.json').read_text())[0] == 'F4:55000000'
    capability = tmp_path / _UART_FILES[2]
    document = json.loads(capability.read_text())
    assert document['register_semantics'][0]['write_policy'] == 'full_word_reserved_zero'
    document['register_semantics'][0].pop('write_policy')
    capability.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='full_word_reserved_zero policy'):
        generate_scenario(declaration, base_dir=tmp_path, output=tmp_path / 'missing-policy')
    capability.write_text(json.dumps({
        **document, 'register_semantics': [{**document['register_semantics'][0],
            'write_policy': 'full_word_reserved_zero'}]}))
    with pytest.raises(ValueError, match='write_values'):
        generate_scenario({**declaration, 'write_values': [0x80000000]},
                          base_dir=tmp_path, output=tmp_path / 'reserved-bit-value')
