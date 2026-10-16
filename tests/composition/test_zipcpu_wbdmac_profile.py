"""Static DMA slice A contracts; no DMA clocks or transfers are simulated."""
import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'configs/peripherals/zipcpu_wbdmac'


def test_profile_maps_every_elaborated_port_once_and_keeps_pipelined_master():
    profile = load_component_profile(DIRECTORY/'component_profile.json')
    document = json.loads((DIRECTORY/'component_profile.json').read_text())
    ports = json.loads((DIRECTORY/'evidence/elaborated_ports.json').read_text())['ports']
    declared = [(r['port'], 'input', 1) for r in document['clocks']+document['resets']]
    for endpoint in document['endpoints']:
        declared += [(field['aliases'][0], field['direction'], field['width'])
                     for field in endpoint['fields']]
    assert len(declared) == len(set(name for name, _, _ in declared)) == len(ports)
    assert set(declared) == {(p['name'], p['direction'], p['width']) for p in ports}
    assert profile.source.revision == 'git:42606d2d6ef55df313772232977621b2d72f0159'
    master = next(e for e in profile.endpoints if e.endpoint_id == 'dma.memory')
    assert master.protocol == ('wishbone', 'pipelined')
    assert len([e for e in profile.endpoints if e.function == 'mmio_slave']) == 1


def test_source_lock_and_measured_closure_are_pinned_without_runtime_claim():
    lock = json.loads((ROOT/'configs/soc/sources.lock.json').read_text())
    record = next(r for r in lock['components'] if r['id'] == 'zipcpu_wbdmac')
    closure_path = ROOT / record['elaboration']['evidence']
    assert hashlib.sha256(closure_path.read_bytes()).hexdigest() == record['elaboration']['evidence_sha256']
    closure = json.loads(closure_path.read_text())
    assert closure['lint']['exit_code'] == closure['lint']['errors'] == 0
    assert record['runtime_status'] == 'runtime_unverified'
    for row in closure['closure_files']:
        assert hashlib.sha256((ROOT/row['root']/row['path']).read_bytes()).hexdigest() == row['sha256']
    assert closure['closure_files'][0]['sha256'] == 'a948bab4a155ddc42be1d9b2ee588c1b8b9c9ab587d9e5125e24870c2169aacd'


def test_initial_transfer_configuration_uses_executable_rtl_key_and_word_count():
    config = json.loads((DIRECTORY/'ram_to_ram_config.json').read_text())
    assert config['start_control'] == 0x0FED0004
    assert config['total_length_words'] == config['block_words'] == 4
    assert config['master_address_translation'] == 'zero_extend(word_address) << 2'
    assert config['master_fixed_byte_enable'] == 15
    assert config['runtime_status'] == 'unsupported_composite_dma_runtime'
