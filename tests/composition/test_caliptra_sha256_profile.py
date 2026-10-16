"""Static Caliptra SHA256 source/profile contracts; no hash engine execution."""
import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT/'configs/peripherals/caliptra_sha256'


def test_physical_profile_preserves_both_reset_inputs_and_all_real_ports():
    profile = load_component_profile(DIRECTORY/'component_profile.json')
    document = json.loads((DIRECTORY/'component_profile.json').read_text())
    ports = json.loads((DIRECTORY/'evidence/elaborated_ports.json').read_text())['ports']
    declared = [(r['port'], 'input', 1) for r in document['clocks']+document['resets']]
    for endpoint in document['endpoints']:
        declared += [(f['aliases'][0], f['direction'], f['width']) for f in endpoint['fields']]
    assert len(declared) == len(set(name for name, _, _ in declared)) == len(ports)
    assert set(declared) == {(r['name'], r['direction'], r['width']) for r in ports}
    assert {r.port for r in profile.resets} == {'reset_n', 'cptra_pwrgood'}
    assert all(r.polarity == 'active_low' and not r.synchronous for r in profile.resets)
    assert profile.source.revision == 'git:49370266d12cb0c4a8f71b3a0ff7e54ba7d4866e'
    assert document['port_actions'] == [{'port':'debugUnlock_or_scan_mode_switch', 'action':'constant', 'value':0,'reason':'Disable debug/scan side effects in initial fixed environment'}]
    assert not document.get('interrupts'), 'passive outputs do not imply IRQ trigger/capture contract'


def test_closure_and_source_lock_pin_actual_measured_inputs_without_runtime_claim():
    lock = json.loads((ROOT/'configs/soc/sources.lock.json').read_text())
    row = next(r for r in lock['components'] if r['id']=='caliptra_sha256')
    closure_path = ROOT/row['elaboration']['evidence']
    assert hashlib.sha256(closure_path.read_bytes()).hexdigest() == row['elaboration']['evidence_sha256']
    closure = json.loads(closure_path.read_text())
    assert closure['lint']['exit_code'] == closure['lint']['errors'] == 0
    assert row['runtime_status'] == 'runtime_unverified'
    for entry in closure['closure_files']:
        assert hashlib.sha256((ROOT/entry['root']/entry['path']).read_bytes()).hexdigest() == entry['sha256']
    names = {e['path'] for e in closure['closure_files']}
    assert 'src/libs/rtl/caliptra_sva.svh' in names
    assert not any('uvm' in n or '/tb/' in n for n in names)


def test_capability_is_identity_bound_and_reset_sequence_is_explicit():
    profile = load_component_profile(DIRECTORY/'component_profile.json')
    capability = load_ip_test_capability(DIRECTORY/'test_capability.json', profile=profile)
    assert capability.component_id == 'caliptra_sha256'
    policy = json.loads((DIRECTORY/'reset_policy.json').read_text())
    assert policy['runtime_status'] == 'unsupported_ahb_lite_register_runtime'
    assert policy['initial_asserted'] == {'reset_n':0,'cptra_pwrgood':0}
    assert policy['released'] == {'reset_n':1,'cptra_pwrgood':1}
