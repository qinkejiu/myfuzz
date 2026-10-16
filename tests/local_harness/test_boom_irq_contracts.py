"""Software contracts only; these tests never claim native IRQ execution."""
import copy
import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_irq_variant_has_exact_second_endpoint_and_exclusive_meip():
    from myfuzz.local_harness.boom_irq_contract import validate_irq_profile
    baseline = json.loads((ROOT/'configs/cpus/boom/component_profile.json').read_text())
    variant = json.loads((ROOT/'configs/cpus/boom_irq/component_profile.json').read_text())
    validate_irq_profile(variant, baseline)
    assert len(variant['endpoints']) == 2
    assert len(variant['endpoints'][0]['fields']) == 39
    for mutate in ('tie', 'alias', 'missing_bus', 'extra_endpoint'):
        bad = copy.deepcopy(variant)
        if mutate == 'tie':
            bad['port_actions'].append({'port':'auto_int_local_in_2_0','action':'constant','value':0})
        elif mutate == 'alias':
            bad['endpoints'][1]['fields'][0]['aliases'] = ['auto_int_local_in_3_0']
        elif mutate == 'missing_bus':
            bad['endpoints'][0]['fields'].pop()
        else:
            bad['endpoints'].append(copy.deepcopy(bad['endpoints'][1]))
        with pytest.raises(ValueError):
            validate_irq_profile(bad, baseline)


@pytest.mark.parametrize('value', [True, -1, 2, '1', None])
def test_bad_irq_input_rejected_before_native_command(value):
    from myfuzz.local_harness.boom_irq_contract import validate_irq_inputs
    with pytest.raises(ValueError):
        validate_irq_inputs({'irq': value})


def test_mret_requires_exact_actual_system_command_and_address():
    from myfuzz.local_harness.boom_irq_contract import observed_mret
    assert observed_mret({'system_return':1,'csr_cmd':4,'csr_addr':0x302})
    for address in (0x102, 0x7b2):
        assert not observed_mret({'system_return':1,'csr_cmd':4,'csr_addr':address})
    assert not observed_mret({'system_return':1,'csr_cmd':1,'csr_addr':0x302})


def test_probe_inventory_requires_actual_exact_name_width_and_no_duplicates():
    from myfuzz.local_harness.boom_irq_contract import PROBES, validate_probe_inventory
    actual = [{'id':key,'path':path,'width':width} for key,(path,width) in PROBES.items()]
    validate_probe_inventory(actual)
    for field, value in [('width', 0), ('path', 'TOP.wrong.core.csr.reg_mie')]:
        bad = copy.deepcopy(actual); bad[0][field] = value
        with pytest.raises(ValueError): validate_probe_inventory(bad)
    with pytest.raises(ValueError): validate_probe_inventory(actual + [actual[0]])


def test_inventory_rejects_boolean_width():
    from myfuzz.local_harness.boom_irq_contract import PROBES, validate_probe_inventory
    rows = [{'id':key,'path':path,'width':width} for key,(path,width) in PROBES.items()]
    rows[0]['width'] = True
    with pytest.raises(ValueError): validate_probe_inventory(rows)


def test_irq_firmware_has_exact_mret_and_no_result_image():
    from myfuzz.scenario.boom_gpio_irq_runner import boom_gpio_irq_program
    image = boom_gpio_irq_program()
    words = [int.from_bytes(image[i:i+4], 'little') for i in range(0,len(image),4)]
    assert len(image) == 1280
    assert words.count(0x30200073) == 1
    assert 0x10200073 not in words and 0x7b200073 not in words
    assert words.index(0x30200073) >= 256


def test_native_irq_inputs_fail_before_transport():
    from myfuzz.local_harness.boom_irq_cpu_session import GeneratedBoomIrqCpuSession
    session = object.__new__(GeneratedBoomIrqCpuSession)
    session._command = lambda *a: pytest.fail('invalid input reached native')
    for value in ({}, {'irq':0,'extra':1}, {'irq':True}, {'irq':2}):
        with pytest.raises(ValueError): session.step_local(value)


def test_irq_variant_stale_epoch_and_duplicate_d_refused_before_command():
    from myfuzz.local_harness.boom_irq_cpu_session import GeneratedBoomIrqCpuSession
    session = object.__new__(GeneratedBoomIrqCpuSession)
    session.reset_epoch = 3
    session._external_pending = dict(source=1,size=2,request_sequence=1)
    session._external_response_submitted = False
    commands=[]
    session._command = lambda *a: commands.append(a)
    with pytest.raises(ValueError):
        session.respond_external(source=1,size=2,request_sequence=1,reset_epoch=2)
    assert commands == []
    session.respond_external(source=1,size=2,request_sequence=1,reset_epoch=3)
    with pytest.raises(ValueError):
        session.respond_external(source=1,size=2,request_sequence=1,reset_epoch=3)
    assert len(commands) == 1


def test_declared_pulse_is_exact64_reset_cancelled_and_overrun_not_extended():
    from myfuzz.scenario.irq import IrqPulseDelivery
    pulse=IrqPulseDelivery(width_ticks=64)
    pulse.observe_source(1,source_tick=4,cpu_tick=10)
    assert sum(pulse.input_at(tick) for tick in range(11,76)) == 64
    pulse.observe_source(0,source_tick=5,cpu_tick=10)
    pulse.observe_source(1,source_tick=6,cpu_tick=10)
    assert pulse.status == 'unsupported_irq_overrun'
    assert pulse.input_at(75) == 0
    pulse.reset(cpu_tick=10)
    assert not pulse.pending and pulse.input_at(11) == 0
    assert any(e['kind']=='pulse_cancelled_by_reset' for e in pulse.events)


def test_irq_profile_loads_without_mutating_baseline():
    from myfuzz.composition.component_profile import load_component_profile
    profile=load_component_profile(ROOT/'configs/cpus/boom_irq/component_profile.json')
    assert profile.component_id == 'boom_irq'


def test_irq_generation_authenticates_sources_without_build(tmp_path, monkeypatch):
    from myfuzz.local_harness import boom_irq_generation as generation
    monkeypatch.setattr(generation.subprocess,'check_output',lambda *a,**kw:'software-test-version')
    artifact=generation.generate_irq(ROOT,tmp_path/'artifact')
    assert artifact['probes_runtime_confirmed'] is False
    assert '--vpi' in artifact['command']
    assert artifact['physical_ports'] == 47 and artifact['coherent_fields'] == 39
    assert artifact['profile_sha256'] != artifact['base_profile_sha256']
    assert set(artifact['auxiliary_hashes']) == set(generation.AUXILIARY)
    assert artifact['driver_sha256'] == generation.digest(tmp_path/'artifact/driver.cpp')
    assert 'boom_irq_scenario_session.py' in artifact['implementation_source_hashes']


@pytest.mark.parametrize('name', ['artifact.json','session-artifact.json',
                                  'irq-session-artifact.json','driver.cpp','unrelated.txt'])
def test_builder_preserves_every_nonempty_output_before_lock_or_generation(tmp_path,monkeypatch,name):
    from myfuzz.local_harness import boom_irq_generation as generation
    output=tmp_path/'output'; output.mkdir()
    sentinel=output/name; sentinel.write_bytes(b'historical-evidence\x00')
    monkeypatch.setattr(generation,'generate_irq',lambda *a:pytest.fail('generation touched nonempty output'))
    monkeypatch.setattr(generation.subprocess,'run',lambda *a,**k:pytest.fail('native/build invoked'))
    with pytest.raises(ValueError,match='empty'):
        generation.build_boom_irq_session(ROOT,output,heavy_lock=tmp_path/'missing-parent/lock')
    assert sentinel.read_bytes() == b'historical-evidence\x00'
    assert list(output.iterdir()) == [sentinel]
    assert not (tmp_path/'missing-parent').exists()


def test_builder_rejects_output_file_and_directory_symlink(tmp_path,monkeypatch):
    from myfuzz.local_harness import boom_irq_generation as generation
    monkeypatch.setattr(generation,'generate_irq',lambda *a:pytest.fail('generation invoked'))
    ordinary=tmp_path/'file'; ordinary.write_text('history')
    empty=tmp_path/'empty'; empty.mkdir()
    link=tmp_path/'link'; link.symlink_to(empty,target_is_directory=True)
    for output in (ordinary,link):
        with pytest.raises(ValueError,match='empty'):
            generation.build_boom_irq_session(ROOT,output,heavy_lock=tmp_path/'missing-parent/lock')
    assert ordinary.read_text() == 'history' and list(empty.iterdir()) == []


@pytest.mark.parametrize('already_exists',[False,True])
def test_builder_allows_new_or_empty_directory_to_reach_generation_only(tmp_path,monkeypatch,already_exists):
    from myfuzz.local_harness import boom_irq_generation as generation
    output=tmp_path/'output'
    if already_exists: output.mkdir()
    class ReachedGeneration(Exception): pass
    def stop(repo,destination):
        assert destination == output
        raise ReachedGeneration
    monkeypatch.setattr(generation,'generate_irq',stop)
    monkeypatch.setattr(generation.subprocess,'run',lambda *a,**k:pytest.fail('native/build invoked'))
    with pytest.raises(ReachedGeneration):
        generation.build_boom_irq_session(ROOT,output,heavy_lock=tmp_path/'test-only.lock')
    assert not output.exists() or list(output.iterdir()) == []


def test_builder_rechecks_output_after_lock_acquisition(tmp_path,monkeypatch):
    from myfuzz.local_harness import boom_irq_generation as generation
    output=tmp_path/'output'; output.mkdir()
    monkeypatch.setattr(generation.fcntl,'flock',lambda *a:(output/'concurrent.json').write_text('preserve'))
    monkeypatch.setattr(generation,'generate_irq',lambda *a:pytest.fail('generation touched concurrently occupied output'))
    with pytest.raises(ValueError,match='empty'):
        generation.build_boom_irq_session(ROOT,output,heavy_lock=tmp_path/'test-only.lock')
    assert (output/'concurrent.json').read_text() == 'preserve'
