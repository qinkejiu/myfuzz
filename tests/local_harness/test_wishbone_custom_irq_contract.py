"""Profile-driven Pico IRQ observations; no source or retirement inference."""
from pathlib import Path
from unittest.mock import patch

import pytest

from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession, _LIMITS
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter
from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE

ROOT = Path(__file__).resolve().parents[2]

@pytest.fixture(scope='module')
def cpu_artifact():
    return artifact(PROFILE, 'cpu_irq')


def session(art):
    return GeneratedWishboneCpuSession(art, base_dir=ROOT, cache_dir=ROOT/'unused',
        memory=PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
            initialization_seed=0, max_initialized_bytes=4096),
        router=DataflowRouter(()), custom_irq_observations=True)


def test_profile_declares_source_backed_custom_abi(cpu_artifact):
    from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
    contract = verify_custom_irq_artifact(cpu_artifact, base_dir=ROOT)
    assert contract['abi'] == 'picorv32_custom0'
    assert contract['handler_address'] == 16
    assert contract['retirq_encoding'] == 0x0400000b
    assert contract['source_attribution'] == 'unknown'
    assert contract['retirement'] == 'unknown'


def test_session_observes_real_vector_and_eoi_without_cause_inference(cpu_artifact):
    cpu = session(cpu_artifact)
    physical = {r['runtime_name']: ('0'*r['hex_digits'] if r['width'] > 64 else 0)
                for r in cpu_artifact.runtime_document['physical_exports']}
    ports = {r['physical_port']:r['runtime_name'] for r in cpu_artifact.runtime_document['physical_exports']}
    pre = dict(physical, **{ports['irq']: 8, ports['eoi']: 0})
    post = dict(physical, **{ports['irq']: 8, ports['eoi']: 16})
    backend = {name:0 for name in _LIMITS}
    sample = {'local_tick':1, 'pre':{'backend':backend, 'physical':pre},
              'post':{'backend':backend, 'physical':post}}
    payload = {'kind':'wishbone_cpu','pre_backend':backend,'samples':[sample],
               'observations':sample['post']}
    cpu._case_id = 'test'
    with patch.object(cpu, 'command', return_value=DriverReceipt('result','a'*32,1,0,1,1,payload)):
        observation = cpu.step_local({'irq':8})['custom_irq_observation']
    assert observation['irq_pre'] == 8 and observation['eoi_post'] == 16
    assert observation['source_attribution'] == 'unknown'
    assert observation['retirement'] == 'unknown'


def test_custom_observation_requires_declared_irq_abi():
    disabled = artifact('configs/cpus/picorv32_wb/component_profile.json', 'cpu_disabled')
    with pytest.raises(ValueError, match='custom-IRQ'):
        session(disabled)


def test_custom_observation_identity_is_replay_verified(cpu_artifact):
    from myfuzz.scenario.contracts import _verify_generated_session
    cpu = session(cpu_artifact)
    identity = cpu.identity_document()
    assert _verify_generated_session(identity).runtime_document == cpu_artifact.runtime_document
    identity['cpu_custom_irq_observation']['schema_version'] = 'forged'
    with pytest.raises(ValueError):
        _verify_generated_session(identity)


def test_custom_observation_rejects_driven_input_mismatch(cpu_artifact):
    from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact, observe_custom_irq
    contract = verify_custom_irq_artifact(cpu_artifact, base_dir=ROOT)
    binding = contract['bindings']
    physical = {binding['input_port']:8, binding['eoi_port']:0, binding['trap_port']:0}
    sample = {'local_tick':1, 'pre':{'physical':physical},
              'post':{'physical':{**physical, binding['input_port']:0}}}
    with pytest.raises(ValueError, match='input-sample-mismatch'):
        observe_custom_irq(contract, sample, 8)
