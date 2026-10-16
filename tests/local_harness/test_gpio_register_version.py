"""Only actual registered command receipts can issue live GPIOEN versions."""
import os
from pathlib import Path
from types import SimpleNamespace
import pytest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
from tests.local_harness.test_renderer import real_plan, ROOT


def target(tmp_path, causal=True):
    profile='pulp_gpio_causal_local' if causal else 'pulp_gpio'
    plan=real_plan(f'configs/peripherals/{profile}/component_profile.json','gpio')
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
    return GeneratedPulpGpioSession(artifact,base_dir=ROOT,cache_dir=tmp_path)


def test_version_rejects_unregistered_target_and_unobserved_state(tmp_path):
    with pytest.raises(ValueError,match='fresh-actual-target'):
        GpioRegisterVersionAuthority(SimpleNamespace())
    with pytest.raises(ValueError,match='producer-unsupported'):
        GpioRegisterVersionAuthority(target(tmp_path,False))
    gpio=target(tmp_path)
    authority=GpioRegisterVersionAuthority(gpio)
    with pytest.raises(ValueError,match='current-state-unavailable'):
        authority.issue(reset_epoch=0)
    with pytest.raises(ValueError,match='already-installed'):
        GpioRegisterVersionAuthority(gpio)
    with pytest.raises(ValueError,match='actual-producer-required'):
        authority._actual_command(gpio,'STEP_GPIO',(0,),SimpleNamespace())
    with pytest.raises(ValueError,match='authority-invalid'):
        authority.issue(reset_epoch=0)


def test_version_rejects_replaced_producer_before_install(tmp_path,monkeypatch):
    from myfuzz.local_harness.session import GeneratedLocalSession
    gpio=target(tmp_path)
    monkeypatch.setattr(GeneratedLocalSession,'_command_impl',lambda *a:None)
    with pytest.raises(ValueError,match='producer method drift'):
        GpioRegisterVersionAuthority(gpio)


@pytest.mark.skipif(os.environ.get('MYFUZZ_GPIO_VERSION_REAL')!='1',reason='real RTL gate')
def test_actual_GPIOEN_versions_revoke_and_follow_real_writes(tmp_path):
    gpio=target(Path(os.environ.get('MYFUZZ_GPIO_VERSION_CACHE',str(tmp_path))))
    authority=GpioRegisterVersionAuthority(gpio,max_tokens=1)
    gpio.prepare_local();gpio.begin_case('live-gpioen-version')
    try:
        gpio.step_local({'gpio_in':0})
        first=authority.issue(reset_epoch=0)
        assert authority.consume(first)['value']==0
        with pytest.raises(ValueError,match='token-invalid-or-revoked'):
            authority.consume(first)
        from myfuzz.scenario.router import DataflowRouter,DeviceWindow
        from myfuzz.scenario.ledger import TransactionLedger,TransactionKey
        router=DataflowRouter((DeviceWindow('gpio',0x40001000,4096,gpio),))
        ledger=TransactionLedger()
        for sequence,value in enumerate((0x55,0xaa),1):
            old=authority.issue(reset_epoch=0)
            key=TransactionKey('version-gate','live-gpioen-version','cpu',0,'data',sequence)
            router.transact(ledger,key,address=0x40001004,write=True,wdata=value,be=15,beat_bytes=4)
            with pytest.raises(ValueError,match='token-invalid-or-revoked'):
                authority.consume(old)
            assert authority.consume(authority.issue(reset_epoch=0))['value']==value
        assert [w['after'] for w in authority.writes()]==[0x55,0xaa]
        assert all(w['context']['source_transaction']['source_component']=='cpu'
                   for w in authority.writes())
        old=authority.issue(reset_epoch=0)
        gpio.reset_local()
        with pytest.raises(ValueError,match='current-state-unavailable'):
            authority.consume(old)
        gpio.step_local({'gpio_in':0})
        assert authority.consume(authority.issue(reset_epoch=1))['value']==0
        authority._tokens={object():{'value':123}}
        with pytest.raises(ValueError,match='token-invalid-or-revoked'):
            authority.consume(next(iter(authority._tokens)))
        authority.issue(reset_epoch=1)
        with pytest.raises(ValueError,match='token-capacity'):
            authority.issue(reset_epoch=1)
        with pytest.raises(ValueError,match='authority-invalid'):
            authority.consume(object())
    finally:
        gpio.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_GPIO_VERSION_REAL')!='1',reason='real RTL gate')
def test_actual_write_capacity_aborts_process_and_revokes_versions(tmp_path):
    gpio=target(Path(os.environ.get('MYFUZZ_GPIO_VERSION_CACHE',str(tmp_path))))
    authority=GpioRegisterVersionAuthority(gpio,max_writes=1)
    gpio.prepare_local();gpio.begin_case('write-capacity')
    try:
        gpio.step_local({'gpio_in':0})
        gpio.write_register(4,0x55)
        token=authority.issue(reset_epoch=0)
        with pytest.raises(ValueError,match='write-capacity'):
            gpio.write_register(4,0xaa)
        assert gpio.process is None
        with pytest.raises(ValueError,match='authority-invalid'):
            authority.consume(token)
    finally:
        gpio.end_case()
