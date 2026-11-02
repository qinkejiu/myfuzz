from myfuzz.integration.shared_gpio_irq_isr import _firmware_view
from tests.integration.test_compiled_f6_firmware import contract
from tests.integration.test_shared_irq_dispatcher import declaration
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware


def test_shared_gpio_view_uses_GPIO_branch_and_exact_memory_positions():
    c=contract();c['program_contract']['gpio_irq']=declaration()
    program=build_f6_firmware(c);stages=program.document()['irq_dispatch']['stages']
    view=_firmware_view(program)
    assert [pc for pc,_ in view['retirement_path']]==stages['gpio_dispatch_path']+stages['gpio']['instruction_addresses']
    assert not set(stages['dma']['instruction_addresses']) & {pc for pc,_ in view['retirement_path']}
    assert view['read_retirement_pcs'][36]==stages['gpio_status_ack']
    assert view['write_retirement_pcs'][4]==stages['gpio_status_store']
    offsets=view['transaction_sequence_offsets']
    assert offsets[2]<offsets[3]<offsets[0]<offsets[1]
    assert len(set(offsets))==4


def test_saved_support_dictionary_cannot_create_live_GPIO_ISR_evidence(monkeypatch):
    from types import SimpleNamespace
    from myfuzz.integration.shared_gpio_irq_isr import observe_shared_gpio_irq
    import myfuzz.integration.shared_irq_firmware as checker
    def must_not_observe(*args):
        raise AssertionError('unregistered support reached native observer')
    monkeypatch.setattr(checker,'observe_irq_isr',must_not_observe)
    runtime=SimpleNamespace(cpu=object())
    receipt=SimpleNamespace(case_id='forged-case')
    forged={'case_id':'forged-case','flow':'F5','fixed_support':{'role':'fixed_support'}}
    result=observe_shared_gpio_irq(runtime,receipt,forged,forged)
    assert result['status']=='unknown'
    assert result['certificates']==[]
    assert result['reward_eligible'] is False
    assert result['grants_prerequisites'] is False


def test_gpio_irq_uses_gpio_route_even_when_f4_targets_another_device():
    from types import SimpleNamespace
    import pytest
    from myfuzz.integration.shared_gpio_irq_isr import _gpio_irq_access

    gpio, timer = object(), object()
    declared = (SimpleNamespace(target_instance='peripheral', device_id='gpio-mmio', base=0x40001000, size=4096),
                SimpleNamespace(target_instance='target', device_id='timer-mmio', base=0x40003000, size=4096))
    routed = (SimpleNamespace(device_id='gpio-mmio', base=0x40001000, size=4096, target=gpio),
              SimpleNamespace(device_id='timer-mmio', base=0x40003000, size=4096, target=timer))
    runtime = SimpleNamespace(cpu_id='cpu', compiled_inputs={'request': SimpleNamespace(wiring=SimpleNamespace(windows=declared))},
        runner=SimpleNamespace(sessions={'peripheral':gpio, 'target':timer,
            'cpu':SimpleNamespace(router=SimpleNamespace(windows=routed))}))
    irq = {'component':'peripheral', 'gpio_base':0x40001000}
    assert _gpio_irq_access(runtime, irq) == {'device_id':'gpio-mmio'}
    runtime.runner.sessions['peripheral'] = timer
    with pytest.raises(ValueError, match='GPIO-IRQ.*route'):
        _gpio_irq_access(runtime, irq)
