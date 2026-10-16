"""Code-owned queue callback confirmation, separate from mutable deliveries."""
from dataclasses import asdict

import pytest
from tests.scenario.test_ordinary_apb_access_router import setup, enqueue


def test_successful_callback_confirmation_is_detached_and_not_public_delivery():
    target, router, ledger, key = setup()
    enqueue(router, ledger, key, lambda response: None)
    assert router.drain_one('gpio_a')
    confirmation = router.ordinary_delivery_confirmation(key)
    assert confirmation['source_transaction'] == asdict(key)
    assert confirmation['source_delivery_confirmed'] is True
    assert confirmation['target_access_id'] == router.deliveries[0]['target_access_id']
    router.deliveries[0]['read_value'] = 999
    confirmation['target_access_receipt']['delivery_context']['offset'] = 88
    original = router.ordinary_delivery_confirmation(key)
    assert original['read_value'] == 7
    assert original['target_access_receipt']['delivery_context']['offset'] == 4


def test_synchronous_public_boolean_cannot_create_callback_confirmation():
    target, router, ledger, key = setup()
    router.transact(ledger, key, address=0x40000004, write=False,
                    wdata=0, be=15, beat_bytes=4)
    router.deliveries[0]['source_delivery_confirmed'] = True
    with pytest.raises(ValueError):
        router.ordinary_delivery_confirmation(key)


def test_failed_callback_public_forgery_cannot_create_confirmation():
    target, router, ledger, key = setup()
    def fail(response):
        raise RuntimeError('source callback failed')
    enqueue(router, ledger, key, fail)
    with pytest.raises(RuntimeError):
        router.drain_one('gpio_a')
    router.deliveries.append(dict(source_transaction=key, source_delivery_confirmed=True,
                                 target_access_id='access:1'))
    with pytest.raises(ValueError):
        router.ordinary_delivery_confirmation(key)
    assert len(target.calls) == 1


def test_confirmation_is_unavailable_before_callback_returns():
    target, router, ledger, key = setup()
    def callback(response):
        with pytest.raises(ValueError):
            router.ordinary_delivery_confirmation(key)
    enqueue(router, ledger, key, callback)
    assert router.drain_one('gpio_a')
    assert router.ordinary_delivery_confirmation(key)['read_value'] == 7


def test_confirmation_capacity_refuses_before_second_target_command(monkeypatch):
    import myfuzz.scenario.router as module
    monkeypatch.setattr(module, '_MAX_ORDINARY_DELIVERY_CONFIRMATIONS', 1, raising=False)
    target, router, ledger, key = setup()
    enqueue(router, ledger, key, lambda response: None)
    router.drain_one('gpio_a')
    from dataclasses import replace
    second = replace(key, source_sequence=2)
    enqueue(router, ledger, second, lambda response: pytest.fail('capacity callback'))
    with pytest.raises(ValueError, match='capacity'):
        router.drain_one('gpio_a')
    assert len(target.calls) == 1
    assert router.ordinary_delivery_confirmation(key)['read_value'] == 7
