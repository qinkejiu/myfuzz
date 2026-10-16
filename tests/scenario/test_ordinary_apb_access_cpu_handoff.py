"""Actual generated CPU/router/target objects, strict parsed software transport."""
from dataclasses import asdict

from tests.local_harness.test_ordinary_apb_access_receipts import native_factory, software_transport


def test_actual_cpu_queued_read_hands_key_and_measured_reply_to_target(native_factory):
    runner = native_factory()
    cpu = runner.sessions['cpu']
    target = runner.sessions['gpio_a']
    target.configure_ordinary_apb_access_receipts()
    calls = software_transport(target, rdata=0x12345678)
    cpu._case_id = 'stream'
    window = next(row for row in cpu.router.windows if row.device_id == 'gpio_a')
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    key = cpu.router.acceptances[-1]['source_transaction']
    assert cpu._queued_mmio and cpu.router.deliveries == []
    assert cpu.router.drain_one('gpio_a')
    delivery = cpu.router.deliveries[-1]
    receipt = delivery['target_access_receipt']
    assert delivery['source_delivery_confirmed'] is True
    assert receipt['source_transaction'] == asdict(key)
    assert receipt['delivery_context']['window_base'] == window.base
    assert receipt['rdata'] == 0x12345678
    assert cpu._pending_data == (0x12345678, 0, key.source_sequence)
    assert not cpu._queued_mmio and cpu.mmio_read_count == 1
    assert len(calls) == 1
    assert all(not receipt[name] for name in ('grants_verified', 'grants_storage', 'grants_functional'))
    assert all(row['ordinary_apb_access_ref']['access_id'] == receipt['access_id']
               for row in target.drain_tick_samples())
    assert not cpu.router.enqueue(cpu.service.ledger, key, address=window.base + 12,
        write=False, wdata=0, be=15, beat_bytes=4,
        callback=lambda result: (_ for _ in ()).throw(AssertionError('duplicate callback')))
    assert not cpu.router.drain_one('gpio_a')
    assert len(calls) == 1
