"""Task5 read issuance on the exact ScenarioRunner DMA subclass.

This uses a software transport double. It exercises the real Wishbone session
step, MemoryService callback, issued-read bridge, and Task5 consumer, but makes
no native RTL or hardware claim.
"""
import json

import pytest

from myfuzz.local_harness.wishbone_dma_scenario_session import (
    GeneratedWishboneDmaScenarioSession,
)
from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
from myfuzz.scenario.memory_service import (
    _f6_dma_read_results,
    _validate_f6_dma_read,
)
from tests.integration.f6_compiled_support import inputs, make_case


def test_task5_dma_read_issuer_executes_on_scheduler_subclass(
        inputs, tmp_path, monkeypatch):
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case

    runtime, attempt = make_case(inputs, tmp_path, monkeypatch,
        dma_session_type=GeneratedWishboneDmaScenarioSession)

    assert type(runtime.dma) is GeneratedWishboneDmaScenarioSession
    from myfuzz.local_harness.wishbone_dma_session import (
        GeneratedWishboneDmaSession, _f6_dma_session_instance_data_is_canonical,
        _f6_dma_session_type_allowlist,
    )
    assert _f6_dma_session_type_allowlist() == (
        GeneratedWishboneDmaSession, GeneratedWishboneDmaScenarioSession)
    assert _f6_dma_session_instance_data_is_canonical(runtime.dma)
    issued = _f6_dma_read_results(runtime.dma)
    assert len(issued) == 4
    for key, snapshot, handle in issued:
        event = _validate_f6_dma_read(runtime.dma,
            runtime.dma.memory_service, key, snapshot, handle)
        callback_rows = [row for row in runtime.dma.memory_service.events
            if row.get('kind') == 'memory_read'
            and row.get('transaction') == {
                name: getattr(key, name) for name in key.__dataclass_fields__}]
        assert len(callback_rows) == 1
        assert event == json.loads(json.dumps(callback_rows[0]))
        assert event['kind'] == 'memory_read'
        ledger_entry = runtime.dma.memory_service.ledger._entries[key]
        assert ledger_entry.status == 'complete'
        assert ledger_entry.receipt is snapshot

    material = capture_f6_case(runtime, attempt)
    assert [row['status'] for row in material['observations'].values()] == [
        'passed'] * 5, {
            eid: (row['status'], row['reason'])
            for eid, row in material['observations'].items()}

    samples = runtime.dma.drain_tick_samples()
    assert samples
    irq_name = runtime.dma._irq_runtime_name
    for sample in samples:
        assert sample['local_tick'] > 0
        assert sample['pre']['physical'][irq_name] in (0, 1)
        assert sample['post']['physical'][irq_name] in (0, 1)


@pytest.mark.parametrize('mutation', [
    'unregistered_subclass', 'instance_shadow', 'method_drift'])
def test_task5_consumer_rejects_unpinned_scheduler_dma(mutation,
        inputs, tmp_path, monkeypatch):
    from myfuzz.integration.compiled_f6_consumer import capture_f6_case

    runtime, attempt = make_case(inputs, tmp_path, monkeypatch,
        dma_session_type=GeneratedWishboneDmaScenarioSession)
    if mutation == 'unregistered_subclass':
        class UnregisteredDma(GeneratedWishboneDmaSession):
            pass
        replacement = object.__new__(UnregisteredDma)
        replacement.__dict__.update(runtime.dma.__dict__)
        runtime.dma = replacement
    elif mutation == 'instance_shadow':
        runtime.dma.artifact_kind = 'wishbone_dma'
    else:
        monkeypatch.setattr(GeneratedWishboneDmaScenarioSession,
            'step_local', GeneratedWishboneDmaSession.step_local)

    material = capture_f6_case(runtime, attempt)
    assert any(row['status'] == 'failed'
        for row in material['observations'].values())
