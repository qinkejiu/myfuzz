"""Full slot configuration is captured once and remains exactly guarded."""
from dataclasses import replace
import pytest
from myfuzz.scenario.memory import PersistentMemory
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory


def installed(native_factory):
    runner = native_factory()
    memory = runner.sessions['cpu'].memory
    memory.declare_instruction_slots(0x11000, 4096)
    runner.sessions['gpio_a'].configure_ordinary_apb_access_receipts()
    runner.install_ordinary_apb_access_evidence()
    return runner._ordinary_apb_access_evidence, memory


def test_repeated_validation_does_not_reserialize_entire_slot_identity(native_factory, monkeypatch):
    calls = []
    original = PersistentMemory.identity_document
    def counted(memory):
        calls.append(memory)
        return original(memory)
    monkeypatch.setattr(PersistentMemory, 'identity_document', counted)
    observer, memory = installed(native_factory)
    before = len(calls)
    for _ in range(3):
        observer.validate()
    assert len(calls) == before
    assert len(observer.configuration()['bindings'][0]['memory']['instruction_slots']) == 16384


@pytest.mark.parametrize('mutation', ['slots_same_length', 'slots_grow', 'seed', 'region'])
def test_full_memory_configuration_drift_remains_rejected(native_factory, mutation):
    observer, memory = installed(native_factory)
    if mutation == 'slots_same_length':
        old = min(memory._instruction_slots)
        memory._instruction_slots.remove(old)
        memory._instruction_slots.add((old[0], old[1] + 20000))
    elif mutation == 'slots_grow':
        memory.declare_instruction_slots(0x21000, 1)
    elif mutation == 'seed':
        memory.initialization_seed += 1
    else:
        memory._regions = (replace(memory._regions[0], writable=not memory._regions[0].writable), *memory._regions[1:])
    with pytest.raises(ValueError):
        observer.validate()
    assert observer.snapshot()['status'] == 'incomplete'


def test_startup_digest_is_readonly_and_snapshot_uses_cached_digest(native_factory, monkeypatch):
    observer, _ = installed(native_factory)
    digest = observer.snapshot()['configuration_sha256']
    assert observer.configuration_sha256 == digest
    with pytest.raises(AttributeError):
        observer.configuration_sha256 = '0' * 64
    import myfuzz.scenario.ordinary_apb_access_evidence as module
    original = module._json
    def reject_full_configuration(value):
        assert value is not observer._configuration
        return original(value)
    monkeypatch.setattr(module, '_json', reject_full_configuration)
    assert observer.snapshot()['configuration_sha256'] == digest


def test_export_guard_keeps_incomplete_prefix_but_rejects_configuration_drift(native_factory):
    observer, memory = installed(native_factory)
    observer._fail('actual_callback_failed')
    observer.validate(allow_incomplete=True)
    assert observer.snapshot()['reason'] == 'actual_callback_failed'
    with pytest.raises(ValueError, match='permanently-incomplete'):
        observer.validate()
    memory.initialization_seed += 1
    with pytest.raises(ValueError, match='memory-configuration-drift'):
        observer.validate(allow_incomplete=True)
