"""Actual shared construction/callbacks, with native launch explicitly forbidden.

These controls verify compatibility, not a DUT execution claim. Root separately
runs the unified scenario original/fresh to validate native OBI consumption.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests.integration.test_shared_f5_runtime import prepared, ROOT


@pytest.fixture
def shared_ram(prepared, tmp_path, monkeypatch):
    from myfuzz.integration import compiled_f4 as f4, compiled_f2 as f2
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    monkeypatch.setattr(GeneratedLocalSession, 'prepare_local', lambda self: None)
    monkeypatch.setattr(GeneratedLocalSession, 'configure_built_executable_receipt', lambda self: None)
    monkeypatch.setattr(GeneratedLocalSession, 'validate_built_executable_receipt', lambda self: {})
    monkeypatch.setattr(f4, 'validate_built_receipts', lambda *args: None)
    monkeypatch.setattr(f2, 'validate_built_receipts', lambda *args: None)
    monkeypatch.setattr(f4, 'build_storage_producer', lambda binding, artifact, base_dir, cache_dir, max_cases:
        (GeneratedPulpGpioSession(artifact, base_dir=base_dir, cache_dir=cache_dir), SimpleNamespace()))
    with patch('subprocess.Popen', side_effect=AssertionError('native launch forbidden')):
        runtime = f4.CompiledF4Runtime(artifacts=prepared.artifacts,
            compiled_inputs=prepared.compiled_inputs(), base_dir=ROOT, cache_dir=tmp_path,
            defer_begin=True, mixed_flows=True, memory_flows=True, f5_preparation=prepared)
    return runtime


def test_shared_exact_cpu_class_and_installed_ram_selector_attach_without_widening(shared_ram):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.integration.shared_f5_runtime import PhysicalIrqCpuSession
    from myfuzz.search.ram_case_adapter import RamRecordSelector
    runtime = shared_ram
    cpu = runtime.runner.sessions[runtime.cpu_id]
    assert type(cpu) is GeneratedCve2Session
    assert PhysicalIrqCpuSession is GeneratedCve2Session
    assert cpu.memory_commit_receipts_enabled and cpu.memory_readback_receipts_enabled
    assert runtime._f2_flows is False and runtime._memory_flows is True
    selector = RamRecordSelector(None, flow='mixed', records=['F3:55000000', 'F1:03200000'],
                                 policy='state', seed=7, cases=4)
    selector.attach_runtime(runtime)
    assert selector._handle.current_state()['status'] == 'unknown'  # No running native scope.
    assert selector.document()['compiled_source_bindings']['F1'] == runtime.memory_bindings['F1'].document()
    assert selector.document()['compiled_source_bindings']['F3'] == runtime.memory_bindings['F3'].document()
    assert selector._runtime is runtime


def test_shared_actual_callbacks_retain_same_writer_versions_and_read_certificates(shared_ram):
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    from myfuzz.runtime.flows.memory import lower_memory_code, RAM_READ_TOKEN
    runtime = shared_ram
    runner = runtime.runner
    cpu = runner.sessions[runtime.cpu_id]
    cpu._case_id = 'software-callback-control'
    address = runtime.result - 4
    code, operation, lowered_address = lower_memory_code(runtime, RAM_READ_TOKEN, flow='F1')
    assert operation == 'ram_read_word' and lowered_address == address and code != RAM_READ_TOKEN
    tracker = LiveMemoryEffectTracker(consumer=runner._memory_dependency_consumer)
    cpu._serve('data', 1, address, 85, 15)
    runner._append_external_events(runtime.cpu_id, 1)
    offset = address - runtime.image['range'][0]
    witnesses = [tracker.retained_ram_witnesses(runtime.image['port'], offset + lane) for lane in range(4)]
    assert all(len(rows) == 1 for rows in witnesses)
    assert runner.memory_dependency_evidence_report()['counts']['verified'] == 0
    cpu._serve('data', 0, address, 0, 15)
    runner._append_external_events(runtime.cpu_id, 1)
    report = runner.memory_dependency_evidence_report()
    assert report['journal_integrity'] is True
    assert report['counts']['verified'] == 4
    assert all(c['byte_version'] == list(witnesses[lane][0].version)
               for lane, c in enumerate(report['certificates']))
    assert all(c['memory_kind'] == 'modeled_host_persistent_memory'
               and c['source_origin'] == 'unknown' for c in report['certificates'])


def test_shared_documents_still_cannot_restore_live_ram_installation(shared_ram):
    from myfuzz.search.ram import install_ram_consumer, read_ram_current
    saved = {'runtime': shared_ram, 'runner': shared_ram.runner}
    assert read_ram_current(saved)['status'] == 'unknown'
    with pytest.raises(ValueError, match='actual mixed RAM runtime'):
        install_ram_consumer(SimpleNamespace(**saved))
