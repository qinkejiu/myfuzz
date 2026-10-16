"""Opt-in raw CPU ticks from measured STEP_CPU receipts, software transport."""
from unittest.mock import patch

import pytest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.session import GeneratedLocalSession


def cpu_session(*, enabled=None):
    from tests.local_harness.test_cpu_session import GeneratedCpuSessionTests
    base = GeneratedCpuSessionTests()
    base.setUp()
    if enabled is None:
        return base.cpu
    cpu = GeneratedCve2Session(base.cpu.artifact, base_dir=base.cpu.base_dir,
        cache_dir=base.cpu.cache_dir, memory=base.memory, router=base.router,
        physical_tick_samples=enabled)
    cpu._case_id, cpu._process = base.cpu._case_id, base.cpu._process
    return cpu


def step(cpu, *, capture=None):
    from tests.local_harness.test_cpu_session import make_receipt
    def command(op, fields):
        receipt = make_receipt(cpu, fields, {})
        if capture is not None:
            capture.append(receipt)
        return receipt
    with patch.object(GeneratedLocalSession, 'command', side_effect=command):
        return cpu.step_local({'irq': 0})


def test_default_cpu_keeps_existing_last_samples_without_raw_stream():
    cpu = cpu_session()
    step(cpu)
    assert len(cpu.last_samples) == 1
    assert cpu.drain_tick_samples() == []


def test_enabled_cpu_stream_preserves_receipts_and_drains_detached_once():
    cpu = cpu_session(enabled=True)
    receipts = []
    step(cpu, capture=receipts)
    step(cpu, capture=receipts)
    receipts[0].payload['samples'][0]['pre']['backend']['i_req_addr'] = 123
    samples = cpu.drain_tick_samples()
    assert [s['local_tick'] for s in samples] == [1, 2]
    assert samples[0]['pre']['backend']['i_req_addr'] == 0
    samples[1]['post']['backend']['i_req_addr'] = 456
    assert cpu.last_samples[0]['post']['backend']['i_req_addr'] == 0
    assert cpu.drain_tick_samples() == []


def test_cpu_stream_uses_lifetime_ticks_after_process_tick_reset():
    from dataclasses import replace
    from tests.local_harness.test_cpu_session import make_receipt
    cpu = cpu_session(enabled=True)
    cpu._tick_base = cpu.local_ticks = 100
    def command(op, fields):
        receipt = make_receipt(cpu, fields, {})
        receipt.payload['samples'][0]['local_tick'] = 1
        return replace(receipt, tick_before=0, tick_after=1)
    with patch.object(GeneratedLocalSession, 'command', side_effect=command):
        cpu.step_local({'irq': 0})
    assert cpu.drain_tick_samples()[0]['local_tick'] == 101


def test_full_cpu_stream_rejects_before_command_and_never_evicts():
    cpu = cpu_session(enabled=True)
    for _ in range(256):
        step(cpu)
    with patch.object(GeneratedLocalSession, 'command') as command:
        with pytest.raises(RuntimeError, match='tick.*capacity'):
            cpu.step_local({'irq': 0})
        command.assert_not_called()
    assert len(cpu.drain_tick_samples()) == 256
    step(cpu)
    assert cpu.drain_tick_samples()[0]['local_tick'] == 257


@pytest.mark.parametrize('enabled', (0, 1, None, 'true'))
def test_cpu_stream_switch_requires_exact_bool(enabled):
    from tests.local_harness.test_cpu_session import GeneratedCpuSessionTests
    base = GeneratedCpuSessionTests()
    base.setUp()
    with pytest.raises(ValueError, match='physical.*boolean'):
        GeneratedCve2Session(base.cpu.artifact, base_dir=base.cpu.base_dir,
            cache_dir=base.cpu.cache_dir, memory=base.memory, router=base.router,
            physical_tick_samples=enabled)


def test_cpu_stream_identity_is_explicit_only_when_enabled():
    with patch.object(GeneratedLocalSession, 'identity_document', return_value={}):
        assert 'cpu_physical_tick_stream' not in cpu_session().identity_document()
        document = cpu_session(enabled=True).identity_document()['cpu_physical_tick_stream']
    assert document == {'schema_version': 'cpu_physical_tick_stream.v1',
                        'capacity': 256, 'sampling': 'pre_post'}


def test_cpu_reset_clears_undrained_ticks():
    cpu = cpu_session(enabled=True)
    step(cpu)
    with patch.object(GeneratedLocalSession, 'reset_local', return_value={}):
        cpu.reset_local()
    assert cpu.drain_tick_samples() == []


def test_rejected_cpu_reset_preserves_undrained_ticks():
    cpu = cpu_session(enabled=True)
    step(cpu)
    cpu._process = None
    with pytest.raises(RuntimeError, match='not running'):
        cpu.reset_local()
    assert len(cpu.drain_tick_samples()) == 1


@pytest.mark.parametrize('case_id', ('duplicate', ''))
def test_rejected_cpu_begin_preserves_undrained_ticks(case_id):
    cpu = cpu_session(enabled=True)
    step(cpu)
    if not case_id:
        cpu._process = None  # Exercise invalid ID independently of duplicate begin.
    with pytest.raises(ValueError):
        cpu.begin_case(case_id)
    assert len(cpu.drain_tick_samples()) == 1
