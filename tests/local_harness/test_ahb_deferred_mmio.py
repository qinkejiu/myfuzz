"""Deferred AHB service checks without starting a generated CPU."""
from types import SimpleNamespace

from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow


class Target:
    def read_register(self, offset):
        return 0x1234

    def write_register(self, offset, value, *, be=15):
        pass


def session():
    result = object.__new__(GeneratedAhbMemorySession)
    result.router = DataflowRouter((DeviceWindow('target', 0x40001000, 4096, Target()),))
    result.service = SimpleNamespace(ledger=TransactionLedger())
    result.defer_mmio = True
    result._pending = None
    result.last_samples = ()
    result._pending_error = 0
    result._queued_mmio = False
    result._sequence_memory = 1
    result.mmio_read_count = result.mmio_write_count = 0
    return result


def test_deferred_request_has_no_response_until_real_router_callback():
    from myfuzz.local_harness.native_session import _QUEUED_RESPONSE
    local = session()
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    assert local._service_accepted_request(key, 0x40001000, 0, 15, 0) is _QUEUED_RESPONSE
    assert local._pending is None and local._queued_mmio
    assert local.mmio_read_count == 0
    assert local.router.drain_one('target')
    assert local._pending == (0x1234, 1)
    assert local._pending_error == 0 and not local._queued_mmio
    assert local.mmio_read_count == 1


def test_target_callback_preserves_real_error_bit():
    local = session()
    callbacks = []
    local.router.enqueue = lambda *a, callback, **k: callbacks.append(callback) or True
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    local._service_accepted_request(key, 0x40001000, 0, 15, 0)
    callbacks[0]((0xAB, 1))
    assert local._pending == (0xAB, 1)
    assert local._pending_error == 1


def test_cancel_removes_queued_work_and_callback_cannot_complete():
    local = session()
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    local._service_accepted_request(key, 0x40001000, 0, 15, 0)
    local._cancel_queued_mmio()
    assert not local._queued_mmio
    assert not local.router.drain_one('target')
    assert local._pending is None


def test_queued_request_withholds_backend_ready_and_error_reaches_native_input():
    from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
    local = session()
    local._quiescing = False
    local._online_instruction_slots = False
    local._native_bus_observer = None
    local._artifact_document = {'physical_exports': []}
    local.memory = SimpleNamespace(advance_step=lambda: None)
    local.reset_epoch = 0
    local._observe_verified_memory_edge = lambda receipt: None
    local._record_native_bus_receipt = lambda receipt, pending: None
    controls_seen = []

    def command(operation, controls):
        controls_seen.append(controls)
        pre = dict(zip(('m_req_ready', 'm_rsp_valid', 'm_rsp_rdata', 'm_rsp_error'), controls))
        pre.update(m_req_valid=0, m_rsp_ready=1, m_req_write=0,
                   m_req_addr=0, m_req_wdata=0, m_req_be=15)
        return SimpleNamespace(status='result', new_ticks=1,
            payload={'pre_backend': pre, 'samples': [{'pre': {'backend': pre}}],
                     'observations': {'physical': {}}})

    local.command = command
    local._queued_mmio = True
    GeneratedNativeMemorySession.step_local(local, {})
    assert controls_seen[-1] == (0, 0, 0, 0)
    local._queued_mmio = False
    local._pending, local._pending_error = (0xAB, 1), 1
    result = GeneratedNativeMemorySession.step_local(local, {})
    assert controls_seen[-1] == (0, 1, 0xAB, 1)
    assert result['data_rsp_consumed'] == 1
    assert local._pending is None and local._pending_error == 0


def test_startup_exports_original_envelopes_once_and_detaches_them():
    local = session()
    record = {'startup_edge_index': 0, 'reset_pre': 1, 'reset_post': 1,
              'sample': {'pre': {'physical': {'hprot': 3}}}}
    local._ahb_startup_records = [record]
    local._ahb_startup_output_pending = True
    outputs = {}
    local._attach_ahb_startup_samples(outputs)
    assert outputs['ahb_startup_samples'] == [record]
    outputs['ahb_startup_samples'][0]['sample']['pre']['physical']['hprot'] = 0
    assert record['sample']['pre']['physical']['hprot'] == 3
    outputs = {}
    local._attach_ahb_startup_samples(outputs)
    assert 'ahb_startup_samples' not in outputs


def test_explicit_hold_uses_actual_requested_declared_slot_without_source():
    local = session()
    local.instruction_source = None
    local.hold_declared_instructions = True
    local._measured_request = lambda: (0xC0000100, False)
    local._instruction_slot_required = lambda address: address == 0xC0000100
    local._boot_word_required = lambda: False
    assert local._held_instruction_address() == 0xC0000100
    local._measured_request = lambda: (0xC0000100, True)
    assert local._held_instruction_address() is None


def test_actual_rtl_ready_equation_waits_for_response_and_keeps_idle_ready():
    import re
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] /
              'src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv').read_text()
    equation = re.search(r'assign HREADYEXT\s*=\s*(.*?);', source).group(1)
    equation = equation.replace('&&', ' and ').replace('||', ' or ')
    for state in range(5):
        for reset_n in (0, 1):
            for valid in (0, 1):
                actual = eval(equation, {'__builtins__': {}},
                    dict(rst_ni=reset_n, state_q=state, IDLE=0, COMPLETE=4, rsp_valid_i=valid))
                assert bool(actual) == bool(reset_n and (state == 0 or (state == 4 and valid)))


def test_declared_hold_sees_new_post_request_before_next_edge_accepts_it():
    local = session()
    local.instruction_source = None
    local.hold_declared_instructions = True
    local.last_samples = ({'pre': {'backend': {'m_req_valid': 0}},
                           'post': {'backend': {'m_req_valid': 1, 'm_req_write': 0,
                                               'm_req_addr': 0xC0000100}}},)
    local._instruction_slot_required = lambda address: address == 0xC0000100
    local._boot_word_required = lambda: False
    assert local._held_instruction_address() == 0xC0000100


def test_default_sync_service_still_runs_target_inline():
    local = session()
    local.defer_mmio = False
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    assert local._service_accepted_request(key, 0x40001000, 0, 15, 0) == 0x1234
    assert not local._queued_mmio and local._pending is None
    assert local.mmio_read_count == 1
    assert not local.router.pending_targets


def test_end_cancels_queue_even_when_cleanup_raises_primary(monkeypatch):
    import pytest
    from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
    local = session()
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    local._service_accepted_request(key, 0x40001000, 0, 15, 0)
    failure = RuntimeError('primary close failure')
    def close(self):
        raise failure
    monkeypatch.setattr(GeneratedNativeMemorySession, 'end_case', close)
    with pytest.raises(RuntimeError) as caught:
        local.end_case()
    assert caught.value is failure
    assert not local._queued_mmio and not local.router.pending_targets


def test_reset_cancels_queued_response_and_reports_it(monkeypatch):
    from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
    local = session()
    key = TransactionKey('run', 'case', 'cpu', 0, 'memory', 1)
    local._service_accepted_request(key, 0x40001000, 0, 15, 0)
    local._ahb_observer = SimpleNamespace(require_active=lambda: None, end_scope=lambda: None)
    local.instruction_source = None
    local.declare_boot_instruction_slot = lambda: None
    monkeypatch.setattr(GeneratedNativeMemorySession, 'reset_local',
                        lambda self: {'cancelled_responses': 0})
    assert local.reset_local()['cancelled_responses'] == 1
    assert not local._queued_mmio and not local.router.pending_targets


def test_ahb_online_acceptance_uses_latched_original_hprot_not_next_bus():
    local = session()
    local._online_instruction_slots = True
    local.native_instruction_fetch_count = 0
    local._ahb_accepted_request = {'address': 0xC0000000, 'write': 0, 'hprot': 0}
    # Current bus can carry an unrelated data address; it is not the held beat.
    sample = {'pre': {'physical': {'HPROT': 3}}}
    pre = {'m_req_addr': 0xC0000000, 'm_req_write': 0}
    local._check_native_online_acceptance(pre, sample)
    assert local.native_instruction_fetch_count == 1


def test_ahb_online_acceptance_rejects_missing_or_mismatched_source():
    import pytest
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    local = session()
    local._online_instruction_slots = True
    local.native_instruction_fetch_count = 0
    pre = {'m_req_addr': 0xC0000000, 'm_req_write': 0}
    for source in (None, {'address': 0xC0000004, 'write': 0, 'hprot': 0},
                   {'address': 0xC0000000, 'write': 0, 'hprot': None}):
        local._ahb_accepted_request = source
        with pytest.raises(ProtocolEnvironmentError):
            local._check_native_online_acceptance(pre, {})
    assert local.native_instruction_fetch_count == 0


def test_actual_source_backed_ahb_can_declare_online_slots_without_fake_marker():
    from pathlib import Path
    import pytest
    from tests.local_harness.test_ahb_lite_session import _artifact, _memory, ROOT
    artifact = _artifact()
    local = GeneratedAhbMemorySession(artifact, base_dir=ROOT,
        cache_dir=Path('/tmp/unused-ahb-online-declaration'), memory=_memory(),
        defer_mmio=True, hold_declared_instructions=True)
    assert 'instruction_identity_observation' not in local._artifact_document
    local.declare_instruction_slots(0xC0000100, 16)
    assert local._online_instruction_slots
    local._online_instruction_slots = False
    local._ahb_signal_map.pop('hprot')
    with pytest.raises(ValueError):
        local.declare_instruction_slots(0xC0000200, 16)


def test_address_phase_identity_is_captured_before_observer_advances():
    local = session()
    original = {'address': 0xC0000000, 'write': 0, 'controls': {'hprot': 0}}
    def observe(sample, *, rows):
        original['address'] = 0x40001000
        original['controls']['hprot'] = 3
    local._ahb_observer = SimpleNamespace(pending=original, observe=observe)
    local._ahb_rows = lambda sample: {}
    local.last_samples = ({'pre': {'backend': {'m_req_valid': 1, 'm_req_ready': 1}}},)
    local._observe_verified_memory_edge(None)
    assert local._ahb_accepted_request == {'address': 0xC0000000, 'write': 0, 'hprot': 0}


def test_plain_native_session_still_requires_physical_marker():
    import pytest
    from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
    local = object.__new__(GeneratedNativeMemorySession)
    local._process = None
    local._case_id = None
    local._artifact_document = {}
    with pytest.raises(ValueError, match='physical instruction identity'):
        local.declare_instruction_slots(0, 1)
