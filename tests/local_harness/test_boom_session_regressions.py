"""Focused software regressions; these fixtures do not claim RTL execution."""
import json
from pathlib import Path

import pytest

from myfuzz.local_harness import boom_cpu_session as native
from myfuzz.scenario.boom_gpio_verification import scoped_prefix


def _artifact(tmp_path, monkeypatch):
    output = tmp_path / 'output'
    output.mkdir()
    module = Path(native.__file__)
    canonical = {'source_revision': 'pinned', 'source_manifest_sha256': 'manifest',
                 'profile_sha256': 'profile', 'manager_sha256': 'manager',
                 'trace_verifier_sha256': 'verifier'}

    def authenticate(repo, temporary):
        rtl = temporary / 'cpu.v'
        rtl.write_text('authenticated RTL')
        return {**canonical, 'command': ['verilator', str(rtl)]}

    monkeypatch.setattr(native, 'generate', authenticate)
    monkeypatch.setattr(native.subprocess, 'Popen', lambda *a, **kw: pytest.fail('invalid closure launched native process'))
    artifact = {**canonical, 'schema_version': 'generated_boom_session.v1',
        'python_session_sha256': native.digest(module),
        'generator_sha256': native.digest(module.with_name('tilelink_coherent_cpu_session.py')),
        'driver_sha256': native.digest(module.with_name('boom_cpu_driver.cpp')),
        'session_files': {'driver.cpp': native.digest(module.with_name('boom_cpu_driver.cpp')),
                         'tl_ram.h': 'manager', 'cpu.v': __import__('hashlib').sha256(b'authenticated RTL').hexdigest(),
                         'obj/VBoomTile': 'executable'}}
    return output, artifact


@pytest.mark.parametrize('name', ['obj/VBoomTile', 'tl_ram.h', 'cpu.v'])
def test_missing_required_manifest_entry_rejected_before_launch(tmp_path, monkeypatch, name):
    output, artifact = _artifact(tmp_path, monkeypatch)
    del artifact['session_files'][name]
    (output / 'session-artifact.json').write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match='file set mismatch'):
        native.GeneratedBoomCpuSession(output, repo=tmp_path)


@pytest.mark.parametrize('name', ['tl_ram.h', 'cpu.v'])
def test_rehashed_modified_manager_or_rtl_rejected_before_launch(tmp_path, monkeypatch, name):
    output, artifact = _artifact(tmp_path, monkeypatch)
    artifact['session_files'][name] = 'attacker-updated-local-file-hash'
    (output / 'session-artifact.json').write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match='authenticated source closure mismatch'):
        native.GeneratedBoomCpuSession(output, repo=tmp_path)


def test_duplicate_response_rejected_without_native_command():
    session = object.__new__(native.GeneratedBoomCpuSession)
    session.reset_epoch = 2
    session._external_pending = {'source': 1, 'size': 2, 'request_sequence': 7}
    session._external_response_submitted = False
    commands = []
    session._command = lambda *args: commands.append(args)
    response = dict(source=1, size=2, request_sequence=7, reset_epoch=2, data=53 << 32)
    session.respond_external(**response)
    with pytest.raises(ValueError, match='does not match'):
        session.respond_external(**response)
    assert len(commands) == 1


def test_stale_epoch_response_does_not_reach_native_command():
    session = object.__new__(native.GeneratedBoomCpuSession)
    session.reset_epoch = 3
    session._external_pending = {'source': 1, 'size': 2, 'request_sequence': 1}
    session._external_response_submitted = False
    session._command = lambda *args: pytest.fail('stale response reached native transport')
    with pytest.raises(ValueError, match='does not match'):
        session.respond_external(source=1, size=2, request_sequence=1, reset_epoch=2)


def test_full_prefix_scope_policy_preserves_payloads_and_unknown_identities():
    ids = {'cpu_execution': 'cpu-nonce', 'coherent_stream': 'stream-nonce',
           'gpio_execution': 'gpio-nonce', 'runner_execution': 'runner-nonce'}
    row = {'execution_id': 'cpu-nonce', 'raw_event_scope': 'stream-nonce',
           'local_event_id': 'stream-nonce|cpu|7|accept',
           'payload': {'data': 'cpu-nonce', 'execution_id': 'cpu-nonce'},
           'source_transaction': {'execution_id': 'cpu-nonce', 'source_sequence': 7}}
    normalized = scoped_prefix([row], ids)[0]
    assert normalized['execution_id'] == 'declared-scope:cpu_execution'
    assert normalized['local_event_id'] == 'declared-scope:coherent_stream|cpu|7|accept'
    assert normalized['payload'] == row['payload']
    assert normalized['source_transaction']['source_sequence'] == 7
    assert row['execution_id'] == 'cpu-nonce'


@pytest.mark.parametrize('change', [
    {'size': 1}, {'address': 0x400d}, {'mask': 0x0f},
    {'opcode': 6}, {'param': 1}, {'source': 8}, {'reset_epoch': 0},
])
def test_invalid_register_shape_cannot_enqueue_or_touch_target(change):
    from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow

    class Target:
        def write_register(self, *args, **kwargs):
            pytest.fail('invalid request touched real-target interface')

        def read_register(self, *args, **kwargs):
            pytest.fail('invalid request touched real-target interface')

    adapter = object.__new__(GeneratedBoomScenarioSession)
    adapter.router = DataflowRouter((DeviceWindow('device', 0x4000, 0x1000, Target()),))
    adapter.mmio_ledger = TransactionLedger()
    adapter.reset_epoch = 1
    adapter._active = None
    request = dict(channel='A', opcode=0, param=0, size=2, source=1,
                   address=0x400c, mask=0xf0, data=53 << 32,
                   request_sequence=1, reset_epoch=1)
    request.update(change)
    with pytest.raises(ValueError):
        adapter._enqueue(request)
    assert adapter.router.acceptances == []
    assert adapter.router.pending_targets == ()
    assert adapter.mmio_ledger.pending_keys == ()


def test_code_owned_discovery_scope_reuses_walk_but_preserves_bytes():
    import hashlib
    import sys
    from myfuzz.local_harness import build
    code = build._discover_host_sources.__code__
    calls = []

    def profile(frame, event, arg):
        if event == 'call' and frame.f_code is code:
            calls.append(1)

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        first = build._host_sources()
        second = build._host_sources()
        unscoped_calls = len(calls)
        calls.clear()
        with build.host_source_discovery_scope():
            scoped_first = build._host_sources()
            scoped_second = build._host_sources()
        scoped_calls = len(calls)
    finally:
        sys.setprofile(previous)
    assert first == second == scoped_first == scoped_second
    assert unscoped_calls == 2
    assert scoped_calls == 1
    assert all(hashlib.sha256(first[name]).digest() == hashlib.sha256(scoped_second[name]).digest()
               for name in first)
