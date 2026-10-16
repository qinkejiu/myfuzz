"""Independent mechanical Popen negatives; never native/RTL-positive authority."""
import copy

import pytest

from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.local_harness.test_native_reset_observation import wire_local


def finish(local):
    if local.process is not None:
        try:
            local.end_case()
        except ValueError:
            if local.process is not None:
                raise


def test_actual_wire_control_then_observer_never_promotes_python_binary(native_factory, tmp_path):
    control = wire_local(native_factory, tmp_path)
    control.begin_case('mechanical-control')
    try:
        reply = control.command('ACCESS_GPIO', (0, 1, 24, 0, 15))
        assert reply.status == 'result' and reply.sequence == 1
    finally:
        finish(control)
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation(max_lifecycles=8, max_commands=32)
    try:
        local.begin_case('mechanical-observation')
        first, = local.native_reset_observation_lifecycles()
        assert first['native_eligible'] is False
        before = copy.deepcopy(local.native_reset_observation_snapshot())
        public = local.native_reset_observation_lifecycles()
        public[0]['native_eligible'] = True
        assert local.native_reset_observation_snapshot() == before
        local.reset_local()
        rows = local.native_reset_observation_lifecycles()
        assert len(rows) == 2 and all(row['native_eligible'] is False for row in rows)
        assert rows[1]['kind'] == 'explicit_reset'
        assert rows[1]['target_epoch'] == rows[0]['target_epoch'] + 1
    finally:
        finish(local)


@pytest.mark.parametrize('name', ['prepare_local', '_command_impl', '_expected_ready'])
@pytest.mark.parametrize('scope', ['instance', 'class'])
def test_preconfigure_method_replacement_cannot_become_new_trust_pin(native_factory, tmp_path, monkeypatch, name, scope):
    local = wire_local(native_factory, tmp_path)
    original = getattr(type(local), name)
    def replacement(self, *args, **kwargs):
        return original(self, *args, **kwargs)
    if scope == 'class':
        monkeypatch.setattr(type(local), name, replacement)
    else:
        monkeypatch.setattr(local, name, replacement.__get__(local, type(local)))
    with pytest.raises(ValueError):
        local.configure_native_reset_observation(max_lifecycles=8, max_commands=32)
    assert not local.native_reset_observation_enabled and local.process is None


def test_parsed_applied_write_then_gpio_take_failure_permanently_incomplete(native_factory, tmp_path):
    local = wire_local(native_factory, tmp_path, bad_padcfg=True)
    local.configure_native_reset_observation(max_lifecycles=8, max_commands=32)
    try:
        local.begin_case('mechanical-applied-write')
        with pytest.raises(ValueError, match='padcfg'):
            local.write_register(24, 0x80000000)
        assert local._sequence == 1
        snapshot = local.native_reset_observation_snapshot()
        assert snapshot['status'] == 'incomplete' and snapshot['commands']
        with pytest.raises(ValueError):
            local._native_reset_observation.validate()
    finally:
        finish(local)


def test_foreign_issuer_and_json_cannot_consume_private_facts(native_factory, tmp_path):
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation(max_lifecycles=8, max_commands=32)
    try:
        local.begin_case('mechanical-foreign-issuer')
        observer = local._native_reset_observation
        with pytest.raises(ValueError):
            observer._register_private_issuer(object(), runner=object())
        with pytest.raises(ValueError):
            observer._private_facts_since(0, issuer=object())
        with pytest.raises(ValueError):
            observer._resolve_fact(local.native_reset_observation_lifecycles()[0], issuer=object())
    finally:
        finish(local)


def test_caller_cannot_inject_fact_through_private_append_method(native_factory, tmp_path):
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation()
    try:
        local.begin_case('mechanical-fact-origin')
        observer = local._native_reset_observation
        with pytest.raises(ValueError):
            observer._fact('lifecycle', local.native_reset_observation_lifecycles()[0],
                           process=local.process, execution=local._execution)
    finally:
        finish(local)


def test_caller_ready_cannot_duplicate_real_parsed_lifecycle(native_factory, tmp_path):
    from myfuzz.local_harness.wire import parse_driver_ready
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation()
    try:
        local.begin_case('mechanical-ready-origin')
        digest, asserted, released, _ = local._expected_ready()
        ready = parse_driver_ready(f'READY local_driver.v1 {digest} {asserted:x} {released:x}',
                                   digest=digest, assert_ticks=asserted, release_ticks=released)
        with pytest.raises(ValueError):
            local._native_reset_observation._ready(local, ready)
    finally:
        finish(local)


@pytest.mark.parametrize('which', ['document', 'process_nonce'])
def test_same_size_fact_registry_tamper_is_detected(native_factory, tmp_path, which):
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation()
    try:
        local.begin_case('mechanical-registry-tamper')
        observer = local._native_reset_observation
        token, kind, encoded, process, execution = observer._facts[0]
        if which == 'document':
            import json
            row = json.loads(encoded)
            row['native_eligible'] = True
            encoded = json.dumps(row, sort_keys=True, separators=(',', ':'))
        else:
            process, execution = object(), 'f' * 32
        observer._facts[0] = (token, kind, encoded, process, execution)
        with pytest.raises(ValueError):
            observer.validate(allow_incomplete=True)
    finally:
        finish(local)


def test_dead_actual_process_before_command_cannot_leave_complete_interval(native_factory, tmp_path):
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation()
    try:
        local.begin_case('mechanical-dead-process')
        local.process.kill()
        local.process.wait(timeout=2)
        with pytest.raises((ValueError, RuntimeError)):
            local.command('STEP_GPIO', (0,))
        state = local.native_reset_observation_snapshot()
        assert state['status'] == 'incomplete'
    finally:
        finish(local)


def test_module_fact_origin_replacement_cannot_authorize_caller_fact(native_factory, tmp_path, monkeypatch):
    from myfuzz.local_harness import native_reset_observation as module
    local = wire_local(native_factory, tmp_path)
    local.configure_native_reset_observation()
    try:
        local.begin_case('mechanical-helper-origin')
        observer = local._native_reset_observation
        row = local.native_reset_observation_lifecycles()[0]
        assert row['native_eligible'] is False
        forged = copy.deepcopy(row)
        forged['lifecycle_ordinal'] = 99
        with monkeypatch.context() as patch:
            patch.setattr(module, '_actual_fact_origin', lambda owner: None)
            with pytest.raises(ValueError):
                observer._fact('lifecycle', forged, process=local.process,
                               execution=local._execution)
                observer.validate(allow_incomplete=True)
        assert local.native_reset_observation_snapshot()['status'] == 'incomplete'
    finally:
        finish(local)
