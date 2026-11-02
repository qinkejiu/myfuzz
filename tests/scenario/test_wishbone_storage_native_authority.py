"""Native Wishbone storage authority hooks: software-only refusal coverage.

No RTL is compiled or run here.  The observed-protocol assertions are exercised
against the pure ``_analyse_wishbone_transfer`` reducer with hand-built receipts
that reproduce the measured ten-phase write/read shape, and the journal/state
hooks are exercised against a real (rendered, never built) Wishbone artifact
whose session carries a fake live process and a fake built-receipt document.
That is exactly why this module can only assert refusals and journal mechanics:
it never claims native evidence, a build identity or a reset observation.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_driver,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.wishbone_register_session import (
    GeneratedWishboneRegisterSession)
from myfuzz.local_harness.wishbone_storage_probe_contract import (
    ROLES, wishbone_probe_widths)
from myfuzz.scenario import wishbone_storage_register_version as module
from myfuzz.scenario.wishbone_storage_register_version import (
    WISHBONE_STORAGE_CONTEXT_SCHEMA, WishboneStorageRegisterVersionAuthority,
    _analyse_wishbone_transfer)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
BUILD_DIGEST = 'a' * 64
BINARY_SHA256 = 'b' * 64
CONTEXT_KEYS = module._PENDING_CONTEXT_KEYS


@pytest.fixture(scope='module')
def generated():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='uart_setup', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16, tuning={
            'endpoint_policies': [dict(endpoint_id='uart.bus',
                template_id='target.wishbone', template_version='1',
                variant_id='word-addressed-registered-ack',
                max_outstanding=1)],
            'wishbone_storage_observations': [dict(endpoint_id='uart.bus',
                contract_id=CONTRACT, register='SETUP')],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


@pytest.fixture(scope='module')
def observation(generated):
    document = generated.runtime_document
    return dict(signals=deepcopy(document['base_protocol_trace']['signals']),
                widths=wishbone_probe_widths(
                    document['storage_observation']['source_contract']))


def _row(**overrides):
    probes = dict(storage_value=0x19, storage_reset=0, storage_cyc=0,
                  storage_stb=0, storage_we=0, storage_adr=0, storage_sel=0,
                  storage_dat_w=0, storage_ack=0, storage_dat_r=0x19,
                  storage_stall=0)
    for name, value in overrides.items():
        key = name if name in probes else 'storage_' + name
        assert key in probes, key
        probes[key] = value
    return probes


def _sample(tick, pre, post, signals):
    return dict(
        local_tick=tick,
        pre=dict(storage_probes=deepcopy(pre),
                 backend={signals[role]: pre['storage_' + role]
                          for role in ROLES}),
        post=dict(storage_probes=deepcopy(post),
                  backend={signals[role]: post['storage_' + role]
                           for role in ROLES}))


def measured_write_samples(signals, *, value=0x55, before=0x19):
    idle = _row(value=before, dat_r=before)
    request = _row(cyc=1, stb=1, we=1, sel=15, dat_w=value, dat_r=before,
                   value=before)
    held = _row(cyc=1, stb=0, we=1, sel=15, dat_w=value, dat_r=before,
                value=value)
    ack = _row(cyc=1, stb=0, we=1, sel=15, dat_w=value, ack=1, dat_r=value,
               value=value)
    released = _row(value=value, dat_r=value)
    return [
        _sample(1, idle, request, signals),
        _sample(2, request, held, signals),
        _sample(3, held, ack, signals),
        _sample(4, ack, released, signals),
        _sample(5, released, released, signals)]


def measured_read_samples(signals, *, value=0x55):
    idle = _row(value=value, dat_r=value)
    request = _row(cyc=1, stb=1, we=0, sel=15, dat_r=value, value=value)
    held = _row(cyc=1, stb=0, we=0, sel=15, dat_r=value, value=value)
    ack = _row(cyc=1, stb=0, we=0, sel=15, ack=1, dat_r=value, value=value)
    released = _row(value=value, dat_r=value)
    return [
        _sample(1, idle, request, signals),
        _sample(2, request, held, signals),
        _sample(3, held, ack, signals),
        _sample(4, ack, released, signals),
        _sample(5, released, released, signals)]


def patch_probes(samples, signals, tick, phase, **overrides):
    """Mutate one phase's probes and keep the backend trace in step."""
    sample = next(row for row in samples if row['local_tick'] == tick)
    probes = sample[phase]['storage_probes']
    backend = sample[phase]['backend']
    for name, value in overrides.items():
        key = name if name in probes else 'storage_' + name
        probes[key] = value
        role = key[len('storage_'):]
        if role in ROLES:
            backend[signals[role]] = value
    return samples


def analyse(samples, observation, *, write=True, value=0x55, rdata=0,
            word_index=0, first_tick=1):
    return _analyse_wishbone_transfer(
        samples, first_tick=first_tick, write=write, word_index=word_index,
        value=value, rdata=rdata, signals=observation['signals'],
        widths=observation['widths'])


# --- pure observed-protocol reducer ---------------------------------------

def test_measured_write_shape_is_reduced(observation):
    transfer = analyse(measured_write_samples(observation['signals']),
                       observation)
    assert transfer.request_index == 1
    assert transfer.request_tick == 2
    assert transfer.request['storage_value'] == 0x19
    assert transfer.post['storage_value'] == 0x55
    assert transfer.ack['storage_ack'] == 1
    assert transfer.ack['storage_dat_r'] == 0x55
    assert transfer.ack_post['storage_value'] == 0x55


def test_measured_read_shape_is_reduced(observation):
    samples = measured_read_samples(observation['signals'])
    transfer = analyse(samples, observation, write=False, value=0,
                       rdata=0x55)
    assert transfer.request_index == 1
    assert transfer.request['storage_stb'] == 1
    assert transfer.ack['storage_dat_r'] == 0x55


def test_missing_ack_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 3, 'post', ack=0)
    patch_probes(samples, observation['signals'], 4, 'pre', ack=0)
    with pytest.raises(ValueError, match='missing-ack'):
        analyse(samples, observation)


def test_duplicate_ack_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 5, 'pre', ack=1)
    with pytest.raises(ValueError, match='duplicate-ack'):
        analyse(samples, observation)


def test_ack_that_never_releases_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    for tick, phase in ((4, 'post'), (5, 'pre'), (5, 'post')):
        patch_probes(samples, observation['signals'], tick, phase, ack=1)
    with pytest.raises(ValueError, match='ack-release-missing'):
        analyse(samples, observation)


def test_stalled_accept_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 2, 'pre', stall=1)
    with pytest.raises(ValueError, match='stall-observed'):
        analyse(samples, observation)


def test_foreign_word_index_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    for phase in ('pre', 'post'):
        patch_probes(samples, observation['signals'], 2, phase, adr=1)
    with pytest.raises(ValueError, match='word-index-mismatch'):
        analyse(samples, observation)


def test_non_full_word_write_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 2, 'pre', sel=7)
    with pytest.raises(ValueError, match='select-mismatch'):
        analyse(samples, observation)


def test_reset_asserted_on_the_accept_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 2, 'pre', reset=1)
    with pytest.raises(ValueError, match='protocol-mismatch'):
        analyse(samples, observation)


def test_probe_and_backend_disagreement_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    sample = next(row for row in samples if row['local_tick'] == 2)
    # ``storage_value`` has no backend tap; the nine bus roles do.
    sample['pre']['storage_probes']['storage_we'] = 0
    with pytest.raises(ValueError, match='probe-trace-mismatch'):
        analyse(samples, observation)


def test_missing_accepted_request_is_refused(observation):
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 2, 'pre', stb=0)
    with pytest.raises(ValueError, match='native-transfer-missing'):
        analyse(samples, observation)


def test_read_that_returns_the_wrong_word_is_refused(observation):
    samples = measured_read_samples(observation['signals'])
    with pytest.raises(ValueError, match='native-read-value-mismatch'):
        analyse(samples, observation, write=False, value=0, rdata=0x54)


def test_write_samples_are_bound_to_the_carried_write(observation):
    samples = measured_write_samples(observation['signals'])
    with pytest.raises(ValueError, match='native-write-value-mismatch'):
        analyse(samples, observation, value=0x66)


def test_discontinuous_relative_ticks_are_refused(observation):
    samples = measured_write_samples(observation['signals'])
    samples[2]['local_tick'] = 7
    with pytest.raises(ValueError, match='sample-tick'):
        analyse(samples, observation)


# --- journal/state hooks on a rendered (never built) artifact -------------

@pytest.fixture
def sessions():
    started = []
    yield started
    for session in started:
        session._process = None


def bind(generated, tmp_path, sessions, *, max_writes=4, max_samples=65536,
         max_tokens=2, prepared=True):
    session = GeneratedWishboneRegisterSession(
        generated, base_dir=ROOT, cache_dir=tmp_path / 'cache')
    authority = WishboneStorageRegisterVersionAuthority(
        session, max_writes=max_writes, max_samples=max_samples,
        max_tokens=max_tokens)
    session._process = SimpleNamespace(pid=4242, poll=lambda: None)
    session._execution = 'exec'
    session._case_id = 'case'
    if prepared:
        document = generated.runtime_document
        session.built_executable_receipt_document = lambda: dict(
            schema_version='local_harness_built_receipt.v1',
            artifact_digest=document['artifact_digest'],
            build_digest=BUILD_DIGEST,
            build_identity=dict(build_digest=BUILD_DIGEST),
            binary_sha256=BINARY_SHA256)
    sessions.append(session)
    return session, authority


def routed_context(session, *, write=True, value=0x55, sequence=None):
    context = dict(
        source_transaction=dict(
            execution_id='exec', testcase_id='case', source_component='cpu0',
            source_epoch=0, channel_id='data',
            source_sequence=session._sequence + 1),
        device_id='uart_setup', window_base=0x60000000, window_size=16,
        address=0x60000000, offset=0, word_index=0, write=write,
        value=value if write else 0, read_value=0, byte_enable=15,
        execution=session._execution, reset_epoch=session.reset_epoch,
        command_sequence=(session._sequence + 1 if sequence is None
                          else sequence),
        schema_version=WISHBONE_STORAGE_CONTEXT_SCHEMA,
        source_authenticated=False)
    assert set(context) == CONTEXT_KEYS
    return context


def _relabelled(samples, first_tick):
    rows = deepcopy(samples)
    for index, row in enumerate(rows, start=first_tick):
        row['local_tick'] = index
    return rows


def drive(session, authority, samples, *, routed=True, write=True,
          value=0x55, rdata=0):
    """Mimic the session's real command commit around the two producer hooks."""
    sequence = session._sequence + 1
    first_tick = session.local_ticks - session._tick_base + 1
    fields = (int(write), 0, value if write else 0, 15)
    session._storage_active_context = (
        routed_context(session, write=write, value=value) if routed else None)
    try:
        authority._actual_begin(session, 'ACCESS_WB_REG', fields)
    finally:
        session._storage_active_context = None
    last_tick = first_tick + len(samples) - 1
    session._sequence = sequence
    session.local_ticks = session._tick_base + last_tick
    receipt = SimpleNamespace(
        status='result', execution=session._execution, sequence=sequence,
        tick_before=first_tick - 1, tick_after=last_tick, new_ticks=len(samples),
        payload=dict(schema_version='local_driver_result.v1',
                     kind='wishbone_register_observe',
                     samples=_relabelled(samples, first_tick),
                     observations={}, pre_backend={}, rdata=rdata, error=0))
    authority._actual_command(session, 'ACCESS_WB_REG', fields, receipt)
    return receipt


def drive_step(session, authority, observation):
    sequence = session._sequence + 1
    first_tick = session.local_ticks - session._tick_base + 1
    authority._actual_begin(session, 'STEP_WB_REG', ())
    last_tick = first_tick
    session._sequence = sequence
    session.local_ticks = session._tick_base + last_tick
    idle = _row(value=module._LIVE[authority]['state']['value'],
                dat_r=module._LIVE[authority]['state']['value'])
    samples = [_sample(first_tick, idle, idle, observation['signals'])]
    receipt = SimpleNamespace(
        status='result', execution=session._execution, sequence=sequence,
        tick_before=first_tick - 1, tick_after=last_tick, new_ticks=1,
        payload=dict(schema_version='local_driver_result.v1',
                     kind='wishbone_register_observe', samples=samples,
                     observations={}, pre_backend={}, rdata=0, error=0))
    authority._actual_command(session, 'STEP_WB_REG', (), receipt)


def test_actual_begin_requires_a_bound_built_receipt(
        generated, tmp_path, sessions):
    session, authority = bind(generated, tmp_path, sessions, prepared=False)
    with pytest.raises(ValueError, match='actual-native-build-required'):
        authority._actual_begin(session, 'ACCESS_WB_REG', (1, 0, 0x55, 15))
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_actual_begin_refuses_a_context_on_a_step(
        generated, tmp_path, sessions):
    session, authority = bind(generated, tmp_path, sessions)
    session._storage_active_context = routed_context(session)
    try:
        with pytest.raises(ValueError, match='context-command-mismatch'):
            authority._actual_begin(session, 'STEP_WB_REG', ())
    finally:
        session._storage_active_context = None
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_actual_begin_refuses_a_foreign_command_sequence(
        generated, tmp_path, sessions):
    session, authority = bind(generated, tmp_path, sessions)
    session._storage_active_context = routed_context(session, sequence=9)
    try:
        with pytest.raises(ValueError, match='context-command-mismatch'):
            authority._actual_begin(session, 'ACCESS_WB_REG', (1, 0, 0x55, 15))
    finally:
        session._storage_active_context = None
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_routed_write_journals_exactly_one_commit(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    drive(session, authority,
          measured_write_samples(observation['signals']))
    writes = authority.writes()
    assert len(writes) == 1
    commit = writes[0]
    assert set(commit) == {
        'tick', 'raw_address', 'before', 'after', 'sample_index', 'phase',
        'command_sequence', 'context', 'raw_reference'}
    assert commit['before'] == 0x19
    assert commit['after'] == 0x55
    assert commit['raw_address'] == 0
    assert commit['tick'] == 2
    assert commit['sample_index'] == 1
    assert commit['phase'] == 'pre'
    assert commit['command_sequence'] == 1
    assert commit['context']['tick'] == 2
    assert commit['context']['command_sequence'] == 1
    assert commit['raw_reference'] == dict(
        execution='exec', sequence=1, sample_index=1, phase='pre')
    state = module._LIVE[authority]['state']
    assert state['value'] == 0x55
    assert state['tick'] == 5
    assert state['sequence'] == 1
    assert state['reset_waveform_observed'] is False
    token = authority.issue(register='SETUP', reset_epoch=0)
    witness = authority.consume(token)
    assert witness['value'] == 0x55
    assert witness['write_count'] == witness['field_version'] == 1
    assert witness['build_identity_sha256'] == BUILD_DIGEST
    assert witness['command_sequence'] == 1
    assert witness['local_tick'] == 5
    assert witness['pid'] == 4242


def test_routed_read_advances_state_without_a_commit(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    drive(session, authority,
          measured_write_samples(observation['signals']))
    drive(session, authority,
          measured_read_samples(observation['signals']), write=False,
          value=0, rdata=0x55)
    assert len(authority.writes()) == 1
    state = module._LIVE[authority]['state']
    assert state['value'] == 0x55
    assert state['sequence'] == 2
    assert state['tick'] == 10


def test_ordinary_access_is_analysed_but_never_journalled(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    drive(session, authority,
          measured_write_samples(observation['signals']), routed=False)
    assert authority.writes() == []
    assert module._LIVE[authority]['state']['value'] == 0x55
    assert module._LIVE[authority]['unrouted_writes'] == 1
    with pytest.raises(ValueError, match='history-incomplete'):
        authority.issue(register='SETUP', reset_epoch=0)
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_step_keeps_sequence_and_tick_exact(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    drive(session, authority,
          measured_write_samples(observation['signals']))
    drive_step(session, authority, observation)
    state = module._LIVE[authority]['state']
    assert state['value'] == 0x55
    assert state['sequence'] == 2
    assert state['tick'] == 6
    assert len(authority.writes()) == 1
    # The next measured write still starts from the tracked state value.
    drive(session, authority,
          measured_write_samples(observation['signals'], before=0x55,
                                 value=0x66), value=0x66)
    writes = authority.writes()
    assert len(writes) == 2
    assert writes[1]['before'] == 0x55
    assert writes[1]['after'] == 0x66
    assert writes[1]['tick'] == 8
    assert writes[1]['command_sequence'] == 3


def test_journal_limit_refuses_and_poisons(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions, max_writes=1)
    drive(session, authority,
          measured_write_samples(observation['signals']))
    with pytest.raises(ValueError, match='write-capacity'):
        drive(session, authority,
              measured_write_samples(observation['signals'], before=0x55,
                                     value=0x66), value=0x66)
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_sample_budget_refuses_and_poisons(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions, max_samples=4)
    with pytest.raises(ValueError, match='sample-capacity'):
        drive(session, authority,
              measured_write_samples(observation['signals']))
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_second_commit_without_a_measured_state_is_refused(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    drive(session, authority,
          measured_write_samples(observation['signals']))
    module._LIVE[authority]['state'] = None
    with pytest.raises(ValueError, match='initial-state-required'):
        drive(session, authority,
              measured_write_samples(observation['signals'], before=0x55,
                                     value=0x66), value=0x66)
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()


def test_protocol_refusal_poisons_permanently(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    samples = measured_write_samples(observation['signals'])
    patch_probes(samples, observation['signals'], 3, 'post', ack=0)
    patch_probes(samples, observation['signals'], 4, 'pre', ack=0)
    with pytest.raises(ValueError, match='missing-ack'):
        drive(session, authority, samples)
    for attempt in (lambda: authority.writes(),
                    lambda: authority.issue(register='SETUP', reset_epoch=0),
                    lambda: authority.consume(object())):
        with pytest.raises(ValueError, match='drift-or-revoked'):
            attempt()


def test_probe_backend_disagreement_poisons_the_authority(
        generated, tmp_path, sessions, observation):
    session, authority = bind(generated, tmp_path, sessions)
    samples = measured_write_samples(observation['signals'])
    sample = next(row for row in samples if row['local_tick'] == 2)
    sample['pre']['backend'][observation['signals']['we']] = 0
    with pytest.raises(ValueError, match='probe-trace-mismatch'):
        drive(session, authority, samples)
    with pytest.raises(ValueError, match='drift-or-revoked'):
        authority.writes()
