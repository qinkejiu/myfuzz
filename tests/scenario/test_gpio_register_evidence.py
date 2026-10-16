from copy import deepcopy

import pytest

from tests.scenario.test_gpio_consumption_versions import access, probes, tick


def consumer(**kwargs):
    from myfuzz.scenario import gpio_register_evidence as module
    return module.GpioRegisterEvidenceConsumer(
        component='gpio', register='out', bit_lo=0, width=2,
        runtime_contract_sha256='a' * 64, **kwargs)


def read(n=2, value=1):
    e = tick(n, probes(psel=1, penable=1, pready=1, apb_addr=12,
                       decoded_word=3, out=value, prdata=value), probes(out=value))
    e.update(kind='gpio_apb_access', status='observed', phase='pre',
             access_id='access-' + str(n), raw_offset=12, decoded_offset=12,
             write=False, read_rdata=value,
             source_transaction=dict(execution_id='e', testcase_id='b',
                 source_component='cpu', source_epoch=0, channel_id='data',
                 source_sequence=n),
             command_scope=dict(component='gpio', reset_epoch=0, command_sequence=n),
             target_response=dict(rdata=value, error=0))
    return e


def test_actual_write_read_versions_enter_classified_ledger_only():
    c = consumer()
    c.consume(access())
    c.consume(read())
    r = c.report()
    assert r['counts']['verified'] == 1
    proof = r['certificates'][0]
    assert proof['writer_event_ids'] == [1]
    assert proof['read_event_id'] == 2
    assert proof['write_transactions'][0]['testcase_id'] == 'a'
    assert proof['read_transaction']['testcase_id'] == 'b'
    evidence = r['ledger']['records']['verified'][0]
    assert evidence['scope'] == 'register_version'
    assert evidence['validity'] == 'historical'
    assert r['functional_status'] == 'unknown'


@pytest.mark.parametrize('policy', ['warm_all', 'cold_all'])
def test_global_reset_barrier_cannot_complete_old_register_writer(policy):
    c = consumer()
    c.consume(access())
    c.consume(dict(event_id=2, kind='reset_barrier', policy=policy))
    old_read = read()
    old_read['event_id'] = 3
    c.consume(old_read)
    assert c.report()['counts']['verified'] == 0
    assert c.report()['register_status'] == 'incomplete'
    assert c.report()['awaiting_native_reset'] is True


@pytest.mark.parametrize('reset_before_barrier', [True, False])
def test_global_barrier_preserves_history_and_allows_only_new_native_epoch(reset_before_barrier):
    c = consumer()
    c.consume(access())
    c.consume(read())
    history = deepcopy(c.report()['certificates'])
    barrier = dict(kind='reset_barrier', policy='warm_all')
    reset = dict(kind='gpio_reset', component='gpio', reset_epoch=1)
    middle = [reset, barrier] if reset_before_barrier else [barrier, reset]
    for i, event in enumerate(middle, 3):
        c.consume(dict(event, event_id=i))
    assert c.report()['awaiting_native_reset'] is False
    for i, event in enumerate([access(), read()], 5):
        event.update(event_id=i, reset_epoch=1, source_epoch=1)
        event['command_scope']['reset_epoch'] = 1
        c.consume(event)
    report = c.report()
    assert report['counts']['verified'] == 2
    assert report['certificates'][:1] == history
    assert report['certificates'][1]['reset_epoch'] == 1


def test_one_native_reset_cannot_acknowledge_two_global_barriers():
    c = consumer()
    c.consume(dict(event_id=1, kind='gpio_reset', component='gpio', reset_epoch=1))
    for i in [2, 3]:
        c.consume(dict(event_id=i, kind='reset_barrier', policy='cold_all'))
    assert c.report()['awaiting_native_reset'] is True
    c.consume(dict(event_id=4, kind='gpio_reset', component='gpio', reset_epoch=1))
    assert c.report()['awaiting_native_reset'] is True
    assert c.report()['register_status'] == 'incomplete'


@pytest.mark.parametrize('provider', ['register', 'sync'])
def test_reset_after_barrier_cannot_also_acknowledge_next_barrier(provider):
    from tests.scenario.test_gpio_sync_evidence import consumer as sync_consumer, rows as sync_rows
    c = consumer() if provider == 'register' else sync_consumer()
    c.consume(dict(event_id=1, kind='reset_barrier', policy='warm_all'))
    c.consume(dict(event_id=2, kind='gpio_reset', component='gpio', reset_epoch=1))
    c.consume(dict(event_id=3, kind='reset_barrier', policy='cold_all'))
    assert c.report()['awaiting_native_reset'] is True
    def observations(start, epoch):
        events = [access(), read()] if provider == 'register' else sync_rows()[:2]
        for i, event in enumerate(events, start):
            event.update(event_id=i, reset_epoch=epoch, source_epoch=epoch)
            if 'command_scope' in event:
                event['command_scope']['reset_epoch'] = epoch
            c.consume(event)
    observations(4, 1)
    assert c.report()['counts']['verified'] == 0
    c.consume(dict(event_id=6, kind='gpio_reset', component='gpio', reset_epoch=2))
    observations(7, 2)
    assert c.report()['awaiting_native_reset'] is False
    assert c.report()['counts']['verified'] == 1


@pytest.mark.parametrize('provider', ['register', 'sync'])
def test_reset_barrier_and_native_reset_cannot_heal_journal_identity_conflict(provider):
    from tests.scenario.test_gpio_sync_evidence import consumer as sync_consumer, rows as sync_rows
    c = consumer() if provider == 'register' else sync_consumer()
    events = [access(), read()] if provider == 'register' else sync_rows()[:2]
    for event in events:
        c.consume(event)
    history = deepcopy(c.report()['certificates'])
    c.consume(dict(event_id=1, kind='changed_saved_annotation'))
    c.consume(dict(event_id=3, kind='reset_barrier', policy='warm_all'))
    c.consume(dict(event_id=4, kind='gpio_reset', component='gpio', reset_epoch=1))
    events = [access(), read()] if provider == 'register' else sync_rows()[:2]
    for i, event in enumerate(events, 5):
        event.update(event_id=i, reset_epoch=1, source_epoch=1)
        if 'command_scope' in event:
            event['command_scope']['reset_epoch'] = 1
        c.consume(event)
    assert c.report()['journal_integrity'] is False
    assert c.report()['certificates'] == history
    status = 'register_status' if provider == 'register' else 'functional_status'
    assert c.report()[status] == 'incomplete'


def test_same_value_overwrite_read_uses_new_writer():
    c = consumer()
    c.consume(access())
    c.consume(access(2, value=1, old=1, new=1))
    c.consume(read(3))
    assert c.report()['certificates'][0]['writer_event_ids'] == [2]


def test_paired_tick_preserves_native_access_versions():
    c = consumer()
    a, b = access(), read()
    b['event_id'] = 3
    for e in (a, b):
        c.consume(e)
        paired = deepcopy(e)
        paired.update(kind='gpio_tick_observation', event_id=e['event_id'] + 1,
                      local_tick=e['local_tick'])
        c.consume(paired)
    assert c.report()['counts']['verified'] == 1
    assert c.report()['register_status'] == 'verified'


def test_set_operation_preserves_untouched_bit_writer():
    c = consumer()
    c.consume(access(value=0, new=0))
    c.consume(access(2, 16, 2, 0, 2))
    c.consume(read(3, 2))
    assert c.report()['certificates'][0]['writer_event_ids'] == [1, 2]


@pytest.mark.parametrize('ready', [0, 1])
def test_deleted_access_keeps_same_value_tick_from_reusing_old_writer(ready):
    c = consumer()
    c.consume(access())
    e = access(2, value=1, old=1, new=1)
    e['kind'] = 'gpio_tick_observation'
    e['pre']['gpio_probe_pready'] = ready
    c.consume(e)
    c.consume(read(3))
    assert c.report()['counts']['verified'] == 0
    assert c.report()['register_status'] == 'incomplete'


def test_conflicting_transaction_identity_does_not_certify_later_read():
    c = consumer()
    c.consume(access())
    e = access(2, value=1, old=1, new=1)
    e['source_transaction']['source_sequence'] = 1
    c.consume(e)
    c.consume(read(3))
    assert c.report()['counts']['verified'] == 0


def test_unbounded_extras_are_not_retained_in_native_tracker_or_edge():
    c = consumer()
    e = access()
    e['unused_annotation'] = ['large'] * 10000
    e['pre']['unused_annotation'] = ['large'] * 10000
    e['target_response']['unused_annotation'] = ['large'] * 10000
    c.consume(e)
    assert 'unused_annotation' not in c._last_edge['pre']
    assert 'unused_annotation' not in next(iter(c._tracker._accesses.values()))
    assert 'unused_annotation' not in next(iter(c._tracker._accesses.values()))['target_response']


def test_reset_after_certificate_reports_history_separately_from_current_status():
    c = consumer()
    c.consume(access())
    c.consume(read())
    c.consume(dict(event_id=3, kind='gpio_reset', component='gpio', reset_epoch=1))
    assert c.report()['counts']['verified'] == 1
    assert c.report()['register_status'] == 'unknown'
    assert c.report()['ledger']['records']['verified'][0]['validity'] == 'historical'


def test_native_access_capacity_cannot_discard_uncertainty():
    c = consumer(max_accesses=1)
    c.consume(access())
    c.consume(read())
    c.consume(dict(event_id=3, kind='gpio_register_commit', component='gpio'))
    assert c.report()['register_status'] == 'incomplete'
    assert c.report()['counts']['verified'] == 0


def test_production_runner_journal_recomputes_cross_case_without_derived_annotations():
    from tests.scenario.test_runner_source_provenance import configured_runner
    from tests.scenario.test_session_runtime_paths import declaration
    from myfuzz.scenario.gpio_register_evidence import GpioRegisterEvidenceConsumer

    runner, _, _ = configured_runner(journal=True, gpio_causal=True)
    stream = []
    for e in (access(), read()):
        e['component'] = e['command_scope']['component'] = 'b'
        stream.append(e)
        paired = deepcopy(e)
        paired['kind'] = 'gpio_tick_observation'
        stream.append(paired)
    runner.sessions['b'].gpio_events = stream
    runner._append_external_events('b', 1)
    rows = list(runner.events)
    raw_w = next(e for e in rows if e['kind'] == 'gpio_apb_access' and e['write'])
    raw_r = next(e for e in rows if e['kind'] == 'gpio_apb_access' and not e['write'])
    assert any(e['kind'] == 'gpio_register_commit' for e in rows)
    reports = []
    for annotations in (True, False):
        c = GpioRegisterEvidenceConsumer(component='b', register='out', bit_lo=0,
            width=2, runtime_contract_sha256=declaration()[1].identity_sha256)
        for event in deepcopy(rows):
            if not annotations and event['kind'] in ('gpio_register_commit', 'gpio_register_read'):
                event = dict(event_id=event['event_id'], kind='ignored_annotation')
            c.consume(event)
        reports.append(c.report())
    assert reports[0]['certificates'] == reports[1]['certificates']
    assert reports[0]['counts']['verified'] == 1
    assert reports[0]['certificates'][0]['writer_event_ids'] == [raw_w['event_id']]
    assert reports[0]['certificates'][0]['read_event_id'] == raw_r['event_id']


@pytest.mark.parametrize('mutation', ['response', 'post', 'contract', 'epoch', 'gap'])
def test_missing_or_conflicting_actual_evidence_cannot_certify(mutation):
    c = consumer()
    c.consume(access())
    e = read()
    if mutation == 'response':
        e['target_response']['rdata'] = 0
    elif mutation == 'post':
        e['post']['gpio_probe_out'] = 0
    elif mutation == 'contract':
        e['observation_contract'] = {}
    elif mutation == 'epoch':
        e['reset_epoch'] = e['source_epoch'] = 1
        e['command_scope']['reset_epoch'] = 1
    else:
        e['local_tick'] = 3
    c.consume(e)
    assert c.report()['counts']['verified'] == 0
    assert c.report()['register_status'] == 'incomplete'


def test_forged_annotation_and_protocol_accept_never_create_versions():
    c = consumer()
    c.consume(dict(event_id=1, kind='ip_request_accept', component='gpio'))
    c.consume(dict(event_id=2, kind='gpio_register_commit', component='gpio',
                   status='observed', register='out', bit_resources=[dict(version=99)]))
    e = read(3)
    e['local_tick'] = 1
    c.consume(e)
    assert c.report()['counts']['verified'] == 0
    assert c.report()['functional_status'] == 'unknown'


def test_global_conflict_and_gap_prevent_future_proofs():
    for bad in (dict(event_id=1, kind='other'), dict(event_id=3, kind='other')):
        c = consumer()
        c.consume(access())
        c.consume(bad)
        c.consume(read())
        assert c.report()['counts']['verified'] == 0
        assert not c.report()['journal_integrity']


def test_window_expiry_does_not_revive_equal_value_writer():
    c = consumer(max_event_gap=1)
    c.consume(access())
    c.consume(dict(event_id=2, kind='other'))
    e = read(3)
    e['local_tick'] = 2
    c.consume(e)
    assert c.report()['counts']['verified'] == 0


def test_report_is_detached_and_record_capacity_is_bounded():
    c = consumer(max_records=1)
    c.consume(access())
    c.consume(read())
    c.consume(read(3))
    r = c.report()
    assert r['counts']['verified'] == 1
    r['certificates'].clear()
    assert c.report()['counts']['verified'] == 1


def test_reset_discards_writer_without_turning_history_into_active_witness():
    c = consumer()
    c.consume(access())
    c.consume(dict(event_id=2, kind='gpio_reset', component='gpio', reset_epoch=1))
    e = read(3)
    e.update(reset_epoch=1, source_epoch=1, local_tick=1)
    e['command_scope']['reset_epoch'] = 1
    c.consume(e)
    assert c.report()['counts']['verified'] == 0


@pytest.mark.parametrize('kwargs', [dict(width=True), dict(bit_lo=-1),
    dict(width=33), dict(register='DONE'), dict(runtime_contract_sha256='bad'),
    dict(max_records=0), dict(max_event_gap=True), dict(max_accesses=65537)])
def test_invalid_configuration_is_rejected(kwargs):
    from myfuzz.scenario import gpio_register_evidence as module
    values = dict(component='gpio', register='out', bit_lo=0, width=2,
                  runtime_contract_sha256='a' * 64)
    values.update(kwargs)
    with pytest.raises(ValueError):
        module.GpioRegisterEvidenceConsumer(**values)
