from copy import deepcopy

import pytest

from tests.scenario.test_gpio_consumption_versions import probes, tick


def state(a=0, b=0, c=0, enabled=1):
    p = probes(gpioen=enabled, input_clock_enable=int(bool(enabled)),
        sync0=a, sync1=b, padin_latch=c, rise=b & ~c, fall=~b & c & 0xffffffff)
    p['gpio_in'] = 1
    return p


def rows():
    return [tick(1, state(), state(1)),
            tick(2, state(1), state(1, 1)),
            tick(3, state(1, 1), state(1, 1, 1))]


def consumer(**bounds):
    from myfuzz.scenario import gpio_sync_evidence as module
    return module.GpioSyncConsumptionEvidenceConsumer(component='gpio', bit_lo=0,
        width=1, runtime_contract_sha256='a'*64, **bounds)


def test_internal_consumption_requires_observed_exact_prior_stage_version():
    c = consumer()
    c.consume(rows()[0])
    assert c.report()['counts']['verified'] == 0
    c.consume(rows()[1])
    r = c.report()
    assert r['counts']['verified'] == 1
    assert r['functional_status'] == 'verified'
    cert = r['certificates'][0]
    assert cert['source_event_ids'] == [1] and cert['consumer_event_id'] == 2
    e = r['ledger']['records']['verified'][0]
    assert e['scope'] == 'functional_consumption' and e['validity'] == 'historical'
    assert cert['proof_scope'] == 'sync0_to_sync1_version_consumption'


@pytest.mark.parametrize('policy', ['warm_all', 'cold_all'])
def test_global_barrier_cannot_consume_old_sync_stage_version(policy):
    c = consumer()
    source, target = rows()[:2]
    c.consume(source)
    c.consume(dict(event_id=2, kind='reset_barrier', policy=policy))
    target['event_id'] = 3
    c.consume(target)
    report = c.report()
    assert report['counts']['verified'] == 0
    assert report['functional_status'] == 'incomplete'
    assert report['awaiting_native_reset'] is True


@pytest.mark.parametrize('reset_before_barrier', [True, False])
def test_sync_global_barrier_preserves_history_and_requires_new_epoch(reset_before_barrier):
    c = consumer()
    for event in rows()[:2]:
        c.consume(event)
    history = deepcopy(c.report()['certificates'])
    barrier = dict(kind='reset_barrier', policy='cold_all')
    reset = dict(kind='gpio_reset', component='gpio', reset_epoch=1)
    middle = [reset, barrier] if reset_before_barrier else [barrier, reset]
    for i, event in enumerate(middle, 3):
        c.consume(dict(event, event_id=i))
    assert c.report()['awaiting_native_reset'] is False
    for i, event in enumerate(rows()[:2], 5):
        event.update(event_id=i, reset_epoch=1, source_epoch=1)
        c.consume(event)
    report = c.report()
    assert report['counts']['verified'] == 2
    assert report['certificates'][:1] == history


def test_same_value_new_stage_versions_keep_distinct_consumers():
    c = consumer()
    for e in rows():
        c.consume(e)
    certs = c.report()['certificates']
    assert [e['source_event_ids'] for e in certs] == [[1], [2]]
    assert certs[0]['source_resources'][0]['version'] != certs[1]['source_resources'][0]['version']


@pytest.mark.parametrize('fault', ['missing_source', 'gap', 'post', 'epoch', 'forged'])
def test_missing_or_false_consumer_observation_never_certifies(fault):
    c = consumer()
    source, target = rows()[:2]
    if fault == 'missing_source':
        source = dict(event_id=1, kind='other')
    elif fault == 'gap':
        target['local_tick'] = 3
    elif fault == 'post':
        target['post'] = state(1)
    elif fault == 'epoch':
        target['reset_epoch'] = target['source_epoch'] = 1
    else:
        target = dict(event_id=2, kind='gpio_input_sample', status='observed',
                      stages={'sync1': [dict(version=99, dependencies=[dict(version=1)])]})
    c.consume(source)
    c.consume(target)
    assert c.report()['counts']['verified'] == 0


def test_disabled_stage_equal_values_do_not_create_consumption():
    c = consumer()
    c.consume(tick(1, state(1, 1, 1, enabled=0), state(1, 1, 1, enabled=0)))
    c.consume(tick(2, state(1, 1, 1, enabled=0), state(1, 1, 1, enabled=0)))
    assert c.report()['counts']['verified'] == 0


def test_reset_preserves_history_but_discards_sources():
    c = consumer()
    for e in rows()[:2]:
        c.consume(e)
    c.consume(dict(event_id=3, kind='gpio_reset', component='gpio', reset_epoch=1))
    assert c.report()['functional_status'] == 'unknown'
    e = rows()[1]
    e.update(event_id=4, local_tick=1, reset_epoch=1, source_epoch=1)
    c.consume(e)
    assert c.report()['counts']['verified'] == 1


def test_source_expiry_and_record_limits_are_bounded():
    c = consumer(max_event_gap=1, max_records=1)
    c.consume(rows()[0])
    c.consume(dict(event_id=2, kind='other'))
    e = rows()[1]
    e['event_id'] = 3
    c.consume(e)
    assert c.report()['counts']['verified'] == 0
    c = consumer(max_records=1)
    for e in rows():
        c.consume(e)
    assert c.report()['counts']['verified'] == 1


def test_historical_success_does_not_hide_missing_current_version():
    c = consumer(max_event_gap=2)
    for e in rows()[:2]:
        c.consume(e)
    c.consume(dict(event_id=3, kind='other'))
    c.consume(dict(event_id=4, kind='other'))
    e = rows()[2]
    e['event_id'] = 5
    c.consume(e)
    assert c.report()['counts']['verified'] == 1
    assert c.report()['functional_status'] == 'incomplete'


def test_catalog_integrates_l3_without_upgrading_register_evidence():
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    c = EdgeProvenanceConsumer(RuntimePathContract('a'*64, (), ()))
    c.configure_semantic_events({'sync': dict(level='L3', provider='gpio_sync_consumption.v1',
        parameters=dict(component='gpio', bit_lo=0, width=1))})
    c.ingest(rows()[:2])
    r = c.semantic_evidence_report()
    assert r['counts'] == dict(register_version=0, functional_consumption=1)
    assert r['operations']['sync']['status'] == 'verified'


def test_production_runner_cross_case_raw_refs_survive_removed_derived_events():
    from tests.scenario.test_runner_source_provenance import configured_runner
    from tests.scenario.test_session_runtime_paths import declaration
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer

    runner, _, _ = configured_runner(journal=True, gpio_causal=True)
    stream = []
    runner.sessions['b'].gpio_events = stream
    for index, e in enumerate(rows()[:2]):
        runner.set_observation_case('producer' if index == 0 else 'consumer', index)
        e['component'] = 'b'
        stream.append(e)
        runner._append_external_events('b', 1)
    journal = list(runner.events)
    raw = [e for e in journal if e['kind'] == 'gpio_tick_observation']
    assert raw[0]['provenance']['observed_case']['case_id'] == 'producer'
    assert raw[1]['provenance']['observed_case']['case_id'] == 'consumer'
    for annotations in (True, False):
        c = EdgeProvenanceConsumer(declaration()[1])
        c.configure_semantic_events({'sync': dict(level='L3', provider='gpio_sync_consumption.v1',
            parameters=dict(component='b', bit_lo=0, width=1))})
        for e in deepcopy(journal):
            if not annotations and e['kind'] == 'gpio_input_sample':
                e = dict(event_id=e['event_id'], kind='removed_annotation')
            c.ingest([e])
        r = c.semantic_evidence_report()
        assert r['counts']['functional_consumption'] == 1
        cert = r['operations']['sync']['evidence']['certificates'][0]
        assert cert['source_event_ids'] == [raw[0]['event_id']]
        assert cert['consumer_event_id'] == raw[1]['event_id']
