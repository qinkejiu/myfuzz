from copy import deepcopy

from tests.scenario.test_ip_semantic_evidence import consumer, configuration
from tests.scenario.test_gpio_consumption_versions import access
from tests.scenario.test_gpio_register_evidence import read


def test_register_event_preserves_actual_refs_rule_scope_and_base_gap():
    c = consumer()
    c.ingest([access(), read()])
    events = c.semantic_derived_events()
    assert len(events) == 1
    e = events[0]
    assert e['schema_version'] == 'ip_register_event.v1'
    assert e['raw_event_refs'] == [1, 2]
    assert e['base_event_refs'] == []
    assert e['base_evidence_gap'] == 'native-observation-has-no-ip-base-projection'
    assert e['rule_id'] == 'gpio_register_version' and e['rule_version'] == '1'
    assert e['proof_scope'] == 'register_version'
    assert e['validity'] == 'historical'


def test_function_event_is_scoped_internal_consumption_not_completion():
    from tests.scenario.test_gpio_sync_evidence import rows
    config = configuration()
    config['sync'] = dict(level='L3', provider='gpio_sync_consumption.v1',
        parameters=dict(component='gpio', bit_lo=0, width=1))
    c = consumer(config)
    c.ingest(rows()[:2])
    e, = c.semantic_derived_events()
    assert e['schema_version'] == 'ip_function_event.v1'
    assert e['event_type'] == 'consumption'
    assert e['proof_scope'] == 'functional_consumption'
    assert e['payload']['proof_scope'] == 'sync0_to_sync1_version_consumption'


def test_projected_events_are_detached_stable_and_do_not_mutate_journal():
    c = consumer()
    journal = [access(), read()]
    before = deepcopy(journal)
    c.ingest(journal)
    first = c.semantic_derived_events()
    stable_id = first[0]['derived_event_id']
    first[0]['raw_event_refs'].clear()
    assert c.semantic_derived_events()[0]['raw_event_refs'] == [1, 2]
    assert c.semantic_derived_events()[0]['derived_event_id'] == stable_id
    assert journal == before


def test_fake_base_annotation_never_fills_base_refs():
    c = consumer()
    r = read()
    r['event_id'] = 3
    c.ingest([access(), dict(event_id=2, kind='ip_base_event', raw_event_refs=[1],
                            component='gpio'), r])
    e, = c.semantic_derived_events()
    assert e['base_event_refs'] == []
