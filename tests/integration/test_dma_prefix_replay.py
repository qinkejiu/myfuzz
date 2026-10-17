"""Pure tests for the unified typed DMA prefix replay (S4)."""
from types import SimpleNamespace

import pytest

from myfuzz.integration.dma_prefix_replay import (
    DmaPrefixReference, compare_dma_prefix, prefix_reference)
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent, ScenarioBatchPlan
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.replay_normalize import PrefixDivergence

IDS = {'cpu': 'a' * 32, 'dma': 'b' * 32, 'uart': 'c' * 32, 'runner': 'd' * 32}
FRESH = {'cpu': '1' * 32, 'dma': '2' * 32, 'uart': '3' * 32, 'runner': '4' * 32}
IDENTITIES = {'cpu': {'artifact': 'ibex'}, 'dma': {'artifact': 'wbdmac'},
              'uart': {'artifact': 'uart'}, 'runner': {'runner': 1}}
BUDGET = ResourceBudget(max_wall_time_ms=600000)


def _template():
    return ScenarioGenome('descriptor-dma-three-directions', 'IP_TO_CPU',
        'uart-descriptor-dma-ram-tx-cpu-isr', ('dma', 'cpu', 'uart'), 1000, ())


def _plan():
    return ScenarioBatchPlan(_template(), (
        BatchSourceEvent('descriptor-1-0', 'uart', 'uart_rx_byte', 0, width=8),
        BatchAdvance(('uart',)),
        BatchSourceEvent('descriptor-2-0', 'uart', 'uart_rx_byte', 0x5A,
                         width=8),
        BatchAdvance(('dma', 'cpu'))))


def _events(ids, *, tamper=None):
    events = [
        {'event_id': 1, 'kind': 'source_injection', 'action_id': 'descriptor-1-0',
         'value': 'payload-0x5a', 'execution_id': ids['cpu']},
        {'event_id': 2, 'kind': 'uart_rdata_access', 'local_tick': 71,
         'read_value': 0x5A, 'access_id': 'uart-access:uart:0:1'},
        {'event_id': 3, 'kind': 'dma_edge', 'native_local_tick': 92,
         'payload': {'observations': {'physical': {'irq': 1}}}},
        {'event_id': 4, 'kind': 'memory_write', 'component': 'dma',
         'address': 0x23000, 'value': 0x5A, 'version': [0, 2],
         'writer_event_id': "TransactionKey(execution_id='%s', testcase_id='c', "
                            "source_component='dma', source_epoch=0, "
                            "channel_id='dma-memory', source_sequence=3)"
                            % ids['dma']}]
    if tamper == 'tick':
        events[1]['local_tick'] = 72
    elif tamper == 'byte':
        events[1]['read_value'] = 0x5B
    elif tamper == 'irq':
        events[2]['payload']['observations']['physical']['irq'] = 0
    return events


def _cases(ticks_first, *, authority='unknown'):
    return (
        {'case_index': 1, 'source_start_command': 0, 'command_end': 2,
         'event_start': 0, 'event_end': 2, 'ticks_after': dict(ticks_first),
         'fifo_origin': authority, 'direction': 'RX_TO_RAM'},
        {'case_index': 2, 'source_start_command': 2, 'command_end': 4,
         'event_start': 2, 'event_end': 4,
         'ticks_after': dict(ticks_first, cpu=ticks_first['cpu'] + 3),
         'fifo_origin': authority, 'direction': 'RAM_TO_TX'})


def _reference():
    events = _events(IDS)
    return DmaPrefixReference(direction='DMA_DESCRIPTOR', plan=_plan(),
        cases=_cases({'cpu': 10, 'dma': 20, 'uart': 30}), local_ticks={},
        events=tuple(events), uncertain_status={'source_drift': False},
        identities=dict(IDENTITIES), execution_ids=dict(IDS),
        source_pins={'pins': 1}, budget=BUDGET, phase='complete',
        case_index=2, error=None, trace=None)


def _fresh(**kwargs):
    events = _events(FRESH, tamper=kwargs.pop('event_tamper', None))
    return SimpleNamespace(plan=_plan(), cases=_cases(
        kwargs.pop('ticks', {'cpu': 10, 'dma': 20, 'uart': 30}),
        authority=kwargs.pop('authority', 'unknown')),
        events=tuple(events), identities=dict(IDENTITIES),
        execution_ids=dict(FRESH), local_ticks={})


def test_fresh_prefix_with_only_execution_identity_changes_is_equal():
    result = compare_dma_prefix(_reference(), _fresh(), case_count=2)
    assert result.equal
    assert result.case_count == 2 and result.event_count == 4
    assert result.command_count == 4
    assert result.ticks == {'cpu': 13, 'dma': 20, 'uart': 30}
    assert result.fresh_execution_ids == FRESH


def test_prefix_digest_is_stable_and_prefix_sensitive():
    reference = _reference()
    assert reference.prefix_digest(1) == reference.prefix_digest(1)
    assert reference.prefix_digest(1) != reference.prefix_digest(2)
    assert reference.prefix_digest(1) == DmaPrefixReference(
        **{**reference.__dict__, 'events': reference.events}).prefix_digest(1)


@pytest.mark.parametrize('event_tamper, path', [
    ('tick', [1, 'local_tick']),
    ('byte', [1, 'read_value']),
    ('irq', [2, 'payload', 'observations', 'physical', 'irq'])])
def test_tampered_tick_byte_or_irq_is_the_first_event_difference(
        event_tamper, path):
    with pytest.raises(PrefixDivergence) as caught:
        compare_dma_prefix(_reference(), _fresh(event_tamper=event_tamper),
            case_count=2)
    assert caught.value.scope == 'event'
    assert caught.value.difference['path'] == path


def test_tampered_case_tick_or_evidence_is_the_first_case_difference():
    with pytest.raises(PrefixDivergence) as caught:
        compare_dma_prefix(_reference(),
            _fresh(ticks={'cpu': 11, 'dma': 20, 'uart': 30}), case_count=2)
    assert caught.value.scope == 'case'
    assert caught.value.difference['path'][:2] == ['cases', 0]
    with pytest.raises(PrefixDivergence) as caught:
        compare_dma_prefix(_reference(),
            _fresh(authority='accepted_uart_fifo_entry'), case_count=2)
    assert caught.value.scope == 'case'
    assert caught.value.difference['path'] == ['cases', 0, 'fifo_origin']


def test_tampered_plan_command_is_the_first_plan_difference():
    fresh = _fresh()
    fresh.plan = ScenarioBatchPlan(_template(), (
        BatchSourceEvent('descriptor-1-0', 'uart', 'uart_rx_byte', 1, width=8),
        BatchAdvance(('uart',)),
        BatchSourceEvent('descriptor-2-0', 'uart', 'uart_rx_byte', 0x5A,
                         width=8),
        BatchAdvance(('dma', 'cpu'))))
    with pytest.raises(PrefixDivergence) as caught:
        compare_dma_prefix(_reference(), fresh, case_count=2)
    assert caught.value.scope == 'plan'
    assert caught.value.difference['path'] == [0, 'value']


def test_whole_json_replacement_cannot_hide_a_payload_difference():
    # The retained ``value`` embeds its own run's execution token.  Replacing
    # each side's UUID in the whole JSON would make the two payloads look equal;
    # the typed comparison must report the real difference instead.
    reference = _reference()
    fresh = _fresh()
    reference_events = list(reference.events)
    fresh_events = list(fresh.events)
    reference_events[0] = dict(reference_events[0],
        value='payload-A-' + IDS['cpu'])
    fresh_events[0] = dict(fresh_events[0],
        value='payload-A-' + FRESH['cpu'])
    reference = DmaPrefixReference(**{**reference.__dict__,
        'events': tuple(reference_events)})
    tampered = SimpleNamespace(**{**fresh.__dict__,
        'events': tuple(fresh_events)})
    import json

    def wash(events, ids):
        text = json.dumps(list(events), sort_keys=True)
        for role in ('cpu', 'dma', 'uart', 'runner'):
            text = text.replace(ids[role], 'EXEC-' + role)
        return text

    assert wash(reference.events, IDS) == wash(tampered.events, FRESH)
    with pytest.raises(PrefixDivergence) as caught:
        compare_dma_prefix(reference, tampered, case_count=2)
    assert caught.value.scope == 'event'
    assert caught.value.difference['path'] == [0, 'value']


def test_replay_reference_is_derived_from_a_recorded_result():
    plan, cases = _plan(), _cases({'cpu': 1, 'dma': 2, 'uart': 3})
    result = SimpleNamespace(plan=plan, cases=cases,
        local_ticks={'cpu': 1, 'dma': 2, 'uart': 3},
        events=tuple(_events(IDS)),
        uncertain_status={'source_drift': False}, identities=dict(IDENTITIES),
        execution_ids=dict(IDS), source_pins={'pins': 1}, budget=BUDGET,
        phase='complete', case_index=2, error=None, trace=None)
    reference = prefix_reference(result)
    assert isinstance(reference, DmaPrefixReference)
    assert reference.case_count == 2
    assert tuple(reference.prefix_document(1)['events']) == result.events[:2]
    assert reference.command_documents(1) == (
        {'kind': 'source_event', 'action_id': 'descriptor-1-0',
         'component': 'uart', 'port': 'uart_rx_byte', 'value': 0,
         'bit_offset': 0, 'width': 8},
        {'kind': 'advance', 'schedule': ['uart']})
    with pytest.raises(ValueError):
        reference.prefix_document(3)
