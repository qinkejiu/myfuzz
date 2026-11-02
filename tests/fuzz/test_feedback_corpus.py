"""Tests for the feature feedback and bounded corpus of the closed-loop fuzzer.

The representative case dictionaries below mirror the key vocabulary the
unified in-process executor prints in its ``case`` lines (``CASE_OBSERVATION_KEYS``,
``CASE_COUNTER_KEYS`` and the ``PIN_*`` tables), including the APB3 spellings
``apb_*`` that an APB target prints where an AXI4-Lite target prints
``target_*``.  They are written out literally so these tests do not import the
executor.
"""

import copy
import dataclasses
import json
import random

import pytest

from myfuzz.fuzz.corpus import CORPUS_SCHEMA, Corpus, CorpusEntry
from myfuzz.fuzz.feedback import (COUNTER_KEYS, FEATURE_SCHEMA, FLOWS,
                                  CaseFeedback, FeedbackState, bucket,
                                  value_class)

# ---------------------------------------------------------------------------
# Representative parsed case lines
# ---------------------------------------------------------------------------
COUNTERS = {
    'i_fetches': 37,
    'd_reads': 1,
    'd_writes': 2,
    'apb_reads': 1,
    'apb_writes': 0,
    'retires': 4,
    'rvfi_writebacks': 3,
    'rvfi_order_monotonic': 1,
    'traps': 0,
    'bus_errors': 0,
}

COUNTER_FEATURES = {
    ('count', 'i_fetches', '17+'),
    ('count', 'd_reads', '1'),
    ('count', 'd_writes', '2-4'),
    ('count', 'apb_reads', '1'),
    ('count', 'apb_writes', '0'),
    ('count', 'retires', '2-4'),
    ('count', 'rvfi_writebacks', '2-4'),
    ('count', 'rvfi_order_monotonic', '1'),
    ('count', 'traps', '0'),
    ('count', 'bus_errors', '0'),
}


def f1_case(**overrides):
    case = {
        'index': 0,
        'status': 'observations_passed',
        'flow': 'F1',
        'record': 'F1:000012b7:00528313:00000013:00000023',
        'fetch': 0x10000,
        'retire_pc': 0x10000,
        'retire_insn': 0x000012b7,
        'successor_pc': 0x10004,
        'prog_words': 4,
        'prog_retires': 4,
        'prog_pc_ordered': 1,
        'prog_insns_match': 1,
        'prog_writebacks': 3,
        'prog_rd_mask': 0x000000e0,
        'prog_last_rd': 7,
        'prog_last_wdata': 0x20,
        'prog_last_pc': 0x1000c,
        'prog_last_insn': 0x00002020,
        'prog_traps': 0,
        'data_hash_before': 0x811c9dc5,
        'data_hash_after': 0xcbf29ce4,
        'data_changed': 1,
        **COUNTERS,
    }
    case.update(overrides)
    return case


def f2_case(**overrides):
    case = {
        'index': 1,
        'status': 'observations_passed',
        'flow': 'F2',
        'read_addr': 0x10,
        'read_value': 5,
        'echo_value': 5,
        'read_from': 'apb',
        'apb_rdata': 5,
        'apb_reads': 1,
        'apb_writes': 0,
        'pad_before': 0,
        'pad_after': 0,
        'out_before': 0,
        'out_after': 0,
        'dir_after': 0,
        'ext_value': 0,
        'pad_changes': 0,
        'pad_rise_events': 0,
        'rise_mask': 0,
        'fall_mask': 0,
        'pad_at_read': 0,
        'padin_latch': 0,
        'pin_stimulus': 'applied',
    }
    case.update(overrides)
    return case


def f3_case(**overrides):
    case = {
        'index': 2,
        'status': 'observations_passed',
        'flow': 'F3',
        'write_addr': 0x100,
        'write_value': 7,
        'write_be': 15,
        'ram_before': 0,
        'ram_after': 7,
        'd_reads': 0,
        'd_writes': 1,
    }
    case.update(overrides)
    return case


def f4_apb_case(**overrides):
    case = {
        'index': 3,
        'status': 'observations_passed',
        'flow': 'F4',
        'mmio_addr': 0x400,
        'mmio_value': 0x20,
        'apb_offset': 0x8,
        'apb_pwdata': 0x20,
        'apb_pready': 1,
        'apb_writes': 1,
    }
    case.update(overrides)
    return case


def f4_axi_case(**overrides):
    case = {
        'index': 3,
        'status': 'observations_passed',
        'flow': 'F4',
        'mmio_addr': 0x400,
        'mmio_value': 0x3,
        'target_offset': 0x10,
        'target_wdata': 0x3,
        'target_resp': 0,
        'target_ready': 1,
        'target_writes': 1,
        'target_reads': 0,
        'axi_aw': 1,
        'axi_w': 1,
        'axi_b': 1,
        'axi_ar': 0,
        'axi_r': 0,
        'target_error': 'unknown',
        'i_fetches': 10,
        'd_writes': 1,
    }
    case.update(overrides)
    return case


def f5_case(**overrides):
    case = {
        'index': 4,
        'status': 'observations_passed',
        'flow': 'F5',
        'trigger_writes': 3,
        'apb_read_offset': 0x0,
        'apb_read_data': 1,
        'apb_last_write_offset': 0x4,
        'apb_last_write_data': 1,
        'irq_edges': 5,
        'irq_high_ticks': 10,
        'device_high_ticks': 10,
        'delivered_high_ticks': 10,
        'irq_takes': 3,
        'isr_result': 1,
        'isr_flag': 1,
        'isr_read_addr': 0x10,
        'isr_read_value': 1,
        'isr_read_register_kind': 'control',
        'isr_cause': 'unknown',
        'irq_cause_pins': 0x2,
        'inten_at_irq': 0x2,
        'first_rise_tick': 10,
        'first_irq_tick': 11,
        'status_after_read': 1,
        'i_fetches': 20,
    }
    case.update(overrides)
    return case


def f6_case(**overrides):
    case = {
        'index': 5,
        'status': 'observations_passed',
        'flow': 'F6',
        'dma_reads': 4,
        'dma_writes': 4,
        'dma_first_read_addr': 0x1000,
        'dma_first_read_value': 1,
        'dma_last_write_addr': 0x2000,
        'dma_last_write_value': 1,
        'ctl_config_writes': 1,
        'ctl_start_writes': 1,
        'ctl_clear_writes': 1,
        'ctl_reads': 2,
        'ctl_status': 3,
        'irq_edges': 1,
        'irq_high_ticks': 5,
        'device_high_ticks': 5,
        'delivered_high_ticks': 5,
        'irq_takes': 1,
        'isr_result': 3,
        'isr_flag': 1,
        'ctl_reads_before_start': 1,
        'busy_before': 0,
        'err_before': 0,
        'busy_after': 0,
        'err_after': 0,
        'dma_clear_declared': 1,
        'dma_status_kind': 'zipdma',
        'dma_done_tick': 100,
        'dst0': 1,
        'dst1': 2,
        'dst2': 3,
        'dst3': 4,
    }
    case.update(overrides)
    return case


def features_of(case):
    return set(FeedbackState().observe(case).features)


# ---------------------------------------------------------------------------
# Feature extraction: one representative case per flow
# ---------------------------------------------------------------------------
def test_every_flow_is_in_the_vocabulary():
    assert FLOWS == ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')
    for flow in FLOWS:
        feedback = FeedbackState().observe({'flow': flow})
        assert feedback.flow == flow
        assert feedback.features == ()
        assert feedback.summary == (f'{flow} unknown with no recognised '
                                    'observation')


def test_f1_representative_case_yields_its_exact_feature_set():
    expected = COUNTER_FEATURES | {
        ('F1', 'words', 4),
        ('F1', 'retires', 4),
        ('F1', 'pc_ordered', 1),
        ('F1', 'insns_match', 1),
        ('F1', 'rd_mask', 0x000000e0),
        ('F1', 'last_rd', 7),
        ('F1', 'last_wdata_class', 'small'),
        ('F1', 'traps', 0),
        ('F1', 'data_changed', 1),
        ('F1', 'data_hash', 0xcbf29ce4),
    }
    feedback = FeedbackState().observe(f1_case())
    assert set(feedback.features) == expected
    assert feedback.index == 0
    assert feedback.flow == 'F1'
    assert feedback.status == 'observations_passed'
    assert feedback.failed is False
    assert feedback.new == feedback.features


def test_f1_rd_mask_is_kept_exact_and_is_not_bucketed():
    features = features_of(f1_case(prog_rd_mask=0x00000001))
    assert ('F1', 'rd_mask', 0x00000001) in features
    assert ('F1', 'rd_mask', '0') not in features


def test_f2_representative_case_yields_its_exact_feature_set():
    features = features_of(f2_case())
    assert features == {
        ('count', 'apb_reads', '1'),
        ('count', 'apb_writes', '0'),
        ('F2', 'read_from', 'apb'),
        ('F2', 'read_addr', 0x10),
        ('F2', 'target_reads', '1'),
        ('F2', 'value_class', 'small'),
        ('F2', 'echo', 'committed'),
        ('F2', 'pin_stimulus', 'applied'),
    }


def test_f3_representative_case_yields_its_exact_feature_set():
    features = features_of(f3_case())
    assert features == {
        ('count', 'd_reads', '0'),
        ('count', 'd_writes', '1'),
        ('F3', 'write_addr', 0x100),
        ('F3', 'value_class', 'small'),
        ('F3', 'ram_committed', 'yes'),
        ('F3', 'be', 15),
    }


def test_f3_reports_a_lost_ram_write():
    features = features_of(f3_case(ram_after=0))
    assert ('F3', 'ram_committed', 'no') in features


def test_f4_axi_representative_case_yields_its_exact_feature_set():
    features = features_of(f4_axi_case())
    assert features == {
        ('count', 'i_fetches', '9-16'),
        ('count', 'd_writes', '1'),
        ('F4', 'target_offset', 0x10),
        ('F4', 'value_class', 'small'),
        ('F4', 'target_writes', '1'),
        ('F4', 'target_resp', 0),
    }


def test_f4_reads_the_apb_spellings_of_the_neutral_target_fields():
    features = features_of(f4_apb_case())
    assert features == {
        ('count', 'apb_writes', '1'),
        ('F4', 'target_offset', 0x8),
        ('F4', 'value_class', 'small'),
        ('F4', 'target_writes', '1'),
    }


def test_f5_representative_case_yields_its_exact_feature_set():
    features = features_of(f5_case())
    assert features == {
        ('count', 'i_fetches', '17+'),
        ('F5', 'irq_edges', 3),
        ('F5', 'irq_takes', 2),
        ('F5', 'status_class', 'one'),
        ('F5', 'isr_kind', 'control'),
        ('F5', 'cause_enabled', 'yes'),
    }


def test_f6_representative_case_yields_its_exact_feature_set():
    feedback = FeedbackState().observe(f6_case())
    dst_hash = [feature for feature in feedback.features
                if feature[:2] == ('F6', 'dst_hash')]
    assert len(dst_hash) == 1
    assert 0 <= dst_hash[0][2] <= 0xFFFFFFFF
    assert set(feedback.features) - set(dst_hash) == {
        ('F6', 'dma_reads', '2-4'),
        ('F6', 'dma_writes', '2-4'),
        ('F6', 'status_class', 'small'),
        ('F6', 'busy_after', 0),
        ('F6', 'err_after', 0),
        ('F6', 'irq_takes', 1),
    }


# ---------------------------------------------------------------------------
# Bounded values
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('count, expected', [
    (0, '0'), (1, '1'), (2, '2-4'), (4, '2-4'), (5, '5-8'), (8, '5-8'),
    (9, '9-16'), (16, '9-16'), (17, '17+'), (1000, '17+'),
])
def test_counter_buckets(count, expected):
    assert bucket(count) == expected


@pytest.mark.parametrize('not_a_count', ['4', 'unknown', None, 4.0, [4], True])
def test_non_integer_counts_are_unknown(not_a_count):
    assert bucket(not_a_count) == 'unknown'


@pytest.mark.parametrize('value, expected', [
    (0, 'zero'), (1, 'one'), (2, 'small'), (255, 'small'), (256, 'other'),
    (0x7FFFFFFF, 'other'), (0x80000000, 'high'), (0xFFFFFFFE, 'high'),
    (0xFFFFFFFF, 'all-ones'), (-1, 'other'),
])
def test_value_classes(value, expected):
    assert value_class(value) == expected


@pytest.mark.parametrize('not_a_value', ['0x10', 'unknown', None, 1.0, [1]])
def test_non_integer_values_are_unknown(not_a_value):
    assert value_class(not_a_value) == 'unknown'


def test_counters_are_bucketed_from_the_case_line():
    features = features_of({'flow': 'F2', 'i_fetches': 100, 'd_reads': 3})
    assert ('count', 'i_fetches', '17+') in features
    assert ('count', 'd_reads', '2-4') in features


def test_unknown_counter_tokens_produce_no_count_feature():
    features = features_of({'flow': 'F2', 'i_fetches': 'unknown'})
    assert not any(feature[0] == 'count' for feature in features)


def test_irq_facts_are_capped():
    cases = {
        0: features_of(f5_case(irq_edges=0, irq_takes=0)),
        1: features_of(f5_case(irq_edges=1, irq_takes=1)),
        3: features_of(f5_case(irq_edges=9, irq_takes=9)),
    }
    assert ('F5', 'irq_edges', 0) in cases[0]
    assert ('F5', 'irq_takes', 0) in cases[0]
    assert ('F5', 'irq_edges', 1) in cases[1]
    assert ('F5', 'irq_takes', 1) in cases[1]
    assert ('F5', 'irq_edges', 3) in cases[3]
    assert ('F5', 'irq_takes', 2) in cases[3]


def test_f6_irq_takes_is_capped():
    features = features_of(f6_case(irq_takes=9))
    assert ('F6', 'irq_takes', 2) in features
    assert ('F6', 'irq_takes', 9) not in features


# ---------------------------------------------------------------------------
# F1 data hash
# ---------------------------------------------------------------------------
def test_f1_data_hash_is_a_feature_only_when_the_window_changed():
    changed = features_of(f1_case())
    assert ('F1', 'data_hash', 0xcbf29ce4) in changed
    unchanged = features_of(f1_case(data_changed=0))
    assert not any(feature[:2] == ('F1', 'data_hash') for feature in unchanged)


def test_f1_data_hash_is_not_taken_from_the_before_image():
    features = features_of(f1_case(data_hash_after='unknown'))
    assert not any(feature[:2] == ('F1', 'data_hash') for feature in features)


def test_f1_data_changed_above_zero_still_provides_the_after_hash():
    features = features_of(f1_case(data_changed=2))
    assert ('F1', 'data_hash', 0xcbf29ce4) in features


# ---------------------------------------------------------------------------
# F2 echo and protocol spellings
# ---------------------------------------------------------------------------
def test_f2_echo_is_committed_when_the_read_value_survives():
    assert ('F2', 'echo', 'committed') in features_of(f2_case())


def test_f2_echo_is_lost_when_the_echo_differs():
    assert ('F2', 'echo', 'lost') in features_of(f2_case(echo_value=6))


def test_f2_echo_needs_both_observed_values():
    features = features_of(f2_case(echo_value=None))
    assert not any(feature[:2] == ('F2', 'echo') for feature in features)


def test_f2_target_reads_can_come_from_the_neutral_axi_counter():
    features = features_of(f2_case(target_reads=3, apb_reads='unknown'))
    assert ('F2', 'target_reads', '2-4') in features


# ---------------------------------------------------------------------------
# Pin-only facts
# ---------------------------------------------------------------------------
def test_f4_pin_facts_appear_only_when_the_line_carries_them():
    without = features_of(f4_apb_case())
    assert not any(feature[1] in ('out_after', 'dir_after')
                   for feature in without)
    with_pins = features_of(f4_apb_case(out_after=0x5, dir_after=0x3))
    assert ('F4', 'out_after', 0x5) in with_pins
    assert ('F4', 'dir_after', 0x3) in with_pins


def test_f2_pin_stimulus_appears_only_when_the_line_carries_it():
    assert ('F2', 'pin_stimulus', 'declared_default') in features_of(
        f2_case(pin_stimulus='declared_default'))
    assert not any(feature[:2] == ('F2', 'pin_stimulus')
                   for feature in features_of(f2_case(pin_stimulus=None)))
    assert not any(feature[:2] == ('F2', 'pin_stimulus')
                   for feature in features_of(f2_case(pin_stimulus='unknown')))


def test_f5_cause_enabled_compares_the_cause_pins_with_the_enable_mask():
    assert ('F5', 'cause_enabled', 'yes') in features_of(f5_case())
    assert ('F5', 'cause_enabled', 'no') in features_of(
        f5_case(inten_at_irq=0x4))
    assert not any(feature[:2] == ('F5', 'cause_enabled')
                   for feature in features_of(f5_case(inten_at_irq=None)))


def test_f5_status_class_reads_whichever_target_field_is_present():
    assert ('F5', 'status_class', 'zero') in features_of(
        f5_case(apb_read_data='unknown', target_read_data=0))
    assert ('F5', 'status_class', 'high') in features_of(
        f5_case(apb_read_data=0x80000000))


# ---------------------------------------------------------------------------
# F6 destination hash
# ---------------------------------------------------------------------------
def test_f6_dst_hash_is_stable_for_the_same_destination_block():
    first = features_of(f6_case())
    second = features_of(f6_case())
    digest = {feature for feature in first if feature[:2] == ('F6', 'dst_hash')}
    assert digest
    assert digest <= second


def test_f6_dst_hash_changes_when_the_destination_data_changes():
    first = {feature for feature in features_of(f6_case())
             if feature[:2] == ('F6', 'dst_hash')}
    changed = {feature for feature in features_of(f6_case(dst0=9))
               if feature[:2] == ('F6', 'dst_hash')}
    assert first and changed
    assert first != changed


def test_f6_dst_hash_requires_all_four_destination_words():
    assert not any(feature[:2] == ('F6', 'dst_hash')
                   for feature in features_of(f6_case(dst3='unknown')))
    assert not any(feature[:2] == ('F6', 'dst_hash')
                   for feature in features_of(f6_case(dst2=None)))


# ---------------------------------------------------------------------------
# Absence, unknown tokens, failure and repeats
# ---------------------------------------------------------------------------
def test_unknown_fields_are_ignored_without_a_crash():
    base = features_of(f3_case())
    extended = features_of(f3_case(future_field='value', extra_counter=12))
    assert base == extended


def test_unknown_strings_never_become_integers():
    feedback = FeedbackState().observe({
        'flow': 'F3',
        'status': 'failed',
        'write_addr': 'unknown',
        'write_value': 'unknown',
        'ram_after': 'unknown',
        'write_be': 'unknown',
        'i_fetches': 'unknown',
    })
    assert feedback.features == (('status', 'F3', 'failed'),)
    assert feedback.failed is True
    assert feedback.summary == ('F3 failed with no recognised observation')


def test_numeric_strings_are_not_reinterpreted():
    feedback = FeedbackState().observe(
        {'flow': 'F1', 'prog_words': '4', 'data_changed': '1'})
    assert feedback.features == ()


def test_a_failed_case_contributes_a_status_feature():
    feedback = FeedbackState().observe(f1_case(status='failed'))
    assert ('status', 'F1', 'failed') in feedback.features
    assert feedback.failed is True


def test_a_passing_case_has_no_status_feature():
    feedback = FeedbackState().observe(f1_case())
    assert feedback.failed is False
    assert not any(feature[0] == 'status' for feature in feedback.features)


def test_a_case_without_a_status_is_not_reported_as_failed():
    feedback = FeedbackState().observe({'flow': 'F1', 'prog_words': 2})
    assert feedback.failed is False
    assert feedback.status == 'unknown'
    assert ('F1', 'words', 2) in feedback.features


def test_repeat_observation_adds_no_new_features():
    state = FeedbackState()
    first = state.observe(f1_case())
    discovered = state.discovered
    second = state.observe(f1_case())
    assert first.new == first.features
    assert second.new == ()
    assert state.discovered == discovered
    assert state.document() == state.document()


def test_observe_does_not_mutate_the_case_dictionary():
    case = f1_case()
    before = copy.deepcopy(case)
    FeedbackState().observe(case)
    assert case == before


def test_every_feature_is_a_hashable_tuple_of_ints_and_strings():
    for case in (f1_case(), f2_case(), f3_case(), f4_axi_case(), f5_case(),
                 f6_case()):
        for feature in FeedbackState().observe(case).features:
            assert isinstance(feature, tuple)
            assert all(type(part) in (int, str) for part in feature)
            assert isinstance(hash(feature), int)


def test_case_feedback_is_frozen_and_slotted():
    feedback = FeedbackState().observe(f2_case())
    assert isinstance(feedback, CaseFeedback)
    assert not hasattr(feedback, '__dict__')
    with pytest.raises(dataclasses.FrozenInstanceError):
        feedback.status = 'failed'


@pytest.mark.parametrize('case', [None, [], 'F1', 3])
def test_observe_refuses_a_non_dictionary(case):
    with pytest.raises(ValueError, match='dict'):
        FeedbackState().observe(case)


def test_observe_refuses_a_missing_flow():
    with pytest.raises(ValueError, match='flow'):
        FeedbackState().observe({'status': 'observations_passed'})


@pytest.mark.parametrize('flow', ['F0', 'F7', 'f1', '', ['F1'], 1])
def test_observe_refuses_an_unsupported_flow(flow):
    with pytest.raises(ValueError, match='flow'):
        FeedbackState().observe({'flow': flow})


# ---------------------------------------------------------------------------
# Summaries and documents
# ---------------------------------------------------------------------------
def test_f1_summary_lists_the_program_facts():
    feedback = FeedbackState().observe(f1_case())
    assert feedback.summary.startswith(
        'F1 program 4 words retired 4, rd_mask 0x000000e0, data_changed 1')


def test_f2_summary_names_the_source_offset_and_value_class():
    summary = FeedbackState().observe(
        f2_case(read_from='target', echo_value=None,
                pin_stimulus=None)).summary
    assert summary == 'F2 target read offset 0x10 value class small'


def test_f3_f4_f5_summaries_name_the_observed_facts():
    f3 = FeedbackState().observe(f3_case()).summary
    assert f3.startswith('F3 write offset 0x100 value class small')
    assert 'ram committed yes' in f3
    f4 = FeedbackState().observe(f4_axi_case()).summary
    assert f4.startswith('F4 target write offset 0x10 value class small')
    assert 'target writes 1' in f4
    f5 = FeedbackState().observe(f5_case()).summary
    assert f5.startswith('F5 irq edges 3 takes 2')
    assert 'isr kind control' in f5
    assert 'cause enabled yes' in f5


def test_f6_summary_lists_the_dma_facts():
    summary = FeedbackState().observe(f6_case()).summary
    assert summary.startswith(
        'F6 dma_reads 4 dma_writes 4 status 0x3 busy_after 0 err_after 0')
    assert 'irq_takes 1' in summary
    assert 'dst_hash 0x' in summary


def test_a_case_with_only_counters_is_summarised_by_those_counters():
    summary = FeedbackState().observe(
        {'flow': 'F3', 'i_fetches': 5, 'd_reads': 0}).summary
    assert summary == 'F3 i_fetches 5 d_reads 0'


def test_a_case_with_nothing_recognised_gets_the_fallback_summary():
    feedback = FeedbackState().observe({'flow': 'F4', 'status': 'failed'})
    assert feedback.summary == 'F4 failed with no recognised observation'


def test_feedback_document_is_json_serialisable_and_counted():
    state = FeedbackState()
    state.observe(f1_case())
    state.observe(f6_case())
    document = state.document()
    assert document['schema_version'] == FEATURE_SCHEMA
    assert document['distinct'] == len(state.discovered)
    assert document['distinct'] == len(document['features'])
    assert all(isinstance(item['feature'], list)
               for item in document['features'])
    by_family = {}
    for item in document['features']:
        family = item['feature'][0]
        by_family[family] = by_family.get(family, 0) + 1
    assert document['by_family'] == by_family
    json.dumps(document)


def test_feedback_document_ordering_does_not_depend_on_observation_order():
    first = FeedbackState()
    first.observe(f1_case())
    first.observe(f1_case(prog_words=2, prog_last_wdata=0xFFFFFFFF))
    second = FeedbackState()
    second.observe(f1_case(prog_words=2, prog_last_wdata=0xFFFFFFFF))
    second.observe(f1_case())
    assert first.document() == second.document()


def test_feedback_features_are_stable_across_two_states():
    left = FeedbackState()
    right = FeedbackState()
    for case in (f2_case(), f4_axi_case(), f5_case()):
        left.observe(case)
        right.observe(case)
    assert left.discovered == right.discovered
    assert left.document() == right.document()


def test_the_counter_vocabulary_matches_the_executor_keys():
    assert COUNTER_KEYS == ('i_fetches', 'd_reads', 'd_writes', 'apb_reads',
                            'apb_writes', 'retires', 'rvfi_writebacks',
                            'rvfi_order_monotonic', 'traps', 'bus_errors')


# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------
def record(flow, fields):
    return flow + ':' + ':'.join(format(field, '08x') for field in fields)


def add(corpus, flow='F1', words=(1,), text=None, **kwargs):
    fields = tuple(words)
    return corpus.add(flow, fields, text or record(flow, fields), **kwargs)


def sample_corpus(max_entries=4):
    corpus = Corpus(max_entries=max_entries)
    a = corpus.seed('F1', (1,), 'F1:00000001')
    b = corpus.seed('F2', (2,), 'F2:00000002')
    corpus.add('F1', (3,), 'F1:00000003', parent='F1:00000001',
               origin='mutation')
    corpus.add('F2', (4,), 'F2:00000004', parent='F2:00000002',
               origin='mutation')
    for _ in range(2):
        corpus.mark_picked(a)
    corpus.note_discovery(a)
    for _ in range(2):
        corpus.note_discovery(b)
    corpus.add('F1', (5,), 'F1:00000005', origin='fresh')
    return corpus


# ---------------------------------------------------------------------------
# Corpus: seeding, adding, duplicates
# ---------------------------------------------------------------------------
def test_seed_records_origin_and_defaults():
    corpus = Corpus(max_entries=4)
    entry = corpus.seed('F1', (0x13,), 'F1:00000013')
    assert entry.origin == 'seed'
    assert entry.parent is None
    assert entry.picks == 0
    assert entry.discoveries == 0
    assert entry.fields == (0x13,)
    assert corpus.entries == (entry,)


def test_add_accepts_a_list_of_fields_and_an_explicit_origin():
    corpus = Corpus(max_entries=4)
    entry = corpus.add('F2', [1, 2], 'F2:00000001:00000002',
                       origin='fresh')
    assert entry.fields == (1, 2)
    assert entry.origin == 'fresh'
    entry = add(corpus, 'F2', (3,), parent='F2:00000001:00000002')
    assert entry.origin == 'mutation'
    assert entry.parent == 'F2:00000001:00000002'


def test_duplicate_add_keeps_one_entry_and_its_counts():
    corpus = Corpus(max_entries=4)
    first = corpus.seed('F1', (1,), 'F1:00000001')
    corpus.mark_picked(first)
    corpus.note_discovery(first)
    again = corpus.add('F1', (1,), 'F1:00000001')
    assert again is first
    assert len(corpus.entries) == 1
    assert again.picks == 1
    assert again.discoveries == 1
    assert again.origin == 'seed'


def test_duplicate_add_does_not_evict():
    corpus = Corpus(max_entries=1)
    entry = corpus.seed('F1', (1,), 'F1:00000001')
    corpus.add('F1', (1,), 'F1:00000001')
    assert corpus.entries == (entry,)
    assert corpus.document()['evicted'] == 0


@pytest.mark.parametrize('limit', [0, -1, 4097, True, 1.5, '8', None])
def test_max_entries_outside_the_bounds_is_refused(limit):
    with pytest.raises(ValueError, match='max_entries'):
        Corpus(max_entries=limit)


@pytest.mark.parametrize('limit', [1, 256, 4096])
def test_max_entries_inside_the_bounds_is_accepted(limit):
    assert Corpus(max_entries=limit).entries == ()


# ---------------------------------------------------------------------------
# Corpus: eviction
# ---------------------------------------------------------------------------
def test_eviction_removes_the_most_picked_entry():
    corpus = Corpus(max_entries=2)
    a = corpus.seed('F1', (1,), 'F1:00000001')
    b = corpus.seed('F1', (2,), 'F1:00000002')
    for _ in range(3):
        corpus.mark_picked(a)
    corpus.mark_picked(b)
    c = corpus.add('F1', (3,), 'F1:00000003')
    assert a not in corpus.entries
    assert b in corpus.entries
    assert c in corpus.entries
    assert corpus.document()['evicted'] == 1


def test_eviction_prefers_few_discoveries_when_picks_tie():
    corpus = Corpus(max_entries=2)
    a = corpus.seed('F1', (1,), 'F1:00000001')
    b = corpus.seed('F1', (2,), 'F1:00000002')
    corpus.mark_picked(a)
    corpus.mark_picked(b)
    corpus.note_discovery(a)
    corpus.note_discovery(a)
    corpus.add('F1', (3,), 'F1:00000003')
    assert a in corpus.entries
    assert b not in corpus.entries


def test_eviction_never_removes_the_just_added_entry():
    corpus = Corpus(max_entries=1)
    corpus.seed('F1', (1,), 'F1:00000001')
    added = corpus.add('F1', (2,), 'F1:00000002')
    assert corpus.entries == (added,)
    assert corpus.document()['evicted'] == 1


# ---------------------------------------------------------------------------
# Corpus: choice
# ---------------------------------------------------------------------------
def test_choose_returns_none_for_an_empty_corpus():
    assert Corpus(max_entries=2).choose(random.Random(0)) is None


def test_choose_is_deterministic_for_a_seeded_rng():
    corpus = Corpus(max_entries=8)
    for index in range(6):
        add(corpus, words=(index,))
    for entry in corpus.entries[:3]:
        corpus.mark_picked(entry)
    first = []
    rng = random.Random(9)
    for _ in range(20):
        first.append(corpus.choose(rng).record_text)
    second = []
    rng = random.Random(9)
    for _ in range(20):
        second.append(corpus.choose(rng).record_text)
    assert first == second


def test_choose_prefers_the_least_picked_entries():
    corpus = Corpus(max_entries=8)
    for index in range(6):
        add(corpus, words=(index,))
    for entry in corpus.entries[:3]:
        for _ in range(4):
            corpus.mark_picked(entry)
    rng = random.Random(5)
    for _ in range(200):
        assert corpus.choose(rng).picks == 0


def test_choose_can_reach_every_entry_tied_at_the_least_picked_count():
    corpus = Corpus(max_entries=8)
    for index in range(6):
        add(corpus, words=(index,))
    rng = random.Random(0)
    seen = {corpus.choose(rng).record_text for _ in range(200)}
    assert seen == {entry.record_text for entry in corpus.entries}


def test_choose_moves_away_from_an_entry_once_it_was_picked():
    corpus = Corpus(max_entries=4)
    add(corpus, words=(1,))
    add(corpus, words=(2,))
    chosen = corpus.choose(random.Random(1))
    corpus.mark_picked(chosen)
    assert corpus.choose(random.Random(1)) is not chosen


# ---------------------------------------------------------------------------
# Corpus: bookkeeping and views
# ---------------------------------------------------------------------------
def test_mark_picked_and_note_discovery_increment_the_stored_entry():
    corpus = Corpus(max_entries=4)
    entry = corpus.seed('F1', (1,), 'F1:00000001')
    corpus.mark_picked(entry)
    corpus.mark_picked(entry)
    corpus.note_discovery(entry)
    assert entry.picks == 2
    assert entry.discoveries == 1
    assert corpus.entries[0].picks == 2


def test_mark_picked_and_note_discovery_refuse_a_foreign_entry():
    corpus = Corpus(max_entries=4)
    stray = CorpusEntry(flow='F1', fields=(1,), record_text='F1:00000001',
                        origin='fresh', parent=None, picks=0, discoveries=0)
    with pytest.raises(ValueError, match='not in this corpus'):
        corpus.mark_picked(stray)
    with pytest.raises(ValueError, match='not in this corpus'):
        corpus.note_discovery(stray)
    with pytest.raises(ValueError, match='CorpusEntry'):
        corpus.mark_picked('F1:00000001')


def test_flow_returns_only_that_flows_entries_in_record_order():
    corpus = Corpus(max_entries=8)
    add(corpus, 'F1', words=(0x20,))
    add(corpus, 'F2', words=(2,))
    add(corpus, 'F1', words=(0x10,))
    f1 = corpus.flow('F1')
    assert [entry.record_text for entry in f1] == ['F1:00000010', 'F1:00000020']
    assert corpus.flow('F3') == ()
    with pytest.raises(ValueError, match='flow'):
        corpus.flow(3)


def test_entries_are_returned_in_a_stable_order():
    corpus = Corpus(max_entries=8)
    add(corpus, 'F2', words=(2,))
    add(corpus, 'F1', words=(1,))
    add(corpus, 'F1', words=(3,))
    assert [entry.record_text for entry in corpus.entries] == [
        'F1:00000001', 'F1:00000003', 'F2:00000002']


# ---------------------------------------------------------------------------
# Corpus: documents and persistence
# ---------------------------------------------------------------------------
def test_corpus_document_is_stable_and_json_serialisable():
    first = sample_corpus()
    second = sample_corpus()
    document = first.document()
    assert document['schema_version'] == CORPUS_SCHEMA
    assert document['evicted'] == 1
    assert document['by_flow'] == {'F1': 2, 'F2': 2}
    assert document == second.document()
    json.dumps(document)


def test_corpus_entry_document_is_json_serialisable():
    entry = CorpusEntry(flow='F1', fields=(1, 2), record_text='F1:00000001',
                        origin='mutation', parent='F1:00000000', picks=2,
                        discoveries=1)
    document = entry.document()
    assert document['fields'] == [1, 2]
    assert document['parent'] == 'F1:00000000'
    assert json.loads(json.dumps(document)) == document


def test_save_and_load_round_trip_every_documented_field(tmp_path):
    corpus = sample_corpus()
    path = tmp_path / 'corpus.json'
    corpus.save(path)
    loaded = Corpus.load(path, max_entries=4)
    assert loaded.document() == corpus.document()
    assert loaded.document()['evicted'] == 1
    assert all(isinstance(entry, CorpusEntry) for entry in loaded.entries)
    assert loaded.flow('F2') == corpus.flow('F2')


def test_saved_text_has_no_absolute_path_or_timestamp(tmp_path):
    corpus = sample_corpus()
    path = tmp_path / 'corpus.json'
    corpus.save(path)
    text = path.read_text(encoding='utf-8')
    assert str(tmp_path) not in text
    assert '/home' not in text
    assert 'timestamp' not in text
    assert 'saved_at' not in text
    assert text.endswith('\n')
    payload = json.loads(text)
    assert set(payload) == {'schema_version', 'entries', 'by_flow', 'evicted'}


def test_load_restores_the_eviction_count(tmp_path):
    corpus = sample_corpus()
    path = tmp_path / 'corpus.json'
    corpus.save(path)
    loaded = Corpus.load(path, max_entries=4)
    assert loaded.document()['evicted'] == corpus.document()['evicted']


def test_load_with_a_smaller_bound_evicts_and_still_loads(tmp_path):
    corpus = sample_corpus()
    path = tmp_path / 'corpus.json'
    corpus.save(path)
    loaded = Corpus.load(path, max_entries=2)
    assert len(loaded.entries) == 2
    assert loaded.document()['evicted'] >= 1


def test_load_refuses_an_unsupported_schema(tmp_path):
    path = tmp_path / 'corpus.json'
    path.write_text(json.dumps({'schema_version': 'inprocess_fuzz_corpus.v2',
                                'entries': []}), encoding='utf-8')
    with pytest.raises(ValueError, match='schema version'):
        Corpus.load(path)
    path.write_text(json.dumps({'entries': []}), encoding='utf-8')
    with pytest.raises(ValueError, match='schema version'):
        Corpus.load(path)


def test_load_refuses_non_json_text(tmp_path):
    path = tmp_path / 'corpus.json'
    path.write_text('{not json', encoding='utf-8')
    with pytest.raises(ValueError, match='malformed corpus document'):
        Corpus.load(path)


def good_entry(**overrides):
    row = {'flow': 'F1', 'fields': [1], 'record_text': 'F1:00000001',
           'origin': 'seed', 'parent': None, 'picks': 0, 'discoveries': 0}
    row.update(overrides)
    return row


def malformed_documents():
    duplicate = good_entry()
    missing_flow = good_entry()
    del missing_flow['flow']
    missing_text = good_entry()
    del missing_text['record_text']
    return [
        [],
        {'schema_version': CORPUS_SCHEMA, 'entries': {}},
        {'schema_version': CORPUS_SCHEMA, 'entries': [], 'evicted': -1},
        {'schema_version': CORPUS_SCHEMA, 'entries': [], 'evicted': '1'},
        {'schema_version': CORPUS_SCHEMA, 'entries': [missing_flow]},
        {'schema_version': CORPUS_SCHEMA, 'entries': [missing_text]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(fields='F1')]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(fields=[True])]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(origin='guess')]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(parent=3)]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(picks=-1)]},
        {'schema_version': CORPUS_SCHEMA,
         'entries': [good_entry(discoveries='one')]},
        {'schema_version': CORPUS_SCHEMA, 'entries': ['not an entry']},
        {'schema_version': CORPUS_SCHEMA, 'entries': [duplicate, duplicate]},
    ]


@pytest.mark.parametrize('payload', malformed_documents())
def test_load_refuses_malformed_documents(tmp_path, payload):
    path = tmp_path / 'corpus.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError):
        Corpus.load(path)


@pytest.mark.parametrize('args, kwargs', [
    (('', (1,), 'F1:00000001'), {}),
    ((5, (1,), 'F1:00000001'), {}),
    (('F1', 'not-fields', 'F1:00000001'), {}),
    (('F1', (1, 'x'), 'F1:00000001'), {}),
    (('F1', (True,), 'F1:00000001'), {}),
    (('F1', (1,), ''), {}),
    (('F1', (1,), None), {}),
    (('F1', (1,), 'F1:00000001'), {'origin': 'guess'}),
    (('F1', (1,), 'F1:00000001'), {'parent': 3}),
])
def test_add_refuses_invalid_inputs(args, kwargs):
    corpus = Corpus(max_entries=4)
    with pytest.raises(ValueError):
        corpus.add(*args, **kwargs)
    assert corpus.entries == ()


def test_seed_refuses_invalid_inputs():
    corpus = Corpus(max_entries=4)
    with pytest.raises(ValueError):
        corpus.seed('', (1,), 'F1:00000001')
    assert corpus.entries == ()
