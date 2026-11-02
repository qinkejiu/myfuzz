"""Tests for the bounded feedback vocabulary (long-run stability, Task 2)."""
import json

import pytest

from myfuzz.fuzz.feedback import (DEFAULT_MAX_FEATURES, FEATURE_SAMPLE_LIMIT,
                                  FeedbackState)


def f6_case(index):
    return dict(index=index, flow='F6', status='observations_passed',
                dma_reads=4, dma_writes=4, ctl_status=3, busy_after=0, err_after=0,
                irq_takes=1, dst0=index, dst1=index + 1, dst2=index + 2,
                dst3=index + 3)


def test_the_default_cap_is_a_positive_finite_number():
    assert type(DEFAULT_MAX_FEATURES) is int and DEFAULT_MAX_FEATURES > 0
    assert FEATURE_SAMPLE_LIMIT <= DEFAULT_MAX_FEATURES


def test_a_long_sequence_does_not_grow_past_the_cap():
    state = FeedbackState(max_features=64)
    for index in range(5000):
        state.observe(f6_case(index))
    document = state.document()
    assert document['distinct'] <= 64
    assert document['features_retained'] <= 64
    assert document['features_truncated'] is True
    assert len(state.discovered) <= 64


def test_the_document_keeps_only_a_bounded_feature_sample():
    state = FeedbackState(max_features=4096)
    for index in range(3000):
        state.observe(f6_case(index))
    document = state.document()
    assert document['features_retained'] <= 4096
    assert len(document['features']) <= FEATURE_SAMPLE_LIMIT
    assert document['features_sampled'] == len(document['features'])
    json.dumps(document)


def test_the_document_reports_observed_counts_even_when_truncated():
    state = FeedbackState(max_features=4)
    for index in range(50):
        state.observe(f6_case(index))
    document = state.document()
    assert document['features_observed'] > document['features_retained']
    assert document['features_retained'] == document['distinct']
    assert document['by_family'].get('F6', 0) == document['distinct']


def test_a_duplicate_case_adds_nothing():
    state = FeedbackState(max_features=64)
    first = state.observe(f6_case(1))
    second = state.observe(f6_case(1))
    assert first.new and not second.new
    assert state.document()['distinct'] == len(first.new)


def test_the_cap_never_counts_an_unretained_feature_as_new():
    state = FeedbackState(max_features=1)
    last = None
    for index in range(10):
        last = state.observe(f6_case(index))
    # Once the one slot is used, later cases cannot claim a new feature.
    assert last.new == ()
    assert state.document()['distinct'] == 1


def test_a_non_positive_cap_is_refused():
    with pytest.raises(ValueError, match='max_features'):
        FeedbackState(max_features=0)
    with pytest.raises(ValueError, match='max_features'):
        FeedbackState(max_features=-1)
