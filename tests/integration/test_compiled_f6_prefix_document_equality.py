"""The prefix comparison must accept exactly what whole-document canonical JSON accepts."""
from copy import deepcopy

import pytest

from myfuzz.integration.compiled_f6 import (
    _canonical, _documents_equal, _first_difference)


def _reference_equal(left, right):
    return _canonical(left) == _canonical(right)


BASE = {
    'schema_version': 'compiled_F6_prefix.v1',
    'records': [{'raw8_hex': '01', 'flow': 'F6'}],
    'attempts': [{'case_id': 'a', 'feedback': [0, 0, 0, 0, 0], 'ok': True}],
    'assertion_material': {'events': [{'event_id': 1, 'value': 7}], 'meta': {'n': 2}},
    'actual_events': [{'event_id': 1, 'kind': 'cpu_retire', 'tick': 3}],
}


def _mutations():
    only_top = deepcopy(BASE)
    only_top['status'] = 'complete'
    yield only_top, deepcopy(BASE)

    nested_list = deepcopy(BASE)
    nested_list['actual_events'][0]['tick'] = 4
    yield nested_list, deepcopy(BASE)

    deep = deepcopy(BASE)
    deep['assertion_material']['meta']['n'] = 2.0
    yield deep, deepcopy(BASE)

    tuple_value = deepcopy(BASE)
    tuple_value['assertion_material']['meta']['n'] = (2,)
    yield tuple_value, deepcopy(BASE)

    extra_key = deepcopy(BASE)
    extra_key['extra'] = None
    yield extra_key, deepcopy(BASE)


@pytest.mark.parametrize('left,right', list(_mutations()))
def test_sectionwise_equality_matches_full_canonical_equality(left, right):
    assert _documents_equal(left, right) == _reference_equal(left, right)


def test_identical_and_permuted_documents_compare_equal():
    assert _documents_equal(BASE, deepcopy(BASE))
    reordered = {name: deepcopy(BASE[name]) for name in reversed(list(BASE))}
    assert _documents_equal(reordered, deepcopy(BASE)) == _reference_equal(
        reordered, deepcopy(BASE))
    assert _documents_equal(reordered, deepcopy(BASE))


def test_same_prefix_is_rendered_once_per_section_and_still_validated(monkeypatch):
    from myfuzz.integration import compiled_f6
    canonical = compiled_f6._canonical
    calls = []
    def counted(value):
        calls.append(value)
        return canonical(value)
    monkeypatch.setattr(compiled_f6, '_canonical', counted)
    assert _documents_equal(BASE, BASE)
    assert len(calls) == len(BASE)
    invalid = {'a': [float('nan')]}
    with pytest.raises(ValueError):
        _documents_equal(invalid, invalid)


def test_non_document_values_fall_back_to_canonical_equality():
    assert _documents_equal([1, 2], [1, 2])
    assert not _documents_equal([1, 2], [1, 3])
    assert not _documents_equal({'a': 1}, [('a', 1)])


def test_first_difference_still_reports_the_same_first_site():
    left = deepcopy(BASE)
    right = deepcopy(BASE)
    right['assertion_material']['meta']['n'] = 3
    difference = _first_difference(left, right)
    assert difference['path'] == '$.assertion_material.meta.n'
    assert difference['expected'] == 2 and difference['actual'] == 3
    assert _first_difference(left, deepcopy(BASE)) is None
