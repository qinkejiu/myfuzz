"""Captured original/fresh comparison normalizes only legal APB nonce ids."""
import json
from copy import deepcopy
import pytest
from tests.integration.test_compiled_f6_contract import ROOT


@pytest.fixture(scope='module')
def captured_pair():
    directory = ROOT/'research/input-strategy-audit-20261027/runs/three-component-20261028/f6-storage-support-buildjoinfix'
    if not (directory/'replay.json').is_file():
        pytest.skip('captured original/fresh pair unavailable')
    return json.loads((directory/'prefix.json').read_text()), json.loads((directory/'replay.json').read_text())['actual_prefix']


def test_captured_eight_legal_apb_nonce_differences_normalize_to_equal(captured_pair):
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix
    original, actual = captured_pair
    assert _normalized_f6_prefix(original) == _normalized_f6_prefix(actual)


@pytest.mark.parametrize('mutation', ['sequence', 'value'])
def test_apb_sequence_or_actual_value_change_is_not_normalized(captured_pair, mutation):
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix
    original, actual = captured_pair
    actual = deepcopy(actual)
    row = next(row for row in actual['actual_events'] if str(row.get('target_access_id', '')).startswith('apb-storage:'))
    if mutation == 'sequence':
        row['target_access_id'] += '1'
    else:
        row['read_value'] = 999
    assert _normalized_f6_prefix(original) != _normalized_f6_prefix(actual)
