"""A reused result belongs to observed inputs, never to the order of calls.

The exit re-authentication still has to *prove* that nothing it authenticated
changed.  These tests pin both directions: an unchanged input is not computed
again, and a changed input (including a same-size edit with a restored mtime)
is.
"""
import os

import pytest

from myfuzz.local_harness import execution_validation as ev
from myfuzz.local_harness.execution_validation import (
    ExecutionValidationError,
    execution_validation_scope,
    file_digest,
    identity_of,
    identity_memo,
    key_identity,
    register_key_identity,
    static_validation,
)


@pytest.fixture(autouse=True)
def fresh_memos():
    """Each test observes the same process memos from an empty state."""
    registered = list(ev._KEY_IDENTITIES)
    ev._IDENTITY_RESULTS.clear()
    ev._DIGESTS.clear()
    try:
        yield
    finally:
        ev._IDENTITY_RESULTS.clear()
        ev._DIGESTS.clear()
        ev._KEY_IDENTITIES[:] = registered


def test_one_computation_per_observed_identity():
    calls = []

    def compute():
        calls.append(1)
        return {'value': len(calls)}

    assert identity_memo('namespace', 'a', compute) == {'value': 1}
    assert identity_memo('namespace', 'a', compute) == {'value': 1}
    assert identity_memo('namespace', 'b', compute) == {'value': 2}
    assert identity_memo('other-namespace', 'a', compute) == {'value': 3}
    assert len(calls) == 3


def test_result_is_copied_out_so_callers_cannot_share_state():
    result = identity_memo('namespace', 'a', lambda: {'rows': [1]})
    result['rows'].append(2)
    assert identity_memo('namespace', 'a', lambda: {'rows': [1]}) == {'rows': [1]}


def test_an_unobservable_identity_is_never_treated_as_unchanged():
    calls = []

    def compute():
        calls.append(1)
        return 'accepted'

    assert identity_memo('namespace', None, compute) == 'accepted'
    assert identity_memo('namespace', None, compute) == 'accepted'
    assert len(calls) == 2


def test_identity_of_is_content_addressed_and_order_independent():
    left = identity_of('name', [('a', '1'), ('b', '2')])
    right = identity_of('name', [('a', '1'), ('b', '2')])
    changed = identity_of('name', [('a', '1'), ('b', '3')])
    assert left == right != changed
    # A different namespace with the same body is a different identity.
    assert identity_of('other', [('a', '1'), ('b', '2')]) != left


def test_exit_reuses_an_unchanged_input_without_computing_it_again(tmp_path):
    source = tmp_path / 'source.sv'
    source.write_bytes(b'original')
    calls = []

    def validate():
        calls.append(1)
        return source.read_bytes()

    with execution_validation_scope() as state:
        assert static_validation('source', validate,
                                 identity=lambda: file_digest(source)) == b'original'
    assert calls == [1]
    assert state == {'status': 'verified', 'matches': True}


def test_exit_recomputes_a_same_size_edit_with_restored_mtime(tmp_path):
    source = tmp_path / 'source.sv'
    source.write_bytes(b'original')
    stamp = source.stat()
    calls = []

    def validate():
        calls.append(1)
        return source.read_bytes()

    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            assert static_validation('source', validate,
                                     identity=lambda: file_digest(source)) == b'original'
            source.write_bytes(b'modified')
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert len(calls) == 2


def test_exit_recomputes_when_the_identity_cannot_be_observed(tmp_path):
    source = tmp_path / 'source.sv'
    source.write_bytes(b'original')
    calls = []

    def validate():
        calls.append(1)
        return source.read_bytes()

    with execution_validation_scope() as state:
        static_validation('source', validate, identity=lambda: None)
    assert len(calls) == 2
    assert state['status'] == 'verified'


def test_a_registered_key_identity_observes_a_key_owned_elsewhere(tmp_path):
    observed = ['first']
    register_key_identity('demo-gate', lambda key: observed[0])
    calls = []

    def validate():
        calls.append(1)
        return observed[0]

    with execution_validation_scope():
        assert static_validation(('demo-gate', 'x'), validate) == 'first'
    assert len(calls) == 1
    assert key_identity(('demo-gate', 'x')) == 'first'
    observed[0] = 'second'
    with pytest.raises(ExecutionValidationError):
        with execution_validation_scope():
            assert static_validation(('demo-gate', 'x'), validate) == 'second'
            observed[0] = 'third'
    # Body, then the exit boundary re-authenticates the changed input and
    # reports the mismatch instead of keeping the accepted result.
    assert len(calls) == 3


def test_nested_static_results_are_covered_by_the_outer_observation():
    inner, outer = [], []

    def outer_validate():
        outer.append(1)

        def inner_validate():
            inner.append(1)
            return 'inner'

        return static_validation('inner', inner_validate) + '-accepted'

    with execution_validation_scope() as state:
        assert static_validation('outer', lambda: identity_memo(
            'outer-namespace', 'observed', outer_validate),
            identity=lambda: 'observed') == 'inner-accepted'
    # The nested acceptance is covered by the outer identity, so neither is
    # recomputed at the exit boundary.
    assert (outer, inner) == ([1], [1])
    assert state['status'] == 'verified'


def test_reuse_can_be_disabled_without_weakening_any_check(tmp_path, monkeypatch):
    source = tmp_path / 'source.sv'
    source.write_bytes(b'original')
    calls = []

    def validate():
        calls.append(1)
        return 'accepted'

    monkeypatch.setenv('MYFUZZ_IDENTITY_REUSE', '0')
    assert identity_memo('namespace', 'a', validate) == 'accepted'
    assert identity_memo('namespace', 'a', validate) == 'accepted'
    with execution_validation_scope() as state:
        static_validation('source', validate, identity=lambda: 'unchanged')
    # Nothing is reused anywhere: one computation in the body, one at exit.
    assert len(calls) == 4
    assert state['status'] == 'verified'
    monkeypatch.setenv('MYFUZZ_IDENTITY_REUSE', 'invalid')
    with pytest.raises(ValueError, match='identity-reuse'):
        identity_memo('namespace', 'a', validate)
