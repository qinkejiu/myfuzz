"""Independent software callback-outcome review; no RTL RAM claim."""
from dataclasses import replace
from unittest.mock import patch

import pytest

from tests.scenario.test_uart_store_commit_contract import fixture, key, write


EQUIVALENT_VERSIONS = [(False, 1), (0, True), (0.0, 1), (0, 1.0), (False, 1.0)]


@pytest.mark.parametrize('version', EQUIVALENT_VERSIONS)
def test_post_effect_returned_version_requires_exact_integer_types(version):
    memory, ledger, service = fixture()
    original = memory.write

    def misleading_outcome(*args, **kwargs):
        original(*args, **kwargs)
        return version

    with patch.object(memory, 'write', side_effect=misleading_outcome):
        with pytest.raises(RuntimeError):
            write(service)
    assert memory._commit_sequences['host-ram'] == 1
    assert ledger.uncertain_keys == (key(),)
    assert not service.events
    with pytest.raises(RuntimeError, match='uncertain_effect'):
        write(service)
    assert memory._commit_sequences['host-ram'] == 1


@pytest.mark.parametrize('version', EQUIVALENT_VERSIONS)
def test_post_effect_store_cell_version_requires_exact_integer_types(version):
    memory, ledger, service = fixture()
    original = memory.write

    def misleading_cell(*args, **kwargs):
        measured = original(*args, **kwargs)
        cell = memory._bytes[('host-ram', 0)]
        memory._bytes[('host-ram', 0)] = replace(cell, version=version)
        return measured

    with patch.object(memory, 'write', side_effect=misleading_cell):
        with pytest.raises(RuntimeError):
            write(service)
    assert memory._commit_sequences['host-ram'] == 1
    assert ledger.uncertain_keys == (key(),)
    assert not service.events


@pytest.mark.parametrize('byte_enable,generation,offset', [
    (15, 0, False), (15, 0, 0.0), (0, False, 0), (0, 0.0, 0),
])
def test_callback_span_identity_rejects_numeric_type_substitution(
        byte_enable, generation, offset):
    memory, ledger, service = fixture()
    with patch.object(memory, 'resolve_span',
                      return_value=('host-ram', generation, offset)):
        with pytest.raises(RuntimeError):
            write(service, be=byte_enable)
    assert memory._commit_sequences['host-ram'] == (1 if byte_enable else 0)
    assert ledger.uncertain_keys == (key(),)
    assert not service.events
    with pytest.raises(RuntimeError, match='uncertain_effect'):
        write(service, be=byte_enable)
    assert memory._commit_sequences['host-ram'] == (1 if byte_enable else 0)
