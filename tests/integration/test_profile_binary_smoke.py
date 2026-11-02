"""External binary mode observes CPU retirement without inventing expected values."""
from types import SimpleNamespace

import pytest

from scripts.run_profile_rv32i_smoke import binary_exit_status, load_binary_program, observe_binary_retirements


def test_load_binary_at_actual_boot_address(tmp_path):
    source = tmp_path / 'test.bin'
    source.write_bytes(bytes.fromhex('93005000 6f000000'))
    profile = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=['i']))
    program = load_binary_program(profile, source, base=0x10080)
    assert program.base == 0x10080
    assert program.code == source.read_bytes()


def test_external_retirements_are_observed_without_asserting_result():
    events = [
        {'kind': 'fetch_completion', 'address': 0x10080},
        {'kind': 'cpu_retire', 'pc_rdata': 0x10080, 'insn': 0x500093, 'order': 1,
         'rd_addr': 1, 'rd_wdata': 5},
        {'kind': 'cpu_retire', 'pc_rdata': 0x10084, 'insn': 0x6f, 'order': 2},
    ]
    feedback = observe_binary_retirements(events)
    assert feedback['status'] == 'observed'
    assert [row['pc_rdata'] for row in feedback['retirements']] == [0x10080, 0x10084]
    assert feedback['retirements'][0]['rd_wdata'] == 5
    assert 'rd_wdata' not in feedback['retirements'][1]
    assert observe_binary_retirements(events[:1])['status'] == 'unobserved'


def test_incomplete_requested_retirements_do_not_count_as_completed():
    events = [{'kind': 'cpu_retire', 'pc_rdata': 0x10080, 'insn': 0x13, 'order': 1}]
    partial = observe_binary_retirements(events, requested_count=2)
    assert partial['status'] == 'observed'
    assert partial['requested_retirements'] == 2
    assert partial['stop_condition_met'] is False
    assert binary_exit_status(partial) == 1
    assert observe_binary_retirements(events, requested_count=1)['stop_condition_met'] is True
    assert binary_exit_status(observe_binary_retirements(events, requested_count=1)) == 0
    assert observe_binary_retirements(events)['stop_condition_met'] is None


def test_binary_requires_matching_cpu_and_nonempty_image(tmp_path):
    source = tmp_path / 'test.bin'
    source.write_bytes(b'')
    profile = SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=32, extensions=['i']))
    with pytest.raises(ValueError):
        load_binary_program(profile, source, base=0x10080)
    source.write_bytes(b'\x13\x00\x00\x00')
    with pytest.raises(ValueError):
        load_binary_program(SimpleNamespace(cpu=SimpleNamespace(family='riscv', xlen=64, extensions=['i'])), source, base=0x10080)
