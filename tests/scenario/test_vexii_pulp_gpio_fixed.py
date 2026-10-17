"""Pure and opt-in real tests for the VexiiRiscv + PULP GPIO fixed IRQ row."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario import vexii_pulp_gpio_fixed as fixed

ROOT = Path(__file__).resolve().parents[2]


def test_program_image_layout_and_audited_words():
    program = fixed.build_program_image((0x11, 0x22))
    assert program['entry'] == fixed.BOOT == 0x80000000
    assert program['isr_address'] == fixed.ISR_ADDRESS == 0x80000200
    assert program['mtvec_value'] == fixed.ISR_ADDRESS
    assert program['cases'] == [0x11, 0x22]
    assert program['driven_values'] == [0x11, 0x23]
    main = program['main_words']
    isr = program['isr_words']
    # The program installs mtvec, enables MEIE and MIE, and writes the GPIO
    # configuration registers that the profile's address map declares.
    assert 0x305D9073 in main          # csrw mtvec, x27
    assert 0x304D9073 in main          # csrw mie, x27
    assert 0x300DA073 in main          # csrs mstatus, x27
    assert 0x01692223 in main          # sw x22, 4(x18)   GPIOEN
    assert 0x01692C23 in main          # sw x22, 24(x18)  INTEN
    assert 0x01692E23 in main          # sw x22, 28(x18)  INTTYPE_LOW
    assert 0x01692A23 in main          # sw x22, 20(x18)  PADOUTCLR
    assert 0x01692823 in main          # sw x22, 16(x18)  PADOUTSET
    assert 0x001B6B13 in main          # ori x22, x22, 1
    assert [word for word in main if word == 0] == []
    assert isr[0] == 0x400002B7        # lui x5, 0x40000
    assert isr[1] == 0x00C2A303        # lw x6, 12(x5)   PADOUT
    assert isr[2] == 0x0242A383        # lw x7, 36(x5)   INTSTATUS
    assert isr[-1] == 0x30200073       # mret
    assert [word for word in isr if word == 0] == []
    image = program['image']
    assert len(image) == program['image_length']
    assert program['image_sha256'] == hashlib.sha256(image).hexdigest()
    # Main code is at the boot address, the ISR exactly at mtvec, and the case
    # table holds the values the program reads.
    assert image[:4] == main[0].to_bytes(4, 'little')
    offset = fixed.ISR_ADDRESS - fixed.BOOT
    assert image[offset:offset + 4] == isr[0].to_bytes(4, 'little')
    table = fixed.TABLE_ADDRESS - fixed.BOOT
    assert image[table:table + 8] == (0x11).to_bytes(4, 'little') + (0x22).to_bytes(4, 'little')
    assert fixed.build_program_image((0x11, 0x22)) == program


@pytest.mark.parametrize('cases', [
    (), (0x11, 0x11), (0x10, 0x11),
    (0x100000000,), (True,), (0x1, 'x'),
])
def test_case_validation_refuses_non_distinct_or_invalid_values(cases):
    with pytest.raises(ValueError):
        fixed.validate_cases(cases)


def test_case_validation_bounds_the_row():
    assert fixed.validate_cases((0x11,)) == (0x11,)
    with pytest.raises(ValueError):
        fixed.validate_cases(tuple(range(1, fixed.MAX_CASES + 2)))


def _synthetic_row(*, result=0x11, include_rise=True, levels=None):
    deliveries = [
        {'write': True, 'offset': fixed.REG_PADOUTSET, 'write_value': 0x11},
        {'write': False, 'offset': fixed.REG_PADOUT, 'read_value': 0x11},
        {'write': False, 'offset': fixed.REG_INTSTATUS, 'read_value': 1},
        {'write': True, 'offset': fixed.REG_PADOUTCLR, 'write_value': fixed.PADOUTCLR_ALL},
    ]
    rounds = [{'rise_cpu_tick': 10, 'fall_cpu_tick': 20, 'isr_vector_fetches': 1,
               'late_pulses': 0, 'deliveries': deliveries}]
    events = [{'kind': 'irq_rise'}, {'kind': 'irq_fall'}] if include_rise else []
    return {
        'error': None,
        'program': {'cases': [0x11], 'driven_values': [0x11]},
        'rounds': rounds,
        'ram': {'result': [result], 'status': [1], 'check': [0], 'done': fixed.DONE_MARK},
        'host_events': events,
        'cpu_irq_edges': levels if levels is not None else [{'level': 1}, {'level': 0}],
    }


def test_row_verification_accepts_observed_rounds_and_refuses_corruption():
    checks = fixed.verify_row_document(_synthetic_row())
    assert {check['name']: check['ok'] for check in checks} and all(
        check['ok'] for check in checks)
    assert not all(check['ok'] for check in
                   fixed.verify_row_document(_synthetic_row(result=0x12)))
    assert not all(check['ok'] for check in
                   fixed.verify_row_document(_synthetic_row(include_rise=False)))
    assert not all(check['ok'] for check in
                   fixed.verify_row_document(_synthetic_row(levels=[{'level': 1}])))
    missing = _synthetic_row()
    missing['error'] = 'host round bound exhausted before the row finished'
    by_name = {check['name']: check['ok'] for check in fixed.verify_row_document(missing)}
    assert by_name['row-completed-all-cases'] is False


def _replay_document(execution, *, result=0x11):
    document = _synthetic_row(result=result)
    document.update({
        'status': 'verified',
        'identities': {'cpu': {'kind': 'reduced_dual_axi_irq_cpu'},
                       'gpio': {'kind': 'apb_gpio'}},
        'execution': execution,
        'program': {'cases': [0x11], 'driven_values': [0x11]},
        'deliveries': [{'source_transaction': {
            'execution_id': execution['cpu'], 'testcase_id': 'label',
            'source_component': 'cpu', 'source_epoch': 0, 'channel_id': 'data',
            'source_sequence': 1}}],
        'acceptances': [],
        'host_events': [{'kind': 'irq_rise', 'cpu_tick': 10},
                        {'kind': 'irq_fall', 'cpu_tick': 20}],
        'fetch_addresses': [fixed.BOOT], 'cpu_irq_edges': [{'level': 1}, {'level': 0}],
        'ram': {'result': [result], 'status': [1], 'check': [0], 'done': fixed.DONE_MARK},
        'checks': [], 'counts': {'cpu_ticks': 21},
    })
    return document


def test_fresh_replay_compares_evidence_modulo_run_identity():
    first = _replay_document({'cpu': 'a' * 32, 'gpio': 'b' * 32})
    fresh = _replay_document({'cpu': 'c' * 32, 'gpio': 'd' * 32})
    verdict = fixed.compare_fresh_runs(first, fresh)
    assert verdict['matches'] is True
    assert verdict['first_execution']['cpu'] != verdict['fresh_execution']['cpu']
    changed = _replay_document({'cpu': 'e' * 32, 'gpio': 'f' * 32}, result=0x12)
    assert fixed.compare_fresh_runs(first, changed)['matches'] is False
    same_execution = _replay_document({'cpu': 'a' * 32, 'gpio': 'b' * 32})
    assert fixed.compare_fresh_runs(first, same_execution)['matches'] is False


def test_fixed_chain_defaults_are_a_small_distinct_row():
    cases = fixed.validate_cases(fixed.DEFAULT_CASES)
    driven = [value | 1 for value in cases]
    assert 2 <= len(cases) <= fixed.MAX_CASES
    assert len(set(driven)) == len(driven)
    assert all(0 <= value < 1 << 32 for value in cases)


@pytest.mark.skipif(os.environ.get('MYFUZZ_VEXII_IRQ_REAL') != '1',
                    reason='explicit real CPU + GPIO IRQ gate')
def test_real_vexii_gpio_irq_fixed_row_and_fresh_replay(tmp_path):
    output = tmp_path / 'evidence'
    cache = Path(os.environ.get('MYFUZZ_VEXII_IRQ_CACHE', str(tmp_path / 'cache')))
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                   'PYTHONPATH': str(ROOT / 'src'),
                   'MYFUZZ_VEXII_IRQ_CACHE': str(cache),
                   'LC_ALL': 'C'}
    completed = subprocess.run(
        [sys.executable, 'scripts/run_vexiiriscv_irq_fixed_row.py',
         '--output', str(output), '--cache', str(cache),
         '--cases', '17', '34', '291'],
        cwd=str(ROOT), env=environment, capture_output=True, text=True, timeout=1800)
    summary = json.loads((output / 'summary.json').read_text())
    assert completed.returncode == 0, (completed.stdout[-2000:], completed.stderr[-4000:])
    assert summary['status'] == 'verified'
    assert summary['replay']['matches'] is True
    assert summary['cases'] == [17, 34, 291]
    assert summary['counts']['first']['irq_rises'] == 3
    assert summary['counts']['first']['irq_falls'] == 3
    assert summary['counts']['first']['isr_vector_fetches'] >= 3
    assert summary['counts']['first']['apb_deliveries'] == 4 + 3 * 4
    assert all(check['ok'] for check in summary['row_checks']['first'])
    assert all(check['ok'] for check in summary['row_checks']['fresh'])
    assert summary['first_execution']['cpu'] != summary['fresh_execution']['cpu']
    assert not (output / 'first.json').exists()
    for label in ('first', 'fresh'):
        raw = (output / f'{label}.json.gz').read_bytes()
        assert raw[:2] == b'\x1f\x8b'
        assert summary['artifacts'][label]['gzip_sha256'] == hashlib.sha256(raw).hexdigest()
        unpinned = gzip.decompress(raw)
        assert summary['artifacts'][label]['json_sha256'] == hashlib.sha256(unpinned).hexdigest()
        document = json.loads(unpinned)
        assert document['status'] == 'verified'
        assert document['ram'] == {'result': [17, 35, 291],
                                   'status': [1, 1, 1], 'check': [0, 0, 0],
                                   'done': fixed.DONE_MARK}
        assert document['wiring']['injects_trap'] is False
        assert document['irq_entry']['physical_port'] == (
            'PrivilegedPlugin_logic_harts_0_int_m_external')
        assert document['implementation']['scenario_module']['sha256'] == hashlib.sha256(
            (ROOT / 'src/myfuzz/scenario/vexii_pulp_gpio_fixed.py').read_bytes()).hexdigest()
