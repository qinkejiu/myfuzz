"""Declared-IRQ F5 script helpers: pure case image, fields and CPU trace setup.

No native session is constructed here; the three real runs are the lead's frozen
window work.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.run_declared_irq_f5 import (
    ADMITTED_AUTHORITY, case_program, check_cpu_authority, cpu_authority, cpu_obi_traces,
    f5_fields, f5_source_options, f5_source_ids, semantic_digest, trigger_words)
from myfuzz.integration.declared_irq_consumption import (
    admit_declared_irq_consumption, build_declared_irq_firmware)

ROOT = Path(__file__).resolve().parents[2]
CASES = ('declared-irq-f5-wb-timer', 'declared-irq-f5-apb-spi', 'declared-irq-f5-ahb-sha',
         'declared-irq-f5-wb-timer-cv32e40p', 'declared-irq-f5-apb-spi-cv32e40p',
         'declared-irq-f5-pulp-timer', 'declared-irq-f5-pulp-timer-single')
LIMITED_CASES = ('declared-irq-f5-wb-timer-cv32e40p', 'declared-irq-f5-apb-spi-cv32e40p')


def configuration(name):
    return json.loads((ROOT / 'configs/scenarios' / name / 'config.json').read_text())


def admission_and_firmware(name):
    config = configuration(name)
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    assert admission['status'] == 'admitted'
    fields = f5_fields(config, admission)
    firmware = build_declared_irq_firmware(
        image_start=fields['image_start'], image_end=fields['image_end'],
        first_fetch=0x10080, target_base=fields['target_base'],
        status_offsets=fields['status_offsets'], result_address=fields['result_address'],
        clear_writes=fields['clear_writes'])
    return config, admission, fields, firmware


def words(data_hex):
    data = bytes.fromhex(data_hex)
    return [int.from_bytes(data[offset:offset + 4], 'little')
            for offset in range(0, len(data), 4)]


def addi_immediate(word):
    immediate = (word >> 20) & 0xfff
    return immediate - (1 << 12) if immediate & 0x800 else immediate


@pytest.mark.parametrize('name', CASES)
def test_case_image_encodes_only_the_declared_trigger_writes_and_a_park(name):
    config, _, fields, firmware = admission_and_firmware(name)
    options = dict(trigger_writes=tuple(tuple(row) for row in config['trigger_writes']))
    program = case_program(firmware, options, fields)
    image = words(program['images'][str(program['case_entry'])])
    trigger = [row for row in config['trigger_writes']]
    # x8 = declared target window base, then per trigger write: value load + SW.
    assert image[0] & 0x7f == 0x37 and image[1] & 0x7f == 0x13
    assert (image[0] & 0xfffff000) + addi_immediate(image[1]) == config['target_window']['base']
    position = 2
    for offset, value in trigger:
        if offset < 2048:
            assert image[position] & 0x7f == 0x37
            assert ((image[position] & 0xfffff000) + addi_immediate(image[position + 1])) & 0xffffffff == value
            store = image[position + 2]
            assert store & 0x7f == 0x23
            assert (store >> 15) & 31 == 8
            assert ((store >> 25) & 0x7f) << 5 | ((store >> 7) & 31) == offset
            position += 3
        else:
            assert (image[position] & 0xfffff000) + addi_immediate(image[position + 1]) == \
                config['target_window']['base'] + offset
            assert (image[position + 2] & 0xfffff000) + addi_immediate(image[position + 3]) == value
            store = image[position + 4]
            assert store & 0x7f == 0x23 and (store >> 15) & 31 == 10
            position += 5
    # The declared case image ends with a real self-loop park; no host pulse.
    assert image[-1] == 0x0000006f
    assert program['park'] == program['case_entry'] + 4 * (len(image) - 1)
    assert program['park'] == firmware['dynamic_start'] + 4 * (len(image) - 1)
    assert set(program) == {'images', 'case_entry', 'park', 'trigger_writes', 'trigger_words',
                            'dynamic_sha256'}
    assert sum(len(bytes.fromhex(data)) // 4 for data in program['images'].values()) >= \
        firmware['handler_words']


@pytest.mark.parametrize('name', CASES)
def test_case_image_never_overlaps_the_fixed_segments(name):
    config, _, fields, firmware = admission_and_firmware(name)
    options = dict(trigger_writes=tuple(tuple(row) for row in config['trigger_writes']))
    program = case_program(firmware, options, fields)
    fixed = [(row['address'], row['address'] + len(bytes.fromhex(row['data_hex'])))
             for row in firmware['segments']]
    fixed.append((firmware['scratch'], firmware['scratch'] + 16))
    fixed.append((firmware['result_address'],
                  firmware['result_address'] + 4 * firmware['result_words']))
    entry = program['case_entry']
    end = program['park'] + 4
    assert all(stop <= entry or end <= start for start, stop in fixed)
    assert firmware['image_start'] <= entry < end <= firmware['image_end']


def test_trigger_words_refuse_offsets_outside_the_declared_window():
    with pytest.raises(ValueError, match='declared-F5-configuration-trigger-write'):
        trigger_words(0x40001000, ((4, 1),), 4)
    with pytest.raises(ValueError, match='declared-F5-configuration-trigger-write'):
        trigger_words(0x40001000, ((2, 1),), 4096)
    with pytest.raises(ValueError, match='declared-F5-configuration-trigger-writes'):
        trigger_words(0x40001000, (), 4096)
    # A large offset materializes the complete word address.
    encoded = trigger_words(0x40001000, ((2048, 1),), 4096)
    assert encoded[0] & 0x7f == 0x37
    assert (encoded[0] & 0xfffff000) + addi_immediate(encoded[1]) == 0x40001000
    # Address pair first (x10), then the value pair (x9) and the store.
    assert (encoded[2] & 0xfffff000) + addi_immediate(encoded[3]) == 0x40001000 + 2048
    assert (encoded[4] & 0xfffff000) + addi_immediate(encoded[5]) == 1
    assert encoded[6] & 0x7f == 0x23 and (encoded[6] >> 15) & 31 == 10


def test_f5_fields_cross_check_the_admitted_declared_map():
    spi = configuration('declared-irq-f5-apb-spi')
    admission = admit_declared_irq_consumption(spi, base_dir=ROOT)
    assert f5_fields(spi, admission)['status_offsets'] == [40]
    with pytest.raises(ValueError, match='configuration-status-offset-undeclared'):
        f5_fields(dict(spi, status_offsets=[42]), admission)
    with pytest.raises(ValueError, match='configuration-window-base'):
        f5_fields(dict(spi, active_base=0x40002000), admission)
    with pytest.raises(ValueError, match='configuration-window-size'):
        f5_fields(dict(spi, target_window=dict(base=0x40001000, size=4)), admission)
    with pytest.raises(ValueError, match='configuration-clear-offset-undeclared'):
        f5_fields(dict(spi, clear_writes=[[40, 0]]), admission)
    with pytest.raises(ValueError, match='configuration-cause-bit-offset'):
        f5_fields(dict(spi, status_cause_bits={'36': 1}), admission)
    fields = f5_fields(dict(spi, status_cause_bits={'40': 0}), admission)
    assert fields['cause_bits'] == {40: 0}
    with pytest.raises(ValueError, match='configuration-f5-fields-missing'):
        f5_fields({key: value for key, value in spi.items() if key != 'image_start'}, admission)


def test_pulp_timer_uses_declared_overflow_and_readable_count_register():
    config, admission, fields, _ = admission_and_firmware('declared-irq-f5-pulp-timer')
    assert config['source_request'] == 'configs/peripherals/pulp_timer/irq_request.json'
    assert config['source_port'] == 'irq_o' and config['source_bit_offset'] == 0
    assert config['trigger_writes'] == [[4, 0], [8, 0], [0, 0xffffffff]]
    assert admission['target']['status_registers'][0]['name'] == 'TIMER0_COUNT'
    assert fields['status_offsets'] == [0] and fields['clear_writes'] == ()


def test_single_source_profile_reuses_existing_irq_source_contract():
    original = configuration('declared-irq-f5-pulp-timer')
    single = {k: v for k, v in original.items() if k not in ('idle_id', 'idle_base')}
    single['single_source'] = True
    options = f5_source_options(single)
    assert f5_source_ids(options) == ('pulp_timer_active',)
    assert options['idle_id'] is None and options['idle_base'] is None
    assert options['source_request'] == original['source_request']
    assert options['trigger_writes'] == tuple(map(tuple, original['trigger_writes']))
    legacy = f5_source_options(original)
    assert f5_source_ids(legacy) == ('pulp_timer_active', 'pulp_timer_idle')


def test_single_source_rejects_non_boolean_mode():
    config = configuration('declared-irq-f5-pulp-timer')
    with pytest.raises(ValueError, match='single.source'):
        f5_source_options(dict(config, single_source='true'))


def test_cpu_obi_traces_follow_the_declared_master_endpoints():
    artifact = SimpleNamespace(
        plan=SimpleNamespace(profile=SimpleNamespace(
            cpu=SimpleNamespace(master_endpoints=['processor.instruction', 'processor.data']))),
        runtime_document=dict(base_protocol_traces=dict(traces=[
            dict(endpoint_id='processor.instruction', protocol='obi', boundary='cpu_physical_abi',
                 max_outstanding=1, signals={'req': 'i_req', 'gnt': 'i_gnt', 'addr': 'i_addr',
                                            'rvalid': 'i_rvalid', 'rdata': 'i_rdata',
                                            'error': 'i_error'}),
            dict(endpoint_id='processor.data', protocol='obi', boundary='cpu_physical_abi',
                 max_outstanding=1, signals={'req': 'd_req', 'gnt': 'd_gnt', 'addr': 'd_addr',
                                             'rvalid': 'd_rvalid', 'rdata': 'd_rdata',
                                             'error': 'd_error', 'we': 'd_we',
                                             'wdata': 'd_wdata', 'be': 'd_be'})])))
    traces, policy = cpu_obi_traces(artifact)
    assert traces['instr']['addr'] == 'i_addr' and traces['data']['we'] == 'd_we'
    assert policy == dict(mode='native_error_role', native_error_observation=True)
    # A CPU whose declared traces lack the error role must not claim one.
    del artifact.runtime_document['base_protocol_traces']['traces'][1]['signals']['error']
    traces, policy = cpu_obi_traces(artifact)
    assert policy == dict(mode='fail_stop_no_error_pin', native_error_observation=False)
    artifact.runtime_document['base_protocol_traces']['traces'] = []
    with pytest.raises(ValueError, match='CPU-OBI-instr-trace-required'):
        cpu_obi_traces(artifact)


def test_semantic_digest_is_stable_and_order_independent():
    assert semantic_digest({'b': 2, 'a': 1}) == semantic_digest({'a': 1, 'b': 2})
    assert semantic_digest({'a': 1}) != semantic_digest({'a': 2})


@pytest.mark.parametrize('name', LIMITED_CASES)
def test_limited_cpu_cases_bind_the_realized_authority_to_admission(name):
    from myfuzz.local_harness.native_irq_receipt_contract import cv32e40p_irq_receipt_contract
    config = configuration(name)
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    contract = cv32e40p_irq_receipt_contract()
    assert cpu_authority(contract) == 'pc_insn_order_only'
    assert check_cpu_authority(admission, contract) == 'pc_insn_order_only'
    assert ADMITTED_AUTHORITY['pc_insn_order_only'] == admission['cpu']['retirement_authority']
    assert admission['cpu']['retirement_joins'] == 'by_documented_order'
    assert admission['cpu']['retirement_only_provider']['module'] == \
        'myfuzz.integration.shared_irq_firmware'
    bound = admit_declared_irq_consumption(config, base_dir=ROOT, cpu_contract=contract)
    assert semantic_digest(bound) == semantic_digest(admission)


def test_full_rvfi_cases_keep_the_exact_field_authority_binding():
    from myfuzz.local_harness.native_irq_receipt_contract import ibex_irq_receipt_contract
    config = configuration('declared-irq-f5-apb-spi')
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    contract = ibex_irq_receipt_contract()
    assert cpu_authority(contract) == 'full_rvfi'
    assert check_cpu_authority(admission, contract) == 'full_rvfi'
    assert ADMITTED_AUTHORITY['full_rvfi'] == admission['cpu']['retirement_authority']
    assert admission['cpu']['retirement_joins'] == 'exact_fields'
    assert admission['cpu']['retirement_only_provider'] is None
    bound = admit_declared_irq_consumption(config, base_dir=ROOT, cpu_contract=contract)
    assert semantic_digest(bound) == semantic_digest(admission)


def test_limited_authority_binding_refuses_a_full_rvfi_admission():
    from myfuzz.local_harness.native_irq_receipt_contract import (
        cv32e40p_irq_receipt_contract, ibex_irq_receipt_contract)
    limited = admit_declared_irq_consumption(
        configuration('declared-irq-f5-apb-spi-cv32e40p'), base_dir=ROOT)
    with pytest.raises(ValueError, match='admission-CPU-retirement-authority-mismatch'):
        check_cpu_authority(limited, ibex_irq_receipt_contract())
    full = admit_declared_irq_consumption(configuration('declared-irq-f5-apb-spi'),
                                          base_dir=ROOT)
    with pytest.raises(ValueError, match='admission-CPU-retirement-authority-mismatch'):
        check_cpu_authority(full, cv32e40p_irq_receipt_contract())
