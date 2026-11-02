"""Declared-IRQ F5 fixed firmware: layout, encodings, ordered retirement path."""
import json
from pathlib import Path
import pytest

from myfuzz.integration.declared_irq_consumption import (
    MRET_WORD, _csr, admit_declared_irq_consumption, build_declared_irq_firmware,
    firmware_code)

ROOT = Path(__file__).resolve().parents[2]
CASES = ('declared-irq-f5-wb-timer', 'declared-irq-f5-apb-spi', 'declared-irq-f5-ahb-sha')
# Derived from the declared component register maps, not from the builder output:
#   zipcpu_timer  : the single 4-byte COUNT register at offset 0 (no address bits)
#   pulp_spi      : INTSTA at offset 40 (ro, read_rearms_interrupt)
#   caliptra_sha  : STATUS at offset 24 (ro)
EXPECTED_STATUS = {'declared-irq-f5-wb-timer': (0, 'COUNT', 'zipcpu_timer'),
                   'declared-irq-f5-apb-spi': (40, 'INTSTA', 'pulp_spi'),
                   'declared-irq-f5-ahb-sha': (24, 'STATUS', 'caliptra_sha256')}
EXPECTED_PROTOCOL = {'declared-irq-f5-wb-timer': 'wishbone',
                     'declared-irq-f5-apb-spi': 'apb3',
                     'declared-irq-f5-ahb-sha': 'ahb-lite'}


def configuration(name):
    return json.loads((ROOT / 'configs/scenarios' / name / 'config.json').read_text())


def firmware_for(name):
    config = configuration(name)
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    assert admission['status'] == 'admitted'
    build = dict(image_start=config['image_start'], image_end=config['image_end'],
                 first_fetch=0x10080, target_base=config['target_window']['base'],
                 status_offsets=config['status_offsets'], result_address=config['result_address'],
                 clear_writes=tuple(tuple(row) for row in config.get('clear_writes', ())))
    return config, admission, build_declared_irq_firmware(**build)


def words_of(data_hex):
    data = bytes.fromhex(data_hex)
    return [int.from_bytes(data[offset:offset + 4], 'little') for offset in range(0, len(data), 4)]


def csr_fields(word):
    assert word & 0x7f == 0x73, hex(word)
    return (word >> 20, (word >> 15) & 31, (word >> 12) & 7, (word >> 7) & 31)


def load_store_fields(word):
    opcode = word & 0x7f
    if opcode == 0x03:
        return dict(kind='read', rd=(word >> 7) & 31, base=(word >> 15) & 31,
                    offset=(word >> 20) & 0xfff)
    if opcode == 0x23:
        return dict(kind='write', rs2=(word >> 20) & 31, base=(word >> 15) & 31,
                    offset=(((word >> 25) & 0x7f) << 5) | ((word >> 7) & 31))
    raise AssertionError(hex(word))


def register_constants(words, *, limit):
    """Decode the LUI/ADDI pairs that materialize one handler base register."""
    registers = {}
    for word in words[:limit]:
        opcode = word & 0x7f
        destination = (word >> 7) & 31
        immediate = (word >> 20) & 0xfff
        if immediate & 0x800:
            immediate -= 1 << 12
        if opcode == 0x37:
            registers[destination] = word & 0xfffff000
        elif opcode == 0x13 and (word >> 12) & 7 == 0:
            registers[destination] = (registers.get((word >> 15) & 31, 0) + immediate) & 0xffffffff
    return registers


@pytest.mark.parametrize('name', CASES)
def test_firmware_matches_the_declared_register_map_and_image_layout(name):
    config, admission, firmware = firmware_for(name)
    offset, register, component = EXPECTED_STATUS[name]
    assert admission['target']['component_id'] == component
    assert admission['target']['protocol'] == EXPECTED_PROTOCOL[name]
    assert admission['target']['status_registers'][0]['offset'] == offset
    assert admission['target']['status_registers'][0]['name'] == register
    assert config['status_offsets'] == [offset]
    # Fixed layout: bootstrap at the configured first fetch, direct/external
    # vectors at +0x200/+0x22c, handler at +0x400, case entry at +0x1000.
    assert firmware['first_fetch'] == 0x10080
    assert firmware['vector'] == config['image_start'] + 0x200
    assert firmware['vector_external'] == config['image_start'] + 0x22c
    assert firmware['handler'] == config['image_start'] + 0x400
    assert firmware['dynamic_start'] == config['image_start'] + 0x1000
    assert firmware['result_address'] == config['result_address']
    segments = {row['name']: row for row in firmware['segments']}
    assert set(segments) == {'vector_direct', 'vector_external', 'handler', 'bootstrap'}
    assert segments['bootstrap']['address'] == firmware['first_fetch']
    assert len(words_of(segments['bootstrap']['data_hex'])) == 12
    # Both fixed vectors reach the handler, so either CPU IRQ cause entry works.
    code = firmware_code(firmware)
    assert code[firmware['vector']] & 0x7f == 0x6f
    assert code[firmware['vector_external']] & 0x7f == 0x6f
    assert (firmware['vector'] + ((code[firmware['vector']] >> 21) & 0x3ff) * 2
            - ((code[firmware['vector']] >> 20) & 1) * 0x800) == firmware['handler']


@pytest.mark.parametrize('name', CASES)
def test_retirement_path_is_the_exact_handler_image_and_ends_with_mret(name):
    _, _, firmware = firmware_for(name)
    handler = {row['address']: row['data_hex'] for row in firmware['segments']
               if row['name'] == 'handler'}
    code = bytes.fromhex(handler[firmware['handler']])
    expected = [(firmware['handler'] + offset,
                 int.from_bytes(code[offset:offset + 4], 'little'))
                for offset in range(0, len(code), 4)]
    assert [tuple(row) for row in firmware['retirement_path']] == expected
    assert firmware['retirement_path'][-1][1] == MRET_WORD
    assert firmware['retirement_path'][-1][0] == firmware['mret_pc']
    assert firmware['mret_pc'] == firmware['handler'] + len(code) - 4
    assert firmware['handler_words'] == len(expected)
    # The path is strictly sequential in one straight-line handler.
    assert [pc for pc, _ in expected] == list(range(firmware['handler'],
                                                    firmware['handler'] + len(code), 4))


@pytest.mark.parametrize('name', CASES)
def test_memory_operations_document_the_declared_read_then_dependent_write(name):
    config, _, firmware = firmware_for(name)
    operations = firmware['memory_operations']
    offset = config['status_offsets'][0]
    assert [row['kind'] for row in operations] == ['read', 'write']
    assert [row['index'] for row in operations] == [0, 1]
    read, write = operations
    assert read['offset'] == offset
    assert read['address'] == config['target_window']['base'] + offset
    assert write['address'] == config['result_address']
    assert write['value_source'] == 'read_value[0]'
    assert write['result_index'] == 0
    assert firmware['result_words'] == 1
    code = firmware_code(firmware)
    read_fields = load_store_fields(code[read['pc']])
    write_fields = load_store_fields(code[write['pc']])
    # LW x2, offset(x1) with x1 materialized to the declared target window base.
    assert read_fields == dict(kind='read', rd=2, base=1, offset=offset)
    # SW x2, 0(x3) with x3 materialized to the declared result address.
    assert write_fields == dict(kind='write', rs2=2, base=3, offset=0)
    handler_words = words_of({row['address']: row['data_hex']
                              for row in firmware['segments'] if row['name'] == 'handler'}[
                                  firmware['handler']])
    position = (read['pc'] - firmware['handler']) // 4
    bases = register_constants(handler_words, limit=position)
    # x1 is the declared target window base; x3 the declared result address.
    assert bases[read_fields['base']] + read_fields['offset'] == read['address']
    assert bases[read_fields['base']] == config['target_window']['base']
    assert bases[write_fields['base']] + write_fields['offset'] == write['address']
    assert bases[write_fields['base']] == config['result_address']


@pytest.mark.parametrize('name', CASES)
def test_bootstrap_enables_the_declared_line_and_installs_mtvec(name):
    _, _, firmware = firmware_for(name)
    bootstrap = words_of({row['name']: row['data_hex'] for row in firmware['segments']}['bootstrap'])
    triples = [csr_fields(word) for word in bootstrap if word & 0x7f == 0x73]
    # mtvec, mscratch, mie set (machine external bit 11) and mstatus MIE set.
    assert triples == [(0x305, 3, 1, 0), (0x340, 3, 1, 0), (0x304, 3, 2, 0), (0x300, 3, 2, 0)]
    assert bootstrap[-1] & 0x7f == 0x6f
    assert firmware['scratch'] == firmware['image_start'] + 0xc00
    assert firmware['scratch_register'] == firmware['register_count'] - 1


def test_csr_and_branch_encodings_match_the_reference_fixed_smoke():
    from scripts.run_cv32e20_irq_smoke import fixed_program
    program = fixed_program(0x10000)
    reference = words_of(program['images']['65536'])
    reference_words = {word for word in reference}
    reference_triples = {csr_fields(word) for word in reference if word & 0x7f == 0x73}
    # The reference smoke already covers mtvec/mie/mstatus with the same operands.
    for triple in ((0x305, 3, 1, 0), (0x304, 3, 2, 0), (0x300, 3, 2, 0)):
        assert triple in reference_triples
        assert _csr(*triple) in reference_words
    # Only mscratch is new here; its encoding is the same checked formula.
    assert _csr(0x340, 3, 1, 0) == (0x340 << 20) | (3 << 15) | (1 << 12) | 0x73
    with pytest.raises(ValueError):
        _csr(0x305, 32)


def test_multiple_status_offsets_and_declared_clear_write_order():
    firmware = build_declared_irq_firmware(
        image_start=0x10000, image_end=0x30000, first_fetch=0x10000, target_base=0x40001000,
        status_offsets=(36, 40), result_address=0x10c40, clear_writes=((36, 0),))
    operations = firmware['memory_operations']
    assert [(row['kind'], row.get('offset'), row.get('result_index')) for row in operations] == [
        ('read', 36, None), ('write', None, 0), ('write', 36, None),
        ('read', 40, None), ('write', None, 1)]
    assert operations[2]['value_source'] == 'read_value[0]'
    assert operations[2]['role'] == 'declared_clear_or_ack'
    assert operations[2]['address'] == 0x40001000 + 36
    assert operations[4]['value_source'] == 'read_value[1]'
    assert operations[4]['address'] == 0x10c44
    # The ack write happens only after that register's value was read and stored.
    assert operations[0]['pc'] < operations[2]['pc'] < operations[3]['pc']
    assert firmware['result_words'] == 2


def test_large_status_offset_materializes_the_complete_address():
    firmware = build_declared_irq_firmware(
        image_start=0x10000, image_end=0x30000, first_fetch=0x10000, target_base=0x40001000,
        status_offsets=(2076,), result_address=0x10c40)
    read = firmware['memory_operations'][0]
    code = firmware_code(firmware)
    fields = load_store_fields(code[read['pc']])
    # A 12-bit displacement cannot reach offset 2076, so the full address is built.
    assert read['address'] == 0x40001000 + 2076
    assert fields == dict(kind='read', rd=2, base=4, offset=0)
    handler_words = words_of({row['name']: row['data_hex']
                              for row in firmware['segments']}['handler'])
    position = (read['pc'] - firmware['handler']) // 4
    bases = register_constants(handler_words, limit=position)
    assert bases[fields['base']] == 0x40001000 + 2076


@pytest.mark.parametrize('overrides,match', [
    (dict(first_fetch=0x0fffc), 'firmware-first-fetch'),
    (dict(image_start=0x10001), 'firmware-image-window'),
    (dict(image_end=0x10000 + 0x1000), 'firmware-image-window'),
    (dict(target_base=0x40001002), 'firmware-target-base'),
    (dict(status_offsets=()), 'firmware-status-count'),
    (dict(status_offsets=(6,)), 'firmware-status-offset'),
    (dict(status_offsets=(0, 0)), 'firmware-status-duplicate'),
    (dict(register_count=8), 'register-bank-unsupported'),
    (dict(result_address=0x10c02), 'firmware-result-window'),
    (dict(result_address=0x10c04), 'firmware-result-overlaps-scratch'),
    (dict(clear_writes=((36, 1),)), 'firmware-clear-write-declaration'),
    (dict(clear_writes=((36, 0), (36, 0))), 'firmware-clear-write-duplicate'),
])
def test_invalid_declared_layouts_are_refused(overrides, match):
    arguments = dict(image_start=0x10000, image_end=0x30000, first_fetch=0x10080,
                     target_base=0x40001000, status_offsets=(36,), result_address=0x10c40)
    arguments.update(overrides)
    with pytest.raises(ValueError, match='declared-F5-' + match):
        build_declared_irq_firmware(**arguments)


def test_admission_refuses_undeclared_and_unreadable_offsets():
    spi = configuration('declared-irq-f5-apb-spi')
    # INTCFG(36) is a declared, readable rw register; INTSTA(40) is the declared
    # read-rearm status register. Both are admissible status offsets.
    for offsets in ((40,), (36,), (36, 40)):
        admission = admit_declared_irq_consumption(dict(spi, status_offsets=list(offsets)), base_dir=ROOT)
        assert admission['status'] == 'admitted'
        assert [row['offset'] for row in admission['target']['status_registers']] == list(offsets)
    with pytest.raises(ValueError, match='admission-status-offset-undeclared'):
        admit_declared_irq_consumption(dict(spi, status_offsets=[42]), base_dir=ROOT)
    with pytest.raises(ValueError, match='admission-status-offsets'):
        admit_declared_irq_consumption(dict(spi, status_offsets=[40, 40]), base_dir=ROOT)
    sha = configuration('declared-irq-f5-ahb-sha')
    # The Caliptra intr block is real RTL but outside the declared register map.
    for undeclared in (2048, 2068, 2076):
        with pytest.raises(ValueError, match='admission-status-offset-undeclared'):
            admit_declared_irq_consumption(dict(sha, status_offsets=[undeclared]), base_dir=ROOT)
    # A write-only declared register cannot be read as a status.
    with pytest.raises(ValueError, match='admission-status-register-unreadable'):
        admit_declared_irq_consumption(dict(sha, status_offsets=[16]), base_dir=ROOT)
    # A clear/ack write must target a writable declared register.
    with pytest.raises(ValueError, match='admission-clear-register-unwritable'):
        admit_declared_irq_consumption(dict(sha, clear_writes=[[24, 0]]), base_dir=ROOT)
    with pytest.raises(ValueError, match='admission-clear-value-source'):
        admit_declared_irq_consumption(dict(spi, clear_writes=[[36, 1]]), base_dir=ROOT)
    timer = configuration('declared-irq-f5-wb-timer')
    # The ZipTimer declares exactly one 4-byte COUNT window at offset 0.
    with pytest.raises(ValueError, match='admission-status-offset-undeclared'):
        admit_declared_irq_consumption(dict(timer, status_offsets=[4]), base_dir=ROOT)
    assert admit_declared_irq_consumption(timer, base_dir=ROOT)['target']['status_registers'][0][
        'name'] == 'COUNT'


def test_pc_insn_order_only_cpu_admission_admits_the_documented_order_path():
    config = dict(configuration('declared-irq-f5-apb-spi'),
                  cpu_profile='configs/cpus/cv32e40p_rvfi_local/component_profile.json')
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    assert admission['status'] == 'admitted'
    assert admission['reason'] is None
    assert admission['cpu']['retirement_authority'] == 'pc_insn_order_only'
    provider = admission['cpu']['retirement_only_provider']
    # The provider names the real limited branch of shared_irq_firmware, never an
    # invented entry point.
    assert provider['module'] == 'myfuzz.integration.shared_irq_firmware'
    assert provider['entry_point'] == '_observe_limited_irq_isr'
    assert provider['retirement_window'] == '_limited_retirement_window'
    assert provider['successor_entry_point'] == 'validate_return_successor'
    assert admission['cpu']['retirement_joins'] == 'by_documented_order'
    assert admission['consumption']['retirement_joins'] == 'by_documented_order'
    assert admission['consumption']['value_joins'] == \
        'delivery_read_value==OBI_rdata==RAM_write_value'
    assert admission['layers']['consumption'] == 'order_only'
    assert admission['cpu']['retirement_fields'] == ['valid', 'order', 'insn', 'pc_rdata']
    assert 'mem_wdata' in admission['cpu']['unobserved_retirement_fields']
    assert 'pc_wdata' in admission['cpu']['unobserved_retirement_fields']
    assert admission['cpu']['contract_serial_observation'] is False
    assert admission['cpu']['observation_contract']['retirement_authority'] == 'pc_insn_order_only'
    for flag in ('reward_eligible', 'grants_F5', 'grants_F6', 'grants_prerequisites'):
        assert admission[flag] is False


def test_pc_insn_order_only_admission_is_unsupported_without_the_real_helpers(monkeypatch):
    import myfuzz.integration.shared_irq_firmware as shared
    from myfuzz.integration.declared_irq_consumption import retirement_only_provider
    assert retirement_only_provider() is not None
    monkeypatch.delattr(shared, '_limited_retirement_window')
    assert retirement_only_provider() is None
    config = dict(configuration('declared-irq-f5-apb-spi'),
                  cpu_profile='configs/cpus/cv32e40p_rvfi_local/component_profile.json')
    admission = admit_declared_irq_consumption(config, base_dir=ROOT)
    assert admission['status'] == 'unsupported'
    assert admission['cpu']['retirement_only_provider'] is None
    assert admission['reason'] == 'declared-F5-pc-insn-order-only-retirement-work-unavailable'
    assert admission['layers']['consumption'] == 'unsupported'
    assert admission['irq_consumption'] == 'unknown'


def test_pc_insn_order_only_admission_refuses_a_mismatched_cpu_contract():
    from myfuzz.local_harness.native_irq_receipt_contract import (
        cv32e40p_irq_receipt_contract, ibex_irq_receipt_contract)
    config = dict(configuration('declared-irq-f5-apb-spi'),
                  cpu_profile='configs/cpus/cv32e40p_rvfi_local/component_profile.json')
    admitted = admit_declared_irq_consumption(
        config, base_dir=ROOT, cpu_contract=cv32e40p_irq_receipt_contract())
    assert admitted['status'] == 'admitted'
    with pytest.raises(ValueError, match='admission-CPU-contract-mismatch'):
        admit_declared_irq_consumption(config, base_dir=ROOT,
                                       cpu_contract=ibex_irq_receipt_contract())
    with pytest.raises(ValueError, match='unregistered-native-IRQ-receipt-contract'):
        admit_declared_irq_consumption(config, base_dir=ROOT,
                                       cpu_contract=dict(cv32e40p_irq_receipt_contract(),
                                                         profile_id='other'))


def test_full_rvfi_cpu_admission_keeps_the_exact_field_join():
    admission = admit_declared_irq_consumption(
        configuration('declared-irq-f5-wb-timer'), base_dir=ROOT)
    assert admission['status'] == 'admitted'
    assert admission['cpu']['retirement_authority'] == 'full_rvfi_retirement_receipt'
    assert admission['cpu']['retirement_only_provider'] is None
    assert admission['cpu']['retirement_joins'] == 'exact_fields'
    assert admission['consumption']['retirement_joins'] == 'exact_fields'
    assert admission['consumption']['value_joins'] == \
        'delivery_read_value==OBI_rdata==retirement_mem_value==RAM_write_value'
    assert admission['layers']['consumption'] == 'full'
    assert admission['cpu']['unobserved_retirement_fields'] == []


def test_admission_reports_unknown_cause_and_version_layers():
    admission = admit_declared_irq_consumption(configuration('declared-irq-f5-wb-timer'), base_dir=ROOT)
    assert admission['layers']['internal_cause'] == 'unknown'
    assert admission['layers']['internal_version'] == 'unknown'
    assert admission['layers']['case_origin'] == 'unknown'
    assert admission['irq_consumption'] == 'unknown' and admission['isr_mmio'] == 'unknown'
    assert admission['target']['status_registers'][0]['side_effect'] == \
        'write_stops_or_starts_countdown'
