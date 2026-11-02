"""Pure-Python coverage of the GPIO in-process entry: no RTL, no Verilator.

Every fact these tests touch is either the argument/record contract, the fixed
RAM image the C++ host loads, the compact line format it prints (including the
pin lines), the correspondence check applied to a saved observation, or the
named refusal of a declaration the selected components cannot serve.  No model
is built and no device is simulated.
"""
import json
from pathlib import Path

import pytest

from scripts.run_inprocess_gpio import (
    CASE_PIN_KEYS, DATA_OFFSET, HB, HB_STATUS, HANDLER_BLOCK_BYTES, HANDLER_OFFSET,
    MAILBOX_OFFSET, RESULT_OFFSET, SLOT_OFFSET, VECTOR_OFFSET, _expected_out,
    build_firmware, build_layout, case_document, correspondence, declared_windows,
    final_status, flow_arity, irq_declaration, parse_case_line, parse_record,
    parse_run_log, parse_summary_line, pin_declaration, validate_record)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-obi-apb-gpio-pins.json'
CONFIG = json.loads(CONFIG_PATH.read_text())
CPU_PROFILE = ROOT / CONFIG['cpu_profile']
GPIO_PROFILE = ROOT / CONFIG['source_profile']
BOOT = 0x10080
WINDOWS = declared_windows(CONFIG)
LAYOUT = build_layout(WINDOWS, BOOT)


def _profile(path):
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(json.loads(path.read_text()))


IP_PROFILE = _profile(GPIO_PROFILE)
IRQ = irq_declaration(CONFIG, IP_PROFILE)
PINS = pin_declaration(CONFIG, IP_PROFILE)
WINDOWS['registers'] = {row.name: row.offset for row in IP_PROFILE.address.registers}
ARITY = flow_arity(IRQ)
IP_BASE = WINDOWS['ip_base']
PADIN = IP_BASE + CONFIG['pins']['padin_offset']
EVIDENCE = ('F1:2ab00693,F3:00014004:0badf00d,F4:40000004:ffffffff,'
            'P:40000008:0000aaaa,F2:40000008,F5:ffffffff:00000001:00000001:0000002b')


def record(text):
    return parse_record(text, windows=WINDOWS, arity=ARITY, pins=PINS)


def case_line(**fields):
    """One `case` line in the shape the C++ host prints."""
    words = ['case', str(fields.pop('index', 0)), fields.pop('status', 'observations_passed')]
    for key, value in fields.items():
        words += [key, value if isinstance(value, str) else str(value)]
    return ' '.join(words)


def base_case(flow, **extra):
    fields = dict(flow=flow, ticks=40, seconds=0.0001, i_fetches=10, d_reads=2, d_writes=1,
                  apb_reads=0, apb_writes=0, pad_before='0x00000000', pad_after='0x00000000',
                  out_after='0x00000000', dir_after='0x00000000', ext_value='0x00000000',
                  pad_changes=0, pad_rise_events=0, rise_mask='0x00000000',
                  fall_mask='0x00000000')
    fields.update(extra)
    return fields


# --- declared windows and the fixed RAM image -----------------------------

def test_the_two_windows_come_from_the_declaration():
    assert WINDOWS['ram_base'] == CONFIG['image_start']
    assert WINDOWS['data_base'] == CONFIG['image_start'] + DATA_OFFSET
    assert WINDOWS['ip_base'] == CONFIG['target_window']['base']
    assert WINDOWS['ip_size'] == CONFIG['target_window']['size']


@pytest.mark.parametrize('key,value,match', [
    ('image_end', CONFIG['image_start'] + 8, 'too small'),
    ('target_window', dict(base=1073741824, size=2), 'unusable'),
    ('target_window', dict(base=CONFIG['image_start'], size=4096), 'overlaps'),
    ('image_start', 'x', 'integer'),
])
def test_unusable_declared_windows_are_refused(key, value, match):
    with pytest.raises(ValueError, match=match):
        declared_windows(dict(CONFIG, **{key: value}))


def test_one_image_carries_every_fixed_address_without_overlap():
    spans = sorted([(LAYOUT['boot'], 'boot'), (LAYOUT['vector'], 'vector'),
                    (LAYOUT['handler'], 'handler'), (LAYOUT['main'], 'main'),
                    (LAYOUT['slot'], 'slot'), (LAYOUT['mailbox'], 'mailbox'),
                    (LAYOUT['handler_block'], 'handler_block'),
                    (LAYOUT['data_base'], 'data'), (LAYOUT['result_f5'], 'result')])
    assert len({name for _, name in spans}) == len(spans)
    assert LAYOUT['data_end'] == CONFIG['image_end']
    assert LAYOUT['handler_block'] == LAYOUT['mailbox'] + HB_STATUS
    assert LAYOUT['flag'] == LAYOUT['result_f5'] + 8
    for name, offset in dict(slot=SLOT_OFFSET, mailbox=MAILBOX_OFFSET,
                             data_base=DATA_OFFSET, result_f5=RESULT_OFFSET,
                             vector=VECTOR_OFFSET, handler=HANDLER_OFFSET).items():
        assert LAYOUT[name] == CONFIG['image_start'] + offset
    assert spans[0][0] == LAYOUT['boot']


@pytest.mark.parametrize('boot', [LAYOUT['vector'] - 4, CONFIG['image_start'] + 2])
def test_a_boot_address_without_room_is_refused(boot):
    with pytest.raises(ValueError, match='aligned RAM word|no room'):
        build_layout(WINDOWS, boot)


# --- input records --------------------------------------------------------

def test_the_declared_flow_word_counts():
    assert ARITY == {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'P': 2, 'F5': 4}
    counts = [len(record(text)['fields']) for text in EVIDENCE.split(',')]
    assert counts == [1, 2, 2, 2, 1, 4]


def test_the_pin_flow_is_refused_when_the_target_declares_no_irq():
    arity = flow_arity(None)
    assert 'F5' not in arity
    with pytest.raises(ValueError, match='unsupported flow tag: F5'):
        parse_record('F5:1:2:3:4', windows=WINDOWS, arity=arity, pins=PINS)


def test_one_record_keeps_the_canonical_text_the_host_echoes():
    parsed = record('P:40000008:0000AAAA')
    assert parsed['text'] == 'P:40000008:0000aaaa'
    assert parsed['message'] == 'CASE P 40000008 0000aaaa'
    assert parsed['fields'] == (IP_BASE + 8, 0xAAAA)


@pytest.mark.parametrize('text,match', [
    ('F9:00014000', 'unsupported flow tag'),
    ('F5:00000001:00000000', 'needs 4 word'),
    ('P:40000008', 'needs 2 word'),
    ('P:4000000c:00000001', 'PADIN address'),
    ('F2:00013000', 'APB or data-window'),
    ('F3:40001000:1', 'data-window RAM'),
    ('F4:40002000:1', 'APB window'),
    ('F1:10000000', 'instruction word'),
    ('F1:2ab0069g', 'hexadecimal'),
    ('F1:', 'hexadecimal'),
    ('', 'record text is required'),
])
def test_bad_records_are_refused_by_name(text, match):
    with pytest.raises(ValueError, match=match):
        record(text)


def test_the_f1_legality_gate_still_applies():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.isa.constraints import f1_isa_from_profile
    isa = f1_isa_from_profile(load_component_profile(CPU_PROFILE))
    assert validate_record(record('F1:2ab00693'), isa=isa, windows=WINDOWS)
    with pytest.raises(ValueError, match='mailbox register'):
        validate_record(record('F1:00000413'), isa=isa, windows=WINDOWS)


# --- declaration checks ---------------------------------------------------

def test_the_declared_irq_source_is_the_pulse_the_profile_states():
    assert IRQ['port'] == CONFIG['irq']['source_port']
    assert IRQ['trigger'] == 'pulse' and IRQ['polarity'] == 'active_high'
    assert IRQ['pulse_ticks'] == CONFIG['irq']['pulse_width_ticks']
    assert IRQ['status_offset'] == WINDOWS['registers']['INTSTATUS']
    assert IRQ['trigger_offsets'] == CONFIG['irq']['trigger_offsets']
    assert IRQ['clear'] is None


@pytest.mark.parametrize('patch,match', [
    (dict(status_offset=16), 'readable word'),
    (dict(trigger_offsets=[8]), 'writable word'),
    (dict(trigger_offsets=[]), 'trigger offsets'),
    (dict(pulse_width_ticks=0), 'delivery width'),
    (dict(source_port='nope'), 'no single IRQ output'),
    (dict(source_bit_offset=7), 'no single IRQ output'),
])
def test_irq_declarations_the_device_cannot_serve_are_refused(patch, match):
    with pytest.raises(ValueError, match=match):
        irq_declaration(dict(CONFIG, irq=dict(CONFIG['irq'], **patch)), IP_PROFILE)


def _stub_profile(*, trigger):
    """A minimal profile shape: the fields irq_declaration actually reads."""
    from types import SimpleNamespace
    registers = SimpleNamespace(registers=tuple(
        SimpleNamespace(offset=offset, width=32, access=access)
        for offset, access in ((36, 'ro'), (4, 'rw'), (24, 'rw'), (28, 'rw'), (12, 'rw'))))
    pins = SimpleNamespace(endpoint_id='gpio.pins', function='external_pins', fields=(
        SimpleNamespace(role='in', direction='input', width=32),
        SimpleNamespace(role='out', direction='output', width=None),
        SimpleNamespace(role='dir', direction='output', width=None)))
    irq = SimpleNamespace(endpoint_id='gpio.interrupts', function='interrupt_source', fields=(
        SimpleNamespace(role='irq', direction='output', width=1, aliases=['interrupt']),))
    address = SimpleNamespace(window_size=4096, alignment=4096, registers=registers.registers)
    source = SimpleNamespace(endpoint_id='gpio.interrupts', role='irq', bit=0,
                             polarity='active_high', trigger=trigger)
    return SimpleNamespace(address=address, endpoints=(pins, irq), interrupts=(source,))


def test_a_level_source_is_refused_because_the_host_samples_a_pulse():
    with pytest.raises(ValueError, match='transition pulse only'):
        irq_declaration(CONFIG, _stub_profile(trigger='level'))
    declared = irq_declaration(CONFIG, _stub_profile(trigger='pulse'))
    assert declared['trigger'] == 'pulse' and declared['pulse_ticks'] == 16


def test_the_declared_pad_model_matches_the_pin_endpoint():
    assert PINS['width'] == 32 and PINS['external_value'] == 0
    assert PINS['padin_offset'] == WINDOWS['registers']['PADIN']


@pytest.mark.parametrize('patch,match', [
    (dict(pad_resolution='open_drain'), 'dir-resolved pad model'),
    (dict(external_value=-1), '32-bit word'),
    (dict(external_value=1 << 32), '32-bit word'),
    (dict(padin_offset=20), 'readable word'),
    (dict(padin_offset=999), 'readable word'),
])
def test_pad_declarations_the_device_cannot_serve_are_refused(patch, match):
    with pytest.raises(ValueError, match=match):
        pin_declaration(dict(CONFIG, pins=dict(CONFIG['pins'], **patch)), IP_PROFILE)


# --- the one RAM image ----------------------------------------------------

def test_the_firmware_carries_the_handler_and_the_declared_parameters():
    firmware = build_firmware(LAYOUT, irq=IRQ)
    images = firmware['images']
    assert set(images) == {LAYOUT['boot'], LAYOUT['vector'], LAYOUT['handler'],
                           LAYOUT['main'], LAYOUT['slot'], LAYOUT['data_base'],
                           LAYOUT['handler_block']}
    assert len(images[LAYOUT['vector']]) == 12 * 4
    assert images[LAYOUT['slot']][:4] == b'\x13\x00\x00\x00'
    assert len(images[LAYOUT['handler_block']]) == HANDLER_BLOCK_BYTES
    flag_cell = images[LAYOUT['handler_block']][HB + 16 - HB:HB + 16 - HB + 4]
    assert int.from_bytes(flag_cell, 'little') == LAYOUT['flag']
    assert firmware['slot_return'] > LAYOUT['main']


def test_the_firmware_without_an_irq_declaration_carries_no_handler():
    firmware = build_firmware(LAYOUT, irq=None)
    assert firmware['images'][LAYOUT['handler']] == b''
    assert len(firmware['images'][LAYOUT['main']]) > 0


# --- run log --------------------------------------------------------------

def test_a_case_line_keeps_the_pin_and_flow_fields():
    line = case_line(record='P:40000008:0000aaaa', **base_case(
        'P', read_addr='0x40000008', read_value='0x0000aaaa', echo_value='0x0000aaaa',
        read_from='apb', apb_rdata='0x0000aaaa', pad_at_read='0x0000aaaa',
        padin_latch='0x0000aaaa', apb_reads=1, pad_after='0x0000aaaa',
        ext_value='0x0000aaaa', pad_changes=1))
    parsed = parse_case_line(line, flows=ARITY)
    assert parsed['flow'] == 'P' and parsed['status'] == 'observations_passed'
    assert parsed['read_value'] == 0xAAAA and parsed['read_from'] == 'apb'
    assert parsed['ext_value'] == 0xAAAA and parsed['apb_reads'] == 1


@pytest.mark.parametrize('line,match', [
    ('case 0 failed flow F9 ticks 1', 'supported flow tag'),
    ('case x observations_passed flow F1 ticks 1', 'not an integer'),
    ('case 0 maybe flow F1 ticks 1', 'unsupported case status'),
    ('case 0 observations_passed flow F1 ticks', 'key/value pairs'),
    ('case 0 observations_passed flow F1 ticks 1 ticks 2', 'duplicate'),
    ('summary observations_passed cases 1', 'not a case line'),
])
def test_unreadable_case_lines_are_refused(line, match):
    with pytest.raises(ValueError, match=match):
        parse_case_line(line, flows=ARITY)


def test_a_run_log_without_a_summary_line_is_refused():
    with pytest.raises(ValueError, match='no summary line'):
        parse_run_log('case 0 observations_passed flow F1 ticks 1\n', flows=ARITY)


def test_the_run_log_keeps_pin_events_and_irq_edges_apart_from_cases():
    text = '\n'.join([
        'pin 184 pad 0x00000000 0x0000aaaa out 0x00000000 dir 0x00000000 ext 0x0000aaaa',
        'pin 186 edge rise 0x0000aaaa fall 0x00000000',
        'irq_edge 536 cause 0x00000001',
        'case 0 observations_passed flow F4 ticks 44',
        'NEED_RECORD 1 tick 60',
        'CASE_INSTALLED 1',
        'summary observations_passed cases 1 ticks 61']) + '\n'
    parsed = parse_run_log(text, flows=ARITY)
    assert parsed['pin_events'] == 2 and parsed['irq_edges'] == 1
    assert parsed['installed'] == [1]
    assert parsed['summary']['status'] == 'observations_passed'
    assert parsed['summary']['cases'] == 1


def test_a_duplicate_summary_line_is_refused():
    text = 'summary observations_passed cases 0\nsummary observations_passed cases 0\n'
    with pytest.raises(ValueError, match='duplicate summary line'):
        parse_run_log(text, flows=ARITY)


# --- correspondence -------------------------------------------------------

def test_a_matching_pin_write_is_accepted():
    case = parse_case_line(case_line(record='F4:4000000c:0000002a', **base_case(
        'F4', mmio_addr='0x4000000c', mmio_value='0x0000002a', apb_offset='0x0000000c',
        apb_pwdata='0x0000002a', apb_pready=1, apb_writes=1, out_before='0x00000000',
        dir_before='0xffffffff', out_after='0x0000002a', dir_after='0xffffffff',
        pad_after='0x0000002a', pad_changes=1, pad_rise_events=1)), flows=ARITY)
    assert correspondence(record('F4:4000000c:0000002a'), case, layout=LAYOUT,
                          windows=WINDOWS, irq=IRQ, pins=PINS) is None


def test_a_pin_write_that_the_output_port_did_not_follow_is_a_mismatch():
    case = parse_case_line(case_line(record='F4:4000000c:0000002a', **base_case(
        'F4', mmio_addr='0x4000000c', mmio_value='0x0000002a', apb_offset='0x0000000c',
        apb_pwdata='0x0000002a', apb_pready=1, apb_writes=1, out_before='0x00000000',
        out_after='0x00000000', dir_after='0xffffffff', pad_after='0x00000000')), flows=ARITY)
    assert 'gpio_out' in correspondence(record('F4:4000000c:0000002a'), case, layout=LAYOUT,
                                        windows=WINDOWS, irq=IRQ, pins=PINS)


def test_a_write_outside_the_padout_family_must_not_move_the_pins():
    case = parse_case_line(case_line(record='F4:40000018:00000001', **base_case(
        'F4', mmio_addr='0x40000018', mmio_value='0x00000001', apb_offset='0x00000018',
        apb_pwdata='0x00000001', apb_pready=1, apb_writes=1, out_before='0x0000002a',
        out_after='0x0000002a', dir_after='0xffffffff', pad_after='0x0000002a')), flows=ARITY)
    assert correspondence(record('F4:40000018:00000001'), case, layout=LAYOUT,
                          windows=WINDOWS, irq=IRQ, pins=PINS) is None
    moved = dict(case, out_after=0x2B)
    assert 'gpio_out' in correspondence(record('F4:40000018:00000001'), moved, layout=LAYOUT,
                                        windows=WINDOWS, irq=IRQ, pins=PINS)


@pytest.mark.parametrize('register,expected', [
    (12, 0x00000005),          # PADOUT overwrites
    (16, 0x0000000F),          # PADOUTSET sets
    (20, 0x0000000A),          # PADOUTCLR clears
    (4, 0x0000000F),           # any other register keeps the output
])
def test_the_padout_family_semantics_are_the_reviewed_ones(register, expected):
    registers = WINDOWS['registers']
    before, value = 0x0000000F, 0x00000005
    name = {registers['PADOUT']: 'PADOUT', registers['PADOUTSET']: 'PADOUTSET',
            registers['PADOUTCLR']: 'PADOUTCLR'}.get(register)
    if name is None:
        assert _expected_out(register, before, value, registers) == before
    else:
        assert _expected_out(register, before, value, registers) == expected


def test_a_pin_read_that_the_cpu_did_not_commit_is_a_mismatch():
    case = parse_case_line(case_line(record='P:40000008:0000aaaa', **base_case(
        'P', read_addr='0x40000008', read_value='0x0000aaaa', echo_value='0x00000000',
        read_from='apb', apb_rdata='0x0000aaaa', pad_at_read='0x0000aaaa',
        padin_latch='0x0000aaaa', apb_reads=1, ext_value='0x0000aaaa')), flows=ARITY)
    assert 'commit' in correspondence(record('P:40000008:0000aaaa'), case, layout=LAYOUT,
                                      windows=WINDOWS, irq=IRQ, pins=PINS)


def test_a_pin_read_that_differs_from_the_host_driver_is_a_mismatch():
    case = parse_case_line(case_line(record='P:40000008:0000aaaa', **base_case(
        'P', read_addr='0x40000008', read_value='0x0000aaaa', echo_value='0x0000aaaa',
        read_from='apb', apb_rdata='0x0000aaaa', pad_at_read='0x00005555',
        padin_latch='0x0000aaaa', apb_reads=1, ext_value='0x0000aaaa')), flows=ARITY)
    assert 'pad the host resolved' in correspondence(record('P:40000008:0000aaaa'), case,
                                                     layout=LAYOUT, windows=WINDOWS,
                                                     irq=IRQ, pins=PINS)


def test_a_ram_read_is_not_allowed_to_claim_an_apb_transfer():
    case = parse_case_line(case_line(record='F2:00014000', **base_case(
        'F2', read_addr='0x00014000', read_value='0xdeadbeef', echo_value='0xdeadbeef',
        read_from='ram', apb_reads=1)), flows=ARITY)
    assert 'plain RAM read' in correspondence(record('F2:00014000'), case, layout=LAYOUT,
                                              windows=WINDOWS, irq=IRQ, pins=PINS)


def _causal_case(**patch):
    fields = base_case('F5', trigger_writes=4, apb_read_offset='0x00000024',
                       apb_read_data='0x00000001', apb_last_write_offset='0x0000000c',
                       apb_last_write_data='0x0000002b', irq_edges=1, irq_high_ticks=1,
                       irq_takes=1, irq_cause_pins='0x00000001', inten_at_irq='0x00000001',
                       first_rise_tick=534, first_irq_tick=536,
                       status_after_read='0x00000000', isr_result='0x00000001', isr_flag=1,
                       apb_reads=1, apb_writes=4, pad_changes=1, pad_rise_events=1,
                       rise_mask='0x00000001', pad_after='0x0000002b',
                       out_after='0x0000002b', dir_after='0xffffffff')
    fields.update(patch)
    return parse_case_line(case_line(record='F5:ffffffff:00000001:00000001:'
                                                  '0000002b', **fields), flows=ARITY)


def test_the_causal_pin_interrupt_case_is_accepted():
    assert correspondence(record('F5:ffffffff:00000001:00000001:0000002b'), _causal_case(),
                          layout=LAYOUT, windows=WINDOWS, irq=IRQ, pins=PINS) is None


@pytest.mark.parametrize('patch,match', [
    (dict(pad_rise_events=0), 'no pin transition'),
    (dict(first_rise_tick=540, first_irq_tick=536), 'preceded the pin transition'),
    (dict(irq_cause_pins='0x00000002', inten_at_irq='0x00000001'), 'no enabled pin'),
    (dict(isr_flag=0), 'handler did not complete'),
    (dict(apb_read_offset='0x00000000'), 'declared status register'),
    (dict(apb_last_write_data='0x0000002a'), 'last trigger value'),
    (dict(irq_takes=0), 'IRQ edge and CPU take'),
])
def test_a_causal_claim_the_pins_do_not_support_is_a_mismatch(patch, match):
    mismatch = correspondence(record('F5:ffffffff:00000001:00000001:0000002b'),
                              _causal_case(**patch), layout=LAYOUT, windows=WINDOWS,
                              irq=IRQ, pins=PINS)
    assert match in mismatch


def test_the_case_document_keeps_every_pin_field():
    case = parse_case_line(case_line(**base_case('F4', mmio_addr='0x4000000c')),
                           flows=ARITY)
    document = case_document(record('F4:4000000c:0000002a'), case)
    for key in CASE_PIN_KEYS:
        assert key in document['observation']
    assert document['observation']['pad_changes'] == 0
    assert document['record'] == 'F4:4000000c:0000002a'


# --- final status ---------------------------------------------------------

def test_a_run_is_only_passed_when_every_case_and_the_summary_agree():
    passed = dict(returncode=0)
    parsed = dict(cases=[dict(index=0, status='observations_passed')],
                  summary=dict(status='observations_passed'))
    assert final_status(passed, parsed, [1]) == 'observations_passed'
    assert final_status(dict(returncode=1), parsed, [1]) == 'failed'
    assert final_status(passed, None, [1]) == 'failed'
    assert final_status(passed, parsed, [1, 2]) == 'failed'
    failed = dict(cases=[dict(index=0, status='failed')],
                  summary=dict(status='observations_passed'))
    assert final_status(passed, failed, [1]) == 'failed'
