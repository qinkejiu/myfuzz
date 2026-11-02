"""Pure-Python coverage of the Wishbone-CPU in-process entry: no RTL, no Verilator.

The facts these tests touch are the argument/record contract, the fixed RAM image
the C++ host loads (whose bootstrap sits at the CPU's own reset vector), the
compact bus/retire/case lines it prints, the correspondence check applied to a
saved observation, and the named refusals.  No model is built.
"""
import json
from pathlib import Path

import pytest

from scripts.run_inprocess_wbcpu import (
    DATA_OFFSET, MAILBOX_OFFSET, MAIN_OFFSET, SLOT_OFFSET, build_firmware, build_layout,
    case_document, correspondence, cpu_bus_declaration, declared_windows, final_status,
    parse_case_line, parse_record, parse_run_log, parse_summary_line, validate_record)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-wb-cpu-apb-timer-f1f4.json'
CONFIG = json.loads(CONFIG_PATH.read_text())
CPU_PROFILE = ROOT / CONFIG['cpu_profile']
BOOT = 0x0
WINDOWS = declared_windows(CONFIG)
LAYOUT = build_layout(WINDOWS, BOOT)
FLOWS = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
IP_BASE = WINDOWS['ip_base']
EVIDENCE = 'F1:2ab00693,F2:00004000,F3:00004004:0badf00d,F4:40000008:00000123'


def record(text):
    return parse_record(text, windows=WINDOWS)


def case_line(**fields):
    words = ['case', str(fields.pop('index', 0)), fields.pop('status', 'observations_passed')]
    for key, value in fields.items():
        words += [key, value if isinstance(value, str) else str(value)]
    return ' '.join(words)


def base_case(flow, **extra):
    fields = dict(flow=flow, ticks=80, seconds=0.0001, i_fetches=12, d_reads=2, d_writes=1,
                  wb_retires=11, wb_rvfi_order_rising=11, apb_reads=0, apb_writes=0)
    fields.update(extra)
    return fields


# --- declared windows and the fixed RAM image -----------------------------

def test_the_cpu_boots_at_its_own_reset_vector_inside_the_declared_ram():
    assert WINDOWS['ram_base'] == CONFIG['image_start'] == 0
    assert LAYOUT['boot'] == BOOT
    assert LAYOUT['data_base'] == DATA_OFFSET
    assert WINDOWS['ip_base'] == CONFIG['target_window']['base']


@pytest.mark.parametrize('key,value,match', [
    ('image_end', 8, 'too small'),
    ('target_window', dict(base=1073741824, size=2), 'unusable'),
    ('target_window', dict(base=65536, size=4096), 'overlaps'),
    ('image_start', None, 'integer'),
])
def test_unusable_declared_windows_are_refused(key, value, match):
    with pytest.raises(ValueError, match=match):
        declared_windows(dict(CONFIG, **{key: value}))


def test_the_bootstrap_is_one_real_jump_from_address_zero():
    firmware = build_firmware(LAYOUT)
    boot = firmware['images'][LAYOUT['boot']]
    assert len(boot) == 4                      # one `jal x0, main`
    assert int.from_bytes(boot, 'little') & 0x7F == 0x6F
    spans = sorted([(LAYOUT['boot'], 'boot'), (LAYOUT['main'], 'main'),
                    (LAYOUT['slot'], 'slot'), (LAYOUT['mailbox'], 'mailbox'),
                    (LAYOUT['data_base'], 'data')])
    assert len({name for _, name in spans}) == len(spans)
    for name, offset in dict(main=MAIN_OFFSET, slot=SLOT_OFFSET, mailbox=MAILBOX_OFFSET,
                             data_base=DATA_OFFSET).items():
        assert LAYOUT[name] == offset
    assert firmware['slot_return'] > LAYOUT['main']
    assert firmware['images'][LAYOUT['slot']][:4] == b'\x13\x00\x00\x00'


@pytest.mark.parametrize('boot', [2, CONFIG['image_end']])
def test_a_boot_address_outside_the_declared_ram_is_refused(boot):
    with pytest.raises(ValueError, match='aligned RAM word|no room'):
        build_layout(WINDOWS, boot)


# --- the CPU bus declaration ----------------------------------------------

def test_a_generated_cpu_without_a_fetch_marker_is_refused():
    with pytest.raises(ValueError, match='mem_instr'):
        cpu_bus_declaration(dict(kind='wishbone_cpu'))
    with pytest.raises(ValueError, match='Wishbone CPU'):
        cpu_bus_declaration(dict(kind='obi_cpu', instruction_identity_observation='x'))
    assert cpu_bus_declaration(dict(kind='wishbone_cpu',
                                    instruction_identity_observation='rt_lh_p_2_0_0')) == \
        dict(instruction_identity='rt_lh_p_2_0_0')


# --- input records --------------------------------------------------------

def test_the_declared_flow_word_counts():
    assert [len(record(text)['fields']) for text in EVIDENCE.split(',')] == [1, 1, 2, 2]


def test_one_record_keeps_the_canonical_text_the_host_echoes():
    parsed = record('F4:40000008:00000123')
    assert parsed['text'] == 'F4:40000008:00000123'
    assert parsed['message'] == 'CASE F4 40000008 00000123'
    assert parsed['fields'] == (IP_BASE + 8, 0x123)


@pytest.mark.parametrize('text,match', [
    ('F5:00000001', 'unsupported flow tag'),
    ('F6:00000001:2:3:4', 'unsupported flow tag'),
    ('F3:00004004', 'needs 2 word'),
    ('F2:00002000', 'APB or data-window'),
    ('F3:40000000:1', 'data-window RAM'),
    ('F4:00004000:1', 'APB window'),
    ('F1:10000000', 'instruction word'),
    ('F1:2ab0069g', 'hexadecimal'),
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


# --- run log --------------------------------------------------------------

def test_a_case_line_keeps_the_bus_and_rvfi_counters():
    line = case_line(record='F1:2ab00693', **base_case(
        'F1', fetch='0x00002000', retire_pc='0x00002000', retire_insn='0x2ab00693',
        successor_pc='0x00002004', slot_rd_wdata='0x000002ab', slot_order=10))
    parsed = parse_case_line(line, flows=FLOWS)
    assert parsed['wb_retires'] == 11 and parsed['wb_rvfi_order_rising'] == 11
    assert parsed['slot_order'] == 10 and parsed['retire_insn'] == 0x2AB00693


@pytest.mark.parametrize('line,match', [
    ('case 0 failed flow F5 ticks 1', 'supported flow tag'),
    ('case 0 observations_passed flow F1 ticks 1 apb_reads 1 apb_reads 2', 'duplicate'),
    ('case 0 observations_passed flow F1 ticks', 'key/value pairs'),
    ('case 0 maybe flow F1 ticks 1', 'unsupported case status'),
])
def test_unreadable_case_lines_are_refused(line, match):
    with pytest.raises(ValueError, match=match):
        parse_case_line(line, flows=FLOWS)


def test_the_run_log_keeps_bus_and_retirement_lines_out_of_the_cases():
    text = '\n'.join([
        'wb 4c fetch 0x00001044 0x00000000 sel 0',
        'wb 80 write 0x00003000 0x00000000 sel 15',
        'retire 82 0x00001040 0x00042023 order 12 rd 0 rd_wdata 0x00000000',
        'case 0 observations_passed flow F1 ticks 81',
        'summary observations_passed cases 1 ticks 82']) + '\n'
    parsed = parse_run_log(text, flows=FLOWS)
    assert parsed['bus_events'] == 2 and parsed['retire_events'] == 1
    assert parsed['summary']['cases'] == 1


def test_a_run_log_without_a_summary_line_is_refused():
    with pytest.raises(ValueError, match='no summary line'):
        parse_run_log('case 0 observations_passed flow F1 ticks 1\n', flows=FLOWS)


def test_a_duplicate_summary_line_is_refused():
    with pytest.raises(ValueError, match='duplicate summary line'):
        parse_run_log('summary observations_passed cases 0\n'
                      'summary observations_passed cases 0\n', flows=FLOWS)


# --- correspondence -------------------------------------------------------

def test_a_retired_slot_word_with_a_rising_rvfi_order_is_accepted():
    case = parse_case_line(case_line(record='F1:2ab00693', **base_case(
        'F1', fetch='0x00002000', retire_pc='0x00002000', retire_insn='0x2ab00693',
        successor_pc='0x00002004', slot_rd_wdata='0x000002ab', slot_order=10)), flows=FLOWS)
    assert correspondence(record('F1:2ab00693'), case, layout=LAYOUT, windows=WINDOWS) is None


def test_a_retirement_without_a_rising_order_is_a_mismatch():
    case = parse_case_line(case_line(record='F1:2ab00693', **base_case(
        'F1', fetch='0x00002000', retire_pc='0x00002000', retire_insn='0x2ab00693',
        successor_pc='0x00002004', slot_rd_wdata='0x000002ab', slot_order=10,
        wb_rvfi_order_rising=10)), flows=FLOWS)
    assert 'RVFI order' in correspondence(record('F1:2ab00693'), case, layout=LAYOUT,
                                          windows=WINDOWS)


def test_a_retirement_without_an_rvfi_order_is_a_mismatch():
    case = parse_case_line(case_line(record='F1:2ab00693', **base_case(
        'F1', fetch='0x00002000', retire_pc='0x00002000', retire_insn='0x2ab00693',
        successor_pc='0x00002004', slot_rd_wdata='0x000002ab', slot_order=0)), flows=FLOWS)
    assert 'RVFI order' in correspondence(record('F1:2ab00693'), case, layout=LAYOUT,
                                          windows=WINDOWS)


def test_a_ram_read_and_an_apb_read_are_told_apart():
    ram = parse_case_line(case_line(record='F2:00004000', **base_case(
        'F2', read_addr='0x00004000', read_value='0xdeadbeef', echo_value='0xdeadbeef',
        read_from='ram')), flows=FLOWS)
    assert correspondence(record('F2:00004000'), ram, layout=LAYOUT, windows=WINDOWS) is None
    apb = parse_case_line(case_line(record='F2:40000000', **base_case(
        'F2', read_addr='0x40000000', read_value='0x00000049', echo_value='0x00000049',
        read_from='apb', apb_rdata='0x00000049', apb_reads=1)), flows=FLOWS)
    assert correspondence(record('F2:40000000'), apb, layout=LAYOUT, windows=WINDOWS) is None
    moved = dict(apb, apb_rdata=0x48)
    assert 'APB read data' in correspondence(record('F2:40000000'), moved, layout=LAYOUT,
                                             windows=WINDOWS)


def test_a_store_that_the_ram_did_not_commit_is_a_mismatch():
    case = parse_case_line(case_line(record='F3:00004004:0badf00d', **base_case(
        'F3', write_addr='0x00004004', write_value='0x0badf00d', write_be=15,
        ram_before='0x11111111', ram_after='0x11111111')), flows=FLOWS)
    assert 'RAM did not commit' in correspondence(record('F3:00004004:0badf00d'), case,
                                                  layout=LAYOUT, windows=WINDOWS)


def test_an_apb_write_must_show_the_transfer_it_claims():
    case = parse_case_line(case_line(record='F4:40000008:00000123', **base_case(
        'F4', mmio_addr='0x40000008', mmio_value='0x00000123', apb_offset='0x00000008',
        apb_pwdata='0x00000123', apb_pready=1, apb_writes=1)), flows=FLOWS)
    assert correspondence(record('F4:40000008:00000123'), case, layout=LAYOUT,
                          windows=WINDOWS) is None
    wrong = dict(case, apb_pwdata=0x124)
    assert 'APB transfer' in correspondence(record('F4:40000008:00000123'), wrong,
                                            layout=LAYOUT, windows=WINDOWS)


def test_the_case_document_keeps_the_bus_counters():
    case = parse_case_line(case_line(**base_case('F4', mmio_addr='0x40000008')), flows=FLOWS)
    document = case_document(record('F4:40000008:00000123'), case)
    assert document['observation']['wb_retires'] == 11
    assert document['observation']['wb_rvfi_order_rising'] == 11
    assert document['record'] == 'F4:40000008:00000123'


# --- final status ---------------------------------------------------------

def test_a_run_is_only_passed_when_every_case_and_the_summary_agree():
    passed = dict(returncode=0)
    parsed = dict(cases=[dict(index=0, status='observations_passed')],
                  summary=dict(status='observations_passed'))
    assert final_status(passed, parsed, [1]) == 'observations_passed'
    assert final_status(dict(returncode=1), parsed, [1]) == 'failed'
    assert final_status(passed, None, [1]) == 'failed'
    assert final_status(passed, dict(parsed, cases=[dict(index=0, status='failed')]),
                        [1]) == 'failed'
