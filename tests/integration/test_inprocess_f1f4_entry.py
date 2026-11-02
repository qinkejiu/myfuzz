"""Pure-Python coverage of the F1-F4 in-process entry: no RTL, no Verilator.

Every fact these tests touch is either the argument/record contract, the fixed
RAM image the C++ host loads, the compact line format it prints, or the
correspondence check applied to a saved observation.  No model is built.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.isa.constraints import IsaContract
from scripts.run_inprocess_f1f4 import (
    SLOT_OFFSET, MAIN_OFFSET, case_document, correspondence, declared_windows,
    final_status, main, parse_case_line, parse_record, parse_run_log,
    parse_summary_line, render_bindings, validate_record, build_firmware, build_layout)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((ROOT / 'configs/scenarios/inprocess-irq-pulp-timer-profile.json').read_text())
WINDOWS = declared_windows(CONFIG)
BOOT = 0x10080
LAYOUT = build_layout(WINDOWS, BOOT)
ISA = IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)
ROLES = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
         'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
EVIDENCE_RECORDS = ('F1:2ab00693', 'F2:00014000', 'F3:00014004:0badf00d',
                    'F4:40001008:0fffffff', 'F2:40001008')


def record(text):
    return parse_record(text, windows=WINDOWS)


def clock_schedule(frequency=80_000_000):
    return dict(phase_policy='all_low_then_half_period_toggle',
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=frequency)])


def cpu_document(**overrides):
    exports = [dict(physical_port='rvfi_' + role, direction='output',
                    runtime_name='rvfi_' + role)
               for role in ('valid', 'trap', 'insn', 'pc_rdata')]
    exports.append(dict(endpoint_id='processor.interrupts', role='external', direction='input',
                        width=1, runtime_name='irq_i'))
    document = dict(kind='obi_cpu', module_name='local_cpu', clock_schedule=clock_schedule(),
                    physical_exports=exports,
                    backend_ports=[dict(channel=channel, role=role, name=channel + '_' + role)
                                   for channel in ('i', 'd') for role in ROLES],
                    plan=dict(timing=dict(reset_assert_ticks=8, reset_release_ticks=8)))
    document.update(overrides)
    return document


def ip_document(**overrides):
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')}
    document = dict(kind='apb3_register_observe', module_name='local_ip',
                    clock_schedule=clock_schedule(), base_protocol_trace=dict(protocol='apb3',
                                                                             signals=signals),
                    backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                                   for role in ROLES],
                    physical_exports=[dict(physical_port='irq_o', direction='output', width=4,
                                           bit_lo=0, bit_hi=3, runtime_name='irq_o')],
                    plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))
    document.update(overrides)
    return document


@pytest.fixture(scope='module')
def cpu_profile():
    return load_component_profile(ROOT / CONFIG['cpu_profile'])


# --- argument contract ---------------------------------------------------

def test_every_declared_flow_parses_to_one_canonical_record():
    parsed = [record(text) for text in EVIDENCE_RECORDS]
    assert [row['text'] for row in parsed] == [
        'F1:2ab00693', 'F2:00014000', 'F3:00014004:0badf00d',
        'F4:40001008:0fffffff', 'F2:40001008']
    assert [row['flow'] for row in parsed] == ['F1', 'F2', 'F3', 'F4', 'F2']
    assert parsed[2]['fields'] == (0x0001_4004, 0x0BAD_F00D)
    assert parsed[0]['message'] == 'CASE F1 2ab00693'
    assert parsed[2]['message'] == 'CASE F3 00014004 0badf00d'


@pytest.mark.parametrize('text,match', [
    ('F5:00014000', 'unsupported flow tag'),
    ('F1:2ab00693:1', 'needs 1 word'),
    ('F3:00014004', 'needs 2 word'),
    ('F2:00014001', 'aligned'),
    ('F2:00090000', 'aligned APB or data-window RAM'),
    ('F3:40001000:1', 'data-window RAM'),
    ('F3:00013000:1', 'data-window RAM'),
    ('F4:00014000:1', 'APB window'),
    ('F1:2ab0069', '32-bit instruction'),
    ('F1:zzzzzzzz', 'hexadecimal'),
    ('', 'record text is required'),
])
def test_operator_records_outside_the_supported_shape_are_refused(text, match):
    with pytest.raises(ValueError, match=match):
        record(text)


def test_declared_windows_refuse_an_unusable_declaration():
    broken = dict(CONFIG, image_start=65536, image_end=65536 + 0x4004)
    with pytest.raises(ValueError, match='unusable'):
        declared_windows(broken)
    with pytest.raises(ValueError, match='target_window'):
        declared_windows({key: value for key, value in CONFIG.items() if key != 'target_window'})


def test_boot_address_must_be_an_aligned_ram_word():
    with pytest.raises(ValueError, match='aligned RAM word'):
        build_layout(WINDOWS, BOOT + 2)


# --- F1 word admission ---------------------------------------------------

@pytest.mark.parametrize('word', [0x0000_8063, 0x0000_006F, 0x0004_8067,
                                  0x01F1_2023, 0x3051_9073, 0x02B5_06B3])
def test_only_executable_alu_words_pass_f1_admission(word):
    if word == 0x02B5_06B3:
        validate_record(dict(flow='F1', fields=(word,)), isa=ISA, windows=WINDOWS)
        return
    with pytest.raises(ValueError):
        validate_record(dict(flow='F1', fields=(word,)), isa=ISA, windows=WINDOWS)


def test_f1_word_may_not_clobber_the_mailbox_register():
    with pytest.raises(ValueError, match='mailbox register x8'):
        validate_record(dict(flow='F1', fields=(0x0010_0413,)), isa=ISA, windows=WINDOWS)


def test_declared_cpu_isa_admits_the_evidence_f1_words(cpu_profile):
    from myfuzz.isa.constraints import f1_isa_from_profile
    isa = f1_isa_from_profile(cpu_profile)
    for word in (0x2AB0_0693, 0x1234_56B7, 0x02B5_06B3):
        validate_record(dict(flow='F1', fields=(word,)), isa=isa, windows=WINDOWS)
    with pytest.raises(ValueError, match='escape|outside|instruction'):
        validate_record(dict(flow='F1', fields=(0x0000_0013 & ~3,)), isa=isa, windows=WINDOWS)


# --- the fixed RAM image -------------------------------------------------

def test_firmware_is_one_image_with_a_real_indirect_slot_fetch():
    firmware = build_firmware(LAYOUT)
    words = [int.from_bytes(data[index:index + 4], 'little')
             for data in (firmware['images'][LAYOUT['main']],)
             for index in range(0, len(data), 4)]
    jalr = [index for index, word in enumerate(words) if word & 0x7F == 0x67]
    assert len(jalr) == 1, 'exactly one indirect jump into the slot'
    assert words[jalr[0]] >> 7 & 31 == 0, 'the slot jump does not link back to a register'
    assert SLOT_OFFSET == LAYOUT['slot'] - WINDOWS['ram_base']
    assert MAIN_OFFSET == LAYOUT['main'] - WINDOWS['ram_base']
    # The return target is the store of zero that both completes the case and
    # arms the next one, and it sits right after the indirect jump.
    assert firmware['slot_return'] == LAYOUT['main'] + 4 * (jalr[0] + 1)
    assert words[jalr[0] + 1] & 0x7F == 0x23, 'the slot returns into a store'
    assert (words[jalr[0] + 1] >> 20) & 31 == 0 and (words[jalr[0] + 1] >> 15) & 31 == 8
    assert any(word & 0x7F == 0x63 for word in words), 'the CPU polls the mailbox'
    assert words[-1] & 0x7F == 0x6F, 'the loop never runs off the program'


def test_firmware_segments_stay_inside_the_declared_ram():
    firmware = build_firmware(LAYOUT)
    spans = sorted((address, address + len(data))
                   for address, data in firmware['images'].items())
    assert all(WINDOWS['ram_base'] <= start and end <= WINDOWS['ram_base'] + WINDOWS['ram_size']
               for start, end in spans)
    assert all(left[1] <= right[0] for left, right in zip(spans, spans[1:]))
    assert firmware['images'][LAYOUT['slot']][4:8] == _jal_bytes(LAYOUT['slot'] + 4,
                                                                firmware['slot_return'])


def _jal_bytes(pc, target):
    from myfuzz.integration.rv32_fixed_firmware import _jal
    return _jal(pc, target).to_bytes(4, 'little')


def test_firmware_refuses_a_layout_whose_regions_collide():
    colliding = dict(LAYOUT, mailbox=LAYOUT['data_base'])
    with pytest.raises(ValueError, match='overlaps|mailbox'):
        build_firmware(colliding)


def test_firmware_text_is_address_hex_pairs_for_the_host_loader():
    firmware = build_firmware(LAYOUT)
    from scripts.run_inprocess_f1f4 import firmware_text
    for line in firmware_text(firmware).splitlines():
        address, data = line.split()
        assert len(data) and len(data) % 2 == 0
        assert address == format(int(address, 16), 'x')
        assert bytes.fromhex(data) == firmware['images'][int(address, 16)]


# --- binding rendering --------------------------------------------------

def test_bindings_bind_the_generated_ports_and_the_optional_ip_irq(cpu_profile):
    header = render_bindings(CONFIG, cpu_document(), ip_document(), LAYOUT, cpu_profile)
    assert '#define CPU_MODEL Vlocal_cpu' in header
    assert '#define CPU_RVFI_INSN rvfi_insn' in header
    assert '#define CPU_I_REQ_ADDR i_req_addr' in header
    assert '#define IP_TRACE_PREADY trace_pready' in header
    assert '#define HAVE_IP_IRQ 1' in header and '#define IP_IRQ_BIT 0' in header
    assert f'#define SLOT_ADDRESS {LAYOUT["slot"]}u' in header
    assert '#define CPU_RESET_ASSERT 8u' in header and '#define IP_RESET_RELEASE 3u' in header


@pytest.mark.parametrize('cpu,ip,match', [
    (dict(kind='axi4_cpu'), dict(), 'OBI CPU'),
    (dict(), dict(kind='wishbone_register_observe'), 'OBI CPU'),
    (dict(), dict(base_protocol_trace=dict(protocol='wishbone', signals={})), 'APB3 protocol trace'),
    (dict(driver_timing=dict()), dict(), 'timed models'),
    (dict(clock_schedule=clock_schedule(40_000_000)), dict(), 'clock frequencies differ'),
    (dict(physical_exports=[row for row in cpu_document()['physical_exports']
                            if row.get('physical_port') != 'rvfi_trap']), dict(),
     'rvfi_\\* retirement probe'),
    (dict(), dict(base_protocol_trace=dict(protocol='apb3', signals={})), 'lacks'),
])
def test_bindings_refuse_an_artifact_that_cannot_support_the_path(cpu_profile, cpu, ip, match):
    with pytest.raises(ValueError, match=match):
        render_bindings(CONFIG, cpu_document(**cpu), ip_document(**ip), LAYOUT, cpu_profile)


def test_bindings_omit_the_ip_irq_when_the_declaration_names_no_source(cpu_profile):
    declaration = {key: value for key, value in CONFIG.items() if key != 'source_port'}
    header = render_bindings(declaration, cpu_document(), ip_document(), LAYOUT, cpu_profile)
    assert '#define HAVE_IP_IRQ 0' in header


# --- compact output format ----------------------------------------------

def case_line(**overrides):
    fields = dict(flow='F1', record='F1:2ab00693', ticks=42, seconds=0.000123,
                  i_fetches=11, d_reads=2, d_writes=1, apb_reads=0, apb_writes=0,
                  fetch='0x00012000', retire_pc='0x00012000', retire_insn='0x2ab00693',
                  successor_pc='0x00012004')
    fields.update(overrides)
    pairs = ' '.join(f'{key} {value}' for key, value in fields.items())
    return f'case 0 observations_passed {pairs}'


def test_a_case_line_keeps_its_typed_observation():
    parsed = parse_case_line(case_line())
    assert parsed['index'] == 0 and parsed['status'] == 'observations_passed'
    assert parsed['fetch'] == LAYOUT['slot'] and parsed['retire_insn'] == 0x2AB0_0693
    assert parsed['ticks'] == 42 and parsed['seconds'] == pytest.approx(0.000123)
    assert parsed['flow'] == 'F1'


@pytest.mark.parametrize('line,match', [
    ('event 3 cpu_data', 'not a F1-F4 case line'),
    ('case zero observations_passed flow F1', 'case index'),
    ('case 0 unknown_status flow F1', 'unsupported case status'),
    ('case 0 observations_passed flow F9', 'supported flow tag'),
    ('case 0 observations_passed flow F1 apb_reads', 'key/value pairs'),
    ('case 0 observations_passed flow F1 flow F2', 'duplicate observation field'),
])
def test_malformed_case_lines_are_rejected(line, match):
    with pytest.raises(ValueError, match=match):
        parse_case_line(line)


def test_a_run_log_without_a_summary_is_rejected():
    with pytest.raises(ValueError, match='no summary line'):
        parse_run_log(case_line() + '\nretire 3 0x00012000 0x2ab00693\n')


def test_a_run_log_parses_cases_summary_and_installation_order():
    text = ('NEED_RECORD 0 tick 0\nCASE_INSTALLED 0\n' + case_line() +
            '\nsummary observations_passed cases 1 ticks 60 irq_delivery unknown '
            'runtime_seconds 0.25\n')
    parsed = parse_run_log(text)
    assert parsed['installed'] == [0]
    assert parsed['summary']['status'] == 'observations_passed'
    assert parsed['summary']['cases'] == 1 and parsed['summary']['runtime_seconds'] == 0.25
    assert parsed['summary']['irq_delivery'] == 'unknown'


def test_summary_line_requires_a_status_and_pairs():
    with pytest.raises(ValueError, match='not a F1-F4 summary line'):
        parse_summary_line('summary')
    assert parse_summary_line('summary failed cases 0')['status'] == 'failed'


# --- correspondence and status -----------------------------------------

def test_each_flow_reports_the_expected_correspondence():
    cases = {
        'F1': dict(flow='F1', record='F1:2ab00693', fetch=LAYOUT['slot'],
                   retire_pc=LAYOUT['slot'], retire_insn=0x2AB0_0693,
                   successor_pc=LAYOUT['slot'] + 4),
        'F2': dict(flow='F2', record='F2:00014000', read_addr=0x0001_4000,
                   read_value=0xDEAD_BEEF, echo_value=0xDEAD_BEEF, read_from='ram',
                   apb_reads=0),
        'F2ip': dict(flow='F2', record='F2:40001008', read_addr=WINDOWS['ip_base'] + 8,
                     read_value=0x0FFF_FFFF, echo_value=0x0FFF_FFFF, read_from='apb',
                     apb_reads=1, apb_rdata=0x0FFF_FFFF),
        'F3': dict(flow='F3', record='F3:00014004:0badf00d', write_addr=0x0001_4004,
                   write_value=0x0BAD_F00D, write_be=15, ram_after=0x0BAD_F00D),
        'F4': dict(flow='F4', record='F4:40001008:0fffffff', mmio_addr=WINDOWS['ip_base'] + 8,
                   mmio_value=0x0FFF_FFFF, apb_offset=8, apb_pwdata=0x0FFF_FFFF,
                   apb_pready=1, apb_writes=1),
    }
    inputs = dict(F1='F1:2ab00693', F2='F2:00014000', F2ip='F2:40001008',
                  F3='F3:00014004:0badf00d', F4='F4:40001008:0fffffff')
    for key, case in cases.items():
        assert correspondence(record(inputs[key]), case, layout=LAYOUT,
                              windows=WINDOWS) is None, key


@pytest.mark.parametrize('text,override,reason', [
    ('F1:2ab00693', dict(retire_insn=0x0050_0093), 'retired word'),
    ('F1:2ab00693', dict(fetch=LAYOUT['slot'] + 4), 'trampoline slot'),
    ('F1:2ab00693', dict(successor_pc=LAYOUT['slot']), 'no observed successor'),
    ('F2:00014000', dict(read_addr=0x0001_4004), 'read address'),
    ('F2:00014000', dict(echo_value=0x0000_0001), 'commit'),
    ('F2:00014000', dict(read_from='apb', apb_reads=1, apb_rdata=0), 'APB read data'),
    ('F3:00014004:0badf00d', dict(write_value=1), 'write differs'),
    ('F3:00014004:0badf00d', dict(ram_after=0), 'did not commit'),
    ('F4:40001008:0fffffff', dict(apb_offset=12), 'APB transfer differs'),
    ('F4:40001008:0fffffff', dict(apb_pwdata=1), 'APB transfer differs'),
])
def test_a_mismatched_observation_is_named(text, override, reason):
    matched = {
        'F1:2ab00693': dict(flow='F1', fetch=LAYOUT['slot'], retire_pc=LAYOUT['slot'],
                            retire_insn=0x2AB0_0693, successor_pc=LAYOUT['slot'] + 4),
        'F2:00014000': dict(flow='F2', read_addr=0x0001_4000, read_value=0xDEAD_BEEF,
                            echo_value=0xDEAD_BEEF, read_from='ram', apb_reads=0),
        'F3:00014004:0badf00d': dict(flow='F3', write_addr=0x0001_4004, write_value=0x0BAD_F00D,
                                     write_be=15, ram_after=0x0BAD_F00D),
        'F4:40001008:0fffffff': dict(flow='F4', mmio_addr=WINDOWS['ip_base'] + 8,
                                     mmio_value=0x0FFF_FFFF, apb_offset=8,
                                     apb_pwdata=0x0FFF_FFFF, apb_pready=1, apb_writes=1),
    }[text]
    case = dict(matched, record=text, **override)
    reason_text = correspondence(record(text), case, layout=LAYOUT, windows=WINDOWS)
    assert reason_text is not None and reason in reason_text


def test_unobserved_facts_stay_unknown_in_the_case_document():
    document = case_document(record('F2:00014000'), dict(index=0, flow='F2', status='failed',
                                                         record='F2:00014000'))
    assert document['observation']['read_from'] == 'unknown'
    assert document['observation']['echo_value'] == 'unknown'
    assert document['seconds'] == 'unknown'


def test_status_requires_a_passing_host_summary_and_every_case():
    parsed = dict(cases=[dict(status='observations_passed')],
                  summary=dict(status='observations_passed'))
    passed = dict(returncode=0)
    assert final_status(passed, parsed, [record('F1:2ab00693')]) == 'observations_passed'
    assert final_status(dict(returncode=1), parsed, [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, None, [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, parsed, [record('F1:2ab00693'), record('F3:00014004:00000001')]) \
        == 'failed'
    assert final_status(passed, dict(parsed, summary=dict(status='failed')),
                        [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, dict(parsed, cases=[dict(status='failed')]),
                        [record('F1:2ab00693')]) == 'failed'


# --- entry failures before any model exists -----------------------------

@pytest.mark.parametrize('argv,match', [
    (['--records', 'F9:00014000'], 'unsupported flow tag'),
    (['--records', 'F3:40001000:1'], 'data-window RAM'),
    (['--records', ''], 'record text is required'),
    (['--records', 'F1:2ab00693', '--max-ticks', '0'], 'max-ticks must be positive'),
    (['--records', 'F1:2ab00693', '--config', 'configs/scenarios/absent-config.json'],
     'cannot read the declaration'),
    (['--records', 'F1:2ab00693', '--ip-profile', 'configs/peripherals/absent/profile.json'],
     'source_profile is not a readable component profile'),
])
def test_the_entry_refuses_bad_arguments_before_creating_the_output(tmp_path, argv, match, capsys):
    output = tmp_path / 'out'
    command = ['--cache', str(tmp_path / 'cache'), '--output', str(output), *argv]
    with pytest.raises(SystemExit) as exit_code:
        main(command)
    assert exit_code.value.code == 2
    assert match in capsys.readouterr().err
    assert not output.exists(), 'a rejected invocation must not leave a run directory'


def test_the_entry_refuses_a_declaration_without_a_usable_window(tmp_path, capsys):
    declaration = tmp_path / 'broken.json'
    declaration.write_text(json.dumps(dict(CONFIG, image_end=CONFIG['image_start'] + 0x4004)))
    output = tmp_path / 'out'
    with pytest.raises(SystemExit) as exit_code:
        main(['--cache', str(tmp_path / 'cache'), '--output', str(output),
              '--config', str(declaration), '--records', 'F1:2ab00693'])
    assert exit_code.value.code == 2
    assert 'unusable' in capsys.readouterr().err
    assert not output.exists()


def test_the_entry_refuses_an_existing_output_directory(tmp_path):
    output = tmp_path / 'taken'
    output.mkdir()
    with pytest.raises(SystemExit) as exit_code:
        main(['--cache', str(tmp_path / 'cache'), '--output', str(output),
              '--records', 'F1:2ab00693'])
    assert exit_code.value.code == 2
    assert list(output.iterdir()) == []


def test_the_entry_requires_its_mandatory_options(tmp_path):
    for missing in (['--cache', str(tmp_path / 'cache')],
                    ['--output', str(tmp_path / 'out')]):
        with pytest.raises(SystemExit) as exit_code:
            main(['--records', 'F1:2ab00693', *missing])
        assert exit_code.value.code == 2
