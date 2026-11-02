"""Pure-Python coverage of the AXI4-Lite in-process entry: no RTL, no Verilator.

Every fact these tests touch is either the argument/record contract, the named
refusal of a declaration the selected components cannot serve, the generated
binding header, the compact line format the C++ host prints, or the
correspondence check applied to a saved observation.  No model is built and no
evidence directory is required: the case dictionaries below carry the values the
host printed in `runs/stage2-breadth-axi4lite-20261101/f1f4-preloaded/run.log`.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from scripts.run_inprocess_axi4lite import (
    CASE_COUNTER_KEYS, CASE_OBSERVATION_KEYS, DEFAULT_CONFIG, FLOW_ARITY,
    SUMMARY_COUNTER_KEYS, TRACE_ROLES, axi_declaration, build_firmware, build_layout,
    case_document, correspondence, declared_windows, final_status, fixed_inputs, main,
    parse_case_line, parse_record, parse_run_log, parse_summary_line,
    render_bindings, source_request_from_profile)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((ROOT / DEFAULT_CONFIG).read_text())
WINDOWS = declared_windows(CONFIG)
BOOT = 0x10080
LAYOUT = build_layout(WINDOWS, BOOT)
WRITE_MASK = CONFIG['write_mask']
REGISTER = dict(name='SETUP', offset=0, width=32, access='rw', side_effect='write_resets_uart_state')
DECLARATION = dict(register=REGISTER, write_mask=WRITE_MASK, read_mask=CONFIG['read_mask'],
                   address_width=4, max_wait_cycles=16)
IP_WINDOW = WINDOWS['ip_base']
ROLES = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
         'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
# The five records of the passing preloaded run, at the values it reported.
EVIDENCE = ('F1:2ab00693', 'F2:00014000', 'F3:00014004:0badf00d',
            'F4:40001000:00005a5a', 'F2:40001000')


def record(text):
    return parse_record(text, windows=WINDOWS, write_mask=WRITE_MASK)


def clock_schedule(frequency=50_000_000):
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
    signals = {role: 'trace_' + role for role in TRACE_ROLES}
    document = dict(kind='axi4lite_register_observe', module_name='local_target',
                    clock_schedule=clock_schedule(),
                    base_protocol_trace=dict(protocol='axi4-lite', signals=signals),
                    backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                                   for role in ROLES],
                    fixed_physical_inputs=[
                        dict(endpoint_id='uart.pins', role='cts_n', width=1,
                             runtime_name='rt_lh_p_21_0_0', value=0),
                        dict(endpoint_id='uart.pins', role='rx', width=1,
                             runtime_name='rt_lh_p_22_0_0', value=1)],
                    plan=dict(timing=dict(reset_assert_ticks=8, reset_release_ticks=8)))
    document.update(overrides)
    return document


@pytest.fixture(scope='module')
def cpu_profile():
    return load_component_profile(ROOT / CONFIG['cpu_profile'])


@pytest.fixture(scope='module')
def target_profile():
    return load_component_profile(ROOT / CONFIG['source_profile'])


@pytest.fixture(scope='module')
def profile_document():
    return json.loads((ROOT / CONFIG['source_profile']).read_text())


# --- argument and record contract ----------------------------------------

def test_every_declared_flow_parses_to_one_canonical_record():
    parsed = [record(text) for text in EVIDENCE]
    assert [row['text'] for row in parsed] == list(EVIDENCE)
    assert [row['flow'] for row in parsed] == ['F1', 'F2', 'F3', 'F4', 'F2']
    assert parsed[3]['fields'] == (IP_WINDOW, 0x5a5a)
    assert parsed[3]['message'] == 'CASE F4 40001000 00005a5a'


def test_record_words_are_normalized_to_eight_lowercase_digits():
    assert record('F3:14004:BADF00D')['text'] == 'F3:00014004:0badf00d'
    assert record('F1:2AB00693')['text'] == 'F1:2ab00693'


@pytest.mark.parametrize('text', ['F2:00014000:00000001', 'F4:40001000',
                                  'F3:00014000', 'F2', ''])
def test_wrong_operand_count_is_refused(text):
    with pytest.raises(ValueError):
        record(text)


@pytest.mark.parametrize('flow', ['F5', 'F6', 'F0', 'f1'])
def test_flow_outside_the_wired_set_is_refused_by_name(flow):
    with pytest.raises(ValueError, match='unsupported flow tag'):
        record(flow + ':00000000')


@pytest.mark.parametrize('text', ['F2:0001400g', 'F2:000140000', 'F2:zzzzzzzz',
                                  'F2:'])
def test_non_hex_or_overlong_words_are_refused(text):
    with pytest.raises(ValueError, match='hexadecimal'):
        record(text)


@pytest.mark.parametrize('text', ['F2:00014001', 'F2:00012000', 'F2:40001010',
                                  'F4:00014000:00000000', 'F4:40001002:00000000'])
def test_addresses_outside_the_declared_windows_are_refused(text):
    with pytest.raises(ValueError):
        record(text)


def test_f4_value_with_a_bit_the_declared_mask_drops_is_refused():
    with pytest.raises(ValueError, match='write mask'):
        record('F4:40001000:80005a5a')
    assert record('F4:40001000:7fffffff')['fields'][1] == 0x7fffffff


def test_f1_word_must_be_thirty_two_bit():
    with pytest.raises(ValueError, match='32-bit instruction'):
        record('F1:00000001')


@pytest.mark.parametrize('window,ram', [({'base': 1073745920, 'size': 18}, (65536, 262144)),
                                        ({'base': 1073745922, 'size': 16}, (65536, 262144)),
                                        ({'base': 1073745920, 'size': 16}, (65536, 65540)),
                                        ('missing', (65536, 262144))])
def test_declared_windows_refuse_an_unusable_window(window, ram):
    broken = json.loads(json.dumps(CONFIG))
    broken['target_window'], broken['image_start'], broken['image_end'] = window, ram[0], ram[1]
    if window == 'missing':
        broken.pop('target_window')
    with pytest.raises(ValueError):
        declared_windows(broken)


def test_declared_windows_are_the_declared_image_not_a_guess():
    assert WINDOWS == dict(ram_base=65536, ram_size=196608, ip_base=1073745920,
                           ip_size=16, data_base=81920)
    assert LAYOUT['slot'] == 65536 + 0x2000 and LAYOUT['mailbox'] == 65536 + 0x3000


# --- fixed target pins ---------------------------------------------------

def test_fixed_inputs_read_the_declared_pins(profile_document):
    pins = fixed_inputs(CONFIG, _view(profile_document))
    assert pins == {('uart.pins', 'cts_n'): 0, ('uart.pins', 'rx'): 1}


@pytest.mark.parametrize('rows', [
    [{'endpoint_id': 'uart.pins', 'role': 'rx', 'value': 1}],
    [{'endpoint_id': 'uart.pins', 'role': 'rx', 'value': 1},
     {'endpoint_id': 'uart.pins', 'role': 'cts_n', 'value': 0},
     {'endpoint_id': 'uart.pins', 'role': 'tx', 'value': 0}],
    [{'endpoint_id': 'uart.pins', 'role': 'rx', 'value': '1'},
     {'endpoint_id': 'uart.pins', 'role': 'cts_n', 'value': 0}],
    [{'endpoint_id': 'uart.pins', 'role': 'rx', 'value': 1},
     {'endpoint_id': 'uart.bus', 'role': 'cts_n', 'value': 0}],
    [],
])
def test_fixed_inputs_refuse_an_incomplete_or_invented_pin_set(rows, profile_document):
    broken = dict(CONFIG, source_fixed_inputs=rows)
    with pytest.raises(ValueError):
        fixed_inputs(broken, _view(profile_document))


def _view(document):
    from scripts.run_inprocess_axi4lite import _Profile
    return _Profile(document)


# --- the generated request ----------------------------------------------

def test_request_declares_the_admitted_template_and_the_pin_constants(profile_document):
    request = source_request_from_profile(CONFIG, profile_document)
    assert request['schema_version'] == 'local_harness.v2'
    assert request['instance_id'] == CONFIG['active_id']
    assert request['reset_assert_ticks'] == 8 and request['max_wait_cycles'] == 16
    assert request['tuning']['endpoint_policies'] == [
        dict(endpoint_id='uart.bus', template_id='target.axi4-lite', template_version='1',
             variant_id='single-outstanding-error-codes', max_outstanding=1)]
    assert request['tuning']['fixed_inputs'] == [
        dict(endpoint_id='uart.pins', role='cts_n', value=0),
        dict(endpoint_id='uart.pins', role='rx', value=1)]


def test_request_refuses_a_profile_without_one_axi4lite_slave(profile_document):
    document = json.loads(json.dumps(profile_document))
    for endpoint in document['endpoints']:
        if endpoint.get('protocol') == ['axi4-lite', '1']:
            endpoint['protocol'] = ['apb', '3']
    with pytest.raises(ValueError, match='exactly one AXI4-Lite MMIO slave endpoint'):
        source_request_from_profile(CONFIG, document)


def test_request_refuses_a_profile_whose_endpoint_lacks_a_declared_role(profile_document):
    document = json.loads(json.dumps(profile_document))
    for endpoint in document['endpoints']:
        if endpoint.get('protocol') == ['axi4-lite', '1']:
            endpoint['fields'] = [row for row in endpoint['fields']
                                  if row.get('role') != 'rresp']
    with pytest.raises(ValueError, match='lacks rresp'):
        source_request_from_profile(CONFIG, document)


# --- the declared register ----------------------------------------------

def test_declaration_reads_the_declared_register_and_masks(target_profile):
    declaration = axi_declaration(CONFIG, target_profile)
    assert declaration['register'] == REGISTER
    assert declaration['write_mask'] == declaration['read_mask'] == 0x7fffffff
    assert declaration['address_width'] == 4


@pytest.mark.parametrize('change', [
    {'target_window': {'base': 1073745920, 'size': 8}},
    {'target_window': {'base': 1073745932, 'size': 16}},
    {'register_offset': 4},
    {'register_offset': 16},
    {'register': 'FIFO_STATUS'},
    {'write_mask': '0x7fffffff'},
    {'read_mask': 1 << 32},
])
def test_declaration_refuses_a_window_register_or_mask_it_cannot_serve(change, target_profile):
    broken = dict(CONFIG, **change)
    windows = declared_windows(broken)
    assert windows['ip_size'] == broken['target_window']['size']
    with pytest.raises(ValueError):
        axi_declaration(broken, target_profile)


def test_declaration_refuses_a_write_mask_on_a_read_only_register(target_profile):
    broken = dict(CONFIG, register='FIFO_STATUS', register_offset=4)
    with pytest.raises(ValueError, match='read-only'):
        axi_declaration(broken, target_profile)


# --- the generated binding header ---------------------------------------

def header(cpu=None, ip=None, config=None, profile=None, declaration=None):
    return render_bindings(config or CONFIG, cpu or cpu_document(), ip or ip_document(),
                           LAYOUT, profile, declaration or DECLARATION)


def test_bindings_expose_every_axi4lite_role_and_the_pin_constants(cpu_profile):
    text = header(profile=cpu_profile)
    for role in TRACE_ROLES:
        assert '#define IP_TRACE_' + role.upper() + ' trace_' + role in text
    assert '#define IP_FIXED_INPUT_COUNT 2' in text
    assert 'X(rt_lh_p_21_0_0, 0u)' in text and 'X(rt_lh_p_22_0_0, 1u)' in text
    assert '#define IP_TRACE_AWADDR trace_awaddr' in text
    assert '#define WRITE_MASK 0x7fffffffu' in text
    assert '#define REGISTER_OFFSET 0u' in text
    assert '#define CPU_I_REQ_VALID i_req_valid' in text


@pytest.mark.parametrize('ip', [
    ip_document(kind='apb3_register_observe'),
    ip_document(base_protocol_trace=dict(protocol='apb3', signals={})),
    ip_document(base_protocol_trace=dict(
        protocol='axi4-lite',
        signals={role: 'trace_' + role for role in TRACE_ROLES if role != 'bresp'})),
    ip_document(fixed_physical_inputs=None),
    ip_document(fixed_physical_inputs=[
        dict(endpoint_id='uart.pins', role='cts_n', width=1,
             runtime_name='rt_lh_p_21_0_0', value=1),
        dict(endpoint_id='uart.pins', role='rx', width=1,
             runtime_name='rt_lh_p_22_0_0', value=1)]),
    ip_document(fixed_physical_inputs=[
        dict(endpoint_id='uart.pins', role='cts_n', width=1,
             runtime_name='rt_lh_p_21_0_0', value=0)]),
])
def test_bindings_refuse_a_target_that_cannot_serve_the_loop(ip, cpu_profile):
    with pytest.raises(ValueError):
        header(ip=ip, profile=cpu_profile)


def test_bindings_refuse_a_cpu_without_the_obi_rvfi_probe(cpu_profile):
    document = cpu_document(kind='native_memory_cpu')
    with pytest.raises(ValueError, match='OBI CPU and an AXI4-Lite register target'):
        header(cpu=document, profile=cpu_profile)


@pytest.mark.parametrize('frequency', [40_000_000, 80_000_000])
def test_bindings_refuse_a_clock_mismatch_unless_it_is_assumed(frequency, cpu_profile):
    document = ip_document(clock_schedule=clock_schedule(frequency))
    with pytest.raises(ValueError, match='clock rates differ'):
        header(ip=document, profile=cpu_profile)
    asserted = dict(CONFIG, assume_single_clock=True)
    assert 'IP_TRACE_AWVALID' in header(ip=document, config=asserted, profile=cpu_profile)


# --- the compact run log -------------------------------------------------

def test_case_line_parses_values_and_hex_fields():
    fields = parse_case_line(
        'case 3 observations_passed flow F4 record F4:40001000:00005a5a ticks 45 '
        'seconds 3.7766e-05 axi_reads 0 axi_writes 1 axil_awaddr 0x00000000 '
        'axil_wdata 0x00005a5a axil_wstrb 15 axil_bresp 0 ram_store 0')
    assert fields['index'] == 3 and fields['status'] == 'observations_passed'
    assert fields['flow'] == 'F4' and fields['axil_wdata'] == 0x5a5a
    assert fields['axil_awaddr'] == 0 and fields['axi_writes'] == 1
    assert fields['seconds'] == pytest.approx(3.7766e-05)


@pytest.mark.parametrize('line', [
    'case 0 failed flow F7 record F7:00000000',
    'case zero observations_passed flow F1 record F1:2ab00693',
    'case 0 unsupported flow F1 record F1:2ab00693',
    'case 0 observations_passed flow F1 record F1:2ab00693 odd',
    'not a case line at all',
])
def test_case_line_refuses_a_malformed_or_unsupported_line(line):
    with pytest.raises(ValueError):
        parse_case_line(line)


def test_summary_line_is_parsed_and_a_duplicate_is_refused():
    line = ('summary observations_passed cases 5 ticks 195 axi_aw 1 axi_w 1 axi_b 1 '
            'bresp_okay 1 bresp_non_okay 0 error_response unknown runtime_seconds 0.0018')
    summary = parse_summary_line(line)
    assert summary['status'] == 'observations_passed' and summary['axi_aw'] == 1
    assert summary['error_response'] == 'unknown'
    log = 'case 0 observations_passed flow F1 record F1:2ab00693\n' + line + '\n' + line + '\n'
    with pytest.raises(ValueError, match='duplicate summary'):
        parse_run_log(log)


def test_run_log_without_a_summary_line_is_refused():
    with pytest.raises(ValueError, match='no summary line'):
        parse_run_log('case 0 observations_passed flow F1 record F1:2ab00693\n')
    with pytest.raises(ValueError, match='run log text required'):
        parse_run_log(None)


def test_run_log_reads_incremental_handover_markers():
    log = ('NEED_RECORD 0 tick 0\nCASE_INSTALLED 0\n'
           'summary observations_passed cases 1 ticks 47\n')
    parsed = parse_run_log(log)
    assert parsed['installed'] == [0] and len(parsed['cases']) == 0


def test_the_native_summary_carries_every_field_the_entry_checks():
    source = (ROOT / 'scripts/inprocess_obi_axi4lite_spike.cpp').read_text()
    for key in SUMMARY_COUNTER_KEYS:
        assert ' ' + key + ' ' in source, key


# --- case documents and correspondence ----------------------------------

def _fmt(value):
    return hex(value) if isinstance(value, int) and value > 99 else str(value)


def case_line(**fields):
    tokens = ['case', str(fields.pop('index', 0)), fields.pop('status', 'observations_passed'),
              'record', fields.pop('record', EVIDENCE[0])]
    tokens += ['flow', fields.pop('flow', 'F1')]
    for key, value in fields.items():
        tokens += [key, _fmt(value)]
    return parse_case_line(' '.join(tokens))


def f1_case(**overrides):
    values = dict(flow='F1', record='F1:2ab00693', fetch=LAYOUT['slot'],
                  retire_pc=LAYOUT['slot'], retire_insn=0x2ab00693,
                  successor_pc=LAYOUT['slot'] + 4, i_fetches=24, d_reads=1, d_writes=1,
                  axi_reads=0, axi_writes=0, axi_aw=0, axi_w=0, axi_b=0, axi_ar=0, axi_r=0)
    values.update(overrides)
    return parse_case_line(' '.join(['case', '0', 'observations_passed', 'record', values['record'],
                                     'flow', values['flow']]
                                    + [str(item) for key, value in values.items()
                                       if key not in ('flow', 'record')
                                       for item in (key, _fmt(value))]))


def axi_read_case(**overrides):
    values = dict(flow='F2', record='F2:40001000', read_addr=IP_WINDOW, read_value=0x5a5a,
                  echo_value=0x5a5a, read_from='axi4lite', axil_araddr=0, axil_arprot=0,
                  axil_rdata=0x5a5a, axil_rresp=0, i_fetches=15, d_reads=2, d_writes=2,
                  axi_reads=1, axi_writes=0, axi_aw=0, axi_w=0, axi_b=0, axi_ar=1, axi_r=1)
    values.update(overrides)
    return parse_case_line(' '.join(['case', '1', 'observations_passed', 'record', values['record'],
                                     'flow', values['flow']]
                                    + [str(item) for key, value in values.items()
                                       if key not in ('flow', 'record')
                                       for item in (key, _fmt(value))]))


def test_case_document_reports_unknown_for_a_field_the_host_did_not_print():
    document = case_document(record(EVIDENCE[0]), f1_case())
    assert document['observation']['fetch'] == LAYOUT['slot']
    assert document['observation']['retire_insn'] == 0x2ab00693
    assert set(document['observation']) == set(CASE_OBSERVATION_KEYS['F1']) | set(CASE_COUNTER_KEYS)
    blank = case_line(flow='F3', record='F3:00014004:0badf00d')
    assert case_document(record('F3:00014004:0badf00d'), blank)['observation']['ram_after'] == 'unknown'


def test_correspondence_matches_the_evidence_records():
    assert correspondence(record('F1:2ab00693'), f1_case(), layout=LAYOUT, windows=WINDOWS,
                          declaration=DECLARATION) is None
    assert correspondence(record('F2:40001000'), axi_read_case(), layout=LAYOUT,
                          windows=WINDOWS, declaration=DECLARATION) is None


@pytest.mark.parametrize('case,text,reason', [
    (f1_case(fetch=LAYOUT['slot'] + 4), 'F1:2ab00693', 'fetch address'),
    (f1_case(retire_insn=0x2ab00613), 'F1:2ab00693', 'retired word'),
    (f1_case(successor_pc=0), 'F1:2ab00693', 'successor'),
    (axi_read_case(axil_araddr=4), 'F2:40001000', 'read address'),
    (axi_read_case(axil_rdata=0x1111), 'F2:40001000', 'read data'),
    (axi_read_case(axil_rresp=2), 'F2:40001000', 'response'),
    (axi_read_case(axi_ar=0), 'F2:40001000', 'AR and R handshake'),
    (axi_read_case(read_from='ram'), 'F2:40001000', 'plain RAM read'),
    (axi_read_case(read_value=0xffffffff, echo_value=0xffffffff, axil_rdata=0xffffffff),
     'F2:40001000', 'read mask'),
    (f1_case(record='F1:2ab00693', flow='F1'), 'F1:2ab00613', 'differs from the input'),
])
def test_correspondence_reports_the_first_mismatch(case, text, reason):
    mismatch = correspondence(record(text), case, layout=LAYOUT, windows=WINDOWS,
                              declaration=DECLARATION)
    assert mismatch is not None and reason in mismatch


def f4_case(**overrides):
    values = dict(flow='F4', record='F4:40001000:00005a5a', mmio_addr=IP_WINDOW,
                  mmio_value=0x5a5a, axil_awaddr=0, axil_awprot=0, axil_wdata=0x5a5a,
                  axil_wstrb=15, axil_bresp=0, ram_store=0, axi_reads=0, axi_writes=1,
                  axi_aw=1, axi_w=1, axi_b=1, axi_ar=0, axi_r=0, i_fetches=19,
                  d_reads=3, d_writes=1)
    values.update(overrides)
    return parse_case_line(' '.join(['case', '3', 'observations_passed', 'record', values['record'],
                                     'flow', values['flow']]
                                    + [str(item) for key, value in values.items()
                                       if key not in ('flow', 'record')
                                       for item in (key, _fmt(value))]))


@pytest.mark.parametrize('overrides,reason', [
    ({'axil_awaddr': 4}, 'write differs'),
    ({'axil_wdata': 0x1111}, 'write differs'),
    ({'axil_wstrb': 3}, 'write differs'),
    ({'axil_bresp': 2}, 'write differs'),
    ({'axi_w': 0}, 'AW, W and B'),
    ({'axi_b': 2}, 'AW, W and B'),
    ({'ram_store': 1}, 'landed in RAM'),
    ({'mmio_value': 0x1111}, 'MMIO write differs'),
])
def test_f4_correspondence_refuses_a_different_transaction(overrides, reason):
    mismatch = correspondence(record('F4:40001000:00005a5a'), f4_case(**overrides),
                              layout=LAYOUT, windows=WINDOWS, declaration=DECLARATION)
    assert mismatch is not None and reason in mismatch


def test_f4_correspondence_matches():
    assert correspondence(record('F4:40001000:00005a5a'), f4_case(), layout=LAYOUT,
                          windows=WINDOWS, declaration=DECLARATION) is None


def test_f3_correspondence_needs_the_ram_commit():
    case = parse_case_line('case 2 observations_passed record F3:00014004:0badf00d flow F3 '
                           'write_addr 0x00014004 write_value 0x0badf00d write_be 15 '
                           'ram_before 0x11111111 ram_after 0x0badf00d')
    assert correspondence(record('F3:00014004:0badf00d'), case, layout=LAYOUT,
                          windows=WINDOWS, declaration=DECLARATION) is None
    stale = parse_case_line('case 2 observations_passed record F3:00014004:0badf00d flow F3 '
                            'write_addr 0x00014004 write_value 0x0badf00d write_be 15 '
                            'ram_before 0x11111111 ram_after 0x11111111')
    assert 'did not commit' in correspondence(record('F3:00014004:0badf00d'), stale,
                                              layout=LAYOUT, windows=WINDOWS,
                                              declaration=DECLARATION)


# --- overall status ------------------------------------------------------

def results(**overrides):
    base = dict(returncode=0)
    base.update(overrides)
    return base


def test_final_status_requires_every_case_and_the_summary():
    parsed = parse_run_log('case 0 observations_passed record F1:2ab00693 flow F1\n'
                           'summary observations_passed cases 1 ticks 47\n')
    assert final_status(results(), parsed, [record('F1:2ab00693')]) == 'observations_passed'
    assert final_status(results(returncode=1), parsed, [record('F1:2ab00693')]) == 'failed'
    assert final_status(results(), None, [record('F1:2ab00693')]) == 'failed'
    assert final_status(results(), parsed, []) == 'failed'


def test_final_status_fails_when_the_summary_does_not_pass():
    parsed = parse_run_log('case 0 observations_passed record F1:2ab00693 flow F1\n'
                           'summary failed cases 1 ticks 47\n')
    assert final_status(results(), parsed, [record('F1:2ab00693')]) == 'failed'


# --- the entry refuses before it builds anything -------------------------

def test_main_refuses_an_unsupported_flow_before_building(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(['--cache', str(tmp_path / 'cache'), '--output', str(tmp_path / 'out'),
              '--records', 'F5:00000000'])
    assert error.value.code == 2
    assert not (tmp_path / 'out').exists()


def test_main_refuses_an_existing_output_directory(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(SystemExit) as error:
        main(['--cache', str(tmp_path / 'cache'), '--output', str(out),
              '--records', 'F1:2ab00693'])
    assert error.value.code == 2


@pytest.mark.parametrize('argv', [
    ['--output', 'out', '--records', 'F1:2ab00693'],
    ['--cache', 'cache', '--records', 'F1:2ab00693'],
    ['--cache', 'cache', '--output', 'out'],
    ['--cache', 'cache', '--output', 'out', '--records', 'F1:2ab00693', '--max-ticks', '0'],
    ['--cache', 'cache', '--output', 'out', '--records', 'F4:40001000:80000000'],
    ['--config', 'missing.json', '--cache', 'cache', '--output', 'out',
     '--records', 'F1:2ab00693'],
])
def test_main_refuses_missing_or_invalid_arguments(argv, tmp_path):
    with pytest.raises(SystemExit) as error:
        main(argv)
    assert error.value.code == 2


def test_the_declared_flow_arity_is_the_wired_one():
    assert FLOW_ARITY == {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}


def test_the_ram_image_is_the_f1_f4_one_and_fits_the_declared_ram():
    firmware = build_firmware(LAYOUT)
    assert firmware['layout']['slot'] == LAYOUT['slot']
    assert LAYOUT['main'] <= firmware['slot_return'] < LAYOUT['data_base']
    assert firmware['slot_return'] % 4 == 0
    assert sorted(firmware['images']) == sorted([LAYOUT['boot'], LAYOUT['main'],
                                                 LAYOUT['slot'], LAYOUT['park'],
                                                 LAYOUT['data_base']])
