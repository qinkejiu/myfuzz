"""Pure-Python coverage of the P2 IP-only increment: fuzz, protocols, long running.

No RTL, no Verilator, no model is built here.  Every fact is either the record
and policy contract, the generated-header text, the log parser, the per-case
correspondence check, or a case line quoted verbatim from this campaign's own
runs (``runs/p2-ip-only-20261103/``), whose provenance is stated beside it.  The
real four-protocol batches, the fuzz batches and the two-mode cost comparison are
those directories; this file never claims a run.
"""
import json
from pathlib import Path

import pytest

from scripts.inprocess_ip_only import (
    CASE_ISOLATION_DEFAULT, CASE_ISOLATION_MODES, FUZZ_DEFAULT_CASES,
    IpFuzzPolicy, SUPPORTED_PROTOCOLS, build_request, case_isolation_mode,
    check_case, classify_child_process, fuzz_offsets, fuzz_specification,
    ip_port_fields, parse_ip_run_log, scan_assertion_lines,
    session_advance_measurement,
)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/p2-ip-only-pulp-timer-apb3.json'
CONFIG = json.loads(SCENARIO.read_text())
WINDOW = dict(CONFIG['target_window'])
PROFILE = json.loads((ROOT / CONFIG['source_profile']).read_text())
TLUL_SCENARIO = json.loads(
    (ROOT / 'configs/scenarios/p2-ip-only-opentitan-rv-timer-tlul.json').read_text())

#: Real case lines, one per protocol, quoted from this campaign's own runs.  The
#: APB3 line is byte-identical to runs/p0-ip-only/declared/run.log (the
#: regression proof for the long-running shape is the ``loop`` word only).
APB3_CASE = (
    'case 2 observations_passed op read offset 0x00000000 addr 0x40000000 '
    'be 0x0000000f wdata 0x00000000 rdata 0x00000055 response_error 0 '
    'response_seen 1 ticks 4 total_tick 17 target_transfers 1 target_ready 1 '
    'irq_edges 0 irq_high_ticks 0 irq_final 0x00000000 loop 0 protocol apb3 '
    'apb_psel 1 apb_penable 1 apb_pready 1 apb_pwrite 0 apb_paddr 0x00000000 '
    'apb_pwdata 0x00000000 apb_prdata 0x00000055 apb_pslverr 0')
# runs/p2-ip-only-20261103/tlul-long-running/run.log case 2
TLUL_CASE = (
    'case 2 observations_passed op read offset 0x00000104 addr 0x40003104 '
    'be 0x0000000f wdata 0x00000000 rdata 0x00000001 response_error 0 '
    'response_seen 1 ticks 4 total_tick 17 target_transfers 1 target_ready 1 '
    'irq_edges 0 irq_high_ticks 0 irq_final 0x00000000 loop 0 protocol tl-ul '
    'tlul_a_valid 1 tlul_a_ready 1 tlul_a_opcode 4 tlul_a_address 0x00000104 '
    'tlul_a_mask 15 tlul_a_data 0x00000000 tlul_d_valid 1 tlul_d_ready 1 '
    'tlul_d_data 0x00000001 tlul_d_error 0 tlul_a_handshakes 1 '
    'tlul_d_handshakes 1 target_offset 0x00000104')
# runs/p2-ip-only-20261103/wishbone-long-running/run.log case 3
WB_CASE = (
    'case 3 observations_passed op read offset 0x00000004 addr 0x40001004 '
    'be 0x0000000f wdata 0x00000000 rdata 0x403f4000 response_error 0 '
    'response_seen 1 ticks 5 total_tick 24 target_transfers 1 target_ready 1 '
    'irq_edges 0 irq_high_ticks 0 irq_final 0x00000000 loop 0 protocol '
    'wishbone wb_cyc 1 wb_stb 0 wb_ack 1 wb_we 0 wb_adr 0x00000001 wb_offset '
    '0x00000004 wb_dat_w 0x00000000 wb_dat_r 0x403f4000 wb_sel 15 wb_acks 1 '
    'wb_stb_pulses 1 wb_stall 0 target_offset 0x00000004')
# runs/p2-ip-only-20261103/axi4lite-long-running/run.log case 1
AXIL_CASE = (
    'case 1 observations_passed op write offset 0x00000000 addr 0x40000200 '
    'be 0x0000000f wdata 0x0000000a rdata 0x00000000 response_error 0 '
    'response_seen 1 ticks 5 total_tick 14 target_transfers 1 target_ready 1 '
    'irq_edges 0 irq_high_ticks 0 irq_final 0x00000000 loop 0 protocol '
    'axi4-lite axi_aw 1 axi_w 1 axi_b 1 axi_ar 0 axi_r 0 axi_awaddr '
    '0x00000000 axi_wdata 0x0000000a axi_wstrb 15 axi_bresp 0 axi_araddr '
    '0x00000000 axi_rdata 0x00000000 axi_rresp 0 axi_resp_non_okay 0 '
    'target_offset 0x00000000')

#: A real long-running abort: the probe model's own assertion, printed by
#: Verilator 5.051 in the shape the IP-only host uses (see
#: runs/p2-ip-only-20261103/assertion-probe/).
PROBE_ABORT_LOG = (
    'ip_only model probe protocol apb3 base 0x00000000 size 16\n'
    'tick 1 case 0 phase reset\n'
    'tick 5 case 0 phase reset\n'
    'case_begin 0 op write offset 0x00000004 value 0x00000000 ticks 0 loop 0 '
    'record CASE W 00000004 00000000\n'
    'tick 7 case 0 phase request\n'
    'case 0 observations_passed op write offset 0x00000004 addr 0x00000004 '
    'rdata 0x00000000 response_error 0 response_seen 1 ticks 2 total_tick 7 '
    'target_transfers 1 target_ready 1\n'
    'case_begin 1 op write offset 0x00000008 value 0x00000001 ticks 0 loop 0 '
    'record CASE W 00000008 00000001\n'
    'tick 8 case 1 phase request\n'
    'tick 9 case 1 phase request\n'
    '[0] %Error: probe.sv:11: Assertion failed in probe.probe: declared probe '
    'assertion fired at cycle 9\n'
    '%Error: probe.sv:11: Verilog $stop\n'
    'Aborting...\n')


def parse_one(line):
    parsed = parse_ip_run_log(line)
    assert len(parsed['cases']) == 1
    return parsed['cases'][0]


# --- protocols ------------------------------------------------------------
def test_the_four_target_protocols_are_the_supported_set():
    assert SUPPORTED_PROTOCOLS == ('apb3', 'axi4-lite', 'wishbone', 'tl-ul')


def beat_document(protocol, trace_roles, extra_ports=()):
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata',
             'req_be', 'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    ports = [dict(role=role, name='reg_' + role, channel='reg') for role in roles]
    ports += [dict(role=role, name='trace_' + role, channel='ip_protocol_trace')
              for role in trace_roles]
    ports += list(extra_ports)
    return dict(module_name='local_runtime_t_' + protocol.replace('-', '_'),
                backend_ports=ports,
                base_protocol_trace=dict(
                    protocol=protocol,
                    signals={role: 'trace_' + role for role in trace_roles}))


def test_each_protocol_binds_exactly_its_own_trace_roles():
    from scripts.run_inprocess_f1f6 import PROTOCOL_TRACE_ROLES
    for protocol in SUPPORTED_PROTOCOLS:
        roles = PROTOCOL_TRACE_ROLES[protocol]
        fields = ip_port_fields(beat_document(protocol, roles), protocol)
        bound = {key[len('IP_TRACE_'):].lower() for key in fields
                 if key.startswith('IP_TRACE_')}
        assert bound == set(roles), protocol
        # Every beat role is bound too, so the host's drive loop is the same one
        # for all four protocols.
        assert fields['IP_REQ_VALID'] == 'reg_req_valid'
        assert fields['IP_RSP_ERROR'] == 'reg_rsp_error'


def test_a_protocol_outside_the_supported_set_is_refused_by_name():
    with pytest.raises(ValueError, match='unsupported-ip-only:protocol:ahb-lite'):
        ip_port_fields(beat_document('ahb-lite', ['haddr']), 'ahb-lite')


@pytest.mark.parametrize('protocol,role', [
    ('wishbone', 'adr'), ('wishbone', 'dat_r'),
    ('tl-ul', 'd_error'), ('tl-ul', 'a_mask'),
    ('axi4-lite', 'bresp'), ('axi4-lite', 'awready'),
    ('apb3', 'pready'),
])
def test_a_trace_missing_this_protocol_role_is_refused_by_name(protocol, role):
    from scripts.run_inprocess_f1f6 import PROTOCOL_TRACE_ROLES
    roles = [row for row in PROTOCOL_TRACE_ROLES[protocol] if row != role]
    with pytest.raises(ValueError, match='unsupported-ip-only:trace-lacks:' + role):
        ip_port_fields(beat_document(protocol, roles), protocol)


def test_the_wishbone_stall_pin_is_optional_and_reported_when_absent():
    from scripts.run_inprocess_f1f6 import WB_TRACE_ROLES
    fields = ip_port_fields(beat_document('wishbone', WB_TRACE_ROLES), 'wishbone')
    assert 'IP_TRACE_STALL' not in fields
    with_stall = ip_port_fields(
        beat_document('wishbone', WB_TRACE_ROLES + ('stall',)), 'wishbone')
    assert with_stall['IP_TRACE_STALL'] == 'trace_stall'


# --- the request each protocol is built from -----------------------------
#: The two UART pin constants the zipCPU UART targets declare as inputs.  A
#: declaration that does not pin them is refused by the request builder, which is
#: the behaviour this campaign's UART scenarios satisfy.
UART_PINS = [dict(endpoint_id='uart.pins', role='rx', value=1),
             dict(endpoint_id='uart.pins', role='cts_n', value=0)]


def request_for(profile_path, **overrides):
    config = dict(CONFIG, source_profile=profile_path)
    if 'zipcpu_' in profile_path:
        config['source_fixed_inputs'] = list(UART_PINS)
    config.update(overrides)
    profile = json.loads((ROOT / profile_path).read_text())
    from scripts.run_inprocess_f1f6 import profile_protocol
    return build_request(config, profile_protocol(profile), profile)


@pytest.mark.parametrize('profile_path,protocol,template,variant', [
    ('configs/peripherals/pulp_timer_irq/component_profile.json', 'apb3',
     'target.apb3', 'full-word'),
    ('configs/peripherals/opentitan_rv_timer_local/component_profile.json', 'tl-ul',
     'target.tl-ul', 'user-integrity'),
    ('configs/peripherals/zipcpu_uart/component_profile.json', 'wishbone',
     'target.wishbone', 'word-addressed-registered-ack'),
    ('configs/peripherals/zipcpu_axiluart/component_profile.json', 'axi4-lite',
     'target.axi4-lite', 'single-outstanding-error-codes'),
])
def test_each_protocol_builds_its_own_declared_request(
        profile_path, protocol, template, variant):
    request = request_for(profile_path)
    assert request['schema_version'] == 'local_harness.v2'
    assert request['profile_path'] == profile_path
    policy = request['tuning']['endpoint_policies'][0]
    assert policy['template_id'] == template
    assert policy['variant_id'] == variant
    assert policy['max_outstanding'] == 1


def test_an_addressless_wishbone_target_is_refused_by_name():
    with pytest.raises(ValueError, match='unsupported-ip-only:target-request:wishbone:'
                                         'unsupported-target-trace:wishbone:addressless'):
        request_for('configs/peripherals/zipcpu_timer/component_profile.json')


def test_an_ahb_lite_target_is_refused_by_name_before_any_build():
    with pytest.raises(ValueError, match='unsupported-ip-only:protocol:ahb-lite'):
        request_for('configs/peripherals/caliptra_sha256/component_profile.json')


# --- the case check reads the sampled trace offset -----------------------
@pytest.mark.parametrize('line,op,offset', [
    (APB3_CASE, 'read', 0x00), (TLUL_CASE, 'read', 0x104),
    (WB_CASE, 'read', 0x04), (AXIL_CASE, 'write', 0x00),
])
def test_a_real_case_line_of_each_protocol_matches_its_own_request(line, op, offset):
    case = parse_one(line)
    spec = dict(op=op, offset=offset, value=0x0a, ticks=None, expect_rdata=0x55
                if op == 'read' and offset == 0x00 and 'apb3' in line else None,
                expect_error=0)
    spec['expect_rdata'] = None if op == 'write' else spec['expect_rdata']
    if op == 'read' and spec['expect_rdata'] is None:
        del spec['expect_rdata']
    assert check_case(spec, case) is None


def test_the_sampled_trace_offset_is_checked_and_a_mismatch_is_reported():
    case = parse_one(TLUL_CASE)
    assert case['fields']['offset'] == 0x104
    spec = dict(op='read', offset=0x104, value=None, ticks=None, expect_error=0)
    assert check_case(spec, case) is None
    # The request field still says 0x104; the slave's own A-channel address says
    # something else.  That is the mismatch the trace check must report.
    case['fields']['target_offset'] = 0x108
    assert 'target_offset' in check_case(spec, case)


def test_a_response_without_the_trace_completion_is_not_a_passed_transaction():
    case = parse_one(WB_CASE)
    case['fields']['target_ready'] = 0
    spec = dict(op='read', offset=0x04, value=None, ticks=None)
    assert check_case(spec, case) == 'the protocol trace did not show a completed transfer'


# --- session shapes ------------------------------------------------------
def test_long_running_is_the_default_and_prefix_replay_stays_selectable():
    assert CASE_ISOLATION_DEFAULT == 'long-running'
    assert CASE_ISOLATION_MODES == ('long-running', 'prefix-replay')
    assert case_isolation_mode({}) == ('long-running', None)
    assert case_isolation_mode({'case_isolation': 'prefix-replay'})[0] == 'prefix-replay'
    assert case_isolation_mode({}, 'prefix-replay')[0] == 'prefix-replay'


@pytest.mark.parametrize('declared,mode', [
    (None, 'long-running'), (False, 'long-running'), (True, 'prefix-replay'),
    ('long-running', 'long-running'), ('prefix-replay', 'prefix-replay'),
])
def test_the_declaration_spellings_state_the_session_shape(declared, mode):
    config = {} if declared is None else {'case_isolation': declared}
    assert case_isolation_mode(config)[0] == mode


def test_an_online_handover_is_always_one_process_and_says_so():
    mode, note = case_isolation_mode({'case_isolation': True}, online=True)
    assert mode == 'long-running'
    assert 'online hand-over is one process' in note
    with pytest.raises(ValueError, match='prefix-replay-with-online-handover'):
        case_isolation_mode({}, 'prefix-replay', online=True)


def test_a_session_shape_this_host_does_not_offer_is_refused_by_name():
    with pytest.raises(ValueError, match='unsupported-ip-only:case-isolation'):
        case_isolation_mode({'case_isolation': 'per-tick-restart'})


# --- fuzz ----------------------------------------------------------------
def policy(seed=11, cases=24, wait_every=8, scenario=CONFIG, profile=PROFILE):
    offsets, registers = fuzz_offsets(scenario, scenario['target_window'], profile)
    return IpFuzzPolicy(seed=seed, offsets=offsets, registers=registers, cases=cases,
                        wait_every=wait_every, window=scenario['target_window'])


def run_policy(policy, answers):
    """Drive the policy the way the session driver does, answering each case."""
    records = []
    for index in range(policy.cases):
        record = policy.next_record()
        if record is None:
            break
        records.append(record)
        fields = dict(answers(index, record))
        policy.observe(index, dict(index=index, status='observations_passed',
                                   fields=fields))
    return records


def test_the_same_seed_and_the_same_answers_reproduce_the_same_records():
    first = run_policy(policy(), lambda index, record: dict(
        rdata=0x10 + index, response_error=0, target_transfers=1, target_ready=1,
        response_seen=1, offset=None))
    second = run_policy(policy(), lambda index, record: dict(
        rdata=0x10 + index, response_error=0, target_transfers=1, target_ready=1,
        response_seen=1, offset=None))
    assert first == second
    assert len(first) == 24


def test_the_next_value_is_mutated_from_the_device_readback_not_from_the_write():
    policy_state = policy(cases=6, wait_every=1000)
    seen = []

    def answer(index, record):
        # The device stores only the low byte: every readback is masked.
        value = int(record.split()[-1], 16) if record.startswith('CASE W') else 0
        seen.append(record)
        return dict(rdata=value & 0xFF if record.startswith('CASE R') else 0,
                    response_error=0, target_transfers=1, target_ready=1,
                    response_seen=1, offset=None)

    run_policy(policy_state, answer)
    readbacks = [row for row in policy_state.rows
                 if row is not None and row.get('readback')]
    assert readbacks, 'the policy must ask for a readback after a write'
    differs = [row for row in readbacks if not row['readback']['equal']]
    assert differs, 'a masked write must be recorded as differing'
    offset = differs[0]['offset']
    assert offset in policy_state.derived
    # The learned offsets are where later writes are picked from, so a derived
    # offset must be able to be chosen again.
    assert policy_state.derived <= set(policy_state.offsets)


def test_a_fuzz_case_checks_completion_but_not_error_freeness():
    case = parse_one(APB3_CASE)
    case['status'] = 'observations_passed'
    case['fields']['response_error'] = 1
    fuzz_spec = dict(op='write', offset=0x00, value=0x1, ticks=None, fuzz=True)
    declared_spec = dict(op='write', offset=0x00, value=0x1, ticks=None)
    assert check_case(fuzz_spec, case) is None
    assert 'response_error' in check_case(declared_spec, case)


def test_a_fuzz_case_whose_trace_did_not_complete_is_still_a_mismatch():
    case = parse_one(APB3_CASE)
    case['fields']['target_transfers'] = 0
    spec = dict(op='read', offset=0x00, value=None, ticks=None, fuzz=True)
    assert 'target transfers' in check_case(spec, case)


def test_the_fuzz_budget_and_seed_are_declared_and_bounded():
    assert fuzz_specification(None, {}) is None
    assert fuzz_specification(True, {}) == dict(cases=FUZZ_DEFAULT_CASES, seed=0,
                                                wait_every=9)
    assert fuzz_specification(dict(cases=5, seed=3), {'fuzz': {'wait_every': 4}}) == \
        dict(cases=5, seed=3, wait_every=4)
    for bad, match in ((dict(cases=0), 'fuzz-cases'), (dict(seed=-1), 'fuzz-seed'),
                       (dict(cases='many'), 'fuzz-cases'),
                       (dict(wait_every=0), 'fuzz-wait-every'),
                       (dict(strategy='x'), 'fuzz-key')):
        with pytest.raises(ValueError, match='unsupported-ip-only:' + match):
            fuzz_specification(bad, {})


def test_the_fuzz_offsets_are_the_declaration_s_own_words():
    offsets, registers = fuzz_offsets(CONFIG, WINDOW, PROFILE)
    declared = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c}
    assert declared <= set(offsets[:registers + len(declared)])
    assert offsets[:4] == [0x04, 0x00, 0x08, 0x0c]
    assert all(offset % 4 == 0 and offset <= WINDOW['size'] - 4 for offset in offsets)
    assert max(offsets) >= 0x3c


# --- log parsing and the measured advance --------------------------------
def test_the_host_timing_line_is_parsed_as_measured_seconds():
    parsed = parse_ip_run_log(
        'timing wall_seconds 0.001515 dut_seconds 0.000021 dut_fraction 0.013624 '
        'ticks 125 cases 26\n')
    assert parsed['timing'] == dict(wall_seconds=0.001515, dut_seconds=0.000021,
                                    dut_fraction=0.013624, ticks=125, cases=26)


def test_one_process_advance_is_the_single_pass_and_replays_nothing():
    timing = dict(wall_seconds=0.001515, dut_seconds=0.000021, ticks=125)
    advance = session_advance_measurement(
        isolation=False, timing=timing, prefix_runs=[],
        run_seconds=0.00523, planned_cases=26)
    assert advance['child_runs'] == 1
    assert advance['single_pass']['ticks'] == 125
    assert advance['total']['ticks'] == 125
    assert advance['transaction_runs'] == 26
    assert advance['replayed_transactions'] == 0
    assert advance['restart_overhead_seconds'] == pytest.approx(0.005209)


def test_prefix_replay_states_the_repeated_work_and_the_restart_cost():
    runs = [dict(index=index, prefix_transactions=index + 1, seconds=0.004,
                 timing=dict(wall_seconds=0.003, dut_seconds=0.000005,
                             ticks=9 + 4 * index))
            for index in range(26)]
    advance = session_advance_measurement(
        isolation=True, timing=None, prefix_runs=runs, run_seconds=0.128,
        planned_cases=26)
    assert advance['child_runs'] == 26
    assert advance['single_pass']['ticks'] == 9 + 4 * 25
    assert advance['transaction_runs'] == 351
    assert advance['replayed_transactions'] == 351 - 26
    assert advance['total']['ticks'] == sum(row['timing']['ticks'] for row in runs)
    assert advance['restart_overhead_seconds'] == pytest.approx(0.128 - 0.00013)


# --- a real abort in the long-running shape ------------------------------
def test_a_real_abort_ends_the_session_at_the_transaction_that_raised_it():
    verdict = classify_child_process('', PROBE_ABORT_LOG, 1)
    assert verdict['kind'] == 'dut_assertion'
    assert (verdict['source'], verdict['line']) == ('probe.sv', 11)
    assert verdict['scope'] == 'probe.probe'
    events = scan_assertion_lines(PROBE_ABORT_LOG, model='probe')
    assert len(events) == 1
    event = events[0]
    assert event['tick'] == 9
    assert event['transaction']['index'] == 1
    assert event['transaction']['offset'] == '0x00000008'
    assert event['transaction']['record'] == 'CASE W 00000008 00000001'
    assert 'cycle 9' in event['text']


def test_a_process_that_dies_without_an_assertion_is_kept_apart():
    verdict = classify_child_process('', 'ip_only: no record text and not --online\n', 2)
    assert verdict['kind'] == 'host_abort'
    assert scan_assertion_lines('ip_only: no record text\n', model='m') == []


# --- the unified entry ---------------------------------------------------
def test_the_entry_passes_the_fuzz_mapping_and_the_session_shape(monkeypatch):
    import sys
    from types import SimpleNamespace
    from scripts.run_inprocess_f1f6 import dispatch_secondary_mode
    calls = {}

    def run_ip_only(config, cache, output, **kwargs):
        calls.update(kwargs)
        return dict(status='fuzz_completed', cases_executed=2,
                    components_loaded=dict(cpu=0, targets=1, dma=0, ram=0,
                                           model_archives=1),
                    model_archives=dict(all=['/cache/Vt__ALL.a']), total_seconds=0.1)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_ip_only',
                        SimpleNamespace(run_ip_only=run_ip_only))
    import argparse
    parser = argparse.ArgumentParser()
    args = SimpleNamespace(mode='ip-only', config=Path('/tmp/c.json'),
                           cache=Path('/tmp/cache'), output=Path('/tmp/out'),
                           records=None, fuzz=True, max_ticks=None, online=False,
                           quiet=False, cases=7, seed=5,
                           case_isolation='prefix-replay', replay_prefix=None)
    code, payload = dispatch_secondary_mode(args, parser)
    assert code == 0
    assert calls['fuzz'] == dict(cases=7, seed=5)
    assert calls['case_isolation'] == 'prefix-replay'
    assert payload['status'] == 'fuzz_completed'


def test_the_entry_still_dispatches_a_fixed_ip_only_batch(monkeypatch, tmp_path):
    import sys
    from types import SimpleNamespace
    from scripts.run_inprocess_f1f6 import dispatch_secondary_mode
    calls = {}

    def run_ip_only(config, cache, output, **kwargs):
        calls.update(kwargs)
        return dict(status='observations_passed', cases_executed=3,
                    components_loaded=dict(cpu=0, targets=1, dma=0, ram=0,
                                           model_archives=1),
                    model_archives=dict(all=['/cache/Vt__ALL.a']), total_seconds=0.1)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_ip_only',
                        SimpleNamespace(run_ip_only=run_ip_only))
    import argparse
    parser = argparse.ArgumentParser()
    args = SimpleNamespace(mode='ip-only', config=Path('/tmp/c.json'),
                           cache=Path('/tmp/cache'), output=tmp_path / 'out',
                           records='R:00000004', fuzz=False, max_ticks=20000,
                           online=False, quiet=False, cases=32, seed=0,
                           case_isolation=None, replay_prefix=None)
    code, payload = dispatch_secondary_mode(args, parser)
    assert code == 0
    assert calls['fuzz'] is None
    assert calls['records'] == 'R:00000004'
    assert payload['components_loaded'] == dict(cpu=0, targets=1, dma=0, ram=0,
                                                model_archives=1)
