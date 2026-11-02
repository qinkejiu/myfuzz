"""Pure-Python coverage of the IP-only mode and the unified ``--mode`` entry.

No RTL, no Verilator, no model: every fact here is the transaction-record
contract, the generated-header text, the child-process assertion classification,
the log parser, the per-case correspondence check, or the component inventory the
summary prints.  The real IP-only batch (and its saved log lines) lives under
``runs/p0-ip-only``; this file never claims a run.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.inprocess_ip_only import (
    ASSERTION_RE, SCHEMA_VERSION, case_issue, check_case, classify_child_process,
    component_inventory, declared_transactions, ip_fixed_rows, ip_port_fields,
    model_archive_inventory, parse_ip_run_log, parse_transaction, render_header,
    scan_assertion_lines, sequence_loops, transaction_specs,
)
from scripts.run_inprocess_f1f6 import (
    MODES, SECONDARY_MODE_OK_STATUSES, dispatch_secondary_mode, main,
)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/p0-ip-only-pulp-timer.json'
CONFIG = json.loads(SCENARIO.read_text())
WINDOW = dict(CONFIG['target_window'])
PROFILE = json.loads((ROOT / CONFIG['source_profile']).read_text())

#: The exact assertion text Verilator 5.051 printed for a standalone probe model
#: (``assert (1'b0) else $error(...)``), captured through a child process.
VERILATOR_ASSERTION = (
    '[0] %Error: t.sv:3: Assertion failed in TOP.t: ip assertion fired\n'
    '%Error: t.sv:3: Verilog $stop\n'
    'Aborting...\n')

#: One real case line from ``runs/p0-ip-only/declared/run.log``.
REAL_CASE_LINE = (
    'case 2 observations_passed op read offset 0x00000000 addr 0x40000000 '
    'be 0x0000000f wdata 0x00000000 rdata 0x00000055 response_error 0 '
    'response_seen 1 ticks 4 total_tick 17 target_transfers 1 target_ready 1 '
    'irq_edges 0 irq_high_ticks 0 irq_final 0x00000000 loop 0 protocol apb3 '
    'apb_psel 1 apb_penable 1 apb_pready 1 apb_pwrite 0 apb_paddr 0x00000000 '
    'apb_pwdata 0x00000000 apb_prdata 0x00000055 apb_pslverr 0')


# --- transaction records --------------------------------------------------
def test_the_declared_scenario_parses_into_canonical_records():
    specs = declared_transactions(CONFIG, WINDOW)
    assert len(specs) == 13
    assert [spec['text'] for spec in specs[:4]] == [
        'CASE W 00000004 00000000', 'CASE W 00000000 00000055',
        'CASE R 00000000', 'CASE W 00000004 00000028']
    assert specs[2]['expect_rdata'] == 0x55
    assert specs[8]['op'] == 'wait' and specs[8]['ticks'] == 12
    assert specs[8]['expect_irq_edges_min'] == 1
    assert specs[11]['offset'] == 0x0c and specs[11]['expect_rdata'] == 0
    assert specs[12]['offset'] == 0x1c


@pytest.mark.parametrize('text,text_out', [
    ('R:00000004', 'CASE R 00000004'),
    ('r:0x4', 'CASE R 00000004'),
    ('W:00000004:00000028', 'CASE W 00000004 00000028'),
    ('CASE R 00000004', 'CASE R 00000004'),
    # An absolute address inside the declared window resolves to its offset.
    ('R:40000004', 'CASE R 00000004'),
    ('WAIT:0000000c', 'CASE WAIT 0000000c'),
])
def test_one_transaction_round_trips_through_its_canonical_text(text, text_out):
    parsed = parse_transaction(text, window=WINDOW)
    assert parsed['text'] == text_out
    assert parse_transaction(parsed['text'], window=WINDOW)['text'] == text_out


@pytest.mark.parametrize('text,match', [
    ('X:00000000', 'unsupported-transaction-tag'),
    ('F2:00000000', 'unsupported-transaction-tag'),
    ('R:00002000', 'offset-outside-window'),
    ('R:00000002', 'offset-not-word-aligned'),
    ('W:00000004', 'write-takes-an-offset-and-a-value'),
    ('R:00000004:00000000', 'read-takes-one-offset'),
    ('WAIT:0', 'invalid-wait-ticks'),
    ('WAIT:0000000c:1', 'wait-takes-one-tick-count'),
    ('', 'empty'),
])
def test_a_malformed_transaction_is_refused_by_name(text, match):
    with pytest.raises(ValueError, match=match):
        parse_transaction(text, window=WINDOW)


@pytest.mark.parametrize('row,match', [
    ({'op': 'read', 'offset': '0x04', 'value': '0x1'}, 'read-takes-no-value'),
    ({'op': 'write', 'offset': '0x04'}, 'write-needs-a-value'),
    ({'op': 'write', 'offset': '0x04', 'value': '0x1', 'ticks': 2},
     'bus-transaction-takes-no-ticks'),
    ({'op': 'wait', 'offset': '0x04', 'ticks': 2}, 'wait-takes-no-address'),
    ({'op': 'read', 'offset': '0x04', 'expect_rdata': '0x1', 'ticks': 2},
     'bus-transaction-takes-no-ticks'),
    ({'op': 'read', 'offset': '0x04', 'unknown': 1}, 'transaction-key'),
    ({'op': 'read', 'offset': '0x2000'}, 'offset-outside-window'),
])
def test_a_malformed_declared_transaction_is_refused_by_name(row, match):
    with pytest.raises(ValueError, match=match):
        declared_transactions(dict(CONFIG, transactions=[row]), WINDOW)


def test_handed_over_records_override_the_scenario_and_keep_its_expectations():
    specs, source = transaction_specs(
        CONFIG, WINDOW, 'R:00000004,W:00000004:00000028,R:00000004')
    assert source == 'records'
    assert [spec['text'] for spec in specs] == [
        'CASE R 00000004', 'CASE W 00000004 00000028', 'CASE R 00000004']
    # The count differs from the scenario's 13, so no positional expectation is
    # borrowed: the run still checks the device's response, not a declared value.
    assert 'expect_rdata' not in specs[2]


def test_a_handed_over_record_count_equal_to_the_declaration_keeps_expectations():
    texts = ','.join(spec['text'] for spec in declared_transactions(CONFIG, WINDOW))
    specs, source = transaction_specs(CONFIG, WINDOW, texts)
    assert source == 'records'
    assert specs[2]['expect_rdata'] == 0x55


@pytest.mark.parametrize('sequence,match', [
    ({'loops': 0}, 'sequence-loops'),
    ({'loops': 17}, 'sequence-loops'),
    ({'loops': '2'}, 'sequence-loops'),
    ({'loop': 2}, 'sequence-key'),
    ([2], 'sequence-not-an-object'),
])
def test_the_light_sequence_loop_is_declared_and_bounded(sequence, match):
    with pytest.raises(ValueError, match=match):
        sequence_loops(dict(CONFIG, sequence=sequence))


# --- generated header and the target trait --------------------------------
def ip_document(protocol='apb3', module='local_runtime_timer_target'):
    trace_roles = {
        'apb3': ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata',
                 'pslverr'),
        'axi4-lite': ('awaddr', 'awprot', 'awvalid', 'awready', 'wdata', 'wstrb',
                      'wvalid', 'wready', 'bresp', 'bvalid', 'bready', 'araddr',
                      'arprot', 'arvalid', 'arready', 'rdata', 'rresp', 'rvalid',
                      'rready'),
    }[protocol]
    ports = [dict(name='reg_' + role, direction=('input' if role in
                                                 ('req_valid', 'req_write', 'req_addr',
                                                  'req_wdata', 'req_be', 'rsp_ready')
                                                 else 'output'),
                  width=1, role=role, channel='reg')
             for role in ('req_valid', 'req_ready', 'req_write', 'req_addr',
                          'req_wdata', 'req_be', 'rsp_valid', 'rsp_ready',
                          'rsp_rdata', 'rsp_error')]
    ports += [dict(name='trace_' + role, direction='output', width=1, role=role,
                   channel='ip_protocol_trace') for role in trace_roles]
    return dict(module_name=module, instance_id='timer',
                backend_ports=ports,
                base_protocol_trace=dict(protocol=protocol,
                                         signals={role: 'trace_' + role
                                                  for role in trace_roles}),
                physical_exports=[dict(runtime_name='rt_irq', physical_port='irq_o',
                                       direction='output', width=1, bit_lo=0,
                                       endpoint_id='timer.interrupts', role='irq')],
                fixed_physical_inputs=[],
                plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))


def test_the_header_binds_one_target_and_the_shared_trait_interface():
    document = ip_document()
    fields = ip_port_fields(document, 'apb3')
    header, facts = render_header(
        document=document, protocol='apb3', window=WINDOW, fields=fields,
        fixed_rows=[], observed_irq=document['physical_exports'][0], config=CONFIG)
    assert '#include "Vlocal_runtime_timer_target.h"' in header
    assert '#define IP_MODEL_0 Vlocal_runtime_timer_target' in header
    assert 'namespace myfuzz_ip {' in header
    assert 'struct IpTarget<0>' in header
    assert 'static bool apb_sel(const Model &m)' in header
    assert 'static uint64_t irq_value(const Model &m)' in header
    assert facts['trait_interface'] == 'myfuzz_ip::IpTarget<0>'
    assert facts['bridge'] == 'apb3_mmio_bridge'
    # No CPU model, CPU channel or DMA port exists in an IP-only header.
    assert 'CPU_MODEL' not in header
    assert 'DMA_MODEL' not in header
    assert 'CPU_BUS_' not in header


def test_the_ip_only_header_states_only_the_target_archive_model():
    document = ip_document()
    fields = ip_port_fields(document, 'apb3')
    header, facts = render_header(
        document=document, protocol='apb3', window=WINDOW, fields=fields,
        fixed_rows=[], observed_irq=None, config=CONFIG)
    includes = [line for line in header.splitlines() if line.startswith('#include')]
    assert includes == ['#include "Vlocal_runtime_timer_target.h"']
    assert facts['model'] == 'Vlocal_runtime_timer_target'
    assert '#define IP_ONLY_HAS_IRQ 0' in header


@pytest.mark.parametrize('role', ['req_valid', 'rsp_rdata'])
def test_a_target_without_one_beat_role_is_refused_by_name(role):
    document = ip_document()
    document['backend_ports'] = [row for row in document['backend_ports']
                                 if row['role'] != role]
    with pytest.raises(ValueError, match='beat-role:' + role):
        ip_port_fields(document, 'apb3')


def test_a_trace_missing_a_protocol_role_is_refused_by_name():
    document = ip_document()
    del document['base_protocol_trace']['signals']['pready']
    with pytest.raises(ValueError, match='trace-lacks:pready'):
        ip_port_fields(document, 'apb3')


def test_the_four_supported_protocols_are_driven_and_a_fifth_is_refused_by_name():
    # P2 widened this host from APB3 to the four target protocols the combined
    # entry already samples (axi4-lite, wishbone and tl-ul were refused here
    # before); the named refusal now belongs to a protocol outside that set.
    fields = ip_port_fields(ip_document('axi4-lite'), 'axi4-lite')
    assert fields['IP_TRACE_AWVALID'] == 'trace_awvalid'
    with pytest.raises(ValueError, match='unsupported-ip-only:protocol:ahb-lite'):
        ip_port_fields(ip_document('apb3'), 'ahb-lite')


def test_declared_fixed_inputs_must_match_the_generated_pins():
    document = ip_document()
    with pytest.raises(ValueError, match='generated-target-pins-differ'):
        ip_fixed_rows(document, [dict(endpoint_id='timer.ctrl', role='start', value=1)])


# --- assertion capture ----------------------------------------------------
def test_a_real_verilator_assertion_is_classified_with_source_and_line():
    verdict = classify_child_process('', VERILATOR_ASSERTION, 1)
    assert verdict['kind'] == 'dut_assertion'
    assert verdict['source'] == 't.sv'
    assert verdict['line'] == 3
    assert verdict['scope'] == 'TOP.t'
    assert verdict['text'] == 'ip assertion fired'
    assert verdict['returncode'] == 1


def test_a_verilator_error_without_an_assertion_is_not_an_assertion():
    verdict = classify_child_process('', '%Error: bad parameter\nAborting...\n', 1)
    assert verdict['kind'] == 'verilator_error'
    assert 'Assertion failed' not in json.dumps(verdict)


def test_a_clean_exit_has_no_classification():
    assert classify_child_process('case 0 observations_passed', '', 0) is None


def test_an_assertion_is_attributed_to_the_last_transaction_and_tick():
    log = '\n'.join([
        'ip_only model local_runtime_pulp_timer_active protocol apb3',
        'case_begin 4 op write offset 0x00000008 value 0x00000008 ticks 0 loop 0 '
        'record CASE W 00000008 00000008',
        'tick 40 case 4 phase request',
        'tick 41 case 4 phase request',
        VERILATOR_ASSERTION,
    ])
    events = scan_assertion_lines(log, model='local_runtime_pulp_timer_active')
    assert len(events) == 1
    event = events[0]
    assert event['tick'] == 41
    assert event['transaction']['index'] == 4
    assert event['transaction']['record'] == 'CASE W 00000008 00000008'
    assert event['source'] == 't.sv' and event['line'] == 3
    assert event['classification'] == 'dut_assertion'


def test_an_assertion_before_any_transaction_states_no_transaction():
    events = scan_assertion_lines(VERILATOR_ASSERTION, model='m')
    assert len(events) == 1
    assert events[0]['transaction'] is None
    assert events[0]['tick'] is None
    assert 'unavailable' in events[0]['tick_attribution']


def test_the_assertion_pattern_is_the_verilator_line_and_nothing_else():
    assert ASSERTION_RE.search(VERILATOR_ASSERTION) is not None
    assert ASSERTION_RE.search('%Error: Verilog $stop') is None


# --- case parsing and correspondence --------------------------------------
def test_one_real_case_line_parses_into_the_observed_device_answer():
    parsed = parse_ip_run_log(REAL_CASE_LINE + '\n')
    assert len(parsed['cases']) == 1
    case = parsed['cases'][0]
    assert case['index'] == 2 and case['status'] == 'observations_passed'
    assert case['fields']['op'] == 'read'
    assert case['fields']['offset'] == 0
    assert case['fields']['rdata'] == 0x55
    assert case['fields']['target_transfers'] == 1
    assert case['fields']['apb_pready'] == 1
    assert case['fields']['response_error'] == 0


def test_a_read_matches_only_when_the_response_and_the_trace_agree():
    spec = parse_transaction('R:00000000', window=WINDOW)
    spec['expect_rdata'] = 0x55
    case = parse_ip_run_log(REAL_CASE_LINE + '\n')['cases'][0]
    assert check_case(spec, case) is None
    mismatched = json.loads(json.dumps(case))
    mismatched['fields']['rdata'] = 0
    assert 'rdata: expected 0x00000055' in check_case(spec, mismatched)
    no_trace = json.loads(json.dumps(case))
    no_trace['fields']['target_transfers'] = 0
    assert 'target transfers: expected exactly 1' in check_case(spec, no_trace)
    no_response = json.loads(json.dumps(case))
    no_response['fields']['response_seen'] = 0
    assert 'beat response was not observed' in check_case(spec, no_response)


def test_a_declared_error_expectation_is_checked_against_the_device_answer():
    spec = parse_transaction('R:00000000', window=WINDOW)
    spec['expect_error'] = 0
    case = parse_ip_run_log(REAL_CASE_LINE + '\n')['cases'][0]
    case['fields']['response_error'] = 1
    assert 'response_error: expected 0, observed 1' in check_case(spec, case)


def test_a_wait_case_checks_only_its_declared_interrupt_edge_minimum():
    spec = parse_transaction('WAIT:0000000c', window=WINDOW)
    spec['expect_irq_edges_min'] = 1
    case = dict(index=8, status='observations_passed',
                fields=dict(irq_edges=1, irq_high_ticks=1, irq_final=2))
    assert check_case(spec, case) is None
    case['fields']['irq_edges'] = 0
    assert 'expected at least 1' in check_case(spec, case)


def test_a_bus_timeout_is_an_environment_issue_and_not_an_assertion():
    case = dict(index=3, status='environment_timeout',
                fields=dict(reason='response-not-valid', waited=256))
    spec = parse_transaction('W:00000004:00000028', window=WINDOW)
    assert check_case(spec, case) is None
    issue = case_issue(case, spec)
    assert issue['kind'] == 'bus_timeout'
    assert issue['classification'] == 'environment'
    assert issue['reason'] == 'response-not-valid'
    assert 'not a device assertion' in issue['statement']
    assert case_issue(dict(index=0, status='observations_passed', fields={}),
                      spec) is None


# --- component inventory: no CPU in an IP-only link ------------------------
def test_an_ip_only_link_reports_one_target_archive_and_no_cpu_or_dma():
    components = component_inventory(['/cache/obj/Vtimer__ALL.a'])
    assert components == dict(cpu=0, targets=1, dma=0, ram=0, model_archives=1)
    archives = model_archive_inventory(
        [dict(path='/cache/obj/Vtimer__ALL.a', sha256='00' * 32)])
    assert archives['cpu'] == [] and archives['dma'] == []
    assert archives['all'] == ['/cache/obj/Vtimer__ALL.a']
    assert archives['targets'] == ['/cache/obj/Vtimer__ALL.a']


def test_an_ip_only_declaration_may_not_name_a_cpu_or_dma_profile(tmp_path):
    from scripts.inprocess_ip_only import run_ip_only
    for key in ('cpu_profile', 'dma_profile'):
        scenario = tmp_path / ('scenario-' + key + '.json')
        scenario.write_text(json.dumps(dict(CONFIG, **{key: 'configs/cpus/ibex/'
                                                       'component_profile.json'})))
        with pytest.raises(ValueError, match='names-a-cpu-or-dma'):
            run_ip_only(scenario, tmp_path / 'cache', tmp_path / ('out-' + key))
        assert not (tmp_path / ('out-' + key)).exists()


# --- the unified --mode entry --------------------------------------------
def fake_args(**overrides):
    base = dict(mode='ip-only', config=Path('/tmp/scenario.json'),
                cache=Path('/tmp/cache'), output=Path('/tmp/out'),
                records='R:00000004', fuzz=False, max_ticks=20000,
                cases=32, seed=0, online=False, quiet=False,
                replay_prefix=None, fuzz_mode='program')
    base.update(overrides)
    return SimpleNamespace(**base)


def test_the_entry_declares_the_three_modes():
    assert MODES == ('combined', 'cpu-only', 'ip-only')
    assert 'observations_passed' in SECONDARY_MODE_OK_STATUSES


def test_ip_only_mode_dispatches_to_the_ip_only_runner(monkeypatch, tmp_path):
    calls = {}

    def run_ip_only(config, cache, output, **kwargs):
        calls.update(dict(config=config, cache=cache, output=output, kwargs=kwargs))
        return dict(status='observations_passed', cases_executed=3,
                    components_loaded=dict(cpu=0, targets=1, dma=0, ram=0,
                                           model_archives=1),
                    model_archives=dict(all=['/cache/Vtimer__ALL.a']),
                    total_seconds=0.5)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_ip_only',
                        SimpleNamespace(run_ip_only=run_ip_only))
    output = tmp_path / 'out'
    code, payload = dispatch_secondary_mode(fake_args(output=output), _parser())
    assert code == 0
    assert payload['mode'] == 'ip-only'
    assert payload['model_archives'] == ['/cache/Vtimer__ALL.a']
    assert calls['kwargs']['records'] == 'R:00000004'
    assert calls['kwargs']['fuzz'] is None
    assert calls['kwargs']['max_ticks'] == 20000
    # The entry documents the selected mode beside the runner's own summary.
    mode_document = json.loads((output / 'entry_mode.json').read_text())
    assert mode_document['mode'] == 'ip-only'
    assert mode_document['components_loaded'] == dict(cpu=0, targets=1, dma=0,
                                                      ram=0, model_archives=1)
    assert mode_document['model_archives'] == ['/cache/Vtimer__ALL.a']


def test_cpu_only_mode_dispatches_to_agent_cs_api_without_touching_targets(
        monkeypatch, tmp_path):
    calls = {}

    def run_cpu_only(config, cache, output, **kwargs):
        calls.update(dict(config=config, cache=cache, output=output, kwargs=kwargs))
        return dict(status='observations_passed', case_count=2,
                    archives=[dict(path='/cache/Vcpu__ALL.a', sha256='00' * 32,
                                   kind='cpu')],
                    wall_seconds=0.25)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_cpu_only',
                        SimpleNamespace(run_cpu_only=run_cpu_only))
    output = tmp_path / 'out'
    code, payload = dispatch_secondary_mode(
        fake_args(mode='cpu-only', records='0x11,0x22', output=output), _parser())
    assert code == 0
    assert payload['mode'] == 'cpu-only'
    # The CPU-only route consumes one mailbox word per record, so the entry hands
    # the words over as a list and leaves their parsing to that runner.
    assert calls['kwargs'] == dict(records=['0x11', '0x22'], fuzz=None,
                                   max_ticks=20000)
    assert payload['cases'] == 2
    assert payload['model_archives'] == ['/cache/Vcpu__ALL.a']
    # The CPU-only runner owns its own summary document; the entry derives the
    # same component counters from its archive rows and states them separately.
    mode_document = json.loads((output / 'entry_mode.json').read_text())
    assert mode_document['mode'] == 'cpu-only'
    assert mode_document['components_loaded'] == dict(cpu=1, targets=0, dma=0,
                                                      ram=0, model_archives=1)
    assert 'archives[].kind' in mode_document['components_source']


def test_cpu_only_mode_maps_the_entry_fuzz_options_onto_its_fuzz_mapping(
        monkeypatch):
    calls = {}

    def run_cpu_only(config, cache, output, **kwargs):
        calls.update(kwargs)
        return dict(status='observations_passed', case_count=4)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_cpu_only',
                        SimpleNamespace(run_cpu_only=run_cpu_only))
    dispatch_secondary_mode(fake_args(mode='cpu-only', records=None, fuzz=True,
                                      cases=4, seed=7), _parser())
    # --fuzz-mode travels with the mapping: the cpu-only runner owns the loop and
    # needs to know whether each case is a different RV32 program (the default)
    # or one mailbox word per case (the opt-in P0 shape).
    assert calls['fuzz'] == dict(cases=4, seed=7, mode='program')
    assert calls['records'] is None
    calls.clear()
    dispatch_secondary_mode(fake_args(mode='cpu-only', records=None, fuzz=True,
                                      cases=1, seed=3, fuzz_mode='data'), _parser())
    assert calls['fuzz'] == dict(cases=1, seed=3, mode='data')


def test_a_secondary_mode_maps_a_non_passing_status_to_a_nonzero_exit(
        monkeypatch, tmp_path):
    def run_ip_only(config, cache, output, **kwargs):
        return dict(status='dut_assertion', cases_executed=1, model_archives={},
                    total_seconds=0.1)

    monkeypatch.setitem(sys.modules, 'scripts.inprocess_ip_only',
                        SimpleNamespace(run_ip_only=run_ip_only))
    code, payload = dispatch_secondary_mode(
        fake_args(output=tmp_path / 'out'), _parser())
    assert code == 1 and payload['status'] == 'dut_assertion'


def test_a_replay_is_refused_by_name_in_a_secondary_mode():
    with pytest.raises(SystemExit) as exit_code:
        dispatch_secondary_mode(fake_args(replay_prefix=Path('/tmp/prefix.txt')),
                                _parser())
    assert exit_code.value.code == 2


def test_the_entry_refuses_an_unknown_mode_by_name(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_code:
        main(['--mode', 'gpu-only', '--config', str(SCENARIO),
              '--cache', str(tmp_path / 'cache'), '--output', str(tmp_path / 'out')])
    assert exit_code.value.code == 2
    assert 'invalid choice' in capsys.readouterr().err


def test_ip_only_mode_rejects_an_invalid_scenario_before_creating_output(
        tmp_path, capsys):
    scenario = tmp_path / 'bad-scenario.json'
    scenario.write_text(json.dumps(dict(CONFIG, schema_version='nope')))
    output = tmp_path / 'out'
    with pytest.raises(SystemExit) as exit_code:
        main(['--mode', 'ip-only', '--config', str(scenario),
              '--cache', str(tmp_path / 'cache'), '--output', str(output)])
    assert exit_code.value.code == 2
    assert 'unsupported-ip-only:schema:nope' in capsys.readouterr().err
    assert not output.exists()


def _parser():
    import argparse
    parser = argparse.ArgumentParser()
    return parser
