"""P1: a DMA route is executed on the routed target's own protocol.

Three layers are pinned here, and none of them claims a transfer the run did not
make:

* the *planner* (``myfuzz.composition.dma_transfer``) reports the routed target's
  own wire protocol from that target's profile endpoint and refuses a protocol
  with no beat adapter, so a route is never described as APB3 by default;
* the *entry's host gate* (``dma_route_support``) admits every protocol whose
  generated artifact binds a bridge to the same generic beat port, records the
  protocol and the beat port in its answer, and refuses an unadmitted wire under
  its own name; ``dma_route_protocol_check`` states the same admitted set;
* the *saved runs* under ``runs/p1-dma-route/`` are the evidence: their case lines
  carry the routed target's own handshake counters (TL-UL A/D, Wishbone ack,
  AXI4-Lite channels), the captured word, ``dma_ram_reads 0`` and the CPU's own
  pre/post readback of the same register.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.dma_transfer import (
    DmaTransferError,
    ROUTE_PROTOCOLS,
    dma_route_target,
    dma_transfer_declaration,
    validate_transfer_plan,
)
from myfuzz.local_harness.wishbone_dma_fields import dma_profile_edge_contract

from scripts.run_inprocess_f1f6 import (
    DMA_ROUTE_PROTOCOLS,
    DMA_ROUTE_PROTOCOL_REFUSAL,
    DMA_ROUTE_TRACE_KEYS,
    dma_route_protocol_check,
    dma_route_support,
    flow_arity,
    parse_run_log,
)

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'runs/p1-dma-route'
ZIPDMA_PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json'
ZIPDMA_CAPABILITY = ROOT / ('configs/scenarios/compiled-f1-f6-ibex-gpio-zipdma-'
                            'shared/dma.test_capability.json')
TLUL_CONFIG = ROOT / ('configs/scenarios/inprocess-obi-tlul-timer-zipdma-route-'
                      'read-f1f6.json')
WB_READ_CONFIG = ROOT / ('configs/scenarios/inprocess-obi-wb-uart-zipdma-route-'
                         'read-f1f6.json')
WB_WRITE_CONFIG = ROOT / ('configs/scenarios/inprocess-obi-wb-uart-zipdma-route-'
                          'write-f1f6.json')
AXIL_READ_CONFIG = ROOT / ('configs/scenarios/inprocess-obi-axil-uart-zipdma-route-'
                           'read-f1f6.json')
AXIL_WRITE_CONFIG = ROOT / ('configs/scenarios/inprocess-obi-axil-uart-zipdma-route-'
                            'write-f1f6.json')
TLUL_PROFILE = ROOT / 'configs/peripherals/opentitan_rv_timer_local/component_profile.json'
WB_PROFILE = ROOT / 'configs/peripherals/zipcpu_uart/component_profile.json'
AXIL_PROFILE = ROOT / 'configs/peripherals/zipcpu_axiluart/component_profile.json'
I2C_PROFILE = ROOT / 'configs/peripherals/pulp_i2c/component_profile.json'
READ_APB_CONFIG = ROOT / 'configs/scenarios/inprocess-obi-apb-timer-i2c-dma-read-f1f6.json'
APB_WINDOW = {'base': 0x20001000, 'size': 4096}
TLUL_WINDOW = {'base': 0x20004000, 'size': 4096}
WB_WINDOW = {'base': 0x20005000, 'size': 16}
AXIL_WINDOW = {'base': 0x20006000, 'size': 16}


@pytest.fixture(scope='module')
def zipdma_profile():
    return load_component_profile(ZIPDMA_PROFILE)


@pytest.fixture(scope='module')
def zipdma_artifact(zipdma_profile):
    contract = dma_profile_edge_contract(dict(zipdma_profile.capabilities))
    return {'dma_edge_contract': contract}


def _config(path: Path, **overrides) -> dict:
    document = json.loads(Path(path).read_text())
    document.update(overrides)
    return document


def _plan(path: Path, profile, artifact, **overrides) -> dict:
    return dma_transfer_declaration(_config(path, **overrides), profile, artifact,
                                    base_dir=ROOT)


BRIDGES = {'apb3': 'apb3_mmio_bridge', 'tl-ul': 'beat_to_tlul',
           'wishbone': 'beat_to_wishbone', 'axi4-lite': 'axi4_lite_mmio_bridge'}


def _target_row(index, name, profile_path, window, protocol):
    return dict(index=index, name=name, window=dict(window),
                profile=load_component_profile(profile_path),
                profile_path=str(profile_path.relative_to(ROOT)),
                protocol=protocol, bridge=BRIDGES[protocol])


# --- the planner states the target's own protocol -------------------------

def test_the_route_module_admits_the_four_target_protocols():
    assert set(ROUTE_PROTOCOLS) == {'apb3', 'tl-ul', 'wishbone', 'axi4-lite'}
    assert DMA_ROUTE_PROTOCOLS == ROUTE_PROTOCOLS
    for protocol in ('apb3', 'tl-ul', 'wishbone', 'axi4-lite'):
        assert dma_route_protocol_check(protocol, 'target') is None
    with pytest.raises(ValueError) as error:
        dma_route_protocol_check('ahb-lite', 'ahbsha')
    assert str(error.value) == (
        DMA_ROUTE_PROTOCOL_REFUSAL + 'ahb-lite:ahbsha')


def test_the_plan_reports_the_routed_targets_own_protocol(zipdma_profile,
                                                          zipdma_artifact):
    plan = _plan(TLUL_CONFIG, zipdma_profile, zipdma_artifact)
    facts = plan['route']['target_profile_facts']
    assert facts['protocol'] == 'tl-ul'
    assert facts['register']['name'] == 'COMPARE_LOWER0_0'
    report = validate_transfer_plan(plan, zipdma_profile, zipdma_artifact)
    assert report['route']['protocol'] == 'tl-ul'
    described = dma_route_target(
        plan, [{'name': 'tlultimer', 'index': 0, **TLUL_WINDOW}])
    assert described['target_protocol'] == 'tl-ul'
    # The route's transport is the target's generic beat port, stated by the
    # module itself: the declaration claims no transfer and no protocol single.
    assert set(described['host_support']['protocols']) == set(ROUTE_PROTOCOLS)
    assert 'req_valid' in described['host_support']['beat_interface']
    assert described['host_support']['completion_claimed'] is False


@pytest.mark.parametrize('path,protocol', [
    (TLUL_CONFIG, 'tl-ul'),
    (WB_READ_CONFIG, 'wishbone'),
    (WB_WRITE_CONFIG, 'wishbone'),
    (AXIL_READ_CONFIG, 'axi4-lite'),
    (AXIL_WRITE_CONFIG, 'axi4-lite'),
    (READ_APB_CONFIG, 'apb3'),
])
def test_every_route_scenario_names_its_targets_own_protocol(
        path, protocol, zipdma_profile, zipdma_artifact):
    plan = _plan(path, zipdma_profile, zipdma_artifact)
    assert plan['route']['target_profile_facts']['protocol'] == protocol


# --- the host dispatches the route on that protocol -----------------------

@pytest.mark.parametrize('config,profile_path,window,protocol,index', [
    (READ_APB_CONFIG, I2C_PROFILE, APB_WINDOW, 'apb3', 1),
    (TLUL_CONFIG, TLUL_PROFILE, TLUL_WINDOW, 'tl-ul', 0),
    (WB_READ_CONFIG, WB_PROFILE, WB_WINDOW, 'wishbone', 0),
    (WB_WRITE_CONFIG, WB_PROFILE, WB_WINDOW, 'wishbone', 0),
    (AXIL_READ_CONFIG, AXIL_PROFILE, AXIL_WINDOW, 'axi4-lite', 0),
    (AXIL_WRITE_CONFIG, AXIL_PROFILE, AXIL_WINDOW, 'axi4-lite', 0),
])
def test_the_host_support_states_the_target_protocol(config, profile_path, window,
                                                    protocol, index, zipdma_profile,
                                                    zipdma_artifact):
    plan = _plan(config, zipdma_profile, zipdma_artifact)
    # The routed row comes first, so a route to index 0 is not shadowed by a
    # second row that also happens to carry index 0.
    rows = [_target_row(index, 'target', profile_path, window, protocol)]
    if index != 0:
        rows.append(_target_row(0, 'other', TLUL_PROFILE, TLUL_WINDOW, 'tl-ul'))
    support = dma_route_support(plan, rows, cpu_bus='obi')
    assert support['target_protocol'] == protocol
    assert support['target_index'] == index
    assert support['target_bridge'] == BRIDGES[protocol]
    assert 'req_valid' in support['beat_port']
    # One outstanding master beat, and the routed direction's own counts.
    assert plan['max_outstanding'] == 1
    if plan['route']['direction'] == 'read':
        assert support['reads'] == plan['block_words']
        assert support['pushes'] == plan['block_words']
    else:
        assert support['reads'] == 0


def test_the_host_refuses_a_protocol_with_no_beat_adapter(zipdma_profile,
                                                          zipdma_artifact):
    plan = _plan(TLUL_CONFIG, zipdma_profile, zipdma_artifact)
    rows = [dict(_target_row(0, 'ahbsha', TLUL_PROFILE, TLUL_WINDOW, 'tl-ul'),
                 protocol='ahb-lite', bridge='none')]
    with pytest.raises(ValueError) as error:
        dma_route_support(plan, rows, cpu_bus='obi')
    assert str(error.value) == (
        DMA_ROUTE_PROTOCOL_REFUSAL + 'ahb-lite:ahbsha')


#: The TL-UL timer profile with its MMIO endpoint's protocol changed to an
#: AHB-Lite word: the target declares a wire this host has no beat adapter and no
#: passive trace for, so the planner must refuse the route from that fact.
AHB_PROFILE = EVIDENCE / 'configs/ahb-lite-timer-profile.json'


def test_a_protocol_the_target_profile_does_not_declare_is_refused(
        zipdma_profile, zipdma_artifact):
    config = _config(TLUL_CONFIG)
    config['dma_route']['target_profile'] = str(
        AHB_PROFILE.relative_to(ROOT))
    with pytest.raises(DmaTransferError) as error:
        dma_transfer_declaration(config, zipdma_profile, zipdma_artifact,
                                 base_dir=ROOT)
    assert error.value.reason == 'dma-route-target-protocol-unsupported'
    assert 'ahb-lite' in str(error.value)


def test_the_route_trace_group_is_the_protocol_that_carried_the_beat():
    assert DMA_ROUTE_TRACE_KEYS['wishbone'] == ('dma_route_wb_acks',)
    assert DMA_ROUTE_TRACE_KEYS['tl-ul'] == ('dma_route_tlul_a_handshakes',
                                             'dma_route_tlul_d_handshakes')
    assert DMA_ROUTE_TRACE_KEYS['axi4-lite']['write'] == (
        'dma_route_axi_aw', 'dma_route_axi_w', 'dma_route_axi_b')
    assert DMA_ROUTE_TRACE_KEYS['axi4-lite']['read'] == (
        'dma_route_axi_ar', 'dma_route_axi_r')
    # APB3 keeps the counters its route always printed and is not in the group.
    assert 'apb3' not in DMA_ROUTE_TRACE_KEYS


# --- the saved runs are the evidence --------------------------------------

def _run(name):
    path = EVIDENCE / name / 'run.log'
    if not path.exists():
        pytest.skip('run not produced in this checkout: ' + name)
    text = path.read_text()
    if '\nsummary ' not in text:
        pytest.skip('the saved run did not complete (no summary line): ' + name)
    # The saved batches may carry F5 (the TL-UL timer declares the four F5
    # facts), so the parse table is stated with an F5 link present.  Only the
    # case lines the run really printed are parsed.
    irq = dict(trigger_offsets=[0], source_count=1, status_offset=0)
    return parse_run_log(text, flows=flow_arity(irq, {'block_words': 16}))


def _f6(case_log):
    return next(case for case in case_log['cases'] if case['flow'] == 'F6')


def test_the_saved_tlul_timer_route_reads_the_register_on_the_a_d_channels():
    log = _run('tlul-timer-read')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_route_protocol'] == 'tl-ul'
    assert case['dma_route_protocol_transfers'] == case['dma_route_reads'] == 4
    assert case['dma_route_tlul_a_handshakes'] == 4
    assert case['dma_route_tlul_d_handshakes'] == 4
    assert case['dma_route_target_reads'] == 4
    assert case['dma_ram_reads'] == 0 and case['dma_ram_writes'] == 4
    # The word the F4 case stored through the CPU is the word every routed read
    # returned, the word the RAM block holds and the word the CPU read back.
    assert case['dma_route_read_value'] == 0x0BADC0DE
    assert case['dma_route_read_stable'] == 4
    assert case['dma_route_evidence_before'] == 0x0BADC0DE
    assert case['dma_route_evidence_after'] == 0x0BADC0DE
    for index in range(4):
        assert case['dst%d' % index] == 0x0BADC0DE


def test_the_saved_tlul_route_keeps_a_full_f1_to_f6_batch():
    """All six flows in one process, with the route inside the same batch.

    F4 runs after F5 on purpose: the pinned rv_timer's own F5 clear is a write to
    COMPARE_LOWER0_0 (rv_timer.sv:82-83 clears intr_state on a compare update), so
    a source write before F5 would be overwritten by that clear and the routed
    read would capture the clear word instead of the written one.  The order the
    saved run states is the one the RTL supports.
    """
    log = _run('tlul-timer-read-flows')
    assert log['summary']['status'] == 'observations_passed'
    flows = [case['flow'] for case in log['cases']]
    assert flows == ['F1', 'F2', 'F3', 'F5', 'F4', 'F6']
    assert all(case['status'] == 'observations_passed' for case in log['cases'])
    f5 = next(case for case in log['cases'] if case['flow'] == 'F5')
    assert f5['irq_takes'] == 1 and f5['isr_flag'] == 1
    f4 = [case for case in log['cases'] if case['flow'] == 'F4'][-1]
    assert f4['mmio_addr'] == 0x20004118 and f4['mmio_value'] == 0x0BADC0DE
    f6 = _f6(log)
    assert f6['dma_route_protocol'] == 'tl-ul'
    assert f6['dma_route_tlul_d_handshakes'] == 4
    assert f6['dma_route_read_value'] == 0x0BADC0DE


def test_the_saved_wishbone_uart_write_pushes_on_its_own_cyc_stb_ack():
    log = _run('wb-uart-write')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_route_protocol'] == 'wishbone'
    assert case['dma_route_protocol_transfers'] == 4
    assert case['dma_route_wb_acks'] == 4
    assert case['dma_route_wb_stb_pulses'] == 4
    assert case['dma_route_target_writes'] == case['dma_route_writes'] == 4
    assert case['dma_route_acks'] == 4
    assert case['dma_ram_writes'] == 0
    # The routed destination is the UART SETUP register: the last pushed word is
    # the word the CPU's own readback returns, and it is the F6 record's last
    # input word.
    assert case['dma_route_offset'] == 0
    assert case['fifo_status_after'] == 0x12345678
    assert case['fifo_status_before'] != case['fifo_status_after']


def test_the_saved_wishbone_uart_read_captures_the_setup_register():
    log = _run('wb-uart-read')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_route_protocol'] == 'wishbone'
    assert case['dma_route_wb_acks'] == 4
    assert case['dma_route_target_reads'] == case['dma_route_reads'] == 4
    assert case['dma_ram_reads'] == 0 and case['dma_ram_writes'] == 4
    assert case['dma_route_read_value'] == 0xABCD
    assert case['dma_route_read_stable'] == 4
    assert case['dma_route_evidence_before'] == 0xABCD
    assert case['dma_route_evidence_after'] == 0xABCD
    for index in range(4):
        assert case['dst%d' % index] == 0xABCD


def test_the_saved_axi4lite_uart_read_uses_ar_r():
    log = _run('axil-uart-read')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_route_protocol'] == 'axi4-lite'
    assert case['dma_route_axi_ar'] == 4 and case['dma_route_axi_r'] == 4
    assert case['dma_route_target_reads'] == 4 and case['dma_ram_reads'] == 0
    assert case['dma_route_read_value'] == 0xABCD
    assert case['dma_route_evidence_after'] == 0xABCD


def test_the_saved_axi4lite_uart_write_uses_aw_w_b():
    log = _run('axil-uart-write')
    assert log['summary']['status'] == 'observations_passed'
    case = _f6(log)
    assert case['status'] == 'observations_passed'
    assert case['dma_route_protocol'] == 'axi4-lite'
    assert case['dma_route_axi_aw'] == 4 and case['dma_route_axi_w'] == 4
    assert case['dma_route_axi_b'] == 4
    assert case['dma_route_target_writes'] == 4 and case['dma_ram_writes'] == 0
    assert case['fifo_status_after'] == 0x12345678


# --- the APB3 route lines are unchanged ----------------------------------

def test_the_saved_apb3_routes_keep_their_own_case_lines():
    """The APB3 routes print no route-protocol group: their lines are as before."""
    for name in ('regressions/fifo-write', 'regressions/prescaler-read',
                 'regressions/fifo-read', 'regressions/aperture',
                 'regressions/error'):
        log = _run(name)
        assert log['summary']['status'] == 'observations_passed', name
        case = _f6(log)
        assert case['status'] in ('observations_passed',
                                  'declared_error_injected'), name
        for key in ('dma_route_protocol', 'dma_route_protocol_transfers',
                    'dma_route_wb_acks', 'dma_route_tlul_a_handshakes',
                    'dma_route_axi_aw'):
            assert key not in case, (name, key)
