"""Pure-Python coverage of the AHB-Lite branch of the in-process entry.

Every fact here is either the generated artifact's own declaration shape (the
`ahb_lite_cpu` runtime document, its beat face, its manager-domain contract and
its protocol taps), the binding header rendered from it, the fixed RAM image, the
case-line contract, or the named refusal of a flow this CPU cannot witness.  No
model is built and no Verilator runs: the AHB branch is checked as a pure
function of the declaration.

The three claims these tests pin are the ones a report must not overstate:

* the beat face and the manager-domain observation are bound from the artifact,
  not from a CPU name, and the fetch/data identity is the address phase's
  HPROT[0] sampled at the manager's aggregate HREADY;
* F1 is refused by name because this boundary exports no RVFI/commit channel -
  a fetch beat is not a retirement;
* F5 is refused by name because this boundary exports no interrupt input at all.
"""
import json
from pathlib import Path

import pytest

from scripts.run_inprocess_f1f6 import (
    AHB_F1_REFUSAL, AHB_F5_REFUSAL, AHB_IDENTITY_ROLES, BUS_CHANNELS, CPU_BUSES,
    CPU_BUS_LABELS, ahb_beat_address_width, ahb_declared_boot, build_firmware,
    build_layout, case_counter_keys, case_document, correspondence, declared_windows,
    event_document, f5_declaration, flow_arity, parse_event_line, parse_record,
    render_bindings, summarize_events, target_protocol)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-ahb-cvw-apb-timer-f1f4.json'
CONFIG = json.loads(CONFIG_PATH.read_text())
WINDOWS = declared_windows(CONFIG)
BOOT = ahb_declared_boot({'boot_contract': {'configured_boot_base': CONFIG['image_start']}},
                         WINDOWS)
LAYOUT = build_layout(WINDOWS, BOOT)
ROLES = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
         'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
AHB_ROLES = {role: 'cpu_ahb_trace_' + role for role in AHB_IDENTITY_ROLES}


def clock(frequency=50000000):
    return dict(phase_policy='all_low_then_half_period_toggle',
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=frequency)])


def ahb_cpu_document(**overrides):
    """The generated `ahb_lite_cpu` shape: beat face + manager domain + taps."""
    document = dict(
        kind='ahb_lite_cpu', module_name='local_runtime_cpu', clock_schedule=clock(),
        # The generated model instantiates the subordinate adapter itself, so the
        # only functional ports this host sees are the beat face.
        backend_ports=[dict(channel='m', role=role, name='m_' + role,
                            direction='input' if role in ('req_ready', 'rsp_valid',
                                                          'rsp_rdata', 'rsp_error')
                            else 'output',
                            width=34 if role == 'req_addr' else 1)
                       for role in ROLES],
        # HREADY and HRESETn: the two observation roles this CPU exports and the
        # only two things the classifier needs from the manager domain.
        manager_domain=dict(
            schema_version='ahb_manager_domain_contract.v1',
            endpoint_id='cpu.manager_domain', protocol_endpoint_id='cpu.external_bus',
            authority='observation_only',
            roles={'manager_ready': dict(physical_port='HREADY', width=1,
                                         direction='output', runtime_name='rt_hready'),
                   'bus_reset_n': dict(physical_port='HRESETn', width=1,
                                       direction='output', runtime_name='rt_hresetn')}),
        base_protocol_traces=dict(
            schema_version='ip_protocol_trace_set.v1',
            traces=[dict(schema_version='ip_protocol_trace.v1', protocol='ahb-lite',
                         endpoint_id='cpu.external_bus', signals=dict(AHB_ROLES,
                                                                     hready='cpu_ahb_trace_hready'))]),
        # No RVFI, no interrupt input: exactly the CVW boundary.
        physical_exports=[dict(physical_port='HCLK', direction='output', width=1,
                               runtime_name='rt_hclk')],
        runtime_ports=[],
        plan=dict(timing=dict(reset_assert_ticks=8, reset_release_ticks=8)))
    document.update(overrides)
    return document


def ip_document(**overrides):
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata', 'pslverr')}
    document = dict(kind='apb3_register_observe', module_name='local_ip',
                    clock_schedule=clock(),
                    base_protocol_trace=dict(protocol='apb3', signals=signals),
                    physical_exports=[dict(physical_port='irq_o', direction='output',
                                           width=4, bit_lo=0, bit_hi=3,
                                           runtime_name='irq_wide')],
                    backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                                   for role in ROLES],
                    plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))
    document.update(overrides)
    return document


def cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['cpu_profile'])


def header(**overrides):
    return render_bindings(CONFIG, ahb_cpu_document(**overrides), ip_document(), None,
                           LAYOUT, cpu_profile(), irq=None, dma=None, dma_irq=None)


# --- the bus this entry drives -------------------------------------------

def test_an_ahb_artifact_selects_the_ahb_branch():
    assert CPU_BUSES['ahb_lite_cpu'] == 'ahb'
    assert CPU_BUS_LABELS['ahb'] == 'AHB-Lite single manager'
    assert 'ahb' in BUS_CHANNELS


def test_the_declared_address_width_comes_from_the_beat_face():
    assert ahb_beat_address_width(ahb_cpu_document()) == 34


@pytest.mark.parametrize('document,match', [
    (dict(backend_ports=[dict(channel='m', role=role, name='m_' + role)
                         for role in ROLES if role != 'req_addr']),
     'unsupported-ahb-beat-width'),
    (dict(backend_ports=[dict(channel='m', role=role, name='m_' + role,
                              width=65 if role == 'req_addr' else 1)
                         for role in ROLES]),
     'unsupported-ahb-beat-width'),
])
def test_a_beat_face_without_a_usable_address_is_refused(document, match):
    base = ahb_cpu_document()
    base.update(document)
    with pytest.raises(ValueError, match=match):
        ahb_beat_address_width(base)


# --- the binding header ---------------------------------------------------

def test_the_header_binds_the_beat_face_and_the_manager_domain():
    text = header()
    assert '#define CPU_BUS_AHB 1' in text
    assert '#define CPU_BUS_WISHBONE 0' in text
    assert '#define CPU_M_ADDR_WIDTH 34u' in text
    for role in ROLES:
        assert f'#define CPU_M_{role.upper()} m_{role}' in text
    # The classifier's two manager-domain observations, taken from the artifact.
    assert '#define AHB_MANAGER_READY rt_hready' in text
    assert '#define AHB_BUS_RESET_N rt_hresetn' in text
    for role in AHB_IDENTITY_ROLES:
        assert f'#define CPU_AHB_TRACE_{role.upper()} cpu_ahb_trace_{role}' in text


def test_the_header_declares_no_retirement_and_no_interrupt_pin():
    text = header()
    assert 'CPU_RVFI_' not in text
    assert '#define CPU_IRQ ' not in text
    assert '#define HAVE_RVFI_WRITEBACK 0' in text
    assert '#define HAVE_RVFI_EXPANDED 0' in text
    assert '#define HAVE_CPU_TAKE 0' in text
    assert '#define HAVE_IRQ_LINKS 0' in text
    assert '#define CPU_IRQ_WIDTH 0' in text


def test_the_header_refuses_a_manager_domain_without_both_roles():
    document = ahb_cpu_document(manager_domain=dict(
        roles={'manager_ready': dict(physical_port='HREADY', width=1,
                                     direction='output', runtime_name='rt_hready')}))
    with pytest.raises(ValueError, match='unsupported-ahb-manager-domain:bus_reset_n'):
        header(manager_domain=document['manager_domain'])


def test_the_header_refuses_a_manager_domain_that_is_not_declared():
    with pytest.raises(ValueError, match='unsupported-ahb-manager-domain:no_declared_contract'):
        header(manager_domain=None)


def test_the_header_refuses_a_trace_that_cannot_identify_a_beat():
    signals = dict(AHB_ROLES)
    signals.pop('hprot')
    document = ahb_cpu_document(base_protocol_traces=dict(
        traces=[dict(protocol='ahb-lite', signals=signals)]))
    with pytest.raises(ValueError, match='unsupported-ahb-trace:lacks:hprot'):
        header(**document)


def test_the_header_refuses_a_second_ahb_trace():
    traces = dict(traces=[dict(protocol='ahb-lite', signals=dict(AHB_ROLES)),
                          dict(protocol='ahb-lite', signals=dict(AHB_ROLES))])
    with pytest.raises(ValueError, match='unsupported-ahb-trace:expected_one'):
        header(base_protocol_traces=traces)


def test_an_ahb_build_refuses_a_dma_model():
    from tests.integration.test_inprocess_f1f6_entry import dma_document
    with pytest.raises(
            ValueError,
            match='unsupported-f6:cpu-dma-port-unexported:ahb'):
        render_bindings(CONFIG, ahb_cpu_document(), ip_document(), dma_document(),
                        LAYOUT, cpu_profile(), irq=None, dma=None, dma_irq=None)


# --- the two named refusals ----------------------------------------------

def test_f1_is_refused_by_name_because_a_fetch_is_not_a_retirement():
    assert AHB_F1_REFUSAL == 'unsupported-f1:no-retirement-observation:ahb_cvw'
    arity = flow_arity(None, None)
    arity.pop('F1')
    with pytest.raises(ValueError) as error:
        parse_record('F1:112230b7', windows=WINDOWS, arity=arity,
                     refusals={'F1': AHB_F1_REFUSAL})
    assert str(error.value) == AHB_F1_REFUSAL


def test_f5_is_refused_by_name_because_the_cpu_exports_no_interrupt_input():
    assert AHB_F5_REFUSAL == 'unsupported-f5:cpu-irq-unexported:ahb_cvw'
    irq, refusal = f5_declaration(dict(CONFIG), ip_profile(), 'apb3', cpu_bus_kind='ahb')
    assert irq is None
    assert refusal == AHB_F5_REFUSAL


def ip_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['source_profile'])


def test_only_f2_to_f4_are_served_by_this_cpu():
    arity = flow_arity(None, None)
    arity.pop('F1')
    assert sorted(arity) == ['F2', 'F3', 'F4']
    for text in ('F2:c8000000', 'F3:c0004004:0badf00d', 'F4:c8000008:0000002a'):
        record = parse_record(text, windows=WINDOWS, arity=arity)
        assert record['flow'] in ('F2', 'F3', 'F4')


# --- boot address and RAM image ------------------------------------------

def test_the_boot_address_is_the_declared_configuration_constant():
    assert BOOT == CONFIG['image_start'] == 0xC0000000
    assert WINDOWS['ram_base'] <= BOOT < WINDOWS['ram_base'] + WINDOWS['ram_size']


@pytest.mark.parametrize('contract,match', [
    ({'configured_boot_base': 0x40000000}, 'ram-base-does-not-follow-boot-contract'),
    ({'configured_boot_base': None}, 'unsupported-ahb-boot-contract'),
    ({'configured_boot_base': 0xC0000002}, 'unsupported-ahb-boot-contract'),
])
def test_a_boot_address_outside_the_declared_image_is_refused(contract, match):
    with pytest.raises(ValueError, match=match):
        ahb_declared_boot({'boot_contract': contract}, WINDOWS)


def test_the_target_window_sits_inside_the_cpus_external_memory_region():
    # CVW decodes 0xC0000000..0xCFFFFFFF as external memory; a window outside it
    # would never assert HSELEXT and the beat would never reach this host.
    assert 0xC0000000 <= CONFIG['target_window']['base'] < 0xD0000000
    assert WINDOWS['ip_base'] % 4096 == 0
    assert not (WINDOWS['ram_base'] <= WINDOWS['ip_base']
                < WINDOWS['ram_base'] + WINDOWS['ram_size'])
    assert not (WINDOWS['ip_base'] <= WINDOWS['data_base']
                < WINDOWS['ip_base'] + WINDOWS['ip_size'])


def test_the_fixed_image_holds_every_declared_region():
    firmware = build_firmware(LAYOUT, irq=None, dma=None, interrupt_bootstrap=False)
    assert firmware['layout']['slot'] == LAYOUT['slot']
    assert LAYOUT['ram_base'] == 0xC0000000


# --- the case line and the event layer -----------------------------------

def test_an_ahb_case_line_carries_its_identity_counts():
    keys = case_counter_keys('apb3', bus='ahb')
    for key in ('i_fetches', 'd_reads', 'd_writes', 'ahb_beats', 'ahb_unknown',
                'ahb_unknown_reset'):
        assert key in keys
    assert 'ahb_beats' not in case_counter_keys('apb3')


def test_a_saved_ahb_case_documents_its_identity_counts():
    record = parse_record('F2:c8000000', windows=WINDOWS,
                          arity={'F2': 1, 'F3': 2, 'F4': 2})
    case = dict(index=0, flow='F2', status='observations_passed', record=record['text'],
                ticks=41, i_fetches=0, d_reads=2, d_writes=2, apb_reads=1, apb_writes=0,
                ahb_beats=5, ahb_unknown=0, ahb_unknown_reset=0, retires=0,
                rvfi_writebacks=0, rvfi_order_monotonic=1, traps=0, bus_errors=0,
                read_addr=0xC8000000, read_value=0, echo_value=0, read_from='apb',
                apb_rdata=0)
    document = case_document(record, case, protocol='apb3', bus='ahb')
    assert document['observation']['ahb_beats'] == 5
    assert document['observation']['ahb_unknown'] == 0
    assert document['failure_class'] == 'passed'
    assert correspondence(record, case, layout=LAYOUT, windows=WINDOWS, irq=None, dma=None,
                          protocol='apb3', bus='ahb') is None


def test_the_ahb_error_channel_is_a_stated_unknown():
    event = parse_event_line('bus_error unknown ahb')
    assert event == dict(kind='bus_error', tick=None, channel='ahb', address=None)
    log = ('bus_error unknown ahb\n'
           'ahb 0 unknown 0xc0000000 0x00000000 be 15\n'
           'ifetch 3 0xc0000004 0x00000000\n'
           'ahb 3 fetch 0xc0000004 0x00000000 be 15\n'
           'case 0 observations_passed flow F2 record F2:c0004000 ticks 190\n'
           'summary observations_passed cases 1 bus_error_ahb unknown '
           'bus_error unknown ifetch_evidence observed retirement_evidence missing\n')
    events = summarize_events(log)
    assert events['counts']['bus_error'] == 1
    assert events['counts']['ifetch'] == 1
    # An `ahb` line is host detail, not an event family of its own.
    assert 'ahb' not in events['counts']
    document = event_document(events, dict(bus_error_ahb='unknown', bus_error='unknown',
                                           ifetch_evidence='observed',
                                           retirement_evidence='missing'))
    assert document['evidence']['bus_error_channels']['ahb'] == 'unknown'
    assert document['conflicts'] == []


def test_the_ahb_target_protocol_is_the_declared_apb3():
    assert target_protocol(ip_document()) == 'apb3'
