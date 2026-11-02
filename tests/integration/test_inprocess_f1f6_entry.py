"""Pure-Python coverage of the F1-F6 in-process entry: no RTL, no Verilator.

Every fact these tests touch is either the argument/record contract, the fixed
RAM image the C++ host loads, the compact line format it prints, the
correspondence check applied to a saved observation, or the named refusal of a
declaration the selected components cannot serve.  No model is built.
"""
import json
from pathlib import Path

import pytest

from scripts.run_inprocess_f1f6 import (
    BUS_CHANNELS, DMA_BUSY_BIT, DMA_ERR_BIT, DMA_SOURCE_OFFSET, DMA_DESTINATION_OFFSET,
    DATA_OFFSET, EVENT_KINDS, HB, HB_FLAG, HB_STATUS, HANDLER_BLOCK_BYTES, HANDLER_OFFSET,
    DMA_DESTINATION_SENTINEL, MAILBOX_OFFSET, RESULT_OFFSET, SLOT_OFFSET, VECTOR_OFFSET,
    build_firmware, build_layout, case_observation_keys,
    case_document, correspondence, dma_declaration, declared_windows, event_document,
    final_status, flow_arity, irq_declaration, main, parse_case_line, parse_event_line,
    parse_record, parse_run_log, parse_summary_line, register_kind, render_bindings,
    f5_declaration, pin_declaration, pin_registers, summarize_events, validate_record,
    advanced_irq_refusals, f5_both_selected, f5_link_table)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json'
CONFIG = json.loads(CONFIG_PATH.read_text())
DMA_WINDOW_SIZE = 16
WINDOWS = declared_windows(CONFIG, DMA_WINDOW_SIZE)
BOOT = 0x10080
LAYOUT = build_layout(WINDOWS, BOOT)
TRIGGER_OFFSETS = [row[0] for row in CONFIG['trigger_writes']]
IRQ = dict(port='irq_o', bit=0, trigger='pulse', polarity='active_high', pulse_ticks=16,
           status_offset=0, trigger_offsets=TRIGGER_OFFSETS, status_kind='count',
           status_read_clears=False,
           cause_declared=False, cause_bits=[], cause_mask=0, clear=None,
           # The ordered clear sequence this link declares (none here): the
           # declaration always states it, so a reader never has to guess whether
           # a missing clear is "no clear" or "not carried".
           clears=[], clear_steps=0)
DMA = dict(control_offset=0, source_offset=4, destination_offset=8, length_offset=12,
           start_word=0, block_words=4, length_value=16, length_unit='bytes',
           master_shift=2, control_select=1, master_select=1, status_kind='status',
           clear=dict(offset=0, value=0x80000000),
           master_byte_enable=dict(kind='full_word', mask=15, lane_pattern=[15],
                                   lanes_per_beat=4, beats_per_word=1, size_bytes=4,
                                   size_code=0, partial=False),
           expected_reads=4, expected_writes=4, delay_ticks=0,
           max_outstanding=1, device_family='zipdma',
           source_destination_byte_address_bits=30,
           response_delay=dict(ticks=0, mode='zero_wait', source='device_default',
                               backpressure=None, observation=None),
           planner_host_supported=True, host_limits=[], host_limits_satisfied=[],
           host_limits_raised=[], behavior_loader_refusal=None,
           behavior_declared_by='inline', supported=True, refusal=None,
           irq=dict(port='o_interrupt', trigger='level', polarity='active_high',
                    pulse_ticks=0, endpoint='dma.interrupt'))
ARITY = flow_arity(IRQ, DMA)
EVIDENCE = ('F1:2ab00693,F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff,'
            'F5:00000001:00000000:ffffffff,F6:0110c000:08000000:deadbeef:12345678')


def record(text):
    return parse_record(text, windows=WINDOWS, arity=ARITY)


# --- declared windows and the fixed RAM image ----------------------------

def test_the_three_windows_come_from_the_declaration():
    assert WINDOWS['ram_base'] == CONFIG['image_start']
    assert WINDOWS['data_base'] == CONFIG['image_start'] + DATA_OFFSET
    assert WINDOWS['ip_base'] == CONFIG['target_window']['base']
    assert WINDOWS['dma_base'] == CONFIG['dma_window']['base']
    assert not (WINDOWS['ip_base'] <= WINDOWS['dma_base'] < WINDOWS['ip_base'] + WINDOWS['ip_size'])
    assert not (WINDOWS['dma_base'] <= WINDOWS['ip_base'] < WINDOWS['dma_base'] + WINDOWS['dma_size'])


@pytest.mark.parametrize('key,value,match', [
    ('image_end', CONFIG['image_start'] + DMA_DESTINATION_OFFSET + 8, 'too small'),
    ('target_window', dict(base=1073745920, size=2), 'unusable'),
])
def test_unusable_declared_windows_are_refused(key, value, match):
    with pytest.raises(ValueError, match=match):
        declared_windows(dict(CONFIG, **{key: value}), DMA_WINDOW_SIZE)


def test_the_dma_window_must_match_the_declared_dma_window_size():
    with pytest.raises(ValueError, match='DMA control window'):
        declared_windows(CONFIG, 32)


def test_overlapping_mmio_windows_are_refused():
    overlapping = dict(CONFIG, dma_window=dict(base=CONFIG['target_window']['base'], size=16))
    with pytest.raises(ValueError, match='overlap'):
        declared_windows(overlapping, DMA_WINDOW_SIZE)


def test_one_image_carries_every_fixed_address_without_overlap():
    spans = sorted([(LAYOUT['boot'], 'boot'), (LAYOUT['vector'], 'vector'),
                    (LAYOUT['handler'], 'handler'), (LAYOUT['main'], 'main'),
                    (LAYOUT['slot'], 'slot'), (LAYOUT['mailbox'], 'mailbox'),
                    (LAYOUT['handler_block'], 'handler_block'),
                    (LAYOUT['data_base'], 'data'), (LAYOUT['result'], 'result'),
                    (LAYOUT['dma_source'], 'dma_source'),
                    (LAYOUT['dma_destination'], 'dma_destination')])
    assert len({name for _, name in spans}) == len(spans)
    assert LAYOUT['data_end'] == CONFIG['image_end']
    assert LAYOUT['handler_block'] == LAYOUT['mailbox'] + HB_STATUS
    assert LAYOUT['result_f5'] == LAYOUT['result']
    assert LAYOUT['result_f6'] == LAYOUT['result'] + 4
    assert LAYOUT['flag'] == LAYOUT['result'] + 8
    assert LAYOUT['ctl_before'] == LAYOUT['result'] + 12
    offsets = dict(slot=SLOT_OFFSET, mailbox=MAILBOX_OFFSET, data_base=DATA_OFFSET,
                   result=RESULT_OFFSET, vector=VECTOR_OFFSET, handler=HANDLER_OFFSET)
    for name, offset in offsets.items():
        assert LAYOUT[name] == CONFIG['image_start'] + offset
    assert spans[0][0] == LAYOUT['boot']


@pytest.mark.parametrize('boot', [LAYOUT['vector'] - 4, CONFIG['image_start'] + 2])
def test_a_boot_address_without_room_is_refused(boot):
    with pytest.raises(ValueError, match='aligned RAM word|no room'):
        build_layout(WINDOWS, boot)


# --- input records --------------------------------------------------------

def test_the_six_flows_have_the_declared_word_counts():
    assert ARITY == {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
    counts = [len(record(text)['fields']) for text in EVIDENCE.split(',')]
    assert counts == [1, 1, 2, 2, 3, 4]


def test_one_record_keeps_the_canonical_text_the_host_echoes():
    parsed = record('F5:1:0:FFFFFFFF')
    assert parsed['text'] == 'F5:00000001:00000000:ffffffff'
    assert parsed['message'] == 'CASE F5 00000001 00000000 ffffffff'
    assert parsed['fields'] == (1, 0, 0xFFFFFFFF)
    assert record('F6:0110c000:08000000:deadbeef:12345678')['text'] == \
        'F6:0110c000:08000000:deadbeef:12345678'


@pytest.mark.parametrize('text,match', [
    ('F9:00014000', 'unsupported flow tag'),
    ('F5:00000001:00000000', 'needs 3 word'),
    ('F6:1:2:3', 'needs 4 word'),
    ('F3:40001000:1', 'data-window RAM'),
    ('F2:00013000', 'APB or data-window'),
    ('F4:40002000:1', 'APB window'),
    ('F1:10000000', 'instruction word'),
    ('F1:2ab0069g', 'hexadecimal'),
    ('F1:', 'hexadecimal'),
    ('', 'record text is required'),
])
def test_bad_records_are_refused_by_name(text, match):
    with pytest.raises(ValueError, match=match):
        record(text)


def test_a_record_cannot_address_a_window_the_flows_do_not_own():
    with pytest.raises(ValueError, match='APB window'):
        record('F4:40003000:1')
    with pytest.raises(ValueError, match='APB or data-window'):
        record('F2:00012000')


def test_the_f2_read_window_includes_the_apb_target():
    parsed = record('F2:40001000')
    assert parsed['fields'] == (CONFIG['target_window']['base'],)


def test_the_f1_legality_gate_is_the_existing_one():
    from myfuzz.isa.constraints import IsaContract
    isa = IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)
    assert validate_record(record('F1:2ab00693'), isa=isa, windows=WINDOWS)['flow'] == 'F1'
    with pytest.raises(ValueError, match='mailbox register x8'):
        validate_record(record('F1:2ab00413'), isa=isa, windows=WINDOWS)


# --- declarations the selected components cannot serve -------------------

def timer_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['source_profile'])


def zipdma_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['dma_profile'])


def dma_artifact(master_sel=True):
    """Only the shape the entry reads: generated port names and the edge contract.

    ``master_sel`` states whether the generated environment exposes the device's
    master byte-enable port.  The pinned ZipDMA has one (``mwb_sel``) and the
    selected edge contract names it; the pinned wbdmac has none, and its contract
    fixes the master enable at a full word instead.  Declaring one on a device
    that has none is refused by the planning module, so the two shapes are kept
    apart here rather than shared.
    """
    ports = [dict(channel=channel, role=role, name=channel + '_' + role, direction=direction,
                  width=width) for channel, role, direction, width in (
        ('swb', 'cyc', 'input', 1), ('swb', 'stb', 'input', 1), ('swb', 'we', 'input', 1),
        ('swb', 'adr', 'input', 2), ('swb', 'dat_w', 'input', 32), ('swb', 'sel', 'input', 4),
        ('swb', 'stall', 'output', 1), ('swb', 'ack', 'output', 1), ('swb', 'dat_r', 'output', 32),
        ('mwb', 'cyc', 'output', 1), ('mwb', 'stb', 'output', 1), ('mwb', 'we', 'output', 1),
        ('mwb', 'adr', 'output', 30), ('mwb', 'dat_w', 'output', 32),
        ('mwb', 'stall', 'input', 1), ('mwb', 'ack', 'input', 1), ('mwb', 'dat_r', 'input', 32),
        ('mwb', 'err', 'input', 1))]
    if master_sel:
        ports.append(dict(channel='mwb', role='sel', name='mwb_sel', direction='output',
                          width=4))
    edge = dict(master_address_units='word', master_address_shift=2,
                environment_max_outstanding=1, same_edge_accept_and_complete=False,
                control_address_units='word_index')
    if master_sel:
        edge.update(schema_version='wishbone_dma_selected_edge.v1',
                    control_byte_enable_signal='swb_sel',
                    master_byte_enable_signal='mwb_sel')
    else:
        edge.update(schema_version='wishbone_dma_edge.v1',
                    master_fixed_byte_enable=15)
    return dict(kind='wishbone_dma', backend_ports=ports, dma_edge_contract=edge)


def test_the_declared_irq_behavior_is_checked_against_the_timer_map():
    assert IRQ == irq_declaration(CONFIG, timer_profile())


@pytest.mark.parametrize('override,match', [
    ({'status_offsets': [12]}, 'readable word'),
    ({'status_offsets': []}, 'exactly one'),
    ({'trigger_writes': [[12, 0]]}, 'writable word'),
    ({'trigger_writes': []}, 'trigger write sequence'),
    ({'source_port': 'irq_missing'}, 'no single IRQ output'),
    ({'source_bit_offset': 9}, 'no single IRQ output'),
    ({'pulse_width_ticks': 0}, 'delivery width'),
    # The ordered clear is bounded by the handler's two clear cell pairs: a
    # three-step declaration is refused by name rather than truncated.
    ({'clear_writes': [[0, 1], [4, 2], [8, 3]]}, 'at most 2'),
])
def test_an_unsupported_irq_declaration_is_refused_by_name(override, match):
    with pytest.raises(ValueError, match=match):
        irq_declaration(dict(CONFIG, **override), timer_profile())


def test_a_second_irq_source_is_a_named_refusal_not_a_guess():
    with pytest.raises(ValueError, match='exactly one'):
        irq_declaration(dict(CONFIG, status_offsets=[0, 4]), timer_profile())


def test_the_declared_dma_behavior_is_checked_against_the_zipdma_profile():
    declaration = dma_declaration(CONFIG, zipdma_profile(), dma_artifact())
    assert declaration['block_words'] == 4
    assert declaration['length_value'] == 16
    assert declaration['clear'] == dict(offset=0, value=0x80000000)
    assert declaration['irq']['trigger'] == 'level'


@pytest.mark.parametrize('override,artifact_change,match', [
    # A block deeper than this entry's RAM image executes is refused by the
    # entry's own bound, with the planner's far larger device bound stated apart.
    ({'dma_block_words': 9}, None, 'unsupported-dma-block'),
    ({'dma_block_words': 0}, None, 'positive integer'),
    ({'dma_transfer_size_bytes': 3}, None, 'master-byte-enable-unsupported'),
    # A mask the host would have to force onto a device that drives its own
    # strobes is refused instead of being emulated.
    ({'dma_master_byte_enable': 5}, None, 'not-driven-by-device'),
    (None, ('swb', 'adr', 'width', 4), 'four words'),
    (None, ('swb', 'cyc', 'name', 'cyc'), 'does not expose'),
    (None, ('edge', 'master_address_shift', 1), 'master-address'),
    (None, ('edge', 'same_edge_accept_and_complete', True), 'same_edge'),
])
def test_an_unsupported_dma_declaration_is_refused_by_name(override, artifact_change, match):
    document = dma_artifact()
    if artifact_change is not None:
        if artifact_change[0] == 'edge':
            document['dma_edge_contract'][artifact_change[1]] = artifact_change[2]
        else:
            channel, role, key, value = artifact_change
            row = next(row for row in document['backend_ports']
                       if row['channel'] == channel and row['role'] == role)
            row[key] = value
    with pytest.raises(ValueError, match=match):
        dma_declaration(dict(CONFIG, **(override or {})), zipdma_profile(), document)


def test_a_declared_pulse_dma_irq_needs_its_delivery_width(monkeypatch):
    """A pulse DMA source is either delivered for its declared width or refused."""
    from dataclasses import replace
    import myfuzz.scenario.f6_dma_source_provider as provider_module
    provider = provider_module.select_f6_dma_source_provider(zipdma_profile(), base_dir=ROOT)
    pulse = replace(provider, irq_trigger='pulse')
    monkeypatch.setattr(provider_module, 'select_f6_dma_source_provider',
                        lambda profile, *, base_dir: pulse)
    with pytest.raises(ValueError, match='dma_irq_pulse_ticks'):
        dma_declaration(dict(CONFIG, dma_irq_pulse_ticks=0), zipdma_profile(), dma_artifact())
    declaration = dma_declaration(dict(CONFIG, dma_irq_pulse_ticks=24), zipdma_profile(),
                                  dma_artifact())
    assert declaration['irq']['trigger'] == 'pulse'
    assert declaration['irq']['pulse_ticks'] == 24


def test_a_second_dma_profile_is_refused_by_name_instead_of_shifted(monkeypatch):
    """A declaration in shifted address units is refused, never silently shifted.

    The refusal is a property of this entry, so it is exercised with a shifted
    declaration instead of whichever units the shipped wbdmac profile declares
    today.
    """
    from dataclasses import replace
    import myfuzz.scenario.f6_dma_source_provider as provider_module
    provider = provider_module.select_f6_dma_source_provider(zipdma_profile(), base_dir=ROOT)
    shifted = replace(provider, csr=dict(provider.csr, source_destination_units='word_address'))
    monkeypatch.setattr(provider_module, 'select_f6_dma_source_provider',
                        lambda profile, *, base_dir: shifted)
    with pytest.raises(ValueError, match='byte addresses'):
        dma_declaration(CONFIG, zipdma_profile(), dma_artifact())


# --- the declared transfer plans the entry now consumes ------------------
#
# The device/encodability half is ``myfuzz.composition.dma_transfer``; these
# tests cover what the *entry* does with a plan: the fields it wires into the
# generated header and firmware, the host limits it answers by name, and the
# correspondence checks that keep a case line honest about byte enables and
# backpressure.  The two long case lines below are real host output saved from
# runs/round1-dma-a (byte-enable and delay), so "a record of 8 words parses" and
# "the delay was observed" are readings of lines the host really printed.

LEN8_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-len8-f1f6.json')
    .read_text())
BYTEEN_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-byteen-f1f6.json')
    .read_text())
DELAY_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-delay-f1f6.json')
    .read_text())
FIFO_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-fifo-f1f6.json')
    .read_text())
#: Real host case lines saved from runs/round1-dma-a (len8, byte-enable, delay).
#: They are read here so the entry's case parser and its correspondence checks are
#: exercised against output the host actually printed, not against a hand-built
#: line that could drift away from it.
LEN8_CASE_LINE = ('case 0 observations_passed flow F6 record '
           'F6:0110c000:08000000:deadbeef:12345678:00000001:00000002:00000003:00000004 ticks 313 '
           'seconds 0.000500028 i_fetches 144 d_reads 19 d_writes 22 apb_reads 0 apb_writes 0 '
           'retires 121 rvfi_writebacks 72 rvfi_order_monotonic 1 traps 0 bus_errors 0 dma_reads 8 '
           'dma_writes 8 dma_first_read_addr 0x00016000 dma_first_read_value 0x0110c000 '
           'dma_last_write_addr 0x0001701c dma_last_write_value 0x00000004 ctl_config_writes 3 '
           'ctl_start_writes 1 ctl_clear_writes 1 ctl_reads 2 ctl_status 0x00000040 irq_edges 1 '
           'irq_high_ticks 32 device_high_ticks 32 delivered_high_ticks 32 irq_takes 1 wait_timeout '
           '0 isr_result 0x00000040 isr_flag 1 ctl_reads_before_start 1 busy_before 0 err_before 0 '
           'busy_after 0 err_after 0 dma_clear_declared 1 dma_status_kind status dma_done_tick 249 '
           'dma_start_word 0x00000000 dma_block_words 8 dma_master_beats_per_word 1 '
           'dma_master_partial 0 dma_lane_count 1 dma_lane_masks 0x0000000f dma_expected_reads 8 '
           'dma_expected_writes 8 dma_start_write 0x00000000 dma_response_delay_declared 0 dma_acks '
           '16 dma_delayed_acks 1 dma_wait_min 1 dma_wait_max 2 dma_wait_total 17 dma_stall_ticks '
           '17 dma_max_consecutive_stalls 2 dma_sel_full 8 dma_sel_partial 0 dma_sel_undeclared 0 '
           'dma_read_lane_partial 0 dma_lane_written 32 dma_lane_missing 0 dma_lane_extra 0 '
           'dma_bytes_outside_block 0 dma_guard_lo 0xa5a5a5a5 dma_guard_hi 0xa5a5a5a5 '
           'dma_delay_evidence not_declared dma_stall_expectation none_declared '
           'dma_stall_expect_min 0 dma_stall_expect_max 0 dst0 0x0110c000 dst1 0x08000000 dst2 '
           '0xdeadbeef dst3 0x12345678 dst4 0x00000001 dst5 0x00000002 dst6 0x00000003 dst7 '
           '0x00000004')

BYTEEN_CASE_LINE = ('case 0 observations_passed flow F6 record F6:0110c000:08000000:deadbeef:12345678 ticks '
           '327 seconds 0.000458728 i_fetches 155 d_reads 18 d_writes 18 apb_reads 0 apb_writes 0 '
           'retires 125 rvfi_writebacks 74 rvfi_order_monotonic 1 traps 0 bus_errors 0 dma_reads 16 '
           'dma_writes 16 dma_first_read_addr 0x00016000 dma_first_read_value 0x0110c000 '
           'dma_last_write_addr 0x0001700c dma_last_write_value 0x12000000 ctl_config_writes 3 '
           'ctl_start_writes 1 ctl_clear_writes 1 ctl_reads 2 ctl_status 0x00330040 irq_edges 1 '
           'irq_high_ticks 34 device_high_ticks 34 delivered_high_ticks 34 irq_takes 1 wait_timeout '
           '0 isr_result 0x00330040 isr_flag 1 ctl_reads_before_start 1 busy_before 0 err_before 0 '
           'busy_after 0 err_after 0 dma_clear_declared 1 dma_status_kind status dma_done_tick 257 '
           'dma_start_word 0x00330000 dma_block_words 4 dma_master_beats_per_word 4 '
           'dma_master_partial 1 dma_lane_count 4 dma_lane_masks 0x00008421 dma_expected_reads 16 '
           'dma_expected_writes 16 dma_start_write 0x00330000 dma_response_delay_declared 0 '
           'dma_acks 32 dma_delayed_acks 1 dma_wait_min 1 dma_wait_max 2 dma_wait_total 33 '
           'dma_stall_ticks 33 dma_max_consecutive_stalls 2 dma_sel_full 0 dma_sel_partial 16 '
           'dma_sel_undeclared 0 dma_read_lane_partial 16 dma_lane_written 16 dma_lane_missing 0 '
           'dma_lane_extra 0 dma_bytes_outside_block 0 dma_guard_lo 0xa5a5a5a5 dma_guard_hi '
           '0xa5a5a5a5 dma_delay_evidence not_declared dma_stall_expectation none_declared '
           'dma_stall_expect_min 0 dma_stall_expect_max 0 dst0 0x0110c000 dst1 0x08000000 dst2 '
           '0xdeadbeef dst3 0x12345678')

DELAY_CASE_LINE = ('case 0 observations_passed flow F6 record F6:0110c000:08000000:deadbeef:12345678 ticks '
           '289 seconds 0.000422065 i_fetches 136 d_reads 15 d_writes 18 apb_reads 0 apb_writes 0 '
           'retires 113 rvfi_writebacks 68 rvfi_order_monotonic 1 traps 0 bus_errors 0 dma_reads 4 '
           'dma_writes 4 dma_first_read_addr 0x00016000 dma_first_read_value 0x0110c000 '
           'dma_last_write_addr 0x0001700c dma_last_write_value 0x12345678 ctl_config_writes 3 '
           'ctl_start_writes 1 ctl_clear_writes 1 ctl_reads 2 ctl_status 0x00000040 irq_edges 1 '
           'irq_high_ticks 32 device_high_ticks 32 delivered_high_ticks 32 irq_takes 1 wait_timeout '
           '0 isr_result 0x00000040 isr_flag 1 ctl_reads_before_start 1 busy_before 0 err_before 0 '
           'busy_after 0 err_after 0 dma_clear_declared 1 dma_status_kind status dma_done_tick 225 '
           'dma_start_word 0x00000000 dma_block_words 4 dma_master_beats_per_word 1 '
           'dma_master_partial 0 dma_lane_count 1 dma_lane_masks 0x0000000f dma_expected_reads 4 '
           'dma_expected_writes 4 dma_start_write 0x00000000 dma_response_delay_declared 2 dma_acks '
           '8 dma_delayed_acks 8 dma_wait_min 3 dma_wait_max 4 dma_wait_total 25 dma_stall_ticks 25 '
           'dma_max_consecutive_stalls 4 dma_sel_full 4 dma_sel_partial 0 dma_sel_undeclared 0 '
           'dma_read_lane_partial 0 dma_lane_written 16 dma_lane_missing 0 dma_lane_extra 0 '
           'dma_bytes_outside_block 0 dma_guard_lo 0xa5a5a5a5 dma_guard_hi 0xa5a5a5a5 '
           'dma_delay_evidence observed dma_stall_expectation declared dma_stall_expect_min 2 '
           'dma_stall_expect_max 2 dst0 0x0110c000 dst1 0x08000000 dst2 0xdeadbeef dst3 0x12345678')


def declaration(config, artifact=None, **kwargs):
    return dma_declaration(config, zipdma_profile(),
                           dma_artifact() if artifact is None else artifact, **kwargs)


def test_the_entry_plans_an_eight_word_zipdma_block_from_the_device_bound():
    plan = declaration(LEN8_CONFIG)
    assert plan['block_words'] == 8 and plan['length_value'] == 32
    assert plan['plan']['device']['device_max_block_words'] == 64
    assert plan['expected_reads'] == plan['expected_writes'] == 8
    assert plan['master_byte_enable']['kind'] == 'full_word'
    # The planner still reports its own 1..4 host bound; the entry answers it
    # with the bound it actually implements instead of inheriting it.
    assert plan['planner_host_supported'] is False
    assert [row['code'] for row in plan['host_limits']] == ['host-block-words-cap']
    raised = {row['code']: row for row in plan['host_limits_raised']}
    assert raised['host-block-words-cap']['host_limit'] == 8


def test_an_eight_word_block_reaches_the_firmware_and_the_header():
    plan = declaration(LEN8_CONFIG)
    firmware = build_firmware(LAYOUT, irq=IRQ, dma=plan)
    # The firmware copies eight input words into the DMA source block, reading
    # the mailbox at INPUT_BLOCK + 4*7; the mailbox span has to hold them.
    from scripts.run_inprocess_f1f6 import INPUT_BLOCK
    assert INPUT_BLOCK + 4 * plan['block_words'] <= firmware['layout']['mailbox_bytes']
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ, dma=plan, dma_irq=plan['irq'])
    assert '#define DMA_BLOCK_WORDS 8u' in header
    assert '#define DMA_EXPECTED_READS 8u' in header
    assert '#define DMA_EXPECTED_WRITES 8u' in header
    assert '#define DMA_MASTER_PARTIAL 0' in header
    assert '#define DMA_RESPONSE_DELAY 0u' in header


def test_an_eight_word_record_parses_and_its_case_document_covers_every_word():
    text = ('F6:0110c000:08000000:deadbeef:12345678:00000001:00000002:00000003:00000004')
    parsed = parse_record(text, windows=WINDOWS, arity=flow_arity(IRQ, declaration(LEN8_CONFIG)))
    assert len(parsed['fields']) == 8 and parsed['flow'] == 'F6'
    # The host's own block loop printed dst0..dst7 for that record; every one of
    # those keys is a declared observation of the case, not a stray field.
    keys = case_observation_keys('F6', 'apb3')
    assert {'dst0', 'dst3', 'dst4', 'dst7', 'dst15'} <= set(keys)
    line = LEN8_CASE_LINE
    case = parse_case_line(line, flows={'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2,
                                        'F5': 3, 'F6': 8})
    assert case['dma_block_words'] == 8 and case['dst7'] == 0x00000004
    document = case_document(parsed, case)
    assert document['observation']['dst7'] == 0x00000004
    assert document['observation']['dma_lane_written'] == 32
    assert document['observation']['dma_guard_hi'] == DMA_DESTINATION_SENTINEL


def test_the_plan_start_word_is_what_the_header_and_the_case_carry():
    plan = declaration(BYTEEN_CONFIG)
    assert plan['start_word'] == 0x00330000
    assert plan['master_byte_enable']['kind'] == 'size_derived_lanes'
    assert plan['master_byte_enable']['lane_pattern'] == [1, 2, 4, 8]
    assert plan['master_byte_enable']['beats_per_word'] == 4
    assert plan['expected_reads'] == plan['expected_writes'] == 16
    header = render_bindings(BYTEEN_CONFIG, cpu_document(), ip_document(),
                             dma_document(), LAYOUT, cpu_profile(), irq=IRQ,
                             dma=plan, dma_irq=plan['irq'])
    assert '#define DMA_START_WORD 3342336u' in header
    assert '#define DMA_MASTER_PARTIAL 1' in header
    assert '#define DMA_MASTER_BEATS_PER_WORD 4u' in header
    assert '#define DMA_MASTER_LANE_COUNT 4u' in header
    assert '#define DMA_MASTER_LANES_PER_BEAT 1u' in header
    assert '#define DMA_EXPECTED_WRITES 16u' in header


def test_a_start_word_the_plan_does_not_encode_is_refused():
    with pytest.raises(ValueError, match='start-word'):
        declaration(dict(BYTEEN_CONFIG, dma_start_word=0))
    # A non-incrementing destination is encodable by wbdmac's keyed start word,
    # and the entry carries the plan's word instead of a fixed one.
    from myfuzz.composition.component_profile import load_component_profile
    wbdmac = json.loads(
        (ROOT / 'configs/scenarios/inprocess-generality-wbdmac-f1f6-dma-decl.json')
        .read_text())
    plan = dma_declaration(dict(wbdmac, dma_increment_destination=False),
                           load_component_profile(ROOT / wbdmac['dma_profile']),
                           dma_artifact(master_sel=False))
    assert plan['start_word'] & (1 << 28)
    assert plan['plan']['increment_destination'] is False
    # ZipDMA encodes the same fact in control bit 22 (s2mm_inc_n); the plan's
    # word is what the header renders, so the host never assumes increments.
    fixed = declaration(dict(CONFIG, dma_increment_destination=False))
    assert fixed['start_word'] == 0x00400000
    assert fixed['plan']['start']['increment_destination_bit'] == 22


def test_wbdmac_refuses_a_partial_byte_enable_by_name():
    from myfuzz.composition.component_profile import load_component_profile
    wbdmac = json.loads(
        (ROOT / 'configs/scenarios/inprocess-generality-wbdmac-f1f6-dma-decl.json')
        .read_text())
    profile = load_component_profile(ROOT / wbdmac['dma_profile'])
    with pytest.raises(ValueError, match='master-byte-enable-unsupported|wbdmac'):
        dma_declaration(dict(wbdmac, dma_transfer_size_bytes=1), profile,
                        dma_artifact(master_sel=False))


def test_a_byte_enable_case_shows_every_lane_once_and_untouched_neighbours():
    plan = declaration(BYTEEN_CONFIG)
    case = parse_case_line(BYTEEN_CASE_LINE, flows={'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2,
                                                    'F5': 3, 'F6': 4})
    assert case['dma_sel_partial'] == 16 and case['dma_sel_full'] == 0
    assert case['dma_writes'] == plan['expected_writes']
    record = parse_record(case['record'], windows=WINDOWS, arity=flow_arity(IRQ, plan))
    assert correspondence(record, case, layout=LAYOUT, windows=WINDOWS, irq=IRQ,
                          dma=plan) is None
    # A host (or a saved line) that reports a skipped byte lane is a mismatch.
    bad = dict(case, dma_lane_missing=1, dma_lane_written=15)
    assert 'every byte of the declared destination block' in correspondence(
        record, bad, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)
    # A transfer that wrote one byte twice is a mismatch as well.
    twice = dict(case, dma_lane_extra=1)
    assert 'written twice' in correspondence(
        record, twice, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)
    # So is a transfer that stroked a byte outside its declared block, and a
    # transfer whose strobe landed on a guard word.
    outside = dict(case, dma_bytes_outside_block=1)
    assert 'outside the declared destination block' in correspondence(
        record, outside, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)
    guard = dict(case, dma_guard_hi=0)
    assert 'guard word' in correspondence(
        record, guard, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)


def test_a_declared_response_delay_is_only_a_pass_when_it_was_observed():
    plan = declaration(DELAY_CONFIG)
    assert plan['delay_ticks'] == 2
    header = render_bindings(DELAY_CONFIG, cpu_document(), ip_document(),
                             dma_document(), LAYOUT, cpu_profile(), irq=IRQ,
                             dma=plan, dma_irq=plan['irq'])
    assert '#define DMA_RESPONSE_DELAY 2u' in header
    assert '#define DMA_STALL_EXPECT_MIN 2u' in header
    assert '#define DMA_STALL_EXPECT_MAX 2u' in header
    case = parse_case_line(DELAY_CASE_LINE, flows={'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2,
                                                   'F5': 3, 'F6': 4})
    assert case['dma_delay_evidence'] == 'observed'
    assert case['dma_wait_min'] == 3 and case['dma_max_consecutive_stalls'] >= 3
    record = parse_record(case['record'], windows=WINDOWS, arity=flow_arity(IRQ, plan))
    assert correspondence(record, case, layout=LAYOUT, windows=WINDOWS, irq=IRQ,
                          dma=plan) is None
    # A line that declared the delay but never measured it cannot be a pass.
    unmeasured = dict(case, dma_delay_evidence='unknown')
    assert 'not observed' in correspondence(
        record, unmeasured, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)
    # And a wait shorter than the declaration is a mismatch too.
    short = dict(case, dma_wait_min=2, dma_max_consecutive_stalls=2)
    assert 'shorter than the declaration' in correspondence(
        record, short, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=plan)


def test_the_cpp_host_reads_the_plan_macros_instead_of_its_own_bounds():
    """Host-mirror check: the C++ loop consumes what the entry renders.

    The model link is a separate program, so this reads the one host source and
    asserts the plan-derived macros are what drive the record shape, the start
    write, the lane mask and the declared delay.  A host that hard-coded four
    words, a SEL of 0xf or a zero delay would fail here instead of silently
    ignoring the header.
    """
    source = (ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp').read_text()
    # The record length is the header's block, and the record echo loops over it.
    assert 'case kF6: return DMA_BLOCK_WORDS;' in source
    assert 'for (unsigned index = 0; index < kDmaBlockWords; ++index)' in source
    assert 'for (unsigned index = 1; index < record.words; ++index)' in source
    # The start write is compared with the plan's word, and the pass criterion
    # requires the device to have received exactly that word.
    assert 'else if (control.value == kDmaStartWord)' in source
    assert 'observation.dma_start_write == kDmaStartWord' in source
    # Byte enables: the declared lane pattern is enforced, and a lane mask the
    # plan does not declare aborts the run instead of being masked away.
    assert '#if DMA_MASTER_PARTIAL' in source
    assert 'DMA_MASTER_LANES_PER_BEAT' in source
    assert 'presented an undeclared byte enable' in source
    assert 'memory.write(master_address, master_value, master_select);' in source
    # Backpressure: the declared delay is added to the pending response and the
    # per-response wait is measured before any pass is claimed.
    assert 'master.delay = unsigned(DMA_RESPONSE_DELAY)' in source
    assert 'const unsigned waited = unsigned(tick - master.accept_tick);' in source
    assert 'observation.dma_wait_min >= DMA_RESPONSE_DELAY + 1' in source
    assert 'dma_delay_evidence(observation)' in source


def test_a_backpressure_pattern_the_host_would_only_partly_apply_is_refused():
    for bad, match in ((dict(pattern='periodic_stall'), 'unsupported-dma-backpressure'),
                       (dict(applies_to=['read']), 'applies_to'),
                       (dict(max_consecutive_ticks=1), 'max_consecutive_ticks')):
        with pytest.raises(ValueError, match=match):
            declaration(dict(DELAY_CONFIG,
                             dma_backpressure=dict(DELAY_CONFIG['dma_backpressure'], **bad)))


def test_a_route_this_build_cannot_execute_is_refused_by_name():
    # The checked-in FIFO scenario declares target index 1 (the PULP SPI) of a
    # two-target build.  This declaration has only the timer, so the route names
    # a target this build does not have and the entry refuses F6 by name before
    # any model is built - it never runs the RAM-only path as if it were the
    # declared FIFO transfer.
    with pytest.raises(ValueError, match='unsupported-dma'):
        declaration(FIFO_CONFIG)
    timer_row = dict(index=0, name='timer', window=dict(WINDOWS['ip_targets'][0]
                                                        if 'ip_targets' in WINDOWS
                                                        else dict(base=WINDOWS['ip_base'],
                                                                  size=WINDOWS['ip_size'])),
                     profile=CONFIG['source_profile'], protocol='apb3')
    with pytest.raises(ValueError, match='unsupported-dma'):
        declaration(FIFO_CONFIG, targets=[timer_row])
    # A read route is not a shape this host drives: the C++ master path only
    # presents a write on the routed target's request port.
    read_route = dict(FIFO_CONFIG,
                      dma_route=dict(FIFO_CONFIG['dma_route'], direction='read'))
    with pytest.raises(ValueError, match='unsupported-dma-route|unsupported-dma-declaration'):
        declaration(read_route)


def test_a_plan_this_increment_cannot_execute_is_refused_by_name():
    with pytest.raises(ValueError, match='error-injection'):
        declaration(dict(CONFIG, dma_error_injection=True))
    with pytest.raises(ValueError, match='outstanding-beyond-one'):
        declaration(dict(CONFIG, dma_max_outstanding=2))
    with pytest.raises(ValueError, match='response-delay|not-declarable'):
        declaration(dict(CONFIG, dma_response_delay=4096))


# --- the one RAM image ----------------------------------------------------

def test_the_image_holds_every_fixed_region_at_its_declared_address():
    firmware = build_firmware(LAYOUT, irq=IRQ, dma=DMA)
    images = firmware['images']
    assert set(images) == {LAYOUT['boot'], LAYOUT['vector'], LAYOUT['handler'],
                           LAYOUT['main'], LAYOUT['slot'], LAYOUT['data_base'],
                           LAYOUT['handler_block']}
    assert len(images[LAYOUT['handler_block']]) == HANDLER_BLOCK_BYTES
    flag_cell = HB_FLAG - HB
    assert int.from_bytes(images[LAYOUT['handler_block']][flag_cell:flag_cell + 4], 'little') \
        == LAYOUT['flag']
    assert len(images[LAYOUT['slot']]) == 8
    assert images[LAYOUT['slot']][:4] == b'\x13\x00\x00\x00'
    assert firmware['handler_words'] >= 12
    assert firmware['slot_return'] > LAYOUT['main']


def test_the_image_is_identical_for_every_case():
    first = build_firmware(LAYOUT, irq=IRQ, dma=DMA)
    second = build_firmware(build_layout(WINDOWS, BOOT), irq=IRQ, dma=DMA)
    assert first['images'] == second['images']


def test_a_layout_that_cannot_hold_the_images_is_refused():
    cramped = dict(LAYOUT, handler_block=LAYOUT['data_base'])
    with pytest.raises(ValueError, match='overlaps|leaves'):
        build_firmware(cramped, irq=IRQ, dma=DMA)


def test_the_handler_block_is_the_mailbox_pointer_offset_the_isr_reads():
    assert HB == 0x40
    assert HB_STATUS == HB
    assert HB_FLAG == HB + 16


# --- the binding header ---------------------------------------------------

def cpu_document(**overrides):
    exports = [dict(physical_port='rvfi_' + role, direction='output',
                    runtime_name='rvfi_' + role)
               for role in ('valid', 'trap', 'insn', 'pc_rdata', 'order', 'rd_addr',
                            'rd_wdata')]
    exports.append(dict(physical_port='rvfi_ext_expanded_insn_valid', direction='output',
                        runtime_name='rvfi_expanded_valid'))
    exports.append(dict(endpoint_id='processor.interrupts', role='external', direction='input',
                        width=1, runtime_name='irq_i'))
    document = dict(kind='obi_cpu', module_name='local_cpu', clock_schedule=clock(50),
                    physical_exports=exports,
                    runtime_ports=[dict(name='probe_irq_taken_pre', direction='output')],
                    backend_ports=[dict(channel=channel, role=role, name=channel + '_' + role)
                                   for channel in ('i', 'd') for role in ROLES],
                    plan=dict(timing=dict(reset_assert_ticks=8, reset_release_ticks=8)))
    document.update(overrides)
    return document


def ip_document(**overrides):
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata', 'pslverr')}
    document = dict(kind='apb3_register_observe', module_name='local_ip', clock_schedule=clock(50),
                    base_protocol_trace=dict(protocol='apb3', signals=signals),
                    physical_exports=[dict(physical_port='irq_o', direction='output', width=4,
                                           bit_lo=0, bit_hi=3, runtime_name='irq_wide')],
                    backend_ports=[dict(channel='reg', role=role, name='reg_' + role)
                                   for role in ROLES],
                    plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))
    document.update(overrides)
    return document


def dma_document(**overrides):
    document = dma_artifact()
    document.update(module_name='local_dma', clock_schedule=clock(1),
                    physical_exports=[dict(physical_port='o_interrupt', direction='output',
                                           width=1, bit_lo=0, bit_hi=0,
                                           runtime_name='dma_irq')],
                    plan=dict(timing=dict(reset_assert_ticks=8, reset_release_ticks=8)))
    document.update(overrides)
    return document


def clock(frequency):
    return dict(phase_policy='all_low_then_half_period_toggle',
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=frequency)])


ROLES = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
         'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')


def cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['cpu_profile'])


def test_the_header_binds_models_and_their_declared_pins():
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert '#define HAVE_DMA 1' in header
    assert '#define HAVE_IRQ_LINKS 1' in header
    assert '#define HAVE_CPU_TAKE 1' in header
    assert '#define IRQ_SOURCE_COUNT 2' in header
    assert 'X((uint64_t(ip.irq_wide)), 0u, 16u, 0u)' in header
    assert 'X((uint64_t(dma.dma_irq)), 0u, 0u, 0u)' in header
    assert f'#define DMA_BASE 0x{LAYOUT["dma_base"]:x}u' in header
    assert f'#define TRIGGER_COUNT {len(TRIGGER_OFFSETS)}u' in header
    assert f'#define IP_STATUS_OFFSET {IRQ["status_offset"]}u' in header
    assert f'#define FLAG_ADDRESS {LAYOUT["flag"]}u' in header
    assert '#define CPU_IRQ irq_i' in header
    assert '#define IP_TRACE_PREADY trace_pready' in header
    # The event layer is on only when the pins exist, and every switch says so.
    assert '#define HAVE_EVENT_LAYER 1' in header
    assert '#define HAVE_RVFI_WRITEBACK 1' in header
    assert '#define HAVE_RVFI_EXPANDED 1' in header
    assert '#define HAVE_APB_PSLVERR 1' in header
    assert '#define IP_TRACE_PSLVERR trace_pslverr' in header
    assert '#define CPU_RVFI_ORDER rvfi_order' in header
    assert '#define CPU_RVFI_RD_ADDR rvfi_rd_addr' in header
    assert '#define CPU_RVFI_RD_WDATA rvfi_rd_wdata' in header
    assert '#define IP_STATUS_KIND "count"' in header
    assert '#define DMA_STATUS_KIND "status"' in header
    assert '#define IP_CAUSE_DECLARED 0' in header
    assert '#define DMA_CLEAR_DECLARED 1' in header
    assert '#define DMA_CLEAR_MASK 0x80000000u' in header
    assert f'#define DMA_CTL_BEFORE_ADDRESS {LAYOUT["ctl_before"]}u' in header
    assert f'#define DMA_BUSY_BIT {DMA_BUSY_BIT}u' in header
    assert f'#define DMA_ERR_BIT {DMA_ERR_BIT}u' in header
    assert '#define IRQ_DMA_LINK_INDEX 1u' in header


def test_an_undeclared_dma_clear_is_stated_as_not_expected():
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ,
                             dma=dict(DMA, clear=None), dma_irq=DMA['irq'])
    assert '#define DMA_CLEAR_DECLARED 0' in header
    assert '#define DMA_CLEAR_MASK 0u' in header


def test_a_cpu_without_writeback_pins_reports_the_event_as_missing():
    exports = [row for row in cpu_document()['physical_exports']
               if row.get('physical_port') not in ('rvfi_order', 'rvfi_rd_addr',
                                                   'rvfi_rd_wdata',
                                                   'rvfi_ext_expanded_insn_valid')]
    header = render_bindings(CONFIG, cpu_document(physical_exports=exports), ip_document(),
                             dma_document(), LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                             dma_irq=DMA['irq'])
    assert '#define HAVE_RVFI_WRITEBACK 0' in header
    assert '#define HAVE_RVFI_EXPANDED 0' in header
    assert 'CPU_RVFI_ORDER' not in header


def test_an_apb_trace_without_pslverr_keeps_the_error_channel_unknown():
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')}
    header = render_bindings(CONFIG, cpu_document(),
                             ip_document(base_protocol_trace=dict(protocol='apb3',
                                                                  signals=signals)),
                             dma_document(), LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                             dma_irq=DMA['irq'])
    assert '#define HAVE_APB_PSLVERR 0' in header
    assert 'IP_TRACE_PSLVERR' not in header


def test_a_clock_rate_mismatch_is_normalized_or_refused_by_name():
    # 50:1 is a whole divider, so the per-model plan states it instead of falling
    # back to the assumption: the DMA half period is 50 reference half periods and
    # its clock still starts low and rises at its own half period.
    header = render_bindings(dict(CONFIG, assume_single_clock=False), cpu_document(),
                             ip_document(), dma_document(), LAYOUT, cpu_profile(),
                             irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert '#define CLOCK_PLAN_MODE "per_model_ratio"' in header
    assert '#define CLOCK_IP_HALF_TICKS 1u' in header
    assert '#define CLOCK_DMA_HALF_TICKS 50u' in header
    # A declared rate that is not an integer divider of the reference CPU is
    # placed on the exact common grid rather than refused or rounded: 50 Hz
    # beside 30 Hz and a 1 Hz DMA has lcm 150, so the reference CPU half period
    # is 3 grid steps, the target's is 5 and the DMA's is 150, and one host tick
    # advances 6.  (Before the P2 rational grid this pair was refused by name;
    # the refusal that remains is the unusable grid below.)
    header = render_bindings(dict(CONFIG, assume_single_clock=False), cpu_document(),
                             ip_document(clock_schedule=clock(30)), dma_document(),
                             LAYOUT, cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert '#define CLOCK_PLAN_MODE "per_model_ratio"' in header
    assert '#define CLOCK_GRID_LCM_HZ 150u' in header
    assert '#define CLOCK_GRID_STEPS_PER_TICK 6u' in header
    assert '#define CLOCK_CPU_HALF_TICKS 3u' in header
    assert '#define CLOCK_IP_HALF_TICKS 5u' in header
    assert '#define CLOCK_DMA_HALF_TICKS 150u' in header
    # A ratio beyond the phase-grid bound is refused by name, instead of asking
    # the host to run 50 million phases for one DMA cycle.
    with pytest.raises(ValueError, match='phase-grid bound'):
        render_bindings(dict(CONFIG, assume_single_clock=False),
                        cpu_document(clock_schedule=clock(50_000_000)), ip_document(),
                        dma_document(clock_schedule=clock(1)), LAYOUT, cpu_profile(),
                        irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    # The explicit fallback still renders the historical one-tick header, and says
    # that the equal period is assumed rather than derived.
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert header.count('#define CPU_RESET_ASSERT') == 1
    assert header.count('#define IP_RESET_ASSERT') == 2  # flat alias and target 0
    assert header.count('#define DMA_RESET_ASSERT') == 1
    assert '#define CLOCK_PLAN_MODE "assumed_single_clock"' in header
    assert '#define CLOCK_ASSUMED_SINGLE 1' in header


@pytest.mark.parametrize('override,which,match', [
    ({'kind': 'axi_cpu'}, 'cpu', 'unsupported-cpu-kind'),
    ({'kind': 'apb3_register_observe'}, 'dma', 'requires-wishbone-dma'),
])
def test_the_header_refuses_the_wrong_component_kinds(override, which, match):
    documents = dict(cpu=cpu_document(), ip=ip_document(), dma=dma_document())
    documents[which] = dict(documents[which], **override)
    with pytest.raises(ValueError, match=match):
        render_bindings(CONFIG, documents['cpu'], documents['ip'], documents['dma'],
                        LAYOUT, cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])


def test_the_header_refuses_a_cpu_without_a_take_probe():
    document = cpu_document(runtime_ports=[])
    header = render_bindings(CONFIG, document, ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert '#define HAVE_CPU_TAKE 0' in header


def test_the_header_refuses_an_incomplete_apb_trace():
    signals = {role: 'trace_' + role for role in ('psel', 'penable', 'pready', 'pwrite', 'paddr')}
    with pytest.raises(ValueError, match='APB trace lacks'):
        render_bindings(CONFIG, cpu_document(),
                        ip_document(base_protocol_trace=dict(protocol='apb3', signals=signals)),
                        dma_document(), LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                        dma_irq=DMA['irq'])


# --- run log ------------------------------------------------------------

F5_LINE = ('case 4 observations_passed flow F5 record F5:00000001:00000000:ffffffff ticks 140 '
           'seconds 0.000164291 i_fetches 58 d_reads 9 d_writes 8 apb_reads 1 apb_writes 3 '
           'retires 46 rvfi_writebacks 24 rvfi_order_monotonic 1 traps 0 bus_errors 0 '
           'trigger_writes 3 apb_read_offset 0x00000000 apb_read_data 0x00000010 '
           'apb_last_write_offset 0x00000000 apb_last_write_data 0xffffffff irq_edges 1 '
           'irq_high_ticks 1 device_high_ticks 1 delivered_high_ticks 16 irq_takes 1 '
           'isr_result 0x00000010 isr_flag 1 isr_read_addr 0x40001000 '
           'isr_read_value 0x00000010 isr_read_register_kind count isr_cause unknown')
F6_LINE = ('case 5 observations_passed flow F6 record '
           'F6:0110c000:08000000:deadbeef:12345678 ticks 279 seconds 0.000407784 '
           'i_fetches 131 d_reads 14 d_writes 18 apb_reads 0 apb_writes 0 retires 109 '
           'rvfi_writebacks 66 rvfi_order_monotonic 1 traps 0 bus_errors 0 dma_reads 4 '
           'dma_writes 4 dma_first_read_addr 0x00016000 dma_first_read_value 0x0110c000 '
           'dma_last_write_addr 0x0001700c dma_last_write_value 0x12345678 '
           'ctl_config_writes 3 ctl_start_writes 1 ctl_clear_writes 1 ctl_reads 2 '
           'ctl_status 0x00000040 irq_edges 1 irq_high_ticks 34 device_high_ticks 34 '
           'delivered_high_ticks 34 irq_takes 1 wait_timeout 0 isr_result 0x00000040 '
           'isr_flag 1 ctl_reads_before_start 1 busy_before 0 err_before 0 busy_after 0 '
           'err_after 0 dma_clear_declared 1 dma_status_kind status dma_done_tick 209 '
           'dma_start_word 0x00000000 dma_block_words 4 dma_master_beats_per_word 1 '
           'dma_master_partial 0 dma_lane_count 1 dma_lane_masks 0x0000000f '
           'dma_expected_reads 4 dma_expected_writes 4 dma_start_write 0x00000000 '
           'dma_response_delay_declared 0 dma_acks 8 dma_delayed_acks 1 dma_wait_min 1 '
           'dma_wait_max 2 dma_wait_total 9 dma_stall_ticks 9 '
           'dma_max_consecutive_stalls 2 dma_sel_full 4 dma_sel_partial 0 '
           'dma_sel_undeclared 0 dma_read_lane_partial 0 dma_lane_written 16 '
           'dma_lane_missing 0 dma_lane_extra 0 dma_bytes_outside_block 0 dma_guard_lo '
           '0xa5a5a5a5 dma_guard_hi 0xa5a5a5a5 dma_delay_evidence not_declared '
           'dma_stall_expectation none_declared dma_stall_expect_min 0 '
           'dma_stall_expect_max 0 dst0 0x0110c000 dst1 0x08000000 dst2 0xdeadbeef dst3 '
           '0x12345678')
SUMMARY_LINE = ('summary observations_passed cases 6 ticks 534 instruction_fetches 243 '
                'ram_reads 34 ram_writes 27 apb_transfers 5 apb_reads 1 apb_writes 4 '
                'irq_high_ticks 36 device_high_ticks 36 delivered_high_ticks 51 '
                'irq_edges 2 irq_takes 2 irq_delivery observed irq_sources 2 dma observed '
                'dma_reads 4 dma_writes 4 dma_control_writes 5 '
                'instruction_fetch_evidence observed retirement_evidence observed '
                'ifetch_events 243 ifetch_evidence observed retirements 189 '
                'rvfi_writebacks 104 rvfi_order_monotonic 1 rvfi_writeback_evidence observed '
                'traps 0 trap_evidence observed expanded_insn_events 0 '
                'expanded_insn_evidence missing apb_errors 0 bus_error unknown '
                'bus_error_apb observed bus_error_obi_i unknown bus_error_obi_d unknown '
                'bus_error_mwb unknown irq_cause unknown irq_cause_bits none_declared '
                'dma_block_words 4 dma_start_word 0x00000000 '
                'dma_master_beats_per_word 1 dma_master_partial 0 '
                'dma_lane_masks 0x0000000f dma_expected_reads 4 dma_expected_writes 4 '
                'dma_response_delay_declared 0 dma_f6_cases 1 dma_acks 8 '
                'dma_delayed_acks 1 dma_stall_ticks 9 dma_max_consecutive_stalls 2 '
                'dma_sel_full 4 dma_sel_partial 0 dma_lane_written 16 '
                'dma_lane_missing 0 dma_lane_extra 0 dma_bytes_outside_block 0 '
                'dma_delay_evidence not_declared '
                'dma_done_events 1 dma_done_evidence observed '
                'dma_done_derivation last_master_write_ack+irq_edge dma_busy_port missing '
                'dma_busy_high_reads 0 dma_busy_evidence missing '
                'dma_status_bits undeclared_in_profile failures 0 '
                'runtime_seconds 0.002221501')
IFETCH_LINES = ['ifetch 0 0x00010080 0x00013437',
                'ifetch 2 0x00010084 0x00040413',
                'ifetch 4 0x00010088 0x000101b7']
RVFI_LINES = ['rvfi 3 1 8 0x00013000',
              'rvfi 5 2 8 0x00013000',
              'rvfi 7 3 3 0x00010000']
BUS_UNKNOWN_LINES = ['bus_error unknown obi_i', 'bus_error unknown obi_d',
                     'bus_error unknown mwb']
TRAP_LINE = 'trap 61 pc 0x00012000 insn 0x2ab00693 cause unknown'
DMA_DONE_LINE = 'dma_done 471'


def test_the_two_new_flows_parse_from_the_real_line_shape():
    f5 = parse_case_line(F5_LINE, flows=ARITY)
    assert f5['flow'] == 'F5' and f5['apb_read_data'] == 0x10 and f5['isr_flag'] == 1
    assert f5['record'] == 'F5:00000001:00000000:ffffffff'
    assert f5['device_high_ticks'] == 1 and f5['delivered_high_ticks'] == 16
    assert f5['isr_read_register_kind'] == 'count' and f5['isr_cause'] == 'unknown'
    f6 = parse_case_line(F6_LINE, flows=ARITY)
    assert f6['dma_reads'] == 4 and f6['dst3'] == 0x12345678
    assert f6['ctl_reads'] == 2 and f6['ctl_reads_before_start'] == 1
    assert f6['busy_before'] == 0 and f6['busy_after'] == 0 and f6['err_after'] == 0
    assert f6['dma_clear_declared'] == 1 and f6['dma_done_tick'] == 209
    summary = parse_summary_line(SUMMARY_LINE)
    assert summary['status'] == 'observations_passed'
    assert summary['irq_delivery'] == 'observed'
    assert summary['irq_edges'] == 2
    assert summary['device_high_ticks'] == 36 and summary['delivered_high_ticks'] == 51
    assert summary['retirements'] == 189 and summary['rvfi_writebacks'] == 104
    assert summary['bus_error'] == 'unknown'
    assert summary['bus_error_apb'] == 'observed'
    assert summary['irq_cause'] == 'unknown'
    assert summary['dma_busy_evidence'] == 'missing'
    assert summary['dma_done_evidence'] == 'observed'


# --- event lines ---------------------------------------------------------

def test_an_ifetch_line_carries_the_accepted_address_and_word():
    event = parse_event_line(IFETCH_LINES[0])
    assert event == dict(kind='ifetch', tick=0, address=0x00010080, word=0x00013437)


def test_an_rvfi_line_carries_order_and_the_register_writeback():
    event = parse_event_line(RVFI_LINES[0])
    assert event['kind'] == 'rvfi' and event['order'] == 1
    assert event['rd_addr'] == 8 and event['rd_wdata'] == 0x00013000


def test_a_trap_line_is_an_event_not_an_abort():
    event = parse_event_line(TRAP_LINE)
    assert event['kind'] == 'trap' and event['tick'] == 61
    assert event['pc'] == 0x00012000 and event['insn'] == 0x2AB00693
    assert event['cause'] == 'unknown'


def test_bus_error_lines_cover_the_observed_and_the_unknown_form():
    assert parse_event_line('bus_error 7 apb 0x00000004') == dict(
        kind='bus_error', tick=7, channel='apb', address=4)
    unknown = parse_event_line(BUS_UNKNOWN_LINES[0])
    assert unknown['kind'] == 'bus_error' and unknown['tick'] is None
    assert unknown['channel'] == 'obi_i'
    assert parse_event_line(DMA_DONE_LINE) == dict(kind='dma_done', tick=471)


@pytest.mark.parametrize('line,match', [
    ('ifetch 0 0x00010080', 'tick, address and word'),
    ('ifetch 0 10080 0x00013437', 'hexadecimal word'),
    ('rvfi 3 1 8', 'order, rd_addr and rd_wdata'),
    ('rvfi 3 x 8 0x00013000', 'rvfi order'),
    ('trap 1 pc 0x2 insn 0x3', 'pc, insn and cause'),
    ('bus_error 1 apb', 'tick, a channel and an address'),
    ('bus_error 1 bogus 0x0', 'not a valid channel|channel'),
    ('bus_error 4', 'tick, a channel and an address'),
    ('dma_done', 'exactly one tick'),
    ('retire 3 0x1 0x2', 'not an event line'),
])
def test_malformed_event_lines_are_refused(line, match):
    with pytest.raises(ValueError, match=match):
        parse_event_line(line)


def test_the_event_summary_counts_every_family_and_its_tri_state():
    log = '\n'.join(BUS_UNKNOWN_LINES + IFETCH_LINES + RVFI_LINES + [F5_LINE, F6_LINE,
                                                                     TRAP_LINE,
                                                                     DMA_DONE_LINE,
                                                                     SUMMARY_LINE]) + '\n'
    events = summarize_events(log)
    assert events['counts'] == dict(ifetch=3, rvfi=3, trap=1, bus_error=3, dma_done=1,
                                    axi=0)
    assert events['lines'] == 11
    assert events['declarations']['bus_error'] == 3
    assert events['bus_error_unknown_channels'] == ['mwb', 'obi_d', 'obi_i']
    assert events['rvfi_writebacks'] == 3 and events['rvfi_order_monotonic'] is True
    assert events['traps'][0]['tick'] == 61 and events['dma_done'][0]['tick'] == 471
    # The first bucket holds everything before case index 4, so the F5 bucket is
    # the one before its own line and the F6 bucket is the trailing one.
    assert events['per_case'][0] == dict(ifetch=3, rvfi=3, trap=0, bus_error=0, dma_done=0,
                                         axi=0)
    assert events['per_case'][1] == dict(ifetch=0, rvfi=0, trap=0, bus_error=0, dma_done=0,
                                         axi=0)
    assert events['trailing']['dma_done'] == 1 and events['trailing']['trap'] == 1
    assert events['evidence']['ifetch'] == 'observed'
    assert events['evidence']['dma_done'] == 'observed'


def test_a_log_without_retirements_reports_missing_evidence():
    events = summarize_events(SUMMARY_LINE + '\n')
    assert events['counts'] == dict(ifetch=0, rvfi=0, trap=0, bus_error=0, dma_done=0,
                                    axi=0)
    assert events['evidence']['rvfi'] == 'missing'
    assert events['evidence']['trap'] == 'missing'
    assert events['evidence']['rvfi_writeback'] == 'missing'


def test_the_event_document_compares_the_log_with_the_summary():
    log = '\n'.join(BUS_UNKNOWN_LINES + IFETCH_LINES + RVFI_LINES + [TRAP_LINE, DMA_DONE_LINE,
                                                                     F5_LINE, F6_LINE,
                                                                     SUMMARY_LINE]) + '\n'
    document = event_document(summarize_events(log), parse_summary_line(SUMMARY_LINE))
    assert document['evidence']['bus_error_channels'] == dict(
        apb='observed', axi='missing', obi_i='unknown', obi_d='unknown', mwb='unknown',
        wb='missing', tlul='missing', ahb='missing')
    assert document['evidence']['bus_error'] == 'unknown'
    assert document['evidence']['expanded_insn'] == 'missing'
    assert document['evidence']['dma_busy'] == 'missing'
    assert document['conflicts'] == []


def test_a_summary_that_claims_more_than_the_log_shows_is_a_conflict():
    quoted = SUMMARY_LINE.replace('retirement_evidence observed',
                                  'retirement_evidence missing')
    document = event_document(summarize_events(IFETCH_LINES[0] + '\n' + RVFI_LINES[0] + '\n' +
                                               quoted + '\n'),
                              parse_summary_line(quoted))
    assert 'rvfi' in document['conflicts']


@pytest.mark.parametrize('line,match', [
    ('case 0 observations_passed flow F7 ticks 1', 'supported flow tag'),
    ('case 0 exploded flow F1 ticks 1', 'unsupported case status'),
    ('case x observations_passed flow F1 ticks 1', 'index is not an integer'),
    ('case 0 observations_passed flow F1 ticks', 'key/value pairs'),
    ('case 0 observations_passed flow F1 ticks 1 ticks 2', 'duplicate observation field'),
    ('observation 0 observations_passed flow F1', 'not a case line'),
    ('summary observations_passed cases 1 seconds nope', 'invalid seconds value'),
    ('summary observations_passed cases', 'key/value pairs'),
    ('summary', 'not a summary line'),
])
def test_bad_log_lines_are_refused(line, match):
    parser = parse_summary_line if line.startswith('summary') else \
        (lambda text: parse_case_line(text, flows=ARITY))
    with pytest.raises(ValueError, match=match):
        parser(line)


def test_the_log_reader_needs_exactly_one_summary():
    with pytest.raises(ValueError, match='no summary line'):
        parse_run_log('case 0 observations_passed flow F1 ticks 1\n', flows=ARITY)
    with pytest.raises(ValueError, match='duplicate summary line'):
        parse_run_log(SUMMARY_LINE + '\n' + SUMMARY_LINE, flows=ARITY)
    parsed = parse_run_log('NEED_RECORD 0 tick 3\nCASE_INSTALLED 0\n' + F5_LINE + '\n' +
                          F6_LINE + '\n' + SUMMARY_LINE + '\n', flows=ARITY)
    assert [case['flow'] for case in parsed['cases']] == ['F5', 'F6']
    assert parsed['installed'] == [0]


def test_unobserved_facts_stay_unknown_in_the_case_document():
    document = case_document(record('F5:00000001:00000000:ffffffff'),
                             dict(index=0, flow='F5', status='failed',
                                  record='F5:00000001:00000000:ffffffff'))
    assert document['observation']['isr_flag'] == 'unknown'
    assert document['observation']['irq_takes'] == 'unknown'
    assert document['seconds'] == 'unknown'
    assert document['ticks'] == 'unknown'


# --- correspondence -----------------------------------------------------

MATCHED = {
    'F1:2ab00693': dict(flow='F1', fetch=LAYOUT['slot'], retire_pc=LAYOUT['slot'],
                        retire_insn=0x2AB0_0693, successor_pc=LAYOUT['slot'] + 4),
    'F2:00014000': dict(flow='F2', read_addr=0x0001_4000, read_value=0xDEAD_BEEF,
                        echo_value=0xDEAD_BEEF, read_from='ram', apb_reads=0),
    'F3:00014004:0badf00d': dict(flow='F3', write_addr=0x0001_4004, write_value=0x0BAD_F00D,
                                 write_be=15, ram_after=0x0BAD_F00D),
    'F4:40001008:0fffffff': dict(flow='F4', mmio_addr=WINDOWS['ip_base'] + 8,
                                 mmio_value=0x0FFF_FFFF, apb_offset=8,
                                 apb_pwdata=0x0FFF_FFFF, apb_pready=1, apb_writes=1),
    'F5:00000001:00000000:ffffffff': dict(
        flow='F5', apb_writes=3, apb_reads=1, apb_read_offset=IRQ['status_offset'],
        apb_read_data=0x1D, apb_last_write_offset=TRIGGER_OFFSETS[-1],
        apb_last_write_data=0xFFFF_FFFF, trigger_writes_declared=3,
        trigger_writes_observed=3, clear_writes=0,
        last_trigger_offset=TRIGGER_OFFSETS[-1], last_trigger_data=0xFFFF_FFFF,
        last_clear_offset=0, last_clear_data=0,
        isr_result=0x1D, isr_flag=1, irq_edges=1,
        irq_takes=1, device_high_ticks=1, delivered_high_ticks=16,
        isr_read_addr=WINDOWS['ip_base'] + IRQ['status_offset'], isr_read_value=0x1D,
        isr_read_register_kind=IRQ['status_kind'], isr_cause='unknown'),
    'F6:0110c000:08000000:deadbeef:12345678': dict(
        flow='F6', dma_reads=4, dma_writes=4, dma_first_read_addr=LAYOUT['dma_source'],
        dma_last_write_addr=LAYOUT['dma_destination'] + 12, dst0=0x0110_C000,
        dst1=0x0800_0000, dst2=0xDEAD_BEEF, dst3=0x1234_5678, ctl_config_writes=3,
        ctl_start_writes=1, ctl_clear_writes=1, ctl_reads=2, ctl_status=0x40,
        ctl_reads_before_start=1, busy_before=0, err_before=0, busy_after=0, err_after=0,
        dma_clear_declared=1, dma_status_kind=DMA['status_kind'], dma_done_tick=209,
        device_high_ticks=35, delivered_high_ticks=35,
        isr_result=0x40, isr_flag=1, irq_edges=1, irq_takes=1,
        # The declared transfer shape and the byte-enable/backpressure facts the
        # entry now checks.  A full-word four-word block writes 4 destination
        # beats, covers all 16 bytes once and leaves both guard words alone.
        dma_block_words=4, dma_expected_reads=4, dma_expected_writes=4,
        dma_start_word=DMA['start_word'], dma_start_write=DMA['start_word'],
        dma_master_partial=0, dma_lane_written=16, dma_lane_missing=0,
        dma_lane_extra=0, dma_bytes_outside_block=0,
        dma_guard_lo=DMA_DESTINATION_SENTINEL, dma_guard_hi=DMA_DESTINATION_SENTINEL,
        dma_sel_full=4, dma_sel_partial=0, dma_sel_undeclared=0,
        dma_response_delay_declared=0, dma_delay_evidence='not_declared'),
}


def check(text, **override):
    case = dict(MATCHED[text])
    case.update(override)
    case.setdefault('record', text)
    return correspondence(record(text), case, layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=DMA)


@pytest.mark.parametrize('text', list(MATCHED))
def test_a_matching_case_corresponds(text):
    assert check(text) is None, text


@pytest.mark.parametrize('text,override,reason', [
    ('F1:2ab00693', dict(record='F1:00000013'), 'echoed record differs'),
    ('F1:2ab00693', dict(flow='F2'), 'flow differs'),
    ('F1:2ab00693', dict(retire_insn=0x13), 'retired word differs'),
    ('F2:00014000', dict(read_addr=0x0001_4004), 'read address differs'),
    ('F3:00014004:0badf00d', dict(ram_after=0), 'did not commit'),
    ('F4:40001008:0fffffff', dict(apb_pwdata=0), 'target transfer differs'),
    ('F5:00000001:00000000:ffffffff', dict(trigger_writes_observed=2),
     'every declared trigger write'),
    ('F5:00000001:00000000:ffffffff', dict(last_trigger_data=0), 'trigger value differs'),
    ('F5:00000001:00000000:ffffffff', dict(apb_read_offset=4), 'status register'),
    ('F5:00000001:00000000:ffffffff', dict(isr_result=0xFFFFFFFF), 'store differs'),
    ('F5:00000001:00000000:ffffffff', dict(isr_read_addr=0), 'ISR read address'),
    ('F5:00000001:00000000:ffffffff', dict(isr_read_value=0), 'ISR read value'),
    ('F5:00000001:00000000:ffffffff', dict(isr_read_register_kind='status'), 'read kind'),
    ('F5:00000001:00000000:ffffffff', dict(isr_cause='timer0_overflow'), 'cause the device'),
    ('F5:00000001:00000000:ffffffff', dict(device_high_ticks=0), 'device level'),
    ('F5:00000001:00000000:ffffffff', dict(delivered_high_ticks=0), 'delivered level'),
    ('F5:00000001:00000000:ffffffff', dict(isr_flag=0), 'handler did not complete'),
    ('F5:00000001:00000000:ffffffff', dict(irq_takes=0), 'no sampled target IRQ edge'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(dma_writes=3), 'complete the declared block'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(dst2=0), 'destination word 2 differs'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(dma_first_read_addr=0), 'read start'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(ctl_start_writes=0), 'configure and start'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(ctl_clear_writes=0), 'clear write'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(dma_clear_declared=0), 'clear expectation'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(ctl_reads=1), 'once before the start'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(ctl_reads_before_start=0),
     'once before the start'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(busy_after=1), 'still busy'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(err_after=1), 'still busy'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(isr_result=0), 'status read and its store'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(dma_done_tick='unknown'), 'completion event'),
    ('F6:0110c000:08000000:deadbeef:12345678', dict(irq_edges=0), 'no sampled DMA IRQ edge'),
])
def test_a_case_that_does_not_belong_to_its_input_is_reported(text, override, reason):
    reason_text = check(text, **override)
    assert reason_text is not None and reason in reason_text


def test_a_declaration_without_a_clear_does_not_expect_one():
    """The host's clear expectation is the declaration's, not a constant."""
    no_clear = dict(DMA, clear=None)
    case = dict(MATCHED['F6:0110c000:08000000:deadbeef:12345678'],
                ctl_clear_writes=0, dma_clear_declared=0, record='F6:0110c000:08000000:deadbeef:12345678')
    assert correspondence(record('F6:0110c000:08000000:deadbeef:12345678'), case,
                          layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=no_clear) is None
    present = dict(case, ctl_clear_writes=1)
    assert 'declaration does not have' in correspondence(
        record('F6:0110c000:08000000:deadbeef:12345678'), present,
        layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=no_clear)


def test_status_requires_a_passing_host_summary_and_every_case():
    parsed = dict(cases=[dict(status='observations_passed')],
                  summary=dict(status='observations_passed'))
    passed = dict(returncode=0)
    assert final_status(passed, parsed, [record('F1:2ab00693')]) == 'observations_passed'
    assert final_status(dict(returncode=1), parsed, [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, None, [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, parsed,
                        [record('F1:2ab00693'), record('F3:00014004:00000001')]) == 'failed'
    assert final_status(passed, dict(parsed, summary=dict(status='failed')),
                        [record('F1:2ab00693')]) == 'failed'
    assert final_status(passed, dict(parsed, cases=[dict(status='failed')]),
                        [record('F1:2ab00693')]) == 'failed'


# --- the failure path: a failed case is recorded, not an abort -----------

FAILED_F6_LINE = F6_LINE.replace('case 5 observations_passed', 'case 5 failed').replace(
    'busy_after 0', 'busy_after 1')
FAILED_SUMMARY_LINE = SUMMARY_LINE.replace('summary observations_passed',
                                           'summary failed').replace('failures 0', 'failures 1')


def test_a_failed_case_keeps_the_later_cases_and_the_summary():
    log = '\n'.join(BUS_UNKNOWN_LINES + [IFETCH_LINES[0], RVFI_LINES[0], F5_LINE, TRAP_LINE,
                                         DMA_DONE_LINE, FAILED_F6_LINE,
                                         FAILED_SUMMARY_LINE]) + '\n'
    parsed = parse_run_log(log, flows=ARITY)
    assert [case['status'] for case in parsed['cases']] == ['observations_passed', 'failed']
    assert parsed['summary']['status'] == 'failed'
    assert parsed['summary']['failures'] == 1
    # The trap belongs to the failed case and stays an event line, not a crash.
    events = summarize_events(log)
    assert events['counts']['trap'] == 1
    assert events['per_case'][1]['trap'] == 1
    document = event_document(events, parsed['summary'])
    assert document['conflicts'] == []
    failure = final_status(dict(returncode=0), parsed,
                           [record('F5:00000001:00000000:ffffffff'),
                            record('F6:0110c000:08000000:deadbeef:12345678')])
    assert failure == 'failed'
    case = parsed['cases'][1]
    assert case['status'] == 'failed'
    assert correspondence(record('F6:0110c000:08000000:deadbeef:12345678'), case,
                          layout=LAYOUT, windows=WINDOWS, irq=IRQ, dma=DMA) is not None


def test_a_trapped_case_is_a_failed_case_not_a_lost_run():
    document = case_document(record('F1:2ab00693'),
                             dict(index=0, flow='F1', status='failed', traps=1,
                                  record='F1:2ab00693'),
                             events=dict(ifetch=2, rvfi=2, trap=1, bus_error=0, dma_done=0))
    assert document['status'] == 'failed'
    assert document['observation']['traps'] == 1
    assert document['events']['trap'] == 1


# --- entry failures before any model exists -----------------------------

@pytest.mark.parametrize('argv,match', [
    (['--records', 'F1:2ab00693', '--config', str(CONFIG_PATH), '--max-ticks', '0'],
     'max-ticks must be positive'),
    (['--records', 'F1:2ab00693', '--config', 'configs/scenarios/absent-config.json'],
     'cannot read the declaration'),
])
def test_the_entry_refuses_bad_arguments_before_creating_the_output(tmp_path, argv, match, capsys):
    output = tmp_path / 'out'
    with pytest.raises(SystemExit) as exit_code:
        main(['--cache', str(tmp_path / 'cache'), '--output', str(output), *argv])
    assert exit_code.value.code == 2
    assert match in capsys.readouterr().err
    assert not output.exists(), 'a rejected invocation must not leave a run directory'


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


def test_the_entry_defaults_to_the_combined_mode(tmp_path, capsys):
    """No ``--mode`` means the historical combined session, not one side.

    The combined path is the one that demands its F1-F6 records before any model
    exists, so that demand is what proves the default: an IP-only or CPU-only
    dispatch would not reject a missing ``--records`` this way.
    """
    output = tmp_path / 'out'
    with pytest.raises(SystemExit) as exit_code:
        main(['--config', str(CONFIG_PATH), '--cache', str(tmp_path / 'cache'),
              '--output', str(output)])
    assert exit_code.value.code == 2
    assert '--records is required' in capsys.readouterr().err
    assert not output.exists()


# --- the second target protocol: AXI4-Lite ------------------------------
# The target kind selects the adapter.  These tests pin the three things that
# decision touches: which tap roles the header binds, which words the run log
# prints for a completed transfer, and the named refusal of everything else.

AXI_CONFIG_PATH = (ROOT / 'configs/scenarios/'
                   'inprocess-obi-axi4lite-ibex-zipcpu-axiluart-zipdma-f1f6.json')
AXI_CONFIG = json.loads(AXI_CONFIG_PATH.read_text())
AXI_WINDOWS = declared_windows(AXI_CONFIG, DMA_WINDOW_SIZE)
AXI_TRACE = {'signals': {role: 'trace_' + role for role in
                         ('awaddr', 'awprot', 'awvalid', 'awready', 'wdata', 'wstrb',
                          'wvalid', 'wready', 'bresp', 'bvalid', 'bready', 'araddr',
                          'arprot', 'arvalid', 'arready', 'rdata', 'rresp', 'rvalid',
                          'rready')}}


def axi_ip_document(**overrides):
    document = ip_document(kind='axi4lite_register_observe',
                           base_protocol_trace=dict(protocol='axi4-lite',
                                                    signals=dict(AXI_TRACE['signals'])),
                           fixed_physical_inputs=[
                               dict(endpoint_id='uart.pins', role='rx', width=1,
                                    value=1, runtime_name='rx_pin'),
                               dict(endpoint_id='uart.pins', role='cts_n', width=1,
                                    value=0, runtime_name='cts_pin')],
                           physical_exports=[dict(physical_port='o_uart_tx_int',
                                                  direction='output', width=1, bit_lo=0,
                                                  bit_hi=0, runtime_name='tx_irq')])
    document.update(overrides)
    return document


def axi_header(**keywords):
    irq = keywords.pop('irq', None)
    return render_bindings(AXI_CONFIG, cpu_document(), axi_ip_document(), dma_document(),
                           LAYOUT, cpu_profile(), irq=irq,
                           dma=keywords.pop('dma', DMA), dma_irq=DMA['irq'])


def test_the_target_kind_selects_the_bridge_and_nothing_else():
    header = axi_header()
    assert '#define TARGET_PROTOCOL_APB3 0' in header
    assert '#define TARGET_PROTOCOL_AXI4LITE 1' in header
    assert '#define TARGET_BRIDGE "axi4_lite_mmio_bridge"' in header
    assert '#define TARGET_BUS_CHANNEL "axi"' in header
    assert '#define IP_TRACE_AWVALID trace_awvalid' in header
    assert '#define IP_TRACE_RREADY trace_rready' in header
    # The beat side of the bridge is the same 'reg' channel the APB3 target exposes,
    # so the host drives both targets the same way.
    assert '#define IP_REQ_VALID reg_req_valid' in header
    assert '#define IP_RSP_READY reg_rsp_ready' in header
    # An AXI4-Lite target has no pslverr, and samples bresp/rresp instead.
    assert '#define HAVE_APB_PSLVERR 0' in header
    assert 'IP_TRACE_PSLVERR' not in header


def test_an_axi4lite_header_prints_the_neutral_target_counters():
    header = axi_header()
    for key, value in (('KEY_TARGET_READS', 'target_reads'),
                       ('KEY_TARGET_WRITES', 'target_writes'),
                       ('KEY_TARGET_TRANSFERS', 'target_transfers'),
                       ('KEY_TARGET_READY', 'target_ready'),
                       ('KEY_TARGET_OFFSET', 'target_offset'),
                       ('KEY_TARGET_WDATA', 'target_wdata'),
                       ('KEY_TARGET_RDATA', 'target_rdata'),
                       ('KEY_TARGET_ERRORS', 'target_errors')):
        assert f'#define {key} "{value}"' in header
    assert '#define KEY_READ_FROM_TARGET "axi4lite"' in header
    # An APB3 header keeps its own spelling, so saved APB3 evidence stays readable.
    apb = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                          cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert 'KEY_TARGET_READS' not in apb
    assert 'TARGET_PROTOCOL_APB3 1' in apb


def test_the_declared_target_pins_are_driven_from_the_header():
    header = axi_header()
    assert '#define IP_FIXED_INPUT_COUNT 2' in header
    assert 'X(rx_pin, 1u)' in header and 'X(cts_pin, 0u)' in header


def test_an_axi4lite_target_without_f5_declares_one_irq_source():
    header = axi_header()
    assert '#define IRQ_SOURCE_COUNT 1' in header
    assert '#define IRQ_DMA_LINK_INDEX 0u' in header
    assert '#define TRIGGER_COUNT 0u' in header
    assert '#define IP_STATUS_KIND "undeclared"' in header


@pytest.mark.parametrize('change,match', [
    # A kind with no adapter this entry implements is still refused by name.  A
    # TL-UL register target is now mapped (its own generated kind/trace is
    # admitted), so the unmapped example is a specialised kind that exposes no
    # passive protocol trace.
    ({'kind': 'tlul_gpio'}, 'unsupported-target-kind:tlul_gpio'),
    ({'base_protocol_trace': dict(protocol='axi4-lite', signals={})},
     'AXI4-Lite trace lacks'),
    ({'base_protocol_trace': dict(protocol='apb3', signals={})},
     'unsupported-target-trace:axi4lite_register_observe:apb3'),
])
def test_an_unsupported_axi4lite_target_is_refused_by_name(change, match):
    with pytest.raises(ValueError, match=match):
        render_bindings(AXI_CONFIG, cpu_document(), axi_ip_document(**change),
                        dma_document(), LAYOUT, cpu_profile(), irq=None, dma=DMA,
                        dma_irq=DMA['irq'])


def test_an_apb3_target_kind_is_refused_for_an_axi4lite_trace():
    with pytest.raises(ValueError, match='unsupported-target-trace:apb3_register_observe'):
        render_bindings(CONFIG, cpu_document(),
                        ip_document(base_protocol_trace=dict(protocol='axi4-lite',
                                                             signals={})),
                        dma_document(), LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                        dma_irq=DMA['irq'])


def test_a_target_kind_without_an_adapter_is_named():
    from scripts.run_inprocess_f1f6 import target_protocol
    with pytest.raises(ValueError, match='unsupported-target-kind:tlul_gpio'):
        target_protocol(dict(ip_document(), kind='tlul_gpio'))
    # A mapped kind whose trace contradicts it is refused under the trace, not
    # silently given the protocol its kind name suggests.
    with pytest.raises(ValueError,
                       match='unsupported-target-trace:tlul_register_observe:apb3'):
        target_protocol(dict(ip_document(), kind='tlul_register_observe'))
    assert target_protocol(ip_document()) == 'apb3'
    assert target_protocol(axi_ip_document()) == 'axi4-lite'


def test_the_profile_protocol_selects_the_request_builder():
    from scripts.run_inprocess_f1f6 import profile_protocol
    assert profile_protocol(json.loads((ROOT / AXI_CONFIG['source_profile']).read_text())) \
        == 'axi4-lite'
    assert profile_protocol(json.loads((ROOT / CONFIG['source_profile']).read_text())) \
        == 'apb3'
    with pytest.raises(ValueError, match='unsupported-target-protocol'):
        profile_protocol(dict(endpoints=[dict(function='mmio_slave',
                                              protocol=['tlul', '1'])]))
    with pytest.raises(ValueError, match='expected-one-mmio-slave'):
        profile_protocol(dict(endpoints=[]))


def test_the_axi4lite_scenario_declares_the_same_image_and_no_f5():
    from scripts.run_inprocess_f1f6 import f5_declaration
    from myfuzz.composition.component_profile import load_component_profile
    assert AXI_WINDOWS['ip_base'] == 0x40001000 and AXI_WINDOWS['ip_size'] == 16
    assert AXI_WINDOWS['ram_base'] == WINDOWS['ram_base']
    assert AXI_WINDOWS['dma_base'] == 0x40001100
    assert AXI_CONFIG['dma_block_words'] == CONFIG['dma_block_words']
    profile = load_component_profile(ROOT / AXI_CONFIG['source_profile'])
    irq, reason = f5_declaration(AXI_CONFIG, profile, 'axi4-lite')
    assert irq is None
    assert reason == ('unsupported-f5:target-irq-semantics:axi4-lite:'
                      'source_port,source_bit_offset,trigger_writes,status_offsets')
    # The APB3 scenario keeps F5, and drops nothing.
    irq, reason = f5_declaration(CONFIG, load_component_profile(ROOT / CONFIG['source_profile']),
                                 'apb3')
    assert reason is None and irq['status_kind'] == 'count'


def test_a_refused_flow_says_why_instead_of_unknown_tag():
    reason = 'unsupported-f5:target-irq-semantics:axi4-lite:x'
    with pytest.raises(ValueError) as error:
        parse_record('F5:00000000', windows=AXI_WINDOWS,
                     arity=flow_arity(None, DMA), label='AXI4-Lite',
                     refusals={'F5': reason})
    assert reason in str(error.value)


def test_the_neutral_target_view_reads_either_spelling():
    from scripts.run_inprocess_f1f6 import target_view
    apb = target_view(dict(apb_writes=1, apb_offset=8, apb_pwdata=0x0FFFFFFF,
                           apb_pready=1, apb_reads=1, apb_read_data=0x1D,
                           apb_read_offset=0, apb_last_write_offset=8,
                           apb_last_write_data=0x0FFFFFFF, read_from='apb'))
    axi = target_view(dict(target_writes=1, target_offset=8, target_wdata=0x0FFFFFFF,
                           target_ready=1, target_reads=1, target_read_data=0x1D,
                           target_read_offset=0, target_last_write_offset=8,
                           target_last_write_data=0x0FFFFFFF, read_from='axi4lite'))
    assert apb == axi
    assert apb['target_reads'] == 1 and apb['read_from'] == 'target'
    # A field neither spelling carries stays unknown; it never becomes zero.
    assert target_view({})['target_writes'] == 'unknown'


def test_an_axi4lite_case_corresponds_through_the_same_check():
    from scripts.run_inprocess_f1f6 import target_view
    f2 = dict(flow='F2', read_addr=0x40001004, read_value=0x403F4000,
              echo_value=0x403F4000, read_from='axi4lite', target_rdata=0x403F4000,
              target_resp=0, target_reads=1, target_writes=0, target_offset=4,
              target_ready=1, record='F2:40001004')
    assert correspondence(parse_record('F2:40001004', windows=AXI_WINDOWS,
                                       arity=flow_arity(None, DMA), label='AXI4-Lite'),
                          f2, layout=LAYOUT, windows=AXI_WINDOWS, irq=None, dma=DMA,
                          protocol='axi4-lite') is None
    f4 = dict(flow='F4', mmio_addr=0x4000100C, mmio_value=0x5A5A, target_offset=12,
              target_wdata=0x5A5A, target_wstrb=15, target_resp=0, target_ready=1,
              target_writes=1, target_reads=0, axi_aw=1, axi_w=1, axi_b=1,
              record='F4:4000100c:00005a5a')
    assert correspondence(parse_record('F4:4000100c:00005a5a', windows=AXI_WINDOWS,
                                       arity=flow_arity(None, DMA), label='AXI4-Lite'),
                          f4, layout=LAYOUT, windows=AXI_WINDOWS, irq=None, dma=DMA,
                          protocol='axi4-lite') is None
    # A partial-strobe write and a non-OKAY response are the two AXI4-Lite facts
    # an APB3 case has no field for, so each is checked where it exists.
    assert 'strobes' in correspondence(
        parse_record('F4:4000100c:00005a5a', windows=AXI_WINDOWS,
                     arity=flow_arity(None, DMA), label='AXI4-Lite'),
        dict(f4, target_wstrb=7), layout=LAYOUT, windows=AXI_WINDOWS, irq=None, dma=DMA,
        protocol='axi4-lite')
    assert 'not OKAY' in correspondence(
        parse_record('F4:4000100c:00005a5a', windows=AXI_WINDOWS,
                     arity=flow_arity(None, DMA), label='AXI4-Lite'),
        dict(f4, target_resp=2), layout=LAYOUT, windows=AXI_WINDOWS, irq=None, dma=DMA,
        protocol='axi4-lite')


@pytest.mark.parametrize('line,expected', [
    ('axi aw 171 0x0000000c prot 0',
     dict(kind='axi', channel='aw', tick=171, address=12, prot=0, data=None, strb=None,
          resp=None)),
    ('axi w 171 0x00005a5a strb 15',
     dict(kind='axi', channel='w', tick=171, data=0x5A5A, strb=15, address=None, prot=None,
          resp=None)),
    ('axi b 172 resp 0',
     dict(kind='axi', channel='b', tick=172, resp=0, address=None, data=None, prot=None,
          strb=None)),
    ('axi ar 88 0x00000004 prot 0',
     dict(kind='axi', channel='ar', tick=88, address=4, prot=0, data=None, strb=None,
          resp=None)),
    ('axi r 90 0x403f4000 resp 0',
     dict(kind='axi', channel='r', tick=90, data=0x403F4000, resp=0, address=None,
          prot=None, strb=None)),
])
def test_one_axi_channel_event_is_parsed(line, expected):
    assert parse_event_line(line) == expected


@pytest.mark.parametrize('line', ['axi zz 1 0x0 resp 0', 'axi aw 1 0x0',
                                  'axi b 1 0x00000000', 'axi r 1 0x0'])
def test_a_malformed_axi_event_line_is_refused(line):
    with pytest.raises(ValueError):
        parse_event_line(line)


def test_axi_channel_events_and_summary_agree():
    from scripts.run_inprocess_f1f6 import event_document
    log = '\n'.join(['bus_error unknown axi',
                     'axi aw 171 0x0000000c prot 0',
                     'axi w 171 0x00005a5a strb 15',
                     'axi b 172 resp 0',
                     'axi ar 88 0x00000004 prot 0',
                     'axi r 90 0x403f4000 resp 0',
                     'summary observations_passed cases 5 ticks 395 axi_transfers 2 '
                     'axi_aw 1 axi_w 1 axi_b 1 axi_ar 1 axi_r 1 target_error unknown '
                     'bus_error unknown bus_error_axi unknown'])
    events = summarize_events(log)
    assert events['counts']['axi'] == 5
    document = event_document(events, parse_summary_line(log.splitlines()[-1]))
    assert document['evidence']['axi'] == 'observed'
    assert document['stated']['axi'] == 'observed'
    assert document['conflicts'] == []


# --- the pin target and the Wishbone CPU, in the same loop ----------------
#
# These two are separate axes of the same one-process loop: a pin target adds the
# pad model the host drives and samples, a Wishbone CPU replaces the two OBI
# channels with one cyc/stb master.  Everything here is pure Python: the declared
# shapes, the record rules, the rendered header, the fixed RAM image and the
# correspondence check applied to case lines of the recorded runs.

PIN_CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5.json'
PIN_CONFIG = json.loads(PIN_CONFIG_PATH.read_text())
WB_CONFIG_PATH = ROOT / 'configs/scenarios/inprocess-wbcpu-apb-timer-f1f4.json'
WB_CONFIG = json.loads(WB_CONFIG_PATH.read_text())
PIN_WINDOWS = declared_windows(PIN_CONFIG)
PIN_LAYOUT = build_layout(PIN_WINDOWS, 0x10080)
WB_WINDOWS = declared_windows(WB_CONFIG)
WB_LAYOUT = build_layout(WB_WINDOWS, 0)
PIN_IP_BASE = PIN_WINDOWS['ip_base']
PADIN = PIN_IP_BASE + PIN_CONFIG['pins']['padin_offset']
PIN_EVIDENCE = ('F1:2ab00693,F3:00014004:0badf00d,F4:40000004:ffffffff,'
                'F4:40000000:00000001,F2:40000008:00000002,'
                'F5:ffffffff:00000001:00000001:0000002b')


def pin_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / PIN_CONFIG['source_profile'])


def wb_cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / WB_CONFIG['cpu_profile'])


PIN = pin_declaration(PIN_CONFIG, pin_profile())
PIN_REGISTERS = pin_registers(pin_profile(), PIN_CONFIG)
PIN_IRQ, PIN_F5_REASON = f5_declaration(PIN_CONFIG, pin_profile(), 'apb3')
PIN_ARITY = flow_arity(PIN_IRQ, None)


def pin_record(text):
    return parse_record(text, windows=PIN_WINDOWS, arity=PIN_ARITY, pin=PIN)


def wb_cpu_document(**overrides):
    exports = [dict(physical_port='rvfi_' + role, direction='output',
                    runtime_name='rvfi_' + role)
               for role in ('valid', 'trap', 'insn', 'pc_rdata', 'order', 'rd_addr',
                            'rd_wdata')]
    exports.append(dict(endpoint_id='processor.interrupts', role='custom', direction='input',
                        width=32, runtime_name='irq'))
    ports = [dict(channel='wb', role=role, name='wb_' + role, direction='output')
             for role in ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel')]
    ports += [dict(channel='wb', role=role, name='wb_' + role, direction='input')
              for role in ('ack', 'dat_r')]
    document = dict(kind='wishbone_cpu', module_name='local_wb_cpu', clock_schedule=clock(50),
                    instruction_identity_observation='mem_instr',
                    physical_exports=exports, runtime_ports=[], backend_ports=ports,
                    plan=dict(timing=dict(reset_assert_ticks=4, reset_release_ticks=4)))
    document.update(overrides)
    return document


def gpio_ip_document(**overrides):
    signals = {role: 'trace_' + role for role in
               ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata',
                'pslverr')}
    exports = [dict(endpoint_id='gpio.pins', role=role, direction=direction, width=32,
                    runtime_name='pin_' + role)
               for role, direction in (('in', 'input'), ('out', 'output'),
                                       ('dir', 'output'), ('in_sync', 'output'))]
    exports += [dict(physical_port='gpio_probe_' + name, direction='output',
                     runtime_name='probe_' + name)
                for name in ('status', 'padin_latch', 'rise', 'fall', 'inten')]
    exports.append(dict(physical_port='interrupt', direction='output', width=1,
                        bit_lo=0, bit_hi=0, runtime_name='gpio_irq'))
    document = dict(kind='apb_gpio', module_name='local_gpio', clock_schedule=clock(50),
                    base_protocol_trace=dict(protocol='apb3', signals=signals),
                    physical_exports=exports,
                    backend_ports=[dict(channel='gpio', role=role, name='gpio_' + role)
                                   for role in ROLES],
                    plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)))
    document.update(overrides)
    return document


def pin_case(flow, record, **fields):
    case = dict(index=0, flow=flow, status='observations_passed', record=record['text'])
    case.update(fields)
    return case


def pin_check(record, **fields):
    return correspondence(record, pin_case(record['flow'], record, **fields),
                          layout=PIN_LAYOUT, windows=PIN_WINDOWS, irq=PIN_IRQ, dma=None,
                          protocol='apb3', pins=PIN, registers=PIN_REGISTERS)


def test_the_pin_target_declares_the_pad_model_it_uses():
    assert PIN == dict(endpoint_id='gpio.pins', width=32, external_value=0,
                       padin_offset=8)
    assert PIN_REGISTERS == {'PADOUT': 12, 'PADOUTSET': 16, 'PADOUTCLR': 20}
    with pytest.raises(ValueError, match='disagrees'):
        pin_registers(pin_profile(), dict(PIN_CONFIG, registers={'PADOUT': 16}))
    with pytest.raises(ValueError, match='declares a dir-resolved pad endpoint'):
        pin_declaration(dict(PIN_CONFIG, pins=None), pin_profile())
    with pytest.raises(ValueError, match='no dir-resolved pad endpoint'):
        pin_declaration(PIN_CONFIG, timer_profile())


def test_the_pin_stimulus_is_the_optional_second_word_of_f2():
    parsed = pin_record('F2:40000008:00000002')
    assert parsed['text'] == 'F2:40000008:00000002'
    assert parsed['fields'] == (PADIN, 2)
    assert parsed['message'] == 'CASE F2 40000008 00000002'
    assert pin_record('F2:40000008')['fields'] == (PADIN,)
    assert [len(pin_record(text)['fields']) for text in PIN_EVIDENCE.split(',')] == \
        [1, 2, 2, 2, 2, 4]
    with pytest.raises(ValueError, match='PADIN'):
        pin_record('F2:40000000:00000001')
    with pytest.raises(ValueError, match='needs 1 or 2'):
        pin_record('F2:40000008:00000002:00000003')
    with pytest.raises(ValueError, match='unsupported-flow:P'):
        pin_record('P:40000008:00000002')


def test_the_pin_header_binds_the_pad_ports_and_no_dma():
    header = render_bindings(PIN_CONFIG, cpu_document(), gpio_ip_document(), None,
                             PIN_LAYOUT, cpu_profile(), irq=PIN_IRQ, dma=None,
                             dma_irq=None, pins=PIN, registers=PIN_REGISTERS)
    assert '#define HAVE_PINS 1' in header
    assert '#define HAVE_DMA 0' in header and 'DMA_BASE' not in header
    assert '#define HAVE_IRQ_LINKS 1' in header
    assert '#define CPU_BUS_WISHBONE 0' in header
    assert '#define PAD_WIDTH 32' in header
    assert '#define IP_PADIN_OFFSET 8u' in header
    assert '#define IP_PADOUT_OFFSET 12u' in header
    assert '#define IP_PADOUTSET_OFFSET 16u' in header
    assert '#define IP_PADOUTCLR_OFFSET 20u' in header
    for key, name in (('IP_PIN_IN', 'pin_in'), ('IP_PIN_OUT', 'pin_out'),
                      ('IP_PIN_DIR', 'pin_dir'), ('IP_PIN_IN_SYNC', 'pin_in_sync'),
                      ('IP_PROBE_RISE', 'probe_rise'), ('IP_PROBE_PADIN_LATCH',
                                                        'probe_padin_latch')):
        assert f'#define {key} {name}' in header
    assert '#define IP_REQ_VALID gpio_req_valid' in header
    assert '#define IP_TRACE_PSEL trace_psel' in header
    assert '#define TRIGGER_COUNT 4u' in header
    assert '#define IRQ_SOURCE_COUNT 1' in header
    assert '#define FPAD' not in header


def test_the_wishbone_cpu_header_binds_the_single_master():
    header = render_bindings(WB_CONFIG, wb_cpu_document(), ip_document(), None, WB_LAYOUT,
                             wb_cpu_profile(), irq=None, dma=None, dma_irq=None)
    assert '#define CPU_BUS_WISHBONE 1' in header
    assert '#define CPU_IRQ_WIDTH 32' in header
    assert '#define CPU_IRQ_WIRED 0' in header
    assert '#define CPU_WB_INSTR mem_instr' in header
    assert '#define CPU_WB_CYC wb_cyc' in header
    assert '#define CPU_WB_DAT_R wb_dat_r' in header
    assert 'CPU_I_REQ_VALID' not in header and 'CPU_D_REQ_READY' not in header
    assert '#define HAVE_DMA 0' in header
    assert '#define HAVE_IRQ_LINKS 0' in header
    assert '#define TRIGGER_COUNT 0u' in header
    with pytest.raises(
            ValueError,
            match='unsupported-f6:cpu-dma-port-unexported:wishbone'):
        render_bindings(WB_CONFIG, wb_cpu_document(), ip_document(), dma_document(),
                        WB_LAYOUT, wb_cpu_profile(), irq=None, dma=DMA, dma_irq=DMA['irq'])


def test_the_wishbone_build_refuses_f5_by_name():
    irq, reason = f5_declaration(WB_CONFIG, timer_profile(), 'apb3',
                                 cpu_bus_kind='wishbone', cpu_irq_bits=32)
    assert irq is None
    assert reason == 'unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero'
    irq, reason = f5_declaration(PIN_CONFIG, pin_profile(), 'apb3')
    assert irq is not None and reason is None and PIN_F5_REASON is None


def test_the_f6_of_a_dma_less_declaration_is_refused_by_name():
    with pytest.raises(ValueError, match='unsupported-f6:no-dma-model:APB'):
        parse_record('F6:0110c000:08000000:deadbeef:12345678', windows=PIN_WINDOWS,
                     arity=PIN_ARITY, refusals={'F6': 'unsupported-f6:no-dma-model:APB'})
    assert 'F6' not in PIN_ARITY and 'F6' not in flow_arity(PIN_IRQ, None)


def test_the_ram_base_follows_the_cpu_boot_contract():
    assert WB_WINDOWS['ram_base'] == 0 and WB_WINDOWS['dma_base'] is None
    assert WB_LAYOUT['boot'] == 0
    assert PIN_WINDOWS['dma_base'] is None
    with pytest.raises(ValueError, match='not an aligned RAM word'):
        build_layout(WB_WINDOWS, 0x20000)
    with pytest.raises(ValueError, match='requires a declared dma_window'):
        declared_windows(WB_CONFIG, 16)


def test_the_wishbone_bootstrap_is_one_jump_from_the_reset_vector():
    plain = build_firmware(WB_LAYOUT, irq=None, dma=None, interrupt_bootstrap=False)
    obi = build_firmware(WB_LAYOUT, irq=None, dma=None)
    boot = plain['images'][WB_LAYOUT['boot']]
    assert len(boot) == 4 and int.from_bytes(boot, 'little') & 0x7f == 0x6f
    assert len(obi['images'][WB_LAYOUT['boot']]) > 4
    assert plain['images'][WB_LAYOUT['main']] == obi['images'][WB_LAYOUT['main']]
    with pytest.raises(ValueError, match='unsupported-cpu-kind:axi_cpu'):
        from scripts.run_inprocess_f1f6 import cpu_bus
        cpu_bus({'kind': 'axi_cpu'})


def test_the_pin_f2_reads_the_pad_the_host_drove():
    record = pin_record('F2:40000008:00000002')
    fields = dict(read_addr=PADIN, read_value=2, echo_value=2, read_from='apb',
                  apb_reads=1, apb_rdata=2, apb_offset=8, apb_pready=1,
                  pad_at_read=2, padin_latch=2, ext_value=2, dir_after=1,
                  pad_before=0, pad_after=2, out_before=0, out_after=0,
                  pin_stimulus='applied', pad_changes=1, pad_rise_events=1)
    assert pin_check(record, **fields) is None
    assert 'synchronizer' in pin_check(record, **dict(fields, padin_latch=3))
    # The instantaneous wire may already have moved while the device's own
    # synchronizer still holds the previous value: that is the device's declared
    # latency and must not be reported as a mismatch.  `pad_settled` records
    # whether the two happened to agree in this sample.
    assert pin_check(record, **dict(fields, pad_at_read=3, pad_settled=0)) is None
    assert 'did not reach' in pin_check(record, **dict(fields, ext_value=4))
    assert 'was not applied' in pin_check(record, **dict(fields, pin_stimulus='declared_default'))


def test_the_pin_f4_write_shows_its_declared_register_effect():
    record = pin_record('F4:4000000c:0000002b')
    fields = dict(mmio_addr=0x4000000C, mmio_value=0x2B, apb_writes=1, apb_offset=12,
                  apb_pwdata=0x2B, apb_pready=1, apb_reads=0,
                  out_before=0, out_after=0x2B, dir_after=1, pad_after=1,
                  pad_before=0, ext_value=0)
    assert pin_check(record, **fields) is None
    assert 'does not follow' in pin_check(record, **dict(fields, out_after=0x2A))
    assert 'device-driven pads' in pin_check(record, **dict(fields, pad_after=0))
    assert 'without a host stimulus' in pin_check(
        record, **dict(fields, dir_after=0, pad_after=0, ext_value=1))


def test_the_pin_f5_interrupt_is_attributed_to_the_transition():
    record = pin_record('F5:ffffffff:00000001:00000001:0000002b')
    fields = dict(trigger_writes=4, trigger_writes_declared=4,
                  trigger_writes_observed=4, clear_writes=0,
                  last_trigger_offset=12, last_trigger_data=0x2B,
                  last_clear_offset=0, last_clear_data=0,
                  apb_read_offset=36, apb_read_data=1,
                  apb_last_write_offset=12, apb_last_write_data=0x2B, apb_reads=1,
                  apb_writes=4, apb_pready=1, irq_edges=1, irq_high_ticks=1,
                  device_high_ticks=1, delivered_high_ticks=16, irq_takes=1,
                  isr_result=1, isr_flag=1, isr_read_addr=0x40000024, isr_read_value=1,
                  isr_read_register_kind='status', isr_cause='unknown',
                  pad_before=2, pad_after=1, out_before=0, out_after=0x2B, dir_after=1,
                  ext_value=0, pad_changes=2, pad_rise_events=1, rise_mask=1, fall_mask=2,
                  irq_cause_pins=1, inten_at_irq=1, first_rise_tick=316,
                  first_irq_tick=316, status_after_read=0)
    assert pin_check(record, **fields) is None
    assert 'preceded' in pin_check(record, **dict(fields, first_irq_tick=100))
    assert 'enabled pin' in pin_check(record, **dict(fields, irq_cause_pins=0))
    assert 'no pin transition' in pin_check(record, **dict(fields, pad_rise_events=0,
                                                           pad_fall_events=0))
    assert 'no sampled transition tick' in pin_check(record, **dict(fields,
                                                                    first_rise_tick='unknown'))
    # The device's programmed interrupt type may make a falling transition the
    # cause; the checker accepts either direction as long as the cause mask has
    # an enabled pin and the transition was sampled first.
    assert pin_check(record, **dict(fields, pad_rise_events=0, pad_fall_events=1,
                                    first_rise_tick='unknown', first_fall_tick=316,
                                    first_transition_tick=316)) is None



# --- declared target count and the per-target address route ---------------

def test_a_declared_case_tick_budget_reaches_the_header():
    """The scenario's own budget is the header's CASE_TICK_BUDGET."""
    budget = 9000
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                             cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'],
                             case_tick_budget=budget)
    assert f'#define CASE_TICK_BUDGET {budget}u' in header
    default = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(), LAYOUT,
                              cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'])
    assert '#define CASE_TICK_BUDGET 4000u' in default


def test_the_entry_passes_the_declared_budget_to_the_header():
    """Guard the wiring itself: main must hand the declared budget over."""
    import inspect
    source = inspect.getsource(main)
    assert 'case_tick_budget=case_tick_budget' in source


def test_the_two_ip_scenario_routes_every_record_to_its_target_window():
    from myfuzz.composition.multi_target import target_windows, two_ip_scenario
    windows = target_windows(two_ip_scenario())
    arity = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3}
    timer_read = parse_record('F2:40001000', windows=windows, arity=arity)
    i2c_read = parse_record('F2:40002008', windows=windows, arity=arity)
    ram_read = parse_record('F2:00014000', windows=windows, arity=arity)
    i2c_write = parse_record('F4:40002010:0000005a', windows=windows, arity=arity)
    f5 = parse_record('F5:00000001:00000000:ffffffff', windows=windows, arity=arity,
                      f5_target_index=0)
    assert (timer_read['target_index'], i2c_read['target_index']) == (0, 1)
    assert ram_read['target_index'] is None
    assert i2c_write['target_index'] == 1
    assert f5['target_index'] == 0
    # The DMA control window is not a target; a record cannot address it.
    with pytest.raises(ValueError, match='aligned word in the APB window'):
        parse_record('F4:40003000:00000001', windows=windows, arity=arity)


def test_a_multi_target_case_has_to_name_the_routed_target_and_zero_the_others():
    from myfuzz.composition.multi_target import target_windows, two_ip_scenario
    windows = target_windows(two_ip_scenario())
    record = parse_record('F4:40002010:0000005a', windows=windows,
                          arity={'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3})
    case = dict(flow='F4', record=record['text'], mmio_addr=0x40002010,
                mmio_value=0x5A, apb_offset=0x10, apb_pwdata=0x5A, apb_pready=1,
                apb_reads=0, apb_writes=1, target_index=1,
                target0_reads=0, target0_writes=0, target1_reads=0, target1_writes=1)
    common = dict(layout=LAYOUT, windows=windows, irq=IRQ, dma=DMA,
                  irq_base=0x40001000, f5_target_index=0)
    assert correspondence(record, case, **common) is None
    moved = dict(case, target0_writes=1)
    assert 'target0 moved' in correspondence(record, moved, **common)
    wrong = dict(case, target_index=0)
    assert 'target_index' in correspondence(record, wrong, **common)


def test_a_multi_target_header_states_every_target_and_its_own_ports():
    from myfuzz.composition.multi_target import target_windows, two_ip_scenario
    scenario = two_ip_scenario()
    windows = target_windows(scenario)
    timer = ip_document(module_name='local_timer')
    i2c = ip_document(module_name='local_i2c', physical_exports=[
        dict(physical_port='interrupt_o', direction='output', width=1,
             bit_lo=0, bit_hi=0, runtime_name='i2c_irq')])
    targets = [
        dict(index=0, name='timer', artifact=timer, protocol='apb3', irq=IRQ,
             pins=None, registers=None, fixed_inputs=[], has_f5=True,
             window=windows['ip_targets'][0]),
        dict(index=1, name='i2c', artifact=i2c, protocol='apb3', irq=None,
             pins=None, registers=None, fixed_inputs=[], has_f5=False,
             window=windows['ip_targets'][1]),
    ]
    layout = build_layout(windows, BOOT)
    header = render_bindings(scenario, cpu_document(), timer, dma_document(), layout,
                             cpu_profile(), irq=IRQ, dma=DMA, dma_irq=DMA['irq'],
                             targets=targets, f5_target_index=0,
                             case_tick_budget=9000)
    assert '#define IP_COUNT 2' in header
    assert '#define IP_MODEL_1 Vlocal_i2c' in header
    assert '#define IP_BASE_0 0x40001000u' in header
    assert '#define IP_BASE_1 0x40002000u' in header
    assert '#define IP_HAS_F5_0 1' in header
    assert '#define IP_HAS_F5_1 0' in header
    assert '#define IP_REQ_VALID_1 reg_req_valid' in header
    assert '#define IP_TRACE_PREADY_1 trace_pready' in header
    assert '#define IP_FIXED_INPUT_COUNT_1 0' in header
    assert 'template <> struct IpTarget<1>' in header
    assert 'X((uint64_t(g_ip_irq[0])), 0u, 16u, 0u)' in header
    assert 'X((uint64_t(dma.dma_irq)), 0u, 0u, 0u)' in header
    assert '#define IP_HAS_IRQ_1 1' in header
    assert '#define IP_F5_TARGET_INDEX 0u' in header
    assert '#define CASE_TICK_BUDGET 9000u' in header


def test_the_two_ip_scenario_selects_the_timer_as_the_one_f5_target():
    from myfuzz.composition.inprocess_behavior import source_behavior
    from myfuzz.composition.multi_target import (declared_targets, target_as_legacy_config,
                                                 target_for_f5, two_ip_scenario)
    scenario = two_ip_scenario()
    targets = declared_targets(scenario)
    facts = [source_behavior(target_as_legacy_config(target), base_dir=ROOT)
             for target in targets]
    assert target_for_f5(targets, facts)['index'] == 0
    # A second complete declaration is refused under the one-IRQ-line rule.
    scenario['targets'][1]['behavior'] = scenario['targets'][0]['behavior']
    targets = declared_targets(scenario)
    facts = [source_behavior(target_as_legacy_config(target), base_dir=ROOT)
             for target in targets]
    with pytest.raises(ValueError, match='multiple-target-irq-sources'):
        target_for_f5(targets, facts)


# --- multi-declaring F5 targets: one global link numbering ------------------
# The entry numbers every declaring target's links in one table (timer link 0,
# I2C link 1), and an F5 record carries that global index first.  These tests
# exercise the pure-Python half: the record mapping, the generated header and
# the correspondence checks.  The real RTL evidence lives under
# runs/round1-multi-f5/.
I2C_LINK = dict(port='interrupt_o', bit=0, trigger='level', polarity='active_high',
                pulse_ticks=0, status_offset=12, trigger_offsets=[4, 16, 20],
                status_kind='status', cause_declared=True, cause_bits=[0],
                cause_mask=1, clear=dict(offset=20, value=1))


def multi_f5_declaration():
    """The two-declaring-target global link table: timer link 0, I2C link 1."""
    links = [dict(IRQ, index=0, target_index=0, base=0x40001000),
             dict(I2C_LINK, index=1, target_index=1, base=0x40002000)]
    irq = dict(links=links, source_count=2, multi_target=True, **links[0])
    return irq, links


def two_ip_windows():
    from myfuzz.composition.multi_target import target_windows, two_ip_scenario
    return target_windows(two_ip_scenario())


def test_a_multi_declaring_scenario_maps_each_link_to_its_target():
    irq, links = multi_f5_declaration()
    windows = two_ip_windows()
    arity = flow_arity(irq, None)
    assert arity['F5'] == 4

    i2c = parse_record('F5:00000001:000000c0:0000005a:00000010', windows=windows,
                       arity=arity, f5_links=links, f5_target_index=0)
    timer = parse_record('F5:00000000:00000000:00000000:ffffffff', windows=windows,
                         arity=arity, f5_links=links, f5_target_index=0)
    assert i2c['fields'] == (1, 0xC0, 0x5A, 0x10)
    assert i2c['target_index'] == 1
    assert timer['fields'] == (0, 0, 0, 0xFFFFFFFF)
    assert timer['target_index'] == 0
    with pytest.raises(ValueError, match='is not one of the 2 declared links'):
        parse_record('F5:00000002:000000c0:0000005a:00000010', windows=windows,
                     arity=arity, f5_links=links, f5_target_index=0)


def test_a_one_target_f5_declaration_keeps_its_record_shape_and_mapping():
    windows = two_ip_windows()
    arity = flow_arity(IRQ, None)
    assert arity['F5'] == 3
    link = dict(IRQ, index=0, target_index=0, base=0x40001000)
    record = parse_record('F5:00000000:00000000:ffffffff', windows=windows,
                          arity=arity, f5_links=[link], f5_target_index=0)
    assert record['fields'] == (0, 0, 0xFFFFFFFF)
    assert record['target_index'] == 0
    # Without a global table the header keeps the historical single-target
    # rendering (the per-link family is still stated, with one row).
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                             LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                             dma_irq=DMA['irq'])
    assert '#define IRQ_TARGET_LINK_COUNT 1u' in header
    assert '#define IRQ_LINK_TARGETS 0u' in header
    assert '#define IRQ_LINK_BASES 0x40001000u' in header
    assert '#define IP_F5_TARGET_COUNT 1u' in header
    assert '#define IP_F5_TARGET_MULTI 0' in header
    assert 'X((uint64_t(ip.irq_wide)), 0u, 16u, 0u)' in header


def test_a_multi_target_header_carries_every_link_and_its_target():
    from myfuzz.composition.multi_target import target_windows, two_ip_scenario
    irq, links = multi_f5_declaration()
    windows = target_windows(two_ip_scenario())
    timer = ip_document(module_name='local_timer')
    i2c = ip_document(module_name='local_i2c', physical_exports=[
        dict(physical_port='interrupt_o', direction='output', width=1,
             bit_lo=0, bit_hi=0, runtime_name='i2c_irq')])
    targets = [
        dict(index=0, name='timer', artifact=timer, protocol='apb3', irq=links[0],
             pins=None, registers=None, fixed_inputs=[], has_f5=True,
             window=windows['ip_targets'][0]),
        dict(index=1, name='i2c', artifact=i2c, protocol='apb3', irq=links[1],
             pins=None, registers=None, fixed_inputs=[], has_f5=True,
             window=windows['ip_targets'][1]),
    ]
    layout = build_layout(windows, BOOT, irq_base=0x40001000)
    header = render_bindings(CONFIG, cpu_document(), timer, None, layout,
                             cpu_profile(), irq=irq, dma=None, dma_irq=None,
                             targets=targets, f5_target_index=0, f5_links=links,
                             case_tick_budget=80000)
    assert '#define IRQ_TARGET_LINK_COUNT 2u' in header
    assert '#define IRQ_SOURCE_COUNT 2' in header
    # Each link samples its own target's real output and carries its own facts.
    assert 'X((uint64_t(g_ip_irq[0])), 0u, 16u, 0u)' in header
    assert 'X((uint64_t(g_ip_irq[1])), 0u, 0u, 0u)' in header
    assert '#define IRQ_LINK_TARGETS 0u, 1u' in header
    assert '#define IRQ_LINK_BASES 0x40001000u, 0x40002000u' in header
    assert '#define IRQ_LINK_STATUS_OFFSETS 0u, 12u' in header
    assert '#define IRQ_LINK_CLEAR_DECLARED 0u, 1u' in header
    assert '#define IRQ_LINK_TRIGGER_COUNTS 3u, 3u' in header
    assert '#define IP_F5_TARGET_COUNT 2u' in header
    assert '#define IP_F5_TARGET_MULTI 1' in header
    assert '#define IP_HAS_F5_0 1' in header
    assert '#define IP_HAS_F5_1 1' in header
    assert '#define IP_HAS_IRQ_1 1' in header


def test_a_multi_target_f5_case_has_to_read_and_clear_the_selected_target():
    irq, links = multi_f5_declaration()
    windows = two_ip_windows()
    layout = build_layout(windows, BOOT, irq_base=0x40001000)
    record = parse_record('F5:00000001:000000c0:0000005a:00000010', windows=windows,
                          arity=flow_arity(irq, None), f5_links=links,
                          f5_target_index=0)
    case = dict(flow='F5', record=record['text'], trigger_writes_observed=3,
                clear_writes=1, last_trigger_offset=20, last_trigger_data=0x10,
                last_clear_offset=20, last_clear_data=1, isr_cause=1,
                target_reads=1, target_writes=4, target_read_offset=12,
                target_read_data=0x81, isr_result=0x81,
                isr_read_addr=0x4000200C, isr_read_value=0x81,
                isr_read_register_kind='status', irq_level_final=0,
                device_high_ticks=38, delivered_high_ticks=38, isr_flag=1,
                irq_edges=1, irq_takes=1, irq_link=1, irq_link_target=1,
                target_index=1, target0_reads=0, target0_writes=0,
                target1_reads=1, target1_writes=4)
    common = dict(layout=layout, windows=windows, irq=irq, dma=None,
                  irq_base=0x40001000, f5_target_index=0)
    assert correspondence(record, case, **common) is None
    # The ISR read address has to be the selected link's target, not the first
    # target's window.
    wrong_address = dict(case, isr_read_addr=0x4000100C)
    assert 'ISR read address' in correspondence(record, wrong_address, **common)
    wrong_target = dict(case, irq_link_target=0)
    assert 'selected link target' in correspondence(record, wrong_target, **common)


# --- the two-source ("both") F5 row ---------------------------------------

def both_f5_declaration():
    """The physical two-link table plus the synthetic both row over it."""
    irq, links = multi_f5_declaration()
    timer, i2c = links
    both = dict(index=2, mode='both', target_index=None, base=None,
                target_indices=[0, 1], members=[timer, i2c],
                trigger_offsets=[4, 8, 0, 4, 16, 20],
                status_offsets=[0, 12], status_kinds=['count', 'status'],
                cause_declared=True, cause_mask=1, cause_masks=[0, 1],
                cause_bits=[0], clear=None,
                clears=[None, dict(offset=20, value=1)],
                trigger='both', level=True, port=None, bit=None, polarity=None,
                status_kind='both')
    return dict(irq, both=both, both_refusal=None), links, both


BOTH_RECORD = ('F5:00000002:00000000:00000000:ffffffff:'
               '000000c0:0000005a:00000010')


def both_case(**overrides):
    """One saved two-source case line, as the C++ host prints it."""
    case = dict(index=2, status='observations_passed', flow='F5',
                record=BOTH_RECORD,
                both_link=2, both_members='0,1', both_targets='0,1',
                both_link_edges='1,1', both_level_final=0,
                both_trigger_writes=6, both_clear_writes=1,
                trigger_writes=6, trigger_writes_observed=6, clear_writes=1,
                irq_link=2, irq_edges=2, irq_takes=2, isr_flag=1,
                wait_timeout=0, level_stuck=0,
                isr_result=0, isr_read_addr=0x40001000,
                isr_read_value=0, isr_read_register_kind='count',
                isr_cause='unknown',
                isr_result2=0x81, isr_read_addr2=0x4000200C,
                isr_read_value2=0x81, isr_read_register_kind2='status',
                isr_cause2=1,
                target0_reads=2, target0_read_offset=0, target0_read_data=0,
                target0_last_trigger_offset=0,
                target0_last_trigger_data=0xFFFFFFFF,
                target0_clear_writes=0, target0_last_clear_offset=0,
                target0_last_clear_data=0, target0_irq_high_ticks=1,
                target1_reads=2, target1_read_offset=12,
                target1_read_data=0x81, target1_last_trigger_offset=20,
                target1_last_trigger_data=0x10, target1_clear_writes=1,
                target1_last_clear_offset=20, target1_last_clear_data=1,
                target1_irq_high_ticks=38)
    case.update(overrides)
    return case


def test_the_both_record_carries_both_trigger_sequences_and_selects_no_one_target():
    irq, links, both = both_f5_declaration()
    windows = two_ip_windows()
    table = f5_link_table(irq)
    assert [link['index'] for link in table] == [0, 1, 2]
    record = parse_record(BOTH_RECORD, windows=windows, arity=flow_arity(irq, None),
                          f5_links=table, f5_target_index=0)
    assert record['fields'] == (2, 0, 0, 0xFFFFFFFF, 0xC0, 0x5A, 0x10)
    assert record['target_index'] is None
    assert f5_both_selected(irq, record)
    # The single-link shapes are still accepted, and a both shape with one word
    # missing is refused by its declared count rather than truncated.
    single = parse_record('F5:00000000:00000000:00000000:ffffffff', windows=windows,
                          arity=flow_arity(irq, None), f5_links=table,
                          f5_target_index=0)
    assert not f5_both_selected(irq, single)
    with pytest.raises(ValueError, match='needs 4 or 7 word'):
        parse_record(BOTH_RECORD.rsplit(':', 1)[0], windows=windows,
                     arity=flow_arity(irq, None), f5_links=table,
                     f5_target_index=0)


def test_the_both_image_publishes_two_result_cells_and_the_longer_isr():
    irq, links, both = both_f5_declaration()
    windows = two_ip_windows()
    layout = build_layout(windows, BOOT, irq_base=0x40001000)
    assert layout['result_f5b'] == layout['result'] + 28
    single = build_firmware(layout, irq=IRQ, dma=None)
    firmware = build_firmware(layout, irq=irq, dma=None)
    # The both image writes both trigger sequences and publishes the second
    # status/result/clear set, so both its body and its ISR are longer.  The
    # single-link image is unchanged byte for byte (the historical handler).
    assert firmware['main_words'] > single['main_words']
    assert firmware['handler_words'] > single['handler_words']
    assert len(firmware['images'][layout['handler_block']]) == HANDLER_BLOCK_BYTES
    assert build_firmware(layout, irq=IRQ, dma=None)['images'] == single['images']


def test_the_header_states_the_both_row_and_the_second_result_cell():
    irq, links, both = both_f5_declaration()
    # The rendering test reuses one target document for both targets, so both
    # link ports are the same real output port at different bits.
    render_links = [dict(links[0]), dict(links[1], port='irq_o', bit=1)]
    render_both = dict(both, members=render_links)
    render_irq = dict(irq, links=render_links, both=render_both)
    windows = two_ip_windows()
    layout = build_layout(windows, BOOT, irq_base=0x40001000)
    target = dict(artifact=ip_document(), protocol='apb3', pins=None,
                  registers=None, fixed_inputs=[])
    targets = [dict(target, index=0, name='timer', irq=render_links[0],
                    window=dict(base=0x40001000, size=0x1000)),
               dict(target, index=1, name='i2c', irq=render_links[1],
                    window=dict(base=0x40002000, size=0x1000))]
    header = render_bindings(CONFIG, cpu_document(), ip_document(), None, layout,
                             cpu_profile(), irq=render_irq, dma=None, dma_irq=None,
                             targets=targets, f5_target_index=0,
                             f5_links=render_links, f5_both=render_both)
    assert '#define IRQ_BOTH_ENABLED 1' in header
    assert '#define IRQ_BOTH_LINK_INDEX 2u' in header
    assert '#define IRQ_BOTH_MEMBER_COUNT 2u' in header
    assert '#define IRQ_BOTH_LINKS 0u, 1u' in header
    assert '#define IRQ_BOTH_WORDS 7u' in header
    assert '#define IRQ_BOTH_TRIGGER_WORDS 6u' in header
    assert '#define IRQ_BOTH_TRIGGER_POSITIONS 1, 4' in header
    assert '#define IRQ_BOTH_TRIGGER_COUNTS 3u, 3u' in header
    assert '#define IRQ_BOTH_CAUSE_MASKS 0x00000000u, 0x00000001u' in header
    assert '#define IRQ_BOTH_CLEAR_DECLARED 0u, 1u' in header
    assert '#define IRQ_BOTH_TARGETS 0u, 1u' in header
    assert '#define IP_RESULT2_ADDRESS' in header
    # A header without a both row states the fact and nothing else.
    plain = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                            LAYOUT, cpu_profile(), irq=IRQ, dma=DMA,
                            dma_irq=DMA['irq'])
    assert '#define IRQ_BOTH_ENABLED 0' in plain


def test_a_both_case_has_to_read_store_and_clear_both_targets():
    irq, links, both = both_f5_declaration()
    windows = two_ip_windows()
    layout = build_layout(windows, BOOT, irq_base=0x40001000)
    record = parse_record(BOTH_RECORD, windows=windows, arity=flow_arity(irq, None),
                          f5_links=f5_link_table(irq), f5_target_index=0)
    common = dict(layout=layout, windows=windows, irq=irq, dma=None,
                  irq_base=0x40001000, f5_target_index=0)
    assert correspondence(record, both_case(), **common) is None
    # Neither status read, store, clear nor edge may be skipped and still pass.
    assert 'stored result' in correspondence(
        record, both_case(isr_result2=0), **common)
    assert 'clear write' in correspondence(
        record, both_case(target1_clear_writes=0), **common)
    assert 'did not raise' in correspondence(
        record, both_case(both_link_edges='1,0'), **common)
    assert 'timed out' in correspondence(
        record, both_case(wait_timeout=1), **common)
    assert 'still asserted' in correspondence(
        record, both_case(both_level_final=1), **common)
    assert 'members differ' in correspondence(
        record, both_case(both_members='1,0'), **common)
    assert 'cause bits' in correspondence(
        record, both_case(isr_cause2=0), **common)


# --- multi-bit status vector (PULP GPIO INTSTATUS) ------------------------

def test_a_two_bit_gpio_status_declares_a_status_vector_not_a_cpu_vector():
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(
        ROOT / 'configs/peripherals/pulp_gpio_causal_local/component_profile.json')
    behavior = json.loads(
        (ROOT / 'configs/behaviors/pulp_gpio_multibit_f5_pins.json').read_text())
    declared = irq_declaration(dict(behavior,
                                    target_window=dict(base=0x40000000, size=0x1000)),
                               profile)
    assert declared['cause_bits'] == [0, 1]
    assert declared['cause_mask'] == 0b11
    # The status word is the read-clearing one, so the two-bit cause is cleared
    # by the ISR's read and no clear write is declared.
    assert declared['status_read_clears'] is True
    assert declared['clear'] is None
    assert declared['trigger_offsets'] == [4, 24, 28, 12]
    # The scenario that declares this behavior is the multi-bit one, and its
    # profile really states the read_clears side effect (the RTL fact).
    status = next(row for row in profile.address.registers if row.name == 'INTSTATUS')
    assert status.side_effect == 'read_clears'


# --- named NMI / PLIC / CPU-vector refusals -------------------------------

def test_the_pinned_cpu_boundary_states_the_irq_features_it_does_not_compose():
    ibex = json.loads(
        (ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json').read_text())
    refusals = advanced_irq_refusals(ibex)
    assert refusals['nmi'] == (
        'unsupported-irq:nmi-uncomposed:ibex_rvfi_local:irq_nm_i=constant-0')
    assert refusals['plic'] == (
        'unsupported-irq:plic-not-composed:ibex_rvfi_local:'
        'no-declared-interrupt-controller-endpoint')
    assert refusals['cpu_vector'] == (
        'unsupported-irq:cpu-multibit-vector:ibex_rvfi_local:'
        'one-external-input:irq_external_i-width-1')
    assert refusals['device_active_low'] == (
        'unsupported-irq:device-active-low:no-declared-target-output-active-low')
    assert refusals['write_one_clear'].startswith(
        'unsupported-irq:write-one-clear:')
    # A profile that really composes an NMI input is not refused for NMI; the
    # refusal is the profile's own constant action, never a harness preference.
    composed = dict(ibex, port_actions=[
        dict(row, action='connect') if row.get('port') == 'irq_nm_i' else row
        for row in ibex['port_actions']])
    assert advanced_irq_refusals(composed)['nmi'] is None
