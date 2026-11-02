"""Declared-IRQ F5 on a pc/insn/order-only CPU: real limited chain and refusals.

The journal below is synthetic but shaped exactly like an actual
``cv32e40p_rvfi_local`` journal: every ``cpu_retire.v2`` event carries only
``valid``/``order``/``insn``/``pc_rdata`` (never ``intr``, ``pc_wdata``,
``trap``, ``halt``, ``mode`` or ``mem_*``), the take carries the real pre-edge
ack/id/entry-PC acceptance and no serial document at all, and the target/CPU
OBI/data events keep the same shapes the full-RVFI journals use.

Expectations come from the declared firmware image, the registered CPU
contract and the journal, never from the observation document.
"""
import json
from types import SimpleNamespace

import pytest

from myfuzz.integration.declared_irq_consumption import (
    MRET_WORD, _jal, build_declared_irq_firmware, firmware_code,
    observe_declared_irq_consumption, retirement_only_provider)
from myfuzz.local_harness.native_irq_receipt_contract import (
    cv32e40p_irq_receipt_contract)
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember

BASE = 0x40001000
RESULT = 0x10c40
PARK = 0x11040
IMAGE = (0x10000, 0x30000)
FIRST_FETCH = 0x10080
TARGET = 'spi_active'
IDLE = 'spi_idle'
PORT = 'events_o'
WIRE = 'rt_lh_p_16_1_0'
EXECUTION = 'local-driver:cpu:1'
TAKE_EVENT = 11
CONTRACT = cv32e40p_irq_receipt_contract()
TRANSACTION = dict(execution_id='local-execution', testcase_id='declared-irq-f5-limited',
                   source_component='cpu', source_epoch=0, channel_id='data',
                   source_sequence=1)
WRITE_TRANSACTION = dict(TRANSACTION, source_sequence=2)
OBI_DATA = {'addr': 'trace_obi_d_addr', 'be': 'trace_obi_d_be', 'error': 'trace_obi_d_error',
            'gnt': 'trace_obi_d_gnt', 'rdata': 'trace_obi_d_rdata', 'req': 'trace_obi_d_req',
            'rvalid': 'trace_obi_d_rvalid', 'wdata': 'trace_obi_d_wdata', 'we': 'trace_obi_d_we'}
OBI_INSTR = {'addr': 'trace_obi_i_addr', 'error': 'trace_obi_i_error', 'gnt': 'trace_obi_i_gnt',
             'rdata': 'trace_obi_i_rdata', 'req': 'trace_obi_i_req', 'rvalid': 'trace_obi_i_rvalid'}
TRACES = {'data': OBI_DATA, 'instr': OBI_INSTR}
POLICY = dict(mode='native_error_role', native_error_observation=True)
TARGET_TRACES = {
    'apb3': {'protocol': 'apb3', 'signals': {
        'paddr': 'trace_paddr', 'psel': 'trace_psel', 'penable': 'trace_penable',
        'pwrite': 'trace_pwrite', 'pready': 'trace_pready', 'prdata': 'trace_prdata',
        'pslverr': 'trace_pslverr', 'pwdata': 'trace_pwdata'}},
    'wishbone': {'protocol': 'wishbone', 'signals': {
        'cyc': 'trace_cyc', 'stb': 'trace_stb', 'we': 'trace_we', 'dat_w': 'trace_dat_w',
        'sel': 'trace_sel', 'ack': 'trace_ack', 'stall': 'trace_stall', 'dat_r': 'trace_dat_r'}},
}
#: The two declared targets of the new limited configs.
TARGETS = (('apb3', 40), ('wishbone', 0))


def firmware(offset=40):
    return build_declared_irq_firmware(image_start=IMAGE[0], image_end=IMAGE[1],
                                       first_fetch=FIRST_FETCH, target_base=BASE,
                                       status_offsets=(offset,), result_address=RESULT)


def delivery_group():
    return IrqDeliveryGroup('declared-f5-or-' + TARGET, 'cpu', 'irq', (
        IrqDeliveryMember(TARGET, PORT, pulse_width_ticks=16, source_bit_offset=0,
                          source_adapter='declared-output.v1'),
        IrqDeliveryMember(IDLE, PORT, pulse_width_ticks=16, source_bit_offset=0,
                          source_adapter='declared-output.v1')))


def access(offset=40):
    return dict(device_id=TARGET, target_component=TARGET, window_base=BASE,
                window_size=4096, offset=offset)


def entry_address(build, kind):
    return {'vector': build['vector'],
            'vector_external': build['vector_external'],
            'handler': build['handler']}[kind]


def cpu_step(identifier, tick, *, data=None, instr=None):
    """One parsed CPU step with its OBI driver taps (same shape as the real one)."""
    taps = {signal: 0 for signal in {**OBI_DATA, **OBI_INSTR}.values()}
    taps[OBI_INSTR['gnt']] = 1
    for roles, values in ((OBI_DATA, data or {}), (OBI_INSTR, instr or {})):
        for role, value in values.items():
            taps[roles[role]] = value
    return dict(kind=None, component='cpu', event_id=identifier, local_tick=tick,
                inputs={'irq': 0},
                outputs={'driver_samples': [dict(local_tick=tick, pre={'protocol_taps': taps},
                                                 post={})]})


def sample_row(identifier, *, component, phase, tick, backend, value=0):
    return dict(kind='local_tick_sample', component=component, event_id=identifier,
                local_tick=tick, phase=phase, reset_epoch=0, producer_event_id=10 ** 6,
                observation_schema_version='ip_raw_observation.v1',
                outputs=dict(backend=backend, physical={WIRE: value, 'rt_lh_p_17_0_0': 0},
                             **{PORT: value, 'spi_clk': 0, 'spi_csn0': 1}))


def target_rows(signals, protocol, offset, value, ids):
    """The target's own native samples of one accepted register read."""
    rows = []
    blank = {name: 0 for name in signals.values()}
    if protocol == 'apb3':
        backend = dict(blank)
        backend.update({signals['psel']: 1, signals['penable']: 1, signals['pready']: 1,
                        signals['pwrite']: 0, signals['paddr']: offset,
                        signals['prdata']: value})
        rows.append(sample_row(ids[0], component=TARGET, phase='pre', tick=100, backend=backend))
        rows.append(sample_row(ids[1], component=TARGET, phase='post', tick=100, backend=dict(blank)))
        return rows
    request = dict(blank)
    request.update({signals['cyc']: 1, signals['stb']: 1, signals['we']: 0,
                    signals['sel']: 15, signals['stall']: 0, signals['ack']: 0})
    held = dict(request)
    held[signals['stb']] = 0
    rows.append(sample_row(ids[0], component=TARGET, phase='pre', tick=100, backend=request))
    rows.append(sample_row(ids[1], component=TARGET, phase='post', tick=100, backend=held))
    ack = dict(blank)
    ack.update({signals['cyc']: 1, signals['stb']: 0, signals['stall']: 0,
                signals['ack']: 1, signals['dat_r']: value})
    rows.append(sample_row(ids[2], component=TARGET, phase='pre', tick=101, backend=ack))
    return rows


def retirement(identifier, *, order, pc, insn, tick, sequence):
    """One pc/insn/order-only retirement: only the four real RVFI fields."""
    return dict(kind='cpu_retire', component='cpu', event_id=identifier, order=order,
                pc_rdata=pc, insn=insn, valid=1, local_tick=tick, phase='post',
                schema_version='cpu_retire.v2',
                receipt_id=dict(execution=EXECUTION, sequence=sequence),
                observation_contract=CONTRACT)


def build_limited_journal(*, protocol='apb3', offset=40, value=0x0, entry='vector_external',
                          successor_pc=PARK, successor_insn=None):
    """One complete declared-IRQ F5 case journal of a field-light CPU.

    Event identity layout (actual causal order, producer channels interleaved):
      1..12   target pulse origin, idle sample, CPU input sample, native take, OR frame
      20      documented entry retirement at the real pre-edge entry PC
      30..62  data-channel request, MMIO acceptance, delivery, target samples, response,
              dependent RAM store and its response
      100..   the declared handler path from the entry to exactly one MRET
      300..   successor instruction response, source read and retirement
    """
    build = firmware(offset)
    path = [(pc, word) for pc, word in build['retirement_path']]
    code = firmware_code(build)
    read_pc = next(row['pc'] for row in build['memory_operations'] if row['kind'] == 'read')
    write_pc = next(row['pc'] for row in build['memory_operations']
                    if row['kind'] == 'write' and 'result_index' in row)
    entry_pc = entry_address(build, entry)
    signals = TARGET_TRACES[protocol]['signals']
    group = delivery_group()
    successor_insn = _jal(PARK, PARK) if successor_insn is None else successor_insn
    events = []
    blank = {name: 0 for name in signals.values()}

    def add(row):
        events.append(row)
        return row

    add(dict(kind='local_tick_sample', component=TARGET, event_id=1, local_tick=60, phase='post',
             reset_epoch=0, producer_event_id=1,
             observation_schema_version='ip_raw_observation.v1',
             outputs=dict(backend=dict(blank), physical={WIRE: 1, 'rt_lh_p_17_0_0': 0},
                          **{PORT: 1})))
    add(dict(kind='local_tick_sample', component=IDLE, event_id=2, local_tick=60, phase='post',
             reset_epoch=0, producer_event_id=2,
             observation_schema_version='ip_raw_observation.v1',
             outputs=dict(backend=dict(blank), physical={WIRE: 0, 'rt_lh_p_17_0_0': 0},
                          **{PORT: 0})))
    add(dict(kind='cpu_external_irq_sample', component='cpu', event_id=10, local_tick=90,
             producer_event_id=9, expected_input=1, actual_pre_input=1, actual_post_input=1,
             irq_masked_pre=0, reset_epoch=0, phase='pre_post_rising',
             schema_version='cpu_external_irq_sample.v1',
             receipt_id=dict(execution=EXECUTION, sequence=3),
             observation_contract=CONTRACT))
    add(dict(kind='cpu_external_irq_taken', component='cpu', event_id=TAKE_EVENT,
             local_tick=90, producer_event_id=9, sample_event_id=10, take_key=['cpu', 0, 1],
             expected_input=1, actual_pre_input=1, actual_post_input=1, irq_masked_pre=0,
             irq_taken_pre=1, irq_ack_pre=1, irq_id_pre=11, irq_entry_pc=entry_pc,
             accepted_source_id=11, reset_epoch=0, phase='pre_post_rising',
             schema_version='cpu_external_irq_taken.v1',
             receipt_id=dict(execution=EXECUTION, sequence=3),
             observation_contract=CONTRACT))
    add(dict(kind='irq_group_delivery', event_id=12, group_id=group.group_id,
             group_sha256=group.identity_sha256, target_component='cpu', target_port='irq',
             cpu_tick=90, value=1, attribution_status='unique',
             unique_source=TARGET + '.' + PORT, active_sources=[TARGET + '.' + PORT],
             native_sample_event_id=10, native_take_event_id=TAKE_EVENT,
             cpu_step_event_id=9, take_key=['cpu', 0, 1], members=[
                 dict(source_id=TARGET + '.' + PORT, mode='pulse', value=1,
                      native_source=dict(adapter_id='declared-output.v1', component=TARGET,
                                         event_id=1, local_tick=60, phase='post',
                                         reset_epoch=0, runtime_name=WIRE),
                      latest_native_source=dict(adapter_id='declared-output.v1',
                                                component=TARGET, event_id=1, local_tick=60,
                                                phase='post', reset_epoch=0,
                                                runtime_name=WIRE)),
                 dict(source_id=IDLE + '.' + PORT, mode='pulse', value=0,
                      native_source=dict(adapter_id='declared-output.v1', component=IDLE,
                                         event_id=2, local_tick=60, phase='post',
                                         reset_epoch=0, runtime_name=WIRE),
                      latest_native_source=dict(adapter_id='declared-output.v1',
                                                component=IDLE, event_id=2, local_tick=60,
                                                phase='post', reset_epoch=0,
                                                runtime_name=WIRE))]))
    entry_insn = code[entry_pc]
    order = 10
    sequence = 100
    if entry_pc != path[0][0]:
        add(retirement(20, order=order, pc=entry_pc, insn=entry_insn, tick=95, sequence=sequence))
    read_position = next(position for position, (pc, _) in enumerate(path) if pc == read_pc)
    write_position = next(position for position, (pc, _) in enumerate(path) if pc == write_pc)
    for position, (pc, word) in enumerate(path):
        order += 1
        sequence += 1
        # Data-channel identity slots: nine ids below each retirement, so every
        # parsed service event lands strictly between the previous retirement and
        # the load/store it belongs to (the real causal order).
        identifier = 1000 + 10 * position
        if position == read_position:
            base = identifier - 9
            tap = cpu_step(base, 97, data={'req': 1, 'gnt': 1, 'addr': BASE + offset, 'we': 0,
                                           'be': 15, 'wdata': 0, 'rvalid': 0, 'error': 0})
            acceptance = dict(kind='mmio_acceptance', component='cpu', event_id=base + 1,
                              device_id=TARGET, address=BASE + offset, offset=offset,
                              write=False, byte_enable=15, producer_event_id=base,
                              source_transaction=dict(TRANSACTION))
            delivery = dict(kind='mmio_delivery', component='cpu', event_id=base + 2,
                            device_id=TARGET, address=BASE + offset, offset=offset,
                            write=False, byte_enable=15, read_value=value, write_value=None,
                            producer_event_id=base, source_transaction=dict(TRANSACTION),
                            beat_bytes=4)
            samples = target_rows(signals, protocol, offset, value,
                                  (base + 3, base + 4, base + 5))
            for row in samples:
                row['producer_event_id'] = base
            response = cpu_step(base + 6, 98, data={'req': 0, 'gnt': 1, 'addr': BASE + offset,
                                                    'rvalid': 1, 'rdata': value, 'error': 0,
                                                    'be': 15})
            events.extend([tap, acceptance, delivery, *samples, response])
        if position == write_position:
            base = identifier - 9
            tap = cpu_step(base, 99, data={'req': 1, 'gnt': 1, 'addr': RESULT, 'we': 1,
                                           'be': 15, 'wdata': value, 'rvalid': 0, 'error': 0})
            memory_write = dict(kind='memory_write', component='cpu', event_id=base + 1,
                                address=RESULT, value=value, byte_enable=15, width_bytes=4,
                                generation=0, byte_offset=RESULT - IMAGE[0],
                                producer_event_id=base, transaction=dict(WRITE_TRANSACTION),
                                version=[0, 1])
            response = cpu_step(base + 2, 100, data={'req': 0, 'gnt': 1, 'addr': RESULT,
                                                     'rvalid': 1, 'rdata': 0, 'error': 0, 'be': 15})
            events.extend([tap, memory_write, response])
        add(retirement(identifier, order=order, pc=pc, insn=word,
                       tick=96 + position, sequence=sequence))
    mret_pc = path[-1][0]
    tail = 1000 + 10 * len(path)
    successor = retirement(tail + 2, order=order + 1, pc=successor_pc, insn=successor_insn,
                           tick=200, sequence=sequence + 1)
    instr_response = dict(kind='instr_response', component='cpu', event_id=tail,
                          address=successor_pc, rdata=successor_insn, error=0,
                          response_tick=199, acceptance_tick=198, reset_epoch=0,
                          transaction=dict(TRANSACTION, channel_id='instr', source_sequence=9))
    memory_read = dict(kind='memory_read', component='cpu', event_id=tail + 1,
                       address=successor_pc,
                       data_hex=successor_insn.to_bytes(4, 'little').hex(), value=successor_insn,
                       generation=0, memory_id='ram', byte_offset=successor_pc - IMAGE[0],
                       width_bytes=4, versions=[[0, 0]] * 4,
                       writer_event_ids=['initial-image'] * 4,
                       transaction=dict(instr_response['transaction']), producer_event_id=tail - 1)
    events.extend([instr_response, memory_read, successor])
    return dict(events=events, firmware=build, group=group, path=path, entry=entry,
                entry_pc=entry_pc, read_pc=read_pc, write_pc=write_pc, mret_pc=mret_pc,
                successor_pc=successor_pc, successor_id=successor['event_id'],
                successor_insn=successor_insn, value=value,
                protocol=protocol, offset=offset, order=order, sequence=sequence)


def observe(journal, **overrides):
    arguments = dict(events=tuple(journal['events']),
                     receipt=SimpleNamespace(case_id='declared-irq-f5-limited',
                                             events=tuple(journal['events'])),
                     traces=TRACES, error_policy=POLICY, cpu_id='cpu', target_id=TARGET,
                     access=access(journal['offset']), firmware=journal['firmware'],
                     group=journal['group'],
                     target_trace=TARGET_TRACES[journal['protocol']],
                     successor_range=IMAGE, cpu_contract=CONTRACT)
    arguments.update(overrides)
    return observe_declared_irq_consumption(**arguments)


def find(event_id, journal):
    return next(row for row in journal['events'] if row['event_id'] == event_id)


def handler_event(position, journal):
    """The retirement of one documented handler-path position."""
    return find(1000 + 10 * position, journal)


def assert_refused(document, reason):
    assert document['status'] == 'refused', document['refusals']
    assert document['irq_consumption'] == 'unknown'
    assert document['consumption']['irq_consumption'] == 'unknown'
    assert document['reward_eligible'] is False and document['grants_F5'] is False
    assert any(reason in refusal for refusal in document['refusals']), document['refusals']


# ---------------------------------------------------------------------------
# Positive chain
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('protocol,offset', TARGETS)
@pytest.mark.parametrize('entry', ['vector', 'vector_external', 'handler'])
def test_limited_chain_is_verified_by_documented_order(protocol, offset, entry):
    journal = build_limited_journal(protocol=protocol, offset=offset, entry=entry)
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['irq_consumption'] == 'verified'
    transport = document['transport']
    # No serial token exists on this CPU, so the transport never mints one.
    assert transport['decision_serial'] is None
    assert transport['decision_serial_status'] == 'unavailable'
    assert 'irq_serial_observation' not in transport['native_take']
    assert transport['native_take']['irq_entry_pc'] == journal['entry_pc']
    assert transport['native_take']['irq_ack_pre'] == 1
    assert transport['native_take']['irq_id_pre'] == 11
    assert transport['first_handler_retirement']['scope'] == \
        'first_retirement_after_native_take'
    assert transport['first_handler_retirement']['retirement_joins'] == 'by_documented_order'
    consumption = document['consumption']
    assert consumption['retirement_joins'] == 'by_documented_order'
    assert consumption['retirement_authority'] == 'pc_insn_order_only'
    assert consumption['per_retirement_join'] == 'unobservable'
    assert consumption['join_scope'] == 'ordered_retirement_to_actual_data_transaction'
    assert consumption['pre_entry_retirements'] == []
    assert 'mem_wdata' in consumption['unobserved_retirement_fields']
    assert consumption['value_join'] == 'delivery_read_value==OBI_rdata==RAM_write_value'
    # The real value joins survive; only the per-retirement mem_* value is absent.
    read, = consumption['register_reads']
    assert read['offset'] == journal['offset'] and read['value'] == journal['value']
    assert read['retirement_join'] == 'by_documented_order'
    assert read['native_OBI']['rdata'] == journal['value']
    assert consumption['result_ram_writes'][0]['value'] == journal['value']
    assert consumption['result_ram_writes'][0]['address'] == RESULT
    assert consumption['result_ram_writes'][0]['retirement_pc'] == journal['write_pc']
    # The documented path starts at the real entry PC and ends at exactly one MRET.
    expected = [(journal['entry_pc'], firmware_code(journal['firmware'])[journal['entry_pc']])] \
        if journal['entry'] != 'handler' else []
    expected.extend(journal['path'])
    assert [(row['pc'], row['insn']) for row in consumption['handler_retirements']] == expected
    assert consumption['mret']['insn'] == MRET_WORD
    assert consumption['mret']['pc'] == journal['mret_pc']
    assert consumption['return_target'] == journal['successor_pc']
    assert consumption['successor']['source_byte_version']['status'] == 'observed'
    # No field this CPU never drives is required or emitted.
    assert 'raw_pc_wdata' not in consumption['mret']
    assert 'raw_mret_pc_wdata' not in consumption['successor']
    assert 'raw_mret_pc_wdata' not in json.dumps(consumption)
    assert 'raw_pc_wdata' not in json.dumps(consumption)
    assert consumption['successor']['return_target_source'] == \
        'first_subsequent_valid_retirement_pc'
    assert consumption['successor']['retirement_authority'] == 'pc_insn_order_only'
    for row in consumption['handler_retirements']:
        assert not ({'intr', 'trap', 'halt', 'mode', 'pc_wdata', 'mem_addr', 'mem_rdata',
                     'mem_wdata', 'mem_rmask', 'mem_wmask'} & set(row))
    assert document['unknown']['cpu_observation_contract'] == 'declared'
    assert document['cause_source'] == 'unknown'
    assert document['unknown']['internal_ip_cause'] == 'unknown'
    assert document['unknown']['internal_version'] == 'unknown'
    assert document['unknown']['case_origin'] == 'unknown'
    for flag in ('reward_eligible', 'grants_F5', 'grants_F6', 'grants_prerequisites'):
        assert document[flag] is False


def test_limited_chain_accepts_a_pre_entry_retirement_by_documented_order():
    """A retirement between the take and the entry stays evidence, not a guess."""
    journal = build_limited_journal(entry='vector_external')
    entry = find(20, journal)
    before = retirement(13, order=entry['order'] - 1, pc=0x10ffc, insn=0x00000013,
                        tick=94, sequence=entry['receipt_id']['sequence'] - 1)
    before['event_id'] = 13
    journal['events'].insert(5, before)
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    pre_entry = document['consumption']['pre_entry_retirements']
    assert [row['pc'] for row in pre_entry] == [0x10ffc]
    assert document['consumption']['handler_retirements'][0]['pc'] == journal['entry_pc']


def test_limited_chain_refuses_without_the_real_shared_helpers(monkeypatch):
    import myfuzz.integration.shared_irq_firmware as shared
    journal = build_limited_journal()
    assert retirement_only_provider() is not None
    monkeypatch.delattr(shared, '_limited_retirement_window')
    document = observe(journal)
    assert_refused(document, 'declared-F5-pc-insn-order-only-retirement-work-unavailable')


# ---------------------------------------------------------------------------
# Refusals: fabricated fields, serial, order and successor
# ---------------------------------------------------------------------------
def test_fabricated_intr_on_a_handler_retirement_is_refused():
    journal = build_limited_journal()
    handler_event(3, journal)['intr'] = 0
    assert_refused(observe(journal), 'native-limited-fabricated-retirement-field:intr')


def test_fabricated_pc_wdata_on_the_mret_is_refused():
    journal = build_limited_journal()
    for row in journal['events']:
        if row.get('kind') == 'cpu_retire' and row.get('pc_rdata') == journal['mret_pc']:
            row['pc_wdata'] = journal['successor_pc']
    assert_refused(observe(journal), 'native-limited-fabricated-retirement-field:pc_wdata')


def test_fabricated_mem_field_on_a_load_retirement_is_refused():
    journal = build_limited_journal()
    for row in journal['events']:
        if row.get('kind') == 'cpu_retire' and row.get('pc_rdata') == journal['read_pc']:
            row['mem_addr'] = BASE + journal['offset']
    assert_refused(observe(journal), 'native-limited-fabricated-retirement-field:mem_addr')


def test_fabricated_successor_pc_wdata_is_refused():
    journal = build_limited_journal()
    find(journal['successor_id'], journal)['pc_wdata'] = journal['successor_pc']
    assert_refused(observe(journal), 'native-limited-fabricated-successor-retirement-field:pc_wdata')


def test_observed_decision_serial_on_the_take_is_refused():
    journal = build_limited_journal()
    find(TAKE_EVENT, journal)['irq_serial_observation'] = dict(
        decision=dict(status='observed', value=1, phase='pre'),
        retirement=dict(status='observed', value=0, phase='post'))
    assert_refused(observe(journal), 'declared-F5-limited-CPU-fabricated-decision-serial')


def test_observed_retirement_serial_on_the_take_is_refused():
    journal = build_limited_journal()
    find(TAKE_EVENT, journal)['irq_serial_observation'] = dict(
        retirement=dict(status='observed', value=0, phase='post'))
    assert_refused(observe(journal), 'declared-F5-limited-CPU-fabricated-retirement-serial')


def test_observed_serial_on_a_handler_retirement_is_refused():
    journal = build_limited_journal()
    handler_event(3, journal)['irq_serial_observation'] = dict(
        retirement=dict(status='observed', value=3, phase='post'))
    assert_refused(observe(journal), 'declared-F5-limited-CPU-fabricated-retirement-serial')


def test_explicitly_unobservable_serial_is_not_a_claim():
    journal = build_limited_journal()
    find(TAKE_EVENT, journal)['irq_serial_observation'] = dict(
        retirement=dict(status='unobservable', value=None))
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['transport']['decision_serial'] is None


def test_non_contiguous_retirement_order_is_refused():
    journal = build_limited_journal()
    handler_event(4, journal)['order'] += 1
    assert_refused(observe(journal), 'native-fixed-ISR-retirement-order-mismatch')


def test_successor_order_skip_is_refused():
    journal = build_limited_journal()
    find(journal['successor_id'], journal)['order'] = journal['order'] + 2
    assert_refused(observe(journal), 'native-ISR-first-successor-not-current-dynamic-return')


def test_fabricated_intr_on_the_successor_is_refused():
    journal = build_limited_journal()
    find(journal['successor_id'], journal)['intr'] = 0
    assert_refused(observe(journal), 'native-ISR-first-successor-not-current-dynamic-return')


def test_missing_mret_is_refused():
    journal = build_limited_journal()
    journal['events'] = [row for row in journal['events']
                         if not (row.get('kind') == 'cpu_retire'
                                 and row.get('pc_rdata') == journal['mret_pc'])]
    assert_refused(observe(journal), 'native-fixed-ISR-retire-sequence-mismatch')


def test_entry_pc_outside_the_fixed_vector_is_refused():
    journal = build_limited_journal()
    find(TAKE_EVENT, journal)['irq_entry_pc'] = 0x20000
    assert_refused(observe(journal),
                   'declared-F5-limited-CPU-entry-retirement-outside-fixed-vector')


def test_missing_retirement_observation_contract_is_refused():
    journal = build_limited_journal()
    del handler_event(2, journal)['observation_contract']
    assert_refused(observe(journal), 'native-fixed-ISR-retire-scope-mismatch')


def test_unverified_take_acceptance_is_refused():
    journal = build_limited_journal()
    find(TAKE_EVENT, journal)['irq_ack_pre'] = 0
    assert_refused(observe(journal), 'declared-F5-limited-CPU-native-acceptance')


def test_real_exception_redirect_before_the_mret_is_refused():
    """trap/halt are unobservable here, so the real redirect probe is the evidence."""
    journal = build_limited_journal()
    redirect = dict(kind='cpu_native_exception_redirect', component='cpu', event_id=21,
                    local_tick=95, redirect_cause=2, observation_contract=CONTRACT)
    journal['events'].insert(6, redirect)
    assert_refused(observe(journal), 'declared-F5-limited-CPU-exception-redirect-before-MRET')


def test_limited_document_never_claims_a_value_level_retirement_join():
    journal = build_limited_journal()
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    consumption = document['consumption']
    assert consumption['retirement_joins'] != 'exact_fields'
    assert consumption['successor']['retirement_authority'] == 'pc_insn_order_only'
    assert 'retirement_mem_value' not in consumption['value_join']
    # A saved full-RVFI judgement cannot be replayed as a limited one: the raw
    # MRET write data is simply absent from the document.
    serialized = json.dumps(document['consumption'], sort_keys=True)
    assert '"raw_mret_pc_wdata"' not in serialized
    assert '"raw_pc_wdata"' not in serialized
