"""Declared-IRQ F5 layered observation: positive chain and every refusal.

The input journals below are synthetic but shaped exactly like the actual
journals of the existing native chains (APB3/Wishbone/AHB-Lite target samples,
CPU OBI driver taps, mmio acceptance/delivery, memory writes, RVFI retirements
and the host OR group frame).  Expectations are derived from those input
documents and from the fixed firmware image, never from the observation output.
"""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration.declared_irq_consumption import (
    MRET_WORD, _jal, _lw, _sw, build_declared_irq_firmware, firmware_code,
    observe_declared_irq_consumption)
from myfuzz.local_harness.native_irq_receipt_contract import ibex_irq_receipt_contract
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x40001000
RESULT = 0x10c40
PARK = 0x11040
TARGET = 'spi_active'
IDLE = 'spi_idle'
PORT = 'events_o'
WIRE = 'rt_lh_p_16_1_0'
STATUS_OFFSET = 40
READ_VALUE = 0x0
TRANSACTION = dict(execution_id='local-execution', testcase_id='declared-irq-f5-case',
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
    'ahb-lite': {'protocol': 'ahb-lite', 'signals': {
        'haddr': 'trace_haddr', 'hwdata': 'trace_hwdata', 'hsel': 'trace_hsel',
        'hwrite': 'trace_hwrite', 'hreadyin': 'trace_hreadyin', 'htrans': 'trace_htrans',
        'hsize': 'trace_hsize', 'hresp': 'trace_hresp', 'hreadyout': 'trace_hreadyout',
        'hrdata': 'trace_hrdata'}},
}


def firmware(**overrides):
    arguments = dict(image_start=0x10000, image_end=0x30000, first_fetch=0x10080,
                     target_base=BASE, status_offsets=(STATUS_OFFSET,), result_address=RESULT)
    arguments.update(overrides)
    return build_declared_irq_firmware(**arguments)


def delivery_group():
    return IrqDeliveryGroup('declared-f5-or-' + TARGET, 'cpu', 'irq', (
        IrqDeliveryMember(TARGET, PORT, pulse_width_ticks=16, source_bit_offset=0,
                          source_adapter='declared-output.v1'),
        IrqDeliveryMember(IDLE, PORT, pulse_width_ticks=16, source_bit_offset=0,
                          source_adapter='declared-output.v1')))


def access():
    return dict(device_id=TARGET, target_component=TARGET, window_base=BASE, window_size=4096,
                offset=STATUS_OFFSET)


def operation_pcs(build):
    """Decode the handler image and locate the declared LW and its dependent SW."""
    handler = {row['address']: bytes.fromhex(row['data_hex']) for row in build['segments']
               if row['name'] == 'handler'}[build['handler']]
    words = [int.from_bytes(handler[offset:offset + 4], 'little')
             for offset in range(0, len(handler), 4)]
    read_pc = write_pc = None
    for position, word in enumerate(words):
        pc = build['handler'] + 4 * position
        if word & 0x7f == 0x03 and read_pc is None and word >> 20 == STATUS_OFFSET:
            read_pc = pc
        elif word & 0x7f == 0x23 and write_pc is None and ((word >> 15) & 31) == 3:
            write_pc = pc
    assert read_pc is not None and write_pc is not None
    return read_pc, write_pc


def cpu_step(identifier, tick, *, data=None, instr=None):
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
                local_tick=tick, phase=phase, reset_epoch=0,
                producer_event_id=10**6,
                observation_schema_version='ip_raw_observation.v1',
                outputs=dict(backend=backend, physical={WIRE: value, 'rt_lh_p_17_0_0': 0},
                             **{PORT: value, 'spi_clk': 0, 'spi_csn0': 1}))


def target_rows(signals, protocol, offset, value, ids):
    """The target's own native samples of one accepted register read."""
    rows = []
    blank = {name: 0 for name in signals.values()}
    if protocol == 'apb3':
        backend = dict(blank)
        backend[signals['psel']] = 1
        backend[signals['penable']] = 1
        backend[signals['pready']] = 1
        backend[signals['pwrite']] = 0
        backend[signals['paddr']] = offset
        backend[signals['prdata']] = value
        rows.append(sample_row(ids[0], component=TARGET, phase='pre', tick=100, backend=backend))
        rows.append(sample_row(ids[1], component=TARGET, phase='post', tick=100, backend=dict(blank)))
        return rows
    if protocol == 'wishbone':
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
    request = dict(blank)
    request.update({signals['hsel']: 1, signals['htrans']: 2, signals['hwrite']: 0,
                    signals['hreadyin']: 1, signals['haddr']: offset, signals['hsize']: 2})
    rows.append(sample_row(ids[0], component=TARGET, phase='pre', tick=100, backend=request))
    rows.append(sample_row(ids[1], component=TARGET, phase='post', tick=100, backend=dict(blank)))
    data = dict(blank)
    data.update({signals['htrans']: 0, signals['hresp']: 0, signals['hreadyout']: 1,
                 signals['hrdata']: value})
    rows.append(sample_row(ids[2], component=TARGET, phase='pre', tick=101, backend=data))
    return rows


def retirement(identifier, *, order, pc, insn, tick, sequence, intr=0, serial=0, **extra):
    row = dict(kind='cpu_retire', component='cpu', event_id=identifier, order=order,
               pc_rdata=pc, insn=insn, local_tick=tick, intr=intr, trap=0, halt=0, valid=1,
               schema_version='cpu_retire.v2',
               receipt_id=dict(execution='local-driver:cpu:1', sequence=sequence),
               irq_serial_observation=dict(
                   sampling='pre_post_rising', schema_version='ibex_irq_serial_observation.v1',
                   width_bits=64, zero_semantics='no_provable_source_lineage',
                   decision=dict(status='observed', value=serial),
                   retirement=dict(status='observed', value=serial, phase='post',
                                   physical_port='irq_retirement_serial')))
    row.update(extra)
    return row


def build_journal(*, protocol='apb3', value=READ_VALUE, contract=None, full_fields=True,
                  successor_pc=PARK, successor_insn=None):
    """One complete declared-IRQ F5 case journal of the fixed firmware.

    Event identity layout (strictly increasing, actual causal order):
      1..12   target pulse origin, idle sample, CPU input sample, native take, OR frame
      30..50  data-channel request, MMIO acceptance, delivery, target samples, response
      60..62  dependent RAM store request, memory write, response
      100..   trap entry retirement (serial 3) then the documented handler path
      300..   successor instruction response, source read and retirement
    """
    build = firmware()
    path = [(pc, word) for pc, word in build['retirement_path']]
    read_pc, write_pc = operation_pcs(build)
    code = firmware_code(build)
    vector = build['vector']
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
             irq_masked_pre=0, reset_epoch=0,
             **({'observation_contract': contract} if contract is not None else {})))
    add(dict(kind='cpu_external_irq_taken', component='cpu', event_id=11, local_tick=90,
             producer_event_id=9, sample_event_id=10, take_key=['cpu', 0, 1],
             expected_input=1, actual_pre_input=1, actual_post_input=1, irq_masked_pre=0,
             irq_taken_pre=1, reset_epoch=0,
             irq_serial_observation=dict(
                 sampling='pre_post_rising', schema_version='ibex_irq_serial_observation.v1',
                 width_bits=64, zero_semantics='no_provable_source_lineage',
                 decision=dict(status='observed', value=3, phase='pre',
                               physical_port='irq_decision_serial'),
                 retirement=dict(status='observed', value=0, phase='post',
                                 physical_port='irq_retirement_serial')),
             **({'observation_contract': contract} if contract is not None else {})))
    add(dict(kind='irq_group_delivery', event_id=12, group_id=group.group_id,
             group_sha256=group.identity_sha256, target_component='cpu', target_port='irq',
             cpu_tick=90, value=1, attribution_status='unique',
             unique_source=TARGET + '.' + PORT, active_sources=[TARGET + '.' + PORT],
             native_sample_event_id=10, native_take_event_id=11, cpu_step_event_id=9,
             take_key=['cpu', 0, 1], members=[
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

    entry = retirement(20, order=10, pc=vector, insn=code[vector], tick=95, sequence=100,
                       intr=1, serial=3)
    if contract is not None:
        entry['observation_contract'] = contract
    add(entry)

    read_acceptance = cpu_step(30, 97, data={'req': 1, 'gnt': 1, 'addr': BASE + STATUS_OFFSET,
                                             'we': 0, 'be': 15, 'wdata': 0, 'rvalid': 0,
                                             'error': 0})
    acceptance = dict(kind='mmio_acceptance', component='cpu', event_id=31, device_id=TARGET,
                      address=BASE + STATUS_OFFSET, offset=STATUS_OFFSET, write=False,
                      byte_enable=15, producer_event_id=30, source_transaction=dict(TRANSACTION))
    delivery = dict(kind='mmio_delivery', component='cpu', event_id=32, device_id=TARGET,
                    address=BASE + STATUS_OFFSET, offset=STATUS_OFFSET, write=False,
                    byte_enable=15, read_value=value, write_value=None, producer_event_id=30,
                    source_transaction=dict(TRANSACTION), beat_bytes=4)
    samples = target_rows(signals, protocol, STATUS_OFFSET, value,
                          (40, 41, 42) if protocol != 'apb3' else (40, 41))
    for row in samples:
        row['producer_event_id'] = 30
    read_response = cpu_step(50, 98, data={'req': 0, 'gnt': 1, 'addr': BASE + STATUS_OFFSET,
                                           'rvalid': 1, 'rdata': value, 'error': 0, 'be': 15})
    write_acceptance = cpu_step(60, 99, data={'req': 1, 'gnt': 1, 'addr': RESULT, 'we': 1,
                                              'be': 15, 'wdata': value, 'rvalid': 0, 'error': 0})
    memory_write = dict(kind='memory_write', component='cpu', event_id=61, address=RESULT,
                        value=value, byte_enable=15, width_bytes=4, generation=0,
                        byte_offset=RESULT - 0x10000, producer_event_id=60,
                        transaction=dict(WRITE_TRANSACTION), version=[0, 1])
    write_response = cpu_step(62, 100, data={'req': 0, 'gnt': 1, 'addr': RESULT, 'rvalid': 1,
                                             'rdata': 0, 'error': 0, 'be': 15})

    order = 10
    sequence = 100
    for position, (pc, word) in enumerate(path):
        order += 1
        sequence += 1
        if pc == read_pc:
            events.extend([read_acceptance, acceptance, delivery, *samples, read_response])
        if pc == write_pc:
            events.extend([write_acceptance, memory_write, write_response])
        if pc == read_pc:
            memory = dict(mem_addr=BASE + STATUS_OFFSET, mem_rmask=15, mem_rdata=value,
                          mem_wmask=0, mem_wdata=0)
        elif pc == write_pc:
            memory = dict(mem_addr=RESULT, mem_rmask=0, mem_rdata=0, mem_wmask=15,
                          mem_wdata=value)
        else:
            memory = dict(mem_addr=0, mem_rmask=0, mem_rdata=0, mem_wmask=0, mem_wdata=0)
        if not full_fields:
            memory = {}
        row = retirement(100 + position, order=order, pc=pc, insn=word, tick=96 + position,
                         sequence=sequence, **memory)
        if contract is not None:
            row['observation_contract'] = contract
        add(row)
    mret_pc = path[-1][0]
    successor = retirement(302, order=order + 1, pc=successor_pc, insn=successor_insn,
                           tick=200, sequence=sequence + 1)
    if contract is not None:
        successor['observation_contract'] = contract
    instr_response = dict(kind='instr_response', component='cpu', event_id=300,
                          address=successor_pc, rdata=successor_insn, error=0,
                          response_tick=199, acceptance_tick=198, reset_epoch=0,
                          transaction=dict(TRANSACTION, channel_id='instr', source_sequence=9))
    memory_read = dict(kind='memory_read', component='cpu', event_id=301, address=successor_pc,
                       data_hex=successor_insn.to_bytes(4, 'little').hex(), value=successor_insn,
                       generation=0, memory_id='ram', byte_offset=successor_pc - 0x10000,
                       width_bytes=4, versions=[[0, 0]] * 4,
                       writer_event_ids=['initial-image'] * 4,
                       transaction=dict(instr_response['transaction']), producer_event_id=299)
    events.extend([instr_response, memory_read, successor])
    return dict(events=events, firmware=build, group=group, path=path, read_pc=read_pc,
                write_pc=write_pc, mret_pc=mret_pc, successor_pc=successor_pc,
                successor_insn=successor_insn, value=value, protocol=protocol, vector=vector)


def observe(journal, **overrides):
    arguments = dict(events=tuple(journal['events']),
                     receipt=SimpleNamespace(case_id='declared-irq-f5-case',
                                             events=tuple(journal['events'])),
                     traces=TRACES, error_policy=POLICY, cpu_id='cpu', target_id=TARGET,
                     access=access(), firmware=journal['firmware'], group=journal['group'],
                     target_trace=TARGET_TRACES[journal['protocol']],
                     successor_range=(0x10000, 0x30000))
    arguments.update(overrides)
    return observe_declared_irq_consumption(**arguments)


def find(event_id, journal):
    return next(row for row in journal['events'] if row['event_id'] == event_id)


@pytest.mark.parametrize('protocol', ['apb3', 'wishbone', 'ahb-lite'])
def test_positive_chain_is_verified_with_real_values_and_joins(protocol):
    journal = build_journal(protocol=protocol, value=0x0)
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['irq_consumption'] == 'verified'
    transport = document['transport']
    assert transport['attribution'] == 'unique'
    assert transport['native_output']['raw_value'] == 1
    assert transport['native_output']['bit_value'] == 1
    assert transport['native_output']['runtime_name'] == WIRE
    assert transport['or_frame']['native_take_event_id'] == 11
    assert transport['cpu_input']['actual_pre_input'] == transport['cpu_input']['actual_post_input'] == 1
    assert transport['native_take']['irq_taken_pre'] == 1
    assert transport['decision_serial'] == 3
    consumption = document['consumption']
    read, = consumption['register_reads']
    assert read['offset'] == STATUS_OFFSET and read['value'] == journal['value']
    assert read['delivery_event'] == 32 and read['acceptance_event'] == 31
    assert read['native_OBI']['rdata'] == journal['value']
    assert read['native_pre_event'] in (40,)
    assert consumption['result_ram_writes'][0]['value'] == journal['value']
    assert consumption['result_ram_writes'][0]['address'] == RESULT
    assert consumption['result_ram_writes'][0]['retirement_pc'] == journal['write_pc']
    assert read['retirement_pc'] == journal['read_pc']
    assert [row['pc'] for row in consumption['handler_retirements']] == [pc for pc, _ in journal['path']]
    assert consumption['mret']['insn'] == MRET_WORD
    assert consumption['return_target'] == journal['successor_pc']
    assert consumption['successor']['source_byte_version']['status'] == 'observed'
    assert consumption['value_join'].endswith('retirement_mem_value==RAM_write_value')
    assert consumption['retirement_joins'] == 'exact_fields'
    # Explicit unknowns and false grants.
    assert document['cause_source'] == 'unknown'
    assert document['unknown']['internal_ip_cause'] == 'unknown'
    assert document['unknown']['internal_version'] == 'unknown'
    assert document['unknown']['case_origin'] == 'unknown'
    assert document['unknown']['cross_case_writer_attribution'] == 'unknown'
    for flag in ('reward_eligible', 'grants_F5', 'grants_F6', 'grants_prerequisites'):
        assert document[flag] is False


def test_shared_case_uses_full_real_obi_history_but_case_scoped_evidence():
    journal=build_journal()
    pending=cpu_step(0,1,instr={'req':1,'gnt':1,'addr':0x11000})
    response=cpu_step(29,96,instr={'rvalid':1,'rdata':0x13})
    case_events=tuple(sorted([*journal['events'],response],key=lambda row:row['event_id']))
    full_events=(pending,*case_events)
    receipt=SimpleNamespace(case_id='declared-irq-f5-case',events=case_events)
    verified=observe(journal,events=full_events,receipt=receipt)
    assert verified['status']=='verified', verified['refusals']
    no_history=observe(journal,events=case_events,receipt=receipt)
    assert no_history['status']=='refused'
    assert any('native-response-unowned' in reason for reason in no_history['refusals'])
    no_case_delivery=SimpleNamespace(case_id=receipt.case_id,
        events=tuple(row for row in case_events if row.get('event_id')!=32))
    refused=observe(journal,events=full_events,receipt=no_case_delivery)
    assert refused['status']=='refused'
    assert any('declared-status-read-missing' in reason for reason in refused['refusals'])


def test_positive_chain_joins_the_real_cpu_contract_when_provided():
    contract = ibex_irq_receipt_contract()
    journal = build_journal(contract=contract)
    document = observe(journal, cpu_contract=contract)
    assert document['status'] == 'verified', document['refusals']
    assert document['unknown']['cpu_observation_contract'] == 'declared'
    # A contract mismatch is an observed contradiction, never a silent pass.
    other = dict(contract, sampling='post_rising')
    with pytest.raises(ValueError):
        from myfuzz.local_harness.native_irq_receipt_contract import (
            validate_native_irq_receipt_contract)
        validate_native_irq_receipt_contract(other)
    journal = build_journal(contract=contract)
    journal['events'] = [dict(row, observation_contract=dict(contract, profile_id='other'))
                         if (row.get('kind') or '').startswith('cpu_external') else row
                         for row in journal['events']]
    refused = observe(journal, cpu_contract=contract)
    assert refused['status'] == 'refused' and refused['irq_consumption'] == 'unknown'
    assert any('CPU-observation-contract-mismatch' in reason for reason in refused['refusals'])


def test_missing_target_native_sample_refuses_consumption():
    journal = build_journal()
    journal['events'] = [row for row in journal['events']
                         if not (row.get('kind') == 'local_tick_sample'
                                 and row['component'] == TARGET and row['local_tick'] in (100, 101))]
    document = observe(journal)
    assert document['status'] == 'refused'
    assert document['irq_consumption'] == 'unknown'
    assert document['reward_eligible'] is False
    assert any('target-native-sample-missing' in reason for reason in document['refusals'])
    assert document['consumption']['irq_consumption'] == 'unknown'


def test_ambiguous_or_attribution_returns_ambiguous_without_credit():
    journal = build_journal()
    frame = find(12, journal)
    frame['attribution_status'] = 'joint'
    frame['unique_source'] = None
    frame['active_sources'] = [TARGET + '.' + PORT, IDLE + '.' + PORT]
    frame['members'][1]['value'] = 1
    document = observe(journal)
    assert document['status'] == 'ambiguous'
    assert document['irq_consumption'] == 'unknown'
    assert document['consumption']['status'] == 'ambiguous'
    assert document['consumption']['irq_consumption'] == 'unknown'
    assert document['transport']['attribution'] == 'ambiguous'
    assert document['transport']['or_frame']['active_sources'] == [TARGET + '.' + PORT,
                                                                   IDLE + '.' + PORT]
    assert document['refusals'] == ['declared-F5-OR-attribution-not-unique']
    assert document['reward_eligible'] is False and document['grants_F5'] is False


def test_take_not_from_this_receipt_refuses_transport():
    journal = build_journal()
    del find(12, journal)['native_take_event_id']
    document = observe(journal)
    assert document['status'] == 'refused'
    assert document['transport']['status'] == 'refused'
    assert any('actual-OR-delivery-take-join-required' in reason
               for reason in document['refusals'])


def test_read_value_differing_from_the_target_sample_refuses():
    journal = build_journal(protocol='apb3')
    for row in journal['events']:
        if row.get('kind') == 'local_tick_sample' and row.get('component') == TARGET \
                and row.get('local_tick') == 100 and row.get('phase') == 'pre':
            row['outputs']['backend']['trace_prdata'] = 0xdead
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('target-native-read-value-mismatch' in reason for reason in document['refusals'])


def test_ram_write_value_not_the_read_value_refuses():
    journal = build_journal()
    find(61, journal)['value'] = 0xbeef
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('dependent-RAM-write-missing' in reason for reason in document['refusals'])


def test_retirement_path_mismatch_refuses():
    journal = build_journal()
    for row in journal['events']:
        if row.get('kind') == 'cpu_retire' and row.get('pc_rdata') == journal['path'][6][0]:
            row['insn'] ^= 0x1
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('retirement-path-mismatch' in reason for reason in document['refusals'])


def test_missing_mret_refuses():
    journal = build_journal()
    journal['events'] = [row for row in journal['events']
                         if not (row.get('kind') == 'cpu_retire'
                                 and row.get('pc_rdata') == journal['mret_pc'])]
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('retirement-path-mismatch' in reason or 'retirement-path-truncated' in reason
               for reason in document['refusals'])


def test_wrong_successor_refuses():
    journal = build_journal()
    for row in journal['events']:
        if row.get('kind') == 'cpu_retire' and row.get('pc_rdata') == journal['successor_pc']:
            row['intr'] = 1
            row['irq_serial_observation']['retirement']['value'] = 1
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('native-ISR-first-successor-not-current-dynamic-return' in reason
               for reason in document['refusals'])


def test_successor_outside_the_declared_image_range_refuses():
    journal = build_journal(successor_pc=0x40001000, successor_insn=0x00000013)
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('native-ISR-first-successor-not-current-dynamic-return' in reason
               for reason in document['refusals'])


def test_fabricated_internal_version_claim_is_never_reported():
    journal = build_journal()
    # A fabricated claim injected into the caller's firmware document must not
    # reach the layered evidence.
    journal['firmware'] = dict(journal['firmware'], internal_version='sha256-v2.1.2',
                               internal_cause='error0_sts', case_origin='fuzz-case-7')
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['unknown']['internal_version'] == 'unknown'
    assert document['unknown']['internal_ip_cause'] == 'unknown'
    assert document['unknown']['case_origin'] == 'unknown'
    serialized = json.dumps(document)
    assert 'sha256-v2.1.2' not in serialized
    assert 'error0_sts' not in serialized
    assert 'fuzz-case-7' not in serialized


def test_read_status_bit_cause_needs_the_actual_read_value():
    journal = build_journal(value=0x1)
    journal['firmware'] = dict(journal['firmware'], cause_bits={str(STATUS_OFFSET): 0x1})
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['cause_source'] == 'read_status_bit'
    assert document['unknown']['internal_ip_cause'] == 'read_status_bit'
    assert document['unknown']['internal_ip_cause_proof'] == dict(
        offset=STATUS_OFFSET, mask=1, value=1, source='actual_ISR_status_read')
    # A zero status read proves nothing, so the cause stays unknown.
    journal = build_journal(value=0x0)
    journal['firmware'] = dict(journal['firmware'], cause_bits={str(STATUS_OFFSET): 0x1})
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['cause_source'] == 'unknown'
    assert document['unknown']['internal_ip_cause'] == 'unknown'


def test_field_light_retirements_join_by_documented_order_only():
    journal = build_journal(full_fields=False)
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    consumption = document['consumption']
    assert consumption['retirement_joins'] == 'by_documented_order'
    assert consumption['register_reads'][0]['retirement_join'] == 'by_documented_order'
    assert consumption['value_join'] == 'delivery_read_value==OBI_rdata==RAM_write_value'
    assert 'retirement_mem_value' not in json.dumps(consumption['value_join'])


#: Canonical digests of the full-RVFI observation documents produced before the
#: pc/insn/order-only branch landed.  Ibex and CV32E20 must stay byte-identical:
#: a limited CPU may only add its own labelled fields, never perturb these.
FULL_RVFI_DOCUMENTS = {
    'ibex_default': ('cef98817e3b8718a67e03ddbc80c1e48ac4aa86bc312b073374e991c08048578',
                     {}, True),
    'ibex_contract': ('950946ff92283d3eb0c321679cc6a4a8e4382664950b342fb6fdf8c0c5cfe01b',
                      {'contract': 'ibex'}, True),
    'cv32e20_contract': ('950946ff92283d3eb0c321679cc6a4a8e4382664950b342fb6fdf8c0c5cfe01b',
                         {'contract': 'cv32e20'}, True),
    'field_light': ('51f18ad44415ff113a6121166664ccfea39ed2e745e4bcfc303ef1fc0d5ea107',
                    {'full_fields': False}, False),
}


def _full_rvfi_digest(name, options):
    from hashlib import sha256
    from myfuzz.local_harness.native_irq_receipt_contract import (
        cv32e20_irq_receipt_contract, ibex_irq_receipt_contract)
    options = dict(options)
    kind = options.pop('contract', None)
    contract = {'ibex': ibex_irq_receipt_contract(),
                'cv32e20': cv32e20_irq_receipt_contract()}.get(kind)
    journal = build_journal(contract=contract, **options)
    document = observe(journal, cpu_contract=contract)
    assert document['status'] == 'verified', document['refusals']
    canonical = json.dumps(document, sort_keys=True, separators=(',', ':'))
    return sha256(canonical.encode()).hexdigest(), document


@pytest.mark.parametrize('name', sorted(FULL_RVFI_DOCUMENTS))
def test_full_rvfi_observation_documents_are_unchanged(name):
    digest, options, exact = FULL_RVFI_DOCUMENTS[name]
    actual, document = _full_rvfi_digest(name, options)
    assert actual == digest
    # The exact-field join and the real MRET write data stay in place.
    consumption = document['consumption']
    assert consumption['retirement_joins'] == ('exact_fields' if exact else 'by_documented_order')
    if exact:
        assert consumption['value_join'].endswith('retirement_mem_value==RAM_write_value')
    assert 'raw_pc_wdata' in consumption['mret']
    assert 'raw_mret_pc_wdata' in consumption['successor']
    assert 'retirement_authority' not in consumption
    assert 'unobserved_retirement_fields' not in consumption
    assert 'retirement_joins' not in document['transport']['first_handler_retirement']


def test_absent_observation_contract_and_source_version_stay_unavailable():
    journal = build_journal()
    journal['events'] = [row for row in journal['events']
                         if row.get('kind') != 'memory_read']
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['unknown']['cpu_observation_contract'] == 'unavailable'
    assert document['consumption']['successor']['source_byte_version'] == dict(
        status='unavailable', reason='successor-source-byte-version-not-observed')


def test_missing_native_obi_beat_refuses():
    # Without the OBI response the read beat stays outstanding, which the reused
    # native collector refuses instead of inventing a completed consumption.
    journal = build_journal()
    journal['events'] = [row for row in journal['events']
                         if not (row.get('kind') is None and row['event_id'] == 50)]
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('declared-F5-native-OBI-collection' in reason
               for reason in document['refusals'])


def test_read_outside_the_handler_window_refuses():
    journal = build_journal()
    delivery = find(32, journal)
    delivery['event_id'] = 5000
    for row in journal['events']:
        if row.get('kind') == 'mmio_acceptance':
            row['event_id'] = 4999
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('declared-status-read-missing' in reason for reason in document['refusals'])


def test_target_trace_is_required_for_the_register_read_join():
    journal = build_journal()
    document = observe(journal, target_trace=None)
    assert document['status'] == 'refused'
    assert any('target-declared-trace-required' in reason for reason in document['refusals'])


def test_second_native_take_refuses_the_single_case_claim():
    journal = build_journal()
    duplicate = deepcopy(find(11, journal))
    duplicate['event_id'] = 13
    journal['events'].insert(3, duplicate)
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('one-actual-native-CPU-take-required' in reason
               for reason in document['refusals'])


def test_target_output_bit_that_is_not_asserted_refuses():
    journal = build_journal()
    origin = find(1, journal)
    origin['outputs']['physical'][WIRE] = 2
    origin['outputs'][PORT] = 2
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('target-native-output-bit' in reason for reason in document['refusals'])


def test_foreign_group_frame_refuses():
    journal = build_journal()
    find(12, journal)['group_id'] = 'another-group'
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('OR-frame-group-identity' in reason for reason in document['refusals'])


def test_access_window_must_match_the_firmware_target_base():
    # A caller geometry that does not match the fixed firmware document is an
    # argument error, not evidence: it is refused before any layer is claimed.
    journal = build_journal()
    with pytest.raises(ValueError, match='observation-register-window-access'):
        observe(journal, access=dict(access(), window_base=BASE + 0x1000))
    with pytest.raises(ValueError, match='observation-register-window-access'):
        observe(journal, access=dict(access(), offset=None))


def test_zero_decision_serial_cannot_link_a_first_handler_retirement():
    journal = build_journal()
    find(11, journal)['irq_serial_observation']['decision']['value'] = 0
    document = observe(journal)
    assert document['status'] == 'refused'
    assert any('non-zero-native-decision-serial-required' in reason
               for reason in document['refusals'])


def test_absent_decision_serial_joins_by_take_order_with_a_weaker_label():
    journal = build_journal()
    take = find(11, journal)
    take['irq_serial_observation']['decision'] = dict(status='unobservable', value=None)
    document = observe(journal)
    assert document['status'] == 'verified', document['refusals']
    assert document['transport']['decision_serial'] is None
    assert document['transport']['decision_serial_status'] == 'unavailable'
    assert document['transport']['first_handler_retirement']['scope'] == \
        'first_retirement_after_native_take'
    # A contract that declares the serial observation cannot fall back.
    from myfuzz.local_harness.native_irq_receipt_contract import cv32e20_irq_receipt_contract
    contract = cv32e20_irq_receipt_contract()
    journal = build_journal(contract=contract)
    find(11, journal)['irq_serial_observation']['decision'] = dict(status='unobservable', value=None)
    refused = observe(journal, cpu_contract=contract)
    assert refused['status'] == 'refused'
    assert any('native-decision-serial-unobservable' in reason for reason in refused['refusals'])
