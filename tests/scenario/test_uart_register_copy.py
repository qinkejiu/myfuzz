"""Raw receipt software tests; real RTL ADDI copy still requires a run."""
from copy import deepcopy
import pytest

from tests.scenario.test_uart_retired_read import Stream
from tests.scenario.test_uart_operand_seed import overwrite
from tests.scenario.test_cpu_retirement import fetch
from myfuzz.scenario.uart_register_copy import UartRegisterCopyTracker

ADDI_X4_X3_0 = 0x00018213


def fixture(*, delayed=False):
    stream = Stream()
    stream.lifecycle()
    load = next(e for e in stream.events if e.get('kind') == 'cpu_retire')
    copy = overwrite(load)
    copy.update(event_id='copy-retire', insn=ADDI_X4_X3_0, order=1,
        pc_rdata=0x104, pc_wdata=0x108, rs1_addr=3, rs1_rdata=0,
        rs2_addr=0, rs2_rdata=0, rd_addr=4, rd_wdata=0,
        mem_addr=0, mem_rmask=0, mem_wmask=0, mem_rdata=0, mem_wdata=0, mode=3)
    copy['observation']['physical'] = {'rvfi_'+name: copy[name]
        for name in load['observation']['physical'] for name in [name[5:]]}
    instruction = fetch(ADDI_X4_X3_0, seq=2, pc=0x104)
    instruction.update(event_id='copy-fetch')
    instruction['transaction'].update(execution_id=load['execution_id'],
        source_component=load['source_component'], source_epoch=load['source_epoch'])
    instruction['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,
        writer_event_ids=['initial-image']*4)
    if delayed:
        proof = next(e for e in stream.events if e.get('kind') == 'uart_consumption_match')
        stream.events.remove(proof)
        stream.events.extend((instruction, copy, proof))
    else:
        stream.events.extend((instruction, copy))
    return stream, copy


def tracker(stream, **kwargs):
    return UartRegisterCopyTracker(admission_registry=stream.registry,
        ownership=stream.owner, edge_index=stream.index, **kwargs)


def play(model, events):
    return [report for event in events for report in model.consume(deepcopy(event))]


def accepted(reports):
    return [report for report in reports if report['status'] == 'accepted']


def test_exact_authenticated_source_version_and_measured_copy_destination():
    stream, copy = fixture()
    proof, = accepted(play(tracker(stream), stream.events))
    assert proof['source_register_version_key'] == ['cpu', 0, 0, 3]
    assert proof['destination_register_version_key'] == ['cpu', 0, 1, 4]
    assert proof['retirement_event_id'] == copy['event_id']
    assert proof['actual_post_ref'] == copy['actual_post_ref']
    assert proof['influenced_bits'] == [0, 8]
    assert proof['upper_bits_origin'] == proof['whole_word_origin'] == 'unknown'


def test_delayed_raw_seed_certifies_historical_copy_once():
    stream, copy = fixture(delayed=True)
    model = tracker(stream)
    reports = play(model, stream.events[:-1])
    assert not accepted(reports) and model.pending_count == 1
    proof, = accepted(play(model, stream.events[-1:]))
    assert proof['destination_register_version_key'] == ['cpu', 0, 1, 4]
    assert model.pending_count == 0
    assert not accepted(play(model, stream.events[-1:]))


@pytest.mark.parametrize('field,value', [('rs1_addr', 2), ('rs1_rdata', 1),
    ('rd_addr', 5), ('rd_wdata', 1), ('source_epoch', 1), ('order', 3),
    ('trap', 1), ('ext_rf_wr_suppress', 1), ('mem_wmask', 1),
    ('mem_rmask', 1), ('mode', 0), ('insn', 0x00118213)])
def test_wrong_copy_field_cannot_promote(field, value):
    stream, copy = fixture()
    copy[field] = value
    if 'rvfi_'+field in copy['observation']['physical']:
        copy['observation']['physical']['rvfi_'+field] = value
    assert not accepted(play(tracker(stream), stream.events))


def test_same_value_stale_register_version_cannot_promote():
    stream, copy = fixture()
    load = next(e for e in stream.events if e.get('kind') == 'cpu_retire')
    overwrite_source = overwrite(load)
    overwrite_source.update(event_id='overwrite-source', order=1, rd_addr=3,
        rd_wdata=0, insn=0x00000193, rs1_addr=0, rs1_rdata=0,
        rs2_addr=0, rs2_rdata=0, mem_addr=0, mem_rmask=0,
        mem_wmask=0, mem_rdata=0, mem_wdata=0, mode=3,
        pc_rdata=0x104, pc_wdata=0x108)
    overwrite_source['observation']['physical'] = {'rvfi_'+name: overwrite_source[name]
        for name in load['observation']['physical'] for name in [name[5:]]}
    instruction = fetch(0x00000193, seq=2, pc=0x104)
    instruction.update(event_id='overwrite-fetch')
    instruction['transaction'].update(execution_id=load['execution_id'],
        source_component='cpu', source_epoch=0)
    instruction['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,
        writer_event_ids=['initial-image']*4)
    stream.events[-2]['transaction']['source_sequence'] = 3
    stream.events[-2]['event_id'] = 'copy-fetch-after-overwrite'
    stream.events.insert(-2, instruction)
    stream.events.insert(-2, overwrite_source)
    copy.update(order=2, local_tick=3)
    copy.update(pc_rdata=0x108, pc_wdata=0x10c)
    copy['command_scope']['command_sequence'] = 3
    copy['receipt_id']['sequence'] = 3
    copy['actual_post_ref'] = dict(command_scope=deepcopy(copy['command_scope']),
        local_tick=3, phase='post')
    copy['receipt_ticks'].update(tick_before=2, tick_after=3)
    copy['observation']['physical']['rvfi_order'] = 2
    assert not accepted(play(tracker(stream), stream.events))


def test_reset_and_flush_cancel_pending_delayed_copy():
    for barrier in ('cpu_reset', 'cpu_flush'):
        stream, _ = fixture(delayed=True)
        model = tracker(stream)
        play(model, stream.events[:-1])
        if barrier == 'cpu_reset':
            event = dict(kind=barrier, event_id='reset', component='cpu',
                source_component='cpu', reset_epoch=1, source_epoch=1,
                physical_reset=True, execution_id='cpu-execution')
        else:
            event = dict(kind=barrier, event_id='flush', source_component='cpu',
                source_epoch=0, execution_id='cpu-execution')
        play(model, [event])
        assert not accepted(play(model, stream.events[-1:]))


def test_pending_capacity_fails_closed():
    stream, copy = fixture(delayed=True)
    model = tracker(stream, max_pending_copies=1)
    late_proof = stream.events.pop()
    chained = overwrite(copy)
    chained.update(event_id='chained-copy-retire', insn=0x00020293, order=2,
        pc_rdata=0x108, pc_wdata=0x10c,
        rs1_addr=4, rs1_rdata=0, rd_addr=5, rd_wdata=0)
    chained['observation']['physical'] = {'rvfi_'+name: chained[name]
        for name in copy['observation']['physical'] for name in [name[5:]]}
    instruction = fetch(0x00020293, seq=3, pc=0x108)
    instruction.update(event_id='chained-copy-fetch')
    instruction['transaction'].update(execution_id=copy['execution_id'],
        source_component='cpu', source_epoch=0)
    instruction['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,
        writer_event_ids=['initial-image']*4)
    stream.events.extend((instruction, chained, late_proof))
    reports = play(model, stream.events[:-1])
    assert any(p['reason'] == 'register_copy_pending_capacity' for p in reports)
    assert model.pending_count == 1
    assert not accepted(play(model, stream.events[-1:]))


@pytest.mark.parametrize('event', [[], {'kind': []},
    {'kind': 'cpu_retire', 'event_id': [], 'source_component': 'cpu', 'source_epoch': 0}])
def test_malformed_event_identity_or_container_fails_closed_without_exception(event):
    stream, _ = fixture()
    assert not accepted(tracker(stream).consume(event))


def test_delayed_seed_can_resolve_two_measured_copy_steps_in_order():
    stream, copy = fixture(delayed=True)
    late_proof = stream.events.pop()
    chained = overwrite(copy)
    chained.update(event_id='chained-copy-retire', insn=0x00020293, order=2,
        pc_rdata=0x108, pc_wdata=0x10c,
        rs1_addr=4, rs1_rdata=0, rd_addr=5, rd_wdata=0)
    chained['observation']['physical'] = {'rvfi_'+name: chained[name]
        for name in copy['observation']['physical'] for name in [name[5:]]}
    instruction = fetch(0x00020293, seq=3, pc=0x108)
    instruction.update(event_id='chained-copy-fetch')
    instruction['transaction'].update(execution_id=copy['execution_id'],
        source_component='cpu', source_epoch=0)
    instruction['snapshot'].update(writer_kinds=['INITIAL_IMAGE']*4,
        writer_event_ids=['initial-image']*4)
    stream.events.extend((instruction, chained, late_proof))
    model = tracker(stream)
    assert not accepted(play(model, stream.events[:-1]))
    assert model.pending_count == 2
    proofs = accepted(play(model, stream.events[-1:]))
    assert [p['destination_register_version_key'] for p in proofs] == [
        ['cpu', 0, 1, 4], ['cpu', 0, 2, 5]]
