"""Pure-software controls for the S3 declared illegal descriptor / error ISR.

Two independent software fixtures are used and neither claims native evidence:

* the fixed firmware is executed by the S2 RV32I behavioural model, proving the
  illegal path programs the declared illegal target, drains the queued payload,
  never writes the destination RAM and records the real ISR layout;
* a synthetic journal fixture mirrors the *real* S3 event shape (rejected
  master request + ``environment_error_receipt`` + error response + native
  error IRQ pulse + CPU take + ISR status/length/witness/counter), and every
  negative reduction that would hide a missing error witness must fail.

The status word in the synthetic fixture is a labelled software layout value,
not an RTL measurement.  The real gate must save the measured word; the pure
tests assert the evidence's status against the fixture row, never against a
pre-baked ``0x40000000``.
"""
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration import dma_uart_descriptor_runtime as runtime
from myfuzz.integration.dma_uart_descriptor_runtime import (
    CaseWitnesses, DescriptorCase, DescriptorCaseRejected,
    certify_descriptor_case, descriptor_windows, extract_case_witnesses)
from myfuzz.scenario import ibex_dma_uart_descriptor as firmware
from myfuzz.scenario.dma_chain_feedback import dma_chain_features
from tests.integration.test_dma_uart_descriptor import (
    _FakeRecorder, _FakeRunner, _Machine, _case_result, _fake_ids, _run_model,
    _synthetic_rows)

ROOT = Path(__file__).resolve().parents[2]
# A synthetic status word whose only semantic claim is the declared wbdmac
# layout (bit 30 error).  It is deliberately not presented as a measurement.
SYNTHETIC_STATUS = 1 << firmware.DMA_STATUS_ERROR_BIT
NONCANONICAL_STATUS = SYNTHETIC_STATUS | (1 << 16) | (1 << 8)
CAPTURED_FIXTURE = Path(os.environ.get(
    'MYFUZZ_DMA_ERROR_STATUS_FIXTURE',
    str(Path(__file__).with_name('fixtures') / 'dma_error_status_measured.json')))


# ---------------------------------------------------------------------------
# A. fixed firmware really takes the declared illegal target path
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('length', [1, 2, 3, 4])
def test_firmware_illegal_direction_programs_the_declared_target_without_data(
        length):
    case = DescriptorCase.create('ILLEGAL', dst_index=2, payload=0x5A,
        length=length)
    program = case.program()
    machine = _run_model(case.source_bytes, counter=1)
    assert machine.dma.error is True
    assert machine.dma.beats == []
    assert machine.dma.status & (1 << firmware.DMA_STATUS_ERROR_BIT)
    assert machine.dma.status == 1 << firmware.DMA_STATUS_ERROR_BIT
    assert machine.dma.writes == [
        (8, firmware.ILLEGAL_TARGET), (12, firmware.ILLEGAL_TARGET),
        (4, length), (0, firmware.CONTROL_WORDS['ILLEGAL'])]
    # The illegal path drains the queued payload bytes; every serial byte was
    # popped exactly once and the DMA itself never popped the FIFO.
    assert machine.uart.pops == list(case.source_bytes)
    assert machine.uart.tx == []
    assert all(machine.mem_word(address) == 0
               for address in program['destination_words'] or ())
    assert all(machine.mem_word(firmware.DESTINATION + 4 * index) == 0
               for index in range(firmware.DEST_WORDS))
    result = _case_result(machine, 1)
    assert result['mcause'] == runtime.DMA_IRQ_MCAUSE
    assert result['status'] == machine.dma.status
    assert result['length'] == length
    assert result['counter'] == 1
    assert result['witness_pointer'] == program['witness']
    assert result['payload'] == 0


def test_illegal_case_serial_stream_is_canonical_and_refuses_data_flow_claims():
    case = DescriptorCase.create('ILLEGAL', dst_index=1, payload=0x33, length=2)
    assert case.source_bytes == (0x03, 0x01, 0x01, 0x33, 0x33, 0x33)
    assert case.expect == 'environment_error'
    assert case.validate()['source'] == firmware.ILLEGAL_TARGET
    # An illegal case cannot be relabelled as a successful dataflow.
    with pytest.raises(DescriptorCaseRejected, match='only the declared illegal'):
        DescriptorCase(case.direction, case.dst_index, case.payload, case.length,
            case.source_bytes, dict(case.descriptor), expect='complete')
    # A narrowed declared-illegal window must refuse the case pre-RTL.
    windows = descriptor_windows()
    with pytest.raises(DescriptorCaseRejected, match='declared illegal master target'):
        case.validate({**windows, 'declared_illegal': (0, 4)})
    with pytest.raises(DescriptorCaseRejected, match='descriptor_direction'):
        case.validate({**windows, 'descriptor_direction': (0, 3)})


# ---------------------------------------------------------------------------
# B. synthetic journal fixture with the real S3 error event shape
# ---------------------------------------------------------------------------
SYNTHETIC_TRANSACTION = {'execution_id': 'a' * 32,
    'testcase_id': 'descriptor-dma-error-isr', 'source_component': 'dma',
    'source_epoch': 0, 'channel_id': 'dma-memory'}


class _Rows:
    def __init__(self):
        self.rows = []

    def add(self, kind, **fields):
        row = {'event_id': len(self.rows) + 1, 'kind': kind, **fields}
        self.rows.append(row)
        return row


def _fifo(depth, head, *, phase):
    return {'probe_uart_fifo_depth': depth, 'probe_uart_fifo_head': head,
        'probe_uart_fifo_rvalid': 1 if phase == 'pre' else 0,
        'probe_uart_fifo_rdata_re': 1 if phase == 'pre' else 0,
        'probe_uart_fifo_under_rst': 0}


def _transaction(sequence):
    return {**SYNTHETIC_TRANSACTION, 'source_sequence': sequence}


def error_rows(case, case_index=1, *, status=SYNTHETIC_STATUS,
               length_actual=None, witness_value=0):
    """Real-shape journal slice for one certified environment error.

    The shape comes from the saved real DMA error-recovery evidence
    (``docs/reports/evidence/dma-error-recovery-20261017``): the rejected
    request carries ``accepted.target_rejection`` and the top-level
    ``environment_error_receipt``; the next DMA edge carries
    ``response.error=1`` with ``i_mwb_err=1`` and the native IRQ pulse.
    """
    rows = _Rows()
    program = case.program()
    depth = case.source_count
    for slot, byte in enumerate(case.source_bytes):
        rows.add('source_injection', action_id=f'descriptor-{case_index}-{slot}',
            value=byte)
        rows.add('uart_frame_validation',
            action_id=f'descriptor-{case_index}-{slot}', byte=byte,
            waveform_matched=True, frame_id=f'frame-{case_index}-{slot}')
        rows.add('uart_tick_observation', post={
            'probe_uart_fifo_wvalid': 1, 'probe_uart_fifo_wready': 1,
            'probe_uart_fifo_depth': slot, 'probe_uart_fifo_data': byte,
            'probe_uart_fifo_head': 0 if slot == 0 else case.source_bytes[0]})
        rows.add('uart_tick_observation', post={
            'probe_uart_fifo_wvalid': 0, 'probe_uart_fifo_wready': 1,
            'probe_uart_fifo_depth': slot + 1, 'probe_uart_fifo_data': byte,
            'probe_uart_fifo_head': case.source_bytes[0]})
    rows.add('mmio_delivery', device_id='uart',
        offset=firmware.UART_STATUS_OFFSET, write=False, read_value=0)
    descriptor = case.source_bytes[:firmware.DESCRIPTOR_WORDS]
    drained = case.source_bytes[firmware.DESCRIPTOR_WORDS:]
    for pop_index, byte in enumerate(descriptor + drained):
        depth -= 1
        access = dict(access_id=f'cpu-access-{case_index}-{pop_index}',
            source_transaction={'channel_id': 'data'},
            raw_offset=firmware.UART_RDATA_OFFSET, status='observed',
            read_value=byte, read_capture={
                'pre': _fifo(depth + 1, byte, phase='pre'),
                'post': _fifo(depth, 0, phase='post')})
        rows.add('uart_rdata_access', **access)
        rows.add('mmio_delivery', device_id='uart',
            offset=firmware.UART_RDATA_OFFSET, write=False, read_value=byte,
            target_uart_access=dict(access, kind='uart_rdata_access'))
    rows.add('memory_write', component='cpu',
        address=firmware.WITNESS_POINTER, value=program['witness'],
        version=[0, 1])
    for offset, value in ((8, program['source']),
                          (12, program['destination']),
                          (4, program['length']), (0, program['control'])):
        rows.add('mmio_delivery', device_id='dma', offset=offset, write=True,
            write_value=value, read_value=None)
    transaction = _transaction(1)
    accepted = dict(transaction=transaction, address=program['source'],
        write=False, value=0, byte_enable=15,
        target_rejection='declared_master_target_access')
    receipt = dict(source_transaction=transaction, error=1,
        target_effect=False, op='master_environment_error',
        address=program['source'], write=False, value=0, byte_enable=15,
        reason='declared_master_target_access')
    rows.add('dma_edge', native_local_tick=200 + case_index, accepted=accepted,
        environment_error_receipt=receipt,
        payload={'error': 0, 'observations': {'physical': {'irq': 0}},
                 'pre_backend': {'mwb_cyc': 1, 'mwb_stb': 1, 'mwb_ack': 0,
                                 'mwb_we': 0, 'mwb_err': 0}})
    pulse_tick = 201 + case_index
    rows.add('dma_edge', native_local_tick=pulse_tick,
        response=dict(transaction=transaction, rdata=0, error=1, delay=0),
        payload={'error': 0, 'observations': {'physical': {'irq': 1}},
                 'pre_backend': {'mwb_cyc': 1, 'mwb_stb': 0, 'mwb_ack': 0,
                                 'mwb_we': 0, 'mwb_err': 1}})
    rows.add('source_start', source=('dma', 'irq'), target=('cpu', 'irq'),
        source_tick=pulse_tick, source_event_id=1)
    rows.add('cpu_external_irq_taken', local_tick=pulse_tick + 10)
    rows.add('cpu_irq_taken', source=('dma', 'irq'), target=('cpu', 'irq'),
        source_event_id=1, cpu_tick=pulse_tick + 10)
    rows.add('memory_write', component='cpu', address=firmware.RESULT,
        value=runtime.DMA_IRQ_MCAUSE, version=[0, 20])
    status_key = {'channel_id': 'data', 'source_component': 'cpu',
                  'source_sequence': 3}
    rows.add('mmio_delivery', device_id='dma', offset=0, write=False,
        read_value=status, source_transaction=status_key)
    rows.add('data_response', transaction=status_key, rdata=status)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_status'],
        mem_addr=firmware.DMA_BASE, mem_rmask=15, mem_rdata=status, rd_addr=7,
        rd_wdata=status)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_status'] + 4,
        mem_addr=firmware.RESULT + 4, mem_wmask=15, mem_wdata=status,
        rs2_addr=7)
    rows.add('memory_write', component='cpu',
        address=firmware.RESULT + 4, value=status, version=[0, 21])
    length = case.length if length_actual is None else length_actual
    rows.add('mmio_delivery', device_id='dma', offset=4, write=False,
        read_value=length, source_transaction={'channel_id': 'data',
        'source_component': 'cpu', 'source_sequence': 4})
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_length'],
        mem_addr=firmware.DMA_BASE + 4, mem_rmask=15, mem_rdata=length,
        rd_addr=8, rd_wdata=length)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_length'] + 4,
        mem_addr=firmware.RESULT + 8, mem_wmask=15, mem_wdata=length,
        rs2_addr=8)
    rows.add('memory_write', component='cpu',
        address=firmware.RESULT + 8, value=length, version=[0, 22])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness_pointer'],
        mem_addr=firmware.WITNESS_POINTER, mem_rmask=15,
        mem_rdata=program['witness'], rd_addr=9,
        rd_wdata=program['witness'])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness'],
        mem_addr=program['witness'], mem_rmask=15, mem_rdata=witness_value,
        rd_addr=9, rd_wdata=witness_value)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_witness'] + 4,
        mem_addr=firmware.WITNESS, mem_wmask=15, mem_wdata=witness_value,
        rs2_addr=9)
    rows.add('memory_write', component='cpu', address=firmware.WITNESS,
        value=witness_value, version=[0, 23])
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_counter_load'],
        mem_addr=firmware.COMPLETED, mem_rmask=15,
        mem_rdata=case_index - 1, rd_addr=9, rd_wdata=case_index - 1)
    rows.add('cpu_retire', pc_rdata=firmware.ISR_PCS['isr_counter_load'] + 8,
        mem_addr=firmware.COMPLETED, mem_wmask=15, mem_wdata=case_index,
        rs2_addr=9)
    rows.add('memory_write', component='cpu', address=firmware.COMPLETED,
        value=case_index, version=[0, 24])
    return rows.rows


def _certify(rows, case, case_index=1, **kwargs):
    return certify_descriptor_case(extract_case_witnesses(rows), case,
        case_index=case_index, **kwargs)


def _row(rows, kind, **match):
    return next(row for row in rows if row.get('kind') == kind and all(
        row.get(field) == value for field, value in match.items()))


def _drop(rows, predicate):
    return [row for row in rows if not predicate(row)]


def _sealed_error_case():
    case = DescriptorCase.create('ILLEGAL', dst_index=1, payload=0x5A, length=2)
    status = NONCANONICAL_STATUS
    rows = error_rows(case, status=status)
    return case, status, rows


# ---------------------------------------------------------------------------
# C. the certified error case is real, sealed and never a dataflow
# ---------------------------------------------------------------------------
def test_error_case_is_certified_from_the_real_error_evidence_only():
    case, status, rows = _sealed_error_case()
    witnesses = extract_case_witnesses(rows)
    assert len(witnesses.beats) == 0
    assert len(witnesses.rejections) == 1
    assert len(witnesses.environment_errors) == 1
    assert len(witnesses.error_responses) == 1
    assert len(witnesses.error_irq_edges) == 1
    evidence = certify_descriptor_case(witnesses, case, case_index=1)
    fields = firmware.dma_status_fields(status)
    assert evidence['outcome'] == 'environment_error'
    assert evidence['completed'] is False
    assert evidence['sealed'] is True
    assert evidence['error_path'] == 'declared_illegal_master_target'
    assert evidence['no_target_delivery'] is True
    assert evidence['destination_committed'] is False
    assert evidence['beats'] == [] and evidence['beat_count'] == 0
    assert evidence['ram_commits'] == []
    assert evidence['tx_captures'] == []
    assert evidence['environment_error_receipt']['error'] == 1
    assert evidence['environment_error_receipt']['target_effect'] is False
    assert evidence['environment_error_receipt']['reason'] \
        == 'declared_master_target_access'
    assert evidence['environment_error_receipt']['address'] \
        == firmware.ILLEGAL_TARGET
    assert evidence['environment_error']['fifo_dma_pops'] == 0
    assert evidence['environment_error']['destination_commits'] == 0
    # The fixture status is asserted from the fixture variable, not from a
    # literal expected measurement.
    assert evidence['isr']['status'] == status
    assert evidence['isr']['status_bits'] == list(fields['bits'])
    assert evidence['isr']['status_error'] == 1
    assert evidence['isr']['status_busy'] == 0
    assert evidence['isr']['status'] & (1 << firmware.DMA_STATUS_ERROR_BIT)
    assert evidence['isr']['length'] == case.length
    assert evidence['isr']['mcause'] == runtime.DMA_IRQ_MCAUSE
    assert evidence['isr']['counter'] == 1
    assert evidence['isr']['payload'] is None
    assert evidence['isr']['witness'] == 0
    assert evidence['irq']['error'] is True
    assert evidence['irq']['edge_tick'] == evidence['irq']['source_tick']
    assert evidence['fifo']['pushes'] == case.source_count
    assert [pop['kind'] for pop in evidence['fifo']['pops']] == ['cpu'] * case.source_count
    assert evidence['fifo']['dma_pops'] == 0
    assert evidence['fifo']['depth_after'] == 0
    assert evidence['fifo_origin'] == 'unknown'
    assert evidence['source_authority'] == 'incomplete'
    assert evidence['proof_grade'] == 'bounded_historical_chain'


def test_error_status_is_recorded_verbatim_and_never_normalized():
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x11, length=1)
    status = NONCANONICAL_STATUS
    evidence = _certify(error_rows(case, status=status), case)
    assert evidence['isr']['status'] == status
    assert evidence['isr']['status_bits'] == [bit for bit in range(32)
                                              if status & (1 << bit)]
    assert evidence['environment_error']['status'] == status
    assert evidence['environment_error']['status_bits'] \
        == evidence['isr']['status_bits']


def test_illegal_case_cannot_be_relabelled_as_a_complete_case():
    # The declared illegal direction has no success certificate: its only
    # valid outcome is environment_error and the evidence says so.
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x22, length=1)
    with pytest.raises(DescriptorCaseRejected, match='only the declared illegal'):
        DescriptorCase(case.direction, case.dst_index, case.payload, case.length,
            case.source_bytes, dict(case.descriptor), expect='complete')
    evidence = _certify(error_rows(case), case, case_index=1)
    assert evidence['completed'] is False
    assert evidence['outcome'] == 'environment_error'


def test_dma_chain_feedback_counts_the_error_honestly():
    case, status, rows = _sealed_error_case()
    features = dma_chain_features(rows, start=0, end=len(rows),
        destination=firmware.DESTINATION, uart_base=firmware.UART_BASE)
    assert features.target_error is True
    assert features.completed_chain is False
    assert features.status_error is True
    assert features.status_bits == tuple(bit for bit in range(32)
                                         if status & (1 << bit))
    assert features.features.get('env_error') == 1
    assert features.features.get('no_target_effect') == 1
    assert features.features.get('isr_status_error') == 1
    assert 'dma_master_read' not in features.features
    assert 'dma_master_write' not in features.features
    assert 'ram_commit_dma' not in features.features
    assert 'fifo_dma_pop' not in features.features
    # A stray successful dataflow in an error slice must not become a chain.
    polluted = list(rows)
    polluted.append({'event_id': len(polluted) + 1, 'kind': 'memory_write',
        'component': 'dma', 'address': firmware.DESTINATION,
        'value': case.payload, 'version': [0, 99]})
    assert dma_chain_features(polluted, start=0, end=len(polluted),
        destination=firmware.DESTINATION, uart_base=firmware.UART_BASE) \
        .completed_chain is False


# ---------------------------------------------------------------------------
# D. negative reductions: every missing error witness must fail
# ---------------------------------------------------------------------------
def _remove_receipt(rows):
    for row in rows:
        if row.get('kind') == 'dma_edge' and 'environment_error_receipt' in row:
            del row['environment_error_receipt']
            return rows
    return rows


def _drop_error_pulse(rows):
    for row in rows:
        if row.get('kind') == 'dma_edge' and isinstance(row.get('response'), dict):
            row['payload']['observations']['physical']['irq'] = 0
            return rows
    return rows


def _remove_accepted(rows):
    for row in rows:
        if row.get('kind') == 'dma_edge' and 'accepted' in row:
            del row['accepted']
            return rows
    return rows


@pytest.mark.parametrize('mutate,message', [
    (_remove_receipt, 'environment error receipt'),
    (lambda rows: _remove_accepted(rows), 'accepted master request'),
    (lambda rows: _drop(rows, lambda row: row.get('kind') == 'source_start'),
     'source start'),
    (lambda rows: _drop(rows, lambda row: row.get('kind') == 'cpu_external_irq_taken'),
     'external IRQ take'),
    (lambda rows: _drop(rows, lambda row: row.get('kind') == 'cpu_irq_taken'),
     'CPU IRQ take'),
    (_drop_error_pulse, 'error IRQ pulse'),
])
def test_certifier_refuses_a_missing_error_witness(mutate, message):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = mutate(error_rows(case))
    with pytest.raises(RuntimeError, match=message):
        _certify(rows, case)


def _clear_error_receipt(rows):
    _row(rows, 'dma_edge')['environment_error_receipt']['error'] = 0
    return rows


def _receipt_with_target_effect(rows):
    _row(rows, 'dma_edge')['environment_error_receipt']['target_effect'] = True
    return rows


def _receipt_wrong_address(rows):
    _row(rows, 'dma_edge')['environment_error_receipt']['address'] = \
        firmware.ILLEGAL_TARGET + 4
    return rows


def _receipt_wrong_reason(rows):
    _row(rows, 'dma_edge')['environment_error_receipt']['reason'] = \
        'memory_access_rejected'
    return rows


def _rejection_without_target_rejection(rows):
    _row(rows, 'dma_edge')['accepted'].pop('target_rejection')
    return rows


def _rejection_with_target_delivery(rows):
    _row(rows, 'dma_edge')['accepted']['target_delivery'] = {'target_component': 'uart'}
    return rows


def _error_response_cleared(rows):
    next(row for row in rows if row.get('kind') == 'dma_edge'
         and isinstance(row.get('response'), dict))['response']['error'] = 0
    return rows


def _error_response_rdata(rows):
    next(row for row in rows if row.get('kind') == 'dma_edge'
         and isinstance(row.get('response'), dict))['response']['rdata'] = 0x5A
    return rows


def _error_edge_backend_cleared(rows):
    next(row for row in rows if row.get('kind') == 'dma_edge'
         and isinstance(row.get('response'), dict))['payload']['pre_backend']['mwb_err'] = 0
    return rows


@pytest.mark.parametrize('mutate,message', [
    (_clear_error_receipt, 'field error'),
    (_receipt_with_target_effect, 'field target_effect'),
    (_receipt_wrong_address, 'field address'),
    (_receipt_wrong_reason, 'field reason'),
    (_rejection_without_target_rejection, 'not the declared target rejection'),
    (_rejection_with_target_delivery, 'no target delivery'),
    (_error_response_cleared, 'error response'),
    (_error_response_rdata, 'bus error'),
    (_error_edge_backend_cleared, 'error IRQ pulse'),
])
def test_certifier_refuses_a_tampered_error_receipt_or_response(mutate, message):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = mutate(error_rows(case))
    with pytest.raises(RuntimeError, match=message):
        _certify(rows, case)


@pytest.mark.parametrize('build,message', [
    (lambda case: error_rows(case, status=0), 'does not report the declared error bit'),
    (lambda case: error_rows(case, status=SYNTHETIC_STATUS | (1 << 31)),
     'still reports busy'),
    (lambda case: error_rows(case, status=SYNTHETIC_STATUS | (1 << 29)),
     'inc bits differ'),
    (lambda case: error_rows(case, length_actual=4), 'length'),
])
def test_certifier_refuses_a_false_or_incomplete_error_status(build, message):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    with pytest.raises(RuntimeError, match=message):
        _certify(build(case), case)


def _add_destination_commit(rows):
    rows.append({'event_id': len(rows) + 1, 'kind': 'memory_write',
        'component': 'dma', 'address': firmware.DESTINATION, 'value': 0x5A,
        'version': [0, 99]})
    return rows


def _add_dma_fifo_pop(rows, access_id='dma-pop-1', value=0x5A):
    # The pinned DMA master path reads RDATA through read_register, so the
    # event has no routed source_transaction but does carry a real access id.
    rows.append({'event_id': len(rows) + 1, 'kind': 'uart_rdata_access',
        'access_id': access_id, 'source_transaction': None,
        'raw_offset': firmware.UART_RDATA_OFFSET, 'status': 'observed',
        'read_value': value,
        'read_capture': {'pre': _fifo(1, value, phase='pre'),
                         'post': _fifo(0, 0, phase='post')}})
    return rows


def _add_late_cpu_rdata(rows, access_id='uart-access:uart:0:10', value=0x5A,
                        *, identified=True):
    # The real failed S3 shape: the previous valid RX case's fourth CPU RDATA
    # access is journaled only as a nested target_uart_access, and its late
    # top-level copy (source_transaction=None) lands in the next case slice.
    record = {'event_id': len(rows) + 1, 'kind': 'uart_rdata_access',
        'source_transaction': None,
        'raw_offset': firmware.UART_RDATA_OFFSET, 'status': 'observed',
        'read_value': value,
        'read_capture': {'pre': _fifo(1, value, phase='pre'),
                         'post': _fifo(0, 0, phase='post')}}
    if identified:
        record['access_id'] = access_id
    rows.append(record)
    return rows


def _add_data_beat(rows):
    rows.append({'event_id': len(rows) + 1, 'kind': 'dma_edge',
        'accepted': {'address': firmware.SOURCE_RAM, 'write': False,
                     'value': 0, 'transaction': {'channel_id': 'dma-memory'}}})
    return rows


@pytest.mark.parametrize('mutate,message', [
    (_add_destination_commit, 'must not commit RAM data'),
    (_add_dma_fifo_pop, 'must not pop the UART RX FIFO'),
    (_add_data_beat, 'must not accept a data beat'),
    (_drop_error_pulse, 'error IRQ pulse'),
])
def test_certifier_refuses_target_effect_or_a_fifo_pop_after_err(mutate, message):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = mutate(error_rows(case))
    with pytest.raises(RuntimeError, match=message):
        _certify(rows, case)


def test_late_fifo_pop_from_a_previous_case_is_not_a_dma_pop():
    # Real S3 gate shapes: uart-access:uart:0:10 was first a CPU access copy
    # and later the previous valid RX case's DMA payload pop.  Both surface as
    # a late top-level uart_rdata_access with source_transaction=None in the
    # next ILLEGAL slice; once the boot has settled that real access id it is
    # not a DMA read of 0x50000020.  Without the settled set it must fail.
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    late_id = 'uart-access:uart:0:10'
    rows = _add_late_cpu_rdata(error_rows(case), late_id, value=90)
    with pytest.raises(RuntimeError, match='must not pop the UART RX FIFO'):
        _certify(rows, case)
    evidence = _certify(rows, case,
        settled_access_ids=frozenset({late_id}))
    assert evidence['settled_dma_rdata_access_ids'] == [late_id]
    assert evidence['environment_error']['fifo_dma_pops'] == 0
    assert evidence['fifo']['dma_pops'] == 0
    assert evidence['no_target_delivery'] is True


def test_settled_pop_ids_collect_every_cpu_and_dma_fifo_pop():
    # This is the boot-side invariant behind the fix: a previous RX case's DMA
    # payload pop id must be settled, not just its CPU pop ids.
    evidence = dict(cpu_pop_access_ids=['cpu-access-1', 'cpu-access-2'],
        fifo=dict(pops=[dict(kind='cpu', access_id='cpu-access-1'),
                        dict(kind='dma', source='dma-master',
                             access_id='uart-access:uart:0:10'),
                        dict(kind='cpu')]))
    assert runtime._settled_pop_access_ids(evidence) == {
        'cpu-access-1', 'cpu-access-2', 'uart-access:uart:0:10'}


def _settlement_evidence(witnesses, case, *, case_index, tx_captures=(),
                         action_ids=None, settled_access_ids=None):
    return dict(case_index=case_index, direction=case.direction,
        outcome=case.expect, completed=case.expect == 'complete', sealed=True,
        payload=case.payload,
        cpu_pop_access_ids=[f'cpu-access-{case_index}'],
        fifo=dict(pops=[dict(kind='cpu', access_id=f'cpu-access-{case_index}'),
                        dict(kind='dma', source='dma-master',
                             access_id=f'dma-access-{case_index}')]),
        tx_captures=list(tx_captures))


def test_boot_settles_the_previous_cases_dma_pop_access_id(monkeypatch):
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.genome import ScenarioGenome
    _FakeRecorder.instances = []
    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', _FakeRecorder)
    monkeypatch.setattr(runtime, 'certify_descriptor_case',
        _settlement_evidence)
    runner = _FakeRunner(_fake_ids())
    budget = ResourceBudget(max_wall_time_ms=1000)
    runner.set_resource_budget(budget)
    template = ScenarioGenome('descriptor-dma-three-directions', 'IP_TO_CPU',
        'uart-descriptor-dma-ram-tx-cpu-isr', ('dma', 'cpu', 'uart'),
        100000, ())
    boot = runtime.DescriptorBoot(runner, budget=budget, template=template,
        source_pins=runtime._source_pins())
    boot.boot()
    first = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A,
        length=1)
    boot.cases.append(boot.run_case(first, case_index=1))
    assert boot.settled_access_ids == {'cpu-access-1', 'dma-access-1'}
    # The next declared illegal case inherits the previous DMA pop identity;
    # a late copy of it must not be mistaken for a new DMA pop.
    second = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0xA5,
        length=1)
    boot.cases.append(boot.run_case(second, case_index=2))
    assert 'dma-access-1' in boot.settled_access_ids
    assert 'dma-access-2' in boot.settled_access_ids


def test_unidentified_late_rdata_copy_stays_fail_closed():
    # An access without a real id cannot be proven settled, so it is never
    # guessed away, even when some other id is already settled.
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = _add_late_cpu_rdata(error_rows(case), identified=False)
    with pytest.raises(RuntimeError, match='must not pop the UART RX FIFO'):
        _certify(rows, case, settled_access_ids=frozenset({'some-other-access'}))


def test_real_dma_rdata_pop_is_not_hidden_by_an_unrelated_settled_id():
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = _add_dma_fifo_pop(error_rows(case), access_id='uart-access:uart:0:19',
        value=0x5A)
    with pytest.raises(RuntimeError, match='must not pop the UART RX FIFO'):
        _certify(rows, case,
            settled_access_ids=frozenset({'uart-access:uart:0:10'}))


@pytest.mark.parametrize('address,value', [
    (firmware.RESULT, runtime.DMA_IRQ_MCAUSE),
    (firmware.RESULT + 4, SYNTHETIC_STATUS),
    (firmware.RESULT + 8, 1),
    (firmware.WITNESS, 0),
    (firmware.COMPLETED, 1),
])
def test_certifier_refuses_a_missing_isr_store(address, value):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = [row for row in error_rows(case)
            if not (row.get('kind') == 'memory_write'
                    and row.get('component') == 'cpu'
                    and row.get('address') == address and row.get('value') == value)]
    with pytest.raises(RuntimeError, match='ISR .* store is missing or duplicated'):
        _certify(rows, case)


@pytest.mark.parametrize('pc', [
    firmware.ISR_PCS['isr_status'],
    firmware.ISR_PCS['isr_status'] + 4,
    firmware.ISR_PCS['isr_length'],
    firmware.ISR_PCS['isr_length'] + 4,
    firmware.ISR_PCS['isr_witness_pointer'],
    firmware.ISR_PCS['isr_witness'],
    firmware.ISR_PCS['isr_witness'] + 4,
    firmware.ISR_PCS['isr_counter_load'],
    firmware.ISR_PCS['isr_counter_load'] + 8,
])
def test_certifier_refuses_a_missing_isr_retirement(pc):
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    rows = [row for row in error_rows(case)
            if not (row.get('kind') == 'cpu_retire'
                    and row.get('pc_rdata') == pc)]
    with pytest.raises(RuntimeError, match='lacks exactly one real retirement'):
        _certify(rows, case)


def test_a_complete_case_cannot_carry_an_environment_error_receipt():
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A, length=1)
    rows = _synthetic_rows(case)
    rows.append({'event_id': len(rows) + 1, 'kind': 'dma_edge',
        'environment_error_receipt': {'error': 1, 'target_effect': False,
            'op': 'master_environment_error',
            'address': firmware.ILLEGAL_TARGET, 'write': False,
            'byte_enable': 15, 'reason': 'declared_master_target_access'}})
    with pytest.raises(RuntimeError, match='must not contain an environment error'):
        _certify(rows, case)


def test_certifier_refuses_an_illegal_case_with_a_tx_capture():
    case = DescriptorCase.create('ILLEGAL', dst_index=0, payload=0x5A, length=1)
    with pytest.raises(RuntimeError, match='must not transmit'):
        _certify(error_rows(case), case, tx_captures=(0x5A,))


# ---------------------------------------------------------------------------
# E. the real measured status fixture is optional and fail-closed
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not CAPTURED_FIXTURE.exists(),
    reason='the real S3 gate has not captured the post-error status word yet')
def test_captured_real_error_status_matches_the_declared_layout():
    document = json.loads(CAPTURED_FIXTURE.read_text(encoding='utf-8'))
    cases = document['cases'] if isinstance(document, dict) else document
    assert cases
    for case in cases:
        fields = firmware.dma_status_fields(case['status'])
        assert fields['bits'] == case['status_bits']
        assert fields['error'] == 1
        assert fields['busy'] == 0
