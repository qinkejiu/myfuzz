"""Event-level DMA chain features are bounded, typed and replay-auditable.

The synthetic records mirror the field names of the saved attempt6 journal
(`docs/reports/evidence/dma-continuous-20261017/attempt6-complete.tar`); no
model is started and no serialized record is treated as authority.
"""
import pytest

from myfuzz.scenario.dma_chain_feedback import (
    DMA_FEATURES, DMA_TARGETS, DmaChainFeatures, dma_chain_features,
    is_declared_feature, new_features)

UART_BASE = 0x50000000
DESTINATION = 0x23000
RESULT = 0x24000
COMPLETED = 0x2400c
MCAUSE = 0x8000000b


def chain(byte, *, counter=1, matched=True, write_value=None, order=True,
          environment_error=False, no_target_effect=False, tx=False,
          real_receipt=False, status_value=0):
    """Build one case-sized journal slice with real attempt6 field names."""
    rows = []

    def add(**record):
        rows.append({'event_id': len(rows) + 1, **record})
        return rows[-1]

    add(kind='source_injection', action_id=f'case-{counter}', component='uart',
        port='uart_rx_byte', value=byte, execution_id='a' * 32)
    frame = add(kind='uart_frame_validation', action_id=f'case-{counter}', byte=byte,
        waveform_matched=matched, frame_id=f'uart-frame:0:{counter}',
        fifo_origin='unknown')
    add(kind='uart_tick_observation',
        pre={'probe_uart_fifo_depth': 0},
        post={'probe_uart_fifo_wvalid': 1, 'probe_uart_fifo_wready': 1,
              'probe_uart_fifo_depth': 0, 'probe_uart_fifo_data': byte})
    add(kind='mmio_delivery', device_id='uart', offset=0x14, write=False,
        address=UART_BASE + 0x14, read_value=28)
    delivery = {'address': UART_BASE + 0x18, 'offset': 24, 'write': False,
                'value': byte, 'byte_enable': 15, 'target_component': 'uart',
                'source_transaction': {'channel_id': 'dma-memory',
                    'source_component': 'dma', 'source_sequence': 1,
                    'execution_id': 'b' * 32},
                'target_uart_access': {
                    'read_capture': {'pre': {'probe_uart_fifo_rdata_re': 1},
                                     'post': {'probe_uart_fifo_depth': 0}},
                    'read_value': byte}}
    accepted = {'address': UART_BASE + 0x18, 'write': False, 'value': 0,
                'byte_enable': 15,
                'transaction': dict(delivery['source_transaction'])}
    payload = {'observations': {'physical': {'rt_lh_p_12_0_0': 0}}}
    if environment_error:
        payload = {**payload, 'error': 1}
    if no_target_effect:
        accepted = {**accepted, 'target_rejection': {'reason': 'environment_error'}}
    if environment_error or no_target_effect:
        edge = add(kind='dma_edge', native_local_tick=11, accepted=accepted,
            payload=payload)
        if real_receipt:
            accepted['target_rejection'] = 'declared_master_target_access'
            receipt = {'source_transaction': dict(delivery['source_transaction']),
                'error': 1, 'target_effect': False,
                'op': 'master_environment_error', 'address': accepted['address'],
                'write': False, 'value': 0, 'byte_enable': 15,
                'reason': 'declared_master_target_access'}
            edge['environment_error_receipt'] = receipt
    else:
        accepted = {**accepted, 'target_delivery': delivery}
        add(kind='dma_edge', native_local_tick=10, accepted=accepted,
            target_delivery=delivery, payload=payload)
        add(kind='dma_edge', native_local_tick=12,
            accepted={'address': DESTINATION, 'write': True,
                      'value': byte if write_value is None else write_value,
                      'byte_enable': 15,
                      'transaction': {'channel_id': 'dma-memory'}},
            payload={'observations': {'physical': {'rt_lh_p_12_0_0': 0}}})
        add(kind='memory_write', component='dma', address=DESTINATION,
            value=byte if write_value is None else write_value,
            transaction={'channel_id': 'dma-memory', 'execution_id': 'b' * 32})
        add(kind='dma_edge', native_local_tick=79,
            payload={'observations': {'physical': {'rt_lh_p_12_0_0': 1}},
                     'error': 0})
        add(kind='source_start', source=['dma', 'irq'], target=['cpu', 'irq'],
            source_event_id=1, source_tick=79, cpu_tick=62)
        add(kind='cpu_irq_taken', source=['dma', 'irq'], target=['cpu', 'irq'],
            source_event_id=1, cpu_tick=66, cpu_step_event_id=1)
        add(kind='cpu_external_irq_taken', component='cpu', local_tick=66)
        add(kind='memory_write', component='cpu', address=RESULT, value=MCAUSE)
        add(kind='memory_write', component='cpu', address=RESULT + 4,
            value=status_value)
        add(kind='memory_write', component='cpu', address=RESULT + 8, value=byte)
        add(kind='memory_write', component='cpu', address=COMPLETED, value=counter)
    if tx:
        add(kind='uart_serial_tx_capture', component='uart', local_tick=120,
            byte=byte, capture_index=1)
    if not order:
        # Move the destination write ahead of the FIFO read: still one of each,
        # but the causal order is wrong.
        write = next(row for row in rows if row.get('kind') == 'memory_write'
                     and row.get('component') == 'dma')
        rows.remove(write)
        rows.insert(1, write)
        for index, row in enumerate(rows, 1):
            row['event_id'] = index
    return rows, frame


def features(rows, **kwargs):
    return dma_chain_features(rows, start=0, end=len(rows),
        destination=DESTINATION, uart_base=UART_BASE, **kwargs)


def test_complete_chain_reports_every_declared_feature():
    rows, frame = chain(0x5a)
    result = features(rows)
    assert isinstance(result, DmaChainFeatures)
    assert result.completed_chain is True
    assert result.target_error is False
    assert all(is_declared_feature(key) for key in result.features)
    for name in ('uart_frame_matched', 'fifo_push', 'status_nonempty',
                 'fifo_dma_pop', 'dma_master_read', 'dma_master_write',
                 'ram_commit_dma', 'dma_irq_pulse', 'cpu_irq_take', 'isr_mcause',
                 'isr_status', 'isr_payload', 'isr_counter'):
        assert result.features.get(name) == 1, name
    assert result.features['ram_commit_cpu'] == 4
    assert result.payloads == (0x5a, 0x5a, 0x5a)
    assert set(result.targets) <= set(DMA_TARGETS)
    for name in ('uart.frame_matched', 'uart.fifo_push', 'dma.master_read',
                 'dma.master_write', 'dma.irq_pulse', 'cpu.irq_take',
                 'isr.mcause', 'isr.payload', 'ram.commit_dma'):
        assert name in result.targets, name
    assert frame['event_id'] in [row['event_id'] for row in rows]


def test_tx_capture_is_a_declared_feature_only_when_observed():
    rows, _ = chain(0x11, tx=True)
    assert features(rows).features.get('tx_capture') == 1
    rows, _ = chain(0x11)
    assert 'tx_capture' not in features(rows).features


@pytest.mark.parametrize('change', ['unmatched', 'write', 'order', 'missing_isr'])
def test_incomplete_chain_is_not_a_completed_chain(change):
    if change == 'unmatched':
        rows, _ = chain(0x5a, matched=False)
    elif change == 'write':
        rows, _ = chain(0x5a, write_value=0x00)
    elif change == 'order':
        rows, _ = chain(0x5a, order=False)
    else:
        rows, _ = chain(0x5a)
        rows = [row for row in rows if row.get('value') != MCAUSE]
        for index, row in enumerate(rows, 1):
            row['event_id'] = index
    assert features(rows).completed_chain is False


def test_environment_error_and_missing_target_effect_are_reported():
    rows, _ = chain(0x5a, environment_error=True)
    result = features(rows)
    assert result.target_error is True
    assert result.features.get('env_error') == 1
    assert result.completed_chain is False
    rows, _ = chain(0x5a, no_target_effect=True)
    result = features(rows)
    assert result.target_error is True
    assert result.features.get('no_target_effect') == 1


def test_slice_bounds_are_exact_and_bounded():
    rows, _ = chain(0x5a)
    for start, end in ((-1, 1), (0, len(rows) + 1), (2, 1)):
        with pytest.raises(ValueError):
            dma_chain_features(rows, start=start, end=end,
                destination=DESTINATION, uart_base=UART_BASE)
    decoy, _ = chain(0x00, counter=2)
    offset = len(decoy)
    combined = decoy + [dict(row, event_id=row['event_id'] + offset) for row in rows]
    sliced = dma_chain_features(combined, start=offset, end=len(combined),
        destination=DESTINATION, uart_base=UART_BASE)
    assert sliced.completed_chain is True
    assert sliced.features['uart_frame_matched'] == 1
    assert sliced.payloads[0] == 0x5a


def test_new_features_is_relative_to_the_seen_set():
    rows, _ = chain(0x5a)
    current = features(rows)
    assert new_features(frozenset(), current) == tuple(sorted(current.features))
    assert new_features(frozenset(current.features), current) == ()
    same, _ = chain(0x5a, counter=2)
    repeated = dma_chain_features(same, start=0, end=len(same),
        destination=DESTINATION, uart_base=UART_BASE)
    assert new_features(frozenset(current.features), repeated) == ()
    other, _ = chain(0x00, counter=2)
    extra = dma_chain_features(other, start=0, end=len(other),
        destination=DESTINATION, uart_base=UART_BASE)
    novel = new_features(frozenset(current.features), extra)
    assert 'payload_00' in novel and 'isr_payload' not in novel
    shifted = dict(extra.features)
    shifted['fifo_push_depth_2'] = 1
    changed = DmaChainFeatures(shifted, extra.targets, extra.completed_chain,
        extra.target_error, extra.payloads)
    assert 'fifo_push_depth_2' in new_features(frozenset(current.features), changed)


def test_cpu_fifo_pop_requires_a_cpu_data_transaction():
    rows, _ = chain(0x5a)
    rows = list(rows)
    rows.append({'event_id': len(rows) + 1, 'kind': 'uart_rdata_access',
        'component': 'uart', 'read_value': 0x5a,
        'read_capture': {'pre': {'probe_uart_fifo_rdata_re': 1}},
        'access': {'source_transaction': {'channel_id': 'data'}}})
    result = features(rows)
    assert result.features.get('fifo_cpu_pop') == 1
    assert result.features.get('fifo_dma_pop') == 1
    assert 'uart.fifo_cpu_pop' in result.targets


def test_declared_feature_and_target_vocabulary_is_frozen():
    assert DMA_FEATURES == ('uart_frame_matched', 'fifo_push', 'fifo_cpu_pop',
        'fifo_dma_pop', 'status_nonempty', 'dma_master_read', 'dma_master_write',
        'dma_irq_pulse', 'cpu_irq_take', 'isr_mcause', 'isr_status',
        'isr_payload', 'isr_counter', 'env_error', 'no_target_effect',
        'ram_commit_cpu', 'ram_commit_dma', 'tx_capture')
    assert len(set(DMA_TARGETS)) == len(DMA_TARGETS)


def test_real_top_level_environment_error_receipt_is_counted_once():
    rows, _ = chain(0x5a, environment_error=True, real_receipt=True)
    result = features(rows)
    assert result.features.get('env_error') == 1
    assert result.features.get('no_target_effect') == 1
    assert result.target_error is True
    assert result.completed_chain is False
    assert 'dma_master_read' not in result.features


def test_declared_status_error_bit_prevents_a_completed_chain():
    rows, _ = chain(0x5a, status_value=1 << 30)
    result = features(rows)
    assert result.status_error is True
    assert result.status_bits == (30,)
    assert result.target_error is True
    assert result.completed_chain is False
    assert result.features.get('isr_status_error') == 1
    assert is_declared_feature('isr_status_error')
    assert 'isr.status' in result.targets
