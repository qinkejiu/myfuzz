"""Pure tests: accepted UART FIFO authority only from exact real joins (S4)."""
from types import SimpleNamespace

import pytest

from myfuzz.integration.dma_uart_descriptor_runtime import (
    _attach_source_authority, DescriptorCase)
from myfuzz.scenario.source_provenance import SourceAdmission
from myfuzz.scenario.uart_fifo_authority import (
    ACCEPTED, ACCEPTED_CHAIN, UNKNOWN, source_authority_evidence)

PATH_ID = 'path-1'
SOURCE_ID = 'uart.external_rx_byte'
COMPONENT = 'uart'
BYTES = (0x00, 0x00, 0x00, 0x5A, 0x5A)
ACTIONS = ('descriptor-1-0', 'descriptor-1-1', 'descriptor-1-2',
           'descriptor-1-3', 'descriptor-1-4')
FRAMES = tuple(f'frame-{index}' for index in range(len(BYTES)))


def _admissions():
    return tuple(SourceAdmission.create(case_id='descriptor-case-1',
        case_index=0, source_id=SOURCE_ID, path_id=PATH_ID,
        direction='IP_TO_CPU', component=COMPONENT, action_id=action,
        role='fuzz_source', input_kind='source_event',
        input_sha256=f'{index:064x}')
        for index, action in enumerate(ACTIONS))


def _authority(admissions):
    return dict(schema_version='dma_source_provenance.v1', installed=True,
        source_id=SOURCE_ID, source_component=COMPONENT,
        source_port='uart_rx_byte', source_width=8, direction='IP_TO_CPU',
        producer_ref='external-serial-byte', path_id=PATH_ID,
        graph_sha256='g' * 64, contract_sha256='c' * 64,
        topology_sha256='t' * 64, edge_index_sha256='e' * 64,
        master_route={'base': 0x50000000, 'size': 0x1000},
        admissions=[admission.document() for admission in admissions])


def _entries():
    return tuple(dict(index=index, action_id=ACTIONS[index],
        admission_id=None, frame_id=FRAMES[index], value=BYTES[index])
        for index in range(len(BYTES)))


def _retention(admission, index, **overrides):
    row = dict(kind='uart_consumption_match',
        schema_version='uart_consumption_match.v1', component='uart',
        reset_epoch=0, local_tick=100 + index,
        observation_event_id=200 + index, status='accepted',
        proof_scope='uart_fifo_retention', frame_id=FRAMES[index],
        entry_id=[COMPONENT, 0, 0, index + 1], receiver_id=[COMPONENT, 0, index],
        source_admission=admission.document(), path_id=PATH_ID,
        graph_path_certified=True, retained_at_push=True,
        disposition='retained', push_event=10 + index,
        validation_event=20 + index)
    row.update(overrides)
    return row


def _read(admission, index, *, route='router', access_id=None, **overrides):
    key = dict(execution_id='b' * 32, testcase_id='case-A',
        source_component='dma' if route == 'dma_master' else 'cpu',
        source_epoch=0,
        channel_id='dma-memory' if route == 'dma_master' else 'data',
        source_sequence=index + 1)
    row = dict(kind='uart_consumption_match',
        schema_version='uart_consumption_match.v1', component='uart',
        reset_epoch=0, local_tick=300 + index, observation_event_id=400 + index,
        status='accepted', proof_scope='uart_fifo_read_consumption',
        frame_id=FRAMES[index], entry_id=[COMPONENT, 0, 0, index + 1],
        source_admission=admission.document(), path_id=PATH_ID,
        graph_path_certified=True,
        access_id=access_id or ACCESS_IDS[index],
        read_value=BYTES[index], route_context_mode=route,
        address=0x50000018, window_base=0x50000000, window_size=0x1000,
        source_transaction=key, request_tick=280 + index,
        response_tick=290 + index, request_event=250 + index,
        response_event=260 + index, pop_event=240 + index,
        access_event=251 + index)
    row.update(overrides)
    return row


def _reads(admissions, *, dma_index=4):
    return tuple(_read(admission, index,
        route='dma_master' if index == dma_index else 'router')
        for index, admission in enumerate(admissions))


ACCESS_IDS = tuple(f'access-{index}' for index in range(len(BYTES)))


def _expectations():
    """The consumption-order expectations joined to the real pop rows."""
    return tuple(dict(access_id=ACCESS_IDS[index], entry_index=index,
        value=BYTES[index],
        route='dma_master' if index == 4 else 'router')
        for index in range(len(BYTES)))


def _rows(admissions, *, retention=True, reads=True):
    rows = []
    for index, admission in enumerate(admissions):
        if retention:
            rows.append(_retention(admission, index))
        if reads:
            rows.append(_read(admission, index,
                route='dma_master' if index == 4 else 'router'))
    return tuple(rows)


def _evidence():
    return dict(schema_version='uart_fifo_source_authority.v1',
        fifo_origin=UNKNOWN, source_authority='incomplete',
        proof_grade='bounded_historical_chain',
        fifo=dict(pops=[dict(kind='dma' if index == 4 else 'cpu',
                             access_id=ACCESS_IDS[index],
                             read_value=BYTES[index])
                        for index in range(len(BYTES))]))


def _entries_with_admissions(admissions):
    return tuple(dict(entry, admission_id=admissions[entry['index']].admission_id)
                 for entry in _entries())


def test_exact_retention_and_read_joins_become_accepted():
    admissions = _admissions()
    authority = _authority(admissions)
    document = source_authority_evidence(_rows(admissions),
        entries=_entries_with_admissions(admissions),
        admissions=authority['admissions'], reads=_expectations(),
        authority=authority)
    assert document['fifo_origin'] == ACCEPTED
    assert document['source_authority'] == ACCEPTED
    assert document['proof_grade'] == ACCEPTED_CHAIN
    assert document['reason'] is None and document['missing'] == []
    assert len(document['retention']) == len(BYTES)
    assert len(document['reads']) == len(BYTES)
    assert document['reads'][4]['route_context_mode'] == 'dma_master'
    assert document['reads'][4]['channel_id'] == 'dma-memory'
    assert document['authority']['edge_index_sha256'] == 'e' * 64


def test_missing_provenance_stays_unknown_with_its_missing_element():
    authority = dict(schema_version='dma_source_provenance.v1', installed=False)
    document = source_authority_evidence((),
        entries=_entries(), admissions=None, reads=(), authority=authority)
    assert document['fifo_origin'] == UNKNOWN
    assert document['source_authority'] == 'incomplete'
    assert document['reason'] == 'source_provenance_not_installed'
    assert document['missing'] == ['installed']


def test_missing_retention_or_read_stays_unknown_and_names_the_gap():
    admissions = _admissions()
    authority = _authority(admissions)
    no_retention = source_authority_evidence(_rows(admissions, retention=False),
        entries=_entries_with_admissions(admissions),
        admissions=authority['admissions'], reads=_expectations(),
        authority=authority)
    assert no_retention['fifo_origin'] == UNKNOWN
    assert any(item.startswith('uart_fifo_retention:')
               for item in no_retention['missing'])
    no_read = source_authority_evidence(_rows(admissions, reads=False),
        entries=_entries_with_admissions(admissions),
        admissions=authority['admissions'], reads=_expectations(),
        authority=authority)
    assert no_read['fifo_origin'] == UNKNOWN
    assert any(item.startswith('uart_fifo_read_consumption:')
               for item in no_read['missing'])


def test_incomplete_tracker_proofs_are_reported_as_reasons():
    admissions = _admissions()
    authority = _authority(admissions)
    rows = _rows(admissions) + (dict(kind='uart_consumption_match',
        status='incomplete', proof_scope='uart_fifo_retention',
        reason='unproven_uart_source_authority'),)
    document = source_authority_evidence(rows,
        entries=_entries_with_admissions(admissions),
        admissions=authority['admissions'], reads=_expectations(),
        authority=authority)
    assert document['fifo_origin'] == ACCEPTED
    assert document['incomplete_reasons'] == ['unproven_uart_source_authority']


@pytest.mark.parametrize('tamper', ['admission', 'path', 'source', 'entry',
                                    'not_certified', 'retained_at_push',
                                    'disposition', 'push_event'])
def test_tampered_retention_proof_is_a_hard_failure(tamper):
    admissions = _admissions()
    authority = _authority(admissions)
    row = _retention(admissions[0], 0)
    if tamper == 'admission':
        row['source_admission']['admission_id'] = 'f' * 64
    elif tamper == 'path':
        row['path_id'] = 'other-path'
    elif tamper == 'source':
        row['source_admission']['source_id'] = 'external-serial-byte'
    elif tamper == 'entry':
        row['entry_id'] = [COMPONENT, 0, 0, 99]
    elif tamper == 'not_certified':
        row['graph_path_certified'] = False
    elif tamper == 'retained_at_push':
        row['retained_at_push'] = False
    elif tamper == 'disposition':
        row['disposition'] = 'invented'
    elif tamper == 'push_event':
        row['push_event'] = None
    rows = list(_rows(admissions))
    rows[0] = row
    with pytest.raises(RuntimeError):
        source_authority_evidence(tuple(rows),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


@pytest.mark.parametrize('tamper', ['value', 'route', 'channel', 'entry',
                                    'admission', 'ticks'])
def test_tampered_read_proof_is_a_hard_failure(tamper):
    admissions = _admissions()
    authority = _authority(admissions)
    rows = list(_rows(admissions))
    # rows alternate retention, read; use the DMA master read (entry 4).
    index = 9
    row = dict(rows[index])
    if tamper == 'value':
        row['read_value'] = row['read_value'] + 1
    elif tamper == 'route':
        row['route_context_mode'] = 'direct'
    elif tamper == 'channel':
        row['source_transaction'] = dict(row['source_transaction'],
                                         channel_id='data')
    elif tamper == 'entry':
        row['entry_id'] = [COMPONENT, 0, 0, 99]
    elif tamper == 'admission':
        row['source_admission'] = dict(row['source_admission'],
                                       admission_id='f' * 64)
    elif tamper == 'ticks':
        row['request_tick'] = row['response_tick'] + 1
    rows[index] = row
    with pytest.raises(RuntimeError):
        source_authority_evidence(tuple(rows),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


def test_router_read_cannot_claim_the_dma_master_channel():
    admissions = _admissions()
    authority = _authority(admissions)
    rows = list(_rows(admissions))
    row = dict(rows[1])  # read of entry 0, expected router/data
    row['source_transaction'] = dict(row['source_transaction'],
                                     channel_id='dma-memory')
    rows[1] = row
    with pytest.raises(RuntimeError, match='wrong channel'):
        source_authority_evidence(tuple(rows),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


def test_foreign_retention_or_read_proofs_are_a_hard_failure():
    admissions = _admissions()
    authority = _authority(admissions)
    foreign_frame = _retention(admissions[0], 0, frame_id='frame-999')
    with pytest.raises(RuntimeError, match='foreign frame'):
        source_authority_evidence((*_rows(admissions), foreign_frame),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)
    foreign_access = _read(admissions[0], 0, access_id='access-999')
    with pytest.raises(RuntimeError, match='foreign access'):
        source_authority_evidence((*_rows(admissions), foreign_access),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


def test_duplicate_accepted_retention_or_read_is_a_hard_failure():
    admissions = _admissions()
    authority = _authority(admissions)
    duplicate = _retention(admissions[0], 0)
    with pytest.raises(RuntimeError, match='duplicate'):
        source_authority_evidence((*_rows(admissions), duplicate),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)
    duplicate_read = _read(admissions[0], 0)
    with pytest.raises(RuntimeError, match='duplicate'):
        source_authority_evidence((*_rows(admissions), duplicate_read),
            entries=_entries_with_admissions(admissions),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


def test_unregistered_action_or_bad_entry_order_is_refused():
    admissions = _admissions()
    authority = _authority(admissions)
    with pytest.raises(RuntimeError, match='no registered source admission'):
        source_authority_evidence(_rows(admissions),
            entries=tuple(dict(entry, action_id='unknown-action')
                          for entry in _entries())
            , admissions=authority['admissions'], reads=_expectations(),
            authority=authority)
    with pytest.raises(ValueError, match='serial order'):
        source_authority_evidence(_rows(admissions),
            entries=tuple(reversed(_entries())),
            admissions=authority['admissions'], reads=_expectations(),
            authority=authority)


def test_attach_source_authority_flips_the_case_only_with_exact_proofs():
    admissions = _admissions()
    authority = _authority(admissions)
    evidence = _evidence()
    witnesses = SimpleNamespace(rows=_rows(admissions))
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A,
        length=1)
    attached = _attach_source_authority(evidence, witnesses, case,
        action_ids=ACTIONS, frame_ids=FRAMES, source_authority=authority)
    assert attached['fifo_origin'] == ACCEPTED
    assert attached['source_authority'] == ACCEPTED
    assert attached['proof_grade'] == ACCEPTED_CHAIN
    assert attached['source_authority_evidence']['authority']['path_id'] == PATH_ID
    # The raw frame field convention is untouched: case evidence only reports
    # the accepted join; the per-frame ``fifo_origin`` stays unknown in events.
    assert attached['source_authority_evidence']['reads'][4]['entry_id'] == [
        COMPONENT, 0, 0, 5]

    unknown = _evidence()
    unknown_witnesses = SimpleNamespace(rows=())
    attached_unknown = _attach_source_authority(unknown, unknown_witnesses, case,
        action_ids=ACTIONS, frame_ids=FRAMES, source_authority=authority)
    assert attached_unknown['fifo_origin'] == UNKNOWN
    assert attached_unknown['source_authority'] == 'incomplete'
    assert attached_unknown['source_authority_evidence']['reason']


def test_attach_source_authority_without_provenance_is_explicitly_unknown():
    admissions = _admissions()
    evidence = _evidence()
    case = DescriptorCase.create('RX_TO_RAM', dst_index=0, payload=0x5A,
        length=1)
    attached = _attach_source_authority(evidence,
        SimpleNamespace(rows=()), case, action_ids=ACTIONS, frame_ids=FRAMES,
        source_authority=None)
    assert attached['fifo_origin'] == UNKNOWN
    assert attached['source_authority'] == 'incomplete'
    assert attached['proof_grade'] == 'bounded_historical_chain'
    assert attached['source_authority_evidence']['reason'] == (
        'source_provenance_not_installed')
