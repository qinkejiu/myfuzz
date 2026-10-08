"""The P3 action must use live receipts to cross logical case boundaries."""

import pytest

from myfuzz.scenario.uart_cross_case_action import UartHostRamCrossCaseAction
from myfuzz.scenario.session_runtime import OnlineCaseReceipt


class Session:
    def __init__(self, event_batches):
        self.event_batches = list(event_batches)
        self.cases = []

    def submit_case(self, case):
        self.cases.append(case)
        events = self.event_batches.pop(0)
        return OnlineCaseReceipt(case.case_id, 0, len(events), tuple(events),
                                 {'cpu': 0}, {'cpu': 1}, 'running')


def writer(case_id):
    return {'kind': 'uart_store_memory_match', 'status': 'accepted',
            'store_fullkey': {'source_sequence': 7, 'channel_id': 'data'},
            'store_retirement_event_id': 11, 'store_order': 8,
            'commit_id': 'commit-7', 'byte_version': [0, 3],
            'memory_id': 'ram', 'generation': 0, 'byte_offset': 65536,
            'byte_value': 0x5a, 'source_path_certified': True,
            'source_admission': {'case_id': 'uart-fixed-warmup', 'component': 'uart',
                                 'source_id': 'uart.external_rx_byte', 'role': 'bootstrap'},
            'provenance': {'observed_case': {'case_id': case_id, 'case_index': 1}}}


def readback(load_case_id):
    return {'kind': 'uart_memory_readback', 'status': 'accepted',
            'store_fullkey': {'source_sequence': 7, 'channel_id': 'data'},
            'store_retirement_event_id': 11, 'store_byte_version': [0, 3],
            'store_commit_id': 'commit-7', 'source_case_id': 'uart-fixed-warmup',
            'load_observed_case': {'case_id': load_case_id, 'case_index': 3},
            'load_retirement_event_id': 20, 'load_order': 9,
            'memory_id': 'ram', 'generation': 0, 'byte_offset': 65536,
            'byte_value': 0x5a, 'influenced_bits': [0, 8]}


def action():
    return UartHostRamCrossCaseAction(path_id='declared-cpu-path',
                                      instruction_start=0x11000, action_id='p3-example')


def test_load_requires_live_writer_and_preserves_case_identity():
    item = action()
    with pytest.raises(ValueError, match='accepted Store'):
        item.submit_load(Session([]), ticks=2)
    store_id = 'p3-example:store:0'
    load_id = 'p3-example:load:2'
    session = Session([[writer(store_id)], [], [readback(load_id)]])
    item.submit_store(session, ticks=2)
    item.submit_gap(session, ticks=2)
    item.submit_load(session, ticks=2)
    assert [case.case_id for case in session.cases] == [store_id, 'p3-example:gap:1', load_id]
    assert [case.source.address for case in session.cases] == [0x11000, 0x11004, 0x11008]
    assert item.terminated
    assert item.document()['schema_version'] == 'uart_host_ram_cross_case_action.v1'


def test_writer_with_wrong_uart_source_cannot_enable_load():
    item = action()
    bad = writer('p3-example:store:0')
    bad['source_admission']['case_id'] = 'unrelated'
    session = Session([[bad]])
    item.submit_store(session, ticks=2)
    with pytest.raises(ValueError, match='accepted Store'):
        item.submit_load(session, ticks=2)


def test_intervening_commit_invalidates_writer_before_load():
    item = action()
    session = Session([[writer('p3-example:store:0')],
                       [{'kind': 'memory_write_commit'}]])
    item.submit_store(session, ticks=2)
    item.submit_gap(session, ticks=2)
    with pytest.raises(ValueError, match='accepted Store'):
        item.submit_load(session, ticks=2)


def test_wrong_readback_cannot_terminate():
    item = action()
    proof = readback('p3-example:load:1')
    proof['store_byte_version'] = [0, 4]
    session = Session([[writer('p3-example:store:0')], [proof]])
    item.submit_store(session, ticks=2)
    item.submit_load(session, ticks=2)
    assert not item.terminated


def test_store_can_advance_uart_and_cpu_before_cpu_only_ticks():
    item = action()
    session = Session([[writer('p3-example:store:0')]])
    item.submit_store(session, ticks=3, paired_ticks=2)
    assert [advance.schedule for advance in session.cases[0].advances] == [
        ('uart', 'cpu'), ('uart', 'cpu'), ('cpu',)]
