"""Shared-slot consumers read the journal by reference and detach what they keep.

``shared_slot_consumers.submit_non_dma`` and ``shared_f6_slots.submit_writer``
used to deep-copy the whole journal per case (``events_since(0)``). They now
borrow the journal (``compiled_f4._borrow_exact_events``) under the documented
"no mutate, no retain, detach outputs" rule. These tests hold that rule: the
borrowed records are the journal's own objects, the documents produced from
them do not contain any of those objects, and mutating a borrowed record
afterwards cannot change an already-produced document.
"""
from copy import deepcopy
from types import SimpleNamespace

from tests.integration.test_compiled_f2_consumer import native_step


CPU = 'cpu'
CODE = bytes.fromhex('13000000b300000093000000')
ADDRESS = 0x1000
ACTION = 'case-1:source'
SCOPE = {'execution_id': 'local-execution', 'testcase_id': 'testcase',
         'source_component': CPU, 'source_epoch': 0}


class _Snapshot:
    """The memory-side authoritative read used as the instruction snapshot."""

    def __init__(self, offset, writer=ACTION, generation=3):
        self.data = CODE[offset:offset + 4]
        self.byte_offset = offset
        self.versions = [[generation, 1]] * 4
        self.writer_event_ids = (writer,) * 4
        self.writer_kinds = ('INSTRUCTION_SOURCE',) * 4


def _traces():
    return {'instr': {role: role for role in
                      ('req', 'gnt', 'addr', 'rvalid', 'rdata', 'we', 'wdata', 'be', 'error')}}


def _world():
    """One F1 case: an instruction source plus three fetched words on real OBI beats."""
    events = [dict(event_id=1, kind='instruction_source', component=CPU,
                   source_event_id=ACTION, address=ADDRESS, data_hex=CODE.hex(), generation=3)]
    for sequence, offset in enumerate(range(0, len(CODE), 4)):
        acceptance = native_step(len(events) + 1, req=1, gnt=1, addr=ADDRESS + offset, we=0, be=15)
        events.append(acceptance)
        word = CODE[offset:offset + 4]
        events.append(dict(event_id=len(events) + 1, kind='memory_read', component=CPU,
            producer_event_id=acceptance['event_id'], address=ADDRESS + offset,
            transaction=dict(SCOPE, channel_id='instr', source_sequence=sequence + 1),
            memory_id='shared_ram', generation=3, byte_offset=offset, width_bytes=4,
            writer_event_ids=[ACTION] * 4, writer_kinds=['INSTRUCTION_SOURCE'] * 4,
            versions=[[3, 1]] * 4, data_hex=word.hex()))
        events.append(native_step(len(events) + 1, rvalid=1, error=0,
                                  rdata=int.from_bytes(word, 'little')))
    return events


def _runtime():
    snapshots = [_Snapshot(offset) for offset in range(0, len(CODE), 4)]
    return SimpleNamespace(cpu_id=CPU, cpu=SimpleNamespace(reset_epoch=0),
        memory=SimpleNamespace(generation=3,
            read=lambda address, width, *, transaction_id: snapshots[(address - ADDRESS) // 4]),
        session=SimpleNamespace(template=SimpleNamespace(testcase_id='testcase')))


DECLARATION = dict(code_hex=CODE.hex(), functional_bytes=len(CODE),
                   operation='ram_write_word', ram_address=0x2000, result_address=0x2100)
IMAGE = dict(port='shared_ram', range=[0, 0x1000], component=CPU)
ERROR_POLICY = {'mode': 'native_error_role', 'native_error_observation': True}


def _consume(events):
    from myfuzz.integration.shared_slot_consumers import _consume_memory
    return _consume_memory(_runtime(), {'flow': 'F1'}, DECLARATION, None, IMAGE, _traces(),
        ERROR_POLICY, events, ADDRESS, ACTION, b'\x01\x00\x00\x00')


def _identities(value, found=None):
    """Ids of every mutable container reachable in a document."""
    found = set() if found is None else found
    if isinstance(value, dict):
        found.add(id(value))
        for key, item in value.items():
            _identities(item, found)
    elif isinstance(value, (list, tuple)):
        found.add(id(value))
        for item in value:
            _identities(item, found)
    return found


def test_memory_consumer_document_is_unchanged_by_reading_the_journal_by_reference():
    records = _world()
    borrowed = _consume(tuple(records))
    detached = _consume(deepcopy(tuple(records)))
    assert borrowed == detached
    assert len(borrowed['instruction_hops']) == 3


def test_f1_feedback_reports_only_actual_scoped_retirement():
    from myfuzz.integration.shared_slot_consumers import _consume_memory
    records = _world()
    physical = {'rvfi_valid': 1, 'rvfi_order': 7, 'rvfi_pc_rdata': ADDRESS,
                'rvfi_insn': int.from_bytes(CODE[:4], 'little'),
                'rvfi_rd_addr': 0, 'rvfi_rd_wdata': 0, 'rvfi_trap': 0}
    event = {'event_id': len(records) + 1, 'kind': 'cpu_retire', 'schema_version': 'cpu_retire.v2',
             'component': CPU, 'source_component': CPU, 'execution_id': 'local-execution',
             'source_epoch': 0, 'reset_epoch': 0, 'pc_rdata': ADDRESS,
             'insn': physical['rvfi_insn'], 'valid': 1, 'order': 7,
             'rd_addr': 0, 'rd_wdata': 0, 'trap': 0,
             'observation': {'sampling_edge': 'post_rising', 'physical': physical}}
    records.append(event)
    declaration = dict(DECLARATION, operation='instruction')
    result = _consume_memory(_runtime(), {'flow': 'F1'}, declaration, None, IMAGE, _traces(),
        ERROR_POLICY, records, ADDRESS, ACTION, CODE[:4])
    assert result['retirement'] == 'observed'
    assert result['retirement_observation']['event_id'] == event['event_id']
    assert result['retirement_observation']['reward_eligible'] is False
    event['source_epoch'] = 1
    result = _consume_memory(_runtime(), {'flow': 'F1'}, declaration, None, IMAGE, _traces(),
        ERROR_POLICY, records, ADDRESS, ACTION, CODE[:4])
    assert result['retirement'] == 'unknown'


def test_f1_compressed_pair_reports_two_real_retirements(monkeypatch):
    import sys
    from myfuzz.integration.shared_slot_consumers import _consume_memory
    code = bytes.fromhex('1d460506') + CODE[4:]
    monkeypatch.setattr(sys.modules[__name__], 'CODE', code)
    records = _world()
    for offset in (0, 2):
        event_id = len(records) + 1
        word = int.from_bytes(code[offset:offset + 2], 'little')
        physical = {'rvfi_valid': 1, 'rvfi_order': event_id,
                    'rvfi_pc_rdata': ADDRESS + offset, 'rvfi_insn': word}
        records.append({'event_id': event_id, 'kind': 'cpu_retire', 'schema_version': 'cpu_retire.v2',
            'component': CPU, 'source_component': CPU, 'execution_id': 'local-execution',
            'source_epoch': 0, 'reset_epoch': 0, 'pc_rdata': ADDRESS + offset,
            'insn': word, 'valid': 1, 'order': event_id,
            'observation': {'sampling_edge': 'post_rising', 'physical': physical}})
    declaration = dict(DECLARATION, operation='instruction', code_hex=code.hex())
    result = _consume_memory(_runtime(), {'flow': 'F1'}, declaration, None, IMAGE, _traces(),
        ERROR_POLICY, records, ADDRESS, ACTION, code[:4])
    assert result['retirement'] == 'observed'
    assert [row['pc'] for row in result['retirement_observation']['instructions']] == [ADDRESS, ADDRESS + 2]
    records.pop()
    result = _consume_memory(_runtime(), {'flow': 'F1'}, declaration, None, IMAGE, _traces(),
        ERROR_POLICY, records, ADDRESS, ACTION, code[:4])
    assert result['retirement'] == 'unknown'


def test_memory_consumer_does_not_retain_borrowed_records():
    records = _world()
    produced = _consume(tuple(records))
    assert _identities(produced).isdisjoint(_identities(records))
    # The derived hop rows are copies of the read-row versions, not the lists.
    assert produced['instruction_hops'][0]['versions'] is not records[2]['versions']


def test_mutating_a_borrowed_record_cannot_change_a_produced_document():
    records = _world()
    produced = _consume(tuple(records))
    pristine = deepcopy(produced)
    for record in records:
        if record.get('kind') == 'memory_read':
            record['versions'][0][0] = 99
            record['versions'].append([9, 9])
            record['data_hex'] = 'ffffffff'
            record['transaction']['source_sequence'] = 77
        samples = record.get('outputs', {}).get('driver_samples')
        if samples:
            samples[0]['pre']['protocol_taps']['rdata'] = 0xffffffff
    assert produced == pristine


def test_submit_non_dma_borrows_the_journal_instead_of_copying_it(monkeypatch):
    from myfuzz.integration import compiled_f4, shared_f6_slots as slots, shared_slot_consumers
    from tests.scenario.test_session_runtime_paths import factory
    runner = factory()
    for index in range(1, 4):
        runner._events.append(dict(event_id=index, kind='fixture', component='a'))
    journal = [runner._events[index] for index in range(3)]
    runtime = SimpleNamespace(runner=runner,
        compiled_inputs={'compiled': {'paths': [dict(flow_id='F1', status='executable',
            sources=[dict(kind='instruction_image', endpoint_id=CPU)])]}},
        contract={'cpu': {'data_endpoint_id': CPU}},
        cpu=SimpleNamespace(artifact=object()),
        runtime_path_admission={'shared_flow_paths': {'F1': {'path_id': 'path-1'}}},
        execution_binding_sha256='0' * 64,
        _drain_observer_view=lambda: None)
    monkeypatch.setattr(compiled_f4, '_cpu_traces', lambda *arguments: _traces())
    monkeypatch.setattr(compiled_f4, '_cpu_error_policy', lambda *arguments: ERROR_POLICY)
    monkeypatch.setattr(slots, 'execute_fragment',
        lambda *arguments: (SimpleNamespace(case_id='case-1'), ADDRESS, ACTION, {'address': 0x2000}))
    monkeypatch.setattr(slots, 'seal_case', lambda *arguments: None)
    seen = {}

    def consume_memory(owner, mapping, declaration, receipt, image, traces, error_policy,
                       events, address, action, raw):
        seen['events'] = events
        return dict(schema_version='compiled_memory_shared_slot.v1')

    monkeypatch.setattr(shared_slot_consumers, '_consume_memory', consume_memory)
    monkeypatch.setattr(runner, 'events_since',
        lambda *arguments, **keywords: (_ for _ in ()).throw(
            AssertionError('the detaching whole-journal reader was used')))
    certificate = shared_slot_consumers.submit_non_dma(runtime, b'\x01\x00\x00\x00',
        dict(flow='F1', case_id='case-1'), DECLARATION)
    assert len(seen['events']) == 3
    assert all(record is alive for record, alive in zip(seen['events'], journal))
    assert certificate['status'] == 'certified'
    assert certificate['next_fetch'] == {'address': 0x2000}
