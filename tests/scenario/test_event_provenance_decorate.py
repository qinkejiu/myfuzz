"""Append-time provenance copies only what it derives from the record.

The decorator writes exactly one key (``provenance``) and reads the rest of the
record. Its documented contract is that the supplied record is never modified,
so the record may be copied shallowly; every value inside ``provenance`` that
derives from the record is copied instead. These tests hold both halves of that
contract, and hold the output to the value produced by the former whole-record
``deepcopy`` implementation.
"""
from copy import deepcopy
from hashlib import sha256

import pytest

from myfuzz.scenario.source_provenance import SourceAdmission


def _legacy_decorate(provenance, record):
    """The former ``decorate`` body, kept verbatim as the value oracle."""
    result = deepcopy(record)
    kind = record.get('kind')
    refs = []
    resource = None
    scope = 'observation_only'
    if kind == 'source_admission':
        document = record.get('admission')
        if isinstance(document, dict):
            refs = [document.get('action_id')]
        scope = 'authorized_attempt'
    elif kind in ('source_injection', 'instruction_source'):
        refs = [record.get('action_id' if kind == 'source_injection' else 'source_event_id')]
        scope = 'source_action'
    elif kind in ('uart_source_frame_admission', 'uart_source_frame_begin',
                  'uart_source_frame_end', 'uart_source_frame_cancel'):
        refs = [record.get('action_id')]
        scope = 'uart_pin_drive' if kind in ('uart_source_frame_begin', 'uart_source_frame_end') else 'source_action'
    elif kind == 'memory_read':
        raw = record.get('writer_event_ids')
        refs = list(raw) if isinstance(raw, (list, tuple)) else []
        scope = 'memory_writer_snapshot'
    elif kind == 'cpu_retirement_match' and record.get('status') == 'accepted':
        raw = record.get('source_refs')
        refs = list(raw) if isinstance(raw, (list, tuple)) else []
        scope = 'retired_instruction_origin'
    if kind in ('memory_read', 'memory_write', 'memory_initialization', 'instruction_source'):
        resource = {}
        for name in ('memory_id', 'generation', 'byte_offset', 'address',
                     'width_bytes', 'byte_enable', 'transaction', 'version',
                     'versions', 'writer_event_id', 'writer_event_ids', 'writer_kinds'):
            if name in record:
                value = record[name]
                resource[name] = list(deepcopy(value)) if isinstance(value, tuple) else deepcopy(value)
    known, unknown = {}, []
    invalid_refs = 0
    writer_kinds = record.get('writer_kinds')
    for offset, ref in enumerate(refs):
        if type(ref) is not str or not ref.strip():
            invalid_refs += 1
            continue
        admission = provenance.registry.get(ref)
        if kind in ('uart_source_frame_admission', 'uart_source_frame_begin',
                    'uart_source_frame_end', 'uart_source_frame_cancel',
                    'cpu_retirement_match') and admission is not None:
            expected_kind = 'instruction' if kind == 'cpu_retirement_match' else 'source_event'
            if admission.input_kind != expected_kind or admission.component != record.get('component'):
                admission = None
            if kind == 'cpu_retirement_match':
                cpu_scope = record.get('cpu_scope')
                if (not isinstance(cpu_scope, dict) or
                        cpu_scope.get('source_component') != record.get('component')):
                    admission = None
        if kind == 'memory_read' and (
                not isinstance(writer_kinds, (list, tuple))
                or offset >= len(writer_kinds)
                or writer_kinds[offset] != 'INSTRUCTION_SOURCE'
                or admission is not None and admission.input_kind != 'instruction'):
            admission = None
        if admission is None:
            if ref not in unknown:
                unknown.append(ref)
        else:
            known[admission.admission_id] = admission
    candidates = list(provenance.edge_index.match_event(record))
    if candidates and scope == 'observation_only':
        scope = 'transport_candidates_only'
    result['provenance'] = {
        'schema_version': 'event_source_provenance.v1',
        'observed_case': deepcopy(provenance.observed_case),
        'origin_admission_ids': sorted(known),
        'origin_status': 'partial' if known and (unknown or invalid_refs) else 'known' if known else 'unknown',
        'unknown_writer_ids': unknown,
        'invalid_origin_references': invalid_refs,
        'proof_scope': scope,
        'edge_candidates': candidates,
        'resource': resource}
    return result


@pytest.fixture()
def decorator():
    from tests.scenario.test_runner_source_provenance import configured_runner
    runner, _path, path_id = configured_runner()
    provenance = runner._provenance
    provenance.observed_case = {'case_id': 'case-a', 'case_index': 0}
    provenance.registry.register(SourceAdmission.create(case_id='case-a', case_index=0,
        source_id='s', path_id=path_id, direction='CPU_TO_IP', component='a',
        action_id='instruction-a', role='fuzz_source', input_kind='instruction',
        input_sha256=sha256(b'\x13\x00\x00\x00').hexdigest()))
    provenance.registry.register(SourceAdmission.create(case_id='case-a', case_index=0,
        source_id='s', path_id=path_id, direction='IP_TO_IP', component='a',
        action_id='source-a', role='fuzz_source', input_kind='source_event',
        input_sha256=sha256(b'\x01\x00\x00\x00').hexdigest()))
    return provenance


def _records():
    transaction = {'execution_id': 'e', 'testcase_id': 'case-a', 'source_component': 'a',
                   'source_epoch': 0, 'channel_id': 'data', 'source_sequence': 4}
    return [
        # Every branch of the origin/ref/resource derivation.
        dict(kind='source_admission', component='a', event_id=1,
             admission={'action_id': 'instruction-a', 'extra': [1, 2]}),
        dict(kind='memory_read', component='a', event_id=2,
             writer_event_ids=['instruction-a', 'source-a', 'unknown', 17],
             writer_kinds=['INSTRUCTION_SOURCE', 'INSTRUCTION_SOURCE', 'STORE', 'STORE'],
             memory_id='shared_ram', generation=3, byte_offset=16, address=0x1000,
             width_bytes=4, byte_enable=15, transaction=transaction,
             version=(3, 1), versions=[[3, 1], [3, 1], [3, 1], [3, 1]],
             data_hex='13000000', stages=[{'pre': {'a': 1}}]),
        dict(kind='memory_write', component='a', event_id=3,
             memory_id='shared_ram', generation=4, byte_offset=20, address=0x1004,
             width_bytes=4, byte_enable=15, transaction=dict(transaction, source_sequence=5),
             version=[4, 1], writer_event_id='instruction-a',
             writer_kinds=('STORE',), value=0x55, oracle={'nested': [1, {'x': 2}]}),
        dict(kind='instruction_source', component='a', event_id=4,
             source_event_id='instruction-a', address=0x1000, data_hex='13000000',
             generation=3, transaction=transaction),
        dict(kind='uart_source_frame_begin', component='a', event_id=5,
             action_id='instruction-a', frame_id='frame0'),
        dict(kind='cpu_retirement_match', status='accepted', component='a', event_id=6,
             source_refs=('instruction-a',), cpu_scope={'source_component': 'a'}),
        dict(kind='cpu_retirement_match', status='accepted', component='b', event_id=7,
             source_refs=['instruction-a'], cpu_scope={'source_component': 'a'}),
        dict(kind='gpio_input_sample', component='a', event_id=8,
             inputs={'pad': [1, 2]}, outputs={'stage': {'value': 1}},
             causes=[{'pin': 0, 'current_sample': {'value': 1}}]),
        dict(kind='memory_read', component='a', event_id=9,
             writer_event_ids='not-a-list', writer_kinds=None,
             memory_id={'nested': [1, 2]}, generation=None),
        dict(kind='mmio_delivery', component='a', event_id=10, device_id='gpio',
             address=0x4000, source_transaction=transaction, write=False,
             read_value=7, outputs={'driver_samples': [{'pre': {'protocol_taps': {'x': 1}}}]}),
    ]


def test_decorate_does_not_modify_the_supplied_record(decorator):
    records = _records()
    hooks = {}
    for index, record in enumerate(records):
        hooks[index] = [value for value in record.values()
                        if isinstance(value, (dict, list, tuple))]
    before = deepcopy(records)
    for record in records:
        decorator.decorate(record)
    assert records == before
    # The caller's own nested objects are the same objects and are untouched.
    for index, record in enumerate(records):
        held = hooks[index]
        assert held == [value for value in record.values()
                        if isinstance(value, (dict, list, tuple))]
        assert all(any(value is current for current in record.values()) for value in held)


def test_record_copy_detaches_every_nested_value_the_caller_still_holds(decorator):
    """The journal keeps no object of the supplied record, at any depth."""
    record = _records()[1]
    decorated = decorator.decorate(record)
    assert decorated is not record and decorated.keys() == record.keys() | {'provenance'}
    assert decorated['stages'] is not record['stages'] and decorated['stages'] == record['stages']
    assert decorated['versions'] is not record['versions']
    assert decorated['transaction'] is not record['transaction']
    record['stages'][0]['pre']['a'] = 2
    record['versions'].append([9, 9])
    assert decorated['stages'] == [{'pre': {'a': 1}}]
    assert decorated['versions'] == [[3, 1]] * 4
    assert decorated['provenance']['resource']['versions'] == [[3, 1]] * 4


def test_appended_event_cannot_be_rewritten_through_the_caller_record(decorator):
    """The documented journal invariant this decorator must keep."""
    record = {'event_id': 1, 'kind': 'harness_failure', 'outputs': {'out': 1}}
    decorated = decorator.decorate(record)
    record['outputs']['out'] = 2
    record['kind'] = 'other'
    assert decorated['outputs'] == {'out': 1}
    assert decorated['kind'] == 'harness_failure'


def test_decorate_value_equals_the_former_deepcopy_path(decorator):
    for record in _records():
        assert decorator.decorate(deepcopy(record)) == _legacy_decorate(decorator, deepcopy(record))


def test_decoration_derives_copied_values_from_restorable_record_state(decorator):
    """Mutating the record after decoration cannot change the provenance it produced."""
    record = _records()[1]
    decorated = decorator.decorate(record)
    provenance = deepcopy(decorated['provenance'])
    record['versions'].append([9, 9])
    record['transaction']['source_sequence'] = 99
    record['writer_kinds'][0] = 'STORE'
    record['stages'][0]['pre']['a'] = 2
    assert decorated['provenance'] == provenance
    assert decorated['provenance']['resource']['versions'] == [[3, 1], [3, 1], [3, 1], [3, 1]]
    assert decorated['provenance']['resource']['transaction']['source_sequence'] == 4
    assert decorated['provenance']['origin_status'] == 'partial'
