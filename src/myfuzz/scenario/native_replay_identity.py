"""Narrow native-observation comparison projection; never a live authority.

Callers must supply the actual process identity from the owned live session.
This module does not infer identity from events, change raw evidence, verify a
DUT process, or issue a source-consumption/certification capability.
"""
from copy import deepcopy
import json
import re

SCHEMA_VERSION = 'native_observation_comparison.v1'
_SCOPE_KEYS = {'execution', 'command_sequence', 'reset_epoch', 'local_tick'}
_KINDS = {'native_backend_request_accepted',
          'native_backend_response_consumed', 'native_bus_completed'}
_UUID = re.compile(r'[0-9a-f]{32}\Z')
# EventJournal decorates persisted completion facts with provenance. The
# comparison accepts that metadata only as observation-only and case-bound.
_COMPLETION_EVENT_KEYS = {
    'schema_version', 'kind', 'proof_scope', 'grants_source_authority',
    'component', 'event_id', 'producer_event_id', 'key', 'snapshot',
    'binding', 'address', 'data_hex', 'reset_epoch', 'accepted_scope',
    'response_scope', 'completion_scope', 'native_pre', 'admission_event_id',
    'host_binding_event_id', 'service_event_id', 'native_accepted_event_id',
    'native_response_event_id', 'native_completed_event_id', 'provenance'}
_COMPLETION_PROVENANCE_KEYS = {
    'schema_version', 'observed_case', 'origin_status', 'origin_admission_ids',
    'edge_candidates', 'invalid_origin_references', 'proof_scope', 'resource',
    'unknown_writer_ids'}
_TRANSACTION_KEY_FIELDS = {'execution_id', 'testcase_id', 'source_component',
                           'source_epoch', 'channel_id', 'source_sequence'}
_SNAPSHOT_FIELDS = {'transaction_id', 'memory_id', 'generation', 'byte_offset',
    'versions', 'writer_event_ids', 'materialized_offsets', 'writer_kinds', 'data_hex'}
_BINDING_FIELDS = {'component', 'execution', 'reset_epoch', 'case_index',
                   'admission', 'source', 'acceptance'}


def _json_material(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def native_observation_comparison_events(events, *, component, reset_epoch,
                                         execution, native_trace_signals=None,
                                         native_instruction_marker=None):
    """Copy a complete journal and rewrite only declared native scope nonces.

    This bounded single-epoch projection is intended for packet sessions, which
    forbid inter-case resets. A wrong component/epoch, unknown execution, raw
    producer mismatch or unsupported native event refuses comparison. All
    signal values, transaction/snapshot data, ordering, ticks and other fields
    are preserved. Integration with full replay is a separate responsibility.
    """
    if (type(component) is not str or not component
            or type(reset_epoch) is not int or reset_epoch < 0
            or type(execution) is not str or _UUID.fullmatch(execution) is None):
        raise ValueError('native-comparison-owned-scope-required')
    if native_trace_signals is not None:
        required_signals = {'valid', 'ready', 'addr', 'wstrb', 'wdata', 'rdata'}
        if (type(native_trace_signals) is not dict
                or not required_signals <= native_trace_signals.keys()
                or any(type(role) is not str or type(signal) is not str or not signal
                       for role, signal in native_trace_signals.items())
                or len(set(native_trace_signals.values())) != len(native_trace_signals)
                or type(native_instruction_marker) is not str
                or not native_instruction_marker):
            raise ValueError('native-comparison-trace-signal-map-required')
    token = f'native-process:{component}:epoch:{reset_epoch}'
    rows = []
    raw = {}
    scopes = {}
    seen_native = False
    prior_events = {}
    host_bindings = {}
    completed_projections = {}

    def checked_scope(value):
        if (type(value) is not dict or set(value) != _SCOPE_KEYS
                or value['execution'] != execution
                or type(value['reset_epoch']) is not int
                or value['reset_epoch'] != reset_epoch
                or type(value['command_sequence']) is not int
                or value['command_sequence'] < 1
                or type(value['local_tick']) is not int
                or value['local_tick'] < 1):
            raise ValueError('native-comparison-scope-mismatch')
        return dict(value, execution=token)

    def prior_reference(event_id, predicate, error_code):
        if type(event_id) is not int or event_id < 1:
            raise ValueError(error_code)
        event = prior_events.get(event_id)
        matches = [candidate for candidate in prior_events.values()
                   if predicate(candidate)]
        if event is None or len(matches) != 1 or matches[0] is not event:
            raise ValueError(error_code)
        return event

    for source in events:
        if type(source) is not dict:
            raise ValueError('native-comparison-event-required')
        row = deepcopy(source)
        event_id = row.get('event_id')
        if type(event_id) is int and (event_id < 1 or event_id in prior_events):
            raise ValueError('native-comparison-duplicate-event-id')
        has_scope = 'native_driver_scope' in row
        native = row.get('schema_version') == 'native_bus_observation.v1'
        host_binding = row.get('schema_version') == 'native_instruction_source_binding.v1'
        if host_binding:
            if (row.get('kind') != 'native_instruction_source_bound'
                    or row.get('component') != component or row.get('execution') != execution
                    or type(row.get('reset_epoch')) is not int or row['reset_epoch'] != reset_epoch
                    or row.get('proof_scope') != 'host_instruction_input_bound'
                    or any(row.get(key) is not False for key in ('grants_source_authority',
                        'native_bus_completion_observed', 'retirement', 'grants_feedback'))):
                raise ValueError('native-comparison-host-binding-scope')
            source_document = row.get('source')
            acceptance_document = row.get('acceptance')
            if type(source_document) is not dict or type(acceptance_document) is not dict:
                raise ValueError('native-comparison-host-binding-journal-reference')
            service = prior_reference(row.get('producer_event_id'), lambda candidate:
                candidate.get('kind') == 'instruction_source'
                and candidate.get('component') == component
                and candidate.get('source_event_id') == source_document.get('action_id'),
                'native-comparison-host-binding-journal-reference')
            admission = prior_reference(row.get('admission_event_id'), lambda candidate:
                candidate.get('kind') == 'source_admission'
                and candidate.get('admission') == row.get('admission'),
                'native-comparison-host-binding-journal-reference')
            try:
                service_data = bytes.fromhex(service.get('data_hex'))
                source_data = bytes.fromhex(source_document.get('data_hex'))
                acceptance_data = bytes.fromhex(acceptance_document.get('data_hex'))
            except (AttributeError, TypeError, ValueError):
                raise ValueError('native-comparison-host-binding-journal-reference') from None
            if (service is None or service.get('kind') != 'instruction_source'
                    or service.get('component') != component
                    or type(source_document) is not dict
                    or source_document.get('kind') != 'instruction'
                    or source_document.get('component') != component
                    or type(source_document.get('action_id')) is not str
                    or not source_document.get('action_id')
                    or type(source_document.get('address')) is not int
                    or source_document['address'] % 4
                    or type(source_document.get('data_hex')) is not str
                    or re.fullmatch(r'[0-9a-f]+', source_document['data_hex']) is None
                    or set(acceptance_document) != {'memory_id', 'address',
                        'byte_offset', 'generation', 'data_hex', 'source_event_id',
                        'versions', 'writer_event_ids', 'writer_kinds'}
                    or type(acceptance_document.get('memory_id')) is not str
                    or not acceptance_document.get('memory_id')
                    or type(acceptance_document.get('address')) is not int
                    or type(acceptance_document.get('byte_offset')) is not int
                    or type(acceptance_document.get('generation')) is not int
                    or acceptance_document['generation'] < 0
                    or acceptance_document['byte_offset'] < 0
                    or type(acceptance_document.get('data_hex')) is not str
                    or re.fullmatch(r'[0-9a-f]+', acceptance_document['data_hex']) is None
                    or acceptance_data != source_data
                    or acceptance_document['address'] != source_document['address']
                    or acceptance_document['source_event_id'] != source_document['action_id']
                    or service.get('source_event_id') != source_document['action_id']
                    or type(service.get('address')) is not int
                    or service.get('address') != source_document['address']
                    or type(service.get('data_hex')) is not str
                    or service.get('data_hex') != source_document['data_hex']
                    or type(service.get('generation')) is not int
                    or service.get('generation') != acceptance_document['generation']
                    or service_data != source_data
                    or admission is None or admission.get('kind') != 'source_admission'
                    or admission.get('admission') != row.get('admission')
                    or service.get('producer_event_id') != admission['event_id']
                    or type(row.get('event_id')) is not int
                    or row['event_id'] <= service['event_id']
                    or service['event_id'] <= admission['event_id']):
                raise ValueError('native-comparison-host-binding-journal-reference')
            row['execution'] = token
            binding = {name: row[name] for name in _BINDING_FIELDS}
            binding['execution'] = token
            binding_key = (component, reset_epoch, binding['case_index'],
                           binding['source']['action_id'])
            if binding_key in host_bindings:
                raise ValueError('native-comparison-host-binding-reused')
            host_bindings[binding_key] = dict(binding=binding,
                event_id=row.get('event_id'), admission_event_id=row.get('admission_event_id'),
                service_event_id=row.get('producer_event_id'))
        if has_scope:
            if (row.get('kind') != 'local_tick_sample'
                    or row.get('component') != component
                    or row.get('phase') not in ('pre', 'post')
                    or type(row.get('event_id')) is not int
                    or row['event_id'] < 1 or row['event_id'] in raw):
                raise ValueError('native-comparison-raw-producer-mismatch')
            scope = source['native_driver_scope']
            row['native_driver_scope'] = checked_scope(scope)
            if row.get('local_tick') != scope['local_tick']:
                raise ValueError('native-comparison-raw-tick-mismatch')
            sequence = scope['command_sequence']
            if sequence in scopes and scopes[sequence] != scope:
                raise ValueError('native-comparison-command-scope-reused')
            scopes[sequence] = deepcopy(scope)
            raw[row['event_id']] = source
            seen_native = True
        if native:
            if (row.get('kind') not in _KINDS
                    or row.get('component') != component
                    or row.get('phase') != 'pre'
                    or type(row.get('producer_event_id')) is not int):
                raise ValueError('native-comparison-projection-kind-mismatch')
            scope = {key: row.get(key) for key in _SCOPE_KEYS}
            checked_scope(scope)
            producer = raw.get(row['producer_event_id'])
            if (producer is None or producer.get('phase') != 'pre'
                    or producer['native_driver_scope'] != scope):
                raise ValueError('native-comparison-projection-producer-mismatch')
            row['execution'] = token
            for name in ('accepted_scope', 'response_scope'):
                if name in row:
                    nested = source[name]
                    row[name] = checked_scope(nested)
                    if (scopes.get(nested['command_sequence']) != nested
                            or nested['command_sequence'] >= scope['command_sequence']
                            or nested['local_tick'] >= scope['local_tick']):
                        raise ValueError('native-comparison-prior-scope-mismatch')
            if row['kind'] == 'native_bus_completed':
                if not {'accepted_scope', 'response_scope'} <= row.keys():
                    raise ValueError('native-comparison-completion-scopes-required')
                if (row['accepted_scope']['command_sequence']
                        >= row['response_scope']['command_sequence']
                        or row['accepted_scope']['local_tick']
                        >= row['response_scope']['local_tick']
                        or row['response_scope']['local_tick'] + 1 != row['local_tick']):
                    raise ValueError('native-comparison-completion-order')
                completed_projections[(component, scope['reset_epoch'],
                    scope['command_sequence'], scope['local_tick'])] = row
            elif 'accepted_scope' in row or 'response_scope' in row:
                raise ValueError('native-comparison-unexpected-prior-scope')
            seen_native = True
        completion = row.get('schema_version') == 'native_instruction_bus_completion.v1'
        if completion:
            if (set(row) != _COMPLETION_EVENT_KEYS
                    or row.get('kind') != 'native_instruction_bus_completion'
                    or row.get('component') != component
                    or row.get('proof_scope') != 'native_instruction_bus_transfer_completed'
                    or row.get('grants_source_authority') is not False
                    or type(row.get('reset_epoch')) is not int
                    or row['reset_epoch'] != reset_epoch
                    or type(row.get('event_id')) is not int or row['event_id'] < 1
                    or row['event_id'] in prior_events
                    or type(row.get('producer_event_id')) is not int):
                raise ValueError('native-comparison-completion-shape')
            provenance = row.get('provenance')
            observed_case = (provenance.get('observed_case')
                if type(provenance) is dict else None)
            if (type(provenance) is not dict
                    or set(provenance) != _COMPLETION_PROVENANCE_KEYS
                    or provenance.get('schema_version') != 'event_source_provenance.v1'
                    or type(observed_case) is not dict
                    or set(observed_case) != {'case_id', 'case_index'}
                    or type(observed_case.get('case_id')) is not str
                    or not observed_case['case_id']
                    or type(observed_case.get('case_index')) is not int
                    or observed_case['case_index'] < 0
                    or provenance.get('origin_status') != 'unknown'
                    or type(provenance.get('origin_admission_ids')) is not list
                    or provenance['origin_admission_ids']
                    or type(provenance.get('edge_candidates')) is not list
                    or provenance['edge_candidates']
                    or type(provenance.get('invalid_origin_references')) is not int
                    or provenance['invalid_origin_references'] != 0
                    or provenance.get('proof_scope') != 'observation_only'
                    or provenance.get('resource') is not None
                    or type(provenance.get('unknown_writer_ids')) is not list
                    or provenance['unknown_writer_ids']):
                raise ValueError('native-comparison-completion-provenance')
            key = row['key']
            snapshot = row['snapshot']
            binding = row['binding']
            if (type(key) is not dict or set(key) != _TRANSACTION_KEY_FIELDS
                    or key.get('execution_id') != 'local-execution'
                    or key.get('source_component') != component
                    or key.get('source_epoch') != reset_epoch
                    or key.get('channel_id') != 'memory'
                    or type(key.get('testcase_id')) is not str or not key['testcase_id']
                    or type(key.get('source_sequence')) is not int
                    or key['source_sequence'] < 1
                    or type(snapshot) is not dict or set(snapshot) != _SNAPSHOT_FIELDS
                    or type(snapshot.get('transaction_id')) is not str
                    or type(snapshot.get('memory_id')) is not str or not snapshot['memory_id']
                    or type(snapshot.get('generation')) is not int or snapshot['generation'] < 0
                    or type(snapshot.get('byte_offset')) is not int or snapshot['byte_offset'] < 0
                    or type(snapshot.get('data_hex')) is not str
                    or re.fullmatch(r'[0-9a-f]{8}', snapshot['data_hex']) is None
                    or type(binding) is not dict or set(binding) != _BINDING_FIELDS
                    or binding.get('component') != component
                    or binding.get('execution') != execution
                    or binding.get('reset_epoch') != reset_epoch
                    or type(binding.get('case_index')) is not int or binding['case_index'] < 0
                    or type(binding.get('admission')) is not dict
                    or type(binding.get('source')) is not dict
                    or type(binding.get('acceptance')) is not dict):
                raise ValueError('native-comparison-completion-source-material')
            try:
                from .ledger import TransactionKey
                expected_transaction_id = str(TransactionKey(**key))
            except (TypeError, ValueError):
                raise ValueError('native-comparison-completion-key') from None
            binding_source = binding['source']
            admission = binding['admission']
            acceptance = binding['acceptance']
            if (provenance['observed_case']['case_id'] != admission.get('case_id')
                    or provenance['observed_case']['case_index'] != binding.get('case_index')
                    or type(admission.get('case_index')) is not int
                    or admission['case_index'] < 0
                    or admission['case_index'] != binding['case_index']):
                raise ValueError('native-comparison-completion-provenance')
            address = row.get('address')
            data_hex = row.get('data_hex')
            native_pre = row.get('native_pre')
            try:
                source_data = bytes.fromhex(binding_source['data_hex'])
                acceptance_data = bytes.fromhex(acceptance['data_hex'])
                snapshot_data = bytes.fromhex(snapshot['data_hex'])
                source_address = binding_source['address']
                offset = address - source_address
                acceptance_fields = {'memory_id', 'address', 'byte_offset', 'generation',
                    'data_hex', 'source_event_id', 'versions', 'writer_event_ids',
                    'writer_kinds'}
                versions = acceptance['versions']
                writer_ids = acceptance['writer_event_ids']
                writer_kinds = acceptance['writer_kinds']
                snapshot_versions = snapshot['versions']
                snapshot_writer_ids = snapshot['writer_event_ids']
                snapshot_writer_kinds = snapshot['writer_kinds']
                native_shape_ok = (type(native_pre) is list and len(native_pre) == 6
                    and all(type(value) is int for value in native_pre))
                source_join_ok = native_shape_ok and (
                    type(address) is int and address >= 0 and address % 4 == 0
                    and type(data_hex) is str and re.fullmatch(r'[0-9a-f]{8}', data_hex)
                    and type(binding_source.get('data_hex')) is str
                    and re.fullmatch(r'[0-9a-f]+', binding_source['data_hex'])
                    and type(acceptance.get('data_hex')) is str
                    and re.fullmatch(r'[0-9a-f]+', acceptance['data_hex'])
                    and snapshot['transaction_id'] == expected_transaction_id
                    and snapshot_data == bytes.fromhex(data_hex)
                    and type(binding_source.get('kind')) is str
                    and binding_source['kind'] == 'instruction'
                    and binding_source.get('component') == component
                    and type(binding_source.get('action_id')) is str
                    and bool(binding_source['action_id'])
                    and type(source_address) is int and source_address >= 0
                    and source_address % 4 == 0 and len(source_data) >= 4
                    and len(source_data) % 4 == 0 and offset >= 0 and offset % 4 == 0
                    and offset + 4 <= len(source_data)
                    and type(acceptance) is dict and set(acceptance) == acceptance_fields
                    and acceptance_data == source_data
                    and acceptance['source_event_id'] == binding_source['action_id']
                    and type(acceptance['address']) is int
                    and acceptance['address'] == source_address
                    and type(acceptance['memory_id']) is str and bool(acceptance['memory_id'])
                    and type(acceptance['generation']) is int and acceptance['generation'] >= 0
                    and type(acceptance['byte_offset']) is int and acceptance['byte_offset'] >= 0
                    and type(versions) in (list, tuple)
                    and len(versions) == len(source_data)
                    and all(type(version) in (list, tuple) and len(version) == 2
                            and all(type(part) is int and part >= 0 for part in version)
                            for version in versions)
                    and type(writer_ids) in (list, tuple)
                    and len(writer_ids) == len(source_data)
                    and all(type(value) is str and value == binding_source['action_id']
                            for value in writer_ids)
                    and type(writer_kinds) in (list, tuple)
                    and len(writer_kinds) == len(source_data)
                    and all(type(value) is str and value == 'INSTRUCTION_SOURCE'
                            for value in writer_kinds)
                    and type(snapshot_versions) in (list, tuple)
                    and len(snapshot_versions) == 4
                    and all(type(version) in (list, tuple) and len(version) == 2
                            and all(type(part) is int and part >= 0 for part in version)
                            for version in snapshot_versions)
                    and type(snapshot_writer_ids) in (list, tuple)
                    and len(snapshot_writer_ids) == 4
                    and all(type(value) is str for value in snapshot_writer_ids)
                    and type(snapshot_writer_kinds) in (list, tuple)
                    and len(snapshot_writer_kinds) == 4
                    and all(type(value) is str for value in snapshot_writer_kinds)
                    and type(snapshot['materialized_offsets']) in (list, tuple)
                    and snapshot['memory_id'] == acceptance['memory_id']
                    and snapshot['generation'] == acceptance['generation']
                    and snapshot['byte_offset'] == acceptance['byte_offset'] + offset
                    and snapshot_data == source_data[offset:offset + 4]
                    and tuple(tuple(version) for version in snapshot_versions)
                        == tuple(tuple(version) for version in versions[offset:offset + 4])
                    and tuple(snapshot_writer_ids) == tuple(writer_ids[offset:offset + 4])
                    and tuple(snapshot_writer_kinds) == tuple(writer_kinds[offset:offset + 4])
                    and not snapshot['materialized_offsets']
                    and native_pre == [1, 1, address, 0,
                        int.from_bytes(bytes.fromhex(data_hex), 'little'), 1])
            except (KeyError, TypeError, ValueError, OverflowError):
                source_join_ok = False
            if not source_join_ok:
                raise ValueError('native-comparison-completion-source-join')
            binding_key = (component, reset_epoch, binding['case_index'], binding_source['action_id'])
            issued_binding = host_bindings.get(binding_key)
            normalized_binding = deepcopy(binding)
            normalized_binding['execution'] = token
            if (issued_binding is None
                    or _json_material(issued_binding['binding']) != _json_material(normalized_binding)):
                raise ValueError('native-comparison-completion-binding-reference')
            original_scopes = {}
            for name in ('accepted_scope', 'response_scope', 'completion_scope'):
                original = row[name]
                normalized = checked_scope(original)
                if scopes.get(original['command_sequence']) != original:
                    raise ValueError('native-comparison-completion-scope-reference')
                original_scopes[name] = normalized
            accepted = original_scopes['accepted_scope']
            response = original_scopes['response_scope']
            completed = original_scopes['completion_scope']
            if (accepted['command_sequence'] >= response['command_sequence']
                    or response['command_sequence'] >= completed['command_sequence']
                    or accepted['local_tick'] >= response['local_tick']
                    or response['local_tick'] + 1 != completed['local_tick']):
                raise ValueError('native-comparison-completion-order')
            raw_producer = prior_reference(row['producer_event_id'], lambda event:
                event.get('kind') == 'local_tick_sample'
                and event.get('component') == component
                and event.get('phase') == 'pre'
                and event.get('native_driver_scope') == row['completion_scope'],
                'native-comparison-completion-raw-reference')
            if (raw_producer is None or raw_producer.get('kind') != 'local_tick_sample'
                    or raw_producer.get('component') != component
                    or raw_producer.get('phase') != 'pre'
                    or raw_producer.get('native_driver_scope') != row['completion_scope']):
                raise ValueError('native-comparison-completion-raw-reference')
            completion_event = row['event_id']

            def scope_event_matches(event, kind, scope):
                return (event.get('schema_version') == 'native_bus_observation.v1'
                    and event.get('kind') == kind and event.get('component') == component
                    and event.get('phase') == 'pre' and event.get('transaction') == key
                    and all(event.get(field) == scope[field] for field in
                        ('execution', 'command_sequence', 'reset_epoch', 'local_tick')))

            admission_event = prior_reference(row['admission_event_id'], lambda event:
                event.get('kind') == 'source_admission'
                and event.get('admission') == admission,
                'native-comparison-completion-admission-reference')
            service_event = prior_reference(row['service_event_id'], lambda event:
                event.get('kind') == 'instruction_source'
                and event.get('component') == component
                and event.get('source_event_id') == binding_source['action_id']
                and event.get('producer_event_id') == admission_event.get('event_id'),
                'native-comparison-completion-service-reference')
            host_event = prior_reference(row['host_binding_event_id'], lambda event:
                event.get('schema_version') == 'native_instruction_source_binding.v1'
                and event.get('kind') == 'native_instruction_source_bound'
                and event.get('component') == component
                and event.get('execution') == execution
                and event.get('reset_epoch') == reset_epoch
                and event.get('case_index') == binding['case_index']
                and event.get('source', {}).get('action_id') == binding_source['action_id'],
                'native-comparison-completion-host-binding-reference')
            accepted_event = prior_reference(row['native_accepted_event_id'], lambda event:
                scope_event_matches(event, 'native_backend_request_accepted', row['accepted_scope']),
                'native-comparison-completion-accepted-reference')
            response_event = prior_reference(row['native_response_event_id'], lambda event:
                scope_event_matches(event, 'native_backend_response_consumed', row['response_scope']),
                'native-comparison-completion-response-reference')
            completed_event = prior_reference(row['native_completed_event_id'], lambda event:
                scope_event_matches(event, 'native_bus_completed', row['completion_scope'])
                and event.get('accepted_scope') == row['accepted_scope']
                and event.get('response_scope') == row['response_scope'],
                'native-comparison-completion-completed-reference')
            expected_binding = host_bindings.get(binding_key)
            if (expected_binding is None
                    or expected_binding['event_id'] != host_event['event_id']
                    or expected_binding['admission_event_id'] != admission_event['event_id']
                    or expected_binding['service_event_id'] != service_event['event_id']
                    or host_event['admission_event_id'] != admission_event['event_id']
                    or host_event['producer_event_id'] != service_event['event_id']
                    or not (admission_event['event_id'] < service_event['event_id']
                        < host_event['event_id'] < accepted_event['event_id']
                        < response_event['event_id'] < completed_event['event_id']
                        < completion_event)
                    or accepted_event.get('producer_event_id') == response_event.get('producer_event_id')
                    or accepted_event.get('producer_event_id') == row['producer_event_id']
                    or response_event.get('producer_event_id') == row['producer_event_id']
                    or completed_event.get('producer_event_id') != row['producer_event_id']):
                raise ValueError('native-comparison-completion-reference-order')
            if (type(service_event.get('address')) is not int
                    or service_event.get('address') != binding_source['address']
                    or type(service_event.get('data_hex')) is not str
                    or service_event.get('data_hex') != binding_source['data_hex']
                    or type(service_event.get('source_event_id')) is not str
                    or service_event.get('source_event_id') != binding_source['action_id']
                    or type(service_event.get('generation')) is not int
                    or service_event.get('generation') != acceptance['generation']
                    or service_event.get('producer_event_id') != admission_event['event_id']):
                raise ValueError('native-comparison-completion-service-join')
            if native_trace_signals is None:
                raise ValueError('native-comparison-trace-signal-map-required')
            accepted_raw = prior_reference(accepted_event.get('producer_event_id'), lambda event:
                event.get('kind') == 'local_tick_sample'
                and event.get('component') == component
                and event.get('phase') == 'pre'
                and event.get('native_driver_scope') == row['accepted_scope'],
                'native-comparison-completion-accepted-raw-reference')
            try:
                accepted_outputs = accepted_raw['outputs']
                accepted_taps = accepted_outputs['protocol_taps']
                accepted_physical = accepted_outputs['physical']
                expected_accepted_native = {role: accepted_taps[native_trace_signals[role]]
                    for role in ('valid', 'ready', 'addr', 'wstrb', 'wdata', 'rdata')}
                expected_accepted_native['instruction'] = accepted_physical[native_instruction_marker]
            except (KeyError, TypeError):
                raise ValueError('native-comparison-completion-accepted-raw-reference') from None
            accepted_native = accepted_event.get('native')
            if (any(type(value) is not int for value in expected_accepted_native.values())
                    or type(accepted_native) is not dict
                    or set(accepted_native) != set(expected_accepted_native)
                    or any(type(value) is not int for value in accepted_native.values())
                    or accepted_native != expected_accepted_native
                    or accepted_native.get('valid') != 1
                    or accepted_native.get('ready') != 0
                    or accepted_native.get('addr') != address
                    or accepted_native.get('wstrb') != 0
                    or accepted_native.get('instruction') != 1):
                raise ValueError('native-comparison-completion-accepted-request-join')
            if (type(response_event.get('value')) is not int
                    or response_event.get('value') != int.from_bytes(snapshot_data, 'little')
                    or response_event.get('native_post_is_offer_only') is not True):
                raise ValueError('native-comparison-completion-response-join')
            projected = completed_projections.get((component, reset_epoch,
                completed['command_sequence'], completed['local_tick']))
            native = completed_event.get('native')
            native_projection = (native.get('valid'), native.get('ready'),
                native.get('addr'), native.get('wstrb'), native.get('rdata'),
                native.get('instruction')) if type(native) is dict else None
            if (projected is None
                    or projected.get('event_id') != completed_event['event_id']
                    or projected.get('producer_event_id') != row['producer_event_id']
                    or projected.get('transaction') != key
                    or projected.get('accepted_scope') != accepted
                    or projected.get('response_scope') != response
                    or type(native) is not dict
                    or not {'valid', 'ready', 'addr', 'wstrb', 'wdata', 'rdata', 'instruction'} <= native.keys()
                    or any(type(native[name]) is not int for name in
                        ('valid', 'ready', 'addr', 'wstrb', 'wdata', 'rdata', 'instruction'))
                    or tuple(native_projection) != tuple(native_pre)):
                raise ValueError('native-comparison-completion-bus-reference')
            row['binding']['execution'] = token
            for name, normalized in original_scopes.items():
                row[name] = normalized
            seen_native = True
        rows.append(row)
        if type(source.get('event_id')) is int:
            prior_events[source['event_id']] = source
    if not seen_native:
        raise ValueError('native-comparison-native-observation-required')
    return rows
