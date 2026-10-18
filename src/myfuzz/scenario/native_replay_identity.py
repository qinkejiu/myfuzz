"""Narrow native-observation comparison projection; never a live authority.

Callers must supply the actual process identity from the owned live session.
This module does not infer identity from events, change raw evidence, verify a
DUT process, or issue a source-consumption/certification capability.
"""
from copy import deepcopy
import re

SCHEMA_VERSION = 'native_observation_comparison.v1'
_SCOPE_KEYS = {'execution', 'command_sequence', 'reset_epoch', 'local_tick'}
_KINDS = {'native_backend_request_accepted',
          'native_backend_response_consumed', 'native_bus_completed'}
_UUID = re.compile(r'[0-9a-f]{32}\Z')


def native_observation_comparison_events(events, *, component, reset_epoch,
                                         execution):
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
    token = f'native-process:{component}:epoch:{reset_epoch}'
    rows = []
    raw = {}
    scopes = {}
    seen_native = False
    prior_events = {}

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

    for source in events:
        if type(source) is not dict:
            raise ValueError('native-comparison-event-required')
        row = deepcopy(source)
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
            service = prior_events.get(row.get('producer_event_id'))
            admission = prior_events.get(row.get('admission_event_id'))
            if (service is None or service.get('kind') != 'instruction_source'
                    or service.get('component') != component
                    or service.get('source_event_id') != row['source']['action_id']
                    or admission is None or admission.get('kind') != 'source_admission'
                    or admission.get('admission') != row['admission']
                    or service.get('producer_event_id') != admission['event_id']):
                raise ValueError('native-comparison-host-binding-journal-reference')
            row['execution'] = token
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
            elif 'accepted_scope' in row or 'response_scope' in row:
                raise ValueError('native-comparison-unexpected-prior-scope')
            seen_native = True
        rows.append(row)
        if type(source.get('event_id')) is int:
            prior_events[source['event_id']] = source
    if not seen_native:
        raise ValueError('native-comparison-native-observation-required')
    return rows
