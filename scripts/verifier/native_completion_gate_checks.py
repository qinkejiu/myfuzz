"""Independent saved-raw directed-gate checks; no live observer or authority."""
from collections import Counter
import hashlib
import json


def _json_equivalent(left, right):
    """Compare JSON-shaped live and saved values without Python bool/int aliasing."""
    try:
        return json.dumps(left, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False) == json.dumps(
            right, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return False


def _sequence(value):
    """Return an immutable view of an actual list/tuple, rejecting lookalikes."""
    if type(value) not in (list, tuple):
        return None
    return tuple(value)


def _version_vector(value, *, length):
    rows = _sequence(value)
    if rows is None or len(rows) != length:
        return None
    normalized = []
    for row in rows:
        parts = _sequence(row)
        if (parts is None or len(parts) != 2
                or any(type(part) is not int or not 0 <= part < 1 << 64
                       for part in parts)):
            return None
        normalized.append(tuple(parts))
    return tuple(normalized)


def _string_vector(value, *, length):
    rows = _sequence(value)
    if (rows is None or len(rows) != length
            or any(type(item) is not str or not item for item in rows)):
        return None
    return tuple(rows)


def check_host_source_bindings(events, plan, *, execution):
    """Saved host-input facts only; no live issuance or bus/source grant."""
    report = dict(schema_version='native_host_binding_gate_checks.v1', status='failed',
        errors=[], bindings=[], source_authority=False, retirement=False, feedback_authority=False)

    def require(value, reason):
        if not value:
            raise ValueError(reason)

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')

    try:
        require(plan['schema_version'] in (20, 21, 22, 23)
                and plan['native_packet_configuration']['enabled'] is True,
                'native-binding-plan-required')
        by_id = {event['event_id']: event for event in events}
        selected = {case['source']['action_id']: (index, case) for index, case in enumerate(plan['cases'])
            if case['source']['kind'] == 'instruction' and case['source_role'] == 'fuzz_source'}
        rows = [event for event in events if event.get('schema_version') == 'native_instruction_source_binding.v1']
        require(len(rows) == len(selected), 'native-binding-selected-source-count')
        seen = set()
        for row in rows:
            source = row['source']; action = source['action_id']
            require(action in selected and action not in seen, 'native-binding-foreign-or-duplicate-action')
            seen.add(action)
            index, case = selected[action]
            require(row['kind'] == 'native_instruction_source_bound' and row['component'] == 'cpu'
                    and row['execution'] == execution and row['reset_epoch'] == 0
                    and row['case_index'] == index and source == case['source']
                    and row['proof_scope'] == 'host_instruction_input_bound'
                    and all(row[key] is False for key in ('grants_source_authority',
                        'native_bus_completion_observed', 'retirement', 'grants_feedback')), 'native-binding-scope')
            admission = row['admission']
            admission_material = {key: value for key, value in admission.items() if key != 'admission_id'}
            require(admission['role'] == 'fuzz_source' and admission['input_kind'] == 'instruction'
                    and admission['schema_version'] == 'source_admission.v1'
                    and admission['admission_id'] == hashlib.sha256(canonical(admission_material)).hexdigest()
                    and admission['case_id'] == case['case_id'] and admission['case_index'] == index
                    and admission['action_id'] == action and admission['component'] == source['component'] == 'cpu'
                    and admission['path_id'] == case['path_id'] and admission['direction'] == case['direction']
                    and admission['input_sha256'] == hashlib.sha256(canonical(source)).hexdigest(),
                    'native-binding-admission-input')
            acceptance = row['acceptance']; raw = bytes.fromhex(source['data_hex'])
            require(len(raw) == 4 and acceptance['address'] == source['address']
                    and acceptance['data_hex'] == source['data_hex'] and acceptance['source_event_id'] == action
                    and list(acceptance['writer_event_ids']) == [action] * 4
                    and list(acceptance['writer_kinds']) == ['INSTRUCTION_SOURCE'] * 4
                    and len(acceptance['versions']) == 4
                    and all(len(version) == 2 and version[0] == acceptance['generation']
                        and all(type(part) is int and part >= 0 for part in version)
                        for version in acceptance['versions']), 'native-binding-actual-acceptance')
            service = by_id[row['producer_event_id']]
            registered = by_id[row['admission_event_id']]
            require(registered['kind'] == 'source_admission' and registered['admission'] == admission
                    and service['kind'] == 'instruction_source' and service['component'] == 'cpu'
                    and service['producer_event_id'] == registered['event_id']
                    and service['source_event_id'] == action and service['address'] == source['address']
                    and service['data_hex'] == source['data_hex']
                    and service['generation'] == acceptance['generation']
                    and registered['event_id'] < service['event_id'] < row['event_id'],
                    'native-binding-actual-service-reference')
            report['bindings'].append(row)
        require(seen == set(selected), 'native-binding-missing-selected-source')
        report['status'] = 'host_input_binding_checks_passed'
    except (KeyError, ValueError, TypeError, IndexError) as error:
        report['errors'].append(dict(type=type(error).__name__, message=str(error)))
    return report


def check_native_completion(events, runtime_document, *, controlled_response_records=(),
                            terminal_refusal=None):
    """Reconstruct every native transfer from raw samples, then check projections.

    Return failures with partial joins so the caller can save evidence before
    rejecting the gate. Artifact admission remains the actual session's job.
    """
    metrics = dict(schema_version='native_completion_gate_raw_checks.v1',
                   status='failed', errors=[], joins=[], counts={},
                   source_authority=False, retirement=False, feedback_authority=False,
                   terminal_refusal=None)
    errors, joins = metrics['errors'], metrics['joins']
    counts = Counter()
    excluded_injected_writes = []

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))

    try:
        expected_injected_writes = (terminal_refusal.get('write_transactions', [])
            if type(terminal_refusal) is dict else [])
        require(type(expected_injected_writes) is list
                and all(type(key) is dict for key in expected_injected_writes)
                and len({canonical(key) for key in expected_injected_writes})
                    == len(expected_injected_writes), 'terminal-refusal-write-key-list')
        injected_write_keys = {canonical(key) for key in expected_injected_writes}
        contract = runtime_document['native_completion_observation']
        traces = runtime_document['base_protocol_traces']['traces']
        require(len(traces) == 1, 'one-native-trace-required')
        trace = traces[0]
        require(contract['schema_version'] == 'native_completion_observation.v1'
                and trace['protocol'] == 'ready-valid-memory'
                and trace['boundary'] == 'cpu_physical_abi'
                and trace['endpoint_id'] == contract['endpoint_id']
                and trace['clock_domain'] == contract['clock_domain'], 'metadata-binding')
        widths = dict(valid=1, ready=1, addr=32, wdata=32, wstrb=4, rdata=32)
        require(trace['signal_widths'] == widths and set(trace['signals']) == set(widths),
                'native-role-widths')
        marker = contract['instruction_marker']['signal']
        require(contract['instruction_marker']['width'] == 1
                and contract['completion']['phase'] == 'pre', 'native-marker-phase')
        by_id = {}
        frames = {}
        projections = {}
        services = {}
        mmio_acceptances = {}
        for event in events:
            eid = event['event_id']
            require(type(eid) is int and eid > 0 and eid not in by_id, 'duplicate-event-id')
            by_id[eid] = event
            kind = event.get('kind')
            if kind == 'mmio_acceptance' and event.get('component') == 'cpu':
                key = event['source_transaction']
                token = (key['source_epoch'], key['source_sequence'])
                require(token not in mmio_acceptances, 'duplicate-mmio-acceptance')
                mmio_acceptances[token] = event
            if event.get('component') == 'cpu' and kind == 'local_tick_sample':
                require('native_driver_scope' in event, 'cpu-raw-scope-missing')
                scope = event['native_driver_scope']
                token = canonical(scope)
                phase = event['phase']
                require(phase in ('pre', 'post'), 'raw-phase')
                require(phase not in frames.setdefault(token, {}), 'duplicate-raw-phase')
                frames[token][phase] = event
                counts['raw_' + phase] += 1
            if kind in ('native_backend_request_accepted', 'native_backend_response_consumed',
                        'native_bus_completed'):
                require(event.get('component') == 'cpu', 'projection-component')
                ref = event['producer_event_id']
                require(kind not in projections.setdefault(ref, {}), 'duplicate-projection')
                projections[ref][kind] = event
            if event.get('component') == 'cpu' and kind in ('memory_read', 'memory_write', 'mmio_delivery'):
                key = event.get('transaction', event.get('source_transaction'))
                require(type(key) is dict, 'service-memory-key')
                if canonical(key) in injected_write_keys:
                    require(kind == 'memory_write' and key['source_component'] == 'cpu'
                            and type(key.get('source_epoch')) is int
                            and type(key.get('source_sequence')) is int,
                            'terminal-refusal-injected-write-shape')
                    excluded_injected_writes.append(dict(event_id=event['event_id'],
                        transaction=key, service_event=event))
                    continue
                require(key['channel_id'] == 'memory', 'service-memory-key')
                token = (key['source_epoch'], key['source_sequence'])
                require(token not in services, 'duplicate-service-transaction')
                services[token] = event

        require(frames, 'no-native-raw-frames')
        pending, offered, previous = None, None, None
        sequence = 0
        execution, epoch = None, None
        used_projections, used_services = set(), set()

        def native(event):
            output = event['outputs']
            result = {}
            for role, width in widths.items():
                value = output['protocol_taps'][trace['signals'][role]]
                require(type(value) is int and 0 <= value < 1 << width, 'raw-native-width:' + role)
                result[role] = value
            value = output['physical'][marker]
            require(type(value) is int and value in (0, 1), 'raw-marker')
            result['instruction'] = value
            return result

        def stable(actual, saved):
            return actual['valid'] == 1 and all(actual[k] == saved[k] for k in
                ('addr', 'wstrb', 'instruction')) and (not saved['wstrb'] or actual['wdata'] == saved['wdata'])

        def projection(raw, kind, key, scope):
            row = projections.get(raw['event_id'], {}).get(kind)
            require(row is not None, 'missing-projection:' + kind)
            require(row['schema_version'] == 'native_bus_observation.v1'
                    and row['phase'] == 'pre' and row['proof_scope'] == 'native_bus_transfer_only'
                    and row['grants_source_authority'] is False and row['retirement'] is False
                    and row['artifact_digest'] == runtime_document['artifact_digest']
                    and row['endpoint_id'] == contract['endpoint_id']
                    and row['clock_domain'] == contract['clock_domain']
                    and row['transaction'] == key
                    and all(row[k] == v for k, v in scope.items()), 'projection-scope-or-key')
            used_projections.add((raw['event_id'], kind))
            return row

        for pair in sorted(frames.values(), key=lambda p: p.get('pre', p.get('post'))['event_id']):
            require(set(pair) == {'pre', 'post'}, 'missing-raw-phase')
            pre_event, post_event = pair['pre'], pair['post']
            scope = pre_event['native_driver_scope']
            require(post_event['native_driver_scope'] == scope
                    and pre_event['local_tick'] == post_event['local_tick'] == scope['local_tick']
                    and pre_event['producer_event_id'] == post_event['producer_event_id'], 'raw-pair-scope')
            require(type(scope['command_sequence']) is int and type(scope['local_tick']) is int
                    and type(scope['reset_epoch']) is int and bool(scope['execution']), 'raw-scope-types')
            if previous is not None:
                require(scope['execution'] == execution and scope['reset_epoch'] == epoch
                        and scope['local_tick'] == previous['local_tick'] + 1
                        and scope['command_sequence'] > previous['command_sequence'], 'raw-gap-or-reset')
            execution, epoch, previous = scope['execution'], scope['reset_epoch'], scope
            pre, post = native(pre_event), native(post_event)
            backend = pre_event['outputs']['backend']
            for role, width in dict(m_req_valid=1, m_req_ready=1, m_req_addr=32,
                    m_req_write=1, m_req_wdata=32, m_req_be=4, m_rsp_valid=1,
                    m_rsp_ready=1, m_rsp_rdata=32, m_rsp_error=1).items():
                require(type(backend[role]) is int and 0 <= backend[role] < 1 << width,
                        'raw-backend-width:' + role)
            if offered is None and pre['valid']:
                offered = pre
            if offered is not None:
                require(stable(pre, offered), 'offered-request-changed')
            accepted = backend['m_req_valid'] == backend['m_req_ready'] == 1
            consumed = backend['m_rsp_valid'] == backend['m_rsp_ready'] == 1
            completed = pre['valid'] == pre['ready'] == 1
            if completed:
                counts['raw_completed'] += 1
                require(pending is not None and 'response_scope' in pending
                        and scope['local_tick'] == pending['response_scope']['local_tick'] + 1
                        and stable(pre, pending['native']) and pre['rdata'] == pending['response'],
                        'native-completion-without-raw-response')
                service = pending['service']
                is_terminal_refusal = (type(terminal_refusal) is dict
                    and terminal_refusal.get('producer_event_id') == pre_event['event_id'])
                if is_terminal_refusal:
                    refusal_key = terminal_refusal.get('transaction')
                    refusal_scope = terminal_refusal.get('refused_scope')
                    require(type(refusal_key) is dict and refusal_key == pending['key']
                            and refusal_scope == scope and pending['service']['kind'] == 'memory_read'
                            and terminal_refusal.get('accepted_scope') == pending['accepted_scope']
                            and terminal_refusal.get('response_scope') == pending['response_scope']
                            and pre['instruction'] == 1 and pre['wstrb'] == 0
                            and pre['addr'] == pending['native']['addr']
                            and projections.get(pre_event['event_id'], {}).get(
                                'native_bus_completed') is None
                            and not any(event.get('kind') == 'native_instruction_bus_completion'
                                and (event.get('key') == refusal_key
                                     or event.get('producer_event_id') == pre_event['event_id'])
                                for event in events), 'terminal-refusal-raw-shape')
                    metrics['terminal_refusal'] = dict(
                        producer_event_id=pre_event['event_id'], transaction=refusal_key,
                        native=pre,
                        accepted_raw_event_id=pending['accepted_raw'],
                        response_raw_event_id=pending['response_raw'],
                        accepted_scope=pending['accepted_scope'],
                        response_scope=pending['response_scope'], refused_scope=scope,
                        service_event_id=service['event_id'],
                        snapshot=dict(memory_id=service['memory_id'],
                            generation=service['generation'], byte_offset=service['byte_offset'],
                            data_hex=service['data_hex'], versions=service['versions'],
                            writer_event_ids=service['writer_event_ids'],
                            writer_kinds=service.get('writer_kinds')))
                    pending['terminal_refusal'] = pre_event['event_id']
                    pending['terminal_refusal_key'] = refusal_key
                    counts['terminal_refusals'] += 1
                    offered = post if post['valid'] else None
                else:
                    row = projection(pre_event, 'native_bus_completed', pending['key'], scope)
                    require(row['native'] == pre and row['accepted_scope'] == pending['accepted_scope']
                            and row['response_scope'] == pending['response_scope']
                            and row['transfer_type'] == ('instruction_bus_transfer' if pre['instruction'] else 'data_bus_transfer'),
                            'completion-projection-fields')
                snapshot = None if is_terminal_refusal else row.get('memory_read_snapshot')
                if not is_terminal_refusal:
                    if service['kind'] == 'memory_read':
                        require(type(snapshot) is dict, 'missing-read-snapshot')
                        for name in ('memory_id', 'generation', 'byte_offset', 'data_hex',
                                     'versions', 'writer_event_ids'):
                            require(canonical(snapshot[name]) == canonical(service[name]), 'snapshot-service:' + name)
                        kinds = snapshot['writer_kinds']
                        require(isinstance(kinds, (list, tuple)) and len(kinds) == 4
                                and all(type(kind) is str and bool(kind) for kind in kinds),
                                'snapshot-writer-kinds-shape')
                        if 'writer_kinds' in service:
                            require(canonical(kinds) == canonical(service['writer_kinds']),
                                    'snapshot-service:writer_kinds')
                        require(snapshot['transaction_id'] == 'TransactionKey(' + ', '.join(
                            f'{k}={pending["key"][k]!r}' for k in ('execution_id', 'testcase_id',
                            'source_component', 'source_epoch', 'channel_id', 'source_sequence')) + ')',
                            'snapshot-transaction-id')
                        require(int.from_bytes(bytes.fromhex(snapshot['data_hex']), 'little') == pre['rdata'],
                                'snapshot-rdata')
                    else:
                        require(snapshot is None, 'non-ram-snapshot')
                    joins.append(dict(transaction=pending['key'], accepted_raw_event_id=pending['accepted_raw'],
                        response_raw_event_id=pending['response_raw'], completed_raw_event_id=pre_event['event_id'],
                        service_event_id=service['event_id'], accepted_scope=pending['accepted_scope'],
                        response_scope=pending['response_scope'], completed_scope=scope,
                        native=pre, response_value=pending['response'], snapshot=snapshot))
                    joins[-1]['actual_service_response'] = pending['actual_service_response']
                    joins[-1]['accepted_native'] = pending['native']
                    joins[-1]['service_kind'] = service['kind']
                    joins[-1]['writer_kinds_independently_recorded'] = (
                        service['kind'] == 'memory_read' and 'writer_kinds' in service)
                    joins[-1]['source_authority'] = False
                    joins[-1]['writer_kind_boundary'] = (
                        'service_writer_kinds_not_recorded_no_independent_lane_kind_join'
                        if service['kind'] == 'memory_read' and 'writer_kinds' not in service
                        else 'transfer_observation_only_no_source_authority')
                    joins[-1]['actual_ram_store'] = (
                        {name: service[name] for name in ('address', 'width_bytes', 'value',
                            'byte_enable', 'memory_id', 'generation', 'byte_offset', 'version')}
                        if service['kind'] == 'memory_write' else None)
                    counts['instruction_completed' if pre['instruction'] else 'data_completed'] += 1
                    counts['completed'] += 1
                    pending = None
                    offered = post if post['valid'] else None
            else:
                require(not pre['ready'], 'ready-without-valid')
                if offered is not None:
                    require(stable(post, offered), 'post-offer-changed')
                if pending is not None:
                    require(stable(pre, pending['native']), 'pending-native-changed')
                    require(scope['local_tick'] - pending['accepted_scope']['local_tick']
                            <= 2 * trace['max_wait_cycles'] + 4, 'pending-wait-bound')
                if offered is None and post['valid']:
                    offered = post
            if accepted:
                require(pending is None and not consumed and not completed and pre['valid']
                        and backend['m_req_addr'] == pre['addr']
                        and backend['m_req_write'] == int(bool(pre['wstrb']))
                        and backend['m_req_be'] == (pre['wstrb'] or 15)
                        and (not pre['wstrb'] or backend['m_req_wdata'] == pre['wdata'])
                        and not (pre['instruction'] and pre['wstrb']), 'backend-native-request')
                sequence += 1
                token = (epoch, sequence)
                service = services.get(token)
                require(service is not None, 'missing-service')
                key = service.get('transaction', service.get('source_transaction'))
                require(set(key) == {'execution_id', 'testcase_id', 'source_component',
                        'source_epoch', 'channel_id', 'source_sequence'}
                        and all(type(key[name]) is str and key[name] for name in
                            ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                        and type(key['source_epoch']) is int and type(key['source_sequence']) is int,
                        'service-real-key-shape')
                require(key['source_component'] == 'cpu' and service['address'] == pre['addr'], 'service-address')
                require(key['source_epoch'] == epoch and key['source_sequence'] == sequence,
                        'service-sequence')
                is_write = service['kind'] == 'memory_write' or service.get('write') is True
                require(is_write == bool(pre['wstrb']), 'service-operation')
                if is_write:
                    require(service.get('value', service.get('write_value')) == pre['wdata']
                            and service['byte_enable'] == pre['wstrb'], 'service-write-data')
                if service['kind'] in ('memory_read', 'memory_write'):
                    require(service['width_bytes'] == 4, 'service-memory-width')
                require(service['event_id'] > pre_event['producer_event_id'], 'service-event-order')
                if service['kind'] != 'mmio_delivery':
                    require(service['producer_event_id'] == pre_event['producer_event_id'],
                            'service-accepted-command-reference')
                else:
                    acceptance = mmio_acceptances.get(token)
                    require(acceptance is not None and acceptance['source_transaction'] == key
                            and acceptance['producer_event_id'] == pre_event['producer_event_id']
                            and acceptance['address'] == pre['addr']
                            and acceptance['write'] == service['write']
                            and acceptance['byte_enable'] == service['byte_enable']
                            and acceptance['write_value'] == service['write_value']
                            and acceptance['device_id'] == service['device_id'],
                            'mmio-accepted-command-reference')
                used_services.add(token)
                row = projection(pre_event, 'native_backend_request_accepted', key, scope)
                require(row['native'] == pre, 'accepted-projection-native')
                pending = dict(key=key, native=pre, service=service,
                               accepted_scope=scope, accepted_raw=pre_event['event_id'])
                counts['accepted'] += 1
            if consumed:
                require(pending is not None and 'response_scope' not in pending and not pre['ready']
                        and backend['m_rsp_error'] == 0 and post['ready'] == 1
                        and post['rdata'] == backend['m_rsp_rdata'], 'backend-response-raw')
                service = pending['service']
                require(service['event_id'] < pre_event['event_id'], 'service-before-response')
                if service['kind'] == 'memory_read':
                    value = int.from_bytes(bytes.fromhex(service['data_hex']), 'little')
                    require(value == service['value'], 'service-read-value')
                elif service['kind'] == 'memory_write' or service.get('write'):
                    value = 0
                else:
                    value = service['read_value']
                actual_target_value = value
                faults = [fault for fault in controlled_response_records
                          if fault['transaction'] == pending['key']]
                require(len(faults) <= 1, 'duplicate-controlled-response')
                if faults:
                    fault = faults[0]
                    require(service['kind'] == 'mmio_delivery' and not service['write']
                            and fault['address'] == service['address'] == 0x4000000c
                            and fault['actual_target_response'] == [value, 0]
                            and fault['delivered_response'] == [value ^ 1, 0], 'controlled-response-shape')
                    value ^= 1
                cpu_command = by_id[pre_event['producer_event_id']]
                require(cpu_command['outputs']['data_rsp_source_sequence'] == pending['key']['source_sequence']
                        and cpu_command['outputs']['data_rsp_source_epoch'] == epoch
                        and cpu_command['outputs']['data_rsp_rdata'] == backend['m_rsp_rdata'], 'pending-response-key')
                require(value == backend['m_rsp_rdata'], 'service-response-value')
                row = projection(pre_event, 'native_backend_response_consumed', pending['key'], scope)
                require(row['value'] == value and row['native_post_is_offer_only'] is True, 'response-projection')
                pending.update(response=value, response_scope=scope, response_raw=pre_event['event_id'])
                pending['actual_service_response'] = actual_target_value
                counts['responses'] += 1
        has_terminal_refusal = terminal_refusal is not None
        require((pending is None and not has_terminal_refusal)
                or (has_terminal_refusal and pending is not None
                    and pending.get('terminal_refusal') == terminal_refusal.get('producer_event_id')
                    and pending.get('terminal_refusal_key') == terminal_refusal.get('transaction')
                    and 'response_scope' in pending), 'terminal-pending-transfer')
        require(used_services == set(services), 'orphan-service')
        require({canonical(row['transaction']) for row in excluded_injected_writes}
                == injected_write_keys
                and len(excluded_injected_writes) == len(expected_injected_writes),
                'terminal-refusal-injected-write-completeness')
        require(set(mmio_acceptances) == {token for token, service in services.items()
                if service['kind'] == 'mmio_delivery'}, 'orphan-mmio-acceptance')
        require(used_projections == {(ref, kind) for ref, kinds in projections.items() for kind in kinds},
                'orphan-projection')
        if has_terminal_refusal:
            require(counts['terminal_refusals'] == 1
                    and counts['accepted'] == counts['responses'] == counts['raw_completed']
                    and counts['raw_completed'] == counts['completed'] + counts['terminal_refusals'],
                    'incomplete-terminal-refusal-counts')
            terminal_raw_ids = [pair['pre']['event_id'] for pair in frames.values()
                if 'pre' in pair]
            require(terminal_raw_ids and max(terminal_raw_ids)
                    == terminal_refusal.get('producer_event_id'),
                    'terminal-refusal-not-last-native-pre')
            metrics['excluded_injected_writes'] = excluded_injected_writes
            metrics['status'] = 'raw_checks_passed_with_terminal_refusal'
        else:
            require(counts['accepted'] == counts['responses'] == counts['completed']
                    and counts['raw_completed'] == counts['completed']
                    and counts['instruction_completed'] > 0 and counts['data_completed'] > 0,
                    'incomplete-transfer-counts')
            metrics['status'] = 'raw_checks_passed'
    except (KeyError, TypeError, ValueError, IndexError) as error:
        errors.append(dict(type=type(error).__name__, message=str(error)))
    metrics['counts'] = dict(counts)
    return metrics


def check_native_source_completion_events(events, plan, raw_checks, *, execution):
    """Join issued completion projections to selected sources and raw transfers.

    ``raw_checks`` must be the result of :func:`check_native_completion` over
    this same event list. That checker reconstructs the full native transfer
    stream independently; this function then proves that the source-completion
    rows name exactly the selected four-byte instructions and their actual
    journal references. A completed noncandidate instruction fetch is retained
    as an explicit no-grant row.
    """
    report = dict(schema_version='native_source_completion_event_checks.v1',
        status='failed', errors=[], completions=[], noncandidate_no_grants=[],
        source_authority=False, retirement=False, feedback_authority=False)

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False)

    try:
        require(type(plan) is dict and plan.get('schema_version') == 22,
                'native-source-completion-plan-required')
        policy = plan.get('native_source_completion')
        require(type(policy) is dict
                and policy.get('schema_version') == 'native_packet_source_completion.v1'
                and policy.get('enabled') is True
                and type(policy.get('max_cases')) is int
                and policy['max_cases'] <= 28,
                'native-source-completion-policy')
        require(type(execution) is str and execution, 'native-source-completion-execution')
        require(type(raw_checks) is dict and raw_checks.get('status') == 'raw_checks_passed'
                and type(raw_checks.get('joins')) is list,
                'native-source-completion-requires-complete-raw-audit')

        by_id = {}
        for event in events:
            eid = event.get('event_id')
            require(type(eid) is int and eid > 0 and eid not in by_id,
                    'native-source-completion-duplicate-event-id')
            by_id[eid] = event

        selected = {}
        fixed_support = {}
        for index, case in enumerate(plan['cases']):
            source = case['source']
            if source.get('kind') == 'instruction' and case.get('source_role') == 'fuzz_source':
                require(source.get('component') == 'cpu'
                        and type(source.get('address')) is int
                        and source['address'] % 4 == 0
                        and len(bytes.fromhex(source.get('data_hex', ''))) == 4,
                        'native-source-completion-selected-source-shape')
                action = source.get('action_id')
                require(type(action) is str and action and action not in selected,
                        'native-source-completion-duplicate-selected-action')
                selected[action] = (index, case)
            for support in case.get('support_instructions', ()):
                fixed_support[(support['address'], support['data_hex'])] = case['case_id']
        require(selected, 'native-source-completion-selected-source-missing')
        selected_addresses = {case['source']['address'] for _, case in selected.values()}
        require(len(selected_addresses) == len(selected),
                'native-source-completion-selected-address-alias')

        bindings = [event for event in events
            if event.get('schema_version') == 'native_instruction_source_binding.v1'
            and event.get('kind') == 'native_instruction_source_bound']
        binding_by_action = {}
        for binding in bindings:
            action = binding.get('source', {}).get('action_id')
            require(action in selected and action not in binding_by_action,
                    'native-source-completion-binding-foreign-or-duplicate')
            index, case = selected[action]
            require(binding.get('component') == 'cpu'
                    and binding.get('execution') == execution
                    and binding.get('reset_epoch') == 0
                    and binding.get('case_index') == index
                    and binding.get('source') == case['source'],
                    'native-source-completion-binding-selected-identity')
            binding_by_action[action] = binding
        require(set(binding_by_action) == set(selected),
                'native-source-completion-selected-binding-count')

        raw_joins = raw_checks['joins']
        join_by_completed_raw = {}
        for join in raw_joins:
            raw_id = join.get('completed_raw_event_id')
            if raw_id is None:
                continue
            require(raw_id not in join_by_completed_raw,
                    'native-source-completion-duplicate-raw-completion')
            join_by_completed_raw[raw_id] = join
        completions = [event for event in events
            if event.get('kind') == 'native_instruction_bus_completion']
        completion_by_raw = {}
        completion_by_action = {}
        for row in completions:
            raw_id = row.get('producer_event_id')
            action = row.get('binding', {}).get('source', {}).get('action_id')
            require(raw_id not in completion_by_raw,
                    'native-source-completion-duplicate-raw-grant')
            require(action in selected and action not in completion_by_action,
                    'native-source-completion-foreign-or-duplicate-action')
            completion_by_raw[raw_id] = row
            completion_by_action[action] = row
        require(set(completion_by_action) == set(selected),
                'native-source-completion-selected-completion-count')

        def referenced(row, field, kind):
            ref_id = row.get(field)
            target = by_id.get(ref_id)
            require(target is not None and ref_id < row['event_id']
                    and target.get('kind') == kind,
                    'native-source-completion-reference:' + field)
            return target

        for action, (case_index, case) in selected.items():
            row = completion_by_action[action]
            source = case['source']
            binding = binding_by_action[action]
            require(row.get('schema_version') == 'native_instruction_bus_completion.v1'
                    and row.get('proof_scope') == 'native_instruction_bus_transfer_completed'
                    and row.get('grants_source_authority') is False
                    and row.get('component') == 'cpu'
                    and row.get('reset_epoch') == 0
                    and row.get('address') == source['address']
                    and row.get('data_hex') == source['data_hex']
                    and row.get('binding') == {name: binding[name] for name in
                        ('component', 'execution', 'reset_epoch', 'case_index',
                         'admission', 'source', 'acceptance')},
                    'native-source-completion-issued-source-identity')
            require(row['binding']['case_index'] == case_index,
                    'native-source-completion-case-index')
            join = join_by_completed_raw.get(row.get('producer_event_id'))
            require(join is not None
                    and join.get('transaction') == row.get('key')
                    and join.get('completed_scope') == row.get('completion_scope')
                    and join.get('accepted_scope') == row.get('accepted_scope')
                    and join.get('response_scope') == row.get('response_scope'),
                    'native-source-completion-raw-transaction-join')
            require(join.get('service_event_id') in by_id,
                    'native-source-completion-read-service-missing')
            read_service = by_id[join['service_event_id']]
            snapshot = row.get('snapshot')
            acceptance = binding['acceptance']
            source_bytes = bytes.fromhex(source['data_hex'])
            snapshot_versions = _version_vector(snapshot.get('versions'), length=4) \
                if type(snapshot) is dict else None
            acceptance_versions = _version_vector(acceptance.get('versions'), length=4)
            snapshot_writers = _string_vector(snapshot.get('writer_event_ids'), length=4) \
                if type(snapshot) is dict else None
            acceptance_writers = _string_vector(acceptance.get('writer_event_ids'), length=4)
            snapshot_kinds = _string_vector(snapshot.get('writer_kinds'), length=4) \
                if type(snapshot) is dict else None
            acceptance_kinds = _string_vector(acceptance.get('writer_kinds'), length=4)
            materialized_offsets = _sequence(snapshot.get('materialized_offsets')) \
                if type(snapshot) is dict else None
            require(type(snapshot) is dict and len(source_bytes) == 4
                    and snapshot.get('data_hex') == source['data_hex']
                    and snapshot.get('memory_id') == acceptance.get('memory_id')
                    and snapshot.get('generation') == acceptance.get('generation')
                    and snapshot.get('byte_offset') == acceptance.get('byte_offset')
                    and snapshot_versions is not None
                    and snapshot_versions == acceptance_versions
                    and snapshot_writers is not None
                    and snapshot_writers == acceptance_writers
                    and snapshot_kinds is not None
                    and snapshot_kinds == acceptance_kinds
                    and materialized_offsets == ()
                    and snapshot.get('transaction_id') == (
                        "TransactionKey(" + ', '.join(f"{name}={row['key'][name]!r}"
                        for name in ('execution_id', 'testcase_id', 'source_component',
                                     'source_epoch', 'channel_id', 'source_sequence')) + ")"),
                    'native-source-completion-snapshot-not-exact-source')
            read_versions = _version_vector(read_service.get('versions'), length=4)
            read_writers = _string_vector(read_service.get('writer_event_ids'), length=4)
            read_kinds = (_string_vector(read_service.get('writer_kinds'), length=4)
                if 'writer_kinds' in read_service else snapshot_kinds)
            require(read_service.get('kind') == 'memory_read'
                    and read_service.get('transaction') == row.get('key')
                    and read_service.get('address') == source['address']
                    and read_service.get('width_bytes') == 4
                    and read_service.get('data_hex') == snapshot['data_hex']
                    and read_service.get('generation') == snapshot['generation']
                    and read_service.get('byte_offset') == snapshot['byte_offset']
                    and read_versions is not None and read_versions == snapshot_versions
                    and read_writers is not None and read_writers == snapshot_writers
                    and read_kinds is not None and read_kinds == snapshot_kinds,
                    'native-source-completion-real-read-snapshot-join')
            require(_json_equivalent(join.get('snapshot'), snapshot)
                    and int.from_bytes(source_bytes, 'little') == join['native']['rdata'],
                    'native-source-completion-completed-byte-join')

            admission_event = referenced(row, 'admission_event_id', 'source_admission')
            host_binding_event = referenced(row, 'host_binding_event_id',
                                             'native_instruction_source_bound')
            service_event = referenced(row, 'service_event_id', 'instruction_source')
            accepted_event = referenced(row, 'native_accepted_event_id',
                                        'native_backend_request_accepted')
            response_event = referenced(row, 'native_response_event_id',
                                        'native_backend_response_consumed')
            completed_event = referenced(row, 'native_completed_event_id', 'native_bus_completed')
            require(admission_event.get('admission') == binding['admission']
                    and host_binding_event.get('source') == source
                    and host_binding_event.get('producer_event_id') == service_event['event_id']
                    and service_event.get('producer_event_id') == admission_event['event_id']
                    and service_event.get('source_event_id') == action
                    and service_event.get('address') == source['address']
                    and service_event.get('data_hex') == source['data_hex'],
                    'native-source-completion-host-input-reference-join')
            require(all(event.get('transaction') == row['key'] for event in
                        (accepted_event, response_event, completed_event))
                    and accepted_event.get('execution') == row['accepted_scope']['execution']
                    and accepted_event.get('local_tick') == row['accepted_scope']['local_tick']
                    and response_event.get('execution') == row['response_scope']['execution']
                    and response_event.get('local_tick') == row['response_scope']['local_tick']
                    and completed_event.get('execution') == row['completion_scope']['execution']
                    and completed_event.get('local_tick') == row['completion_scope']['local_tick']
                    and accepted_event['event_id'] == row.get('native_accepted_event_id')
                    and response_event['event_id'] == row.get('native_response_event_id')
                    and completed_event['event_id'] == row.get('native_completed_event_id')
                    and completed_event.get('producer_event_id') == row.get('producer_event_id')
                    and completed_event.get('native') == join.get('native')
                    and _json_equivalent(completed_event.get('memory_read_snapshot'), snapshot),
                    'native-source-completion-native-projection-reference-join')
            raw_completion = by_id.get(row.get('producer_event_id'))
            raw_native = join['native']
            raw_native_tuple = tuple(raw_native[name] for name in
                ('valid', 'ready', 'addr', 'wstrb', 'rdata', 'instruction'))
            require(raw_completion is not None
                    and raw_completion.get('kind') == 'local_tick_sample'
                    and raw_completion.get('component') == 'cpu'
                    and raw_completion.get('phase') == 'pre'
                    and raw_completion.get('native_driver_scope') == row.get('completion_scope')
                    and row.get('native_pre') == list(raw_native_tuple)
                    and raw_native['addr'] == source['address']
                    and raw_native['valid'] == raw_native['ready'] == raw_native['instruction'] == 1,
                    'native-source-completion-raw-pre-reference')
            report['completions'].append(dict(action_id=action, case_index=case_index,
                address=source['address'], data_hex=source['data_hex'],
                completion_event_id=row['event_id'], completed_raw_event_id=row['producer_event_id'],
                transaction=row['key'], snapshot=snapshot))

        for join in raw_joins:
            native = join.get('native')
            if not isinstance(native, dict) or native.get('instruction') != 1:
                continue
            raw_id = join.get('completed_raw_event_id')
            if native.get('addr') in selected_addresses:
                require(raw_id in completion_by_raw,
                        'native-source-completion-selected-fetch-without-grant')
                continue
            require(raw_id not in completion_by_raw,
                    'native-source-completion-noncandidate-granted')
            support_case = fixed_support.get((native.get('addr'),
                join.get('snapshot', {}).get('data_hex') if join.get('snapshot') else None))
            report['noncandidate_no_grants'].append(dict(
                completed_raw_event_id=raw_id, address=native.get('addr'),
                data_hex=(join.get('snapshot') or {}).get('data_hex'),
                classification=('fixed_support_instruction' if support_case else
                    'startup_or_unselected_instruction'), support_case_id=support_case))
        require(report['noncandidate_no_grants'],
                'native-source-completion-noncandidate-fetch-not-observed')
        report['status'] = 'source_completion_event_checks_passed'
    except (KeyError, TypeError, ValueError, IndexError) as error:
        report['errors'].append(dict(type=type(error).__name__, message=str(error)))
    return report


def check_native_source_completion(events, plan, runtime_document, *, execution):
    """Run the host-binding, complete raw-bus, and source-completion audits."""
    binding = check_host_source_bindings(events, plan, execution=execution)
    raw = check_native_completion(events, runtime_document)
    source = check_native_source_completion_events(events, plan, raw,
                                                   execution=execution)
    errors = []
    if binding['status'] != 'host_input_binding_checks_passed':
        errors.extend(binding['errors'])
    if raw['status'] != 'raw_checks_passed':
        errors.extend(raw['errors'])
    if source['status'] != 'source_completion_event_checks_passed':
        errors.extend(source['errors'])
    return dict(schema_version='native_source_completion_gate_checks.v1',
        status=('native_source_completion_checks_passed' if not errors else 'failed'),
        errors=errors, binding_checks=binding, raw_checks=raw,
        source_completion_checks=source, source_authority=False,
        retirement=False, feedback_authority=False)


def check_native_source_completion_refusal_events(events, plan, raw_checks, *,
                                                  execution, refusal_record):
    """Audit one real selected-source snapshot contradiction and its refusal."""
    report = dict(schema_version='native_source_completion_refusal_event_checks.v1',
        status='failed', errors=[], source_authority=False, retirement=False,
        feedback_authority=False, terminal_failure=None, terminal_refusal=None)

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False)

    key_fields = ('execution_id', 'testcase_id', 'source_component',
                  'source_epoch', 'channel_id', 'source_sequence')

    def valid_key(key):
        return (type(key) is dict and set(key) == set(key_fields)
            and all(type(key[name]) is str and bool(key[name]) for name in
                    ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
            and all(type(key[name]) is int and 0 <= key[name] < 1 << 64 for name in
                    ('source_epoch', 'source_sequence')))

    def transaction_id(key):
        return 'TransactionKey(' + ', '.join(
            f'{name}={key[name]!r}' for name in key_fields) + ')'

    try:
        require(type(plan) is dict and plan.get('schema_version') == 23,
                'native-source-refusal-schema23-required')
        policy = plan.get('native_source_completion')
        require(type(policy) is dict
                and policy.get('schema_version') == 'native_packet_source_completion.v1'
                and policy.get('enabled') is True
                and type(policy.get('max_cases')) is int
                and 1 <= policy['max_cases'] <= 28,
                'native-source-refusal-policy')
        require(type(execution) is str and execution,
                'native-source-refusal-execution')
        cases = plan.get('cases')
        require(type(cases) is list and cases, 'native-source-refusal-cases')
        selected = [(index, case) for index, case in enumerate(cases)
            if case.get('source_role') == 'fuzz_source'
            and case.get('source', {}).get('kind') == 'instruction']
        require(len(selected) == 1, 'native-source-refusal-requires-one-selected-source')
        case_index, case = selected[0]
        source = case['source']
        failure = plan.get('terminal_failure')
        template = plan.get('template')
        session_testcase_id = (template.get('testcase_id')
            if type(template) is dict else None)
        require(type(failure) is dict
                and failure.get('phase') == 'step'
                and failure.get('case_index') == case_index == len(cases) - 1
                and failure.get('case_id') == case['case_id']
                and type(failure.get('command_index')) is int
                and failure['command_index'] >= 0
                and failure.get('error_type') == 'ValueError'
                and failure.get('error_message') == 'native_source_candidate_refused',
                'native-source-refusal-terminal-failure')
        require(type(session_testcase_id) is str and session_testcase_id.strip(),
                'native-source-refusal-session-testcase-id')
        report['terminal_failure'] = failure

        binding_checks = check_host_source_bindings(events, plan, execution=execution)
        require(binding_checks['status'] == 'host_input_binding_checks_passed',
                'native-source-refusal-host-binding')
        binding_rows = binding_checks['bindings']
        require(len(binding_rows) == 1, 'native-source-refusal-selected-binding-count')
        binding = binding_rows[0]
        acceptance = binding['acceptance']
        require(source.get('component') == 'cpu'
                and type(source.get('address')) is int and source['address'] % 4 == 0
                and len(bytes.fromhex(source['data_hex'])) == 4,
                'native-source-refusal-source-shape')

        require(type(refusal_record) is dict
                and refusal_record.get('schema_version') == 'native_source_candidate_refusal.v1'
                and refusal_record.get('selected_action_id') == source['action_id'],
                'native-source-refusal-record-shape')
        native_key = refusal_record.get('native_transaction')
        write_key = refusal_record.get('write_transaction')
        refused_raw_id = refusal_record.get('refused_raw_event_id')
        require(valid_key(native_key) and valid_key(write_key)
                and native_key['source_component'] == write_key['source_component'] == 'cpu'
                and native_key['channel_id'] == 'memory'
                and write_key['channel_id'] == 'native-source-poison'
                and native_key['execution_id'] == write_key['execution_id']
                and native_key['testcase_id'] == write_key['testcase_id'] == session_testcase_id
                and native_key['source_epoch'] == write_key['source_epoch'] == 0
                and write_key['source_sequence'] == 1
                and native_key != write_key,
                'native-source-refusal-full-transaction-key')
        require(type(refused_raw_id) is int and refused_raw_id > 0,
                'native-source-refusal-raw-reference')

        by_id = {}
        for event in events:
            eid = event.get('event_id')
            require(type(eid) is int and eid > 0 and eid not in by_id,
                    'native-source-refusal-duplicate-event-id')
            by_id[eid] = event
        raw_audit = raw_checks if type(raw_checks) is dict else {}
        terminal = raw_audit.get('terminal_refusal')
        require(raw_audit.get('status') == 'raw_checks_passed_with_terminal_refusal'
                and type(terminal) is dict
                and terminal.get('producer_event_id') == refused_raw_id
                and terminal.get('transaction') == native_key,
                'native-source-refusal-requires-complete-terminal-raw-audit')
        require(raw_audit.get('counts', {}).get('accepted')
                == raw_audit.get('counts', {}).get('responses')
                == raw_audit.get('counts', {}).get('raw_completed')
                and raw_audit.get('counts', {}).get('raw_completed')
                == raw_audit.get('counts', {}).get('completed', 0)
                    + raw_audit.get('counts', {}).get('terminal_refusals', 0)
                and raw_audit.get('counts', {}).get('terminal_refusals') == 1,
                'native-source-refusal-raw-prefix-counts')

        expected_write_keys = [write_key]
        require([row['transaction'] for row in raw_audit.get('excluded_injected_writes', ())]
                == expected_write_keys,
                'native-source-refusal-injected-write-raw-audit')
        write_receipt_object = refusal_record.get('write_receipt_object')
        commit_document = refusal_record.get('write_receipt')
        write_service_event = refusal_record.get('write_service_event')
        receipt_version = (write_receipt_object.get('version')
            if type(write_receipt_object) is dict else None)
        commit_version = (commit_document.get('version')
            if type(commit_document) is dict else None)
        def version_tuple(value):
            if (type(value) not in (tuple, list) or len(value) != 2
                    or any(type(part) is not int or not 0 <= part < 1 << 64
                           for part in value)):
                return None
            return tuple(value)
        expected_receipt_fields = {
            'schema_version', 'fullkey', 'memory_kind', 'memory_id', 'generation',
            'byte_offset', 'width_bytes', 'byte_enable', 'version', 'payload_sha256',
            'commit_status', 'performed_effect', 'enabled_byte_cells', 'commit_id'}
        expected_payload = dict(op='write', address=source['address'], value=0x13,
                                width_bytes=4, byte_enable=15)
        expected_payload_sha256 = hashlib.sha256(json.dumps(expected_payload,
            sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode('utf-8')).hexdigest()
        require(type(write_receipt_object) is dict
                and set(write_receipt_object) == {'transaction_id', 'version', 'byte_enable'}
                and write_receipt_object.get('transaction_id') == write_key
                and version_tuple(receipt_version) is not None
                and version_tuple(receipt_version) == version_tuple(commit_version)
                and type(write_receipt_object.get('byte_enable')) is int
                and write_receipt_object['byte_enable'] == 15,
                'native-source-refusal-actual-write-receipt-object')
        require(type(commit_document) is dict
                and set(commit_document) == expected_receipt_fields
                and commit_document.get('schema_version') == 'memory_write_commit_receipt.v1'
                and commit_document.get('fullkey') == write_key
                and commit_document.get('memory_kind') == 'modeled_host_persistent_memory'
                and type(commit_document.get('memory_id')) is str
                and commit_document['memory_id']
                and type(commit_document.get('generation')) is int
                and 0 <= commit_document['generation'] < 1 << 64
                and type(commit_document.get('byte_offset')) is int
                and 0 <= commit_document['byte_offset'] < 1 << 64
                and commit_document.get('commit_status') == 'complete'
                and commit_document.get('performed_effect') is True
                and type(commit_document.get('width_bytes')) is int
                and commit_document['width_bytes'] == 4
                and type(commit_document.get('byte_enable')) is int
                and commit_document['byte_enable'] == 15
                and type(commit_document.get('version')) in (list, tuple)
                and len(commit_document['version']) == 2
                and all(type(part) is int and 0 <= part < 1 << 64
                        for part in commit_document['version'])
                and version_tuple(commit_document['version']) == version_tuple(receipt_version)
                and commit_document['version'][0] == commit_document['generation']
                and commit_document['version'][1] > 0
                and commit_document.get('payload_sha256') == expected_payload_sha256,
                'native-source-refusal-actual-commit-document')
        commit_id = commit_document.get('commit_id')
        commit_material = {name: value for name, value in commit_document.items()
                           if name != 'commit_id'}
        expected_commit_id = hashlib.sha256(json.dumps(commit_material,
            sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        require(type(commit_id) is str and len(commit_id) == 64
                and all(char in '0123456789abcdef' for char in commit_id)
                and commit_id == expected_commit_id,
                'native-source-refusal-actual-commit-id')
        version = list(commit_document['version'])
        writer_id = transaction_id(write_key)
        byte_values = list(bytes.fromhex('13000000'))
        cells = commit_document.get('enabled_byte_cells')
        require(type(cells) is list and len(cells) == 4
                and all(_json_equivalent(cells[index], dict(
                    byte_offset=commit_document['byte_offset'] + index,
                    value=byte_values[index], version=version, writer_kind='STORE',
                    writer_event_id=writer_id)) for index in range(4)),
                'native-source-refusal-actual-commit-byte-cells')
        require(type(write_service_event) is dict
                and write_service_event.get('kind') == 'memory_write'
                and write_service_event.get('transaction') == write_key
                and type(write_service_event.get('address')) is int
                and write_service_event.get('address') == source['address']
                and type(write_service_event.get('width_bytes')) is int
                and write_service_event.get('width_bytes') == 4
                and type(write_service_event.get('value')) is int
                and write_service_event.get('value') == 0x00000013
                and type(write_service_event.get('byte_enable')) is int
                and write_service_event.get('byte_enable') == 15
                and version_tuple(write_service_event.get('version')) == tuple(version)
                and write_service_event.get('memory_id') == commit_document.get('memory_id')
                and write_service_event.get('generation') == commit_document.get('generation')
                and write_service_event.get('byte_offset') == commit_document.get('byte_offset'),
                'native-source-refusal-actual-service-write')
        write_journal_id = refusal_record.get('write_journal_event_id')
        journal_write = by_id.get(write_journal_id)
        write_producer_id = (journal_write.get('producer_event_id')
            if type(journal_write) is dict else None)
        write_producer = by_id.get(write_producer_id)
        require(type(write_journal_id) is int and journal_write is not None
                and canonical(journal_write) == canonical(refusal_record.get('write_journal_event'))
                and journal_write.get('kind') == 'memory_write'
                and journal_write.get('component') == 'cpu'
                and journal_write.get('transaction') == write_key
                and type(journal_write.get('address')) is int
                and journal_write.get('address') == source['address']
                and type(journal_write.get('width_bytes')) is int
                and journal_write.get('width_bytes') == 4
                and type(journal_write.get('value')) is int
                and journal_write.get('value') == 0x00000013
                and type(journal_write.get('byte_enable')) is int
                and journal_write.get('byte_enable') == 15
                and version_tuple(journal_write.get('version')) == tuple(version)
                and journal_write.get('memory_id') == commit_document.get('memory_id')
                and journal_write.get('generation') == commit_document.get('generation')
                and journal_write.get('byte_offset') == commit_document.get('byte_offset')
                and write_service_event.get('memory_id') == journal_write.get('memory_id')
                and write_service_event.get('generation') == journal_write.get('generation')
                and write_service_event.get('byte_offset') == journal_write.get('byte_offset')
                and version_tuple(write_service_event.get('version'))
                    == version_tuple(journal_write.get('version'))
                and type(write_producer_id) is int and write_producer is not None
                and write_producer.get('component') == 'cpu'
                and (write_producer.get('kind') == 'harness_failure'
                     or ('kind' not in write_producer
                         and type(write_producer.get('outputs')) is dict))
                and binding['event_id'] < write_producer_id < write_journal_id,
                'native-source-refusal-journal-write-join')
        require(refusal_record.get('original_acceptance') == acceptance,
                'native-source-refusal-original-acceptance-reference')

        reads = [event for event in events if event.get('kind') == 'memory_read'
            and event.get('component') == 'cpu'
            and event.get('transaction') == native_key]
        require(len(reads) == 1, 'native-source-refusal-real-read-count')
        read = reads[0]
        read_versions = _version_vector(read.get('versions'), length=4)
        read_writers = _string_vector(read.get('writer_event_ids'), length=4)
        read_kinds = _string_vector(read.get('writer_kinds'), length=4)
        acceptance_versions = _version_vector(acceptance.get('versions'), length=4)
        acceptance_writers = _string_vector(acceptance.get('writer_event_ids'), length=4)
        acceptance_kinds = _string_vector(acceptance.get('writer_kinds'), length=4)
        require(read.get('address') == source['address'] and read.get('width_bytes') == 4
                and read.get('data_hex') == '13000000' and read.get('value') == 0x13
                and read.get('memory_id') == commit_document.get('memory_id')
                and read.get('generation') == commit_document.get('generation')
                and read.get('byte_offset') == commit_document.get('byte_offset')
                and read_versions == (tuple(version),) * 4
                and read_writers == (writer_id,) * 4
                and read_kinds == ('STORE',) * 4,
                'native-source-refusal-real-read-is-poison-write-snapshot')
        require(acceptance.get('data_hex') == source['data_hex']
                and acceptance.get('data_hex') != read['data_hex']
                and acceptance_versions is not None
                and acceptance_versions != read_versions
                and acceptance_writers is not None
                and acceptance_writers != read_writers
                and acceptance_kinds is not None
                and acceptance_kinds != read_kinds,
                'native-source-refusal-binding-snapshot-contradiction')

        raw_pre = by_id.get(refused_raw_id)
        raw_scope = raw_pre.get('native_driver_scope') if raw_pre else None
        require(raw_pre is not None and raw_pre.get('kind') == 'local_tick_sample'
                and raw_pre.get('component') == 'cpu' and raw_pre.get('phase') == 'pre'
                and raw_scope == terminal.get('refused_scope')
                and raw_scope.get('execution') == execution
                and raw_scope.get('reset_epoch') == 0,
                'native-source-refusal-raw-pre-scope')
        # The raw audit already binds artifact roles and widths. Re-read the
        # terminal PRE tuple here to tie this candidate to that independent join.
        raw_values = raw_audit.get('terminal_refusal', {}).get('native')
        require(type(raw_values) is dict
                and raw_values.get('valid') == raw_values.get('ready') == 1
                and raw_values.get('instruction') == 1
                and raw_values.get('addr') == source['address']
                and raw_values.get('rdata') == 0x13,
                'native-source-refusal-candidate-pre-values')
        raw_pair = [event for event in events
            if event.get('kind') == 'local_tick_sample'
            and event.get('component') == 'cpu'
            and event.get('native_driver_scope') == raw_scope]
        require({event.get('phase') for event in raw_pair} == {'pre', 'post'}
                and len(raw_pair) == 2
                and all(event.get('producer_event_id') == raw_pre.get('producer_event_id')
                    for event in raw_pair),
                'native-source-refusal-raw-pair')

        accepted_raw = by_id.get(terminal.get('accepted_raw_event_id'))
        response_raw = by_id.get(terminal.get('response_raw_event_id'))
        accepted_command_id = (accepted_raw.get('producer_event_id')
            if type(accepted_raw) is dict else None)
        accepted_command = by_id.get(accepted_command_id)
        require(accepted_raw is not None and response_raw is not None
                and accepted_raw.get('kind') == response_raw.get('kind') == 'local_tick_sample'
                and accepted_raw.get('phase') == response_raw.get('phase') == 'pre'
                and accepted_raw.get('native_driver_scope') == terminal.get('accepted_scope')
                and response_raw.get('native_driver_scope') == terminal.get('response_scope')
                and type(accepted_command_id) is int and accepted_command is not None
                and accepted_command.get('component') == 'cpu'
                and accepted_command.get('kind') is None
                and read.get('producer_event_id') == accepted_command_id
                and accepted_command_id < read['event_id'] < accepted_raw['event_id']
                < response_raw['event_id']
                < raw_pre['event_id'],
                'native-source-refusal-raw-service-order')
        accepted_projection = [event for event in events
            if event.get('kind') == 'native_backend_request_accepted'
            and event.get('transaction') == native_key]
        response_projection = [event for event in events
            if event.get('kind') == 'native_backend_response_consumed'
            and event.get('transaction') == native_key]
        require(len(accepted_projection) == len(response_projection) == 1
                and accepted_projection[0].get('producer_event_id') == accepted_raw['event_id']
                and response_projection[0].get('producer_event_id') == response_raw['event_id']
                and response_projection[0].get('value') == 0x13
                and response_projection[0].get('execution') == raw_scope['execution'],
                'native-source-refusal-native-transaction-join')
        failure_events = [event for event in events
            if event.get('kind') == 'harness_failure' and event.get('component') == 'cpu'
            and event.get('error_type') == 'ValueError']
        require(len(failure_events) == 1
                and failure_events[0]['event_id'] < raw_pre['event_id']
                and raw_pre.get('producer_event_id') == failure_events[0]['event_id'],
                'native-source-refusal-real-runner-failure')
        # This run has exactly one selected source and that source refused. Any
        # completion projection anywhere in the trace is therefore a forged or
        # stale grant, even if it names a bootstrap or foreign action.
        completion_rows = [event for event in events
            if event.get('kind') == 'native_instruction_bus_completion']
        completed_projections = [event for event in events
            if event.get('kind') == 'native_bus_completed'
            and event.get('producer_event_id') == refused_raw_id]
        require(not completion_rows and not completed_projections,
                'native-source-refusal-no-completion-grant')
        require(write_journal_id < read['event_id'] < raw_pre['event_id'],
                'native-source-refusal-write-read-pre-order')

        report['terminal_refusal'] = dict(
            selected_action_id=source['action_id'], address=source['address'],
            bound_data_hex=acceptance['data_hex'], actual_read_data_hex=read['data_hex'],
            refused_raw_event_id=refused_raw_id, native_transaction=native_key,
            write_transaction=write_key, write_event_id=write_journal_id,
            write_version=version, read_event_id=read['event_id'],
            accepted_raw_event_id=accepted_raw['event_id'],
            response_raw_event_id=response_raw['event_id'],
            no_completion=True)
        report['status'] = 'native_source_refusal_checks_passed'
    except (KeyError, TypeError, ValueError, IndexError) as error:
        report['errors'].append(dict(type=type(error).__name__, message=str(error)))
    return report


def check_native_source_completion_refusal(events, plan, runtime_document, *,
                                           execution, refusal_record):
    """Run complete raw-prefix and actual-write checks for the expected refusal."""
    binding = check_host_source_bindings(events, plan, execution=execution)
    terminal_raw = refusal_record.get('refused_raw_event_id') if type(refusal_record) is dict else None
    raw_row = next((event for event in events if event.get('event_id') == terminal_raw), None)
    refusal_scope = raw_row.get('native_driver_scope') if raw_row else None
    native_key = refusal_record.get('native_transaction') if type(refusal_record) is dict else None
    accepted = next((event for event in events
        if event.get('kind') == 'native_backend_request_accepted'
        and event.get('transaction') == native_key), None)
    response = next((event for event in events
        if event.get('kind') == 'native_backend_response_consumed'
        and event.get('transaction') == native_key), None)
    raw = check_native_completion(events, runtime_document, terminal_refusal=dict(
        producer_event_id=terminal_raw, transaction=native_key,
        accepted_scope=({name: accepted.get(name) for name in
            ('execution', 'command_sequence', 'reset_epoch', 'local_tick')} if accepted else None),
        response_scope=({name: response.get(name) for name in
            ('execution', 'command_sequence', 'reset_epoch', 'local_tick')} if response else None),
        refused_scope=refusal_scope,
        write_transactions=[refusal_record.get('write_transaction')]
            if type(refusal_record) is dict else []))
    event_checks = check_native_source_completion_refusal_events(events, plan, raw,
        execution=execution, refusal_record=refusal_record)
    errors = []
    for check in (binding, raw, event_checks):
        if check.get('status') not in (
                'host_input_binding_checks_passed',
                'raw_checks_passed_with_terminal_refusal',
                'native_source_refusal_checks_passed'):
            errors.extend(check.get('errors', ()))
    return dict(schema_version='native_source_completion_refusal_gate_checks.v1',
        status=('native_source_refusal_checks_passed' if not errors else 'failed'),
        errors=errors, binding_checks=binding, raw_checks=raw,
        refusal_checks=event_checks,
        terminal_failure=event_checks.get('terminal_failure'),
        terminal_refusal=event_checks.get('terminal_refusal'),
        source_authority=False,
        retirement=False, feedback_authority=False)
