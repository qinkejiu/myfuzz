"""Independent saved-raw directed-gate checks; no live observer or authority."""
from collections import Counter
import json


def check_native_completion(events, runtime_document, *, controlled_response_records=()):
    """Reconstruct every native transfer from raw samples, then check projections.

    Return failures with partial joins so the caller can save evidence before
    rejecting the gate. Artifact admission remains the actual session's job.
    """
    metrics = dict(schema_version='native_completion_gate_raw_checks.v1',
                   status='failed', errors=[], joins=[], counts={},
                   source_authority=False, retirement=False, feedback_authority=False)
    errors, joins = metrics['errors'], metrics['joins']
    counts = Counter()

    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))

    try:
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
                require(type(key) is dict and key['channel_id'] == 'memory', 'service-memory-key')
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
                require(pending is not None and 'response_scope' in pending
                        and scope['local_tick'] == pending['response_scope']['local_tick'] + 1
                        and stable(pre, pending['native']) and pre['rdata'] == pending['response'],
                        'native-completion-without-raw-response')
                row = projection(pre_event, 'native_bus_completed', pending['key'], scope)
                require(row['native'] == pre and row['accepted_scope'] == pending['accepted_scope']
                        and row['response_scope'] == pending['response_scope']
                        and row['transfer_type'] == ('instruction_bus_transfer' if pre['instruction'] else 'data_bus_transfer'),
                        'completion-projection-fields')
                service = pending['service']
                snapshot = row.get('memory_read_snapshot')
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
        require(pending is None, 'terminal-pending-transfer')
        require(used_services == set(services), 'orphan-service')
        require(set(mmio_acceptances) == {token for token, service in services.items()
                if service['kind'] == 'mmio_delivery'}, 'orphan-mmio-acceptance')
        require(used_projections == {(ref, kind) for ref, kinds in projections.items() for kind in kinds},
                'orphan-projection')
        require(counts['accepted'] == counts['responses'] == counts['completed']
                and counts['instruction_completed'] > 0 and counts['data_completed'] > 0,
                'incomplete-transfer-counts')
        metrics['status'] = 'raw_checks_passed'
    except (KeyError, TypeError, ValueError, IndexError) as error:
        errors.append(dict(type=type(error).__name__, message=str(error)))
    metrics['counts'] = dict(counts)
    return metrics
