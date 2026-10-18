#!/usr/bin/env python3
"""Offline saved-evidence audit; never imports project/checker or starts children.

Input is a downloaded operation directory containing control/, gate-control/,
run-directed/ and gate-parent.stdout/stderr. Missing/failed evidence refuses.
This script does not download evidence. Run only after terminal collection.
"""
import argparse
import datetime
from collections import Counter
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import re

FREEZE = 'd5ce57a590fc3f1668f9e1606c187818fffc66a78c7367f268e54884267c3024'
DIRS = '861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36'
COPY = '4263255b32575423fd682a8a2abfe04e687c153e9614a21a3de90bb2c54834ba'
BASELINE = '3c287137bfa7e98c6b28444b20b26fa2e6ab25d6a01c2262594408fa380e44be'
ENV = '9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c'
INVENTORY = '9672f2b6ab65a587c8533e574851cf8990ead9867e0d089d0c3f030af1470d10'
TOOLS = '6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b'
REMOTE_BASE = '/root/fanzehui/myfuzz/operations/p6-native-source-binding-20261018-attempt1'
REMOTE_INPUTS = '/root/fanzehui/myfuzz/operations/p6-native-source-binding-inputs-20261018-attempt2'
SCOPE = {'execution', 'command_sequence', 'reset_epoch', 'local_tick'}
KINDS = {'native_backend_request_accepted', 'native_backend_response_consumed', 'native_bus_completed'}


def check(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bundle(folder, row):
    path = folder / row['path']
    check(path.name == row['path'], 'bundle-relative-name')
    data = path.read_bytes()
    check(digest(data) == row['gzip_sha256'], 'bundle-gzip-pin')
    raw = gzip.decompress(data)
    check(digest(raw) == row['json_sha256'], 'bundle-json-pin')
    return json.loads(raw)


def semantic(trace):
    return digest(encoded({k: trace[k] for k in ('status', 'events', 'local_ticks')}))


def comparison_copy(events, owner):
    """Use process receipt nonce; rewrite only explicitly declared execution fields."""
    check(owner['component'] == 'cpu' and owner['reset_epoch'] == 0, 'process-owner')
    nonce = owner['execution_nonce']
    check(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'owned-nonce')
    result = []
    for original in events:
        row = deepcopy(original)
        if 'native_driver_scope' in row:
            check(row.get('component') == 'cpu' and row.get('kind') == 'local_tick_sample'
                  and row.get('phase') in ('pre', 'post'), 'scope-on-unsupported-event')
            locations = [row['native_driver_scope']]
        elif row.get('schema_version') == 'native_bus_observation.v1':
            check(row.get('kind') in KINDS and row.get('component') == 'cpu'
                  and row.get('phase') == 'pre', 'unsupported-native-projection')
            locations = [row] + [row[n] for n in ('accepted_scope', 'response_scope') if n in row]
        elif row.get('schema_version') == 'native_instruction_source_binding.v1':
            check(row.get('kind') == 'native_instruction_source_bound' and row.get('component') == 'cpu'
                  and row.get('reset_epoch') == 0 and row.get('execution') == nonce, 'owned-host-binding-scope')
            row['execution'] = '<independent-owned-cpu-epoch0>'
            locations = []
        else:
            locations = []
        for scope in locations:
            check((scope is row or set(scope) == SCOPE) and scope['execution'] == nonce
                  and type(scope['reset_epoch']) is int and scope['reset_epoch'] == 0
                  and type(scope['command_sequence']) is int and scope['command_sequence'] > 0
                  and type(scope['local_tick']) is int and scope['local_tick'] > 0, 'unowned-native-scope')
            scope['execution'] = '<independent-owned-cpu-epoch0>'
        result.append(row)
    return result


def raw_audit(events, metrics, owner, faults):
    """Rebuild accepted/service/response/T+1 joins directly from raw PRE/POST."""
    doc = metrics['artifact_document']
    check(doc['artifact_digest'] == owner['artifact_digest'], 'artifact-process-binding')
    contract = doc['native_completion_observation']
    check(contract['schema_version'] == 'native_completion_observation.v1'
          and contract['completion']['phase'] == 'pre', 'native-contract')
    traces = doc['base_protocol_traces']['traces']
    check(len(traces) == 1, 'one-native-trace')
    trace = traces[0]
    widths = dict(valid=1, ready=1, addr=32, wdata=32, wstrb=4, rdata=32)
    check(trace['signal_widths'] == widths and set(trace['signals']) == set(widths)
          and trace['protocol'] == 'ready-valid-memory' and trace['boundary'] == 'cpu_physical_abi'
          and trace['endpoint_id'] == contract['endpoint_id']
          and trace['clock_domain'] == contract['clock_domain'], 'trace-roles')
    ids = {e['event_id']: e for e in events}
    check(len(ids) == len(events) and list(ids) == sorted(ids)
          and all(type(i) is int and i > 0 for i in ids), 'whole-event-order')
    frames, projections, services, accepted_mmio = {}, {}, {}, {}
    for e in events:
        if e.get('component') == 'cpu' and e.get('kind') == 'local_tick_sample':
            scope = e['native_driver_scope']
            check(set(scope) == SCOPE and scope['execution'] == owner['execution_nonce']
                  and scope['reset_epoch'] == owner['reset_epoch']
                  and e['local_tick'] == scope['local_tick'], 'raw-process-scope')
            key = scope['command_sequence']
            pair = frames.setdefault(key, {})
            check(e['phase'] not in pair, 'duplicate-raw-phase')
            pair[e['phase']] = e
        if e.get('kind') in KINDS:
            key = (e['producer_event_id'], e['kind'])
            check(key not in projections, 'duplicate-native-projection')
            projections[key] = e
        if e.get('component') == 'cpu' and e.get('kind') in ('memory_read', 'memory_write', 'mmio_delivery'):
            key = e.get('transaction', e.get('source_transaction'))
            token = (key['source_epoch'], key['source_sequence'])
            check(token not in services and key['channel_id'] == 'memory', 'duplicate-service')
            services[token] = e
        if e.get('component') == 'cpu' and e.get('kind') == 'mmio_acceptance':
            key = e['source_transaction']; token = (key['source_epoch'], key['source_sequence'])
            check(token not in accepted_mmio, 'duplicate-mmio')
            accepted_mmio[token] = e
    check(frames, 'missing-raw')
    def native(e):
        out = e['outputs']; n = {r: out['protocol_taps'][name] for r, name in trace['signals'].items()}
        for role, width in widths.items():
            check(type(n[role]) is int and 0 <= n[role] < 1 << width, 'signal-width')
        n['instruction'] = out['physical'][contract['instruction_marker']['signal']]
        check(type(n['instruction']) is int and n['instruction'] in (0, 1), 'instruction-marker')
        return n
    def stable(a, b):
        return a['valid'] == 1 and all(a[r] == b[r] for r in ('addr', 'wstrb', 'instruction')) and (not b['wstrb'] or a['wdata'] == b['wdata'])
    used, joins, counts, sequence = set(), [], Counter(), 0
    previous, previous_command, previous_post, pending, offered = None, None, None, None, None
    faults_used = set()
    # Dict insertion order is the saved journal order: never sort commands and
    # accidentally repair an exchanged frame in damaged evidence.
    for command, pair in frames.items():
        check(set(pair) == {'pre', 'post'}, 'incomplete-raw-frame')
        pre, post = pair['pre'], pair['post']; scope = pre['native_driver_scope']
        check(list(pair) == ['pre', 'post'] and pre['event_id'] < post['event_id']
              and (previous_post is None or previous_post < pre['event_id'])
              and post['native_driver_scope'] == scope and pre['producer_event_id'] == post['producer_event_id'], 'raw-pair')
        check(type(command) is int and command > 0 and type(scope['local_tick']) is int
              and (previous is None or scope['local_tick'] == previous + 1)
              and (previous_command is None or command > previous_command), 'raw-command-order-tick-gap')
        previous, previous_command = scope['local_tick'], command
        previous_post = post['event_id']
        n, after = native(pre), native(post); b = pre['outputs']['backend']
        for phase_event in (pre, post):
            backend = phase_event['outputs']['backend']
            for role, width in dict(m_req_valid=1, m_req_ready=1, m_req_addr=32,
                    m_req_write=1, m_req_wdata=32, m_req_be=4, m_rsp_valid=1,
                    m_rsp_ready=1, m_rsp_rdata=32, m_rsp_error=1).items():
                check(type(backend[role]) is int and 0 <= backend[role] < 1 << width,
                      'backend-field-width-' + role)
        counts.update(raw_pre=1, raw_post=1)
        if offered is None and n['valid']: offered = n
        check(offered is None or stable(n, offered), 'offered-tuple')
        flags = dict(native_bus_completed=n['valid'] == n['ready'] == 1,
                     native_backend_request_accepted=b['m_req_valid'] == b['m_req_ready'] == 1,
                     native_backend_response_consumed=b['m_rsp_valid'] == b['m_rsp_ready'] == 1)
        def project(kind, key):
            tag = (pre['event_id'], kind); check(tag in projections, 'missing-projection')
            e = projections[tag]; used.add(tag)
            check(e['schema_version'] == 'native_bus_observation.v1' and e['component'] == 'cpu'
                  and e['phase'] == 'pre' and e['proof_scope'] == 'native_bus_transfer_only'
                  and e['grants_source_authority'] is False and e['retirement'] is False
                  and e['artifact_digest'] == doc['artifact_digest']
                  and e['endpoint_id'] == contract['endpoint_id'] and e['clock_domain'] == contract['clock_domain']
                  and e['transaction'] == key and all(e[k] == v for k, v in scope.items()), 'projection-binding')
            return e
        if flags['native_bus_completed']:
            check(pending is not None and 'response' in pending
                  and scope['local_tick'] == pending['response_scope']['local_tick'] + 1
                  and stable(n, pending['native']) and n['rdata'] == pending['response'], 'actual-T-plus-1-completion')
            e = project('native_bus_completed', pending['key'])
            check(e['native'] == n and e['accepted_scope'] == pending['accepted_scope']
                  and e['response_scope'] == pending['response_scope']
                  and e['transfer_type'] == ('instruction_bus_transfer' if n['instruction'] else 'data_bus_transfer'), 'completion-projection')
            service = pending['service']; snap = e.get('memory_read_snapshot')
            if service['kind'] == 'memory_read':
                check(type(snap) is dict, 'read-snapshot')
                for name in ('memory_id', 'generation', 'byte_offset', 'data_hex', 'versions', 'writer_event_ids'):
                    check(encoded(snap[name]) == encoded(service[name]), 'snapshot-service-' + name)
                check(len(bytes.fromhex(snap['data_hex'])) == 4 and int.from_bytes(bytes.fromhex(snap['data_hex']), 'little') == n['rdata'], 'snapshot-byte-value')
                check(all(type(snap[name]) is list and len(snap[name]) == 4
                          for name in ('versions', 'writer_event_ids', 'writer_kinds'))
                      and type(snap['generation']) is int and snap['generation'] >= 0
                      and all(type(v) is list and len(v) == 2
                              and all(type(part) is int and part >= 0 for part in v)
                              and v[0] == snap['generation'] for v in snap['versions'])
                      and all(v is None or type(v) is str and v for v in snap['writer_event_ids'])
                      and all(type(v) is str and v for v in snap['writer_kinds']), 'snapshot-four-lanes')
                expected_transaction = 'TransactionKey(' + ', '.join(
                    f'{k}={pending["key"][k]!r}' for k in ('execution_id', 'testcase_id',
                    'source_component', 'source_epoch', 'channel_id', 'source_sequence')) + ')'
                check(snap['transaction_id'] == expected_transaction, 'snapshot-exact-transaction')
                if 'writer_kinds' in service: check(snap['writer_kinds'] == service['writer_kinds'], 'recorded-writer-kinds')
            else: check(snap is None, 'unexpected-snapshot')
            join = dict(transaction=pending['key'], accepted_raw_event_id=pending['accepted_raw'],
                        response_raw_event_id=pending['response_raw'], completed_raw_event_id=pre['event_id'],
                        service_event_id=service['event_id'], accepted_scope=pending['accepted_scope'],
                        response_scope=pending['response_scope'], completed_scope=scope, native=n,
                        response_value=pending['response'], snapshot=snap,
                        actual_service_response=pending['actual'], accepted_native=pending['native'], service_kind=service['kind'])
            joins.append(join); counts['completed'] += 1
            counts['instruction_completed' if n['instruction'] else 'data_completed'] += 1
            pending = None; offered = after if after['valid'] else None
        else:
            check(not n['ready'] and (offered is None or stable(after, offered)), 'premature-ready-or-offer-change')
            if pending is not None:
                check(stable(n, pending['native']) and scope['local_tick'] - pending['accepted_scope']['local_tick'] <= 2 * trace['max_wait_cycles'] + 4, 'pending-stability-bound')
            if offered is None and after['valid']: offered = after
        if flags['native_backend_request_accepted']:
            check(pending is None and not flags['native_backend_response_consumed'] and not flags['native_bus_completed']
                  and n['valid'] and stable(after, n) and b['m_req_addr'] == n['addr']
                  and b['m_req_write'] == int(bool(n['wstrb'])) and b['m_req_be'] == (n['wstrb'] or 15)
                  and (not n['wstrb'] or b['m_req_wdata'] == n['wdata']) and not (n['instruction'] and n['wstrb']), 'accepted-native-backend')
            sequence += 1; service = services[(scope['reset_epoch'], sequence)]
            key = service.get('transaction', service.get('source_transaction'))
            check(key['source_component'] == 'cpu' and service['address'] == n['addr']
                  and (service['kind'] == 'memory_write' or service.get('write') is True) == bool(n['wstrb']), 'service-operation')
            if n['wstrb']: check(service.get('value', service.get('write_value')) == n['wdata'] and service['byte_enable'] == n['wstrb'], 'service-write')
            if service['kind'] == 'mmio_delivery':
                acceptance = accepted_mmio[(scope['reset_epoch'], sequence)]
                check(acceptance['producer_event_id'] == pre['producer_event_id'] and acceptance['source_transaction'] == key, 'mmio-producer')
            else: check(service['producer_event_id'] == pre['producer_event_id'] and service['width_bytes'] == 4, 'memory-producer')
            check(service['event_id'] > pre['producer_event_id'], 'service-order')
            check(project('native_backend_request_accepted', key)['native'] == n, 'accepted-projection')
            pending = dict(key=key, native=n, service=service, accepted_scope=scope, accepted_raw=pre['event_id'])
            counts['accepted'] += 1
        if flags['native_backend_response_consumed']:
            check(pending is not None and 'response' not in pending and not n['ready']
                  and b['m_rsp_error'] == 0 and after['ready'] == 1 and after['rdata'] == b['m_rsp_rdata'], 'raw-response')
            service = pending['service']; check(service['event_id'] < pre['event_id'], 'service-response-order')
            actual = (int.from_bytes(bytes.fromhex(service['data_hex']), 'little') if service['kind'] == 'memory_read'
                      else 0 if service['kind'] == 'memory_write' or service.get('write') else service['read_value'])
            delivered = actual
            for i, fault in enumerate(faults):
                if fault['transaction'] == pending['key']:
                    check(i not in faults_used and service['kind'] == 'mmio_delivery' and not service['write']
                          and service['address'] == fault['address'] == 0x4000000c
                          and fault['actual_target_response'] == [actual, 0]
                          and fault['delivered_response'] == [actual ^ 1, 0], 'controlled-actual-delivered')
                    delivered ^= 1; faults_used.add(i)
            command_event = ids[pre['producer_event_id']]['outputs']
            check(command_event['data_rsp_source_sequence'] == pending['key']['source_sequence']
                  and command_event['data_rsp_source_epoch'] == scope['reset_epoch']
                  and command_event['data_rsp_rdata'] == b['m_rsp_rdata'] == delivered, 'response-command-key-value')
            e = project('native_backend_response_consumed', pending['key'])
            check(e['value'] == delivered and e['native_post_is_offer_only'] is True, 'response-projection')
            pending.update(response=delivered, actual=actual, response_scope=scope, response_raw=pre['event_id'])
            counts['responses'] += 1
    check(pending is None and len(services) == sequence and used == set(projections)
          and faults_used == set(range(len(faults))), 'orphan-transaction-projection-fault')
    check(set(accepted_mmio) == {token for token, service in services.items()
                              if service['kind'] == 'mmio_delivery'}, 'orphan-mmio-acceptance')
    check(counts['accepted'] == counts['responses'] == counts['completed']
          and counts['instruction_completed'] > 0 and counts['data_completed'] > 0, 'transfer-conservation')
    check(metrics['status'] == 'raw_checks_passed' and not metrics['errors'] and metrics['counts'] == dict(counts)
          and all(metrics[k] is False for k in ('source_authority', 'retirement', 'feedback_authority')), 'saved-metrics')
    check(len(metrics['joins']) == len(joins), 'saved-join-count')
    for rebuilt, saved in zip(joins, metrics['joins']):
        for key, value in rebuilt.items(): check(encoded(saved[key]) == encoded(value), 'saved-join-' + key)
        service = ids[rebuilt['service_event_id']]
        independently_recorded = service['kind'] == 'memory_read' and 'writer_kinds' in service
        boundary = ('service_writer_kinds_not_recorded_no_independent_lane_kind_join'
                    if service['kind'] == 'memory_read' and not independently_recorded
                    else 'transfer_observation_only_no_source_authority')
        store = ({name: service[name] for name in ('address', 'width_bytes', 'value',
                  'byte_enable', 'memory_id', 'generation', 'byte_offset', 'version')}
                 if service['kind'] == 'memory_write' else None)
        check(saved['source_authority'] is False
              and saved['writer_kinds_independently_recorded'] is independently_recorded
              and saved['writer_kind_boundary'] == boundary and saved['actual_ram_store'] == store,
              'saved-join-boundary-store')
    return dict(counts=dict(counts), joins=len(joins), events=len(events), controlled_responses=len(faults))


PACKET_CONFIGURATION = dict(schema_version='native_packet_source_binding.v1',enabled=True,max_cases=3,
 packet_policy='native_online_packet.v1',instruction_start=512,instruction_end=3584,stride_bytes=32,
 source_binding_schema='native_instruction_source_binding.v1',native_completion_observation_required=True,
 proof_scope='host_instruction_input_bound',grants_source_consumption=False,grants_retirement=False)

def host_audit(events, plan, owner, saved):
    """Rebuild host input records from saved raw journals; never mint live authority."""
    ids={e['event_id']:e for e in events}
    check(len(ids)==len(events), 'host-whole-event-ids')
    expected={c['source']['action_id']:(i,c) for i,c in enumerate(plan['cases'])
              if c['source_role']=='fuzz_source' and c['source']['kind']=='instruction'}
    rows=[e for e in events if e.get('schema_version')=='native_instruction_source_binding.v1']
    seen=set()
    journals=[e for e in events if e.get('component')=='cpu' and e.get('kind') in
              ('instruction_source','memory_initialization','memory_read','memory_write','memory_write_commit')]
    for row in rows:
        source=row['source'];action=source['action_id']
        check(action in expected and action not in seen,'unique-selected-host-action');seen.add(action)
        index,case=expected[action];ad=row['admission'];ac=row['acceptance']
        check(row['kind']=='native_instruction_source_bound' and row['component']=='cpu'
              and row['execution']==owner['execution_nonce'] and type(row['reset_epoch'])is int
              and row['reset_epoch']==0 and type(row['case_index'])is int and row['case_index']==index
              and source==case['source'] and row['proof_scope']=='host_instruction_input_bound'
              and all(row[k] is False for k in ('grants_source_authority','native_bus_completion_observed','retirement','grants_feedback')),'host-only-owned-facts')
        material={k:v for k,v in ad.items() if k!='admission_id'}
        check(ad['schema_version']=='source_admission.v1' and ad['admission_id']==digest(encoded(material))
              and ad['input_sha256']==digest(encoded(source)) and ad['action_id']==action
              and ad['case_id']==case['case_id'] and ad['case_index']==index
              and ad['path_id']==case['path_id'] and ad['direction']==case['direction']
              and ad['role']=='fuzz_source' and ad['input_kind']=='instruction'
              and ad['component']=='cpu' and ad['source_id']=='cpu.instructions','canonical-selected-admission')
        data=bytes.fromhex(source['data_hex'])
        check(len(data)==4 and ac['data_hex']==source['data_hex'] and ac['address']==source['address']
              and ac['source_event_id']==action and ac['writer_event_ids']==[action]*4
              and ac['writer_kinds']==['INSTRUCTION_SOURCE']*4 and type(ac['memory_id'])is str and ac['memory_id']
              and all(type(ac[k])is int and ac[k]>=0 for k in ('generation','byte_offset','address'))
              and len(ac['versions'])==4 and all(type(v)is list and len(v)==2 and v[0]==ac['generation']
                 and all(type(x)is int and x>=0 for x in v) for v in ac['versions']),'actual-four-byte-host-acceptance')
        registration=ids[row['admission_event_id']];service=ids[row['producer_event_id']]
        check(registration['kind']=='source_admission' and registration['admission']==ad
              and service['kind']=='instruction_source' and service['component']=='cpu'
              and service['producer_event_id']==registration['event_id'] and service['source_event_id']==action
              and service['address']==source['address'] and service['data_hex']==source['data_hex']
              and service['generation']==ac['generation'] and registration['event_id']<service['event_id']<row['event_id'], 'actual-ordered-host-producer-references')
        check(type(row['service_event_index'])is int and row['service_event_index']>=0
              and journals[row['service_event_index']] is service,'actual-service-journal-position')
        following_reads=[e for e in journals if e['kind']=='memory_read' and e['event_id']>row['event_id'] and e['address']==ac['address']]
        check(following_reads, 'selected-input-has-actual-read-journal')
        first_read=following_reads[0]
        check(all(first_read[k]==ac[k] for k in ('memory_id','generation','byte_offset','data_hex','versions','writer_event_ids')), 'acceptance-lanes-versus-independent-read-snapshot')
        completions=[e for e in events if e.get('kind')=='native_bus_completed'
                     and e.get('schema_version')=='native_bus_observation.v1'
                     and e.get('memory_read_snapshot') is not None
                     and e['memory_read_snapshot']['writer_event_ids']==[action]*4]
        check(completions,'actual-native-snapshot-for-selected-host-write')
        matching=[e for e in completions if e['transaction']==first_read['transaction']]
        check(len(matching)==1,'exact-read-transaction-native-completion')
        snapshot=matching[0]['memory_read_snapshot']
        check(all(snapshot[k]==ac[k] for k in ('memory_id','generation','byte_offset','data_hex','versions','writer_event_ids','writer_kinds')), 'actual-completion-snapshot-four-lanes')
        # raw_audit separately proves this projection against raw PRE and service;
        # service omits writer kinds, so kinds are recorded by snapshot only.
    check(seen==set(expected),'all-and-only-selected-host-bindings')
    check(saved==dict(schema_version='native_host_binding_gate_checks.v1',status='host_input_binding_checks_passed',
          errors=[],bindings=rows,source_authority=False,retirement=False,feedback_authority=False),'independent-host-check-cross-comparison')
    return rows

def audit_run(folder, corrupt):
    result = load(folder / 'result.json.gz')
    check(result['status'] == 'bounded_directed_gate_passed' and result['controlled_fault'] is corrupt
          and result['native_completion_observation'] is True and not result['capture_errors'], 'run-terminal')
    expected = ['cpu.instructions'] if corrupt else ['cpu.instructions', 'gpio0.pin_byte', 'cpu.instructions']
    check(result['source_selection'] == expected and len(result['cases']) == len(expected), 'directed-inputs')
    processes = result['processes']; check(len(processes) == 4, 'four-processes')
    check(all(p['terminal_returncode'] == 0 and p['reset_epoch'] == 0 for p in processes), 'actual-process-rc')
    check(len({p['pid'] for p in processes}) == len({p['execution_nonce'] for p in processes}) == 4, 'distinct-processes')
    for component in ('cpu', 'gpio0'):
        pair = [p for p in processes if p['component'] == component]
        check(len(pair) == 2 and {p['runner_namespace'] for p in pair} == {'runner-0', 'runner-1'}
              and pair[0]['artifact_digest'] == pair[1]['artifact_digest'], 'fresh-artifact-process-pair')
    first = bundle(folder, result['first_bundle']); comparison = bundle(folder, result['fresh_bundle']); fresh = comparison['actual_trace']
    check(result['native_source_binding'] is True, 'binding-enabled')
    hostchecks = bundle(folder, result['native_source_binding_checks'])
    checks = bundle(folder, result['native_observation_checks'])
    check(checks['original']['artifact_document'] == checks['fresh']['artifact_document'], 'same-whole-artifact-document')
    plan_raw = (folder / 'plan.json').read_bytes(); plan = json.loads(plan_raw)
    check(first['genome_sha256'] == fresh['genome_sha256'] == digest(plan_raw), 'whole-plan-hash')
    check(first['semantic_sha256'] == semantic(first) and fresh['semantic_sha256'] == semantic(fresh), 'raw-semantic-hashes')
    check(first['status'] == fresh['status'] and first['local_ticks'] == fresh['local_ticks']
          and first['manifest_sha256'] == fresh['manifest_sha256'], 'full-trace-state')
    check(comparison['matches'] is True and comparison['verification_scope'] == 'full'
          and comparison['first_difference'] is None, 'saved-full-comparison')
    owners = [next(p for p in processes if p['component'] == 'cpu' and p['runner_namespace'] == ns) for ns in ('runner-0', 'runner-1')]
    check(encoded(comparison_copy(first['events'], owners[0])) == encoded(comparison_copy(fresh['events'], owners[1])), 'independent-full-typed-comparison')
    check(plan['schema_version']==20 and plan['native_packet_configuration']==PACKET_CONFIGURATION, 'exact-enabled-plan20')
    check(plan['instruction_slots'] == [['cpu', a, 1] for a in range(0x200, 0xe01, 32)], '97-reservations')
    check(plan['warmup_advances'] and len(plan['warmup_advances']) <= 512
          and all(x == ['cpu', 'gpio0'] for x in plan['warmup_advances']), 'saved-full-warmup')
    images = plan['template']['initial_images']; check(len(images) == 97, 'bootstrap-and-96-tails')
    check(images[0]['address'] == 0 and len(bytes.fromhex(images[0]['data_hex'])) == 24, 'bootstrap-layout')
    tails = images[1:]
    check([i['address'] for i in tails] == list(range(0x204, 0xe00, 32))
          and len({i['data_hex'] for i in tails}) == 1 and len(bytes.fromhex(tails[0]['data_hex'])) == 28, 'full-fixed-tail-layout')
    check(len(plan['cases']) == len(result['cases']), 'all-saved-cases')
    for index, (saved, record) in enumerate(zip(plan['cases'], result['cases'])):
        check(record == load(folder / f'case-{index+1}.json.gz'), 'saved-case-bundle')
        check(record['selected_source'] == expected[index] and record['actual_next_slot'] == 0x200 + 32 * (index + 1), 'packet-cursor')
        check(record['process_identities'] == result['initial_process_identities'], 'cross-case-owner')
        for component, identity in record['process_identities'].items():
            owner = next(p for p in processes if p['component'] == component and p['runner_namespace'] == 'runner-0')
            check(all(owner[k] == v for k, v in identity.items()), 'case-process-receipt')
        case = record['case']; source = saved['source']; check(source['action_id'] == case['source']['action_id'], 'saved-case-source')
        check(len(saved['advances']) == 128 and all(s == ['cpu', 'gpio0'] for s in saved['advances']), 'case-schedule')
        fragment = source if source['kind'] == 'instruction' else saved['support_instructions'][0]
        check(fragment['address'] == 0x200 + index * 32 and len(bytes.fromhex(fragment['data_hex'])) == 4, 'one-word-stride')
        receipt_events = record['receipt']['events']; ids = {e['event_id']: e for e in first['events']}
        check(all(ids[e['event_id']] == e for e in receipt_events), 'case-full-trace-membership')
        relation = record['relation']; findings = relation['findings']
        check(set(findings) == ({'routed_read_response_mismatch', 'joint_ram_mismatch', 'joint_gpio_mismatch'} if corrupt else set()), 'relation-findings')
        deliveries = [e for e in receipt_events if e.get('kind') == 'mmio_delivery']
        check([(e['write'], e['offset']) for e in deliveries] == [(True, 12), (False, 12), (False, 8), (True, 12)], 'four-real-deliveries')
        a, b = deliveries[1]['read_value'], deliveries[2]['read_value']; joint = a ^ b
        ram = ids[relation['ram_event_id']]
        check(relation['actual_a'] == a and relation['actual_b'] == b and relation['expected_joint'] == joint
              and ram['value'] == relation['actual_ram'] and deliveries[-1]['write_value'] == relation['actual_final_gpio'], 'saved-relation-values')
        check(ram['value'] == deliveries[-1]['write_value'] == (joint ^ int(corrupt)), 'real-joint-response-propagation')
        if expected[index] == 'cpu.instructions':
            word = int.from_bytes(bytes.fromhex(source['data_hex']), 'little')
            check(word & 0xfffff == 0x513 and 0 <= word >> 20 <= 255 and a == word >> 20, 'actual-cpu-source')
        else: check(b == source['value'] and fragment['data_hex'] == '13000000', 'actual-pin-source')
    faults = result['controlled_response_records']; check(len(faults) == (2 if corrupt else 0), 'fault-count')
    summaries = {}
    for label, trace, owner, subset in (('original', first, owners[0], faults[:1]), ('fresh', fresh, owners[1], faults[1:])):
        independently_bound = host_audit(trace['events'], plan, owner, hostchecks[label])
        check(len(independently_bound)==(1 if corrupt else 2), 'directed-host-binding-count')
        summaries[label] = raw_audit(trace['events'], checks[label], owner, subset)
        check(summaries[label]['joins']==(21 if corrupt else 47), 'complete-directed-transfer-count')
        summaries[label]['host_bindings']=len(independently_bound)
    return dict(processes=processes, traces=summaries, warmup_advances=len(plan['warmup_advances']), cases=len(expected))


def audit(root):
    check(type(COPY) is str and re.fullmatch('[0-9a-f]{64}', COPY), 'actual-copy-pin-not-configured')
    gate, control = root / 'gate-control', root / 'control'
    for name, pin in (('final-file-freeze.json', FREEZE), ('final-directories.json', DIRS), ('copy-receipt.json', COPY)):
        check(file_sha(control / name) == pin, 'preparation-pin-' + name)
    for name,pin in [('run_native_gate.py','04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717'),('launch-native-gate.sh','ba69f47e08e2563f1e1f2d07334d544dd657fa176164e013521544fda21b3e92'),('prepare_copy.py','9a2f9efd8ce6331eb396625a9cfc83e3ca0d8be82838330be425efc4b22d13b3')]:
        check(file_sha(root/'inputs'/name)==pin,'actual-deployed-controller-'+name)
    parent = load(gate / 'parent-terminal.json')
    check(parent['controller_sha256']=='04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717', 'actual-parent-controller-pin')
    parent_start=load(gate/'parent-start.json')
    check(all(parent.get(k)==v for k,v in parent_start.items()),'actual-parent-start-terminal-join')
    check(parent['returncode'] == parent['gate_returncode'] == 0 and not parent['errors']
          and parent['status'] == 'collected_pending_independent_audit', 'parent-terminal')
    check(parent['cwd'] == REMOTE_BASE + '/project'
          and parent['argv'] == [REMOTE_INPUTS + '/run_native_gate.py', '--freeze-sha256', FREEZE,
                                '--receipt-sha256', COPY, '--directories-file-sha256', DIRS], 'parent-argv-cwd')
    receipt = load(control / 'copy-receipt.json')
    check(receipt['status'] == 'prepared_pending_independent_review_no_execution'
          and receipt['source_unchanged'] is True and receipt['native_run'] is False
          and receipt['destination'] == REMOTE_BASE + '/project'
          and receipt['source'] == '/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt2/project'
          and receipt['host_paths'] == 70 and receipt['freeze_sha256'] == FREEZE, 'copy-receipt-binding')
    for suffix, pin in (('files', BASELINE), ('directories', DIRS)):
        before, after = control / f'source-before-{suffix}.json', control / f'source-after-{suffix}.json'
        check(file_sha(before) == file_sha(after) == pin and load(before) == load(after), 'copy-baseline-before-after')
    frozen_files = load(control / 'final-file-freeze.json')
    source_files = load(control / 'source-before-files.json')
    hosts=load(control/'explicit-host-files.json')
    check(len(hosts)==70 and all(frozen_files.get(k)==v for k,v in hosts.items()), 'actual-host70-freeze-rows')
    overlay = load(root / 'inputs/overlay-map.json')
    check(len(overlay['files']) == 12 and frozen_files == {**source_files, **overlay['files']}
          and all(p.startswith(('src/', 'scripts/')) for p in overlay['files'])
          and not any(p.startswith('src/myfuzz/frontend/') for p in overlay['files']), 'exact-twelve-overlay')
    check(len(frozen_files)==8892 and len(load(control/'final-directories.json'))==601, 'new-copy-counts')
    check(receipt['files'] == len(frozen_files)
          and receipt['directories'] == len(load(control / 'final-directories.json')), 'copy-file-directory-count')
    for suffix in ('files', 'directories'):
        before, after = load(gate / f'before-{suffix}.json'), load(gate / f'after-{suffix}.json')
        frozen = load(control / ('final-file-freeze.json' if suffix == 'files' else 'final-directories.json'))
        check(before == after == frozen, 'source-file-directory-unchanged')
    tool_inputs = root / 'tool-inputs'
    for name, pin in (('inventory.json', INVENTORY), ('tool-freeze.json', TOOLS), ('environment.sh', ENV)):
        check(file_sha(tool_inputs / name) == pin, 'fixed-tool-input-' + name)
    inventory = load(tool_inputs / 'inventory.json')
    entrypoints = load(tool_inputs / 'tool-freeze.json')
    share = {str(Path(p).relative_to('share/verilator')):
             {field: row[field] for field in ('bytes', 'sha256')}
             for p, row in inventory['verilator_share'].items()}
    check(len(share) == 115 and len(inventory['pythonlib_files']) == 581, 'fixed-tool-dependency-counts')
    expected_tools = dict(entrypoints=entrypoints, system_entrypoints=inventory['system_entrypoints'],
                          environment_sha256=ENV, inventory_sha256=INVENTORY,
                          verilator_share=share, pythonlib_files=inventory['pythonlib_files'])
    check(load(gate / 'before-tools.json') == load(gate / 'after-tools.json') == expected_tools,
          'exact-fixed-tools-environment-and-full-maps')
    expected_commands = {
        'git-root-head': ['git', 'rev-parse', 'HEAD'],
        'git-closures-tracked': ['git', 'ls-files', '--error-unmatch',
                                'configs/soc/closures/picorv32.json', 'configs/soc/closures/pulp_gpio.json'],
        'git-picorv32_upstream_reference-connectivity': ['git', '-C', REMOTE_BASE + '/project/third_party/picorv32_upstream_reference', 'fsck', '--connectivity-only', '--no-dangling'],
        'git-soc-pulp-apb-gpio-connectivity': ['git', '-C', REMOTE_BASE + '/project/third_party/soc-pulp-apb-gpio', 'fsck', '--connectivity-only', '--no-dangling'],
        'native-directed-gate': ['/usr/bin/python3', REMOTE_BASE + '/project/scripts/verify_picorv32_native_online.py',
                                 '--output', REMOTE_BASE + '/run-directed', '--cache-dir', REMOTE_BASE + '/cache-native',
                                 '--heavy-lock', '/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock',
                                 '--native-completion-observation', '--native-source-binding'],
    }
    for name in ('git-root-head', 'git-closures-tracked', 'git-picorv32_upstream_reference-connectivity', 'git-soc-pulp-apb-gpio-connectivity', 'native-directed-gate'):
        child = load(gate / f'{name}.terminal.json')
        launch=load(gate/f'{name}.launch.json')
        check(all(child.get(k)==launch[k] for k in ('pid','argv','cwd','started_unix')), 'actual-child-launch-terminal-join-'+name)
        check(type(child['pid']) is int and child['pid']>0, 'actual-child-positive-pid')
        check(child['returncode'] == 0 and child['error'] is None, 'actual-child-rc-' + name)
        check(child['argv'] == expected_commands[name] and child['cwd'] == REMOTE_BASE + '/project', 'child-argv-cwd-' + name)
        for stream in ('stdout', 'stderr'): check(file_sha(gate / f'{name}.{stream}') == child[f'{stream}_sha256'], 'child-stream-pin')
    check((gate / 'git-root-head.stdout').read_text().strip() == '6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941', 'baseline-git-head')
    for stream in ('stdout', 'stderr'): check(file_sha(root / f'gate-parent.{stream}') == parent[f'{stream}_sha256'], 'parent-output-pin')
    run = root / 'run-directed'; summary = load(run / 'summary.json.gz')
    check(summary['positive_status'] == summary['controlled_status'] == 'bounded_directed_gate_passed'
          and summary['native_completion_observation'] is True and summary['native_source_binding'] is True
          and all(summary[k] is False for k in ('formal_p6_complete', 'source_authority', 'retirement_authority', 'coverage_guided_search')), 'bounded-summary')
    positive, controlled = audit_run(run / 'positive', False), audit_run(run / 'controlled-response', True)
    processes = positive['processes'] + controlled['processes']
    check(len(processes) == len({p['pid'] for p in processes}) == len({p['execution_nonce'] for p in processes}) == 8, 'eight-distinct-actual-processes')
    for component in ('cpu', 'gpio0'):
        check(len({p['artifact_digest'] for p in processes if p['component'] == component}) == 1, 'same-artifact-positive-control')
    observation=load(root/'readonly-terminal-observation.json')
    gatechild=load(gate/'native-directed-gate.terminal.json')
    pids=[parent['pid'],gatechild['pid'],*[p['pid'] for p in processes]]
    check(all(type(pid)is int and pid>0 for pid in pids) and len(set(pids))==10,'strict-parent-gate-eight-model-pids')
    check(observation['operation']==REMOTE_BASE and observation['remote_read_only'] is True
          and observation['model_execution_by_collection'] is False
          and observation['specified_pid_presence']=={str(pid):False for pid in pids}
          and all(type(v)is bool for v in observation['specified_pid_presence'].values()), 'later-all-ten-processes-gone')
    collected=datetime.datetime.fromisoformat(observation['collected_at'])
    check(collected.tzinfo is not None and collected.timestamp()>=parent['ended_unix']
          and collected.timestamp()>=gatechild['ended_unix'],'later-collection-after-actual-terminal')
    return dict(schema_version='native_completion_independent_saved_audit.v1', status='saved_evidence_checks_passed',
                positive=positive, controlled=controlled, actual_process_count=len(processes),
                source_authority=False, retirement=False, coverage_guided_search=False, formal_p6_complete=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.operation_dir), sort_keys=True, indent=2))
