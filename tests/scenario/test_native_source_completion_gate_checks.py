import hashlib
import importlib.util
import json
import copy
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = ROOT / 'scripts' / 'verifier' / 'native_completion_gate_checks.py'
SPEC = importlib.util.spec_from_file_location('_native_source_completion_gate_checks', CHECKS_PATH)
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)
AUDIT_PATH = ROOT / 'scripts' / 'audit_native_source_completion_evidence.py'
AUDIT_SPEC = importlib.util.spec_from_file_location('_native_source_completion_independent_audit', AUDIT_PATH)
AUDIT = importlib.util.module_from_spec(AUDIT_SPEC)
AUDIT_SPEC.loader.exec_module(AUDIT)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def _fixture():
    execution = 'a' * 32
    address = 0x80000040
    action = 'action-1'
    source = dict(kind='instruction', component='cpu', action_id=action,
                  address=address, data_hex='13051000')
    admission = dict(schema_version='source_admission.v1', case_id='case-1',
        case_index=0, source_id='source-1', path_id='path-1',
        direction='CPU_TO_IP_TO_CPU', component='cpu', action_id=action,
        role='fuzz_source', input_kind='instruction',
        input_sha256=hashlib.sha256(_canonical(source)).hexdigest())
    admission['admission_id'] = hashlib.sha256(_canonical(admission)).hexdigest()
    acceptance = dict(memory_id='ram', address=address, byte_offset=0x40,
        generation=0, data_hex='13051000', source_event_id=action,
        versions=[[0, 1]] * 4, writer_event_ids=[action] * 4,
        writer_kinds=['INSTRUCTION_SOURCE'] * 4)
    binding = dict(component='cpu', execution=execution, reset_epoch=0,
        case_index=0, admission=admission, source=source, acceptance=acceptance)
    key = dict(execution_id='local-execution', testcase_id='case-1',
        source_component='cpu', source_epoch=0, channel_id='memory', source_sequence=1)
    accepted_scope = dict(execution=execution, command_sequence=1,
        reset_epoch=0, local_tick=1)
    response_scope = dict(execution=execution, command_sequence=2,
        reset_epoch=0, local_tick=2)
    completion_scope = dict(execution=execution, command_sequence=3,
        reset_epoch=0, local_tick=3)
    snapshot = dict(transaction_id=("TransactionKey(execution_id='local-execution', "
        "testcase_id='case-1', source_component='cpu', source_epoch=0, "
        "channel_id='memory', source_sequence=1)"), memory_id='ram',
        generation=0, byte_offset=0x40, versions=[[0, 1]] * 4,
        writer_event_ids=[action] * 4, materialized_offsets=[],
        writer_kinds=['INSTRUCTION_SOURCE'] * 4, data_hex='13051000')
    native = dict(valid=1, ready=1, addr=address, wstrb=0,
                  wdata=0, rdata=0x00100513, instruction=1)
    events = [
        dict(event_id=1, kind='source_admission', admission=admission),
        dict(event_id=2, kind='instruction_source', component='cpu', address=address,
             data_hex='13051000', generation=0, source_event_id=action,
             producer_event_id=1),
        dict(event_id=3, schema_version='native_instruction_source_binding.v1',
             kind='native_instruction_source_bound', component='cpu', execution=execution,
             reset_epoch=0, case_index=0, admission=admission, source=source,
             acceptance=acceptance, admission_event_id=1, producer_event_id=2,
             proof_scope='host_instruction_input_bound', grants_source_authority=False,
             native_bus_completion_observed=False, retirement=False, grants_feedback=False),
        dict(event_id=4, kind='local_tick_sample', component='cpu', phase='pre',
             native_driver_scope=accepted_scope),
        dict(event_id=5, kind='native_backend_request_accepted', component='cpu',
             schema_version='native_bus_observation.v1', producer_event_id=4,
             transaction=key, **accepted_scope),
        dict(event_id=6, kind='memory_read', component='cpu', transaction=key,
             address=address, width_bytes=4, memory_id='ram', generation=0,
             byte_offset=0x40, value=0x00100513, data_hex='13051000',
             versions=[[0, 1]] * 4, writer_event_ids=[action] * 4,
             writer_kinds=['INSTRUCTION_SOURCE'] * 4),
        dict(event_id=7, kind='local_tick_sample', component='cpu', phase='pre',
             native_driver_scope=response_scope),
        dict(event_id=8, kind='native_backend_response_consumed', component='cpu',
             schema_version='native_bus_observation.v1', producer_event_id=7,
             transaction=key, value=0x13, native_post_is_offer_only=True,
             **response_scope),
        dict(event_id=9, kind='local_tick_sample', component='cpu', phase='pre',
             native_driver_scope=completion_scope),
        dict(event_id=10, kind='native_bus_completed', component='cpu',
             schema_version='native_bus_observation.v1', producer_event_id=9,
             transaction=key, accepted_scope=accepted_scope,
             response_scope=response_scope, native=native,
        memory_read_snapshot=snapshot, **completion_scope),
    ]
    completion = dict(schema_version='native_instruction_bus_completion.v1',
        kind='native_instruction_bus_completion', proof_scope='native_instruction_bus_transfer_completed',
        grants_source_authority=False, component='cpu', event_id=11,
        producer_event_id=9, key=key, snapshot=snapshot, binding=binding,
        address=address, data_hex='13051000', reset_epoch=0,
        accepted_scope=accepted_scope, response_scope=response_scope,
        completion_scope=completion_scope, native_pre=[1, 1, address, 0, 0x00100513, 1],
        admission_event_id=1, host_binding_event_id=3, service_event_id=2,
        native_accepted_event_id=5, native_response_event_id=8,
        native_completed_event_id=10)
    events.append(completion)
    events.append(dict(event_id=12, kind='local_tick_sample', component='cpu',
        phase='pre', native_driver_scope=dict(execution=execution, command_sequence=4,
            reset_epoch=0, local_tick=4)))
    plan = dict(schema_version=22,
        native_packet_configuration=dict(enabled=True, max_cases=1),
        native_source_completion=dict(schema_version='native_packet_source_completion.v1',
            enabled=True, max_cases=1, proof_scope='native_instruction_bus_transfer_completed'),
        cases=[dict(case_id='case-1', direction='CPU_TO_IP_TO_CPU', path_id='path-1',
            source=source, source_role='fuzz_source', support_instructions=[], advances=[])])
    raw_checks = dict(status='raw_checks_passed', joins=[
        dict(completed_raw_event_id=9, accepted_raw_event_id=4, response_raw_event_id=7,
             service_event_id=6, transaction=key, native=native,
             accepted_scope=accepted_scope, response_scope=response_scope,
             completed_scope=completion_scope, snapshot=snapshot),
        dict(completed_raw_event_id=12, native=dict(valid=1, ready=1, addr=0x1000,
             wstrb=0, wdata=0, rdata=0x13, instruction=1), snapshot=None),
    ])
    return events, plan, raw_checks, execution


def _independent_source_completion_fixture():
    events, plan, raw_checks, _ = _fixture()
    session_testcase_id = 'native-pulp-online'
    action_case_id = 'online-0-generated-action'
    source_id = 'cpu.instructions'
    plan['template'] = dict(testcase_id=session_testcase_id)
    case = plan['cases'][0]
    case['case_id'] = action_case_id
    case['source_role'] = 'fuzz_source'
    action = action_case_id + ':' + source_id
    case['source']['action_id'] = action
    transaction = events[4]['transaction']
    transaction['testcase_id'] = session_testcase_id
    case['direction'] = 'CPU_TO_IP_TO_CPU'
    case['path_id'] = 'path-1'

    admission = events[0]['admission']
    admission.update(case_id=action_case_id, case_index=0, source_id=source_id,
        action_id=action, input_sha256=hashlib.sha256(_canonical(case['source'])).hexdigest())
    admission['admission_id'] = hashlib.sha256(_canonical({
        name: value for name, value in admission.items() if name != 'admission_id'
    })).hexdigest()
    case['source']['action_id'] = action
    events[1]['source_event_id'] = action
    binding = events[2]
    binding['event_id'] = 3
    binding['service_event_index'] = 0
    binding['provenance'] = _audit_provenance(
        dict(case_id=action_case_id, case_index=0))
    binding['acceptance']['source_event_id'] = action
    binding['acceptance']['writer_event_ids'] = [action] * 4
    events[5]['writer_event_ids'] = [action] * 4
    snapshot = events[9]['memory_read_snapshot']
    snapshot['writer_event_ids'] = [action] * 4
    snapshot['transaction_id'] = AUDIT.tx_text(transaction)

    plan['source_admissions'] = dict(schema_version='source_admission_registry.v1',
        admissions=[admission])
    plan['runtime_paths'] = dict(declaration=dict(
        schema_version='prepared_runtime_paths.v1',
        selections=[dict(path_id='path-1', direction='CPU_TO_IP_TO_CPU',
                         source_ids=[source_id])],
        graph=dict(sources=[dict(source_id=source_id, kind='instruction',
            component='cpu', directions=['CPU_TO_IP_TO_CPU'])])))

    observed_case = dict(case_id=action_case_id, case_index=0)
    accepted_native = dict(valid=1, ready=0, addr=case['source']['address'],
        wstrb=0, wdata=0, rdata=0, instruction=1)
    events[4]['native'] = accepted_native
    events[7]['value'] = int.from_bytes(bytes.fromhex(case['source']['data_hex']), 'little')
    events[4]['provenance'] = _audit_provenance(observed_case)
    events[7]['provenance'] = _audit_provenance(observed_case)
    events[9]['provenance'] = _audit_provenance(observed_case)
    completion = events[10]
    completion['provenance'] = _audit_provenance(observed_case)

    selected_join = raw_checks['joins'][0]
    selected_join.update(accepted_native=accepted_native,
        accepted_projection_event_id=5, response_projection_event_id=8,
        completion_projection_event_id=10)
    noncandidate_key = dict(transaction, source_sequence=2)
    raw_checks['joins'][1].update(transaction=noncandidate_key,
        snapshot=dict(data_hex='00000013'))

    return events, plan, raw_checks


def _refusal_fixture():
    _, plan, _, execution = _fixture()
    session_testcase_id = 'native-pulp-online'
    action_case_id = 'online-0-generated-action'
    plan['template'] = dict(testcase_id=session_testcase_id)
    plan['cases'][0]['case_id'] = action_case_id
    source = plan['cases'][0]['source']
    action = source['action_id']
    native_key = dict(execution_id='local-execution', testcase_id=session_testcase_id,
        source_component='cpu', source_epoch=0, channel_id='memory', source_sequence=1)
    write_key = dict(execution_id='local-execution', testcase_id=session_testcase_id,
        source_component='cpu', source_epoch=0, channel_id='native-source-poison',
        source_sequence=1)
    version = [0, 2]
    poison_write = dict(kind='memory_write', transaction=write_key,
        address=source['address'], width_bytes=4, memory_id='ram', generation=0,
        byte_offset=0x40, value=0x13, byte_enable=15, version=version)
    committed = dict(schema_version='memory_write_commit_receipt.v1',
        fullkey=write_key, memory_kind='modeled_host_persistent_memory',
        memory_id='ram', generation=0, byte_offset=0x40, width_bytes=4,
        byte_enable=15, version=version,
        payload_sha256=hashlib.sha256(_canonical(dict(op='write',
            address=source['address'], value=0x13, width_bytes=4,
            byte_enable=15))).hexdigest(),
        commit_status='complete',
        performed_effect=True, enabled_byte_cells=[dict(byte_offset=0x40 + lane,
            value=(0x13 >> (lane * 8)) & 0xff, version=version,
            writer_kind='STORE', writer_event_id=_transaction_key_repr(write_key))
            for lane in range(4)])
    committed['commit_id'] = hashlib.sha256(json.dumps(committed, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    accepted_scope = dict(execution=execution, command_sequence=1, reset_epoch=0, local_tick=1)
    response_scope = dict(execution=execution, command_sequence=2, reset_epoch=0, local_tick=2)
    refused_scope = dict(execution=execution, command_sequence=3, reset_epoch=0, local_tick=3)
    binding = _fixture()[0][2]
    admission = binding['admission']
    admission['case_id'] = action_case_id
    admission['admission_id'] = hashlib.sha256(_canonical({
        name: value for name, value in admission.items() if name != 'admission_id'
    })).hexdigest()
    binding['admission'] = admission
    acceptance = binding['acceptance']
    trace = dict(protocol='ready-valid-memory', boundary='cpu_physical_abi',
        endpoint_id='cpu-native-endpoint', clock_domain='cpu-clock',
        signal_widths=dict(valid=1, ready=1, addr=32, wdata=32, wstrb=4, rdata=32),
        signals=dict(valid='valid', ready='ready', addr='addr', wdata='wdata',
            wstrb='wstrb', rdata='rdata'), max_wait_cycles=16)
    runtime_document = dict(artifact_digest='artifact',
        native_completion_observation=dict(schema_version='native_completion_observation.v1',
            endpoint_id='cpu-native-endpoint', clock_domain='cpu-clock',
            instruction_marker=dict(signal='instruction_marker', width=1),
            completion=dict(phase='pre')),
        base_protocol_traces=dict(traces=[trace]))
    taps = dict(valid=1, ready=1, addr=source['address'], wdata=0,
        wstrb=0, rdata=0x13)
    backend = dict(m_req_valid=0, m_req_ready=1, m_req_addr=source['address'],
        m_req_write=0, m_req_wdata=0, m_req_be=15, m_rsp_valid=0,
        m_rsp_ready=0, m_rsp_rdata=0x13, m_rsp_error=0)
    def outputs(*, valid=1, ready=0, rdata=0x13, backend_values=None):
        return dict(protocol_taps=dict(valid=valid, ready=ready,
            addr=source['address'], wdata=0, wstrb=0, rdata=rdata),
            physical=dict(instruction_marker=1),
            backend=dict(backend, **(backend_values or {})))
    native_accept = dict(valid=1, ready=0, addr=source['address'],
        wdata=0, wstrb=0, rdata=0, instruction=1)
    def projection(kind, raw_id, scope, **fields):
        return dict(kind=kind, component='cpu', schema_version='native_bus_observation.v1',
            producer_event_id=raw_id, proof_scope='native_bus_transfer_only', phase='pre',
            grants_source_authority=False, retirement=False, artifact_digest='artifact',
            endpoint_id='cpu-native-endpoint', clock_domain='cpu-clock',
            transaction=native_key, **scope, **fields)
    events = [
        dict(event_id=1, kind='source_admission', admission=binding['admission']),
        dict(event_id=2, kind='instruction_source', component='cpu',
            address=source['address'], data_hex=source['data_hex'], generation=0,
            source_event_id=action, producer_event_id=1),
        binding,
        dict(event_id=4, component='cpu', local_tick=1,
            outputs=dict(data_rsp_consumed=0, data_rsp_source_sequence=0,
                         data_rsp_source_epoch=0, data_rsp_rdata=0)),
        dict(event_id=5, kind='memory_write', component='cpu', producer_event_id=4,
            transaction=write_key, address=source['address'], width_bytes=4,
            memory_id='ram', generation=0, byte_offset=0x40, value=0x13,
            byte_enable=15, version=version),
        dict(event_id=6, kind='memory_read', component='cpu', producer_event_id=4,
            transaction=native_key,
            address=source['address'], width_bytes=4, memory_id='ram', generation=0,
            byte_offset=0x40, value=0x13, data_hex='13000000', versions=[version] * 4,
            writer_event_ids=[_transaction_key_repr(write_key)] * 4,
            writer_kinds=['STORE'] * 4),
        dict(event_id=7, kind='local_tick_sample', component='cpu', local_tick=1,
            phase='pre', producer_event_id=4, native_driver_scope=accepted_scope,
            outputs=outputs(valid=1, ready=0, rdata=0,
                backend_values=dict(m_req_valid=1, m_req_ready=1))),
        projection('native_backend_request_accepted', 7, accepted_scope,
            native=native_accept, event_id=8),
        dict(event_id=9, kind='local_tick_sample', component='cpu', local_tick=1,
            phase='post', producer_event_id=4, native_driver_scope=accepted_scope,
            outputs=outputs(valid=1, ready=0)),
        dict(event_id=10, component='cpu', local_tick=2,
            outputs=dict(data_rsp_consumed=1, data_rsp_source_sequence=1,
                         data_rsp_source_epoch=0, data_rsp_rdata=0x13)),
        dict(event_id=11, kind='local_tick_sample', component='cpu', local_tick=2,
            phase='pre', producer_event_id=10, native_driver_scope=response_scope,
            outputs=outputs(valid=1, ready=0,
                backend_values=dict(m_rsp_valid=1, m_rsp_ready=1))),
        projection('native_backend_response_consumed', 11, response_scope,
            value=0x13, native_post_is_offer_only=True, event_id=12),
        dict(event_id=13, kind='local_tick_sample', component='cpu', local_tick=2,
            phase='post', producer_event_id=10, native_driver_scope=response_scope,
            outputs=outputs(valid=1, ready=1)),
        dict(event_id=14, kind='harness_failure', component='cpu', error_type='ValueError'),
        dict(event_id=15, kind='local_tick_sample', component='cpu', local_tick=3,
            phase='pre', producer_event_id=14, native_driver_scope=refused_scope,
            outputs=outputs(valid=1, ready=1)),
        dict(event_id=16, kind='local_tick_sample', component='cpu', local_tick=3,
            phase='post', producer_event_id=14, native_driver_scope=refused_scope,
            outputs=outputs(valid=0, ready=0)),
    ]
    plan['schema_version'] = 23
    plan['terminal_failure'] = dict(phase='step', case_index=0, case_id=action_case_id,
        command_index=0, error_type='ValueError',
        error_message='native_source_candidate_refused')
    plan['native_source_completion'] = dict(schema_version='native_packet_source_completion.v1',
        enabled=True, max_cases=1, proof_scope='native_instruction_bus_transfer_completed')
    terminal_refusal = dict(producer_event_id=15, transaction=native_key,
        accepted_scope=accepted_scope, response_scope=response_scope,
        refused_scope=refused_scope, accepted_raw_event_id=7,
        response_raw_event_id=11, native=dict(valid=1, ready=1,
            addr=source['address'], wstrb=0, wdata=0, rdata=0x13, instruction=1))
    raw_checks = dict(status='raw_checks_passed_with_terminal_refusal', joins=[],
        counts=dict(accepted=1, responses=1, raw_completed=1, completed=0,
            instruction_completed=0, data_completed=0, terminal_refusals=1),
        terminal_refusal=terminal_refusal,
        excluded_injected_writes=[dict(event_id=5, transaction=write_key,
            service_event=events[4])])
    refusal_record = dict(schema_version='native_source_candidate_refusal.v1',
        selected_action_id=action, native_transaction=native_key,
        refused_raw_event_id=15, write_transaction=write_key,
        write_receipt_object=dict(transaction_id=write_key, version=tuple(version),
            byte_enable=15), write_receipt=committed, write_service_event=poison_write,
        write_journal_event_id=5, write_journal_event=events[4],
        original_acceptance=acceptance)
    return events, plan, raw_checks, execution, runtime_document, refusal_record


def _transaction_key_repr(key):
    return 'TransactionKey(' + ', '.join(
        f'{name}={key[name]!r}' for name in ('execution_id', 'testcase_id',
            'source_component', 'source_epoch', 'channel_id', 'source_sequence')) + ')'


def _reseal_commit(document):
    material = {name: value for name, value in document.items() if name != 'commit_id'}
    document['commit_id'] = hashlib.sha256(_canonical(material)).hexdigest()


def _audit_transaction(testcase_id, sequence):
    return dict(execution_id='local-execution', testcase_id=testcase_id,
        source_component='cpu', source_epoch=0, channel_id='memory',
        source_sequence=sequence)


def _audit_provenance(observed_case):
    return dict(schema_version='event_source_provenance.v1',
        observed_case=observed_case, origin_admission_ids=[], origin_status='unknown',
        unknown_writer_ids=[], invalid_origin_references=0,
        proof_scope='observation_only', edge_candidates=[], resource=None)


def _audit_relation_fixture(session_testcase_id='native-pulp-online',
                            case_id='online-0-generated-action'):
    keys = [_audit_transaction(session_testcase_id, sequence)
            for sequence in range(1, 5)]
    deliveries = [
        dict(event_id=1, kind='mmio_delivery', device_id='gpio0', offset=12,
            write=True, write_value=0, byte_enable=15, beat_bytes=4,
            source_transaction=keys[0]),
        dict(event_id=2, kind='mmio_delivery', device_id='gpio0', offset=12,
            write=False, read_value=0, byte_enable=15, beat_bytes=4,
            source_transaction=keys[1]),
        dict(event_id=4, kind='mmio_delivery', device_id='gpio0', offset=8,
            write=False, read_value=5, byte_enable=15, beat_bytes=4,
            source_transaction=keys[2]),
        dict(event_id=7, kind='mmio_delivery', device_id='gpio0', offset=12,
            write=True, write_value=5, byte_enable=15, beat_bytes=4,
            source_transaction=keys[3]),
    ]
    events = deliveries + [
        dict(event_id=3, component='cpu', outputs=dict(data_rsp_consumed=1,
            data_rsp_source_sequence=2, data_rsp_source_epoch=0, data_rsp_rdata=0)),
        dict(event_id=5, component='cpu', outputs=dict(data_rsp_consumed=1,
            data_rsp_source_sequence=3, data_rsp_source_epoch=0, data_rsp_rdata=5)),
        dict(event_id=6, kind='memory_write', address=0x100,
            value=5, byte_enable=15, transaction=keys[3]),
    ]
    plan_case = dict(case_id=case_id, source=dict(kind='instruction',
        data_hex='00000000'))
    return events, plan_case, keys


class NativeSourceCompletionGateAuditTests(unittest.TestCase):
    def test_independent_audit_keeps_session_id_separate_from_case_provenance(self):
        session_testcase_id = 'native-pulp-online'
        action_case_id = 'online-0-generated-action'
        case_indices = {action_case_id: 0}
        plan = dict(template=dict(testcase_id=session_testcase_id),
            cases=[dict(case_id=action_case_id)])
        self.assertEqual(session_testcase_id, AUDIT.plan_session_testcase_id(plan))

        projection = dict(transaction=_audit_transaction(session_testcase_id, 1),
            provenance=_audit_provenance(dict(case_id=action_case_id, case_index=0)))
        AUDIT.require_native_transaction_projection_identity(
            projection, session_testcase_id, case_indices)

        bootstrap = dict(transaction=_audit_transaction(session_testcase_id, 2),
            provenance=_audit_provenance(None))
        AUDIT.require_native_transaction_projection_identity(
            bootstrap, session_testcase_id, case_indices)

        wrong_session = dict(transaction=_audit_transaction(action_case_id, 1),
            provenance=_audit_provenance(dict(case_id=action_case_id, case_index=0)))
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.require_native_transaction_projection_identity(
                wrong_session, session_testcase_id, case_indices)

        wrong_case_index = dict(transaction=_audit_transaction(session_testcase_id, 1),
            provenance=_audit_provenance(dict(case_id=action_case_id, case_index=1)))
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.require_native_transaction_projection_identity(
                wrong_case_index, session_testcase_id, case_indices)

    def test_independent_relation_audit_uses_session_transaction_identity(self):
        events, plan_case, keys = _audit_relation_fixture()
        relation = AUDIT.relation_for_events(events, plan_case,
            case_id=plan_case['case_id'], session_testcase_id='native-pulp-online')
        self.assertEqual(plan_case['case_id'], relation['case_id'])
        self.assertEqual(keys[1], relation['padout_read_transaction'])

        raw = dict(joins=[dict(transaction=keys[1], service_event_id=2,
            service_kind='mmio_delivery', service_address=0x4000000c,
            service_offset=12, service_beat_bytes=4, service_write=False,
            service_byte_enable=15, service_device_id='gpio0',
            accepted_native=dict(addr=0x4000000c, wstrb=0),
            actual_service_response=0, delivered_response=0,
            response_command_event_id=3)])
        join = AUDIT.raw_padout_join(relation, raw,
            session_testcase_id='native-pulp-online')
        self.assertEqual(keys[1], join['transaction'])

        events[0]['source_transaction']['testcase_id'] = plan_case['case_id']
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.relation_for_events(events, plan_case,
                case_id=plan_case['case_id'], session_testcase_id='native-pulp-online')

    def test_independent_completion_requires_selected_projection_case_provenance(self):
        events, plan, raw_checks = _independent_source_completion_fixture()
        session_testcase_id = plan['template']['testcase_id']
        action_case_id = plan['cases'][0]['case_id']
        self.assertNotEqual(session_testcase_id, action_case_id)
        positive = AUDIT.source_completion_audit(events, plan, raw_checks)
        self.assertEqual(['online-0-generated-action:cpu.instructions'],
                         [row['action_id'] for row in positive['selected_completions']])

        projections = {
            'native_backend_request_accepted': 5,
            'native_backend_response_consumed': 8,
            'native_bus_completed': 10,
        }
        for kind, event_id in projections.items():
            for corruption in ('null', 'foreign-case', 'wrong-index'):
                with self.subTest(kind=kind, corruption=corruption):
                    corrupted_events, corrupted_plan, corrupted_raw = copy.deepcopy(
                        (events, plan, raw_checks))
                    projection = next(row for row in corrupted_events
                                      if row.get('event_id') == event_id)
                    if corruption == 'null':
                        projection['provenance']['observed_case'] = None
                    elif corruption == 'foreign-case':
                        projection['provenance']['observed_case'] = dict(
                            case_id='online-1-foreign-action', case_index=0)
                    else:
                        projection['provenance']['observed_case'] = dict(
                            case_id=action_case_id, case_index=1)
                    with self.assertRaises(AUDIT.AuditError):
                        AUDIT.source_completion_audit(
                            corrupted_events, corrupted_plan, corrupted_raw)

    def test_positive_selected_completion_and_noncandidate_no_grant(self):
        events, plan, raw_checks, execution = _fixture()
        report = CHECKS.check_native_source_completion_events(
            events, plan, raw_checks, execution=execution)
        self.assertEqual('source_completion_event_checks_passed', report['status'])
        self.assertEqual(['action-1'], [row['action_id'] for row in report['completions']])
        self.assertEqual([12], [row['completed_raw_event_id'] for row in report['noncandidate_no_grants']])

    def test_selected_completion_cannot_be_reassigned_to_noncandidate_raw_fetch(self):
        events, plan, raw_checks, execution = _fixture()
        completion = next(row for row in events
                          if row.get('kind') == 'native_instruction_bus_completion')
        completion['producer_event_id'] = 12
        report = CHECKS.check_native_source_completion_events(
            events, plan, raw_checks, execution=execution)
        self.assertEqual('failed', report['status'])

    def test_selected_completion_rejects_snapshot_or_reference_tampering(self):
        for field in ('versions', 'writer_event_ids', 'native_completed_event_id'):
            with self.subTest(field=field):
                events, plan, raw_checks, execution = _fixture()
                completion = next(row for row in events
                                  if row.get('kind') == 'native_instruction_bus_completion')
                if field == 'native_completed_event_id':
                    completion[field] = 8
                else:
                    completion['snapshot'][field][0] = [0, 2] if field == 'versions' else 'other'
                report = CHECKS.check_native_source_completion_events(
                    events, plan, raw_checks, execution=execution)
                self.assertEqual('failed', report['status'])

    def test_positive_audit_accepts_live_tuple_snapshots_without_weakening_types(self):
        events, plan, raw_checks, execution = _fixture()
        binding = next(row for row in events
                       if row.get('kind') == 'native_instruction_source_bound')
        completion = next(row for row in events
                          if row.get('kind') == 'native_instruction_bus_completion')
        read = next(row for row in events if row.get('kind') == 'memory_read')
        snapshot = completion['snapshot']
        acceptance = binding['acceptance']
        for document in (snapshot, acceptance):
            document['versions'] = tuple(tuple(version) for version in document['versions'])
            document['writer_event_ids'] = tuple(document['writer_event_ids'])
            document['writer_kinds'] = tuple(document['writer_kinds'])
        snapshot['materialized_offsets'] = ()
        for field in ('versions', 'writer_event_ids', 'writer_kinds'):
            read[field] = tuple(tuple(value) if field == 'versions' else value
                                for value in read[field])
        raw_checks['joins'][0]['snapshot'] = snapshot

        report = CHECKS.check_native_source_completion_events(
            events, plan, raw_checks, execution=execution)
        self.assertEqual('source_completion_event_checks_passed', report['status'])

        snapshot['versions'] = ((False, 1),) * 4
        report = CHECKS.check_native_source_completion_events(
            events, plan, raw_checks, execution=execution)
        self.assertEqual('failed', report['status'])

    def test_refusal_audit_accepts_live_tuple_read_snapshots(self):
        events, plan, _, execution, runtime_document, refusal_record = _refusal_fixture()
        binding = next(row for row in events
                       if row.get('kind') == 'native_instruction_source_bound')
        acceptance = binding['acceptance']
        acceptance['versions'] = tuple(tuple(version) for version in acceptance['versions'])
        acceptance['writer_event_ids'] = tuple(acceptance['writer_event_ids'])
        acceptance['writer_kinds'] = tuple(acceptance['writer_kinds'])
        read = next(row for row in events if row.get('kind') == 'memory_read')
        read['versions'] = tuple(tuple(version) for version in read['versions'])
        read['writer_event_ids'] = tuple(read['writer_event_ids'])
        read['writer_kinds'] = tuple(read['writer_kinds'])

        report = CHECKS.check_native_source_completion_refusal(
            events, plan, runtime_document, execution=execution,
            refusal_record=refusal_record)
        self.assertEqual('native_source_refusal_checks_passed', report['status'])

        read['versions'] = ((False, 2),) * 4
        report = CHECKS.check_native_source_completion_refusal(
            events, plan, runtime_document, execution=execution,
            refusal_record=refusal_record)
        self.assertEqual('failed', report['status'])

    def test_host_binding_auditor_accepts_completion_plan_schema(self):
        events, plan, _, execution = _fixture()
        report = CHECKS.check_host_source_bindings(events, plan, execution=execution)
        self.assertEqual('host_input_binding_checks_passed', report['status'])

    def test_selected_candidate_contradiction_requires_actual_write_and_refusal_without_grant(self):
        events, plan, _, execution, runtime_document, refusal_record = _refusal_fixture()
        self.assertNotEqual(plan['template']['testcase_id'], plan['cases'][0]['case_id'])
        self.assertEqual(plan['template']['testcase_id'],
                         refusal_record['native_transaction']['testcase_id'])
        self.assertEqual(plan['template']['testcase_id'],
                         refusal_record['write_transaction']['testcase_id'])
        report = CHECKS.check_native_source_completion_refusal(
            events, plan, runtime_document, execution=execution,
            refusal_record=refusal_record)
        self.assertEqual('native_source_refusal_checks_passed', report['status'])
        self.assertEqual('native_source_candidate_refused',
                         report['terminal_failure']['error_message'])
        self.assertEqual(15, report['terminal_refusal']['refused_raw_event_id'])
        self.assertEqual('13000000', report['terminal_refusal']['actual_read_data_hex'])
        self.assertEqual(1, report['terminal_refusal']['write_transaction']['source_sequence'])

    def test_write_receipt_version_accepts_typed_tuple_and_json_list_forms(self):
        for container in (tuple, list):
            with self.subTest(container=container.__name__):
                events, plan, _, execution, runtime_document, refusal_record = _refusal_fixture()
                refusal_record['write_receipt_object']['version'] = container((0, 2))
                report = CHECKS.check_native_source_completion_refusal(
                    events, plan, runtime_document, execution=execution,
                    refusal_record=refusal_record)
                self.assertEqual('native_source_refusal_checks_passed', report['status'])

    def test_refusal_auditor_rejects_wrong_execution_key_or_minted_completion(self):
        for corruption in ('write-execution', 'write-testcase', 'minted-completion',
                           'foreign-minted-completion', 'commit-id',
                           'payload-digest', 'memory-kind'):
            with self.subTest(corruption=corruption):
                events, plan, _, execution, runtime_document, refusal_record = _refusal_fixture()
                if corruption == 'write-execution':
                    refusal_record['write_transaction']['execution_id'] = 'other-execution'
                elif corruption == 'write-testcase':
                    refusal_record['write_transaction']['testcase_id'] = plan['cases'][0]['case_id']
                elif corruption == 'minted-completion':
                    events.append(dict(event_id=17,
                        kind='native_instruction_bus_completion',
                        transaction=refusal_record['native_transaction'],
                        producer_event_id=refusal_record['refused_raw_event_id']))
                elif corruption == 'foreign-minted-completion':
                    events.append(dict(event_id=17,
                        kind='native_instruction_bus_completion',
                        key=dict(execution_id='other-execution', testcase_id='other-case',
                            source_component='cpu', source_epoch=0, channel_id='memory',
                            source_sequence=9),
                        producer_event_id=999,
                        binding=dict(source=dict(action_id='bootstrap-or-foreign-action'))))
                elif corruption == 'payload-digest':
                    refusal_record['write_receipt']['payload_sha256'] = '0' * 64
                    _reseal_commit(refusal_record['write_receipt'])
                elif corruption == 'memory-kind':
                    refusal_record['write_receipt']['memory_kind'] = 'unmodeled-memory'
                    _reseal_commit(refusal_record['write_receipt'])
                else:
                    refusal_record['write_receipt']['commit_id'] = '0' * 64
                report = CHECKS.check_native_source_completion_refusal(
                    events, plan, runtime_document, execution=execution,
                    refusal_record=refusal_record)
                self.assertEqual('failed', report['status'])


if __name__ == '__main__':
    unittest.main()
def test_native_source_completion_cli_is_explicit():
    import subprocess
    import sys

    script = ROOT / 'scripts' / 'verify_picorv32_native_online.py'
    result = subprocess.run(
        [sys.executable, str(script), '--help'],
        check=True, capture_output=True, text=True)
    assert '--native-source-completion' in result.stdout


def test_native_source_completion_saved_event_checker_exists():
    assert callable(getattr(CHECKS, 'check_native_source_completion_events', None))
