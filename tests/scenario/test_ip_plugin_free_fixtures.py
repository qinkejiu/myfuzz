"""Software receipt fixtures for the L1 path; no functional-family plugin.

The local sessions supply raw signal receipts only. Production Runner,
normalizers, checker, journal, provenance and coverage consumer do the work.
These are protocol/port facts, never DUT functionality or a certified chain.
"""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimeEdgeContract, RuntimeNode, RuntimePathContract)
from myfuzz.scenario.source_provenance import SourceAdmission


WIDTHS = {
    'tl-ul': dict(a_valid=1, a_ready=1, a_source=8, a_opcode=3, a_size=2,
                  a_address=32, a_mask=4, a_data=32, d_valid=1, d_ready=1,
                  d_source=8, d_opcode=3, d_size=2, d_data=32, d_error=1),
    'apb3': dict(psel=1, penable=1, pwrite=1, paddr=12, pwdata=32,
                 pready=1, prdata=32, pslverr=1),
    'wishbone': dict(cyc=1, stb=1, we=1, adr=32, dat_w=32, sel=4,
                     ack=1, stall=1, dat_r=32, err=1),
}
KINDS = {'tl-ul': 'tlul_register_observe', 'apb3': 'apb3_register_observe',
         'wishbone': 'wishbone_register_observe'}


def artifact(protocol, *, component='opaque', instance='dut', exports=(), bound=(),
             max_wait=8):
    trace = dict(schema_version='ip_protocol_trace.v1', protocol=protocol,
                 endpoint_id='bus', clock_domain='local_clk', max_wait_cycles=max_wait,
                 signals={role: 'tap_' + role for role in WIDTHS[protocol]},
                 signal_widths=WIDTHS[protocol])
    return SimpleNamespace(runtime_document={
        'kind': KINDS[protocol], 'base_event_schema_version': 'ip_base_event.v1',
        'base_protocol_trace': trace,
        'clock_schedule': {'primary_clock_domain': 'local_clk'},
        'effective_max_wait_cycles': max_wait, 'physical_exports': list(exports),
        'bound_physical_inputs': list(bound)}, plan=SimpleNamespace(
            request=SimpleNamespace(instance_id=instance,
                                    document=lambda: {'schema_version': 'local_harness.v2'}),
            profile=SimpleNamespace(component_id=component, endpoints=(
                SimpleNamespace(endpoint_id='bus', clock='local_clk'),))))


class ReceiptSession:
    """Raw ABI observations only, with none of the functional opt-in flags."""
    reset_epoch = 0

    def __init__(self, built):
        self.artifact = built
        self.samples = []

    def drain_tick_samples(self):
        samples, self.samples = self.samples, []
        return samples


class Fixture:
    def __init__(self, protocol, *, max_wait=8):
        self.protocol = protocol
        self.session = ReceiptSession(artifact(protocol, max_wait=max_wait))
        self.runner = ScenarioRunner(sessions={'dut': self.session},
                                     ownership=compile_ownership((), ()), bindings=())
        self.runner.enable_event_journal(chunk_size=2)
        self.runner._status = 'running'
        self.coverage = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                               endpoint_protocols={'bus': protocol})

    def sample(self, *, producer_event_id=1, **signals):
        values = dict.fromkeys(WIDTHS[self.protocol], 0)
        if self.protocol == 'tl-ul':
            values.update(a_source=7, a_opcode=4, a_size=2, a_address=0x20,
                          a_mask=15, d_source=7, d_opcode=1, d_size=2, d_ready=1)
        elif self.protocol == 'wishbone':
            values.update(sel=15, adr=0x20)
        else:
            values.update(paddr=0x20)
        values.update(signals)
        tick = self.runner.local_ticks['dut'] + 1
        backend = {'tap_' + role: value for role, value in values.items()}
        self.session.samples.append(dict(local_tick=tick, pre={'backend': backend},
                                          post={'backend': dict(backend)}))
        self.runner.local_ticks['dut'] = tick
        self.runner._drain_tick_samples(producer_event_id=producer_event_id)
        cursor = self.coverage.cursor
        rows = self.runner.events_since(cursor)
        before = deepcopy(rows)
        consumed = self.coverage.consume(rows, start_cursor=cursor)
        assert rows == before
        assert [row.cursor for row in consumed] == list(range(cursor, self.coverage.cursor))
        return rows

    def rows(self, kind):
        return [row for row in self.runner.events if row.get('event_type') == kind]


def assert_l1_only(fixture):
    assert fixture.coverage.snapshot()['category'] == 'base_coverage'
    assert not any(key in fixture.coverage.snapshot() for key in
                   ('candidate_novelty', 'verified_dependency', 'functional_coverage'))
    assert not any(row.get('schema_version') in ('ip_function_event.v1',
                                               'ip_register_event.v1',
                                               'dependency_evidence.v1')
                   for row in fixture.runner.events)
    assert fixture.runner._gpio_consumption_tracker is None
    assert fixture.runner._uart_consumption_tracker is None


@pytest.mark.parametrize('protocol', tuple(WIDTHS))
def test_function_annotations_do_not_change_base_coverage_or_raw_trace(protocol):
    f = Fixture(protocol)
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=1)
        f.sample(d_valid=1)
    elif protocol == 'apb3':
        f.sample(psel=1)
        f.sample(psel=1, penable=1, pready=1)
    else:
        f.sample(cyc=1, stb=1)
        f.sample(cyc=1, ack=1)
    original = deepcopy(f.runner.events)
    annotated = []
    for row in original:
        annotated.append(row)
        annotated.append({'schema_version': 'ip_function_event.v1',
                          'event_type': 'completion', 'base_event_refs': [row['event_id']]})
    consumer = IpBaseCoverageConsumer(component_id='opaque', instance_id='dut',
                                      endpoint_protocols={'bus': protocol})
    consumer.consume(annotated, start_cursor=0)
    assert consumer.counts == f.coverage.counts
    assert consumer.diagnostics == f.coverage.diagnostics
    assert consumer.pending_count == f.coverage.pending_count
    assert annotated[::2] == original == f.runner.events


@pytest.mark.parametrize('protocol', tuple(WIDTHS))
def test_legal_raw_transaction_and_stall_feed_base_coverage_without_plugin(protocol):
    f = Fixture(protocol)
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=0)
        f.sample(a_valid=1, a_ready=1)
        f.sample(d_valid=1)
        operation, latency = 'opcode-4', '1'
    elif protocol == 'apb3':
        f.sample(psel=1)
        f.sample(psel=1, penable=1)
        f.sample(psel=1, penable=1, pready=1)
        operation, latency = 'read', '0'
    else:
        f.sample(cyc=1, stb=1, stall=1)
        f.sample(cyc=1, stb=1)
        f.sample(cyc=1, ack=1)
        operation, latency = 'read', '1'
    assert f.runner.failure_status is None
    assert f.runner._status == 'running'
    assert f.coverage.counts[f'transaction:bus:{operation}'] == 1
    # TL also observes a D wait on the accepting edge; the A stall remains
    # separately identified by its channel and raw reference.
    assert f.coverage.counts['event:bus:wait_observation'] == (2 if protocol == 'tl-ul' else 1)
    waits = f.rows('wait_observation')
    if protocol == 'tl-ul':
        assert [row['payload']['channel'] for row in waits] == ['A', 'D']
    assert f.coverage.counts['event:bus:transaction_accept'] == 1
    assert f.coverage.counts['response:bus:ok'] == 1
    assert f.coverage.counts[f'latency:bus:{latency}'] == 1
    request, response = f.rows('transaction_request')[0], f.rows('transaction_response')[0]
    assert response['related_request_event_refs'] == request['raw_event_refs']
    raw_by_id = {row['event_id']: row for row in f.runner.events}
    for row in (request, response):
        assert raw_by_id[row['raw_event_refs'][0]]['kind'] == 'local_tick_sample'
    if protocol == 'tl-ul':
        assert response['transaction_key']['source'] == 7
        assert response['native_identity'] == {'channel': 'D', 'source': 7}
    else:
        assert request['transaction_key'] is response['transaction_key'] is None
        assert request['native_identity'] is response['native_identity'] is None
        assert response['identity_gap'] == 'protocol_has_no_transaction_id'
    before = f.coverage.snapshot()
    assert f.coverage.consume(f.runner.events, start_cursor=0) == ()
    assert f.coverage.snapshot() == before
    assert_l1_only(f)


@pytest.mark.parametrize(('protocol', 'signals', 'violation'), (
    ('tl-ul', {'a_valid': 1, 'a_ready': 1, 'a_opcode': 2}, 'tlul_unsupported_opcode'),
    ('apb3', {'psel': 1, 'penable': 1, 'pready': 1}, 'apb_access_without_setup'),
    ('wishbone', {'cyc': 1, 'ack': 1}, 'wishbone_response_without_request')))
def test_illegal_transaction_is_recorded_and_runner_fails_closed(protocol, signals, violation):
    f = Fixture(protocol)
    f.sample(**signals)
    finding = f.rows('protocol_violation')[0]
    assert finding['payload']['violation_code'] == violation
    assert f.runner.failure_status == 'protocol_violation'
    assert f.runner._status == 'failed'
    raw = next(row for row in f.runner.events
               if row['event_id'] == finding['raw_event_refs'][0])
    assert raw['kind'] == 'local_tick_sample' and raw['phase'] == 'pre'
    assert_l1_only(f)


@pytest.mark.parametrize('protocol', tuple(WIDTHS))
def test_native_error_response_is_distinct_from_checker_protocol_violation(protocol):
    f = Fixture(protocol)
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=1)
        f.sample(d_valid=1, d_error=1)
    elif protocol == 'apb3':
        f.sample(psel=1)
        f.sample(psel=1, penable=1, pready=1, pslverr=1)
    else:
        f.sample(cyc=1, stb=1)
        f.sample(cyc=1, err=1)
    assert f.coverage.counts['response:bus:error'] == 1
    assert f.coverage.counts['event:bus:protocol_error'] == 1
    assert 'response:bus:ok' not in f.coverage.counts
    assert f.rows('protocol_violation') == []
    assert f.runner.failure_status is None
    assert_l1_only(f)


def test_duplicate_native_source_keeps_original_request_and_accepts_once():
    f = Fixture('tl-ul')
    f.sample(a_valid=1, a_ready=1)
    original = f.rows('transaction_request')[0]
    f.sample(a_valid=1, a_ready=1)
    duplicate = f.rows('transaction_duplicate')[0]
    assert duplicate['transaction_key'] == original['transaction_key']
    assert duplicate['native_identity']['source'] == 7
    assert f.coverage.counts['event:bus:transaction_accept'] == 1
    assert f.coverage.counts['event:bus:transaction_duplicate'] == 1
    assert f.rows('protocol_violation')[0]['payload']['violation_code'] == 'tlul_source_already_outstanding'
    f.sample(d_valid=1)
    assert f.rows('transaction_response')[0]['related_request_event_refs'] == original['raw_event_refs']
    assert f.coverage.counts['response:bus:ok'] == 1
    assert f.runner.failure_status == 'protocol_violation'
    assert_l1_only(f)


@pytest.mark.parametrize('protocol', tuple(WIDTHS))
def test_reset_cancels_previous_work_and_old_response_cannot_supply_latency(protocol):
    f = Fixture(protocol)
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=1)
    elif protocol == 'apb3':
        f.sample(psel=1)
    else:
        f.sample(cyc=1, stb=1)
    request = f.rows('transaction_request')[0]
    f.session.reset_epoch = 1
    f.sample()
    cancellation = f.rows('transaction_cancel')[0]
    assert cancellation['reset_epoch'] == 0
    assert cancellation['related_request_event_refs'] == request['raw_event_refs']
    assert cancellation['payload']['to_reset_epoch'] == 1
    assert f.coverage.pending_count == 0
    if protocol == 'tl-ul':
        f.sample(d_valid=1)
    elif protocol == 'apb3':
        f.sample(psel=1, penable=1, pready=1)
    else:
        f.sample(cyc=1, ack=1)
    response = f.rows('transaction_response')[0]
    assert response['reset_epoch'] == 1
    assert response['related_request_event_refs'] != request['raw_event_refs']
    if protocol == 'apb3':
        # With no native ID, the projector links the new illegal access to its
        # own raw row. The checker diagnoses missing setup; it cannot recover
        # the cancelled transaction from this matching address/value.
        assert response['related_request_event_refs'] == response['raw_event_refs']
        assert f.coverage.counts['latency:bus:0'] == 1
        assert f.rows('protocol_violation')[0]['payload']['violation_code'] == 'apb_access_without_setup'
    else:
        assert response['related_request_event_refs'] == []
        assert not any(key.startswith('latency:') for key in f.coverage.counts)
        assert f.coverage.diagnostics['latency_uncorrelated'] == 1
    assert f.runner.failure_status == 'protocol_violation'
    assert_l1_only(f)


def test_late_response_after_timeout_remains_failed_and_source_is_reserved():
    f = Fixture('tl-ul', max_wait=1)
    f.sample(a_valid=1, a_ready=1, d_ready=0)
    original = f.rows('transaction_request')[0]
    f.sample()
    timeout = f.rows('transaction_timeout')[0]
    assert timeout['related_request_event_refs'] == original['raw_event_refs']
    f.sample(a_valid=1, a_ready=1, d_ready=0)
    assert f.rows('transaction_duplicate')[0]['payload']['reason'] == 'source_id_not_released_after_timeout'
    assert f.coverage.counts['event:bus:transaction_accept'] == 1
    f.sample(d_valid=1)
    response = f.rows('transaction_response')[0]
    assert response['related_request_event_refs'] == original['raw_event_refs']
    assert response['payload']['signals']['matched_timed_out'] is True
    assert response['payload']['signals']['matched_outstanding'] is False
    assert f.coverage.diagnostics['late_response'] == 1
    assert f.runner.failure_status == 'protocol_violation'
    assert f.runner._status == 'failed'
    assert_l1_only(f)


def test_cross_case_binding_consumption_retains_source_action_and_raw_case_chain():
    output = dict(endpoint_id='bus', role='output', physical_port='out',
                  runtime_name='rt_out', direction='output', encoding='integer',
                  bit_lo=0, bit_hi=0, width=1)
    pin = dict(endpoint_id='bus', role='pin', physical_port='pin',
               runtime_name='rt_pin', direction='input', encoding='integer',
               bit_lo=0, bit_hi=0, width=1)
    bound = dict(endpoint_id='bus', role='pin', input_name='bus.pin',
                 runtime_name='rt_pin', width=1, producer_ref='source.out')
    source = ReceiptSession(artifact('apb3', component='opaque_source', instance='source0',
                                    exports=(output,)))
    target = ReceiptSession(artifact('apb3', component='opaque_target', instance='target0',
                                    exports=(pin,), bound=(bound,)))
    ownership = compile_ownership(
        (InputField('source', 'external', 1), InputField('target', 'bus.pin', 1)),
        (InputOwner('source', 'external', 0, 1, 'source', 'external.bits'),
         InputOwner('target', 'bus.pin', 0, 1, 'bound', 'source.out')))
    for session in (source, target):
        session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    runner = ScenarioRunner(sessions={'source': source, 'target': target},
                            ownership=ownership,
                            bindings=(Binding('source', 'out', 'target', 'bus.pin', 1),))
    runner.enable_event_journal(chunk_size=2)
    graph = DependencyGraph(
        sources=(FuzzableSource('input', 'source', 'external', 0, 1, ('IP_TO_IP',)),),
        rules=(DependencyRule('output', ('input',), 'EVENT_ORDER'),
               DependencyRule('consume', ('output',), 'DATA_BINDING')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                                       separators=(',', ':')).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('input', 'source', 'physical', 'external', 0, 1),
        RuntimeNode('output', 'source', 'physical', 'out', 0, 1),
        RuntimeNode('consume', 'target', 'physical', 'bus.pin', 0, 1)),
        (RuntimeEdgeContract(1, 0, 'direct_binding'),))
    paths = tuple(('IP_TO_IP', path) for path in graph.edge_paths_to('consume', direction='IP_TO_IP'))
    prepared = PreparedRuntimePathContract(graph, contract, paths)
    runner.configure_provenance(RuntimeEdgeIndex(
        {**prepared.bind(runner).document(), 'declaration': prepared.document()},
        contract.document()))
    admission = SourceAdmission.create(
        case_id='source-case', case_index=0, source_id='input',
        path_id=prepared.path_ids[0], direction='IP_TO_IP', component='source',
        action_id='source-action', role='fuzz_source', input_kind='source_event',
        input_sha256=hashlib.sha256(b'\x01').hexdigest())
    runner.register_source_admission(admission)
    runner._status = 'running'
    runner.set_observation_case('source-case', 0)
    runner.inject_source('source', 'external', 1, direction='IP_TO_IP', action_id=admission.action_id)
    injection = runner.events[-1]
    assert injection['provenance']['origin_admission_ids'] == [admission.admission_id]
    backend = {'tap_' + role: 0 for role in WIDTHS['apb3']}
    source.samples = [dict(local_tick=1,
                           pre={'out': 1, 'backend': backend, 'physical': {'rt_out': 1}},
                           post={'out': 1, 'backend': backend, 'physical': {'rt_out': 1}})]
    runner.local_ticks['source'] = 1
    runner._drain_tick_samples(producer_event_id=injection['event_id'])
    # Both receipt phases route an observed output. The target keeps the
    # latest exact delivery, so use the post-edge record it actually samples.
    delivery = [row for row in runner.events if row.get('event_type') == 'binding_delivery'][-1]
    assert delivery['provenance']['observed_case'] == {'case_id': 'source-case', 'case_index': 0}
    consumer = IpBaseCoverageConsumer(component_id='opaque_target', instance_id='target0',
                                      endpoint_protocols={'bus': 'apb3'}, physical_exports=(pin,),
                                      targets=(CoverageTarget('sampled_pin', 'target', 'rt_pin', 1, 1),))
    consumer.consume(runner.events_since(0), start_cursor=0)
    boundary = consumer.cursor
    before = deepcopy(runner.events)
    runner.set_observation_case('consumer-case', 1)
    target.samples = [dict(local_tick=1,
                           pre={'backend': backend, 'physical': {'rt_pin': 1}},
                           post={'backend': backend, 'physical': {'rt_pin': 1}})]
    runner.local_ticks['target'] = 1
    runner._drain_tick_samples(producer_event_id=delivery['event_id'])
    consumed = consumer.consume(runner.events_since(boundary), start_cursor=boundary)
    sample = next(row.event for row in consumed if row.event.get('event_type') == 'input_sample')
    assert sample['provenance']['observed_case'] == {'case_id': 'consumer-case', 'case_index': 1}
    assert sample['binding_delivery_event_id'] == delivery['event_id']
    rows = {row['event_id']: row for row in runner.events}
    source_raw = rows[delivery['raw_event_refs'][0]]
    assert source_raw['provenance']['observed_case']['case_id'] == 'source-case'
    assert source_raw['producer_event_id'] == injection['event_id']
    assert injection['action_id'] == admission.action_id
    assert admission.case_id == 'source-case'
    assert rows[sample['raw_event_refs'][0]]['component'] == 'target'
    assert runner.events[:boundary] == before
    assert consumer.counts == {'target:sampled_pin': 2}
    assert consumer.snapshot()['category'] == 'base_coverage'
    # Command scope and explicit binding are retained. An EVENT_ORDER
    # declaration never proves that the source action caused an output bit.
    assert sample['action_ref'] is None
    assert sample['provenance']['origin_status'] == 'unknown'
    assert runner._gpio_consumption_tracker is None
    assert runner._uart_consumption_tracker is None
    assert not any(row.get('schema_version') in ('ip_function_event.v1', 'dependency_evidence.v1')
                   for row in runner.events)

    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer, EdgeEndpoints
    endpoint_nodes = {node.node_id: node for node in contract.nodes}
    proof = EdgeProvenanceConsumer(contract, endpoints={
        (1, 0): EdgeEndpoints(endpoint_nodes['output'], endpoint_nodes['consume'])})
    proof.configure_base_events({
        'source': dict(component_id='opaque_source', instance_id='source0',
                       endpoint_clock_domains={'bus': 'local_clk'}, physical_exports=[output]),
        'target': dict(component_id='opaque_target', instance_id='target0',
                       endpoint_clock_domains={'bus': 'local_clk'}, physical_exports=[pin],
                       bound_physical_inputs=[bound]),
    })
    for event in runner.events:
        proof.ingest([event])
    certified = proof.report()['edges'][0]
    assert certified['status'] == 'certified'
    assert certified['hops'][-1]['raw_input_event_id'] == sample['raw_event_refs'][0]
    assert certified['hops'][-1]['base_delivery_event_id'] == delivery['event_id']
    assert certified['hops'][0]['event_id'] == source_raw['event_id']


@pytest.mark.parametrize('protocol', tuple(WIDTHS))
def test_protocol_request_and_response_cross_case_keep_original_raw_request(protocol):
    f = Fixture(protocol)
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    runner = f.runner
    runner._status = 'created'
    runner.ownership = compile_ownership((InputField('dut', 'external', 1),),
                                         (InputOwner('dut', 'external', 0, 1,
                                                     'source', 'external.bits'),))
    graph = DependencyGraph(
        sources=(FuzzableSource('input', 'dut', 'external', 0, 1, ('IP_TO_IP',)),),
        rules=(DependencyRule('observe', ('input',), 'EVENT_ORDER'),))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                                       separators=(',', ':')).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('input', 'dut', 'physical', 'external', 0, 1),
        RuntimeNode('observe', 'dut', 'physical', 'out', 0, 1)), ())
    paths = tuple(('IP_TO_IP', path) for path in graph.edge_paths_to('observe', direction='IP_TO_IP'))
    prepared = PreparedRuntimePathContract(graph, contract, paths)
    runner.configure_provenance(RuntimeEdgeIndex(
        {**prepared.bind(runner).document(), 'declaration': prepared.document()},
        contract.document()))
    admission = SourceAdmission.create(
        case_id='request-case', case_index=0, source_id='input',
        path_id=prepared.path_ids[0], direction='IP_TO_IP', component='dut',
        action_id='request-action', role='fuzz_source', input_kind='source_event',
        input_sha256=hashlib.sha256(b'\x01').hexdigest())
    runner.register_source_admission(admission)
    runner._status = 'running'
    runner.set_observation_case('request-case', 0)
    runner.inject_source('dut', 'external', 1, direction='IP_TO_IP', action_id=admission.action_id)
    injection = runner.events[-1]
    if protocol == 'tl-ul':
        f.sample(producer_event_id=injection['event_id'], a_valid=1, a_ready=1)
    elif protocol == 'apb3':
        f.sample(producer_event_id=injection['event_id'], psel=1)
    else:
        f.sample(producer_event_id=injection['event_id'], cyc=1, stb=1)
    request = f.rows('transaction_request')[0]
    boundary = f.coverage.cursor
    previous = deepcopy(runner.events)
    runner.set_observation_case('response-case', 1)
    if protocol == 'tl-ul':
        f.sample(d_valid=1)
    elif protocol == 'apb3':
        f.sample(psel=1, penable=1, pready=1)
    else:
        f.sample(cyc=1, ack=1)
    response = f.rows('transaction_response')[0]
    assert request['provenance']['observed_case'] == {'case_id': 'request-case', 'case_index': 0}
    assert response['provenance']['observed_case'] == {'case_id': 'response-case', 'case_index': 1}
    assert response['related_request_event_refs'] == request['raw_event_refs']
    original_raw = next(row for row in runner.events if row['event_id'] == request['raw_event_refs'][0])
    assert original_raw['producer_event_id'] == injection['event_id']
    assert original_raw['provenance']['observed_case']['case_id'] == admission.case_id
    assert injection['action_id'] == admission.action_id
    assert injection['provenance']['origin_admission_ids'] == [admission.admission_id]
    assert runner.events[:boundary] == previous
    assert f.coverage.counts['response:bus:ok'] == 1
    assert f.coverage.pending_count == 0
    assert f.coverage.consume(runner.events_since(boundary), start_cursor=boundary) == ()
    assert runner.failure_status is None
    # The exact request ref proves transaction correlation across cases. It
    # does not make a declared input-to-output relation a verified dependency.
    assert response['action_ref'] is None and response['source_ref'] is None
    assert response['provenance']['origin_status'] == 'unknown'
    assert_l1_only(f)
    from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
    proof = EdgeProvenanceConsumer(contract)
    proof.configure_protocol_events({'dut': dict(component_id='opaque', instance_id='dut',
        protocol_trace=f.session.artifact.runtime_document['base_protocol_trace'])})
    for event in runner.events:
        proof.ingest([event])
    certificates = proof.protocol_evidence_report()['certificates']
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate['request_raw_event_id'] == request['raw_event_refs'][0]
    assert certificate['response_raw_event_id'] == response['raw_event_refs'][0]
    assert certificate['request_case'] == {'case_id': 'request-case', 'case_index': 0}
    assert certificate['response_case'] == {'case_id': 'response-case', 'case_index': 1}
    assert certificate['evidence']['validity'] == 'historical'
    # EVENT_ORDER input->output was not silently promoted into a topology edge.
    assert proof.report()['edges'] == []


def test_versioned_raw_observations_freeze_actual_session_epoch():
    f = Fixture('apb3')
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.session.reset_epoch = 4
    f.sample()
    raw = [row for row in f.runner.events if row.get('kind') == 'local_tick_sample']
    assert raw
    assert all(row.get('observation_schema_version') == 'ip_raw_observation.v1' for row in raw)
    assert all(row.get('reset_epoch') == 4 for row in raw)


def test_old_artifacts_keep_their_raw_observation_envelope():
    f = Fixture('apb3')
    f.sample()
    raw = [row for row in f.runner.events if row.get('kind') == 'local_tick_sample']
    assert raw
    assert all('observation_schema_version' not in row and 'reset_epoch' not in row for row in raw)
