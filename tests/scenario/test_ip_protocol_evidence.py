"""Protocol proof requires raw handshakes plus exact projected references."""
from copy import deepcopy

import pytest

from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
from myfuzz.scenario.runtime_path_contract import RuntimePathContract
from tests.scenario.test_ip_plugin_free_fixtures import Fixture


def fixture(protocol, *, native_error=False, max_wait=8):
    f = Fixture(protocol, max_wait=max_wait)
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.runner.set_observation_case('request-case', 0)
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=1)
    elif protocol == 'apb3':
        f.sample(psel=1)
    else:
        f.sample(cyc=1, stb=1)
    f.runner.set_observation_case('response-case', 1)
    if protocol == 'tl-ul':
        f.sample(d_valid=1, d_error=int(native_error))
    elif protocol == 'apb3':
        f.sample(psel=1, penable=1, pready=1, pslverr=int(native_error))
    else:
        f.sample(cyc=1, ack=int(not native_error), err=int(native_error))
    return f


def configuration(f):
    return {'dut': dict(component_id='opaque', instance_id='dut',
                       protocol_trace=deepcopy(f.session.artifact.runtime_document['base_protocol_trace']))}


def consumer(f, **bounds):
    proof = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    configure = getattr(proof, 'configure_protocol_events', None)
    if configure is not None:
        configure(configuration(f), **bounds)
    return proof


def report(proof):
    method = getattr(proof, 'protocol_evidence_report', None)
    return method() if method is not None else {'certificates': []}


def consume(f, rows=None, *, chunked=False, **bounds):
    proof = consumer(f, **bounds)
    rows = f.runner.events if rows is None else rows
    if chunked:
        for row in rows:
            proof.ingest([row])
    else:
        proof.ingest(rows)
    return report(proof)


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
@pytest.mark.parametrize('chunked', [False, True])
def test_exact_cross_case_request_accept_response_certifies(protocol, chunked):
    f = fixture(protocol)
    result = consume(f, chunked=chunked)
    assert len(result['certificates']) == 1
    certificate = result['certificates'][0]
    for kind, field in [('transaction_request', 'request_event_id'),
                        ('transaction_accept', 'accept_event_id'),
                        ('transaction_response', 'response_event_id')]:
        assert certificate[field] == f.rows(kind)[0]['event_id']
    evidence = certificate['evidence']
    assert evidence['evidence_type'] == 'verified'
    assert evidence['relation'] == 'protocol_transaction'
    assert evidence['scope'] == 'protocol_accept_response'
    assert evidence['validity'] == 'historical'
    assert certificate['transaction_key'] == f.rows('transaction_request')[0]['transaction_key']
    if protocol != 'tl-ul':
        assert certificate['transaction_key'] is None
        assert certificate['identity_gap'] == 'protocol_has_no_transaction_id'


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
def test_native_error_response_is_boundary_proof_with_error_outcome(protocol):
    result = consume(fixture(protocol, native_error=True))
    assert len(result['certificates']) == 1
    assert result['certificates'][0]['outcome'] == 'error'


@pytest.mark.parametrize('kind', ['transaction_request', 'transaction_accept', 'transaction_response'])
def test_removed_projection_never_certifies_even_if_raw_handshake_was_legal(kind):
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    # Preserve global cursor positions; substitute an unrelated annotation.
    original = next(row for row in rows if row.get('event_type') == kind)
    event_id = original['event_id']
    original.clear()
    original.update(event_id=event_id, kind='unrelated_annotation')
    assert consume(f, rows)['certificates'] == []


@pytest.mark.parametrize('path,value', [
    (('related_request_event_refs',), [999]),
    (('transaction_key', 'source'), 8),
    (('payload', 'signals', 'd_data'), 0x1234),
    (('reset_epoch',), 1),
    (('instance_id',), 'other'),
    (('raw_event_refs',), [999]),
])
def test_forged_response_fields_do_not_authenticate(path, value):
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    response = next(row for row in rows if row.get('event_type') == 'transaction_response')
    for key in path[:-1]:
        response = response[key]
    response[path[-1]] = value
    assert consume(f, rows)['certificates'] == []


def test_protocol_checker_is_recomputed_without_reported_findings():
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    raw = next(row for row in rows if row.get('kind') == 'local_tick_sample')
    raw['outputs']['backend']['tap_a_mask'] = 0
    assert consume(f, rows)['certificates'] == []


def test_unversioned_raw_evidence_cannot_upgrade_old_artifact():
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    for row in rows:
        if row.get('kind') == 'local_tick_sample':
            row.pop('reset_epoch', None)
            row.pop('observation_schema_version', None)
    assert consume(f, rows)['certificates'] == []


def add_second_tl_transaction(f, *, epoch=0):
    f.session.reset_epoch = epoch
    f.sample(a_valid=1, a_ready=1)
    f.sample(d_valid=1)


def test_tl_source_reuse_has_two_distinct_original_request_references():
    f = fixture('tl-ul')
    add_second_tl_transaction(f)
    certificates = consume(f)['certificates']
    assert len(certificates) == 2
    assert certificates[0]['transaction_key'] == certificates[1]['transaction_key']
    assert certificates[0]['request_raw_event_id'] != certificates[1]['request_raw_event_id']
    assert certificates[0]['evidence']['evidence_id'] != certificates[1]['evidence']['evidence_id']


def test_same_value_response_for_other_request_cannot_complete_second_transaction():
    f = fixture('tl-ul')
    add_second_tl_transaction(f)
    rows = deepcopy(list(f.runner.events))
    responses = [row for row in rows if row.get('event_type') == 'transaction_response']
    responses[-1]['related_request_event_refs'] = responses[0]['related_request_event_refs']
    assert len(consume(f, rows)['certificates']) == 1


def test_new_epoch_does_not_reuse_old_request_identity():
    f = fixture('tl-ul')
    add_second_tl_transaction(f, epoch=1)
    certificates = consume(f)['certificates']
    assert len(certificates) == 2
    assert certificates[0]['evidence']['epochs'] == {'dut': 0}
    assert certificates[1]['evidence']['epochs'] == {'dut': 1}
    assert certificates[0]['transaction_key'] != certificates[1]['transaction_key']


def test_reset_cancels_old_transaction_but_can_prove_later_legal_transaction():
    f = Fixture('tl-ul')
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.sample(a_valid=1, a_ready=1)
    f.session.reset_epoch = 1
    f.sample()
    f.sample(a_valid=1, a_ready=1)
    f.sample(d_valid=1)
    certificates = consume(f)['certificates']
    assert len(certificates) == 1
    assert certificates[0]['request_event_id'] == f.rows('transaction_request')[-1]['event_id']
    assert certificates[0]['evidence']['epochs'] == {'dut': 1}


def test_timeout_and_late_response_do_not_certify_when_reported_violation_is_removed():
    f = Fixture('tl-ul', max_wait=2)
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.sample(a_valid=1, a_ready=1)
    f.sample()
    f.sample()
    f.sample(d_valid=1)
    rows = deepcopy(list(f.runner.events))
    for row in rows:
        if row.get('event_type') == 'protocol_violation':
            event_id = row['event_id']
            row.clear()
            row.update(event_id=event_id, kind='unrelated_annotation')
    result = consume(f, rows)
    assert result['certificates'] == []
    assert result['diagnostics']['checker_violation'] >= 1


def test_accept_projection_before_request_is_not_a_valid_chain():
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    request = next(i for i, row in enumerate(rows) if row.get('event_type') == 'transaction_request')
    accept = next(i for i, row in enumerate(rows) if row.get('event_type') == 'transaction_accept')
    rows[request], rows[accept] = rows[accept], rows[request]
    rows[request]['event_id'], rows[accept]['event_id'] = request + 1, accept + 1
    assert consume(f, rows)['certificates'] == []


def test_record_capacity_and_expired_pending_never_create_replacement_witnesses():
    f = fixture('tl-ul')
    add_second_tl_transaction(f)
    result = consume(f, max_records=1)
    assert len(result['certificates']) == 1
    assert result['diagnostics']['record_limit'] == 1
    expired = consume(f, max_event_gap=2)
    assert expired['certificates'] == []
    assert expired['diagnostics']['evidence_expired'] >= 1


def test_native_outstanding_state_is_bounded_and_disabled_on_overflow():
    f = Fixture('tl-ul')
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.sample(a_valid=1, a_ready=1, a_source=1)
    f.sample(a_valid=1, a_ready=1, a_source=2)
    f.sample(d_valid=1, d_source=1)
    result = consume(f, max_pending=1)
    assert result['certificates'] == []
    assert result['counts']['pending'] <= 1
    assert result['diagnostics']['native_state_limit'] == 1


def test_journal_gap_and_conflicting_duplicate_raw_id_prevent_certification():
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    gap = deepcopy(rows)
    del gap[3]
    assert consume(f, gap)['certificates'] == []
    proof = consumer(f)
    proof.ingest(rows[:1])
    conflict = deepcopy(rows[0])
    conflict['outputs']['backend']['tap_a_source'] = 8
    proof.ingest([conflict])
    proof.ingest(rows[1:])
    assert report(proof)['certificates'] == []
    assert report(proof)['journal_integrity'] is False


def test_configuration_and_reports_are_detached_from_caller_mutation():
    f = fixture('tl-ul')
    proof = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    config = configuration(f)
    proof.configure_protocol_events(config)
    config['dut']['protocol_trace']['signals']['a_valid'] = 'forged'
    proof.ingest(f.runner.events)
    assert report(proof)['counts']['verified'] == 1
    detached = report(proof)
    detached['certificates'][0]['transaction_key']['source'] = 99
    assert report(proof)['certificates'][0]['transaction_key']['source'] == 7
    with pytest.raises(ValueError, match='configured once'):
        proof.configure_protocol_events(configuration(f))


@pytest.mark.parametrize('bound', ['max_pending', 'max_event_gap', 'max_records', 'counter_cap'])
@pytest.mark.parametrize('value', [True, 0, 65537])
def test_invalid_resource_bounds_are_rejected(bound, value):
    with pytest.raises(ValueError, match='bound-invalid'):
        consumer(fixture('tl-ul'), **{bound: value})


@pytest.mark.parametrize('provenance', [None, 'bad',
    {'observed_case': ['x'] * 10000},
    {'observed_case': {'case_id': 'x' * 1025, 'case_index': 0}},
    {'observed_case': {'case_id': 'case', 'case_index': True}},
])
def test_malformed_or_unbounded_case_metadata_cannot_enter_certificate(provenance):
    f = fixture('tl-ul')
    rows = deepcopy(list(f.runner.events))
    raw = next(row for row in rows if row.get('kind') == 'local_tick_sample')
    raw['provenance'] = provenance
    assert consume(f, rows)['certificates'] == []


def test_protocol_proofs_use_d1_ledger_and_link_frozen_declaration():
    from myfuzz.scenario.dependency_evidence import DependencyEvidenceLedger
    result = consume(fixture('tl-ul'))
    ledger = result.get('evidence_ledger')
    assert ledger is not None
    assert ledger['record_counts'] == {'declared': 1, 'candidate': 0, 'verified': 1}
    verified = ledger['records']['verified'][0]
    assert verified['declaration_ref'] == ledger['records']['declared'][0]['evidence_id']
    assert DependencyEvidenceLedger.from_document(ledger).document() == ledger


def test_protocol_configuration_is_rejected_after_even_invalid_ingest():
    f = fixture('tl-ul')
    proof = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    proof.ingest([None])
    with pytest.raises(ValueError, match='configured once'):
        proof.configure_protocol_events(configuration(f))


@pytest.mark.parametrize('digest', [None, True, 'bad', 'Z' * 64])
def test_runtime_contract_identity_must_be_canonical(digest):
    from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer
    f = fixture('tl-ul')
    with pytest.raises(ValueError, match='runtime-contract'):
        IpProtocolEvidenceConsumer(configuration(f), runtime_contract_sha256=digest)


def test_signal_names_have_a_finite_contract_bound():
    f = fixture('tl-ul')
    config = configuration(f)
    config['dut']['protocol_trace']['signals']['a_valid'] = 'x' * 1025
    proof = EdgeProvenanceConsumer(RuntimePathContract('a' * 64, (), ()))
    with pytest.raises(ValueError, match='trace-bound'):
        proof.configure_protocol_events(config)


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
def test_stalled_offer_proves_the_later_actual_acceptance(protocol):
    f = Fixture(protocol)
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    if protocol == 'tl-ul':
        f.sample(a_valid=1, a_ready=0, d_ready=0)
        f.sample(a_valid=1, a_ready=1, d_ready=0)
        f.sample(d_valid=1)
    elif protocol == 'apb3':
        f.sample(psel=1)
        f.sample(psel=1, penable=1)
        f.sample(psel=1, penable=1, pready=1)
    else:
        f.sample(cyc=1, stb=1, stall=1)
        f.sample(cyc=1, stb=1)
        f.sample(cyc=1, ack=1)
    certificates = consume(f, chunked=True)['certificates']
    assert len(certificates) == 1
    assert certificates[0]['request_raw_event_id'] != certificates[0]['accept_raw_event_id']
    assert certificates[0]['accept_event_id'] == f.rows('transaction_accept')[0]['event_id']


def test_out_of_order_tl_responses_match_each_native_source_and_original_request():
    f = Fixture('tl-ul')
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.sample(a_valid=1, a_ready=1, a_source=1)
    f.sample(a_valid=1, a_ready=1, a_source=2)
    f.sample(d_valid=1, d_source=2)
    f.sample(d_valid=1, d_source=1)
    certificates = consume(f, max_pending=2)['certificates']
    assert [row['transaction_key']['source'] for row in certificates] == [2, 1]
    requests = {row['transaction_key']['source']: row for row in f.rows('transaction_request')}
    assert certificates[0]['request_raw_event_id'] == requests[2]['raw_event_refs'][0]
    assert certificates[1]['request_raw_event_id'] == requests[1]['raw_event_refs'][0]


def test_duplicate_outstanding_source_disables_proof_without_trusting_finding_annotation():
    f = Fixture('tl-ul')
    f.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    f.sample(a_valid=1, a_ready=1)
    f.sample(a_valid=1, a_ready=1)
    f.sample(d_valid=1)
    result = consume(f)
    assert result['certificates'] == []
    assert result['diagnostics']['checker_violation'] >= 1
