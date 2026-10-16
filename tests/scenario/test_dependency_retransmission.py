"""D7 replay/retransmission cannot manufacture additional protocol proof.

These run the production normalizer/checker/evidence consumer over software
Runner fixtures. They do not certify a real DUT or grant active prerequisites.
"""
from copy import deepcopy
import pytest

from tests.scenario.test_ip_protocol_evidence import fixture, consumer, report


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
def test_response_projection_before_accept_cannot_certify_consumer(protocol):
    source = fixture(protocol)
    control = consumer(source)
    control.ingest(source.runner.events)
    assert len(report(control)['certificates']) == 1
    rows = deepcopy(list(source.runner.events))
    accept = next(i for i, row in enumerate(rows) if row.get('event_type') == 'transaction_accept')
    response = next(i for i, row in enumerate(rows) if row.get('event_type') == 'transaction_response')
    assert accept < response
    # Keep all measured raw rows and the complete request in place. Only
    # change the projection order: consumption cannot precede its acceptance.
    rows[accept], rows[response] = rows[response], rows[accept]
    rows[accept]['event_id'], rows[response]['event_id'] = accept + 1, response + 1
    verifier = consumer(source)
    verifier.ingest(rows)
    assert report(verifier)['certificates'] == []
    assert report(verifier)['evidence_ledger']['record_counts']['verified'] == 0


def test_native_tl_response_before_request_acceptance_cannot_certify():
    from tests.scenario.test_ip_plugin_free_fixtures import Fixture
    source = Fixture('tl-ul')
    source.session.artifact.runtime_document['raw_observation_schema_version'] = 'ip_raw_observation.v1'
    source.sample(a_valid=1, a_ready=0)
    source.sample(a_valid=1, a_ready=0, d_valid=1)
    assert source.rows('transaction_request')
    assert not source.rows('transaction_accept')
    assert source.rows('transaction_response')
    verifier = consumer(source)
    verifier.ingest(source.runner.events)
    final = report(verifier)
    assert final['certificates'] == []
    assert final['evidence_ledger']['record_counts']['verified'] == 0


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
@pytest.mark.parametrize('retransmission', ['identical_ids', 'new_ids_same_ticks'])
def test_retransmitted_journal_cannot_count_a_second_protocol_certificate(protocol, retransmission):
    source = fixture(protocol)
    rows = deepcopy(list(source.runner.events))
    verifier = consumer(source)
    verifier.ingest(rows)
    first = deepcopy(report(verifier)['certificates'])
    assert len(first) == 1  # Positive control authenticates the complete chain.
    repeated = deepcopy(rows)
    if retransmission == 'new_ids_same_ticks':
        # New journal positions do not make the same physical ticks into a
        # new request. All other raw identity/transaction content is retained.
        for row in repeated:
            row['event_id'] += len(rows)
    verifier.ingest(repeated)
    final = report(verifier)
    assert final['certificates'] == first
    assert final['evidence_ledger']['record_counts']['verified'] == 1
    assert all(record['validity'] == 'historical'
               for record in final['evidence_ledger']['records']['verified'])


@pytest.mark.parametrize('protocol', ['apb3', 'tl-ul', 'wishbone'])
def test_late_same_id_changed_content_preserves_history_but_blocks_future_proof(protocol):
    source = fixture(protocol)
    rows = deepcopy(list(source.runner.events))
    verifier = consumer(source)
    verifier.ingest(rows)
    first = deepcopy(report(verifier)['certificates'])
    assert len(first) == 1
    raw = next(row for row in rows if row.get('kind') == 'local_tick_sample')
    conflict = deepcopy(raw)
    conflict['reset_epoch'] = 1
    verifier.ingest([conflict])
    # Continue the same physical tick stream with a second legal request.
    source.sample()
    if protocol == 'tl-ul':
        source.sample(a_valid=1, a_ready=1)
        source.sample(d_valid=1)
    elif protocol == 'apb3':
        source.sample(psel=1)
        source.sample(psel=1, penable=1, pready=1)
    else:
        source.sample(cyc=1, stb=1)
        source.sample(cyc=1, ack=1)
    complete_stream = deepcopy(list(source.runner.events))
    control = consumer(source)
    control.ingest(complete_stream)
    assert len(report(control)['certificates']) == 2
    later = complete_stream[len(rows):]
    verifier.ingest(later)
    final = report(verifier)
    assert final['certificates'] == first
    assert final['evidence_ledger']['record_counts']['verified'] == 1
    assert final['journal_integrity'] is False
