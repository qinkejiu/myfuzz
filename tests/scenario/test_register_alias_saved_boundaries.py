"""Closed saved alias comparison data from actual software private evidence."""
from copy import deepcopy
import hashlib
import json
import pytest
from myfuzz.scenario.register_program_verifier import validate_register_program_verifier_session_document
from tests.scenario.test_register_alias_verifier import alias_environments, alias_fixture


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


@pytest.fixture(scope='module')
def actual_alias_documents(alias_environments):
    documents = {}
    for operation in ('set_bits', 'clear_bits'):
        fixture = alias_fixture(alias_environments, operation=operation)
        document = json.loads(canonical(fixture['verifier'].session_document()))
        aliases = [c for c in document['state']['current_certificates']
                   if c['case_id'] == 'alias']
        assert len(aliases) == 1, document['state']['gaps']
        assert aliases[0]['rule'] == 'ordinary_register_alias_readback.v1'
        documents[operation] = (document, fixture['runtime'].configuration())
    return documents


@pytest.mark.parametrize('operation', ['set_bits', 'clear_bits'])
def test_actual_alias_saved_document_is_closed_detached_comparison(actual_alias_documents, operation):
    document, configuration = actual_alias_documents[operation]
    parsed = validate_register_program_verifier_session_document(document, configuration=configuration)
    assert parsed == document and parsed is not document
    parsed['state']['current_certificates'].clear()
    assert document['state']['current_certificates']


def rehash_alias(document, mutate):
    cert = next(c for c in document['state']['historical_certificates'] if c['case_id'] == 'alias')
    old = cert['evidence_id']
    mutate(cert)
    cert['evidence_id'] = hashlib.sha256(canonical({k: v for k, v in cert.items()
                                                 if k != 'evidence_id'}).encode()).hexdigest()
    for index, current in enumerate(document['state']['current_certificates']):
        if current['evidence_id'] == old:
            document['state']['current_certificates'][index] = deepcopy(cert)
    for snapshot in document['verified_capabilities'].values():
        for operation in snapshot['operations']:
            operation['evidence_refs'] = [ref.replace(old, cert['evidence_id'])
                                          for ref in operation['evidence_refs']]


@pytest.mark.parametrize('mutation', ['operation', 'width_bool', 'width_float', 'width16',
    'source', 'destination', 'destination_field', 'endpoint', 'extra_relation',
    'evidence', 'expected_value', 'missing_before_commit', 'forged_before_commit',
    'forged_after_commit', 'before_after_swap', 'foreign_source_epoch',
    'foreign_target_epoch', 'foreign_memory_generation', 'after_wrong_offset',
    'before_wrong_offset', 'wrong_untouched_bits', 'storage_grant'])
def test_self_consistently_rehashed_alias_tampering_is_rejected(actual_alias_documents, mutation):
    document, configuration = actual_alias_documents['set_bits']
    changed = deepcopy(document)
    def mutate(cert):
        result = cert['result']; relation = result['alias_relation']
        if mutation == 'operation': relation['operation'] = 'clear_bits'
        elif mutation == 'width_bool': relation['bus_width'] = True
        elif mutation == 'width_float': relation['bus_width'] = 32.0
        elif mutation == 'width16': relation['bus_width'] = 16
        elif mutation == 'source': relation['source_register'] = 'PADOUTCLR'
        elif mutation == 'destination': relation['destination_register'] = 'PADDIR'
        elif mutation == 'destination_field': relation['destination_field'] = 'invented'
        elif mutation == 'endpoint': relation['endpoint_id'] = 'foreign.bus'
        elif mutation == 'extra_relation': relation['saved_authority'] = True
        elif mutation == 'evidence': relation['evidence_ref'] = 'invented-source'
        elif mutation == 'expected_value': result['expected_value'] ^= 2
        elif mutation == 'missing_before_commit': del result['before_result_commit']
        elif mutation == 'forged_before_commit': result['before_result_commit']['commit_id'] = '0' * 64
        elif mutation == 'forged_after_commit': result['after_result_commit']['commit_id'] = '1' * 64
        elif mutation == 'before_after_swap':
            result['before_readback_access'], result['after_readback_access'] = (
                result['after_readback_access'], result['before_readback_access'])
        elif mutation == 'foreign_source_epoch':
            result['after_readback_access']['association']['source_transaction']['source_epoch'] += 1
        elif mutation == 'foreign_target_epoch':
            result['after_readback_access']['association']['target_reset_epoch'] += 1
        elif mutation == 'foreign_memory_generation':
            result['after_readback_access']['association']['memory_generation'] += 1
        elif mutation == 'after_wrong_offset': result['after_readback_access']['receipt']['delivery_context']['offset'] = 0
        elif mutation == 'before_wrong_offset': result['before_readback_access']['receipt']['delivery_context']['offset'] = 0
        elif mutation == 'wrong_untouched_bits': result['after_readback_access']['cpu_response'][0] ^= 2
        elif mutation == 'storage_grant': cert['grants_storage'] = True
    rehash_alias(changed, mutate)
    with pytest.raises(ValueError, match='invalid-register-verifier-session-document|ordinary-access-'):
        validate_register_program_verifier_session_document(changed, configuration=configuration)
