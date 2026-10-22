"""Read-only F2 wire candidates preserve exact source and planned slot identity."""
from copy import deepcopy
import importlib
import importlib.util
import pytest
from tests.integration.test_compiled_f4_storage_producer import timer_loaded


@pytest.fixture(scope='module')
def inputs(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f2decoder'))[1]


def decoder(inputs):
    name='myfuzz.scenario.compiled_f2_decoder'
    assert importlib.util.find_spec(name) is not None, 'F2 decoder is not installed'
    return importlib.import_module(name).CompiledF2Decoder.from_request(
        request=inputs['request'],compiled=inputs['compiled'],run_id='f2decoder',
        schedule=('processor','peripheral'),rounds=32,result_address=0x3fffc)


def row(inputs):
    return next(p for p in inputs['compiled']['paths'] if p['flow_id']=='F2')


def wire(inputs, suffix=b'\x00'*4):
    contract=row(inputs)['execution_contract']
    return contract['address'].to_bytes(4,'little')+suffix


def test_exact_read_candidate_and_detached_document(inputs):
    dec=decoder(inputs)
    candidate=dec.decode_candidate(wire(inputs,b'\xff'*4),cursor=0x10000,case_index=0)
    assert candidate.case.path_id==row(inputs)['runtime_path_identity']['path_id']
    assert candidate.case.source.source_id==row(inputs)['runtime_path_identity']['source_ids'][0]
    assert candidate.address==row(inputs)['execution_contract']['address']
    assert candidate.unbound_bytes==b'\xff'*4
    assert candidate.candidate_bytes==wire(inputs)[:4]
    assert candidate.declaration['xor_constant']==0x5a5
    document=candidate.document();document['declaration']['xor_constant']=0
    assert candidate.document()['declaration']['xor_constant']==0x5a5
    assert dec.document()['flow_id']=='F2'


@pytest.mark.parametrize('raw', [b'',b'\0'*7,b'\0'*8,b'\0'*9])
def test_refuses_invalid_record_before_source_creation(inputs,raw):
    dec=decoder(inputs)
    with pytest.raises(ValueError):dec.decode_candidate(raw,cursor=0x10000,case_index=0)


def test_sequence_prevalidates_every_record_and_slot_budget(inputs):
    dec=decoder(inputs);valid=wire(inputs)
    with pytest.raises(ValueError):dec.decode_sequence((valid,b'\0'*8),cursor=0x10000,case_index=0)
    candidates=dec.decode_sequence((valid,valid),cursor=0x10000,case_index=0)
    assert candidates[1].case.source.address==0x10000+len(bytes.fromhex(candidates[0].declaration['code_hex']))
    with pytest.raises(ValueError):dec.decode_sequence((valid,valid),cursor=0x3ffd0,case_index=0)


def test_stale_compiled_document_refuses(inputs):
    dec=decoder(inputs)
    dec.compiled['paths'][0]['flow_name']='tampered'
    with pytest.raises(ValueError):dec.decode_candidate(wire(inputs),cursor=0x10000,case_index=0)


def test_bound_response_is_never_candidate_input(inputs):
    dec=decoder(inputs)
    a=dec.decode_candidate(wire(inputs,b'\x01'*4),cursor=0x10000,case_index=0)
    b=dec.decode_candidate(wire(inputs,b'\x02'*4),cursor=0x10000,case_index=0)
    assert a.declaration==b.declaration
    assert a.candidate_bytes==b.candidate_bytes
