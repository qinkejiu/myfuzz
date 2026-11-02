"""Pure F6 admission tests; no native execution is implied."""
from dataclasses import FrozenInstanceError
import importlib
import importlib.util

import pytest


def module():
    name = 'myfuzz.integration.compiled_f6_layout'
    assert importlib.util.find_spec(name) is not None, 'F6 layout is not installed'
    return importlib.import_module(name)


def raw(words):
    return sum(v << (11*i) for i, v in enumerate(words)).to_bytes(8, 'little')


def declared_path(seed=(1, 2, 3, 4)):
    slices = [dict(source_id=f'cpu.f6.word{i}', bit_offset=i*11, width=11,
                   mask=2047, register=3, instruction_offset=40+8*i) for i in range(4)]
    source_id = 'ram.image'
    sources = [dict(s, origin='fuzzable', kind='cpu_instruction_operand', component='cpu',
        endpoint_id='processor.instruction', port='ram', field='imm11', alignment=1,
        range=[0, 2047], origin_ref=source_id, instruction_source_id=source_id,
        constraint_basis='compiled_F6_cpu_dma_contract.v1') for s in slices]
    return dict(flow_id='F6', status='executable', path_id='f6', sources=sources,
                seed=dict(kind='cpu_instruction_operands', words=list(seed),
                          raw8_hex=raw(seed).hex(), source_ids=[s['source_id'] for s in slices]),
                execution_contract=dict(cpu=dict(instance_id='cpu', instruction_endpoint_id='processor.instruction'),
                    instruction_source_id=source_id, candidate_layout=dict(wire_bytes=8, record_limit=1,
                    reserved_zero_mask=((1 << 64)-(1 << 44)), distinct=True,
                    seed=list(seed), sources=slices)))


@pytest.mark.parametrize('words', [(0, 1, 1024, 2047), (2047, 1024, 1, 0), (1, 2, 3, 4)])
def test_bit_boundaries_and_frozen_candidate(words):
    api = module()
    layout = api.compile_f6_candidate_layout(declared_path())
    candidate = layout.decode(raw(words))
    assert candidate.raw == raw(words) and candidate.words == words
    with pytest.raises(FrozenInstanceError):
        candidate.words = (4, 3, 2, 1)
    document = layout.document()
    document['seed'][0] = 100
    assert layout.document()['seed'] == [1, 2, 3, 4]


@pytest.mark.parametrize('record', [b'', bytes(7), bytes(9), bytearray(8), True,
    (1 << 44).to_bytes(8, 'little'), (1 << 63).to_bytes(8, 'little'),
    bytes(8), raw((1, 2, 1, 4))])
def test_invalid_raw_refused(record):
    layout = module().compile_f6_candidate_layout(declared_path())
    with pytest.raises(ValueError):
        layout.decode(record)


@pytest.mark.parametrize('field,value', [('wire_bytes', True), ('wire_bytes', 7),
    ('record_limit', 2), ('distinct', 1), ('reserved_zero_mask', 0),
    ('seed', [0, 0, 0, 0]), ('seed', [True, 2, 3, 4]), ('seed', [2048, 2, 3, 4])])
def test_layout_refuses_declaration_drift(field, value):
    path = declared_path()
    path['execution_contract']['candidate_layout'][field] = value
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)


@pytest.mark.parametrize('field,value', [('width', True), ('width', 12), ('mask', 4095),
    ('register', 4), ('instruction_offset', 44), ('bit_offset', 1)])
def test_source_slice_cannot_change_encoding(field, value):
    path = declared_path()
    path['execution_contract']['candidate_layout']['sources'][0][field] = value
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)


def test_seed_is_declaration_owned_and_candidate_constructor_is_checked():
    api = module()
    path = declared_path((8, 16, 32, 64))
    assert api.f6_seed_record(path) == raw((8, 16, 32, 64))
    with pytest.raises(ValueError):
        api.F6Candidate(raw((1, 2, 3, 4)), (1, 2, 3, True))
    with pytest.raises(ValueError):
        api.F6Candidate(raw((1, 2, 3, 4)), (1, 2, 3, 5))


@pytest.mark.parametrize('field,value', [('component', 'other'), ('kind', 'dma_transfer_descriptor'),
    ('instruction_source_id', 'other.image'), ('width', True), ('instruction_offset', 0),
    ('origin', 'bound'), ('port', ''), ('field', 'imm12')])
def test_d3_operand_source_must_match_bound_cpu_image_and_layout(field, value):
    path = declared_path()
    path['sources'][0][field] = value
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)


def test_d3_seed_and_source_set_cannot_drift():
    path = declared_path()
    path['seed']['words'][0] = 5
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)
    path = declared_path(); path['sources'].pop()
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)


@pytest.mark.parametrize('container', ['seed.words', 'seed.source_ids', 'source.range'])
def test_protocol_arrays_refuse_tuple_containers(container):
    path = declared_path()
    owner, key = ((path['sources'][0], 'range') if container == 'source.range'
                  else (path['seed'], container.split('.')[1]))
    owner[key] = tuple(owner[key])
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)


@pytest.mark.parametrize('container', ['seed', 'source'])
def test_protocol_objects_refuse_dict_subclasses(container):
    class DerivedDict(dict):
        pass
    path = declared_path()
    if container == 'seed':
        path['seed'] = DerivedDict(path['seed'])
    else:
        path['sources'][0] = DerivedDict(path['sources'][0])
    with pytest.raises(ValueError):
        module().compile_f6_candidate_layout(path)
