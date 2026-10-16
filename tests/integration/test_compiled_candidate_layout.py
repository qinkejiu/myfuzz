"""Software only checks for declaration bound F4 candidate bytes."""
from copy import deepcopy
import pytest
from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout, CandidateLayoutError
from tests.integration.test_compiled_f4 import loaded


@pytest.fixture(scope="module")
def compiled_path(tmp_path_factory):
    _, inputs = loaded(tmp_path_factory.mktemp("candidate-layout"))
    return next(p for p in inputs['compiled']['paths'] if p['flow_id'] == 'F4')


def test_real_schema_roundtrip_and_independent_sources(compiled_path):
    p = deepcopy(compiled_path)
    layout = compile_candidate_layout(p)
    ids = [s['source_id'] for s in p['sources'] if s['kind'] != 'instruction_image']
    assert layout.byte_length == 8
    assert layout.decode(layout.encode(dict(zip(ids, [0x12345678, 0xaabbccdd])))) == dict(zip(ids, [0x12345678, 0xaabbccdd]))
    assert layout.digest == compile_candidate_layout(deepcopy(p)).digest
    extra = deepcopy(p['sources'][-1]); extra['source_id'] = 'different'; extra['port'] = 'other_pin'
    p['sources'].append(extra)
    constraint = deepcopy(p['constraints']['source_constraints'][-1]); constraint['source_id'] = 'different'
    p['constraints']['source_constraints'].append(constraint)
    layout = compile_candidate_layout(p)
    assert layout.byte_length == 12
    assert [s.raw_bit_offset for s in layout.slices] == [0, 32, 64]
    assert layout.decode(layout.encode(dict(zip(ids + ['different'], [1, 2, 3])))) == dict(zip(ids + ['different'], [1, 2, 3]))


@pytest.mark.parametrize('alter,code', [
    (lambda p: p.update(seed=12), 'seed-unsupported'),
    (lambda p: [row.update(origin='bound') for row in (p['sources'][-1], p['constraints']['source_constraints'][-1])], 'source-ownership'),
    (lambda p: p['constraints']['source_constraints'][-1].update(mask=1), 'constraint-mismatch'),
    (lambda p: p['sources'][0].update(mask=1), 'constraint-mismatch'),
    (lambda p: p['constraints'].update(register_field_constraints=[{}]), 'register-constraints-unsupported'),
])
def test_refuses_unknown_or_conflicting_declarations(compiled_path, alter, code):
    p = deepcopy(compiled_path); alter(p)
    with pytest.raises(CandidateLayoutError, match=code): compile_candidate_layout(p)


def test_invalid_classification_and_pin_range_padding(compiled_path):
    p = deepcopy(compiled_path)
    for row in (p['sources'][-1], p['constraints']['source_constraints'][-1]):
        row.update(width=3, mask=7, range=[1, 5], alignment=1)
    layout = compile_candidate_layout(p)
    ids = [s.source_id for s in layout.slices]
    assert layout.byte_length == 5
    assert layout.classify(b'').code == 'record-length'
    assert layout.classify(bytes(5)).code == 'value-range'
    assert layout.classify(bytes(4) + b'\x81').code == 'record-padding'
    for bad in ({ids[0]: 1}, {ids[0]: True, ids[1]: 2}, {ids[0]: 1 << 32, ids[1]: 2}, {ids[0]: 1, ids[1]: 6}):
        with pytest.raises(CandidateLayoutError): layout.encode(bad)
    assert layout.classify(layout.encode({ids[0]: 1, ids[1]: 3})).valid


def test_overlapping_physical_pins_refused(compiled_path):
    p = deepcopy(compiled_path)
    source = deepcopy(p['sources'][-1]); source['source_id'] = 'alias'
    constraint = deepcopy(p['constraints']['source_constraints'][-1]); constraint['source_id'] = 'alias'
    p['sources'].append(source); p['constraints']['source_constraints'].append(constraint)
    with pytest.raises(CandidateLayoutError, match='source-ownership-overlap'):
        compile_candidate_layout(p)


def test_derived_image_shape_and_identity_bound(compiled_path):
    p = deepcopy(compiled_path)
    p['sources'][0]['width'] = 32
    p['constraints']['source_constraints'][0]['width'] = 32
    with pytest.raises(CandidateLayoutError, match='derived-image-unsupported'):
        compile_candidate_layout(p)
    p = deepcopy(compiled_path)
    original = compile_candidate_layout(p)
    p['sources'][-1]['component'] = 'new-owner'
    assert compile_candidate_layout(p).digest != original.digest


@pytest.mark.parametrize("alter", [
    lambda p: p.update(constraints=[]),
    lambda p: [row.update(register_access=[]) for row in (p['sources'][1], p['constraints']['source_constraints'][1])],
    lambda p: p['sources'][-1].update(unknown_semantics=True),
])
def test_malformed_or_unknown_semantics_refused(compiled_path, alter):
    p = deepcopy(compiled_path); alter(p)
    with pytest.raises(CandidateLayoutError):
        compile_candidate_layout(p)
