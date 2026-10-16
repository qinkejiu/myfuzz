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


def _pin_domain(compiled_path, *, width, mask, bounds, alignment):
    p = deepcopy(compiled_path)
    for row in (p['sources'][-1], p['constraints']['source_constraints'][-1]):
        row.update(width=width, mask=mask, range=bounds, alignment=alignment)
    return p


@pytest.mark.parametrize('mask,bounds,alignment', [(1, [2, 3], 1), (3, [1, 1], 2),
    (0x80000001, [0x80000000, 0x80000001], 5),
    (0xffffffff, [0xfffffffe, 0xffffffff], 0x80000001)])
def test_empty_source_domains_refused(compiled_path, mask, bounds, alignment):
    p = _pin_domain(compiled_path, width=32 if mask > 3 else 2,
                    mask=mask, bounds=bounds, alignment=alignment)
    with pytest.raises(CandidateLayoutError, match='source-domain-empty') as caught:
        compile_candidate_layout(p)
    assert caught.value.pointer == '/sources/2'


@pytest.mark.parametrize('mask,bounds,alignment,value', [
    (0x80000001, [0x80000000, 0x80000001], 3, 0x80000001),
    (0xffffffff, [0x80000001, 0x80000001], 0x80000001, 0x80000001),
    (0xffffffff, [0xffffffff, 0xffffffff], 3, 0xffffffff),
    (3, [0, 0], 3, 0)])
def test_nonempty_32bit_domains_encode(compiled_path, mask, bounds, alignment, value):
    p = _pin_domain(compiled_path, width=32, mask=mask, bounds=bounds, alignment=alignment)
    layout = compile_candidate_layout(p)
    values = {layout.slices[0].source_id: 0, layout.slices[1].source_id: value}
    assert layout.decode(layout.encode(values)) == values


def _many_pins(compiled_path, count, width):
    p = deepcopy(compiled_path)
    pin, mirror = p['sources'].pop(), p['constraints']['source_constraints'].pop()
    for index in range(count):
        source = deepcopy(pin); source.update(source_id=f'pin-{index}', port=f'port-{index}',
            width=width, mask=(1 << width)-1)
        constraint = deepcopy(mirror); constraint.update(source_id=source['source_id'],
            width=width, mask=source['mask'])
        p['sources'].append(source); p['constraints']['source_constraints'].append(constraint)
    return p


def test_source_count_and_raw_bits_have_explicit_budgets(compiled_path):
    from myfuzz.integration.compiled_candidate_layout import MAX_LAYOUT_SOURCES, MAX_CANDIDATE_BITS
    boundary = compile_candidate_layout(_many_pins(compiled_path, MAX_LAYOUT_SOURCES-2, 1))
    assert len(boundary.slices) == MAX_LAYOUT_SOURCES-1
    with pytest.raises(CandidateLayoutError, match='source-budget'):
        compile_candidate_layout(_many_pins(compiled_path, MAX_LAYOUT_SOURCES-1, 1))
    boundary = compile_candidate_layout(_many_pins(compiled_path, MAX_CANDIDATE_BITS//32-1, 32))
    assert boundary.bit_length == MAX_CANDIDATE_BITS
    with pytest.raises(CandidateLayoutError, match='raw-bit-budget'):
        compile_candidate_layout(_many_pins(compiled_path, MAX_CANDIDATE_BITS//32, 32))


@pytest.mark.parametrize('metadata', [float('nan'), object(), {1, 2}])
def test_non_json_metadata_has_layout_diagnostic(compiled_path, metadata):
    p = deepcopy(compiled_path); p['metadata'] = metadata
    with pytest.raises(CandidateLayoutError, match='declaration-json-invalid'):
        compile_candidate_layout(p)


def test_small_domains_match_exhaustive_reference(compiled_path):
    import random
    randomizer = random.Random(17)
    for _ in range(160):
        mask = randomizer.randrange(1, 64)
        low = randomizer.randrange(64); high = randomizer.randrange(low, 64)
        alignment = randomizer.randrange(1, 65)
        p = _pin_domain(compiled_path, width=6, mask=mask, bounds=[low, high], alignment=alignment)
        possible = any(v & ~mask == 0 and v % alignment == 0 for v in range(low, high+1))
        if possible:
            compile_candidate_layout(p)
        else:
            with pytest.raises(CandidateLayoutError, match='source-domain-empty'):
                compile_candidate_layout(p)


def test_domain_enumeration_bound_and_fast_paths():
    from unittest.mock import patch
    from myfuzz.integration.compiled_candidate_layout import _submasks, _domain_nonempty
    assert len(set(_submasks(0xffff))) == 65536
    with patch('myfuzz.integration.compiled_candidate_layout._submasks',
               side_effect=AssertionError('fast path must not enumerate')):
        assert _domain_nonempty(0x80000001, 0, 0xffffffff, 31)
        assert _domain_nonempty(0xffffffff, 0xffffffff, 0xffffffff, 3)
        assert not _domain_nonempty(0xffffffff, 1, 2, 3)
    # Dense high/low halves take the bounded MITM path, with a non-power-two modulus.
    assert _domain_nonempty(0xfffffffe, 0xfffffff0, 0xffffffff, 3)
    assert not _domain_nonempty(0xfffffffe, 0xfffffffe, 0xfffffffe, 3)
