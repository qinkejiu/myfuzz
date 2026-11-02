"""Pure raw44 F6 candidate admission; this module grants no execution authority."""
from dataclasses import dataclass
from hashlib import sha256
import json


def _require(condition, code):
    if not condition:
        raise ValueError('compiled-F6-layout-' + code)


def _validate_document_containers(value):
    """Reject Python container coercions before canonical JSON comparison."""
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError('compiled-F6-document-key-type')
        for item in value.values():
            _validate_document_containers(item)
    elif type(value) is list:
        for item in value:
            _validate_document_containers(item)
    elif type(value) not in (str, int, float, bool, type(None)):
        raise ValueError('compiled-F6-document-container-type')


def _decode(raw):
    _require(type(raw) is bytes, 'record-type')
    _require(len(raw) == 8, 'record-length')
    value = int.from_bytes(raw, 'little')
    _require(value >> 44 == 0, 'reserved-bits')
    words = tuple((value >> (11*i)) & 0x7ff for i in range(4))
    _require(len(set(words)) == 4, 'duplicate-word')
    return words


@dataclass(frozen=True)
class F6Candidate:
    raw: bytes
    words: tuple[int, int, int, int]

    def __post_init__(self):
        _require(type(self.words) is tuple and len(self.words) == 4
                 and all(type(w) is int for w in self.words), 'word-type')
        _require(_decode(self.raw) == self.words, 'raw-word-mismatch')


@dataclass(frozen=True)
class F6Layout:
    _canonical: str
    digest: str
    byte_length: int = 8

    def decode(self, raw):
        return F6Candidate(raw, _decode(raw))

    def document(self):
        return json.loads(self._canonical)


def compile_f6_candidate_layout(path) -> F6Layout:
    _require(type(path) is dict and path.get('flow_id') == 'F6'
             and path.get('status') == 'executable', 'path')
    contract = path.get('execution_contract')
    _require(type(contract) is dict, 'contract')
    layout = contract.get('candidate_layout')
    _validate_document_containers(layout)
    keys = {'wire_bytes', 'record_limit', 'reserved_zero_mask', 'distinct', 'seed', 'sources'}
    _require(type(layout) is dict and set(layout) == keys, 'fields')
    for key, expected in [('wire_bytes', 8), ('record_limit', 1),
                          ('reserved_zero_mask', (1 << 64)-(1 << 44))]:
        _require(type(layout[key]) is int and layout[key] == expected, key)
    _require(layout['distinct'] is True, 'distinct')
    seed = layout['seed']
    _require(type(seed) is list and len(seed) == 4
             and all(type(w) is int and 0 <= w <= 2047 for w in seed)
             and len(set(seed)) == 4, 'seed')
    sources = layout['sources']
    _require(type(sources) is list and len(sources) == 4, 'sources')
    seen = set()
    for i, source in enumerate(sources):
        _require(type(source) is dict and set(source) == {'source_id', 'bit_offset',
                 'width', 'mask', 'register', 'instruction_offset'}, 'source-fields')
        identity = source['source_id']
        _require(type(identity) is str and identity and identity not in seen, 'source-id')
        seen.add(identity)
        for key, expected in [('bit_offset', i*11), ('width', 11), ('mask', 2047),
                              ('register', 3), ('instruction_offset', 40+8*i)]:
            _require(type(source[key]) is int and source[key] == expected, 'source-' + key)
    cpu = contract.get('cpu')
    _require(type(cpu) is dict and type(cpu.get('instance_id')) is str
             and type(cpu.get('instruction_endpoint_id')) is str, 'cpu-binding')
    image = contract.get('instruction_source_id')
    _require(type(image) is str and image.endswith('.image') and len(image) > 6,
             'image-binding')
    declared = path.get('sources')
    _validate_document_containers(declared)
    _require(type(declared) is list and len(declared) == 4, 'd3-source-set')
    for source, actual in zip(sources, declared):
        expected = dict(source, origin='fuzzable', kind='cpu_instruction_operand',
            component=cpu['instance_id'], endpoint_id=cpu['instruction_endpoint_id'],
            port=image[:-6], field='imm11', alignment=1, range=[0, 2047],
            origin_ref=image, instruction_source_id=image,
            constraint_basis='compiled_F6_cpu_dma_contract.v1')
        _require(json.dumps(actual, sort_keys=True, allow_nan=False)
                 == json.dumps(expected, sort_keys=True, allow_nan=False), 'd3-source-drift')
    raw_seed = sum(w << (11*i) for i, w in enumerate(seed)).to_bytes(8, 'little')
    expected_seed = dict(kind='cpu_instruction_operands', words=seed,
                         raw8_hex=raw_seed.hex(), source_ids=[s['source_id'] for s in sources])
    _validate_document_containers(path.get('seed'))
    _require(json.dumps(path.get('seed'), sort_keys=True, allow_nan=False)
             == json.dumps(expected_seed, sort_keys=True, allow_nan=False), 'd3-seed-drift')
    canonical = json.dumps(layout, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return F6Layout(canonical, sha256(canonical.encode()).hexdigest())


def f6_seed_record(path) -> bytes:
    layout = compile_f6_candidate_layout(path)
    seed = layout.document()['seed']
    raw = sum(w << (11*i) for i, w in enumerate(seed)).to_bytes(8, 'little')
    return layout.decode(raw).raw
