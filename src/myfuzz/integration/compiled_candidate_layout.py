"""Pure bounded F4 candidate layout; grants no execution authority.

Values are target words or pin values keyed by exact D3 source_id. Bits are
packed little endian in source declaration order, with zero final padding.
The current one word plus 32 pin bits has the historical eight byte encoding;
additional pins have independent slices, and narrower pins use fewer bits.
Instruction images identify derived writer arenas, never candidate seed bytes.
Arena permissions and space for the actual writer remain admission checks.
Callers must separately authenticate D3 against the original compile request,
validate runtime rules and physical ownership, and admit an actual CPU writer.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from collections.abc import Mapping


class CandidateLayoutError(ValueError):
    def __init__(self, code, pointer=''):
        self.code, self.pointer = code, pointer
        super().__init__(f'{code}:{pointer}')


@dataclass(frozen=True)
class CandidateSlice:
    source_id: str
    kind: str
    component: str
    endpoint_id: str
    port: str | None
    raw_bit_offset: int
    width: int
    bit_offset: int
    mask: int
    minimum: int
    maximum: int
    alignment: int


@dataclass(frozen=True)
class CandidateClassification:
    valid: bool
    code: str | None
    source_id: str | None = None


@dataclass(frozen=True)
class CandidateLayout:
    slices: tuple[CandidateSlice, ...]
    digest: str
    derived_image_source_id: str

    @property
    def bit_length(self):
        return sum(s.width for s in self.slices)

    @property
    def byte_length(self):
        return (self.bit_length + 7) // 8

    def _validate(self, source, value):
        if type(value) is not int or not 0 <= value < 1 << source.width:
            raise CandidateLayoutError('value-width', source.source_id)
        if value & ~source.mask:
            raise CandidateLayoutError('value-mask', source.source_id)
        if not source.minimum <= value <= source.maximum:
            raise CandidateLayoutError('value-range', source.source_id)
        if value % source.alignment:
            raise CandidateLayoutError('value-alignment', source.source_id)

    def encode(self, values):
        if not isinstance(values, Mapping) or set(values) != {s.source_id for s in self.slices}:
            raise CandidateLayoutError('source-set')
        raw = 0
        for source in self.slices:
            value = values[source.source_id]
            self._validate(source, value)
            raw |= value << source.raw_bit_offset
        return raw.to_bytes(self.byte_length, 'little')

    def decode(self, raw):
        if type(raw) is not bytes:
            raise CandidateLayoutError('record-type')
        if len(raw) != self.byte_length:
            raise CandidateLayoutError('record-length')
        word = int.from_bytes(raw, 'little')
        if word >> self.bit_length:
            raise CandidateLayoutError('record-padding')
        values = {}
        for source in self.slices:
            value = (word >> source.raw_bit_offset) & ((1 << source.width) - 1)
            self._validate(source, value)
            values[source.source_id] = value
        return values

    def classify(self, raw):
        try:
            self.decode(raw)
        except CandidateLayoutError as error:
            return CandidateClassification(False, error.code, error.pointer or None)
        return CandidateClassification(True, None)


def _require(condition, code, pointer=''):
    if not condition:
        raise CandidateLayoutError(code, pointer)


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def compile_candidate_layout(path):
    """Compile the supported D3 F4 subset, refusing unimplemented semantics.

    source_constraints must mirror every source exactly. Runtime rule semantics
    remain the execution admission layer's responsibility; this module never
    evaluates or claims satisfaction of runtime reachable-window constraints.
    Register field claims and seeds currently have no decoder and are refused.
    """
    _require(isinstance(path, dict) and path.get('flow_id') == 'F4'
             and path.get('status') == 'executable', 'path-unsupported')
    _require(path.get('seed') is None, 'seed-unsupported')
    constraints = path.get('constraints', {})
    _require(isinstance(constraints, dict), 'constraints-invalid')
    _require(set(constraints) <= {'schema_version', 'policy_hash', 'layout_hash',
             'rule_ids', 'rules', 'register_field_constraints', 'source_constraints'},
             'constraint-kind-unsupported')
    _require(not constraints.get('register_field_constraints'), 'register-constraints-unsupported')
    sources = path.get('sources', [])
    mirrors = constraints.get('source_constraints', [])
    _require(isinstance(sources, list) and isinstance(mirrors, list)
             and len(sources) == len(mirrors), 'constraint-mismatch')
    keys = ('source_id', 'origin', 'kind', 'width', 'bit_offset', 'mask',
            'alignment', 'range', 'constraint_basis', 'register_access')
    seen = set(); slices = []; offset = 0; images = []; streams = []; pin_owners = []
    for index, source in enumerate(sources):
        pointer = f'/sources/{index}'
        _require(isinstance(source, dict), 'source-invalid', pointer)
        _require(set(source) <= set(keys) | {'component', 'endpoint_id', 'port',
                 'register', 'field', 'origin_ref'}, 'source-fields-unsupported', pointer)
        identity = source.get('source_id')
        _require(isinstance(identity, str) and identity and identity not in seen, 'source-id', pointer)
        seen.add(identity)
        matching = [m for m in mirrors if isinstance(m, dict) and m.get('source_id') == identity]
        _require(len(matching) == 1 and set(matching[0]) <= set(keys) and all(source.get(k) == matching[0].get(k) for k in keys),
                 'constraint-mismatch', pointer)
        _require(source.get('origin') == 'fuzzable', 'source-ownership', pointer)
        _require(all(isinstance(source.get(k), str) and source[k] for k in ('component', 'endpoint_id')),
                 'source-ownership', pointer)
        kind = source.get('kind')
        if kind == 'instruction_image':
            images.append(source)
            continue
        width = source.get('width'); bit = source.get('bit_offset'); mask = source.get('mask')
        _require(_integer(width, 1, 32) and _integer(bit, 0, 31)
                 and width + bit <= 32 and _integer(mask, 1, 0xffffffff), 'source-shape', pointer)
        if kind == 'cpu_mmio_stream':
            access = source.get('register_access', {})
            _require(isinstance(access, dict), 'register-access', pointer)
            _require(access.get('schema_version') == 'register_source_access.v1'
                     and access.get('operation') == 'write'
                     and access.get('value_origin') == 'cpu_transaction_wdata'
                     and access.get('register_origin') == 'bound_target_register_commit'
                     and access.get('source_component') == source['component']
                     and access.get('source_endpoint') == source['endpoint_id']
                     and access.get('register') == source.get('register')
                     and access.get('field') == source.get('field')
                     and access.get('value_mask') == mask,
                     'register-access', pointer)
            _require(access.get('width_bytes') == 4 and access.get('allowed_byte_enables') == [15]
                     and access.get('byte_enable_domain') == 'target_word_lanes'
                     and source.get('alignment') == access.get('access_alignment') == 4
                     and _integer(access.get('address'), 0, 0xfffffffc)
                     and access['address'] % 4 == 0
                     and source.get('range') == [access['address'], access['address']], 'register-word-shape', pointer)
            _require(mask & ~(((1 << width) - 1) << bit) == 0, 'source-mask', pointer)
            streams.append(source)
            packed_width, minimum, maximum, alignment = 32, 0, 0xffffffff, 1
        elif kind == 'external_pin':
            _require(isinstance(source.get('port'), str) and source['port']
                     and mask < 1 << width and bit + width <= 32, 'pin-shape', pointer)
            bounds = source.get('range')
            _require(bounds is None or (isinstance(bounds, (list, tuple)) and len(bounds) == 2
                     and all(_integer(v, 0, (1 << width)-1) for v in bounds)
                     and bounds[0] <= bounds[1]), 'pin-range', pointer)
            alignment = source.get('alignment')
            _require(_integer(alignment, 1, 1 << width), 'pin-alignment', pointer)
            physical = (source['component'], source['port'], bit, bit + width)
            _require(not any(c == physical[0] and p == physical[1]
                     and lo < physical[3] and physical[2] < hi
                     for c, p, lo, hi in pin_owners), 'source-ownership-overlap', pointer)
            pin_owners.append(physical)
            minimum, maximum = bounds if bounds is not None else (0, (1 << width)-1)
            packed_width = width
        else:
            raise CandidateLayoutError('source-kind-unsupported', pointer)
        slices.append(CandidateSlice(identity, kind, source['component'], source['endpoint_id'],
            source.get('port'), offset, packed_width, bit, mask, minimum, maximum, alignment))
        offset += packed_width
    _require(len(images) == len(streams) == 1, 'derived-writer-shape')
    image = images[0]
    bounds = image.get('range')
    _require(image['component'] == streams[0]['component'] and image.get('bit_offset') == 0
             and image.get('mask') == 0xffffffff and image.get('alignment') in (2, 4)
             and isinstance(image.get('port'), str) and image['port']
             and isinstance(bounds, (list, tuple)) and len(bounds) == 2
             and all(_integer(v, 0, 0xffffffff) for v in bounds)
             and bounds[0] % 4 == 0 and bounds[1] >= bounds[0]
             and image.get('width') == (bounds[1] - bounds[0] + 1) * 8,
             'derived-image-unsupported')
    canonical = json.dumps(path, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return CandidateLayout(tuple(slices), sha256(canonical.encode()).hexdigest(), image['source_id'])
