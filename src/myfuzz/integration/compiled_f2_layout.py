"""Pure immutable address-only F2 candidate admission; no runtime authority."""
from dataclasses import dataclass
from hashlib import sha256
import json

from .compiled_candidate_layout import CandidateLayoutError, _require, _integer


@dataclass(frozen=True)
class F2AddressSlice:
    source_id: str
    component: str
    endpoint_id: str
    raw_bit_offset: int
    width: int
    minimum: int
    maximum: int
    alignment: int


@dataclass(frozen=True)
class F2Classification:
    accepted: bool
    address: int | None
    reason: str | None


@dataclass(frozen=True)
class CompiledF2CandidateLayout:
    source_slices: tuple[F2AddressSlice, ...]
    digest: str
    _canonical: str
    byte_length: int = 4

    def document(self):
        return json.loads(self._canonical)

    def classify(self, raw):
        if type(raw) is not bytes:
            return F2Classification(False, None, 'record-type')
        if len(raw) != 4:
            return F2Classification(False, None, 'record-length')
        address = int.from_bytes(raw, 'little')
        source = self.source_slices[0]
        if address % source.alignment:
            return F2Classification(False, address, 'address-alignment')
        if not source.minimum <= address <= source.maximum:
            return F2Classification(False, address, 'address-range')
        return F2Classification(True, address, None)


def compile_f2_candidate_layout(path):
    from myfuzz.scenario.f2_read_contract import validate_f2_read_contract
    contract = validate_f2_read_contract(path)
    _require(path.get('seed') is None, 'seed-unsupported')
    constraints = path.get('constraints')
    _require(isinstance(constraints, dict), 'constraints-invalid')
    _require(set(constraints) <= {'schema_version','policy_hash','layout_hash','rule_ids',
        'rules','register_field_constraints','source_constraints'}, 'constraint-kind-unsupported')
    _require(not constraints.get('register_field_constraints'), 'register-constraints-unsupported')
    sources = path.get('sources'); mirrors = constraints.get('source_constraints')
    _require(isinstance(sources,list) and isinstance(mirrors,list) and len(sources)==len(mirrors)==2,
             'constraint-mismatch')
    keys = {'source_id','origin','kind','width','bit_offset','mask','alignment','range',
            'constraint_basis','register_access'}
    for source in sources:
        _require(isinstance(source,dict) and set(source) <= keys | {'component','endpoint_id',
                 'port','register','field','origin_ref'}, 'source-fields-unsupported')
        matches=[m for m in mirrors if isinstance(m,dict) and m.get('source_id')==source.get('source_id')]
        _require(len(matches)==1 and set(matches[0])<=keys and
                 all(source.get(k)==matches[0].get(k) for k in keys), 'constraint-mismatch')
        _require(source.get('origin')=='fuzzable', 'source-ownership')
    image=next((s for s in sources if s.get('source_id')==contract['instruction_source_id']),None)
    load=next((s for s in sources if s.get('source_id')==contract['load_source_id']),None)
    _require(image is not None and load is not None and image is not load, 'source-set')
    bounds=image.get('range')
    _require(image.get('kind')=='instruction_image' and image.get('component')==load.get('component')
             and image.get('bit_offset')==0
             # A 64-bit CPU declares its image source with the full 64-bit
             # field mask; only the *range* bounds the 4-byte candidate
             # record, and that range must still be a 32-bit address.
             and image.get('mask') in (0xffffffff,(1<<64)-1)
             and image.get('alignment') in (2,4) and isinstance(image.get('port'),str)
             and isinstance(bounds,(list,tuple)) and len(bounds)==2
             and all(_integer(v,0,0xffffffff) for v in bounds) and bounds[0]%4==0
             and bounds[1]>=bounds[0] and image.get('width')==(bounds[1]-bounds[0]+1)*8,
             'derived-image-unsupported')
    _require(load.get('kind')=='cpu_load_stream' and load.get('width')==32
             and load.get('bit_offset')==0 and load.get('mask')==0xffffffff
             and load.get('range')==[contract['address'],contract['address']]
             and load.get('alignment')==4 and _integer(contract['response_mask'],0,0xffffffff),
             'register-word-shape')
    access=load.get('register_access')
    _require(isinstance(access,dict) and set(access)=={
        'schema_version','source_component','source_endpoint','target_component','target_endpoint',
        'device_id','register','field','register_offset','address','window_base','window_size',
        'window_alignment','access_alignment','width_bytes','byte_enable_domain',
        'allowed_byte_enables','operation','value_origin','register_origin','value_mask'}
             and access.get('schema_version')=='register_source_access.v1'
             and access.get('operation')=='read' and access.get('value_origin')=='bound_target_rdata'
             and access.get('register_origin')=='bound_target_register_commit'
             and access.get('source_component')==load.get('component')==contract['source_component']
             and access.get('source_endpoint')==load.get('endpoint_id')==contract['source_endpoint']
             and access.get('register')==load.get('register')
             and access.get('field')==load.get('field')
             and access.get('value_mask')==contract['response_mask'] and access.get('width_bytes')==4
             and access.get('allowed_byte_enables')==[15]
             and access.get('byte_enable_domain')=='target_word_lanes'
             and access.get('access_alignment')==4
             and _integer(access.get('address'),0,0xfffffffc)
             and access['address']%4==0, 'register-access')
    source=F2AddressSlice(load['source_id'],load['component'],load['endpoint_id'],0,32,
                          contract['address'],contract['address'],4)
    try:
        canonical=json.dumps(dict(schema_version='compiled_F2_candidate_layout.v1',
            byte_length=4,source_slices=[source.__dict__],path=path),sort_keys=True,
            separators=(',',':'),allow_nan=False)
    except (TypeError,ValueError,RecursionError) as error:
        raise CandidateLayoutError('declaration-json-invalid') from error
    return CompiledF2CandidateLayout((source,),sha256(canonical.encode()).hexdigest(),canonical)
