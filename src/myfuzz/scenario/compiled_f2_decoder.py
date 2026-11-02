"""Exact address-only F2 wire decoding into admitted instruction sources.

No bound response is decoded from raw bytes. All records of a test are checked
before the caller may submit their instruction cases to the native runtime.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json

from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
from myfuzz.integration.compiled_f2_runtime_path import admit_compiled_f2_runtime_path
from myfuzz.integration.generated_register_reader import declare_reader
from .batch import BatchAdvance
from .compiled_paths import compiled_document_sha256
from .session_runtime import OnlineCase, BoundOnlineInstruction
from .rfuzz_decoder import RECORD_BYTES

MAX_CANDIDATE_RECORDS = 8


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


class CompiledF2CandidateRefused(ValueError):
    """A candidate or preflight refusal, compatible with existing callers."""
    def __init__(self, code, pointer='', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__('compiled-F2-decoder-'+code)


def _require(condition, code, pointer=None, detail=None):
    if not condition:
        raise CompiledF2CandidateRefused(code, pointer or '/'+code, detail)


@dataclass(frozen=True)
class CompiledF2Candidate:
    case: OnlineCase
    raw: bytes
    candidate_bytes: bytes
    unbound_bytes: bytes
    address: int
    source_id: str
    path_id: str
    compiled_sha256: str
    layout_digest: str
    _declaration_bytes: bytes

    @property
    def declaration(self):
        return json.loads(self._declaration_bytes)

    def document(self):
        return dict(schema_version='compiled_F2_candidate.v1',
            case_id=self.case.case_id,source_id=self.source_id,path_id=self.path_id,
            runtime_path_id=self.case.path_id,instruction_source_id=self.case.source.source_id,
            address=self.address,compiled_sha256=self.compiled_sha256,
            layout_digest=self.layout_digest,raw_hex=self.raw.hex(),
            candidate_bytes_hex=self.candidate_bytes.hex(),
            unbound_wire_bytes_hex=self.unbound_bytes.hex(),
            declaration=self.declaration)


class CompiledF2Decoder:
    """One frozen compile request and selected F2 path, no launch authority."""
    @property
    def path_id(self):
        return self.path['path_id']

    @property
    def source_id(self):
        return self.contract['load_source_id']

    @property
    def direction(self):
        return self.path['direction']

    @property
    def max_input_bytes(self):
        return RECORD_BYTES

    @classmethod
    def from_request(cls,*,request,compiled,run_id,schedule,rounds,result_address):
        return cls(request=request,compiled=compiled,run_id=run_id,schedule=schedule,
                   rounds=rounds,result_address=result_address)

    @classmethod
    def from_runtime(cls,runtime):
        decoder=cls.from_request(request=runtime.inputs['request'],
            compiled=runtime.inputs['compiled'],run_id=runtime.run_id,
            schedule=tuple(runtime.runner.sessions),rounds=runtime.rounds,
            result_address=runtime.result)
        decoder._cursor_provider=lambda:runtime.cursor
        return decoder

    def __init__(self,*,request,compiled,run_id,schedule,rounds,result_address):
        self.request=request
        self._caller_compiled=compiled
        self.compiled=deepcopy(compiled)
        self.compiled_sha256=compiled_document_sha256(compiled)
        self.runtime_path_admission=admit_compiled_f2_runtime_path(request=request,compiled=self.compiled)
        self.path=next(p for p in self.compiled['paths'] if p['flow_id']=='F2' and p['status']=='executable')
        self._path_bytes=_canonical(self.path)
        self.contract=self.path['execution_contract']
        self.layout=compile_f2_candidate_layout(self.path)
        self.run_id=run_id;self.schedule=schedule;self.rounds=rounds;self.result=result_address
        self.image=next(s for s in self.path['sources'] if s['kind']=='instruction_image')
        self._cursor_provider=None
        _require(type(run_id) is str and bool(run_id),'run-id')
        _require(type(rounds) is int and 1<=rounds<=65536,'rounds')
        _require(type(schedule) is tuple and len(schedule)==2 and
            set(schedule)=={self.contract['source_component'],self.contract['target_component']},'schedule')
        _require(type(result_address) is int and result_address%4==0 and
            self.image['range'][0]<=result_address and result_address+3<=self.image['range'][1],'result-range')
        self._config=(run_id,schedule,rounds,result_address)
        declare_reader(request,self.compiled,source_id=self.contract['load_source_id'],
                       address=self.contract['address'],result_address=result_address)

    def verify(self):
        _require((self.run_id,self.schedule,self.rounds,self.result)==self._config,'configuration-drift')
        _require(compiled_document_sha256(self._caller_compiled)==self.compiled_sha256 and
            compiled_document_sha256(self.compiled)==self.compiled_sha256,'compiled-drift')
        _require(_canonical(self.path)==self._path_bytes,'path-drift')
        current=admit_compiled_f2_runtime_path(request=self.request,compiled=self.compiled,path=self.path)
        self.runtime_path_admission.validate_cached_identity()
        _require(current.document()==self.runtime_path_admission.document(),'admission-drift')
        _require(compile_f2_candidate_layout(self.path)==self.layout,'layout-drift')
        _require(self.contract==self.path['execution_contract'],'contract-drift')

    def _at(self,raw,*,cursor,case_index,case_id=None):
        _require(type(raw) is bytes and len(raw)==RECORD_BYTES,'wire-record', '/records')
        _require(type(cursor) is int and cursor%4==0 and self.image['range'][0]<=cursor<self.result,'cursor')
        _require(type(case_index) is int and case_index>=0,'case-index')
        selection=self.layout.classify(raw[:4])
        _require(selection.accepted,'candidate-'+str(selection.reason),
                 '/records/address', {'reason': selection.reason})
        declaration=declare_reader(self.request,self.compiled,
            source_id=self.contract['load_source_id'],address=selection.address,result_address=self.result)
        code=bytes.fromhex(declaration['code_hex'])
        _require(cursor+len(code)<=self.result,'slot-exhausted')
        identity=f'{self.run_id}:{case_index}' if case_id is None else case_id
        _require(type(identity) is str and bool(identity),'case-id')
        instruction=BoundOnlineInstruction(self.image['source_id']+f':{case_index}',
            self.contract['source_component'],cursor,code.hex(),self.runtime_path_admission.instruction_binding.source_id)
        case=OnlineCase(identity,'CPU_TO_IP',self.runtime_path_admission.runtime_path_id,
            instruction,tuple(BatchAdvance(self.schedule) for _ in range(self.rounds)))
        return CompiledF2Candidate(case,raw,raw[:4],raw[4:],selection.address,
            self.contract['load_source_id'],self.path['path_id'],self.compiled_sha256,
            self.layout.digest,_canonical(declaration))

    def decode_candidate(self,raw,*,cursor,case_index,case_id=None):
        self.verify()
        _require(self._cursor_provider is None or cursor==self._cursor_provider(),'runtime-cursor')
        return self._at(raw,cursor=cursor,case_index=case_index,case_id=case_id)

    def decode_sequence(self,records,*,cursor,case_index):
        self.verify()
        _require(type(records) is tuple and 1<=len(records)<=MAX_CANDIDATE_RECORDS,'sequence', '/records')
        _require(self._cursor_provider is None or cursor==self._cursor_provider(),'runtime-cursor')
        result=[]
        for offset,raw in enumerate(records):
            candidate=self._at(raw,cursor=cursor,case_index=case_index+offset)
            result.append(candidate);cursor+=len(bytes.fromhex(candidate.declaration['code_hex']))
        return tuple(result)

    def document(self):
        self.verify()
        return dict(schema_version='compiled_F2_decoder.v1',flow_id='F2',run_id=self.run_id,
            path_id=self.path['path_id'],compiled_sha256=self.compiled_sha256,
            source_id=self.contract['load_source_id'],candidate_layout=self.layout.document(),
            candidate_layout_sha256=self.layout.digest,wire_record_bytes=RECORD_BYTES,
            unbound_wire_bytes=RECORD_BYTES-4,result_address=self.result,
            max_records=MAX_CANDIDATE_RECORDS,runtime_path_admission=self.runtime_path_admission.document(),
            direction=self.direction,candidate_bytes=self.layout.byte_length,max_input_bytes=RECORD_BYTES,
            instruction_source_id=self.image['source_id'],
            instruction_address_range=[self.image['range'][0],self.result],
            address=self.contract['address'],register=self.contract['register'],
            runtime_contract=self.runtime_path_admission.prepared.contract.document(),
            graph=self.runtime_path_admission.prepared.graph.edge_document(),
            path_mapping=self.runtime_path_admission.prepared.document()['selections'],
            instruction_image_bindings=[self.runtime_path_admission.instruction_binding.document()])
