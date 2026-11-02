"""Pure F6 raw8 operand/program preflight. No case is admitted here."""
from dataclasses import dataclass
from hashlib import sha256
import json
from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()

class CompiledF6CandidateRefused(ValueError):
    def __init__(self,code,pointer='/records',detail=None):
        self.code,self.pointer,self.detail=code,pointer,detail
        super().__init__('compiled-F6-decoder-'+code)

@dataclass(frozen=True)
class CompiledF6DecodedCandidate:
    candidate: object
    case_id: str
    case_index: int
    instruction_address: int
    prefix_hex: str
    path_id: str
    source_ids: tuple
    @property
    def raw(self):return self.candidate.raw
    @property
    def words(self):return self.candidate.words
    def document(self):
        return dict(schema_version='compiled_F6_candidate.v1',raw8_hex=self.raw.hex(),
            words=list(self.words),case_id=self.case_id,case_index=self.case_index,
            instruction_address=self.instruction_address,prefix_hex=self.prefix_hex,
            path_id=self.path_id,source_ids=list(self.source_ids))

class CompiledF6Decoder:
    max_input_bytes=8
    direction='CPU_TO_IP'
    @classmethod
    def from_runtime(cls,runtime):return cls(runtime)
    def __init__(self,runtime):
        self.runtime=runtime
        self.path=runtime.path
        self.layout=compile_f6_candidate_layout(self.path)
        self.path_id=self.path['path_id']
        self.source_ids=tuple(s['source_id'] for s in self.path['sources'])
        self.source_id=self.source_ids[0]
        self.runtime_path_admission=admit_compiled_f6_runtime_path(artifacts=runtime.artifacts,
            compiled_inputs=runtime.compiled_inputs,base_dir=runtime.base_dir)
        self._initial=_canonical(self.runtime_path_admission)
        self._path_initial=_canonical(self.path)
        self._run_id=runtime.run_id
    def verify(self):
        if self.runtime.run_id!=self._run_id or _canonical(self.runtime.path)!=self._path_initial:
            raise ValueError('compiled-F6-decoder-path-drift')
        current=admit_compiled_f6_runtime_path(artifacts=self.runtime.artifacts,
            compiled_inputs=self.runtime.compiled_inputs,base_dir=self.runtime.base_dir)
        if _canonical(current)!=self._initial or compile_f6_candidate_layout(self.runtime.path)!=self.layout:
            raise ValueError('compiled-F6-decoder-admission-drift')
    def decode_sequence(self,records,*,cursor,case_index):
        if type(records) is not tuple or len(records)!=1:
            raise CompiledF6CandidateRefused('record-count',detail={'required':1})
        self.verify()
        r=self.runtime
        if (type(cursor) is not int or type(case_index) is not int
                or cursor!=r.cursor or case_index!=len(r.attempts) or cursor!=case_index):
            raise CompiledF6CandidateRefused('cursor')
        if r.finished or getattr(r,'_terminal_error',None) is not None or getattr(r,'_stop_after_expected_error',False):
            raise ValueError('compiled-F6-decoder-runtime-stopped')
        if not 0<=cursor<r.max_cases:raise CompiledF6CandidateRefused('slot-exhausted')
        try: candidate=self.layout.decode(records[0])
        except ValueError as error:raise CompiledF6CandidateRefused('candidate',detail=str(error)) from error
        program=r.program.prefix(candidate,case_index=case_index)
        address=r.contract['program_contract']['slot_base']+256*case_index
        return (CompiledF6DecodedCandidate(candidate,f'{r.run_id}:case:{case_index}',case_index,
            address,program.hex(),self.path_id,self.source_ids),)
    def document(self):
        self.verify()
        r=self.runtime
        return dict(schema_version='compiled_F6_decoder.v1',flow_id='F6',run_id=r.run_id,
            path_id=self.path_id,source_id=self.source_id,source_ids=list(self.source_ids),direction=self.direction,
            max_input_bytes=8,wire_record_bytes=8,candidate_bytes=8,max_records=1,
            candidate_layout=self.layout.document(),candidate_layout_sha256=self.layout.digest,
            runtime_path_admission=json.loads(self._initial),program=r.program.document(),
            runtime_contract=self.runtime_path_admission['runtime_contract'],
            graph=self.runtime_path_admission['runtime_graph'],
            path_mapping=self.runtime_path_admission['prepared_runtime_paths']['selections'],
            instruction_image_bindings=list(r.session.instruction_image_binding_documents),
            feedback_projection=dict(schema_version='compiled_F6_feedback_projection.v1',
                expectation_ids=list(r.contract['expectation_ids']),counter_count=5,
                implementation='myfuzz.scenario.f6_assertion_evidence:f6_case_feedback',
                partial_or_failed_vector=[0]*5,useful_search_benefit_claimed=False))
