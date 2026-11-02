"""Synthetic transport spy only: no build, launch, or native authority."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from tests.integration.test_compiled_f4_storage_producer import timer_loaded
from myfuzz.integration.compiled_f2 import CompiledF2Runtime
from myfuzz.scenario.compiled_f2_decoder import CompiledF2Decoder
from myfuzz.scenario.compiled_paths import compiled_document_sha256

@pytest.fixture(scope="module")
def f2_transport_inputs(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp("f2-transport-source"))[1]

@pytest.fixture
def transport_case(f2_transport_inputs, monkeypatch):
    from myfuzz.integration import compiled_f2_rfuzz as module
    inputs=dict(f2_transport_inputs)
    inputs["compiled"]=deepcopy(inputs["compiled"])
    runtime=CompiledF2Runtime.__new__(CompiledF2Runtime)
    runtime.inputs=inputs;runtime.run_id='synthetic-transport';runtime.rounds=32
    runtime.result=0x3fffc;runtime.cursor=0x10000;runtime.max_cases=32
    runtime.runner=SimpleNamespace(sessions={'processor':None,'peripheral':None},local_ticks={'processor':0,'peripheral':0})
    decoder=CompiledF2Decoder.from_runtime(runtime)
    runtime.path=decoder.path;runtime.compiled_digest=compiled_document_sha256(inputs['compiled'])
    admission=decoder.runtime_path_admission;runtime.runtime_path_admission=admission
    runtime.session=SimpleNamespace(runtime_contract=admission.prepared.contract,
        runtime_path_document={'declaration':admission.prepared.document()},
        instruction_image_binding_documents=(admission.instruction_binding.document(),),
        encode_plan=lambda:b'synthetic-plan',trace=lambda:runtime.trace)
    runtime.execution_binding=SimpleNamespace(digest='synthetic-binding')
    runtime.records=[];runtime.attempts=[];runtime.submits=[];runtime._failed_attempt=None
    runtime.trace={'synthetic_transport_only':True};runtime.finish_calls=0;runtime.fail_at=None
    def submit(raw):
        index=len(runtime.attempts)
        candidate=decoder.decode_candidate(raw+bytes(4),cursor=runtime.cursor,case_index=index)
        runtime.submits.append(raw);runtime.attempts.append({'case_id':candidate.case.case_id})
        runtime.runner.local_ticks['processor']+=1
        if runtime.fail_at==index:
            runtime._failed_attempt=candidate.case.case_id
            raise RuntimeError('synthetic-submit-fault')
        certificate=dict(status='certified',case_id=candidate.case.case_id,path_id=decoder.path_id,
            source_id=decoder.source_id,execution_binding_sha256='synthetic-binding',
            runtime_path_id=admission.runtime_path_id,runtime_path_admission_sha256=admission.digest,
            runtime_admitted=True,instruction_address=candidate.case.source.address,
            instruction_source_id=decoder.image["source_id"],
            instruction_sha256=__import__("hashlib").sha256(bytes.fromhex(candidate.declaration["code_hex"])).hexdigest())
        runtime.records.append({'certificate':deepcopy(certificate)})
        runtime.cursor+=len(bytes.fromhex(candidate.declaration['code_hex']))
        return certificate
    def finish():
        runtime.finish_calls+=1
        return {'synthetic_transport_only':True}
    runtime.submit=submit;runtime.finish=finish;runtime.execution_audit=lambda:{'synthetic_transport_only':True}
    # Explicitly synthetic projection; real feedback validation has separate fixtures.
    monkeypatch.setattr(module,'f2_observation_hits',lambda **kwargs:(frozenset(),{'synthetic_transport_only':True}))
    executor=module.build_compiled_f2_rfuzz_executor(runtime,run_id=runtime.run_id)
    yield executor,runtime,module.f2_seed_record(runtime.path)
