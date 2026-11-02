"""F6 same-call live/fresh lifecycle; JSON never reconstructs native authority."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from .compiled_f6 import CompiledF6Runtime
from .compiled_f6_rfuzz import build_compiled_f6_rfuzz_executor, f6_seed_record
from .compiled_f6_receipts import join_compiled_f6_receipts
from .compiled_f6_build_join import build_compiled_f6_build_join, verify_compiled_f6_build_join
from .compiled_f6_saved_outputs import write_pinned_json, expected_f6_documents, save_f6_replay_outputs, verify_pins, expected_f6_failed_prefix_documents
from .scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material


def assess_compiled_f6_support(*,artifacts,compiled_inputs,base_dir):
    from .compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    try:
        from myfuzz.local_harness.generated_artifact_admission import validated_f6_provider_credentials
        provider_credentials=validated_f6_provider_credentials(artifacts)
        admission=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)
        from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
        contract=admission['execution_contract']
        from .compiled_f6_runtime_path import _artifact_link_document
        dma_id=contract['dma']['instance_id']
        if set(provider_credentials)!={dma_id} or provider_credentials[dma_id]!=_artifact_link_document(artifacts[dma_id]):
            raise ValueError('compiled-F6-loaded-provider-admission-mismatch')
        profile=artifacts[contract['dma']['instance_id']].plan.profile
        native=verify_wbdmac_source_contract(profile,base_dir=base_dir)['irq']
        forms=profile.interrupts
        expected=dict(endpoint_id='dma.interrupt',role='irq',polarity=native['polarity'],clock_domain='core',trigger='pulse',pulse_width_cycles=1,
            hold='Registered native completion/error pulse from wbdmac.v:378-387; asserted for the last write ACK with cfg_len=1 or a non-idle native master error.',
            clear='Reset clears o_interrupt; each subsequent i_clk edge replaces it with the current completion/error predicate. No software IRQ-clear register.')
        if native['physical_port']!='o_interrupt' or native['trigger']!='native_pulse' or len(forms)!=1 or any(
                getattr(forms[0],key,None)!=value for key,value in expected.items()):
            raise ValueError('compiled-F6-irq-source-declaration-mismatch')
    except (ValueError,TypeError,KeyError) as error:
        return dict(status='unsupported',execution_supported=0,flow_id='F6',reason=str(error),runtime_admitted=False)
    return dict(status='supported',execution_supported=1,flow_id='F6',runtime_admitted=False,
        admission=admission,path_id=admission['logical_path']['path_id'])

def verify_f6_live_commitment(session_dir,*,executor):
    context=executor._live_context
    commitment=context.get('online_artifact_commitment') if type(context) is dict else None
    if type(commitment) is not dict or type(commitment.get('artifacts')) is not dict:
        raise ValueError('compiled-F6-rfuzz-live-initial-bytes-required')
    expected=dict(commitment['artifacts']);expected['online_run_identity.json']=commitment.get('identity_file_sha256')
    initial=context.get('f6_initial_bytes')
    if type(initial) is not dict or not {'seed.bin','receipts.jsonl','online_plan.json','online_final_trace.json'}<=set(initial):
        raise ValueError('compiled-F6-first-writer-pins-required')
    for name,digest in initial.items():
        if expected.get(name)!=digest:raise ValueError('compiled-F6-first-writer-identity-changed:'+name)
    root=Path(session_dir)
    for name,digest in expected.items():
        path=root/name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('compiled-F6-rfuzz-live-initial-bytes-changed:'+name)
    return {str(root/name):digest for name,digest in expected.items()}

def validate_f6_session_material(session_dir,*,runtime,seed_record):
    from .scenario_rfuzz_live import _verify_online_run_identity
    from myfuzz.scenario.event_journal import canonical_json_chunks
    root=Path(session_dir)
    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode()
    if (root/'seed.bin').read_bytes()!=seed_record:raise ValueError('compiled-F6-same-call-seed')
    if canonical(json.loads((root/'online_session_manifest.json').read_bytes()))!=canonical(runtime.session.manifest_document):
        raise ValueError('compiled-F6-same-call-manifest')
    from myfuzz.scenario.dma_binding_replay import parse_dma_bound_payload
    saved=(root/'online_plan.json').read_bytes()
    document=json.loads(saved)
    if document.get('schema_version')=='p7_dma_bound_payload.v1':
        saved=parse_dma_bound_payload(saved,expected_identity_sha256=document['identity_sha256']).payload_bytes
    if saved!=runtime.session.encode_plan():raise ValueError('compiled-F6-same-call-plan')
    trace_path=root/'online_final_trace.json'
    if not trace_path.is_file():raise ValueError('compiled-F6-original-raw-trace-required')
    digest=sha256()
    for chunk in canonical_json_chunks(runtime.trace):digest.update(chunk.encode())
    if digest.digest()!=sha256(canonical(json.loads(trace_path.read_bytes()))).digest():raise ValueError('compiled-F6-same-call-trace')
    if _verify_online_run_identity(root,plan_path=root/'online_plan.json',trace_path=trace_path,trace=runtime.trace) is None:
        raise ValueError('compiled-F6-same-call-run-identity')

def f6_fresh_verification(replay,plan,*,route='rfuzz'):
    entries = {
        'rfuzz': 'myfuzz.integration.compiled_f6_rfuzz:run_compiled_f6_rfuzz_session',
        'directed_file': 'myfuzz.integration.compiled_execution_files:run_compiled_execution_files',
    }
    if type(route) is not str or route not in entries:
        raise ValueError('compiled-F6-replay-entry-unsupported')
    scope='full' if plan.get('completed') is True else 'failed_prefix_full'
    if (replay.get('matches') is not True or replay.get('first_difference','absent') is not None
            or replay.get('verification_scope')!=scope or type(replay.get('actual_prefix')) is not dict
            or type(replay.get('actual_events')) is not list or replay.get('execution_audit',{}).get('closed') is not True):
        raise ValueError('compiled-F6-full-fresh-material-required')
    return dict(schema_version='fresh_verification.v1',matches=True,first_difference=None,verification_scope=scope,
        completed=plan['completed'],expected_semantic_hash=plan['semantic_hash'],
        actual_semantic_hash=replay['actual_prefix']['semantic_hash'],record_count=len(plan['records']),
        event_count=len(replay['actual_events']),replay_entry=entries[route])

def _run_f6_live_and_fresh_owned(*,artifacts,compiled_inputs,base_dir,cache_dir,run_id,session_dir,output_dir,
        client_binary,budget_seconds,max_tests,search_seed,max_runs_per_batch,rounds_per_case=128):
    if type(max_tests) is not int or max_tests<1:raise ValueError('compiled-F6-max-tests')
    if type(rounds_per_case) is not int or not 1<=rounds_per_case<=65536:raise ValueError('compiled-F6-rounds')
    if not Path(cache_dir).is_dir():raise ValueError('compiled-F6-build-cache-required')
    support=assess_compiled_f6_support(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)
    if support['execution_supported']!=1:raise ValueError('compiled-F6-support-refused:'+str(support))
    from myfuzz.local_harness.generated_artifact_admission import validated_f6_provider_credentials
    provider_pins=validated_f6_provider_credentials(artifacts,include_files=True)['file_pins']
    runtime=None;primary=None;pins={};snapshots={'original':{},'fresh':{}}
    output=Path(output_dir);session=Path(session_dir)
    def original(snapshot):snapshots['original']=deepcopy(snapshot)
    def fresh(envelope):
        for key,destination in [('original_build','original'),('fresh_build','fresh')]:
            if envelope.get(key) is not None:snapshots[destination]=deepcopy(envelope[key])
        save_f6_replay_outputs(output,envelope,pins)
    def build(error=None):
        return build_compiled_f6_build_join(artifacts=artifacts,
            execution_binding=runtime.execution_binding if runtime else None,
            original=snapshots['original'],fresh=snapshots['fresh'],error=error)
    try:
        runtime=CompiledF6Runtime(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=Path(base_dir),
            cache_dir=Path(cache_dir),run_id=run_id,rounds_per_case=rounds_per_case,
            max_cases=min(max_tests,16,support['admission']['execution_contract']['program_contract']['slot_count']),
            build_audit_sink=original,defer_begin=True)
        runtime.begin()
        executor=build_compiled_f6_rfuzz_executor(runtime,run_id=run_id)
        seed=f6_seed_record(runtime.path)
        live=run_scenario_rfuzz_live(executor=executor,client_binary=Path(client_binary),output_dir=session,
            duration_seconds=budget_seconds,seed_records=(seed,),max_tests=max_tests,search_seed=search_seed,
            max_runs_per_batch=max_runs_per_batch)
        transport=verify_f6_live_commitment(session,executor=executor)
        transport.update(provider_pins)
        validate_f6_session_material(session,runtime=runtime,seed_record=seed)
        required={'seed.bin','receipts.jsonl','online_session_manifest.json','online_plan.json','online_final_trace.json'}
        for name in required:
            path=session/name
            if not path.is_file():raise ValueError('compiled-F6-transport-required:'+name)
            if str(path) not in transport:transport[str(path)]=sha256(path.read_bytes()).hexdigest()
        plan=runtime.finish();write_pinned_json(output/'compiled_f6_prefix.json',plan,pins)
        if live.client_returncode!=0 and plan.get('status')!='expected_error':raise ValueError('compiled-F6-client-failed')
        replay=runtime.replay(plan,audit_sink=fresh)
        verification=f6_fresh_verification(replay,plan)
        join=join_compiled_f6_receipts(runtime=runtime,executor=executor,receipts_path=session/'receipts.jsonl',replay=replay)
        joined=build();verify_compiled_f6_build_join(joined,artifacts=artifacts,execution_binding=runtime.execution_binding,
            original=snapshots['original'],fresh=snapshots['fresh'])
        material=build_f6_assertion_material(runtime)
        material['assertion_evidence']=dict(execution_binding=deepcopy(runtime.execution_binding),
            path_id=runtime.path['path_id'],run_id=runtime.run_id,cases=deepcopy(material['assertion_evidence']['cases']))
        outcome=dict(live=live,plan=plan,replay=replay,verification=verification,join=join,executor=executor,runtime=runtime,
            build_join=joined,assertion_material=material,saved_output_hashes=pins,transport_files=transport,
            useful_search_benefit_claimed=False,search_diversity=None)
        if plan['completed']:
            documents=expected_f6_documents(outcome)
        else:
            documents=expected_f6_failed_prefix_documents(outcome)
        for name,value in documents.items():
            if name not in pins:write_pinned_json(output/name,value,pins)
        verify_pins(output,pins)
        for name,digest in transport.items():
            if sha256(Path(name).read_bytes()).hexdigest()!=digest:raise ValueError('compiled-F6-transport-bytes-changed:'+name)
        outcome['expected_error']=not plan['completed']
        outcome['completed']=plan['completed']
        outcome['scope']=plan['scope']
        return outcome
    except BaseException as error:primary=error;raise
    finally:
        cleanup_only=None
        if runtime is not None and not runtime.finished:
            try:runtime.finish()
            except BaseException as error:
                if primary is None:primary=error;cleanup_only=error
                elif error is not primary:primary.add_note('F6 finish: '+repr(error))
        if primary is not None:
            exports=[('compiled_f6_build_join.v1.json',lambda:build(primary))]
            if runtime is not None:
                exports += [('compiled_f6_partial_events.json',lambda:list(runtime.runner.events_since(0))),
                    ('compiled_f6_partial_prefix.json',lambda:runtime._finish_document),
                    ('compiled_f6_execution_audit.json',runtime.execution_audit),
                    ('compiled_assertion_results.v1.json',lambda:build_f6_assertion_material(runtime)['assertions']),
                    ('compiled_assertion_evidence.v1.json',lambda:build_f6_assertion_material(runtime)['assertion_evidence'])]
            for name,capture in exports:
                if name in pins:continue
                try:write_pinned_json(output/name,capture(),pins)
                except BaseException as error:primary.add_note('F6 failure export: '+repr(error))
        if cleanup_only is not None:raise cleanup_only


def run_f6_live_and_fresh(*,artifacts,compiled_inputs,base_dir,cache_dir,run_id,session_dir,output_dir,
        client_binary,budget_seconds,max_tests,search_seed,max_runs_per_batch,rounds_per_case=128):
    from myfuzz.local_harness.generated_artifact_admission import release_f6_provider_credentials
    try:
        return _run_f6_live_and_fresh_owned(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir,
            cache_dir=cache_dir,run_id=run_id,session_dir=session_dir,output_dir=output_dir,client_binary=client_binary,
            budget_seconds=budget_seconds,max_tests=max_tests,search_seed=search_seed,
            max_runs_per_batch=max_runs_per_batch,rounds_per_case=rounds_per_case)
    finally:
        release_f6_provider_credentials(artifacts)
