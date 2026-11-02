"""Explicit F6 RFuzz executor. Candidate, evidence and feedback semantics are F6 owned."""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time
from .compiled_f6 import CompiledF6Runtime
from .compiled_f6_layout import f6_seed_record
from .compiled_rfuzz_transport import process_compiled_owned_pair
from .rfuzz_wire import InputBatch
from .scenario_rfuzz import ScenarioRfuzzExecutor, ScenarioRfuzzReceipt
from myfuzz.scenario.compiled_f6_decoder import CompiledF6Decoder, CompiledF6CandidateRefused
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material, f6_case_feedback

def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()).hexdigest()

class CompiledF6RfuzzExecutor(ScenarioRfuzzExecutor):
    compiled_flow='F6'
    def __init__(self,*,runtime,decoder,targets,run_id,feedback_interval=16,evidence_dir=None):
        if not isinstance(decoder,CompiledF6Decoder) or decoder.runtime is not runtime or run_id!=runtime.run_id:
            raise ValueError('compiled-F6-rfuzz-runtime-decoder-required')
        if tuple(t.target_id for t in targets)!=tuple(EXPECTATION_IDS):
            raise ValueError('compiled-F6-rfuzz-five-targets-required')
        if type(feedback_interval) is not int or feedback_interval<1:
            raise ValueError('compiled-F6-rfuzz-feedback-interval-invalid')
        decoder.verify()
        self.runtime=runtime
        self.decoder=None
        self.online_decoder=decoder
        self.targets=targets
        self.run_id=run_id
        self.session=runtime.session
        self.factory=lambda:runtime.runner
        self.checker=self.checker_config=self.checker_identity_target=None
        self.runtime_contract=runtime.session.runtime_contract
        self.runtime_path_status='contract_preflight'
        from .compiled_f6_runtime_path import restore_prepared_runtime_paths
        self._prepared_runtime_paths=restore_prepared_runtime_paths(decoder.runtime_path_admission)
        self._runtime_declaration_document=self._prepared_runtime_paths.document()
        self.fresh_runtime_path_documents={}
        self.replay_only = False
        self.feedback_interval = feedback_interval
        self.closed_loop_energy = False
        self.closed_loop_energy_source = 'default'
        self.path_switch = False
        self.path_switch_source = 'default'
        self._path_switch_records = Counter()
        self._path_switch_attempts = 0
        self._path_switch_granted = 0
        self._path_switch_changed = 0
        self._path_switch_refusals = Counter()
        self._path_switch_codes = Counter()
        self.classified_feedback = False
        self._classified_feedback_requested = False
        self._classified_feedback = None
        self.candidate_exploration = False
        self._candidate_exploration = None
        self.source_action_gate = None
        self.case_witness_recorder = None
        self.evidence_dir = (Path(evidence_dir) if evidence_dir is not None
                             else None)
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.receipts = []
        self.online_decisions = []
        self._online_decisions_by_slot = {}
        self._completed = {}
        self.first_receipt_completed_at = None
        self._session_stop_reason = None
        self._hint_sequence = 0
        self._published_hints = []
        self._hint_source_uses = {source_id:0 for source_id in decoder.source_ids}
        self._latest_completed_batch = ()
        self._max_completed_buffer_id = None
        self._selection_uses = Counter()
        self._selection_gains = Counter()
        self._target_hits = set()
        self._online_live_max_tests = None
        self._online_live_duration_seconds = None
        self._online_finish_attempted = False
        # Only execute_batch failures belong here. Terminal cleanup errors must
        # not outrank an earlier transport failure in the live finalizer.
        self._online_primary_error = None
        self._online_final_trace = None
        self._online_final_plan_hex = None
        self._live_context = None
        self.compiled_plan = None
        self.compiled_plan_sha256 = None

    def process_owned_pair(self,input_id,coverage_id,*,creator_pid,on_receipt=None):
        return process_compiled_owned_pair(self,input_id,coverage_id,creator_pid=creator_pid,on_receipt=on_receipt)

    def execute_batch(self,batch,*,on_receipt=None):
        if not isinstance(batch,InputBatch) or batch.input_bytes!=8:
            raise ValueError('compiled-F6-rfuzz-raw8-required')
        vectors=[];before=len(self.receipts)
        for slot,records in enumerate(batch.tests):
            records=tuple(records);raw=b''.join(records);digest=sha256(raw).hexdigest();key=(batch.buffer_id,slot)
            cached=self._completed.get(key)
            if cached is not None:
                if cached[0]!=digest:
                    self._session_stop_reason='slot_identity_changed'
                    raise ValueError('RFuzz slot identity reused with different input')
                vectors.append(cached[1])
                if on_receipt is not None and cached[2] is not None:on_receipt(cached[2])
                continue
            coverage=bytes(5);case_hits=set()
            decision=dict(buffer_id=batch.buffer_id,slot=slot,raw_sha256=digest,
                raw_records_hex=[r.hex() for r in records],raw_record_sha256=[sha256(r).hexdigest() for r in records],
                wire_cycle_count=len(records),wire_record_sha256=digest,flow_id='F6',
                path_id=self.online_decoder.path_id,source_id=self.online_decoder.source_id,
                direction='CPU_TO_IP',case_id=None,case_ids=[],candidate_count=0,
                committed=False,admitted_status='not_admitted',rejection=None,
                weights={s:1 for s in self.online_decoder.source_ids})
            self.online_decisions.append(decision);self._online_decisions_by_slot[key]=decision
            if self._duration_reached():self._session_stop_reason=self._session_stop_reason or 'duration_budget'
            if self._session_stop_reason is not None or (self._online_live_max_tests is not None and len(self.receipts)>=self._online_live_max_tests):
                decision.update(candidate_disposition='not_admitted',candidate_disposition_reason='search_budget_exhausted')
                self._completed[key]=(digest,coverage,None);vectors.append(coverage);continue
            candidates=();admitted=();error_text=None;rejection=None;status='input_invalid'
            ticks=self._local_ticks()
            try:
                candidates=self.online_decoder.decode_sequence(records,cursor=self.runtime.cursor,case_index=len(self.runtime.attempts))
                candidate=candidates[0]
                decision.update(candidate_count=1,candidate=candidate.document())
                initial=len(self.runtime.attempts)
                try:result=self.runtime.submit(candidate.raw)
                finally:
                    attempts=self.runtime.attempts[initial:]
                    if attempts:
                        if len(attempts)!=1 or attempts[0].get('case_id')!=candidate.case_id:
                            raise ValueError('compiled-F6-rfuzz-admitted-case-mismatch')
                        admitted=candidates
                if not admitted or any(result.get(k)!=v for k,v in candidate.document().items()
                        if k in ('case_id','case_index','raw8_hex','words','instruction_address','prefix_hex')):
                    raise ValueError('compiled-F6-rfuzz-result-candidate-mismatch')
                material=build_f6_assertion_material(self.runtime)
                coverage=f6_case_feedback(material,case_ids=(candidate.case_id,))
                status='certified' if result['status']=='passed' and coverage==bytes([1]*5) else 'execution_failed'
                if status!='certified':
                    coverage=bytes(5);self._session_stop_reason='compiled_case_failed'
                decision.update(committed=True,candidate_disposition='admitted',admitted_status='submit_attempted',
                    candidate_disposition_reason=result['status'],feedback_observations=deepcopy(result['observations']))
                if status=='certified':
                    case_hits={target.target_id for target,hit in zip(self.targets,coverage) if hit}
            except CompiledF6CandidateRefused as error:
                coverage=bytes(5);case_hits.clear()
                rejection=dict(code=error.code,pointer=error.pointer,detail=error.detail)
                decision.update(candidate_disposition='rejected',candidate_disposition_reason='compiled_candidate_refused',rejection=rejection)
                error_text=str(error)
            except Exception as error:
                coverage=bytes(5);case_hits.clear()
                status='environment_error';error_text=str(error);self._session_stop_reason='environment_error'
                decision.update(candidate_disposition='uncertain',candidate_disposition_reason='compiled_execution_error',
                    admitted_status='submit_attempted' if admitted else 'not_admitted')
                if self._online_primary_error is None:self._online_primary_error=error
                elif error is not self._online_primary_error:self._online_primary_error.add_note('F6 execution: '+repr(error))
            decision.update(status=status,case_ids=[c.case_id for c in admitted],case_id=admitted[0].case_id if admitted else None)
            delta=self._tick_delta(ticks,self._local_ticks())
            source=dict(schema_version='compiled_F6_sequence.v1',path_id=self.online_decoder.path_id,
                source_ids=list(self.online_decoder.source_ids),candidates=[c.document() for c in admitted],candidate_count=len(admitted))
            receipt=ScenarioRfuzzReceipt(run_id=self.run_id,buffer_id=batch.buffer_id,slot=slot,raw_sha256=digest,
                genome_sha256=sha256(raw).hexdigest() if admitted else None,semantic_sha256=None,status=status,
                total_local_ticks=sum(delta.values()),coverage_hex=coverage.hex(),violations=(),error=error_text,
                trace=None,local_ticks=delta,path_id=self.online_decoder.path_id,
                applied_sources=self.online_decoder.source_ids if admitted else (),
                applied_source_ids=self.online_decoder.source_ids if status=='certified' else (),
                applied_template=0,applied_path=0,applied_hint_sequence=self._hint_sequence,
                effective_genome_sha256=sha256(raw).hexdigest() if admitted else None,
                online_case={'source':source},online_weights={s:1 for s in self.online_decoder.source_ids},rejection=rejection)
            self._receipts_append(key,digest,coverage,receipt)
            # Commit only after final receipt construction and archival. A
            # provisional all-passed projection cannot leak from a failed case.
            if receipt.status=='certified':self._target_hits.update(case_hits)
            vectors.append(coverage)
            if on_receipt is not None:on_receipt(receipt)
        self._latest_completed_batch=tuple(self.receipts[before:])
        self._max_completed_buffer_id=max(batch.buffer_id,self._max_completed_buffer_id or batch.buffer_id)
        return tuple(vectors)

    def mutation_hint(self):
        self._hint_sequence+=1
        return dict(schema_version='scenario_mutation_hint.v1',run_id=self.run_id,sequence=self._hint_sequence,
            feedback_scope='cumulative_run_feedback',max_completed_buffer_id=self._max_completed_buffer_id,
            latest_completed_batch=[dict(run_id=r.run_id,buffer_id=r.buffer_id,slot=r.slot,raw_sha256=r.raw_sha256,
                genome_sha256=r.genome_sha256,path_id=r.path_id,status=r.status) for r in self._latest_completed_batch],
            target_id=self.online_decoder.path_id,template=0,path=0,source=0,
            source_id=self.online_decoder.source_id,energy=1,online_weights={s:1 for s in self.online_decoder.source_ids},
            candidate_layout_digest=self.online_decoder.layout.digest)
    def _duration_reached(self):
        limit = self._online_live_duration_seconds
        if limit is None or self.first_receipt_completed_at is None:
            return False
        return time.monotonic() - self.first_receipt_completed_at >= limit

    def _local_ticks(self):
        runner = getattr(self.runtime, 'runner', None)
        ticks = getattr(runner, 'local_ticks', None)
        if not isinstance(ticks, dict):
            return {}
        return {name: int(value) for name, value in ticks.items()
                if type(value) is int}

    @staticmethod
    def _tick_delta(before, after):
        delta = {name: value - before.get(name, 0)
                 for name, value in after.items()}
        if any(value < 0 for value in delta.values()):
            raise ValueError('compiled RFuzz local ticks regressed')
        return delta

    def _receipts_append(self, identity, raw_hash, coverage, receipt):
        self.receipts.append(receipt)
        self._completed[identity] = (raw_hash, coverage, receipt)
        for source_id in receipt.applied_sources:
            self._hint_source_uses[source_id] = self._hint_source_uses.get(source_id,0)+1
            self._selection_uses[(0,0,source_id)] += 1
        if self.first_receipt_completed_at is None:
            self.first_receipt_completed_at = time.monotonic()

    def note_published_hint(self, hint):
        self._published_hints.append(dict(hint))

    def applied_source_uses(self):
        return dict(self._hint_source_uses)

    def _finish_online_session(self, *, defer_semantic_hash=False):
        """Finish the compiled runtime once and expose its exact session plan."""
        if not self._online_finish_attempted:
            self._online_finish_attempted = True
            primary = self._online_primary_error
            def remember(error, label):
                nonlocal primary
                if primary is None:
                    primary = error
                elif error is not primary:
                    primary.add_note(label + ': ' + repr(error))
                    for note in getattr(error, '__notes__', ()):
                        primary.add_note(label + ' note: ' + note)
            try:
                self.compiled_plan = self.runtime.finish()
            except BaseException as error:
                remember(error, 'F6 runtime finish')
            for attribute, exporter in (
                    ('_online_final_trace', lambda: self.runtime.trace
                     if self.compiled_plan is not None else self.runtime.session.trace()),
                    ('_online_final_plan_hex', lambda: self.runtime.session.encode_plan().hex())):
                try:
                    setattr(self, attribute, exporter())
                except BaseException as error:
                    remember(error, 'F6 partial ' + attribute)
            if self.compiled_plan is not None:
                try:
                    self.compiled_plan_sha256 = _digest(self.compiled_plan)
                except BaseException as error:
                    remember(error, 'F6 compiled plan digest')
            self._online_primary_error=primary
            if primary is not None:
                raise primary
        if self._online_primary_error is not None:raise self._online_primary_error
        return self._online_final_trace, self._online_final_plan_hex

    def execution_audit(self):
        return self.runtime.execution_audit()

    def closed_loop_state(self):
        return None

    def candidate_exploration_state(self):
        return None

    def classified_feedback_state(self):
        return None


def build_compiled_f6_rfuzz_executor(runtime,*,run_id,evidence_dir=None,feedback_interval=16):
    if not isinstance(runtime,CompiledF6Runtime):raise ValueError('compiled-F6-rfuzz-runtime-required')
    decoder=CompiledF6Decoder.from_runtime(runtime)
    targets=tuple(CoverageTarget(eid,runtime.cpu_id,'f6_evidence',1,1) for eid in EXPECTATION_IDS)
    return CompiledF6RfuzzExecutor(runtime=runtime,decoder=decoder,targets=targets,run_id=run_id,
        evidence_dir=evidence_dir,feedback_interval=feedback_interval)

def run_compiled_f6_rfuzz_session(*, artifacts, compiled_inputs, base_dir,
        cache_dir, run_id, session_dir, output_dir, client_binary, budget_seconds,
        max_tests, search_seed, max_runs_per_batch, rounds_per_case=128):
    from .compiled_f6_rfuzz_session import run_f6_live_and_fresh
    return run_f6_live_and_fresh(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir,
        cache_dir=cache_dir,run_id=run_id,session_dir=session_dir,output_dir=output_dir,client_binary=client_binary,
        budget_seconds=budget_seconds,max_tests=max_tests,search_seed=search_seed,
        max_runs_per_batch=max_runs_per_batch,rounds_per_case=rounds_per_case)
