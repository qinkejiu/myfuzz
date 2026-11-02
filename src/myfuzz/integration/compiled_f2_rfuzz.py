"""Address-only F2 seed for the compiled RFuzz transport."""
from .compiled_f2_layout import compile_f2_candidate_layout


def f2_seed_record(path) -> bytes:
    layout = compile_f2_candidate_layout(path)
    raw = path['execution_contract']['address'].to_bytes(4, 'little') + bytes(4)
    if not layout.classify(raw[:4]).accepted:
        raise ValueError('compiled-F2-rfuzz-seed-refused')
    return raw

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time
from myfuzz.integration.compiled_f2 import CompiledF2Runtime
from myfuzz.integration.compiled_f2_feedback import f2_observation_targets, f2_observation_hits
from myfuzz.integration.compiled_rfuzz_transport import process_compiled_owned_pair
from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor, ScenarioRfuzzReceipt
from myfuzz.scenario.compiled_f2_decoder import CompiledF2Decoder, CompiledF2CandidateRefused
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import RECORD_BYTES

EXECUTOR_NAME = 'compiled-f2-rfuzz'

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()

def _digest(value):
    return sha256(_canonical(value)).hexdigest()

def preflight_f2_test(runtime, decoder, records):
    if type(records) is not tuple or not 1 <= len(records) <= 8:
        raise CompiledF2CandidateRefused('sequence-count','/wire/records',{'observed':len(records)})
    if runtime._failed_attempt is not None:
        raise ValueError('compiled-F2-rfuzz-runtime-already-failed')
    if len(runtime.attempts)+len(records)>runtime.max_cases:
        raise CompiledF2CandidateRefused('case-budget-exhausted','/cases',
            {'admitted':len(runtime.attempts),'requested':len(records),'max_cases':runtime.max_cases})
    return decoder.decode_sequence(records,cursor=runtime.cursor,case_index=len(runtime.attempts))

class CompiledF2RfuzzExecutor(ScenarioRfuzzExecutor):
    def __init__(self, *, runtime, decoder, targets, run_id,
                 feedback_interval=16, evidence_dir=None):
        if not isinstance(decoder, CompiledF2Decoder):
            raise ValueError('compiled-F2-rfuzz-decoder-required')
        if decoder.path_id != runtime.path['path_id']:
            raise ValueError('compiled-F2-rfuzz-decoder-path-mismatch')
        if decoder.compiled_sha256 != getattr(runtime, 'compiled_digest', None):
            raise ValueError('compiled-F2-rfuzz-decoder-compiled-mismatch')
        if (not isinstance(targets, tuple) or not targets
                or any(not isinstance(row, CoverageTarget) for row in targets)):
            raise ValueError('compiled-F2-rfuzz-coverage-targets-required')
        if len({row.target_id for row in targets}) != len(targets):
            raise ValueError('compiled-F2-rfuzz-coverage-target-duplicate')
        if type(feedback_interval) is not int or feedback_interval < 1:
            raise ValueError('compiled-F2-rfuzz-feedback-interval-invalid')
        if not run_id:
            raise ValueError('compiled-F2-rfuzz-run-id-required')
        # --- the shared executor/report surface, initialized explicitly ----
        self.runtime = runtime
        self.decoder = None
        self.online_decoder = decoder
        self.session = getattr(runtime, 'session', None)
        runner = getattr(runtime, 'runner', None)
        self.factory = (lambda: runner) if runner is not None else None
        self.targets = targets
        self.run_id = run_id
        self.checker = None
        self.checker_config = None
        self.checker_identity_target = None
        self.runtime_contract = None
        self.runtime_path_status = 'legacy_unchecked'
        self._prepared_runtime_paths = None
        self._runtime_declaration_document = None
        self.fresh_runtime_path_documents = {}
        admission = decoder.runtime_path_admission
        if admission is not None:
            admission.validate_cached_identity()
            if (self.session is None
                    or self.session.runtime_contract != admission.prepared.contract
                    or self.session.runtime_path_document is None
                    or self.session.runtime_path_document['declaration'] != admission.prepared.document()
                    or self.session.instruction_image_binding_documents !=
                        (admission.instruction_binding.document(),)):
                raise ValueError('compiled-F2-rfuzz-runtime-path-session-mismatch')
            if getattr(runtime, 'runtime_path_admission', None) is None or (
                    runtime.runtime_path_admission.document() != admission.document()):
                raise ValueError('compiled-F2-rfuzz-runtime-path-admission-mismatch')
            self.runtime_contract = self.session.runtime_contract
            self.runtime_path_status = 'contract_preflight'
            self._prepared_runtime_paths = admission.prepared
            self._runtime_declaration_document = admission.prepared.document()
        else:
            raise ValueError('compiled-F2-rfuzz-runtime-path-admission-required')
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
        self._hint_source_uses = {decoder.source_id: 0}
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
        self._check_shared_surface()

    #: Attributes the shipped live transport and its report helpers read.  The
    #: compiled route owns their initialization explicitly instead of calling
    #: the genome-decoder base initializer, so a future transport change that
    #: adds a read fails here instead of deep inside a run.
    _SHARED_SURFACE = (
        'runtime', 'decoder', 'online_decoder', 'session', 'factory',
        'targets', 'run_id', 'checker', 'checker_config',
        'checker_identity_target', 'runtime_contract', 'runtime_path_status',
        'replay_only', 'feedback_interval', 'closed_loop_energy',
        'closed_loop_energy_source', 'path_switch', 'path_switch_source',
        'receipts', 'online_decisions', '_online_decisions_by_slot',
        '_completed', 'first_receipt_completed_at', '_session_stop_reason',
        '_hint_sequence', '_published_hints', '_latest_completed_batch',
        '_max_completed_buffer_id', '_selection_uses', '_selection_gains',
        '_target_hits', '_online_live_max_tests',
        '_online_live_duration_seconds', '_online_finish_attempted',
        '_online_final_trace', '_online_final_plan_hex', '_live_context',
        'evidence_dir', 'source_action_gate', 'case_witness_recorder',
        'classified_feedback', 'candidate_exploration',
        '_path_switch_attempts', '_path_switch_granted',
        '_path_switch_changed', '_path_switch_refusals', '_path_switch_codes')

    def _check_shared_surface(self):
        missing = [name for name in self._SHARED_SURFACE
                   if not hasattr(self, name)]
        if missing:
            raise RuntimeError(
                'compiled-F2-rfuzz-executor-surface-incomplete:'
                + ','.join(missing))

    def process_owned_pair(self, input_id, coverage_id, *, creator_pid, on_receipt=None):
        return process_compiled_owned_pair(self,input_id,coverage_id,creator_pid=creator_pid,on_receipt=on_receipt)

    def _check_case_budget(self, requested=1):
        if len(self.runtime.attempts)+requested>self.runtime.max_cases:
            raise CompiledF2CandidateRefused('case-budget-exhausted','/cases')

    def _new_decision(self,batch,slot,records,raw,raw_hash):
        return dict(buffer_id=batch.buffer_id,slot=slot,raw_sha256=raw_hash,
            raw_records_hex=[row.hex() for row in records],
            raw_record_sha256=[sha256(row).hexdigest() for row in records],
            wire_cycle_count=len(records),wire_record_sha256=raw_hash,
            source_id=self.online_decoder.source_id,path_id=self.online_decoder.path_id,
            direction=self.online_decoder.direction,flow_id='F2',case_id=None,case_ids=[],
            candidate_count=0,committed=False,admitted_status='not_admitted',
            weights={self.online_decoder.source_id:1},rejection=None)

    def _build_receipt(self,batch,slot,raw_hash,candidates,*,status,coverage,ticks,error,rejection=None):
        source=dict(schema_version='compiled_F2_sequence.v1',
            path_id=self.online_decoder.path_id,source_id=self.online_decoder.source_id,
            candidates=[candidate.document() for candidate in candidates],
            candidate_count=len(candidates))
        digest=sha256(b''.join(c.candidate_bytes for c in candidates)).hexdigest() if candidates else None
        return ScenarioRfuzzReceipt(run_id=self.run_id,buffer_id=batch.buffer_id,slot=slot,
            raw_sha256=raw_hash,genome_sha256=digest,semantic_sha256=None,status=status,
            total_local_ticks=sum(ticks.values()),coverage_hex=coverage.hex(),violations=(),error=error,
            trace=None,local_ticks=ticks,path_id=self.online_decoder.path_id,
            applied_sources=(self.online_decoder.source_id,) if candidates else (),
            applied_source_ids=(self.online_decoder.source_id,) if status=='certified' else (),
            applied_template=0,applied_path=0,applied_hint_sequence=self._hint_sequence,
            effective_genome_sha256=digest,online_case={'source':source},
            online_weights={self.online_decoder.source_id:1},rejection=rejection)

    def _validate_certificate(self,candidate,certificate):
        expected=dict(status='certified',case_id=candidate.case.case_id,path_id=candidate.path_id,
            source_id=candidate.source_id,execution_binding_sha256=self.runtime.execution_binding.digest,
            instruction_address=candidate.case.source.address,
            instruction_source_id=self.online_decoder.image['source_id'],
            instruction_sha256=sha256(bytes.fromhex(candidate.declaration['code_hex'])).hexdigest(),
            runtime_path_id=candidate.case.path_id,
            runtime_path_admission_sha256=self.runtime.runtime_path_admission.digest,runtime_admitted=True)
        if not isinstance(certificate,dict) or any(certificate.get(k)!=v for k,v in expected.items()):
            raise ValueError('compiled-F2-rfuzz-certificate-identity-mismatch')

    def execute_batch(self,batch,*,on_receipt=None):
        if not isinstance(batch,InputBatch) or batch.input_bytes!=RECORD_BYTES:
            raise ValueError('compiled F2 RFuzz input must use eight byte records')
        vectors=[];before_batch=len(self.receipts)
        for slot,records in enumerate(batch.tests):
            records=tuple(records);raw=b''.join(records);raw_hash=sha256(raw).hexdigest();identity=(batch.buffer_id,slot)
            previous=self._completed.get(identity)
            if previous is not None:
                if previous[0]!=raw_hash:
                    self._session_stop_reason='slot_identity_changed'
                    raise ValueError('RFuzz slot identity reused with different input')
                vectors.append(previous[1])
                if on_receipt is not None and previous[2] is not None:on_receipt(previous[2])
                continue
            coverage=bytes(self.counter_count)
            decision=self._new_decision(batch,slot,records,raw,raw_hash)
            self.online_decisions.append(decision);self._online_decisions_by_slot[identity]=decision
            if self._duration_reached():self._session_stop_reason=self._session_stop_reason or 'duration_budget'
            if self._session_stop_reason is not None or (self._online_live_max_tests is not None and len(self.receipts)>=self._online_live_max_tests):
                decision.update(candidate_disposition='not_admitted',candidate_disposition_reason='search_budget_exhausted')
                self._completed[identity]=(raw_hash,coverage,None);vectors.append(coverage);continue
            planned=();attempted=[];submission_attempted=False;failure_error=None
            before_ticks=self._local_ticks();status='certified';error_text=None;rejection=None
            try:
                planned=preflight_f2_test(self.runtime,self.online_decoder,records)
                decision.update(candidate_count=len(planned),candidate={'schema_version':'compiled_F2_sequence.v1',
                    'candidates':[c.document() for c in planned]},
                    projected_candidate_sha256=[sha256(c.candidate_bytes).hexdigest() for c in planned])
                certificates=[]
                for candidate in planned:
                    if self.runtime.cursor!=candidate.case.source.address:
                        raise ValueError('compiled-F2-rfuzz-runtime-cursor-diverged')
                    # Calling submit is distinct from the runtime admitting a case.
                    # Its stable/admission checks can fail before appending attempts.
                    attempt_start = len(self.runtime.attempts)
                    submission_attempted = True
                    try:
                        certificate=self.runtime.submit(candidate.candidate_bytes)
                    finally:
                        admitted = self.runtime.attempts[attempt_start:]
                        if (len(admitted) == 1 and
                                admitted[0].get('case_id') == candidate.case.case_id):
                            attempted.append(candidate)
                    if (len(admitted) != 1 or
                            admitted[0].get('case_id') != candidate.case.case_id):
                        raise ValueError('compiled-F2-rfuzz-runtime-attempt-identity-mismatch')
                    self._validate_certificate(candidate,certificate);certificates.append(certificate)
                hits,diagnostics=f2_observation_hits(runtime=self.runtime,candidates=planned,certificates=tuple(certificates))
                coverage=bytes(int(target.target_id in hits) for target in self.targets)
                self._target_hits.update(hits)
                decision.update(feedback_observations=diagnostics,committed=True,
                    candidate_disposition='admitted',candidate_disposition_reason='rtl_case_certified',admitted_status='submit_attempted')
            except CompiledF2CandidateRefused as error:
                error_text=str(error)
                if submission_attempted:
                    status='environment_error';self._session_stop_reason='environment_error'
                    decision.update(candidate_disposition='uncertain',candidate_disposition_reason='compiled_execution_error',admitted_status='submit_attempted')
                    failure_error=error
                else:
                    status='input_invalid'
                    rejection=dict(code=error.code,pointer=error.pointer,detail=deepcopy(error.detail))
                    decision.update(candidate_disposition='rejected',candidate_disposition_reason='compiled_candidate_refused',rejection=rejection)
            except Exception as error:
                status='environment_error';error_text=f'{type(error).__name__}: {error}'
                self._session_stop_reason='environment_error'
                decision.update(candidate_disposition='uncertain',candidate_disposition_reason='compiled_execution_error',
                    admitted_status='submit_attempted' if submission_attempted else 'not_admitted')
                failure_error=error
            decision['case_ids']=[c.case.case_id for c in attempted]
            decision['case_id']=decision['case_ids'][0] if attempted else None
            decision['status']=status
            if failure_error is not None:
                if self._online_primary_error is None:
                    self._online_primary_error = failure_error
                elif failure_error is not self._online_primary_error:
                    self._online_primary_error.add_note('F2 execution: '+repr(failure_error))
                self._save_failure(batch,slot,raw,decision,failure_error)
            receipt=self._build_receipt(batch,slot,raw_hash,tuple(attempted),status=status,
                coverage=coverage,ticks=self._tick_delta(before_ticks,self._local_ticks()),error=error_text,rejection=rejection)
            self._receipts_append(identity,raw_hash,coverage,receipt);vectors.append(coverage)
            if on_receipt is not None:on_receipt(receipt)
        self._latest_completed_batch=tuple(self.receipts[before_batch:])
        self._max_completed_buffer_id=max(batch.buffer_id,self._max_completed_buffer_id or batch.buffer_id)
        return tuple(vectors)

    def _save_failure(self,batch,slot,raw,decision,error):
        if self.evidence_dir is None:return
        try:
            payload=dict(schema_version='compiled_F2_rfuzz_failure.v1',decision=deepcopy(decision),
                raw_hex=raw.hex(),attempts=deepcopy(self.runtime.attempts),records=deepcopy(self.runtime.records),error=repr(error))
            (self.evidence_dir/f'compiled-f2-failure-{batch.buffer_id}-{slot}.json').write_bytes(_canonical(payload))
        except Exception as export_error:
            error.add_note('F2 failure export: '+repr(export_error))

    def mutation_hint(self):
        self._hint_sequence+=1
        return dict(schema_version='scenario_mutation_hint.v1',run_id=self.run_id,sequence=self._hint_sequence,
            feedback_scope='cumulative_run_feedback',max_completed_buffer_id=self._max_completed_buffer_id,
            latest_completed_batch=[dict(run_id=r.run_id,buffer_id=r.buffer_id,slot=r.slot,
                raw_sha256=r.raw_sha256,genome_sha256=r.genome_sha256,path_id=r.path_id,status=r.status) for r in self._latest_completed_batch],
            target_id=self.online_decoder.path_id,template=0,path=0,source=0,
            source_id=self.online_decoder.source_id,energy=1,online_weights={self.online_decoder.source_id:1},
            candidate_layout_digest=self.online_decoder.layout.digest,compiled_sha256=self.online_decoder.compiled_sha256)

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
        self._hint_source_uses[self.online_decoder.source_id] = (
            self._hint_source_uses.get(self.online_decoder.source_id, 0) + 1)
        self._selection_uses[(0, 0, self.online_decoder.source_id)] += 1
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
                remember(error, 'F2 runtime finish')
            for attribute, exporter in (
                    ('_online_final_trace', lambda: self.runtime.trace
                     if self.compiled_plan is not None else self.runtime.session.trace()),
                    ('_online_final_plan_hex', lambda: self.runtime.session.encode_plan().hex())):
                try:
                    setattr(self, attribute, exporter())
                except BaseException as error:
                    remember(error, 'F2 partial ' + attribute)
            if self.compiled_plan is not None:
                try:
                    self.compiled_plan_sha256 = _digest(self.compiled_plan)
                except BaseException as error:
                    remember(error, 'F2 compiled plan digest')
            if primary is not None:
                raise primary
        return self._online_final_trace, self._online_final_plan_hex

    def execution_audit(self):
        return self.runtime.execution_audit()

    def candidate_exploration_state(self):
        return None

    def classified_feedback_state(self):
        return None


def build_compiled_f2_rfuzz_executor(runtime, *, run_id, evidence_dir=None, feedback_interval=16):
    if not isinstance(runtime,CompiledF2Runtime):raise ValueError('compiled-F2-rfuzz-runtime-required')
    if run_id!=runtime.run_id:raise ValueError('compiled-F2-rfuzz-run-id-mismatch')
    decoder=CompiledF2Decoder.from_runtime(runtime)
    return CompiledF2RfuzzExecutor(runtime=runtime,decoder=decoder,targets=f2_observation_targets(runtime.path),
        run_id=run_id,evidence_dir=evidence_dir,feedback_interval=feedback_interval)


def run_compiled_f2_rfuzz_session(*, artifacts, compiled_inputs, base_dir,
        cache_dir, run_id, session_dir, output_dir, client_binary, budget_seconds,
        max_tests, search_seed, max_runs_per_batch, rounds_per_case=128):
    """Run the F2-specific live/fresh lifecycle behind the explicit entry."""
    from .compiled_f2_rfuzz_session import run_f2_live_and_fresh
    return run_f2_live_and_fresh(artifacts=artifacts, compiled_inputs=compiled_inputs,
        base_dir=base_dir, cache_dir=cache_dir, run_id=run_id,
        session_dir=session_dir, output_dir=output_dir, client_binary=client_binary,
        budget_seconds=budget_seconds, max_tests=max_tests, search_seed=search_seed,
        max_runs_per_batch=max_runs_per_batch, rounds_per_case=rounds_per_case)
