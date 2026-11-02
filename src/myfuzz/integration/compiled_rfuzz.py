"""Compiled F4 candidates over the real RFuzz transport, with real receipts.

One admitted ``CompiledF4Runtime`` owns the whole session.  Every RFuzz raw
decision record is decoded by :mod:`myfuzz.scenario.compiled_online_decoder`
into the exact compiled candidate and submitted to that one runtime, so the
same native processes are fed continuously.  The session's terminal prefix is
then re-executed by ``CompiledF4Runtime.replay`` on fresh native processes and
the saved plan is compared there -- never by re-reading the same trace.

Coverage
--------
The coverage targets are declared predicates on the committed register word of
the certificate the runtime actually returned (``certificate["commit"]["after"]``
for both the GPIO causal row and the generic APB storage row).  They are real
observation bits: a target is a hit only when the observed commit word has that
bit set.  A refused candidate produces the zero coverage vector, never a
fabricated hit.

Receipts
--------
Every admitted candidate becomes one ``ScenarioRfuzzReceipt`` whose
``path_id`` is the compiled F4 path and whose decision carries the exact
``source_id``, register contract, value and compiled/layout digests.  The
transport persists exactly these rows to ``session/receipts.jsonl``;
:func:`join_compiled_receipts` re-checks that every saved row joins the
executable F4 path of ``compiled_paths.v1``.

The raw wire record is retained verbatim in the receipt decision
(``raw_records_hex``).  The compiled candidate retained by the runtime is the
declared byte prefix of that record; the bytes after ``layout.byte_length`` are
unreferenced transport lanes that never reach the RTL (see the decoder module).
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

from myfuzz.integration.compiled_f4 import CompiledF4Runtime
from myfuzz.integration.rfuzz_wire import (
    InputBatch,
)
from myfuzz.integration.compiled_rfuzz_transport import (
    parse_compiled_input_buffer as _parse_compiled_input_buffer,
    process_compiled_owned_pair,
)
from myfuzz.integration.scenario_rfuzz import (
    ScenarioRfuzzExecutor,
    ScenarioRfuzzReceipt,
)
from myfuzz.scenario.compiled_online_decoder import (
    MAX_CANDIDATE_RECORDS,
    CompiledCandidateRefused,
    CompiledOnlineDecoder,
)
from myfuzz.scenario.compiled_paths import compiled_document_sha256
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import RECORD_BYTES

EXECUTOR_NAME = 'compiled-f4-rfuzz'
JOIN_SCHEMA = 'compiled_receipt_join.v1'
FRESH_VERIFICATION_SCHEMA = 'fresh_verification.v1'

#: The register commit word bits this route observes.  The real native
#: scenario mutations submitted values 0/1/2/4, i.e. the LOW byte; targets on
#: bits 24..31 were never reached and produced an all-zero coverage vector.
#: Bits 0..7 are the reachable low byte, so a value of 1/2/4 really hits a
#: target and the coverage-guided contract is not vacuous.
COMMIT_TARGET_BITS = tuple(range(0, 8))
COMMIT_OBSERVATION_LANE = 'storage_commit_after'

#: The native scenario test can carry a longer wire sequence than the eight
#: decision fields (the legacy genome decoder accepts up to 200 records).  The
#: parser therefore uses the legacy bound and never clips it.
COMPILED_WIRE_MAX_CYCLES = 200
#: Only the first eight records of one test are compiled candidates; every
#: further record is an unreferenced transport lane and is recorded as such.
COMPILED_CANDIDATE_CYCLES = MAX_CANDIDATE_RECORDS
SEQUENCE_SCHEMA = 'compiled_online_sequence.v1'


def parse_compiled_input_buffer(data):
    """Parse one RFuzz input buffer with the legacy 200-record bound.

    The shipped ``process_owned_pair`` used
    ``online_decoder.max_input_bytes // RECORD_BYTES`` (8 // 8 = 1) for this
    bound, which refuses the real native scenario test.  The wire parser
    accepts 1..200 records, exactly like ``GenomeRecordDecoder.max_records``;
    the candidate count is capped separately by the executor.
    """
    return _parse_compiled_input_buffer(data)


def _canonical(value) -> bytes:
    # The runtime's canonical form is the default ASCII-escaped JSON; every
    # compiled-route digest that can be compared with a runtime digest (and the
    # prefix/replay evidence digests) uses it so no second spelling can drift.
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def _digest(value) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sequence_digest(candidates) -> str:
    """One identity for the whole test's ordered candidate sequence."""
    return sha256(b''.join(candidate.candidate_bytes
                           for candidate in candidates)).hexdigest()


def _sequence_document(candidates, *, wire_cycle_count=None,
                       unreferenced=()) -> dict:
    """The one-candidate document, or the ordered-sequence document.

    ``wire_cycle_count`` is the whole test's record count; ``unreferenced``
    holds the records beyond the eight-candidate cap, which never reach the
    RTL and are retained only as transport-lane evidence.
    """
    total = (len(candidates) + len(unreferenced)
             if wire_cycle_count is None else wire_cycle_count)
    if len(candidates) == 1:
        document = dict(candidates[0].document())
    else:
        document = {
            'schema_version': SEQUENCE_SCHEMA,
            'path_id': candidates[0].path_id,
            'source_id': candidates[0].source_id,
            'register': candidates[0].register,
            'compiled_sha256': candidates[0].compiled_sha256,
            'layout_digest': candidates[0].layout_digest,
            'candidates': [candidate.document() for candidate in candidates],
            'values': [candidate.value for candidate in candidates],
        }
    document.update(
        wire_cycle_count=total,
        candidate_count=len(candidates),
        unreferenced_wire_cycle_count=len(unreferenced),
        unreferenced_wire_records_hex=[record.hex()
                                       for record in unreferenced])
    return document


def compiled_commit_targets(path) -> tuple:
    """The real coverage targets: declared bits of the observed commit word."""
    if not isinstance(path, dict) or path.get('flow_id') != 'F4':
        raise ValueError('compiled-rfuzz-F4-path-required')
    streams = [row for row in path.get('sources', ())
               if row.get('kind') == 'cpu_mmio_stream']
    if len(streams) != 1:
        raise ValueError('compiled-rfuzz-stream-source-required')
    access = streams[0].get('register_access', {})
    component = access.get('target_component')
    register = access.get('register')
    if not isinstance(component, str) or not component:
        raise ValueError('compiled-rfuzz-target-component-required')
    if not isinstance(register, str) or not register:
        raise ValueError('compiled-rfuzz-register-required')
    targets = tuple(
        CoverageTarget(
            f'compiled_f4.{component}.{register}.commit_word_bit_{bit}',
            component, COMMIT_OBSERVATION_LANE, 1 << bit, 1 << bit)
        for bit in COMMIT_TARGET_BITS)
    if len({target.target_id for target in targets}) != len(targets):
        raise ValueError('compiled-rfuzz-coverage-target-duplicate')
    return targets


def compiled_commit_hits(certificate, targets) -> frozenset:
    """Apply the declared target predicates to the actual commit observation."""
    if not isinstance(certificate, dict) or certificate.get('status') != 'certified':
        raise ValueError('compiled-rfuzz-certified-certificate-required')
    commit = certificate.get('commit')
    if not isinstance(commit, dict):
        raise ValueError('compiled-rfuzz-commit-observation-required')
    word = commit.get('after')
    if type(word) is not int or not 0 <= word <= 0xffffffff:
        raise ValueError('compiled-rfuzz-commit-word-invalid')
    return frozenset(target.target_id for target in targets
                     if word & target.mask == target.value)


def join_compiled_receipts(receipts_path, compiled) -> dict:
    """Re-check every saved receipt row against the executable F4 path.

    The join is the evidence join the gate needs: a row that names another
    path, another source or another flow is a refusal, not a warning.
    """
    path = Path(receipts_path)
    if not path.is_file():
        raise ValueError('compiled-receipt-file-required')
    if not isinstance(compiled, dict):
        raise ValueError('compiled-receipt-document-required')
    paths = [row for row in compiled.get('paths', ())
             if row.get('flow_id') == 'F4' and row.get('status') == 'executable']
    if len(paths) != 1:
        raise ValueError('compiled-receipt-f4-path-required')
    path_row = paths[0]
    streams = [row for row in path_row.get('sources', ())
               if row.get('kind') == 'cpu_mmio_stream']
    if len(streams) != 1:
        raise ValueError('compiled-receipt-stream-source-required')
    expected_path = path_row['path_id']
    expected_source = streams[0]['source_id']
    rows = 0
    statuses = Counter()
    raw = path.read_bytes()
    for line_number, line in enumerate(raw.splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except ValueError as error:
            raise ValueError(
                f'compiled-receipt-row-invalid:line {line_number}') from error
        if not isinstance(row, dict):
            raise ValueError(f'compiled-receipt-row-invalid:line {line_number}')
        if row.get('path_id') != expected_path:
            raise ValueError(
                'compiled-receipt-path-mismatch:'
                f'line {line_number}: expected {expected_path!r}, '
                f'observed {row.get("path_id")!r}')
        if row.get('source_id') != expected_source:
            raise ValueError(
                'compiled-receipt-source-mismatch:'
                f'line {line_number}: expected {expected_source!r}, '
                f'observed {row.get("source_id")!r}')
        if row.get('flow_id') not in (None, 'F4'):
            raise ValueError(
                'compiled-receipt-flow-mismatch:'
                f'line {line_number}: observed {row.get("flow_id")!r}')
        rows += 1
        statuses[row.get('status')] += 1
    if rows == 0:
        raise ValueError('compiled-receipt-join-empty')
    return {
        'schema_version': JOIN_SCHEMA,
        'status': 'ok',
        'path_id': expected_path,
        'source_id': expected_source,
        'rows': rows,
        'status_counts': dict(sorted(statuses.items())),
        'receipts_sha256': sha256(raw).hexdigest(),
        'compiled_sha256': compiled_document_sha256(compiled),
    }


class CompiledRfuzzExecutor(ScenarioRfuzzExecutor):
    """The RFuzz executor interface backed by one compiled F4 runtime.

    ``ScenarioRfuzzExecutor`` is subclassed only to enter the shipped live
    transport's executor gate.  This route has no genome decoder, no family
    factory and no online case reservation, so the base initializer is
    deliberately not called: every shared attribute the transport and its
    report helpers read is initialized here, every operation that would use
    base genome state is overridden, and finalization is the compiled
    runtime's own full-prefix finish.  ``execute_batch`` refuses before any
    native command when the case or slot budget is exhausted.
    """

    def __init__(self, *, runtime, decoder, targets, run_id,
                 feedback_interval=16, evidence_dir=None):
        if not isinstance(decoder, CompiledOnlineDecoder):
            raise ValueError('compiled-rfuzz-decoder-required')
        if decoder.path_id != runtime.path['path_id']:
            raise ValueError('compiled-rfuzz-decoder-path-mismatch')
        if decoder.compiled_sha256 != getattr(runtime, 'compiled_digest', None):
            raise ValueError('compiled-rfuzz-decoder-compiled-mismatch')
        if (not isinstance(targets, tuple) or not targets
                or any(not isinstance(row, CoverageTarget) for row in targets)):
            raise ValueError('compiled-rfuzz-coverage-targets-required')
        if len({row.target_id for row in targets}) != len(targets):
            raise ValueError('compiled-rfuzz-coverage-target-duplicate')
        if type(feedback_interval) is not int or feedback_interval < 1:
            raise ValueError('compiled-rfuzz-feedback-interval-invalid')
        if not run_id:
            raise ValueError('compiled-rfuzz-run-id-required')
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
                raise ValueError('compiled-rfuzz-runtime-path-session-mismatch')
            if getattr(runtime, 'runtime_path_admission', None) is None or (
                    runtime.runtime_path_admission.document() != admission.document()):
                raise ValueError('compiled-rfuzz-runtime-path-admission-mismatch')
            self.runtime_contract = self.session.runtime_contract
            self.runtime_path_status = 'contract_preflight'
            self._prepared_runtime_paths = admission.prepared
            self._runtime_declaration_document = admission.prepared.document()
        elif self.session is not None:
            raise ValueError('compiled-rfuzz-runtime-path-admission-required')
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
                'compiled-rfuzz-executor-surface-incomplete:'
                + ','.join(missing))

    # ------------------------------------------------------------------
    # The live transport's wire entry point
    # ------------------------------------------------------------------
    def process_owned_pair(self, input_id, coverage_id, *, creator_pid,
                           on_receipt=None):
        """Exchange one bounded compiled wire buffer through owned segments."""
        return process_compiled_owned_pair(self, input_id, coverage_id,
            creator_pid=creator_pid, on_receipt=on_receipt)

    # ------------------------------------------------------------------
    # The live transport's batch entry point
    # ------------------------------------------------------------------
    def execute_batch(self, batch, *, on_receipt=None):
        if not isinstance(batch, InputBatch) or batch.input_bytes != RECORD_BYTES:
            raise ValueError('compiled RFuzz input must use eight byte records')
        coverages = []
        before_batch = len(self.receipts)
        for slot, records in enumerate(batch.tests):
            wire_records = tuple(records)
            candidate_records = wire_records[:COMPILED_CANDIDATE_CYCLES]
            unreferenced = wire_records[COMPILED_CANDIDATE_CYCLES:]
            raw = b''.join(wire_records)
            raw_hash = sha256(raw).hexdigest()
            identity = (batch.buffer_id, slot)
            previous = self._completed.get(identity)
            if previous is not None:
                if previous[0] != raw_hash:
                    raise ValueError('RFuzz slot identity reused with different input')
                coverages.append(previous[1])
                if on_receipt is not None and previous[2] is not None:
                    on_receipt(previous[2])
                continue
            coverage = bytes(self.counter_count)
            decision = self._new_decision(batch, slot, records, raw, raw_hash)
            decision['wire_cycle_count'] = len(wire_records)
            decision['candidate_count'] = 0
            decision['unreferenced_wire_cycle_count'] = len(unreferenced)
            decision['unreferenced_wire_records_hex'] = [
                record.hex() for record in unreferenced]
            self.online_decisions.append(decision)
            self._online_decisions_by_slot[identity] = decision
            if self._session_stop_reason is None and self._duration_reached():
                self._session_stop_reason = 'duration_budget'
            if (self._session_stop_reason is not None
                    or (self._online_live_max_tests is not None
                        and len(self.receipts) >= self._online_live_max_tests)):
                decision['candidate_disposition'] = 'not_admitted'
                decision['candidate_disposition_reason'] = 'search_budget_exhausted'
                self._completed[identity] = (raw_hash, coverage, None)
                coverages.append(coverage)
                continue
            receipt = None
            planned = None
            try:
                decode_started = time.monotonic()
                planned = self.online_decoder.decode_sequence(
                    candidate_records, cursor=self.runtime.cursor,
                    case_index=len(self.runtime.records))
                decision['candidate_count'] = len(planned)
                self._check_case_budget(len(planned))
                select_seconds = time.monotonic() - decode_started
                before_ticks = self._local_ticks()
                submit_started = time.monotonic()
                certificates = []
                for candidate in planned:
                    if self.runtime.cursor != candidate.case.source.address:
                        raise ValueError(
                            'compiled-rfuzz-runtime-cursor-diverged')
                    certificates.append(
                        self.runtime.submit(candidate.candidate_bytes))
                submit_seconds = time.monotonic() - submit_started
                after_ticks = self._local_ticks()
                ticks = self._tick_delta(before_ticks, after_ticks)
                hits = set()
                for certificate in certificates:
                    hits.update(compiled_commit_hits(certificate, self.targets))
                coverage = bytes(int(target.target_id in hits)
                                 for target in self.targets)
                self._target_hits.update(hits)
                receipt = self._build_receipt(
                    batch, slot, raw_hash, planned, status='certified',
                    coverage=coverage, ticks=ticks, error=None,
                    wire_cycle_count=len(wire_records),
                    unreferenced=unreferenced)
                self._observe_cost(select_seconds, submit_seconds)
                decision.update(
                    source_id=planned[0].source_id,
                    path_id=planned[0].path_id,
                    case_id=planned[0].case_id,
                    direction=planned[0].direction,
                    flow_id='F4', target_id=planned[0].path_id,
                    operator_id='compiled_candidate_layout',
                    candidate_id=_sequence_digest(planned),
                    source_selection_reason='compiled_candidate_layout',
                    candidate_disposition='admitted',
                    candidate_disposition_reason='rtl_case_committed',
                    admitted_status='submit_attempted', committed=True,
                    candidate=_sequence_document(
                        planned, wire_cycle_count=len(wire_records),
                        unreferenced=unreferenced),
                    candidate_count=len(planned),
                    phase_timing_seconds={
                        'selection_decode': select_seconds,
                        'rtl_submit': submit_seconds,
                        'receipt_build': 0.0},
                    submit_timing_seconds=submit_seconds,
                    runner_timing_seconds={},
                    interaction_source_gains={})
            except CompiledCandidateRefused as error:
                decision.update(
                    source_id=self.online_decoder.source_id,
                    path_id=self.online_decoder.path_id,
                    direction=self.online_decoder.direction,
                    flow_id='F4', target_id=self.online_decoder.path_id,
                    candidate_disposition='rejected',
                    candidate_disposition_reason='compiled_candidate_refused',
                    admitted_status='not_admitted', committed=False,
                    rejection={'schema_version': 'compiled_candidate_rejection.v1',
                               'code': error.code, 'pointer': error.pointer,
                               'detail': deepcopy(error.detail)})
                receipt = self._build_receipt(
                    batch, slot, raw_hash, planned, status='input_invalid',
                    coverage=coverage, ticks={}, error=str(error),
                    rejection=decision['rejection'],
                    wire_cycle_count=len(wire_records),
                    unreferenced=unreferenced)
                if error.code in ('slot-budget-exhausted',
                                  'case-budget-exhausted'):
                    self._session_stop_reason = error.code
            except Exception as error:
                decision.update(
                    source_id=self.online_decoder.source_id,
                    path_id=self.online_decoder.path_id,
                    direction=self.online_decoder.direction,
                    flow_id='F4', target_id=self.online_decoder.path_id,
                    candidate_disposition='uncertain',
                    candidate_disposition_reason='compiled_execution_error',
                    admitted_status='submit_attempted', committed=False)
                receipt = self._build_receipt(
                    batch, slot, raw_hash, None, status='environment_error',
                    coverage=coverage, ticks={},
                    error=f'{type(error).__name__}: {error}',
                    wire_cycle_count=len(wire_records),
                    unreferenced=unreferenced)
                self._session_stop_reason = 'environment_error'
                self._save_failure(batch, slot, raw, decision, error)
            self._receipts_append(identity, raw_hash, coverage, receipt)
            coverages.append(coverage)
            if on_receipt is not None:
                on_receipt(receipt)
        if len(self.receipts) > before_batch:
            self._latest_completed_batch = tuple(self.receipts[before_batch:])
        self._max_completed_buffer_id = (
            batch.buffer_id if self._max_completed_buffer_id is None
            else max(self._max_completed_buffer_id, batch.buffer_id))
        return tuple(coverages)

    # ------------------------------------------------------------------
    # Budget / evidence / receipt helpers
    # ------------------------------------------------------------------
    def _check_case_budget(self, requested=1):
        limit = getattr(self.runtime, 'max_cases', None)
        admitted = len(getattr(self.runtime, 'records', ()))
        if type(limit) is not int or limit < 1:
            raise ValueError('compiled-rfuzz-runtime-case-budget-invalid')
        if type(requested) is not int or requested < 1:
            raise ValueError('compiled-rfuzz-case-budget-request-invalid')
        if admitted + requested > limit:
            raise CompiledCandidateRefused(
                'case-budget-exhausted',
                detail={'admitted': admitted, 'requested': requested,
                        'max_cases': limit})

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

    def _new_decision(self, batch, slot, records, raw, raw_hash):
        source_id = self.online_decoder.source_id
        return {
            'buffer_id': batch.buffer_id, 'slot': slot,
            'raw_sha256': raw_hash,
            'raw_records_hex': [record.hex() for record in records],
            'weights': {source_id: self._source_weight()},
            'source_id': source_id,
            'path_id': self.online_decoder.path_id,
            'case_id': None, 'direction': self.online_decoder.direction,
            'flow_id': 'F4', 'target_id': self.online_decoder.path_id,
            'operator_id': 'compiled_candidate_layout', 'candidate_id': None,
            'source_selection_reason': 'compiled_candidate_layout',
            'candidate_disposition': None,
            'candidate_disposition_reason': None,
            'rejection': None, 'source_action': None,
            'closed_loop_feedback': None,
            'admitted_status': 'not_admitted', 'committed': False,
            'wire_record_sha256': raw_hash,
            'wire_cycle_count': len(records),
            'candidate_count': 0,
            'unreferenced_wire_cycle_count': max(
                0, len(records) - COMPILED_CANDIDATE_CYCLES),
            'unreferenced_wire_records_hex': [
                record.hex()
                for record in records[COMPILED_CANDIDATE_CYCLES:]],
        }

    def _build_receipt(self, batch, slot, raw_hash, candidates, *, status,
                       coverage, ticks, error, rejection=None,
                       wire_cycle_count=None, unreferenced=()):
        if candidates:
            source_id = candidates[0].source_id
            path_id = candidates[0].path_id
            genome_sha256 = _sequence_digest(candidates)
            source_document = {'source': _sequence_document(
                candidates, wire_cycle_count=wire_cycle_count,
                unreferenced=unreferenced)}
        else:
            source_id = self.online_decoder.source_id
            path_id = self.online_decoder.path_id
            genome_sha256 = None
            source_document = {'source': {
                'schema_version': 'compiled_online_candidate.v1',
                'source_id': source_id, 'path_id': path_id,
                'wire_cycle_count': (wire_cycle_count
                                     if wire_cycle_count is not None else 0),
                'candidate_count': 0,
                'unreferenced_wire_cycle_count': len(unreferenced),
                'unreferenced_wire_records_hex': [
                    record.hex() for record in unreferenced]}}
        total = sum(ticks.values())
        return ScenarioRfuzzReceipt(
            self.run_id, batch.buffer_id, slot, raw_hash,
            genome_sha256, None, status, total, coverage.hex(), (), error,
            None, None, ticks, path_id, (source_id,), 0, 0,
            self._hint_sequence, genome_sha256, None, (source_id,), None,
            source_document, {source_id: self._source_weight()}, None,
            (rejection if rejection is not None else None), None, None)

    def _receipts_append(self, identity, raw_hash, coverage, receipt):
        self.receipts.append(receipt)
        self._completed[identity] = (raw_hash, coverage, receipt)
        self._hint_source_uses[self.online_decoder.source_id] = (
            self._hint_source_uses.get(self.online_decoder.source_id, 0) + 1)
        self._selection_uses[(0, 0, self.online_decoder.source_id)] += 1
        if self.first_receipt_completed_at is None:
            self.first_receipt_completed_at = time.monotonic()

    def _observe_cost(self, select_seconds, submit_seconds):
        key = (0, 0, self.online_decoder.source_id)
        hits = len(self._target_hits)
        self._selection_gains[key] += hits

    def _source_weight(self):
        key = (0, 0, self.online_decoder.source_id)
        uses = self._selection_uses[key]
        uncovered = any(target.target_id not in self._target_hits
                        for target in self.targets)
        score = ((64 if uncovered else 8)
                 + 32 / (uses + 1)
                 + 16 * self._selection_gains[key] / (uses + 1))
        return max(1, min(255, round(score)))

    def _save_failure(self, batch, slot, raw, decision, error):
        if self.evidence_dir is None:
            return
        directory = Path(self.evidence_dir)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            name = (f'compiled-f4-failure-{batch.buffer_id}-{slot}.json')
            payload = {
                'schema_version': 'compiled_rfuzz_failure.v1',
                'run_id': self.run_id,
                'buffer_id': batch.buffer_id, 'slot': slot,
                'raw_records_hex': [raw.hex()],
                'decision': deepcopy(decision),
                'error_type': type(error).__name__, 'error': str(error),
                'partial_evidence': False,
            }
            (directory / name).write_bytes(_canonical(payload) + b'\n')
        except Exception:
            # Evidence collection must never turn a real execution failure into
            # a success; the failing receipt already records the error.
            pass

    # ------------------------------------------------------------------
    # Mutation hint / finalization
    # ------------------------------------------------------------------
    def mutation_hint(self):
        if self.replay_only:
            raise ValueError('replay-only executor cannot provide mutation hints')
        self._hint_sequence += 1
        weight = self._source_weight()
        return {
            'schema_version': 'scenario_mutation_hint.v1',
            'run_id': self.run_id,
            'sequence': self._hint_sequence,
            'feedback_scope': 'cumulative_run_feedback',
            'max_completed_buffer_id': self._max_completed_buffer_id,
            'latest_completed_batch': [
                {'run_id': receipt.run_id, 'buffer_id': receipt.buffer_id,
                 'slot': receipt.slot, 'raw_sha256': receipt.raw_sha256,
                 'genome_sha256': receipt.genome_sha256,
                 'path_id': receipt.path_id, 'status': receipt.status}
                for receipt in self._latest_completed_batch],
            'target_id': self.online_decoder.path_id,
            'template': 0, 'path': 0, 'source': 0,
            'source_id': self.online_decoder.source_id,
            'energy': weight,
            'online_weights': {self.online_decoder.source_id: weight},
            'candidate_layout_digest': self.online_decoder.layout.digest,
            'compiled_sha256': self.online_decoder.compiled_sha256,
        }

    def note_published_hint(self, hint):
        self._published_hints.append(dict(hint))

    def applied_source_uses(self):
        return dict(self._hint_source_uses)

    def _finish_online_session(self, *, defer_semantic_hash=False):
        """Finish the compiled runtime once and expose its exact session plan."""
        if not self._online_finish_attempted:
            self._online_finish_attempted = True
            try:
                self.compiled_plan = self.runtime.finish()
            except BaseException:
                try:
                    self._online_final_trace = self.runtime.session.trace()
                    self._online_final_plan_hex = (
                        self.runtime.session.encode_plan().hex())
                except BaseException:
                    pass
                raise
            self._online_final_trace = self.runtime.trace
            self._online_final_plan_hex = self.runtime.session.encode_plan().hex()
            self.compiled_plan_sha256 = _digest(self.compiled_plan)
        return self._online_final_trace, self._online_final_plan_hex

    def execution_audit(self):
        return self.runtime.execution_audit()

    def candidate_exploration_state(self):
        return None

    def classified_feedback_state(self):
        return None


def build_compiled_rfuzz_executor(runtime, *, run_id, evidence_dir=None,
                                  feedback_interval=16):
    """Assemble the one executor this compiled route uses for the session."""
    if not isinstance(runtime, CompiledF4Runtime):
        raise ValueError('compiled-rfuzz-runtime-required')
    decoder = CompiledOnlineDecoder.from_runtime(runtime, run_id=run_id)
    targets = compiled_commit_targets(runtime.path)
    return CompiledRfuzzExecutor(
        runtime=runtime, decoder=decoder, targets=targets, run_id=run_id,
        feedback_interval=feedback_interval, evidence_dir=evidence_dir)


def _saved_json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2,
                      ensure_ascii=False, allow_nan=False).encode('utf-8') + b'\n'


def _write_json(path: Path, value) -> Path:
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.tmp')
    temporary.write_bytes(_saved_json_bytes(value))
    temporary.replace(path)
    return path


def _write_pinned_json(path, value, saved_output_hashes):
    """Pin the bytes of the same-call value before any later file mutation."""
    path=Path(path)
    expected=_saved_json_bytes(value)
    _write_json(path,value)
    if path.read_bytes()!=expected:
        raise ValueError('compiled-F4-saved-output-initial-bytes-mismatch:'+path.name)
    saved_output_hashes[path.name]=sha256(expected).hexdigest()


def _replay_summary(envelope):
    summary={key:value for key,value in envelope.items()
        if key not in ('actual_prefix','actual_events')}
    summary['actual_event_count']=len(envelope.get('actual_events') or ())
    return summary


def _save_replay_outputs(output,envelope,saved_output_hashes):
    """Retain available raw evidence first, even if another export fails."""
    failures=[]
    for key,name in (
            ('actual_events','compiled_f4_fresh_events.json'),
            ('actual_prefix','compiled_f4_fresh_prefix.json'),
            ('execution_audit','compiled_f4_fresh_execution_audit.json')):
        if envelope.get(key) is not None:
            try:_write_pinned_json(Path(output)/name,envelope[key],saved_output_hashes)
            except BaseException as error:failures.append((name,error))
    try:
        _write_pinned_json(Path(output)/'compiled_f4_replay.json',
            _replay_summary(envelope),saved_output_hashes)
    except BaseException as error:failures.append(('compiled_f4_replay.json',error))
    if failures:
        primary=failures[0][1]
        for name,error in failures[1:]:
            primary.add_note('compiled-F4 replay output '+name+': '+repr(error))
        raise primary


def _required_fresh_replay_documents(envelope):
    documents={}
    for key,name,kind in (
            ('actual_prefix','compiled_f4_fresh_prefix.json',dict),
            ('actual_events','compiled_f4_fresh_events.json',list),
            ('execution_audit','compiled_f4_fresh_execution_audit.json',dict)):
        if type(envelope.get(key)) is not kind:
            raise ValueError('compiled-F4-fresh-output-required:'+key)
        documents[name]=envelope[key]
    if envelope['execution_audit'].get('closed') is not True:
        raise ValueError('compiled-F4-fresh-closed-audit-required')
    return documents


def fresh_verification_document(envelope, plan, *, session_dir=None) -> dict:
    """The full-prefix fresh replay conclusion, from the replay's own values."""
    if not isinstance(envelope, dict):
        raise ValueError('compiled-rfuzz-replay-envelope-required')
    matches = envelope.get('matches') is True
    expected = plan.get('semantic_hash')
    actual = envelope.get('actual_semantic_hash')
    document = {
        'schema_version': FRESH_VERIFICATION_SCHEMA,
        'matches': matches,
        'first_difference': envelope.get('first_difference'),
        'difference_context': (None if matches else {
            'error_type': envelope.get('error_type'),
            'error': envelope.get('error')}),
        'verification_scope': 'full',
        'verification_scope_basis': envelope.get('scope'),
        'replay_entry': ('myfuzz.integration.compiled_rfuzz:'
                         'run_compiled_f4_rfuzz_session'),
        'expected_semantic_hash': expected,
        'actual_semantic_hash': actual,
        'semantic_sha256': plan.get('semantic_hash'),
        'record_count': len(plan.get('records') or ()),
        'event_count': len(envelope.get('actual_events') or ()),
        'expected_prefix_sha256': _digest(plan),
        'actual_prefix_sha256': _digest(envelope.get('actual_prefix')),
        'fresh_process_identities': (
            (envelope.get('execution_audit') or {}).get('identities')),
        'original_process_identities': (
            (envelope.get('original_execution_audit') or {}).get('identities')),
        'replayed_from': {
            'compiled_prefix': 'compiled_f4_prefix.json',
            'session': (str(session_dir) if session_dir is not None else None)},
        'not_a_substitute_for': (
            'a full fresh replay of the saved compiled prefix is not a new '
            'search and confirms nothing the session did not already record'),
    }
    return document


def verify_saved_compiled_f4_build_outputs(output_dir, *, outcome, harness_set, manifest):
    """Check persisted documents against same-call values before publishing hashes."""
    from .compiled_f4_build_join import verify_compiled_f4_build_material
    output = Path(output_dir)
    replay = _replay_summary(outcome['replay'])
    expected = {'compiled_f4_build_join.v1.json':outcome['build_join'],
                'compiled_f4_prefix.json':outcome['plan'],
                'compiled_f4_replay.json':replay,
                **_required_fresh_replay_documents(outcome['replay']),
                'compiled_f4_fresh_verification.json':outcome['verification']}
    initial_hashes=outcome.get('saved_output_hashes')
    if type(initial_hashes) is not dict or not set(expected)<=set(initial_hashes):
        raise ValueError('compiled-F4-saved-output-initial-byte-pins-required')
    saved = {}; hashes = {}
    for name, document in expected.items():
        raw = (output/name).read_bytes()
        parsed = json.loads(raw)
        if _canonical(parsed) != _canonical(document):
            raise ValueError('compiled-F4-saved-build-output-mismatch:'+name)
        if sha256(raw).hexdigest()!=initial_hashes[name]:
            raise ValueError('compiled-F4-saved-output-bytes-changed:'+name)
        saved[name] = parsed
        hashes[name] = sha256(raw).hexdigest()
    verify_compiled_f4_build_material(saved['compiled_f4_build_join.v1.json'],
        harness_set=harness_set,manifest=manifest,
        prefix=saved['compiled_f4_prefix.json'],replay=saved['compiled_f4_replay.json'])
    return hashes


def run_compiled_f4_rfuzz_session(*, artifacts, compiled_inputs, base_dir,
                                  cache_dir, run_id, session_dir, output_dir,
                                  client_binary, budget_seconds, max_tests,
                                  search_seed, max_runs_per_batch,
                                  rounds_per_case=128) -> dict:
    """Start the compiled runtime, run the transport, then replay it fresh.

    The caller owns the repository's heavy-worker lock.  Nothing here reads
    the saved trace back as if it were a replay: ``runtime.replay`` constructs
    new native processes, re-admits the private source documents and re-executes
    every saved candidate before comparing the saved plan.
    """
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live

    if type(rounds_per_case) is not int or not 1 <= rounds_per_case <= 4096:
        raise ValueError('compiled-rfuzz-rounds-per-case-invalid')
    output = Path(output_dir)
    session = Path(session_dir)
    cache = Path(cache_dir)
    if not cache.is_dir():
        raise ValueError('compiled-rfuzz-build-cache-required')
    # The client stops on test receipts; one test may carry up to eight
    # declared decision records, so the runtime must have case headroom for
    # every record the transport can still admit before that stop.
    limit = min(max_tests * COMPILED_CANDIDATE_CYCLES
                + COMPILED_CANDIDATE_CYCLES, 65536)
    from .compiled_f4_build_join import (
        build_compiled_f4_build_join, verify_compiled_f4_build_join)
    from .compiled_f4 import _diagnostic_build_snapshot
    runtime = None
    error = None
    build_evidence = {'original':{}, 'fresh':{}}
    saved_output_hashes = {}
    def save_original_build(snapshot):
        build_evidence['original'] = snapshot
    def make_build_join(failure=None):
        binding = None
        if runtime is not None:
            try:
                binding = runtime.execution_binding.document()
            except BaseException as export_error:
                if failure is None:
                    raise
                failure.add_note('compiled-F4 execution binding export: ' + repr(export_error))
            build_evidence['original'] = _diagnostic_build_snapshot(runtime,
                previous=build_evidence['original'], error=failure)
        return build_compiled_f4_build_join(artifacts=artifacts,
            execution_binding=binding,
            compiled_document_sha256=compiled_document_sha256(compiled_inputs['compiled']),
            runtime_path_id=binding.get('runtime_path_id') if binding else None,
            logical_path_id=binding.get('path_id') if binding else None,
            original=build_evidence['original'], fresh=build_evidence['fresh'], error=failure)
    try:
        runtime = CompiledF4Runtime(
            artifacts=artifacts, compiled_inputs=compiled_inputs,
            base_dir=Path(base_dir), cache_dir=cache, run_id=run_id,
            rounds_per_case=rounds_per_case, max_cases=limit,
            build_audit_sink=save_original_build)
        executor = build_compiled_rfuzz_executor(runtime, run_id=run_id)
        live = run_scenario_rfuzz_live(
            executor=executor, client_binary=Path(client_binary),
            output_dir=session, duration_seconds=budget_seconds,
            seed_records=(bytes(RECORD_BYTES),), max_tests=max_tests,
            search_seed=search_seed, max_runs_per_batch=max_runs_per_batch)
        if live.client_returncode != 0:
            raise ValueError('compiled-F4-rfuzz-client-exit:' + str(live.client_returncode))
        plan = runtime.finish()
        _write_pinned_json(output / 'compiled_f4_prefix.json', plan,saved_output_hashes)

        def save_replay(envelope):
            if envelope.get('original_build') is not None:
                build_evidence['original'] = envelope['original_build']
            if envelope.get('fresh_build') is not None:
                build_evidence['fresh'] = envelope['fresh_build']
            _save_replay_outputs(output,envelope,saved_output_hashes)

        replay = runtime.replay(plan, audit_sink=save_replay)
        _required_fresh_replay_documents(replay)
        verification = fresh_verification_document(replay, plan,
                                                   session_dir=session)
        _write_pinned_json(output / 'compiled_f4_fresh_verification.json', verification,saved_output_hashes)
        join = join_compiled_receipts(session / 'receipts.jsonl',
                                      compiled_inputs['compiled'])
        _write_json(output / 'compiled_receipt_join.v1.json', join)
        build_join = make_build_join()
        verify_compiled_f4_build_join(build_join, artifacts=artifacts,
            execution_binding=runtime.execution_binding.document(),
            original=build_evidence['original'], fresh=build_evidence['fresh'])
        _write_pinned_json(output / 'compiled_f4_build_join.v1.json', build_join,saved_output_hashes)
        return {
            'live': live, 'plan': plan, 'replay': replay,
            'verification': verification, 'join': join,
            'executor': executor, 'runtime': runtime, 'build_join':build_join,
            'saved_output_hashes':dict(saved_output_hashes),
        }
    except BaseException as exc:
        error = exc
        raise
    finally:
        try:
            if runtime is not None and not runtime.finished:
                try:
                    runtime.finish()
                except BaseException as cleanup:
                    if error is None:
                        error = cleanup
                        raise
                    error.add_note('compiled-F4 runtime cleanup: '+repr(cleanup))
        finally:
            if error is not None:
                try:
                    _write_json(output / 'compiled_f4_build_join.v1.json', make_build_join(error))
                except BaseException as audit_error:
                    error.add_note('compiled-F4 refused build join: '+repr(audit_error))
