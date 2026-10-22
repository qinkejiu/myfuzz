# Reduced AXI Journal Crosswalk Implementation Plan

> **For agentic workers:** Use subagent-driven-development task by task with independent task and whole-slice reviews. Preserve the shared feature branch; do not stage/commit/reset/clean or rewrite other agents' files.

**Goal:** Implement the approved receipt/lifecycle-bound Reduced AXI production import, reference mapping and observation consumer, then execute software and native acceptance.

**Architecture:** A bounded source issues ordered operations containing native receipt/lifecycle witnesses and exact emitted observation spans. Runner preserves original observations and writes separately authenticated binding/reference rows. A consumer reprojects issued receipt samples and validates the complete journal, including terminal expected records and source seals.

**Tech Stack:** Python, generated reduced-dual-AXI session, ScenarioRunner, EventJournal, existing durable JSONL/zlib views, pytest and supervised generated RTL sessions.

## Global constraints

- Approved spec: `../specs/2026-10-22-reduced-axi-journal-crosswalk-design.md` (user approved 2026-10-22).
- All source/consumer outputs remain observation_only, runtime_accepted=false, semantic_accepted=false; no retirement/MemoryService/DMA/ISR or functional authority.
- Dispatch by admitted capability/protocol contract, never CPU/IP names. Preserve all original fields and raw local refs; sidecars own journal refs.
- One implementer owns each task's listed files; reviews may run independently. Shared checkout contains necessary uncommitted source; use the existing codex/system-completion-20261016 branch without copying a stale HEAD worktree.
- Exact existing producer budgets remain lifetime scoped. Source/consumer queues, mappings and new journal records have additional explicit bounds and terminal failure capacity.
- Preserve failed evidence, exact executed bytes, distinct native process identities, pending states and first/fresh comparison rules. Local verification only unless remote rules in agent.md are applied.

## Task 1: Bounded source operation issuance

**Files:** create `src/myfuzz/scenario/observation_stream.py`, `tests/scenario/test_observation_stream.py`.

**Interfaces:**

```python
class ObservationStreamSource:
    def __init__(self, *, binding: dict, max_operations: int = 100000,
                 max_pending_operations: int = 1024,
                 max_pending_bytes: int = 8388608,
                 max_operation_bytes: int = 1048576): ...
    def issue(self, kind: str, payload: dict, observations: list[dict]) -> object: ...
    def pending(self) -> tuple[object, ...]: ...
    def lookup(self, token: object) -> dict: ...
    def ack(self, token: object) -> None: ...
    def poison(self, reason: str) -> None: ...
    def identity_document(self) -> dict: ...
    @property
    def state(self) -> str: ...  # active / sealed / poisoned; read-only
```

Binding has exact keys `schema_version=observation_stream_binding.v1`, `session_id`, `observer_stream_id`, `source_component`, `artifact_digest`, `observer_contract`. session_id/observer_stream_id/source_component are nonempty strings; observer_contract is a nonempty JSON dict (strings refuse); artifact digest is 64 lowercase hex. No random identity is created by report/export/lookup. Instance identity is checked by owning source at import; serialized tokens cannot be reconstructed as live capability.

Operation kinds are `begin_scope`, `end_scope`, `receipt`, `seal`; payloads are detached JSON dictionaries (later task validates each protocol-specific shape). Source envelopes contain schema_version `observation_stream_operation.v1`, binding digest, operation_index, kind, payload, observations, first_record_index, record_count and canonical content digest. Operation indices start1, increase across ACK/reset; record positions start1 and count every observation, not just raw. Empty operations retain current next record position and increment operation index. Canonical JSON uses sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False. Reject non-JSON values, non-string dictionary keys and tuple coercion instead of accepting type confusion. Tokens are fresh opaque objects retained only while pending; lookup returns copies and rejects unknown/foreign/acked tokens. ACK must be FIFO and release payload bytes; stale ACK never clears a later operation. New operations after seal/poison refuse; one seal only. Read-only state distinguishes active/sealed/poisoned (poison takes precedence), so retained diagnostic lookup after poison cannot authorize further import. Cumulative max_operations and pending/individual byte bounds are separate; no reset API clears lifetime counters. Pending bounds are checked before queue mutation. max_operation_bytes covers encoded envelope including digest. Failed issue poisons source; bounded failure status does not allocate another unbounded operation.

- [x] Write failing API tests: two ordered operations with zero/nonzero records; original input and exported copy mutations; token ownership/FIFO/stale ack; seal/poison; bool/float limit confusion; non-JSON/NaN/tuple; N-1/N/N+1 counts/bytes; counters after release.
- [x] Run `PYTHONPATH=src:. python3 -m pytest tests/scenario/test_observation_stream.py -q` and preserve expected initial failure.
- [x] Implement exactly the interface above with detached canonical envelopes and bounded opaque issuance state; no observer/session/Runner edits in this task.
- [x] Run focused tests, save logs and source hashes; independently review spec compliance and quality. This module alone grants no source authentication to a session.

## Task 2: Receipt and lifecycle source integration

**Files:** modify `src/myfuzz/scenario/reduced_axi_events.py`, `src/myfuzz/local_harness/vexii_axi_session.py`; create `tests/scenario/test_reduced_axi_stream_source.py`.

Consumes Task1 API. Add a declared session observation export capability backed by an actual ObservationStreamSource, not a schema string. Register exact artifact/source_component/observer contract and stable session/stream IDs. Capture immutable command execution/sequence/tick/sample witness after existing receipt parser and exact physical checks, before observer projection. Snapshot each observation at emit time; group each command and lifecycle operation into the shared ordered source sequence, including empty begin/end operations. Verify raw_ref equals issued record ordinal. Preserve current runtime_events records and wire formats. Source emission failure poisons the session before another command advances transport. A parsed error receipt or physical-check failure is retained as failure evidence without a fabricated success sample; a genuine observer violation retains its issued receipt plus actual raw/violation span and poisons subsequent observer/session transport. This protocol failure does not invalidate a correctly issued source envelope: source.poison is reserved for issuance/integrity failure. Such a violation is authentic failure evidence, never a successful transaction. Expose seal only at an explicit terminal checkpoint; reset closes a scope, not the observer lifetime stream. Seal fixes recording integrity separately from protocol pending and never invents end_scope/cancellation. No genuine pending operation is silently discarded by _clear.

Capability state is disabled by default (no new queues); Runner admits/activates before first begin_case/command, late activation refuses. Once active, no silent legacy fallback or return to disabled. A source is never created and allowed to accumulate unacknowledged operations in old direct-session runs. session identity includes export limits; its generated build closure must include imported new source modules. Exact native receipt and original wire command/reply bytes are retained in a detached witness; command sequence is not operation_index. Source lookup after poison is diagnostic only; consumers must check read-only state.

Actual DriverReceipt fields are execution, sequence, tick_before, tick_after, new_ticks, status, payload, error_code and error_detail. Include called operation/command_fields and exact original wire reply; no command identity may be inferred later from mutable observer rows. Save these exact parsed fields. sample.local_tick is native-process-local and is already checked by wire parsing against the receipt interval; session.local_ticks includes _tick_base. Validate new_ticks==1, tick_after==tick_before+1, sample.local_tick==tick_after, cumulative_after==tick_base+tick_after, not equality of these two tick domains. Sequence restarts per native execution. super.reset_local dynamically calls self.begin_case: record one actual end/begin transition, never a duplicate scope opening. Test two restarted executions explicitly.

- [x] Tests begin/end empty scope, two native executions sharing observer lifetime, all reset pending slots, mutable runtime_events tamper against original issuance, scope reuse refusal and source fail-before-next-command.
- [x] Existing ReducedAxiObserver tests remain compatible; new capability is opt-in until Runner support lands.
- [x] Independent exact diff review and focused software source/session regressions before Task3.

## Task 3: Role-aware reference consumer

**Files:** create `src/myfuzz/scenario/reduced_axi_journal.py`, `tests/scenario/test_reduced_axi_journal.py`.

Expose `ReducedAxiJournalConsumer(binding, *, runner_component, runtime_document, limits)`, `consume(event)`, `report()` and `finalize()` (validates the actual consumed seal, never a detached dictionary); reports have explicit complete/prefix/failed status and observation_only authority. Accept full journal IDs, source binding/operation envelopes, original observations and `reduced_axi_journal_binding.v1` sidecars. Replay only issued witness samples with a fresh ReducedAxiObserver, including begin/end operations; validate exact expected observation queue. Resolve raw refs to actual earlier raw journal IDs with complete separately authenticated scope. Validate reset's nested contexts and same-edge AW/W repeated reference roles. Keep source and journal sequence spaces separate; terminal seal must detect missing final derived rows. Declared prefix pending is reported, not certified. Persistent offline consumer rebuilds from saved bindings/witnesses with external manifest trust, never trusting a serialized live token.

- [x] Software positives and all spec negative cases, including fully rehashed false raw+derived contradicted by receipt, separate aliases/streams, last-row deletion and every budget N-1/N/N+1.
- [x] Pure mapping success never creates a verified transaction. Exact completed replay chains alone populate bounded boundary observations.
- [x] Independent review before integration.

## Task 4: Runner capability admission and durable import

**Files:** modify `src/myfuzz/scenario/runner.py`; create `tests/scenario/test_runner_reduced_axi_stream.py`.

Runner admits the actual source capability against session/artifact/contract and alias binding. In _append_external_events, import issued operation, preserve original runtime rows and append sidecars using their true assigned IDs. Do not also import the same runtime_events through the legacy path. Bindings/operations/originals/sidecars/seals use normal budgeted append, never append_unchecked. Source ASCII canonical byte accounting and Runner UTF-8 evidence accounting remain distinct; duplicated observation payload inside operation envelopes is counted, not treated as free. Verify every mutable row against original issued operation before authentication. ACK/clear only after original rows, sidecars and consumer state commit. Partial append/ack failure marks run failed and poisons stream; never retries into verified duplicate rows. Unadmitted legacy observation buffers keep their existing observation-only behavior. Expose explicit reduced observation reports and include capability configuration in Runner identity; keep the existing IP report schema and producer ownership unchanged.

- [x] List-backed and file-backed actual Runner tests, interleaved scheduler IDs, per-sample drains, aliases and two streams, reset, lifecycle without rows, report idempotence, failure injection at export/append/ack.
- [x] Durable JSONL/zlib reload validates all original rows/bindings/witnesses/sidecars and seals; malformed/truncated recording refuses complete status.
- [x] Run existing reduced AXI, OBI, AHB and coverage focused modules alongside new suites; preserve all failures and selected input hashes.
- [x] Independent integration review before native gate.

## Task 5: Native first/fresh and documentation

**Files:** create `tests/integration/test_runner_reduced_axi_reporting_real.py` and a scoped supervised evidence entry; add report/evidence and update CURRENT_PROGRESS, LOCAL_HARNESS_RUNTIME, reports/README and this plan.

Use the existing admitted generated reduced-dual-AXI CPU and actual RAM program, through normal Runner, not synthetic session receipts. Freeze source/artifact/contract/verifier bytes before run; canonical resource lock and budget. Save independent process launches, raw command receipts, issued operations, complete journal, sidecars, terminal seal/pending and report. First/fresh each verifies all measured samples and full semantic prefix. Original nonce-bearing evidence remains intact; normalize only explicitly bijected session/execution scopes and recompute dependent digests in a separate comparison view. Do not require absent physical wait/error/reset witnesses to pass through invented software effects; software negatives and native positives remain separately labeled.

- [x] Review executable verifier; run actual first/fresh and record terminal command/process status. Independent Spec/Quality PASS; supervisor terminal exit0; two distinct native PIDs/execution IDs exit0 and reaped; exact receipts retained in `task-5-r5-independent-review.md` and `native-attempt1/terminal.json`.
- [x] Independent raw-evidence reconstruction plus source/archive audit; all accepted rows trace to admitted receipt samples and original observations. Saved audit: `.superpowers/sdd/reduced-axi-crosswalk-20261022/native-attempt1-independent-audit.md`; root CLI audit and hash receipt are under `native-attempt1/`.
- [x] Reconcile docs with exact verified protocol boundary, remaining unsupported branches and all full-system P6/P7-E/P8 gaps. Keep the full goal active. Scope remains observation_only; instruction-read pending is preserved; no runtime/semantic/retirement/DMA/ISR or generic onboarding grant.
