# Recorded post-reset Session resume: closed design

Status: design only. No production edits or native execution. Actual warm missing-API RED61270 is terminal:1FAIL27.53s after genuine bootstrap/privateREAD/RAM, real process reset/epoch transition and waiting=None. Permission software14PASS22.92s is a separate scope.

## Actual gap and supported boundary

ScenarioSession.reset records {after_cases,policy}; register replay resets after the corresponding case and immediately prepares the next request. GeneratedCve2Session.reset_local clears waiting/request evidence/sequences and restarts actual CPU bootstrap. RegisterProgramRuntime._context requires a real deferred instruction transaction at a declared unmaterialized online slot. advance_initial rejects nonempty case history; case advances execute after source admission. Direct Runner steps and manual _serve(nextslot) are not a saved native bootstrap/resume path.

Warm retains SOURCE instructions, so actual restart executes bootstrap and old fragments before reaching the next missing word. Cold reapplies INITIAL_IMAGE only and returns to first missing online word. LiveMemoryEffectTracker clears reservations on actual reset_barrier; fresh unique actions can reserve current-generation cold slots. Do not replay old declarations as current authority or jump the warm CPU past retained code.

## Public API and precise guards

`ScenarioSession.advance_after_reset(schedule: tuple[str,...]) -> OnlineCaseReceipt` is the only new Session execution API. Calling it explicitly enables recorded-resume content; no Runtime constructor/configuration field is added. It requires an attached actual RegisterProgramRuntime. Preparing a request is pure and does not block advancing: Runtime has no installed pending/prepared registry. A stale prepared manifest is rejected by existing submit revalidation when its actual context changes.

Before mutation or command require:

1. begun, not finished, not halted, Runner status running; _uncertain_reset and _uncertain_reset_advance false.
2. actual attached adapter/Session/Runner binding and startup static identity unchanged; adapter._uncertain false; adapter._active_submission is None. An attempted in-flight Runtime record also cannot be resumed reentrantly.
3. at least one recorded reset; latest reset.after_cases equals len(_cases), >=1. Runner.command_epoch equals len(_reset_operations). Only the latest reset segment accepts more advances until another case is admitted; two consecutive resets at the same boundary remain distinct by reset index.
4. exact tuple, nonempty, exact nonempty str components drawn from template.schedule_order; repeats are legal. One schedule length <=template.max_steps; aggregate component steps for this reset <=template.max_steps. Existing reset capacity65536 remains. Capacity checks occur before appending a row or any STEP.
5. startup-bound runtime validation method and current class/instance identities; pinned runtime.validate (not static-only) rejects uncertain admission. Full ordinary/verifier/source guards apply. Capture Session advance/reset helpers and actual installed Runner execution callables at Session creation, check class and instance replacement before each call and export. Use captured calls; never accept a saved function name/provider. Existing software transport installed before Session construction may be pinned as a test execution implementation, but new replacements are rejected. Production trusted factory remains the code-owned selector.

Use `_active_submission`, not a fictitious prepared state. Source drift/capacity/malformed schedule refusal must leave records/ticks/events/gate reservations unchanged.

## Record and schema contract

Keep `_reset_operations` old two-key rows internally. Add a private map `reset_index -> list[BatchAdvance]`; append the validated attempt before issuing commands. A separate `_uncertain_reset_advance` marks any command/checker/gate failure and prohibits export, so an attempted partial row cannot masquerade as completed.

If every resume list is empty, encode existing16/17 and existing exact two-key reset rows. If any resume exists, encode18 (complete Runtime history) or19 (existing Runtime uncertain terminal attempt); normalize **every** reset row to exact {after_cases,policy,advances}, including empty advances for other resets. `advances` is a list of nonempty schedule lists. Require at least one nonempty advances list across18/19; arbitrary version promotion is invalid. Root keys/register_programs/runtime configuration/case manifests keep current meanings. Version19 is only the existing uncertain register attempt projected after completed resume commands; it does not silently encode failed scheduler commands.

`validate_register_program_plan` itself must validate timeline before any factory: exact integer version, exact row keys, policy enum, exact integer1<=after_cases<=len(cases), nondecreasing boundaries, <=65536 resets, named exact components, per-row and aggregate local-step bounds and actual nonempty18/19 resume usage. In19 no reset/resume may occur after its appended uncertain last case; the unappended terminal None index uses the actual preceding committed prefix. Old16/17 must still reject a row with advances. Return detached data as before; no already-validated flag or caller hash.

Fresh replay uses the same pinned actual public commands:

```python
for reset_index in resets_after_current_successful_case:
    session.reset(row['policy'])
    for schedule in row.get('advances', []):
        pinned_advance_after_reset(session, tuple(schedule))
# Only then adapter.prepare(original_request, expected_manifest=manifest).
```

Original request recompilation, actual manifest/context, full reset timeline, admissions, gate/runtime/ordinary/verifier terminal state, full trace/genome/semantic/manifest hashes remain compared. Saved schedules select only already-declared local components, not executables or reset authority.

## Execution, observation and failure

Capture actual event/tick start, append attempt, execute bounded `runner.step_batch`, construct receipt from actual event suffix/ticks/status, run the existing checker with exact tuple finding contract, ingest `prerequisite_gate.observe(receipt)`, retire actual step receipts, then return a detached receipt. Gate/checker success is part of completion. Finding halts new admission; a finding receipt may be returned, but resume export is refused until an explicit terminal codec exists. Do not silently return a successful prefix after failure.

Any exception after recording or stepping sets `_uncertain_reset_advance=True` and Session halted; preserve an existing halt reason, otherwise uncertain_effect (checker contract/environment failure may keep environment_error). Do not set Runtime._uncertain to fabricate a register attempt. Further reset/advance/submit/encode_plan/finish_export must refuse; actual process cleanup still runs. Partial advance/checker/gate failure is deliberately nonexportable in this package; no new real-RTL fault acceptance is invented.

## Scope and source-method risks

Resume schedules can execute old warm code, RAM stores, IRQs and MMIO writes without a new selected request. Every resulting event must reach actual collectors and the prerequisite gate. Do not count these as new selected register certificates or hide them from all-stream bracket interference. Global resources remain in force; clock capacity is not max_records/new-operation capacity.

Existing GPIO reset receipt is conditional: reset_local emits gpio_reset/authenticated_generated_driver_ready only when routed_register_access_enabled (causal/internal observation mode). Current ordinary alias provider has routed=False. Base/CPU strictly parses READY but does not retain a private startup record. Future native reset-default scope must audit this existing mechanism and its missing ordinary output, not enable causal/internal probe or assume every provider emits it. A separately source/build/binary-bound actual startup/reset descriptor plus actual READ/privateRAM/no-affecting-write rule is still required; saved epoch/reset rows and this18/19 timeline grant none of it.

Current bootstrap writes A DIR/GPIOEN/PADOUT and B GPIOEN/INTEN/INTTYPE; A.INTEN is a stable unmodified candidate, unlike postboot A.PADDIR/PADOUT. Conditional read-clear and PADIN remain gaps. No storage/version dependency/prerequisite/functional/wholeL2 grants are added.

## Ownership and review gates

Task1 owns Session+closed codec+fresh in one file and new actual software tests. Task2 owns integration selector/assembly/writer+new authenticated tests. Task3 independent review and necessary regressions precede any native reset gate. Keep source changes sequential around live actual fixtures. New source closure hashes change; only default16/17 shapes/semantics are preserved, not the old authenticated digest. No commit/reset/worktree or approval prompt is required.
