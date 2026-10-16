# Recorded Post-Reset Resume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Record bounded real post-reset scheduler commands and replay them before compiling the next register request from actual CPU waiting context.

**Architecture:** Add one Session API and explicitly new complete18/incomplete19 schemas only when resume commands exist. Keep old16/17 exact rows and semantics. The trusted selector reconstructs original requests and executes actual reset/resume commands; saved schedules/epochs are comparison input, never provider authority.

**Tech Stack:** Existing ScenarioSession/ScenarioRunner, RegisterProgramRuntime, closed JSON validators, actual generated local READY/END software lifecycle, memory/source gate and production authenticated file replay.

## Global Constraints

- No production implementation was done while writing this plan. Actual warm missing API RED61270:1FAIL27.53s; old source freeze preserved.
- No commits/resets/worktrees, no approval questions, no unrecorded Runner steps/manual waiting or epoch assignments, no saved authority restoration.
- Preserve default16/17 exact row shapes/semantics; new source closure SHA necessarily changes. Require at least one nonempty recorded resume for18/19.
- Initial post-reset command/checker/gate failures halt and refuse export. Schema19 supports only the existing uncertain register attempt after completed resume commands, not invented partial scheduler replay.
- Current reset rows are not native reset-default proof. Conditional causal GPIO reset receipt is not emitted by ordinary provider. New crypto-reset descriptor/default certificate is a separate original-E2 task.
- Full Stage2/reset/permission/field matrix remains open. Native only after full source freeze/software review, one worker and unchanged separate180-second policies; preserve every failure directory.

## Task 1: Session API, closed codec and fresh replay

**Owner:** one implementation agent. **Files:** modify `src/myfuzz/scenario/session_runtime.py`; create `tests/scenario/test_register_reset_resume_boundaries.py`; consume Runner-owned `tests/scenario/test_register_reset_resume.py` without editing it. Do not edit Runtime/Runner/collector or source pins during another actual test.

**Interface:** `ScenarioSession.advance_after_reset(schedule: tuple[str,...]) -> OnlineCaseReceipt`. Existing reset and Runtime APIs unchanged. Shared pure validator remains `validate_register_program_plan(document)` and accepts18/19 with all timeline checks before factory. Detailed exact guards/records are in [Session design](../../reports/stage2-e2-reset-resume-session-design-20261012.md).

- [x] Step1: preserve actual warm RED61270 and add cold/real source waiting positive. Use current READY/END lifecycle and actual CPU._serve/ISA bootstrap execution fixture; call actual Session reset, not an epoch stub.

```python
session.reset('warm_all')
assert cpu.waiting_instruction_address is None
session.advance_after_reset(('cpu','gpio_a','gpio_b'))
# Repeat recorded calls only until actual source obtains a declared missing slot.
assert cpu.waiting_instruction_address is not None
adapter.submit(next_original_request)
```

Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_register_reset_resume.py -k warm -x --tb=short`. Expected initial FAIL missingadvance_after_reset, after genuine reset. Preparation errors are not semantic RED.

- [ ] Step2: implement internal empty map/uncertain flag/method pins without exporting new fields by default. Guard actual registered adapter/session/runner, strict state/lastreset index/commandepoch, `_active_submission is None`, adapter not uncertain, exact bounded components, per-reset total<=template.max_steps and current source/method pins. Prepare alone is not a prohibition.

```python
index = len(self._reset_operations)-1
assert self._reset_operations[index]['after_cases'] == len(self._cases)
assert self.runner.command_epoch == len(self._reset_operations)
advance = BatchAdvance(schedule)
# Exact type/component/length/aggregate checks precede this mutation.
self._reset_resume_advances.setdefault(index, []).append(advance)
# Execute pinned actual call, checker, gate.observe and step-retirement.
```

Assertions above describe guards and must be production ValueError/RuntimeError checks, not removable Python asserts. Add finding/error handling as defined in design; check again after fallible callbacks. Never capture caller-supplied serializer/provider.

- [ ] Step3: encode normalized new rows only with actualresume; check failure flag first.

```python
if self._uncertain_reset_advance:
    raise ValueError('uncertain post-reset advance cannot be exported')
used = any(self._reset_resume_advances.values())
if used:
    document['schema_version'] = 19 if runtime_state['uncertain'] else 18
    document['reset_operations'] = [
        dict(after_cases=row['after_cases'], policy=row['policy'],
             advances=[list(a.schedule) for a in self._reset_resume_advances.get(i,())])
        for i,row in enumerate(self._reset_operations)]
```

Old branch remains exactly current16/17. Pure pre-factory check18/19 exact3keys/all rows, nonempty schedules/known components/strict integers/enum/ascending boundaries/65536 resets/perreset bound/atleastoneadvance. Reject new row keys in16/17 and19 resets after an appended uncertain terminal case.

- [ ] Step4: fresh reset loop calls pinned actual reset then each recorded advance before next actualprepare. Keep all existing originalrequest/fullmanifest/trace/ordinary/verifier/gate/configuration/genome comparisons and finish_export.

- [ ] Step5: actual positive/negative TDD. Run warm/cold fresh, mixed reset rows with empty advances, consecutive resets samecase boundary, old16/17 unchanged, finding/step/checker/gate errors refused export, invalid component/bool/list/capacity no events or reservations, method/source drift beforecommand, stale actualcontext expectedmanifest refusal, schema19 appended/unappended lastattempt boundaries. Checker/gate effects must be fed actual receipt once; no fake Runtime uncertain.

Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_register_reset_resume.py tests/scenario/test_register_program_replay.py tests/scenario/test_online_reset_replay.py`. Expected PASS, save commands/exit/count/time/sourceSHA. Freeze Session and send exact schema/API to Task2 before concurrent source-bound fixtures.

## Task 2: Closed assembly/selector, authenticated save/fresh

**Owner:** independent integration agent. **Files:** modify `src/myfuzz/integration/ibex_pulp_register_replay.py`; modify `scripts/run_ibex_pulp_online.py` only if required to emit actual new comparison scope; create `tests/integration/test_register_reset_resume_replay.py`.

**Consumes:** Task1 advance_after_reset, strict validate_register_program_plan18/19 and pinned fresh branch. **Produces:** existing production saved-file selector understands new version and compares complete reset/resume timeline. The explicit schema18/19 and nonempty closed timeline are the opt-in. Do not add an assembly reset_resume flag or Runtime/configuration field. Existing source closure already covers Session; current full source hashes remain mandatory.

- [x] Step1: observe actual writer-to-closed-validator RED29714 (1 failed, 15.99s) on modelled schema18 after a real baseline16 capture passes; this is a structural boundary test. Prepare separate actual warm/cold authenticated fresh tests; their execution remains Step3. Run `PYTHONPATH=src python3 -m pytest -q tests/integration/test_register_reset_resume_replay.py -x --tb=short`.

- [ ] Step2: extend file writer/selector schema gates to the exact version tuple (16,17,18,19). Validate plan/state and closed timeline before mkdir/factory. No savedpath/provider selection.

```python
if type(document.get('schema_version')) is not int or document['schema_version'] not in (16,17,18,19):
    raise ValueError('register selector requires schema16/17/18/19')
# Existing _validate_saved_register_documents invokes the full pure validator.
# Preserve its position before factory construction or output-directory creation.
```

Use current code-owned factory and originalrequest replay, never register_replay_case(savedbytes).

- [ ] Step3: persist actual originalrequests/resetresume timeline/fulltrace and compare actualfresh context waiting/epochs/generation/ordinary/verifier wrapper. Tamper/re-authenticate schedule order, reset index/boundary, foreign component, bool integer, totalsteps, empty18 channel, downgrade16 newkeys, uncertain lastcase boundary and configuration/sourceSHA; each must reject before factory or mismatch fullfresh. No grant from a self-consistent saved timeline.

- [ ] Step4: run new module plus `tests/integration/test_register_verifier_replay.py` and `tests/scenario/test_register_alias_saved_boundaries.py` after all source owners freeze. Preserve default sourceboundidentity semantics, not old SHA. Report actual results and freeze integration/CLI.

## Task 3: Independent review, regressions and later native evidence

**Owner:** reviewer and Root supervisor; no concurrent production file ownership.

- [ ] Review actual scheduler/source method binding; full18/19 pre-factory closure and atomic capacity; no preparedstate fiction; checker/gate/failure behavior; current Runtime uncertain still closes source admission; sourceclass/instance replacements and no-op fake advance cannot restore certificates.
- [ ] Run new Session/integration+independent malformedtimeline/old16/17/publicfinish/schema17 regressions once all owners stopediting. Root preserves original meaningfulRED and distinguishes fixture errors from production failures.
- [ ] Design source-derived native warm/cold gate only after software PASS. Actual CPU restart must really consume bootstrap/oldwarmprogram and arrive at missing slot through **recorded** API. Complete originalrequests/privateCPU/APB/RAM/fullfresh are compared under original singleworker/180-second policies; no unrecorded runner commands or manual PC/waiting mutation.
- [ ] Keep native observable reset/default certificate separate: reuse/audit existing conditional GPIO receipt appropriately, add code-owned ordinary startup/reset seal only in its separately reviewed task. This resume gate must not claim resetdefault/functional/storage/version/prerequisite/wholeL2.
- [ ] Update progress with scoped software/native/fresh/audit receipts and original Stage2 open requirements; preserve historical aliases/masks current source identities.

## Root review and execution handoff

2026-10-12: Root reviewed Session design and both terminal meaningful REDs. Task1 approved with Renderer owning production Session and NEW boundary tests, Runner retaining actual lifecycle test ownership. Task2 approved with no extra assembly flag: explicit18/19 closed schemas provide the opt-in. Production owners may implement in parallel in their separate files; source-bound test processes wait until both freeze. No commits. Task3 includes independent review and actual compatibility regressions. Original Stage2 remains open.

### 2026-10-12 candidate checkpoint

Session9aabc/integrationbfbb: actual warm/cold and Session fresh2PASS129.08s; writer closed-codec8PASS103.41s; initial pure boundary11PASS0.10s. Independent review identified four remaining dispatch/export/startup pin issues. Renderer dispatch-only unit RED3FAIL0.09s reproduces ordinal, component-range and post-step checker drift; production correction is authorized after all preceding test processes terminated. Authentication-file/final-source/default16/17 regressions remain pending; candidate passes do not close Task1/Task2 or native/fullStage2.

Second candidate d743/bfbb: actual Session and authenticated-file warm/cold4PASS308.04s; portable writer8PASS26.90s. Independent serializer instance/class and same-checker call-method replacement produced3 limited-dispatch REDs. Root authorized the additional pin corrections after all candidate jobs terminated. Actual19 terminal and legacy compatibility results still pending; Task1/Task2 stay open.

Final software gate f7da/bfbb passes: independent/pure34PASS32.72s; actual19 terminal2PASS135.56s; actual warm/cold Session+authenticated-file4PASS320.83s; Root default16/17/reset/final-export regressions59PASS300.98s. Native warm generation1400 is actually launched in its own new v1 directory, 180-second/single-worker budget; cold and fresh/audit are not yet executed. Task3 native remains open and this does not close original Stage2.

## Scoped acceptance result — closed

Final f7da/bfbb/0037 implementation has independent/pure34PASS32.72s, actual19 terminal2PASS135.56s, actual warm/cold Session+authenticated-file4PASS320.83s, and Root legacy59PASS300.98s. Actual warm generation/fresh144.04320875299163/126.435815431003s and cold136.89256155700423/118.051542753994s all completed under independent180-second single-worker/RSS policies. Warm/cold full audits50618/70286 passed without altering assertions:282pins/9artifacts/2exactrecompiles each, warm9391events15assoc45APB3RAM183resume, cold9114events14assoc42APB2RAM159resume, full source/build/binary/journal/IRQ/proof/fresh-wrapper agreement.

This closes the implemented recorded single-reset warm/cold resume package, with [full independent report](../../reports/stage2-e2-native-reset-resume-independent-audit-20261012.md) and [execution checkpoint](../../reports/stage2-e2-reset-resume-root-checkpoint-20261012.md). The broad scenario inventory in Task1 Step5 is a future regression inventory beyond these demonstrated actual single-reset paths; mixed/consecutive reset shapes were checked as pure codec boundaries, not claimed as a separate actual multiple-reset/native run. Native reset-default certification remains a separate original E2 task. Full Stage2 remains active. Next four-field chunk is only designed and has no execution result. All workers are terminal; source freeze may be released for subsequent authorized work while preserving these exact identities.
