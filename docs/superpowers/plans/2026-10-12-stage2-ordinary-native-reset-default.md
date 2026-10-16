# Ordinary Native Reset-Default Implementation Plan

> **本文件身份：** 该文件未纳入 Git，也不在接受验收时自我引用字节哈希（任何写入都会改变其自身哈希）。历史检查点记录的 `45c916bd0caad52a2ceb48569df4cd6f242b21c50e1acb1146458472dfc698d6` 对应更早的草案修订，原始字节无归档可复原，已由 2026-10-12 13:29 定稿取代。任何阶段验收都不得把本文件的字节哈希当作输入或证据，验收身份仅以源码 pins 与真实运行收据为准。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user has already selected parallel execution; do not ask again.

**Goal:** Produce code-owned reset-default evidence from actual ordinary native lifecycle, complete target command coverage, source-bound field semantics and genuine CPU/APB/privateRAM readback, then reconstruct it through trusted saved-file fresh replay.

**Architecture:** A default-off generated-native observer privately seals successful READY/lifecycle facts and every parsed command attempt. Runner binds these private facts to actual reset barriers and CPU/memory domains; a separate semantic verifier checks total field-affect classification and selected READ/issued-RAM evidence. Stable logical process ordinals are exported for comparison, while random PID/nonce bindings remain private; saved documents never install authority.

**Tech Stack:** Python dataclasses/JSON/SHA256, current GeneratedLocalSession/ScenarioRunner/ScenarioSession, source-locked PULP GPIO v3 profile/sidecar, RV32I LW/SW register compiler, existing ordinary APB/private memory authority and authenticated file replay; pytest/software transports first, separately supervised Verilator native generation/fresh only after Root approval of concrete scripts.

## Global Constraints

- Original Stage2/E1/E2 remains open until the complete reset/permission/width/effect requirements are met. First A.INTEN success is a scoped milestone, not DIR/OUT/EN/B.INTEN/PADIN/STATUS/default-matrix completion or wholeL2.
- Dirty shared workspace stays in place. No staging/commits/reset/worktrees, no pin rewrites or edits to previously executed runs. Explicit user instruction overrides skill commit/approval-menu defaults.
- Current accepted artifacts remain frozen historical evidence. Default-disabled schema16/17/18/19 row shapes and semantics stay compatible; source closure SHA changes with implementation and is not promised identical.
- No causal/routed internal-probe enablement to obtain ordinary reset authority. Old routed gpio_reset/D4 behavior remains separately compatible.
- READY means source-bound driver reset execution completion, not captured reset waveform. Existing tick(dut,nullptr) samples cannot be retroactively fabricated. Any reset waveform requirement needs actual additional sampled startup interface and separate versioned evidence.
- Exact bool/int/text types, bounded capacity, detached public reports, source/class/instance/code/object pins, permanent incomplete after possibly applied failure or missing coverage. Capacity checks precede commands.
- Every actual target command path is covered, including direct command/write_register, parsed applied write then callback failure, pending, unknown command/offset, alias/equal/fullwordRMW. Successful completed-access rows alone are insufficient.
- Bind target process/epoch, Runner command epoch/barrier, CPU source execution/epoch and actual memory object/generation as distinct domains; never equate their integer values or reuse another target seal.
- No saved dict/descriptor/certificate, host RAM value, public journal row or token setter restores authority. Private native facts and existing one-shot MemoryCommitAuthority issuance remain actual producers.
- Fresh reexecutes original requests and recorded reset/resume, rederives current configuration and full reports, compares identity/plan/trace/wrappers. Never compare random PID/nonce raw values across fresh runs.
- Software tests do not execute RTL/build/lint. Native generation and fresh each use the current single-worker/RSS policy; full request list retained, no parallel large JSON audit. **2026-10-13 预算修订（`native_gate_budget.v2`，用户授权）：** 本节与 Task5 第 235 行原写"180 秒"。实测该 180 秒对**已启用 reset-default 通道**的门禁不可能达成：越过 reset 需 163.95 秒（构造 14.33＋begin 34.23＋bootstrap 159 步 29.02＋case_0 34.25＋case_1 47.17＋reset 3.64），reset 之后尚需约 60–120 秒（resume 约 183 组件步＋post-reset read＋`finish_export`＋认证保存），合计约 225–285 秒。故 reset-default 四项原生阶段先改为 **300 秒**（`native_gate_budget.v2`）。实测 300 秒**仍不足**：warm generation 于 `attempt-5-budget-v2-wall-timeout-in-resume` 在 300.081 秒被 SIGTERM，此时已完成 bootstrap 与两个 case 并**越过 reset**（`actual_reset_complete` 139.71 秒），但在 resume 第约 160/183 步处耗尽；按实测趋势外推 warm 约 **397 秒**、cold 约 **350 秒**。故进一步修订为 **`native_gate_budget.v3`：wall-clock 上限 600 秒**，具名版本化记入各门禁 `preparation.json`／`hold-state.json`（含 `supersedes` v2=300／v1=180、`unchanged` 列表与 `rss_limit_raised=false`）。**单 worker、RSS 上限、heavy-worker 锁、严格串行、失败不重试、完整捕获、attempt 保留一律不变**，仅 wall-clock 一项变动。同时如实记录：该增长**部分是在为一个尚未优化的热路径买单**——冻结的 `NativeResetEvidence._validate` 每次调用都重新序列化全部已缓存 fact，且每次 `advance_initial` 被调用约 19 次；实测 bootstrap 每步 0.163→0.218 秒（+34%）、resume 每步 0.855→0.955 秒（+11.7%，为 bootstrap 的 4.4–5.9×，因 resume 步携带 MMIO 命令而每命令路径重跑守卫），二者均随 fact 累积单调增长。Task2b 已消除"资格认证"那一半重复（每次 advance 38→0），**重复序列化这一半另立 Task2c 并已授权实施**；在 Task2c 冻结前于身份 `409af86e…` 上取得的 v3 运行结果**只是暂定值**，任何 Task2c 冻结都会使其被取代，验收仍须在最终身份上重跑四阶段。

## Files and dependency/ownership map

1. Local lifecycle/command unit owner: new `src/myfuzz/local_harness/native_reset_observation.py`, modify `src/myfuzz/local_harness/session.py` and `src/myfuzz/local_harness/gpio_session.py`; new `tests/local_harness/test_native_reset_observation.py`.
2. Runner association owner: new `src/myfuzz/scenario/native_reset_evidence.py`, modify `src/myfuzz/scenario/runner.py`; new `tests/scenario/test_native_reset_evidence.py`.
3. Semantic unit owner: new `src/myfuzz/scenario/register_reset_default_verifier.py`; new `tests/scenario/test_register_reset_default_verifier.py`. Read current register_program_verifier.py/ordinary_apb_access_evidence.py; do not add saved ingestion to them.
4. Session owner: modify `src/myfuzz/scenario/session_runtime.py`; new `tests/scenario/test_register_reset_default_session.py`.
5. Integration owner: modify `src/myfuzz/integration/ibex_pulp_register_replay.py` and `scripts/run_ibex_pulp_online.py`; new `tests/integration/test_register_reset_default_replay.py`.
6. Independent reviewer/native scripts and explicit remaining-default extension are sequenced after source freeze. Owners touching shared files wait for prior owner's freeze; Root assigns exact ownership before implementation.

The local observer→Runner evidence→semantic verifier interfaces below are production contracts; each implementer defines only its own unit and consumes the named preceding API. No generic caller-provider factory or restore setter is introduced.

### Task 1: Actual generated lifecycle and complete command ledger

**Files:** create local_harness/native_reset_observation.py and its new tests; modify local_harness/session.py and gpio_session.py.

**Consumes:** actual GeneratedLocalSession artifact/expected READY/build/binary/strict parse, actual `_process`, `_execution`, `_sequence`, `_tick_base`, reset_epoch and command implementation. Native GPIO first support is exact current ordinary GeneratedPulpGpioSession plus authenticated native artifact, not arbitrary lookalike sessions.

**Produces:** `NativeResetObservation(local, *, max_lifecycles=256, max_commands=4096)`; `configure_native_reset_observation(*, max_lifecycles=256, max_commands=4096)` before begin; readonly `native_reset_observation_enabled`; `native_reset_observation_configuration() -> dict`; `native_reset_observation_snapshot() -> dict`; private-class-owned facts exposed as detached `native_reset_observation_lifecycles() -> tuple[dict,...]` and `native_reset_observation_commands() -> tuple[dict,...]`. `NativeResetObservation.validate(*, allow_incomplete=False)` and `_preflight_command(operation, fields)` stay actual-object guards, not public JSON ingress.

- [ ] Define the concrete fixture in `tests/local_harness/test_native_reset_observation.py`, not an undefined external fixture. Render one current ordinary artifact with the existing factory from `tests/local_harness/test_ordinary_apb_access_receipts.py:native_factory`; take its actual `gpio_a` GeneratedPulpGpioSession. Write a bounded Python READY/END worker in pytest tmp_path, set `_binary` only before observer construction, then exercise unmodified GeneratedLocalSession.begin_case/reset_local/end_case. Build/native eligibility remains false for this software executable; no forged build metadata, successful native certificate or RTL claim is permitted. Lifecycle facts may be mechanically retained with native_eligibleFalse; semantic/native installation must refuse that gap. Use a separate worker implementing actual wire commands for command ledger tests, not the prior software_transport instance command override.

```python
@pytest.fixture
def actual_native_software_local(native_factory, tmp_path):
    local = native_factory().sessions['gpio_a']
    digest, asserted, released, _ = local._expected_ready()
    worker = tmp_path / 'ready-end-worker.py'
    ready = f'READY local_driver.v1 {digest} {asserted:x} {released:x}'
    worker.write_text('#!/usr/bin/env python3\nimport sys\nprint(' + repr(ready) +
        ', flush=True)\nfor line in sys.stdin:\n if line.strip()=="END": break\n')
    worker.chmod(0o700)
    local._binary = worker
    yield local
    local.end_case()
```

Import `native_factory` from that exact existing test module into the new test file. The fixture uses real bounded Popen/strict READY/reset lifecycle, **not native RTL qualification**; assert `native_eligible is False` on retained lifecycle documents and reject semantic qualification. The actual native build/binary eligible positive is reserved for supervised native acceptance. If design elects rejecting unverified software launch entirely, keep this mechanical fixture as a rejection+real base lifecycle control, rather than weakening eligibility to turn it into native authority.

- [ ] Write meaningful actual-parser software transport RED: initial READY gives logical_process1 and no explicit reset; real END/reap→begin READY after reset gives logical_process2 and targetepoch+1. Use bounded real software Popen for lifecycle and existing strict receipt parser for commands; no hand epoch/PC/waiting assignment.

```python
def test_actual_begin_and_reset_produce_distinct_private_lifecycle(actual_native_software_local):
    local = actual_native_software_local
    local.configure_native_reset_observation(max_lifecycles=8, max_commands=32)
    local.begin_case('reset-default-case')
    first, = local.native_reset_observation_lifecycles()
    local.reset_local()
    first, second = local.native_reset_observation_lifecycles()
    assert (first['logical_process'], second['logical_process']) == (1, 2)
    assert first['native_eligible'] is False and second['native_eligible'] is False
    assert first['kind'] == 'initial_begin' and second['kind'] == 'explicit_reset'
    assert second['previous_target_epoch'] == first['target_epoch']
    assert second['target_epoch'] == first['target_epoch'] + 1
    local.end_case()
```

Run `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_native_reset_observation.py -x --tb=short`; expected RED missing configure/API, after authentic fixture setup. Save exact failure, not setup typo.

- [ ] Define closed lifecycle document `native_reset_lifecycle.v1`: schema_version, lifecycle_ordinal, kind, logical_process, target_instance, target_epoch, previous_target_epoch, driver_identity, source_binding_sha256, build_inputs_sha256, binary_sha256, native_eligible, reset_assert_ticks, reset_release_ticks, process_exit_confirmed, ready_confirmed, first_command_sequence, proof_scope, grants. Grants storage/version/prerequisites/functional False; no exported PID/random `_execution` field.
- [ ] Define closed command document `native_reset_command.v1`: schema_version, command_ordinal, logical_process, target_epoch, command_sequence, operation, fields, parsed_receipt_projection, status, reason, coverage_cursor. Private record retains actual process and execution nonce/full parsed receipt; exported projection removes only those nondeterministic process identifiers and pins actual logical ordinals. All deterministic tick/sequence/data/status fields remain.
- [ ] Implement configure atomic preflight on exact current native object, no case/process/old observer; source/build/binary are checked at actual launch before/after READY, not assumed from a caller path. Capture class/instance/function code pins for producer methods and registry identities.
- [ ] Instrument `_command_impl` after strict argument validation but before stdin dispatch; preflight capacity then reserve command attempt. After strict actual parse, seal that command and update coverage cursor before GPIO `_take`/router callback. If command may have been sent but parse/transport fails, mark permanent incomplete and retain failure attempt; direct `write_register` and public `command` naturally use same path. ACK transport is covered internally with exact acknowledged sequence and no semantic mutation claim.

```python
observer = self._native_reset_observation
if observer is not None:
    observer._preflight_command(operation, fields)
    attempt = observer._begin_actual_command(self, operation, fields)
try:
    receipt = parse_driver_receipt(answer.strip(), execution=self._execution,
        sequence=sequence, current_tick=self.local_ticks - self._tick_base,
        kind=kind, clock_schedule=self._artifact_document.get('clock_schedule'))
except BaseException:
    if observer is not None:
        observer._fail_actual_command(self, attempt)
    raise
if observer is not None:
    observer._complete_actual_command(self, attempt, receipt)
```

The parse call above uses the existing `_command_impl` locals after real transport reply; it is not a caller receipt argument. Helpers `_begin_actual_command`, `_fail_actual_command`, `_complete_actual_command` are private methods of NativeResetObservation and validate the pinned actual producer/attempt identity. Final source patch retains original off-path statements and DriverReceipt return.

- [ ] Seal READY only after actual parse success; explicit reset first validates actual previous Popen exit/reap and target epoch advance. Rejected READY/partial reset supplies no success seal and cannot heal observer. end_case closes the private process binding even though END bypasses normal ACCESS command dispatch.
- [ ] RED→GREEN directwrite/unknown/missing/repeated/pending/possibly-applied failure/capacity/source-binary/code drift tests. Detached mutation and saved equivalent JSON never changes private record. Confirm ordinary/default-off and routed/causal existing tests.

Run `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_native_reset_observation.py tests/local_harness/test_ordinary_apb_access_receipts.py`; expected PASS. Root selects the existing routed/causal GPIO regression suite without modifying its fixtures or changing disabled behavior. Freeze source SHA before Task2 actual fixtures.

### Task 2: Runner-owned reset and complete command association

**Files:** create scenario/native_reset_evidence.py and tests; modify scenario/runner.py.

**Consumes:** Task1 actual readonly lifecycle/commands and private observer identities; actual ScenarioRunner CPU/router/window/session/ledger/memory and reset_all barriers. Existing `ordinary_apb_access_evidence.completed_accesses()` contributes READ/CPU delivery evidence, not command-interval completeness.

**Produces:** `NativeResetEvidence(runner, *, max_records=256, max_commands=4096)`; `ScenarioRunner.install_native_reset_evidence(*, max_records=256, max_commands=4096) -> dict`; `native_reset_evidence_configuration() -> dict`; `native_reset_evidence_snapshot() -> dict`. Code-owned `NativeResetEvidence.completed_intervals() -> tuple[dict,...]`, `validate(*, allow_incomplete=False)` and `_preflight_command()` bind actual installed providers. No public ingest/restore API.

The Runner-scoped `MemoryCommitAuthority` identity is part of this installation contract. Any configuration that can create or replace it must run before Task2 installation; later configuration that would replace a pinned `None` is rejected. For the selected-read/RAM path, configure actual CPU write/readback receipts and the shared authority first, install Task2 second, then register the Task3 reset-default consumer on that same unused authority. Register any existing `RegisterProgramVerifier` only after Task3 registration, because it pins the authority's complete consumer set at installation. All semantic consumers must be registered before the first commit token is staged.

- [ ] Write an actual-provider software RED→GREEN proving a standalone target reset cannot become Runner-wide reset evidence. Use a real Task1 observer and actual bounded local Popen, call `target.reset_local()` without a Runner barrier, then call the public snapshot before another command; the association must remain permanently incomplete and later preflight must refuse. Do not add a successful joined `begin_test()`/`reset_all()` software fixture: actual `ScenarioRunner.begin_test()` runs `prepare_local()` and builds/replaces the worker, and there is no compliant route under the frozen Task1/no-native-build constraint. Successful distinct target/CPU/Runner/memory domain transitions are deferred to Task5 supervised native acceptance.

```python
def test_snapshot_cannot_heal_standalone_target_reset(native_factory, tmp_path):
    runner = configured_runner(native_factory, tmp_path)
    runner.install_native_reset_evidence(max_commands=32)
    target = runner.sessions['gpio_a']
    target.begin_case('mechanical')
    try:
        target.reset_local()  # Actual Task1 lifecycle; no ScenarioRunner.reset_all barrier.
        state = runner.native_reset_evidence_snapshot()
        assert state['status'] == 'incomplete'
        with pytest.raises(ValueError):
            runner._native_reset_evidence._preflight_command()
    finally:
        target.end_case()
```

Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_native_reset_evidence.py -k snapshot_cannot_heal_standalone_target_reset -x --tb=short`; first confirm the current behavior is a real failing negative, then require the fixed guard to pass. Fixture uses an actual Task1 provider and bounded local Popen; the test does not claim a joined global barrier.

- [ ] At real private event append, verify provider class methods/registries/source binds, obtain private facts then allocate event refs. Require complete coverage cursor from seal through selected command, same actual target/process/epoch, exact command sequences. Do incremental new-fact indexing, bounded refs via `_event_ref_by_id`, not wholejournal scans or caller registrations.
- [ ] Distinguish independent `reset_local` from complete Runner reset_all: per-target seal alone cannot claim global barrier. Partial global reset leaves incomplete with retained history; old barrier/foreign target cannot match.
- [ ] Add default-None Runner semantic binding `_register_reset_default_verifier`, private actual commit hook before current MemoryCommitAuthority acknowledge, and module-pinned `guard_native_reset_evidence(runner, *, new_operation=False)`. Task3 installs the actual verifier into this slot; absent slot preserves old paths. `new_operation=True` checks semantic retained history/selected-operation capacity before source reservation; False checks drift/incomplete but permits last legal case remaining ticks and export. Direct lifecycle command capacity is always checked before actual target command.
- [ ] Preserve actual accepted/pending/callback failure: command ledger can show appliedWRITE even when ordinary completed rows absent; unknown/missing/pending/conflict/current provider incomplete blocks any reset interval qualification. Bind CPU execution/sourceepoch and actual memory object/generation at selected operation and real case context.
- [ ] Module-pinned Runner command guard executes before STEP/reset/admission, cannot be bypassed by instance/class override; capacity rejects before effect, export uses strict static guards while allowing already-incomplete history.
- [ ] Import-time ownership checks cannot learn replacement baselines at installation: regress simultaneous checker/table replacement, checker default mutation, and replacement of `inspect.currentframe`'s `inspect.sys` dependency with a forged caller chain.
- [ ] Before registering any Task1 issuer, pin the Task1 session `_NATIVE_RESET_CHECK_PRODUCERS` dispatch tuple/function/code, then verify every import-time `NativeResetEvidence` and target `NativeResetObservation` method-table entry still matches its class attribute and code object across all targets; preinstall dispatch/class-method drift, including on a later target, must fail with all targets unregistered.
- [ ] Actual commit drain, pending-receipt lookup, and issuance-equality checks are inside the same terminal failure boundary as journal append, all semantic consumers, UART joins, and acknowledgement. A preflight/callback exception leaves the receipt unacknowledged, permanently marks Runner/evidence uncertain, and cannot be silently skipped after stream-offset advance.
- [ ] Actual directwrite/callbackfail/pending/resetbarrier/foreignprocess/privatehash/source drift RED→GREEN and baseline ordinary Runner hooks regressions.

Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_native_reset_evidence.py tests/scenario/test_ordinary_apb_access_runner.py`; both paths are exact, with the existing ordinary hook module present in the workspace. Freeze before Task3.

### Task 3: Source-bound stable-field reset-default semantic rule

**Files:** create scenario/register_reset_default_verifier.py and tests. Existing register semantic verifier stays ordinary consistency scope.

**Consumes:** actual `RegisterProgramRuntime`, Task2 installed NativeResetEvidence, actual successful case/manifest, ordinary sealed completed-accesses, actual one-shot MemoryCommitAuthority. Actual readiness/assert/release execution evidence is required; raw waveform not claimed.

**Produces:** `RegisterResetDefaultVerifier(runtime, *, max_records=256)` before begin; `configuration() -> dict`, `_preflight_command(*, new_operation=False)`, `_consume_actual_commit(logged, token)`, `report() -> dict`, `session_document() -> dict`; public pure `validate_register_reset_default_session_document(document, *, configuration) -> dict` returns detached comparison data only. Constructor registers a new unique actual MemoryCommitAuthority consumer `register_reset_default_verifier`; Runner invokes private consume before acknowledge, matching existing one-shot semantic verifier pattern.

Installation requires that Task2 and any authority-producing CPU evidence configuration already be complete, that the verifier receives the exact authority pinned by Task2, and that the authority is unused. Register this consumer before constructing `RegisterProgramVerifier`, whose current constructor snapshots the complete one-shot recipient set.

**Software/native boundary:** Under the current frozen Task1 and no-native-build constraint, a compliant software fixture cannot execute a successful joined Runner reset/readback sequence. Task3 software tests are therefore limited to source-rule conformance and fail-closed refusal for non-native/incomplete/reset-uncertain evidence. They must not inject native eligibility, synthetic private facts/tokens, completed intervals or successful certificates. The actual warm/cold reset→resume→default-readback certificate is a Task5 supervised native-gate positive. Keep its exact expected lifecycle, CPU, APB and issued-RAM chain here as the native acceptance contract.

- [ ] Write pure source-rule and fail-closed software RED→GREEN cases for actual profile/sidecar/RTL pin agreement, stable-field effect classification, and refusal when lifecycle is mechanically ineligible, a barrier/default read proof is absent, or source/consumer state drifts. In a negative test that offers a software `native_eligible=False` lifecycle, assert no report/session document contains a reset-default certificate. The positive A.INTEN WRITE nonzero→READ→actual warm/cold reset→recorded resume→selected READ0/private issued RAM chain is tested only by Task5 supervised native generation/fresh gates.
- [ ] Closed source rule first supports wholeword INTEN.value with current RTL SHA/reset assignment, PAD_NUM32, no non-reset internal/asynchronous hardware writers, profile/sidecar reset_value0/maskffffffff/no sideeffect. Explicitly audit the asynchronous reset assignment and the `s_write_inten` APB write path; do not call the reset assignment an unsupported writer. Derive aliases from the pinned `PADDR[6:2]` decode and 128-byte alias period, never from saved alias sets. It does not infer support from generic rw/reset_value. Both target instance and typed profile/sidecar bind exact current identity.
- [ ] Total effect function classifies every command from complete cursor. ACCESS_GPIO WRITE to same word or source-bound alias destination invalidates regardless value, BE, field or equal-write; fullword RMW another field on same word invalidates. Known writes to genuinely unrelated current-source addresses may be allowed; unknown/reserved/ambiguous/missing alias/unsupported effect/pending/failed applied command permanently gap/incomplete. STEP_GPIO/environment effects are allowed only for source-reviewed stable INTEN with no internal writers, never PADIN/STATUS.

```python
def classify_inten_command(command, *, inten_offset, known_unrelated_offsets, alias_offsets):
    if command['status'] != 'parsed_complete':
        return 'incomplete'
    if command['operation'] == 'STEP_GPIO':
        return 'stable_field_no_internal_writer'
    if command['operation'] != 'ACCESS_GPIO':
        return 'unknown_command'
    gpio_input, write, offset, value, be = command['fields']
    if not write:
        return 'read'
    if offset == inten_offset or offset in alias_offsets:
        return 'affecting_write'
    return 'unrelated_write' if offset in known_unrelated_offsets else 'unknown_offset'
```

The current-source rule supplies offsets from typed profile/sidecar plus audited RTL; it never trusts saved sets. EqualWRITE invalidates even value0; known-unrelated permission must be complete and source-locked. If no reviewed classification is available, return gap rather than delete bootstrap writes.

- [ ] Native qualifier requires live private descriptor native_eligibleTrue backed by current actual build/binary verification; mechanical software lifecycle, fake READY identity and a standalone binary SHA never satisfy it. Software rule conformance tests may exercise gap/refusal; they cannot fabricate eligibility to claim a native-positive. The first real positive for eligibility is the supervised native gate.
- [ ] Cert chain: actual target seal+Runner binding→continuous complete command interval/no affectingWRITE→exact successful selectedREAD source/target/CPU/memory domains→actual APB request/accept/response and queued CPU response→same fullkey context, sequence afterREAD, actual issuedRAM span/data→reset_value. Compiler remains no expected/reset oracle.
- [ ] Cert schema `ordinary_register_reset_default_certificate.v1`, proof_scope `observed_source_bound_reset_default_readback`, exact requested field/op/source fingerprints/resetseal ref/coverage cursor/READ access/RAMcommit; all storage/version_dependency/prerequisites/functionalFalse. Report current/history separate; later reset, failedresume, runtime uncertain or provider incomplete clears current while preserving immutable history.
- [ ] Tests directwrite/equal/alias/unknownoffset/fullwordRMW/internalwriter unsupported, prior/foreign RAMcommit, external reset_local/wrongbarrier, late process/source/code drift, failedresume/callbackfail. Saved rehash/projection mismatch rejects but never installs cert.

Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_register_reset_default_verifier.py`; expected first genuine missing-rule RED then GREEN. Keep existing source-bound profile/register semantic tests, do not widen compiler readclear whitelist.

### Task 4: Session opt-in closed wrapper and fresh reconstruction

**Files:** modify `src/myfuzz/scenario/session_runtime.py` and, in a separately coordinated owned turn, `src/myfuzz/scenario/register_program_runtime.py` to call Task2 pinned guard before prepare/registration and cached-submit return; new `tests/scenario/test_register_reset_default_session.py`. Do not share these files with another active owner.

**Consumes:** Task1/2 configuration and Task3 actual verifier. Attached current RegisterProgramRuntime and declared actual slots precede final install because memory slot identity is configuration.

**Produces:** `ScenarioSession.configure_register_reset_default(*, max_records=256, max_commands=4096)` before begin; `register_reset_default_document() -> dict`. Optional plan `register_programs.register_reset_default` exact `{schema_version:'register_reset_default_session.v1', configuration, state}`; manifest `register_reset_default_configuration` plus `register_reset_default_source_files` startup-only. Existing schema16/17/18/19 remains version chosen by existing complete/uncertain/resume semantics; new wrapper only explicit opt-in and pure closed validated.

- [ ] Actual beforebegin atomic install RED, already begun/events/foreign runtime/capacity/method drift rejects no halfconsumer/provider; capture all fallible sourceclosure checks before installing consumer. Defaultoff encode exact row/field layout remains unchanged.
- [ ] Runtime.prepare calls module-pinned guard(new_operation=True) before any registration/reservation; cached successful submit and ordinary Session reset/advance call guard(False). ActualREAD commit consumer retains only active selected request result span/fullCPUcontext after one-shot resolve, not bootstrap/unrelated writes; capacity cannot truncate intervals or silently skip candidate commits.
- [ ] Install target observers before native begin, then Runner evidence/verifier; bind actual object/method/config startup SHA. Runtime/Runner/Session guard captures method function+code identities and private registry objects. Used-config beforecommands validates current source/build/binary pointers; terminal export never heals incomplete.
- [ ] Public document obtains one actual report, pure-validates detached; encode final validators still check allmanifest/wrapper fields. No caller alreadyvalidated flag or saved report cache; serialized logical ordinals remain deterministic and cannot register provider.
- [ ] Fresh installer runs before begin with actual sourceconfig; original requests/reset/resume recompile through actual Runtime, lifecycle privately regenerates, and terminal actual wrapper/plan/trace compare. No restore saved PID/nonce/cursor/seal/cert. Existing finish_export pins/final currentstatic guards stay required.

```python
def test_saved_reset_seal_is_only_comparison(actual_reset_session):
    session = actual_reset_session
    session.configure_register_reset_default(max_records=8, max_commands=128)
    session.begin()
    # Fixture executes actual selected request/reset/resume/READ through Session.
    plan, trace = session.finish_export()
    comparison = replay_online_session(plan, actual_reset_session.runner_factory,
        trace, register_runtime_factory=actual_reset_session.trusted_installer)
    assert comparison.matches
```

The new test fixture defines runner_factory/trusted_installer and yields after actual WRITE/READ/reset/resume/READ requests; it is implemented in this test file, using the concrete current lifecycle_factory from tests/scenario/test_register_reset_resume.py for actual CPU bootstrap/reset sequencing. For lifecycle coverage positives, use a new bounded real wire-protocol software worker through unmodified _command_impl, not alias_factory command overrides; software output is mechanical/semantic conformance evidence, never native build/RTL acceptance. Build/binary authentication is exercised negatively with synthetic transport and positively in the native gate; no fake build seal may be exported as native authority. Run `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_register_reset_default_session.py tests/scenario/test_register_reset_resume.py tests/scenario/test_register_program_replay.py`; expected GREEN after explicit missing API RED. Actual source-bound fixtures run only after all owners freeze.

### Task 5: Trusted assembly/file selector and native acceptance

**Files:** modify integration/ibex_pulp_register_replay.py and scripts/run_ibex_pulp_online.py; new integration tests; prepare new `runs/stage2-e2-register-reset-default-warm-20261012-v1` and cold sibling check.py/supervise.py/fresh_cli.py/preparation.json only after software freeze.

**Consumes:** Task4 APIs and pure validator. **Produces:** optional closed assembly `register_reset_default={max_records,max_commands}`, requires ordinary evidence+register runtime; installer order declare slots→configure actual commit/readback authority→Task2 observer→Task3 reset-default verifier (registers its one-shot commit recipient)→existing optional RegisterProgramVerifier→Session configure resetdefault→begin. Current generated identity regeneration verifies exact enabled extension against actual artifacts; no generic saved provider path. Enabled source closure includes all new modules and actual `_host_sources()` transitive closure; defaultoff field layout preserved.

- [ ] Nonempty authenticatedfile RED through actual software factory/callback/READY/privateRAM, then writer/selector pre-mkdir/prefactory closed wrapper validation, exact assembly/config SHA binding. Boolint/unknown fields/nonce in exported wrapper/cursor holes/rehash swapped target/late source/binary drift fail beforefactory or fullfresh comparison.
- [ ] Preserve runidentity artifact hash/compression semantic checks; file selector derives original requests from closed plan, not savedprogrambytes authorization. CLI returns actual reset-default state and complete matches/genome/semantic/eventcount/ordinary/verifier/gate comparisons.
- [ ] Run `PYTHONPATH=src python3 -m pytest -q tests/integration/test_register_reset_default_replay.py tests/integration/test_register_reset_resume_replay.py`; expected first missing channel RED then all PASS. Root runs independent static/schema/saved tamper review plus affected defaultoff/routed/causal compatibility; no source edits during binding tests.
- [ ] Prepare one warm and one cold native gate: current A.INTEN WRITE80000000→READsafeRAM proves oldactualvalue, actual Session.reset(policy)→bounded advance_after_reset at true waiting→new READsafeRAM proves0. Persist actual READY lifecycle process logical ordinal, resetbarrier/target/CPU/generation, complete commands including boot/equalwrite/callbackstatus, all actual raw/APB/IRQ/pending/RAM, exact cert/fresh wrappers; no unrelated field boot-write deletion. Gate expects source-rule-qualified default certificate, not just ordinary read consistency.
- [ ] Each generation and fresh separately `PYTHONPATH=src python3 <newdirectory>/supervise.py` / `.../fresh_cli.py`, original singleworker/RSS, strict current cache/build/binary checks — wall-clock 上限见第 25 行的 `native_gate_budget.v3` 修订（reset-default 四项原生阶段为 600 秒；单 worker／RSS／锁不变）。Keep all cases and status receipts on failure; no reuse old reset-resume success as default proof. Only after both terminal PASS run independent complete JSON audit (sourcepins/artifacts/private-derived projections/fullrequests/fulltrace/wrappers/resources); no concurrent audit reduces memorybudget.

### Task 6: Explicit remaining reset obligations and source-semantic extensions

**Files for subsequent reviewed implementation:** scenario/ibex_pulp_dual_source.py and integration/ibex_pulp_register_replay.py for a closed minimal-bootstrap selector; new tests/scenario/test_register_reset_default_bootstrap.py; separate PADIN/INTSTATUS rule modules/tests selected only after reviewed source semantics. No implementation in this plan's first stable-field release silently closes them.

- [ ] First create minimal code-owned bootstrap fixture that reaches legal online missing slot without writing DIR/OUT/GPIOEN/B.INTEN/default-target words. Bind actual initialimage/sourceaction/memoryslot permissions and fixedselector identity; original loop/ISR side effects remain observable. Direct PC/waiting/epoch assignment or arbitrary saved firmware authorization forbidden. Software/native fresh must execute those original fixed bytes.
- [ ] Expand source-reviewed stable-field support to DIR/OUT/EN/PADCFG/narrow fields with exact reset assignments/masks, no-affecting-write intervals, physical reset/lifecycle evidence and actual CPU/APB/privateRAM default reads, separate fresh gates. Do not claim all default matrix from first A.INTEN example or boot-overwritten values.
- [ ] PADIN needs actual external input/synchronizer history and source-derived conditional expectation; no host instantaneous pad or reset_value alone. INTSTATUS needs actual status-generating event and s_rise_int priority/conditionalclear interval, not simple repeatedzero READ. New compiler allowance/effect consent and semantic rule require explicit separate source audit/RED before any native request; keep current rejection until that is satisfied.
- [ ] Original permission/width/effect requirements remain: actual static precommand RO/WO/invalid admission evidence is not PSLVERR error behavior (RTL fixes0), LW/SW full32/BE15 is not byte/halfword access. Record supported gaps and do not convert narrower consistency proof into functional/storage/version qualification.

## Completion checkpoints and self-review

- [ ] Each task saves exact initial meaningfulRED command/output, finalGREEN count/time, current source SHA and review boundary; setup errors remain honestly separate. Sourcefreeze only after all owners stop editing.
- [ ] First stable-field package complete only when software actual producer/coverage/semantic/saved/fresh negative tests, native warm+cold generation/fresh and independent audits all pass under unchanged budgets. Then update scoped plan/progress while original E1/E2/Stage2 remains open for Task6/full matrix.
- [ ] Coverage audit: directcommands/appliedfail/pending/unknown/equal/alias/RMW, process vs barrier/CPU/memory domains, private one-shot RAM, deterministic logical export, defaultoff/routed compatibility, fullcurrentidentity/plan/trace and non-RAW READY wording are all represented above. No plan task restores saved authority or relies on silent host state.
- [ ] Interface audit: all new APIs are defined in their producing task; Task4 configure/document consumes Task3 verifier, Task5 installer consumes Task4, no new Runtime constructor flag. Capacity/history behavior is consistent across command preflight and terminal read-only exports.
- [ ] Execution is already authorized and multi-agent selected. Root assigns these owners sequentially where shared files overlap; do not ask execution choice, stage or commit.
