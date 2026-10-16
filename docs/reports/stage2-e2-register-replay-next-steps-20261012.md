# E2 register-program saved Session and trusted replay implementation detail

Latest continuation: narrow-field READ now executes a real 32-bit load, CPU shift/mask and field-relative zero-extended RAM store, with exact saved extraction metadata. The actual 14-case v2 gate and separately budgeted production fresh CLI both pass (28 confirmed associations, 6 RAM results, 29985 events). GPIO A/B each report 148 declared / 142 effective / 0 verified rows and aggregate L1. The new bounded READ/WRITE/RMW observational verifier has software boundary coverage but is not installed in that actual gate. Its Session/assembly/save/fresh CLI opt-in is the immediate next package, with real missing-API RED tests already recorded. Full alias/reset/permission/conditional-effects rules and original Stage2 remain open. See [current execution report](stage2-e2-register-verifier-execution-20261012.md) and [next-package design](stage2-e2-ordinary-register-verifier-design-20261012.md).

Historical frozen package details follow; their source counts and capability matrices describe those earlier versions.

2026-10-12 continuation: production ordinary APB Session opt-in, complete startup/terminal data, code-owned 278-file closure and original-request fresh file replay are implemented and software-verified. Actual 10-case execution and authenticated save are verified; separately budgeted production fresh CLI passes with all 24 bootstrap+case associations and 22387 events. The original combined 180-second gate timed out and remains recorded. See [production execution report](stage2-e2-ordinary-access-production-replay-20261012.md). Association still grants no storage, verified or functional capability; the scoped verifier/readback/reset work below remains open.


Date: 2026-10-12. This is implementation detail within the authorized E2 plan, not a new approval boundary. The five implementation steps below are complete for the actual schema 16 production CLI path. Schema 17 has software failure-boundary coverage. The insertion-point descriptions below retain the original implementation proposal; the audit at the end supersedes their historical pending-work status.

The actual-context adapter, explicit RV32I narrow-field RMW and subsequent production saved-file selector have passed their actual gates. Original requests are preserved in the Session plan and every program is rebuilt using fresh actual runtime authority. Remaining original-plan work concerns capability reporting and behavior evidence. No functional oracle, L2 capability, causal decoder support, or complete E2 claim follows from this work alone.

## Existing interfaces and exact insertion points

- `src/myfuzz/scenario/register_program_runtime.py`: `RegisterProgramRuntime(session, *, cpu_component, sidecars, advance_rounds, max_program_bytes=16, max_records=4096)` must be installed after instruction-slot declarations and before `Session.begin`. `prepare(request, expected_manifest=None)` returns a detached manifest and freshly compiled source/case. `submit(...)` registers the exact F4 action, calls the actual `Session.submit_case`, and returns manifest/receipt. Its configuration pins current profile files, typed profile fingerprints and bindings, artifacts, sidecar paths/hashes, Python sources, actual memory/gate policy and provider configuration. Its context binds actual accepted waiting fetch, generation, CPU/target reset epochs, command epoch and tracker epoch. Any error after registration begins leaves a recorded permanently uncertain adapter.
- `src/myfuzz/scenario/session_runtime.py`: `ScenarioSession.__init__` currently initializes case/admission history; `begin` calls `_online_manifest`; `encode_plan` selects schemas 4–15; `replay_online_session` decodes those schemas and calls `trusted_gate.register_replay_case` before submitting each decoded case. These are the minimal Session insertion points.
- `src/myfuzz/scenario/session_runtime.py`: `_online_manifest` and `_ONLINE_SOURCE_PATHS` currently carry runner/checker/runtime-path identity. Register configuration and its complete source closure must become an opt-in identity extension, leaving legacy manifests unchanged.
- `src/myfuzz/integration/ibex_pulp_online.py`: `replay_pulp_dual_source_online_files` verifies the saved run identity before selecting actual factory modes, but currently hard-codes `IbexPulpOnlineChecker` and does not forward the native physical-observation switch. Do not route new register bundles through that unchanged selector.
- `src/myfuzz/integration/scenario_rfuzz_live.py`: `_write_online_run_identity` and `_verify_online_run_identity` provide existing artifact/source authentication. Reuse this authentication before inspecting saved register assembly choices.
- `scripts/run_ibex_pulp_online.py`: add an explicit `replay-register-programs --cache-dir ... --run-dir ...` branch beside `replay` and `replay-candidates`. Its output should identify register reconstruction and complete-prefix comparison, not candidate scoring or functional coverage.

## Closed schemas 16 and 17

Use explicit schema 16 for a register-program Session with no uncertain terminal attempt, and 17 for an uncertain terminal register attempt. Keep schemas 4–15 byte/layout compatible. Do not accept register fields as optional extensions of old schemas.

Both new schemas have the existing base fields `schema_version`, `template`, `instruction_slots`, `warmup_advances`, `cases`, plus mandatory `prerequisite_admissions`, `reset_operations` (possibly empty), and `register_programs`. The initial implementation is directed-only: reject runtime paths, provenance, source scheduling ticks, external-source cases and fixed support instructions. A Session must use its actual installed persistent-memory gate. An arbitrary caller gate or a candidate budget of zero is not an equivalent mode.

The `register_programs` object has an exact versioned shape:

```json
{
  "schema_version": "register_program_session.v1",
  "configuration": "the complete detached installed adapter configuration",
  "case_manifests": ["one exact register runtime manifest per recorded Session case"],
  "terminal_attempt": null,
  "gate_state": "actual installed gate.document(), comparison evidence only"
}
```

Here the quoted descriptions stand for objects/arrays, not literal strings. Each case manifest preserves the original closed `register_program_request.v1`, complete actual context, compiler document, original SourceAction and expected admitted action. Request fields are exactly `schema_version`, `case_id`, `action_id`, `target_instance`, `endpoint_id`, `register`, `field`, `operation`, `value`, `allow_side_effect`, `result_address`, and `read_modify_write`. Both authorization flags require exact booleans. Read requests carry no value/RMW; write requests carry no result address. Addresses, windows, RAM regions, program slot and registers are not request authority.

`case_manifests` must align exactly with `cases` in order and identity. Compare the complete fresh source bytes, direction, path, advance schedule, and empty support list with the saved case. No missing/extra/reordered manifest, duplicate action/case ID, or mixed legacy byte-only case is accepted.

Schema 17 requires a non-null closed terminal-attempt object containing the exact attempted manifest, failure phase, error type and nullable Session case index. Use distinct phases for registration, returned-action verification, and Session submission. It also carries `terminal_failure`, which is null if Session never recorded an execution failure, or the unchanged existing Session failure record otherwise. Cross-check these two records rather than inventing a final Session case for a registration failure.

There are two valid uncertain boundaries:

1. Registration or pre-command submission failed before `Session._cases` appended the attempted case. `terminal_attempt.case_index` is null, and its request is not an additional saved Session case.
2. Session appended the case before a source-admission, step or checker failure. Its attempted manifest is the final aligned `case_manifests` entry, and `case_index` is the final Session case index. Preserve Session's actual failure phase/index.

The adapter now records these explicit phases and the nullable actual Session case index; eight new regressions reached RED then GREEN, with 45 runtime tests passing. The Session schema and replay wiring still require their own verification. Publish a successful last manifest only after `Session.submit_case` succeeds. Preserve failed attempts separately. Never undo only the gate's action dictionary and claim that reservations, declarations, counters and witnesses were rolled back.

## Fresh reconstruction and admission

1. Validate the full saved schema, plan hash, trace hash/semantics, run identity and artifact source closure before creating a runner or issuing commands. Saved sidecar paths must not choose arbitrary files or Python providers.
2. Resolve a closed register assembly through installed code: known CPU/profile, known target-to-sidecar mapping, known factory, exact persistent-memory/native-observation flags, bounded adapter settings and an explicit checker mode. Initially use `checker=None`; do not silently substitute the legacy pilot checker. A saved selector label is matched against a fixed local mapping, not imported or evaluated.
3. Create a fresh actual runner and Session, declare the saved instruction slots through Session's real declaration API, then install the adapter before `begin`. Compare fresh adapter configuration with the authenticated saved configuration. Include this configuration in the opt-in online manifest and compare the full manifest before commands.
4. Begin the Session and replay fixed bootstrap advances. Apply resets at their exact recorded prefix positions. The actual CPU must reach its real waiting fetch; the saved waiting address cannot set that state.
5. For each case, call fresh `adapter.prepare(original_request, expected_manifest=...)`. This recompiles from actual profile, sidecar, router target/window, RAM regions, unmaterialized declared slot and accepted waiting transaction. Compare its whole fresh case with the saved case. Explicit RMW requires the live 36-byte budget and actual read/write permissions; narrow ordinary access remains rejected unless requested RMW is admitted.
6. Compare the saved prerequisite declaration with the deterministic declaration corresponding to the fresh manifest before registration. The permitted directed compiler has no dynamic result-slot load binding: expected support actions are empty and dynamic binding is null. Registration still runs through the actual installed gate, and the adapter already checks the exact returned admitted action. If that contract later gains a dynamic binding, require a dedicated live re-evaluation path rather than assuming null.
7. Submit the original request through the adapter with the exact expected manifest. **Do not call `trusted_gate.register_replay_case(saved_case, saved_declaration)` in this branch.** That existing API reconstructs an action from saved byte input and is appropriate to earlier schemas, not declarative-register authorization.
8. Compare actual generated Session admission declarations, actual installed gate state, adapter attempt state, reset timeline and complete trace against the saved prefix. The saved gate_state is never restored or used to authorize registration. Cleanup must run for construction-after-installation, bootstrap, prepare, registration, submit, reset and finish failures; preserve the primary exception when cleanup also fails.

An expected uncertain failure is comparison evidence, not an instruction to inject a failure. Fresh replay must naturally reach the corresponding failure boundary. If fresh execution succeeds where the saved run failed, report a mismatch. Do not force the saved error or reproduce a saved half-action as authority.

## Trusted file selector and identity

Add a small integration module for a closed `register_program_assembly.v1` and file replay entry, rather than widening the causal runtime-path validator. The assembly should bind known CPU/target profiles, enrolled sidecar selectors, checker mode, native physical observation, memory commit/read evidence and persistent-memory gate mode, actual runtime contract identity, and adapter limits. Every switch is an exact boolean; every numeric limit is an exact integer; every hash has a fixed canonical representation.

The selector must obtain modes only from an already authenticated run identity and verify agreement between assembly, run configuration, Session manifest, plan configuration and fresh adapter configuration. Re-select the actual native physical observation when the bundle declares it. Reject unsupported profile/channel combinations before starting a harness; never fall back to a weaker profile or legacy checker.

Add the runtime adapter, compiler, RV32I encoder/validator, sidecar planner/loader, Session/gate/memory/authority code and selector modules to the authenticated source closure. Keep profile and sidecar file SHA, current typed profile fingerprint and full binding, and source/build inputs bound to their actual paths. Saved compiler/context documents are compared only after fresh compilation; hashes do not make their addresses or regions authoritative.

Persist plan, trace, Session manifest, closed assembly, adapter terminal state and their artifact hashes together. The CLI should return nonzero on malformed identity or any comparison mismatch and print an explicit scope such as `register_program_reconstruction`, `register_program_admission`, and `online_complete_prefix`. It must not label this as functional-oracle verification or causal L2 certification.

## Required fail-closed software regressions

- All old schemas remain unchanged and replayable; schema 16/17 reject legacy/mixed byte-only cases, extra fields, wrong schema scalar types, missing/reordered/duplicate manifests and inconsistent counts.
- Change saved request value/register/field/effect/RMW flag; rehash all saved documents consistently. Fresh reconstruction still rejects or produces a comparison mismatch before registration.
- Change saved source bytes, address, result address, windows, regions, program size, waiting transaction, generation or epochs; rehash consistently. None becomes authorization.
- Change current sidecar content/path, profile file/SHA, typed CPU or target profile under an old plan digest, binding, native GPIO observe action, CPU IRQ role, router object/window target/base/overlap, memory/service/authority, gate/lifecycle/slot policy, or switch/capacity. Reject before commands; recover only when genuine state is restored and no uncertain registration occurred.
- Startup profile/binding drift and post-begin artifact adoption cannot establish a new baseline. Native validation runs against the actual artifact on every admission.
- Explicit result storage cannot overlap any declared instruction/support slot, current fixed image, previously registered source-owned instruction span, MMIO route or actual `INITIAL_IMAGE`/`INSTRUCTION_SOURCE` byte. Inspect without materializing memory. Ordinary data written by an actual STORE remains eligible RAM storage; there is no host expected-value oracle.
- RMW missing read permission, incomplete register semantics, side effects, wrong field access, a boolean budget or insufficient live slot capacity refuses before registration. Read-clear/pop stays refused.
- Bootstrap/reset history is replayed before preparing the next request; saved old-generation manifests and changed accepted waiting fetch keys refuse. Repeated exact successful retries perform no extra registration, reservations or commands; changed retry request/config/epochs refuses.
- Duplicate case/action IDs, invalid schedules, exhausted record/action capacities and unsupported provenance/runtime-path mode refuse before mutation. A zero budget is not an independent mode selector.
- Unexpected returned action, `_reserve` exception and late Session refusal record one uncertain terminal attempt, preserve any real half-mutation and prohibit further admission. Check both nullable and final-case failure boundaries.
- Assembly/run-config/plan/manifest channel mismatch, bool/int ambiguity, unknown selector/checker, unsafe sidecar path, tampered artifact/source hash or malformed compressed trace is rejected before runner start.
- Saved uncertain failure never triggers synthetic failure. Fresh success versus saved failure is a mismatch; primary admission failure survives cleanup failure.

## Minimal implementation order

1. TDD the adapter's explicit attempted phase/case-index record and detached success publication. Keep existing uncertain-state behavior.
2. TDD Session installation/identity hooks and schema 16/17 encoding/closed decoding with unchanged legacy fixtures. Add source-closure pins only in the register opt-in identity.
3. TDD the new fresh replay branch using actual software Runner/CPU/memory/gate fixtures. Verify that saved-byte `register_replay_case` is never called, original requests are rebuilt, and all pre-command rejection/terminal boundaries are preserved.
4. TDD the closed integration assembly/file selector and CLI branch, authenticating the existing run identity first and selecting exact native/gate/checker modes without a causal-profile relaxation.
5. Freeze production sources, run the relevant software regressions, then have root run one serial saved-file actual gate through the production CLI. Compare the complete fresh trace, admissions and adapter terminal state; independently audit original requests, raw APB/RAM evidence references and source/build identities. Only this closes the remaining saved/replay selector portion of E2.

## Original-plan audit after the production CLI gate

Audit date: 2026-10-12. Production files remain frozen. All five implementation steps above are completed for schema 16: installed adapter, opt-in manifest/source closure, closed encoding/decoding, fresh original-request replay, authenticated assembly/file selector and production CLI. [Actual summary](../../runs/stage2-e2-register-file-cli-20261012/summary.json) records 10 cases, 54 actual APB boundaries, two read-to-RAM commits and 22,339 complete-prefix events matching fresh replay. Its scope is `trusted_register_file_cli_fresh_request_recompilation_and_complete_prefix`; `rfuzz_client_executed=false` and `verified_level=null`. Schema 17 is implemented and software-tested, including uncertain registration and nullable case boundaries. An actual injected-fault schema 17 gate is **not an additional E1/E2 acceptance requirement in the original plan**. It may be useful when a genuine failure must be reproduced, but does not replace missing L2 evidence.

### B2 parser and B5 selector

`src/myfuzz/composition/ip_test_levels.py` already implements `RuntimeCapabilitySnapshot`, `VerifiedCapabilitySnapshot`, `assess_ip_test_level()` and `IPTestLevelAssessment.require_minimum()`. Exact `Register.Field` scopes separate L2 operations from generic bus read/write; both snapshots bind profile and sidecar fingerprints. These are delivered B2 contracts, not a missing parser. The actual register adapter calls `plan_register_operation()` and validates runtime context, but neither it nor `ibex_pulp_register_replay.py` constructs a production capability assessment or calls the minimum-level gate. A repository call-site search finds assessment consumption in `ip_semantic_capabilities.py`, not the new register production path. Executable programs therefore do not yet become effective scoped L2 claims, tested behavior does not become verified scoped claims, and the register CLI has no authenticated requested-minimum-level option or gap report.

B5 remains the separate generic harness contract: v2 APB3/TL-UL/Wishbone executor selection follows protocol/schema, preserving old explicit specialized modes. The new `register_program_assembly.v1` selector fixes `ibex_pulp_ordinary_gpio`, enrolled sidecars, native observation, persistent-memory gate and checker=None. It is a trusted directed assembly selector, not the original plan's highest-effective-level selector for an arbitrary admitted IP. Future level selection should compose the existing executor result with B2 assessment and compiler-supported scoped operations. Do not replace B5 protocol selection with peripheral-name classification or promote all 72 declarations automatically.

### E1/E2 behavior and evidence still needed

The GPIO sidecar describes 14 registers/72 fields, including source references, access/masks/reset values and effect labels. Declaration coverage does not verify every field's behavior. `register_program.py` supports full-word ordinary accesses and explicit 36-byte narrow RMW only for complete readable/writable side-effect-free words. Read-clear/pop and unsupported effects remain refused. `INTSTATUS` conditional-read-clear is a source declaration, not an enabled read oracle; FIFO semantics are not part of this GPIO runtime. Conservative refusal should remain a reported gap, consistent with E1's requirement not to enable unverified rules.

The current gate proves actual CPU execution, preservation of other bits in eight selected RMW cases, APB evidence and two full-word reads stored through actual RAM commits. Earlier DIR/OUT/SET/CLR gates remain evidence for their own frozen source identities. No current production verifier joins every requested field operation to actual transaction/base-event references and semantic rules. The current schema 16 gate is not a reset-value test and does not exercise every declared permission/mask boundary or conditional-read-clear behavior. Original E1/E2 requires reset/access-width/mask/permission coverage and observable supported semantics; it does not require guessed write/read equality for undeclared effects.

Existing `ip_semantic_evidence.py` already provides bounded per-operation reports, derived `ip_register_event.v1` projections and `bind_capabilities()`/`capability_snapshot()`. `ip_semantic_capabilities.py` binds code-owned provider rules to precise effective operations and certificate references. These D4 software APIs are reusable, rather than missing event schemas. The frozen ordinary assembly has `gpio_consumption=false` and its factory does not install this semantic capability binding. RAM commit authority proves result storage, not a GPIO register version or side effect. Production wiring must preserve that distinction: SET/CLR cannot acquire direct-write certificates, and APB responses cannot imply functional completion.

### Next executable work within the authorized plan

1. Production capability preflight is now delivered: [implementation and actual-gate report](stage2-e2-register-capability-preflight-20261012.md). The capability-enabled actual file CLI gate passed10cases/22339events with matching startup/saved/fresh reports and honest aggregate L1; independent artifact audit passed (46pins/40production/9artifacts). The implemented scope was to add opt-in production capability preflight around the actual adapter. Derive protocol/endpoint and exact field-operation support from validated artifacts, actual router/gate and compiler policy. Feed `RuntimeCapabilitySnapshot` into `assess_ip_test_level()`, persist an identity-bound assessment/requested minimum, call `require_minimum()` before begin, and compare it in fresh replay. Report unsupported narrow reads/effects; preserve default legacy layout and B5 generic selection.
2. Connect a code-owned register verifier to actual transaction identities, raw APB/base references and declared semantics. Reuse D4 interfaces where native certificate rules genuinely apply; add ordinary-access rules only where observations support them. Emit partial scoped `VerifiedCapabilitySnapshot` results, never from saved compiler bytes or caller references. Negative tests should cover stale fingerprints/epochs, foreign transaction references, absent observations, unsupported effects, generic read/write promotion and minimum-level refusal before commands.
3. Exercise original E1/E2 behavior through the delivered CPU request/file-replay path: observable reset values, permission/mask/width boundaries, stable ordinary registers and supported effects. Observe actual post-reset state instead of treating profile defaults as a host oracle. Keep CPU and any later BFM results separate. Reuse current gate evidence only within its proven scope; add cases for remaining rules rather than rerunning unrelated gates.
4. Publish declared/effective/verified operation matrices and concrete gaps for this composition; then decide whether B2's existing aggregate L2 minimum is met. RFuzz declarative-register generation, other CPU/ISA support, anonymous-IP L2 selection and feature-family L3 work are separate downstream integrations. This directed Ibex/GPIO CLI does not prove them. Full E1/E2 and M2 remain open pending original behavior/level requirements, without an artificial schema 17 fault prerequisite.

### Parallel preflight interface review

2026-10-12: the renderer subagent independently checked the existing APIs after the file CLI audit. The next bounded implementation should add a production capability consumer, reusing `RuntimeCapabilitySnapshot.from_mapping()`, `assess_ip_test_level()`, `require_minimum()` and assessment `to_document()`. Suggested ownership is a new `scenario/register_program_capabilities.py`, a trusted adapter preflight interface, opt-in Session persistence/recomputation, and authenticated integration/CLI minimum-level options. Static preflight must inspect validated actual objects without calling `prepare()`, inventing a waiting transaction, materializing RAM, or changing reservations/counters/command epochs.

The existing aggregate rule requires all declared rows at a level to be effective. Retain the complete 72-field sidecar: unsupported narrow reads and conditional read-clear leave explicit gaps, so partial register support cannot silently satisfy aggregate minimum L2. Minimum L2/L3 refusals must occur before commands. Keep verification absent in this preflight step; replay agreement, program hashes and RAM commit references do not create register verification certificates.

Focused regressions should cover actual profile/sidecar/binding/router/gate drift, unsupported scopes/effects, insufficient 36-byte RMW capacity, permission gaps, unchanged per-request side-effect consent, saved assessments rehashed consistently but differing from fresh computation, malformed minimum/configuration types, zero preflight mutations and default-layout compatibility.

The independent reviewer also identified an instance-binding requirement: B2 snapshots bind component/profile/sidecar, while `gpio_a` and `gpio_b` share those fingerprints. The production wrapper must additionally bind each snapshot to its actual target instance, artifact, router and gate. Reusing one instance's snapshot or transaction evidence for the other must refuse. Saved verified references must never be reconstructed as trusted verifier input; consistently rehashed assessment/minimum changes still require fresh closed configuration and assessment comparison. SET/CLR observations cannot certify PADOUT direct-write behavior.

### 2026-10-12 capability preflight production wiring — in progress

The previous goal turn made concrete progress: authenticated schema16 file replay and independent artifact audit passed, and the execution documents were reconciled. Continue the original Stage2 scope; E1/E2 and the full plan remain open.

This turn runs three authorized parallel tasks with separate file ownership: renderer implements actual-adapter capability derivation and its TDD regressions; runner wires opt-in Session/assembly/file replay/CLI with closed persisted assessments; independent reviewer checks aggregate-level, instance-binding, saved-authority and consent boundaries. Root integrates evidence and maintains this ledger. No RTL gate has been started for this increment.

Default-off identity layouts must remain compatible. Enabled preflight retains the complete sidecar and reports unsupported operations, uses B2 runtime snapshots with verification absent, binds actual target instances and configuration, and refuses unmet requested minimum before commands. Fresh replay recomputes assessment; persisted evidence is never restored as permission. The earlier successful file gate remains evidence for its frozen source version, not for these in-progress changes.

2026-10-12 supplemental pure-software matrix check (64-byte program budget, two actual rendered GPIO instances; no begin/RTL): each complete sidecar yields 148 declared rows, 78 effective rows and zero verified rows. The 75 compiler-supported register conditions comprise five reads, four ordinary writes, two writes requiring explicit effect consent and 64 explicit RMW writes. Sixty-five register read rows remain unavailable (64 narrow fields and conditional read-clear); generic transport read/write/wait/error and pins sampling are also reported as gaps. Aggregate effective level is L1; this is a runtime preflight result, not a behavioral certificate.

### Next production verifier boundary (parallel read-only review)

The existing `gpio_register_version.v1` provider requires authenticated internal probes, continuous edges and routed target receipts carrying transaction, command scope and access IDs. The ordinary assembly does not install those probes/receipts, and the existing rule does not cover PADCFG. Keep its strict admission unchanged. The present gate checks raw APB setup/access/response by direction, address and value; APB base events have a null transaction key. That grouping does not create a source-transaction-to-target-span certificate.

The next implementation should first emit code-owned ordinary target execution receipts joining the actual CPU TransactionKey and router target/window to unique request/accept/response raw/base references, access/command identity, target epoch and memory generation. Missing, repeated, conflicting or cross-epoch spans must refuse verification. Reuse D4 coordination/binding APIs only with a provider whose certificate describes this observable access/readback scope, not internal register storage versions.

Initial operation rules should distinguish observed full-word READ, ordinary WRITE followed by actual CPU READBACK with no intervening reset/write, and explicit RMW plus later CPU READBACK confirming final mask/preserved bits. Existing RMW cases read before writing; a single case does not certify its write's final storage state. Add CPU readback cases for PADCFG/INTTYPE and actual reset confirmation/new-epoch reads. Compiler identity and RAM result commits remain separate evidence. SET/CLR require separate alias-effect rules and actual PADOUT readback, never direct-write certificates; conditional INTSTATUS read-clear remains refused until its trigger/race conditions have real observation evidence. Partial verified scopes cannot bypass the complete sidecar's aggregate L2 rule.

### Ordinary access receipt 第一实现包（2026-10-12，执行中）

三方源码调查已完成并形成 [目标端设计](stage2-e2-ordinary-access-renderer-design-20261012.md)、[Runner 接线设计](stage2-e2-ordinary-access-runner-design-20261012.md)、[独立边界审查](stage2-e2-ordinary-access-review-design-20261012.md)。Root 当前版本伴随回归：capabilities／boundaries／capability replay／native APB runner 四模块 44 passed（97.26 秒，handle 7518 exit0），尚无新生产代码或 RTL 证据。

实施顺序保持原 E2 目标：先目标 Session 实际命令 receipt 与 Router 真实身份交接，再 Runner raw/base journal 唯一绑定、Session/assembly opt-in 身份与 fresh 重建，最后 code-owned 分操作 verifier 和实际 readback/reset 等行为门禁。第一包由 renderer 子代理实现独立默认关闭的目标 API 与有限 receipt helper；runner 子代理仅改 Router 及软件测试；reviewer 独立审查并补拒绝测试。所有权分开，不覆盖原工作区变更；不提交或运行重 RTL。

接口约定：`configure_ordinary_apb_access_receipts()` 在 begin 前显式开启；`ordinary_apb_access_receipts_enabled` 与旧 causal flag 独立；`execute_observed_register_access(key, delivery_context=...)` 只接受实际 Router 所构造的上下文，返回实际 rdata/access ID/target receipt；callback 失败由 `ordinary_apb_delivery_failed(key, access_id)` 记录目标执行与 CPU 确认交付之间的缺口。原 causal dispatch 优先，默认关闭布局兼容。actual parsed command execution/sequence/epoch/tick span 才能标注本命令 samples；saved JSON/raw refs 不能注册为 authority。

本包尚不完成 Runner 的 raw/base 引用绑定或生产 file replay selector，不能声称寄存器行为 verified 或 aggregate L2。后续必须继续原计划，不以目标 receipt 这一中间结果替代 E1/E2 完整验收。

第一包最终软件验证完成：[实现报告](stage2-e2-ordinary-access-receipts-20261012.md)。根handle98275 exit0，十模块166passed／34subtests128.51秒；source pins复核一致。独立19项及容量／身份2项通过，无剩余P1/P2。本包target／Router接口已冻结；下一包实施有界Runner journal association，再生产Session/assembly opt-in及fresh原请求重建。没有新RTL或行为证书，原阶段验收保持打开。


Runner association 后续包正在联合验证，见[当前报告](stage2-e2-ordinary-access-association-20261012.md)。真实 callback closure 来源负例已 RED；修复前不能声称 CPU delivery confirmed。此包不改变后续 Session/assembly/fresh 接线与行为 verifier 的原计划要求。

Runner association 软件包现已实现并独立复核，见[最终报告](stage2-e2-ordinary-access-association-20261012.md)。来源 closure、解码漂移、missing delivery 和容量边界已闭合；软件最终覆盖212个不重复项／34子测试（联合旧fixture失败及最终Runner10项补验证分开记录）。继续 Session/assembly opt-in 配置与闭包、fresh重建，再真实readback/reset行为verifier；原E2尚未完成。
