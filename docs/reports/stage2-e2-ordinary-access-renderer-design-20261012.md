# E2 ordinary native APB execution receipt: implementation design

Date: 2026-10-12. The capability baseline gate completed; this next increment is now in implementation. This note records the preceding read-only design inspection. This specifies the next implementation within original E2, not capability certification or a new approval requirement. No RTL was run for this design.

## Current production path and missing identity

The ordinary PULP GPIO factory installs `GeneratedGpioSession` with `gpio_consumption=false`. `routed_register_access_enabled` in `local_harness/gpio_session.py` means the separate internal-probe observation contract, not ordinary native APB trace availability. Do not enable that property or call its existing `routed_register_access()` merely to get transaction identity.

`DataflowRouter._access()` in `scenario/router.py` receives the actual `TransactionKey`, actual `DeviceWindow` and prepared request. It currently calls ordinary `write_register()`/`read_register()` without passing this identity. The queue is executed by `drain_one()` through `ledger.complete_accepted()`, which caches actual target effects; its delivery record preserves source key, target order, address, offset, direction, byte enable and value. A callback failure after actual target execution must not permit a second target execution.

Ordinary `GeneratedGpioSession.write_register()`/`read_register()` issue `ACCESS_GPIO`, then `_take()` queues detached pre/post samples. Generic `GeneratedApb3RegisterSession._access()` similarly issues `ACCESS_APB3_REG`; `_take()` keeps the measured backend/physical samples. Both lose the parsed command identity when putting samples into the public pending queue.

`GeneratedLocalSession._command_impl()` in `local_harness/session.py` already validates an actual `DriverReceipt` against the current execution nonce, command sequence, process tick and artifact schedule. Only then does it update `_sequence` and `local_ticks`. This parsed receipt is the trusted binding point; no new renderer tap or driver command is needed for the initial design. Confirm payload/sample bounds independently for each implemented session kind.

`ScenarioRunner._drain_tick_samples()` assigns journal IDs to each actual pre/post sample and passes them into base/protocol normalizers. APB base events retain raw references but correctly have `transaction_key=null`, since APB carries no transaction ID. Keep that base fact unchanged. A separate execution association can connect the host's actual routed command to its sampled protocol span without claiming an APB wire ID.

The queued route path calls `_append_external_events(source_component, event_id)` before `_drain_tick_samples(event_id)` in the `finally` following `router.drain_one()`. Thus the complete association must finalize after raw/base IDs exist; it cannot invent future journal IDs in the session or router. Samples from an ordinary local STEP, setup/probe access or another target cannot be associated by nearby time, equal address/value, or shared `producer_event_id`.

## Minimal opt-in interfaces

Introduce a separate ordinary capability flag, e.g. `ordinary_apb_access_receipts_enabled`, derived from the actual validated native `base_protocol_trace` and the implemented session command kind. It must be independent of `routed_register_access_enabled`, which retains its existing causal-probe meaning. Default old sessions keep their current path/layout.

Add `execute_observed_register_access(key, *, delivery_context)` on the implemented ordinary native GPIO and generic APB3 sessions. The exact context includes target instance/endpoint, window base/size, absolute address, offset, direction, normalized 32-bit value and full-word byte enable. The caller is the installed actual router; recheck the key/request/window against the actual target and reject nested active access. No caller callback, saved receipt or arbitrary mapping selects execution.

The method issues the existing ACCESS command exactly once. Capture a detached execution receipt only after parsing the real reply. Bind:

- target instance and unique actual endpoint, target reset epoch;
- parsed driver execution scope, command sequence, command kind and before/after lifetime ticks;
- actual CPU `TransactionKey`, requested absolute address and offset, direction/value/byte enable;
- returned rdata/error and the exact command-local pre/post sample coordinates;
- native trace/configuration identity and receipt status.

Use a version such as `ordinary_apb_target_receipt.v1`. Stable replay scope replaces the random process nonce only in the normalized journal copy, as the existing source transport normalization does. Preserve raw driver receipt identity in the session; never replace the actual parsed nonce before authentication.

Annotate only samples produced by this exact command with a detached finite `target_access_ref` (target, epoch, stable command scope/access ID). STEP and unbound setup/probe samples carry no source transaction association. Capacity preflight must cover both pending samples and pending receipt records before issuing ACCESS. No overflow after actual effect may be described as a clean refusal.

Router dispatch should keep the old causal branch first; enable the new ordinary branch only for the separately admitted ordinary mode, never for an artifact with the causal observation contract. Treat either supported contextual mode as requiring callback-confirmed delivery publication, while preserving their distinct receipt schemas. Its result returns `rdata`, `error`, access ID and parsed receipt reference. Copy this access ID into actual `mmio_delivery`; do not grant delivery success before the real source callback succeeds. If execution occurred but callback fails, record terminal uncertainty and retain the real target receipt; ledger caching prohibits re-execution.

Runner owns the final `ordinary_apb_access_association.v1`. While draining the exact tagged samples, collect their assigned raw IDs and actual base request/accept/response IDs, checking component/endpoint/epoch/tick/phase and command span. Finalize after all command samples are drained. Require one matching setup and completion boundary, measured signal/value agreement, no protocol error/violation and no unrelated access. Preserve explicit failure/incomplete status when evidence is missing. Keep APB base `transaction_key` null; association carries the CPU identity and proof scope `actual_routed_command_protocol_boundary_only`.

The association should link actual delivery ID when available and distinguish target execution from confirmed CPU response delivery. It grants neither register storage version, internal bit resource, CPU retirement, functional completion nor prerequisite authority. Later code-owned per-operation verification consumes this association and separate actual readback/reset evidence.

## Ownership and smallest implementation order

1. One agent owns a new finite data/validation helper, proposed `scenario/ordinary_apb_access.py`, plus `local_harness/gpio_session.py` and new session tests. Implement native ordinary GPIO first. A separate later agent can own `apb3_register_session.py` generic adoption; do not claim generic runtime support from the native-only first patch.
2. One agent owns `scenario/router.py` and new router tests: actual key/context handoff, result/access-ID propagation, ledger cached execution and callback-failure boundary. This depends on the helper/session API.
3. One agent owns `scenario/runner.py` and new Runner association tests: normalize command scopes, assign actual raw/base references, join delivery, bounded completion/failure handling. Existing raw/base event contents remain unchanged when disabled.
4. Root coordinates opt-in assembly/Session source closure and fresh replay identity tests after interfaces freeze. Existing compiler/runtime source admission stays unchanged. Software tests precede one serial actual CPU access/replay check through the production path.

No production changes to `runtime_renderer.py` or `driver_renderer.py` are initially needed: current native passive trace outputs and parsed ACCESS sample payload already provide the required measured signals. If inspection/tests reveal missing data, report that concrete gap before extending the renderer ABI.

## Required fail-closed checks

- Actual router key/window/target must agree; lookalike target, foreign key, overlapping route, wrong offset/address/value/byte-enable or unknown endpoint refuses before command.
- No internal GPIO observation contract, probe or consumption authority is required. Native ordinary and generic APB support must be tested separately.
- Parsed receipt sequence/execution/reset scope, contiguous samples and tick-before/after agree; mutable payload aliases, skipped/duplicated phases, foreign tag, conflicting reset or malformed samples cannot create a verified association.
- Equal address/value and adjacent time cannot join unrelated transactions. Multiple queued accesses, STEP/setup samples and two same-profile target instances retain separate identities.
- Missing setup/accept/response, wait timeout, protocol violation/error or capacity loss produces incomplete/uncertain association, never success by delivery alone.
- Callback failure, lost reply and parser failure preserve actual effect uncertainty; retries do not rerun the target. Cleanup does not synthesize success or erase half effects.
- Fresh replay rebuilds actual command associations from current execution; saved access IDs, spans and raw/base references are comparison data only. Native/protocol/source drift refuses before commands.
- With opt-in disabled, prior layouts and behavior remain unchanged. With opt-in enabled, base APB events still report their native identity gap; neither compiler hash nor RAM commit grants GPIO state semantics.
