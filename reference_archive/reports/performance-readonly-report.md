# Read-only performance assessment: Timer and SPI storage search

This assessment reads existing source and the completed original evidence in `research/input-strategy-audit-20261027/runs/config-driven-20261028/{timer-ibex,spi-cv32e40p}/original`. It does not modify production code, rerun tests, execute native simulation, or claim an optimization benefit. The observations below concern one three-case run per configuration, with 32 advances per case; they are not repeated benchmark estimates.

## Measurements already recorded

Times in seconds. “Case record window” is `campaign.json` case `finished_at_seconds - started_at_seconds`, rather than the complete `engine.submit` call. That window starts after the engine's first admission/identity check and ends before its post-identity check. “Execution cost” is the wider `state-transitions.json` execution_cost_ns interval beginning before the native loop's state query. Consequently the difference includes state queries and checks outside the case record window and cannot be assigned to one function.

| Configuration | Case / flow | Execution cost | Case record window | Wider-interval remainder | Action-finalization increment | Policy choose |
|---|---:|---:|---:|---:|---:|---:|
| Timer / Ibex | 0 / F4 | 26.818150 | 25.376637 | 1.441513 | 0.000335 | 0.000144 |
| Timer / Ibex | 1 / F4 | 26.700335 | 25.269256 | 1.431079 | 0.000621 | 0.000143 |
| Timer / Ibex | 2 / F2 | 26.201426 | 24.773252 | 1.428174 | 0.000685 | 0.000128 |
| SPI / CV32E40P | 0 / F4 | 31.937781 | 30.370445 | 1.567336 | 0.000883 | 0.000161 |
| SPI / CV32E40P | 1 / F4 | 31.891000 | 30.326147 | 1.564853 | 0.000540 | 0.000131 |
| SPI / CV32E40P | 2 / F2 | 31.307000 | 29.757772 | 1.549228 | 0.000647 | 0.000127 |

Timer's accumulated execution cost is 79.719911 s; 75.419145 s (94.61%) is inside its case record windows. SPI's corresponding values are 95.135781 s and 90.454364 s (95.08%). Policy choice totals only 0.000415 s and 0.000418 s. The recorded action-finalization increments total 0.001641 s and 0.002070 s; they include credit settlement and major per-action journal/JSON persistence, not all terminal exports. These measurements give little reason to prioritize policy selection or three-case decision persistence for the current 26–32 s latency.

Completed summary wall/search times are Timer 217.201582 / 79.721742 s and SPI 240.882943 / 95.138006 s. The remaining 137.479840 / 145.744936 s include preparation, build/init, finalization and complete within-invocation replay. Existing summaries report build_seconds and init_seconds as null; the remainder must not be presented as measured build time or measured replay time.

Both campaign documents report one build/start/begin/init lifecycle. The per-case latency is therefore not evidence that each case reconstructs or restarts the persistent runtime.

## Highest-priority hypothesis: repeated toolchain and materialized-build authentication

The strongest static candidate is not the scheduler. Each APB target command enters `StorageRegisterVersionAuthority._actual_begin` and `_actual_complete`; both invoke `_validate(native=True)` (`apb_storage_register_version.py:378,454`). That path reaches `session._native_reset_native_eligible` (`session.py:912`), which:

1. hashes the running harness binary;
2. calls `local_build_identity`, hence `build._prepare`;
3. calls `_validate_cache`, which hashes the binary again and rereads/hashes every materialized build input.

The ordinary prepared-artifact cache does not make its successful check cheap. `build._prepared_if_current` rereads the host-source closure, compares snapshots, and calls `_toolchain()` (`build.py:324`). `_toolchain` runs four `--version` subprocesses plus `verilator -V` on every call, hashes tool executables and Verilator's backend, and traverses/hashes its include tree (`build.py:95-124`).

The saved plan contains 32 target advances in each case. Thus the begin/complete structure alone implies at least 64 native-build validation entries for those target commands per case, before additional routed accesses and state-token issuance/consumption. If those entries follow the ordinary prepared-cache path, they imply at least 320 tool-version subprocess invocations per case. This is a source-derived call-multiplicity hypothesis, not an observed call count or measured timing attribution. The next profiling pass should count and time `_toolchain`, `_prepared_if_current`, `_native_reset_native_eligible` and `_validate_cache`, including bytes read and subprocess counts.

CLI already wraps descriptor execution in `host_source_discovery_scope(reuse_nested=True)`. That reuses AST discovery but deliberately rereads source bytes/probes on every use. Repeated AST discovery therefore must not be assumed to explain all these runs. An optional `harness_validation_scope` exists, but the inspected CLI does not enter it; it relies on size/mtime stamps and should not simply be enabled as a performance fix without reviewing its weaker change-detection boundary.

## Other candidates and measurement priority

| Priority | Candidate and evidence | Next measurement; acceptance constraint |
|---|---|---|
| P0 | Toolchain/binary/materialized-input authentication repeated at APB command begin and completion, described above. | Count calls and inclusive wall time, then split tool subprocess time from file reads/hash and canonicalization. Any reuse design must retain actual executable/build/source drift refusal; skipping authority checks is not a valid measurement baseline. |
| P1 | `CompiledF4Runtime._stable` runs twice for each ordinary F4/F2 case. It recomputes two input identities, recompiles paths, re-admits F4, hashes the entire Python implementation closure, rebuilds execution bindings, and also re-admits/rebuilds F2 in mixed mode (`compiled_f4.py:1233-1317`). | Time `_stable` as a whole, then `_admit_f4`, `_admit_f2`, `_closure`, `_input_identity`, built-receipt validation and binding construction. This separates a fixed per-case guard cost from repeated per-command cost. Preserve both flow contracts and current source validation. |
| P1 | Engine calls `bound_plan.assert_current` before lowering and again before the raw record. Binding rechecks preparation source pins, generated directory contents, adapters and plan identity (`engine.py:314-350`, `binding.py:402`, `preparation.py:419`). | Time both boundary calls separately, report repeated file counts/bytes and adapter guards. The 1.43–1.57 s wider-interval remainder is compatible with such work but is not its direct measurement. |
| P1 | Live `read_current` calls real authority issue/consume before and after each action. Their native validation can reach the same build-authentication chain (`storage.py:35`, `apb_storage_register_version.py:554,592`). | Time each read_current call and count its nested authentication calls; keep live queries at their actual decision/feedback boundary. Do not replace state with saved postconditions. |
| P2 | Runner executes the declared 32 advances through scalar `step`/`execute_step` calls; `step_batch` still loops scalar steps (`runner.py:1445-1483`). Native command parsing, reset/provenance guards, APB routing and checker work occur around each step. | Use inclusive runner/scheduler timers plus a distinct wire-only interval, separate from host guard work. Keep exact component order, command ledger, intermediate observations and uncertain-effect behavior. Reducing rounds or batching away observable intermediate steps changes the executed workload. |
| P2 | SPI records 4,061 events versus Timer's 785, including 3,276 extra `port_sample` events. The saved `events.json` sizes are about 5.26 MB versus 1.52 MB. Both have 234 local_tick_sample and 288 state_dependency events. | Profile per-step event projection/provenance, copies and checker work. The configurations also use different CPUs/targets/source closures, so the roughly five-second per-case difference cannot be attributed to event volume alone. |
| P2 | Full within-invocation fresh replay and final evidence export occur after the measured search loop. Prefix files are about 1.24–1.26 MB, campaigns about 187–189 KB. | Measure preparation/build, init, original search, finish/export, complete replay, archive and cleanup as separate non-overlapping phases. Keep complete replay and its identity/source checks in the acceptance run. |
| P3 for these runs | `persist_action_cost` rewrites the accumulated selected-cases/state JSON each action, so total serialized bytes can grow quadratically with case count. | At three cases its measured increment is below 3 ms total; investigate only after command/guard work or for substantially larger budgets. Current evidence does not support blaming prefix persistence for 26–32 s per case. |

## Profiling boundary cautions

Existing `observe_runtime_timings`/`timed_runtime_call` hooks can attribute inclusive runner/scheduler time. Inclusive nested spans must not be summed as independent cost. `observe_local_command_timings` begins inside `GeneratedLocalSession.command` after its initial `_check_built_mode` and owner guard; it includes `_command_impl` and target authority begin/complete, but omits the initial guards. Calling it “RTL time” would be incorrect.

A useful future single instrumented acceptance run should retain the same source/profile/catalog, seed, cases, rounds and full replay, recording phase spans, target/CPU command counts, toolchain subprocess counts, source/cache bytes read, and true wire wait separately. No profiling run or source alteration was performed for this report, and no speedup magnitude is claimed.
