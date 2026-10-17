# CVW AHB manager-domain observation correction — implementation report

Status: **source-only software correction**. No DUT build, elaboration, model, remote operation or native gate is claimed by this report or by the committed result. The preserved attempt1 receipt remains the only native evidence and it is still a **failed startup attempt**.

Commits:

- `87bef94` — `fix: correct CVW AHB manager-domain observation (contract core)`
- `782b091` — `fix: correct CVW AHB manager-domain observation (negatives and identity)`
  (full `782b091a8f267677e33db2b6d7b6f08a954a767c`)

## 1. Failure and physical boundary

The exact saved attempt1 receipt (SHA256 `2707e1dd…9849`, 16 measured startup edges) was replayed in software. The old interpretation treats the thirteen-role trace's `hready` = `HREADYEXT` as manager acceptance. On edge 11 the measured POST address advances from `0xc0000000/htrans2` to `0xc0000004/htrans3` while `HREADYEXT` PRE is 0, so the old hold check rejects a legal measured progression with `ahb_address_hold`. That is the preserved RED, not a DUT violation.

Measured PRE physical facts used by the correction (root-independent audit, confirmed here):

| signal | edges |
| --- | --- |
| actual `bus_reset_n` (`HRESETn`, `rt_lh_p_8_0_0`) | 1,1,0,0,0,0,0,0,0,0,1,1,1,1,1,1 |
| actual `manager_ready` (`HREADY`, `rt_lh_p_6_0_0`) | 0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0 |
| external `hready` (`HREADYEXT`) | 0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0 |

Consequences implemented: the first actual assertion is PRE edge 3, the observed release is PRE edge 11, the only legal acceptance is edge 11 (`bus_reset_n=1`, `manager_ready=1`, `hsel=1`, `htrans=2`) at `0xc0000000`; external ready is 0 at that acceptance, so the pending phase cannot complete. Edge 12 presents the next address while `manager_ready=0`; it changes from the accepted address but is stable PRE→POST and across the remaining low-ready edges, so it is not an `address_hold` violation.

## 2. RED/GREEN evidence (saved bytes, software only)

The saved receipt bytes are never modified or re-signed. `project_saved_manager_domain` makes a deep copy, adds only the current profile's declared domain binding to metadata, and labels it:

```
provenance = saved_native_artifact_software_projection
source_artifact_digest = old attempt1 artifact_digest
source_profile_sha256  = c60ddb29… (pinned old profile in the native artifact)
domain_profile_sha256  = a04865cd… (current profile bytes)
```

No sample, receipt, reset metadata or raw row is edited; the projection test asserts this.

Commands and current results:

```
$ PYTHONPATH=src python3 -m pytest tests/scenario/test_ahb_manager_domain.py::test_historical_external_ready_interpretation_reproduces_failure -q
1 passed   # explicit old interpretation still raises ahb_address_hold, 11 raw edges

$ PYTHONPATH=src python3 -m pytest tests/scenario/test_ahb_manager_domain.py -q
36 passed
```

The GREEN saved replay (`test_saved_all_sixteen_edges_use_measured_manager_and_bus_reset`) asserts:

- 16 retained `ahb_raw` edges with the unchanged `raw_sample` and a separate `measured_domain`;
- exactly one `ahb_address` at local tick 11 / `0xc0000000`, `acceptance_ready=manager_ready`, `external_ready_at_accept=0`;
- pending address `0xc0000000`, `completed=0`, `accepted=1`, `reads=1`;
- `ahb_bus_reset` assertion at tick 3 and release at tick 11 (PRE only);
- `measured_reset_to_command_prefix is False` after `finish_startup`;
- every event `authority=observation_only`.

Baseline before the fix (captured in `cvw-manager-domain-red.txt`): the same saved bytes without domain rows failed at `ahb_address_hold` in the new-domain test, because the observer still used `HREADYEXT` as manager ready. The RED control now expresses that substitution explicitly (`manager_ready=hready`, nominal bus-reset release at edge 3) so the historical failure remains reproducible without any silent fallback in production code.

## 3. Declaration, binding and runtime contract

Profile (`configs/cpus/cvw/component_profile.json`):

- one non-protocol endpoint `cpu.manager_domain`, `function: observation`, clock `core`, reset `sys_rst`;
- exactly two one-bit output roles: `manager_ready` → `HREADY`, `bus_reset_n` → `HRESETn`;
- `HREADY`/`HRESETn` `port_actions` removed (they were the conflicting owners); `HCLK` remains `observe`;
- the thirteen `cpu.external_bus` roles are unchanged, including `hready=HREADYEXT`.

Runtime document:

- `manager_domain` versioned contract (`ahb_manager_domain_contract.v1`) with endpoint/function, protocol endpoint, declared profile endpoint fields (single alias each), exact role width/direction/physical/wrapper/runtime/source-wire facts, clock provenance (`core`, `clk`), external reset command provenance (`sys_rst`, `reset_ext`, `active_high`, asynchronous), actual bus-reset role semantics (`bus_reset_n`, `active_low`, PRE, actual DUT output, `synchronizer_latency=not_claimed`), sampling rules and explicit scope:
  - response/data validation only for an owned external selected data phase;
  - other-slave context `unvalidated`;
  - aggregate HRESP/HRDATA `exported=false`.
- `physical_exports` for `HREADY`/`HRESETn` now naturally carry `endpoint_id=cpu.manager_domain`, `role=manager_ready|bus_reset_n`; `HCLK` stays observe-only with `endpoint_id/role = null`.
- `bind_ahb_trace` authenticates the external thirteen-role trace and the domain contract against: plan port facts, structural ABI, physical exports, protocol taps, clock schedule and the declared reset provenance. It rejects:
  - missing/extra/duplicated/swapped roles;
  - wrong width/direction/source wire/runtime name;
  - protocol-tap aliases (including any `HREADYEXT` fallback for `manager_ready`);
  - reset proxy/inversion substitutions;
  - mismatched clock/reset provenance;
  - projection metadata inconsistencies.
- Observer contract version is **3** and carries `domain_contract` + `sampling_domain`; identity reconstruction re-renders from the pinned profile and strict-compares the contract, so a v2 identity, a missing domain contract, or a substituted domain is refused.
- Transport capture/page ABI is unchanged: `local_driver_generation.ahb_startup.v2`, `cpu_ahb_startup_capture.v1`; generated runtime SV/driver command bytes are unaffected. Byte changes are limited to profile/document metadata: profile pin `c60ddb29…` → `a04865cd…`, artifact document (new `manager_domain`, ABI/physical-export role facts, plan rows) and observer identity.

`src/myfuzz/local_harness/cvw_contract.py` pins the new profile SHA. `scripts/verify_cvw_ahb_startup.py` `project_rows`/`replay_actual_prefix` now carry explicit domain rows; its saved software replay still reproduces the observer (gate control passes). Any existing source-freeze receipt is invalid by construction and cannot be reused.

## 4. Observer semantics

- Only PRE is a measured phase.
- Startup before the first actually measured bus-reset assertion is raw/unknown (`ahb_domain_unknown` once, no address/data/reset projection).
- A measured `bus_reset_n=0` cancels pending/stall state and emits `ahb_bus_reset(asserted=True)`; no address is accepted while asserted.
- A measured `bus_reset_n=1` after an assertion establishes the bus-domain prefix and may accept an address on that same release edge.
- `finish_startup` fails closed (`ahb_bus_reset_prefix_unmeasured`) when no actual assertion→release was observed; raw edges remain.
- Acceptance uses measured `manager_ready`; completion requires measured `manager_ready` **and** external ready for the owned external selected data phase. `manager_ready=1` with external ready 0 and a pending external phase fails `ahb_external_completion`.
- Address hold is based on measured `manager_ready` continuity: an offer presented while not ready must remain stable PRE→POST and across consecutive not-ready edges. It is not compared for equality with an already accepted address, so the saved edge12 progression is legal while a true global stall with a changed address is still rejected.
- No aggregate HRESP/HRDATA is invented; non-`hsel` address context emits `ahb_unvalidated`.
- `measured_reset_to_command_prefix` becomes true only on the first command edge after the observed startup assertion→release.
- No synchronizer latency is inferred from external reset scheduling.

## 5. Negative controls added

`tests/scenario/test_ahb_manager_domain.py` (36 tests total) now covers:

- missing contract; absent/duplicated/swapped roles; duplicate runtime wire; wrong width/direction/physical port/source wire; profile-endpoint clock/reset substitution;
- structural ABI role substitution, physical-export endpoint substitution, plan endpoint removal, duplicate ABI row;
- clock provenance, external-reset proxy, bus-reset polarity, sampling fallback to external ready, aggregate-HRESP scope claim, authority change, external-ready-role change;
- projection digest/source substitution and refusal of the unprojected old artifact;
- missing actual reset assertion (16 raw retained, prefix false, finish fails);
- tampered measured reset value (raw retained, `ahb_domain_row`);
- true global stall with an owned external phase and changed address (`address_hold`);
- inconsistent external/global completion (`external_completion`, trusted failure);
- constructor/identity domain substitution (v2, missing, software contract, swapped role, trace-binding endpoint change);
- command budget exhaustion retains the offending raw edge, poisons, refuses the next edge, and Runner drains the same records once with global raw refs;
- new runtime document/export contract and external `HREADYEXT`/measured `HREADY` separation.

## 6. Regression results (pure software only)

```
$ PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_ahb_manager_domain.py \
  tests/local_harness/test_ahb_startup.py \
  tests/local_harness/test_ahb_cpu_contract.py \
  tests/local_harness/test_ahb_cpu_observer.py \
  tests/local_harness/test_ahb_lite_renderer_shape.py \
  tests/local_harness/test_cvw_ahb_gate.py \
  tests/scenario/test_contracts.py -q
160 passed, 2 subtests passed in 24.54s
```

`tests/integration/test_cvw_derived_config.py` (pure profile/derivation controls): **7 passed, 1 failed** — `test_the_derivation_changes_only_the_named_parameters` fails on the committed `ZCD_SUPPORTED = 0` line not being listed in `DERIVED_PARAMETERS`. `git show HEAD:configs/cpus/cvw/config_extmem/config.vh` and `git show HEAD:tests/integration/test_cvw_derived_config.py` prove this failure predates and is unrelated to this change; it was not altered.

Not admissible under the no-native boundary:

- `tests/local_harness/test_ahb_lite_session.py`: its `_artifact()` helper calls `verify_local_source_lock` without a frontend monkeypatch, so even the five constructor/helper tests I selected as a "pure subset" executed Verilator elaboration. That follow-up run passed 5 tests but is **not** evidence and will not be repeated; the whole file is excluded. An earlier pre-boundary full run (13 combined session/renderer tests) is likewise not evidence.
- `tests/integration/test_cvw_ahb_runtime_generation.py`: contains verilator-gated build/elaboration/traffic cases; only its pure rendering assertions would be admissible, and the module was not re-run after the boundary notice.
- `tests/integration -k cvw`: contains native/elaboration cases; not run.

## 7. Boundary incident (reported honestly)

Two mistakes were made and are disclosed rather than hidden:

1. Selecting the whole `tests/integration/test_cvw_ahb_runtime_generation.py` module caused its verilator-gated cases to run on this host (verilator is installed). It created `.superpowers/cache/cvw-ahb-elaboration/{wrapper,runtime}.sv`; those were deleted immediately and no process remained.
2. After the boundary notice, I selected five tests from `tests/local_harness/test_ahb_lite_session.py` believing they were pure constructor/helper controls. That file's `_artifact()` calls `verify_local_source_lock` without a frontend monkeypatch, so it ran Verilator elaboration too (72 s, 5 passed). I stopped after that run. No further build/elaboration/model/native case was executed.

Neither run's results are used as evidence here, and neither produced a retained build/elaboration cache: the generated `.superpowers/cache/cvw-ahb-elaboration` directory was deleted, no `.cvw-verify-*` directory newer than 2026-10-15 exists, no process remained, and no `.build-extra-header-*` path remained. The two old `.cvw-verify-*` directories in the checkout are dated 2026-10-15 and predate this work.

## 8. Open risks / boundaries

- This is **not** a native pass. The corrected profile/runtime document has not been elaborated or executed; the old attempt1 receipt binds the old profile and is replayed only as saved-data software projection.
- `HREADY`/`HRESETn` are observed physical outputs of the typed CVW top; no new tap or adapter was added. Whether a future native run observes the same values is not established here.
- Aggregate HRESP/HRDATA remain unexported; only the owned external selected data phase is validated. Other-slave response semantics are explicitly unvalidated.
- No bus-reset synchronizer latency is claimed or modeled.
- `scripts/verify_cvw_ahb_startup.py` has not been re-run natively; its strict `replay_actual_prefix` requires a command prefix and a document already carrying `manager_domain`. A saved attempt1 receipt without a command prefix must use `project_saved_manager_domain` explicitly and cannot pass `replay_actual_prefix`.
- Gate identity tests that hash the host source closure can transiently fail while other agents edit shared host sources (`build._discover_host_sources` covers `session`, `contracts`, integration modules). Nothing in this change weakens that check; concurrent-writer flakes were observed and re-ran clean.
- Profile pin update and source-freeze invalidation are deliberate byte changes required by the new endpoint; no existing native receipt was re-signed or reused.

## 9. Files changed by this work

- `configs/cpus/cvw/component_profile.json`
- `src/myfuzz/local_harness/ahb_manager_domain.py` (new)
- `src/myfuzz/local_harness/ahb_startup.py`
- `src/myfuzz/local_harness/ahb_lite_session.py`
- `src/myfuzz/local_harness/runtime_renderer.py`
- `src/myfuzz/local_harness/cvw_contract.py`
- `src/myfuzz/scenario/ahb_cpu_events.py`
- `scripts/verify_cvw_ahb_startup.py`
- `tests/scenario/test_ahb_manager_domain.py`
- `tests/local_harness/test_ahb_startup.py`
- `tests/local_harness/test_ahb_cpu_contract.py`
- `tests/local_harness/test_ahb_cpu_observer.py`
- `tests/local_harness/ahb_domain_support.py` (new test helper)

No `third_party/` submodule, existing `docs/` report, or another agent's file was modified.
