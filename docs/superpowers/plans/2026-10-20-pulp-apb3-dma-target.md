# PULP APB3 DMA Target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development for bounded parallel review and task execution. Steps use checkbox syntax.

**Goal:** Route one declared ZipCPU `wbdmac` word from shared RAM to real PULP GPIO PADOUT through a keyed APB3 provider receipt.

**Architecture:** `GeneratedWishboneDmaSession` dispatches a declared peripheral beat through the versioned `dma_master_target_access` provider interface when the endpoint implements it. `GeneratedPulpGpioSession` adapts its existing `routed_register_access` and native probes into a closed common receipt. A separate prepared runtime-path builder binds the RAM read and PULP write routes to the live DMA, RAM, and target objects.

**Tech Stack:** Python, pytest, generated Verilator local harnesses, existing `RuntimePathContract` v2 and `MasterTargetWindow`.

## Global Constraints

- Follow `/home/qinkejiu/myfuzz/agent.md`; remote target files are only under `/root/fanzehui/**` and the jump host is connect-only.
- Keep this shared dirty worktree intact: do not reset, clean, stage, or commit unrelated existing work.
- Keep v1 route documents and the existing UART S4 path unchanged.
- A route declaration or compiler result is not runtime transfer proof.
- Keep provider execution transaction-level; do not describe it as a physical Wishbone/APB bridge or global cycle timing.
- Do not claim P7 F6, P6/P7/P8, all DMA providers, or all CPU profiles are complete.

## Files and responsibilities

- Modify `src/myfuzz/local_harness/wishbone_dma_session.py`: constant-time accepted-value validation and common target-provider dispatch/receipt checks.
- Modify `src/myfuzz/local_harness/gpio_session.py`: PULP PADOUT provider translating a keyed write to measured APB and GPIO effect evidence.
- Create `src/myfuzz/scenario/pulp_gpio_dma_paths.py`: prepared RAM-image → DMA-read → DMA-write → PULP-PADOUT graph and exact route declarations.
- Create `tests/local_harness/test_wishbone_dma_target_provider.py`: provider dispatch and receipt validation cases using actual core code with bounded endpoint fixtures.
- Create `tests/local_harness/test_pulp_gpio_dma_target.py`: APB request/response/effect positive case and fail-closed variants.
- Create `tests/scenario/test_pulp_gpio_dma_paths.py`: route graph, exact topology, and mutation cases.
- Create an opt-in real gate under `tests/integration/` using the existing pinned ZipCPU DMA and PULP GPIO harness artifacts; preserve all run evidence in an operation-local directory.
- Update `docs/CURRENT_PROGRESS.md`, `docs/reports/README.md`, and add a report only after the native/fresh gate actually runs.

## Closed provider API

The endpoint method is:

```python
dma_master_target_access(source_transaction, *, address, offset, write,
                         value, byte_enable, delivery_context) -> dict
```

The required result schema is `dma_master_target_access.v1` with `status='observed'`, exact `source_transaction`, exact `request={address, offset, write, value, byte_enable}`, `response={rdata, error}`, nonempty `target_access_id`, observed `target_access`, observed `target_request`, observed `target_response`, and a provider-defined `target_effect` whose source key/request agree. PULP emits the effect shape `pulp_gpio_padout_effect.v1` with register `PADOUT`, offset `12`, accepted value, post `gpio_probe_out` value, access ID, and local tick.

## Task 1 — Provider dispatch and bounded range validation

**Files:**

- Modify `src/myfuzz/local_harness/wishbone_dma_session.py`
- Create `tests/local_harness/test_wishbone_dma_target_provider.py`
- Preserve coverage in `tests/local_harness/test_opentitan_uart_master_target_access.py`

- [x] Add failing unit tests proving a declared write endpoint's `dma_master_target_access` receives the accepted Wishbone transaction key and exact request context.
- [x] Run the focused test and verify it fails before adding common dispatch and receipt validation.
- [x] Add strict validation for the closed common receipt: schema/status, exact key and request fields, 32-bit response, zero error for success, nonempty access ID, observed target request/access/response, and effect-key/request consistency. All four witnesses must share the same access ID.
- [x] Add failing tests for missing receipt, wrong key, altered address/value/byte enable, mismatched witness access IDs, non-observed APB phases, and nonzero error; verify every case fails before the response is accepted as success.
- [x] Replace the UART-only target event-length sampling in the common write path with provider dispatch when the endpoint implements the provider API; retain existing UART reads and legacy `write_register` behavior for existing declared endpoints.
- [x] Change `MasterTargetWindow` accepted-value validation to check tuple members and range bounds without iterating a range; support `range(0, 1 << 32)` and reject empty/out-of-word policies.
- [x] Run the focused provider, Wishbone, and OpenTitan UART target suites successfully.

## Task 2 — PULP GPIO provider

**Files:**

- Modify `src/myfuzz/local_harness/gpio_session.py`
- Create `tests/local_harness/test_pulp_gpio_dma_target.py`

- [x] Add tests with generated-session logic and bounded `DriverReceipt` fixtures for a valid keyed PADOUT APB write and missing/mismatched APB request, APB response, `PSLVERR`, offset, full-word byte enable, and post-PADOUT probe value.
- [x] Run focused tests before and after the provider implementation.
- [x] Implement `dma_master_target_access` for write-only offset `0x0c`, requiring the live GPIO observation contract and exact context; call `routed_register_access` once.
- [x] Return the common v1 receipt plus `pulp_gpio_padout_effect.v1` only when one exact APB access, native APB request and response, zero error, and `post.gpio_probe_out == value` are all observed.
- [x] Confirm failure paths retain uncertainty facts and do not return an observed provider receipt.
- [x] Run the PULP provider and GPIO routed-consumption suites successfully.

## Task 3 — Prepared PULP DMA route graph

**Files:**

- Create `src/myfuzz/scenario/pulp_gpio_dma_paths.py`
- Create `tests/scenario/test_pulp_gpio_dma_paths.py`
- Reuse `src/myfuzz/scenario/runtime_path_contract.py` without changing historical UART route data.

- [x] Add the graph with `memory_image` source `ram.source_word`, typed RAM-read edge `(ram.source_word → dma.read_data)`, ordered internal transfer edge `(dma.read_data → dma.write_data)`, and typed PULP write edge `(dma.write_data → gpio.padout_effect)`.
- [x] Construct the RAM read route with operation `read`, endpoint `read_master`, exact persistent-memory identity, permissions, and aperture from the real shared memory region.
- [x] Construct the GPIO write route with operation `write`, endpoint `write_master`, exact `MasterTargetWindow` identity, PADOUT offset `12`, full-word byte enable, and the declared accepted-value range.
- [x] Add positive compile tests using a real `PersistentMemory`, `MemoryService`, `TransactionLedger`, `MasterTargetWindow`, and live session-shaped runner.
- [x] Add refusal tests for missing/ambiguous window, wrong endpoint object, wrong RAM object/resource, offset/value/permission mismatch, and post-compile master-window mutation; validation rejects before provider execution.
- [x] Run the PULP path, runtime-path contract, and DMA runtime-path suites successfully.

## Task 4 — Real native and fresh-replay gate

**Files:**

- Create `tests/integration/test_dma_pulp_gpio_real.py`
- Create any isolated scenario helper under `src/myfuzz/scenario/` only if the integration gate cannot reuse existing profile/artifact helpers without coupling unrelated CPU code.
- Remote run outputs, if run, must use a unique `/root/fanzehui/myfuzz/operations/pulp-apb3-dma-20261020-<id>/` and evidence `/root/fanzehui/myfuzz/evidence/pulp-apb3-dma-20261020-<id>/`. The final local native/fresh/refusal evidence is under `docs/reports/evidence/pulp-apb3-dma-20261020-local-attempt6/`; attempts 1–5 remain preserved.

- [x] Add and run the opt-in gate controlled by `MYFUZZ_DMA_PULP_REAL=1`; pinned generated DMA and PULP GPIO sessions complete one accepted RAM-to-PADOUT DMA write locally.
- [x] Save the native DMA accepted request/response, DMA memory read, PULP provider receipt, APB request/access/response samples, exact transaction keys, PADOUT effect, artifact identities, and route compiler document locally.
- [x] Start a fresh pair of processes and replay the same pinned word; typed route and effect prefixes match after normalizing only process execution IDs.
- [x] Exercise a native DMA request to unselected PADOUT+4; route admission rejects it before provider dispatch, provider call count is zero, no APB witness is emitted, and a post-refusal GPIO sample remains zero. Unit tests reject partial byte enable/unsupported operations before APB. Common receipt mutation tests reject success and leave the DMA key unresolved; they make no rollback claim for an effect already performed by a provider callback.
- [ ] Run the remote gate under `/root/fanzehui/**`, following `agent.md`; the jump host currently times out at `166.111.80.238:2249`, so no target-host files were touched and no remote result is claimed.

## Task 5 — Documentation and review

**Files:**

- Create `docs/reports/pulp-apb3-dma-target-20261020.md` after evidence exists.
- Modify `docs/CURRENT_PROGRESS.md` and `docs/reports/README.md` to link the implementation report and precise remaining gaps.

- [x] Report the frozen source/profile/cache identities and exact route/prefix digests from the local real run.
- [x] Label route declaration, topology binding, runtime observation, and fresh replay verification separately.
- [x] State that the provider is transaction-level; PADOUT evidence does not prove CPU observation, CPU retirement, a physical bridge, or F6 onboarding.
- [x] Run scoped unit and real gates as authorized, `git diff --check`, and a link check for the new report and plan.
- [x] Complete independent code review against this spec; no Blocker or Important remains.
