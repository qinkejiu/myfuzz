# P7 D4 Caliptra AHB-Lite Target Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit the generated Caliptra SHA256 CTRL-start AHB-Lite target into the existing D4 topology binder under its exact provider and route contract.

**Architecture:** Split `compile_caliptra_sha256_dma_runtime_paths(...)` into a pure preparation API and the existing compatibility API, then extend the closed D4 target predicate for the exact `GeneratedAhbLiteRegisterSession`. D4 validates the generated AHB artifact, D2 template, CTRL policy, provider method implementations and identity before binding the retained prepared graph once.

**Tech Stack:** Python 3.12, pytest, generated local harness artifacts, D2/D3 route compiler, `PreparedRuntimePathContract`.

## Global Constraints

- Admit only exact `GeneratedAhbLiteRegisterSession` with `caliptra_sha256` / `ahb_lite_register_observe` and the pinned `sha256.bus` AHB-Lite artifact.
- The only target operation is write-only full-word `CTRL@0x10 = 5`, `byte_enable == 15`, on `target.ahb-lite` v1 `full-word-single`.
- Preserve `compile_caliptra_sha256_dma_runtime_paths(...)` binding/admission-install behavior; the new prepare API must not bind or install admission.
- D2/D3 route rows remain unchanged; P7-C F6 remains `unsupported`, with no DMA transfer edge added to either compiled graph document.
- The D4 credential remains `topology_bound`; it does not claim another native run, a physical Wishbone-to-AHB bridge, CPU consumption/retirement, or generic AHB onboarding.
- Retain the shared worktree: do not stage, commit, reset, or clean it.

---

## Task 1: Separate Caliptra path preparation from live compilation

**Files:**
- Modify: `src/myfuzz/scenario/caliptra_sha256_dma_paths.py`
- Test: `tests/scenario/test_caliptra_sha256_dma_paths.py`

**Interfaces:**
- Add `prepare_caliptra_sha256_dma_runtime_paths(runner, *, sha_base=0x40002000, sha_size=0x1000, memory_component='cpu', resource_id='ram', image_id='dma_payload', image_address=None, direction=DEFAULT_DIRECTION)`.
- Preparation returns the existing `CaliptraSha256DmaRuntimePaths` with its existing `PreparedRuntimePathContract`, `compiled is None`, and `admission is None`; it must not call `prepared.bind` or `dma.configure_dma_route_admission`.
- Keep `compile_caliptra_sha256_dma_runtime_paths(...)` signature and behavior: call prepare, bind that exact prepared object once, create `CaliptraSha256DmaBeatAdmission`, install it on the DMA session, and return the compiled/admitted path object.

- [x] Write `test_prepare_caliptra_sha256_dma_runtime_paths_is_pure`: use the existing test `_Runner`, call prepare, assert the prepared graph targets `SHA_CTRL_NODE`, `compiled` and `admission` are absent, `runner.dma.admission is None`, and `runner.dma.validator is None`.
- [x] Run the test before implementation; it failed because the prepare API was absent, as expected.
- [x] Add optional `compiled` and `admission` fields to the path result; make `document()` refuse when either is absent because the document schema includes both compilation and beat-admission identity.
- [x] Move existing route validation, graph construction, and `PreparedRuntimePathContract` creation into `prepare_caliptra_sha256_dma_runtime_paths(...)`; leave all runner binding and admission installation in `compile_caliptra_sha256_dma_runtime_paths(...)`.
- [x] Run the preparation test and all `tests/scenario/test_caliptra_sha256_dma_paths.py` tests; existing compile/admission behavior passes.

## Task 2: Build a real generated D2/D3 Caliptra route case

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Read: `configs/peripherals/caliptra_sha256/component_profile.json`
- Read: `src/myfuzz/scenario/caliptra_sha256_dma_paths.py`

**Interfaces:**
- Follow `_generate_zipcpu_uart_dma_route_d2_d3(...)` for `harness_compose.v2`, `generate_harness_set(...)`, and `path_compile_request.v1`.
- Declare route `route.caliptra-ctrl`: DMA `dma.memory` to peripheral `sha` / endpoint `sha256.bus`, base `0x40002000`, size `0x1000`, write-only, byte enable `15`, writable offset `[16]`, accepted value `[5]`.
- Select `target.ahb-lite` v1 `full-word-single`; select the existing DMA Wishbone master template for the `dma.memory` initiator.
- Generate a real Caliptra artifact with endpoint policy `target.ahb-lite` v1 `full-word-single`; build the existing RAM-read / DMA-write / SHA CTRL typed graph with `prepare_caliptra_sha256_dma_runtime_paths(...)`.

- [x] Add `_generate_caliptra_sha256_dma_route_d2_d3(tmp_path)` and assert D2 route/binding rows are byte-for-byte preserved in D3, the target binding is `target.ahb-lite` v1 `full-word-single`, F6 is `unsupported`, and both `runtime_dependency_graph.edges` and `runtime_path_contract.edges` lack `DMA_MASTER_TRANSFER`.
- [x] Add a positive-shaped `test_caliptra_ahb_d2_d3_route_binds_existing_typed_topology`: assemble exact generated DMA and SHA sessions, reuse the existing `MemoryService` and `PersistentMemory`, construct the typed D2/D3 route declaration, then call D4.
- [x] Run the integration case and confirm that the supported target binds while preserving route rows, the F6 refusal, and the no-transfer-edge assertions.

## Task 3: Add exact Caliptra target admission and topology guard

**Files:**
- Modify: `src/myfuzz/scenario/dma_intent_topology_binding.py`
- Test: `tests/integration/test_p7b_p7c_dma_route_intent.py`

**Interfaces:**
- Add a method-snapshot helper for exact `GeneratedAhbLiteRegisterSession`. The guarded methods are `dma_master_target_provider_identity_document`, `dma_master_target_access`, `_check_artifact_stable`, `command`, `_command_impl`, `_expected_ready`, `_take`, and `_take_impl`; resolve descriptors through the class MRO and reject an instance dictionary shadow of any guarded method.
- Extend `_target_binding(...)` with the exact Caliptra branch. Require request instance `sha`, profile `caliptra_sha256`, kind `ahb_lite_register_observe`, `_window == 4096`, `access_operation == 'ACCESS_AHB_REG'`, adapted endpoint `sha256.bus` protocol `('ahb-lite', '1')`, provider identity `caliptra_sha256_dma_target_provider.v1` / `dma_master_target_access.v1` / `caliptra_sha256_ctrl_ahb_write_completion.v1`, and matching artifact digest. Pin class constants `DMA_CTRL_OFFSET == 16` and `DMA_CTRL_START_VALUE == 5`.
- Require trace schema/protocol/endpoint `ip_protocol_trace.v1` / `ahb-lite` / `sha256.bus` and exactly these role widths: `haddr:32`, `hwdata:32`, `hsel:1`, `hwrite:1`, `hreadyin:1`, `htrans:2`, `hsize:3`, `hresp:1`, `hreadyout:1`, `hrdata:32`.
- Require one 32-bit `CTRL` register at offset `16` with write-only access; route operation and permissions `write`, byte enable `15`, readable offsets `()`, writable offsets `(16,)`, accepted write values `(5,)`; and declared target template `target.ahb-lite` v1 `full-word-single`.
- Require the generated artifact request to contain exactly the `sha256.bus` `target.ahb-lite` v1 `full-word-single`, `max_outstanding=1` policy. Recompute the contract and selection from that pinned request and the artifact endpoint/profile because the current generated executor document does not copy this target policy under `protocol_templates`.
- Snapshot MRO-resolved provider implementation descriptors, canonical identity, and pinned stable configuration before live bind; topology guard must recheck them alongside the existing artifact/session snapshots. Do not snapshot mutable event receipts.

- [x] Implement the exact target branch and snapshot list without changing the existing OTI, ZipCPU UART, or PULP admission branches.
- [x] In the positive-shaped test, spy on `PreparedRuntimePathContract.bind`; assert one call with the identical prepared object and a returned credential tier `topology_bound`.
- [x] Run the positive D4 test; route binding succeeds while preserving the F6/no-transfer-edge assertions.

## Task 4: Add hostile refusals, review and update evidence records

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Create: `docs/reports/p7-d4-caliptra-ahb-admission-20261020.md`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`

- [x] Add before-bind refusal cases for subclass/lookalike session, shadow of each guarded method, wrong artifact component/kind/instance/window, missing or changed provider field, wrong trace role/protocol/width, unadapted endpoint, wrong target template, read permission, offset `20`, partial byte enable, value other than `5`, and subwindow.
- [x] Spy on `PreparedRuntimePathContract.bind` and prove every static/provider/template refusal occurs before it. Change only the live `MasterTargetWindow` for one case and prove the original prepared binder rejects it after one attempted bind.
- [x] After positive binding, shadow a provider method, alter an identity input, and alter stable configuration; `bound.validate_topology()` raises `dma-binding-topology-changed` for each, and restoring the exact method/identity/configuration restores validation.
- [x] Run focused verification:

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py::test_caliptra_ahb_d2_d3_route_binds_existing_typed_topology \
  tests/integration/test_p7b_p7c_dma_route_intent.py::test_caliptra_ahb_d4_static_refusals_precede_runtime_bind --tb=short
```

- [x] Run the joint software gate:

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_dma_artifact_endpoint_links.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_runtime_path_contract.py \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/integration/test_dma_intent_binding_replay.py \
  tests/integration/test_dma_master_route_replay_readers.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py \
  tests/integration/test_route_intent_reader_boundaries.py --tb=short
```

- [x] Run `py_compile`, scoped whitespace/diff checks, and an independent read-only code review; record exact commands, counts, runtime, review findings, and the no-native/no-remote boundary in the report and progress indexes. The D4 credential certifies topology binding only; no SHA result is inferred from it.

## Completion record

All listed software tasks and the independent review are complete. The final report distinguishes D4 `topology_bound` software admission from the separately recorded Caliptra native DMA evidence and keeps generic AHB, physical bridge, F6, P6/P7/P8, and overall six-CPU/four-IP completion open.
