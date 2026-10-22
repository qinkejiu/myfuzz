# Protocol-Neutral DMA Route Admission Implementation Plan

> Use the repository's test-first workflow; retain existing worktree changes.

**Goal:** Use one route-admission implementation to join D4-bound DMA routes to real PULP APB3 and ZipCPU Wishbone DMA beats.

**Architecture:** Add a protocol-neutral admission that verifies the selected D4 read/write routes and transaction keys before delegating to each target's existing typed beat policy. Migrate the PULP path and the native ZipCPU path while retaining compiler helper compatibility.

**Tech Stack:** Python 3, pytest, generated local RTL sessions, D2/D3 route compiler, D4 topology binder, gzip JSON evidence.

## Global Constraints

- Preserve existing D2/D3 route rows and binding identities.
- Bind the same prepared ZipCPU route object exactly once in D4.
- Keep target protocol and data semantics inside the existing APB3 and Wishbone providers/beat policies.
- Keep F6 `unsupported`; issue no claim of CPU programming, retirement, or a physical cross-protocol bridge.
- Work only in the local project for this slice; remote host changes remain limited to `/root/fanzehui` by `agent.md`.

---

### Task 1: Define generic route-admission behavior with failing tests

**Files:**
- Create: `tests/scenario/test_dma_route_admission.py`
- Read: `src/myfuzz/scenario/runtime_path_contract.py`
- Read: `src/myfuzz/scenario/runtime_edge_index.py`

**Interfaces:**
- Consumes: `DmaMasterRouteContract`, `DmaMasterRouteMatch`, typed `TransactionKey`, a beat policy with `identity_document`, `begin_case`, `accepted`, and `completed`, and a bound topology with `document`, `identity_sha256`, `validate_topology`, and `match_dma_master_route`.
- Produces: `DmaMasterRouteAdmission(beat_policy, bound_topology, *, path_id, read_route, write_route)` with `accepted`, `completed`, `begin_case`, `state`, `route_matches`, and `identity_document`.

- [x] Write tests proving matching read/write beats are delegated only after exact route matches, route and target-policy refusal do not mutate beat-policy state, unmatched response keys are rejected, and `begin_case()` clears match evidence.
- [x] Run `PYTHONPATH=src pytest tests/scenario/test_dma_route_admission.py -q` and confirm the new production module is absent (3 expected feature-missing failures).

### Task 2: Implement the generic gate and migrate PULP

**Files:**
- Create: `src/myfuzz/scenario/dma_route_admission.py`
- Modify: `src/myfuzz/scenario/pulp_gpio_dma_paths.py`
- Test: `tests/scenario/test_dma_route_admission.py`
- Test: `tests/scenario/test_pulp_gpio_dma_paths.py`

**Interfaces:**
- Consumes: Task 1's API.
- Produces: PULP uses `DmaMasterRouteAdmission` with `PulpGpioDmaBeatAdmission` and its exact bound routes.

- [x] Implement constructor validation for the selected read/write route contracts and bound topology identity.
- [x] Implement exact field-by-field route match verification before policy delegation; retain only accepted route matches.
- [x] Make a response require the exact typed transaction key to have an admitted route match before delegating completion.
- [x] Replace `PulpGpioD4RouteAdmission` internals with the generic class while preserving its public constructor import.
- [x] Run the new scenario tests and PULP path tests; run the PULP route-intent D4 test.

### Task 3: Bind native ZipCPU D4 and consume Wishbone routes

**Files:**
- Modify: `tests/integration/test_p7b_p7c_dma_route_intent.py`
- Modify: `tests/integration/test_dma_zipcpu_uart_real.py`
- Modify: `src/myfuzz/scenario/zipcpu_uart_dma_paths.py`
- Test: `tests/integration/test_dma_zipcpu_uart_real.py`

**Interfaces:**
- Consumes: generated ZipCPU D2/D3 wiring, `prepare_zipcpu_uart_dma_runtime_paths`, generic D4 admission, and existing `_zipcpu_uart_d4_declaration`.
- Produces: native positive/fresh/refusal runs where the prepared path is bound once and both native beats are recorded against D4 routes.

- [x] Parameterize the ZipCPU D2/D3 helper's RAM aperture and keep ROM outside the selected range.
- [x] Build native RAM and DMA with the same geometry as D2/D3; use generated CPU artifact and linked DMA endpoint artifact.
- [x] Prepare the typed route, bind its exact prepared object once, create `DmaMasterRouteAdmission` from the bound routes and ZipCPU beat policy, and install it on the DMA.
- [x] Use the helper in the real positive, fresh replay, and wrong-offset refusal paths; keep UART provider and TX-byte evidence checks.
- [x] Run software gates before the explicit opt-in native gate; save reference, fresh, refusal, and comparison evidence.

### Task 4: Review, document, and verify the slice

**Files:**
- Create: `docs/reports/p7-d4-protocol-neutral-dma-route-consumption-20261021.md`
- Create: `docs/reports/evidence/p7-d4-zipcpu-native-route-consumption-20261021/`
- Create: `docs/reports/evidence/p7-d4-pulp-generic-route-admission-20261021/`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md`

**Interfaces:**
- Consumes: verified test output and captured native evidence from Task 3.
- Produces: indexed evidence with exact claims and explicit limitations.

- [x] Run the software gate after the final added target-policy test. Exact command: `PYTHONPATH=src pytest tests/scenario/test_dma_route_admission.py tests/scenario/test_pulp_gpio_dma_paths.py tests/scenario/test_zipcpu_uart_dma_paths.py tests/integration/test_p7b_p7c_dma_route_intent.py::test_pulp_apb3_d2_d3_route_binds_existing_typed_topology tests/integration/test_p7b_p7c_dma_route_intent.py::test_zipcpu_uart_wishbone_d2_d3_route_binds_existing_typed_topology -q`; result **68 passed / 42.69s**.
- [x] Run the explicit ZipCPU native gate with `PYTHONPATH=src MYFUZZ_DMA_ZIPCPU_UART_REAL=1 MYFUZZ_DMA_ZIPCPU_UART_CACHE=/tmp/myfuzz-zipcpu-d4-cache-20261021 MYFUZZ_DMA_ZIPCPU_UART_EVIDENCE=docs/reports/evidence/p7-d4-zipcpu-native-route-consumption-20261021 pytest tests/integration/test_dma_zipcpu_uart_real.py::test_real_dma_to_zipcpu_uart_txreg_serial_fresh_and_refusal -q`; result **1 passed / 63.42s**.
- [x] Run the complete PULP native gate with `PYTHONPATH=src MYFUZZ_DMA_PULP_REAL=1 MYFUZZ_DMA_PULP_CACHE=/tmp/myfuzz-pulp-generic-route-cache-20261021 MYFUZZ_DMA_PULP_EVIDENCE=docs/reports/evidence/p7-d4-pulp-generic-route-admission-20261021 pytest tests/integration/test_dma_pulp_gpio_real.py -q`; result **2 passed / 76.86s**.
- [x] Run syntax and whitespace checks after the final test-message wording update: the listed `py_compile` command passed; `git diff --check` passed on the touched tracked docs; an explicit trailing-whitespace scan passed on all 12 scoped source, test, design, plan, and report files.
- [x] Record exact commands/counts, bind-once proof, route matches, fresh equality, and wrong-offset refusal in [the report](../../reports/p7-d4-protocol-neutral-dma-route-consumption-20261021.md).
- [x] Update current progress and P7 plan without claiming overall P6/P7/P8 completion.

## Completion record

### Caliptra AHB-Lite follow-on

The shared D4 admission was extended in a separate slice to generated Caliptra SHA256 AHB-Lite. The follow-on binds the same prepared RAM-read/CTRL-write topology once, joins the native Wishbone responses and Caliptra provider effect by typed keys, and saves a fresh replay plus an in-window `CTRL+4` refusal. Its focused software gate passed **41 tests in 285.41s** and the native gate passed **1 test in 92.11s**. See [the Caliptra implementation plan](2026-10-21-caliptra-protocol-neutral-dma-route-consumption.md), [report](../../reports/p7-d4-caliptra-protocol-neutral-dma-route-consumption-20261021.md), and [evidence](../../reports/evidence/p7-d4-caliptra-generic-route-consumption-20261021/). This third target slice does not enable F6 or establish a physical Wishbone-to-AHB bridge, CPU consumption, P7-E, or overall completion.

The generic and target integrations passed: software gate **68 passed / 42.69s**; ZipCPU native gate **1 passed / 63.42s** with in-window wrong offset `UART_BASE + 8`; PULP native file **2 passed / 76.86s**. Fresh normalized comparison is equal for both protocols. Independent review found that the initial ZipCPU refusal used an out-of-window address; this was corrected to the in-window offset and the native test was rerun. Review also requested target-object refusal coverage; a unit test now proves no route row or policy state is committed when the beat policy rejects target identity. The initial PULP extraction run found a stale PULP-specific error-string assertion; it was updated to the shared route-match refusal and the complete PULP native file passed. The final review wording issue is now fixed; fresh read-only follow-ups confirmed the ZipCPU failure text and in-window refusal evidence, and confirmed that the PULP compatibility alias remains used while its offset refusal produces no provider, APB, target-request, or target-response activity. Final syntax check passed with the command above; scoped `git diff --check` and a trailing-whitespace scan over 12 changed source/test/design/plan/report files also passed. Evidence is in `docs/reports/evidence/p7-d4-zipcpu-native-route-consumption-20261021/` and `docs/reports/evidence/p7-d4-pulp-generic-route-admission-20261021/`.
