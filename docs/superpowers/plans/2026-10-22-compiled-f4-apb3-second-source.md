# Compiled F4 second APB3 source implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second source-reviewed APB3 storage contract for PULP SPI `SPICMD` and prove exact D2→D3→D4 CPU write/readback with native first/fresh replay.

**Architecture:** Keep source semantics in a closed code-owned registry keyed by versioned contract ID and exact profile/source bytes. Pass the selected contract's decode and register facts through probe proof, live version issuance, and the existing compiled-F4 storage consumer. Do not add component-name routing or alter the PULP Timer/GPIO rows.

**Tech Stack:** Python 3, pytest, generated Verilator APB3 harness, native C++ probe, RFuzz client, JSON evidence.

## Global Constraints

- Follow `agent.md`; remote project writes are only allowed under `/root/fanzehui/**`.
- Do not clean, reset, stage, commit, or overwrite the shared dirty worktree.
- Only admit the pinned PULP SPI profile, exact source bytes, and `SPICMD` at offset `0x08`; APB decode is `PADDR[5:2] == 2` (mask `0x3c`, value `0x08`).
- The APB3 write/read source contract proves storage only. It does not exercise STATUS transfer strobes, SPI serial pins, TX/RX FIFOs, IRQs, or other registers.
- Source contract metadata alone grants no native authority, reset prerequisite, live version, or functional acceptance. Native evidence requires actual PRE/POST samples and a process-local opaque version token.
- Unknown source/contract/register/profile/template/layout/assertion or missing receipt joins fail closed before a certified testcase is accepted.
- Preserve the existing Timer contract, GPIO causal producer, their evidence identities, and their behavior.
- Keep arbitrary APB3 support, P7-E overall, P6, P8, and aggregate six-CPU/four-IP acceptance open.

---

### Task 1: Register the exact PULP SPI SPICMD source contract

**Files:**
- Modify: `src/myfuzz/local_harness/apb_storage_source_contract.py`
- Modify: `tests/local_harness/test_apb_storage_source_contract.py`
- Modify: `tests/local_harness/test_apb_storage_probe_generation.py`

**Interfaces:**
- Preserve `select_apb_storage_source_contract(profile, *, base_dir, selection)` and `validate_apb_storage_source_contract(document, profile, *, base_dir)`.
- `selection` remains exactly `{contract_id, register}`. Add `pulp-apb-spi.spicmd.source.v1` / `SPICMD`; keep `pulp-apb-timer.ctrl0.source.v1` / `TIMER0_CTRL` byte-compatible.
- `apb_storage_address_matches(document, address)` derives its predicate from the validated document's `decode.mask` and `decode.value`.
- Pin source root `third_party`, revision `sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230`, top `apb_spi_master`, exact seven-file profile closure and parameters `APB_ADDR_WIDTH=12` / `BUFFER_DEPTH=10`. Source files and SHA-256: `soc-pulp-apb-spi/apb_spi_master.sv=dfc82b0f3c91ba44d986288e1884b1eede0aad6ed8c5b09179a629344d547d0e`; `soc-pulp-apb-spi/spi_master_apb_if.sv=a9a32da6cc07768cab293c48989599e36b2000bb572191667960aa1423fc790a`; `soc-pulp-axi-spi/spi_master_clkgen.sv=dbfc81a8afe1c05a4372cf7e46f1217f6b57d56c8927bf25ee5f427761b15332`; `soc-pulp-axi-spi/spi_master_controller.sv=0ba0d90e99949939b3815ed2e69a9f95b980114ec554baca14083ab54496db76`; `soc-pulp-axi-spi/spi_master_fifo.sv=226f53f2e78a82eb9859149a505c287daa8cfd54f55c51b6c1cfa2cd90a38555`; `soc-pulp-axi-spi/spi_master_rx.sv=1290e4beaa7d4b588da9cf84da47b39923010bcfdb355641509ee90295d8ca5f`; `soc-pulp-axi-spi/spi_master_tx.sv=ee9a7d305bc7bb574ece02dbd6dc8a3f0403729d336bd7431689da47a08558f6`.
- SPICMD geometry is width `32`, offset `8`, reset `0`, read/write masks `0xffffffff`; storage decode is mask `0x3c`, value `0x08`, period `64` bytes, `256` raw aliases and `64` aligned-word aliases within the 12-bit bus.

- [x] Add failing selection tests for exact PULP SPI profile + SPICMD, source byte pins, mask/value and alias counts.
- [x] Add failing refusal tests for Timer/SPI cross-pairing, unknown register/contract, altered source root/revision/top/files/parameters, wrong clock/reset, wrong APB endpoint/window, changed SPICMD offset/width/access/side-effect/reset facts, symlink, and byte mutation.
- [x] Run `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_apb_storage_source_contract.py tests/local_harness/test_apb_storage_probe_generation.py` and confirm the new SPI expectations fail for the missing contract.
- [x] Add the immutable SPI contract using the reviewed `apb_spi_master.sv` and `spi_master_apb_if.sv` bytes. Pin storage reset, sole bus writer, full-word overwrite, read mux, source identity, and decode. Keep the contract documentary; do not set any authority/verified flag.
- [x] Generate the storage probe using the selected contract's exact hierarchy expression and include that contract in the probe digest.
- [x] Rerun the two focused modules; the Timer contract assertions must remain unchanged and pass.

### Task 2: Prove the generated PULP SPI hierarchy and physical storage samples

**Files:**
- Modify: `src/myfuzz/local_harness/apb_storage_probe_verification.py`
- Modify: `scripts/verify_apb_storage_probe.py`
- Create: `tests/native/pulp_spi_apb_storage_probe_tb.cpp`
- Create: `tests/local_harness/test_pulp_spi_apb_storage_probe_real.py`
- Create evidence: `docs/reports/evidence/verilog-probe-pulp-apb-spi/`

**Interfaces:**
- Keep the existing Timer proof schema/path and deterministic proof bytes unchanged. Resolve proof references from a closed contract-ID map; PULP SPI uses `docs/reports/evidence/verilog-probe-pulp-apb-spi/proof.json` and contract-specific sample/check validation.
- Generate the SPI proof directly from a `local_harness.v2` request for `configs/peripherals/pulp_spi/local_component_profile.json`, with a `target.apb3` `full-word` policy and the source contract selector on `spi.bus`. This proof is independent of the later compiled-F4 composition and live version consumer.
- The native bench drives only HCLK/reset and APB register accesses; it never writes STATUS or starts SPI serial activity.

- [x] Add failing proof-validator tests for a missing/stale SPI proof, altered generated runtime/wrapper, wrong storage expression, changed source hash, wrong SPICMD address, missing wrong-register refusal control, and a Timer/SPI proof cross-pair.
- [x] Add failing native-sample assertions for reset=0 storage, full-word write/read to offset `0x08`, storage state change, APB readback equality, and a write to `0x0c` that leaves SPICMD unchanged.
- [x] Run the focused proof tests and confirm failure is due to absent SPI proof selection/support.
- [x] Extend the proof tool to generate the exact SPI probe runtime directly through the local harness planner/renderer, run Verilator lint negatives for changed/unbound hierarchy expressions, build the native bench, and collect raw samples. Do not call `prepare_compiled_execution_files()` for SPI. Write a proof only after every named check passes.
- [x] Save full invocation arguments and exit codes, tool/compiler versions, generated wrapper/runtime files and hashes, source hashes, native binary hash, raw samples/logs and proof digest under the new evidence directory; bind the sidecar bundle to its file hashes without changing Timer proof bytes.
- [x] Run the SPI proof integration test and existing Timer proof tests; preserve the Timer proof file unchanged.

### Task 3: Make the live APB storage consumer and version authority contract-driven

**Files:**
- Modify: `src/myfuzz/scenario/apb_storage_register_version.py`
- Modify: `src/myfuzz/integration/generated_storage_consumer.py`
- Modify: `src/myfuzz/integration/compiled_storage_producer.py`
- Modify: `tests/scenario/test_apb_storage_register_version.py`
- Modify: `tests/integration/test_compiled_f4_storage_producer.py`

**Interfaces:**
- `ApbStorageRegisterVersionAuthority(target, ...)` revalidates the immutable source contract from the target artifact against the admitted profile and reviewed source bytes, then captures its digest, register name, width, reset value, write mask, decode mask and decode value for the authority lifetime.
- Preserve the single-use token API `issue(*, register, reset_epoch)`, `consume(token)` and `writes()`; token witnesses include the exact source-contract digest and register.
- `check_storage_observation(...)` derives decode and register identity from the artifact's validated source contract. Keep exact routed-transaction address equality at declaration, physical sample and commit joins; decode aliases do not substitute for the exact address of a receipt.
- The generic compiled-F4 APB producer emits decode facts from the same registered contract and admits either registered storage row through the same validation path; it must not pin the generic row to Timer's `0x1c`/`4` decode.

- [x] Add failing timer/SPI data-driven tests for issue/write/version/readback, exact decode-derived physical sample matching, and generic compiled-F4 producer selection from the registered source contract.
- [x] Add failing cross-contract and tamper controls for register relabeling, source-contract digest, mask/value, reset value, token register, and missing each of the four receipt joins. Also prove a different address that is a valid decode alias cannot satisfy an exact declared-address receipt join.
- [x] Run the two focused test modules and confirm the SPI cases fail at current Timer-only checks.
- [x] Parameterize the reducer, authority witness and consumer checks from the validated contract. Preserve current bounds, identity pins, single-use token checks, process eligibility and fail-closed teardown.
- [x] Keep the Timer expected normalized output and existing GPIO causal row unchanged; run both focused modules and the existing compiled-F4 producer tests.

### Task 4: Add a CV32E40P + PULP SPI compiled-F4 composition

**Files:**
- Create: `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/compose.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/requests/processor.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/requests/peripheral.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/README.md`
- Modify/Create: `tests/integration/test_compiled_f4_storage_producer.py`, `tests/integration/test_compiled_f4_spi_source_real.py`
- Modify/Create: `tests/integration/test_auto_harness_test.py` or an explicit P7-E CLI negative driver

**Interfaces:**
- Reuse `compiled-f4-rfuzz`; do not add `--runtime` or CPU/IP-name routing.
- D2 source contract selection is exactly `pulp-apb-spi.spicmd.source.v1` + `SPICMD`; APB window remains `0x40001000`/4096 bytes and the bound register offset is `8`.
- The CPU candidate writes a full word to SPICMD, reads it back from the same APB register, and stores the returned value to RAM. It does not write STATUS.
- Each certified prefix row includes a typed native RAM result hop joined to the consumer-selected RAM event, exact result address/value/BE/width/memory version/offset, producer OBI store acceptance, transaction scope and sequence, and completed OBI response. Fresh comparison includes this nested witness.

- [x] Add failing composition tests for D2→D3 F4 selection, producer row, candidate register address/value, source contract, assertions and expected `ip_register_version` prerequisite.
- [x] Add failing wrong CPU/profile and wrong APB source/template negatives. For the executor-only CLI negative, keep the composed processor request at CV32E40P and pass the similar `cv32e20` profile as the `--cpu` override; require a located `/cpu/request` `composition-profile-not-reviewed` refusal before D2/native startup, with no default-family artifact substituted. This checks request identity binding and does not introduce a CPU-name allowlist.
- [x] Pin all four SPI `sdi0..sdi3` inputs to zero in the peripheral request's `tuning.fixed_inputs`; assert D3 contains no candidate external-pin sources and the only generated candidate is the SPICMD write/readback/RAM chain.
- [x] Add the configuration using the existing CV32E40P OBI and PULP SPI profiles with only versioned declarations; do not add component-name conditionals.
- [x] Run D1–D3 software generation and the focused compiled-F4 admission/consumer tests.
- [x] Run the real CLI with `--executor compiled-f4-rfuzz`, no runtime family, one worker and the planned budget. Require CPU acceptance→Router delivery→APB pre/post→opaque version token→CPU readback/RAM joins; preserve actual first/fresh process receipts and full normalized comparison. Attempt 5 has four certified records, full first/fresh prefix equality, and per-row `compiled_F4_exact_hops.v2.ram_write_hop` witnesses.
- [x] Run a separate CLI negative using the similarly named `cv32e20` profile with the same SPI target; require a located refusal before native startup and preserve its command/result evidence. It exits 1 with `composition-profile-not-reviewed` at `/cpu/request`.
- [x] Independently audit the saved physical samples, source/probe proof, input archive and process exits before updating acceptance status. Code-path review and independent raw-evidence audit passed; details are in the [Task 4 report](../../reports/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md).

Native gate parameters follow the previously accepted CV32E40P compiled-F4
gate: local RFuzz client `runs/rfuzz_client_native_build/target/debug/kfuzz`,
shared cache `.superpowers/compiled-f4/cache`, 60-second session budget, at
most 8 tests, 32 rounds per case, and one run per batch. No `--runtime` or
`--skip-session` is used.

### Task 5: Reconcile reports and acceptance boundaries

**Files:**
- Create: `docs/reports/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: `docs/reports/dma-six-cpu-four-ip-status-20261022.md`

- [x] Record exact command, exit codes, generated/runtime identities, probe proof hash, per-join evidence, first/fresh comparison and independent audit in the [Task 4 report](../../reports/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md).
- [x] State that this is a second registered PULP APB3 storage source using the existing executor; it is not arbitrary APB3, serial SPI, F6/DMA, P6 row completion, P7-E completion, or a six-CPU/four-IP aggregate run.
- [x] Correct the DMA status audit's stale sentence that calls the Reduced AXI Task5 runtime gate a future step; link it to the accepted observation-only gate.
- [x] Re-read all changed status/index paragraphs and verify every relative link resolves.
