# Ibex PULP GPIO DMA ISR Implementation Plan

> **For agentic workers:** Follow the repository's TDD and review practices. Tasks use checkbox syntax and must preserve the shared dirty worktree.

**Goal:** Run and freshly replay a real Ibex-configured ZipCPU DMA transfer from shared RAM to PULP GPIO PADOUT, then prove DMA IRQ delivery, CPU ISR readback, and result storage.

**Architecture:** Add a new isolated Runner/firmware module that reuses existing Ibex instruction encoders, real `ScenarioRunner` IRQ binding, the PULP GPIO DMA provider, and `compile_pulp_gpio_dma_runtime_paths()`. Keep the existing standalone DMA and CPU-to-RAM fixtures unchanged. A native integration gate records exact transaction and APB evidence, then repeats the same schedule with fresh processes and verifies the full prefix.

**Tech Stack:** Python 3, pytest, generated Verilator sessions, `ScenarioRunner`, `PersistentMemory`, ZipCPU Wishbone DMA, PULP APB3 GPIO.

## Global Constraints

- Follow [agent.md](../../../agent.md); any remote operation or write must remain under `/root/fanzehui/**`.
- Preserve the shared dirty worktree; do not clean, reset, stage, or commit.
- Preserve historical evidence identities by adding new fixture and gate files instead of editing frozen old fixture code unless a focused reusable fix is required.
- Use the existing `MasterTargetWindow` and `dma_master_target_access.v1` PULP target provider; do not introduce a second GPIO transport.
- Use transaction-level target delivery between independent RTL processes; do not claim a physical Wishbone-to-APB bridge or shared physical SRAM.
- Runtime-path compilation is declaration/topology binding; only native receipts and their exact joins prove the measured transfer.
- The route remains one 32-bit read followed by one 32-bit write to the registered PADOUT offset. Unknown windows and offsets fail closed.
- Keep P7 F6, remote PULP execution, six-CPU/four-IP aggregate adaptation, and P6/P7/P8 acceptance open.

---

### Task 1: Add exact firmware and fixture tests

**Files:**

- Create: `src/myfuzz/scenario/ibex_dma_pulp_gpio_example.py`
- Test: `tests/scenario/test_ibex_dma_pulp_gpio_example.py`

**Interfaces:**

- `ibex_dma_pulp_gpio_images(*, source_value: int, destination_address: int, start_key: int = 0xFED) -> dict[int, bytes]`
- Image keys retain the existing RAM layout constants `MAIN`, `ISR`, `SOURCE`, and `RESULT` imported from `ibex_dma_example.py`.
- The native program configures source, destination, one-word length, and start via CPU OBI. Its ISR reads DMA status, PULP PADOUT, and the source word; it stores `mcause`, status, observed value, expected value, and success marker in `RESULT`.

- [x] Write focused tests that decode the fixed instruction words and verify: the start register write follows source/destination/length writes; length is exactly one word; destination equals the supplied address; ISR reads PADOUT and source; ISR branches on value/status mismatch; success is stored only on the matching branch.
- [x] Run `PYTHONPATH=src pytest -q tests/scenario/test_ibex_dma_pulp_gpio_example.py`; confirm the initial failure is due to the new module/interface being absent.
- [x] Implement the image builder using the existing `_lui`, `_addi`, `_sw`, `_lw`, `_csr`, `_bne` encoders from `ibex_dma_example.py`. Keep source and result addresses in the existing shared RAM region.
- [x] Re-run the focused tests and require them to pass.

### Task 2: Assemble the real Ibex/DMA/PULP Runner and compile its route

**Files:**

- Create: `src/myfuzz/scenario/ibex_dma_pulp_gpio_runner.py`
- Test: `tests/scenario/test_ibex_dma_pulp_gpio_runner.py`

**Interfaces:**

- `make_ibex_dma_pulp_gpio_runner(*, cache_dir: Path, source_value: int = 0x5AA55AA5, destination_address: int = PADOUT_ADDRESS) -> tuple[ScenarioRunner, PulpGpioDmaRuntimePaths]`
- Sessions: `cpu` is generated Ibex with native IRQ receipts and deferred MMIO; `dma` is generated ZipCPU `wbdmac` with the PULP `MasterTargetWindow`; `gpio` is the generated PULP observation session.
- Runner binds `dma.irq` to `cpu.irq`, and the CPU router exposes both the DMA register window and the PULP GPIO window.
- Route compilation uses the exact `cpu.memory`, DMA memory service, GPIO session/window, and source word address through `compile_pulp_gpio_dma_runtime_paths()`.
- Declare `Binding('dma', 'irq', 'cpu', 'irq', 1)`, the matching bound CPU IRQ `InputField`/`InputOwner`, and `irq_pulses={binding: 16}`. A narrow native IRQ pulse must be latched by the Runner until the CPU actually takes the interrupt.
- Declare the PULP `gpio_in` 32-bit input as fixed zero in ownership. This path observes PADOUT and does not fuzz external pins.

- [x] Add unit tests with monkeypatched artifact/session builders to require exact session roles, shared `PersistentMemory` identity, DMA master window, CPU router windows, one IRQ binding with a 16-tick pulse latch, fixed-zero GPIO input ownership, and installed route admission. Assert incorrect target offset or substituted memory/window is refused before a native process starts.
- [x] Run `PYTHONPATH=src pytest -q tests/scenario/test_ibex_dma_pulp_gpio_runner.py`; confirm it fails because the new factory is missing.
- [x] Implement the factory in a new module, reusing the existing profile helper, PULP artifact helper, and route compiler without changing the older Runner fixtures.
- [x] Run both new scenario test files and require them to pass.

### Task 3: Add native positive, fresh, and wrong-offset gates

**Files:**

- Create: `tests/integration/test_ibex_dma_pulp_gpio_real.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_pulp_gpio_runner.py`
- Reuse: `src/myfuzz/scenario/pulp_gpio_dma_paths.py`

**Interfaces:**

- Opt-in variable: `MYFUZZ_IBEX_PULP_DMA_REAL=1`.
- Operation-local variables: `MYFUZZ_IBEX_PULP_DMA_CACHE` and `MYFUZZ_IBEX_PULP_DMA_EVIDENCE`.
- The positive helper starts a Runner with a declared one-word `MemoryImage`, compiles/validates the prepared route, executes the selected `(dma, cpu, gpio)` schedule, and returns the evidence bundle.
- The deterministic scheduler repeats exactly `('dma', 'cpu', 'gpio')` in that order, records every component step, and stops after the first completed round that makes `RESULT+16 == 1` visible or after 2,000 rounds (6,000 component steps). The identical recorded prefix is replayed on the fresh Runner; no timing-based or adaptive step selection is permitted.

- [x] Add a skipped-by-default native test that checks actual CPU DMA-register programming, exactly one DMA RAM read and one PADOUT write, exact read/write transaction identities and responses, one APB request/effect/response with matching data, a measured DMA IRQ and actual CPU interrupt take, ISR result stores, and CPU-visible PADOUT/source equality.
- [x] Add fresh replay using a newly constructed Runner and the exact recorded schedule. Compare all events/results and identities with typed field-level normalization for exactly `cpu`, `dma`, `gpio`, and `runner`; require each fresh UUID to differ from the reference UUID and retain every payload, tick, address, value, transaction suffix, and artifact identity.
- [x] Add an invalid destination run at `PADOUT+4`; prove refusal follows an observed native DMA request but precedes provider dispatch, APB requests/responses, or PADOUT mutation. Preserve partial events and cleanup state.
- [x] Run the software gates with `PYTHONPATH=src pytest -q tests/scenario/test_ibex_dma_pulp_gpio_example.py tests/scenario/test_ibex_dma_pulp_gpio_runner.py`.
- [x] Run the native positive and negative gates with operation-local cache/evidence paths and `MYFUZZ_IBEX_PULP_DMA_REAL=1`; require both exits to be 0 and every started DUT to be reaped with return code 0 on the positive/fresh paths.

### Task 4: Record evidence and remaining boundaries

**Files:**

- Create: `docs/reports/ibex-zipcpu-dma-pulp-gpio-isr-20261020.md`
- Create: `docs/reports/evidence/ibex-zipcpu-dma-pulp-gpio-isr-20261020/`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md` only if it helps link the new evidence without changing historical row verdicts.

- [x] Preserve the exact command, positive/fresh event bundles, route compilation, source/target identities, IRQ receipt, ISR result, refusal prefix, exit codes, and SHA-256 manifest.
- [x] Report the measured chain and fresh semantic match. State that PULP delivery is transaction-level provider execution and that this gate does not create a physical bridge.
- [x] Keep remote PULP execution, generic F6, Caliptra payload DMA, online continuous fuzzing, and P6/P7/P8 gates explicitly open.
- [x] Run `git diff --check` and the scoped scenario/native gates; do not run the whole repository suite.

## Acceptance checklist

- [x] CPU OBI writes actually configure source, destination, length, and start before DMA acts.
- [x] DMA reads the exact shared RAM word and writes that same value to the selected PADOUT address under an admitted route.
- [x] PULP APB request, native register effect, APB response, DMA response, and typed transaction keys join exactly.
- [x] DMA IRQ receipt leads to actual Ibex external interrupt take; ISR reads PADOUT/status/source, branches on measured values, and stores its result in RAM.
- [x] Positive/fresh full prefixes match under only declared execution-identity normalization; all DUT processes are reaped successfully.
- [x] The wrong-offset request is refused before any provider/APB side effect and does not produce a successful chain claim.
- [x] Reports describe only this bounded CPU/DMA/PULP path and leave all aggregate phase and generic-flow gates open.
