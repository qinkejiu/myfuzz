# CVW CPU-programmed DMA RAM Implementation Plan

> **For agentic workers:** use subagent-driven-development for independent
> firmware, fixture/gate, and read-only review tasks.

**Goal:** Run genuine CVW CPU configuration, four-word ZipCPU DMA, CPU data
readback, wrong-key refusal and complete schedule fresh replay.

**Architecture:** The existing AHB CPU session routes real CPU MMIO beats to the
existing Wishbone DMA control endpoint. Both sessions use one PersistentMemory
and standard ScenarioRunner. No protocol/Runner component-name branch is added.

**Tech Stack:** Python, generated SystemVerilog/C++ harnesses, Verilator, pytest.

**Status (2026-10-22):** This bounded slice is accepted: native attempt1 actual
exit 0 in 139.83 seconds, positive and wrong-key each complete fresh replay,
eight DUT exits zero, independent saved-evidence audit PASS. Unstarted fixture
and injected Runner-construction cleanup check also passed without native
commands. [Report and raw evidence](../../reports/cvw-dma-ram-20261022.md).
The aggregate six-CPU/four-IP and P6/P7/P8 goals remain OPEN.

## Global constraints

- Follow [design](../specs/2026-10-22-cvw-dma-ram-design.md) exactly.
- Preserve dirty shared tree; no stage/commit/cleanup, no remote access.
- No host configuration of DMA, no host source-word writes, no synthetic IRQ or
  success. Native processes advance only through the declared execution order.
- Run one heavy native worker under the existing canonical local heavy lock.
- Save exact evidence, failed attempts, source identities, real process terminals
  and full first/fresh prefix comparisons. Keep all wider system gates open.

## Task 1: firmware and unstarted fixture

Files: create `src/myfuzz/scenario/cvw_dma_example.py`,
`src/myfuzz/scenario/cvw_dma_runner.py`, and focused tests with matching names.

- [x] Test the firmware's actual stores, polling branches, loadback and success/
  failure paths with a small independent RV32I interpreter; stale key must not
  differ from the positive image except at its programmed key instructions.
- [x] Implement initial images and the standard Runner fixture using the existing
  CVW `_artifact` builder and generated DMA session. Resources and addresses are
  exactly those in the design; memory ownership is shared and unstarted.
- [x] Verify the fixture does not construct a native process, keeps source RAM
  uninitialized, routes only the exact DMA control window, and cleans up partial
  construction failure.

## Task 2: native positive, wrong key, and fresh replay

Entry: `scripts/verify_cvw_dma_ram.py` (standalone; no new pytest integration test).
Executed in native-attempt1; exact command, input bytes, logs and terminal records
are retained with the report.

- [x] Advance `dma,cpu` for at most 4000 rounds; stop only on a real CPU result
  write after all relevant responses have drained. Do not enlarge the bound to
  mask a failure.
- [x] Verify every required transaction/writer/version/control STB/ACK join in
  the design against actual samples and RAM service records.
- [x] Save positive and wrong-key outcomes and rerun each recorded schedule in
  independent fresh native processes. Match complete normalized prefixes.
- [x] Preserve new artifacts/logs under a new attempt directory, source pins and
  actual worker/process return codes; never overwrite a failed attempt.

## Task 3: review and progress records

- [x] Independent read-only review of code and saved native evidence; resolve
  correctness findings before adopting the result.
- [x] Update CURRENT_PROGRESS, LOCAL_HARNESS_RUNTIME, report/plan indexes and a
  dedicated CVW DMA report with actual scope. Do not close broader system gates.
