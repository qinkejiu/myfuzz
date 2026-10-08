# CVA6 + ZipCPU AXI-Lite UART RX M_EXT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove a genome-owned UART RX byte enters pinned ZipCPU axiluart RTL, raises its real RX FIFO level IRQ into CVA6 M_EXT, is consumed by a CVA6 ISR through real AXI4 MMIO routed to the independent AXI4-Lite UART harness, and persists in CPU RAM across replay.

**Architecture:** Keep CVA6 and axiluart in separate generated RTL sessions with independent local clocks. Route accepted CVA6 MMIO beats to the AXI4-Lite UART register service through `DataflowRouter`; this is local register delivery, not a physical AXI4-to-AXI4-Lite bridge. Bind the real RX-not-empty output to CVA6 `irq_external`, and let the ISR's RXREG read pop the FIFO and lower the level.

**Tech Stack:** Python unittest integration scenarios, generated Verilator harnesses, CVA6 packed AXI4 session, ZipCPU AXI4-Lite UART session, ScenarioRunner, genome mutation, persistent memory, evidence save/replay.

## Global Constraints

- Only the external UART RX byte is fuzzable; CPU program, CPU IRQ input, and UART outputs are fixed, bound, or observed.
- Keep independent CPU and UART harnesses and local clocks; do not create a SoC or claim global cycle-accurate timing.
- Preserve real CPU SETUP and RXREG transactions; no harness-owned startup writes or RX reads in CPU-routed mode.
- Do not change `docs/LOCAL_HARNESS_RUNTIME.md`; the parent agent will merge the capability matrix.
- Do not stage or commit files.

---

### Task 1: Specify and fail the AXI-Lite UART CPU-read obligation

**Files:**
- Modify: `tests/local_harness/test_axil_uart_pending.py`
- Create: `tests/local_harness/test_axil_uart_routed_identity.py`
- Test: the two focused files above

**Interfaces:**
- The generated UART session will accept `cpu_routed_mode=True` only with a genome source, no constructor source, no startup writes, and no automatic RX read.
- In that mode, `pending_events` remains nonzero after the serial frame until a CPU-routed read of RXREG offset `8` completes.
- Its identity includes `cpu_routed_mode=True` and a distinct service schema version that evidence validation recognizes.

- [x] Add focused constructor/identity and pending-event tests for the missing CPU-routed behavior.
- [x] Run the focused tests and confirm they fail because the CPU-routed API/obligation is absent.

### Task 2: Implement the minimal CPU-routed obligation

**Files:**
- Modify: `src/myfuzz/local_harness/axil_uart_session.py`
- Modify: `src/myfuzz/scenario/contracts.py`
- Test: `tests/local_harness/test_axil_uart_pending.py`, `tests/local_harness/test_axil_uart_routed_identity.py`

**Interfaces:**
- Mirror the bounded mode already used by `GeneratedWishboneUartSession` and `GeneratedOpentitanUartSession`.
- Do not add general transaction state: mark only whether the single genome source's RXREG read completed.

- [x] Add mode validation, identity/version fields, and `_rx_read` reset behavior.
- [x] Count an outstanding event until an actual offset-8 CPU read; leave legacy standalone and auto-read scenarios unchanged.
- [x] Extend strict generated-session identity validation for the new mode.
- [x] Run focused AXI-Lite UART session tests and existing AXI-Lite UART integration tests.

### Task 3: Add the new real-RTL M_EXT scenario

**Files:**
- Create: `tests/integration/test_scenario_cva6_generated_zipcpu_axiluart_rx_mext_irq_real.py`
- Test: the new scenario under `MYFUZZ_SCENARIO_REAL=1`

**Interfaces:**
- Reuse `GeneratedCva6Axi4Session`, `GeneratedAxiLiteUartSession(cpu_routed_mode=True)`, `DataflowRouter`, `Binding`, and existing CVA6 M_EXT firmware encoders.
- Scenario input is one genome-owned 8-bit `uart_rx_byte`; `uart.uart_rx_int` binds to one-bit `cpu.irq_external`.
- Main firmware installs a direct M_EXT vector, enables MEIE/MIE, writes UART SETUP=25 through CPU MMIO, then waits for the ISR. ISR reads RXREG=8, stores received byte and `mcause` in RAM, records a completion marker, and returns with MRET; main records post-MRET continuation.
- Run seed `0x35` and mutated `0xA6`, preserving firmware and trigger identity; save and replay each evidence bundle with fresh sessions.

- [x] Add assertions for IRQ ownership, actual SETUP and RXREG MMIO deliveries, IRQ high-before-read/low-after-pop, M_EXT cause, ISR RAM writes, MRET continuation, source mutation, and fresh replay.
- [x] Confirm all cases use only the real UART RX byte as a source and never auto-read RXREG.

### Task 4: Record acceptance and rerun regressions

**Files:**
- Create: `docs/reports/generated-cva6-zipcpu-axiluart-rx-mext-irq-20261005.md`
- Do not modify: `docs/LOCAL_HARNESS_RUNTIME.md`

**Interfaces:**
- Report exact source profiles, session identities, local-clock limitation, verified IRQ/MMIO/RAM/replay evidence, commands, and unclaimed physical-topology behavior.

- [x] Run the new real RTL scenario, focused AXI-Lite UART tests, CVA6 M_EXT regression, and the existing CVE2 AXI-Lite UART scenario.
- [x] Record actual command output and acceptance boundaries in the report.
- [x] Confirm `git diff --check`; leave all work unstaged.
