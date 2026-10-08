# PicoRV32 Wishbone / OpenTitan GPIO IRQ Implementation Plan

> **For agentic workers:** Execute the approved task inline; preserve the existing dirty workspace and do not stage or commit.

**Goal:** Accept a real external pin-0 rising edge and pin-7 payload mutation through native OpenTitan GPIO IRQ, the Pico custom IRQ handler, persistent RAM, and fresh evidence replay.

**Architecture:** Two independent generated local harnesses use the existing IRQ-enabled Wishbone CPU profile and GPIO TL-UL profile. `DataflowRouter` delivers the CPU's accepted MMIO to native GPIO register accesses; GPIO IRQ bit 0 binds only CPU `irq[3]`. External low-eight GPIO pins are the sole mutable source. Firmware and result images are fixed.

**Tech Stack:** Python unittest, ScenarioRunner/DependencyGraph, generated Verilator drivers, pinned PicoRV32 and OpenTitan GPIO RTL.

## Global Constraints

- No core, session, profile, source-lock or wrapper changes. Stop and report if those changes are needed.
- No SoC fabric, PLIC, global timing or IRQ pulse policy. Native GPIO IRQ is sticky until W1C.
- CPU IRQ bits 0–2/4–31, GPIO high 24 pins, and strap are fixed inactive.
- Custom `getq`, `maskirq`, `retirq` ABI; q1 is the pending vector, not machine cause.
- Pinned `LATCHED_IRQ=0xffffffff` requires the one-shot handler to mask IRQs after real W1C before returning, so retained pending level cannot overwrite the first observation.
- Run only the focused real RTL acceptance. No staging, commits or dirty-file cleanup.

### Task 1: Real causal acceptance and documentation

**Files:** Create `tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py`; create `docs/reports/generated-picorv32-wishbone-opentitan-gpio-irq-20261005.md`; add one concise matrix row to `docs/LOCAL_HARNESS_RUNTIME.md`.

- [x] Write the acceptance: CPU resets at 0, jumps to main at `0x80`; handler at `0x10` saves real INTR_STATE, DATA_IN and q1 at `0x200`, W1C-clears, records clear readback and `0x55` completion, masks the one-shot IRQ and executes `retirq`. Main polls completion then writes `0x66`.
- [x] RED: omit real rising-edge setup by writing zero to `0x2c`. Execute the exact command below and require failure at `real GPIO IRQ never reached Pico irq[3]` after the actual pin-0 source edge was observed.
- [x] GREEN: change only the rising-edge setup value to one. Source action waits for actual GPIO output (OE already configured). Check all setup deliveries precede injection; native RTL pin/IRQ samples, CPU `irq=8`, `eoi`, handler MMIO, RAM and resumed main form a causal chain.
- [x] Choose the sole source through `DependencyGraph` / `choose_mutation`; use `mutate_genome(..., bit_index=7)` for `0x01` → `0x81`. Accept both only after actual lower pin-0 edge and exact DATA_IN payload are observed.
- [x] Check every MMIO acceptance key matches one delivery, epoch zero, no resets. Save evidence for each payload and replay into fresh CPU/GPIO sessions, checking all acceptance assertions again.
- [x] Record exact RED/GREEN command and output, observed values, no bug found, and limits in the report and matrix.

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real -v
```
