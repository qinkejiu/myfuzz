# Ibex + OpenTitan I2C Command-Complete MEI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify that the generated OBI harness and OpenTitan I2C integration work with a second real CPU, Ibex: a fuzzed peer byte traverses actual I2C RTL, raises command-complete MEI, is handled by an Ibex ISR, persists in RAM, and replays on fresh sessions.

**Architecture:** Keep pinned Ibex and OpenTitan I2C RTL in separate generated local harnesses. The eight-bit external peer byte is the only fuzzable source. Real Ibex OBI writes configure the OpenTitan I2C TL-UL target and start the serial transfer; real `i2c.irq_o[9]` is routed to Ibex's native machine-external interrupt. Reuse the accepted CV32E40P+I2C protocol path while adapting the CPU boot/vector/ISR program to Ibex's existing profile and vectored interrupt behavior.

**Tech Stack:** Pinned Ibex/OpenTitan RTL, `GeneratedCve2Session` with the Ibex profile, `GeneratedOpentitanI2cSession`, `ScenarioRunner`, `DataflowRouter`, dependency-aware mutation, bounded evidence and fresh replay.

## Global Constraints

- Each DUT must run in its own generated harness with native local protocol, state, and timing.
- Use `configs/cpus/ibex_obi_local/component_profile.json` and `configs/peripherals/opentitan_i2c_local/component_profile.json`; do not change generic profiles/runtime.
- Use `GeneratedCve2Session` for the generated Ibex OBI artifact with `defer_mmio=True`; configure `defer_mmio` only on the CPU session.
- Bind only real I2C native IRQ vector bit 9 to CPU scalar IRQ using `Binding('i2c', 'irq_o', 'cpu', 'irq', 1, source_bit_offset=9)`.
- The only fuzzable input is eight-bit `i2c.peer_response`; never fuzz CPU IRQ or infer peripheral status from the Genome.
- The START action only configures the peer response. CPU FDATA `0x1a1` starts actual START/address pad activity; FDATA `0x601` queues the one-byte read and STOP.
- Keep the single read at address `0x50` and the existing peer's no-clock-stretch behavior.
- Enable only `INTR_ENABLE=0x200`; clear only command-complete W1C bit `0x200`.
- Set Ibex `mtvec` to the aligned vectored base `0x10100`; machine-external interrupt cause 11 enters vector slot `0x1012c`.
- Use real CPU CSR `mcause` read, actual I2C status/RDATA MMIO, persistent RAM writes, W1C readback, and MRET return evidence.
- Preserve scenario state without in-test reset; require reset epoch zero and full fresh CPU/I2C replay for both source variants.
- Do not add a Bus/Crossbar/Bridge/Arbiter/PLIC or global cycle-accurate timing.
- Do not claim arbitrary OBI CPU reuse, all I2C modes, multiple-byte/multiple-peer support, clock stretching, or coverage-guided bug discovery.
- Do not stage or commit; Git actions are deferred by the user.

## Files

- Create `tests/integration/test_scenario_ibex_opentitan_i2c_irq_real.py`.
- Create `docs/reports/generated-ibex-opentitan-i2c-irq-20261005.md`.
- Update `docs/LOCAL_HARNESS_RUNTIME.md` only after real RTL acceptance passes.

## Task 1: Second OBI CPU on the OpenTitan I2C MEI path

- [x] Create artifacts from the Ibex and OpenTitan I2C local profiles. Use `GeneratedOpentitanI2cSession` with default construction and `GeneratedCve2Session(..., defer_mmio=True)` with persistent RAM and a `0x40000000` TL-UL device window of size `0x1000`.
- [x] Declare CPU IRQ as bound to `i2c.irq_o` and the one-byte `peer_response` as the sole fuzzable source `external_i2c_peer`; install binding source bit 9 to CPU IRQ bit 0.
- [x] Build Ibex program at reset fetch address `0x10080`. Set vectored `mtvec` base `0x10100` (Ibex enforces this 256-byte alignment and vectored mode), enable `mie.MEIE` bit 11 and `mstatus.MIE`, write TIMING0..4 at offsets `0x3c,0x40,0x44,0x48,0x4c` with `0x00100010,0x00020002,0x00080008,0x00040004,0x00080008`, write INTR_ENABLE `0x04=0x200`, CTRL `0x10=1`, then FDATA `0x1c=0x1a1` and `0x1c=0x601` once each.
- [x] After both FDATA writes, execute WFI followed by a backward branch. Observe native `core_sleep_o=1` before I2C IRQ and `core_sleep_o=0` after interrupt wake so the test demonstrates low-transaction waiting rather than a spinning CPU.
- [x] Place the machine-external interrupt vector handler at `0x1012c` (vectored slot 11 from base `0x10100`). It must read actual INTR_STATE `0x00`, RDATA `0x18`, and `mcause` CSR `0x342`; save these values to RAM at `0x20000`, write W1C `0x200` to INTR_STATE, read the cleared status, save it and completion marker `0x55`, then MRET.
- [x] Seed peer byte `0x5a` with `Trigger('START')`, schedule `('i2c','cpu')`, and mutate bit 0 to `0x5b`. Add dependency rules `external_i2c_peer → i2c.rdata` (`DATA_BINDING`) and `i2c.rdata → cpu.result_ram` (`PERSISTENT_STATE_RULE`). Assert source admission alone does not produce IRQ; actual serial START/read and result follow CPU FDATA.
- [x] Bound each Genome to `max_steps=6000` and `ResourceBudget(max_transactions=512, max_local_cycles_per_component=8192, max_scheduler_steps=12000, max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x20000, max_evidence_bytes=64*1024*1024)`. Assert real native IRQ bit 9 reaches Ibex and the first accepted interrupt-handler fetch is vectored slot `0x1012c`; read actual `mcause=0x8000000b` in the ISR (the Ibex top/profile does not expose physical IRQ acknowledgement or ID outputs); real status/RDATA match; actual peer SDA bits at eight contiguous read SCL rising edges match the selected byte MSB-first; W1C is followed by real IRQ low and cleared state; RAM values differ between sources; no in-test reset; transaction identities are unique and in epoch zero.
- [x] Save bounded bundles for both sources and require full semantic replay equality on fresh CPU and I2C sessions for each variant.
- [x] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_ibex_opentitan_i2c_irq_real.py`; require one passing test covering both variants and full replays.
- [x] Write the report with exact outcomes and limits. State that this proves one fixed Ibex/OpenTitan I2C combination and a second OBI CPU reuse example; it does not establish profile-only adaptation for every OBI CPU.

## Task 2: Runtime capability documentation

- [x] Add a specific Ibex ↔ OpenTitan I2C command-complete ISR matrix row and report reference after Task 1 passes.
- [x] Update the I2C limitation paragraph to distinguish CVE2 polling and CV32E40P/Ibex ISR scenarios.
- [x] Run `git diff --check`; leave all files uncommitted.
- [x] Append task completion to `.superpowers/sdd/progress.md` after independent review is clean.
