# CV32E40P + OpenTitan I2C Command-Complete MEI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify a Genome-selected I2C peer response is received through real OpenTitan I2C RTL, raises native command-complete IRQ, is read by a CV32E40P ISR, persists in RAM, and replays from fresh harnesses.

**Architecture:** Keep the pinned CV32E40P OBI CPU and OpenTitan I2C TL-UL peripheral in separate generated local harnesses. The external peer byte is the only fuzzable source; real CPU MMIO commands start the I2C transaction, and I2C's native `irq_o[9]` is bound to CV32E40P's MEI input at physical bit 11. The byte is admitted to the local peer before execution, which only configures the environment peer. The CPU's first FDATA command queues START/address and initiates pad activity; the second queues READ/STOP and consumes the actual peer byte through I2C RTL.

**Tech Stack:** Pinned OpenHW CV32E40P/OpenTitan RTL, generated OBI/TL-UL harnesses, `GeneratedOpentitanI2cSession`, `ScenarioRunner`, `DataflowRouter`, dependency graph/genome mutation, bounded evidence bundles, fresh-harness replay.

## Global Constraints

- Keep each DUT in its own generated harness and preserve its native local protocol, state, and timing.
- Preserve the existing CV32E40P MEI mapping to physical `irq_i[11]`; do not use the separate MTI profile.
- Bind only the real OpenTitan I2C `irq_o[9]` command-complete interrupt to CPU IRQ; never fuzz the bound CPU IRQ or synthesize IRQ/output.
- The only fuzzable input is the 8-bit OpenTitan I2C `peer_response` source.
- CPU MMIO timing/config/FDATA writes and ISR register accesses must be real OBI transactions routed to the I2C TL-UL target; the `mcause` read must be a real CPU CSR instruction.
- Admit `peer_response` before a CPU FDATA write because the existing I2C session requires the peer byte before it services FDATA. This configures the external peer only; the first accepted FDATA START/address command initiates pad activity and the second accepted FDATA READ/STOP command starts the read phase.
- Use single-byte read from the existing peer address `0x50`, with the current no-clock-stretch peer behavior.
- Configure `INTR_ENABLE=0x200` to select command-complete bit 9; do not enable RX-threshold, which is not needed for the one-byte ISR scenario.
- Use direct `mtvec=0x10100`, 256-byte aligned, with a jump at the direct entry and an infinite-loop guard at vectored MEI slot `0x1012c`.
- The ISR reads actual `INTR_STATE`, actual `RDATA`, and actual `mcause`; it clears only command-complete bit 9 by writing `0x200` to W1C `INTR_STATE`.
- Do not add a Bus/Crossbar/Bridge/Arbiter/PLIC or global cycle-accurate timing.
- Preserve testcase state, require reset epoch zero and no testcase reset, and replay each source variant on fresh CPU/I2C sessions.
- Do not promote source-lock runtime status or modify generic runtime/profile behavior for this scenario.
- Do not stage or commit files; Git work is deferred by the user.

## Files

- Create `tests/integration/test_scenario_cv32e40p_opentitan_i2c_irq_real.py` for source mutation, ISR, bounded evidence, and replay.
- Create `docs/reports/generated-cv32e40p-opentitan-i2c-irq-20261005.md` for exact command, observations, and limits.
- Update `docs/LOCAL_HARNESS_RUNTIME.md` only after the real RTL acceptance passes.

## Task 1: Peer response to native MEI ISR

- [x] Generate artifacts for `configs/cpus/cv32e40p/component_profile.json` and `configs/peripherals/opentitan_i2c_local/component_profile.json`; construct `GeneratedOpentitanI2cSession` normally, construct `GeneratedCve2Session` with `defer_mmio=True`, and use a `DataflowRouter` window at `0x40000000` of size `0x1000`.
- [x] Compile ownership with CPU scalar IRQ bound from I2C vector bit 9 using `Binding('i2c', 'irq_o', 'cpu', 'irq', 1, source_bit_offset=9)`; declare `i2c.peer_response` as the single 8-bit source `external_i2c_peer`.
- [x] Build CPU code at `0x10000` to install `mtvec=0x10100`, enable MEIE/MIE, write TIMING0..4 at offsets `0x3c,0x40,0x44,0x48,0x4c` with `0x00100010,0x00020002,0x00080008,0x00040004,0x00080008`, write `INTR_ENABLE 0x04=0x200`, `CTRL 0x10=1`, then FDATA `0x1c=0x1a1` and `0x1c=0x601`; wait in a loop.
- [x] Set the direct vector at `0x10100` to jump to an ISR, keep the MEI vectored slot `0x1012c` in an infinite loop, and have the ISR read `INTR_STATE 0x00`, `RDATA 0x18`, and CSR `mcause 0x342`; store those values in persistent RAM; write `0x200` to `INTR_STATE`; read back `INTR_STATE` to verify command-complete cleared; store a completion marker and MRET.
- [x] Seed the START-triggered source at `0x5a`, use schedule order `('i2c','cpu')`, and target-aware mutate source bit 0 to `0x5b`. Define dependency rules from `external_i2c_peer` to `i2c.rdata` (`DATA_BINDING`) and from `i2c.rdata` to `cpu.result_ram` (`PERSISTENT_STATE_RULE`). The START action only installs the environment byte; the test must show the I2C RTL's actual serial transfer follows CPU FDATA commands.
- [x] Use a Genome `max_steps=6000` and `ResourceBudget(max_transactions=512, max_local_cycles_per_component=8192, max_scheduler_steps=12000, max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x20000, max_evidence_bytes=64*1024*1024)`. Require exact one-time CPU config and command writes in order; actual I2C START/address pad activity after the first accepted FDATA write; after the second accepted FDATA write, require actual SCL read clocks and eight contiguous SCL-rising `sda_i` samples matching the selected peer byte MSB-first; native `irq_o[9]` high delivered as scalar 1 to CPU; CPU MEI acknowledgement ID 11; first post-ack accepted fetch at `0x10100`; ISR actual `INTR_STATE[9]=1`, `RDATA` equal to the selected byte, and `mcause=0x8000000b`; RAM contains these observations; W1C `0x200` is followed by actual IRQ bit 9 low and status bit 9 cleared; no reset during the testcase; unique epoch-zero CPU transactions.
- [x] Require seed and mutated source to produce different actual I2C RDATA and RAM values. Save both evidence bundles and require full semantic equality when each is replayed with fresh CPU and I2C sessions.
- [x] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_i2c_irq_real.py` and require one passing test covering both variants and both fresh replays.
- [x] Write the report with exact command, source/RDATA/RAM results, IRQ/ack/vector/cause/W1C observations, replay result, timing/reset boundary, and scope limits. Do not claim PLIC/topology, arbitrary I2C/CPU reuse, multiple-byte/multiple-peer coverage, clock stretching, or coverage-guided bug discovery.

## Task 2: Capability matrix and progress ledger

- [x] Add a specific CV32E40P ↔ OpenTitan I2C command-complete ISR row and report reference to `docs/LOCAL_HARNESS_RUNTIME.md` only after Task 1 passes.
- [x] Update the OpenTitan I2C capability paragraph to distinguish the ISR case from prior polling/data-flow coverage.
- [x] Run `git diff --check` and leave changes uncommitted.
- [x] Append task completion to `.superpowers/sdd/progress.md` after independent review is clean.
