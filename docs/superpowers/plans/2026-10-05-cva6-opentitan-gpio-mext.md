# Generated CVA6 + OpenTitan GPIO M_EXT ISR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the generated CVA6 M_EXT gap with a real external GPIO edge that traverses OpenTitan GPIO RTL, enters the CVA6 machine-external ISR, is recorded in persistent RAM, and replays on fresh harnesses.

**Architecture:** Run CVA6 packed AXI4 and OpenTitan GPIO TL-UL in separate generated local harnesses. The CPU configures GPIO through the existing MMIO DataflowRouter; only external `gpio_in[7:0]` is fuzzable. Bind the real held GPIO IRQ to CVA6 `irq_external`; keep `irq_timer=0` and all unrelated interrupt inputs inactive. Do not add a PLIC, bus fabric, or global cycle model.

**Tech Stack:** Pinned CVA6/OpenTitan GPIO RTL, `GeneratedCva6Axi4Session`, `GeneratedOpentitanGpioSession`, `ScenarioRunner`, `DataflowRouter`, dependency-aware mutation, bounded evidence bundles, and fresh replay.

## Global Constraints

- Use `configs/cpus/cva6/component_profile.json` and `configs/peripherals/opentitan_gpio_local/component_profile.json`; do not edit generic profiles or runtimes for this scenario.
- Keep CVA6 and OpenTitan GPIO in separate generated harnesses with their native local interfaces and clocks.
- Bind only real `gpio.irq` to scalar `cpu.irq_external`; keep `cpu.irq_timer=0` and the unused supervisor/external inputs inactive.
- The only Genome source is external `gpio.gpio_in[7:0]`. CPU interrupt input and GPIO outputs/status remain bound or RTL-derived and cannot be fuzzed.
- Trigger from the CPU's observed AXI AW handshake at `awaddr=0x4000002c`; use a delay measured in CPU-local ticks, and separately assert that the routed MMIO delivery of the rising-enable write precedes source injection. The AW observation alone is not write-commit evidence.
- Seed `gpio_in=0x01` and mutate bit 7 to `0x81`. Both values create a real pin-0 low-to-high edge while preserving a distinguishable upper-bit payload in GPIO `DATA_IN`.
- CVA6 sets direct `mtvec=0x10100`, enables `mie.MEIE` bit 11 and `mstatus.MIE`, and executes the ISR only after actual bound GPIO IRQ assertion. Construct MEIE with a sign-safe sequence (`LUI 1; ADDI -2048`), since `ADDI 0x800` sign-extends to -2048. ISR evidence must include actual `mcause=0x800000000000000b`.
- ISR reads real `INTR_STATE` and `DATA_IN`, records those values and 64-bit `mcause` in persistent RAM, clears GPIO bit 0 by W1C to `INTR_STATE`, reads back zero, stores an ISR completion flag, and executes MRET. Main code polls that flag and writes a distinct post-return marker; the test checks this marker appears after the ISR flag to prove execution resumed after MRET. Keep ISR scratch registers disjoint from main's polling registers or preserve them explicitly.
- Preserve epoch-zero state within each testcase; do not reset between setup, external edge, IRQ, ISR, and replay comparison. Full replay uses fresh CPU and GPIO sessions.
- Do not claim PLIC behavior, complete SoC timing, other CVA6 IRQ classes, all GPIO pins/edge modes, or coverage-guided bug discovery.
- Do not stage or commit; Git actions remain deferred by the user.

## Files

- Create `tests/integration/test_scenario_cva6_generated_opentitan_gpio_mext_irq_real.py`.
- Create `docs/reports/generated-cva6-opentitan-gpio-mext-irq-20261005.md`.
- Update `docs/LOCAL_HARNESS_RUNTIME.md` only after the real RTL acceptance passes.
- Append progress to `.superpowers/sdd/progress.md` only after independent review is clean.

## Task 1: GPIO external edge to generated CVA6 M_EXT ISR

- [x] Build artifacts from the CVA6 and OpenTitan GPIO profiles. Use `GeneratedCva6Axi4Session(..., defer_mmio=True, command_timeout_seconds=60)` with `PersistentMemory(regions=(MemoryRegion('ram', 0, 0x40000),), initialization_seed=0, max_initialized_bytes=0x40000)`; this covers the boot image at `0x10000`, ISR at `0x10100`, and result RAM at `0x20000`. Route the `0x40000000..0x40000fff` window to `GeneratedOpentitanGpioSession`.
- [x] Compile ownership for `cpu.irq_external` as bound to `gpio.irq`, `cpu.irq_timer` as fixed zero, `gpio.gpio_in[7:0]` as source `external_gpio_pins`, GPIO input bits `[31:8]` as fixed zero, and `gpio.strap_en` as fixed zero. Bind `Binding('gpio', 'irq', 'cpu', 'irq_external', 1)`.
- [x] Construct a CVA6 image at boot address `0x10000` by preserving the first 16 bytes of `third_party/docs/task-13/cva6-fixed/run/boot/boot.bin` and appending RV64 instructions. The program must enable `mtvec=0x10100`, `mie.MEIE=1`, and `mstatus.MIE=1`; write `INTR_ENABLE 0x04=1` and rising-edge enable `INTR_CTRL_EN_RISING 0x2c=1`; then wait in a stable loop.
- [x] Place the ISR at `0x10100`. It loads GPIO base `0x40000000` and result base `0x20000`, reads `INTR_STATE 0x00`, `DATA_IN 0x10`, and CSR `mcause 0x342`; stores status, input, and full 64-bit cause to RAM offsets `0, 4, 8`; writes W1C value `1` to `INTR_STATE`; reads the cleared state to offset `16`; writes ISR completion flag `0x55` to offset `20`; then executes MRET. Main code polls offset `20` and, after observing `0x55`, writes post-return marker `0x66` to offset `24`. ISR scratch registers must not clobber the main polling registers.
- [x] Create a seed `ScenarioGenome` with direction `IP_TO_CPU`, schedule `('cpu', 'gpio')`, and one `gpio_in` action of value `0x01`, `bit_offset=0`, and `width=8` (the upper 24 input bits are fixed and must not be included in source injection). Trigger it from the CPU's observed `awaddr=0x4000002c` AXI AW handshake, with `delay_component='cpu'` and a bounded CPU-local delay that permits the TL-UL write to commit. Independently assert the actual `mmio_delivery` for `(offset=0x2c, write_value=1)` precedes source injection. Build a `DependencyGraph` from an 8-bit `external_gpio_pins` source to `gpio.data_in` and `gpio.irq`, then to `cpu.result_ram`; use `choose_mutation` to select the source and `mutate_genome(..., bit_index=7)` to create `0x81`.
- [x] Bound each Genome to at most 3000 runner steps and use `ResourceBudget(max_transactions=2048, max_local_cycles_per_component=8192, max_scheduler_steps=12000, max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x40000, max_evidence_bytes=64*1024*1024)`. Assert exactly one source injection; setup writes precede injection; the real GPIO IRQ reaches CVA6 while `irq_timer` remains zero; ISR RAM contains status `1`, `DATA_IN` equal to `0x01` or `0x81`, and `mcause=0x800000000000000b`; W1C readback is zero; IRQ subsequently goes low; the post-return marker is written only after the ISR completion flag; no in-test reset occurs; and all routed CPU transactions are unique in epoch zero.
- [x] Save bounded bundles for both variants and require full semantic replay equality on fresh CVA6 and GPIO sessions. Verify each fresh replay preserves its own RAM result and starts at reset epoch zero.
- [x] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cva6_generated_opentitan_gpio_mext_irq_real.py`; require one passing test covering both source variants and both full replays. If the test reveals a timing issue, measure the actual per-component event order and change only the declared local delay; do not alter DUT output or synthesize the interrupt.
- [x] Write the report with the exact command, source values, actual `mcause`, MMIO/IRQ order, W1C result, replay result, reset/timing boundary, and limits. State that this closes one fixed generated CVA6/OpenTitan GPIO M_EXT combination and does not prove general CVA6 interrupt-controller or SoC support.

## Task 2: Runtime capability documentation

- [x] Add a `CVA6 ↔ OpenTitan GPIO M_EXT` matrix row and report link after Task 1 passes. Update the CVA6 summary to distinguish the existing M_TIMER case from this single M_EXT case.
- [x] Add a concise paragraph describing the real `gpio_in[7:0]` source mutation (`0x01→0x81`), GPIO `irq` binding to `irq_external`, W1C, 64-bit `mcause`, fresh replay, and the fixed-scope limitations.
- [x] Run `git diff --check`; leave all files uncommitted.
- [x] Append task completion to `.superpowers/sdd/progress.md` after independent review is clean.
