# CV32E40P OpenTitan SPI Host MEI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that a fuzzed external SPI word traverses real OpenTitan SPI Host RTL, raises its native M_EXT interrupt, is read by a real CV32E40P ISR, persists in RAM, and replays on fresh harnesses.

**Architecture:** Keep CV32E40P and OpenTitan SPI Host in separate generated local harnesses. The SPI source word is the only fuzzable source; Host `irq_event` is bound to CPU `irq`, and CPU MMIO writes/reads are produced by real OBI execution and routed through the existing transaction layer. Do not add protocol templates or global timing behavior.

**Tech Stack:** Pinned CV32E40P and OpenTitan RTL, generated OBI/TL-UL harnesses, `ScenarioRunner`, `DataflowRouter`, `DependencyGraph`, `ScenarioGenome`, bounded evidence bundles, and fresh-harness replay.

## Global Constraints

- Keep each DUT in its own generated harness and preserve its native local protocol, state, and timing.
- Preserve the existing `configs/cpus/cv32e40p/component_profile.json` MEI mapping to physical `irq_i[11]`.
- Bind `spi_host.irq_event` to `cpu.irq`; never fuzz the bound CPU IRQ or synthesize the Host IRQ.
- Fuzz only `spi_host.spi_source_word`, whose actual value enters the existing SPI peer and real RTL.
- Keep CV32E40P's direct `mtvec` base at 256-byte-aligned `0x10100`; require the first post-ack accepted fetch at `0x10100`, with the `0x1012c` vectored slot looping as a guard.
- Read SPI Host `RXDATA` at `0x24` first in the ISR after the transfer; the current session rejects other Host register accesses until the 32-bit transfer ends and CSB is high.
- Do not clear the SPI event by writing `INTR_STATE`; the RX watermark event is a read-only status bit and should fall when RXDATA is consumed.
- Do not add a Bus/Crossbar/Bridge/Arbiter/PLIC or global cycle-accurate clock.
- Preserve testcase state through execution, require reset epoch zero, and replay each source variant on fresh CPU and Host harnesses.
- Do not promote source-lock runtime status or edit generated runtime/profile files for this scenario.

## Files

- Create `tests/integration/test_scenario_cv32e40p_opentitan_spi_host_irq_real.py` for the two source variants, real ISR checks, bounded evidence, and fresh replay.
- Create `docs/reports/generated-cv32e40p-opentitan-spi-host-irq-20261005.md` for exact commands, outcomes, and capability limits.
- Update `docs/LOCAL_HARNESS_RUNTIME.md` only after the real RTL acceptance passes; add one matrix row and one report reference without changing prior rows.

## Task 1: Add a source-mutation scenario and real RTL acceptance

- [x] Implement a local integration fixture using `GeneratedCve2Session` with `configs/cpus/cv32e40p/component_profile.json` and `GeneratedOpentitanSpiHostSession` with `configs/peripherals/opentitan_spi_host_local/component_profile.json`, `source=None`, and `cpu_routed_mode=True`.
- [x] Compile ownership with `cpu.irq` bound to `spi_host.irq_event` and `spi_host.spi_source_word` as a 32-bit `IP_TO_CPU` source named `external_spi_source_word`.
- [x] Add a `Binding('spi_host', 'irq_event', 'cpu', 'irq', 1)` and an SPI MMIO window at `0x40000000` of size `0x1000`.
- [x] Build the CPU program at `0x10000`: align and install direct `mtvec=0x10100`; enable `mie.MEIE` bit 11 and `mstatus.MIE`; write, in order, CONTROL `0x10=0xa0000001`, CONFIGOPTS `0x18=8`, EVENT_ENABLE `0x34=4`, INTR_ENABLE `0x04=2`, then COMMAND `0x20=0x68`; branch in place while the real Host transfer runs.
- [x] Place a direct-vector jump at `0x10100` to `0x10200`, an infinite-loop guard at vectored slot `0x1012c`, 64 NOPs from `0x10200`, and the ISR at `0x10300`.
- [x] Make the ISR read RXDATA `0x24` before any other Host register, read actual `mcause` CSR `0x342`, store the RX word, cause, and completion marker `0x55` to RAM at `0x20000`, then execute MRET.
- [x] Create a seed Genome with source word `0x12345678`, direction `IP_TO_CPU`, start-triggered source action, schedule order `('spi_host', 'cpu')`, and at most 1800 component-step invocations. The real Host needs at least 641 local ticks for 32 selected samples at the configured 18-tick edge interval, so 600 invocations cannot finish the frame.
- [x] Add dependency rules `external_spi_source_word → spi_host.rx_word` as `DATA_BINDING` and `spi_host.rx_word → cpu.result_ram` as `PERSISTENT_STATE_RULE`; select one target-aware mutation and change source bit 0 so the second word is `0x12345679`.
- [x] Run both Genomes through evidence saving with a per-case transaction cap of 512, per-component local-tick cap of 2048, total local scheduler-tick cap of 4096, and wall cap of 300 seconds; bound materialized memory and evidence bytes. These are scenario resource bounds; component ticks remain independent and do not define global SoC cycles.
- [x] Assert for each trace: `complete`; exact CPU-originated SPI setup/command writes once; exactly 32 peer sample edges and four payload bytes; actual Host IRQ high delivered to CPU; CV32E40P samples IRQ high and acknowledges ID 11; first accepted post-ack fetch is `0x10100`; ISR reads actual `RXDATA`; RAM contains byte-order-correct SPI data, `mcause=0x8000000b`, and marker `0x55`; consuming RXDATA is followed by a real Host IRQ-low sample; no reset barrier or nonzero reset epoch.
- [x] Assert the seed and mutated words lead to distinct expected RAM values; save each bounded bundle and require fresh-harness full replay equality, including a fresh CPU and SPI Host session for each replay.
- [x] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_spi_host_irq_real.py` and require one passing test that covers both source variants and both full replays.

## Task 2: Record verified scope

- [x] Write the report with the exact test command, both source values and RAM results, observed IRQ/ack/cause, sample and payload counts, replay results, and reset/timing boundary.
- [x] State that this validates one pinned CV32E40P OBI profile plus one pinned OpenTitan SPI Host TL-UL profile; it does not validate PLIC/topology, all SPI modes, arbitrary same-protocol CPUs/IP, or coverage-guided bug discovery.
- [x] Add the verified matrix row and report reference to `docs/LOCAL_HARNESS_RUNTIME.md` only after Task 1 passes.
- [x] Run `git diff --check`; do not stage or commit files.
