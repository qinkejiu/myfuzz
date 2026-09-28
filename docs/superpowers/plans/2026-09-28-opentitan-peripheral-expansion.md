# OpenTitan Peripheral Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans`. Work task by task, write a failing test before implementation, and review each deliverable.

**Goal:** Add real OpenTitan SPI Host, I2C and then RV Timer as independent persistent RTL sessions that participate in dependency-aware CPU/IP scenarios.

**Architecture:** Each IP owns one native RTL process and local protocol timing. The existing Runner routes real MMIO data and IRQ, while a source-specific external peer supplies only unbound environment inputs. A testcase keeps RTL/FIFO/memory state across rounds and replays from initial state.

**Tech Stack:** Python ScenarioRunner and source bindings, SystemVerilog OpenTitan RTL, C++ Verilator local process harness, JSON source lock/profile, unittest evidence/replay.

**实施状态（2026-09-28）：** SPI Host、I2C、RV Timer 的独立真实 RTL 会话、两轮 Ibex 跨组件链、切断 IRQ 负例、可信 RFuzz 变异源映射和固定全量回放均已完成。实测命令、结果与仍受限的模式见 `docs/reports/opentitan-peripheral-expansion-20260928.md`。新 closure 文件尚未纳入 Git 跟踪，正式 source-lock tracked-evidence 门槛仍待提交这些文件后复核。

## Global constraints

- No generated SoC fabric, bridge, arbiter or global cycle-accurate timeline.
- Do not mutate an input already bound to real RTL output or persistent state.
- Preserve local TL-UL/SPI/I2C timing and transaction identity; observe DUT outputs without synthesizing them.
- Only claim an IP's real RTL behavior after local build, directed execution and independent replay succeed.
- Do not edit `third_party/soc-opentitan` vendor RTL.

## Task 1 — Lock the SPI Host RTL closure

**Files:** create `configs/peripherals/opentitan_spi_host/component_profile.json`, `configs/soc/closures/opentitan_spi_host.json`; modify `configs/soc/sources.lock.json`; test `tests/integration/test_scenario_opentitan_spi_host_real.py`.

**Interfaces:** profile `source.files` is the exact ordered Verilator file list consumed by `OpenTitanSpiHostSession._binary()`; `source.include_roots` supplies only pinned include directories. Record vendor revision `git:fca045df919a26c47e71616b9dac917b1ea4fd07` and hashes of every actual source.

- [ ] Write a test that reads the closure/profile and rejects a missing `spi_host.core` dependency, duplicate file, missing file or hash mismatch. Confirm RED.
- [ ] Resolve `spi_host.core` files plus `spi_device_pkg`, TL-UL socket/adapter/FIFO and required prim packages/modules; record exact order and hashes. Do not copy UART's file list blindly.
- [ ] Run Verilator elaboration with a minimal independent wrapper. Confirm GREEN and save command, warnings and source identity.
- [ ] Review that no generated Bus/Crossbar/PLIC appeared in the wrapper.

## Task 2 — Real SPI Host local session

**Files:** create `src/myfuzz/scenario/rtl/local_opentitan_spi_host.sv`, `src/myfuzz/scenario/rtl/local_opentitan_spi_host_main.cpp`, `src/myfuzz/scenario/spi_host_session.py`; test `tests/integration/test_scenario_opentitan_spi_host_real.py`.

**Interfaces:** `OpenTitanSpiHostSession` implements `prepare_local`, `begin_case`, `reset_local`, `step_local(inputs: Mapping[str,int])`, `write_register`, `read_register`, `pending_events`, `pending_responses`, `end_case`, `identity_document`. `step_local` accepts only `spi_sd_i` as an environment source and returns real `sck`, `csb`, `sd_out`, `sd_en`, `irq_event`, `irq_error`, `rdata`, `error`.

- [ ] Write RED tests for startup, legal TL-UL byte enables, real register reads, and rejected undeclared inputs.
- [ ] Build a wrapper around real `spi_host` with `beat_to_tlul`; tie alert/RACL/passthrough to safe fixed values and keep NumCS=1. The C++ process follows execution ID/sequence idempotency and returns real observed ports.
- [ ] Execute directed CONTROL/CONFIGOPTS/STATUS/COMMAND transactions, then inspect SCK/CS and FIFO/IRQ changes. Confirm GREEN.
- [ ] Test two commands within one testcase without reset and compare local tick monotonicity; test lost/repeated command identity.

## Task 3 — External SPI peer and ownership

**Files:** create `src/myfuzz/scenario/spi_peer.py`, test `tests/scenario/test_spi_peer.py`.

**Interfaces:** `SpiPeer` consumes observed `sck`, `csb`, configured CPOL/CPHA and a persistent four-byte payload. It produces only the next legal `spi_sd_i` value, placing MISO on bit 1. `reset_case` is allowed only at testcase start or explicit reset.

- [ ] RED: two payloads must produce distinct sampled bit streams; held SCK must not advance bit index; deasserted CS must not consume bits.
- [ ] Implement edge-driven CPOL=CPHA=0 standard mode with stable data before rising edge; reject unsupported modes explicitly.
- [ ] GREEN: confirm exactly 32 real sampling edges and expected byte order `b0 | b1<<8 | b2<<16 | b3<<24` through RTL, not by peer prediction alone.

## Task 4 — Ibex ↔ SPI Host continuous chain

**Files:** create `src/myfuzz/scenario/ibex_spi_host_example.py`, `configs/scenario/ibex_spi_host_two_rounds.json`; modify only necessary ownership/router/host identity declarations; test `tests/integration/test_scenario_ibex_spi_host_chain_real.py`.

**Interfaces:** Runner maps CPU MMIO window to Host native register accesses, binds real `irq_event` to CPU IRQ, and binds Host read response to CPU rdata. SourceBindings declare CPU program image and each peer payload as upstream fuzzable sources. No direct Fuzzer SPI register/CPU IRQ/rdata drive.

- [ ] RED: checker rejects missing Host IRQ edge, fabricated rdata, stale response ID and second-round reset.
- [ ] Create a legal Ibex program/ISR that configures Host, issues a four-byte read twice, reads real RXDATA, writes each value to persistent RAM and clears status by real FIFO drain/event change.
- [ ] GREEN: two rounds complete with distinct payloads, real SCK/CS/RXDATA/IRQ, and exact CPU RAM values; cut-edge negative cases fail.
- [ ] Record a fixed evidence bundle and replay in a fresh process with equal event trace, local ticks and state hashes.

## Task 5 — I2C after SPI Host review

**Files:** new `opentitan_i2c` profile/closure/session, open-drain peer and two-round Ibex fixture under matching `configs/peripherals`, `src/myfuzz/scenario`, `tests/integration` paths.

- [ ] Review SPI Host evidence and freeze the I2C Controller-mode local port contract: SCL/SDA open-drain low or release, external ACK/data slots and bounded stretch.
- [ ] RED: peer cannot drive high, change data in invalid phase or assert fabricated FIFO/IRQ values.
- [ ] Build and run real I2C RTL, then complete CPU config→external peer→real RX/IRQ→CPU chain twice, cut-edge negatives and fresh-process replay.

## Task 6 — RV Timer independent chain

**Files:** create `configs/peripherals/opentitan_rv_timer/component_profile.json`, `configs/soc/closures/opentitan_rv_timer.json`, `src/myfuzz/scenario/rtl/local_opentitan_rv_timer.sv`, `src/myfuzz/scenario/rtl/local_opentitan_rv_timer_main.cpp`, `src/myfuzz/scenario/rv_timer_session.py`, `src/myfuzz/scenario/ibex_timer_example.py`; tests `tests/integration/test_scenario_opentitan_rv_timer_real.py`, `tests/integration/test_scenario_ibex_timer_chain_real.py`.

- [ ] RED: real timer IRQ absent before CPU-origin compare/control writes; byte-enable and pending state survive local steps.
- [ ] Lock the 3 local RV Timer RTL files plus dependencies, build native TL-UL wrapper and persistent session.
- [ ] GREEN: CPU configures CFG/COMPARE/CTRL, real Timer IRQ reaches CPU, ISR reads state and updates compare, then repeats without reset. Include cut IRQ negative and independent replay.
- [ ] State explicitly that Timer has no external fuzzable pin, so this chain does not satisfy IP-external→CPU coverage by itself.

## Delivery gate

For each IP, publish its exact source identity, build command, test commands and counts, observed native outputs, failed negative controls, replay scope and remaining unsupported modes. Mark unimplemented IPs `not_run`; mark locally missing PWM `skipped_unavailable`.
