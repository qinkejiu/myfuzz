# Generated CVA6 MMIO Peripheral Routing Implementation Plan

> **For agentic workers:** Use the `test-driven-development` workflow, write a failing real-RTL test before changing production code, and review the finished diff.

**Goal:** Let the generated CVA6 packed AXI4 CPU session access a real independent IP through `DataflowRouter`, while preserving AXI handshakes, persistent RAM, and fresh-process replay.

**Architecture:** Keep CVA6 as the only AXI master RTL in its own harness. The CPU session classifies accepted addresses against declared RAM and MMIO windows; RAM remains serviced by `MemoryService`, while MMIO requests are queued to the target harness and serviced by that DUT's native protocol session. The target's real read response returns over CVA6's original AXI response channel.

**Tech Stack:** Generated packed AXI4 runtime, Python ScenarioRunner/DataflowRouter/TransactionLedger, pinned CVA6 and OpenTitan GPIO RTL, `ScenarioGenome` evidence replay.

## Global Constraints

- Preserve one testcase lifetime and existing CVA6 AXI IDs, burst accounting, WSTRB, and response checks.
- Keep CPU and IP RTL in separate generated harnesses; add no SoC bus, bridge, arbiter, PLIC, or global cycle-accurate clock.
- Return peripheral read data only from the target RTL session.
- Retain one in-flight MMIO target operation at a time and reject unsupported subword or misaligned peripheral accesses.
- Keep RAM transactions and MMIO target transactions on independent ledgers so queued MMIO cannot block instruction fetch service.
- Replay the full initial program and testcase state in new CPU and IP harness instances.

---

### Task 1: Demonstrate generated CVA6 to real OpenTitan GPIO routing

**Files:**
- Create `tests/integration/test_scenario_cva6_generated_opentitan_gpio_real.py`
- Modify `src/myfuzz/local_harness/cva6_axi4_session.py`
- Modify `docs/LOCAL_HARNESS_RUNTIME.md`
- Create `docs/reports/generated-cva6-opentitan-gpio-20261005.md`

**Interfaces:**
- `GeneratedCva6Axi4Session(..., router: DataflowRouter | None = None, defer_mmio: bool = True)`
- `router` remains optional for current RAM-only callers.
- CVA6 `SW`/`LW` accesses to the declared GPIO window use `DeviceWindow`; all other supported reads/writes use existing `MemoryService`.
- Deferred MMIO completion fills the existing AXI R/B state only after `ScenarioRunner` runs the GPIO target harness.

- [ ] Write the real acceptance first. Boot pinned CVA6, write OpenTitan GPIO DOUT/OE, read DOUT through GPIO RTL, and store it to persistent RAM; use the full real source profiles and an evidence replay factory.
- [ ] Run the acceptance and confirm it fails because the generated CVA6 session has no router argument.
- [ ] Add router ownership, an independent MMIO transaction ledger, and a source sequence for routed requests.
- [ ] Queue one real target access after accepted AXI transactions; hold CVA6 R/B valid low until the target callback returns its true response.
- [ ] Keep target-ready backpressure active while an MMIO request is queued. Ensure memory fetches use their separate ledger.
- [ ] Pass the real acceptance and existing CVA6 RAM/replay tests.
- [ ] Document verification commands and scope limits; run `git diff --check`.

## Acceptance Criteria

- The CPU performs at least one real accepted AXI write and one AXI read to OpenTitan GPIO.
- GPIO DOUT/OE physical outputs equal the CPU-written values.
- The CPU's real GPIO read response is written unchanged into persistent RAM.
- Every MMIO transaction is delivered exactly once, with the CPU transaction identity preserved in evidence.
- CPU and GPIO each run in independent harness processes, with no reset barrier inside the testcase.
- Fresh CPU/GPIO sessions replay the trace and persistent memory result.
- Existing generated CVA6 RAM Store→Load→Store and source-lock/runtime tests continue to pass.
