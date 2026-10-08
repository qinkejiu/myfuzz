# CV32E40P OpenTitan RV Timer MTI Implementation Plan

> **For agentic workers:** Use the approved local harness architecture and implement the profile and acceptance case in the files listed below. Keep each step independently verifiable.

**Goal:** Add a real CV32E40P machine-timer interrupt path using a separate single-line MTI profile and the existing OpenTitan RV Timer harness.

**Architecture:** Preserve the existing CV32E40P MEI profile and add a profile variant that binds the single abstract CPU `irq` input to physical `irq_i[7]`. Reuse the generated OBI CPU session, generated OpenTitan RV Timer TL-UL session, ScenarioRunner, DataflowRouter, persistent memory, and fresh-evidence replay; the actual IRQ and register values must come from their RTL.

**Tech Stack:** JSON component profiles; Python `unittest`/`pytest`; generated Verilator harnesses; pinned CV32E40P and OpenTitan RTL.

## Global Constraints

- Each CPU/IP RTL runs in its own generated local harness and retains its native protocol, state, and local timing.
- Keep the existing `configs/cpus/cv32e40p/component_profile.json` MEI mapping on `irq_i[11]` unchanged.
- The new MTI variant exposes only `irq_i[7]` as the one-bit interrupt entry and fixes every other IRQ bit low, including `irq_i[11]`.
- Route the real Timer `irq` output to the CPU input through a `Binding`; do not inject or synthesize the IRQ in the scheduler or CPU session.
- Do not add a bus fabric, PLIC, protocol bridge, arbiter, or global cycle-accurate SoC clock.
- Preserve testcase state until testcase end; require fresh-harness evidence replay and no in-testcase reset.
- Keep the pinned source identity unchanged and do not promote its source-lock `runtime_status`.

## Files

- Create `configs/cpus/cv32e40p_mtimer/component_profile.json` for the MTI-only one-bit IRQ mapping. The generated-harness request contract admits profile paths ending in `component_profile.json`.
- Create `tests/local_harness/test_cv32e40p_mtimer_profile.py` for its profile and generated OBI runtime contract.
- Create `tests/integration/test_scenario_cv32e40p_opentitan_rv_timer_irq_real.py` for the real CPU→Timer→CPU acceptance and replay.
- Create `docs/reports/generated-cv32e40p-opentitan-rv-timer-mti-20261005.md` for scope, evidence, verification, and limits.
- Update `docs/LOCAL_HARNESS_RUNTIME.md` only after the real acceptance command passes.

## Task 1: Define and verify the MTI profile

- [ ] Add the profile contract test first. It must load and plan the new profile, then assert component ID `cv32e40p`, the existing pinned `cv32e40p_core` source declaration, `processor.interrupts` role `machine_timer` on bit `[7:7]`, CPU IRQ entry role `machine_timer`, semantics `machine_timer`, and constant-low coverage for all other `irq_i` bits.
- [ ] Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.local_harness.test_cv32e40p_mtimer_profile -v` and confirm the test fails because the new profile is missing.
- [ ] Add `configs/cpus/cv32e40p_mtimer/component_profile.json` by preserving the existing source, clocks, resets, OBI endpoints, and non-IRQ port actions; change only the interrupt endpoint role/range, IRQ constant ranges, description, CPU interrupt role/semantics, and the mtvec constant reason.
- [ ] Rerun the profile contract command and require it to pass. Also render the new profile as a generated local OBI runtime and verify its sole dynamic physical IRQ export is `irq_i[7]`.

## Task 2: Add the directed real RTL chain

- [ ] Create an opt-in integration test using `GeneratedCve2Session` with the new profile and `GeneratedOpentitanRvTimerSession` with the existing `configs/peripherals/opentitan_rv_timer_local/component_profile.json`.
- [ ] Use a persistent CPU memory region covering program `0x10000`, aligned vector `0x10100`, and result words starting at `0x20000`; route the timer window at `0x40000000` through `DataflowRouter`.
- [ ] Compile ownership for one bound CPU input `irq` and bind `timer.irq` to `cpu.irq`. Do not add a fuzzable CPU IRQ action.
- [ ] The RV32 program must set direct `mtvec=0x10100`, enable `mie.MTIE` with CSR `0x304` bit 7 and `mstatus.MIE` with CSR `0x300` bit 3, then configure compare low/high at timer offsets `0x118`/`0x11c`, enable `INTR_ENABLE0` at `0x100`, and start the Timer through `CTRL` at `0x004`.
- [ ] Put an explicit direct-vector entry at `0x10100`; make the interrupt-7 vectored slot at `0x1011c` stop in a self-loop so vectored entry cannot accidentally reach the real handler.
- [ ] The ISR must read actual `INTR_STATE0` at `0x104`, actual count at `0x110`, read `mcause` CSR `0x342`, store the values to result RAM, disable/stop the timer, W1C `INTR_STATE0`, verify the real cleared state, write a completion marker, and `MRET`.
- [ ] Save a bounded evidence bundle and replay it on fresh CPU and Timer harnesses. Use scheduler order `('cpu', 'timer')` so both local harnesses advance while the CPU waits; do not assert a common global cycle.
- [ ] Assert a real Timer IRQ producer-high sample, its delivery to CPU `irq`, a CPU sample with `irq_ack_o=1`/`irq_id_o=7`, the first accepted post-ack CPU fetch at `0x10100`, real ISR MMIO reads/writes, `mcause=0x80000007`, Timer status/count and W1C results in RAM, unique transaction identities, reset epoch zero, no reset barrier, and fresh replay equality.
- [ ] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_rv_timer_irq_real.py` and require one passing real RTL test including replay.

## Task 3: Record the verified boundary

- [ ] Write the report with the exact command and observed result, explain that the profile is a single-line MTI variant, state that the current MEI profile remains separate, and list untested PLIC/SoC topology and coverage-guided bug search as limits.
- [ ] Add one capability matrix row and a short report reference in `docs/LOCAL_HARNESS_RUNTIME.md` only after Task 2 passes.
- [ ] Run `git diff --check`; do not stage or commit files.
