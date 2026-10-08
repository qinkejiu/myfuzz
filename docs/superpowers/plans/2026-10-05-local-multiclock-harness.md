# Local harness support for multiple clock and reset domains

### Task 1: Add a deterministic component-local multi-clock runtime

**Files:**
- Modify: `src/myfuzz/local_harness/port_rendering.py`
- Modify: `src/myfuzz/local_harness/runtime_renderer.py`
- Modify: `src/myfuzz/local_harness/driver_renderer.py`
- Modify: `src/myfuzz/local_harness/wire.py`
- Modify: `src/myfuzz/local_harness/session.py`
- Add focused local-harness tests and a small synthetic dual-clock RTL fixture.
- Update: `docs/LOCAL_HARNESS_RUNTIME.md`

**Goal:**

Use the already declared `ClockBinding` and `ResetBinding` entries to run a
single DUT with multiple genuine clock and reset ports. One session step remains
local to that DUT and advances its fastest declared clock once. Other clocks
advance according to a deterministic, artifact-identified frequency schedule.
This does not synchronize steps across separate DUT harnesses.

**Initial supported schedule:**

- Frequencies must be positive integers and every slower clock must divide the
  fastest frequency exactly.
- Ratios must be even and at most 1024; otherwise planning rejects the profile
  with a stable unsupported-schedule error.
- Clock domains start in a fixed documented phase and remain separate signals.
- Every reset port keeps its declared polarity. Resets without a declared
  release dependency may assert and deassert together. Ordered reset release
  remains rejected.
- Reset assert/release lengths count fastest-clock periods. The planner/runtime
  must ensure each declared domain receives a reset edge before READY.
- Trace samples carry the fastest local tick and per-domain edge counts so
  causality can be replayed and inspected.
- Single-clock/single-reset artifacts retain their current behavior and wire
  compatibility.

**Verification:**

Build and run a synthetic two-clock/two-reset DUT whose counters expose the
measured edge counts, asynchronous reset behavior, and stable phase across
multiple commands. Verify initial startup and explicit reset, full fresh replay,
and that invalid ratios and reset sequencing are rejected before RTL starts.
Run the existing single-clock request, source-lock, driver, and generated RTL
regressions.

### Task 2: Adapt OpenTitan sysrst_ctrl using the multi-clock runtime

**Files:**
- Add: `configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json`
- Add: scalar RTL wrapper, pinned source closure and dedicated verifier.
- Add: local contract and real RTL integration tests.
- Update: `docs/LOCAL_HARNESS_RUNTIME.md`
- Add: `docs/reports/generated-opentitan-sysrst-ctrl-20261005.md`

**Goal:**

Run the pinned OpenTitan `sysrst_ctrl` RTL with its true `clk_i`/`clk_aon_i`
and `rst_ni`/`rst_aon_ni` domains. The initial profile uses the source-declared
24 MHz and 200 kHz rates (ratio 120), declares source-owned physical event pins,
retains typed alert defaults and exports all IRQ, wakeup, reset-request and pin
outputs. `rst_req_o` is observed as a DUT result and is never fed back into the
DUT reset. A real TL-UL event configuration and pin transition must produce
real status/IRQ or wakeup behavior and fresh replay evidence.

No equal-clock alias, reset feedback loop, PLIC, bus bridge, or global SoC clock
model is allowed. The component-local frequency and phase policy is explicit in
the artifact identity and tests.

**Acceptance:**

The generated local harness authenticates every source, port, wrapper byte,
clock ratio and reset mapping. A real testcase configures a key event through
TL-UL, changes only its declared external source pin after configuration,
observes the synchronized event through local AON/bus clocks, reads the actual
status, checks native IRQ/wakeup output against independent RTL-derived
properties, and fresh-replays the complete trace. Multi-clock synthetic checks
and existing single-clock adapter tests pass.
