# CV32E40P → ZipCPU DMA → PULP GPIO → CV32E40P ISR

Date: 2026-10-21

## Goal

Add a second CPU instance to the bounded CPU-configured DMA evidence: CV32E40P
programs the existing ZipCPU `wbdmac`, the DMA reads one word from the shared
`PersistentMemory` service and writes that value to PULP GPIO `PADOUT`, the DMA
completion interrupt reaches CV32E40P, and its ISR reads the status and output
back into RAM. Run an independent fresh replay and a wrong-offset refusal.

## Context and choice

Only Ibex currently has a complete measured CPU → DMA → IP → DMA IRQ → CPU ISR
→ fresh replay chain. CV32E40P already has real OBI/IP sessions and IRQ/ISR
fresh evidence, but not CPU-programmed DMA evidence. Reusing PULP GPIO keeps the
target side bounded while adding the second CPU profile to the DMA composition.

The alternatives considered were:

1. **CV32E40P + ZipCPU DMA + PULP GPIO (selected):** reuse the proven PADOUT
   D4 route, generated DMA target, and the CV32E40P direct external-IRQ entry
   pattern. This is the shortest route to measured DMA completion on a second
   CPU. CV32E40P and Ibex both use OBI, so this proves a second CPU instance;
   it does not prove another CPU protocol.
2. **CVA6 + ZipCPU DMA + UART or Caliptra:** adds a packed AXI4 CPU instance,
   but the CPU-to-DMA control path and 64-bit transaction evidence need new
   protocol integration. This remains the next high-impact CPU protocol slice.
3. **CV32E40P + Caliptra SHA256:** adds the second CPU but duplicates more of
   the just-proven Caliptra setup, SHA readback, and typed replay machinery.

## Components and data flow

- CPU profile: `configs/cpus/cv32e40p/component_profile.json`; use the
  `GeneratedCve2Session` OBI runtime, with CV32E40P boot address `0x10000`.
- DMA: generated `zipcpu_wbdmac`; CV32E40P writes source `0x22000`, selected
  destination `0x4000100c`, length one, and keyed start through its real OBI
  route to the D2-declared DMA control window at `0x40002000`.
- Source and result memory: one `PersistentMemory` service visible to CPU and
  DMA, with separate named regions matching D3 geometry: `rom0` at `0x10000`
  of size `0x8000`, and `ram` at `0x20000` of size `0x20000`. The D3
  declaration marks ROM executable and RAM non-executable; runtime
  `PersistentMemory` enforces readable/writable policy but has no execute
  permission field, so this slice makes no runtime execute-protection claim.
  The declared source word is `0x5aa55aa5`; the result words record `mcause`,
  DMA status, GPIO readback, source readback, and success marker.
- Target: the generated PULP GPIO causal profile at `0x40001000`, with only
  full-word write offset `0x0c` and accepted value `0x5aa55aa5` admitted to the
  DMA target window.
- Route: parameterize the existing D2/D3 generator with the CV32E40P profile
  and `rom0` aperture while preserving the helper's current defaults. Keep
  static D3 F6 `unsupported`, prepare and bind the exact live runtime path once through the
  existing D4 topology admission, and install its one-word route admission.
- Interrupt: bind the real DMA IRQ to CV32E40P `irq`; the Runner holds the
  measured source pulse for 16 CPU ticks. The gate checks the actual CV32E40P
  `irq_ack_o`/`irq_id_o` observation and the ISR's real bus transactions and
  RAM stores. CV32E40P has no RVFI retirement receipts in this profile, so the
  gate makes no retirement claim.
- Fresh run: instantiate distinct CPU, DMA, GPIO, memory, Runner, and route
  owners, replay the exact schedule, and compare full typed semantic evidence
  after normalizing only the declared execution identities.

## Firmware and failure behavior

The firmware starts in the D3 `rom0` aperture at `0x10000`. Source and result
data are in the D3 `ram` aperture. It installs a direct-mode `mtvec` at the
256-byte-aligned address `0x10200`, enables machine external interrupts, writes
DMA source/destination/length/start in that order, and waits. The ISR saves
`mcause`, DMA status, actual PADOUT readback, and the source word. It writes
marker `1` only when status is zero and the two words match; otherwise it writes
`0xffffffff`.

For the negative run, firmware uses `PADOUT+4`. The gate captures the real
Wishbone pre-backend request and requires D4 route admission to refuse before
the GPIO provider/APB phase. It records that refusal separately; it does not
claim the DMA received an RTL bus-error response.

Missing CPU DMA setup, missing or malformed DMA read/write keys, a value
mismatch, missing GPIO effect, missing/incorrect IRQ acknowledgement, missing
ISR stores, a wrong marker, nonzero child process exit, changed fresh semantic
prefix, or a target-provider call in the wrong-offset case fails the gate.

## Boundaries

This is one local CPU/profile/target combination with one DMA word. It uses
transaction-level delivery between independently generated native sessions;
it does not establish a physical Wishbone-to-APB3 bridge, physically shared
SRAM, or a globally cycle-accurate SoC. It does not enable static D3 F6, generic
F6, generic CPU/IP onboarding, arbitrary APB3 behavior, multiword DMA,
continuous fuzzing, remote validation, or aggregate P6/P7/P8 acceptance.

## Acceptance evidence

1. Image tests prove encoded DMA programming order, one-word length, direct
   aligned trap setup, bounded ISR branches, result fields, and success-only
   marker. The native gate proves the actual OBI-visible programming order.
2. Fixture tests prove the exact CPU profile, shared memory object, route
   endpoints, PULP target window, IRQ owner, and 16-tick pulse policy.
3. The local opt-in native positive gate joins CPU OBI configuration and ISR
   accesses, DMA RAM read and PADOUT write keys/responses, PULP APB request/
   effect/response, DMA IRQ source, CV32E40P acknowledgement, and result RAM.
4. A distinct fresh process set replays the identical schedule and its typed
   semantic evidence equals the first run under execution-identity-only
   normalization.
5. The wrong-offset native gate observes the actual request and proves refusal
   before provider dispatch, with no APB request/effect, no IRQ, and no ISR
   success marker.
6. The report records exact commands, identities, audits, evidence paths, and
   limits; current progress and runtime capability docs are updated without
   claiming general DMA, remote, or six-CPU/four-IP completion.
