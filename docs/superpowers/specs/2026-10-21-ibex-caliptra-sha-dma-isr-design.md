# Ibex → ZipCPU DMA → Caliptra SHA256 → Ibex ISR

Date: 2026-10-21

## Goal

Extend the existing single-word Caliptra SHA256 DMA route into a bounded CPU
configured path. Real Ibex OBI writes configure ZipCPU `wbdmac`; the DMA reads
the declared word `5` from shared `PersistentMemory`, writes `5` to Caliptra
SHA256 `CTRL` at `0x40002010`, and emits its native completion IRQ. The Runner
delivers that IRQ to Ibex. The ISR reads DMA status, waits for SHA `STATUS`
valid, reads the eight digest registers, and stores its observations and a
success marker in RAM. The native gate checks the stored digest against
SHA-256(`abc`) and repeats the exact component schedule in fresh processes.

## Chosen approach

Create an isolated Ibex/ZipCPU/Caliptra Runner, firmware image, and native gate.
Reuse the existing Caliptra AHB target provider and D3 route geometry, generate
the D3 artifact with the `ibex_rvfi_local` CPU profile, then use
`compiled_f6_runtime_path.v1` preparation and a single D4 bind. The existing
Caliptra D3 artifact pins `ibex_obi_local`; its profile fingerprint does not
match the live RVFI CPU artifact required for retirement and IRQ-take receipts.
Keep the existing Caliptra-only and Ibex/PULP gates unchanged so their evidence
remains tied to their original fixtures.

The CPU router exposes the DMA register window and the Caliptra AHB register
window. The DMA's declared master target window admits only a full-word write
of value `5` to `CTRL@0x10`; its RAM read must name the selected source word.
The SHA padded `abc` block is installed through the existing measured AHB
register session before the CPU schedule starts. This slice therefore proves
CPU DMA programming and CPU observation of completion/status/digest; it does
not claim the CPU itself prepares the SHA block.
Drain the host AHB setup tick samples into a separate prelude stream before the
first Runner step, and retain the setup offset/value/receipt rows. This prevents
the Runner from attributing those queued host setup frames to the first
scheduled component.

The ISR must poll `STATUS` with a fixed upper bound because a DMA completion IRQ
proves transfer completion, not that SHA has produced its digest. It stores
each digest register in a fixed result layout. The host gate joins the CPU
retirement/readback and DMA/AHB transactions, then independently checks the
stored eight words against the known digest.

## Alternatives considered

1. **Extend the current host-driven Caliptra gate in place.** This would reduce
   duplicate test code, but it would change a frozen gate whose CPU is only a
   placeholder and whose DMA is host programmed.
2. **Add an isolated Ibex–DMA–Caliptra fixture and gate (selected).** This
   reuses the working Ibex/IRQ/fresh-replay pattern and the pinned Caliptra
   provider while preserving prior evidence identities.
3. **Build a generic CPU-to-DMA-to-IP executor first.** This is the broader
   onboarding goal, but it would combine multiple protocols and lifecycle
   gaps before this concrete route has a CPU-consumed acceptance example.

## Runtime and evidence boundaries

- The source word is preloaded from the `SOURCE` image into one
  `PersistentMemory` object shared by Ibex and ZipCPU DMA. Ibex writes the
  source address into the DMA source register and does not rewrite the source
  word during the case.
- CPU OBI accesses to DMA registers are routed to the real DMA session. The
  DMA AHB write is delivered to the real Caliptra session through its keyed,
  versioned provider; it is not a physical Wishbone-to-AHB bridge.
- DMA completion is the only IRQ source in this slice. ScenarioRunner delivers
  a fixed 16 CPU-tick pulse; the gate requires Ibex to take the interrupt
  before that pulse expires. This is not an indefinite pending interrupt latch.
- The existing static D3 F6 result remains `unsupported`; this slice consumes
  its live route through a D4 binding and does not upgrade static F6 support.
- The runtime route proves one source word and one `CTRL=5` write. It does not
  prove arbitrary AHB routes, multiword SHA feeding, physical bus arbitration,
  real shared SRAM, continuous fuzzing, or overall P8 completion.

## Failure behavior

- A source address, target window, offset, width, byte enable, or value that
  differs from the declared route is refused before the Caliptra provider
  command.
- The wrong-offset native case uses a real CPU-programmed DMA request to
  `CTRL+4`; it must leave Caliptra AHB ticks/effects unchanged, produce no DMA
  completion IRQ, and leave the ISR success marker unset.
- Missing DMA completion, an IRQ before the final DMA response, a nonzero DMA
  status, SHA status timeout, digest mismatch, missing ISR stores, stale
  transaction identity, or fresh-prefix divergence fails the gate.
- Native child processes are closed on every path and their return codes and
  partial evidence are retained.

## Acceptance

1. Pure firmware tests verify OBI writes occur in source, destination, length,
   start order and that the ISR reads DMA status, polls SHA status, stores all
   eight digest words, and writes success only after the checks.
2. Runner tests verify exact Ibex, ZipCPU DMA, and Caliptra sessions; one shared
   `PersistentMemory`; exact DMA and CPU router windows; a single
   `dma.irq → cpu.irq` binding with a fixed 16 CPU-tick pulse; and the selected
   route's single D4 bind/admission identity.
3. The opt-in native positive gate joins CPU OBI programming and retirement,
   DMA RAM read/write `TransactionKey`s, Caliptra AHB request/data/effect/
   response, DMA completion pulse, CPU external IRQ take, ISR register reads
   and result writes, and SHA-256(`abc`).
4. An independent fresh process set consumes the exact recorded component
   schedule. A SHA-specific typed normalizer validates and projects only the
   Caliptra AHB access-ID session UUID and typed CPU/DMA/SHA/Runner execution
   identities; raw artifact identity documents compare exactly before
   projection, and values, local ticks, transaction shape, and event order are
   retained.
5. The wrong-offset native request is refused before the Caliptra provider,
   leaves no target effect or success marker, and preserves the sampled native
   request and typed DMA transaction for audit.
6. The report records exact commands, exit states, evidence paths, source and
   artifact identities, and limitations. Current progress and report indexes
   are updated without claiming generic F6, remote validation, or P8 completion.
