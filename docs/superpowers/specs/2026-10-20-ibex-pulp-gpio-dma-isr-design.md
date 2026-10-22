# Ibex → ZipCPU DMA → PULP GPIO → Ibex ISR

Date: 2026-10-20

## Goal

Close one real CPU-configured DMA data path through the existing transaction-level
Runner: Ibex writes the ZipCPU `wbdmac` registers, the DMA reads one word from
shared persistent RAM and writes PULP GPIO `PADOUT`, the DMA IRQ reaches Ibex,
and the ISR reads back the GPIO value and commits its result to RAM. Run the
same declared schedule in a fresh set of native processes and compare the full
event prefix.

## Current building blocks

- `ScenarioRunner` already schedules Ibex, `wbdmac`, and independently generated
  IP sessions and binds native DMA IRQ receipts to CPU IRQ inputs.
- `GeneratedPulpGpioSession.dma_master_target_access()` already verifies one
  Wishbone-to-APB3 target delivery through a pinned PULP provider contract.
- `compile_pulp_gpio_dma_runtime_paths()` already binds the exact shared RAM,
  DMA endpoint, PADOUT window, single-word admission, and source genome.
- Separate evidence already proves Ibex-configured DMA-to-RAM with IRQ/ISR and
  standalone RAM-to-PULP PADOUT DMA. This design joins those capabilities in a
  single Runner execution without changing their older evidence identities.

## Design decision

Build a new, isolated Ibex/PULP DMA Runner module and integration gate. The
native CPU program configures source, destination, length, and start through its
actual OBI route to `wbdmac`. The source word is a declared `MemoryImage` in the
same `PersistentMemory` seen by the CPU and DMA. DMA routing is compiled by the
existing versioned `PulpGpioDmaRuntimePaths`; the target remains the exact
registered PADOUT offset and full-word transaction shape.

The Runner owns the DMA IRQ input binding and its 16-tick pulse latch, so a
short measured DMA pulse remains present until Ibex actually takes the
interrupt. PULP `gpio_in` is explicitly fixed at zero; the experiment does not
mutate external GPIO pins. Each run uses a deterministic repeated schedule of
`dma`, `cpu`, `gpio`, stopping on the ISR success marker or after 2,000 rounds.
Fresh replay uses exactly the recorded component prefix.

The Ibex machine-external ISR reads the DMA status and PULP PADOUT through the
CPU's actual MMIO route, reads the expected source word from RAM, compares the
values in firmware, and writes measured values plus a success marker to RAM.
The host gate independently joins the CPU programming accesses, exact DMA
read/write `TransactionKey`s and responses, PULP APB request/effect/response,
native DMA IRQ receipt, actual CPU IRQ-taken event, and ISR result stores.

The gate runs the same schedule in a second fresh Runner. It allows normalization
only for the per-process native execution IDs and the Runner execution ID,
using typed rules scoped to the exact roles `cpu`, `dma`, `gpio`, and `runner`;
events, local ticks, artifact identities, target receipts, transaction shape,
and result values otherwise compare exactly. A controlled wrong-offset DMA
write must fail before the PULP provider call and before APB or PADOUT side
effects. The refusal result is recorded separately from the successful prefix.

The design uses transaction-level delivery across independently clocked native
sessions. It does not add or imply a physical Wishbone-to-APB bridge, physical
SRAM, continuous fuzzing, a generic DMA target inferred from protocol labels,
P7 F6 support, or overall P6/P7/P8 completion.

## Alternatives considered

1. **Extend only the standalone PULP DMA gate.** This would prove a real PADOUT
   effect but would leave CPU configuration, DMA IRQ, and CPU consumption as
   separate experiments.
2. **Join PULP GPIO to the existing Ibex DMA `ScenarioRunner` (selected).** This
   reuses the actual CPU, DMA, IRQ, route admission, and provider contracts and
   closes one bounded CPU-to-DMA-to-IP-to-CPU loop with a fresh replay.
3. **Build a protocol-agnostic F6 executor first.** That is the broader goal,
   but it would combine multiple provider protocols and lifecycle gaps before
   the PULP CPU/DMA route has a single end-to-end acceptance example.

## Failure behavior

- Unknown or changed route, DMA endpoint, RAM object, target instance, window,
  offset, width, or byte enable refuses before a provider effect.
- The wrong-offset native request remains an environment refusal. It cannot
  produce a successful transfer or CPU-consumption certificate.
- Missing IRQ, missing ISR result, wrong PADOUT value, error status, unjoined
  transaction, changed event prefix, or unreaped native child fails the gate.
- Cleanup closes every started session while preserving the original failure
  and the partial evidence prefix.

## Acceptance evidence

1. Pure tests verify the declared firmware image contains the selected DMA
   source/destination/one-word start configuration and expected ISR checks.
2. The opt-in native gate records actual CPU OBI programming/readback, native
   Wishbone DMA read and PADOUT write with matching typed identities, PULP APB
   effect, DMA IRQ, CPU IRQ take, ISR RAM writes, successful comparison, and
   reaped processes.
3. A second independent process set replays the exact schedule and the full
   semantic prefix matches under only the declared execution-ID normalization.
4. The wrong-offset native request is refused before provider dispatch; zero
   PULP APB accesses, zero target requests/responses, and unchanged PADOUT are
   measured.
5. The report updates current progress, names the verified scope, records exact
   commands/exit results, and keeps generic F6, remote PULP, six-CPU, and overall
   phase gates open.
