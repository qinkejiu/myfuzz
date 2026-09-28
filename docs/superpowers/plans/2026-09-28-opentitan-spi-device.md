# OpenTitan SPI Device continuation

## Goal

Run the pinned OpenTitan SPI Device RTL in its own persistent harness. A real
Ibex program configures the Device through abstract MMIO routing; a mutable
external SPI master supplies commands and payload. Device output, FIFO state,
and interrupts are observed from RTL and bound to subsequent CPU inputs.
Each testcase keeps both RTL instances and memory alive until its end.

## Implementation sequence

1. Pin the complete vendor source closure and elaborate a local wrapper with
   native TL-UL and SPI pins. Keep source-lock evidence separate from runtime
   evidence.
2. Add a persistent local process protocol. Each command has an execution ID
   and monotonic sequence so a repeated command cannot repeat a TL write or
   external SPI edge. Preserve the Device instance across commands.
3. Add a mode-0 external SPI master source. It owns SCK, CSb and MOSI, drives
   each level across several Device system-clock ticks, and reads only the
   actual MISO pin. Its command/address/payload bytes are fuzzable sources.
4. Prove a CPU-to-IP path: Ibex writes Device CSRs, then a real SPI read
   returns bytes configured by those CPU writes. Prove an IP-to-CPU path:
   source SPI upload changes real Device FIFO/IRQ, which later changes the
   Ibex interrupt and MMIO-read result. No bound IRQ, MISO or rdata is
   independently randomized.
5. Extend the source decoder with path/source selection and preserve the
   complete genome, initial memory, event order, RTL identity and outputs in
   replay evidence. Add directed rejection cases for cut bindings.

## Acceptance

- Native RTL elaborates from a pinned vendor read set; wrapper and process
  build with the available local Verilator toolchain.
- Two event rounds run in one testcase with no reset. A later CSR/FIFO read
  reflects prior real writes or SPI transfers.
- CPU-program mutation changes a real downstream Device observation; SPI
  source mutation changes a real Device observation and CPU-visible state.
- MMIO writes and SPI edges execute once under retry/replay. Full fresh-process
  replay reproduces the state evolution and final observations.
- An attempt to override a bound IRQ or rdata fails. A wrong RTL outcome is
  recorded, not replaced by an expected value.
- Local SPI setup/hold and sampling are observed; there is no cross-component
  cycle-accurate timing claim or synthesized bus/crossbar.

PWM remains out of scope until its RTL is present in the pinned local source.
