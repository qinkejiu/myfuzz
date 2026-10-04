# Generated PicoRV32 Wishbone custom IRQ acceptance

The separate `configs/cpus/picorv32_wb_irq/component_profile.json` enables
`ENABLE_IRQ=1` on the pinned `picorv32_wb` RTL. The existing `picorv32_wb`
profile retains `ENABLE_IRQ=0`, its source closure and its acceptance claims.

The source is `third_party/picorv32_upstream_reference/picorv32.v` at
`ef203c2b0a3fb793280f5114941416c425c5b461`, SHA256
`0836050971b3c6cdd28ac3b1e5719a67fb645161912bef1e472e63995ceb0622`.
The new independent source-lock record and closure authenticate IRQ=1 as well
as PCPI=0. Actual Verilator lint exits 0 with zero warnings. No upstream RTL
or submodule is changed.

## Adapter and IRQ ABI

The generated Wishbone runtime exports the real 32-bit physical `irq` input
through `processor.interrupts/custom`. The existing `GeneratedWishboneCpuSession`
uses the new bounded `STEP_WISHBONE_IRQ(ack, rdata, irq)` operation only when
that endpoint is declared. The old two-field `STEP_WISHBONE` command remains
the operation for the IRQ-disabled profile. The session rejects undeclared
inputs and IRQ values outside the 32-bit unsigned range, and compares each
driven IRQ with its physical pre-clock observation.

Pico IRQ handling uses custom0 instructions from the pinned upstream
`firmware/custom_ops.S` and `README.md`: `maskirq`, `getq` and `retirq`.
The default handler entry is 0x10, q0 carries the return address, and q1 carries
the handled IRQ bitmask. `ENABLE_IRQ_QREGS=1`, `LATCHED_IRQ=0xffffffff` and
`PROGADDR_IRQ=0x10` are retained RTL defaults. This is Pico's custom ABI.
It does not establish a RISC-V privileged machine-external interrupt ABI.

## Actual RTL and replay result

`tests/local_harness/test_wishbone_cpu_irq.py` uses the existing generated
runtime, memory service, router, ownership map, scheduler and formal evidence
save/replay APIs. Both CPU and timer execute actual Verilator-built pinned RTL.
The CPU program enables only IRQ3, arms the real ziptimer through a full-word
MMIO write of count 80, and runs a RAM-writing main loop. The timer's real native
one-clock IRQ pulse binds to CPU `irq[3]` through the runner's existing pulse
delivery policy. The ownership map marks that bit bound, all remaining IRQ
bits fixed at zero, and rejects direct mutation of IRQ3.

The actual Pico handler reads q1 and writes RAM[0x200]=8 and RAM[0x204]=1.
The test observes CPU input `irq=8`, real `eoi=8` during the handler, `eoi=0`
after `retirq`, and `trap=0` throughout. It also requires a subsequent real
main-program write to RAM[0x208]=1 after EOI deasserts. CPU MMIO write count is
exactly one. These observations are checked independently in the initial run
and the replay run.

Formal save returns `complete`; fresh replay returns `matches=True` and uses
a new RTL process execution identity. The temporary test evidence bundle is
replayed before the acceptance fixture removes it.

## Validation

The initial test run failed with two assertions, both stating
`IRQ-enabled profile is missing`, before production changes were made (TDD RED).

```sh
verilator --lint-only -Wno-fatal --top-module picorv32_wb \
  -GENABLE_PCPI=0 -GENABLE_IRQ=1 \
  third_party/picorv32_upstream_reference/picorv32.v
PYTHONPATH=src python3 -m unittest \
  tests.local_harness.test_wishbone_cpu_irq \
  tests.local_harness.test_wishbone_cpu -v
```

The combined run passes eight tests, including the new real IRQ save/replay and
the six existing Wishbone tests. An earlier run encountered a
`LocalHarnessBuildError` during timer setup while shared host source edits were
in progress. No ISR claim derives from that failed setup; the stable run
rebuilds from the authenticated inputs and completes.

## Coverage boundary

Acceptance covers the pinned IRQ-enabled Wishbone parameterization, one real
external timer pulse on IRQ3 and a minimal custom handler. Nested IRQs, all
other IRQ bits, a general interrupt context-saving ABI, other Pico bus
variants, standard privileged CSR handling and independently varied IRQ timing
are unassessed. ISR behavior is established for this focused CPU→timer→CPU
case; no CPU output or IRQ waveform is synthesized by Python.
