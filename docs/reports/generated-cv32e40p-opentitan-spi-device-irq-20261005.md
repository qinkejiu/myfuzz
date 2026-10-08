# CV32E40P + OpenTitan SPI Device upload IRQ acceptance

Date: 2026-10-05

## Scope

The real generated CV32E40P OBI harness and OpenTitan SPI Device TL-UL harness run as separate local sessions. The CPU routes MMIO through a window at `0x40000000`; its native MEI input at physical `irq_i[11]` receives only the real SPI Device `irq_o[1]` upload-payload output. The only fuzzable source is the 32-bit external `master_frame`. Each testcase keeps both local RTL states through setup, frame transfer, interrupt service, and W1C. No reset occurs within a testcase.

The CPU sets direct `mtvec=0x10100`, enables MEIE/MIE, then writes CONTROL `0x10=0x10`, CMD_INFO `0xa8=0x81010202`, and INTR_ENABLE `0x04=2` once each. A Genome action injects one external upload frame after the CPU output at `0x40000004` and a delay of 30 CPU-local ticks. The direct vector jumps to the ISR at `0x10200`; the vectored IRQ11 slot at `0x1012c` is a self-loop guard.

## Observed acceptance

| Check | Seed | Mutated |
| --- | --- | --- |
| Admitted external frame | `0x0012345a` | `0x0012345b` |
| Real command FIFO low byte | `0x02` | `0x02` |
| Real address FIFO low 24 bits | `0x001234` | `0x001234` |
| Real ingress SRAM payload low byte | `0x5a` | `0x5b` |
| ISR `mcause` saved in CPU RAM | `0x8000000b` | `0x8000000b` |
| ISR completion marker in CPU RAM | `0x55` | `0x55` |
| Fresh-harness semantic replay | Full equality | Full equality |

For each frame, the accepted CPU INTR_ENABLE MMIO write precedes the one source injection. The SPI Device's sampled `irq_o` has bit 1 high before the bound delivery, and the CV32E40P acknowledges physical IRQ ID 11 while that input is high. The first accepted instruction fetch after acknowledgement is `0x10100`. The ISR reads real INTR_STATE, command FIFO, address FIFO, and ingress SRAM through CPU-origin MMIO; it reads `mcause` and saves all observations in persistent CPU RAM. It writes only bit 1 (`2`) to INTR_STATE as W1C. The later INTR_STATE read has bit 1 clear, and a subsequent native SPI Device sample delivers IRQ low. MRET returns to the CPU wait loop.

All SPI Device MMIO transactions have unique CPU source identities in epoch zero. Both sessions remain in reset epoch zero, with no testcase reset event. The two payload bytes differ in the RTL ingress read and saved CPU RAM. Each case uses a bounded evidence bundle and replays with fresh CPU and SPI Device session objects. The test caps transactions at 512, local cycles per component at 4096, scheduler steps at 4096, wall time at 300 seconds, semantic records at 30000, and evidence at 64 MiB; each observed usage stays within its cap.

## Verification

Exact command:

```text
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_spi_device_irq_real.py
```

Full output from the final run:

```text
.                                                                        [100%]
1 passed in 54.83s
```

Before the implementation, the same test was run with no IRQ binding. It failed at the explicit assertion that the real upload-payload IRQ must reach the CPU MEI input. Adding the bit-1 binding and ISR satisfied that assertion and the remaining end-to-end checks.

## Boundary and self-review

This acceptance covers the pinned upload opcode `0x02`, one external frame per testcase, and the generated mode-0 single-line local SPI peer. Timing is expressed only in CPU-local delay ticks and bounded per-session steps; the test introduces no SoC clock relation, bus bridge, crossbar, arbiter, or PLIC. It does not establish all SPI modes, arbitrary same-protocol reuse, or coverage-guided bug discovery.

Review found the native `irq_o[1]` and INTR_STATE/INTR_ENABLE bit 1 mapping in the pinned SPI Device RTL. The ownership producer is named `spi_device.irq_o`, while `Binding(..., source_bit_offset=1)` selects the physical output bit. The test checks the accepted MMIO delivery before injection, actual RTL samples around W1C, full fresh replay for both sources, and epoch-zero transaction uniqueness. Only the scenario test and this report were added for this task.
