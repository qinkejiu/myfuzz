# Six CPU and four IP DMA status audit

**Audit date:** 2026-10-22

**Basis:** the scoped reports and saved evidence linked below. Each result is
bound to its own frozen inputs; these are not one joint run of the current
working tree.

## CPU DMA cells

| CPU | Bounded DMA dataflow with native evidence | IRQ/ISR | Remaining boundary |
|---|---|---|---|
| Ibex | RAM word `5` → ZipCPU `wbdmac` → Caliptra SHA `CTRL=5`; positive/fresh each 525 scheduled steps. A separate wrong-offset refusal is preserved. | DMA completion IRQ is taken; ISR stores status and digest. | `abc` SHA block is host-loaded; wrong-offset refusal is not a fresh replay. Separate frozen Ibex runs also cover four-word RAM→RAM, RAM→UART TX FIFO, and UART RX FIFO→RAM; those are not part of the Caliptra replay. See [Caliptra report](ibex-caliptra-sha-dma-isr-20261021.md) and [runtime summary](../LOCAL_HARNESS_RUNTIME.md). |
| CV32E40P | Shared host `PersistentMemory` word `0x5aa55aa5` → ZipCPU `wbdmac` → PULP GPIO `PADOUT`; positive/fresh each 309 steps. | IRQ ID 11 acknowledgement, ISR fetch, reads, and RAM result are joined. | Fixed one-word provider delivery; no retirement certificate. Wrong-offset case is a separate refusal run. See [report](cv32e40p-zipcpu-pulp-dma-isr-20261021.md). |
| CVW | CPU programs a four-word RAM copy; DMA performs four reads and four writes, followed by CPU readback. Positive and wrong-key branches each have independent fresh replay. | Not bound in this cell. | No peripheral target or ISR in this cell. See [report](cvw-dma-ram-20261022.md). |
| VexiiRiscv | Fixed reduced-AXI CPU programs a four-word RAM copy; positive and wrong-key branches each have independent fresh replay. | This is the non-IRQ profile. | No peripheral target or ISR in this cell. See [report](vexii-dma-ram-20261022.md). |
| CVA6 | RV64/64-bit AXI four-word RAM copy with actual byte lanes and explicit software fences; positive and wrong-key branches each have independent fresh replay. | Not bound in this cell. | Fixed memory cell; coherent DMA and ISR remain open. See [report](cva6-dma-ram-20261022.md). |
| BOOM | Uncached TileLink A/D shared-memory four-word DMA; positive and stale-key branches each have independent fresh replay. | Not bound in this cell. | Does not cover coherent C/E DMA, B/probe, or physical shared SRAM. See [report](boom-dma-ram-20261022.md). |

All six CPUs therefore have a bounded CPU-programmed DMA result in their own
frozen attempt. The combinations are separate and do not establish one
reusable CPU/IP matrix or a current-tree joint acceptance.

## Peripheral IP families

The four series named in [project goals](../PROJECT_GOALS.md) are OpenTitan,
PULP, ZipCPU, and Caliptra.

| IP family | Bounded native DMA path present in the evidence set | Remaining boundary |
|---|---|---|
| OpenTitan | UART FIFO DMA paths include CPU-visible IRQ cases; route-v2 S4 also has three successful word transfers, two error/no-effect cases, and four typed fresh prefixes. See [TX FIFO run](ibex-zipcpu-dma-uart-fifo-directed-20261017.md), [RX FIFO run](ibex-zipcpu-dma-uart-rx-fifo-directed-20261017.md), and [route contract report](dma-master-route-contract-20261019.md). | Fixed UART/route instances; not generic TL-UL DMA admission across arbitrary OpenTitan peripherals. |
| PULP | ZipCPU `wbdmac` writes `PADOUT`; Ibex and CV32E40P chains also close bounded IRQ/ISR and fresh replay. See [target report](pulp-apb3-dma-target-20261020.md), [Ibex chain](ibex-zipcpu-dma-pulp-gpio-isr-20261020.md), and [CV32E40P chain](cv32e40p-zipcpu-pulp-dma-isr-20261021.md). | Fixed APB3 GPIO route/provider; no physical Wishbone-to-APB bridge or generic F6. |
| ZipCPU | `wbdmac` is the DMA mover in the Ibex/CV32E40P peripheral cells above; as a target, `wbuart` receives full-word RAM value `0x41` at TXREG and emits serial byte `0x41` with fresh evidence. See [UART target report](zipcpu-uart-dma-target-20261020.md). | Fixed Wishbone UART target; not generic Wishbone target onboarding. |
| Caliptra | ZipCPU `wbdmac` writes SHA `CTRL`; an Ibex-configured chain also takes completion IRQ and executes an ISR. See [target report](caliptra-ahb-dma-target-20261020.md) and [Ibex chain](ibex-caliptra-sha-dma-isr-20261021.md). | Fixed AHB-Lite SHA route; the digest input block is host-loaded in the CPU/ISR chain. |

These are distinct, protocol-specific bounded routes. The evidence does not
establish a physical Wishbone-to-TL-UL/APB3/AHB bridge, physical shared SRAM,
one global clock, arbitrary D4/F6 execution, continuous fuzzing, or automatic
same-protocol CPU/IP onboarding. P6, P7-E, P8, and the six-CPU/four-IP aggregate
acceptance remain open.

A separate non-DMA F4 result now covers CV32E40P OBI → registered PULP SPI
`SPICMD` APB3 storage/readback → RAM: four first-run cases have typed native
OBI/RAM result hops and an equal full fresh prefix. It adds one bounded PULP
storage source row; it does not change the DMA rows above or close the four-IP
aggregate. See the [compiled-F4 report](compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md).

The source-level Reduced AXI reference fix and accepted runtime crosswalk
observation gate are documented in the [crosswalk report](reduced-axi-journal-crosswalk-20261022.md);
its observer lifecycle fix is detailed in the [lifecycle report](reduced-axi-reference-lifecycle-20261022.md).
