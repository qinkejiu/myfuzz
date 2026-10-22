# CVW CPU-programmed multiword DMA

This extends the already approved six-CPU/DMA objective and the existing
CPU-programmed ZipCPU DMA architecture to the declared CVW AHB-Lite CPU profile.
The existing Ibex/CV32, protocol sessions, Router and Runner remain the common
execution machinery. The intermediate result is a real CVW/DMA RAM dataflow;
the overall IP-target, interrupt, generic onboarding and system gates stay open.

The alternatives are a new compiled multi-IP scheduler, direct CVW/DMA RAM
execution, or a CVW/DMA peripheral target plus interrupt consumer. The RAM chain
first establishes the currently missing CVW CPU-programming/master-response
boundary; the other two require additional independent producer or IRQ contracts.

## Execution contract

- Use the pinned `configs/cpus/cvw/component_profile.json`, its configured
  reset `0xC0000000`, real `GeneratedAhbMemorySession`, and existing
  `GeneratedWishboneDmaScenarioSession` for `zipcpu_wbdmac`.
- Boot code is an initial host image. The CPU itself writes four distinct source
  words to `0xC0001000`, writes the DMA source/destination/length/start registers
  at `0xCFFF1000`, polls real DMA status, loads destination `0xC0002000` and source
  again, compares them, and stores status/data/marker at `0xC0003000`.
- Shared host `PersistentMemory` covers the ordinary external-memory region
  `0xC0000000..0xC000FFFF`; DMA MMIO is outside that RAM and inside CVW's declared
  external aperture. Only boot and zero result/destination images are preloaded.
  Source data and DMA configuration are never host-produced.
- Source words are `0x135`, `0x246`, `0x357`, `0x468`. Transfer length is four;
  start value is `0x0FED0004`. The wrong-key negative uses `0x03DB0004` with
  otherwise identical firmware and resources.
- Two independent sessions run under standard `ScenarioRunner` in deterministic
  `dma,cpu` order. CPU MMIO may advance measured DMA control edges through the
  Router; preserve and account for those indirect ticks.
- No interrupt input is invented for the CVW profile. Firmware polls the pinned
  RTL's status bits 31 (busy) and 30 (error). Native DMA IRQ, if observed, is
  recorded as output only.

## Required evidence

1. Native AHB-backed CPU source writes, all four routed register writes and their
   real Wishbone control STB/ACK receipts, with transaction identity joins.
2. Exactly four DMA master reads followed by four destination writes, keyed RAM
   read snapshots naming CPU source writers/versions, and CPU destination reads
   naming the DMA destination writers/versions.
3. CPU result marker `1`, data equality, no CPU write into the destination, and
   no pending CPU/DMA response at the accepted terminal.
4. Wrong-key branch: real CPU programs the stale key, no accepted DMA master
   traffic or DMA destination write, and the CPU commits failure marker
   `0xFFFFFFFF` after observing unequal destination data.
5. Fresh sessions rerun the complete recorded schedule with distinct process
   and execution identities; compare the complete event prefix using only
   documented execution-ID/PID normalization. Preserve failure attempts.

This is transaction-level composition of real CPU and DMA RTL processes sharing
a host memory service. It does not establish a physical AHB/Wishbone bridge,
physical SRAM, a global SoC clock, retirement, IRQ/ISR, compiled F6/D4 admission,
coverage-guided search, or P6/P7/P8 completion.
