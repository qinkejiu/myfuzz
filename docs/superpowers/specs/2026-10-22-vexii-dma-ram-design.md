# Vexii CPU-programmed multiword DMA

This applies the existing approved six-CPU DMA architecture to the pinned
cacheless32 reduced-dual-AXI profile. It follows CVW's accepted RAM DMA slice.
Manual host register programming would not satisfy CPU programming. A new
interrupt/peripheral-target/coherent-memory path is a separate extension.

## Execution contract

- Exact CPU profile configs/cpus/vexiiriscv/component_profile.json; use
  GeneratedReducedAxiCpuSession, not the IRQ variant. CPU reset/main 0x80000000.
- DMA is GeneratedWishboneDmaScenarioSession using existing zipcpu_wbdmac
  profile. One shared PersistentMemory ram region base 0x80000000,size0x10000,
  initialization_seed17,max_initialized_bytes0x10000. DMA MMIO base0x40000000,
  exact16bytes and outside RAM. No IRQ bindings or external CPU input.
- Host preloads only512bootbytes,zero16destination and zero24results. CPU
  writes source0x80001000 with words0x135,0x246,0x357,0x468, then configures DMA
  source+8,destination+12,length+4=4,start+0=0x0fed0004. Destination0x80002000,
  results0x80003000: finalstatus+0,actualdestwords+4..16,marker+20.
- Firmware polls actual busy31 until0, rejects error30, loads source and
  destination, compares and stores marker1 or FFFFFFFF. Wrong key0x3db otherwise
  identical firmware. No host source words, configuration or success injection.
- Extract a parameterized RV32I DMA RAM image builder from the existing CVW
  firmware; existing cvw_dma_images and exported encoders/constants must retain
  byte-identical first/wrongkey images and parameter refusal. Its new Vexii
  wrapper supplies only the declared address layout. No CPU-name branch.
- Reduced-AXI exposes its existing mmio_router through a read-only router
  property for standard Runner discovery; both interfaces always refer to the
  same object. Existing externally driven usage/identity remains compatible.
  No changes to Runner or bus-width/transaction semantics. Queue callbacks,
  target tick bounds, pending responses and reset cancellation remain intact.
- Runner steps dma,cpu deterministically for at most4000rounds. Actual queued
  MMIO is delivered during scheduled target steps, including its real control
  edges; never call router.drain_one from an unrecorded host loop.
- After a real CPU marker store, record an explicit CPU begin_quiesce action
  (no native edge) if needed to stop new fetch roots, then retain all scheduled
  drain edges within the same4000roundbound. Terminal requires no accepted
  CPU/DMA response or pending Router request. Fresh replays the entire action
  sequence, including quiesce, in independent native sessions.

## Required evidence

1. Real reduced-AXI AW/W and B, AR/R joins to complete TransactionKey in RAM
   service and Router; independent instruction/data channel IDs and sequences.
2. All four CPU configuration stores, exact control STB payload/ACK, queued
   target delivery, measured indirect ticks, four DMA reads and four writes,
   exact keyed native ACK responses. No CPU destination writes.
3. Source DMA snapshot per-byte writer/version equals actual CPU store; CPU
   target snapshot writer/version equals DMA store. CPU source rereads and
   compared actual target words commit a real marker.
4. Wrongkey: no accepted DMA master request/response or memory effect, zero
   destination, CPU mismatch markerFFFFFFFF after actual destination load.
5. First/fresh each branch: exact artifact/session identities before UUID-only
   normalization, complete retained events/actions/raw samples/effects equal,
   distinct PIDs/executions, actual zero process exits, no capture/cleanup errors.
6. Single canonical heavy-worker lock, unique immutable attempt directories,
   failed attempts retained, executed input hashes/bytes and worker receipt.

This is real independent RTL processes with host memory/transaction routing,
not physical shared SRAM, synthesizable AXI/Wishbone bridge, global clock,
IRQ/ISR, retirement, generic D4/F6 or P6/P7/P8 completion.

## Measured layout correction

The initial native-attempt1 used DMA0x40002000 and failed after4000rounds with
fourCPUsourcewrites but zeroMMIOoffers. Pinned generated RTL line4557 and
generated/manifest.json's generation_command permit only MMIO
0x40000000..0x40000fff. The corrected16bytewindow is0x40000000..0x4000000f;
no CPU profile/RTL/PMA modification or runtime budget expansion is made.
The failed attempt and its exact original bytes remain immutable.
