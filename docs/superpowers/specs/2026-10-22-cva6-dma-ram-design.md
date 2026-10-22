# CVA6 CPU-programmed four-word DMA RAM

This extends the approved six-CPU DMA architecture after the accepted CVW and
Vexii fixed RAM chains. CVA6 is RV64 with real64-bit AXI. Alternatives are a
separate duplicated firmware, opt-in shared ordering instructions, or accepting
merged64-bit peripheral accesses. Use opt-in ordering in the existing image
builder; preserve the session's refusal of unsupported merged peripheral beats.

## Exact production contract

- Pinned configs/cpus/cva6/component_profile.json, GeneratedCva6Axi4Session with
  router and defer_mmio=True, existing GeneratedWishboneDmaScenarioSession.
  Existing protocol/Runner semantics and CPU RTL/profile unchanged.
- CPU instance cpu, DMA instance dma, reset16/release20,max_wait32 forCPU.
  DMA existing reset8/release8/wait16. MemoryRegion ram base0x10000,size0x10000,
  initialization_seed17,max_initialized_bytes0x10000. No IRQ bindings.
- MAIN0x10000,boot512bytes; SOURCE0x11000,DESTINATION0x12000,RESULT0x13000;
  DMA_BASE0x40002000,size16. Words0x135,0x246,0x357,0x468; host supplies only
  boot,zero16destination,zero24result. CPU supplies source/configuration.
- Actual selectedPMA caches only[0x80000000,0xc0000000),executes lowRAM
  [0x10000,0x20000); proposed RAM is noncacheable without profile changes.
  The WT buffer can still coalesce adjacentSW. Preserve real64bit lanes and
  MMIO singleword(size2,len0) admission; never split mergedsize3 access.
- Add exact-bool ordered_stores=False to shared dma_ram_images. True inserts
  FENCE iorw,iorw opcode0x0ff0000f after every emittedSW (source/control/status/
  observed data/marker), with all branch labels fixed after instruction insertion.
  StatusSW fence also orders the accepted idle/errorfree status before readback.
  CVA6 wrapper opts in, existing CVW/Vexii wrappers do not; default images and
  start-key refusals stay byte-identical to saved accepted captures.
- FENCE commits only with no_st_pending_ex AND dcache_commit_wbuffer_empty in
  pinnedCVA6; do not claim cache invalidation because cache flush flags disabled.
  Source/control stores must each reach their own native word transaction.
- Source/dest/length/start offsets8,12,4,0; length4,startFED0004; wrongkey3DB0004.
  Firmware polls bit31 busy and separately rejects bit30 error, loads/compares
  source/destination, stores status+0,actual targetwords+4..16,marker+20.
  Low positive layout/data allow RV32I word operations on RV64; no general
  RV64-address generation claim.
- Standard Runner dma,cpu pairs at most4000rounds. SourceMMIO queues toDMA
  scheduledstep with actual controlticks. Record CPU begin_quiesce only after
  actualmarker and then all drainsteps; terminal has noaccepted CPU/DMA/Router
  pending responses. Full independent fresh replays exactactions for bothkeys.

## Required evidence

1. Independently reduce actual64bit AXI AR/R,AW/W/B including burst metadata,
   IDs,size,strobe and response value. Memory transaction key order is session
   _ready_inputs RAMread (beforeedge), MMIOread atAR, RAMwrite after joinedAW/W;
   preserve separate memory/mmio counters and local-execution key namespace.
2. FourCPU sourceSW use expected native lane0f/f0 at alternating offsets,
   width8 service commits with originalWSTRB. CPU source and result word views
   select actual enabledfourbytes; never relabel CPU beat as width4.
3. All four controlstores routed from raw64bit WD/WSTRB(size2,len0), selected
   high/low half correct. Queue acceptance→scheduledDMAstep→controlSTB/ACK
   exact transaction/payload/tick joins. ActualMaster fourreads/fourwrites and
   keyed native ACK responses, no CPUdestination writes.
4. DMA32bit source snapshots match selectedfourbytes' CPU writer/version.
   CPU64bit read snapshots retain all8writers/versions; selectedfourtargetbytes
   match DMA writes, while the otherhalf may have a different writer/version.
   Actual consumed CPU R values supply source/target/status observations.
5. Status/result/marker unique actualCPU stores; consumed readresponses and
   required actual resultstore completions precede marker acceptance. Wrongkey
   no masterrequest/response/memoryeffect; firstdest0 vs source135 produces
   actual FFFFFFFF marker after responses. No hostsource/config/success.
6. Both branch first/fresh exactidentity documents before explicit UUID
   normalization; full events/actions/rawsamples/effects equality, distinct
   nativeprocesses/executions, zero exits, acceptedresponses drained.
7. Single canonical heavylock, unique attempts/logs/PIDterminalreceipts, exact
   executedinputs/bytes including directsource-lock verifier/lock/closure.
   Failedattempts preserved. No wholeelaborationclosure or externaltoolbytesclaim.

This is independent real RTL CPU/DMA processes with shared host RAM routing.
It does not establish coherent/physicalSRAM/interconnect/sharedclock, IRQ/ISR,
retirement, genericD4/F6, continuoussearch or aggregateP6/P7/P8 completion.
