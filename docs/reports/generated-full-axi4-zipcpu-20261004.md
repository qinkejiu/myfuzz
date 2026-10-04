# Generated full AXI4 ZipCPU local runtime (2026-10-04)

The generated local harness admits the pinned `zipaxi` top from `third_party/soc-zipcpu` at `42606d2d6ef55df313772232977621b2d72f0159`. The CPU profile binds both physical AXI4 masters: 37 signals on the instruction side and 37 on the data side. `OPT_LGICACHE=5` selects the upstream instruction cache, so the bounded program causes an eight-beat read (`ARLEN=7`, final `RLAST=1`). The source lock records all 15 Verilator-read RTL files, 14 nonfatal upstream warnings, the exact parameter values, and the matching pinned Git blobs. Replaying the recorded elaboration command confirms the read set equals the closure.

The local driver advances one real ZipCPU clock edge per `STEP_AXI4` command. It snapshots all five channels of each master before and after the edge. The host memory service maintains independent AW, W, B, AR, and R handshakes on both ports. It buffers W independently of AW; returns B only after the AW-specified final W beat; holds B and R stable until consumed; returns the request ID; implements FIXED, INCR, and legal WRAP address sequences; and checks `WLAST`, `RLAST`, alignment, 4 KiB boundaries, sizes, and IDs. RAM reads and writes go through `PersistentMemory` and `MemoryService` with transaction keys. Exclusive accesses and non-RAM addresses raise protocol environment errors. The service has no AXI4-Lite conversion or single-beat adapter.

The bounded real ZipCPU program comes from the repository's existing RTL-derived boot encoder. It fetches from byte address `0x100`, stores `0x0000beef` at `0x200`, loads that value, increments it, stores `0x0000bef0` at `0x204`, then halts. The generated acceptance test requires a real multi-beat fetch, two data writes, exact RAM values, a formal `scenario_runtime_manifest.v1` evidence bundle, and a matching replay with a fresh RTL process. The source lock retains `runtime_unverified` because that status is a source registry declaration; the generated acceptance test is the runtime evidence.

Run the focused acceptance with:

```sh
PYTHONPATH=src python3 -m unittest tests.local_harness.test_axi4_cpu -v
```
