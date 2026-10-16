# DMA Slice D — genuine Ibex configuration, RAM transfer and ISR

## Result and scope

Real pinned Ibex RVFI CPU writes four source RAM words, then its accepted OBI data beats configure real pinned wbdmac source/destination/length/start=0x0fed0004. Existing DataflowRouter delivers each admitted CPU transaction to the same DMA session's real target edges. The DMA's real master reads four words and writes four actual output payloads through ledger-backed MemoryService into shared PersistentMemory. No host control writes or host source-word preload are used.

The observed native DMA pulse drives the real Ibex external IRQ input via an explicit pending-level latch. Actual Ibex interrupt take and ISR execution save mcause=0x8000000b, DMA status=3, the four copied words and a CPU branch-dependent success=1 into RAM. A real ISR DMA status read is also routed through the target.

This is an explicit bounded scheduler fixture, not new generic ScenarioRunner admission or a synthesizable OBI/Wishbone bridge. Source/clock ordering is deterministic host transaction order between separate actual RTL processes. DMA source pins were not changed.

## Files

- `local_harness/wishbone_dma_session.py`: additive routed target entry retains CPU TransactionKey/context and exact measured DMA control edge ticks. Existing standalone register access and master service remain unchanged.
- `scenario/ibex_dma_example.py`: complete initial CPU firmware/ISR images, real authenticated sessions/router/shared RAM, and bounded scheduler iteration plus explicit IRQ latch.
- Focused routed API test, firmware contract test and gated real chain integration test.
- DMA README and compact `evidence/ibex-dma-isr-real-20261017.json` with raw receipt hashes, snapshot hashes, actual build digests and key measured facts.

## Isolated snapshot identity

Shared host-source edits originally caused `build-inputs-changed-during-build`; no check was removed. Final real run used `/tmp/myfuzz-dma-slice-d-snapshot`: tracked files from git archive plus the five owned implementation/test files. Selected pinned third-party DMA and Ibex files were COPIED (not compiled via symlinks), with Git metadata pointers used only for read-only revision verification. Normal generation, source verification, captured build inputs and post-build identity revalidation all ran unchanged.

Snapshot's 1240 host/config/script/test SHA256 entries: `/tmp/myfuzz-dma-slice-d-snapshot-hashes.json`. Selected fixture/session/test hashes and that manifest hash are recorded in committed compact evidence. Actual compiled identity includes all captured RTL and host input hashes and actual Verilator argv/tool identity in each raw receipt's cpu_identity/dma_identity. Caches: `/tmp/myfuzz-dma-cpu-isolated-cache`.

## Commands and results

RED before routed API implementation:
`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_wishbone_dma_session.py -k routed`
-> AttributeError: no routed_register_access. GREEN after implementation: 1 passed.

Final REAL:
```
MYFUZZ_DMA_CPU_REAL=1 MYFUZZ_DMA_CPU_CACHE=/tmp/myfuzz-dma-cpu-isolated-cache MYFUZZ_DMA_CPU_EVIDENCE=/tmp/myfuzz-dma-cpu-isolated-evidence PYTHONPATH=/tmp/myfuzz-dma-slice-d-snapshot/src python3 -m pytest -xq /tmp/myfuzz-dma-slice-d-snapshot/tests/integration/test_ibex_dma_chain_real.py
```
**1 passed in59.39s**. The single test executes TWO fresh real Ibex+DMA process pairs and compares complete traces. Log `/tmp/myfuzz-dma-slice-d-isolated-real.log`; complete receipts `/tmp/myfuzz-dma-cpu-isolated-evidence/run-0.json` and `run-1.json` (about3.8MB each).

## Exact IRQ adapter and measured edges

- Each scheduler iteration advances one DMA edge and drains at most one queued actual CPU MMIO delivery (that delivery may advance several individually recorded DMA control edges).
- Every actual physical native DMA pulse in those measured edges sets the pending-source list. Expected data, completion comparisons or RAM contents NEVER set it.
- Pending nonempty drives actual CPU IRQ=1 for the next real CPU edge.
- Only actual `irq_taken_pre` clears the list AFTER that CPU edge; input next edge is zero.
- Both fresh runs: native DMA pulse=edge92; actual CPU input high=ticks76,77,78,79; actual external take=tick79; latch then clears. Final ISR success appears by CPU tick128. DMA has148 measured edges including all configuration/status-access edges.
- Before latch introduction, an actual one-edge pulse reached CPU pre/post input with mask=0 but was not taken and ISR success stayed zero. Its truthful failed evidence remains `/tmp/myfuzz-dma-cpu-evidence/run-0.json`, log `/tmp/myfuzz-dma-slice-d-real.log`. It is not counted as success.

## Assertion and replay range

Each actual CPU OBI configuration beat is joined by source TransactionKey to the router delivery, then to exact target edges containing one STB and actual ACK. Assert exact four config offsets/values. CPU memory commits establish all source words; DMA frozen snapshots include the CPU writer identities and source versions. Assert exactly four actual master reads and four writes, exact addresses/data, exactly four DMA commits and no CPU writes to destination. Native actual input pre/post and actual take receipts are checked. Real CPU retire PCs enter ISR; actual ISR data loads/status and branch-dependent success stores are checked.

Fresh equality covers every scheduler iteration/CPU physical pre/post driver sample, all DMA pre/post control/master/IRQ samples, every router delivery/source identity, CPU retirement/IRQ/memory events, DMA snapshot/commit events and latch transition. Only fresh CPU/DMA process UUID strings, including embedded writer IDs, are replaced; no ticks, payloads, versions or order are removed.

## Limits

- Pinned DMA burst-tail extra response edge from Slice C remains explicit and required. Uniform latency robustness is not proven.
- Single directed RAM-to-RAM operation only. No RAM-to-IP/FIFO proof, sustained mutation/search, campaign, generic scheduler admission or full P8 claim.
- This adapter latches the real DMA pulse into CPU external level; it does not change native DMA IRQ output.
- Real stale-key/zero-length/error/pending-reset negative controls and broader arbitration/concurrency remain future work.

Final current-tree focused command: `PYTHONPATH=src python3 -m pytest -q tests/composition/test_zipcpu_wbdmac_profile.py tests/local_harness/test_wishbone_dma_transport.py tests/local_harness/test_wishbone_dma_session.py tests/scenario/test_ibex_dma_example.py tests/integration/test_ibex_dma_chain_real.py` -> **15 passed,2 skipped in6.47s** (real gates off). Log `/tmp/myfuzz-dma-slice-d-focused.log`. Production fixture/session and real test bytes match the successful isolated snapshot SHA256s; `git diff --check` passed.
