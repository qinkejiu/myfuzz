# Shared Bus and Live RFuzz Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Continue the already approved generic-platform architecture; do not reopen its design approval.

**Goal:** Remove the one-target-per-source limitation for supported native buses and connect generated input layouts to a real RFuzz-compatible simulator boundary.

**Architecture:** Preserve source annotations, capability matching and deterministic IR. Shared endpoints produce a protocol-specific, CPU-independent fabric with transaction-held selection, one responder, and a default error path. RFuzz consumes generated raw layouts through the verified byte transport and a separately validated DUT input projection; actual coverage must come from simulation, never fabricated Python metrics.

**Tech Stack:** Python standard library, SystemVerilog/Icarus/Verilator, existing process-group supervisor, pinned upstream RFuzz client.

## Global Constraints

- No production renderer, adapter selector, input mapper, or top-level template may branch on a CPU name.
- Required endpoints fail closed when missing, ambiguous, direction-inverted, width-incompatible or protocol-inconsistent. Do not resolve multiple compatible CPU endpoints arbitrarily.
- Source descriptions supply semantics; HDL supplies physical facts. Unknown struct/parameter types remain unavailable until a verified elaboration path exists.
- One build worker, one runtime worker, nice15, no waveforms; runtime soft/hard process-group RSS limits512/768MiB. Large builds must be supervised separately with explicit bounds.
- Preserve the dirty task-2-report and all user-owned files. Work in the existing isolated worktree. Do not stop other users' processes.
- Synthetic RTL, actual CPU execution and actual RFuzz feedback are separate evidence categories.

## Task 1: Protocol-governed shared APB and Wishbone endpoints

Files: modify `src/myfuzz/composition/auto.py`, `protocol_composer.py`; create focused `shared_native_bus.py` if needed; test `tests/integration/test_shared_native_bus.py`; update the usage guide only after review.

Interface: keep `GenericCompositionRequest`, `plan_generic_composition`, `write_generic_composition` unchanged. Multiple component records may select the same endpoint only for validated APB3/APB4/Wishbone Classic native routes. Preserve unique components/address regions and record deterministic fabric semantics in IR (or derive from validated route groups without unverifiable cached metadata).

- [ ] Write a source-backed synthetic host with one bus and three differently named register targets. Plan all three targets through the same endpoint. Catch current planning exception and fail the test with `self.fail(str(error))`. Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_shared_native_bus` and observe the single-target rejection.
- [ ] Implement protocol-only group validation and shared routing. Gate per-target request control; hold selection during a transaction; never wire multiple drivers to a CPU input. Ensure inactive targets cannot latch/buffer a request intended for another target. Per-target translated address and stable payload are retained. Merge only the selected response, mask inactive responses. Invalid addresses receive native error completion without reaching a target. Preserve APB setup/access/back-to-back transfers (PSEL need not fall between transfers); Wishbone Classic retains CYC/STB semantics and no pipelined STALL. Timeouts and aborts must release/recover as the corresponding native protocol permits. Do not enable shared AXI4-Lite or opaque protocols through this task.
- [ ] Real Icarus benches must write/read all3targets and prove no cross-target side effects, APB back-to-back different regions, WB completion/drop/reissue, target wait/error, unmapped address, timeout, abort/reset. Test highest representable address and region end at2**width. Verify mismatch/shared-reset rejection, ambiguous multiple masters still rejected, and unsupported shared protocol failclosed.
- [ ] Run native APB/WB and AXI point-to-point regressions plus shared tests. Independently review before broader protocol support. Commit only owned files; write `.superpowers/sdd/shared-native-report.md` with exact RED/GREEN commands, test output, limitations and SHA.

## Task 2: Materialize and validate a real RFuzz client under resource limits

Files: pinned reference `third_party/rfuzz/upstream/rfuzz_reference`; integration implementation `src/myfuzz/integration/rfuzz_live.py`, tests `tests/integration/test_rfuzz_live.py` as needed. Main agent owns this task.

- [ ] Inspect pinned upstream client/server wire formats and dependencies; preserve the upstream Git pin. Build the client with one job in a new isolated build output, with a finite timeout and measured group RSS. Record dependency/build failures accurately and address only necessary compatibility issues using explicit vendor patches if needed.
- [ ] Define tests for exact big-endian request/coverage headers, aligned input records, finite cycle count and bounded shared buffers from the upstream implementation. Reject malformed lengths, wrong magic and record-size mismatch before driving RTL.
- [ ] Implement the matching simulator connection, generated-layout input projection and real coverage counter return. Verify corpus replay yields the same input/counter trajectory on a deterministic RTL fixture before running mutation mode.
- [ ] Run a short supervised real-client campaign, requiring positive inputs and actual coverage/corpus artifacts, then review. A mere working `kfuzz --help` or random traffic process does not finish this task.

## Subsequent acceptance gates retained from the approved platform plan

Verified parameter/packed-struct elaboration and endpoint member mappings; common peripheral aliases and physical implementations; shared AXI routing with declared ID/burst support; appropriate TileLink boundary and BOOM-generated RTL; actual Ibex/CVA6/BOOM execution. Once those integrate, randomly choose3eligible real CPU/peripheral combinations, run each300seconds sequentially with checkpoints and resource limits, and audit coverage/error evidence. These gates cannot be marked complete with profile templates or synthetic traffic fixtures.
