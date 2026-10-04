# CVA6 Packed AXI4 Local Runtime Implementation Plan

> For agentic workers: implement each task with a failing focused test, then the smallest production change and a real evidence check.

**Goal:** Run the pinned CVA6 RTL in an independently generated local harness with real AXI4 transactions, persistent memory, and fresh replay.

**Architecture:** Retain the existing verified full top profile and 232-file source closure. The structural wrapper expands the pinned filelist deterministically. A dedicated `cva6_packed_axi4_cpu` runtime exports one 64-bit, ID4 AXI4 master and its declared interrupt entry. Its session advances one local edge per step, services only observed handshakes from persistent memory, and rejects unsupported AXI forms. No SoC fabric or CPU behavior is modeled.

**Tech stack:** Python 3, Verilator 5.051, SystemVerilog, C++ local driver, `ScenarioRunner` evidence/replay.

## Global constraints

- Full CVA6 top has 13 ports and 57 declared dispositions; `noc_req_o` is 470 bits and `noc_resp_i` is 210 bits.
- Runtime input ownership is explicit. Only the upstream RTL or persistent state decides bound values.
- No generated-runtime claim until a freshly built binary executes a real CVA6 program and a fresh session reproduces the trace.
- Unsupported ATOP, exclusive access, burst, ID, or outstanding behavior must fail closed or be backpressured according to a documented bounded policy.

## Task 1: Structural wrapper from pinned filelist

**Files:** `src/myfuzz/local_harness/renderer.py`; `tests/local_harness/test_cva6_source_lock.py`.

- [x] Write a failing test for structural CVA6 rendering from the verified 225-file expanded list.
- [x] Allow a filelist only when the trusted plan supplies the full ordered file expansion and source lock verifies it.
- [x] Confirm all 13 top ports and 57 dispositions are represented; commit the milestone.

## Task 2: Packed AXI4 runtime ABI and one-edge driver

**Files:** `src/myfuzz/local_harness/runtime_renderer.py`, `driver_renderer.py`, `rtl/local_driver_v1.h`, `session.py`; a dedicated AXI field contract; focused tests.

- [x] Write a failing test requiring one 64-bit/ID4 AXI4 channel and the physical IRQ port in the generated ABI.
- [x] Add strict shape and capability selection for the pinned CVA6 profile only.
- [ ] Generate driver command parsing, pre-edge observations, and one measured edge without fabricating DUT outputs.
- [ ] Compile the generated binary and observe reset release and a real first AR request.

## Task 3: Persistent service and replay

**Files:** a dedicated CVA6 AXI4 session, scenario/evidence integration tests, runtime documentation.

- [ ] Write failing tests for AR/R, AW/W/B, ID/LAST, strobe, and duplicate-handshake behavior.
- [ ] Service real 64-bit reads and byte-enable writes from `PersistentMemory`; bound B/R responses to accepted requests.
- [ ] Run a pinned RV64 program that fetches, stores, later loads, and writes an observable result.
- [ ] Save evidence and replay with a freshly built session, comparing transactions, memory, and trace.
- [ ] Record exact supported AXI4 subset and any remaining CVA6 runtime limits.
