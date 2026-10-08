# RVX Core standalone persistent RAM acceptance

Date: 2026-10-05. This report records a directed, real-RTL run of the pinned standalone `rvx_core` in a generated local runtime. It establishes a CPU-to-persistent-RAM path and deterministic replay for this profile. It does not establish a CPU-to-IP or SoC integration.

## Runtime scope and input ownership

Only `external_designs/rvx/hardware/rvx_core.v` is the CPU DUT. The harness does not instantiate `rvx.v`, `rvx_bus`, `rvx_ram`, or any peripheral. It exports the core's physical completion-memory pins directly to a host-side `PersistentMemory` service.

The testcase supplies a deterministic RV32I program image and a zeroed 12-byte data image. During execution the CPU response pins are not Fuzzer inputs: each response and read value comes from the accepted physical request and the persistent RAM service. One `STEP_RVX_MEMORY` command advances exactly one CPU-local rising edge. The testcase starts the RTL once, holds it for 128 local ticks, and has `reset_epoch == 0`; there is no testcase-internal reset. The configured response latency is one local tick. Before servicing an observed request, the session checks that the driver RESULT snapshot equals the same tick's post-edge sample. No global SoC clock or cross-component timing is modeled.

## Program and observed memory effects

The program sets `x1=0x100`, writes `0x12345678`, writes byte `0x55` at `0x101`, loads the word, copies it to `0x104`, and stores completion marker `1` at `0x108` before looping:

```text
SW 0x12345678, [0x100]
SB 0x55,       [0x101]   # byte lane 1
LW             [0x100]  # returns 0x12345578
SW 0x12345578, [0x104]
SW 1,           [0x108]  # completion marker
```

The accepted RTL writes, in order, were exactly:

| Address | Write data | Byte strobe |
|---:|---:|---:|
| `0x100` | `0x12345678` | `0xf` |
| `0x100` | `0x00005500` | `0x2` |
| `0x104` | `0x12345578` | `0xf` |
| `0x108` | `0x00000001` | `0xf` |

The load from `0x100` returned `0x12345578`. Final RAM words were `RAM[0x100]=0x12345578`, `RAM[0x104]=0x12345578`, and `RAM[0x108]=1`. The exact write history proves the held byte/word stores did not repeat. The test also checks that each serviced read/write has one unique transaction key, every accepted address is inside the declared 4 KiB RAM region, and the memory ledger has no unresolved transaction.

The evidence bundle replays the same program and memory seed in a new RTL process. Replay matched the complete scenario trace, ordered memory service events, final memory state summary, byte enables, and completion marker. The two `GeneratedRvxMemorySession` instances use distinct execution IDs.

## Reproduction and measured result

Run from the repository root:

```bash
PYTHONPATH=src:. pytest -q \
  tests/local_harness/test_rvx_memory_runtime.py \
  tests/local_harness/test_rvx_memory_session.py \
  tests/local_harness/test_generated_session_registration.py \
  tests/local_harness/test_source_lock.py

MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. pytest -q \
  tests/integration/test_scenario_rvx_core_persistent_memory_real.py
```

Measured result on the final focused run: **32 passed, 33 subtests passed** in 2.76 s; the real RTL acceptance and fresh-process replay completed as **1 passed** in 9.91 s. The integration duration includes generated artifact construction/build and both scenario executions. Tool versions were Verilator `5.051 devel rev vUNKNOWN-built20260806-e413e67` and C++ compiler `g++ 13.3.0`.

## Source and generated artifact identity

| Item | Identity |
|---|---|
| RVX revision | `38bdee0ef8da0b606b7024f85934898e99963756` |
| Selected source closure | `hardware/rvx_core.v` plus `LICENSE`; `rvx_core.v` SHA-256 `10a5672112eba824989923aeff8d6dccb70709177aee00066835421f610a8da4` |
| Lock selected-content hash | `sha256:e62bf4b6f6e0e97adf05c2323b62ad7dec51d38630bb869c5787a30ef7a266ab` |
| Component profile SHA-256 | `1691b168d191a1c141aacbb17d34abc322bdbf3eed46389c60d0d577076b486a` |
| Generated runtime artifact digest | `97f9e3b7c94fe5dc02845036e599a5fd417c98c1d874063c9f947d6528a49d6b` |
| Generated runtime SV SHA-256 | `faada5dfa74fc2d94bf921b9e351c7112a57f17091e34c0d3102685f4d8a304c` |
| Generated driver C++ SHA-256 | `dd6285acb23edac93ae8791954cb5556b16839e1f786ddeb24742116f6f835ad` |

The source-lock record remains `source_verified`, `elaboration_unverified`, and `runtime_unverified`. The generated runtime is compiled and executes in this test, but durable elaboration evidence is not recorded in the source lock. The directed test is not a coverage-guided fuzzing campaign and has not found a DUT bug.

## Limits

- The backend admits only aligned accesses inside the declared RAM region; it does not fabricate read data for unmapped MMIO.
- This directed CPU run preloads its instruction image and the small data window, so it does not exercise first-read initialization of uninitialized RAM through real CPU RTL. The local session tests cover frozen initialization/read snapshots separately.
- IRQ, halt control, instruction decode outside the directed program, and peripheral behavior are not covered.
- `rvx_bus`, the full RVX SoC, bus decode, bridges, arbitration, and global cycle-accurate SoC timing are not tested.
- The result supports this pinned `rvx_core` profile and this single directed scenario. It does not prove automatic harness compatibility for arbitrary CPUs sharing a protocol, or broad bug-finding capability.
- Source-lock `elaboration_status` and `runtime_status` remain unverified until their separate durable evidence gates are satisfied.
