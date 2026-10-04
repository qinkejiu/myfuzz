# Native completion memory runtime — PicoRV32 evidence

Base: `5c7d668`; isolated worktree `/tmp/myfuzz-local-pico`. Plan commit `ce41305`.

## Scope and source facts

Pinned PicoRV32 `ef203c2b0a3fb793280f5114941416c425c5b461` computes `mem_xfer = mem_valid && mem_ready`, consumes read data on completion, holds a transfer until completion, and uses nonzero write strobes for writes. The profile now supplies typed `completion_semantics=completion`, `address_units=byte`, and an explicit physical instruction-marker port. These facts are included in profile/artifact/build identity; missing or contradictory typed semantics are rejected. Selection depends on endpoint protocol/function and typed capabilities, with no component/module-name branch.

The registry selection remains a contract-only record. This report establishes standalone native RAM/ROM operational support with persistent program state and fresh replay. It does not establish native MMIO/IRQ or cross-component acceptance.

## Changes

- A separate `native_completion_memory_adapter` supplies no early ready. It captures one request, accepts one backend response, and asserts ready with actual response data. Backend error, bounded request/response timeout and request instability produce a sticky terminal fault without fake successful completion. Completion-edge instability suppresses ready combinationally. The existing generic ready-valid adapter remains unchanged for its callers.
- Generic `native_memory_cpu` runtime/STEP_MEMORY driver support uses the authenticated wrapper, fixed 32-bit backend, retained native physical observations, bounded wire envelope and exact existing source/header/build admission. Driver faults return ERROR; the native host session aborts the process without successful completion.
- `GeneratedNativeMemorySession` services actual accepted RAM/ROM beats once via MemoryService/TransactionLedger and PersistentMemory. Every accepted write uses observed RTL address/data/strobes. Unsupported/unmapped backend accesses abort the process before delivering completion.
- Strict native service identity names the RAM/ROM-only policy and source component. ScenarioManifest regenerates native source/wrapper/runtime/driver/build identities, binds session class to artifact kind, and checks generated reset counts/hashes. JSON runtime schema includes the dedicated native identity variant.
- Generic source parameter evidence accepts a numeric implicit packed builtin declaration, such as `parameter [0:0] ENABLE_IRQ`. No cast or component-name exception is added; unsupported expressions/types still fail closed.

## Tests

Tests were written before implementation: initial source-backed runtime failed on the implicit packed declaration; native driver failed with `driver-runtime-kind`; native session import was missing; formal service identity lacked its schema field. Additional RED tests exposed completion-edge ready on an unstable request and excessive reset-release clocks exhausting the adapter wait before READY.

Broad regression:

```sh
PYTHONPATH=src python3 -m pytest -q tests/local_harness \
  tests/scenario/test_generated_local_contract.py tests/scenario/test_contracts.py \
  tests/scenario/test_host_source_identity.py
```

**184 passed, 1 skipped, 177 subtests passed in 205.93s**. Existing CVE2/GPIO driver/build/reset/contract tests passed. The skip is retained legacy opt-in coverage. Final native runtime/adapter plus actual program modules: **8 passed, 14 subtests passed in 45.84s**. The focused adapter test uses actual `verilator --binary --timing -j 1` and covers no early ready, data completion, error, timeout, held-request changes and completion-edge changes.

Actual native integration command:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_local_native_memory_generated_real.py
```

**2 passed in 29.59s**: persistent store/load with fresh replay, and unmapped backend termination without fake completion. A separate retained run validates ScenarioManifest and genome preflight before execution. Actual `--lint-only` exited **0 with no diagnostics**. Actual build uses `--cc --exe --build -j 1` and the existing bounded atomic builder.

## Retained real execution

- Status: `complete`; fresh full replay matches: `True`.
- Ticks: 240; semantic event records: 612; physical instruction-marker fetch acceptances: 34.
- One process executes two rounds with state 5 → 6 → 7. Actual accepted stores are `(256,6), (260,6), (256,7), (260,7)`; RTL load readback supplies the mirrored stores. Final RAM words at 256/260 are both 7. No inter-round reset or program reload occurs.
- Program bytes: `9300001003a100001301110023a0200083a1000023a2300003a100001301110023a0200083a1000023a230006f000000`.
- Artifact SHA: `789b16d827585554d51bd1908454f1c7bc8593fb2d18807b91d76a713ab995ca`.
- Driver SHA: `3d3eb0f63d3d0b3e1fce7e5ed8724cbc94f256b057e458f932e70a3d3b8ca040`.
- Build SHA: `57ce31b38c17ac6264c149153b8a091c26a36355e4157c97d43f181c6fd44d15`.
- Binary SHA: `bbf82f5124fc6eab0c3f09acffb7f74b93f72ca08cea26413ac9e6c12b298318`.
- Semantic trace SHA: `b0fdbc016f0423ecf7e59ef6ef7f4ba7b94f4e2b115cb4d773b09eaa6f8acf96`.
- Replay manifest SHA: `72af46d07d0cb69032c24518d8d6aaa6ac4397f5bd8783f9ab993fbd9dfd41de`.
- Verilator: `Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`.

Retained path: `/tmp/native-memory-runtime-evidence/`. It contains `summary.json`, artifact/ScenarioManifests, full reference/replay traces and `lint.json`. The final build directory contains source snapshots, generated SV/C++, actual argv, manifest, build log and executable. The source script `/tmp/record_native_evidence.py` records the separate formal-preflight run.

## Current limits

32-bit byte-addressed, aligned word beats only; write byte strobes are preserved; zero read strobes map to all four read lanes. Single outstanding transfer; no physical error pin, so errors terminate without completion. RAM/ROM service only: no native MMIO router/deferred target, IRQ, clock crossing, pipelining or burst support. Native custom IRQ/PCPI stay disabled by pinned parameters. The optional instruction marker is an explicitly selected observation, not an inferred protocol role. Reset release clocks cannot exceed the effective wait bound, to avoid pre-READY timeout.

Declared per-operation bounds are one driver tick/sample, one transaction, at most one pending response, and at most four materialized RAM bytes. RESULT reservation and cached bytes remain fixed in authenticated driver limits. Uniform final-state/evidence-record byte declarations are a separate parent task; this report does not claim its budgeted-evidence gate. Profile/source-lock evidence retains its source-oriented status rather than silently promoting unrelated protocols or component composition.
