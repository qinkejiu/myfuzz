# Task 16 processor/RFuzz regression and capability matrix

Date: 2026-09-08

## Result

The generic processor composition, generated wiring, real-Ibex execution,
RFuzz IPC feedback, corpus retention, and replay path pass the current bounded
acceptance run. The user explicitly deferred BOOM, the formal Task 14 closure,
and the three 300-second Task 15 campaigns. Those gates remain open and this
report does not claim the complete plan is accepted.

## Fresh verification

- Focused processor/runtime/RFuzz suite: `103 passed, 3 skipped, 114 subtests`
  in 56.15 seconds.
- Composition and integration aggregate: `768 passed, 3 skipped, 558 subtests`
  in 105.12 seconds.
- Full Python regression: `1055 tests`, `OK (skipped=3)` in 105.948 seconds.
- `git diff --check`: exit 0.
- Post-run process/shared-memory audit: no owned `kfuzz`, Verilator, pytest, or
  campaign process remained; `ipcs -m` listed no shared-memory segments.

The full regression command was:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

## Real CPU/RFuzz bounded evidence

Evidence: `runs/task15-live-preflight-v3/`.

- Automatically loaded the source-backed Ibex interface, selected the OBI
  adapter from protocol facts, allocated boot RAM and register-target address
  windows, generated the SystemVerilog top, and compiled it with single-worker
  Verilator.
- Real execution probe: 11 requests, 11 completions, 10 successful reads,
  10 distinct-read progress events, one peripheral pass completion, and zero
  errors; the first fetch matched the boot image.
- Five-second RFuzz run plus bounded drain: return code 0, 15,357 RTL tests,
  13,440 completed feedback receipts, 19 retained corpus entries, and no
  remaining SysV shared-memory segment.
- Every retained corpus entry was replayed against RTL. All 19 entries record
  `coverage_verified=true` and `shared_memory_exchange_verified=true`.
- Replay identity records raw input, layout, constraint, simulator binary,
  physical controls, simulator inputs, coverage, and replay-key hashes.
- Feedback kind is accurately named
  `sampled-dut-signal-bit-events-u8-saturating`: 18 explicitly randomizable
  DUT interrupt-input bits plus two internal backend request/response events.
  It is not represented as branch or line coverage.
- The fixed upstream client revision is
  `651f28f1583e14a4aa9d8dfc624b700e6da3a143`. The bounded cancellation build
  has SHA-256 `a8229ef5d003b1bbdae997b326fb36071a48ecf2c637d61b2c785b84a1c01c38`;
  its explicit patch
  `patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch` checks cancellation
  after a completed IPC batch without dropping a submitted request.

Apply and build the pinned client in its own checkout/output directory with:

```bash
git -C third_party/rfuzz/upstream/rfuzz_reference apply --ignore-space-change \
  ../../../../patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch
RUSTC="$PWD/runs/rfuzz_client_native_build/rustup/toolchains/1.85.1-x86_64-unknown-linux-gnu/bin/rustc" \
CARGO_HOME="$PWD/runs/rfuzz_client_native_build/cargo" \
nice -n15 "$PWD/runs/rfuzz_client_native_build/rustup/toolchains/1.85.1-x86_64-unknown-linux-gnu/bin/cargo" \
  build --jobs 1 \
  --manifest-path third_party/rfuzz/upstream/rfuzz_reference/fuzzer/Cargo.toml \
  --target-dir runs/task14_client_cancel_build
```

## Capability matrix

| Capability | Implemented | Fixture executed | Real CPU executed | RFuzz 300 s passed |
| --- | --- | --- | --- | --- |
| OBI to processor-memory-beat | yes | yes | Ibex: yes | no |
| AXI4 to processor-memory-beat | yes | yes | CVA6: yes | no |
| TL-UL to processor-memory-beat | yes | yes | no real CPU sample | no |
| Scratch-register personality | yes | bounded probe + live preflight | Ibex: yes | no |
| GPIO-register personality | yes | source-backed RTL tests | not run in this checkpoint | no |
| Timer-register personality | yes | source-backed RTL tests | not run in this checkpoint | no |
| BOOM boundary/execution | no | no | deferred by user | no |

## CPU-name dispatch audit

No `ibex`, `cva6`, or `boom` conditional dispatch occurs in the new generic
processor execution, auto-wiring, RFuzz simulator, execution monitor, or real
CPU campaign implementation. Repository-wide search still finds two older,
pre-existing CPU-specific validation paths:

- `src/myfuzz/integration/campaign.py`: legacy Ibex campaign top check.
- `src/myfuzz/composition/protocol_manifest.py`: legacy Ibex manifest check.

They are not called by `real_cpu_campaign.py` or the generic composition path.
Historical scripts/configuration and catalog data may name their test samples.

## Remaining gates

1. Formal Task 14 closure was skipped at the user's direction, although the
   later Task 15 preflight demonstrated its main bounded IPC/corpus properties.
2. Run scratch/GPIO/timer sequentially for at least 300 seconds each, retaining
   30-second checkpoints and independent rebuild/replay evidence.
3. BOOM Task 13c remains deferred and must not be reported as passed.
4. An independent code-review agent was not used because the platform twice
   blocked local RFuzz review prompts as cybersecurity content. The primary
   session performed diff inspection and fresh tests; independent review is
   still an explicit open gate.
