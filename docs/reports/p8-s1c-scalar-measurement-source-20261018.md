# P8 S1c scalar transport measurement source

This report records a source increment only. At that time, no tests, model, build, remote execution, baseline measurement or performance claim had been performed. It implements only Task1's bounded measurement harness from [the batching design](p8-s1c-batching-plan-20261018.md), with the limitations below explicit rather than guessed.

`scripts/measure_dma_uart_transport.py` calls the existing `run_continuous_uart_rx()` once, using its original four bytes by default, unchanged default bounds and300000ms budget. It wraps only that call with the actual `observe_local_command_timings()` context manager. The observer's real signature is `(operation: str, elapsed_seconds: float)`, emitted in `GeneratedLocalSession.command()`'s `finally` after `_command_impl` returns or raises. The initial `_NATIVE_RESET_OWNER_GUARD_PIN[0](self)` call precedes observer lookup/timing and is excluded, including its failures. Therefore **observed command calls include `_command_impl` failures/prewire attempts after that initial guard and are not an actual wire-command count**. ACK time is included in the outer command duration when present. The script does not patch sessions, readers, driver, Runner, firmware, command streams or result fields.

The callback retains count/sum/max for at most64 operation names (name length128); invalid/overflow callback counters cause nonzero exit. It stores no per-call timing array. Inputs are bounded to1..16 bytes. Only an explicitly supplied nonblocking heavy-worker lock is acquired; its parent must already exist, root must supply the canonical path, and this script must be the sole lock owner rather than run under a nested held lock. Project imports and execution occur after lock admission. It disables bytecode writes before project imports. Output must be a new directory.

Outputs:

- `scalar-result.json.gz`: the runtime's unchanged `to_document()` serialization, including original source pins, build/session identities, plan, cases, events, ticks and uncertainty/failure fields. The gzip and uncompressed bytes are SHA256-bound in the report.
- `timing.json`: operation aggregates, logical plan count, saved UART PRE/POST tick-sample and observation event counts, original runtime wall duration, import duration and process CPU deltas. Every count is named by its actual source; no callback count is labeled an actual wire count. `ContinuousRxFailure` retains its original diagnostic result. Runtime exceptions caught after imports yield a timing report with no bundle. Lock-open, nonblocking lock-acquisition and project-import exceptions instead yield `operation.json` without claiming a runtime measurement. Serialization/output errors propagate instead of creating a success report.

Unavailable metrics are explicit: actual wire commands/bytes, ACK count, separate build/startup/steady-state duration, native-only CPU time, effective search duration and fresh comparison. Python CPU is `time.process_time()`; descendant CPU is `RUSAGE_CHILDREN` delta and may include build/compiler children. Runtime wall includes build/startup/finalization if the normal call performs them. Import duration is separately recorded. Operation sums include validation and parsing, and cannot isolate pipe cost. The measurement uses monotonic wall timing and has overhead; it does not compare instrumented and uninstrumented speed itself.

Future root-coordinated invocation after source review and source/tool freeze (not executed):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/measure_dma_uart_transport.py \
  --output /root/fanzehui/myfuzz/evidence/p8-s1c-scalar-measurement-attempt1 \
  --cache-dir /root/fanzehui/myfuzz/cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

The lock example retains the established canonical shared lock; root must verify the new workspace README/current coordination before scheduling. There is no source-copy/lock-policy change in this increment. The script itself can build/run actual hardware when invoked, so it must not be run as a pure syntax check or smoke test.

At source-review time, the next gate was an isolated actual scalar measurement. That one-shot run and its saved-byte audit have since completed; see [the actual measurement report](p8-s1c-scalar-measurement-attempt1-independent-20261018.md). A separately scheduled ordinary full/failure fresh replay remains necessary. Tasks2–5, protocol/driver/Runner batching, 5× performance and P8 acceptance remain open.

## Receipt follow-up (source only)

The outer operation now records bounded `operation.json` with explicit stage (`lock_open`, `lock_acquire`, `project_import`, `measurement_setup`, `runtime`, `result_write`, `timing_write`, `measurement_finished`), lock/import/runtime-entry flags and completed/failed status. Lock/import exceptions are re-raised unchanged after attempting the failure receipt; error type is capped128 characters and message2048. If receipt writing or stderr itself fails, those secondary failures do not replace the primary exception. Output-directory creation and CLI parsing still precede operation ownership, so their failures propagate without writing into an existing/uncreated output directory. No model launch is inferred from `runtime_call_entered`: before that field becomes true, lock is acquired and project imports complete, but model entry is still delegated to the original runtime.

The runtime's original diagnostic document is unchanged. Its independent timing/operation error summaries are bounded. No tests or imports were executed for this follow-up.

## Task2 dependency proposals after source inspection (not implemented)

Current actual bounds live in `driver_renderer.py:render_local_driver`, `rtl/local_driver_v1.h:BoundedReplay`, and `wire.py:_payload`. The generated conservative snapshot bound is `S=len(canonical_json(maximum_snapshot))`, including actual backend widths, physical exports, aliases and any probe/tap groups. Existing register/UART sample maximum is `M=2*effective_max_wait_cycles+5`. Existing reservation is `2*(M*(2*S+128)+S+len(json.dumps(maxima_backend))+1024)+512`; generation rejects reservation above2097664 bytes. Payload JSON cap1048576 bytes, reply cap2097664 bytes, replay cache67108864 bytes, command-line cap1024 bytes and host ACK cadence16 parsed receipts are existing constraints, not proposed increases. `BoundedReplay.accept()` validates/reserves request+reply capacity before Fresh execution.

1. An opt-in UART32 contract must calculate `M=max(2*wait+5,32)` from the admitted concrete snapshot and include block metadata overhead in the root bound; reject before effects if it exceeds current caps. No concrete numeric UART32 snapshot bound was computed in this source-only follow-up, so fit is not yet proven. `clock_edges` for multi-clock samples require explicit serialized maxima too: the existing128-byte sample margin must not silently be assumed sufficient for arbitrary clock schedules. Keep scalar generation unchanged and reject unsupported multi-clock block admission until its exact bound is owned.
2. Current `wire._payload()` accepts an exact7-key `local_driver_result.v1` payload; it rejects count/rx_bits additions. A new closed block schema needs an operation-aware parser entry point selected by exact admitted driver contract, not optional fields accepted globally. `parse_driver_receipt`, its session callsite, `_expected_ready` and canonical build projection must bind that selection. Scalar schemas remain strict. Existing sample parser already demands `len(samples)==after-before` and contiguous ticks; block parser must additionally check count==requested count and exact driven bits.
3. Header `CommandSet` must gate new opcode; `parse_command` and BoundedReplay's reparse must use the same admitted set. Runtime kind alone is insufficient opt-in. The generated metadata's `max_samples_per_command`/`reply_reservation_bytes` and actual C++ reservation must agree; no metadata-only capability. Driver header digest changes affect build identity even on shared scalar consumers.
4. `GeneratedOpentitanUartSession._take` currently checks `len(samples)<=max_local_ticks_per_register_access` and scalar STEP exactly1. It needs a distinct block consumer and actual receipt+edge-index references before any native use, never a global relaxation. Runner peredge commit and typed grouping remain later reviewed tasks. No Task2 code, schema relaxation or new native operation is authorized by this receipt fix.

Frozen script SHA256 for this receipt follow-up: `91eb4652ce81aa2dbddc4da200f9b90f26dd2bebdd2d4ffd5bc98cf9d793f8ee`. This pins source bytes only, not executed verification.
