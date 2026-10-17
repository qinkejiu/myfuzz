# P8 S1c scalar transport measurement source

Source increment only. No tests, model, build, remote execution, baseline measurement or performance claim was performed for this increment. This implements only Task1's bounded measurement harness from [the batching design](p8-s1c-batching-plan-20261018.md), with the limitations below explicit rather than guessed.

`scripts/measure_dma_uart_transport.py` calls the existing `run_continuous_uart_rx()` once, using its original four bytes by default, unchanged default bounds and300000ms budget. It wraps only that call with the actual `observe_local_command_timings()` context manager. The observer's real signature is `(operation: str, elapsed_seconds: float)`, emitted in `GeneratedLocalSession.command()`'s `finally` after `_command_impl` returns or raises. Therefore **observed command calls include failed/prewire attempts and are not an actual wire-command count**. ACK time is included in the outer command duration when present. The script does not patch sessions, readers, driver, Runner, firmware, command streams or result fields.

The callback retains count/sum/max for at most64 operation names (name length128); invalid/overflow callback counters cause nonzero exit. It stores no per-call timing array. Inputs are bounded to1..16 bytes. Only an explicitly supplied nonblocking heavy-worker lock is acquired; its parent must already exist, root must supply the canonical path, and this script must be the sole lock owner rather than run under a nested held lock. Project imports and execution occur after lock admission. It disables bytecode writes before project imports. Output must be a new directory.

Outputs:

- `scalar-result.json.gz`: the runtime's unchanged `to_document()` serialization, including original source pins, build/session identities, plan, cases, events, ticks and uncertainty/failure fields. The gzip and uncompressed bytes are SHA256-bound in the report.
- `timing.json`: operation aggregates, logical plan count, saved UART PRE/POST tick-sample and observation event counts, original runtime wall duration, import duration and process CPU deltas. Every count is named by its actual source; no callback count is labeled an actual wire count. `ContinuousRxFailure` retains its original diagnostic result. Earlier exceptions yield a timing report with no bundle. Serialization/output errors propagate instead of creating a success report.

Unavailable metrics are explicit: actual wire commands/bytes, ACK count, separate build/startup/steady-state duration, native-only CPU time, effective search duration and fresh comparison. Python CPU is `time.process_time()`; descendant CPU is `RUSAGE_CHILDREN` delta and may include build/compiler children. Runtime wall includes build/startup/finalization if the normal call performs them. Import duration is separately recorded. Operation sums include validation and parsing, and cannot isolate pipe cost. The measurement uses monotonic wall timing and has overhead; it does not compare instrumented and uninstrumented speed itself.

Future root-coordinated invocation after source review and source/tool freeze (not executed):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/measure_dma_uart_transport.py \
  --output /root/fanzehui/myfuzz/evidence/p8-s1c-scalar-measurement-attempt1 \
  --cache-dir /root/fanzehui/myfuzz/cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

The lock example retains the established canonical shared lock; root must verify the new workspace README/current coordination before scheduling. There is no source-copy/lock-policy change in this increment. The script itself can build/run actual hardware when invoked, so it must not be run as a pure syntax check or smoke test.

Next gate: independent source review, then root may authorize an isolated actual scalar measurement. A separately scheduled ordinary full/failure fresh replay remains necessary. Tasks2–5, protocol/driver/Runner batching, 5× performance and P8 acceptance remain open.
