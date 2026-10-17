# P8 S1c scalar measurement independent source review

Reviewed commit: `46d27984250a811f1f405c88d4acdbc7637c3c01`, specifically `scripts/measure_dma_uart_transport.py`, its source report, and batching-plan Task1. Read-only source review: no project import, tests, builds, model or remote execution.

## Decision

No High/Medium findings in the bounded command-aggregate measurement implementation. Suitable for root-coordinated scalar measurement after independent source/tool freeze and canonical-lock admission. This does **not** finish batching-plan Task1 and is not a 5× or P8 acceptance decision.

## Checked paths

- Actual callback is `observe_local_command_timings(observer)` with `(operation, elapsed_seconds)`. `GeneratedLocalSession.command` runs `_command_impl` once and invokes the callback in `finally`, so failed/prewire attempts within that region are counted. The script does not replace receipts, methods, clocks or semantic events. Aggregation bounds operation names to64/name length128, stores count/sum/max only, and returns nonzero for invalid/overflow callbacks.
- Actual runtime call is exactly one `run_continuous_uart_rx(args.source_bytes, cache_dir=args.cache_dir)`, with no custom factory or budget argument. The real default four bytes, memory seed17, runtime default300000ms and source/protocol behavior are retained. Argument count1..16 is bounded. `result.to_document()` is serialized without measurement fields or identity normalization and SHA-bound compressed/uncompressed.
- `flock(LOCK_EX|LOCK_NB)` occurs before project imports/build/constructor/model. The lock is held throughout runtime and output handling, and released by the context manager. The reviewed runtime/factory/session/build chain does not acquire this heavy-worker flock again. If an outer controller already holds the same canonical lock through a separate open, the script refuses immediately rather than waiting; run it as sole lock owner. Canonical path/mode/symlink validation remains root's deployment responsibility; arbitrary CLI paths are not proof of exclusive worker admission.
- `ContinuousRxFailure` retains `exc.result`, saves the original diagnostic bundle and returns1. Other exceptions from inside the runtime timing try preserve type/message, aggregates and a timing report, with no invented result bundle. Serialization/output failures propagate. The runtime itself finalizes diagnostics and closes its boot in `finally`; this script adds no retry/restart/fallback.
- `whole_runtime_wall_seconds` includes normal source discovery/build/startup/run/finalization but excludes imports and output serialization. Import duration is separate. CPU deltas use Python process time and waited-descendant rusage, including compiler children where present. Operation sums include validation/transport/ACK/parser cost; they are neither wire counts nor isolated pipe time. Logical plan count, actual saved UART sample phases and observer-event count are separated. Unavailable metrics are explicitly null-by-description rather than inferred.

## Low observations / wording limits

1. The owner's phrase “earlier exceptions yield a timing report” applies only to exceptions inside the runtime try. Lock-open/admission, project imports and later serialization/output failures occur outside that try and produce no timing.json. This is acceptable before a DUT starts, but the scheduling controller must retain stderr/exit independently; do not advertise a report for every failure path.
2. The outer `_NATIVE_RESET_OWNER_GUARD_PIN[0](self)` runs before timing starts, so exceptions in that first guard are not callback-counted. The script's semantics are correct for observed callbacks; counts must not be called all `command()` entry attempts. Successful durations exclude that first guard while the duplicate inner guard remains included.
3. Clock aggregates cannot provide Task1's requested steady-state/build separation, actual wire/ACK/byte counts, native-only CPU, effective search duration, fresh typed prefix or S3 failure replay. The source report acknowledges these gaps. Source/tool/build freeze and full/failure fresh references must be separate root gates; this script must not tick Task1 fully complete or justify proceeding with batching on unmeasured transport dominance.

## Acceptance boundary

This review approves source structure only for a bounded measurement operation. It does not establish runtime success, environment availability, scalar/fresh equivalence, transport dominance, native CPU attribution, batching correctness or performance improvement. Preserve the real run's full diagnostics, operation lifecycle and source/tool maps, including any failure, before deciding the next implementation gate.
