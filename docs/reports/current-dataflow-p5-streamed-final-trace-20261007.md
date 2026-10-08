# P5: streamed terminal JSONL semantic SHA

## Change

Normal live runs that will publish `online_events.jsonl` now defer only the terminal semantic SHA until the JSONL writer. The writer hashes each canonical event while writing its exact UTF-8 bytes, completes the canonical payload with `local_ticks` and `status`, and publishes metadata containing the completed SHA. The in-memory final trace is replaced with that completed trace before run identity is written. `ScenarioSession.finish()` and small JSON traces keep their previous default hashing behavior. If session cleanup fails, the fallback trace still hashes the observed prefix normally; a JSONL write failure publishes no complete run identity.

The semantic preimage remains canonical JSON of `{"events":...,"local_ticks":...,"status":...}` with sorted keys, compact separators, UTF-8 Unicode, and no NaN. The JSONL event bytes remain identical to the previous text writer.

## Tests

- New unit tests checked exact canonical SHA on Unicode, nested objects, nulls, booleans and negative integers; they also checked rejection of a supplied mismatching SHA before metadata publication.
- Live transport test forced JSONL mode, checked the saved event payload, metadata SHA, in-memory final trace SHA, complete run identity, and full fresh replay. Another test forced a JSONL write error and checked that only incomplete identity was published. An explicit deferred-finish test checked the internal empty SHA boundary.
- Focused run: `36 passed, 4 skipped, 2 subtests passed` across terminal identity, JSONL semantic streaming, live client, and wall-cut replay suites.

## Fixed-event measurement

The first 50,000 events from the earlier 2.2 GB long-run `online_events.jsonl` were loaded into a fresh `EventJournal` snapshot and processed both ways in one process. The saved prefix was 51,830,097 bytes. The old procedure took 1.620 s to hash plus 1.707 s to write and `fsync` (3.328 s total). The new writer hashed, wrote, `fsync`ed, and published metadata in 1.796 s. The semantic SHA and JSONL bytes matched exactly. This local measurement excludes run identity artifact hashing and RTL execution, and does not establish an improvement for the full 600 s run until a new frozen long run is measured.

## Frozen RTL short gate

- Snapshot: `/home/qinkejiu/myfuzz_snapshot_p5_streamed_20261007`; manifest: `runs/current-dataflow-p5-streamed-snapshot-20261007.sha256`, 1,818 files, manifest SHA `9491fee5d4a4bd7a7057a11211ff99f88f8210c5451548445c4b22d1dc464844`. Every manifest entry still matches after replay.
- Live output: `runs/current-dataflow-p5-streamed-short-20261007-online`, seed `20261007`, 25/25 complete, 10,418 observed events, 11 MB JSONL, trace format `jsonl.v1`, semantic SHA `168b483471cd3fd60c136de226f7a499e989d1054b09c258ea2d35f19c046716`, complete run identity SHA `baa98103442553c3b60015ad3336fdb4e341a7dfd7cb3de2795552309de27887`.
- The fixed JSONL event threshold was overridden in memory to `1` for this short gate. No snapshot source file changed for the override; the gate directly exercises the JSONL branch with real Ibex and dual GPIO events. It is not a default-threshold performance sample.
- Saved finalization timings: `session_finish` 0.0524 s, `trace_write` 0.3339 s, `identity_write` 0.1334 s, `total_before_report` 0.5701 s. A fresh RTL replay from the same frozen snapshot, using a separate cache, returned `matches: true`, `first_difference: null`.

## Remaining gate

Run a new default-threshold long session to measure total finalization and effective search rate. The earlier long run remains evidence for the previous implementation only.
