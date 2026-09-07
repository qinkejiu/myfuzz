# P0 RFuzz continuation evidence (2026-09-07)

Status: P0 small-RTL official-client loop and hardening verified. No real CPU acceptance is claimed.

## Initial state

Worktree `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`, branch
`feature/ibex-protocol-longrun`, starting HEAD `ed64054`.
Existing tracked and untracked implementation was preserved. The user-owned
`.superpowers/sdd/task-2-report.md` was not edited. No RFuzz client or compiler
was live at initial process inspection. Artifact and protected-file fingerprints
are saved in `runs/p0_resume_20260907/baseline-provenance.json`.

## Independent review

A separate read-only reviewer inspected the projection slice-width/range
snapshot, simulator RSS polling, bounded publication lint and FIFO deadlines.
No blocking issue was found in the slice/range, RSS cadence or finite FIFO
checks. The reviewer identified lost Verilator diagnostics: the campaign
supervisor parses JSON metrics and discards ordinary lint stderr; the temporary
report directory is then removed. A bounded diagnostic capture fix now retains at most 64 KiB plus a truncation sentinel, using os.read and unbuffered file writes; normal-failure and stalled-lint RED/GREEN tests passed.
This review does not prove instantaneous RSS bounds between 100 ms samples.

## Real official-client experiments

The existing unmodified official client binary was used, pinned to
`651f28f1583e14a4aa9d8dfc624b700e6da3a143`. No client rebuild or upstream source
patch was performed. Runs were sequential, nice 15, with no waveforms.

| Run | RTL tests | Corpus entries | Exit | Elapsed | Sampled child-group peak |
|---|---:|---:|---:|---:|---:|
| Original runner, optional `-c` table | 100213 | 7 | -11 | 12.999 s | 17862656 bytes |
| Diagnostic wrapper omitting only `-c` | 100213 | 8 | 0 | 14.094 s | 17342464 bytes |

Both requested a 2-second mutation interval; elapsed time includes the upstream
queue-item drain after SIGINT. The original timeout did not recur after RSS
polling optimization, but the first run segfaulted after `Total Coverage:`.
Logs: `runs/p0_resume_20260907/live-test.log` and
`live-lkdnx11j/run/{client.log,report.json,corpus/}`. Eight creator-owned segments
were cleaned after the crash, and none remained.

The isolation experiment changed only the optional final table output flag,
through a temporary Python Popen wrapper; it retained ordinary deterministic
and havoc mutation. Evidence: `runs/p0_resume_20260907/no-table-experiment.log`
and `no-table/run/{client.log,report.json,corpus/}`. The client removed its own
segments on this successful exit. Event maxima were `[12,11,12]`.

The dependency actually used by this binary, prettytable-rs 0.6.7, implements
`AsRef<TableSlice>` with mutable aliasing and an unchecked `transmute` from a
struct containing a Vec to one containing a slice (`src/lib.rs:528-535`). The
upstream `config.rs:221` table printer reaches that path. This is a strong
source-level explanation of the observed printing failure, not a debugger
backtrace. Omitting presentation is a compatibility choice; coverage feedback,
corpus storage, final raw bitmap and statistics remain enabled.

## Evidence boundaries and outstanding gates

All runs above execute a small synthetic accumulator RTL with actual official
RFuzz mutation and actual sampled-output-bit-events-u8-saturating feedback.
They are neither branch/toggle/line coverage nor Ibex/CVA6/BOOM CPU validation.
The initial peak excludes Python runner RSS and is explicitly child-group only.

The P0 changes and final verification are recorded below. This does not
upgrade the real-core support level. P1-P4 from the
root handoff remain open; historical synthetic 3x300-second campaigns do not
satisfy real CPU acceptance.

## Final P0 implementation and verification

Final official-client run: `runs/p0_resume_20260907/final/live-r4kbrr26/run/`.
It completed 100213 real RTL tests, saved 6 corpus entries, returned event maxima
`[8,8,9]`, and exited 0. Requested duration was 2 seconds; SIGINT was sent at
2.000009 seconds; client drain/cleanup was 7.779795 seconds and total elapsed
including simulator teardown was 10.033051 seconds. Aggregate sampled RSS peak
was 98189312 bytes (runner PID plus owned client/simulator groups). No owned
segments required removal and none remained. Upstream randomized mutation means
corpus counts and inputs differ between runs; no fixed global mutation seed is
claimed. Each entry retains upstream lineage and raw input bytes.

Final binary SHA256:
`bbb72e52e60b1380cccd3b8c25febf0b6ccde51b17802d457ffadef43f87747b`.
Its upstream checkout pin and Cargo.lock hash are in baseline-provenance.json;
run reports contain binary, config and simulator hashes, source hashes/pin,
ISA description, composition hash/seed, transport identity and coverage semantics.

The runtime now persists startup/execution failures, propagates external
SIGTERM/SIGINT at supervised checkpoints, restores prior handlers, and completes
owned client-group TERM/KILL and shared-memory cleanup before propagating errors.
Zero-test, missing-corpus and leftover-segment runs cannot report completed.
Aggregate 512 MiB soft checks include the Python runner and are also invoked
inside blocked RTL exchanges; 768 MiB is the configured hard ceiling, not a claim
of kernel-enforced instantaneous RSS. Sampling is throttled to at least 100 ms;
scheduling and input encoding can delay checkpoints. No unrelated process group
is included in cleanup.

Replay compares every stored input with newly executed RTL counters and validates
upstream coverage-record padding. JSON admission scales with supported input
width and 200-cycle bound. The maximum-width JSON unit test mocks only RTL to
exercise admission; the ordinary fixture and official corpus use real Icarus.
All 6 final entries matched (`run/replay.json`). Independent source-validated
recompilation and replay also matched (`replay-rebuild/replay.json`).

Exact full regression command (same worktree):

```sh
MYFUZZ_RFuzz_CLIENT="$PWD/runs/rfuzz_client_native_build/target/debug/kfuzz" \
MYFUZZ_RFuzz_RUNS="$PWD/runs/p0_resume_20260907/final" \
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
python3 -m unittest discover -s tests -p 'test_*.py'
```

Result: **904 tests / 40.973 seconds / OK**, with official-client opt-in enabled.
Complete stdout/stderr: `runs/p0_resume_20260907/full-regression.log`.
Expected negative CLI diagnostics remain in the log.

Exact independent replay command (choose a fresh output path on a later replay):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
python3 runs/p0_resume_20260907/replay_fixture.py \
  runs/p0_resume_20260907/final/live-r4kbrr26 \
  runs/p0_resume_20260907/final/live-r4kbrr26/replay-rebuild
```

The saved replay command is explicitly for the zero-component P0 accumulator
fixture; it does not claim general CPU artifact loading. Failed and intermediate
runs were retained rather than overwritten. RED/GREEN logs include
`live-failure-*`, `live-cleanup-*`, `sigterm-*`, `memory-red`, `provenance-*`,
`review-cleanup-*`, `monitor-red`, and `lint-*`; final full regression supplies
the integrated GREEN result. One intermediate replay unit fixture used the
wrong raw offset and was corrected to derive it from its layout fields.

A separate read-only reviewer found and rechecked the lost lint diagnostic,
maximum-width replay, signal cleanup windows, zero-work success and blocked-I/O
aggregate-monitor issues. Final static review approved all those corrections.
The main worker independently ran the complete suite and inspected reports.
Protected user-report fingerprint still matched the initial value; the final
process inspection found no active RFuzz/compiler/simulator from this campaign.
The final /proc/sysvipc/shm table was empty; no unrelated segment was removed.

Remaining project gates are P1-P4 in the root handoff: source elaboration and
member evidence, actual CVA6/BOOM RTL, full required protocol subsets, real CPU
execution and the random 3x300-second real-core campaigns. The existing protocol
and ISA references are research baselines with outdated capability snapshots;
they are not proof that their entire catalogs are implemented.
