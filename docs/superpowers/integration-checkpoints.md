# Integration Checkpoints

| Node | Commit | Required gate | Status |
| --- | --- | --- | --- |
| I0 | `c453004` | Contract validation | Published |
| I1 | This commit | `PYTHONPATH=src python3 -m unittest tests.integration.test_memory_gate -v` | Verified memory gate and worktree checkpoint |

## I1 Host Gate

Use the shared host-local memory gate to claim and launch each complete
Verilator build as one lifecycle:

```bash
python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner I3 \
  --exec python3 scripts/run_composition_harness_smoke.py \
  --fixture tests/fixtures/rtl/small_mmio --out-dir /tmp/myfuzz-joint-smoke
```

`--exec` records the blocked child PID, starts that same process only after the
claim succeeds, and releases its token after the process exits. Callers that
already manage a workload process may instead pass its live PID with `--pid`.
A standalone claim prints a JSON lease containing `lock_path`, `owner`, `pid`,
and `token`; its matching release must pass `--token`. If a claim or managed
execution fails after a lease cannot be safely rolled back or released, the
nonzero CLI result also prints that retained lease JSON so the caller can
perform an explicit token-checked release.

The lock lives under the host temporary directory and records its owner,
requested memory, workload PID, timestamp, token, and optional caller fields.
A claimant reclaims a lock only after its recorded PID is no longer alive.
Claim and release polling are bounded. Unreadable records are retained unless
an operator explicitly requests `--cleanup-unreadable`.

Encoded records are rejected before publication when they exceed the bounded
64 KiB observation limit. PID probes normalize values outside the platform
process-ID range to `GateError`. Publication and identity-checked deletion
`fsync` the parent directory; explicit unreadable cleanup also handles a
permission-denied regular inode without following it or deleting a replacement.
The Python `Lease` returned after a successful claim also carries the exact
immutable bounded record bytes that were written and file-`fsync`ed. If claim
finalization must roll back a published lease, a successful unlink retires that
lease even when the later directory `fsync` reports an error; that condition is
a plain `GateError`, while only an extant or unverifiable lease is retained.

The per-lock `flock` sidecar is a cooperative protocol: every claimant,
reclaimer, and releaser must use this script or its Python API. It serializes
participants and narrows pathname replacement races, but cannot protect
against a process that directly rewrites or unlinks gate files while bypassing
the sidecar.

Formal B6 merge prerequisite: this branch does not contain scheduler `jobs.py`.
The harness scheduler's `JobClaim` must retain the exact `Lease` returned by
the gate, `run_job` must pass that same claim to `release_job(job, claim)` on
every exit, and release must pass `claim.lease.token`; owner-only release and
legacy fallback are forbidden. It must validate `Lease.record_payload` rather
than reopening `Lease.path`, including after a FIFO, symlink, malformed, or
oversized successor replacement; automatic audit failures may attempt only an
exact-token release and must not request unreadable-record cleanup. The merged
scheduler test must round-trip `seed` and `candidate_hash` and prove a delayed
release cannot remove a same-owner successor lease.

The composition and harness worktrees are separate branches and must remain
free of build output. Integration work consumes their published commits only.
