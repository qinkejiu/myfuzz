# Integration Checkpoints

| Node | Commit | Required gate | Status |
| --- | --- | --- | --- |
| I0 | `c453004` | Contract validation | Published |
| I1 | This commit | `PYTHONPATH=src python3 -m unittest tests.integration.test_memory_gate -v` | Verified memory gate and worktree checkpoint |

## I1 Host Gate

Use the shared host-local memory gate around each complete Verilator build:

```bash
python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner I3
# Run one complete build or smoke command.
python3 scripts/memory_gate.py --release build --owner I3
```

The lock records its owner, requested memory, PID, and timestamp under the
host temporary directory. A claimant reclaims a lock only after its recorded
PID is no longer alive. Claims poll only until their configured timeout.

The composition and harness worktrees are separate branches and must remain
free of build output. Integration work consumes their published commits only.
