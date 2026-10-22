# P7 I5 Attempt1 independent evidence and rubric audit (2026-10-22)

## Verdict

The current-source CV32E20 + PULP Timer run passes as a **bounded selected compiled-F4 evidence slice**. It improves the I5 evidence and supplies original-process exit receipts for this run. It does **not** close formal P7-E, P6, or P8.

The raw evidence and P7-E rubric were reviewed independently. A further read-only check recomputed all source hashes listed by the saved compiled-F4 prefix against the current working tree. No tests, builds, native runs, or remote operations were performed during these audits.

## Evidence checked

All raw files are under [`attempt-1`](evidence/p7-i5-cv32e20-pulp-timer-20261022/attempt-1/).

- Positive CLI run: `status=complete`, exit 0, five certified receipts, `compiled_receipt_join.v1` status `ok`, five rows. The selected path is `F4:ram.image`, source `peripheral.TIMER0_CTRL.value.mmio`.
- First/fresh replay: full scope, `matches=true`, 1,340 events and five records. Serialized first/fresh prefix bytes are equal (SHA-256 `849ae432d6351204c56e500b228dd4e5c1e2d79058d8a259a10b53ce91992328`). Normalized prefix SHA-256 is `4a2890ade43a24ec465475cd524554cd7629bfa32ef9d8cec47d1a561eb9a9ec`; semantic hash is `ead0380aafc4497d5184ca65036b141f3ee6e24b3fd2ce4bfc01f1a09c89e18f`.
- Both original and fresh execution audits are closed. CPU and peripheral processes in both runs were reaped with return code 0. Original PIDs were 364253/364296; fresh PIDs were 369117/369160; all four execution nonces are distinct.
- Receipt joins and source-lock/artifact/runtime identities are internally consistent; all 17 bundle manifest entries were checked. The online run identity includes 38 source entries checked against the current workspace. The separate [`compiled_f4_prefix` recheck](evidence/p7-i5-cv32e20-pulp-timer-20261022/attempt-1/invocation/source-closure-recheck.json) confirms all 504 listed source hashes match the current worktree at 2026-10-22 13:39 UTC (zero missing, zero mismatch). This comparison is not a clean-room rebuild or proof that the worktree was immutable.
- Wrong-CPU invocation: CV32E40P override refused with CLI exit 1, code `composition-profile-not-reviewed`, pointer `/cpu/request`, and session `not_requested`. It is an early configuration/profile mismatch refusal before harness generation or session startup.
- Software negative-group invocation: exit 0, **231 passed, 2 skipped**. The `pytest -q` log does not identify the skipped tests or reasons. N1–N8 regression groups are represented in that command; the wrong-CPU CLI refusal is not itself the N1 name-similar artifact-admission case.

## Why P7-E remains open

The selected F4 binding is meaningful evidence: the compiled-F4 prefix binds the same-run selected path and its declared execution identity. The ordinary online session nevertheless reports `runtime_path_status=legacy_unchecked`; the runtime projection supports F4 only and does not establish the general D3 runtime-path contract flowing through the live session. `capability-report.assertion_results` is empty. The D2 harness set has `binary=null` and `built=false`, with nested build status `structural_only`; no generated D2 harness binary identity is joined to the native F4 processes.

The plan's useful-throughput gate is also unmet by this report: effective cases/s and certified chains/s are both `0.0`, while the nonzero all-receipt rate (about `0.064/s`) is not a substitute. Build and RTL compile cost are absent. The client is recorded as `external_binary_only`, and the run used the existing shared compiled-F4 cache.

Capability remains bounded to the registered PULP `TIMER0_CTRL` F4 row. F5 IRQ and F6 DMA are unsupported; `Cross-component accepted=0` and `Bug confirmed=0`. The selected-path evidence does not establish general execution of D3 sources, constraints, seeds, all paths, and assertions by the online decoder/Runner/checker, and does not provide a D2 harness build identity tied to the D4 execution.

The former §5 path `tests/onboarding/test_p7_negative_fixtures.py` is absent from the current tree. The P7 implementation plan now points §5 at the six current modules used for the N1–N8 software regression groups. A similar-name CLI admission negative remains a separate formal gap.

P6 still lacks the persistent single-harness, per-edge-source, and closed-loop four-hit gates; P8 S1c remains 1.37x against its 5x target. This I5 audit does not change either status.
