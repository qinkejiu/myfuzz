# Native completion attempt1: independently confirmed planning failure

Actual attempt1 failed. Parent PID3107064 returned1; actual directed gate
child PID3130216 returned1. The outer SSH terminal returned1 at08:33:19UTC.
These are terminal observations, not an inference from a missing process.
The four Git metadata/connectivity children each returned0. All captured
child and parent stdout/stderr hashes agree with their terminal receipts.

The gate traceback reaches frozen `src/myfuzz/local_harness/plan.py:212` and
raises `native-physical-observation-protocol-unsupported` while constructing
the opt-in CPU artifact. The frozen planner admitted raw observation only for
its previous protocol whitelist; the ready-valid-memory request was refused.
The exception occurs before runtime/session construction completes and before
the gate's process capture, begin or case loop. No saved DUT process receipt,
case, plan, original/fresh trace, raw metrics or gate summary exists. Profile
elaboration/frontend activity may already have happened before this refusal;
this attempt must not be described as having performed no frontend work.

Authorized independent read-only collection ran08:35:57–08:35:59UTC over
the required two-hop SSH path. It used only standard-library file reads,
hashing, directory inventory and `/proc` existence checks. The exact specified
parent/gate PIDs3107064 and3130216 were both absent at08:35:58UTC.
`cache-native` exists but contains zero files and zero child directories;
`run-directed` contains only an empty `positive` directory. There are no
compiled model/cache artifacts or model receipts in the collected attempt.
This is the expected pre-model failure boundary, not eight actual DUT exits.
No global process claim is inferred from the two specified PID observations.

Saved source-before/source-after file maps are byte-identical and retain
SHA256 `94de100ab2ab50f3674f179378c9138d73cec873c68ae401bc43f9cb63e76cd1`.
Directory maps likewise retain file SHA256
`861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36`.
Before/after tool records are byte-identical, retaining the selected environment,
entrypoints,115 Verilator share files and581 pythonlib files. Environment SHA
is `9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c`;
inventory SHA is `9672f2b6ab65a587c8533e574851cf8990ead9867e0d089d0c3f030af1470d10`.
The Git root HEAD remains baseline `6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941`;
the separately pinned overlay source selection was
`acc47fe9a2b169e56e873821e27968a47e80ed08`.

Evidence is retained under
`docs/reports/evidence/native-completion-attempt1-20261018/`:
the read-only collector source, complete gate-control and gate-parent streams,
empty run directories, input gate scripts, exact outer launch records and
initial observation, saved-data audit source/result and download receipt.
`remote-terminal-controls.tar.gz` excludes project/cache contents and has
SHA256 `61360b181155ef0f4e6778afb16bbc90aae6264ea74b00ff3a92c62f1fdd8b3e`.
Its members and hashes are recorded in `independent-failed-audit.json`.

The independent saved-data failure audit used no project imports, runtime
checker, live Observer, frontend, compiler, model or tests. The successful-run
auditor remains an unexecuted draft for later review. No retry or source
mutation was performed by this audit. Attempt1 provides no native completion,
source-consumption, fresh replay, feedback or P6 acceptance pass.
