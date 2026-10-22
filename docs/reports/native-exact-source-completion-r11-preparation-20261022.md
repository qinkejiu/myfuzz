# Native exact-source completion r11 preparation

## Current state

The current Stage 1 package is frozen at manifest raw SHA-256 `a944ef09f414642541854d36955a81b906f213b4705b2e09cc96372de7f84059`. Two independent exact-digest reviews accepted this package with no remaining findings; see [review A](evidence/native-completion-r11/reviews/stage1-review-a.json) and [review B](evidence/native-completion-r11/reviews/stage1-review-b.json). The package carries the one-shot controller, two-phase post-gate runner, source bootstrap, pinned gate/auditor copies, plan schema, and external launch contract. All seven member size/SHA rows match; gate and auditor copies match their working-tree sources byte-for-byte.

Executable software validation exposed three defects that static review had missed: the empty relative path represented by `.`, numeric `0`/`0.0` replacing JSON `false`, and loose equality on embedded `plan.intent` / `post.gate_end` copies. These are fixed. Controller admission calls the pure `plan_identity_check` at the original point before preflight map writes or claim; complete embedded copies and lock observations use recursive type-preserving comparison. The existing 64 MiB, no-follow, exclusive claim, frozen tools, cache lifecycle, and typed readback constraints remain in force.

## Executed software evidence

The final nine-file command, exact environment, PID, return code, unchanged input hashes, and raw input copies are retained in [verification.json](evidence/native-completion-r11/software-20261022-attempt2/verification.json); [pytest.log](evidence/native-completion-r11/software-20261022-attempt2/pytest.log) records **266 passed, 3 skipped, 32 subtests passed in 3.64s**, exit 0.

- Two auditors reject 128 numeric false claim substitutions across six receipts and two nested copies after every dependent SHA is resealed; valid baselines pass first.
- The controller admission validator has 38 cases: valid input, numeric replacements in standalone intent, plan, and nested intent, and the source-order check placing validation before claim. These do not execute full Stage 2 admission.
- Real disposable Python children exercise successful reaping and raw evidence/receipt joins, spawn/nonzero/missing-output failure, real source/submodule/protected/lock drift, and observation failures.
- An isolated Linux child-subreaper worker proves that a real same-PGID descendant remains observable after its parent is reaped, and the group disappears after descendant exit and reaping. This test executed successfully without a skip.
- File tests cover exclusive concurrent claim creation, canonical paths, hardlinks/symlinks, FIFO swaps, pre-read size refusal, growing-file refusal before hashing, exact static-manifest joins, and tool inventory identity.

The three skips are native opt-in replay tests requiring `MYFUZZ_SCENARIO_REAL=1` and the pinned PicoRV32 source. This evidence concerns local software and offline audit behavior; it is not a three-branch native gate.

## Preserved history and limits

The earlier reviewed `3d22a101…71feb` package and both review receipts are preserved under [stage1-history](evidence/native-completion-r11/stage1-history/). The `de66e595…740b9f` candidate is preserved with its Important review rejection for nested type equality. Its earlier 195-pass software run remains under `software-20261022-attempt1/` and does not supersede the later defect or final evidence.

R11 Task 4 remains partially covered: a complete frozen Stage 2 input package and full admission path have not been executed. There is no Stage 2 source snapshot, remote upload, claim, real gate, or native audit result. Last known SSH failure was `No route to host`; this continuation did not retry remote access. The independent auditor's `source_tree_closure_verified`, `external_tool_bytes_verified`, and `gate_executable_identity_verified` remain false. Task 5, P6/P7/P8, and the six-CPU/four-IP objective remain open.

## Next work

With target access available, select and justify exact snapshot exclusions, build the source/tool/runtime Stage 2 package, independently verify its exact inventory, complete remaining admission checks, obtain two exact-digest preupload reviews, upload beneath `/root/fanzehui/myfuzz/`, and obtain two complete target readbacks before the one-shot real gate and independent audit.

See the [r11 controller plan](../superpowers/plans/2026-10-22-native-completion-r11-controller.md) and [runtime boundaries](../LOCAL_HARNESS_RUNTIME.md).
