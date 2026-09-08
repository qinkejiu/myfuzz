# Task 9 — Final contract-transducer RFuzz evidence and documentation

Worktree: `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.
Implementation baseline: `a89b713`, following Task 8 `8180065`.

## Changes and scope

- Independently verified the final on-disk run and both independent rebuilds before
  extending `expected/bounded-result.json`. Added byte-exact evidence-file hashes,
  input configuration/client/transducer RTL/control/simulator-input identities,
  all three binary identities, execution cycles, measured RSS and cleanup counts.
  The representative input/coverage/trace/replay keys explicitly name only
  `entry_0001.json`; the hashed manifests retain every entry's full identity.
- README now names the final review-fix run, reports its measured counters and
  timing, identifies both 23-entry rebuilds, distinguishes byte-exact file hashes
  from per-entry replay keys, and explains that ignored `runs/` artifacts are not
  distributed by Git. Replaced its undeclared `jq` dependency with Python's
  `json.tool` because `jq` is absent in this environment.
- The handoff did not exist in this worktree or tracked files. Per controller
  direction, read `/home/qinkejiu/myfuzz/项目目标与后续任务交接.md` as the baseline and
  added the updated document in this feature worktree only. Preserved user goals,
  protection/resource constraints, historical P0/P1/processor report references,
  protocol limitations and outstanding BOOM/long-test requirements. Removed stale
  P0/Task 14 restart instructions, obsolete current-HEAD/uncommitted statements,
  and the old fixed-program campaign command as a current runnable next step.
- Reviewed both Chinese example guides and `commands.sh`. Their contract layout,
  fixed header, handshake/memory semantics, internal v2 protocol, CLI options,
  replay checks and acceptance boundaries agree. No necessary changes to
  `系统能力与工作原理.md` or `commands.sh` were found. The README command dependency
  correction and new handoff are the documented Task 9 consistency adjustments.
- No production code, test implementation, source checkout or run artifact changed.
  TDD was not required for this evidence/documentation task; existing meaningful
  regression coverage and direct artifact verification were used.

## Independent raw-artifact verification

Sources read directly, not inferred from Task 8's report:

1. `runs/examples/contract-rfuzz-review-5s/{summary.json,replay.json}`;
   `build/execution.json`, `build/sim/artifact_provenance.json`, generated
   transducer/testbench source and `build/sim/obj_dir/Vmyfuzz_live_tb`.
2. The same run's `live/report.json`, `live/corpus_manifest.json` and every
   `live/corpus/entry_*.json`.
3. `runs/examples/contract-rfuzz-review-replay/rebuild_replay.json`, execution
   proof, artifact provenance and its actual simulator binary.
4. `runs/examples/contract-rfuzz-original23-review-replay/rebuild_replay.json`,
   execution proof, artifact provenance and actual binary, compared against the
   original `runs/examples/contract-rfuzz-5s/live/` manifest and corpus.
5. Current `input/ibex-scratch.json` and the actual official client executable.

Two read-only Python audits used `json`, `pathlib`, and `hashlib`:

- Compared summary/live scalar counters and exact execution dictionaries, all
  composition/layout/constraint/transducer/header identities against the probe,
  the complete embedded live manifest against the saved manifest, and its file
  bytes against the report's `corpus_manifest_sha256`.
- Compared the current input document, excluding its wrapper schema/personality,
  with the saved probe `cpu_config`; compared personality with the saved metadata.
- For each of the three replay documents, matched file names and exact entry
  counts; hashed actual raw input bytes, all retained trace bytes, and recorded
  freshly executed counters. Checked original manifest hashes and receipt flags,
  record/cycle lengths, zero trace padding, and matching fixed execution identities.
- Recomputed control/simulator-input hashes and every original/fresh replay key
  using canonical JSON (sorted keys, compact separators, ASCII, trailing newline).
  Keys include each build's binary identity; equality across builds is not assumed.
- Hashed the actual three simulator executables and compared them against replay
  documents and provenance. Hashed the actual client and transducer RTL. Confirmed
  generated testbench source declares `RFUZZ_READY 2`.
- Independently mapped **49 expected result fields** to original measured fields,
  actual evidence-file bytes, or the identified representative corpus entry; all
  matched. Checked evidence paths, both false acceptance flags and that both
  implementation commits are ancestors of HEAD. Client help confirmed version.

Audit output:

```text
runs/examples/contract-rfuzz-review-5s/replay.json 23 PASS: raw/trace/coverage/header/layout/contract/control/simulator-input/replay-key/binary
runs/examples/contract-rfuzz-review-replay/rebuild_replay.json 23 PASS: raw/trace/coverage/header/layout/contract/control/simulator-input/replay-key/binary
runs/examples/contract-rfuzz-original23-review-replay/rebuild_replay.json 23 PASS: raw/trace/coverage/header/layout/contract/control/simulator-input/replay-key/binary
PASS: summary/live/probe/config/manifest counters and identities; client and transducer RTL hashes
PASS: 49 expected fields independently match measured source fields / file bytes
PASS: representative raw/input/trace/coverage/replay keys bind entry_0001.json; protocol v2; pending acceptance flags false
```

Final measured run: 124153 tests, 98557 distinct completed input/coverage receipt
pairs, 23 saved corpus entries, 23 same-build replays, 9932240 execution cycles,
249246 requests and 248306 completions; instruction requests/responses/first
initializations are 249246/248306/248306. Protocol/transducer/total errors are all
zero; client exit is zero; remaining and forcibly removed owned segments are zero.
The stop request was at 5.000014610002836 seconds for a requested 5 seconds;
drain was 23.80154176299766 seconds, total 28.802813402002357 seconds, with a
60-second drain limit. Sampled aggregate RSS peak is 108134400 bytes; four ordinary
RTL diagnostics were retained. Complete measured hashes are in the expected file.

This task audited saved real execution/rebuild evidence; it did not initiate a
new live acceptance run or claim that reading replay JSON re-executed the RTL.

## Fresh verification commands and results

Required focused command:

```bash
PYTHONPATH=src python3 -m pytest tests/composition tests/isa tests/examples/test_real_ibex_rfuzz_example.py tests/integration/test_rfuzz_simulator.py tests/integration/test_rfuzz_live.py -q
```

Result: `641 passed, 3 skipped, 441 subtests passed in 66.27s (0:01:06)`.

Full project command after documentation edits:

```bash
PYTHONPATH=src python3 -m pytest tests -q
```

Result: `1406 passed, 3 skipped, 1160 subtests passed in 162.46s (0:02:42)`.

The three skips are the existing optional official-client and real-CPU tests in
`test_rfuzz_live.py`: one requires `MYFUZZ_RFuzz_CLIENT`, and two require the
real-CPU opt-in (including the client where applicable). Saved real live and
independent-rebuild evidence is verified separately above. No project test failure
or unexpected warning was observed in either completed run. The full command
explicitly scopes `tests/`, preserving the confirmed third-party collection boundary;
no optional third-party dependency was installed to change that scope.

All of these exited zero:

```bash
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py --help
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py compose --help
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py test --help
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py inspect --help
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py replay --help
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py inspect --output runs/examples/contract-rfuzz-review-5s
bash -n examples/real_ibex_rfuzz/commands.sh
bash examples/real_ibex_rfuzz/commands.sh help
runs/rfuzz_client_native_build/target/debug/kfuzz --help
git diff --check
```

Top-level help lists `compose`, `test`, `inspect`, `replay`; the subcommand help
confirms the documented required options. Read-only inspect returned the expected
final measured summary. Guide/campaign history and all local report/plan reference
paths were checked for consistency; the new Task 9 report was the sole not-yet-written
reference during the first check and is present in this commit.

## Files, repository audit, self-review and limitations

Exact intended commit paths:

- `examples/real_ibex_rfuzz/expected/bounded-result.json`
- `examples/real_ibex_rfuzz/README.zh-CN.md`
- `项目目标与后续任务交接.md`
- `.superpowers/sdd/contract-transducer-task-9-report.md`

Initial and subsequent NUL-delimited `git status --porcelain=v1 -z` were compared
as exact entry sets. The existing modified `.superpowers/sdd/task-2-report.md` and
all **1006 third_party status entries** remain unchanged; only intended Task 9
files were added to the difference. The initial index was empty. The staged name
set was checked and contains exactly the four intended paths; cached whitespace
checks passed. The existing `.superpowers/sdd/.gitignore` ignores new reports, so
only this report required an explicit path-limited `git add -f`. No broad add or
cleanup was used.

Protected SHA-256 values, unchanged after edits and the completed tests:

```text
5a2bf56f8f1fa3104b6ef7752022c574086a581fdd4e66c715f4cbeece08671f  .superpowers/sdd/task-2-report.md
b668109cf859af1d6a59f0e0e48a255ccc5b728c21b44a7cde6393b9b61bab4c  /home/qinkejiu/myfuzz/项目目标与后续任务交接.md
```

Self-review retained these limits explicitly: current evidence is the real Ibex
split OBI path; targets are disabled in constrained mode; personality metadata
does not prove peripherals; coverage is sampled signal events; fixed targets and
legacy campaign configs have not been migrated; arbitrary longer inputs may hit
capacity/provenance errors; formal 3×300 seconds and BOOM remain uncompleted.
Old binaries must rebuild for the internal v2 protocol; saved inputs remain replayable.

No unresolved correctness concern was found in this documentation task. Full-branch
independent review, final controller verification and remote push remain controller
responsibilities. **No push was performed.**

## Independent-review fix: preserve deferred Task 14 formal closure

Review of `096bd6d` identified one Important documentation omission: the handoff
retained BOOM and 3×300-second deferrals but omitted the independently deferred
Task 14 formal closure. The main-workspace baseline explicitly records that user
decision, and `.superpowers/sdd/progress.md` records Task 14 as bounded preflight
passed with formal closure skipped. The finding was verified against both sources.

Added a focused assertion in `tests/examples/test_real_ibex_rfuzz_example.py`
requiring a separate Task 14 item in the unfinished-work section and an explicit
statement that bounded short evidence does not automatically complete the original
Task 14 acceptance/formal closure. Then updated the handoff introduction and
unfinished-work list with that distinction, preserving the other deferrals.

RED and GREEN used the same command:

```bash
PYTHONPATH=src python3 -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q -k handoff_keeps_task14_formal_closure_pending --tb=short
```

RED: `1 failed, 21 deselected in 0.15s`. The expected failure was the missing
numbered `Task 14 正式收口仍暂缓、未完成` item, not a test setup error.
GREEN after the document-only correction: `1 passed, 21 deselected in 0.10s`.

Related full example verification, including the real-Ibex build/execution test:

```bash
PYTHONPATH=src python3 -m pytest tests/examples/test_real_ibex_rfuzz_example.py -q
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py --help
git diff --check
```

Results: `22 passed, 9 subtests passed in 17.26s`; CLI help exited zero and still
lists compose/test/inspect/replay; whitespace check passed. The project-wide
1406-test result above belongs to the original Task 9 verification before this
review fix; the narrowly scoped follow-up reran the affected example suite.

Fix commit scope is exactly the handoff, its focused example-test assertion and
this appended report. No production code, measured expected values, run artifacts,
progress ledger, main-workspace handoff, task-2 report or third_party files changed.
Self-review found no remaining inconsistency for this finding. No push was performed.
