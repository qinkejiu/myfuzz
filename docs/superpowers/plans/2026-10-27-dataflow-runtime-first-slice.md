# Independent-component dataflow runtime: first implementation slice

**Goal:** Expose the existing persistent mixed F2/F4 execution through the generic scenario entry, preserving real component sessions and cross-case state.

**Architecture:** The host routes data and events among independent RTL harnesses. Reuse the existing preparation, binding, mixed storage kernel, runner and replay; select flow per submitted case and retain the existing single-flow descriptor format. F1–F6 and a fair external RTL-coverage comparison remain the overall objective.

**Constraints:** Preserve the dirty worktree and evidence; no generated SoC hierarchy; no synthetic coverage or native claims; run focused tests first and bound native runs.

## Mixed entry

Files: `src/myfuzz/runtime/generic_campaign.py`, `src/myfuzz/runtime/campaign.py`, `scripts/run_generic_scenario.py`, `tests/runtime/test_generic_scenario_descriptor.py`, and a focused integration test.

- [x] Add tests showing `--flow mixed` accepts an explicit ordered list of `F4:55000000`, `F2:04100040`, `F4:aa000000`, maps each record to its matching path/source, and rejects absent flows or invalid records before creating a native runtime.
- [x] Run the focused tests and observe the expected missing mixed-entry failure.
- [x] Extend `run_descriptor(..., sequence=None)` so `flow='mixed'` uses the existing F4 constructor with `mixed_flows=True`, `MixedStorageFlowBackend`, and `MixedStorageKernel`; prepare and bind once and preserve single-flow behavior. Expose repeated `--record FLOW:HEX` arguments on the CLI and reject records on single-flow runs.
- [x] Fix the existing mixed-kernel import in `run_directed_campaign` and exercise its default selection.
- [x] Run the focused software tests; then run the bounded three-case native mixed sequence with the existing timer descriptor and cache. Check one initialization, F4/F2/F4 ordering, previous-write readback, and replay. Actual native process replay passed in 222.61 seconds under `/tmp/myfuzz-mixed-native-20261027-01`; the separate host-process fresh mode remains to be run.
- [x] Add an explicit round budget and rerun the same three-case directed sequence at 32 rounds: native processes and replay completed in 99.91 seconds under `/tmp/myfuzz-mixed-32-20261027`. This uses fewer advances than the 128-round run and is not a same-workload benchmark.

## Parallel work

- Coverage: instrument and compare independent local harnesses; require verified DUT source and point universe, and report missing experiment conditions as unknown. Verilator line/block points remain separate from semantic and source-branch coverage.
- F6: a separate agent regenerates a temporary fixture and isolates the first real native CPU/DMA failure; it owns only F6-specific files.
- Speed: a separate agent measures F4 identity checks and changes only a proven equivalent hot path, retaining source and effect validation.

## Verification

- [x] Review each agent's files and test evidence; preserve unrelated dirty work.
- [x] Run focused tests and bounded native integration. A four-case F1/F3/F4/F2 run and new-process replay matched under `/tmp/myfuzz-f1f4-trace-20261027`; F1/F3 observation and retirement evidence remain limited. Actual recorded CPU and peripheral commands were separately replayed on coverage-instrumented component harnesses.
- [x] Add standalone F5/F6 descriptor entries that reuse existing component runtimes. Real F5 GPIO input/IRQ and complete replay passed under `/tmp/myfuzz-generic-f5-trace-run2`; real F6 original/fresh and audit-joined command capture passed under `/tmp/myfuzz-generic-f6-trace-run2`. F5 CPU/GPIO and F6 DMA instrumented command replays matched actual recordings.
- [x] Initial focused software verification: 245 passed, 2 skipped, 4 subtests passed. Continuation regression: 679 passed, 2 skipped, 4 subtests passed before the subsequent F6 readiness optimization.
- [x] Separate F6 transition unit tests now explicitly supply consumer approval at their inventory dependency boundary; the real collector remains graph-missing. A new negative test proves missing graph cannot advance scope. The full runtime module passed 111 tests on the pre-optimization production baseline; this does not certify a native graph or the subsequent readiness optimization.
- [x] Continuation native F6 two-case validation: the initial 4096-round attempt timed out. A bounded diagnostic exposed a preloaded park loop and overly strict first-request observation scope. After both fixes, two native cases and full fresh replay passed in 138.26 seconds under `/tmp/myfuzz-f6-two-case-fixed`, with all five observation groups passed per case. Original CPU/DMA ticks were 285/323. The descriptor now defaults to the verified 256-round budget; an explicit override up to 4096 remains available.
- [x] Readiness regression: 41 scheduling/transition tests passed after the cheap latch gate; five relevant tests passed again after the park fix. Independent saved instruction-edge verification passed 74 tests after exact first-request handover support. Firmware and entry checks passed 64 tests. These overlap and are not additive counts for one full-suite run.
- [ ] Complete a shared F1–F6 execution plan and session, full supervisor acceptance, and a controlled external-tool experiment. Standalone F5/F6 report their actual backend and within-invocation replay scope.

## Common execution continuation

Keep each existing backend's execution and evidence authority. Do not invent a
bound plan for F5/F6. First remove duplicated orchestration and fix resource
ownership, before adding further CPU/IP combinations.

- [x] Make shared F1–F4 cleanup exception-safe from preparation through replay
  and export. Close acquired resources once, preserve the primary exception,
  and retain secondary cleanup failures as notes. Test failures at construction,
  submission, finish, replay and export without launching RTL processes. F5
  reuses the same private cleanup helper; partial begin and early finalize
  failure also reap still-live children from a saved session snapshot.
- [x] Reuse one command-trace exporter for F5/F6. Select actual sessions by
  component and execution nonce, preserve incomplete traces, and retain F6's
  exact build/binary/PID/artifact joins and nonce-reuse rejection. Test ambiguous,
  missing, malformed and mismatched identities; verify existing recorded F6
  original/fresh traces without rerunning RTL solely for JSON refactoring.
  Re-exporting the real 285-CPU/323-DMA-command traces matched both saved
  documents exactly. F6 also now saves its common `summary.json`.
- [x] Combined software verification: 136 passed in 24.47 seconds, including
  the existing shared/mixed regressions, failure cleanup and trace identity
  rejection. No synthetic fixture result is treated as a native credential.
- [x] Verify the two changes together with focused tests and one bounded shared
  native run. Four F1/F3/F4/F2 cases and full fresh replay passed in 108.41
  seconds under `/tmp/myfuzz-common-execution-core`; both component processes
  exited normally and were reaped. The read observed the prior write of 85.
  The remaining profile-specific F5 assembly is documented explicitly.
