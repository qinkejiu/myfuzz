# Compiled F4 built executable identity

Status: bounded implementation, independent source reviews and frozen software/native
acceptance passed. Final software: **611 passed, 30 skipped, 53 subtests passed**.
Both native first/fresh gates passed and were independently audited. The two
failed software attempts remain saved. This report does not award system or P7-E completion.

Design: [approved specification](../superpowers/specs/2026-10-22-compiled-f4-built-identity-design.md).
Execution: [implementation plan](../superpowers/plans/2026-10-22-compiled-f4-built-identity.md).
Predecessor: [selected runtime-path acceptance](compiled-f4-runtime-path-admission-20261022.md).

## Implemented association

A receipt-capable builder shares the existing Path build implementation. Its
stable receipt joins the exact artifact, current complete source/toolchain
build identity and validated output executable digest. Cache/stage paths,
compile/cache branch, raw manifest hash and timing remain separate diagnostic
observations. Repeated opted preparation validates the fixed result and raw
manifest without replacing the first receipt or observation.

Selected compiled-F4 sessions prepare both components before final execution
binding and session manifest capture. The binding retains only stable receipts.
Immediately before launch, each session revalidates the selected output; after
Popen and before READY acceptance, it hashes the live `/proc/<pid>/exe` and
requires the admitted digest. READY independently validates artifact identity.
Lifecycle records retain PID/nonce, both digests, failures and exit/reap results.

Fresh independently prepares and compares expected stable receipts before
either native process starts. The full prefix comparison retains output hashes;
no binary difference is normalized away. Cache hits do not establish cold-build
cost or reproducible independent builds.

The run-level `compiled_f4_build_join.v1.json` associates D2 artifacts, stable
receipts, separate original/fresh observations and process/exit audits. The CLI
reads saved join/prefix/replay bytes, compares same-call material, crosschecks
the session's full runtime artifact/receipt/build identity and independent
replay audit, then pins checked byte digests through summary finalization.
Structural D2 generation remains structural when it did not itself build.

## Development gates and reviews

- Task1: receipt gate6 passed; legacy build12 passed/3 subtests. Review's stale
  failure-stage labels reproduced by3 RED injections and fixed (3 GREEN).
  Independent Spec/Quality PASS.
- Task2: irreversible opted receipt and launch lifecycle. Review reproduced
  deleted/replaced registry downgrade and missing post-READY failure stage;
  fixes pass88 tests/2 subtests, with30 skips (recorded IDs/reasons in the frozen log). Independent review
  accepted. Skipped cases do not establish the corresponding reset/RTL capability.
- Pure join helper:45 passed after six missing/swapped/rehashed full-artifact
  controls. Independent review accepted.
- Root wiring:3 passed using real admitted/cache inputs and a fixture output
  only before session begin; no native launch claimed. Original constructor
  refused-join orchestration:1 passed. Fresh primary-error preservation and
  saved-output substitution controls:6 passed. Independent review accepted.
- A concurrent development regression produced51 passed/2 failures, both
  source-identity drift while implementation files changed. Logs are retained;
  this is not final frozen acceptance and the guard was not relaxed.

Development RED/GREEN reports/reviews live in
`.superpowers/sdd/compiled-f4-built-identity/`. Final inputs, commands and
terminal receipts are under
[evidence](evidence/compiled-f4-built-identity-20261022/).

## Final review follow-up

Broad review found one additional cross-layer refusal-diagnostics gap:
strict pin refusal also blocks a launch-observation getter, which can interrupt
partial snapshot export and prevent the refused build join from being written.
Close/reap recording must remain available independently of a damaged receipt
authorization entry. The first frozen software attempt is retained unchanged (537 passed,53
subtests,1 failed;2059 input hashes unchanged). Its failure is a structural
SimpleNamespace double missing the new real-runtime receipt method. The
covering RED/fix/GREEN correction and subsequent frozen attempts are retained.
The correction has meaningful RED8/GREEN82 coverage plus core12 and final
diagnostics7 checks. Independent final source rereview is Spec PASS / Quality
PASS; no current native acceptance is inferred from this source verdict.

## Native identity gates — passed on the frozen source

| Combination | Certified | Full first/fresh events / records | Supervisor exit / wall |
| --- | --- | --- | --- |
| CV32E20 + PULP Timer | 2/2 | 538 / 2 | 0 / 149.95s |
| CV32E40P + PULP SPI SPICMD | 2/2 | 2806 / 2 | 0 / 170.44s |

Both saved prefix files are byte-identical within their invocation, both
sessions report `contract_preflight`, and both run-level build joins are
`complete`. The eight native process records have distinct PID/nonce identities,
matching live executable/READY/artifact/build/receipt hashes, and reaped exit0.
Each invocation archived2059 project Python/config/wrapper inputs unchanged
before/after; the independent auditors also matched current bytes at audit time.
The software-attempt2 and Timer before-input maps are exactly equal; the SPI
snapshot uses its own recorded sibling wrapper with the same production inputs.

- [Timer raw evidence](evidence/compiled-f4-built-identity-20261022/native-attempt1/),
  [independent audit](evidence/compiled-f4-built-identity-20261022/native-attempt1/independent-audit.md).
  ArchiveSHA256 `7285654700f2a48196a34bb4b20b3cbed69670107b579af2ac966725c24a645e`.
- [SPI raw evidence](evidence/compiled-f4-built-identity-20261022/native-sibling-attempt1/),
  [independent audit](evidence/compiled-f4-built-identity-20261022/native-sibling-attempt1/independent-audit.md).
  ArchiveSHA256 `bf92e11ac1ad1a99c47951a8bebabb5cb7cd449f2eeb5e1f694b6a55507aaffc`.

Original preparation actually compiled and published both components. Fresh
independently validated cache hits, with compile_seconds=null and explicit
not-compiled reason. Recorded builder timings (seconds):

| Invocation / component | Preparation | Compile |
| --- | --- | --- |
| Timer / target | 7.2645 | 4.3373 |
| Timer / CPU | 12.4001 | 9.0146 |
| SPI / target | 7.4781 | 4.5223 |
| SPI / CPU | 11.4248 | 8.3539 |

Software regression and native gates ran concurrently. These are observed
per-invocation builder durations, not exclusive performance benchmarks,
controlled cold-build comparisons or complete RTL initialization costs. The
D2 generation rows still truthfully have binary=null/structural_only; the new
run-level join records the later admitted native outputs. This closes the
executable-identity association for these runs only. The separate final software gate is recorded below.

## Final frozen software acceptance

[Software attempt3](evidence/compiled-f4-built-identity-20261022/software-attempt3/)
ran the recorded 30-module focused acceptance command, not the entire repository
suite: **611 passed, 30 skipped, 53 subtests passed in636.98s**. Supervisor
exit0, no timeout, PID907465 reaped; wall637.374979s, maxRSS345436KiB.
All2059 archived inputs match before/after and current bytes at final audit.
ArchiveSHA256 `63cbb16ae98229dacfb0f1964ee0b52de144e9d144551c561efd1b809785554e`.
All30 skips explicitly state `timer-only registered source; GPIO mechanics
tested separately`; skipped cases do not award the omitted capability.

The second attempt remains failed:610 passed/30 skipped/53 subtests/1 failure.
A mocked argument-forwarding unit attempted the real shared worker mutex while
a native gate held it. Only that test's fake-session lock and saved-output
boundary were isolated; held-lock RED1→GREEN1 and whole-file33passed, with
independent review. Production locks and saved-material verification remain
unchanged. The first failed attempt and its structural-double correction are
also retained above.

The final software inventory differs from Timer's native snapshot in exactly
one file, `tests/integration/test_auto_harness_test.py`. SPI additionally uses
its own recorded wrapper. All production source, scripts, configs and all four
native builds' inputs/host sources remain identical. The separate native and
software archives are preserved; this bridge does not claim identical complete
inventories or a later native rerun. See the
[preterminal input/bridge audit](evidence/compiled-f4-built-identity-20261022/software-attempt3/independent-input-audit.md)
and [final independent audit](evidence/compiled-f4-built-identity-20261022/software-attempt3/independent-audit.md).

Failed-build preparation observations and retained launch/cleanup diagnostics
can be exported after refusal or damaged authorization pins. They grant no
receipt or launch authority; strict receipt access and current validation still
refuse absent or damaged pins.

## Next functional gap

D3 can declare F1–F4 executable while the installed compiled runtime executes
only its admitted F4 subset. The next proposed functional slice is a
protocol-capability-selected F2 CPU-load/IP-read-response handler, including
exact D3 prerequisites/assertions and full fresh joins. Typed assertion results,
useful metrics, similar-name CLI refusal and full P7-E gates remain open.
The read-only analysis is in
`.superpowers/sdd/compiled-f4-built-identity/next-p7-gates.md`; it is not a new
implementation or acceptance grant.

## Remaining system limits

Only the selected F4 CPU/APB storage execution subset is extended. Other
protocol/CPU/IP combinations, generic F1-F6 execution, retirement/semantic
consumption, DMA/ISR authority, useful throughput, controlled cold-build comparisons and full initialization costs,
clean-room kfuzz provenance, P6 persistence/per-edge/four-hit gates and P8's5x
performance target remain separate. P7-E and the six-CPU/four-IP system goal
remain open even if this bounded executable identity slice passes.
