# P7-E end-to-end run: one command, real RTL, fresh replay (2026-10-14)

Scope: reproduce the P7-E chain (§4/§5 of
`docs/superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md`)
on the current tree, find and fix real blockers in non-frozen code, and record
the verdict from the run's own artifacts.  Entry point:
`scripts/auto_harness_test.py`; stage semantics:
`src/myfuzz/local_harness/auto_harness_test.py`.

## 1. The command

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/ibex_obi_local/component_profile.json \
  --ip configs/peripherals/pulp_gpio/component_profile.json \
  --compose configs/scenarios/ibex-pulp-dual-gpio/compose.json \
  --output runs/p7-e2e-run2-20261014-185652 \
  --runtime ibex-pulp-dual-source \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --budget-seconds 60 --max-tests 200
```

`--runtime` and `--client-binary` are both required for a live session: without
`--client-binary` the session is the named absence `client-binary-required`
(exit 1), and the family is never guessed from the composition.

The same shape with the second family:

```bash
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e40p/component_profile.json \
  --ip configs/peripherals/pulp_gpio/component_profile.json \
  --compose configs/scenarios/cv32e40p-pulp-dual-gpio/compose.json \
  --output runs/p7-e2e-cv32-20261014-185910 \
  --runtime cv32e40p-pulp-dual-source \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --budget-seconds 60 --max-tests 200
```

## 2. Final status

| run | family | status | exit | refusals | absences | fresh replay |
|---|---|---|---|---|---|---|
| `runs/p7-e2e-run2-20261014-185652` | `ibex-pulp-dual-source` | `complete` | **0** | `[]` | `[]` | `matches: true`, `first_difference: null`, scope `full` |
| `runs/p7-e2e-cv32-20261014-185910` | `cv32e40p-pulp-dual-source` | `complete` | **0** | `[]` | `[]` | `matches: true`, `first_difference: null`, scope `full` |

All seven stages `ok` in both runs: `declaration_review`, `runtime_family`,
`harness_set`, `path_compilation`, `session`, `fresh_verification`,
`capability_report`.  The `.incomplete` marker is removed on completion.

## 3. Artifacts of the Ibex run (what each stage really produced)

| artifact | observed |
|---|---|
| `declaration-review.json` | `status: ok`, `generated: false`; `ibex_obi_local` 9/9 rows ok, `pulp_gpio` 9/9 rows ok |
| `generated/` | `harness_set.json` (3 components, `tier: generated`), `wiring_contract.json`, per-component `cpu/`, `gpio_a/`, `gpio_b/` artifacts |
| `compiled_paths.v1.json` | `{executable: 4, unsupported: 2, total: 6}`; F1–F4 `executable`; F5 `unsupported/interrupt-delivery-missing`; F6 `unsupported/dma-master-not-declared` |
| `session/` | 200 case receipts (`{"complete": 192, "input_invalid": 8}`), RFuzz client rc 0, `elapsed 21.95 s`, `effective_search_seconds 21.76`, `execution_status: complete`, 72629 trace events |
| `bundle/` | `bundle-manifest.json` + byte-identical second view of the authenticated plan/trace |
| `fresh-verification.json` | `matches: true`, `first_difference: null`, `verification_scope: full`, `semantic_sha256 cb0437c5…` |
| `capability-report.json` | `generated: false`, `throughput.status: measured`; tier awards `Catalog 9 / Generated 7 / RTL operational 4 / Cross-component accepted 4 / Coverage-guided searched 4 / Bug confirmed 0` |

Grading is not inflated: F1–F3 stop at `Generated` (the session records no
committed case for them), F4 reaches `Coverage-guided searched` on real receipts
(`bound_consumed:gpio_a:gpio_b` / `bound_delivered:gpio_a:gpio_b`,
`coverage_hex=01010001`), and F5/F6 stop at `Catalog` because the compiled path
is `unsupported`.

The CV32E40P run differs only where the evidence does: 200/200 `complete`,
`Cross-component accepted 3` instead of 4.

## 4. The one refusal observed, and why it was a race and not a defect

`runs/p7-e2e-verify-20261014-185403` (Ibex, same command) stopped at the **last**
stage:

```json
{"stage": "fresh_verification", "code": "fresh-replay-failed",
 "pointer": "/session",
 "detail": {"error": "ValueError: harness build input sha256 mismatch: src/myfuzz/local_harness/cvw_contract.py"}}
```

evidence file `runs/p7-e2e-verify-20261014-185403/fresh-verification-refusal.json`
(D1–D4 and the 200-case session in that run were all `ok`).

Root cause, measured:

* the run started `2026-10-14T18:54:03Z` and was written at `18:55:31Z`;
* `src/myfuzz/local_harness/cvw_contract.py` was written by a concurrent work
  stream at `2026-10-14T18:54:20Z` — **17 s into the run**;
* the session manifest records `cvw_contract.py` at `c88e9ecd…`; the file on
  disk is `e02e71b9…`, and no build-cache manifest anywhere records `c88e9ecd…`,
  so that hash was read from the tree before the edit and never rebuilt;
* `cvw_contract.py` is in the CPU harness's declared host-source closure
  (discovered through `source_lock.py`'s `from .cvw_contract import …`), so the
  fresh replay re-hashes it and refuses.

The refusal is the correct behavior: replaying a saved prefix whose plan was
built from a different source revision would be replaying something the session
did not record.  It is a tree-concurrency artifact, not a code defect, and the
same command on the quiescent tree completes with exit 0 (table above).

## 5. Files changed

Both files were untracked in this intentionally-dirty tree, so `git diff` shows
nothing; the changes are described literally here.

### `scripts/auto_harness_test.py` — stale "Known boundary" replaced

**RED.** `PYTHONPATH=src python3 scripts/auto_harness_test.py --help` announced:

> Known boundary: with the shipped compiler a composition declaring two instances
> of one IP profile (the two PULP GPIO of every shipped runtime family) is refused
> by D3 with ``duplicate-layout-field``, so the chain stops before the session and
> no report is written for that composition …

Every clause of that is false on this tree: `compiled_paths._layout_annotations`
keys its layout by instance (the fix is recorded in the P7 plan §10), and both
runs above are exactly that composition reaching the session, the bundle and the
fresh replay.  A user reading `--help` was told the one working command cannot
work.

**GREEN.** The paragraph now states the shipped behavior (the shape compiles end
to end; unsupported paths and their reasons; the session needs `--runtime` *and*
`--client-binary`; `cvw-ahb-pulp-gpio` still stops at
`cvw-online-assembly-undeclared`).

### `tests/integration/test_auto_harness_test.py` — guard for the above

Added `test_the_help_text_matches_the_shipped_stages` plus the pure helpers
`stale_boundary_claims`, `missing_documented_artifacts` and `unwrapped_help`.  It
pins both directions: the help text must not advertise a refusal the compiler no
longer performs, and it must still name all seven artifacts a run writes.

`unwrapped_help` exists because the first version of this guard failed for the
wrong reason: `argparse` re-wraps the docstring and breaks on hyphens, so the
rendered `--help` contains `declaration-` + newline + `review.json`.  The guard
was fixed to read the text, not the line breaks; this is a fix to the guard, not
a weakening of it (the missing-artifact half is proven RED below).

### RED-capable proof (scratch copies, tree never left broken)

`runs/p7e-scratch-red/` holds two throwaway copies of the CLI.  Running the real
guard against them:

* `auto_harness_test_stale.py` (pre-fix docstring restored) →
  `RED CONFIRMED: the help text still advertises a refusal the shipped compiler
  no longer performs`;
* `auto_harness_test_nofresh.py` (fixed text, `fresh-verification.json` line
  removed) → `RED CONFIRMED: the help text no longer names every artifact a run
  writes`;
* the shipped `scripts/auto_harness_test.py` → `GREEN CONFIRMED (guard passed)`.

## 6. Tests run as evidence

| command | result |
|---|---|
| `PYTHONPATH=src python3 -m pytest -q tests/integration/test_auto_harness_test.py` | **18 passed** in 72.37 s |
| `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_compiled_paths.py tests/integration/test_p7b_to_p7c_chain.py` | **49 passed** in 114.43 s |

Not run: the full suite (over an hour; out of scope for this task), and the two
real-RTL end-to-end runs above are the RTL evidence.

## 7. Not verified here

* The concurrency race in §4 is *explained* by measured timestamps and hashes,
  but no attempt was made to reproduce it deliberately (it needs a concurrent
  writer).
* `cvw-ahb-pulp-gpio` was not run; the P7 plan and the family's own registration
  say its session stage stops at `cvw-online-assembly-undeclared`, and that was
  not re-measured in this pass.
* The driver module's own docstring
  (`src/myfuzz/local_harness/auto_harness_test.py`, lines 47–61) still carries
  the same stale `duplicate-layout-field` boundary.  It is under
  `src/myfuzz/local_harness/`, which this task's rules put off limits, so it was
  left untouched and is reported instead.
