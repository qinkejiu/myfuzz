# P1 bounded Verilator elaboration runner evidence

Status: Task 2 implemented, independently reviewed, and verified. This runner
collects physical compiler evidence from an explicit source closure. It does
not prove a complete CPU module, protocol semantics, or CPU execution.

Starting point: `a264161`. Plan:
`docs/superpowers/plans/2026-09-07-elaborated-physical-port-evidence.md`.

## Delivered boundary

`run_verilator_elaboration(...)` accepts one caller-owned source root, a named
top module, ordered source files, include roots, defines, decimal parameters,
and a new output directory. It constructs a fixed Verilator JSON-only command
without a shell or arbitrary caller flags. The frontend runs in a new process
group at nice 15 with `JOBS=1`, a 30-second deadline, and 512/768 MiB sampled
RSS limits.

The manifest is written before supervision and records the logical command,
tool version, source and Verilator standard-file hashes, return status, sampled
peak RSS, RSS sample count, and at most 64 KiB of diagnostics. User sources,
include contents, and tool standard files are hashed before compilation and
verified again afterward. Compiler metadata may only refer to that source
closure or the exact standard files belonging to the resolved Verilator
installation.

Tree and metadata JSON must be regular non-symlink files no larger than 64 MiB.
A string-aware structural-token budget bounds object expansion before
`json.loads`, and the reader retains its AST, recursion, width, port, and leaf
budgets. Source/include paths, directory entries, closure bytes, identifiers,
parameter values, output paths, and compiler artifacts all fail closed on
unsupported or ambiguous input.

The shared campaign supervisor now distinguishes an RSS sampling race after a
short child has already exited from an RSS failure while the child is live. It
uses the real return code, drains output, terminates any surviving process-group
descendants, and reports `rss_sample_count`; live monitoring failures still
fail closed.

## TDD and review

The initial RED log records the missing runner API. Subsequent review RED logs
cover unbounded/non-regular JSON, include dependency identity, source and tool
TOCTOU changes, metadata closure escapes, pseudo-source forgery, incomplete
manifest states, relative output handling, closure enumeration bounds, and the
short-process RSS race. The corresponding GREEN and regression logs are under
`runs/p1_elaboration_probe_20260907/`:

- `runner-red.log`, `runner-green.log`, `runner-regressions.log`
- `runner-review-red.log`, `runner-review-green.log`,
  `runner-review-regressions.log`
- `runner-race-red.log`, `runner-race-green.log`,
  `runner-race-regressions.log`
- `campaign-tool-red.log`, `campaign-tool-green.log`,
  `campaign-tool-regressions.log`
- `tool-toctou-red.log`, `tool-toctou-green.log`,
  `tool-toctou-regressions.log`

The final independent review returned PASS and confirmed that all findings from
four review rounds were closed.

Main verification command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
python3 -m unittest tests.integration.test_campaign_supervisor \
  tests.composition.test_source_elaboration \
  tests.composition.test_source_elaboration_runner \
  tests.composition.test_source_crawler -v
```

Result: **74 tests / 5.929 seconds / OK**. `git diff --check` returned zero.
The suite includes real installed-Verilator elaboration and fake-front-end
failure, timeout, descendant cleanup, diagnostics, artifact, closure, and race
cases.

## Remaining P1 boundary

Task 3 remains open. `interface_description.v1`, `SourceLocator`, and
`SourceSnapshot` do not yet carry canonical elaboration settings or packed
member facts. Existing source-only behavior is unchanged. Packed members are
physical evidence only and cannot participate in semantic annotation or
composition until that later integration is implemented and reviewed.
