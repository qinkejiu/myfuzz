# P1 opt-in elaboration snapshot integration evidence

Status: Task 3 implemented, independently reviewed, and verified. This change
connects the bounded physical-evidence runner to source snapshots only when an
interface description explicitly requests it. It does not enable packed-member
semantic binding or claim complete CPU elaboration or execution.

Starting point: `de88fbe`. Plan:
`docs/superpowers/plans/2026-09-07-elaborated-physical-port-evidence.md`.

## Delivered boundary

`interface_description.v1` now accepts an optional typed `elaboration` block.
The only supported frontend is `verilator-json`; define and parameter names and
values use the runner's safe subsets, duplicates fail, and pairs are sorted at
construction so their command and identity are canonical. Existing documents
without this block serialize and crawl as before and never invoke Verilator.

An opted-in `SourceCrawler` preserves source-file and include-search order,
runs the Task 2 frontend in a temporary directory below the source root, and
checks every manifest source path, size, and SHA256 against crawler-owned bytes.
Git inputs are also compared with the pinned commit blob. The snapshot identity
adds canonical settings, ordered compilation inputs, stable source/tool hashes,
tool version, and physical evidence; it excludes absolute and temporary paths.
Equivalent trees at different absolute paths produce the same identity, while
compiler-relevant source or include order changes it.

`SourceSnapshot` carries immutable `ElaboratedPortFact` and
`ElaboratedMemberFact` values. Packed structured ports remain in this separate
evidence collection and never enter the scalar `ports` collection used by
annotation and composition. Memberless compiler-resolved top ports may replace
source-only facts, including parameterized vectors. The canonical supporting
evidence is stored as immutable bytes derived from the same bytes used in the
snapshot hash.

The old parser may defer only `unsupported-port-type` or
`unsupported-port-width` for the explicitly selected top when elaboration is
enabled. All other parse failures, default-mode failures, non-top failures,
frontend failures, stale sources, and malformed manifests remain fail closed.
Filelist defines are rejected in this mode until they are migrated into the
typed elaboration block.

## TDD and review

RED/GREEN and regression logs are under
`runs/p1_elaboration_probe_20260907/`:

- `task3-red.log`, `task3-green.log`, `task3-regressions.log`
- `task3-review-red.log`, `task3-review-green.log`,
  `task3-review-regression.log`
- `task3-review2-red.log`, `task3-review2-green.log`,
  `task3-review2-regression.log`

Independent review found and closed: source parsing that blocked a real struct
before the runner, an unbounded include pre-scan, lost compiler ordering,
mutable nested snapshot evidence, direct-construction validation, and a
parameterized-width path that still failed before elaboration. The final review
returned PASS.

The final regression includes interface contracts and loading, source crawling,
the physical reader and runner, generic composition, path-independent identity,
manifest corruption, compiler input ordering, structured-port isolation, and a
real installed-Verilator crawler test where parameter `W` overrides 8 to 13.
Result: **121 tests / 6.756 seconds / OK**. `git diff --check` returned zero.

## Remaining P1 boundary

Packed member roles are not represented in input annotations or renderer
bindings, so structured buses cannot yet participate in composition. Full
CVA6/BOOM module elaboration, actual parent type overrides, generated hierarchy,
real-core simulation, and RFuzz acceptance remain later gates.
