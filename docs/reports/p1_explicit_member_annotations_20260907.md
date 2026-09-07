# P1 explicit packed-member annotation evidence

Status: Task 4 implemented, independently reviewed, and verified. This change
can identify an explicitly selected packed leaf from compiler evidence. Generic
composition still rejects every member binding before layout or IR generation;
slice rendering remains Task 5.

Starting point: `770ce25`. The related process-supervision race fix is
`19aaa4c`. Plan:
`docs/superpowers/plans/2026-09-07-elaborated-physical-port-evidence.md`.

## Delivered boundary

An interface field may opt into a typed `physical` selector containing one HDL
port identifier and a non-empty member path. It is mutually exclusive with
scalar aliases and is accepted only for the elaborated selected top. The
crawler requires an exact, unique compiler leaf and emits the container port,
member path, raw inclusive offsets, container width, leaf width and signedness,
leaf source location, and both `explicit_member` and
`compiler_elaboration` evidence.

Before binding, the crawler verifies that the snapshot revision, canonical
elaboration settings, selected top, and complete typed port/member facts match
the immutable evidence stored in the snapshot. This prevents reuse of facts
from a different revision, parameterization, top, location, or width.

The annotation contract and capability normalizer require `member_path`,
`raw_lo`, `raw_hi`, and `container_width` together, validate their range, and
require compiler evidence. Duplicate `(port, member_path)` mappings fail in
both contract and normalization paths. The normalized values are immutable.
Existing scalar descriptions and annotations keep their previous form.

`plan_generic_composition` rejects any normalized member binding before input
layout, candidate IR, renderer, or publication. Task 4 therefore cannot treat a
container as a scalar or generate an unproved slice connection.

## Review and verification

Independent review found and closed four issues: partial member records could
degrade to scalar facts; normalization lacked duplicate physical-key checks;
direct typed construction accepted a string path or aliases plus a selector;
and snapshot identity initially checked only the top name. Final review PASS
confirmed revision/settings/top and complete compiler facts are now checked.

The full focused regression covered interface schemas, loading, crawling,
reader/runner behavior, capability normalization, generic planning and
publication boundaries, plus the campaign supervisor. Result: **167 tests /
8.246 seconds / OK**. The expected CLI usage diagnostic is produced by a
negative test. `git diff --check` returned zero. Logs are under
`runs/p1_elaboration_probe_20260907/task4-*.log`.

During the regression, a real Verilator process exposed a procfs transition
race: a short-lived child could disappear during one RSS snapshot while its
supervised wrapper remained live. Commit `19aaa4c` retries a snapshot at most
three times with two 5 ms waits; persistent failures still fail closed. The 13
supervisor tests passed and the real Verilator crawler case passed 30
consecutive runs.

## Remaining P1 boundary

No packed-container signal or member part-select is rendered. Task 5 must carry
these facts through canonical IR, enforce complete non-overlapping coverage for
driven input containers, render compiler-proven slices, and compile a real
small packed-struct composition before removing the planning gate. Full
CVA6/BOOM elaboration and execution remain later gates.
