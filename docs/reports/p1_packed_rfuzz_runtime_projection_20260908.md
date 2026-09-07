# Packed RFuzz runtime projection

This Task 8c substep carries compiler-proven packed member coordinates into the
RFuzz input layout and runtime driver. Each logical field records both its
RFuzz raw-bit interval and, when applicable, its physical member path and
container interval. Physical geometry participates in the canonical layout
hash and published runtime layout.

Projection applies range, alignment, gating, byte-enable and ISA rules to
logical fields first. `RuntimeProjector.project_ports()` then reconstructs each
physical DUT input. Packed fields use their compiler-proven physical offsets,
and the generated Icarus bench drives the corresponding packed slices.

Layout construction and runtime initialization require one consistent
container width and complete, non-overlapping coverage. Mixed whole/member
bindings, missing coordinates, holes, overlaps, incorrect slice widths and
duplicated scalar bindings fail closed. Clock and reset must remain independent
one-bit physical ports; packed-member controls are rejected before bench
generation.

Tests verify constraint-before-reconstruction behavior, reversed logical and
physical bit order, layout hash coverage, malformed geometry, packed bench
assignments, scalar compatibility and packed control rejection. The fixed real
CVA6 annotations reconstruct `noc_resp_i` across all 210 bits. Composition
tests passed (328), RFuzz simulator/live integration tests passed (24 plus one
configured skip), and independent review reran 36 focused tests and reported
PASS after the packed clock/reset finding was fixed.
The final repository regression passed 1007 tests with one skip in 47.029
seconds.

Evidence is retained in `runs/p1_processor_backend_20260908/`, including
`task8c-packed-runtime-red.log`, `task8c-packed-real-cva6.log`,
`task8c-packed-composition.log`, and `task8c-packed-rfuzz-integration.log`.
The full-suite log is `task8c-packed-full-regression.log`.

This substep proves field projection and physical reconstruction. Automatic
processor-adapter instantiation and real CPU boot/progress acceptance remain
separate gates.
