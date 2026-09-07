# Generic processor boundary with a real CVA6 sample

Task 8a introduces `processor_boundary.v1`, a CPU-name-independent execution
boundary built from normalized endpoint capabilities.  The builder requires
one clock, one reset and at least one initiator memory endpoint.  It accepts a
unified memory master or separate instruction/data masters, validates every
runtime-required protocol field, direction and width, and requires source
evidence for every selected field.

Packed input containers are checked with sorted intervals, so validation cost
depends on the number of members rather than the container width.  Every bit
must be covered exactly once.  Holes, overlaps, mixed whole-port/member use and
inconsistent container widths fail before a boundary record is produced.  A
container cannot be assembled from different semantic endpoints, and every
member contributing to coverage must retain source evidence.

## Real source-backed sample

The sample description is
`configs/cpus/cva6/official_core_interface_description.json`.  It uses the
official `core/Flist.cva6`, root revision
`2e1336dcff3d1a0b49fbe6282b97802f32ea32af`, the three verified nested gitlinks,
explicit filelist variables and the recorded-nonfatal frontend policy already
reviewed in Tasks 6 and 7.

The generic SourceCrawler and boundary builder completed without any CPU-name
branch:

- source content hash:
  `sha256:c5c43bf31209c575fd472111b074077b6a4bc4910c68501f13b66da5a04efe75`;
- six selected endpoints: unified memory, clock, reset, boot controls,
  interrupts and debug request;
- 45 compiler-proven memory members: 32 in the 470-bit request output and 13
  in the 210-bit response input;
- `noc_resp_i`: 210 of 210 bits covered exactly once;
- all 29 AXI4 v1 protocol roles passed direction and width checks;
- the 16 remaining AXI sideband roles stay explicit facts, each marked
  `requires-explicit-policy`.  Their presence does not claim ATOP, user-field,
  cache or QoS behavior in the common backend.

The member offsets match the compiled artifact: request `[469:0]` runs from
`aw.id` through `r_ready`; response `[209:0]` runs from `aw_ready` through
`r.user`.  The elaboration retained the previously measured 464 upstream
warnings under the explicit recorded policy.  This is interface evidence, not
a CVA6 boot or execution result.

## Retained evidence

- `runs/p1_processor_boundary_20260908/task8a-red.log`
- `runs/p1_processor_boundary_20260908/task8a-focused.log`
- `runs/p1_processor_boundary_20260908/task8a-cva6-real.log`
- `runs/p1_processor_boundary_20260908/task8a-green-after-review.log`
- `runs/p1_processor_boundary_20260908/task8a-final-regression.log`
- `runs/p1_processor_boundary_20260908/task8a-cva6-annotations.json`
- `runs/p1_processor_boundary_20260908/task8a-cva6-boundary.json`

The focused suite covers renamed ports, unified and split memory masters,
missing/duplicate controls, wrong orientation, unknown protocols, missing
runtime fields, width mismatches, missing source evidence, and packed input
holes/overlaps/container conflicts.  Task 8b remains responsible for actual
OBI/AXI4/TileLink-to-backend RTL and its temporal simulations.

Independent review initially found weak optional-control validation and a way
for an unrelated endpoint to fill a packed input hole.  The final version
restricts control roles/directions/widths, rejects protocols on controls,
requires source evidence for every packed member and rejects cross-endpoint
container assembly.  The post-fix independent review passed with 9/9 focused
tests, including the real CVA6 crawl.

The final repository regression completed 985 tests in 45.798 seconds with one
pre-existing skip and no failures.
