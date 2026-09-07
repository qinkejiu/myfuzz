# P1 packed-container renderer evidence

Status: Task 5 implemented, independently reviewed, and verified. Generic
composition now renders explicitly selected packed members whose physical facts
were proven by the Task 1–4 elaboration path. This is a renderer and compile
boundary; it does not claim RFuzz packed runtime support or real CPU execution.

Starting point: `230cf13`. Plan:
`docs/superpowers/plans/2026-09-07-elaborated-physical-port-evidence.md`.

## Delivered boundary

Member path, raw offsets and container width now survive capability
normalization, canonical generic IR and publication freshness reconstruction.
The renderer groups semantic leaves by their physical port, declares one signal
for each packed container, connects that signal once to the source DUT, and
uses compiler-proven `[raw_hi:raw_lo]` part-selects for protocol fields.

Source output members may be consumed independently. A source input container
is internalized only when the members actually routed from components cover
the complete `[width-1:0]` interval without gaps or overlap. Source-only input
containers apply the same complete-coverage rule to annotated leaves. Mixed
whole-port/member bindings, conflicting container facts, overlapping slices,
duplicate response targets and duplicate IRQ targets fail before publication.
Member-based clock/reset controls remain explicitly unsupported.

Coverage validation sorts a bounded list of member intervals and walks it once;
it never builds a set proportional to container bit width. A 16,777,216-bit
regression exercises this constant-in-width behavior.

The generated source instance uses the exact typed elaboration parameter
overrides. Typed defines are retained in canonical IR/freshness state, emitted
in `sources.f`, and supplied to publication lint. Default scalar plans emit no
new parameter clause or define.

## TDD, review and verification

RED/GREEN and regression logs are stored under
`runs/p1_elaboration_probe_20260907/`, including `task5-red.log`,
`task5-green.log`, `task5-connected-red.log`, `task5-define-red.log`,
`task5-connected-final.log`, and `task5-final-regression.log`.

Independent review found and closed three blockers: per-bit coverage sets could
exhaust memory, source instances omitted elaboration parameters, and the first
real compile test covered only a private source-only renderer path. The final
review returned PASS.

The final focused regression covered contracts, description loading, physical
reader/runner, crawler, capability normalization, generic planning, renderer,
publication, and campaign supervision. Result: **172 tests / 8.927 seconds /
OK**. `git diff --check` returned zero.

The connected acceptance test uses an actual parameterized packed DUT and a
small protocol target. It supplies a typed define and overrides address width
from 8 to 16, then runs real Verilator elaboration, planning, canonical IR,
freshness reconstruction, atomic publication, and a strict final Verilator
compile. It verifies one DUT connection per request/response container and
compiler-derived slices for ready, read data, error and IRQ.

## Remaining boundary

The RFuzz simulator's external packed-input projection still assumes one scalar
layout field per external port and therefore does not yet drive member slices.
No packed transaction simulation is claimed here. The next P1 work should use
real CVA6 source to establish module-level elaboration and binding regressions,
then add any runtime projection required by the selected executable boundary.
BOOM still requires a controlled RTL-generation stage before the same checks
can apply.
