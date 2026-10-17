# Declared CV32E20 → PULP timer F4 candidate

This is the same single-register PULP timer target as
`compiled-f4-obi-apb-timer`, retargeted at the pinned CV32E20/CVE2 RTL. It is the
new-CPU composition used to check that the compiled F4 path binds by declared
profile and register contract rather than by a component name. There is no
`scenario/` module that names CV32E20; the generic factory selects the OBI CPU
session from the admitted artifact kind.

The explicit capability sidecar declares only TIMER0_CTRL at byte offset 4,
full 32-bit read/write/reset 0, against the pinned apb_timer/timer sources and
the exact `pulp_timer` profile fingerprint. It does not declare autonomous
TIMER0_COUNT stable, borrow GPIOEN evidence or invent an IRQ consumer.

Each candidate is 4 bytes: the CPU MMIO word alone. There are no external input
pins, dummy pin slices, environment links, setup writes, register probe accesses
or expected outputs. The three explicit records select 0x55, 0xaa, 0x12345678.

`compose.json` plus `requests/` are inputs for D2 generation. The CV32E20 CPU
request uses 8/8 reset ticks because CVE2's reset synchronizer is released only
after a real reset window. `path_compile_request.json` contains an explicitly
DECLARED wiring contract for source-only D3 inspection; it is not presented as
a generated or native-authenticated D2 artifact.

Runtime acceptance remains OPEN until the generic APB storage consumer is
admitted and a real CPU→timer continuous plus fresh replay gate passes. This
declaration alone grants no source authority or P7 acceptance.
