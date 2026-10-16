# Declared Ibex → PULP timer F4 candidate

This is a genuinely different RTL/register target in the compiled F4 candidate set, using the existing generic APB3 register template. It is not a newly imported repository IP and is not another peripheral family. No component-name runtime branch or GPIO alias is introduced.

The explicit capability sidecar declares only TIMER0_CTRL at byte offset4, full32-bit read/write/reset0, against the pinned apb_timer/timer sources and exact profile fingerprint. It does not declare autonomous TIMER0_COUNT stable, borrow GPIOEN evidence or invent an IRQ consumer. CTRL storage/update semantics remain a declaration until an admitted source-owned probe/version producer is implemented.

Each candidate is4bytes: the CPU MMIO word alone. There are no external input pins, dummy pin slices, environment links, setup writes, register probe accesses or expected outputs. The request explicitly selects the registered CTRL0 passive storage observation contract; generated read-only taps remain prospective until a real hierarchy/build/sample gate. The three explicit records select0x55,0xaa,0x12345678. The CPU image and result arena retain the existing explicit Ibex configuration.

compose.json plus requests/ are inputs for future D2 generation. path_compile_request.json contains an explicitly DECLARED wiring contract for source-only D3 inspection; it is not presented as a generated or native-authenticated D2 artifact. The existing compiler selects TIMER0_CTRL and derives a4byte candidate while preserving the ip_register_version prerequisite. Five pure controls pass, including missing sidecar refusal and a wrong-profile negative.

Runtime acceptance remains OPEN: the current compiled executor requires the registered GPIOEN live authority, so this target must not be run as an admitted F4 by deleting that requirement or replacing it with readback. Next work must supply its actual internal storage probe, source/reset/command producer and live single-use version tokens through the protocol-owned factory, then perform a real CPU→timer continuous/fresh gate. This declaration alone grants no source authority, native execution or P7 acceptance.
