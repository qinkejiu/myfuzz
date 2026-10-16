# BOOM persistent simulation session

Implemented standalone `GeneratedBoomCpuSession` and `build_boom_session` in
`src/myfuzz/local_harness/boom_cpu_session.py`, plus native
`boom_cpu_driver.cpp`. Existing one-shot generator and gates are unchanged.
The new builder reuses their authentication and pins built executable,
manager, driver and RTL bytes in a session artifact. Commands use the existing
bounded local process transport; closing reaps the process.

One STEP evaluates the low clock, samples accepted handshakes, then evaluates
one rising edge before updating native manager state. Every A/C/D/E acceptance
is returned in a bounded receipt, with no trace truncation. A testcase reset
starts a fresh CPU and RAM. The pinned reset vector trampoline boots code
loaded at 0x80000000. Loading and backing RAM reads do not clock the CPU.

Optional uncached range supports an externally completed Get/Put with original
source/size identity, masked write request data, response backpressure and one
outstanding transaction. Native coherent RAM remains active outside the range.
This is a transport primitive, not generic router admission; no CPU/IP join is
claimed. B probes, denied/corrupt response injection, cache flush and multiple
external ranges are unsupported. Pending response indication is conservative
0/1 rather than a manager queue count.

Inspected existing direct/runtime gate requirements: two matching fresh runs,
accepted A/C/D/E independent replay, dirty writeback and a causally correlated
read corruption control. Those gates remain separate. No builds or tests were
run, in accordance with the user's pending verification authorization. Local
source inspection only; no remote operations performed.

Follow-up source review restricted external routing to the pinned legal
uncached 0x4000–0x4fff window and program loading to RAM at 0x80000000–0xffffffff.
External request receipts carry reset epoch and sequence; RESPOND requires both
so a delayed callback cannot complete a reused source ID after reset.

Constructor now independently repeats canonical profile/source/physical-port
authentication, compares the recorded source identities, and verifies Python
session/generator/native template hashes. Fresh native processes have distinct
execution UUIDs. Reset/drained receipt fields require strict booleans. The
executable's local hash supplies integrity, not signed build provenance; this
standalone diagnostic session continues to declare generic_router_admitted=false.

Independent source review follow-up: retained the selected external D producer
through backpressure, cross-linked the complete expected executable/RTL/manager
file set, rejected duplicate Python response submissions before native commands,
checked raw request alignment/masks, and returned cancelled external tokens on
reset. The new directed GPIO diagnostic is described separately in
boom-gpio-diagnostic-report.md. No runtime verification performed.
