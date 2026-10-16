# BOOM standard ScenarioRunner source integration

Implemented `GeneratedBoomScenarioSession` in
`src/myfuzz/local_harness/boom_scenario_session.py` and the standard runner
factory/genome in `src/myfuzz/scenario/boom_gpio_runner.py`.

CPU stepping performs one native rising edge and enqueues accepted uncached
Get/Put requests in the existing DataflowRouter/TransactionLedger. It performs
zero target accesses. Generic runner router discovery drains the queued GPIO
access on the target's scheduled step; the callback offers one D beat without
clocking BOOM. A later CPU step verifies accepted D identity/data and clears
the response state. Requests retain native execution UUID, reset epoch,
sequence, source, size, address, data and 64-bit mask/lane semantics. The adapter
rejects unsupported word shapes and out-of-window accesses before target effect.
No component-name branches or runner.py edits were added.

Bounds: CPU step advances one local tick, reports at most four accepted bus
beats and performs zero synchronous target accesses. Native RAM observation
reads advance no clocks. Router target register accesses use the target's
existing bounded-access declarations. Lifetime CPU ticks survive reset.
The adapter exposes mmio_ledger to runner uncertainty accounting and cancels
undelivered router requests at reset/end. A stale callback cannot issue D after
an execution/epoch change. Uncertain target effects reject reset; teardown
still closes the native process. Native startup and commands now respect the
minimum of session timeout and enclosing scenario deadline.

Static boot bytes are part of adapter identity and load at 0x80000000 before
its first edge and after reset. The native authenticated driver supplies the
reset-ROM trampoline. Result RAM is never preloaded. The directed firmware
writes 53 to real generated GPIO PADOUT 0x400c, fences, reads back through the
high 32-bit TileLink lane and branches before storing success at native RAM
0x3000/0x3004. The runner returns actual `ram_3000` observations; there is no
Python PersistentMemory mirror or manufactured commit authority.

The coherent accepted-event wrapper supplies a stable runtime_events list,
with explicit raw stream references and per-source manager ordering. Its
normalizations, checker report and coverage remain observation-only. Errors
are not converted into a pass. Physical GPIO samples/events use the existing
causal observation profile and the standard runner evidence paths.

Remaining limits: this is source integration, not verified runtime acceptance.
No tests, builds, native simulation, source-authentication execution or remote
operations were performed. `generic_router_admitted` and runtime_verified remain
false. Native executable hashes are local integrity checks, not signed build
provenance. Raw native execution UUIDs remain explicit; deterministic replay
needs a declared execution-scope comparison policy and runtime verification.
Native reset currently restarts RAM as well as CPU and reloads static code;
retention across warm resets is unsupported. The factory uses no reset actions.
IRQ/probe handling, denied responses, online ISA inputs, multiple target windows,
ISA retirement and independent persistent-memory commit evidence are unsupported.
Factory/genome execution must separately verify GPIO physical accesses, accepted
CPU A/D, CPU result writes, RAM results, drain and controls before acceptance;
a completed schedule alone is not functional evidence.

Root source-review follow-up: the standard adapter explicitly aborts on a
poisoned structural/normalization report before enqueuing further target
operations. Raw observations remain available, and a violation record states
that the measured CPU edge may already have had effects and requires whole
case replay. The native transport closes on this failure. The wrapper's ability
to retain raw rows after poisoning does not permit the standard chain to
continue or grant functional credit. No tests or builds were run.
