# Derived BOOM physical profile and CPU/RAM execution

`component_profile.json` and `interface_description.json` now select the actual
47-port generated `BoomTile` from derived `chipyard.SmallBoomConfig`. Its one
shared coherent TileLink A/B/C/D/E endpoint has 39 physical fields. Instruction
and data traffic share this boundary. The profile uses the nonzero union pin
of four emitted RTL files in `generated/source_manifest.json`.

`generated/rtl.tar.gz` contains those four authenticated files. Run
`python3 configs/cpus/boom/generated/materialize.py` to reproduce the local RTL
files without network access. The materializer checks the archive and every
member's name, type, size and SHA-256 before writing. The physical port capture
is also authenticated and checked against the emitted module declaration by
the generated session builder.

This is derived source. `chipyard_source_manifest.json` records Chipyard
`4180463d52bc0a6b4c004530601ccdabebf0ab7d` and its BOOM gitlink
`1ad28828673f2fce7a18f7255facd4705f04a58a`.
`derived_source_manifest.json` records published Chisel/FIRRTL dependencies
and the minimal explicit Rocket metadata IO compatibility patch. The separate
BOOM reference commit is not substituted for that gitlink. The original fixed
upstream dependency/elaboration failures and subsequent successful derived
FIRRTL/Verilog generation remain documented in
`generation_evidence_20261017.md` and `evidence/derived-20261017/`.

## Generated CPU/RAM gate

`myfuzz.local_harness.tilelink_coherent_cpu_session` generates a C++ driver
from this physical profile and reuses the working coherent `runtime/tl_ram.h`
manager. It compiles authenticated RTL, boots the real RV64 CPU, and runs two
fresh processes plus a read corruption control under the shared heavy lock.
See `generated/README.md` for the command.

Evidence in `evidence/generated-runtime-20261017/` passes both fresh runs with
identical traces after 598 cycles: 5 Get, 14 AcquireBlock, 2 Put, 10 ReleaseData,
164 D beats and 14 GrantAck. Both CPU results and backing RAM equal 0x123.
Independent trace replay checks all accepted A/C/D/E events and drained state.

A full memory fence orders the final load after earlier conflicting stores.
The control correlates eight target ReleaseData beats to a later AcquireBlock
of 0x80001000, source 1, size 6, then records the eight corrupted D beats.
The first returned word changes 0x123 to 0x122; the real CPU subsequently
writes 0x122 to its uncached 0x4008 result location while its earlier 0x4000
result remains 0x123. The normal success gate rejects that run, as intended.
`gate.json` records the request, accepted substituted responses and CPU marker;
`manifest.json` binds code, profile, RTL archive and evidence bytes.

## Direct probe and boundaries

The earlier direct proof remains in `runtime/` and
`evidence/runtime-20261017/`: 555 cycles, 13 AcquireBlock and two CPU results
of 0x123, with real dirty writeback. Its unfenced final load may execute before
eviction on this out of order CPU. That proof does not independently establish
a later backing RAM read or the new corruption control; its executable and
trace remain unchanged.

Both environments have one coherent client and hold B.valid zero. External
probes are not exercised. Addresses 0x4000/0x4008 are legal uncached locations
in the emitted map, supplied by this isolated RAM manager instead of the full
SoC boot register. This is neither a full Chipyard serial boot nor a generic
CPU/peripheral MMIO router admission. No CPU/IP join is claimed. The abstract
`tilelink@1` plugin is retained for older declarations; this physical profile
uses the separate `tilelink-coherent@1` field vocabulary.

## Persistent clock-step simulation

`myfuzz.local_harness.boom_cpu_session.build_boom_session(repo, output,
heavy_lock=...)` authenticates the same profile, physical ports, source union
and materialized RTL as the one-shot gate, then builds a separate persistent
C++ command driver. Its `session-artifact.json` additionally pins the executable,
driver, manager and copied RTL. The original gate remains available unchanged.

Open `GeneratedBoomCpuSession(output, repo=repo)` as a context manager, call
`begin_case(testcase_id)`, `load_program(instruction_bytes)` and repeatedly call
`step_local({})`. Each call advances exactly one rising edge; the initial 20
calls hold reset. The boot trampoline jumps from 0x10040 to 0x80000000.
`accepted_events` contains every accepted A/C/D/E beat on that edge without
trace truncation. `read64(address)` observes backing RAM, including dirty
writebacks, rather than CPU cache contents. Loading does not advance clocks
and must precede stepping. Reset restarts the process and clears loaded RAM.
`pending_responses` is a conservative 0/1 indication of native manager state,
not a count of individual multibeat responses. `begin_quiesce()` stops new A
requests while allowing C, D and E to drain; it does not flush CPU caches.

An optional `external_range=(start, end)` routes accepted single-beat uncached
Get/Put requests away from native RAM. Accepted A rows retain source, size,
address, mask and data. An external scheduler calls
`respond_external(source=..., size=..., request_sequence=..., reset_epoch=..., data=...)`; the driver holds the D
response until accepted and reports that acceptance with `external: true`.
One external transaction may be outstanding, applying A backpressure while
coherent RAM responses continue draining. Only successful responses and one
contiguous external range are supported. Coherent acquisitions in that range
fail explicitly. This interface does not itself provide generic router
admission or evidence of CPU/peripheral integration. B.valid remains zero.

External ranges are restricted to the pinned legal uncached 0x4000–0x4fff
window. `external_request` returns the epoch and sequence required to complete
a deferred response; stale responses from earlier resets are rejected. Program
loads must fit the 0x80000000–0xffffffff RAM window.

The raw external interface preserves 64-bit TileLink lane placement: byte lane
is `address & 7`, write bytes follow A.mask, and D.data must place a narrow read
result in those same lanes. The native driver rejects misaligned requests and
masks outside the natural transfer lanes. Duplicate Python response submission
is rejected before sending a second native command. Once offered, an external
D beat keeps its producer and payload while D.ready is low, including when C
traffic queues a native RAM response.

`myfuzz.scenario.boom_gpio_example.make_boom_gpio_chain` constructs a separate
bounded diagnostic using the existing DataflowRouter/TransactionLedger and
real generated PULP GPIO with physical APB samples. Its static firmware writes
53 to PADOUT at 0x400c, fences, reads it through the high 32-bit lane, and writes
CPU readback/success to native uncached RAM at 0x3000/0x3004. It preloads code
only. Native driver source installs the authenticated reset trampoline at
0x10040–0x10048. The diagnostic returns accepted CPU transactions, target
physical samples, source-keyed router deliveries and RAM results; it does not
provide standard runner admission. This source path has not been built or run.

Actual persistent native / standard ScenarioRunner GPIO verification is now
recorded in `evidence/persistent-runtime-20261017/`: two fresh full prefixes
match under declared scope-only comparison; real GPIO readback and CPU RAM
results pass. Changed/missing actual target response controls are rejected.
The GPIO program covers A/D only; persistent C/E coverage is tracked separately.
The native build and both new/preserved gate commands exit 0. This evidence
does not grant generic runtime admission or full P6 acceptance.

The separate `myfuzz.scenario.boom_coherent_verification` supplement now passes
using the same built persistent executable: two complete fresh599-edge receipts
and scoped runtime streams match, with A21/C80/D164/E14 and dirty backing RAM
0x123. `evidence/persistent-coherent-20261017/` retains full raw evidence and
actual exit0. Its old one-shot bus-field projection comparison is separate.
Run under the shared lock with `--repo`, `--cpu-output`, `--output`, and optional
`--one-shot-trace`. No external probes or full P6 admission are claimed.
