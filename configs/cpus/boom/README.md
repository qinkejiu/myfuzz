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
