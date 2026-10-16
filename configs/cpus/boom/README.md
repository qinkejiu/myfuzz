# BOOM semantic interface profile

This directory contains a source-independent semantic description for a BOOM
RV64 IMAFDC configuration. The description names instruction/data memory,
interrupt, optional debug, clock, and reset roles; it intentionally leaves
physical directions, widths, signedness, hierarchy, and timing to the generic
HDL crawler.

The profile is reference-only. BOOM is normally materialized together with a
generated Rocket Chip/Chipyard design below `third_party/boom`; replace the
reserved all-zero `sha256:` placeholder only after a generated RTL closure is
verified. The catalog must continue to report the profile as unavailable until
annotation and the selected integration boundary both validate.

## Fixed upstream source and generation attempt (2026-10-17)

`chipyard_source_manifest.json` records the actual source snapshot staged at
`/root/fanzehui/system-20261016/chipyard-pinned` on the build host. The BOOM
reference commit `58ef2720eae13be26b3008c02b5a74ce29c61c44` names
Chipyard `4180463d52bc0a6b4c004530601ccdabebf0ab7d` in `CHIPYARD.hash`.
The Chipyard Git tree at that exact commit names a different BOOM submodule,
`1ad28828673f2fce7a18f7255facd4705f04a58a`. The staged source uses the
Chipyard Git tree and its BOOM gitlink as a self-consistent generation input;
it does not claim to generate the separate BOOM reference commit. The manifest
contains the Git commit and SHA-256 of each retrieved source archive, including
the two required Rocket Chip nested submodules. The main Chipyard archive SHA-256
is `876f36eb5fbd01a4ccc5d96f98f8e59037f418d4dbcf696b1996468e307bc59e`.

This Chipyard revision defines `chipyard.SmallBoomConfig`; it has no
`SmallBoomV3Config`. The existing `configs/designs/boom` filelists name
`SmallBoomV3Config` and cannot be treated as outputs from this revision. The
bounded upstream generation command is recorded on the build host in
`/root/fanzehui/system-20261016/evidence/chipyard-smallboom-command.txt`, with
the corresponding `chipyard-smallboom-firrtl.log` and `.exit` files. The command
targets `make firrtl CONFIG=SmallBoomConfig` in `sims/verilator`, uses Java 11,
sbt 1.5.5 from the upstream build definition, and runs under the shared
`project/.superpowers/heavy-worker.lock`.

The attempt exited 2 while sbt resolved project dependencies. In the log,
`targetutils` and `iocell` cannot obtain
`edu.berkeley.cs:chisel3_2.12:3.5-SNAPSHOT`, and `dsptools` cannot obtain
`edu.berkeley.cs:chisel-iotesters_2.12:2.5-SNAPSHOT`. The configured Maven
Central and Sonatype snapshot URLs lack these artifacts; a Sonatype release URL
returns HTTP 402. This is a generator toolchain dependency failure before
Chisel elaboration. The output directory contains only copied simulation
resources and boot ROMs, with no `.fir` or generated RTL. The build host also
records `chipyard-smallboom-toolchain.txt` (Java 11, sbt launcher digest and
Verilator 5.020). A successful generation would still produce a Chipyard SoC
boundary, requiring inspection of the physical BOOM/TileLink ports before
this abstract `boom_tile` interface could be materialized.

An exploratory copy at `/root/fanzehui/system-20261016/chipyard-release-deps`
replaces the unavailable snapshots with published Chisel 3.5.0, FIRRTL 1.5.0,
and chisel-iotesters 2.5.0. Its complete diff is saved as
`/root/fanzehui/system-20261016/evidence/chipyard-release-deps.patch` and its
own logs use the `chipyard-release-deps-` prefix. This copy may help inspect a
generated physical boundary, but it is a modified generator input and cannot
establish generation from the unmodified Chipyard source pin.

There is an additional unavailable dependency. `tilelink@1` is now *declared*
in the protocol catalog (`src/myfuzz/protocols/plugins/tilelink.json`) and the
CPU-side contract `cpu.tilelink` accepts exactly the two endpoint shapes this
description declares (`declared-four-role` for `cpu.instruction_memory`,
`declared-five-role-write-capable` for `cpu.data_memory`). What is still
missing is an *implementation*: the plugin declares no legal adapter because
this repository has no TileLink RTL adapter, and this profile has no
`component_profile.json`. Downloading or generating BOOM sources alone
therefore still cannot make this profile executable. The abstract
instruction/data roles are the declared vocabulary, not a complete TileLink
A/B/C/D/E channel mapping - the contract deliberately does not claim one. TL-UL
support does not provide BOOM TileLink/coherence support.

The explicit materialization entry is `third_party/boom/sources.f`. It must
list generated RTL and its dependencies, including an exported `boom_tile`
boundary. Use actual port aliases/module/hierarchy in the description; there
is no supported `source_anchor` field. Update the profile and description
locators identically and include filelists in the verified source pin.

Runtime enablement additionally requires a supported, validated boundary:
implement the applicable TileLink protocol, full channel mapping and adapter
capabilities, or supply a separately verified boundary converter and describe
its supported protocol honestly. Keep `implemented=false` and
`available=false` until those dependencies exist. A regression test provides
pinned synthetic RTL and verifies that annotation still rejects the missing
`tilelink@1` dependency. This iteration does not download Chipyard or claim
BOOM runtime support.
