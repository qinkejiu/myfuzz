# BOOM/Chipyard source and generation evidence, 2026-10-17

## Source identity

- BOOM reference: `third_party/boom_upstream_reference` commit
  `58ef2720eae13be26b3008c02b5a74ce29c61c44`; its `CHIPYARD.hash` is
  `4180463d52bc0a6b4c004530601ccdabebf0ab7d` (file SHA-256
  `fb39d763345f02d6c5b4b8f8035a37b2f9ccb591bb49aa25040009d2314acd77`).
- The fixed Chipyard Git tree at `4180463d52bc0a6b4c004530601ccdabebf0ab7d`
  points `generators/boom` at `1ad28828673f2fce7a18f7255facd4705f04a58a`.
  That BOOM checkout has a different `CHIPYARD.hash` (`0e6080682b3dd0ce11cdfed1292ec20e70d75f80`).
  Generation used the Chipyard tree's BOOM gitlink. It did not substitute the
  separate reference commit.
- The full list of 21 checked out Scala generator modules and archive SHA-256
  digests is `chipyard_source_manifest.json`. GitHub codeload served the
  commit-addressed archives; the direct partial `git fetch` failed with a TLS
  timeout before it created a checkout. Its log is
  `/root/fanzehui/system-20261016/evidence/chipyard-fetch.log`.
- The source tree is
  `/root/fanzehui/system-20261016/chipyard-pinned`. The original source archive
  is `/root/fanzehui/system-20261016/chipyard-4180463d.tar.gz`, SHA-256
  `876f36eb5fbd01a4ccc5d96f98f8e59037f418d4dbcf696b1996468e307bc59e`.

## Fixed source run

The pinned Chipyard tree defines `chipyard.SmallBoomConfig`, not
`SmallBoomV3Config`. In `chipyard-pinned/sims/verilator`, under
`project/.superpowers/heavy-worker.lock`, the attempted target was:

```sh
make firrtl CONFIG=SmallBoomConfig \
  RISCV=/root/fanzehui/system-20261016/tools \
  SBT_BIN='java -jar /root/fanzehui/system-20261016/tools/sbt-launch-1.10.0.jar' -j1
```

`timeout 900` bounded the command. Java was OpenJDK 11.0.32.1 and the upstream
build loaded sbt 1.5.5. The command exited **2**. sbt loaded the Chipyard,
BOOM, Rocket Chip, and FireSim projects, then failed dependency resolution:

- `edu.berkeley.cs:chisel3_2.12:3.5-SNAPSHOT`, required by `targetutils` and
  `iocell`, was unavailable.
- `edu.berkeley.cs:chisel-iotesters_2.12:2.5-SNAPSHOT`, required by `dsptools`,
  was unavailable.
- Maven Central and Sonatype snapshot paths returned missing artifacts; one
  Sonatype release path returned HTTP 402.

The exact command, log, exit code, and toolchain identity are respectively
`/root/fanzehui/system-20261016/evidence/chipyard-smallboom-{command.txt,firrtl.log,firrtl.exit,toolchain.txt}`.
The output directory contains only copied simulation resources, no `.fir` or
generated RTL. This run did not reach Chisel elaboration.

## Derived dependency experiment

`/root/fanzehui/system-20261016/chipyard-release-deps` is a copy with published
Chisel 3.5.0, FIRRTL 1.5.0, and chisel-iotesters 2.5.0 replacing unavailable
snapshot dependencies. The complete source diff is
`/root/fanzehui/system-20261016/evidence/chipyard-release-deps.patch`.
The first experiment changed only the root `build.sbt` and still failed because
nested build definitions requested snapshots. The second applied the complete
diff and got through dependency resolution and Scala compilation. It exited
**2** during `chipyard.Generator`/BOOM DCache elaboration with a
`NullPointerException` in Chisel's `LegacyModule._compatAutoWrapPorts` and
`reflectivelyFindValIO`, reached through Rocket Chip `ClientMetadata` and
`BoomNonBlockingDCacheModule.onReset`. Evidence is in
`chipyard-release-deps-firrtl-attempt1.{log,exit}` and
`chipyard-release-deps-firrtl.{log,exit}` under the same remote evidence
directory. No FIRRTL or RTL was generated. The derived run does not count as
generation from the fixed upstream source.

The remote evidence hashes are:

| File under `evidence/` | SHA-256 |
| --- | --- |
| `chipyard-fetch.log` | `60be3d169dc5e450ada7d1437bcf08206bee14cffca21523f8d4851b0a8d9cb2` |
| `chipyard-smallboom-firrtl.log` | `4d58724c656f4053794a91f1fe12840779a3a806a121c540b26b4c30d3312029` |
| `chipyard-release-deps.patch` | `6b5e0b579f8e3d3f014b6143392e34a55a5f0d00317e5a9244bd6d64a088308e` |
| `chipyard-release-deps-firrtl-attempt1.log` | `0d34c2c55cfd144f240c36ca5d25be4ea8c0238a98ff6a252ab3ffade7caa744` |
| `chipyard-release-deps-firrtl.log` | `8aefa8cd28ba0a3b969317bf1a62a5e5d7e584408a48d7a148af8ff4610fa4e9` |

## Remaining boundary

The existing `interface_description.json` still has a zero source digest and
an abstract `boom_tile` boundary. There is no verified `sources.f`, physical
port map, or coherent TileLink A/B/C/D/E adapter. The existing
`configs/designs/boom` entries cite `SmallBoomV3Config`, absent from this
Chipyard revision. BOOM therefore remains unavailable for runtime execution.
