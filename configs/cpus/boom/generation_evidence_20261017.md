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

## Derived source compatibility repair

The NPE is caused by IO construction order in Rocket Chip, rather than a
missing BOOM cache parameter. `L1MetadataArray` extends `L1HellaCacheModule`,
which imports legacy `Chisel.Module`. Its first statement evaluates
`rstVal = onReset()` before `val io` is initialized. BOOM supplies
`L1Metadata(0.U, ClientMetadata.onReset)` as that callback. In published
Chisel 3.5.0, the callback's Wire construction reaches `Data.ref`, which
triggers legacy automatic IO wrapping; reflection finds the still-null `io`
value and fails. The preserved original stack explicitly shows that chain.

The derived tree now changes this one module to `chisel3.Module with
HasL1HellaCacheParameters`, with `implicit val p` and explicit `IO(new
Bundle {...})`. The reset expression, storage and handshake logic remain the
same. Reproducible patches with relative paths are in `patches/`, applied
in the order documented there. The fixed upstream checkout remains preserved.

The same `make firrtl CONFIG=SmallBoomConfig` command, with the same published
dependencies and under the unified heavy lock, now exits **0**. The generator
reports 58 seconds and writes a **36,351,476 byte** FIRRTL circuit. The full
successful log, command and exit code are committed under
`evidence/derived-20261017/`. This establishes successful elaboration of the
derived source and confirms that changing this module's IO binding resolves
the previously observed NPE.

The emitted FIRRTL has `BoomTile`, `ChipTop`, and `TestHarness` modules.
`BoomTile` has one coherent TileLink master with all A/B/C/D/E channels,
32-bit addresses, 64-bit data, 3-bit source IDs and 3-bit sink IDs. It also has
a 32-bit reset vector, hart ID, local interrupts, NMI and trace ports.
`ChipTop` instead exports AXI4 memory (32-bit address, 64-bit data, 4-bit ID),
serial TileLink, JTAG and UART. The abstract instruction/data memory split in
the semantic reference is not a physical mapping of this generated tile.

## Successful derived Verilog generation

The existing `make verilog CONFIG=SmallBoomConfig` run completed with exit
**0**. `evidence/derived-20261017/verilog-command.sh`, `verilog.log` and
`verilog.exit` preserve the command, complete output and status. It used the
same shared heavy worker lock and a 900-second timeout. No second lowering
was launched. Barstools emitted both top and harness Verilog and compiled the
sequential memory descriptions into flop based Verilog models.

`capture_generation.py` ran on the completed output directory. Its checked-in
`generated_artifact_manifest.json` records SHA-256 and byte length for 35
FIRRTL, JSON, filelist and Verilog artifacts. `sources.f` enumerates the 12
Verilog/SystemVerilog files on the build host; it is a generation inventory,
not a portable CPU materialization filelist. The main top Verilog is
17,963,255 bytes, SHA-256
`78bc69803c7b993cd1ddfcdb585d477bd27a83710bb1ce426e217aedbbdfaced`.
The top memory model is 101,191 bytes, SHA-256
`97ae4679a1ec21f4f424c56e23b1b1948e77d934c8c11461b56de47160a1a280`.
The manifest gives identities for the remaining files. Generated RTL remains
on the build host rather than being copied into the source repository.

`physical_ports.json` records actual lowered Verilog module headers:
`BoomTile` has 47 ports, `BoomCore` 233, `ChipTop` 55 and `TestHarness` 3.
The lowered `BoomTile` retains the coherent A/B/C/D/E master and five local
interrupt inputs. Unlike the earlier FIRRTL boundary, its reset vector, NMI
and trace ports have been removed by specialization/optimization; a runtime
driver must use the actual emitted boundary. `ChipTop` retains the AXI4 memory,
serial TileLink, JTAG and UART boundary described above.

The generated ChipTop's boot ROM deliberately waits in WFI for the serial
interface to load a program and raise MSIP. On that interrupt it loads the
boot address register at 0x4000 and enters the program. Connecting an AXI RAM
responder alone is insufficient to establish execution. The source is
`generators/testchipip/bootrom/bootrom.S` in the derived tree.

## Remaining boundary

The existing `interface_description.json` still has a zero source digest and
an abstract `boom_tile` boundary. The captured generation inventory and port
map have not been admitted as its CPU materialization. There is no verified
coherent TileLink A/B/C/D/E adapter. The existing
`configs/designs/boom` entries cite `SmallBoomV3Config`, absent from this
Chipyard revision. The reference CPU profile therefore remains unavailable for generic runtime execution.


## Direct emitted BoomTile CPU/RAM execution

A separate direct tile probe now executes the actual generated `BoomTile`
with a host RAM manager. Source and the exact build command are in `runtime/`;
trace, exit status and initial failed attempt are in
`evidence/runtime-20261017/`. It uses the generated top Verilog and SRAM
models above, with no synthetic CPU master. Verilator is 5.020. Compilation
and execution run under the same shared heavy worker lock.

The program fetches at the fixed reset address 0x10040, jumps to code in RAM
at 0x80000000, stores 0x123 into cached RAM at 0x80001000, loads it, and writes
the loaded value to an uncached RAM location. It then stores into twelve
conflicting cache lines, causing dirty releases, and reloads the original
line from backing RAM before reporting the second result. The report
locations 0x4000 and 0x4008 are legal uncached addresses in the emitted tile's
map; this isolated RAM responder supplies them instead of the full SoC's
boot address register.

The final run exits **0**, after **555 cycles**, with both CPU result words
and backing RAM writeback equal to **291 (0x123)**. Accepted traffic comprises
5 A Get, 13 A AcquireBlock, 2 A Put, 10 C ReleaseData (80 beats), 156 D beats
and 13 E GrantAck. All queued responses, partial transfers and allocated
sinks are drained. The independent `verify_trace.py` replays all **269**
accepted channel events and checks response opcode/size/source, multibeat
order, permission parameter, sink identity and complete grant before E.
The standalone host manager test also exercises AcquirePerm, Release,
masked/block Put and stable D data under backpressure.

The first probe stopped at BOOM's pipeline watchdog after its initial reset
fetch. Its RV64 LUI trampoline sign extended the RAM physical address. The
corrected program explicitly constructs zero extended 32-bit addresses;
the CPU then executes the RAM sequence. The original program, failure trace
and exit 134 remain captured as `attempt1.*`. No generator or CPU logic was
changed for that correction.

This proves isolated emitted BOOM CPU/RAM execution with a coherent RAM
manager. B.valid stays zero because the environment has no other coherent
clients; no external probes are claimed. It does not enable the abstract
reference profile, provide a generic TileLink adapter, demonstrate full
Chipyard serial boot, or demonstrate CPU-to-IP protocol joining.
