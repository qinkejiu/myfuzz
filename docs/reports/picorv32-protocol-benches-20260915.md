# Real-CPU benches for the Wishbone and AXI4-Lite CPU-side adapters

Worktree: `.worktrees/ibex-protocol-longrun`
Commits: `3be112f` (adapters + unit benches), `5454d7d` (empty-select read fix),
`ac2c188` + `de032fd` (real PicoRV32 benches, hardened), `59bbba9` (real ZipCPU
bench)

This report covers the two initiator protocols added next to `axi4@1`, `obi@1`,
`tl-ul@1` and `ready-valid-memory@1`, and the real-CPU evidence that they work:
PicoRV32 drives both protocols (AXI4-Lite and classic Wishbone) and ZipCPU, an
unrelated core, drives Wishbone as a second master (section 9).
It records what was measured, what the measurement rules out, which checks were
shown to be able to fail, and what is still **not** proven.

## 1. What was added

| Registry key | Adapter module | CPU-side ports |
|---|---|---|
| `wishbone@classic` | `wishbone_processor_memory_adapter` | 10 (`cyc/stb/we/adr/dat_w/sel` in, `stall/ack/err/dat_r` out) |
| `axi4-lite@1` | `axi4_lite_processor_memory_adapter` | 19 (`aw*`, `w*`, `b*`, `ar*`, `r*`) |

Both adapters are single-outstanding initiators that terminate exactly one beat
per bus transaction, so neither needs reordering or ID bookkeeping:

* the Wishbone adapter derives `READ_ONLY` and `HAS_SEL` from the memory fields
  the driver actually sees, treats `SEL` exactly as the OBI adapter treats `BE`
  (pass-byte-enable, width `dat_w/8`), and applies the same accept-and-ignore
  policy to `awprot`/`arprot` that the AXI4 adapter applies to its sidebands;
* the AXI4-Lite adapter accepts AW and W in either order, gives the write
  channels deterministic priority over reads, and maps a backend error onto
  `SLVERR` with `rdata = 0`.

Neither key was added to the **target**-side registry in
`src/myfuzz/composition/target_adapters.py`: `wishbone` and `axi4-lite` remain
legitimate target protocols (`beat_to_wishbone`, `axi4_lite_mmio_bridge`), and
only the initiator direction is new.

## 2. The datapath the benches actually exercise

```
real PicoRV32 ──► adapter under test ──► myfuzz_processor_memory_backend ──► soc_cpu_beat_ram
 picorv32_axi     axi4_lite_processor_memory_adapter     (generic beat backend)   (testbench RAM)
 picorv32_wb      wishbone_processor_memory_adapter
```

The same core, the same assembled image and the same RAM model are used twice,
so the only difference between the two runs is the initiator protocol. That is
also why one run can be compared against the other: a divergence in
`ram_writes`, `cycles` or the retired stream points at the protocol adaptation
rather than at the CPU or the memory.

## 3. The boot image

`tests/fixtures/soc_picorv32_boot.S` (18 RV32I instructions) is assembled with
the RISC-V target inside clang, not by hand:

```bash
clang --target=riscv32 -march=rv32i -mabi=ilp32 -nostdlib -fuse-ld=lld \
      -Wl,-Ttext=0 -Wl,--no-relax -o boot.elf soc_picorv32_boot.S
```

The program stores a full word, a second full word, one **byte** and one
**halfword**, loads back a word and a halfword, stores both loaded values, and
finishes with a completion marker followed by a self jump. It therefore
exercises word/byte/halfword byte enables, both directions of the data path,
and the fetch path.

The store register holds `0xdeadbea5`, whose upper bytes are non-zero, and that
choice is load-bearing: a byte store must leave `0x000000a5` in memory and a
halfword store `0x0000bea5`, so an adapter that widened either access into a
four-byte store leaves a different word behind and fails. A store value with
zero upper bytes would have made the lane check vacuous. The signed halfword
load is checked too: `lh` of `0xbea5` must produce `0xffffbea5`.

Three independent checks keep the committed `soc_picorv32_boot.hex` honest:

1. an always-runnable test reassembles the committed `.S` and fails if the two
   disagree, so the fixture cannot silently rot;
2. the 18 encodings are listed with their mnemonics in
   `tests/integration/test_soc_real_picorv32.py`, each verified by hand against
   the RV32I specification (for example the first word `0x10000293` is
   `addi t0, x0, 0x100`, and `0xdeadc3b7` + `0xea538393` are
   `lui t2, 0xdeadc` and `addi t2, t2, -0x15b`, i.e. `t2 = 0xdeadbea5`);
3. the benches compare the image against what the CPU **retires**, so a wrong
   word in the fixture fails the run rather than passing quietly.

## 4. Evidence from the two runs

```
SOC_PICORV32_AXILITE_REAL_OK retired=18 stores=7 loads=2 responses=28 ram_writes=7 ram_reads=21 cycles=218 data=5a5a5a5a
SOC_PICORV32_WISHBONE_REAL_OK retired=18 stores=7 loads=2 acks=56 ram_writes=7 ram_reads=21 cycles=246 data=5a5a5a5a
```

| Number | Value (both runs) | What it rules out |
|---|---|---|
| `retired` | 18 | the CPU really executed the whole committed program; every word and PC was compared against the image, so a divergence or a trap fails the run instead of going unnoticed |
| `stores` | 7 | the CPU itself reports 7 retiring stores, matching the 7 stores in the program |
| `loads` | 2 | the word and halfword loads really retired, so the read path carried data back into the pipeline |
| `ram_writes` | 7 | exactly the 7 retired stores reached memory — no write invented by the adapter, none dropped |
| `ram_reads` | 21 | 18 instruction fetches + 2 data loads + 1 fetch beyond the marker |
| `data` | `5a5a5a5a` | the word loaded back from `0x100` equals what was stored there |
| `cycles` | 218 / 246 | the AXI4-Lite master completed in fewer cycles than the Wishbone one; both are far below the 200 000-cycle watchdog |

The RAM is zero-initialised before the image is loaded, and the byte and
halfword stores are checked as whole words. The bench also refuses a `trap` from
the CPU, a non-`OKAY` AXI response, a Wishbone `ERR`, a beat-backend error, a
watchdog expiry, and any retired instruction that is not in the image.

## 5. Mutation controls: the checks were shown to be able to fail

A bench that cannot fail proves nothing, so each load-bearing check was
sabotaged deliberately (in scratch copies, never in the repository) and the
bench was required to fail:

| Sabotage | Result |
|---|---|
| Wishbone adapter ignores `SEL`, always drives a full-lane write enable | `SOC_PICORV32_WISHBONE_FAIL byte store at 0x108 must not widen to a word mem[66]=a5a5a5a5` |
| AXI4-Lite adapter ignores `WSTRB`, always drives a full-lane write enable | `SOC_PICORV32_AXILITE_FAIL byte store at 0x108 must not widen to a word mem[66]=a5a5a5a5` |
| Retirement checker compares against the wrong expected instruction | `SOC_CPU_RVFI_INSN_MISMATCH retired=0 pc=00000000 insn=10000293 expected=5a5a6337`, then the bench fails |
| RAM model under-counts the writes it performed | `write accounting: ram_writes=2 cpu_stores=7`, then the bench fails |

The lane checks are therefore live in both protocol runs, the retirement
comparison is live, and the write accounting is live. What is *not*
mutation-verified is anything not listed above; in particular the checks for
AXI response codes and the cycle watchdog are only reasoned about, not
sabotaged.

## 6. The bug these benches found

The first Wishbone run failed after five cycles with
`adapter reported a Wishbone error for an in-range access`, before any RAM
activity at all. The cause was in the adapter under test, not in the CPU:

* PicoRV32's Wishbone master drives `wbm_sel_o` straight from its write strobe
  (`wbm_sel_o <= mem_wstrb`), and that strobe is zero for **every read**;
* the adapter treated `SEL == 0` as a refusal for reads and writes alike and
  answered `ERR` without issuing a beat request;
* the unit bench had encoded exactly that rule as correct
  (`an empty-select read terminates with ERR`), which is why the unit suite
  passed.

`SEL` is a write-side byte lane in classic Wishbone, so the adapter now refuses
only a **write** with nothing selected and issues an empty-select **read** as a
full-lane read (the defined answer to "this master expressed no lane
preference"). The unit bench was split accordingly: one test for the refusal,
one for the read being issued with a full byte enable. This is the concrete
return on running real CPU RTL instead of only hand-driven bus benches.

## 7. How to reproduce

```bash
# adapter benches (always runnable, Icarus Verilog only)
PYTHONPATH=src python3 -m unittest \
  tests.protocols.test_wishbone_and_axi4_lite_processor_memory_adapters_rtl

# registry/derivation benches
PYTHONPATH=src python3 -m unittest tests.composition.test_processor_adapters

# real PicoRV32 through both adapters (needs the third_party checkout)
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_real_picorv32
```

The simulations need `third_party/picorv32_upstream_reference` (pinned at
`ef203c2`, not part of this repository) and Icarus Verilog, which is why they
are opt-in behind `MYFUZZ_SOC_REAL=1` exactly like the Ibex boundary. The
benches compile with `-DRISCV_FORMAL` because that is what makes PicoRV32
publish the RVFI retirement trace the evidence depends on.

Suite results for this change set: protocols **140 OK**, composition **526 OK**,
integration **696 OK (skipped=32)** including the ZipCPU module, and the full
regression **1658 OK (skipped=32)**.

## 8. What this does not prove

* **Renderer wiring.** The user chose the minimal verifiable scope: adapter plus
  tests. The structural adaptation stage that would emit these two protocols
  around a real CPU in a rendered SoC top has **not** been extended, so no
  eight-cell matrix row or campaign run uses them yet. The evidence here stops
  at the adapter boundary, which the benches drive with a real core.
* **ZipCPU as a Wishbone master.** Done, and reported in section 8.1: a real
  ZipCPU executes a real program through the same frozen adapter. The one thing
  that is still true is that ZipCPU's in-tree assembler and disassembler do not
  build with a modern toolchain, so the image is produced by a Python encoder
  ported from `zopcodes.cpp` plus `idecode.v` rather than by `zasm`.
* **RFuzz feedback.** These two protocols have no coverage-feedback campaign;
  the counters, transport and instrumentation limits documented in
  `docs/reports/soc-acceptance-20260915.md` are unchanged.
* **Silicon.** Instruction-level RVFI evidence in simulation is not a statement
  about hardware.

### 8.1 ZipCPU as a second Wishbone master

`tests/integration/rtl/soc_zipcpu_wishbone_tb.sv`, with the image built by
`tests/integration/zipcpu_boot_image.py`:

```
SOC_ZIPCPU_WISHBONE_REAL_OK stores=2 data=0000beef0000bef0 cycles=125 reads=9 quiet=64
SOC_ZIPCPU_WISHBONE_TRACE store[0] addr=00000200 data=0000beef be=1111
SOC_ZIPCPU_WISHBONE_TRACE store[1] addr=00000204 data=0000bef0 be=1111
SOC_ZIPCPU_WISHBONE_TRACE read[0..8] addr=00000100 ... 00000110 00000200 00000114 00000118 0000011c
```

The program is seven ZipCPU instructions at `0x100`: `LDI 0x200,R1`,
`LDI 0xbeef,R2`, `STO R2,0(R1)`, `LOD 0(R1),R3`, `ADD 1,R3`, `STO R3,4(R1)`,
`HALT`. The fetch stream walks `0x100…0x11c` in order with exactly one data read
at `0x200` interleaved, which is the load.

Why the evidence holds up:

* the pass criterion is `ram[0x200] == 0xbeef` **and**
  `ram[0x204] == 0xbef0` **and** exactly two accepted writes **and** at least one
  read **and** 64 consecutive cycles with no bus request. The second word is
  `first + 1`, so it cannot exist unless the core fetched, decoded, **loaded**,
  ran the ALU and stored again — a CPU that merely fetched something cannot
  produce it;
* the RAM is zero-initialised and only the backend target handshake writes it,
  and the bench `$fatal`s if the image preloads either expected word, so the
  result cannot come from the fixture;
* quiescence is what shows the `HALT` really halted the core rather than the
  testbench merely looking at the right moment;
* the image path is checked against the expected program words at `0x100`, so a
  truncated or wrong image fails at load time.

Negative controls, all re-run independently for this report (each exits
non-zero with no `OK` line): corrupting the `ADD` immediate so the second store
would be `0xbef1` gives
`SOC_ZIPCPU_WISHBONE_TIMEOUT ... ram[00000204]=0000bef1 (want 0000bef0)`;
replacing `HALT` with `BREAK` gives `ZipCPU asserted o_break at cycle 61`;
preloading an expected store word gives `boot image preloads the expected store
results; the pass check would be vacuous`; pointing the plusarg at a missing
file fails at load. (With no plusarg at all the bench falls back to the
committed fixture by design, which is why "no plusarg" is not itself a failure
control.)

Two corrections came out of this bench and were verified here against the RTL:

1. **`sw/zasm/zparser.cpp` is not the encoding authority.** Its own header warns
   it is out of date, and it is: `op_ldi` emits op field `0b1011x`
   (`zparser.h:100` comments `ZIPO_LDI, ZIPO_LDIn // 5'h1011x`), while
   `idecode.v:206` decodes `LDI` from `w_cis_op[4:1] == 4'hc`, i.e. `0b1100`;
   `op_break`'s word decodes as `LDIn` in the RTL. The encoder therefore follows
   `zopcodes.cpp`'s disassembler table together with `idecode.v`, two sources
   that agree with each other and with execution.
2. **`ADDRESS_WIDTH` must be 30, not 32.** `zipcore.v:134` computes
   `RESET_BUS_ADDRESS = RESET_ADDRESS[AW+1:2]`, so `AW=32` selects bits
   `[33:2]` of a 32-bit parameter; the out-of-range bits come back `X`, the `X`
   reaches the program counter, and the core dies on its first fetch. With
   `AW=30` the select is `[31:2]` and `{o_wb_addr, 2'b00}` is exactly the 32-bit
   byte address the adapter wants. This is a ZipCPU RTL property; the adapter
   and backend are not involved.

ZipCPU is configured with `OPT_LGICACHE=0`, `OPT_LGDCACHE=0` (so every fetch,
load and store is a visible bus transfer), `OPT_SIM=1`, `OPT_START_HALTED=1`
(released by dropping `i_halt`) and `OPT_PIPELINED=0`, which matches the
adapter's documented single-outstanding classic contract. The test module
reports 15 tests OK with `MYFUZZ_SOC_REAL=1` and 15 OK (2 skipped) without it.
