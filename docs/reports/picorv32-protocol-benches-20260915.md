# Real PicoRV32 benches for the Wishbone and AXI4-Lite CPU-side adapters

Worktree: `.worktrees/ibex-protocol-longrun`
Commits: `3be112f` (adapters + unit benches), `5454d7d` (empty-select read fix),
`ac2c188` + the follow-up hardening commit (real-CPU benches)

This report covers the two initiator protocols added next to `axi4@1`, `obi@1`,
`tl-ul@1` and `ready-valid-memory@1`, and the real-CPU evidence that they work.
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
integration **681 OK (skipped=30)**.

## 8. What this does not prove

* **Renderer wiring.** The user chose the minimal verifiable scope: adapter plus
  tests. The structural adaptation stage that would emit these two protocols
  around a real CPU in a rendered SoC top has **not** been extended, so no
  eight-cell matrix row or campaign run uses them yet. The evidence here stops
  at the adapter boundary, which the benches drive with a real core.
* **ZipCPU as a Wishbone master.** The original pairing was Wishbone × ZipCPU.
  ZipCPU's in-tree assembler does not build with a modern toolchain
  (`zparser.h`'s `ZIPREG` enum collides with the `ZIP_SP`/`ZIP_CC`/`ZIP_PC`
  macros from `zopcodes.h`, and `zdump.cpp` calls a nonexistent
  `zipi_to_string`), so a ZipCPU program image cannot be produced
  reproducibly from that checkout. PicoRV32 — which has both an AXI4-Lite and a
  Wishbone wrapper — carries the runtime evidence instead. Status of the
  ZipCPU attempt: see section 8.1.
* **RFuzz feedback.** These two protocols have no coverage-feedback campaign;
  the counters, transport and instrumentation limits documented in
  `docs/reports/soc-acceptance-20260915.md` are unchanged.
* **Silicon.** Instruction-level RVFI evidence in simulation is not a statement
  about hardware.

### 8.1 ZipCPU attempt

ZipCPU hardware RTL is present at `third_party/soc-zipcpu/rtl/core/zipwb.v` and
would have been usable as a classic Wishbone master (`o_wb_gbl_cyc/stb`,
`o_wb_lcl_cyc/stb`, `o_wb_we`, `o_wb_addr` as a word address, `o_wb_sel`,
`i_wb_stall/ack/data/err`). The blocker is purely tooling: the vendored
`sw/zasm` assembler and `zdump` disassembler both fail to compile, so an image
would have to be produced by porting the opcode builders from
`zparser.h`/`zparser.cpp` into Python and validating the result by execution.
That attempt is tracked separately; until it lands, the Wishbone protocol's
runtime evidence is the PicoRV32 one above, and no ZipCPU-as-master claim is
made.
