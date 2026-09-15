# Real PicoRV32 benches for the Wishbone and AXI4-Lite CPU-side adapters

Worktree: `.worktrees/ibex-protocol-longrun`
Commits: `3be112f` (adapters + unit benches), `5454d7d` (empty-select read fix),
`ac2c188` (real-CPU benches)

This report covers the two initiator protocols added next to `axi4@1`, `obi@1`,
`tl-ul@1` and `ready-valid-memory@1`, and the real-CPU evidence that they work.
It records what was measured, what the measurement rules out, and what it does
**not** yet prove.

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
`ram_writes`, `cycles` or the retired stream would point at the protocol
adaptation rather than at the CPU or the memory.

## 3. The boot image

`tests/fixtures/soc_picorv32_boot.S` (17 RV32I instructions) is assembled with
the RISC-V target inside clang, not by hand:

```bash
clang --target=riscv32 -march=rv32i -mabi=ilp32 -nostdlib -fuse-ld=lld \
      -Wl,-Ttext=0 -Wl,--no-relax -o boot.elf soc_picorv32_boot.S
```

The program stores a full word, a second full word, one **byte** and one
**halfword**, loads back a word and a halfword, stores both loaded values, and
finishes with a completion marker followed by a self jump. It therefore
exercises word/byte/halfword byte enables, the read path, and the fetch path.

Three independent checks keep the committed `soc_picorv32_boot.hex` honest:

1. an always-runnable test reassembles the committed `.S` and fails if the two
   disagree, so the fixture cannot silently rot;
2. the 17 encodings are listed with their mnemonics in
   `tests/integration/test_soc_real_picorv32.py`; every word was verified by
   hand against the RV32I specification (for example the first word
   `0x10000293` is `addi t0, x0, 0x100`, and `0xa5a30313` is
   `addi t1, t1, -0x5a6`, i.e. the low half of `0x5a5a5a5a`);
3. the benches compare the image against what the CPU **retires**, so a wrong
   word in the fixture fails the run rather than passing quietly.

## 4. Evidence from the two runs

```
SOC_PICORV32_AXILITE_REAL_OK retired=17 stores=7 loads=2 responses=27 ram_writes=7 ram_reads=20 cycles=210 data=5a5a5a5a
SOC_PICORV32_WISHBONE_REAL_OK retired=17 stores=7 loads=2 acks=54 ram_writes=7 ram_reads=20 cycles=237 data=5a5a5a5a
```

| Number | Value (both runs) | What it rules out |
|---|---|---|
| `retired` | 17 | the CPU really executed the whole committed program; every word and PC was compared against the image, so a divergence or a trap fails the run instead of going unnoticed |
| `stores` | 7 | the CPU itself reports 7 retiring stores, matching the 7 stores in the program |
| `loads` | 2 | the two loads really retired, so the read path carried data back into the pipeline |
| `ram_writes` | 7 | exactly the 7 retired stores reached memory — no write invented by the adapter, none dropped |
| `ram_reads` | 20 | 17 instruction fetches + 2 data loads + 1 fetch beyond the marker |
| `data` | `5a5a5a5a` | the word loaded back from `0x100` equals what was stored there |
| `cycles` | 210 / 237 | the AXI4-Lite master completed in fewer cycles than the Wishbone one; both are far below the 200 000-cycle watchdog |

The RAM is zero-initialised before the image is loaded, and the byte and
halfword stores are checked as **whole words** (`0x000000a5` at `0x108` and
`0x10c`). An adapter that widened a one-byte store into a four-byte store would
therefore leave `0x5a5a5a5a`-style contamination in the upper lanes and fail —
this is checked, not assumed.

Additional invariants the benches refuse to violate: a `trap` from the CPU, a
non-`OKAY` AXI response, a Wishbone `ERR` on an in-range access, a beat-backend
error, or a cycle-watchdog expiry. Both benches also fail if the CPU ever
retires an instruction that is not in the image.

## 5. The bug these benches found

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

## 6. How to reproduce

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

## 7. What this does not prove

* **Renderer wiring.** The user chose the minimal verifiable scope: adapter plus
  tests. The structural adaptation stage that would emit these two protocols
  around a real CPU in a rendered SoC top has **not** been extended, so no
  eight-cell matrix row or campaign run uses them yet. The evidence here stops
  at the adapter boundary, which the benches drive with a real core.
* **ZipCPU as a Wishbone master.** The original pairing was Wishbone × ZipCPU.
  ZipCPU's in-tree assembler does not build with a modern toolchain
  (`zparser.h`'s `ZIPREG` enum collides with the `ZIP_SP`/`ZIP_CC`/`ZIP_PC`
  macros from `zopcodes.h`, and `zdump.cpp` calls a nonexistent
  `zipi_to_string`), so a ZipCPU program image cannot currently be produced
  reproducibly. PicoRV32 — which has both an AXI4-Lite and a Wishbone wrapper —
  was used instead for the runtime evidence. Status of the ZipCPU attempt is
  recorded in section 7.1.
* **RFuzz feedback.** These two protocols have no coverage-feedback campaign;
  the counters, transport and instrumentation limits documented in
  `docs/reports/soc-acceptance-20260915.md` are unchanged.
* **Silicon.** Instruction-level RVFI evidence in simulation is not a statement
  about hardware.

### 7.1 ZipCPU attempt

See `docs/reports/soc-acceptance-20260915.md` and the commit history for the
final status. The blocker is a tooling one, not an RTL one: ZipCPU hardware RTL
is present at `third_party/soc-zipcpu/rtl/core/zipwb.v`, and the encoder would
have to be ported to Python from the vendored `zparser.h`/`zparser.cpp` opcode
builders because no working assembler or disassembler can be built from that
checkout.
