# VexiiRiscv full AXI4 CPU + PULP I2C: F1–F4 through the generic executor

This is the configuration-only F1–F4 combination on the same wiring as
`configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/`: the pinned
`configs/cpus/vexiiriscv` processor (full AXI4, not AXI4-Lite: fetch `AR/R` and
LSU `AW/W/B/AR/R`, 32-bit address/data, 1-bit ID, no LEN/BURST/LOCK/QOS pins),
the pinned `configs/peripherals/pulp_i2c` APB target, and the protocol executor
`compiled_mmio` for all four flows. It adds no IP executor, no internal-state
probe and no storage-version source contract.

## What F1/F3 add here

`CompiledMmioRuntime` turns the independent memory flows on by constructing the
CPU session with `memory_commit_receipts=True`, `memory_readback_receipts=True`
and `physical_tick_samples=True`. `GeneratedVexiiAxiMmioSession` implements all
three, so this descriptor runs F1/F3 with the same receipt streams every other
shared CPU row uses:

| flow | real observation |
| --- | --- |
| F3 | the SW is an actual AXI4 `AW/W/B` beat; `MemoryService` publishes `memory_write_commit` (`memory_write_commit.v1`, per-byte `STORE` cells) and the certificate records `memory_store=observed` |
| F1 | the LW is an actual AXI4 `AR/R` beat served through the runner-installed `memory_read_authority`; the certificate records `memory_read=observed`, joined to the earlier F3 commit byte for byte |

Nothing about the F2/F4 path changed: with those three options off (the F2/F4
descriptor) the session is the previous one bit for bit — same service, same
nonce-keyed transactions, no extra identity key and no tick stream.

## Declared transfer

Identical to the F2/F4 descriptor: a 32-bit APB word at **`0x40000000`**
(PRESCALER, offset 0, read/write mask `0xffff`), one RAM resource at
`0x80000000` of 256 KiB (read/write/execute, preloaded) that is both the
instruction image and the LSU backing store, `max_wait_cycles` 16 and `rounds`
256 per case.

The F1/F3 scratch word is the last word inside the declared RAM
(`result - 4 = 0x8003FFF8`). The executor's instruction-slot window stops one
word short of it, so the LSU read is a plain data read and never a fetch slot.

## Records

`generic_scenario.json` declares the corpus (`f1_records`, `f2_records`,
`f3_records`, `f4_records`); `acceptance_sequence.json` is the ordered six-case
smoke:

| record | flow | meaning |
| --- | --- | --- |
| `55000000` | F3 | `LUI`+`ADDI` the value `0x55`, then a real `SW` of it to the RAM scratch word |
| `03200000` | F1 | the F1 RAM-read token lowers to `LUI`+`LW` of that same scratch word |
| `55000000` | F4 | write `0x55` to the register, read it back, store the read value |
| `00000040` | F2 | read the APB register at `0x40000000` and store `value ^ 0x5a5` |
| `aa000000` | F4 | write `0xaa` |
| `00000040` | F2 | read the register again |

The store runs first on purpose: F1's read then joins the actual
`memory_write_commit` of that store (byte versions and writer event ids).

Internal storage version, instruction retirement, operand origin and cross-case
consumption authority stay unknown; a completed beat or a host-RAM commit alone
justifies no reward.

## Run

```sh
# original: six cases
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/generic_scenario.json \
  --flow mixed --mode original --case runs/vexii-f1f4-20261031 \
  --cache runs/vexii-f1f4-20261031/cache --execution-mode search --rounds 256 \
  --records-file configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/acceptance_sequence.json
# fresh: the same six cases in a fresh runtime, compared against the prefix
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/generic_scenario.json \
  --flow mixed --mode fresh --case runs/vexii-f1f4-20261031 \
  --cache runs/vexii-f1f4-20261031/cache --execution-mode search --rounds 256 \
  --records-file configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/acceptance_sequence.json
```

`summary.json` reports `replay_matches`; the `fresh` run must report `true`.

## Measured locally (`runs/vexii-f1f4-20261031/`)

`original` and `fresh` both complete all six cases on the pinned RTL
(`fresh replay_matches=true`, plan `f2873685e977…`):

| case | flow | status | real observation |
| --- | --- | --- | --- |
| 1 | F3 `55000000` | `submitted` | `memory_store=observed`, commit event 600, bytes `55 00 00 00` at RAM offset 262136, channel `data` sequence 1 |
| 2 | F1 `03200000` | `submitted` | `memory_read=observed`, issuance event 1198, value `0x55`, four `STORE` byte relations to case 1's commit |
| 3 | F4 `55000000` | `observed` | `read_value=0x55`, 8 instruction hops, 2 data hops, 1 RAM write hop |
| 4 | F2 `00000040` | `observed` | `read_value=0x55`, result `0x5f0`, 7 hops, 1 data hop |
| 5 | F4 `aa000000` | `observed` | `read_value=0xaa`, 8 hops, 2 data hops |
| 6 | F2 `00000040` | `observed` | `read_value=0xaa`, result `0x50f`, 7 hops |

Every case ends with `instruction_boundary_park.reason =
fragment_end_instruction_fetch`. The run's journal also carries the opt-in CPU
physical tick stream (`local_tick_sample`, PRE/POST per advance) and one
`memory_read_issuance` for the F1 read; five `memory_write_commit` records cover
the F3 store and the four return-dependent result stores of cases 3–6.

## Not declared here

* **Retirement / storage version / cross-case origin.** The slice has no RVFI
  port, no internal storage provider and no cross-case source authority, so
  those fields stay `unknown` and `reward_eligible=false`.
* **Timing/electrical model.** The I2C `SCL/SDA` pins are held at 1 (idle high);
  no I2C transfer is synthesized, and CTRL stays at its reset value.
* **DUT-internal assertions.** Only the generated harness is compiled and
  observed; no SVA/assertion monitor is part of this build.
