# CV32E40P and OpenTitan I2C command-complete MEI acceptance

Date: 2026-10-05

## Result

The real RTL scenario in `tests/integration/test_scenario_cv32e40p_opentitan_i2c_irq_real.py` passed for a seed peer byte and a target-aware bit-0 mutation. Each variant was recorded with bounded evidence and replayed on fresh CPU and I2C sessions with full semantic equality. The generated CV32E40P OBI CPU and OpenTitan I2C TL-UL controller ran in separate local harnesses, joined by a `0x40000000`/`0x1000` MMIO window and a binding from native `i2c.irq_o[9]` to the CPU scalar MEI input (physical IRQ bit 11).

The only fuzzable source was the eight-bit `i2c.peer_response` owned by `external_i2c_peer`. Its Genome `START` action installed the local environment peer byte before CPU FDATA access. It did not initiate a serial transaction: the red real RTL run admitted `0x5a`, clocked I2C for 32 local ticks without FDATA, and failed the expected IRQ assertion because `irq_o[9]` stayed low. In the passing scenario, CPU FDATA `0x1a1` initiated START/address activity and FDATA `0x601` queued the one-byte read and STOP. The trace checks a real SDA falling START edge after the first accepted FDATA, at least 16 SCL rising edges after the second accepted FDATA, and open-drain pad outputs. Eight contiguous native `sda_i` samples at SCL rising edges after the second FDATA matched the selected peer byte MSB first: `01011010` for `0x5a` and `01011011` for `0x5b`. The observed RDATA and RAM values independently matched each selected byte.

| Variant | Genome peer source | Actual I2C RDATA low byte | CPU RAM RDATA low byte | Replay |
| --- | ---: | ---: | ---: | --- |
| Seed | `0x5a` | `0x5a` | `0x5a` | Fresh CPU and I2C, full semantic match |
| Bit-0 mutation | `0x5b` | `0x5b` | `0x5b` | Fresh CPU and I2C, full semantic match |

The CPU wrote TIMING0..4 in order (`0x3c=0x00100010`, `0x40=0x00020002`, `0x44=0x00080008`, `0x48=0x00040004`, `0x4c=0x00080008`), followed by `INTR_ENABLE 0x04=0x200`, `CTRL 0x10=1`, and the two FDATA words. Each configuration or command write occurred exactly once. The ISR's only I2C write was `INTR_STATE 0x00=0x200` for W1C. All routed MMIO transactions had unique CPU source identities in reset epoch zero.

The native I2C `irq_o[9]` sample rose before W1C, and its bound scalar value 1 reached the CPU. The CV32E40P acknowledged physical IRQ ID 11; its first accepted fetch after acknowledgement was the direct entry at `0x10100`. A jump there entered the ISR; the vectored MEI slot at `0x1012c` was an infinite-loop guard. The ISR read actual `INTR_STATE[9]=1`, actual RDATA, and CPU CSR `mcause=0x8000000b`, then committed those values to RAM at `0x20000`, `0x20004`, and `0x20008`. It wrote W1C `0x200`, read back `INTR_STATE[9]=0`, and stored the post-clear status and completion marker `0x55` at `0x2000c` and `0x20010`. A later I2C local-tick sample showed `irq_o[9]=0`, and an accepted CPU fetch after the marker showed MRET resumed the main wait loop.

## Command and output

```text
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_i2c_irq_real.py
.                                                                        [100%]
1 passed in 52.94s
```

The Genome limit was 6000 steps. Each recording used `ResourceBudget(max_transactions=512, max_local_cycles_per_component=8192, max_scheduler_steps=12000, max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x20000, max_evidence_bytes=64*1024*1024)`, and the test checked actual bundle usage against these limits. The CPU's WFI wait loop produced a native `core_sleep_o=1` observation before I2C completed and woke to acknowledge the interrupt. A spin-only wait loop exhausted the 512-transaction bound before I2C finished; WFI kept the same bound without changing the I2C timing registers. Both testcases remained in reset epoch zero with no testcase reset events. The local harnesses have independent clocks and scheduled observations; this result makes no global cycle-accurate timing claim.

## Scope and self-review

This acceptance covers one local OpenTitan I2C controller, its existing single slave at address `0x50`, one peer byte with no clock stretching, one command-complete interrupt, CV32E40P direct MEI service, and bounded fresh replay. It does not establish PLIC or SoC interrupt topology, arbitrary CPU or I2C reuse, multiple bytes or peers, clock stretching, or coverage-guided bug discovery.

Self-review: the source mutation changes only the declared Genome peer action, while status, IRQ, cause, RDATA, RAM, and serial SDA bits are observed from real DUT execution. The asserted pad START follows the first accepted FDATA, and the peer-byte bit window follows the second. The `mcause` value comes from a CPU CSR instruction, not MMIO. The test checks IRQ high before W1C and low in a later local tick, direct-vector fetch, RAM commits, MRET return, unique epoch-zero transactions, budget use, and full replay for both variants. No generic runtime or profile behavior was changed for this scenario.
