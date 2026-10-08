# Ibex and OpenTitan I2C command-complete MEI acceptance

Date: 2026-10-05

## Result

The real RTL integration test passed one test covering a seed peer byte `0x5a`, a bit-0 mutation `0x5b`, and full semantic replay of each variant on fresh Ibex and I2C sessions. The generated Ibex OBI CPU and OpenTitan I2C TL-UL controller ran in separate local harnesses. A `0x40000000` window of size `0x1000` routed CPU MMIO to I2C; native `i2c.irq_o[9]` was bound to the CPU scalar machine-external IRQ input. The sole fuzzable input was eight-bit `i2c.peer_response`, owned by `external_i2c_peer`.

The Genome `START` action only installed the peer response; no IRQ appeared before the CPU's first FDATA write. CPU FDATA `0x1a1` caused a real SDA falling START edge with SCL high, and FDATA `0x601` queued the one-byte read and STOP. After the second FDATA, the test found at least 16 SCL rising edges and eight contiguous `sda_i` samples matching the chosen byte MSB first (`01011010` or `01011011`). The actual I2C RDATA and CPU RAM low byte matched the chosen peer byte in both variants.

| Variant | Peer byte | I2C RDATA low byte | CPU RAM low byte | Replay |
| --- | ---: | ---: | ---: | --- |
| Seed | `0x5a` | `0x5a` | `0x5a` | Fresh CPU and I2C, full semantic match |
| Bit-0 mutation | `0x5b` | `0x5b` | `0x5b` | Fresh CPU and I2C, full semantic match |

The CPU wrote TIMING0..4 exactly once in order (`0x3c=0x00100010`, `0x40=0x00020002`, `0x44=0x00080008`, `0x48=0x00040004`, `0x4c=0x00080008`), then `INTR_ENABLE 0x04=0x200`, `CTRL 0x10=1`, and the two FDATA words. The ISR's only I2C write was `INTR_STATE 0x00=0x200` to clear command complete. Routed MMIO source identities were unique, from the CPU, and in reset epoch zero.

Ibex booted at `0x10080` and wrote the aligned `mtvec` base `0x10100`. Its WFI wait produced native `core_sleep_o=1` before the I2C IRQ and `core_sleep_o=0` after wake with IRQ high. The first accepted CPU fetch after the native IRQ rose was the cause-11 vector slot `0x1012c`. The handler read actual `INTR_STATE[9]=1`, actual RDATA, and CPU CSR `mcause=0x8000000b`, then stored them at `0x20000`, `0x20004`, and `0x20008`. It wrote W1C `0x200`, read back `INTR_STATE[9]=0`, and stored that status and completion marker `0x55` at `0x2000c` and `0x20010`. A later I2C local-tick sample showed `irq_o[9]=0`. An accepted CPU fetch after the marker showed MRET resumed the wait loop.

## Verification command and full output

```text
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_ibex_opentitan_i2c_irq_real.py
.                                                                        [100%]
1 passed in 62.33s (0:01:02)
```

The initial TDD assertion failed because the first image set omitted the required `0x1012c` vector slot. A subsequent real RTL run attempted to write `mtvec=0x1012c` under the incorrect direct-mode assumption; Ibex normalized it to its aligned vectored base and the run reached the serial and native IRQ assertions, then failed on an assumed physical IRQ acknowledgement port. RTL inspection showed that Ibex forces a 256-byte aligned vectored `mtvec` and its profile exposes no physical `irq_ack_o` or `irq_id_o` outputs. The corrected test writes base `0x10100`, uses vector slot `0x1012c`, and checks the CPU's actual `mcause` and accepted fetch as MEI evidence.

Each Genome was limited to 6000 steps. Each bundle used `ResourceBudget(max_transactions=512, max_local_cycles_per_component=8192, max_scheduler_steps=12000, max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x20000, max_evidence_bytes=64*1024*1024)`, and the test checked recorded usage against these limits. Both variants stayed in reset epoch zero with no in-test reset. The local harnesses have independent clocks and scheduled observations, so no global cycle-accurate timing is claimed.

## Scope and self-review

This proves one fixed Ibex/OpenTitan I2C combination and a second OBI CPU reuse example. It does not establish profile-only adaptation for every OBI CPU. Coverage is limited to one local I2C controller, the existing single peer at address `0x50`, one byte without clock stretching, and one command-complete MEI service. It does not cover a PLIC or SoC interrupt topology, multiple bytes or peers, other I2C modes, or coverage-guided bug discovery.

Self-review: the mutation changes only the declared peer byte. The test obtains pad bits, IRQ, status, RDATA, and RAM from real DUT execution, checks first and second FDATA ordering, verifies WFI sleep/wake and the exact vector fetch, observes W1C and later IRQ low, reads `mcause` through an ISR CSR instruction, checks MRET return, confirms unique epoch-zero MMIO identities, and requires full fresh replay for both source values. No generic runtime or profile files were edited for this scenario.
