# Generated CV32E40P / OpenTitan SPI Host MEI acceptance

Date: 2026-10-05

The integration fixture uses separate generated local harnesses for the pinned CV32E40P OBI profile (`configs/cpus/cv32e40p/component_profile.json`) and pinned OpenTitan SPI Host TL-UL profile (`configs/peripherals/opentitan_spi_host_local/component_profile.json`). The existing CV32E40P MEI mapping drives physical `irq_i[11]`; the MTI profile is not used.

## Command and outcome

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cv32e40p_opentitan_spi_host_irq_real.py
```

Final acceptance output: `1 passed in 38.90s` (exit status 0). `git diff --check` also passed.

The single integration test executes both source variants, saves a bounded evidence bundle for each, and checks full replay equality using a fresh CPU and SPI Host session for each replay. Bundles live in the test's temporary directory and are removed after the test.

| Source word | Actual RXDATA / RAM at `0x20000` | Actual `mcause` / RAM at `0x20004` | Completion / RAM at `0x20008` | Fresh replay |
| --- | --- | --- | --- | --- |
| `0x12345678` | `0x78563412` | `0x8000000b` | `0x55` | Full equality |
| `0x12345679` | `0x79563412` | `0x8000000b` | `0x55` | Full equality |

The genome mutates only bit 0 of the 32-bit `IP_TO_CPU` source `external_spi_source_word`, with dependency rules through `spi_host.rx_word` to `cpu.result_ram`. The peer presents source bytes in big-endian order; the Host RX FIFO packs those four bytes into the observed little-endian word. The bound CPU IRQ is not a fuzzable source.

## Verified execution

CPU execution at `0x10000` installs direct, 256-byte-aligned `mtvec=0x10100`, enables MEIE and MIE, and issues exactly these five setup/command writes once, in order:

| Host offset | CPU write |
| --- | --- |
| CONTROL `0x10` | `0xa0000001` |
| CONFIGOPTS `0x18` | `8` |
| EVENT_ENABLE `0x34` | `4` |
| INTR_ENABLE `0x04` | `2` |
| COMMAND `0x20` | `0x68` |

The SPI source traverses the real peer and RTL, yielding exactly 32 peer sample edges and four payload bytes. A real Host `irq_event=1` sample is delivered to CPU `irq`; a CPU sample sees IRQ high and acknowledges ID 11. The first accepted fetch after that acknowledgement is `0x10100`. Its direct jump reaches 64 NOPs at `0x10200`; the ISR starts at `0x10300`. The `0x1012c` vectored slot loops forever as a guard.

The ISR's first Host access is the sole RXDATA read at `0x24`. It reads actual CSR `mcause` (`0x342`), stores RXDATA, the cause and marker in persistent RAM, and executes MRET. An accepted main-loop fetch after the marker verifies return. RXDATA consumption is followed by a real Host IRQ-low sample and its bound delivery. No INTR_STATE write or synthesized IRQ clear is used. All MMIO identities name CPU origin, epoch zero, and unique transactions. No reset barrier occurs; both original and replay sessions remain at reset epoch zero.

## Timing and resource evidence

The first 600-invocation run reached CPU tick 300 and Host tick 320, with CSB still low, only 14 serial samples, and no Host IRQ. Samples occurred at Host ticks 83, 101, 119, ..., 317: 18 local Host ticks per bit with CONFIGOPTS `8`. This established that the original 600-invocation plan bound could not complete the native transfer. The plan was revised to 1,800 invocations without changing the profile, protocol, or local timing.

The passing run used 900 CPU local ticks and 924 Host local ticks: 1,800 component-step invocations and 1,824 total local ticks, including routed register service. The CPU acknowledgement was observed at CPU local tick 633 with ID 11. Each original case used 457 transactions, and materialized 652 RAM bytes. The inspected mutated bundle occupied 10,860,006 evidence bytes before replay reporting.

Per-case enforced caps are 512 transactions, 2,048 local ticks per component, 4,096 total scheduler/local ticks, 300 seconds wall time, 128 KiB materialized bytes per memory, and 64 MiB evidence. Fresh replays reuse the recorded resource contract and match the full semantic trace, local tick counts, and final memory state. Timing is component-local; these are not synchronized global clock cycles.

## Capability limits

This validates one pinned CV32E40P OBI profile and one pinned OpenTitan SPI Host TL-UL profile for this four-byte source transfer and native MEI service. It does not validate PLIC/topology, every SPI mode, arbitrary same-protocol CPUs/IP, or coverage-guided bug discovery. Harness initialization performs the declared local startup reset; testcase execution and replay preserve state without a reset barrier.
