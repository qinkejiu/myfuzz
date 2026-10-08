# Generated CVA6 + PULP I2C two M_EXT acceptance

Date: 2026-10-05

## Verified path

The testcase runs a pinned CVA6 packed AXI4 CPU and a pinned PULP I2C APB3
controller in separate generated harnesses. `DataflowRouter` routes the CPU's
real, aligned single-beat MMIO transactions through a `0x40000000` window into
the I2C harness's native APB3 register interface. The router represents the
cross-component transaction relationship; it does not instantiate a SoC bus
or a physical protocol bridge. The APB3 peripheral accepts full-word writes,
and assertions check the CVA6 64-bit beat size and 32-bit byte enable.

The sole fuzzable source is the external peer's one-byte `peer_response`.
`DependencyGraph` selects the path
`external_i2c_peer → i2c.rxdata → cpu.mmio_rdata → cpu.peer_result_ram`;
`mutate_genome` changes only that action from `0x5a` to `0xa6`. The CPU program
and all memory images are byte-identical in both genomes. The peer byte affects
the real serial RX payload and later CPU RAM value. The two completion IRQs
come from fixed CPU I2C commands and the actual I2C RTL output; the graph keeps
that event chain separate from the fuzzed data path so it does not claim the
peer payload itself causes an IRQ.

The fixed CPU program writes `PRESCALER=2`, `CTRL=0xc0`, `TX=0x85`, then
`CMD=0x90`. `TX=0x85` is the seven-bit address `0x42` with its read bit set;
the command sends START and that address byte. The address phase produces a
real slave ACK and a native I2C IRQ. The level is bound directly to CVA6
`irq_external`; `irq_timer` is fixed low. The first direct-mode M_EXT handler
records STATUS and the full 64-bit `mcause=0x800000000000000b`, issues
`CMD=1` to IACK the IRQ, records marker `0x51`, and executes MRET. The main
program observes the marker before it writes `CMD=0x68` for the one-byte
READ/NACK/STOP operation.

After the read completes, the I2C RTL raises its native IRQ again. The second
M_EXT handler reads RX, STATUS, and `mcause`, records the byte and status in
RAM, issues a second real `CMD=1` IACK, writes marker `0x52`, and executes
MRET. The resumed main program observes that marker and writes `0x66`. The test
checks that both STATUS snapshots report command completion, the first has
`STATUS[7]=0` for the address ACK, and the second has `STATUS[7]=1` for the
master NACK.

Trace assertions check the selected byte in the actual `sda_pad_i` samples at
SCL rising edges between the committed `CMD=0x68` delivery and the second
native IRQ rise. The byte must occur MSB first. The test also checks the
controller's open-drain output data remains zero, actual MMIO RDATA equals the
selected peer byte, and `PersistentMemory` contains the selected byte, both
M_EXT causes, both ISR markers, and the post-MRET marker. It checks native IRQ
levels transition `[1, 0, 1, 0]`; each IACK precedes its corresponding falling
edge, and the first falling edge precedes the later READ command.

Trace `event_id` records when ScenarioRunner appends an evidence receipt. The
ordering assertions use it for cross-transaction and observed-event
precedence; it does not claim cycle precision inside an individual APB
access. CPU and I2C still advance according to their own local clocks.

All seven routed writes and all three routed reads execute once. The ordered
MMIO acceptance identities match delivery identities, the source transaction
keys are unique, and every routed transaction is from CPU epoch zero. Each
payload has a budgeted evidence bundle that fully replays on newly constructed
CPU and I2C sessions. The original and replay sessions remain at
`reset_epoch=0`, with no testcase reset barrier.

## Execution evidence

The parallel PULP I2C session-FSM change followed a RED→GREEN focused test
cycle. Its final focused unit run reported **22 passed, 5 subtests passed**;
the second read-completion IACK is accepted only when the native IRQ is high,
and the session observes the IRQ fall within its bounded local-tick wait.

The first complete CVA6/I2C real-RTL run reached both payload subtests but
failed the expected read-sequence assertion: the first handler read STATUS,
then the shared second-handler entry read STATUS again, producing
`[STATUS, STATUS, RX, STATUS]`. This was a firmware-construction error in the
new acceptance, not an RTL failure. The handler was split before the first
STATUS read so the address ISR reads STATUS once and the read ISR reads
RX→STATUS→cause. No DUT or runtime behavior was changed for this correction.

The final focused run passed with both payloads, both full fresh-session
replays, the serial SDA/SCL byte-window assertion, ACK/NACK status checks,
two M_EXT entries, and the MRET continuation marker: **exit 0,
1 passed, 2 subtests passed in 72.12s**.

The parent agent independently reran the same frozen integration test: **exit
0, 1 passed, 2 subtests passed in 71.65s**. `git diff --check` was clean.

```bash
MYFUZZ_SCENARIO_REAL=1 \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=src \
JOBS=1 \
MYFUZZ_CVA6_PULP_I2C_CACHE=/tmp/myfuzz-cva6-pulp-i2c-cache \
pytest -q tests/integration/test_scenario_cva6_generated_pulp_i2c_two_mext_irq_real.py -vv
```

The cache stores compiled harness executables only. Each recording and replay
starts fresh harness processes and session state. The test keeps evidence
bundles in a temporary directory and removes them after replay. Its resource
budget sets 2048 MMIO transactions, 8192 local ticks per component, 12000
scheduler steps, 300000 ms, 256 KiB materialized memory, and 64 MiB evidence.

## Limits

This directed acceptance covers the pinned CVA6 profile and pinned PULP I2C
profile for one seven-bit slave at address `0x42`, one peer response byte, the
selected prescaler, and one address-completion plus one read-completion IRQ
per testcase. It does not establish other I2C modes, multiple bytes/slaves,
clock stretching, other CPU profiles, or a generalized profile-only adapter.
It does not construct a full SoC, PLIC, physical AXI-to-APB bridge, or global
cycle-accurate timing model. CPU and peripheral keep their own RTL execution
and local timing; cross-component ordering is checked from the testcase event
trace. This run found no DUT bug and is not a coverage-guided bug-search
campaign.
