# Generated CVA6 + two PULP GPIO M_EXT acceptance

Date: 2026-10-05

## Verified path

The acceptance runs three independent generated harness processes: the pinned
CVA6 packed 64-bit AXI4 CPU, PULP GPIO A, and PULP GPIO B. `DataflowRouter`
delivers CVA6's real aligned, single-beat 32-bit MMIO requests to each GPIO's
native APB3 RTL. APB3 writes use full-word byte enables (`15`). CPU AXI data
and WSTRB use the corresponding low or high 32-bit lane of the 64-bit bus;
GPIO read values and persistent RAM marker stores are checked with those lanes.

The dependency graph explicitly represents CPU instruction immediate → CPU
MMIO payload → A's persistent PADOUT state → A's real gpio_out → B's bound
gpio_in → B's real IRQ → CPU RAM. `choose_mutation` selects the sole
`memory_image` FuzzableSource, and `mutate_genome` flips immediate bit 7 from
`0x01` to `0x81`. The test checks that exactly that bit of `cpu.program`
changes, while the ISR/result images are identical and there are no source
injection actions. Bit 0 retains the rising edge; bit 7 carries the changed
payload through real RTL and into ISR RAM.

CVA6 configures direct-mode `mtvec=0x10100`, `mie.MEIE` and `mstatus.MIE`.
Before A.PADOUT is committed, CPU MMIO commits B.GPIOEN=`0xff`, B.INTEN=`1`,
B.INTTYPE_LOW=`1` and A.PADDIR=`0xff`. The pin binding transfers the observed
A.gpio_out[7:0] to B.gpio_in[7:0]; A inputs and B input bits [31:8] are fixed
zero. PADDIR is configured, but does not gate the abstract gpio_out binding.
B's GPIOEN enables the synchronizer in four-pin groups. The acceptance checks
both `gpio_in_sync` (the RTL's sync1 stage) and the CPU's real PADIN read
(the RTL's r_gpio_in stage).

B's native `interrupt` output is a pulse lasting one B local tick. The existing
runner `irq_pulses` policy maps its observed rising edge to a finite four-CVA6-
tick `irq_external` pulse beginning at the next CPU tick. The test checks the
native source start/end and real per-tick interrupt observation, the policy's
start/end ticks and expiry, and exactly four runner-presented CPU input ticks
at one followed by zero. This extension is harness policy; it is not a held IRQ in PULP RTL.
CVA6 `irq_timer` remains zero.

The test observes the real CVA6 AXI read of the ISR instruction line. The ISR
reads B.INTSTATUS=`1`, B.PADIN=`0x01` or `0x81`, and the real 64-bit CSR
`mcause=0x800000000000000b` (machine-external cause 11). INTSTATUS at `0x24`
is read-to-clear at this pinned PULP revision; the second CPU read returns zero.
The ISR records those values in persistent RAM, writes completion marker
`0x55`, and executes MRET. The resumed main program observes the marker and
writes `0x66`; the acceptance verifies the upper 32-bit AXI lane for the ISR
marker and the lower lane for the resumed marker, and their event order.

All routed MMIO acceptance identities equal the delivery identities in order,
with unique source transaction keys and epoch zero. Both payload scenarios
complete with all three sessions at reset_epoch=0 and no reset barrier. Each
scenario saves a budgeted evidence bundle and fully replays it in new CPU/A/B
sessions; trace/state comparison matches and all six RAM fields are identical.

## Execution evidence

The test was written before completing its firmware stimulus. The RED run
omitted the CPU PADOUT store; both payload subtests failed at the expected
assertion `CPU did not commit the real A PADOUT store`. The result was exit 1,
`2 failed, 1 passed in 93.31s` (pytest's unittest/subtest summary). Adding the
real CPU store produced GREEN: exit 0, `1 passed, 2 subtests passed in 55.21s`. An independent final rerun also passed: `1 passed, 2 subtests passed in 55.07s`.
The passing run covers both payloads and both complete fresh-session replays.
No core, router, session or source profile implementation changes were needed.

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 \
MYFUZZ_CVA6_PULP_GPIO_CACHE=/tmp/myfuzz-cva6-pulp-chain-cache \
pytest -q tests/integration/test_scenario_cva6_generated_two_pulp_gpio_mext_irq_real.py
```

The optional cache only reuses compiled harness executables; every recording
and replay starts new process/session state. Omitting the cache variable uses
the test's temporary cache. Evidence bundles are generated in a temporary test
directory, replayed, and removed on test exit; the command regenerates them.
The test has 3000 maximum runner steps per genome. Its ResourceBudget sets
2048 transactions, 8192 local cycles per component, 12000 scheduler steps,
300000 ms, 0x40000 materialized RAM bytes and 64 MiB evidence.

## Limits

This is a directed acceptance for the current pinned CVA6 profile and PULP
GPIO `PAD_NUM=32`, `NBIT_PADCFG=4`, `APB_ADDR_WIDTH=12`, with only pin 0 IRQ
enabled. It does not verify other configurations, other edges, repeated IRQs,
other CPU interrupt classes, PLIC, a full SoC or a physical protocol bridge.
The independent RTL sessions have their own local clocks; the runner's event
ordering and finite pulse extension do not establish global cycle timing or
electrical pad behavior. This acceptance makes no RTL bug-found or
coverage-guided fuzzing campaign claim.
