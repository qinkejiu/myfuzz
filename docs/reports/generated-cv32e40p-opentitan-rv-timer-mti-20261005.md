# CV32E40P + OpenTitan RV Timer machine-timer interrupt acceptance

Date: 2026-10-05

## Scope

This directed testcase runs the pinned OpenHW CV32E40P and OpenTitan RV Timer
RTL in independent generated local harnesses. The separate MTI profile exposes
only physical `irq_i[7]` as the CPU's one-bit `machine_timer` input and holds
every other `irq_i` bit low. The existing CV32E40P MEI profile remains a
separate profile on `irq_i[11]`.

The scenario uses the existing split OBI CPU session, OpenTitan RV Timer TL-UL
session, `ScenarioRunner`, `DataflowRouter`, persistent memory, and fresh
evidence replay. The timer register values and IRQ come from real RTL. The
Timer's `irq` output is bound to the CPU's `irq` input. There is no fuzzable
CPU IRQ action, bus fabric, PLIC, protocol bridge, arbiter, or shared
cycle-accurate SoC clock.

## Program and interrupt path

The RV32 program at `0x10000` installs direct `mtvec=0x10100`, sets `mie.MTIE`
(CSR `0x304`, bit 7) and `mstatus.MIE` (CSR `0x300`, bit 3), then writes the
Timer compare low/high registers at offsets `0x118`/`0x11c`, enables
`INTR_ENABLE0` at `0x100`, and starts the counter through `CTRL` at `0x004`.
The persistent RAM region covers the program, the aligned vector and ISR, and
result words starting at `0x20000`.

Address `0x10100` contains a direct-vector jump to the ISR at `0x10200`. The
interrupt-7 vectored slot at `0x1011c` is an unconditional self-loop. The test
requires the first accepted fetch after CPU acknowledgement to be `0x10100`,
so a vectored-entry error cannot fall through to the real ISR.

The ISR reads real `INTR_STATE0` and the Timer count, reads `mcause`, and saves
them to RAM. It disables and stops the Timer, writes 1 to `INTR_STATE0` as a
W1C, reads back the cleared status, stores it, writes a completion marker, and
executes `MRET`.

## Observed result

- A real Timer `irq` sample was high at Timer local tick 178 and was delivered
  to CPU input `irq`.
- CV32E40P sampled the bound input high and acknowledged `irq_id_o=7`. The first
  accepted post-ack fetch was `0x10100`.
- CPU MMIO deliveries wrote compare `0x80`, compare high `0`, interrupt enable
  `1`, and start `1`; the ISR later disabled interrupts, stopped the counter,
  and W1C-cleared status. Real reads returned `INTR_STATE0=1`, count `155`, and
  post-W1C `INTR_STATE0=0`.
- Result RAM held status `1`, count `155` (at least compare 128),
  `mcause=0x80000007`, cleared status `0`, and completion marker `0x55`.
- CPU and Timer reset epochs remained zero, there was no reset barrier, and
  MMIO transaction identities were unique.
- Fresh CPU and Timer harnesses replayed the evidence with
  `matches=true` and `verification_scope=full`.

The evidence trace has 2,808 semantic events and local ticks CPU 250 / Timer
290. Those tick counts are local to each harness and do not define a shared
SoC cycle. The run used a 32 MiB evidence limit and wrote 2,938,670 evidence
bytes.

Evidence bundle: `/tmp/myfuzz-cv32e40p-opentitan-rv-timer-mti-pxkvah5n/evidence/`.
Its `result.json` reports `status=complete`, `event_count=2808`, and
`local_ticks={"cpu":250,"timer":290}`. `replay_report.json` reports
`matches=true`, `verification_scope=full`, and semantic SHA-256
`c6211126b40019edc98ffa51bef5cbe2ab6ca0562457c76b85a0dad9d32a35f0`.

## Verification

Profile contract command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest \
  tests.local_harness.test_cv32e40p_mtimer_profile -v
```

Result: `Ran 1 test`, `OK`. The contract checks the pinned source declaration,
single-line IRQ7 mapping, constant-low coverage for all other IRQ bits, and the
generated OBI runtime's sole functional physical IRQ export at `irq_i[7]`.

Real RTL acceptance and fresh replay command:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 \
  pytest -q tests/integration/test_scenario_cv32e40p_opentitan_rv_timer_irq_real.py
```

Result: `1 passed in 29.45s`, including the fresh CPU and Timer replay.

## Limits

This verifies one directed machine-timer interrupt path and one RV Timer
configuration. It does not cover PLIC routing, a concrete SoC bus topology,
other interrupt sources, global cycle-accurate timing, or coverage-guided bug
search. The pinned source identity is unchanged, and the CV32E40P and OpenTitan
RV Timer source-lock `runtime_status` values remain `runtime_unverified`.
