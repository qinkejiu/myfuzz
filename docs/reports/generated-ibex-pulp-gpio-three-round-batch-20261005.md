# Ibex and two generated PULP GPIOs: three rounds in one testcase

Date: 2026-10-05

## What this demonstrates

One `ScenarioGenome` runs Ibex and two PULP GPIO RTL instances in three
external-event rounds. The CPU, peripherals, router and RAM keep one continuous
testcase lifetime. The testcase performs no reset between the rounds. B's real
IRQ pulses enter the existing bounded IRQ-delivery policy; every PADIN response,
GPIO A output, RAM write and memory dependency comes from the running RTL and
scenario runtime.

The source sequence is `0x49 → 0x81 → 0xff`. Each value is driven on PULP GPIO
B external pins 15:8, read by the real Ibex ISR, copied to GPIO A through a CPU
MMIO write, and stored at RAM address `0x20000`. Each real store overwrites the
prior word. The trace records all three write values and their persistent
state dependency. The final RAM word is `0xff`.

## Causal scheduling

The first rise becomes eligible after Ibex accepts its GPIO A setup transaction.
The first falling input is released only after Ibex consumes the real response
for its first PADIN read. A second rise is then delayed by 64 **CPU local ticks**
from that same observed response, which leaves the source pin low while the
first ISR completes. The second falling input is released after the real second
PADIN response; the third rise follows after another 64 CPU local ticks.

This boundary matters for the PULP GPIO implementation: its interrupt output is
a short pulse generated from a synchronized edge. Lowering the input as soon as
that pulse appeared changed PADIN before the CPU read it, and delivering the next
edge before the current ISR returned lost the expected CPU-side result. The
accepted schedule waits on an observed CPU response and uses a local delay before
the next external edge. It does not synthesize the IRQ or the response value.

The three independent local clocks still advance under the declared
`cpu → gpio_b → gpio_a` schedule. No shared SoC cycle or bus interconnect is
introduced.

## Acceptance evidence

The test requires:

- all five source actions fire in order: `first-rise`, `first-fall`,
  `second-rise`, `second-fall`, `third-rise`;
- three observed GPIO B IRQ source starts and three bounded CPU IRQ pulses,
  with no overrun;
- real CPU RAM stores at `0x20000` with values `0x49`, `0x81`, then `0xff`;
- the GPIO A output changes through the same three values;
- a persistent write-after-write dependency exists for the repeated RAM word;
- exactly one runtime is created for recording, followed by one fresh runtime for
  replay; replay matches the full event trace.

The sequence is one pre-encoded Genome containing ordered causal actions. This
proves state continuation and complete replay within a long testcase. It does
not prove that the live RFuzz executor can accept new independent mutation slots
online while keeping one RTL process alive; that requires a separate admission
and replay-log interface.

## Verification

```sh
PYTHONPATH=src:. MYFUZZ_SCENARIO_REAL=1 \
MYFUZZ_IBEX_GPIO_CACHE=/tmp/myfuzz-ibex-obi-build \
python3 -m unittest \
  tests.integration.test_scenario_ibex_pulp_gpio_reverse_generated_real.\
ReverseGeneratedIbexPulpGpioTests.test_three_external_phases_share_one_rtl_lifetime_and_replay -v
```

Result: 1/1 real integration test passed in 21.887 seconds. The command reused
authenticated Verilator build artifacts. It records and then replays the
900-step local schedule; each generated RTL process is constructed once per
record or replay, not once per event round.
