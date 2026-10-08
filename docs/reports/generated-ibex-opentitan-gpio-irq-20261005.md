# Ibex ↔ OpenTitan GPIO rising-edge IRQ acceptance

## Scope

This testcase runs the pinned Ibex OBI CPU and OpenTitan GPIO TL-UL RTL in
separate generated local harnesses. CPU MMIO transactions are routed through
`DataflowRouter`; the external pin event, native interrupt, CPU IRQ input, and
register response retain distinct ownership. The testcase does not instantiate
a bus fabric or synchronize the harnesses to a global SoC clock.

## Scenario

Ibex installs a machine external-interrupt handler and enables GPIO pin 0's
rising-edge interrupt through real writes to `INTR_ENABLE` (`0x04`) and
`INTR_CTRL_EN_RISING` (`0x2c`). It then drives the GPIO output high. That real
GPIO output observation admits the testcase's external `gpio_in[0]` rising
event. `gpio_in` is the sole fuzzable GPIO input; Ibex `irq` is bound to bit 0
of the GPIO session's native `irq` output and cannot be randomized separately.

The GPIO RTL raises its real interrupt. Ibex enters its handler, reads the true
`INTR_STATE` (`0x00`) and `DATA_IN` (`0x10`) values, stores both words to
testcase-persistent RAM at `0x20000` and `0x20004`, and writes `1` to
`INTR_STATE` to clear the interrupt through the GPIO's real W1C behavior.
The acceptance checks that the GPIO interrupt falls after that write.

The check also verifies that the native output sample producing the IRQ came
from GPIO RTL, that ISR-specific MMIO reads happen after the IRQ reaches Ibex,
that RAM equals the actual TL-UL return values, and that no testcase reset
barrier occurs. A fresh pair of CPU and GPIO harnesses replays the saved
evidence and must produce an identical trace.

## Verification

The directed integration passed with pinned RTL:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_scenario_ibex_opentitan_gpio_irq_real -v
```

Result: 1/1 passed in 36.249 seconds, including fresh-harness evidence replay.
The standalone OpenTitan GPIO real RTL tests passed 2/2, and the existing
Ibex/OpenTitan UART IRQ/ISR test passed 1/1 with replay. During a combined
parallel regression, the older CVE2/OpenTitan GPIO testcase once ended with
`environment_error` during CPU harness build (`LocalHarnessBuildError` before
any component began). A standalone rerun passed 1/1 in 30.446 seconds; the
initial build failure was not reproduced, and its cause is unconfirmed.

## Limits

This is one rising-edge interrupt scenario for GPIO pin 0. It does not exercise
all 32 interrupt bits, falling-edge or level modes, or a PLIC. GPIO pin timing
is expressed in GPIO-local ticks. The external pin transition is an environment
source; GPIO register state, IRQ, and TL-UL responses are produced by the real
OpenTitan RTL. This directed acceptance does not claim coverage-guided bug
discovery.
