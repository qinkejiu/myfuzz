# PicoRV32 Wishbone / OpenTitan GPIO custom IRQ acceptance

## Scope and real RTL chain

The directed acceptance uses the existing
`configs/cpus/picorv32_wb_irq/component_profile.json` (`ENABLE_IRQ=1`) and
`configs/peripherals/opentitan_gpio_local/component_profile.json`. PicoRV32
Wishbone and OpenTitan GPIO TL-UL run in separate generated local harnesses.
The CPU's accepted Wishbone MMIO is delivered through `DataflowRouter` to
native GPIO TL-UL transactions. No core, session, profile, wrapper or source
lock changes were needed.

Only external `gpio_in[7:0]` is a mutable source. GPIO high 24 input bits and
strap are fixed zero. Native GPIO IRQ bit 0 binds only CPU `irq[3]`; the other
31 CPU IRQ input bits are fixed zero. The bound CPU input is rejected as a
mutation source. Firmware and result initialization images remain identical
between the two payloads.

The real CPU writes `INTR_ENABLE=1` (`0x04`),
`INTR_CTRL_EN_RISING=1` (`0x2c`), `DIRECT_OE=1` (`0x20`), then
`DIRECT_OUT=1` (`0x14`). The actual GPIO output admits the external source
action, with OE asserted in the producing sample. The acceptance verifies
that all four real MMIO deliveries precede source injection.

`DependencyGraph` / `choose_mutation` select the sole external-pin source
through the GPIO data/IRQ/result-RAM path; `mutate_genome(..., bit_index=7)`
changes `0x01` to `0x81`. Both values preserve the triggering lower pin-0
rising edge while pin 7 carries the changed payload. The acceptance checks
exact source identity/range/value, low-before/high-after GPIO input steps,
native `cio_gpio_i` receipts, exactly one actual lower pin-0 rising edge, and
the exact `DATA_IN` value returned by GPIO RTL. Mutation alone cannot satisfy
the test.

Native GPIO IRQ remains high until the ISR's real W1C write and then falls.
No `irq_pulses` policy is used. The CPU samples the bound input as `0x8` and
raises real `eoi=8`. Handler entry at `0x10`, the custom `retirq` fetch at
`0x48`, eventual `eoi=0`, and the main's subsequent accepted RAM store are
checked. The handler executes the pinned custom0 `getq` / `maskirq` /
`retirq` ABI. q1 is its pending vector; this is not `mcause`/MRET handling.

The pinned profile retains `LATCHED_IRQ=0xffffffff`. A sticky external level
can be retained as CPU pending during the handler. This one-shot firmware
performs the actual GPIO W1C and zero readback, writes its completion marker,
then executes `maskirq -1` before `retirq`, suppressing a retained repeat
without changing the real bound line. Main resumes by polling the completion
marker and storing `0x66` after return.

## Observations and replay

Each payload executes exactly five GPIO MMIO writes and three reads. Every
source transaction key has exactly one acceptance and one delivery at epoch
zero, and no reset barrier occurs. Pico's real Wishbone response consumption
matches GPIO reads `[INTR_STATE=1, DATA_IN=payload, INTR_STATE=0]` in order.
Real RAM write events and final persistent RAM contain:

| RAM address | Meaning | Source `0x01` | Source `0x81` |
|---|---|---|---|
| `0x200` | ISR GPIO INTR_STATE | `1` | `1` |
| `0x204` | ISR GPIO DATA_IN | `0x01` | `0x81` |
| `0x208` | custom q1 pending vector | `8` | `8` |
| `0x20c` | GPIO state after W1C | `0` | `0` |
| `0x210` | ISR completion marker | `0x55` | `0x55` |
| `0x214` | main after `retirq` | `0x66` | `0x66` |

The test saves an evidence bundle for each payload in its own temporary
workspace and replays each bundle with fresh CPU and GPIO sessions/process
execution IDs. Full trace comparison matches; the same causal, ownership,
MMIO, IRQ, CPU and RAM assertions are rerun on both fresh traces. This is
four actual RTL executions in the final focused test. Temporary bundles are
removed by the test when it ends.

## TDD and exact focused verification

Only this real RTL unittest module was run. The command for RED and every
GREEN run was:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real -v
```

RED wrote zero instead of one to the real `INTR_CTRL_EN_RISING` register.
Both source vectors were physically applied and passed the pin-edge checks,
then failed at the missing native GPIO IRQ assertion. Exact output from that
test version:

```text
test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) ...
  test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) (payload='0x01') ... FAIL
  test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) (payload='0x81') ... FAIL

======================================================================
FAIL: test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) (payload='0x01')
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/qinkejiu/myfuzz/tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py", line 273, in test_external_gpio_irq_custom_handler_mutation_and_fresh_replay
    self._assert_chain(trace, original, value)
  File "/home/qinkejiu/myfuzz/tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py", line 169, in _assert_chain
    self.assertIsNotNone(high, 'real GPIO IRQ never reached Pico irq[3]')
AssertionError: unexpectedly None : real GPIO IRQ never reached Pico irq[3]

======================================================================
FAIL: test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) (payload='0x81')
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/qinkejiu/myfuzz/tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py", line 273, in test_external_gpio_irq_custom_handler_mutation_and_fresh_replay
    self._assert_chain(trace, original, value)
  File "/home/qinkejiu/myfuzz/tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py", line 169, in _assert_chain
    self.assertIsNotNone(high, 'real GPIO IRQ never reached Pico irq[3]')
AssertionError: unexpectedly None : real GPIO IRQ never reached Pico irq[3]

----------------------------------------------------------------------
Ran 1 test in 21.836s

FAILED (failures=2)
```

Changing only the rising-enable store to use the CPU's register containing
one produced the first GREEN: `Ran 1 test in 24.843s`, `OK`. After adding
stricter physical-edge counting and real CPU response-consumption assertions,
the final GREEN output was:

```text
test_external_gpio_irq_custom_handler_mutation_and_fresh_replay (tests.integration.test_scenario_picorv32_wb_opentitan_gpio_irq_real.GeneratedPicoWishboneOpentitanGpioIrqRealTests.test_external_gpio_irq_custom_handler_mutation_and_fresh_replay) ... ok

----------------------------------------------------------------------
Ran 1 test in 25.263s

OK
```

RED exited 1; both GREEN runs exited 0. A separate root rerun of the final
acceptance also passed: `Ran 1 test in 24.948s`, `OK` (exit 0); its
`git diff --check` completed with no output.

## Limits

This accepts one rising-edge GPIO event, two eight-bit pin payloads, and one
custom Pico IRQ handler in the current pinned profiles. The firmware masks
IRQs after this event; repeated interrupts, nested handlers, falling/level
modes and other GPIO interrupt bits are outside the test. No SoC, bus fabric,
PLIC or global cycle timing is modeled: local harness timing and abstract
cross-protocol delivery are the tested contract. Source actions are directed
dependency-based mutation, not a coverage-guided discovery campaign. No RTL
bug was found.
