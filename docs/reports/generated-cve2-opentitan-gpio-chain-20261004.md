# Generated CVE2 and OpenTitan GPIO data chain (2026-10-04)

The acceptance case in `tests/integration/test_scenario_cve2_opentitan_gpio_generated_real.py`
runs a generated CVE2 OBI harness and a generated OpenTitan GPIO TL-UL harness
as separate persistent RTL processes. The router maps accepted CPU MMIO beats
to the GPIO's real register interface. There is no RTL bus, bridge, arbiter,
or global cycle alignment between them.

The CPU executes a fixed program from persistent RAM. Its real stores enable
GPIO rising interrupts and configure `DIRECT_OUT=0xA5` and `DIRECT_OE=0xFF`.
Its later real read of `DIRECT_OUT` returns the GPIO RTL value, which the CPU
stores at RAM `0x20000`. The scenario's only mutable pin action occurs after
the GPIO has actually reported `gpio_out & 0xFF == 0xA5`; the GPIO sees the
external rise, updates its real `INTR_STATE`, and a subsequent CPU load returns
that value. The CPU stores bit 0 at RAM `0x20004`.

The test asserts both RAM values (`0xA5` and IRQ-state bit 0), the real TL-UL
MMIO delivery, a recorded Fuzzable Source injection, and a full evidence
bundle replay from fresh RTL. CPU interrupt input is fixed at zero here: the
test proves CPU readback of GPIO interrupt state, not CPU interrupt entry.
OpenTitan GPIO alert acknowledgement and RACL policy behavior remain outside
this test's claim.

Run with:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_gpio_generated_real -q
```
