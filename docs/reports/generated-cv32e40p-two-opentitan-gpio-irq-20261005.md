# CV32E40P + two OpenTitan GPIO RTL IRQ acceptance

Date: 2026-10-05.

## Scope

This directed testcase runs one pinned OpenHW CV32E40P RTL and two pinned
OpenTitan GPIO RTL instances in three independent generated local harnesses.
It validates the dataflow and interrupt chain

```text
CV32E40P MMIO writes
  → OpenTitan GPIO A real output and output-enable
  → bound GPIO B input
  → OpenTitan GPIO B real level interrupt
  → bound CV32E40P external interrupt input (irq_i[11])
  → real CV32E40P ISR and GPIO reads
  → persistent RAM observations and GPIO W1C
```

The harnesses preserve each DUT's native interface, local protocol, and local
execution. The test does not instantiate a SoC, interconnect, PLIC, protocol
bridge, arbiter, or global cycle-accurate clock.

## Pinned components and bindings

- CPU RTL: OpenHW `external_designs/cv32e40p`, revision
  `6033d2b1be3295ec774d17ac4cf226faacfdeb08`, with the generated local `obi_cpu`
  runtime and `GeneratedCve2Session`.
- GPIO RTL: OpenTitan source-lock entry `opentitan_gpio`, revision
  `fca045df919a26c47e71616b9dac917b1ea4fd07`, with the generated
  `tlul_gpio` runtime and two `GeneratedOpentitanGpioSession` instances.
- Router windows: GPIO A at `0x40000000` and GPIO B at `0x40001000`, each
  `0x80` bytes. CPU OBI MMIO transactions are delivered through the scenario
  Router; no RTL bus fabric is constructed.
- GPIO A `gpio_out[0]` is bound to GPIO B `gpio_in[0]`. GPIO B's other input
  bits and both strap inputs are fixed low. GPIO A output enable is not
  resolved by the binding layer, so the test also requires the same real
  `local_tick_sample` that produces `gpio_out[0]=1` to show `gpio_dir[0]=1`.
- GPIO B's level `irq[0]` is bound to the CPU's one-bit `irq` alias. The CV32
  profile maps that alias to physical `irq_i[11]`; other interrupt bits remain
  profile constants. The scenario uses a normal level binding, not an IRQ
  pulse policy.

## Real execution and checks

The CPU program sets `mtvec=0x10100`, enables `mie.MEIE=0x800` and
`mstatus.MIE=8`, then uses real MMIO writes to configure GPIO B's
`INTR_ENABLE[0]` (`0x04`) and rising-edge enable (`0x2c`). It writes GPIO A
`DIRECT_OUT[0]` (`0x14`) low, enables `DIRECT_OE[0]` (`0x20`), then writes the
output high. These are CPU transactions, not fuzzed replacements for the
transactions.

The assertions trace the GPIO A-to-B delivery back to the producing GPIO A
real sample and require both the output and output-enable bits to be high. They
trace the asserted GPIO B IRQ delivery back to a GPIO B `local_tick_sample`
with the real `interrupt` output high. One CPU sample must simultaneously show
bound `irq=1`, `irq_ack_o=1`, and `irq_id_o=11`.

The machine external ISR reads GPIO B `INTR_STATE` (`0x00`) and `DATA_IN`
(`0x10`), stores the actual values at RAM `0x20000` and `0x20004`, writes 1 to
`INTR_STATE` as a real W1C, and executes `MRET`. Both RAM words equal 1. The
event log establishes the causal order from GPIO IRQ producer and delivery,
through CPU acknowledgement and ISR reads, to W1C and the subsequent real IRQ
deassertion. Event IDs are used only for trace admission/order; they do not
represent a shared SoC cycle.

The testcase also asserts unique CPU MMIO transaction identities, reset epoch
0 for every original session, and no reset barrier. It writes an evidence
bundle, creates fresh harnesses, and requires `replay_evidence_bundle` to match
the trace and reproduce the ISR RAM values. The evidence bundle lives in the
test's temporary directory and is removed when the test exits.

## Verification

Artifact generation without RTL compilation succeeded for one CV32E40P and
two OpenTitan GPIO runtime artifacts. The real integration command was:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 \
  pytest -q tests/integration/test_scenario_cv32e40p_two_opentitan_gpio_irq_real.py
```

Result: `1 passed in 21.58s`, including the saved-evidence fresh replay.
`python3 -m py_compile` also passed for the integration test.

The first real attempt exposed a test firmware construction error: a single
`LUI` set `mtvec` to `0x10000`, omitting the ISR address's low `0x100`. The
fixture now uses `LUI` plus `ADDI` to set the exact `0x10100` address. This was
a testcase bug, not a DUT or harness failure.

## Limits

This proves one directed rising-edge scenario and one CV32E40P/OpenTitan GPIO
configuration. It does not prove all GPIO edge/level modes, pins, interrupt
combinations, other CPUs, PLIC behavior, or a concrete SoC topology. The
GPIO-to-GPIO connection binds the real `gpio_out` signal and separately checks
`gpio_dir`; it does not model pad electrical behavior. This is not evidence of
coverage-guided bug discovery. The OpenTitan source-lock `runtime_status`
remains `runtime_unverified`; this report records a local generated-harness
integration result, not a source-lock/SoC runtime promotion.
