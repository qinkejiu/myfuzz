# Generic TL-UL physical Bound Input acceptance

The `local_harness.v2` TL-UL register-observe template accepts a `bound_bindings`
entry for a physical `external_pins` input. Each entry declares
`endpoint_id`, `role`, and `producer_ref` in `component.physical_output` form.
The generated artifact records the exact field width, physical runtime signal,
and producer identity. A field has exactly one owner: `fixed_inputs`,
`environment_bindings`, or `bound_bindings`. Overlap and missing ownership fail
at planning.

`ScenarioRunner` checks the target's `InputOwner(kind='bound')`, producer
identity, and one whole-field `Binding` from a registered source component.
For a generic TL-UL source it also checks that the source port is a real
physical output and that the routed bit range fits its width. An `Action`
cannot mutate a bound field. The generic session's ordinary `step_local`
rejects it. During runner execution, real output observations are retained in
scenario input state and sent through the separate `BIND_TLUL_REG` command.
`SOURCE_TLUL_REG` indexes only declared environment fields, so it cannot
address a bound field. An unchanged bound value is held across steps, and the
testcase reset barrier clears it to the declared initial zero policy.

The driver preserves local TL-UL handshakes and the real RTL pin response.
The runner routes each pre/post local tick observation using the generic
session's physical output names. This permits a true pin path without
connecting the two RTL modules as a synthesized SoC.

Acceptance exercised two independent generated OpenTitan GPIO sessions:

```text
GPIO A TL-UL register writes → real cio_gpio_o = 1
→ ScenarioRunner dataflow delivery → GPIO B gpio.pins.in = 1
→ real GPIO B interrupt output, held input across later steps
→ fresh-process evidence replay matches
```

The focused bound-input and existing dynamic-source checks passed 6/6. The
existing generic TL-UL dynamic GPIO, RV Timer, GPIO and SPI Device checks
passed 9/9 with real RTL enabled. This scope proves whole-field physical pin
bindings on the admitted TL-UL register-observe template. It does not admit
arbitrary protocols, partial-field binding, or automatic SoC topology.
