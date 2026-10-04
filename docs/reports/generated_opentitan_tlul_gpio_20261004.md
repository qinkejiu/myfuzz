# Generated OpenTitan TL-UL GPIO evidence (2026-10-04)

## Source and accepted boundary

The real OpenTitan Earlgrey GPIO is pinned at `third_party/soc-opentitan`
`fca045df919a26c47e71616b9dac917b1ea4fd07`. The upstream source lock
record `opentitan_gpio` authenticates the selected GPIO elaboration closure.
The upstream component profile describes the GPIO RTL's packed TL-UL ports but
uses `top_port_selection=declared`: aggregate alert and RACL top ports are
outside that boundary, so it cannot enter the generated local harness directly.

`soc_opentitan_gpio_local_target.sv` is a small, hash-pinned local wrapper.
It connects the real `gpio` instance and exposes all 30 wrapper ports as
scalar or packed vectors. The generated profile has `top_port_selection=all`,
and planning, binding, and rendering cover all 30 ports. The wrapper drives
`alert_rx_i[0]` with `prim_alert_pkg::ALERT_RX_DEFAULT` and `racl_policies_i`
with `top_racl_pkg::RACL_POLICY_VEC_DEFAULT`. It exposes `alert_tx_o[1:0]`
and `racl_error_o[36:0]` for passive observation, along with the 33-bit
sampled straps, all 32 GPIO input/output/enable bits, and all 32 real IRQ bits.
The GPIO instance uses its pinned source defaults, including `EnableRacl=0`,
`GpioAsHwStrapsEn=1`, and `AlertSkewCycles=1`; the local profile permits no
runtime parameter overrides.

The local profile pins the full source union at
`sha256:05655bc876b9a2ee767c0fb482b6cc10353de98302349b145708d4576c632a35`.
The wrapper SHA-256 is
`8046bc87b17a50e4bc5e6effb1c7d3bd8a588a9099b0ca7d28e07ed231101443`.
The specialized source gate checks the upstream lock and closure, exact local
and upstream profile bytes, exact declared files and include roots, union
content hash, and wrapper bytes. The build materializes the wrapper and both
profile files with those hashes. This avoids a self-referential pin to this
repository's moving Git HEAD.

## Runtime behavior

The generated top wires every TL-UL A/D field through `beat_to_tlul`, with
command/data integrity enabled, one source ID, one outstanding transaction,
and a 128-byte decoded register window. The generated C++ driver records
physical A/D observations and uses a persistent process for the whole case.
The session accepts GPIO and strap inputs, reads and writes real registers,
and returns GPIO output, output enable, 32-bit IRQ, alert, RACL, and strap
observations. Startup register writes are declared in the session identity and
checked by the formal manifest contract.

## Acceptance result

`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest
tests.integration.test_local_opentitan_gpio_generated_real -v` passed 2 tests
after rebase. The first test wrote `DIRECT_OUT` at `0x14`, read it back over
TL-UL, wrote `DIRECT_OE` at `0x20`, observed the pads, enabled pad 0 rising
interrupt, observed the real IRQ rise after the input transition, read
`INTR_STATE`, and cleared it by W1C. The second test validated the strict
generated manifest against the JSON schema, saved an evidence bundle for a
persistent pin transition with startup MMIO writes, observed IRQ in its trace,
and matched a fresh RTL replay of the complete bundle.

The target's register byte permits are address specific. `GPIO_PERMIT[5]` in
`gpio_reg_pkg.sv` requires all four byte lanes for `DIRECT_OUT`; a partial
TL-UL write there returned `d_error=1` and left the register unchanged.
`GPIO_PERMIT[3]` permits lane 0 for `ALERT_TEST`; a partial write there
succeeded and drove the exposed differential alert TX from quiet `2'b01`
to asserted `2'b10`. The session preserves the target's response instead of
promising partial writes at every register.

This target proves the first generated TL-UL peripheral and its GPIO/IRQ
behavior. It does not claim a general TL-UL peripheral generator, alert
acknowledgement peer, enabled RACL policy behavior, or other OpenTitan IPs.
