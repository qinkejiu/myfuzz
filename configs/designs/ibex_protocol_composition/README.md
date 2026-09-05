# Ibex Protocol Composition Fixture

This fixture describes one deterministic `ibex_core` composition using the
local lightweight peripherals and the runtime APB4, AXI4-Lite, and TileLink-UL
adapter families. It is an input to the protocol-composition generator; it
does not replace the existing `ibex_multicomponent_ip` design.

## Declared target

- CPU: `ibex_core`, RV32, 32-bit address and data paths.
- Components: one RAM, timer, GPIO, UART, and SPI.
- Protocols: RAM uses TileLink-UL; timer and GPIO use APB4; UART and SPI use
  AXI4-Lite.
- IRQs: timer `1`, GPIO `2`, UART `3`, and SPI `4`. RAM has no IRQ.

The address map is fixed and non-overlapping:

| Component | Base | Size | Protocol |
| --- | ---: | ---: | --- |
| RAM | `0x00000000` | `0x00010000` | TL-UL 1 |
| Timer | `0x80010000` | `0x00001000` | APB4 |
| GPIO | `0x80020000` | `0x00001000` | APB4 |
| UART | `0x80030000` | `0x00001000` | AXI4-Lite 1 |
| SPI | `0x80040000` | `0x00001000` | AXI4-Lite 1 |

The default campaign seed is `7`, with a one-hour duration and checkpoints
every 30 seconds. The campaign runner should keep its worker resource limits
explicit and conservative because other processes share the host.

## Local validation

Run the checker from the repository root:

```bash
python3 configs/designs/ibex_protocol_composition/scripts/check_local.py
```

The checker validates the manifest, address/IRQ invariants, and all local
component and protocol-adapter sources. The real Ibex checkout is intentionally
not vendored in this repository. When it is absent, the checker prints
`dependency-unavailable: third_party/rfuzz/upstream/ibex` and exits with status
`2`; this is an explicit dependency result, not a successful RTL compilation.
With the upstream checkout and its `sources.f` available, the same checker
returns status `0` after the local checks pass.

The checker does not start RFuzz, Verilator, or a long-running campaign.
