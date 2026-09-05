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

## Campaign entrypoint

The campaign configuration is
`configs/designs/ibex_protocol_composition/campaign.json`. It deliberately
uses one build job, one RFuzz worker, no VCD or waveform output, a 512 MiB
soft RSS limit, a 768 MiB hard RSS limit, and a 64 MiB token budget. The
default duration is 3600 seconds, with seed `7` and 30-second checkpoints.

Before an hour-long run, use an explicit 10–60 second real-target run on a
machine that has the Ibex checkout and its source list:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py \
  --config configs/designs/ibex_protocol_composition/campaign.json \
  --duration-seconds 10 \
  --seed 7 \
  --output-dir runs/ibex_protocol_campaign_short
```

The same command with `--duration-seconds 3600` is the default long-run form.
The controller refuses to spawn the real design flow when
`third_party/rfuzz/upstream/ibex/sources.f` is absent and returns the explicit
status `dependency-unavailable`. That status is not a compile or fuzz result.

When the upstream dependency is unavailable, local accounting can still be
checked under the same RSS and process-group supervisor:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py \
  --config configs/designs/ibex_protocol_composition/campaign.json \
  --local-smoke \
  --duration-seconds 10 \
  --seed 7 \
  --output-dir runs/ibex_protocol_campaign_smoke
```

The local producer emits bounded JSON lines for TL-UL/RAM, APB/timer,
APB/GPIO, AXI4-Lite/UART, and AXI4-Lite/SPI, plus one deterministic coverage
point. It is accounting evidence only and explicitly does not claim RTL
compilation.

Each completed run atomically publishes `checkpoint.json` and `report.json`.
The report fields are `schema_version`, `status`, `composition_hash`, `seed`,
`duration_seconds`, `configured_duration_seconds`, `iterations`,
`throughput_iterations_per_second`, `transactions`, `protocol_transactions`,
`component_transactions`, `coverage`, `errors`, `peak_rss_bytes`,
`checkpoint_count`, `last_output_line`, `replay_command`, and `limits`, with
campaign metadata fields `upstream_dependency`, `execution`, and (for local
smoke) `evidence`. A crashed run also records the replay command.
