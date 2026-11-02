# PicoRV32 AXI4-Lite CPU + the APB3 I2C MMIO target (config-driven, native-verified)

This descriptor drives the *fourth* generic CPU protocol, AXI4-Lite, through the
existing config-driven runtime. Nothing about the target changed: the request,
capability and supplement of the PULP APB3 I2C device are shared verbatim from
`compiled-f2-f4-obi-apb-i2c-ibex`, and the CPU's own request is the pinned
`configs/cpus/picorv32_axi/component_profile.json`.

* CPU: `picorv32_axi` (real RTL in `third_party/picorv32_upstream_reference`),
  instance `cpu`, unified `processor.memory` endpoint, `axi4-lite@1`,
  template `cpu.axi4-lite/1/no-response-code`, 32-bit address/data, four-lane
  `wstrb`, no `bresp`/`rresp` pins, `ENABLE_PCPI=0`, `ENABLE_IRQ=0`.
* Target: PULP APB3 I2C, instance `peripheral`, `i2c.bus`, window
  `0x40001000..0x40001FFF`, register `PRESCALER` (offset 0, low 16 bits).
* Memory: RAM `0x00000000..0x0000FFFF`, preloaded, read/write/execute; the CPU
  boots at its configured base `0x00000000`.

## What is really supported today

| step | state |
| --- | --- |
| D2 harness generation (CPU + target) | **works** |
| D3 compiled execution files | **works**: `F1`, `F2`, `F3`, `F4` paths are `executable`; `F5`/`F6` are `unsupported` because the pinned CPU declares no `interrupt_entry` endpoint and no component declares a DMA/`transfer` provider |
| typed admission of both artifacts | **works**: CPU verifier `axi4-lite.cpu.admission.v1`, endpoint `cpu.axi4-lite.v1`, `completion_kind=independent_channels_response` |
| registry selection | **works**: `axi4-lite.cpu.v1` is selected from the admitted descriptor alone |
| adapter binding to the real session | **works**: `GeneratedAxiLiteMemorySession` carries the bound adapter; the pinned harness builds (10.4 s, 300 MB) and reaches its ready handshake |
| CPU protocol observation | **works**: 17 per-tick positional pin taps `cpu_axil_trace_<role>` plus an explicit `fetch_observation` (`arprot[2]`, qualified by `arvalid`/`arready`), authenticated by `integration/axil_cpu_protocol_observations.py` |
| witness reader (`first_fetch` / `completed_beats`) | **works**: `integration/axil_cpu_protocol_observations.collect_axi4lite_cpu_fetches` / `collect_axi4lite_cpu_beats` project the sampled `AR`/`AW`/`W`/`R`/`B` pins of the authenticated trace into real CPU beats and the instruction-fetch witness |
| generic plan compile (`F2`/`F4`) | **works**: both flows are `supported` / `execution_supported=1` with the protocol-neutral `compiled_mmio` executor |
| native F2/F4 original + fresh gate | **works**: the acceptance sequence runs, the APB3 I2C `PRESCALER` read values are `85/85/170/170`, and the fresh replay reports `matches=true` |

The `compiled_mmio` executor joins every MMIO beat to a *native CPU-protocol*
observation (`integration/mmio_cpu_adapter.select_mmio_cpu`). The AXI4-Lite row
authenticates the harness' per-tick pin trace and then projects it; nothing about
the witness is assumed. Two declared protocol facts are load-bearing and are
recorded in the bundle of every case (`exact_hops.read_transfer`):

1. **Read data granularity.** AXI4-Lite has no read strobe, so a read transfers
   the whole addressed word; the pinned PicoRV32 drives `wstrb = 0` there because
   it asserts `ARVALID` only while `mem_wstrb == 0` (`picorv32.v:2777`). The
   routed request therefore presents the declared four-lane access
   (`be=15`) while the *sampled* strobe stays 0 in
   `driver_samples[*].pre.protocol_taps` and in the CPU beat's `byte_enable`.
   A write always presents the sampled `wstrb`. The single machine-readable
   statement is `local_harness/axi_lite_session.READ_TRANSFER_DECLARATION`
   ("read transfers the whole addressed word; the sampled wstrb is 0 because
   AXI4-Lite has no read strobe"), referenced by the session, the reader and the
   `byte_enable` capability limit of the certified surface. It is a protocol
   semantic, never an instance special case, and the shared exact-hop joins of
   the OBI/Wishbone/AHB rows are unchanged.
2. **Instruction-fetch identity.** The generated executor accepts and ignores
   `ARPROT`, so the fetch flag exists only on the sampled `arprot[2]` tap. The
   session uses the *declared* trace bit for online instruction slots and parks a
   fetch whose declared word is not materialised yet; a data read that reaches an
   unfilled slot is still a named error.

## What this CPU can and cannot support

Supported, and observed by the bound session: 32-bit MMIO/data read and write
beats on the unified `processor.memory` endpoint, RAM read/write through the
persistent memory service, MMIO queued at the CPU and drained at the declared
target window with the target's own response as the beat's read data (one target
access per local step), four-lane write strobes, per-tick sampled AXI4-Lite
master pins including the `ARPROT` protection sideband that carries the fetch
flag, the projected `first_fetch`/`completed_beats` witness, and online
instruction slots driven by that declared fetch flag.

Not supported, and stated as such in the certified surface:
instruction retirement (`ENABLE_TRACE=0`, no RVFI), native IRQ (`ENABLE_IRQ=0`,
`irq` held at its inactive value), an error response (no `BRESP`/`RRESP` pin, so
a target error is invisible to this CPU), storage-version authority, and F5/F6.
The artifact still exports no physical `instruction_identity_observation`; the
fetch identity is the declared protocol-trace bit, not a hardware port.

## Commands

Preparation/preflight (chosen generated directory must be new):

```sh
PYTHONPATH=src:. MYFUZZ_BUILD_JOBS=4 \
  python3 runs/axil-picorv32-config-only-20261029/prepare_compile.py runN
PYTHONPATH=src:. MYFUZZ_BUILD_JOBS=4 \
  python3 runs/axil-picorv32-config-only-20261029/bind_real_session.py sessionN
```

Search preflight is accepted (record-catalog backend) even though the campaign
executor refuses:

```sh
PYTHONPATH=src:. python3 scripts/run_dependency_search.py \
  --scenario configs/search/i2c-picorv32-axil.json --preflight
```

The native gate (verified: original `28.0 s` / `291 MB`, fresh `25.1 s` /
`281 MB`, both exit 0, identical plan identity across the two invocations, the
fresh replay reports `matches=true` and the `PRESCALER` read values are
`85/85/170/170`) is:

```sh
PYTHONPATH=src:. python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/generic_scenario.json \
  --flow mixed --mode original --case NEW_OUTPUT --cache CACHE \
  --records-file configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/acceptance_sequence.json \
  --record-local-commands
PYTHONPATH=src:. python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/generic_scenario.json \
  --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE \
  --records-file configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/acceptance_sequence.json
```

`F2:00100040` is the little-endian byte address `0x40001000` (the register this
plan reads); `F4` records are the 32-bit values written to it. Do not put
executable bytes in the I2C window. Running both modes into the *same* case root
(two separate CLI invocations) keeps the recorded absolute wiring path equal, so
the two invocations also agree on the D3 digest and the plan identity; running
them into two different case roots changes only that absolute path.
