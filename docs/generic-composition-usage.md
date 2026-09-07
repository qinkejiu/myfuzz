# Generic source-annotated composition

Task8 adds a small, CPU-name-independent analysis/publication smoke. Its
input is a semantic interface description plus a pinned local source tree;
HDL analysis supplies the physical facts that the input intentionally omits.
The smoke does not run a CPU, RFuzz, or a long campaign.

## Minimal input

```json
{
  "schema_version": "interface_description.v1",
  "source": {
    "root": "source",
    "revision": "sha256:<64-hex-source-tree-digest>",
    "top_module": "synthetic_cpu",
    "files": ["rtl/synthetic_cpu.sv"]
  },
  "endpoints": [{
    "endpoint_id": "cpu.mmio",
    "function": "memory_master",
    "module": "synthetic_cpu",
    "protocol": ["bounded-mmio", "1"],
    "fields": [
      {"role": "clock", "aliases": ["clk_x"]},
      {"role": "reset", "aliases": ["rst_x"]},
      {"role": "addr", "aliases": ["q_addr"]},
      {"role": "valid", "aliases": ["q_valid"]},
      {"role": "ready", "aliases": ["q_ready"]},
      {"role": "wdata", "aliases": ["q_wdata"]},
      {"role": "rdata", "aliases": ["q_rdata"]},
      {"role": "error", "aliases": ["q_error"]}
    ]
  }]
}
```

`direction`, `width`, signedness, and timing are not trusted from this
document. `SourceCrawler` reads the declared HDL and records each module,
port, direction, width, source location, clock/reset membership, sequential
assignment, and observable handshake evidence. A missing or ambiguous
required field is an error.

The caller can pass this typed description to
`myfuzz.composition.GenericCompositionRequest` and select component profiles
and protocol plugins by their declared capabilities. CPU names are not used
to choose an adapter or a renderer. The generated IR records annotations,
capabilities, endpoint matches, protocol contract, address regions, IRQ
routes, source evidence, and the generated input layout. Publication emits:

* `composition_ir.json`;
* `input_layout.json`;
* `rfuzz_input_transport.json` and `rfuzz_input_transport.sv`;
* `generic_composition_top.sv`; and
* `sources.f`.

`write_generic_composition` re-crawls the pinned source before publication,
checks the address map, and uses an atomic staging directory. If Verilator is
installed, it performs a bounded `--lint-only` check before publishing.

### RFuzz transport boundary

The transport sidecar is derived from the same validated `InputLayout`, not a
CPU name or the legacy 395-bit constant. It provides one cycle's byte packing:
`ceil(raw_width / 64) * 8` bytes, MSB-first payload with trailing ignored
padding. Python `build_rfuzz_transport(layout).pack(raw_bits)` and
`.unpack(record)` follow the emitted combinational RTL. Canonical encoders
zero padding; random fuzzer changes to padding do not change the DUT input.
The JSON binds this interpretation to `layout_hash` and `transport_hash`.

The sidecar is **not** instantiated by `generic_composition_top.sv` or added
to its `sources.f`: it is a reusable byte-to-raw-bits boundary for a future
RFuzz harness. It does not yet wire field projection into a DUT, generate a
coverage server, or run RFuzz. Protocol sequencing and RISC-V instruction
legality remain separate obligations; packing a record does not make its
instructions or transaction history legal.

See [pinned upstream boundary probe](reports/upstream_boundary_probe_20260907.md)
for source revisions, transport evidence and real-core integration gaps.

## Local synthetic smoke

The focused test contains a complete source-backed fixture with one synthetic
CPU and five peripherals: RAM, UART, GPIO, CLINT, and PLIC. It uses a strict
single-channel `valid/ready/error` protocol plugin and deliberately gives each
endpoint an explicit semantic protocol declaration. This is a fixture for
generic analysis and generated-top validation, not an Ibex, CVA6, or BOOM
implementation.

Run it with one low-priority Python process:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 \
  nice -n 15 python3 -m unittest \
  tests.integration.test_low_resource_generic_smoke -v
```

The test also proves fail-closed behavior for a missing source, ambiguous
endpoint, invalid protocol feature declaration, overlapping address regions,
and a dependency cycle. None of those cases may publish output artifacts.

## Protocol and CPU boundary

The generic renderer materializes APB3, APB4, Wishbone Classic, AXI4-Lite and the
declared bounded single-channel contract used by the synthetic fixture.
Native routes preserve APB setup/access and Wishbone CYC/STB/ACK/ERR behavior;
clocked tests cover waiting, errors, timeout and aborted requests. Shared
physical clock/reset ports are reused across endpoints.

Native routing currently requires one source endpoint per target, the same
protocol and width, and a supported error response. It does not provide a
shared-bus multi-target interconnect, clock-domain crossing, Wishbone pipelining,
full AXI4 burst/ID routing or OBI routing. AXI4 and OBI standalone MMIO bridges
have separate directed RTL tests. The older Ibex composition path supports
APB4, AXI4-Lite and TL-UL; its availability does not establish support in the
new generic path.

The native AXI4-Lite route accepts AW and W in either order and decodes AW/AR
addresses independently. It uses one outstanding slot total, gives writes
priority on simultaneous arbitration, and retains responses under source
backpressure. Unmapped addresses receive local DECERR without a target
request. The strictest catalog wait bound applies to the downstream transaction
after request assertion, not to collecting the source's missing write channel
or waiting for source response READY. A timeout returns SLVERR and quarantines
the route until the shared reset: pending target VALID/payload remain until
their handshakes or reset; late responses cannot become new responses.
This does not add AXI4-to-Lite conversion or make CVA6 executable.

The CVA6 and BOOM profiles are source-annotated/reference integration data in
this branch; the local Task8 fixture does not execute either real core. A
real-core result requires its pinned RTL source and a connected simulator or
RFuzz flow.

## Low-resource policy semantics

`ResourceProfile` and `apply_resource_profile` constrain planner configuration
values: one build slot, one frontend slot, bounded queues, no waveforms, and
bounded soft/hard memory ceilings. `run_generic_composition_smoke` returns
these values together with `timeout_seconds`, and keeps
`functional_diagnostics` separate from `resource_diagnostics`.

Important limitation: in this smoke entrypoint the returned RSS, timeout,
worker-count, queue, and waveform values are policy metadata. The smoke does
not launch a worker or a process group, so it does not actually enforce RSS or
timeout termination, and `resource_diagnostics` is not evidence that a worker
was supervised. Use the existing `run_supervised_command` path in a real
campaign caller when process-group RSS and timeout enforcement are required.

## Random real-RTL combination campaign

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 \
  nice -n 15 python3 scripts/run_generic_rtl_campaign.py \
  --output runs/my_new_generic_campaign --seconds 300 --count 3
```

Use a new output directory. The command records a randomly chosen seed;
passing `--seed INTEGER` reproduces the selections and stimulus streams.
The pool contains the three two-protocol combinations and one three-protocol
combination of APB3, APB4 and Wishbone Classic register-bank fixtures.

For each selection, pinned local source is analyzed by the production planner,
and the generated top is compiled by Icarus. A synthetic traffic source
performs alternating writes and readback checks against every register bank.
It is a bus validation fixture, not a RISC-V CPU or production peripheral IP.
All endpoints must independently complete more than 100 transactions per
4096-clock batch, with zero readback/protocol errors. DUT state is retained
throughout each campaign; a seeded xorshift stream supplies new write values.

Execution is sequential: one worker and one persistent simulator, without
waveforms. The worker pauses the owned simulator with SIGSTOP for 50 ms after
each reported batch and resumes it with SIGCONT, reducing CPU demand while
preserving DUT state. The existing supervisor enforces the requested elapsed duration
and the combined worker/simulator RSS limit (512 MiB soft, 768 MiB hard).
Source analysis and compilation have their own subprocess timeouts, but are
not subject to the runtime RSS monitor. Runtime timing starts after build and
a successful short preflight.

`campaign.json` records selections and summary outcomes. Each combination
retains its source, interface description, generated layout/IR/top, compiled
simulation, build log, preflight log, runtime checkpoint and `result.json`.
The supervisor's `timed-out` status and SIGTERM at the requested deadline are
expected budget termination; a passing campaign additionally requires elapsed
duration, positive transaction counts, zero metric/monitor errors and a
published checkpoint. Raw metric history is bounded; aggregate counters
continue after truncation. The inherited `iterations` field counts transactions,
not fuzz cases. Neither structural nor code coverage is measured by this runner.

The report explicitly records `riscv_cpu_execution=false` and
`rfuzz_execution=false`. This runner does not validate CVA6/BOOM execution or
RFuzz coverage feedback. Their upstream integration remains outstanding;
the local RFuzz dependency is `third_party/rfuzz/rfuzz_flow` (including `kfuzz`).
