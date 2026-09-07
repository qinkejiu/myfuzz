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
* `generic_composition_top.sv`; and
* `sources.f`.

`write_generic_composition` re-crawls the pinned source before publication,
checks the address map, and uses an atomic staging directory. If Verilator is
installed, it performs a bounded `--lint-only` check before publishing.

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

The generic renderer currently materializes only the declared bounded
single-channel contract used by the synthetic fixture. The repository may
contain protocol catalog entries and separate native RTL bridge work for APB,
AXI4-Lite, TileLink, Wishbone, and OBI, but that does not mean the generic
renderer can route every one of them yet. In particular, APB/AXI/Wishbone
must not be reported as executable generic adapters until their native
point-to-point route and validation are connected.

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

This branch intentionally does not start a 3x300-second campaign. The real
RTL campaign entrypoint, DUT driver, transaction/assertion accounting, and
RFuzz dependency handling are handed to the main thread. If the RFuzz flow is
absent, the caller must report the concrete missing path
`third_party/rfuzz/rfuzz_flow` as `dependency-unavailable` rather than claim a
successful run.
