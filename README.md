# myfuzz

The active implementation is a protocol-driven system builder backed by the
preserved material library, source instrumentation, and RFUZZ input generator.
It accepts an explicit JSON system description, discovers RTL facts, applies
protocol profiles, allocates addresses, validates connections, and emits a
reportable system IR.

- protocol profiles and explicit port bindings
- fixed and deterministic automatic address allocation
- ordered connection and signal-constraint graphs
- uniform unknown-port policy decisions
- optional structural wrappers for direct point-to-point systems
- RFUZZ metadata/testcases and source instrumentation through preserved adapters

## Build The Materials Example

```sh
python3 src/myfuzz/scripts/protocol_system_builder.py \
  --spec examples/materials_simple_system.json \
  --project-root . \
  --output-dir /tmp/myfuzz_materials_system \
  --wrapper \
  --rfuzz \
  --rfuzz-cycles 1024 \
  --rfuzz-seed 1
```

The example integrates the local mock CPU, RAM, UART, GPIO, and timer. Because
it has multiple bus targets, the planner emits a virtual `simple_bus` fabric in
the graph; structural RTL emission for that fabric is intentionally deferred to
a protocol backend and the generation report records why no wrapper was made.

## Layout

```text
src/
  myfuzz/builder/         Input, discovery, profiles, planning, emission, CLI
  myfuzz/instrumentation/ Verilog/SystemVerilog source instrumentation
  myfuzz/rfuzz/           RFUZZ-style testcase byte-stream generation
  myfuzz/targets/         Target metadata and target-specific helpers

materials/
  catalog/               Source metadata catalog
  protocol/              Protocol-split material cases
  generated_protocol_cases/ Legacy generated case materials
  protocol_cpus/         CPU master filelists and protocol wrappers
  simple_ips/            Filelists for built-in simple IPs
  rtl/                   All local RTL models, wrappers, stubs, and vendor RTL
  cases/                 Small runnable local smoke configs

docs/
  Minimal implementation notes and runbooks

PLAN.md
PLAN-REVIEW-LOG.md
```

The removed AutoTop/legacy flow is not used by this builder.

## Generated Artifacts

Each successful build writes `system_ir.json`, `port_bindings.json`,
`address_map.json`, `connection_graph.json`, `signal_constraints.json`,
`unknown_ports.json`, and `generation_report.json`. `--rfuzz` adds action and
transaction metadata plus a binary testcase and JSON action trace. Invalid
input or plans exit with status 2 and still write `generation_report.json`.

## Verilog Instrumentation

```sh
python3 src/myfuzz/instrumentation/source_branch_instrumenter.py \
  --project-root <rtl-root> \
  --out-dir /tmp/myfuzz_instrumented \
  --flist <sources.f> \
  --top-module <top> \
  --force
```

## RFUZZ Input Generation

```sh
python3 src/myfuzz/rfuzz/input_generator.py \
  --generated-dir <harness-metadata-dir> \
  --output-dir /tmp/myfuzz_rfuzz \
  --cycles 1024 \
  --seed 1
```

The generator consumes harness metadata such as `action_definitions.json` and
`transaction_plan.json` when present, and falls back to generic WAIT/UART/PIN
actions otherwise.

## Key Documents

```text
PLAN.md
PLAN-REVIEW-LOG.md
docs/runbooks/QUICKSTART.md
materials/README.md
```
