# myfuzz

当前目标：从组件 RTL 与 profile 自动组合受支持的 CPU、MMIO 外设、
总线、peer 与中断路径，并使用 RFuzz 输入和可重放证据测试真实 SoC。
已验证范围与尚未完成的留出组件、全量回归见
[后续路线图](docs/superpowers/plans/2026-09-22-soc-next-steps-roadmap.md)；
下方历史流程示例不代表所有组件或协议均已验收。

- [当前实施路线与验收边界](docs/superpowers/plans/2026-09-22-soc-next-steps-roadmap.md)
- [能力矩阵](docs/reports/soc-capability-matrix-20260921.md)
- [项目目标与早期验收矩阵（历史）](docs/PROJECT_GOALS.md)

`myfuzz` provides two related RTL fuzzing paths: Verilog/SystemVerilog
source-level instrumentation, and protocol-aware processor composition for
driving real CPU RTL through RFuzz. It embeds extracted Verilator frontend code
as a project-local parser component and keeps generated artifacts outside the
upstream RTL source trees.

The active flow does not use `verilator --xml-only`, does not rely on a
Verilator command-line frontend binary, and does not print an AST back to
Verilog.

## Directory Layout

```text
src/myfuzz/        project code: frontend component and Python orchestration
scripts/           standalone source instrumentation entry points
configs/designs/   smoke, Ibex, CVA6, XiangShan, and BOOM design configs
third_party/rfuzz/ rfuzz flow code plus copied Ibex/CVA6 targets
runs/task*/        regenerable processor-composition and acceptance evidence
runs/designs/      regenerable run outputs
artifacts/         preserved complete run artifacts
```

Use the `src/`, `scripts/`, `configs/`, and `third_party/` paths for new work.
For a fresh checkout, run `git submodule update --init --recursive` before
running source-backed RTL tests. The RFuzz client source is kept under
`third_party/rfuzz/upstream/rfuzz_reference/fuzzer/`; downloaded toolchains,
build outputs, campaign results, and local archives are intentionally not
committed.

## Active Flow

```text
Verilog/SystemVerilog sources
  -> src/myfuzz/frontend/build/libmyfuzz_frontend.so
  -> in-memory frontend manifest
  -> source inserter edits copied RTL under runs/
  -> instrumentation.json + instrumented RTL
  -> rfuzz TOML + harness
  -> Verilator simulation server
  -> shared-memory fuzz run
```

`libmyfuzz_frontend.so` provides parsed/elaborated source metadata: modules,
ports, instances, hierarchy, source files, and branch candidates. The
instrumenter uses that metadata to edit the copied source tree. Original RTL
under `third_party/rfuzz/upstream/...` remains unchanged.

The processor-composition path discovers CPU-facing buses, maps OBI, AXI4, and
TL-UL protocol roles into a common execution model, generates the RFuzz input
transport and monitor, and validates instruction fetch progress against real
RTL. See the
[真实 Ibex 自动组合与 RFuzz 示例](examples/real_ibex_rfuzz/README.zh-CN.md)
for a complete Chinese walkthrough with runnable input and commands,
[QUICKSTART.md](QUICKSTART.md) for the general command summary, and
[`docs/reports/task16_processor_rfuzz_regression_20260908.md`](docs/reports/task16_processor_rfuzz_regression_20260908.md)
for the current acceptance evidence.

### Generic CPU composition CLI

Any source-backed `interface_description.v1` can be composed without naming a
CPU in the generator. The description supplies the source root, top module,
clock/reset, and memory endpoint facts; the endpoint protocol selects the
adapter. For a split instruction/data RISC-V CPU, the standard constrained
command is:

```bash
PYTHONPATH=src python3 scripts/generate_composition.py \
  --interface-description configs/cpus/ibex/official_core_interface_description.json \
  --base-dir . \
  --out-dir runs/examples/generic-ibex-composition \
  --isa-xlen 32 \
  --isa-extension I --isa-extension M --isa-extension C \
  --constrained \
  --max-wait-cycles 16 \
  --memory-capacity-entries 256 \
  --no-allow-error
```

`--constrained` compiles the ISA and `processor-memory-beat@1` contract into
the RFuzz transducer. `--max-wait-cycles` bounds a stalled response,
`--memory-capacity-entries` bounds coherent test memory, and
`--allow-error/--no-allow-error` controls random protocol-error choices. A
unified CPU endpoint is also accepted when its description contains a
source-backed one-bit `instruction_identity` output (for example `mem_instr`);
the generator never guesses instruction/data from a CPU name or address.

The JSON line printed by the command is the machine-readable result. In
addition to the usual `top_path`, `source_list_path`, and `complete` fields,
processor plans report `processor_execution_path`; constrained plans also
report `contract_transducer_path`. The output directory contains
`generic_composition_top.sv`, `processor_execution.v1.json`,
`processor_backend.v1.json`, `contract_transducer.json` (constrained mode),
`rfuzz_input_transport.json`, and `sources.f`.

For an unconstrained wiring-only artifact, omit `--constrained` and the ISA
flags. Tuning flags require `--constrained`. In constrained mode, missing or
ambiguous instruction identity is rejected before any output is published;
unconstrained mode may still be used to inspect a protocol-only route.

### Real CPU × real peripheral matrix

The repository also contains a deterministic matrix runner for source-backed
Ibex, CV32E40P, CV32E20, and CVA6 targets. It composes each CPU through its
declared OBI/AXI interface, maps the common `processor-memory-beat@1` contract
through the existing bridges, and instantiates real RAM, UART, SPI, Timer, and
GPIO RTL targets. Run it from the repository root:

```bash
PYTHONPATH=src python3 scripts/run_real_cpu_peripheral_matrix.py \
  --seed 20260909 \
  --out-dir examples/real_cpu_peripheral_matrix/results
```

The runner clones the two CV32 upstream repositories into a temporary,
committed provenance directory, so it does not modify `third_party/`. Use
`--keep-artifacts` when the temporary source checkouts and generated
compositions are needed for inspection. The target wrappers are in
`configs/designs/ibex_multicomponent_ip/rtl/real_targets/`; they expose the
same generic beat contract while using TL-UL for RAM, AXI4-Lite for UART/SPI,
and APB4 for Timer/GPIO. CVA6 uses corresponding 64-bit wrappers: RAM keeps
both 32-bit lanes in coherent banks, while 32-bit MMIO targets accept one
aligned full-lane access and return an explicit error for unsupported lane or
partial-write shapes. The clocked smoke is bounded to 2048 edges (enough for
CVA6's reset-time I-cache clear), and external IRQ pins are tied off. The
64-bit TL bridge preserves the +4 high-lane read/write case as a legal 32-bit
transfer. CV32E40P has no architectural OBI error pin; an error response
therefore terminates the simulation with `$fatal`, so its matrix evidence
intentionally covers only the no-error path until a core-specific exception
bridge is added. The smoke checks shared backend request/response activity,
not a functional access to every individual peripheral register.

With seed `20260909`, the matrix produced 9/9 successful cases: every case
passed generic planning, publication, Verilator lint, and the generated smoke
test. Ibex, CV32E40P, CV32E20, and CVA6 appeared 2, 2, 2, and 3 times. Each
32-bit real peripheral profile appeared at least twice across compatible CPU
cases; the report records the exact reuse counts in `matrix_report.json`.

## Build

Keep the frontend build single-core unless there is enough memory:

```bash
env JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh
```

Expected output:

```text
src/myfuzz/frontend/build/libmyfuzz_frontend.so
```

## Run

### CLI

```bash
PYTHONPATH=src python3 -m myfuzz check
PYTHONPATH=src python3 -m myfuzz preflight --output runs/preflight
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m myfuzz run \
  --client runs/rfuzz_client_native_build/target/debug/kfuzz \
  --output runs/soc-acceptance/run-1
```

Use `python3 -m myfuzz <command> --help` for the few optional arguments.

Smoke harness check:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/smoke/config.enhanced.json \
  --stage harness \
  --force
```

Ibex instrumentation:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/ibex/config.json \
  --stage instrument \
  --force
```

CVA6 instrumentation:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/cva6/config.json \
  --stage instrument \
  --force
```

BOOM full flow, using generated Chipyard SmallBoomV3 RTL:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/boom/config.json \
  --stage all \
  --jobs 1 \
  --fuzz-seconds 10 \
  --force
```

Use `--stage all --jobs 1 --fuzz-seconds 1` to continue through TOML, harness,
server build, and a short shared-memory fuzzer run.

The default BOOM `TestHarness` config is a zero-input infrastructure smoke after
clock/reset filtering. Use `configs/designs/boom/config.chiptop.json` for the
experimental chip-level BOOM flow with fuzzer-visible IO.

Stages:

```text
frontend -> instrument -> toml -> harness -> server -> fuzz
```

## Instrumentation

The source inserter supports configurable runtime coverage for:

- `if/else`, missing `else`, `case/default`, and optional `else-if` false paths;
- process block entry, procedural assignment, call, and control statements;
- runtime loop body hits, including conservative wrapping for single-statement
  loops;
- assertion hit coverage;
- metadata for ternary expressions, conditions, toggle candidates, assertions,
  and static generate constructs.

Hierarchy propagation is enabled by default. Modules with local or child
coverage get an `output wire __vi_coverage` port. Parent instances connect child
coverage ports and concatenate child vectors upward, so observing the selected
top module coverage port exposes coverage for the reachable hierarchy.

## Important Files

```text
src/myfuzz/frontend/                             extracted frontend component
src/myfuzz/scripts/run_design_flow.py           full pipeline runner
src/myfuzz/scripts/frontend_api.py              ctypes frontend bridge
scripts/source_branch_instrumenter.py           source inserter
third_party/rfuzz/rfuzz_flow/tools/verilog_instrumentation/
configs/designs/{smoke,ibex,cva6,xiangshan,boom}/ runnable configs
```

## Checked Source-Instrumentation Results

- Smoke enhanced: 20 coverage points, 18 metadata points, harness generation
  passed.
- Ibex default: 30 HDL files, 1050 local branch coverage points.
- Ibex enhanced: 2905 coverage points, 3362 metadata points.
- CVA6 default: 186 HDL files, 2910 local branch coverage points.
- CVA6 enhanced: 7935 coverage points, 14905 metadata points.
- XiangShan: source-instrumented `XSTop` flow has been built and fuzzed with
  crash archival/restart support.
- BOOM: configs are provided for Chipyard `SmallBoomV3Config` `TestHarness` and
  an experimental `ChipTop` port-role override flow. The `TestHarness` flow has
  3305 branch coverage points and runs through server/fuzzer smoke on `inner70`;
  `ChipTop` has 3139 branch coverage points, 3 fuzzer-visible input fields, and
  a successful 1 second smoke with no crash archives.

These BOOM results belong to the older source-instrumentation flow; they do not
complete the protocol-aware BOOM processor acceptance task.

## Processor-Composition Acceptance Status

- OBI, AXI4, and TL-UL adapters and executable fixtures are implemented.
- Bounded real-RTL execution has passed for Ibex and CVA6, including first-fetch
  matching and forward-progress evidence.
- The official RFuzz client completed a 5-second Ibex preflight with 15,357 RTL
  tests, 13,440 completed feedback receipts, and 19 retained corpus entries.
- BOOM protocol acceptance is deferred by project decision.
- The three sequential 300-second campaign gate is intentionally not claimed:
  its runner and configuration are checked in, but that long-duration run has
  not been executed.

CVA6 instrument runs may print original-design Verilator warnings such as
`IMPLICITSTATIC` and `SELRANGE`; the instrumentation stage still succeeds.

### SoC composition pipeline acceptance status

The P0-P16 work tracked by
[docs/PROJECT_GOALS.md](docs/PROJECT_GOALS.md) and the
[implementation plan](docs/superpowers/plans/2026-09-14-soc-composition-and-fuzz.md)
adds a separate pipeline; it does not inherit the acceptance above.

Implemented and committed:

| Task | Commit | What it delivers |
|---|---|---|
| P0 | `da3b150`, `f0fcd41`, `43ee22b` | read-only repository inventory and recoverable quarantine, 52 tests |
| P1 | `dbb6ab7`, `8dc1097` | pinned CPU/peripheral sources, per-IP elaboration closures, hardened verifier |
| P2 | `5e62059`, `1c4f25e` | generic planner / processor renderer extraction with forwarding |
| P3 | `9f7f7af`, `07339c0` | `soc_spec.v1` / `soc_plan.v1` / `soc_stimulus.v1` contracts |
| P4-P9 | `8731bcc`…`fb05923` | memory/MMIO coexistence, target adapters, arbitration, stimulus, instruction supply, environment/IRQ |
| P10-P12 | `36ef27d`…`a50cfc7` | renderer, CVA6 source closure, eight-cell matrix |

Reproducible commands and their verified results:

```text
PYTHONPATH=src python3 scripts/verify_soc_sources.py --elaborate
  -> 7 peripherals elaboration_verified, all commands replayed, read set == closure

MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_renderer_cells
  -> 7 tests OK: all eight cells render from real source-backed closures and elaborate

MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_ibex
  -> 10 tests OK, including the real SOC_IBEX_PULP_REAL_OK simulation

MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_cva6
  -> 8 tests OK, including the real CVA6 runtime smoke through packed AXI

PYTHONPATH=src nice -n15 python3 scripts/run_soc_campaigns.py \
  --matrix configs/soc/matrix.json --output runs/soc-acceptance/preflight \
  --seconds 300 --seed 20260914 --preflight-only
  -> 32 tasks planned (24 main + 8 bias-off), unsupported = []
```

Not yet claimed, and therefore not part of any completion statement:

- the eight-cell x three-mode runtime matrix and the per-cell short RFuzz
  campaigns on the new harness (P12/P14) are still being closed;
- real instrumented CPU/IP coverage fed back through IPC for all eight cells
  (P13) has a validated contract and fidelity rules but no full run yet;
- the 300-second-per-task campaign budget of at least 160 effective minutes is
  deliberately out of scope for this round and is NOT claimed.
