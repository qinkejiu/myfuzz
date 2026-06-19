# myfuzz

`myfuzz` is a Verilog/SystemVerilog source-level instrumentation and rfuzz
execution flow. It embeds extracted Verilator frontend code as a project-local
parser component, then inserts coverage logic into copied RTL source files.

The active flow does not use `verilator --xml-only`, does not rely on a
Verilator command-line frontend binary, and does not print an AST back to
Verilog.

## Directory Layout

```text
src/myfuzz/        project code: frontend component and Python orchestration
scripts/           standalone source instrumentation entry points
configs/designs/   smoke, Ibex, CVA6, XiangShan, and BOOM design configs
third_party/rfuzz/ rfuzz flow code plus copied Ibex/CVA6 targets
runs/designs/      regenerable run outputs
artifacts/         preserved complete run artifacts
```

Use the `src/`, `scripts/`, `configs/`, and `third_party/` paths for new work.

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

## Checked Results

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

CVA6 instrument runs may print original-design Verilator warnings such as
`IMPLICITSTATIC` and `SELRANGE`; the instrumentation stage still succeeds.
