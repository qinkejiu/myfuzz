# myfuzz Quickstart

Run commands from the project root:

```bash
cd /path/to/myfuzz
```

## 1. Build The Frontend Component

```bash
env JOBS=1 src/myfuzz/frontend/scripts/build_frontend.sh
```

Build output:

```text
src/myfuzz/frontend/build/libmyfuzz_frontend.so
```

`JOBS=1` is intentional for memory-sensitive Ibex/CVA6 runs.

## 2. Run Smoke

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/smoke/config.enhanced.json \
  --stage harness \
  --force
```

Expected outputs:

```text
runs/designs/smoke_enhanced/frontend.json
runs/designs/smoke_enhanced/instrumented/
runs/designs/smoke_enhanced/harness/top_VHarness.sv
```

## 3. Run Ibex

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/ibex/config.json \
  --stage instrument \
  --force
```

Expected outputs:

```text
runs/designs/ibex/frontend.json
runs/designs/ibex/instrumented/
runs/designs/ibex/instrumented/instrumentation.json
```

Use this for a short full-flow check:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/ibex/config.json \
  --stage all \
  --jobs 1 \
  --fuzz-seconds 1 \
  --force
```

## 4. Run CVA6

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/cva6/config.json \
  --stage instrument \
  --force
```

Expected outputs:

```text
runs/designs/cva6/frontend.json
runs/designs/cva6/instrumented/
runs/designs/cva6/instrumented/instrumentation.json
```

## 5. Stages

```text
frontend -> instrument -> toml -> harness -> server -> fuzz
```

Examples:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/cva6/config.json \
  --stage frontend \
  --force

python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/cva6/config.json \
  --stage harness \
  --jobs 1 \
  --force
```

`frontend` calls the project-local shared library through Python `ctypes`. It
does not invoke `verilator --xml-only`.

## 6. Enhanced Instrumentation

Enhanced configs enable additional source-level coverage and metadata:

```bash
python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/ibex/config.enhanced.json \
  --stage instrument \
  --force

python3 src/myfuzz/scripts/run_design_flow.py \
  --config configs/designs/cva6/config.enhanced.json \
  --stage instrument \
  --force
```

## 7. Direct Source Inserter

After a frontend manifest has been generated, the inserter can be run directly:

```bash
python3 scripts/source_branch_instrumenter.py \
  --project-root third_party/rfuzz/upstream/ibex \
  --out-dir /tmp/ibex_instrumented \
  --flist third_party/rfuzz/upstream/ibex/sources.f \
  --frontend-json runs/designs/ibex/frontend.json \
  --top-module ibex_core \
  --force
```

The inserter only edits copied files under `--out-dir`.

## 8. Inspect Results

```bash
jq '{top_modules, coverage_point_count, coverage_by_kind, metadata_point_count, metadata_by_kind, file_count, skipped}' \
  runs/designs/cva6/instrumented/instrumentation.json

rg "__vi_coverage" runs/designs/cva6/instrumented/core/cva6.sv
```

Latest checked counts:

```text
smoke enhanced: 20 coverage points, 18 metadata points
ibex default:   1050 coverage points
ibex enhanced:  2905 coverage points, 3362 metadata points
cva6 default:   2910 coverage points
cva6 enhanced:  7935 coverage points, 14905 metadata points
```

## 9. Protocol-Aware Real-CPU RFuzz

The generic processor path automatically composes discovered OBI, AXI4, or
TL-UL interfaces with memory and execution monitoring. Its checked-in Ibex
campaign is:

```text
configs/campaigns/ibex-real-rfuzz.json
```

Build the RFuzz client from the fixed upstream checkout. Apply the tracked
client patch once if the checkout does not already contain it:

```bash
git -C third_party/rfuzz/upstream/rfuzz_reference apply --check \
  --ignore-space-change \
  ../../../../patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch

git -C third_party/rfuzz/upstream/rfuzz_reference apply \
  --ignore-space-change \
  ../../../../patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch
```

The first command is a preflight: skip the second command when the patch is
already applied. The exact dependency and simulator build commands, along with
the captured evidence, are recorded in
[`docs/reports/task16_processor_rfuzz_regression_20260908.md`](docs/reports/task16_processor_rfuzz_regression_20260908.md).

Run the configured three-campaign acceptance gate with:

```bash
PYTHONPATH=src JOBS=1 nice -n15 python3 scripts/run_real_cpu_campaigns.py \
  --config configs/campaigns/ibex-real-rfuzz.json \
  --client runs/task14_client_cancel_build/debug/kfuzz \
  --output runs/task15-real-cpu-3x300 \
  --seconds 300 \
  --seed 20260908
```

The runner enforces at least 300 seconds per campaign and executes three
campaigns sequentially. A 5-second real-Ibex preflight has passed; the full
three-by-300-second gate has not yet been run and must not be inferred from the
preflight result. BOOM processor acceptance is currently deferred.

Run the complete Python regression suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```
