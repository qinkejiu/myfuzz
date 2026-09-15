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

### Two more initiator protocols: classic Wishbone and AXI4-Lite

Besides OBI, AXI4, TL-UL and ready-valid-memory, the CPU-side registry now
carries `wishbone@classic` (`wishbone_processor_memory_adapter`) and
`axi4-lite@1` (`axi4_lite_processor_memory_adapter`). Both are single-
outstanding masters that terminate exactly one beat per bus transaction. Run
their behavioural benches with:

```bash
PYTHONPATH=src python3 -m unittest \
  tests.protocols.test_wishbone_and_axi4_lite_processor_memory_adapters_rtl
```

Each protocol also has a real-CPU runtime bench that puts actual PicoRV32 RTL
behind the adapter, once as `picorv32_axi` and once as `picorv32_wb`, with the
same assembled program and the same beat RAM model:

```bash
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_real_picorv32
```

These benches need `third_party/picorv32_upstream_reference`, which is not part
of this repository, hence the opt-in flag. They compare every retired
instruction against the committed boot image rather than only checking side
effects, and they are what exposed the empty-select read refusal that the unit
benches had encoded as correct. The evidence, the accounting and the limits of
what these runs prove are recorded in
[`docs/reports/picorv32-protocol-benches-20260915.md`](docs/reports/picorv32-protocol-benches-20260915.md).

Run the complete Python regression suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

## 10. SoC Composition And Real RFuzz Pipeline

The P0-P16 work in
[docs/PROJECT_GOALS.md](docs/PROJECT_GOALS.md) is a separate pipeline driven by
`configs/soc/`. Its reproducible commands are:

```bash
# P1: re-derive every pinned source and elaboration closure, then replay the
# seven recorded Verilator commands and require the read set to equal the closure
PYTHONPATH=src python3 scripts/verify_soc_sources.py --elaborate

# P0: read-only inventory of the worktree, and recoverable quarantine
PYTHONPATH=src python3 scripts/audit_repository.py --output runs/repository-audit/now/inventory.json
PYTHONPATH=src python3 scripts/audit_repository.py --restore runs/quarantine/<batch>/manifest.json

# P3/P6: the versioned contracts and the SoC fabric plan
PYTHONPATH=src python3 -m unittest tests.composition.test_soc_contracts tests.composition.test_soc_fabric_plan -v

# P10-P12: render all eight cells from real source-backed closures and elaborate
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_renderer_cells -v

# P10/P11: the real CPU acceptances (no skips when the flag is set)
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_ibex -v
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_cva6 -v

# P12 runtime half: eight cells x three modes with a real CPU and real peripherals
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_matrix_runtime.SocMatrixRuntimeTests

# P13: instrument the eight cells and require a real CPU/IP branch point to reach
# RFuzz over IPC (short runs; this proves feedback, not coverage)
MYFUZZ_SOC_REAL=1 MYFUZZ_RFuzz_CLIENT=runs/rfuzz_client_native_build/target/debug/kfuzz \
  PYTHONPATH=src python3 -m unittest tests.integration.test_soc_coverage_run

# P14: official RFuzz closed loop with retained receipts, corpus and rebuild replay
MYFUZZ_SOC_REAL=1 MYFUZZ_RFuzz_CLIENT=runs/rfuzz_client_native_build/target/debug/kfuzz \
  PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_build

# P12/P14/P15: plan the 24 main + 8 bias-off tasks without running them
PYTHONPATH=src nice -n15 python3 scripts/run_soc_campaigns.py \
  --matrix configs/soc/matrix.json --output runs/soc-acceptance/preflight \
  --seconds 300 --seed 20260914 --preflight-only
```

A real campaign additionally needs `MYFUZZ_SOC_REAL=1` and an executable
official RFuzz client in `MYFUZZ_RFuzz_CLIENT`. The 300-second-per-task budget
of at least 160 effective minutes has deliberately not been run in this round
and must not be inferred from the preflight.

The measured results of the commands above are recorded in
[docs/reports/soc-acceptance-20260915.md](docs/reports/soc-acceptance-20260915.md),
including why the project is **not** marked complete.
