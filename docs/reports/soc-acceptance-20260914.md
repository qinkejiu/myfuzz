# SoC composition and RFuzz acceptance report (2026-09-14)

这份报告记录本分支当前可复现的收口证据。`ready`、`preflight-only` 和
`source_bound_pending_elaboration` 均不是“真实 CPU/IP 已运行”的同义词。

## 已提交的实现

- P3/P6/P7/P8 的契约、fabric、stimulus 与 instruction ABI 修复：见
  `b71afc4`、`f25103d`、`f99ce6a`、`8b0d9a8`、`dd9b4e0`。
- P9 environment/IRQ/interaction monitor：`fb05923`。
- P10 source-backed renderer/preflight boundary：`36ef27d`。
- P11/P12 CVA6 profile、八格 matrix 与边界测试：`ee0c957`。
- P13 instance-mapped RTL coverage boundary：`ee0c957`、`f56b14f`。
- P14 official RFuzz evidence wrapper：`e5347da`、`f56b14f`。

## 可复现验证

```text
PYTHONPATH=src python3 -m unittest \
  tests.composition.test_soc_contract_review \
  tests.composition.test_soc_contracts \
  tests.composition.test_soc_plan_fabric -v
86 tests: OK

PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_rfuzz_live \
  tests.integration.test_soc_campaign_matrix \
  tests.integration.test_soc_coverage \
  tests.integration.test_soc_real_ibex \
  tests.integration.test_soc_real_cva6 \
  tests.integration.test_soc_matrix \
  tests.integration.test_rfuzz_live -v
53 tests: OK, 4 explicit opt-in skips

PYTHONPATH=src nice -n15 python3 scripts/run_soc_campaigns.py \
  --matrix configs/soc/matrix.json \
  --output runs/soc-acceptance/preflight-20260914 \
  --seconds 300 --seed 20260914 --preflight-only
soc_campaign_matrix_result.v1: 32 tasks planned, 24 main, 8 bias-off,
unsupported=0, all task rows=ready
```

The preflight command does not create a live RFuzz child, FIFO, shared-memory
segment, corpus, or replay claim. A real run requires an explicit
`MYFUZZ_SOC_REAL=1` and an executable path in `MYFUZZ_RFuzz_CLIENT` (or the
per-campaign config), and uses `soc_result.v1` to retain failure evidence.

## Newly reproduced real Ibex/PULP smoke

The source-backed PULP wrapper was rebuilt after the latest bridge and renderer
changes with Verilator 5.051, then run with a compiled RV32I boot image.  The
image performs a real Ibex store to the PULP GPIO `PADOUT` register; five beats
from `fuzz_mmio_master` traverse the shared arbiter/router and APB bridges,
including a real SPI configuration/TX sequence.  The testbench observes both
CS0 selection and generated-clock transitions:

```text
SOC_IBEX_PULP_REAL_OK cpu_tx=115 fuzz_tx=5 gpio=000000a5
```

The opt-in generated-top closure also elaborates with
`MYFUZZ_ENABLE_REAL_IBEX`; its manifest now records the ordered Ibex/PULP
source files, include directories and runtime top while keeping
`runtime_status=runtime_unverified` until the official RFuzz campaign and
replay are complete.  The opt-in unittest now rebuilds and runs the smoke from
that manifest closure; a focused APB3 bridge test additionally proves a partial
write is completed as an error with zero APB side effect and that a target which
never raises `PREADY` is bounded to an error response.

## Current acceptance boundary

The following evidence is still missing and therefore the project is not
marked globally complete:

- Ibex and CVA6 have not each completed a real client-driven SoC fuzz run with
  source-backed CPU and peripheral internals observed through IPC.
- The six single-family cells and two mixed cells have not completed the
  required three-mode runtime matrix or the 300-second-per-task campaigns.
- No retained corpus has yet been rebuilt with an independently compiled
  binary and replayed for all eight cells.
- The renderer manifest still reports CPU/IP runtime as
  `runtime_unverified`; the generated real top now has a source-backed
  elaboration closure, but that smoke is not an official RFuzz campaign.
- P13 provides the instance-mapped, RTL-only coverage contract and rejects
  sampled input as branch feedback; a full eight-cell instrumented coverage
  run is still outstanding.

Large `third_party/` checkouts, generated traces and user-modified reports
remain untouched and are not part of the commits above.
