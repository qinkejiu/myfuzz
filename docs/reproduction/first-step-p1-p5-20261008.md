# 第一步 P1–P5 复现手册与目录导航

日期：2026-10-08。范围是[当前数据流实施计划](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)的第一步 P1–P5，不是仓库里较早的 SoC P1。本页记录**本次当前工作树上的重新检查**；阶段报告记录各自冻结源码下已执行的真实 RTL 运行。两者不能互相替代。

关键代码、文档矛盾和当前／历史／共享目录的归类见[代码与文档核对](first-step-code-doc-audit-20261008.md)。

## 从哪里找材料

| 位置 | 用途 |
|---|---|
| [当前进度](../CURRENT_PROGRESS.md) | 当前阶段状态与后续边界 |
| [P1](../reports/current-dataflow-p1-cli-identity-20261006.md) · [P2](../reports/current-dataflow-p2-stage-acceptance-20261007.md) · [P3](../reports/current-dataflow-p3-stage-acceptance-20261007.md) · [P4](../reports/current-dataflow-p4-stage-acceptance-20261008.md) · [P5](../reports/current-dataflow-p5-stage-acceptance-20261008.md) | 每阶段验收条文、冻结运行身份、真实 RTL 证据与限制 |
| `scripts/run_p2_acceptance_gate.py`、`scripts/run_p3_acceptance_suite.py`、`scripts/run_p4_acceptance_suite.py`、`scripts/run_p5_acceptance_suite.py` | 已保存产物的分析入口；P1 使用焦点回归 |
| [`runs/first-step-reproduction-20261008/`](../../runs/first-step-reproduction-20261008/) | 本次小型复核输出；`runs/` 被 Git 忽略，跨机器需复制该目录或重新执行下述命令 |
| `runs/current-dataflow-*`、`runs/p3-*`、`runs/p4-*`、`runs/p5-*` | 历史原始运行与 replay 材料；路径被报告和身份记录引用，未移动 |

## 本次复核结果

执行时的 Git HEAD 是 `09a691ed064ad91d53f61ebe9cc96eb040a8a4e1`，工作区已有大量未提交文件；本次结果只代表该工作区。各门禁顺序执行，虚拟内存限制为 1–1.5 GiB；没有启动 RTL 构建、RFuzz 长跑或新的 fresh replay。

| 阶段 | 本次命令结果 | 本次可主张的范围 | 输出 |
|---|---|---|---|
| P1 | 焦点回归退出 0；236 tests，5 skipped | 当前源码下 CLI、身份、evidence 和相关传输软件回归；跳过项未复现 | [`p1-unittest.txt`](../../runs/first-step-reproduction-20261008/p1-unittest.txt) |
| P2 | `p2_acceptance_report.v1` 退出 0，`ready=true`，`critical_missing=[]`，`critical_unmet=[]` | 从已保存的 31,795 事件运行重新分析路径、提前 IRQ、负例和身份门禁；没有重新执行 RTL | [`p2-report.json`](../../runs/first-step-reproduction-20261008/p2-report.json) |
| P3 | `p3_acceptance_suite.v1` 退出 0，`ready=true` | 四个声明运行的**联合**证据；单个运行并未证明全部关键项 | [`p3-suite.json`](../../runs/first-step-reproduction-20261008/p3-suite.json) |
| P4 | 48 项套件测试通过；整阶段套件本次**未完成** | `--skip-heavy` 仍启动算子收益对照，子进程 RSS 增至约 930 MiB 后为保护机器主动终止（退出 143）；历史保存的 `p4_acceptance_suite.v1` 为 8/8、退出 0，文件时间 2026-10-08 06:15，不能称为本次复核通过 | [`p4-tests.txt`](../../runs/first-step-reproduction-20261008/p4-tests.txt)；历史文件 `runs/current-dataflow-p4-acceptance-20261008.json` |
| P5 | `p5_acceptance_suite.v1` 退出 0，关键项 6/6，`no_proving_run=[]` | 七个声明运行的**联合**只读复核；没有生成新的 600 秒搜索、故障复现或 fresh replay | [`p5-suite.json`](../../runs/first-step-reproduction-20261008/p5-suite.json) |

P4 的完整套件即使传入 `--skip-heavy` 仍会调用 `compare_p4_operator_benefit.py`，本次没有继续提高内存额度。历史 P4 输出以及历史算子收益 JSON 的时间戳均早于本次调用；本次没有改写它们。

## 顺序复现命令

在仓库根目录执行。`ulimit -v` 的单位是 KiB；同一时刻只运行一条命令。输出放在新目录，避免覆盖原始证据。

```bash
mkdir -p /tmp/myfuzz-stage1-repro
ulimit -v 1048576
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. timeout 120s python3 -m unittest \
  tests.test_capabilities tests.test_current_cli tests.test_cli \
  tests.local_harness.test_generation_cli \
  tests.scenario.test_evidence_bundle tests.scenario.test_evidence_run_identity \
  tests.scenario.test_evidence_budget tests.scenario.test_generated_evidence_host_identity \
  tests.scenario.test_host_source_identity tests.integration.test_scenario_campaign \
  tests.integration.test_scenario_cva6_campaign \
  tests.integration.test_campaign_run_identity tests.integration.test_fresh_run_identity \
  tests.integration.test_online_run_identity \
  tests.integration.test_scenario_rfuzz_terminal_identity \
  tests.scenario.test_online_session_partial_replay \
  tests.scenario.test_online_uart_source_events \
  tests.scenario.test_rfuzz_scenario_executor \
  tests.integration.test_ibex_uart_online_pilot \
  tests.integration.test_scenario_rfuzz_wall_cut_replay -q \
  2> /tmp/myfuzz-stage1-repro/p1-unittest.txt
```

```bash
ulimit -v 1572864
PYTHONPATH=src timeout 120s python3 scripts/run_p2_acceptance_gate.py analyze \
  --run-dir runs/current-dataflow-p5-chain-acceptance-20261007-online \
  > /tmp/myfuzz-stage1-repro/p2-report.json
PYTHONPATH=src timeout 180s python3 scripts/run_p3_acceptance_suite.py \
  --run primary=runs/p3-lane-selectivity2-20261007-online \
  --run cross_case=runs/p3-ip-cross-case-20261007-online \
  --run feedback=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run controlled_fault=runs/current-dataflow-p5-fault-calibration-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  > /tmp/myfuzz-stage1-repro/p3-suite.json
```

P4 在内存受限机器上先复核小测试与历史报告；完整套件需单独评估内存，因为 `--skip-heavy` **不会跳过**算子收益扫描：

```bash
ulimit -v 524288
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. timeout 45s python3 -m pytest \
  tests/scenario/test_p4_acceptance_suite.py -q -p no:randomly
python3 -m json.tool runs/current-dataflow-p4-acceptance-20261008.json > /dev/null
```

```bash
ulimit -v 1048576
PYTHONPATH=src timeout 240s python3 scripts/run_p5_acceptance_suite.py \
  --run chain_acceptance=runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --run long_search=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run paired_continuous=runs/current-dataflow-p5-paired-20261007-online \
  --run paired_cold_start=runs/current-dataflow-p5-paired-20261007-cold-start \
  --run fault_calibration=runs/current-dataflow-p5-fault-calibration-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  --run fault_family=runs/current-dataflow-p5-fault-family-all-20261007-online \
  --run heterogeneous_uart=runs/p5-uart-routing-gate-20261008-online \
  --artifact long_search=replay=runs/current-dataflow-p5-final-20261007-logs/chain_600s_replay.log \
  > /tmp/myfuzz-stage1-repro/p5-suite.json
```

这些命令核对已保存证据与当前分析代码，不能证明当前源码重新跑出相同 RTL trace。真正的 fresh replay 必须按对应阶段报告的冻结源码、plan、trace、manifest 和工具链身份执行；源码身份不符时应记录为拒绝，不要绕开身份门禁。P5 的“6/6”是跨运行联合判定，UART 单运行和部分完整链仍有报告列明的边界；自然 RTL finding 在该批运行中为 0，故障 finding 是受控校准。

## 目录整理原则

本轮只增加一处复现手册和一处小型输出目录，并从现有入口链接进来。`runs/` 的原始目录、第三方 RTL、缓存与带身份的 replay 材料均保留原位；目录名本身不能说明某份证据是否可由当前源码重新 replay。
