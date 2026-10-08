# 第一步 P1–P5 代码与文档核对

日期：2026-10-08。核对范围是当前独立 CPU/IP harness 与数据流第一步。检查了 CLI、在线接纳路径、阶段分析器、P4/P5 套件、相关测试及文档入口；没有把仓库全部模块逐行审计，也没有重新启动 RTL。测试和已保存产物的复核结果见[复现手册](first-step-p1-p5-20261008.md)。

## 按职责归类

| 类别 | 当前入口或代码 | 证据与文档 | 整理处置 |
|---|---|---|---|
| P1 命令与身份 | [`__main__.py`](../../src/myfuzz/__main__.py)、`scenario/evidence_identity.py`、`scenario/host_identity.py`、`integration/scenario_rfuzz_replay.py` | [P1 报告](../reports/current-dataflow-p1-cli-identity-20261006.md)、`tests/test_current_cli.py`、`tests/integration/test_online_run_identity.py` | 保留当前实现；统一从 `python -m myfuzz` 与阶段报告进入 |
| P2 路径、逐边来源 | `scenario/runtime_path_contract.py`、`scenario/edge_provenance.py`、`scenario/p2_acceptance.py`、[`run_p2_acceptance_gate.py`](../../scripts/run_p2_acceptance_gate.py) | [P2 报告](../reports/current-dataflow-p2-stage-acceptance-20261007.md)、`runs/current-dataflow-p5-chain-acceptance-20261007-online` | 保留代码与冻结运行原路径；归入当前数据流证据 |
| P3 动作与持续会话 | [`source_actions.py`](../../src/myfuzz/scenario/source_actions.py)、`scenario/session_runtime.py`、`integration/scenario_rfuzz.py`、`scenario/p3_acceptance_suite.py` | [P3 报告](../reports/current-dataflow-p3-stage-acceptance-20261007.md)、四个声明运行 | 在线 executor 确实调用 gate 的 `register`/`require_case`；旧文档“只在 ScenarioSession 接线”需更正 |
| P4 变异与反馈 | `scenario/rv32i_sources.py`、`scenario/rejection_codes.py`、`scenario/closed_loop_feedback.py`、[`run_p4_acceptance_suite.py`](../../scripts/run_p4_acceptance_suite.py) | [P4 报告](../reports/current-dataflow-p4-stage-acceptance-20261008.md)、历史 8/8 输出、48 项本次套件测试 | 代码属当前路径；套件资源风险见下表 |
| P5 链、故障、效率 | `scenario/chain_certificates.py`、`scenario/uart_chain_certificates.py`、`scenario/p5_fault_family.py`、`scenario/paired_efficiency.py`、`scenario/p5_acceptance.py` | [P5 报告](../reports/current-dataflow-p5-stage-acceptance-20261008.md)、本次 6/6 输出 | 区分 GPIO 完整链、后续 UART 独立证书与运行自身路由见证；不合并成同一个指标 |
| 共享基础 | `local_harness/`、`protocols/`、`composition/component_profile.py`、`composition/source_crawler.py`、`configs/soc/sources.lock.json` | [代码组织](../CODE_ORGANIZATION.md)、[运行能力](../LOCAL_HARNESS_RUNTIME.md) | `composition/` 和 `configs/soc/` 中有当前依赖，不能按目录名整体挪到历史区 |
| 历史完整 SoC 路线 | `integration/soc_*`、`composition/soc_*`、`scripts/generate_soc.py`、`configs/designs/` 的早期样例 | `docs/reports/soc-*`、较早计划 | 保留原路径与引用，索引标注历史；不计入本次 P1–P5 当前能力 |
| 冻结证据与可重建产物 | `runs/*-online/`、replay 记录、manifest；`runs/*-cache/` 与构建中间物 | 各阶段报告引用具体路径和源码摘要 | 在线运行、trace、replay、身份文件保留；缓存只有逐项核清引用与重建命令后才可清理，本轮未移动或删除 |

这次实际增加 `docs/reproduction/` 文档目录与 `runs/first-step-reproduction-20261008/` 小型输出目录。带身份的原始运行未迁移，避免破坏报告、plan 和 replay 的路径引用。

## 代码核对发现

后续逐文件审阅新增的 P5 漏检、会话异常处理、证书报告与反馈校验问题，以及全文／分段／待审状态，见[逐文件审阅记录](first-step-individual-review-20261008.md)。本页不是全仓库逐行审计完成证明。

| 优先级 | 位置与现象 | 影响与本次证据 |
|---|---|---|
| 高 | [`run_first_step_acceptance.py`](../../scripts/run_first_step_acceptance.py) 的 `run --replay` 把 CLI JSON 包在 `stdout` 字符串里写成 `first_step_acceptance_replay.json`，随后把此文件传给 [`acceptance_metrics._resolve_replay`](../../src/myfuzz/scenario/acceptance_metrics.py)，后者要求顶层布尔 `matches` | 实际 replay 退出 0 后仍会在分析阶段报 `has no boolean 'matches' field`；本次用相同记录结构直接复现。既有 CLI 测试替换了 `analyze_run`，未覆盖这条真实调用链。|
| 中 | [`paired_efficiency._aggregate_identity_pairs`](../../src/myfuzz/scenario/paired_efficiency.py) 在任意一个字段相同、其他字段缺失时返回 `satisfied=True` | 本次用相同 source hash、缺失 component identity 直接得到 `True`；因此部分身份缺失的配对可能被判可比。已保存配对报告的结论属于其具体字段集合，不能把这个缺口概括成所有历史配对均错误。|
| 中 | [`run_p4_acceptance_suite.py`](../../scripts/run_p4_acceptance_suite.py) 的 `--skip-heavy` 只跳过 path-switch 与 initial-RAM gate，仍无条件调用 `check_benefit()`；它又启动大对照并准备写入已有 `runs/.../p4_operator_benefit.json` | 本次子进程 RSS 到约 930 MiB 时主动停止（退出 143），完整套件未复现。历史 JSON 的时间戳早于本次调用，未被改写。命令帮助中的“skip the operator gates that need the long runs”容易低估该选项的资源占用。|
| 中 | [`acceptance_metrics._compare_replay`](../../src/myfuzz/scenario/acceptance_metrics.py) 对两个目录中事件数、语义摘要、状态和链数一致就给 `replay.verified=true` | [现有测试](../../tests/integration/test_first_step_acceptance.py)用两份内容相同的测试目录得到 `verified=true`；该字段只能说明保存材料比较成立，单独不能证明新 RTL 进程执行过回放。|

这些是核对结论，本轮没有改动生产代码。真实重放应保存进程执行结果、身份与比较产物，再分开报告“执行过”和“材料相同”。

## 文档核对与边界

- [`CODE_ORGANIZATION.md`](../CODE_ORGANIZATION.md) 顶部及若干职责行停留在 2026-10-06：写 P2/P3 尚未完成、拒绝码 35 个、在线 source-action 未接线、受控故障尚无真实校准。这些与后续代码和阶段报告冲突；当前状态按本页分类和[当前进度](../CURRENT_PROGRESS.md)，历史冻结报告按其记录时版本解释。
- [`CURRENT_PROGRESS.md`](../CURRENT_PROGRESS.md) 顶部曾把 UART 链证书和路由见证概括为 0；同页后段已记录 2026-10-08 的独立 UART 链证书与新运行自身的路由见证。两种证据的作用域不同，不能把“旧验收运行上为 0”外推到后续新运行。
- P4 的[历史阶段报告](../reports/current-dataflow-p4-stage-acceptance-20261008.md)写 8/8，今天的 P4 复核只有 48 项测试通过、完整套件被主动停止；[复现手册](first-step-p1-p5-20261008.md)已分栏说明。
- 文档相对链接检查覆盖 592 个 Markdown 文件、1183 个链接（含 `runs/` 说明），`broken=0`（本次命令退出 0）；这只证明路径与标题锚点可解析，不证明内容结论正确。

## 后续处理顺序

1. 修正首步 `run --replay` 的记录格式和对应真实调用链测试；在修复前使用阶段报告的独立 replay CLI 命令。
2. 让配对身份先决条件对缺失字段保持 `unverified`；重新核对依赖“可比”的新报告。
3. 为 P4 套件提供真正低内存的只读复核模式，或把大对照单独执行且输出定向到新路径。
4. 如需重新证明**当前源码**的真实 RTL 能力，先冻结源码/配置/工具链与输出目录，再按各阶段报告安排有界运行和 fresh replay；本次文档整理没有执行该步骤。
