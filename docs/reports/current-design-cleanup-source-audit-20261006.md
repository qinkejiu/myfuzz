# 当前方案仓库清理：源码与文档引用审计

日期：2026-10-06。范围：静态引用与工作区状态审计；未运行测试，未改变 RTL 或 runtime 语义。

## 目标口径

当前主方案是由总控环境初始化独立 CPU/IP harness，以程序镜像中的目标指令、外部 IP 源或中断场景组成连续 testcase；真实 RTL 的事务、数据和事件依据 Dependency Path 在跨周期/跨组件间传递。输入所有权、局部协议、持久状态、断言、覆盖和 replay 的范围见 [`CURRENT_DESIGN.md`](../CURRENT_DESIGN.md) 与 [`LOCAL_HARNESS_RUNTIME.md`](../LOCAL_HARNESS_RUNTIME.md)。

清理判据：可证明不被当前源码、测试、配置、CLI 或可重放证据引用的文件才移出；历史实验和单独路线若仍可运行或被引用，就标成历史/可选，不伪称为当前能力，也不按名称直接删除。

## 已移出项目的无关或弃用代码

以下文件在移动前均无 tracked/untracked 工作区修改；保留原始文件模式和字节，SHA-256 已写入外部清理快照 `/home/qinkejiu/myfuzz-cleanup-backup-20261006.MjDhe4/excluded-files-manifest.json`，原文件副本在同一快照目录的 `excluded-files/` 下。

| 原路径 | 审计结论 | 处理 |
|---|---|---|
| `scripts/codegen/generate_constrained_harness.py` | 早期 Ibex 单 harness 生成原型；全仓无调用点 | 移至仓库外，可恢复 |
| `scripts/codegen/generate_lightweight_harness.py` | 固定端口切片原型；全仓无调用点 | 移至仓库外，可恢复 |
| `scripts/codegen/generate_naive_harness.py` | 自身注释标明只作概念演示且建议跳过；全仓无调用点 | 移至仓库外，可恢复 |
| `scripts/delete_codex_conversations_for_workspace.py` | workspace 管理工具；无 fuzz runtime/test/config 调用点 | 移至仓库外，可恢复 |
| `scripts/maintenance/clear_codex_history.py` | Codex 历史管理工具；无 fuzz runtime/test/config 调用点 | 移至仓库外，可恢复 |

## 当前方案的保留源码

- `src/myfuzz/scenario/`：Genome、DependencyGraph、ScenarioRunner、Router、Scheduler、memory/state、feedback、checker 和 replay 构成所需场景执行层。
- `src/myfuzz/local_harness/`：真实 CPU/IP session 与生成器被多个已验收 harness 使用。
- `src/myfuzz/protocols/`：协议插件、RTL adapters/peers/checkers 是本地 harness 的输入约束基础。
- `src/myfuzz/harness/`：虽然名字来自较早 harness 工作，但目前仍被 `composition.input_layout`、`integration`、测试和 campaign 引用，不能作为孤儿源码删除。
- `src/myfuzz/composition/component_profile.py`、`source_crawler.py`、`interface_description.py`、`soc_port_dispositions.py`、`cva6_source_closure.py` 等共享源码事实、端口事实或 profile 逻辑被当前 `local_harness`/`scenario` 导入。

## 独立的历史 SoC 生成路径

`src/myfuzz/integration/soc_builder.py` 和 `soc_matrix_smoke.py` 不是当前主方案。静态引用显示它们仍被 `soc_campaign.py`、`soc_comparison.py`、RFuzz simulator/replay、`soc_boot_program.py`、`soc_candidate_program.py`、`scripts/run_soc_campaigns.py` 和多项 `tests/integration/test_soc_*.py` 引用。对应 `configs/soc/`、生成脚本和报告还提供该路线的复现证据。

因此本轮只将其从主 README/文档入口降为独立历史/可选路线；没有删除其运行时代码、测试、配置或证据。`composition/` 中存在跨路线共享模块，按目录批量移动会破坏独立 harness 构建，后续若要彻底从仓库移除整条旧路线，必须先把共享 helper 拆到路线无关的位置并更新所有旧测试/replay 依赖。

## 保留的数据与材料

- `SoC内部数据流动与去向.docx` 是当前设计来源，保留。
- `trace_hart_0.dasm` 与 Word 的 `Zone.Identifier` 按之前记录的保留约定继续保留；本轮没有把它们误判为垃圾。
- `runs/`、`.downloads/`、`.worktrees/`、`third_party/` 未作目录级清理。检查时分别约 69 GB、2.8 GB、811 MB、1.2 GB；包含证据、下载物、未登记工作副本和真实 RTL。
- 全部预存 Git 修改及新增文件均未清理；开始前快照见外部 `myfuzz-cleanup-backup-20261006.MjDhe4/`。

## 文档整理结果

- 新增 `docs/CURRENT_DESIGN.md` 作为当前设计说明。
- `README.md`、`QUICKSTART.md` 和 `docs/README.md` 将独立 harness 方案置于当前入口，旧 SoC composition 降为单独历史路线。
- `docs/PROJECT_GOALS.md` 加注历史状态，没有改写或销毁 2026-09-14 规格。
- `docs/REPOSITORY_ORGANIZATION.md` 更新为当前清理边界及备份记录。
- `scripts/README.md` 说明当前脚本入口以及已移出原型。

静态检查：9 个当前入口/台账 Markdown 文件的本地链接检查 `0` 个断链；`git diff --check` 通过。按要求未运行测试，也未声称 runtime 回归已通过。

## 同日第二轮：代码与实施计划组织

新增 [代码组织图](../CODE_ORGANIZATION.md)、[唯一当前实施计划](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)、[计划索引](../superpowers/plans/README.md)和[报告索引](README.md)。现行入口进一步标出 `integration/scenario_*` 的 RFuzz/campaign 职责；`python -m myfuzz` 仍指向旧 SoC 矩阵，仅更新 help 描述以避免误认。统一当前 CLI、路径到真实绑定预检、目标动作 testcase、在线 RFuzz batch 和覆盖引导变异列入后续代码门禁，没有在本轮把这些能力写成已完成。

2026-06 的 CPU/IP 实验计划、2026-09 的 SoC 目标、持续场景旧计划与其早期 OpenTitan-only 范围均加注历史/基线状态。旧交接文件的 3 个失效 worktree 文档链接改指仍在仓库的历史文件。两份历史报告各自引用的 6 个 `runs/` 文件当前缺失，已改为原路径文字并明确其原始证据不可在本工作区核验；报告数字仍按原记录保留，不计当前方案验收。

第二轮未再移出源码、配置或证据。全仓 `docs/` Markdown 加根目录 `README.md`、`QUICKSTART.md` 共 242 份的本地链接检查为 `0` 个断链；`python -m myfuzz --help` 正常显示旧路线身份，`git diff --check` 通过。未运行 RTL 或功能测试。
