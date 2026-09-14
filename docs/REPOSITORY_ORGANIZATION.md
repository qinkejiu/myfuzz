# 项目代码与文件整理台账

日期：2026-09-14。本轮已执行文档入口整理；代码迁移在实施计划 P0/P2 中按验证门禁逐项执行。

## 工作区与所有权

- 根目录 `/home/qinkejiu/myfuzz`：旧 composition-core 分支与用户交接入口。
- 当前开发 `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`：已有 CPU 自动接线、协议运行时和 RFuzz 实现。不得在根目录复制一套新实现。
- 其他 integration/harness-runtime worktree：保留，清理前核对未合并提交和被引用路径。
- 当前已知用户修改：`.superpowers/sdd/task-2-report.md`、`docs/系统总览与RFuzz约束组合示例_20260909.md`。本轮不覆盖。
- 未跟踪 `third_party/` 含上游源码及实核证据；不因 untracked 就视为缓存。

## 路径处置表

| 路径 | 职责/现状 | 处置 |
|---|---|---|
| src/myfuzz/frontend、scripts/source_branch_instrumenter.py | 前端、插桩 | 保留，接入新 top 的 CPU/IP 内部覆盖 |
| src/myfuzz/composition/source_*、interface_description.py、endpoint_capabilities.py | 来源与接口事实 | 保留复用 |
| composition/auto.py | 老 catalog 与 generic planning 混合 | P2 抽取 generic planner，旧入口兼容委托 |
| composition/protocol_composer.py | 老 wrapper、generic、processor renderer 混合 | P2 抽取 renderer，再改动新行为 |
| composition/contract_transducer.py、coherent_memory.py、transducer_rtl.py | 指令/内存与总线语义 | P4 限定为内存目标，保留版本化旧模式 |
| composition/processor_*、protocols/rtl | CPU 边界和协议后端 | 保留；新增 target-side adapter 与 N 源仲裁 |
| integration/real_cpu_campaign.py | 旧单 personality 契约模式 | 保留旧复现入口；新 campaign 单独实现 |
| integration/rfuzz_*.py | 官方 RFuzz 传输与执行 | 复用，新增 harness 接入及覆盖证据 |
| configs/designs/*scheme*、toy/common IP | 历史实验、fixture | 标为 legacy/fixture；不得计入真实系列验收 |
| configs/cpus | 既有 profile 混有 reference-only 模板 | P1 检查 source-backed 可用性；状态来自验证结果 |
| docs/reports、ALL_TEST_RESULTS_MASTER.md | 历史证据 | 保留、追加；新结论注明源码 hash |
| docs/superpowers/plans/2026-07-*、2026-09-0* | 旧计划 | 历史参考；新目标由 PROJECT_GOALS.md 统领 |
| runs、artifacts | 可再生产物和保留证据 | 逐目录分类；语料、pin、报告、失败记录先归档 |
| projects、根目录 PPTX、Zone.Identifier、clear_codex_history.py | 用户素材/独立工具 | 不纳入代码清理删除集合 |

## 清理执行规则

1. 先建立精确路径清单：tracked/untracked、大小、用途、引用、所属任务、可重建命令与处置理由。
2. 检查 Python import、CLI、配置 source/filelist、文档命令和保留语料重建依赖。无引用不是删除充分证据。
3. 优先更新入口、抽取职责和保留兼容 wrapper。每次迁移一个职责，不混入协议行为变更。
4. 可移除产物先移入 `runs/quarantine/<batch>/`，记录原路径、目标、内容 hash 与恢复方式；默认不永久删除。
5. 第三方源码、脏文件、用户素材和未合并工作树不自动隔离。依赖失效、回归失败则停止本批迁移并按映射恢复。
6. 完成时列出实际迁移/删除清单。本轮实际迁移与删除数量均为零；整理成果是当前文档入口、目标、实施顺序和代码处置台账。
