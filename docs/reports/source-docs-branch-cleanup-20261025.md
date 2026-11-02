# 代码、文档与本地分支整理 — 2026-10-25

本轮实际删除 **7 个无仓库内调用的旧代码文件**，分类迁移 **13 份文档**，删除 **1 个已合入的本地分支**。现有实现、测试、RTL、原始 evidence 和未合并工作树保留。

## 代码处置

AST 扫描范围是 `src` 549、`scripts` 125、`tests` 1080，共 1,754 个 Python 文件。无直接 import 的候选继续核对源码路径、配置、动态加载、普通文档和冻结记录。七个删除文件在本轮操作前均为已跟踪、与 HEAD 字节一致的文件，原文、mode 与 SHA-256 已备份。

| 删除文件 | 处置依据 |
|---|---|
| `src/myfuzz/integration/cli.py` | 只有早期实施计划提及 `run_pipeline_cli`，无当前调用/导出；统一 CLI 和 pipeline 本身保留 |
| `scripts/runs/run_cva6_scheme1_vs_scheme4_plus2_4h_resume.py` | 无调用的一次性 plus2 参数 launcher；共用 runner 与配置保留 |
| `scripts/runs/run_cva6_scheme1_vs_scheme4_plus3_4h_resume.py` | 无调用的一次性 plus3 参数 launcher；共用 runner 与配置保留 |
| `scripts/runs/run_ibex_lsu_targeted_sweep_1000s.py` | 无调用的早期 LSU sweep launcher |
| `scripts/runs/run_ibex_multicomponent_baseline_vs_depaware_1h.py` | 无调用的旧固定时长对照 launcher |
| `scripts/runs/run_ibex_opcode_mix_sweep_1000s.py` | 无调用的早期 opcode sweep launcher |
| `scripts/runs/run_ibex_uart_gpio_short_campaign.py` | 无调用的逐例保存/重放旧短测入口；当前场景、RFuzz 和场景工厂保留 |

保留三个静态扫描候选：`_reference_supervisor.py` 由子进程路径启动；BOOM coherent verifier 是已记录的 CLI；frontend TOML 工具通过路径加入 `sys.path` 后使用。两组相同 r11 脚本是当前入口和冻结副本，不能按重复字节删除。P5 UART fault 的独立 run/replay 工具也保留。

历史冻结 source map 中的旧文件记录未改写，它们只描述其原始归档；本轮清理不授予当前源码任何旧 gate 的通过身份。

## 文档分类

- [history/experiments/](../history/experiments/)：八份早期实验计划、scheme 说明与结果汇总。
- [history/](../history/README.md)：旧 composition guide、脚本任务流水、拆分前完整进度页。
- [reference/](../reference/README.md)：两份协议/ISA参考。
- [当前进度](../CURRENT_PROGRESS.md)：由 393,170 bytes 缩至 5,075 bytes，只保留状态、范围和证据入口；完整原流水保存在历史页。

所有迁移前原文均保留；迁移页只调整文档路径和相对链接。普通 Markdown 消费者随之更新，冻结 evidence 和归档输入副本保持原字节。根目录当前文档、专题历史与技术参考分别有导航。

## 分支

备份文件 `runs/repository-organization/20261025-deep/branches-before.bundle` 包含四个原始本地 heads 的完整历史，`git bundle verify` 通过。之后使用 `git branch -d` 删除本地 `stage2-declarative-cpu-ip-adaptation`：tip `f03220d9ac7e6043471ba5a87d8aba3455221b1f` 已为当前 HEAD 祖先，无独占提交、无关联 worktree。

`main`、当前 `codex/system-completion-20261016`、有7个独立提交的 native 分支及其脏工作树保留，所有远端 refs 保留。没有 fetch、远端删除、main 快进、历史重写或提交用户改动。分支表见[工作区地图](../WORKSPACE_MAP.md)。

## 验证与恢复

- 49 项 CLI、pipeline、reference-isolation 回归通过；首次沙箱运行因 `.git` 配额锁只读失败，经授权在沙箱外复跑通过，日志分别保留。
- 剩余 1,747 个 Python 文件 AST 解析无语法错误。
- 七个删除文件的原文哈希/mode、13 份迁移页的原文和目标哈希全部核对。
- 全仓文档检查仍为原有 **121** 条断链，逐条归一化对比未新增目标。
- 变更范围 whitespace 检查通过；独立只读复查无 actionable findings。
- 原有脏 source/test/config 路径仍在，Git worktree 登记前后相同；保留分支及 remote refs 的对象 ID 核对一致。

完整路径映射、SHA-256、原文、bundle、测试和文档日志在[本地恢复目录](../../runs/repository-organization/20261025-deep/README.md)。文件恢复使用该目录的逐文件原文，避免整树 reset 覆盖原有实现。清理目标是移除无调用旧入口并改善组织；没有运行 native、RTL 构建、RFuzz 或远程验收，也没有声称整个历史库零断链。

## 2026-10-26 继续整理

十四个仍有历史用途的scheme runner整体迁入 `scripts/legacy/`，保持同目录导入和相对于项目根的目录深度；文件字节与mode未改。`scripts/runs/`剩十个专题工具，测试和冻结入口继续原路径。根 `integration/` 和 `scripts/maintenance/` 两个空目录由非递归rmdir移除。

报告首页从232,486 bytes精简为约2 KB导航；旧文完整迁入 `docs/history/2026-10-26-report-index.md`。另建按九类组织的508份报告目录，避免首页重复维护所有历史测试数。普通历史实验页的脚本命令已更新，旧progress/script快照与原始evidence未改。

验证：全部1,747个Python文件在路径映射下字节一致，14份CLI help前后一致，原有121个断链目标未新增。扩展测试为95 passed、10 failed、54 subtests passed；原路径基线的同一static-campaign模块为10 failed、11 passed、44 subtests passed，十个失败ID相同，均因历史构建输入 `runs/designs/ibex_opentitan_real_ip_static_projection/instrumented/sources.f` 缺失，非脚本迁移产生。没有为获得绿色结果而删除测试或放宽源码身份检查。

只读独立复查指出旧索引中一个 `Store M[A]` 嵌套标签链接未被常规链接解析器识别，已人工修复为正确相对路径；对原始链接目标追加核对后无遗漏，复查无剩余问题。本轮未改变分支、远端refs或工作树登记。恢复说明和原文见[2026-10-26恢复目录](../../runs/repository-organization/20261026/README.md)。
