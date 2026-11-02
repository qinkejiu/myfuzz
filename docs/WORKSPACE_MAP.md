# 工作区地图

整理日期：2026-10-25。这里负责找文件；阶段结论统一查[当前进度](CURRENT_PROGRESS.md)，不从目录名推断支持程度。

## 日常工作区

| 路径 | 放什么 / 从哪里开始 |
|---|---|
| [src/myfuzz/](../src/myfuzz/README.md) | Python 实现；执行链和模块分工 |
| [configs/](../configs/README.md) | CPU/IP profile、场景、campaign、源码锁 |
| [scripts/](../scripts/README.md) | 生成、运行、测量、报告和验证命令 |
| [tests/](../tests/README.md) | 软件契约、RTL 与集成测试 |
| [schemas/](../schemas/) | JSON 数据结构 |
| [examples/](../examples/) | 示例及其输入 |
| [docs/](README.md) | 设计、说明、计划、报告与复现步骤 |

## 证据、依赖与历史

| 路径 | 用途 | 整理规则 |
|---|---|---|
| `runs/` | 当前与历史运行、缓存、夹具、归档 | 混合目录；逐项审计后处理 |
| [docs/reports/evidence/](reports/evidence/) | 原始证据、失败尝试、保存态输入 | 保留原路径和字节 |
| `.superpowers/sdd/`、`.sdd/` | 任务记录、审查、监督器和测试输入 | 部分为执行依赖；不能当聊天日志删除 |
| `source-git-metadata/` | 冻结 gate 使用的 exact Git pins 元数据 | 归入构建输入；由专用脚本准备与验证 |
| [third_party/](../third_party/)、[external_designs/](../external_designs/) | RTL、子模块与固定依赖 | 保留版本和本地修改 |
| [patches/](../patches/) | 上游补丁与应用说明 | 随源码身份保留 |
| `archive/`、`deliverables/` | 历史归档与交付材料 | 保留；不作为当前实现入口 |
| `.downloads/` | 本地工具及下载依赖 | 不按目录整体清空 |
| `.worktrees/` | 工作副本 | 先核对 Git 登记与未提交内容 |
| `reference_archive/` | 已移出运行链的历史脚本和审查报告 | 仅供参考；迁移清单记录原路径，不承诺直接运行 |

根目录 `agent.md` 是远端访问规则；`SoC内部数据流动与去向.docx` 是原始需求；`项目目标与后续任务交接.md` 是有调用引用的交接材料，均保留原位。

## 文档放置约定

- `docs/` 顶层：稳定的概念、使用手册、当前进度与导航。
- `docs/superpowers/specs/`：设计规格；`docs/superpowers/plans/`：实施和验收计划。
- `docs/reports/`：按日期和专题保存的结论；`docs/reports/evidence/`：对应原始材料。
- `docs/reproduction/`：复现、恢复和发布步骤；`docs/research/`：研究笔记；`docs/handover/`：交接。
- `docs/history/`：完整进度流水和早期实验；`docs/reference/`：ISA/协议参考。
- `docs/history/2026-10-25-script-log.md`：原脚本入口中的历史任务流水，链接随迁移调整。

新增产物归入相应目录。已有 Python 模块、配置和冻结包暂保留路径；要迁移时同时更新 import、CLI、filelist、测试、文档、source map 与 replay factory，逐批验证。

## 本轮整理记录

原始入口文件及 Git 状态快照保存在 `runs/repository-organization/20261025/`。变动说明见[整理台账](REPOSITORY_ORGANIZATION.md)，历史空间清理记录见[工作区清单](WORKSPACE_INVENTORY.md)。

## 本地分支（2026-10-25 整理后）

| 分支 | 处置 | 原因 |
|---|---|---|
| `codex/system-completion-20261016` | 保留，当前 checkout | 承载当前未提交的实现与整理 |
| `main` | 保留 | 跟踪 `origin/main`；未改写或快进 |
| `codex/native-exact-source-completion-20261018` | 保留 | 相对当前分支有 7 个独立提交，另一个 worktree 有未提交修改 |
| `stage2-declarative-cpu-ip-adaptation` | 已删除本地引用 | tip `f03220d` 为当前 HEAD 祖先，无独占提交、无关联 worktree；远端引用保留 |

所有原分支 tip 已打包并通过 `git bundle verify`。备份为 `runs/repository-organization/20261025-deep/branches-before.bundle`，恢复说明和逐文件清单位于同目录。原生 worktree 在 `/home/qinkejiu/.codex/worktrees/7c57/myfuzz`，本轮只读检查，没有清理其内容。远端分支未查询或修改，分支表依据本地已有 refs。
