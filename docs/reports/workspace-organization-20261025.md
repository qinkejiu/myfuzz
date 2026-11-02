# 工作区整理 — 2026-10-25

本轮整理入口、职责导航与根目录散落产物；源码模块与冻结输入路径保持原位。

## 交付

- [工作区地图](../WORKSPACE_MAP.md)：当前代码、配置、命令、证据、依赖与历史目录的定位和放置约定。
- 根 README 与[文档首页](../README.md)按任务分组，进度统一指向 `CURRENT_PROGRESS.md`。
- [脚本首页](../../scripts/README.md)由历史流水改为命令导航；原 398 行完整保存在同目录 `HISTORY.md`，字节比对一致。
- [配置首页](../../configs/README.md)、[源码导航](../../src/myfuzz/README.md)、[集成层导航](../../src/myfuzz/integration/README.md)、[测试导航](../../tests/README.md)补齐职责边界。
- 旧 workspace inventory 显式标为历史快照；4 份普通文档中的 8 个错误链接修正。
- 根 `trace_hart_0.dasm` 已移至 `runs/quarantine/folder-organize-20261025/files/`，内容 SHA-256 一致，带 manifest 与恢复命令。

## 验证与边界

新增及重写入口的相对链接逐项验证，无缺失目标；全仓文档检查由 **129** 条断链降至 **121** 条，未新增断链。剩余项目包含已丢失的历史产物、归档输入副本内的原始相对链接及旧任务记录，原始证据不改写。完整 before/final 结果、入口原文和验证摘要位于 `runs/repository-organization/20261025/`。

本轮没有移动 Python 模块、合并 scenario/scenarios、删除运行目录、修改上游源码或改变验收结论；没有运行 native、RFuzz、构建或远程 gate。目录整合属于分批进行的工作：后续源码迁移需先核对引用与冻结 source map，当前成果是导航、文档归类和一项可恢复的实际文件迁移。
