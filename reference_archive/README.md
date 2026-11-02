# 历史参考归档

本目录集中保存已移出当前项目运行路径的历史材料，仅供阅读和参考，不属于当前 CPU/IP 数据流执行系统的依赖。

- `legacy-scripts/`：早期 Ibex/CVA6 固定方案、时长对照、性能实验及阶段性定向验证脚本，分别来自 `scripts/legacy/` 和 `scripts/`。这些脚本及 `previous-readme.md` 保留原始内容，可能仍引用旧布局和旧配置；迁移后不承诺可直接运行，也不被当前入口调用。
- `docs/`：旧版 OBI 复用、AXI4-Lite UART 专项说明、历史交接文档及 `old-plans/` 下的早期实施计划，其结论以当时的组件和运行范围为准；交接文档保留原文，内部相对链接以原位置 `docs/handover/` 为准。
- `reports/`：从仓库根目录移入的 2026-10-28 专项审查记录，结论只适用于各自的历史时点。
- [migration-20261101.json](migration-20261101.json)：每个文件的原路径、归档路径、大小与 SHA-256。需要恢复时按清单复制回原位置；历史脚本的当前依赖未重新验证。
- [temporary-test-logs-20261101.tar.gz](temporary-test-logs-20261101.tar.gz)：从根目录收拢的 23 份临时测试日志；[索引](temporary-test-logs-20261101.json)保留原文件名和 SHA-256。
- [deleted-cache-20261101.json](deleted-cache-20261101.json)：已删除的历史 AXI-Lite 和 BOOM 探针构建缓存及影响；重新构建不能保证二进制哈希相同。

当前系统入口见 [脚本导航](../scripts/README.md)，当前能力见 [能力盘点](../docs/current-system-capabilities-20261101.md)。
