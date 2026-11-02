# 脚本入口

这里按用途导航。命令参数以各脚本的 `--help` 为准；真实 RTL、native 和远程 gate 按对应计划执行。

## 常用操作

| 用途 | 入口 |
|---|---|
| 统一 CLI | `PYTHONPATH=src python3 -m myfuzz --help` |
| 查询已有能力证据 | [query_capabilities.py](query_capabilities.py) |
| 生成单组件 / 多组件 harness | [generate_local_harness.py](generate_local_harness.py)、[generate_local_harness_set.py](generate_local_harness_set.py) |
| 场景记录 / 重放 / campaign | [record_scenario.py](record_scenario.py)、[replay_scenario.py](replay_scenario.py)、[run_scenario_campaign.py](run_scenario_campaign.py) |
| 编译数据流入口 | [run_compiled_dataflow.py](run_compiled_dataflow.py) |
| 单进程 F1–F6 原型 | [run_inprocess_f1f6.py](run_inprocess_f1f6.py)，组件和路径限制见[当前能力盘点](../docs/current-system-capabilities-20261101.md)；`--fuzz` 为同进程闭环变异，用法见[闭环使用说明](../docs/inprocess-fuzz-loop.md) |
| 闭环长跑/性能测量 | [run_fuzz_soak.py](run_fuzz_soak.py)（RSS/吞吐）、[measure_fuzz_phases.py](measure_fuzz_phases.py)（准备/会话/DUT 与事件层 A/B） |
| F1 程序退休核对 | [verify_f1_programs.py](verify_f1_programs.py)（真实 RVFI 退休/写回与参考模型比较） |
| 单进程 F5/F6 与定向反馈 | [run_inprocess_flow.py](run_inprocess_flow.py)、[run_inprocess_irq.py](run_inprocess_irq.py)、[run_inprocess_f6.py](run_inprocess_f6.py)；反馈规则在 [inprocess_feedback.py](inprocess_feedback.py) |
| F2 / F6 保存产物校验 | [verify_compiled_f2_rfuzz.py](verify_compiled_f2_rfuzz.py)、[verify_compiled_f6.py](verify_compiled_f6.py) |
| 冻结源码 Git metadata 准备 | [prepare_compiled_gate_source_metadata.py](prepare_compiled_gate_source_metadata.py) |
| 定向 IRQ 与原生就绪 | [check_irq_protocol_matrix.py](check_irq_protocol_matrix.py)（跨协议接入，仅构造）、[run_directed_irq_native.py](run_directed_irq_native.py)（`--preflight` 只校验声明） |
| 新路径覆盖率与可比性 | [measure_new_path_coverage.py](measure_new_path_coverage.py)（输入缺失时为 `unavailable`） |
| 文档链接检查 | `python3 scripts/check_doc_links.py` |
| 工作区只读审计与可恢复隔离 | [audit_repository.py](audit_repository.py)（先查看 `--help`） |

## 按工作类型找脚本

- `run_*`：运行和验收；`run_p2_*` 至 `run_p7_*` 对应各自阶段，不能相互替代。
- `verify_*`、`check_*`、`audit_*`：保存证据、边界与一致性检查；是否启动 RTL 以脚本实现为准。
- `report_*`：证据分析与报告；`bench_*`、`profile_*`、`measure_*`：性能测量。
- `generate_*`、`derive_*`、`prepare_*`：生成与准备输入。
- `run_soc_*`、`generate_soc.py`、`compare_soc_*`：历史完整 SoC 路线及兼容入口。
- `task5_native_completion_r11/`：r11 Task5 专用打包、控制器和审计材料。
- `verifier/`：验证器辅助文件；名称相似的脚本不能据此视为同一 gate。

[专题运行工具](runs/README.md)保留场景/证据入口；早期 scheme 对照脚本已移至[参考归档](../reference_archive/README.md)。当前 CLI、测试及冻结 gate 的脚本继续使用各自精确路径。

## 状态与历史

最新结论见[当前进度](../docs/CURRENT_PROGRESS.md)，模块关系见[代码组织](../docs/CODE_ORGANIZATION.md)，证据见[报告索引](../docs/reports/README.md)。

原 README 的 398 行任务记录已分类保存到[历史任务记录](../docs/history/2026-10-25-script-log.md)，迁移时调整了相对链接。其中的哈希、测试数和待办属于各自记录时点，不能视作当前源码的验证结果。
