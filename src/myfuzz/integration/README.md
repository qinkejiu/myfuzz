# 集成层导航

此目录保留已有 Python import 路径，按下列模块族定位职责。

| 模块族 | 职责 |
|---|---|
| `scenario_campaign.py`、`scenario_rfuzz*.py` | 持续场景 campaign、在线运行和 replay |
| `compiled_f2*.py` | F2 解码后的执行、读返回消费、反馈、布局与保存产物 |
| `compiled_f4*.py` | F4 构建、执行及 runtime path |
| `compiled_f6*.py` | F6 firmware/layout、DMA/IRQ、运行消费、RFuzz 及保存态语义核验 |
| `compiled_build_join.py`、`compiled_execution_files.py`、`compiled_rfuzz*.py` | compiled 路线共享的 build、文件与传输逻辑 |
| `compiled_git_source_metadata.py`、`compiled_process_audit.py`、`compiled_runtime_report.py` | 冻结源码身份、进程审计与报告 |
| `rfuzz_*.py` | RFuzz 工具链、仿真、FIFO/共享内存/wire 传输 |
| `ibex_*`、`cva6_*`、`cv32e40p_*`、`cvw_*`、`picorv32_*` | 已有组件或固定组合的运行入口，各自支持范围不同 |
| `generated_*`、`generic_rtl_campaign.py` | 生成的寄存器/存储访问与通用 RTL campaign |
| `dma_*` | DMA descriptor、UART 与 prefix replay 专题 |
| `soc_*`、`real_cpu_campaign.py` | 历史完整 SoC / 单 personality 路线和兼容入口 |

`compiled_f6_saved_semantics.py` 等保存态 verifier 与 live producer 必须独立核对原始证据；目录导航不改变它们的边界。真实通过项以[进度](../../../docs/CURRENT_PROGRESS.md)及对应[报告](../../../docs/reports/README.md)为准。
