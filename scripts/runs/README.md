# 专题运行与证据工具

这里只保留仍被测试、复现步骤或专题报告使用的场景和证据工具。日常命令见[脚本首页](../README.md)，早期方案对照已归入[历史 scheme 工具](../legacy/README.md)。

| 类别 | 入口 |
|---|---|
| P4/P5 证据审计与 replay | `audit_p4_uart_compute_store.py`、`replay_p5_online_verified.py`、`summarize_p5_online_timing.py` |
| 保存 trace writer 性能复核 | `benchmark_p5_trace_writer.py` |
| 受控 UART fault 运行 / replay | `run_p5_uart_read_fault.py` |
| 生成式双 GPIO 场景 | `run_generated_ibex_two_gpio_10min.py` |
| Static / sequential campaign | `run_static_projection_campaign.py`、`run_sequential_coverage_pilot.py` |
| Ibex/OpenTitan real-IP pilot | `run_ibex_opentitan_real_ip_pilot.py`、`build_rfuzz_compat_server.py` |

2026-10-25 删除了六个无调用的一次性 launcher；2026-10-26 将十四个仍有历史复现用途的 scheme 工具成组迁往 `scripts/legacy/`。仍被测试和证据消费者使用的本目录十个工具保持原路径。恢复清单分别位于 `runs/repository-organization/20261025-deep/` 与 `runs/repository-organization/20261026/`。
