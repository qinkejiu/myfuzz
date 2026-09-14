# SoC 实施进度（2026-09-14）

计划：`docs/superpowers/plans/2026-09-14-soc-composition-and-fuzz.md`。
执行起点：`029840a`，工作区 `.worktrees/ibex-protocol-longrun`。

## 任务状态

- P0：完成。审计与可恢复隔离工具 + 30 个定向测试；首轮对抗式复审 FAIL 的 7 项缺陷与第二轮 6 项新增缺陷全部修复并回归。
- P1：完成。两款 CPU 与三系列六个真实外设来源、elaboration closure 与能力事实全部固定并可通过 `scripts/verify_soc_sources.py --elaborate` 重放。
- P2：完成。`generic_planner.py` / `processor_renderer.py` 抽取完成，旧入口保持同名转发，改动前后对同一 fixture 矩阵产出的 IR/SV/source list 与 hash 完全一致。
- P3–P16：未开始。

## 本轮基线

`PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend -q`
实际结果：4 tests / OK。未把该定向结果称为全量基线。
Verilator 5.051 与 Icarus Verilog 在用户本地工具目录可用；主机约 7.5 GiB RAM，单构建/单运行。

## P1 实际结果

| 组件 | 顶层 | closure 文件 | lint | 状态 |
|---|---|---|---|---|
| opentitan_uart | uart | 48 | 0 error / 4 warning | elaboration_verified |
| opentitan_gpio | gpio | 42 | 0 error / 1 warning | elaboration_verified |
| pulp_gpio | apb_gpio | 1 | 0 error / 2 warning | elaboration_verified |
| pulp_spi | apb_spi_master | 7 | 0 error / 10 warning | elaboration_verified |
| pulp_spi_dependencies | spi_master_controller | 4 | 0 error / 5 warning | elaboration_verified |
| zipcpu_uart | wbuart | 4 | 0 error / 0 warning | elaboration_verified |
| zipcpu_timer | ziptimer | 1 | 0 error / 0 warning | elaboration_verified |

证据：每个组件一份 `configs/soc/closures/<id>.json`（命令、include/define/参数、closure 文件 sha256、能力结论与不支持项），lock 记录其 sha256；`verify_soc_sources.py` 重新读取并逐文件比对磁盘字节与 pin 版本 git blob，`--elaborate` 再重放命令。
ibex 与 cva6 仍为 `elaboration_unverified`：真正实核属于 P10/P11，本轮不提前声明。
六个外设的 runtime 一律 `runtime_unverified`，未跑过仿真。

## 保护范围

用户修改的 `.superpowers/sdd/task-2-report.md` 和中文系统总览保持原状。
不触碰未跟踪的第三方源码或历史语料。不自动 push。不整体 `git add`。
