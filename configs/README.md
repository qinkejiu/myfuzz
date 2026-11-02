# 配置导航

当前独立 CPU/IP harness 的组件输入从 `cpus/` 和 `peripherals/` 查起。源码版本、协议和参数以具体 profile 为准；有配置不等于通过真实运行验收。

| 目录 | 内容与用途 |
|---|---|
| [cpus/](cpus/) | CPU profile、接口与 harness 声明 |
| [peripherals/](peripherals/) | IP profile、寄存器与源码契约 |
| [scenarios/](scenarios/) | 具体组合实例，包括 compiled F2/F4/F6 相关场景 |
| [scenario/](scenario/) | 既有固定场景、种子与测试声明；与 `scenarios/` 并存，调用者按精确路径读取 |
| [behaviors/](behaviors/) | 设备行为声明（F5 触发/状态/清除、引脚模型、DMA 控制状态位）；与协议适配分离，见[行为声明](../docs/inprocess-behavior-declarations.md) |
| [campaigns/](campaigns/) | campaign 输入 |
| [experiments/](experiments/) | 对照实验配置 |
| [soc/](soc/) | 历史完整 SoC 配置，以及当前仍复用的源码锁和闭包 |
| [designs/](designs/) | 早期 design-flow 输入与对照设计；供 `src/myfuzz/scripts/run_design_flow.py` 等使用 |

`designs/` 中的 smoke、Ibex、CVA6、XiangShan、BOOM 和 Verilog IP 配置仍保留。它们与独立 harness profile 的验收口径不同。

不要直接合并 `scenario/` 与 `scenarios/`，也不要按 `soc` 前缀删除配置：代码、测试、source-lock、归档 manifest 可能依赖原路径。组件支持范围见[运行能力](../docs/LOCAL_HARNESS_RUNTIME.md)，当前状态见[进度](../docs/CURRENT_PROGRESS.md)。
