# Ibex＋OpenTitan UART 在线双源试点

日期：2026-10-06。本报告只记录固定 Ibex＋OpenTitan UART 组合，组件分别在真实 RTL harness 中运行；跨组件使用事务、事件与持久状态，不构造完整 SoC 总线。

## 运行方式与输入

CPU 源是在线 RV32I 指令片段。UART 源是外部 RX 字节，每个 source action 在同一 UART 实例上排入一帧，支持不同字节及重复字节；计划记录本地调度 tick，fresh replay 校验该 tick。UART 的 8N1 波形、FIFO、IRQ 和 MMIO 返回均由真实 RTL 产生。TXDATA 专用 SW 变异把写值约束到 8 bit；已由 UART 输出或持久 RAM 决定的 CPU 输入不再随机覆盖。

通过 Python API 创建 `make_ibex_uart_online_runtime(cache_dir=Path('/tmp/myfuzz-ibex-uart-online-cache'), run_id='uart-online-short-fixed')`，再调用 `run_scenario_rfuzz_live`，参数为 `duration_seconds=30`、`max_tests=12`、`search_seed=20261006`、`max_runs_per_batch=1`。这次运行使用受监督 elaboration。随后修复了 direct elaboration fallback 的闭包哈希：显式文件哈希不符时，纳入声明的 include-root 文件再与固定 SHA256 比较；强制无监督路径下的真实 Ibex＋UART 启动已通过。该修复发生在本报告 12 例运行之后，完整 CLI 搜索仍需在新源码版本回归。

## 真实 RTL 短跑

保存的 [`12 例 plan`](../../runs/ibex-uart-online-20261006-12case/online_plan.json)、[`trace`](../../runs/ibex-uart-online-20261006-12case/online_final_trace.json) 与 [`report`](../../runs/ibex-uart-online-20261006-12case/report.json) 来自 12 例 RFuzz 搜索。12/12 状态为 `complete`；CPU 指令源选中 1 次，UART RX 源选中 11 次。有效搜索 16.850 秒，约 0.71 例/秒，不含构建与固定 warmup；该运行版本每例固定推进 1000 轮，是当时主要吞吐瓶颈。记录中有真实 UART RX watermark、CPU IRQ 输入采样、CPU 对 UART 的 MMIO，以及后续 RXDATA 真实读取；最后一个 RX 字节在会话结束时仍排队，说明 pending 状态跨例保留。该运行在其源码版本上 fresh replay 匹配。

plan SHA-256：`8eb1d8f4ef70b90169aef27c45f7e09aee24b703df58fa270bcd0533531140be`；trace SHA-256：`9d7a7b8da49c56cfd2e3f0f2e577438817aca5a6321e3d16c25b679902670b0c`。原始 RFuzz 回执、decoder manifest 与 client log 同目录保存。

另有 [`定向 2 例计划`](../../runs/ibex-uart-online-20261006-directed2/online_plan.json)、[`trace`](../../runs/ibex-uart-online-20261006-directed2/online_final_trace.json) 和 [`复现脚本`](../../runs/ibex-uart-online-20261006-directed2/reproduce.py)。CPU 指令源经真实 Ibex MMIO 写入 UART TXDATA `0xa6`，IP 侧同时注入外部 RX 字节；2/2 完成并在当时版本 fresh replay 匹配。该定向运行结束前，新 RX 字节尚未被 CPU 读取，因此不声称它单独证明了完整 IP→CPU RXDATA 闭环。两组运行的源码 manifest 不同，不能混作同一版本的 replay 对照。

## 检查范围与待完成项

`IbexUartOnlineChecker` 对已经观察到的 RXDATA MMIO read，检查低 8 位与按序注入字节一致；对 CPU 已消费的 data response，检查 rdata 等于 UART 的真实返回值。缺少 IRQ、读取或 ISR 不自动判定为 DUT bug，而是保留为覆盖缺口；定向 TXDATA 写入另由真实 MMIO delivery 记录核对。

- 当前工作区已改为分类型固定调度：CPU case 96 个 paired advance，RX case 914 个 UART-only 加 320 个 paired advance；尚无当前版本同预算性能对照。进一步动态缩短推进须定义 source-associated RTL RX 完成、pending 状态保留及实际执行前缀的 replay 规则，不能将波形发送结束当作接收完成。
- P1 已在最终稳定源码上通过 CLI 单 CPU case（含固定 RX warmup）及完整 fresh replay，见 [P1 身份报告](current-dataflow-p1-cli-identity-20261006.md)；当前版本多例双源搜索与效率对照仍待验证。
- 在同一固定源码版本上重复双源搜索、断言和 fresh replay，并扩展到 SPI/I2C 等异构外设。
