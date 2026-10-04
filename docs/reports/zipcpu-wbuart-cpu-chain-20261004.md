# CVE2 ↔ ZipCPU Wishbone UART 跨组件验收

## 范围

本验收使用本地已锁定的 CVE2 RTL 和 ZipCPU `wbuart` RTL，各自在生成的独立 harness 中运行。`ScenarioRunner` 保存一个 testcase 内的 CPU、UART、RAM、事务和事件状态；`DataflowRouter` 把 CPU 已接受的 MMIO 请求交给 Wishbone UART，读响应取自 UART RTL。这里没有构造 Bus、Bridge、Crossbar 或精确的全局 SoC 时序。

Wishbone UART 的 `cpu_routed_mode` 要求 `source=None`，并禁止预置寄存器写入和 harness 自动读取 RXREG。因而 SETUP 与 TXREG 写只可能来自 CPU 真实 MMIO；外部 RX 字节由 Genome 的 `uart_rx_byte` 源选定，经 8N1 引脚波形进入 `rxuart`。路由器只返回 `wbuart` 的真实 RXREG 读值；该读同时真实弹出 RX FIFO。`uart_rx_int` 的真实电平绑定到 CVE2 `irq` 输入。

## 场景与断言

启动程序由 `MemoryImage` 提供给 CVE2，顺序执行：

1. `SW SETUP=25`，随后 `SB TXREG=0x41`；目标 Wishbone `STB` 每笔只出现一次。
2. UART TX 实际引脚的 8N1 帧被 peer 解码为 `0x41`。
3. Genome 取 `0x35` 或变异后的 `0xA6`；peer 逐位驱动真实 `i_uart_rx`，UART RTL 产生 RX FIFO 数据和 `uart_rx_int`。
4. `uart_rx_int` 经绑定交付 CVE2 输入；CPU 轮询程序随后真实读取 RXREG，并将低 8 位写入持久 RAM `0x20000`。断言 MMIO 读回与 RAM 值均等于当前 Genome 源字节。
5. 两个 testcase 各自保存 evidence bundle，并由 fresh runner 重新执行、比较语义哈希和 RAM 结果。

验收命令：

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_zip_wb_uart_real -v
```

在 2026-10-04 的独立工作树运行结果为 `Ran 1 test in 144.483s`、`OK`。一个测试方法完整执行两种源值和各自的 fresh replay。原有 Wishbone UART 真实用例为 2/2 通过；场景契约与生成 session 注册回归为 25/25 通过。

## 能力边界

这证明真实 CPU MMIO 配置/TX、真实 UART 串行 RX、真实 UART IRQ 电平到 CPU 输入、真实 UART RXREG 到 CPU RAM 的连续数据链。CPU 程序当前通过延时后轮询 RXREG 获取数据；未使能中断，也未执行中断处理程序，因此不声称已验证 CVE2 的 UART ISR。UART peer 固定单字节 8N1、25 local clocks/bit；访问不与活动 RX 波形重叠。此结果不代表任意 Wishbone UART、任意波特率或整颗 SoC 已通过。
