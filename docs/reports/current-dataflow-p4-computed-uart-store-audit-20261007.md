# P4 CPU 计算值到 UART 字节写的受限架构审计

日期：2026-10-07。本审计复用 [UART WDATA `SB` 真实门禁](current-dataflow-p4-sb-uart-byte-real-gate-20261007.md)已冻结的源码和 63,830 事件 trace；没有启动新的 RTL 运行，也不改变原始证据。原报告记录了快照身份、9/9 在线例、完整 fresh replay 及 UART 真实串口输出。

新增 `scripts/runs/audit_p4_uart_compute_store.py` 从原始事件检查连续 RVFI order、PC、有效退休、指令编码、寄存器读写、精确 instruction action ID、Store retirement match 的 data 事务完整键、accept/response 地址与字节使能、UART WDATA 投递及串口输出计数变化。测试先因审计函数未实现而失败；独立审查指出事务、有效位及 reset 顺序漏验后，新增负例再次先失败再修复。最终 `PYTHONPATH=src:. python3 -m pytest tests/integration/test_p4_uart_compute_store_audit.py -q` 为 **14 passed**，涵盖值、事务、错误响应、无效退休、跨 epoch、迟到的指令匹配及投递后 reset。

复核命令：

```bash
python3 scripts/runs/audit_p4_uart_compute_store.py \
  --trace runs/current-dataflow-p4-sb-final-online-20261007/online_final_trace.json \
  --action-id 'online-2-604caae5c07e4c776cb357d1:cpu.online_instruction' \
  --output runs/current-dataflow-p4-sb-final-online-20261007/compute_store_audit.json
```

命令退出 0。[审计结果](../../runs/current-dataflow-p4-sb-final-online-20261007/compute_store_audit.json)记录相同 action ID 的连续 order 161～164：`LUI x2` 生成 0、`ADDI x2,x2,12` 生成 `0x0c`、`LUI x1` 生成 `0x40000000`、`SB x2,28(x1)` 实际读到 `0x0c`。四次退休各有 accepted 的同源取指匹配。`SB` 的 data accept、UART `mmio_delivery` 和 data response 使用同一完整事务键；投递事件 25150 为 `be=1`、`write_value=0x0c`。串口计数从 0 到 1，事件 28002 的实际 `serial_tx_last=0x0c`。

这是固定指令片段的**架构寄存器顺序关联**：RVFI 的连续退休和寄存器值排除了该片段中 x2 被另一条退休指令覆盖；retirement match、data accept/response 和 MMIO 投递的事务键与地址/字节值一致。串口输出仅由投递前后计数与无 reset 的观察顺序关联，缺少 UART TX FIFO 内部硬件来源 token，不能解释为逐字节内部因果证明。目前只检查一个字节、一个 UART 寄存器和一条实际 `SB`，不计作通用 CPU 计算→IP 数据流证书或 P4 整阶段验收。
