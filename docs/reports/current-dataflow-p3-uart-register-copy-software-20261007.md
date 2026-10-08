# P3 UART 寄存器复制来源证书：软件门禁

日期：2026-10-07。范围：UART 原始接收/读事务证据认证的退休 `LW` 目标寄存器版本，经实际形态的 CPU RVFI 退休 `ADDI rd, rs1, 0`，传播到新目标寄存器版本。

## 实现与证据边界

`src/myfuzz/scenario/uart_register_copy.py` 内嵌原始 `UartOperandSeedTracker`，只接受其重新生成的 UART load seed，不接受外部提交的 accepted 标签。复制必须具备完整 `cpu_retire.v2` post 回执、实际 RVFI 物理字段一致性、独立递增的 native receipt、精确的 `ADDI` 编码和 `imm=0`、`rs1`/`rd` 编码与 RVFI 一致、`rd_wdata == rs1_rdata`、无 trap/抑制/内存副作用。证书同时保存源寄存器版本 key、目标版本 key、实际 post 引用、原始 UART admission 与 seed 证书哈希。

只传播已测量的低 8 位来源；高位、整字和通用 ISR 来源继续为 `unknown`。迟到 UART seed 仅可回填已经在退休时捕获了准确源版本 key 的待决复制。连续复制按历史版本依赖顺序处理。已覆盖寄存器同值也不可复用旧证书。待决容量耗尽、原始证据不完整、epoch 错误、flush 会使该 scope 失效；经物理 reset 且 epoch 递增才可恢复。

## 软件验证

命令：

```sh
PYTHONPATH=src:. pytest -q tests/scenario/test_uart_register_copy.py tests/scenario/test_uart_operand_seed.py tests/scenario/test_uart_operand_use.py
```

结果：100 passed，包含 `rs1`、`rd`、读写值、epoch、退休顺序、trap、内存副作用、旧版本、flush、reset、迟到 seed、连续两步复制、畸形事件及待决容量负例。

## 仍需真实 RTL 门禁

当前证据是实际格式回执的软件模拟，尚无真实 UART 程序执行 `ADDI rd, rs1, 0` 的 RTL trace。最小真实程序变体是在既有 UART ISR 的 `lw x3, UART_RDATA` 后增加 `addi x4, x3, 0`，并以 `x4` 作为后续 `sw` 的数据寄存器。需要冻结完整运行源码、取得带 CPU retirement 的在线 trace，执行独立证书重建与完整 fresh replay。现有 `UartOperandUseTracker` 只识别直接 UART seed 版本用于 `SW rs2`，因此即便复制证书真实成立，复制后的 SW 消费证书仍需下一步显式接入，不能宣称 `LW→ADDI→SW→RAM` 全链完成。
