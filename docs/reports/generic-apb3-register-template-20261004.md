# 通用 APB3 寄存器观察模板验收

`local_harness.v2` 可在固定源码、完整顶层端口和 `target.apb3/full-word` 合同下，使用同一 `apb3_register_observe` 模板运行 PULP GPIO 和 PULP Timer。两者只通过现有组件 profile 与请求中的 endpoint policy、输入归属配置区分；运行时不按组件 ID 选择生成器代码。既有 `local_harness.v1` 的 GPIO、Timer 等专用 session 保留。

模板将 32 位寄存器访问交给现有 APB3 beat 适配器，执行 APB setup/access 握手并观察实际 `PREADY/PRDATA/PSLVERR`。写操作只允许 `be=15`；未声明、重叠、超宽的非总线输入均拒绝。`fixed_inputs`、`environment_bindings`、`bound_bindings` 沿用逐字段唯一归属。动态源和真实输出绑定只改动其所拥有字段，已拥有字段不能再被 Fuzzer 随机覆盖。每个 testcase 使用同一 RTL 进程和寄存器状态；setup 写入只执行一次，后续 step、读回与 fresh replay 使用同一事务顺序。原生输出按物理端口记录，不推断 IRQ 或寄存器预期值。

真实 RTL 验收：

| 固定 RTL | 场景 | 结果 |
|---|---|---|
| PULP GPIO | APB 写 PADDIR/PADOUT，读回 PADOUT，观察 `gpio_out`，fresh replay | 通过 |
| PULP Timer | APB 写比较值及控制，读真实计数，观察 `irq_o`，fresh replay | 通过 |
| PULP GPIO | `gpio.pins.in` 声明为环境源，Genome 触发上升沿，观察真实中断脉冲，fresh replay | 通过 |

该模板的范围是 APB3 full-word 寄存器访问与引脚/IRQ 观察。它没有串行 peer、CPU 中断控制器、特定外设协议语义或任意 APB3 IP 自动运行保证。新 IP 仍须固定源码、完整 profile、端口归属和真实 RTL 验收。
