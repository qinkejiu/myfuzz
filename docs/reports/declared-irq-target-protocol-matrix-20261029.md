# 通用声明式 IRQ target 协议验收矩阵，2026-10-29

同一个 `run_timer_irq_smoke.py` 按实际 artifact kind 选择已有 target session，配置提供输出 port/bit、真实MMIO trigger和CPU profile；`declared-output.v1` 只认证native输出transport，不新增IP source contract。以下各项都独立核对 raw target handshake、输出、OR/CPU input、native take/serial及同调用独立fresh进程。

| target协议 / 原组件 | CPU | 实际触发及输出 | 已验范围 |
| --- | --- | --- | --- |
| APB3 / PULP SPI | Ibex、CV32E20 | INTCFG `0x24=0x80000000`，threshold `events_o[0]` | [两CPU raw验收](declared-irq-spi-acceptance-20261029.md)；非EOT/串行传输 |
| Wishbone / ZipTimer | Ibex | 唯一4-byte COUNT窗口写8，真实`o_int`单周期输出 | [注册ACK及raw验收](declared-irq-spi-acceptance-20261029.md#后续-target-协议复用ziptimer-wishbone)；无RTL地址port，SEL忽略 |
| AHB-Lite / Caliptra SHA256 | CV32E20 | `0x800=1/0x804=1/0x81c=1`，software-triggered sticky `error_intr` | [三次address/data阶段及raw验收](declared-irq-ahb-sha-acceptance-20261029.md)；非digest/HRESP错误 |

各项fresh均为同调用独立新进程，不声称cross-CLI。host pulse是显式delivery策略，不把sticky level改称原生pulse。所有结果均保留internal cause/version/origin unknown、ISR MMIO unknown，不授予完整F5/F6或奖励；未穷举CPU×IP矩阵。原Timer强source adapter仍可独立选择，通用弱transport没有替代它的源语义合同。
