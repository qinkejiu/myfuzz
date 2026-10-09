# 第二阶段逐组合验收矩阵

更新：2026-10-09。第二阶段实施中；本页只登记新门禁，历史固定场景通过不自动取得 L1–L3 等级。实施起点见[基线身份](reports/stage2-baseline-20261009.json)，步骤见[实施计划](superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。

目前尚未进入 B 的等级预检：所有 declared/effective/verified level 都为未确定，L1/L2/L3 门禁均未验证。`pending` 不是 `skipped_unavailable`，后三核是否跳过须在 F 阶段重新核实。

| CPU | 功能族／IP | declared | effective | verified | 独立／8-case | 60 秒＋replay | 600 秒功能＋replay | 状态 |
|---|---|---|---|---|---|---|---|---|
| CVA6 | GPIO／pulp_gpio | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVA6 | UART／opentitan_uart | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVA6 | SPI／opentitan_spi_host | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVA6 | I2C／pulp_i2c | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVA6 | Timer／opentitan_rv_timer | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| BOOM | GPIO／pulp_gpio | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| BOOM | UART／opentitan_uart | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| BOOM | SPI／opentitan_spi_host | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| BOOM | I2C／pulp_i2c | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| BOOM | Timer／opentitan_rv_timer | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVW | GPIO／pulp_gpio | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVW | UART／opentitan_uart | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVW | SPI／opentitan_spi_host | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVW | I2C／pulp_i2c | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVW | Timer／opentitan_rv_timer | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| VexiiRiscv | GPIO／pulp_gpio | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| VexiiRiscv | UART／opentitan_uart | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| VexiiRiscv | SPI／opentitan_spi_host | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| VexiiRiscv | I2C／pulp_i2c | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| VexiiRiscv | Timer／opentitan_rv_timer | 未确定 | 未预检 | 未验证 | pending | pending | pending | pending |
| CVA6 | opentitan_hmac | 未确定 | 未预检 | 未验证 | pending | pending | 不适用（基础强制门禁） | pending |

CVA6 已有固定 profile／AXI4 closure 和历史组合证据；仍须迁移公共 CPU 契约并执行本阶段每行门禁。BOOM 本地有源码及 Chipyard pin，但没有对应 Chipyard checkout、生成 RTL／闭包，PATH 上也没有 Java/SBT/Mill。CVW、VexiiRiscv 在当前仓库没有源码 checkout、固定生成配置或 CPU profile。后三核条件复查不消除 HMAC 强制验收义务。

HMAC 原生 RTL 在本地；实施起点没有 peripheral profile。G1 的 protected core SHA 冻结尚未发生，必须在基础框架冻结后重新采集，不能使用 A1 的 HEAD blob 表替代。

每个可运行 CPU 的五行都必须依次独立交易 → 8-case → 60 秒／fresh replay → 600 秒功能／fresh replay，并单列基础覆盖、依赖和功能证据。CVA6 的五项替换门禁（PULP→OpenTitan GPIO、OpenTitan→ZipCPU UART、OpenTitan→PULP SPI、PULP→OpenTitan I2C、OpenTitan→PULP Timer）也全部 pending。
