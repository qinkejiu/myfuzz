# 第二阶段逐组合验收矩阵

更新：2026-10-09。第二阶段实施中；本页只登记新门禁，历史固定场景通过不自动取得 L1–L3 等级。实施起点见[基线身份](reports/stage2-baseline-20261009.json)，步骤见[实施计划](superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。

目前尚未进入 B 的等级预检：legacy Ibex＋双 PULP GPIO 已在 3-case smoke 中完成 fresh replay，但该组合不在本矩阵且没有完整认证链；所有 declared/effective/verified level 都为未确定，L1/L2/L3 门禁均未验证。`pending` 不是 `skipped_unavailable`，后三核是否跳过须在 F 阶段重新核实。

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

## 本矩阵之外的已闭合项（2026-10-13）

下表 21 行登记的是本阶段指定的 **CVA6／BOOM／CVW／VexiiRiscv × 五功能族** 组合，因此 **Ibex＋PULP GPIO 的寄存器级工作不占本矩阵任何一格**，其完成也不改变上表任何一行的状态（上表全部仍为 `pending`，后三核仍须在 F 阶段核实是否 `skipped_unavailable`）。

| 已闭合项 | 组合 | 等级证据 | 边界 |
|---|---|---|---|
| 寄存器**复位默认值**的源绑定读回（L2 scope） | **Ibex（OBI）＋PULP GPIO**（同一场景内 CPU/APB/持久 RAM） | `cold_all` 下产出 `ordinary_register_reset_default_certificate.v1`（`gpio_a`／`INTEN.value`，`proof_scope=observed_source_bound_reset_default_readback`，`reset_value=0`＝`observed_reset_value=0`，**四项 grants 全 False**，`coverage_cursor.command_count=105`，`reset_seal` barrier 6996／epoch 1／`memory_generation` 1，`ram_commit_ref` be 15／cells 全 0），generation `exit 0`／`status=complete`／377.646 秒，**fresh replay 复现同一 `evidence_id=482723a6…`**；独立 audit `passed_positive_certificate_and_fresh_replay`（12,052 事件、1 证书、285 pins） | **仅 `cold_all`、仅 `gpio_a`**。warm 按设计拒绝（重放 arming 写 → `affecting_write_in_reset_interval`，ord220；resume 207 步），独立 audit `passed_terminal_refusal_and_fresh_replay`。`gpio_b` 不出证（shipped bootstrap 自写其 INTEN）需 Task6 minimal-bootstrap 选取器（未接通）。规则放宽仅限经源码审查、与被观察读回无共享状态的写（`PADDIR`/`GPIOEN`/`PADOUT`），依据被钉定 RTL 原文（`apb_gpio.sv:217` 复位、`:234` 自身 APB 写），并显式 `irq_semantics_granted=false`。**不覆盖** DIR/OUT/EN/PADCFG/PADIN/INTSTATUS 的默认值矩阵，**不授** functional／storage／version／prerequisites |

**该闭项的后果（须在后续会话处理）：** 因 verifier SHA 由 `4c90712e…6296` 变为 `f04ec50893329dfc…`，**Task3b 的独立复核已失效、须在新 SHA 上重做**，且 `downstream-stale-pins.json` 记录 **86 个产物**（含两门禁 pin 文件）仍引用旧 SHA。详见[当前进度](CURRENT_PROGRESS.md)与[任务3c 复核](../runs/stage2-e2-native-reset-task3c-independent-review-20261013/task3c-independent-review.md)。

每个可运行 CPU 的五行都必须依次独立交易 → 8-case → 60 秒／fresh replay → 600 秒功能／fresh replay，并单列基础覆盖、依赖和功能证据。CVA6 的五项替换门禁（PULP→OpenTitan GPIO、OpenTitan→ZipCPU UART、OpenTitan→PULP SPI、PULP→OpenTitan I2C、OpenTitan→PULP Timer）也全部 pending。
