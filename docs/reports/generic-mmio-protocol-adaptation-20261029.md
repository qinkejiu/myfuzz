# 通用 MMIO 协议适配验收（2026-10-29）

本轮验证同一个公共 MMIO 执行器和 APB target adapter，通过配置接入 PULP I2C，并将 CPU request 从 Ibex 换为 CV32E40P。没有新增 CPU×IP 专用执行器、I2C storage-version issuer 或 I2C peer 模型。

## 实际结果

| 配置 | original | 独立 fresh CLI | 独立离线核验 |
|---|---|---|---|
| Ibex OBI + I2C APB | [4 cases，40.04s](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ibex-v2/original/summary.json) | [4 cases，33.68s](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ibex-v2/fresh/summary.json) | [verified](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ibex-v2/mmio-offline-audit.json) |
| CV32E40P OBI + I2C APB | [4 cases，29.90s](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-cv32-v1/original/summary.json) | [4 cases，25.83s](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-cv32-v1/fresh/summary.json) | [verified](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-cv32-v1/mmio-offline-audit.json) |

四次 CLI 均正常退出，summary 状态为 `observed`，完整 within-invocation replay 均 `matches=true`。各配置的独立 fresh CLI summary 保留公共入口原来的 `cross_invocation.status=pending`、`matches=null`；没有改写为已验证。

独立工具 [verify_generic_apb_mmio.py](../../scripts/verify_generic_apb_mmio.py) 读取真实 original/fresh 保存产物后，才在单独 audit 中报告 `cross_invocation.status=verified`、`matches=true`。两份 audit 均保留原 summary 的 pending 状态，并明确 `authority=false`。

每份 original/fresh 的实际序列均为 `F4:55000000 → F2:00100040 → F4:aa000000 → F2:00100040`。实际读值为 `[85,85,170,170]`；每阶段 9012 events，CPU 513 ticks、peripheral 537 ticks，原始命令分别为 CPU 513 条、peripheral 519 条。工具重新解析 wire replies，核对 APB transfer、CPU native OBI 返回与依赖 RAM hop，确认独立进程、退出状态、完整 normalized prefix、决策记录、online plan 和 raw source 一致。

## 通过范围

- CPU 侧为现有 OBI adapter，target 侧为 **APB32 full-word、单 outstanding**。I2C 只增加配置；CPU 切换只更换 request/profile。
- 实际 target 为 PULP I2C 的 PRESCALER、offset 0；候选值落在声明的 16-bit register mask 内。SCL/SDA 输入由配置静态拉高，CTRL 保持 reset 值，不执行 I2C 总线事务或 IRQ 场景。
- F4 检查实际写总线，以及另一次实际读返回；不把“写后读应相等”当作通用协议保证。F2 按实际 APB read value、CPU return 与 XOR-dependent RAM 结果核对。
- 每例 `internal_storage_version=unknown`、`cross_case_origin=unknown`、`component_semantic_effect=unsupported`、`reward_eligible=false`；prefix 的 strong-storage certified/reward 计数均为 0。总线完成没有升级成内部存储版本、跨例来源或强 storage 奖励。

覆盖率重放可复用已保存 local commands 和现有离线 coverage 工具；本报告不声称这两组已测 coverage。Wishbone、AXI、APB subword、其他 I2C register/peer/IRQ、以及其他 CPU 的全 flow 能力都不由以上 OBI 结果推定；随后单独取得的 Wishbone 证据见下节。

表中时间是四次实际 CLI wall 记录，包含各自初始化、执行和重放成本；CPU、构建缓存及执行环境没有构成严格配对性能实验。它们不是性能 A/B 或提速结论。

## 后续独立验收：PicoRV32 Wishbone → 同一 I2C APB

公共 CPU adapter 切换到 `picorv32_wb`，APB target 和 I2C 配置语义不变。实际结果为 [original summary](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-wishbone-v1/original/summary.json) 4 cases / 24.95s、[fresh summary](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-wishbone-v1/fresh/summary.json) 4 cases / 18.69s，within replay 均匹配；[独立 audit](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-wishbone-v1/mmio-offline-audit.json) 的 full-prefix cross 检查 verified。这里 18.69s 是 summary 字段，root 记录的外层 fresh 命令 wall 为 18.70s，二者不混作同一计时边界。

离线另行检查 generated CPU artifact 的实际 `kind=wishbone_cpu`、`plan.component_id=picorv32_wb`；prefix、certificate 和 `execution_binding.cpu_adapter.protocol` 均为 `wishbone`。数据和 RAM hop 使用 `native_cpu`，没有将 WB 标成 `native_obi`。checker 委托同一个 CPU adapter 调用既有 Wishbone native parser，没有新增 WB 专用 checker。

两阶段分别重新解析 CPU 的 513 条原始 wire replies。由绑定的实际 `wb_cyc/wb_stb/wb_we/wb_sel/wb_adr` 字段核对：对 offset 0 的两次 MMIO 写 acceptance 在 CPU tick 37、293，SEL=15；四次读 acceptance 在 tick 48、153、304、409，真实 SEL=0。这些值与 native beat 完全一致，未将 read SEL 改写成 15；APB 侧仍是声明的 full-word 访问。实际读值 `[85,85,170,170]`、9012 events、CPU 513 / peripheral 537 ticks、CPU 513 / peripheral 519 commands 均在 original/fresh 一致。

该结果补充的是 **Wishbone CPU adapter → 同一 APB target adapter** 的实际复用，未扩展到其他 target 协议或组件内部语义。internal version/cross-case origin 仍 unknown，强 storage reward 仍为 0。与前两组的时间同样不是严格性能 A/B。


## 后续独立验收：CVW AHB-Lite → 同一 I2C APB

[original summary](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ahb-v1/original/summary.json) 与 [fresh summary](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ahb-v1/fresh/summary.json) 各完成 4 cases，wall 分别为 65.05s、60.91s，within replay 均匹配。[独立 audit](../../research/input-strategy-audit-20261027/runs/generic-mmio-20261029/i2c-ahb-v1/mmio-offline-audit.json) 重新解析原始 wire replies、重建 CPU native beats，并比较完整 normalized prefix、决策、online plan 和 raw source，结果 verified；fresh summary 的 cross pending 保持原样。两阶段 CPU/target 都是独立 PID 与 execution nonce，均 reaped、exit 0。

实际 generated CPU artifact 为 `cvw` / `ahb_lite_cpu`，prefix、certificate 和绑定 CPU adapter 均声明 `ahb-lite`，hop 使用 `native_cpu`。AHB parser 复用真实接受的地址阶段 HPROT 与后续 READY/data completion：六次 MMIO transfer 的 HPROT 均为 3，规范化 beat 分类为 `data`；实际 source transaction 的 `channel_id` 仍是 `memory`。这两个字段含义不同，checker 保留统一 parser 的 `('data', sequence)` 键，没有把 AHB 原始事务伪装成 OBI channel，也没有按当前周期 HPROT 猜测 pending transfer。

两阶段序列均为 `F4:55000000 → F2:000001c0 → F4:aa000000 → F2:000001c0`，读值 `[85,85,170,170]`，9858 events，CPU 513 / peripheral 537 ticks，CPU 514 / peripheral 519 commands。CPU 多一条命令是实际 recording 数，未改写成其他协议的计数。覆盖范围为 AHB-Lite CPU adapter → 已有 APB32 full-word target adapter，不推定 IRQ、retirement、其他 target 协议或 I2C peer 行为。内部版本及跨例来源仍 unknown，strong-storage 奖励为 0；上述时间也不是严格性能 A/B。
