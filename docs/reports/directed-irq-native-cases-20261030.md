# 定向 IRQ 原生用例：异常、复位、多源与跨协议（2026-10-30 冻结窗口）

本文记录在源码/配置/脚本冻结后集中执行的原生用例，全部读取真实 RTL journal 并由用例自身重算。原始材料根目录：
`research/input-strategy-audit-20261027/runs/native-batch-20261030/`（相对研究 runs 根，下称 `$B`）。

所有用例都不授予 `grants_F5`/`grants_F6`/`reward_eligible`；内部 IP cause/version、跨例来源保持 `unknown`。

## 1. 同步异常不产生 IRQ lineage

`scripts/run_irq_exception_native.py`：真实 ECALL 进入异常向量，全程无外部 IRQ 接受、无 decision serial lineage；handler 在 order 11 退休（PC 69632），handler 的 RAM marker 写真实存在。

| CPU | 旧运行 | 本轮第二次 CLI 调用 | 语义摘要 |
|---|---|---|---|
| Ibex | `cv32e40p-irq-20261030/exception-ibex-v4`（旧脚本，缺两个字段） | `$B/exception/ibex-crosscli` + `ibex-crosscli-v2` | 两次当前脚本调用相等 `bc97ec83…` |
| CV32E40P | `exception-cv32e40p-v2` | `$B/exception/cv32e40p-crosscli` | 相等 `5c127046…` |

旧 Ibex v4 的 `configured_trap_cause`/`redirect_cause_scope` 字段缺失，是脚本版本差异，不作为 cross-CLI 对；当前脚本的两次独立 CLI 调用摘要相等。每次调用内部 original/fresh 也是独立原生进程且 `fresh_matches=true`。E40 侧由真实 `cpu_native_exception_redirect` 探针记录（cause 保持 unknown）；Ibex 侧以 `rvfi_trap_retirement` 为证据。debug/NMI 改道未测，保持 unavailable。

## 2. 复位屏障使旧 lineage 失效

`scripts/run_irq_reset_native.py` + `configs/scenarios/directed-irq-reset/ibex-wb-timer.json`：一次真实 `cpu_external_irq_taken` 与其 handler 退休之间执行真实 `runner.reset_all('warm_all')`，之后继续有界步进。

`$B/reset/ibex-wb-timer/summary.json`：`status=verified`、`fresh_matches=true`、`barrier_observed=true`、`epochs_advanced=true`、`post_reset_take_count=2`、`no_lineage_after_reset=true`、`post_reset_serial_distinct=true`、`post_reset_fresh_take_observed=true`；两阶段各 6 个实际进程（3 组件 × 2 次启动）全部 reaped/exit0。

独立复核（只读 `events.json`）：barrier `event_id=1738`、policy `warm_all`；pre take epoch 0 / token 1；post take epoch 1 / take_key `["cpu",1,1]`、`["cpu",1,2]`；post-reset 退休中与 pre-reset `(epoch, token)` 相同的 join 为 **0**。同数值 token 1 在新 epoch 重复是真实行为（serial 计数器随 `rst_ni` 清零），不是 lineage。

范围：一个定向用例，不证明 reset 后重新安装 provider 并继续 slot execution，也不证明 cold reset 恢复。

## 3. 多源 IRQ group：joint 拒绝与逐成员 unique

`scripts/run_irq_group_native.py` + `configs/scenarios/directed-irq-group/*.json`：两个声明式 target 输出进入同一个真实 OR group。

| 用例 | 实际 frame | 观察文档 |
|---|---|---|
| `joint-two-targets-ibex` | `attribution_status=joint`、`active_sources=[wb_timer.o_int, spi.events_o]`、`value=1`、单 take | `status=ambiguous`、`irq_consumption=unknown`、refusal `declared-F5-OR-attribution-not-unique`、零 credit |
| `unique-wb-timer-ibex` | `unique`、`[wb_timer.o_int]` | `status=verified`、`irq_consumption=verified` |
| `unique-apb-spi-ibex` | `unique`、`[spi.events_o]` | `status=verified`、`irq_consumption=verified` |

三例 original/fresh 各 3 个进程、全部 exit0，`fresh_matches=true`，语义摘要分别 `7b9bcef4…`/`277ce038…`/`5620cdb0…`。

joint 用例用真实 `mstatus.MIE` gate：先关中断、完成两个声明 trigger 写、再开中断，使唯一 take 落在两个真实 pulse 同时为高的 tick；overlap 由真实 frame/样本证明，不是假设。首次执行的三例在派生阶段因脚本读取 mapping 键名错误（`source_bit_offset` 应为生产 mapping 的 `raw_bit_offset`）exit1；原 journal 保留（其 joint/unique frame 已正确），修正后重跑得上述 verified。失败原产物在 `$B/irq-group/`，通过产物在 `$B/irq-group-v2/`。

## 4. 跨协议 directed 矩阵

`scripts/run_directed_irq_native.py` 按 case 声明的 runner 执行，4 个 native-ready 跨协议用例全部 `verified`，每个用例 7 个声明层都由真实 journal 重算：

| case | CPU / target | 结果 |
|---|---|---|
| `cross-protocol.apb-spi-cv32e20` | CV32E20 / APB PULP SPI | `verified`，serial 1 |
| `cross-protocol.apb-spi-ibex` | Ibex / APB PULP SPI | `verified`，serial 1 |
| `cross-protocol.wb-timer-ibex` | Ibex / Wishbone ZipTimer | `verified`，serial 1 |
| `cross-protocol.ahb-sha-cv32e20` | CV32E20 / AHB Caliptra SHA | `verified`，serial 1 |

层为 `source_verification`、`declared_output_mapping`、`irq_group_unique_attribution`、`cpu_native_sample`、`cpu_native_take`、`cpu_retirement_serial`、`irq_serial_certificate`。原始材料 `$B/directed/<case>/`。

## 5. 矩阵更新

`configs/scenarios/directed-irq-matrix.json` 的四个定向 case（`reset-then-irq`、`exception-does-not-mint`、`two-source-ambiguous`、`unique-two-source-each`）已改为 `native_ready=true` 并指向各自的公共 runner；对应软件门与配置校验见 `tests/integration/test_directed_irq_matrix*.py`。`scripts/run_directed_irq_native.py` 会执行 case 声明的 runner，但其内建层派生仍只覆盖单 take 的 transport 用例，因此这四个 case 以各自 runner 的 `summary.json` 为证据（矩阵 notes 已注明）。

## 6. 未声明

- 不把 reset/异常/多源用例升级为 F5/F6 能力或奖励；它们证明的是定向证据边界。
- 不声称所有 CPU×IP 组合已覆盖；本轮的 CPU/target 范围见各表。
- 不声称覆盖率或性能；覆盖率见 `new-path-coverage-20261030.md`，性能见 `journal-cache-campaign-ab-20261030.md`。
