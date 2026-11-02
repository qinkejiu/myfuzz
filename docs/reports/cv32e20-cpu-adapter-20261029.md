# CV32E20 CPU adapter 原生验收（2026-10-29）

本次通过的是 **CV32E20 CPU IRQ/退休 adapter smoke**，不是 F5 外部源因果证明或 F6 DMA 执行认证。验收由 root 执行；本报告另行读取原始记录作离线核对，未重启 DUT。

## 证据与范围

- 脚本：[run_cv32e20_irq_smoke.py](../../scripts/run_cv32e20_irq_smoke.py)。使用现有 GeneratedCve2Session、PersistentMemory、空 DataflowRouter 和 ScenarioRunner 原 STEP 路径，没有 CPU×IP 专用执行器。
- 原生结果：[v4/summary.json](../../research/input-strategy-audit-20261027/runs/cv32e20-irq-smoke-20261029/v4/summary.json)，状态 `verified`，`fresh_matches=true`，`grants_F5=false`、`grants_F6=false`。
- [固定 ROM](../../research/input-strategy-audit-20261027/runs/cv32e20-irq-smoke-20261029/v4/program.json)、[original](../../research/input-strategy-audit-20261027/runs/cv32e20-irq-smoke-20261029/v4/original/)、[fresh](../../research/input-strategy-audit-20261027/runs/cv32e20-irq-smoke-20261029/v4/fresh/) 均保留。两阶段各含完整 `local_commands.json` 原始命令/回复、`events.json`、`executions.json` 和 `result.json`。

使用主 profile `cv32e20`（RV32I，32 GPR），不是 `cv32e20_rv32e`（16 GPR）。固定程序配置 mtvec/mie/mstatus；host IRQ 输入先低、随后在屏蔽时拉高、实际 take 后拉低。ISR 读取 mepc 并存入 RAM，实际 SW 写 marker=42，然后执行 MRET。

## 独立核对结果

| 项目 | original | fresh |
|---|---:|---:|
| 原始 STEP_CPU 回复成功重新解析 | 90/90 | 90/90 |
| 实际 STEP tick | 90 | 90 |
| Runner events | 1120 | 1120 |
| 语义结果中的退休指令 | 38 | 38 |
| 实际首 fetch | 0x10000 | 0x10000 |
| IRQ 高电平观测 tick | 27–63 | 27–63 |
| 高电平且实际 masked 观测 tick | 27–60 | 27–60 |
| 实际 native take tick | 63 | 63 |
| 决策 serial / 对应退休 serial | 1 / 1 | 1 / 1 |
| 对应退休 PC（external vector 槽） | 0x1022c | 0x1022c |
| ISR marker | 42 | 42 |
| 保存的 mepc / MRET 后继 PC | 0x10074 / 0x10074 | 0x10074 / 0x10074 |
| MRET PC / tick | 0x10418 / 86 | 0x10418 / 86 |
| 第一条 MRET 后继退休 tick | 90 | 90 |

两份记录的原始回复共 180 条，均经现有 `parse_driver_receipt` 核对 execution nonce、sequence、tick_before/tick_after 和单 tick 推进。实际 PRE 决策 serial=1 位于 command 63，实际 POST 退休 serial=1 位于 command 69；不是用 host 输入值或计划事件补造 token。

original PID=245，fresh PID=288，execution nonce 分别为 `d7f0eb02de4b4e399dd2b063a6ff6ec2`、`8af5a16cf83942c28cbf383943bc8dbe`。两进程均已回收、exit 0；共享相同 artifact/build/binary 身份。离线重新计算缓存 binary 与 manifest 的 SHA-256，均符合记录。两份 `result.json` 完全相等，语义摘要为 `0e380fc9bf78d8b8296c0a71691485a0c0718218bbab4fda4a2191843823751e`。

## CPU ABI 要点与限制

CVE2 的 source-backed boot PC 是 `{boot_addr_i[31:2],2'b00}`，实际首 fetch 与预测 0x10000 一致。其 mtvec 强制 vectored 模式及 256-byte BASE 对齐；外部 machine IRQ 进入 BASE+11×4。本次 ROM 显式提供 0x1022c→handler 跳转，未扩大 RAM 或填充随机执行区掩盖错误。前一轮缺失该槽的失败保留在同目录 `v3`，不计通过。

本次用两个独立 native 进程的 fresh 对比验证 CPU adapter；没有在同进程执行 reset 中断取消测试。IRQ 来源仍明确为 `unknown-host-driven-IRQ`，没有 GPIO/IP source binding、F5 credit 或 F6 DMA/四 word/ISR issuer 授权。CV32E40P 的完整退休/IRQ adapter、RV32E 变体的 IRQ 原生执行，以及其他 CPU/IP 的完整 flow 组合都不能从本 smoke 推定通过。
