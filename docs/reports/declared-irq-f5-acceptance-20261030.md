# 声明式 IRQ → 完整 F5 消费链验收（2026-10-30）

范围：把已有的“声明式输出 IRQ transport”（真实 target 输出样本 → host OR 组 → 解析后的 CPU 输入 → native take → 首条 handler 退休）接到完整 F5 消费链，并在三个 target 协议上取得 original/fresh 两次独立 CLI 调用。本文依据保存产物并独立重算；没有启动新的 DUT 会话。

原始材料：`research/input-strategy-audit-20261027/runs/declared-irq-f5-20261030/{wb-timer,apb-spi,ahb-sha}/`。
独立重算：各目录下的 `independent-audit.json`，由 `scripts/verify_declared_irq_f5.py` 生成。

## 链路

```
固定 CPU 镜像的 MMIO trigger 写（真实 store）
  → target IP 内部寄存器/状态（真实 target RTL）
  → 声明的 target 输出信号 + bit（local_tick_sample.outputs.physical[wire]）
  → host OR 组 frame（值、唯一/联合归属、native_source 引用）
  → CPU 输入 pre/post 样本（cpu_external_irq_sample）
  → native take + 决策探针（cpu_external_irq_taken）
  → ISR 读声明状态寄存器（mmio_delivery + target 原生 pre/post 样本 + CPU OBI data beat）
  → 依赖的 RAM 结果字 SW（真实值）
  → MRET 退休 → 首条后继退休（PC/insn + 取指响应 + 源字节版本）
```

固定固件（`build_declared_irq_firmware`）只做声明过的动作：`mtvec=vector|1`、`mscratch`、`mie|=1<<11`、`mstatus.MIE`、两个向量入口跳到 handler、handler 保存 `x1..x4`、按声明顺序 `LW` 状态寄存器并 `SW` 到 RAM 结果字、恢复并 `MRET`。没有 host 注入脉冲、没有 host 写寄存器代替 ISR。

## 实际结果

| 配置 | CPU | target 协议 | 状态读 offset / 值 | MRET PC | 返回 PC | 事件数 |
|---|---|---|---|---|---|---|
| `declared-irq-f5-wb-timer` | `ibex_rvfi_local` | Wishbone ZipTimer | 0 / 0 | 66624 | 69652 | 2,154 |
| `declared-irq-f5-apb-spi` | `ibex_rvfi_local` | APB3 PULP SPI | 40 / 0 | 66624 | 69652 | 8,090 |
| `declared-irq-f5-ahb-sha` | `cv32e20` | AHB-Lite Caliptra SHA | 24 / 1 | 66624 | 69700 | 3,663 |

三例 original/fresh 各自 3 个组件进程（CPU、active target、idle target），全部 reaped、exit 0；两阶段 PID 与 execution nonce 独立；`summary.status=verified`、`irq_consumption=verified`、`refusals=[]`。

### 状态寄存器的真实语义

- ZipTimer 只有一个 4 字节 `COUNT` 窗口（offset 0），`o_int` 是寄存器化单周期脉冲；ISR 读到的是实时倒计时值 0，不能证明 pending 位。
- PULP SPI 的 `0x28`（40）是声明为 `ro`、`read_rearms_interrupt` 的 `INTSTA`；该 RTL 的读 mux 没有 `REG_INTSTA` 分支，因此按设计读回 0，同时重装事件状态机。读值只证明值传播，不证明中断原因。
- Caliptra SHA 的 `0x81c` 是写触发的 `error_intr_trig_r`，不在组合声明的寄存器子集内；本链读的是已声明的 `STATUS`（24），实际值 1。没有读取或改写未声明 offset。

## 独立重算（`scripts/verify_declared_irq_f5.py`）

只读保存的 `summary.json`、`observation.json`、`events.json`、`executions.json`，逐项重算：

1. 两阶段 semantic digest：把 `observation` 去掉 `case_id` 后重新规范化哈希，必须等于 `summary.semantic_sha256`；original 与 fresh 必须相等。
2. target 原生输出：`local_tick_sample` 的组件/phase/tick/reset_epoch 与引用一致，`outputs.physical[runtime_name]` 的声明 bit 为 1，`outputs[source_port]` 等于原始向量。
3. OR frame：`attribution_status=unique`、`active_sources` 恰好是 target member、`value=1`，且 `native_take_event_id` 指向同一个 take。
4. CPU 输入：take 的 `sample_event_id` 是真实 `cpu_external_irq_sample`，同 tick、`expected/pre/post` 均为 1；决策 serial 为实际非零值，并恰有一条同 serial 的退休。
5. 消费：每个状态读的 `mmio_delivery.read_value`、CPU OBI `rdata`、依赖 RAM 写值三层相等；MRET 字 `0x30200073`；后继 `order = MRET.order + 1`。
6. 进程：三组件均 `exit_code=0`、`reaped=true`、PID/nonce 两阶段不同、build/binary 身份相同。

三例结果均为 `status=verified`、`problems=[]`。

## 未声明

- 内部 IP cause（`cause_source=unknown`；`status_cause_bits=null`）、内部寄存器版本、跨例 writer 归属、IRQ 通用入口来源仍 `unknown`；`grants_F5=false`、`grants_F6=false`、`grants_prerequisites=false`、`reward_eligible=false`。
- 读值相等不构成“内部原因已被证明”，也不构成跨例消费奖励。
- 本报告不包含 RTL 覆盖率（见新路径覆盖率报告）与性能 A/B；时间是运行记录，不是提速结论。
- 未穷举 CPU×target 矩阵；CV32E40P 的声明式 F5 另见后续报告。

## 复现命令

```bash
# original / fresh 为两次独立调用
PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-wb-timer/config.json \
  --output <run>/wb-timer/original --mode original --cache <cache>
PYTHONPATH=src:. python3 scripts/run_declared_irq_f5.py --native \
  --config configs/scenarios/declared-irq-f5-wb-timer/config.json \
  --output <run>/wb-timer/fresh --mode fresh --cache <cache> \
  --original <run>/wb-timer/original

PYTHONPATH=src:. python3 scripts/verify_declared_irq_f5.py \
  --run <run>/wb-timer --output <run>/wb-timer/independent-audit.json
```
