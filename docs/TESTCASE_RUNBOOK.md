# 按 testcase 讲：一次测试的数据流动、涉及部件、怎么运行

日期：2026-10-08。本文以**一次 testcase**为单位组织：每种 testcase 都讲三件事——**数据怎么流**、**涉及哪些部件**、**实际怎么跑起来**（谁给命令、谁推进时钟、怎么判定、怎么重放）。

所有事件号、地址、指令、命令数都取自本仓库已保存的真实运行：

| 运行 | 配置 | 规模 |
|---|---|---|
| `runs/current-dataflow-p5-chain-acceptance-20261007-online` | Ibex ＋ 双 PULP GPIO | 24 例、32.44 秒、31,795 事件 |
| `runs/p5-uart-routing-gate-20261008-online` | Ibex ＋ OpenTitan UART | 60 例、88.06 秒、76,332 事件 |

> 种类清单见 [testcase 的种类与数据流](TESTCASE_TYPES.md)；变异依据见 [输入的变异依据](INPUT_MUTATION_BASIS.md)；部件逐个功能见 [组件清单与功能](COMPONENT_REFERENCE.md)。

---

## 0. 一次 testcase 的三句话

```text
① 一次输入决策：给一个上游源一个值（程序字节 / 外部事件）
② 一段局部执行：按声明的调度把参与部件各推进若干本地 tick
③ 一次观察判定：真实 RTL 的事件切片交给 checker，产出回执并保存
```

**它不 reset、不重装程序镜像**；上游的 RAM、寄存器、pending event、事务账本跨例延续。

---

## 1. 怎么跑起来：五个阶段与真实命令数

### 1.1 调用路径

```text
Rust fuzzer 客户端（kfuzz）
   │  写共享内存缓冲（raw record，1–8 字节）
   ▼
scenario_rfuzz.py（宿主适配器）
   │  ① _online_weights()            ← 计算本轮的反馈权重
   │  ② decode_candidate(raw, weights)  ← 纯解码：路径/源/载荷 + 分类拒绝
   │  ③ source_action_gate.require_case() ← 先决条件闸门（RTL 之前）
   ▼
ScenarioSession.submit_case(case)        ← 本文的主角
   │  ④ 源接纳声明（source_admission.v1）
   │  ⑤ 指令物化（support NOP / 源指令片段）
   │  ⑥ 源注入（外部事件值 或 指令片段）
   │  ⑦ runner.step_batch(schedule) × advances
   ▼
真实 RTL 部件（各自本地时钟）
   │  ⑧ 事件流：事务/交付/提交/退休/IRQ
   ▼
checker(receipt) → OnlineCaseReceipt（事件切片 + 本地 tick + 状态）
```

### 1.2 五个阶段

| 阶段 | 代码 | 做什么 | 失败会怎样 |
|---|---|---|---|
| ⓪ 先决条件 | `prerequisite_gate.require_case()` | 任何 RTL 命令**之前**查跨例前提 | 拒绝 → `input_invalid`＋精确码，**RTL 零命令**，会话继续 |
| ① 源接纳 | `_case_admissions()` | 写 `source_admission.v1`（`admission_id`/`path_id`/`source_id`/`input_sha256`/`role`） | 源不匹配路径/越宽 → 在任何 RTL 前报错 |
| ② 支持物化 | `accept_instructions()` | 固定 NOP 占住插槽（仅外部事件源需要） | 部件不支持在线指令 → 报错 |
| ③ 源注入 | `inject_source()` / `accept_instructions()` | **被决策的那个输入**落地 | `action_id` 重复 → 报错 |
| ④ 局部执行 | `runner.step_batch(schedule)` | 按 `advances` 逐项推进部件 | 中途抛错 → `uncertain_effect`，**立即停止接纳新例** |
| ⑤ 观察判定 | `checker(receipt)` | 三类断言求值 | checker 抛错 → `environment_error`；报 finding → 停在 `finding` 并保存完整前缀 |

### 1.3 `advances` 到底做了什么（真实数字）

`step_batch` 对调度里的**每个部件发一条本地命令**（`runner.step(component)`），命令走与传输重试相同的命令账本（`execution_id` ＋ 单调 `command_sequence` ＋ `epoch`）。

| 运行 | 每例 `advances` | 每次调度的部件 | 每例本地命令数（实测） |
|---|---|---|---|
| Ibex＋双 PULP GPIO | 32 | `["cpu", "gpio_a", "gpio_b"]` | **96**（实测 min 96 / max 98） |
| Ibex＋OpenTitan UART | 96 | `["uart", "cpu"]` | **192**（实测 min 192 / max 195） |
| UART bootstrap | 1236 | `["uart", "cpu"]` | —（会话首例热身） |

`advances` 的语义是"**每个部件的本地时钟各走一步**"，不是"一个全局周期"：每个 DUT 保留自己的时钟与复位，互不同步（见 [系统说明](SYSTEM_OVERVIEW.md) §3.2）。

### 1.4 每例的耗时构成（实测 p50）

| 运行 | `local_command_roundtrip` | 其余主机时间 | RTL submit | 每例总时长 |
|---|---|---|---|---|
| GPIO | 0.0497 秒 | 1.1839 秒 | 1.234 秒（p50） | 1.297 秒（p50） |
| UART | 0.2088 秒 | 1.1163 秒 | 1.444 秒（p50） | 1.479 秒（p50） |

**结论**：每例的瓶颈在"主机侧其余工作 ＋ 一次 RTL submit"，而不是命令往返；这也是 P5 效率门禁要逐例记录 p50/p95 的原因。

---

## 2. testcase T1：CPU 指令源（CPU→IP→CPU）

### 2.1 数据流动

```text
raw bytes 00 00 00 c2 0c 01 06 b0
  │ byte2=00 → 直接命名源 index 0 = cpu.online_instruction
  │ byte3.. → 12 字节变异熵
  ▼
decode_instruction_fragment(entropy)          ← 合法 RV32I 片段（本例 4 字）
  │ LUI x2,0x0cc2b / ADDI x2,x2,6 / LUI x1,0x40001 / SW x2,0x0c(x1)
  ▼
OnlineInstruction(action_id, address=0x11010, data_hex)
  │ submit_case 阶段③：accept_instructions → 写进预留指令槽
  ▼
Ibex 真实取指：memory_read @0x11010（writer_kinds=INSTRUCTION_SOURCE）   【CPU RTL】
  │ 执行 → 真实 OBI Store：0x4000100c / wdata=0x0cc2b006 / be=0xf
  ▼
mmio_acceptance → data_accept                                        【CPU 侧观测】
  │ 按声明窗口判路 rule0 → gpio_a
  ▼
gpio_target_receipt → gpio_apb_access → gpio_register_commit          【GPIO A RTL】
  │ register "out" 逐 bit 版本：bit0 v2185=0、bit1 v2186=1 …
  ▼
target_request/target_response → mmio_delivery（target_access_id 精确回指）
  ▼
cpu_retired_transaction_target_delivery(status=linked_raw) → gpio_consumption_match(accepted)
```

### 2.2 涉及部件

| 层次 | 部件 | 干什么 |
|---|---|---|
| 解码 | `online_case_decoder` ＋ `rv32i_sources` | raw → 合法指令片段；拒绝越界/非法算子 |
| 会话 | `ScenarioSession` | 接纳、注入、推进、判定 |
| RTL | Ibex（OBI＋RVFI 探针） | 真实取指、执行、总线事务、逐字退休 |
| RTL | PULP GPIO A（APB3，4096 B @0x40001000） | 真实寄存器提交（逐 bit 版本） |
| 控制面 | Router | 按声明窗口把 CPU 事务送到目标 session |
| 控制面 | ownership / source_action | 判定该指令槽可写、先决条件满足 |
| 证据 | 证书（消费匹配、链证书） | 把"谁消费了谁"按身份钉死 |

### 2.3 怎么运行（命令级）

```text
① decode_candidate(raw, weights)            → 纯函数，不碰 RTL
② source_admission.v1 事件写入事件流
③ accept_instructions(0x11010, data)        → 1 条命令（写指令槽）
④ step_batch(["cpu","gpio_a","gpio_b"]) × 32 → 96 条本地命令
⑤ checker(receipt) → 无 violation → status=running/complete
⑥ 回执保存：event_start/event_end、local_ticks_before/after、coverage_hex
```

真实命令数 **96**；实测该例 `online_phase_timing_seconds.total` 约 1.3 秒。

### 2.4 闭环判据与边界

- **闭环**：`mmio_delivery.target_access_id == gpio_target_receipt.access_id`，`gpio_consumption_match.fullkey == mmio_acceptance.source_transaction`（六字段全等），消费证据是**逐 bit 寄存器版本**。
- **不证明**：寄存器写入 ≠ 外设行为正确；不证明该写是后续中断的原因。

---

## 3. testcase T2：GPIO pin8 外部事件源（IP→CPU→IP）

### 3.1 数据流动

```text
raw 1 bit（源切片：gpio_b.gpio_in[8]，width=1）
  │ 归属检查：pin8 未被绑定（被 GPIO A 输出绑定则 ownership.bound_input 拒绝）
  ▼
source_injection(value=1)                                    【注入】
  │ 写进 GPIO B 输入队列，按本地 tick 逐段施加
  ▼
gpio_input_segment_applied：真实采样序列 0,1,1,0,0,0,0,0,1   【GPIO B RTL】
  │ 上升沿 → 原生 IRQ
  ▼
native_irq_binding_delivery（声明绑定 gpio_b.irq → cpu.irq，宽 1）
  │ Runner 交付策略：irq_pulses{width_cpu_ticks:4, overrun_policy=terminate_unsupported}
  ▼
cpu_external_irq_sample(expected=1, actual_post=1)           【CPU 输入】
cpu_external_irq_taken(expected=1, actual_post=1)            【CPU 真实取中断】
  │ vectored：0x1012c(vector slot, rejected 自环) → 0x10200 → ISR
  ▼
ISR 真实执行（RVFI 逐字退休）：
  0x10210 LUI x1,0x40000
  0x10214 LW  x2,0x8(x1)     ← mmio_acceptance(0x40000008, read) → mmio_delivery(read_value=0x106)
  0x10218 LUI x3,0
  0x1021c… SW  x1/x2/x3 → RAM
  ▼
持久 RAM 写入（跨例可见）
```

### 3.2 涉及部件

| 层次 | 部件 | 干什么 |
|---|---|---|
| 归属 | `ownership` | 判定 pin8 是否可写（绑定/固定位拒绝） |
| RTL | PULP GPIO B | 真实引脚采样、原生 IRQ |
| 交付 | `runner._effective_inputs` ＋ `irq_pulses` | 把 IRQ 变成 CPU 的输入（**策略在 Runner，不是 DUT**） |
| RTL | Ibex | 真实取中断（`irq_taken`）、向量入口、ISR 执行、RVFI 退休 |
| RTL | PULP GPIO B（读侧） | 真实 PADIN 读回 `0x106` |
| 控制面 | Router | 0x40000008 → gpio_b |
| 内存 | host RAM（`PersistentMemory`） | 接收 ISR 的 SW |

### 3.3 怎么运行

```text
① decode → 选中 gpio_b.external_pin8（IP_TO_CPU_TO_IP 路径）
② 源接纳 + support NOP 物化（该例带 1 条固定 NOP）
③ inject_source(gpio_b, gpio_in, value=1, bit_offset=8, width=1)
④ step_batch(["cpu","gpio_a","gpio_b"]) × 32 → 96 条本地命令
   （IRQ 交付发生在步进过程中：`_effective_inputs` 把绑定的 IRQ 喂给 CPU）
⑤ checker：IRQ 交付一致性 + 退休身份 + 消费匹配
```

### 3.4 闭环判据与边界

- **闭环**：IRQ 交付的 `expected_input`/`actual_post_input` 全为 1；ISR 读回值 `0x106` 含 pin8=1；RVFI 的 `pc ↔ insn` 逐字对照。
- **不证明**：不证明"这一位是中断的唯一原因"；IRQ 宽度是**交付策略**；不含 PLIC/SoC 拓扑。

---

## 4. testcase T3：UART RX 字节源（IP→CPU）

### 4.1 数据流动

```text
raw 8 bit（源切片：uart.uart_rx_byte，width=8）
  │ ① 归属检查 + 波形互斥闸门（冲突则启动前拒绝，见 §5）
  ▼
source_injection(value=0x5a 等)                                【注入】
  │ ② 真实 8N1 RX 波形：uart_rx_bit_sample × N → uart_rx_receiver_start/complete
  ▼
uart_frame_validation → uart_fifo_push(entry_id=["uart",0,0,N]) 【UART RTL】
  │ ③ uart_irq_update（rx_watermark 类）→ uart_irq_output_definition
  ▼
native_irq_binding_delivery → cpu_external_irq_sample → cpu_external_irq_taken
  │ ④ CPU 真实取中断
  ▼
ISR：LUI x1,0x40000 → LW x2,0x18(x1)                            【CPU】
  │ ⑤ uart_rdata_access(offset=0x18) → mmio_delivery(read_value)
  ▼
uart_fifo_pop → uart_consumption_match → uart_retired_read_match(accepted)
```

### 4.2 涉及部件

| 层次 | 部件 | 干什么 |
|---|---|---|
| 闸门 | `uart_waveform_gate` | 波形进行中的 TL-UL 访问 → 启动前拒绝 |
| RTL | OpenTitan UART（TL-UL，4096 B @0x40000000） | 8N1 采样、FIFO、原生 IRQ、RDATA |
| RTL | Ibex | 取中断、ISR 读 RDATA |
| 交付 | Runner IRQ 交付 | 把 UART 的 IRQ 变成 CPU 输入 |
| 控制面 | Router / source_action | 窗口路由；`transport_idle` 先决条件 |
| 证据 | UART 路由见证 / 链证书 | 逐 case 记录访问与消费见证（[报告](reports/current-dataflow-p5-uart-routing-witness-20261008.md)） |

### 4.3 怎么运行

```text
① decode → 选中 uart.external_rx_byte（IP_TO_CPU 路径）
② 源接纳 + 1 条 support NOP（CPU 陪跑）
③ source_action_gate.require_case() → 查 transport_idle
④ inject_source(uart, uart_rx_byte, value, width=8)
⑤ step_batch(["uart","cpu"]) × 96 → 192 条本地命令
```

### 4.4 真实规模与边界

- 该运行 60 例中 **36 例**走这条路径；实测只有 **7 例**真正完成"接收→读回"（其余停在 `uart_source_frame_begin` 之前）。
- 闭环判据是三见证精确 join（`pop.observation_event_id == rdata.actual_request_event_id` 等）。
- **不证明** IRQ→CPU 因果（只按 take 的 `source_output_key` 把该帧 entry 列为队首来归因）；**不证明** polling。

---

## 5. testcase T5：启动前被拒绝（什么都没发生，但精确记录）

### 5.1 数据流动

```text
raw bytes（如 00 00 00 c7 0c 02 06 b0）
  │ ① 解码 + 归属检查通过
  ▼
source_action 先决条件：transport_idle（UART RX 波形必须空闲）
  │ ② 冲突 → 在任何 RTL 命令之前返回拒绝
  ▼
回执 status=input_invalid
     candidate_disposition=rejected
     candidate_disposition_reason=source_action_prerequisite_unsatisfied
     rejection.code=uart_rx_waveform_conflict，证据 uart-waveform-idle:1832/4456/6296
     effective_genome_sha256=null（没有有效基因组）
  │ ③ 0 条 trace 事件；runner / 内存 / case 历史完全不动
  ▼
会话继续接纳下一例
```

### 5.2 涉及部件

只有**控制面**：解码器、ownership、`source_action` 闸门、回执记录器。**没有部件被推进**——这正是它与其他种类的根本区别。

### 5.3 为什么这样设计

底层"RX 波形进行中的 TL-UL 访问"仍不被支持；系统把它从**运行中停机**改成**启动前可统计的拒绝**：UART 臂的无效/超时比例因此可计算（**0.05 = 3/60**，改前算不出，因为 `input_invalid` 未分类）。

---

## 6. testcase T6：受控故障注入（校准）

### 6.1 数据流动

```text
真实 trace（**原始字节不变**）
  │ ① 按声明 selector 选中一个真实见证：case_id + 源事件号 + 观测事件号 + 原值
  ▼
改写 checker 的观测副本（如 outputs.irq 1 → 0）
     calibration_only=true, observation_boundary=checker_input_copy
  │ ② checker 用改写后的副本求值
  ▼
不变量被违反 → violations=['gpio_b_irq_source_mismatch'] → status=finding
  │ ③ 会话停止接纳，保存完整前缀 + minimal_replay.json
  ▼
新进程从最小重放启动真实 RTL → 同一 finding（可复现）
```

### 6.2 涉及部件

| 部件 | 角色 |
|---|---|
| `p5_controlled_irq_fault` / `p5_controlled_uart_fault` / `p5_fault_family` | 选择见证、改写副本、写最小重放配置 |
| checker（真实不变量） | 报警者 |
| 真实 RTL | 只负责产生原始 trace 与复现 |
| 复核器（只读） | 9 变体逐条独立复核 |

### 6.3 怎么运行（真实两次）

```text
校准运行：3 例 → 2 complete + 1 dut_violation，session_status=finding
复现运行：新进程读取 minimal_replay.json → 3 例 → violations=['gpio_b_irq_source_mismatch']
           fault_document_sha256 与最小重放逐字节一致
```

**边界**：注入仅用于校准检测链（`calibration_only=true` 独立标注）；**没有自然 RTL 缺陷**；不证明检测灵敏度。

---

## 7. testcase T7：初始 RAM 数据（不是 case 输入）

### 7.1 数据流动

```text
声明窗口/mask 内抽地址与取值（受信声明）
  │ 会话启动**之前**
  ▼
初始镜像：initial-ram-data.ram.6 → 0x100E6 = 0x94（trace event 6，kind=initial_image）
  ▼
真实 Ibex 首次读该四字节（event 774，lane 2，c0d894d8）→ lane 值 0x94
  │ writer kind = INITIAL_IMAGE
  ▼
slot 判 immutable、0 violated
```

### 7.2 涉及部件与边界

涉及：初始镜像构造（`initial_ram_data.py`）、host RAM、真实 CPU 读侧、slot 不可变性检查器。**不涉及** raw 解码（它不是 case 输入），也不证明搜索收益。

---

## 8. 一张表：几种 testcase 的部件参与与命令数

| | T1 CPU 指令 | T2 pin8 事件 | T3 UART RX | T5 被拒 | T6 故障校准 |
|---|---|---|---|---|---|
| 源 | `cpu.online_instruction` | `gpio_b.external_pin8` | `uart.external_rx_byte` | 同 T1/T3 | 不改源 |
| 部件（RTL） | Ibex ＋ GPIO A | GPIO B ＋ Ibex | UART ＋ Ibex | **无** | 真实 RTL（只产 trace/复现） |
| 部件（控制面） | Router/ownership/source_action/Scheduler | ＋IRQ 交付 | ＋波形闸门/IRQ 交付 | ＋先决条件闸门 | ＋checker 副本改写 |
| 每例本地命令 | 96 | 96 | 192 | **0** | 3 例（校准） |
| 每例 RTL submit p50 | 1.234 秒 | 1.234 秒 | 1.444 秒 | 0 | — |
| 数据流终点 | 寄存器逐 bit 版本＋退休耦合消费 | ISR 读回值＋写 RAM | pop/消费/退休三见证 | 回执（0 事件） | finding＋最小重放 |
| 闭环判据 | `fullkey` 六字段全等 | IRQ `actual_post_input=1`＋读回 `0x106` | `observation_event_id` 精确 join | 精确拒绝码 | 控制/故障 trace 锚点相同 |

---

## 9. 一次 testcase 怎么重放

```text
保存的产物                         重放时谁校验
─────────────────────────────    ───────────────────────────────────────
online_run_identity.json          _verify_online_run_identity：源文件、decode space、
                                  plan、manifest、trace 语义 sha256、host、artifact 摘要
                                  → **任一不符，在 RTL factory 构建之前拒绝**
seed.bin / receipts.jsonl         identity.artifacts 逐文件 sha256 绑定
online_plan.json                  解码依据（哪个 raw → 哪个 case）
online_events.{zlib,json}         语义 sha256（容器无关）
replay 结果                        {"matches": true, "first_difference": null}
```

真实例子：新运行 `runs/p5-uart-routing-gate-20261008-online` 的 replay 输出就是 `matches=true`、`first_difference=null`；而改动 decode-space 源文件后，旧 bundle 的 24 例冷组 replay 被逐例拒绝（`recorded 11a4b307… vs current ee0be2b8a900…`）——这是机制生效，不是缺陷。

---

## 10. 一句话总结

> 跑一次 testcase ＝ **解码一个源值 → 声明接纳 → 注入 → 按 `advances` 逐部件推进本地时钟（GPIO 96 条命令 / UART 192 条命令）→ 真实 RTL 产生事务与事件 → checker 判定 → 保存回执与事件切片**。
> 数据只在**一个源**处被随机决定，之后每一步都由真实 RTL 或声明式绑定决定；涉及部件分三类：**真实 RTL 部件**（CPU/IP）、**控制面部件**（Router/ownership/Scheduler/闸门/checker）、**证据部件**（证书与身份）。
> 被拒绝的 testcase 也走同一条路径，只是**在第 0 步就停下**——0 条 RTL 命令、精确拒绝码、会话继续。
