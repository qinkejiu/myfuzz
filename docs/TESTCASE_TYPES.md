# testcase 的种类与数据流

日期：2026-10-08。本文回答两件事：**系统里到底有哪几种 testcase**、**每一种的数据怎么流、在哪结束**。每一种都给出：真实运行里的出现次数、源身份、注入方式、经过的组件、闭环证据、以及"它**不**证明什么"。

> 定位与生命周期见 [testcase 与数据流](TESTCASE_AND_DATAFLOW.md)（含两个逐事件号的完整例子）；**"输入的变异依据"见 [输入的变异依据](INPUT_MUTATION_BASIS.md)**；组件清单见 [组件清单与功能](COMPONENT_REFERENCE.md)。

---

## 1. 先看枚举：种类由两个正交维度决定

### 1.1 维度一：被决策的输入（`source.kind`）

| `kind` | 类 | 输入是什么 | 注入方式 |
|---|---|---|---|
| `instruction` | `OnlineInstruction` | 一段 ≤N 条的 RV32I 指令片段（**程序字节**） | `session.accept_instructions(address, data)`，写进会话预留的指令槽 |
| `source_event` | `BatchSourceEvent` | 一个外部环境值（GPIO pin 位、UART RX 字节、peer 字节…） | `runner.inject_source(component, port, value, ...)` |

### 1.2 维度二：数据流方向（`direction`，来自 `genome.DIRECTIONS`）

```text
CPU_TO_IP            仅 CPU→外设
IP_TO_CPU            仅 外设→CPU
IP_TO_IP             外设→外设
CPU_TO_IP_TO_CPU     CPU→外设→CPU（往返闭环）
IP_TO_CPU_TO_IP      外设→CPU→外设（往返闭环）
MULTI_COMPONENT_CHAIN 多组件链
```

### 1.3 维度三：角色（`source_role`）

| 角色 | 含义 | 是否算"被 Fuzz 的源" |
|---|---|---|
| `fuzz_source` | 这条 case 的**唯一被决策输入** | ✅ 计入有效例与覆盖统计 |
| `bootstrap` | 固定热身输入，用来把 DUT 带到可观测初态 | ❌ 不计数（会话首例，`case_index=0`） |
| `fixed_support` | 固定 NOP 陪跑，占住插槽 | ❌ 不计数（每个 `support_instructions` 一条接纳记录） |

### 1.4 两种在线 wiring 声明的源（真实）

| wiring | 声明源 | 种类 | 地址/端口 |
|---|---|---|---|
| Ibex＋双 PULP GPIO（`ibex_pulp_dual_source.py:1699`） | `cpu.online_instruction` | 指令 | 指令槽（真实例在 `0x11010`） |
| 同上（`:1203`） | `gpio_b.external_pin8` | 外部事件 | `gpio_b.gpio_in`，`bit_offset=8`，`width=1` |
| Ibex＋OpenTitan UART（`ibex_uart_online.py:449`） | `cpu.online_instruction` | 指令 | 指令槽 |
| 同上 | `uart.external_rx_byte` | 外部事件 | `uart.uart_rx_byte`，`width=8` |

---

## 2. 种类总览（真实运行里的分布）

| # | 种类 | 双 GPIO 运行（24 例） | UART 运行（60 例） |
|---|---|---|---|
| T1 | CPU 指令源（CPU→IP→CPU） | **9** | 21（CPU_TO_IP） |
| T2 | GPIO 外部 pin8 源（IP→CPU→IP） | **15**（+15 条 fixed_support） | — |
| T3 | UART RX 字节源（IP→CPU） | — | **36**（+36 条 fixed_support） |
| T4 | bootstrap 热身 | — | **1**（`uart-fixed-warmup`，值 `0x5a`） |
| T5 | 启动前被拒绝的 case | 0 | **3**（`input_invalid`） |
| T6 | 受控故障注入 case | 3（独立校准运行） | 1（UART 校准运行） |
| T7 | 初始 RAM 数据（非 case 输入） | opt-in 门禁 | 同 |
| T8 | 跨例链（不是新种类，是 T1/T2/T3 的跨例结果） | 见 §3 T8：P3 定向 3 条、600 秒合计 6 条 | 7 条（UART 认证链，全部跨例） |

> 计数口径：双 GPIO 运行 `plan.cases = 24 = receipts = report.tests`；UART 运行 `report.tests = receipts = 60`，而 `plan.cases = 58`（57 个已执行 case ＋ 1 个 bootstrap）——3 个被拒案例**只有回执没有 RTL 命令**，因此不在 plan 里，见 T5。

---

## 3. 逐种讲解

### T1 CPU 指令源（`cpu.online_instruction`，`CPU_TO_IP_TO_CPU`）

**真实例**：`online-1-819b265ed890cbfc934efd3e`，`address=0x11010`，`data_hex=37b1c20c13016100b710004023a62000`。

**数据流**：

```text
raw 32 bit（RFuzz 原始记录）
  │ ① ISA 约束解码：必须落成合法 RV32I、地址必须是预留指令槽、宽度不越界
  ▼
指令片段（本例如 LUI/ADDI/LUI/SW）
  │ ② instruction_source 事件 → memory_read @0x11010（writer_kinds=INSTRUCTION_SOURCE）
  ▼
Ibex 真实取指与执行                                    【CPU RTL】
  │ ③ 真实 OBI Store：0x4000100c / wdata=0x0cc2b006 / be=0xf
  ▼
DataflowRouter 按声明窗口判路                          【Router（非 RTL）】
  │ ④ mmio_acceptance → data_accept
  ▼
PULP GPIO A：gpio_target_receipt → gpio_apb_access → gpio_register_commit（逐 bit 版本）
  │ ⑤ target_request/target_response → mmio_delivery 回 CPU
  ▼
cpu_retired_transaction_target_delivery(status=linked_raw) → gpio_consumption_match(accepted)
```

**闭环判据**：`mmio_delivery.target_access_id == gpio_target_receipt.access_id`，且 `gpio_consumption_match.fullkey == mmio_acceptance.source_transaction`（六字段全等）；消费证据是**逐 bit 寄存器版本**（如 bit1 `value=1`、`version=2186`）。

**不证明**：寄存器写入 ≠ 外设行为正确；后续消费需要外设自己的观察证据。

**同一源在 UART 上的形态（`CPU_TO_IP`）**：随机指令让 CPU 写 UART 的 TXDATA（`SB lane @0x4000001c`）或读 RDATA，闭环靠 `uart_rdata_access` / `uart_fifo_pop` / `uart_retired_read_match` 三类读侧见证。

---

### T2 GPIO 外部 pin8 源（`gpio_b.external_pin8`，`IP_TO_CPU_TO_IP`）

**真实例**：`online-2-604caae5c07e4c776cb357d1`，`value=1`（pin8 拉高一位）。

**数据流**：

```text
raw 1 bit
  │ ① 归属检查：gpio_b.gpio_in[8] 必须"未被绑定"（若被 GPIO A 输出绑定则直接拒绝）
  ▼
source_injection（值 1）
  │ ② 写进 GPIO B 输入队列，按本地 tick 逐段施加
  ▼
gpio_input_segment_applied（真实采样序列 0,1,1,0,0,0,0,0,1）      【PULP GPIO B RTL】
  │ ③ 上升沿 → 原生 IRQ
  ▼
native_irq_binding_delivery（声明绑定 gpio_b.irq → cpu.irq，宽 1）
  │ ④ Runner 交付策略：irq_pulses{width_cpu_ticks:4, overrun_policy:terminate_unsupported}
  ▼
cpu_external_irq_sample → cpu_external_irq_taken（真实取中断）       【Ibex RTL】
  │ ⑤ vectored：pc=0x1012c(vector slot, rejected 自环) → 0x10200 → ISR
  ▼
ISR 真实执行：LUI x1,0x40000 → LW x2,8(x1) → SW 写 RAM
  │ ⑥ mmio_acceptance(0x40000008, read) → mmio_delivery(read_value=0x106)
  ▼
持久 RAM 写入 → 后续 case / replay 可观察
```

**闭环判据**：IRQ 交付用精确 `expected_input`/`actual_post_input`；ISR 读回值 `0x106` 里含 pin8=1；退休逐字对照 RVFI（`pc=0x10214` ↔ `LW x2,8(x1)`）。

**不证明**：不证明"这一位是中断的唯一原因"；不证明 PLIC/SoC 拓扑；IRQ **交付宽度是 Runner 策略**，不是 DUT 行为。

---

### T3 UART RX 字节源（`uart.external_rx_byte`，`IP_TO_CPU`）

**真实分布**：36 个 `fuzz_source` case ＋ 36 条 `fixed_support`（CPU 陪跑）。

**数据流**：

```text
raw 8 bit
  │ ① 归属检查 + 波形互斥闸门（若冲突：启动前拒绝，见 T5）
  ▼
source_injection（uart_rx_byte，8 位）
  │ ② 真实 8N1 RX 波形：uart_rx_bit_sample → uart_rx_receiver_start/complete
  ▼
uart_frame_validation → uart_fifo_push（entry_id=["uart",0,0,N]）  【OpenTitan UART RTL】
  │ ③ uart_irq_update（rx_watermark 类）→ uart_irq_output_definition
  ▼
native_irq_binding_delivery → cpu_external_irq_sample → cpu_external_irq_taken
  │ ④ CPU 侧：真实取中断 → ISR 读 RDATA
  ▼
uart_fifo_pop → uart_rdata_access(offset=0x18) → uart_retired_read_match(status=accepted)
```

**闭环判据**（实测 7 条）：`uart_fifo_pop.observation_event_id == uart_rdata_access.actual_request_event_id`、`uart_retired_read_match.uart_access_event_id == uart_rdata_access.event_id`、并按 `entry_id` ＋ `frame_id` join 到被 pop 的帧。

**不证明**：37 次注入里只有 7 次被真正"接收→读回"（其余停在 `uart_source_frame_begin` 之前）；IRQ→CPU 因果不被主张（只按 take 的 `source_output_key` 把该帧 entry 列为队首来归因）；polling 不可证。

---

### T4 bootstrap 热身（`source_role=bootstrap`）

**真实例**：`uart-fixed-warmup`（`case_index=0`，`direction=IP_TO_CPU`，值 `0x5a`）。

**作用**：在搜索开始前把 DUT 带到可观测初态，让第一例 fuzz case 有稳定的起点。它是**唯一不进 `fuzz_source` 计数的外部事件 case**。

**数据流**：与 T3 相同（同一个 `uart.external_rx_byte` 源、同一条路径），只是值是固定的。

**必须点名的口径差异**：bootstrap 的保留类见证（本运行 4 条 `uart_consumption_match`）**不进运行自己的 `report.json:source_target_transactions`**（记录器只覆盖已提交的搜索例），但会被"扫全 trace"的只读脚本算进第 61 个 case。两个数字（运行 73/20 对脚本 77/21）都已写明，链的证据两侧一致（`matched=21`）。

---

### T5 启动前被拒绝的 case（`status=input_invalid`）

**真实例**：3 个 UART case（`online-6`/`online-33`/`online-52`），`candidate_disposition=rejected`、`candidate_disposition_reason=source_action_prerequisite_unsatisfied`、`effective_genome_sha256=null`。

**数据流（关键：什么都没有发生）**：

```text
raw 32 bit
  │ ① 解码 + 归属检查
  ▼
source_action 先决条件查询：transport_idle（UART RX 波形必须空闲）
  │ ② 冲突 → 在任何 RTL 命令之前返回拒绝
  ▼
回执 status=input_invalid，带 code + evidence（uart-waveform-idle:1832/4456/6296）
  │ ③ 0 条 trace 事件；runner、内存、case 历史完全不动
  ▼
会话继续接纳下一例（不是停机）
```

**为什么重要**：这是**不确定语义的合理解法**——底层"RX 波形进行中的 TL-UL 访问"仍不被支持，但系统不再在运行中停机，而是把它变成可统计、可复算的拒绝（UART 臂无效/超时比例 **0.05 = 3/60**）。同类拒绝还有 `instruction_slot_unmaterialized`、`ram_byte_version` 未就绪等。

**不证明**：拒绝 ≠ 该访问在硬件上非法；只证明**当前 harness 不支持**该并发组合。

---

### T6 受控故障注入 case（校准，不是自然缺陷）

**两种形态**（都不改程序、不改外部源）：

| 形态 | 机制 | 真实证据 |
|---|---|---|
| 单故障校准 | 只改写 **checker 看到的观测副本**（如 `outputs.irq` 1→0），标 `calibration_only=true`、`observation_boundary=checker_input_copy` | 真实捕获（2 complete ＋ 1 `dut_violation`、`session_status=finding`）＋ `minimal_replay.json` ＋**新进程复现**（`violations=['gpio_b_irq_source_mismatch']`） |
| 故障族 | 通用校准运行器对 9 个变体（错 IRQ 2／错 read data 3 含 1 个 UART／重复提交 2／破坏绑定值 2）各选真实见证 | 9/9 真实 RTL 校准；只读复核 exit 0、0 失败 |

**数据流**：

```text
真实 trace（原始字节不变）
  │ ① 按声明 selector 选中一个真实见证（case_id + 事件号 + 原值）
  ▼
改写观测副本：[outputs.irq] 1 → 0        ← 只改这里
  │ ② checker 用改写后的副本求值
  ▼
不变量被违反 → finding（dut_violation）→ 会话停在 finding 并保存完整前缀
  │ ③ 写最小重放配置：原值、替换值、锚点事件号、fault_document_sha256
  ▼
新进程从最小重放启动真实 RTL → 同一 finding（可复现）
```

**闭环判据**：控制/故障两条 trace 在锚点事件上**逐字段相同**（实测 event 4609），证明报警来自 checker 不变量而非 DUT 真坏了。

**不证明**：不证明检测灵敏度、不构成自然缺陷结论、`verify` 不重跑 RTL。

---

### T7 初始 RAM 数据（**不是 case 输入**，是会话启动前的输入镜像）

| 项 | 内容 |
|---|---|
| 位置 | 会话启动**之前**决定，作为初始镜像的一部分（不是会话内写内存） |
| 真实证据 | `initial-ram-data.ram.6`（`0x100E6` = `0x94`，event 6 为 `initial_image`）；真实 Ibex 首次读该四字节（event 774、lane 2、`c0d894d8`）→ lane 值 `0x94`、writer kind `INITIAL_IMAGE`、slot 判 `immutable` |
| 数据流 | raw → 受信声明窗口/mask 内抽地址与取值 → 写入初始镜像 → CPU 真实读回（成为 F2 流的来源） |
| 不证明 | 只覆盖该声明字节与该运行目录，不证明搜索收益 |

---

### T8 跨例链（不是新种类，而是 T1/T2/T3 的跨例结果）

同一类的 case 连续跑，链可以**跨 case 闭合**：

| 形态 | 实测 | 说明 |
|---|---|---|
| 双 GPIO 600 秒运行 | 27 条认证链中 **6 条 cross_case**（同例 21 条），`cap_reached=false` | 按 direction 的细分是 `CPU_TO_IP_TO_CPU` 20／`IP_TO_CPU_TO_IP` 7；这 6 条跨例链**未按方向再细分**，故本文不把它拆到某一方向 |
| `IP_TO_CPU_TO_IP` 跨例 | P3 定向 **3 条**，`case_gap=1`（例 2 → 例 3，终点 `isr_padin_retirement`，17 跳） | 逐跳可复算 |
| UART 链跨例 | **7/7** 全部 `cross_case=true` | 帧在第 A 例注入、读发生在第 B 例（两个 case_id 都点名） |
| RAM 版本跨例 | P3 真实 **40/40** | `ram_byte_version.evidence_ref` 精确等于前例 `memory_write_commit` |

**保持的机制**：case 边界不 reset、不重装镜像；RAM 字节逐 lane 版本、DUT 寄存器逐 bit 版本、pending event/IRQ、事务账本、指令槽预留（上界 31616 槽）全部延续。

---

## 4. 种类 × 组件 × 闭环矩阵

| | T1 CPU 指令 | T2 GPIO pin8 | T3 UART RX 字节 | T4 bootstrap | T5 被拒 |
|---|---|---|---|---|---|
| 源身份 | `cpu.online_instruction` | `gpio_b.external_pin8` | `uart.external_rx_byte` | 同 T3（固定值） | 同 T1/T3 |
| 方向 | `CPU_TO_IP_TO_CPU` | `IP_TO_CPU_TO_IP` | `IP_TO_CPU` | `IP_TO_CPU` | — |
| 注入 API | `accept_instructions` | `inject_source` | `inject_source` | `inject_source` | 未到注入 |
| 参与的 DUT | Ibex ＋ GPIO A（＋B） | GPIO B ＋ Ibex（＋A） | OpenTitan UART ＋ Ibex | UART ＋ Ibex | 无 RTL |
| 参与的中间层 | Router、ownership、Scheduler | Runner IRQ 交付、Router | 波形闸门、FIFO、IRQ 交付、Router | 同 T3 | 先决条件闸门 |
| 闭环证据 | 寄存器逐 bit 版本 ＋ 退休耦合消费 | IRQ 精确交付 ＋ ISR 读回值 | pop/消费/退休 三见证精确 join | 同 T3 | 0 事件 ＋ 精确拒绝码 |
| 链证书 | 27 条中方向为 `CPU_TO_IP_TO_CPU` 的 20 条 | 27 条中方向为 `IP_TO_CPU_TO_IP` 的 7 条 | UART 链 7 条（另 30 条 incomplete） | 计入 7 条 UART 链的源 | 无 |

---

## 5. 一次会话里这些种类怎么组合

真实运行的组合方式（来自各自的 `online_plan.json`）：

```text
Ibex＋双 PULP GPIO（24 例；两个方向是交错的，不是前半 CPU、后半 IP）
  15 例 IP_TO_CPU_TO_IP  ← T2 随机 pin8 位，每例带 1 条固定 NOP（fixed_support）
   9 例 CPU_TO_IP_TO_CPU ← T1 随机程序字节，无 support
  每例 advances = 32 × [cpu, gpio_a, gpio_b]

Ibex＋OpenTitan UART（plan 58 例 = 57 个搜索例 ＋ 1 个 bootstrap，另有 3 例只存在于回执）
  case_index 0        bootstrap      ← T4 固定 0x5a，advances = 1236
  case_index 1..56    交错出现：
                        CPU_TO_IP  (T1 指令, 无 support)   × 21
                        IP_TO_CPU  (T3 RX 字节, 带 1 条 NOP) × 36
  被拒 3 例（online-6/33/52）          ← T5，只有回执、0 条 trace 事件、不进 plan
  搜索例 advances = 96 × [uart, cpu]
```

注意两处容易被说错的细节：①双 GPIO 运行里 15 个 T2 例各自带 1 条固定 NOP，而 9 个 T1 例不带 support；②UART 运行的 CPU 侧与 UART 侧 case **按决策顺序交错**（如 `0:IP,1:CPU,2:CPU,3:CPU,4:IP,5:IP,6:IP,7:CPU…`），不是分段排列。

**关键点**：Fuzzer 每例只决策**一个**上游源；"更复杂的场景"不是靠一例塞多个输入，而是靠**多例连续 + 跨例状态保持 + 路径反向选择**。

---

## 6. 一句话总结

> testcase 的种类 ＝ **被决策的输入类型**（CPU 程序字节 / 外部事件值）× **数据流方向**（6 个枚举）× **角色**（fuzz_source / bootstrap / fixed_support）。
> 落在真实运行里就是四类正例（T1～T4）、一类"什么都没发生但精确记录"的拒绝（T5）、一类只改 checker 副本的校准（T6）、一类启动前的初始镜像（T7），以及它们连续跑出来的跨例链（T8）。
> 每一种的边界都写在上面——**"我证到了哪一跳"和"我没证什么"是分开陈述的**。
