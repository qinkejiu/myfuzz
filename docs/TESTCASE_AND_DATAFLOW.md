# testcase 与一次 testcase 内的数据流

日期：2026-10-08。本文讲清三件事：**testcase 在系统里到底是什么**、**一次 testcase 里数据怎么流**、**沿途经过哪些组件**。文中所有事件号、地址、指令都取自本仓库已保存的真实运行，不举虚构例子。

> 系统结构见 [系统说明](SYSTEM_OVERVIEW.md)；**组件清单见 [组件清单与功能](COMPONENT_REFERENCE.md)**；**testcase 的完整种类与数据流矩阵见 [testcase 的种类与数据流](TESTCASE_TYPES.md)**；状态与边界见 [当前工作进度](CURRENT_PROGRESS.md)；本文用到的两个例子来自 `runs/current-dataflow-p5-chain-acceptance-20261007-online`（Ibex＋双 PULP GPIO，真实 RTL，24 例、31.27 有效秒）。

---

## 1. testcase 是什么

`OnlineCase`（定义在 `src/myfuzz/scenario/session_runtime.py:253`）的 docstring 一句话概括：

> **One input decision and the local execution needed to observe its effect.**
> 一次输入决策，以及观察它效果所需的局部执行。

拆开看：

| 说法 | 含义 |
|---|---|
| **一次输入决策** | 恰好一个上游源值：一条指令片段，**或**一个外部事件（如 GPIO 某 pin 的值、UART RX 字节） |
| **局部执行** | 一组 `advances`：把参与组件各推进若干个本地 tick |
| **不是**执行边界 | case 之间**不 reset、不重装程序镜像**；RAM、DUT 寄存器、事务账本、pending event 与会话状态全部延续 |
| **不是**数据流边界 | 一条 F1～F6 的链可以跨多个 case 才闭环（实测有 `case_gap=1` 的跨例链） |

数据结构的四个必需字段：

```python
@dataclass(frozen=True)
class OnlineCase:
    case_id: str                        # 会话内唯一；重复使用必须携带完全相同的输入
    direction: str                      # CPU_TO_IP_TO_CPU | IP_TO_CPU_TO_IP
    path_id: str                        # 数据流路径身份（sha256）
    source: OnlineInput                 # BatchSourceEvent | OnlineInstruction（二选一）
    advances: tuple[BatchAdvance, ...]  # 非空；每项是一个组件调度序列
    support_instructions: tuple[...] = ()   # 只允许固定 RV32I NOP
```

- `source` 是 `OnlineInstruction`（CPU 指令）时**不允许**带 `support_instructions`（一次只能有一个"被决策的输入"）。
- `support_instructions` 在代码层只接受固定 NOP 字，作用是"陪跑"占住插槽，不是第二个变异点。
- 同一个 `case_id` 重放时，若输入与角色与已记录的完全一致，直接返回原回执（幂等）；不一致就报错。

---

## 2. 一次 testcase 的生命周期（5 个阶段）

`ScenarioSession.submit_case()`（`session_runtime.py:745`）→ `_execute_case()`（`:814`）。顺序是固定的，而且**每一步都在真实 RTL 上留下事件**：

| 阶段 | 代码位置 | 做什么 | 前提检查 |
|---|---|---|---|
| ⓪ 先决条件闸门 | `prerequisite_gate.require_case(case)` | 在任何 RTL 命令**之前**查询跨例先决条件 | 拒绝时 runner、内存、case 历史**完全不动** |
| ① 源接纳声明 | `_case_admissions()` → `register_source_admission()` | 写出 `source_admission.v1`：`action_id`、`admission_id`、`case_id/case_index`、`direction`、`path_id`、`source_id`、`input_sha256`、`role` | 源必须**恰好匹配所选路径上的一个源节点**；宽度不得超过声明字段 |
| ② 支持指令物化 | `session.accept_instructions()`（固定 NOP） | 把固定片段写进预留的指令槽 | 组件必须支持在线指令输入 |
| ③ 源注入 | `inject_source()` 或 `accept_instructions()` | **被决策的那个输入**落地：外部事件写进 harness 的源队列，或指令片段写进指令槽 | 源 `action_id` 在会话内唯一 |
| ④ 局部执行 | `runner.step_batch(advance.schedule)` | 按 `advances` 逐项推进组件（每项是一个组件名序列） | 组件必须已注册；总步数不得超过模板上限 |
| ⑤ 观察与判定 | checker + 回执 | 该 case 的事件切片交给 checker；产出 `OnlineCaseReceipt` | checker 返回 finding → 会话停在 `finding` 并保存完整前缀 |

失败语义（这部分很重要，决定了"实验作废"还是"如实记录"）：

| 情形 | 结果 |
|---|---|
| ⓪ 被先决条件拒绝 | 回执 `status=input_invalid`，带精确 `code`/`pointer`（如 `uart_rx_waveform_conflict`）；**没有 RTL 命令执行**，会话继续 |
| ① 源与路径/宽度不符 | `ValueError`，**在任何 RTL 命令前**失败，会话不变 |
| ③④ 执行中途抛错 | 会话**立即置 `uncertain_effect` 并停止**接纳新例；因为 RTL 状态已被部分改变，不能再把下一个输入接进一个不确定的前缀 |
| ⑤ checker 抛错 | `environment_error`，停止 |
| ⑤ checker 报 finding | 回执 `status=finding`，停止接纳，保存完整会话前缀供 fresh replay |

回执 `OnlineCaseReceipt` 携带：`case_id`、`event_start`/`event_end`（该 case 在会话事件流中的确切切片）、`local_ticks_before/after`（逐组件本地 tick）、`status`、`violations`。**每个事件都带 `provenance.observed_case = {case_id, case_index}`**，所以"某个事件属于哪个 case"是精确可查的，不靠时间邻近猜。

---

## 3. 例子 A：`CPU_TO_IP_TO_CPU` — CPU 写 GPIO A

真实 case `online-1-819b265ed890cbfc934efd3e`（`case_index=1`）。

### 3.1 case 的输入

```text
direction : CPU_TO_IP_TO_CPU
source    : instruction @ 0x11010（1 个 32 位槽）
            data_hex = 37b1c20c 13016100 b7100040 23a62000   ← 32 raw bit 经 ISA 约束后解出
advances  : 32 × ["cpu", "gpio_a", "gpio_b"]
```

`data_hex` 解出来是三条半指令：

| 偏移 | 指令 | 含义 |
|---|---|---|
| +0 | `LUI x2, 0x0cc2b` | x2 = 0x0cc2b000 |
| +4 | `ADDI x2, x2, 6` | x2 = 0x0cc2b006 |
| +8 | `LUI x1, 0x40001` | x1 = 0x40001000 |
| +12 | `SW x2, 0x00c(x1)` | **写 0x4000100c** = GPIO A 的 `out` 寄存器（base 0x40001000 + 0x0c） |

即：**Fuzzer 随机的是程序字节**，它让 CPU 去写 GPIO A 的输出寄存器；写什么值、写到哪，都由这段程序决定。

### 3.2 真实事件序列（同一 case 内，事件号连续）

```text
3345  source_admission      cpu   admission_id=35f3c000… path_id=8c5173cf… role=fuzz_source
3347  instruction_source    cpu   address=0x11010  data_hex=37b1c20c13016100b710004023a62000
3348  memory_read           cpu   0x11010 ← 0x0cc2b037   writer_kinds=INSTRUCTION_SOURCE×4
3357  instr_response        cpu   0x11010  source_component=cpu          ← 取指响应
3437  cpu_retire            cpu   insn=0x0cc2b037 (LUI)
3438  cpu_retirement_match  cpu   pc=0x11010  status=accepted                ← RVFI 逐字退休
      …（ADDI、LUI 同样各有一条 retirement_match）
3666  mmio_acceptance       cpu   0x4000100c offset=12 device_id=gpio_a write=true  write_value=214085638
                                  source_transaction={channel_id:data, source_epoch:0, source_sequence:7}
                                  edge_candidates=[rule 0 mmio_route → gpio_a, rule 13 mmio_route → gpio_b]
3667  data_accept           cpu   同上
3677  gpio_target_receipt   gpio_a  access_id=gpio-access:gpio_a:0:4 raw_offset=12 status=received
                                  raw_payload: gpio_req_wdata=214085638 gpio_req_be=15 gpio_dir=255
3681  gpio_apb_access       gpio_a  phase=pre/post 观察点
3683  gpio_register_commit  gpio_a  register="out" operation=overwrite
                                  逐 bit 版本：bit0 value=0 version=2185, bit1 value=1 version=2186, …
                                  每个 bit 带同一个 transaction 键（source_sequence=7）
3687  target_request        gpio_a  raw_offset=12 status=observed
3689  target_response       gpio_a  raw_offset=12 status=observed
3690  mmio_delivery         cpu    delivery_order=7 target_access_id=gpio-access:gpio_a:0:4
3770  cpu_retired_transaction_target_delivery  cpu  status=linked_raw
                                  内嵌 consumer_resource：target_apb_access（含 pre/post 全寄存器快照，
                                  其中 gpio_out=214085638）
3771  gpio_consumption_match gpio_a status=accepted  fullkey=同一个 data 事务键
                                  proof_resource=逐 bit {register:"out", value, version, local_tick=109}
```

### 3.3 这条路径上数据怎么变

```text
raw 32 bit
   │  ① ISA 约束解码（RV32I，写的是预留指令槽）
   ▼
程序字节 0x0cc2b037 0x00610113 0x4000b7 0x0020a623        【CPU 取指通道】
   │  ② Ibex 真实取指（memory_read @0x11010，writer=INSTRUCTION_SOURCE）
   ▼
CPU 执行 LUI/ADDI/LUI/SW                                  【CPU 核内】
   │  ③ 真实 OBI Store：地址 0x4000100c、wdata=0x0cc2b006、be=0xf
   ▼
DataflowRouter 按声明窗口判路（rule 0 → gpio_a，4096 B @0x40001000）【Router】
   │  ④ mmio_acceptance → data_accept（CPU 侧）
   ▼
PULP GPIO A APB3 从端：gpio_target_receipt → gpio_apb_access → gpio_register_commit
   │  ⑤ register "out" 逐 bit 写版本（bit0=0/bit1..=1），local_tick 109
   ▼
target_request/target_response → mmio_delivery 回到 CPU                    【回程】
   │  ⑥ 退休耦合：cpu_retired_transaction_target_delivery(status=linked_raw)
   ▼
gpio_consumption_match(status=accepted)                                   【消费闭环】
```

**闭环的判据**：`mmio_delivery.target_access_id` ＝ `gpio_target_receipt.access_id`，且 `gpio_consumption_match.fullkey` ＝ `mmio_acceptance.source_transaction`（六字段全等），并且消费证据是**逐 bit 的寄存器版本**，不是"地址相同"。

---

## 4. 例子 B：`IP_TO_CPU_TO_IP` — 外部 pin 中断 → ISR 读回

真实 case `online-2-604caae5c07e4c776cb357d1`（`case_index=2`）。

### 4.1 case 的输入

```text
direction : IP_TO_CPU_TO_IP
source    : source_event  component=gpio_b  port=gpio_in  bit_offset=8  width=1  value=1
            action_id = online-2-…:gpio_b.external_pin8
advances  : 32 × ["cpu", "gpio_a", "gpio_b"]
```

即：**Fuzzer 随机的是外部环境值**——GPIO B 的 pin 8 拉高一位。程序本身不是本例的变异点。

### 4.2 真实事件序列

```text
4518/4519 source_admission      （本 case 与被绑定输入的接纳声明）
4520  source_injection    gpio_b  port=gpio_in bit_offset=8 width=1 value=1   ← 源落地
4545… gpio_input_segment_applied gpio_b value=0,1,1,0,0,0,0,0,1            ← pin 真实采样
4614  cpu_external_irq_sample cpu  expected_input=1 actual_post_input=1     ← IRQ 到达 CPU 输入
4699  cpu_external_irq_taken  cpu  expected_input=1 actual_post_input=1     ← CPU 真实取中断
4745  cpu_irq_notification    cpu  expected_input=1 actual_post_input=1
4912  cpu_retirement_match    cpu  pc=0x1012c status=rejected               ← vector slot（自环哨兵）
5027  cpu_retirement_match    cpu  pc=0x10200 status=rejected
5188… cpu_retirement_match    cpu  pc=0x10204/0x10208/… status=accepted     ← ISR 真实执行
5477  cpu_retirement_match    cpu  pc=0x10210 insn=0x400000b7 (LUI x1,0x40000)
5511  mmio_acceptance         cpu  0x40000008 offset=8 device_id=gpio_b write=false   ← ISR 读 PADIN
5560  mmio_delivery           cpu  0x40000008 read_value=262 (=0x106)               ← 读到 pin8 位
5663  cpu_retirement_match    cpu  pc=0x10218 insn=0x000101b7 (LUI x3,0)
      …（随后几条 SW 把 x1/x2/x3 写进 RAM，形成可观测结果）
```

ISR 的指令（从 RVFI 退休逐字解出）：

| pc | 指令 | 作用 |
|---|---|---|
| 0x10210 | `LUI x1, 0x40000` | x1 = 0x40000000（GPIO B base） |
| 0x10214 | `LW x2, 0x8(x1)` | **读 PADIN**（offset 8）→ x2 = 0x106 |
| 0x10218 | `LUI x3, 0` | x3 = 0 |
| 0x1021c… | `SW x1/x2/x3, 0(x31)…` | 把 base/padin/cause 存进 RAM |

### 4.3 这条路径上数据怎么变

```text
raw 1 bit
   │  ① 约束与归属检查：gpio_b.gpio_in[8] 必须是"未绑定"位（若被 GPIO A 输出绑定则拒绝）
   ▼
source_injection（值 1）                                   【环境源】
   │  ② 写进 GPIO B 的输入队列，由本地 tick 逐段施加
   ▼
gpio_input_segment_applied（真实 pin 采样序列 0,1,1,0,0,0,0,0,1）【PULP GPIO B RTL】
   │  ③ 上升沿 → 原生 IRQ
   ▼
native_irq_binding_delivery（声明绑定 gpio_b.irq → cpu.irq，宽度 1）  【Runner 的 IRQ 交付】
   │  ④ 交付策略：irq_pulses 声明宽度 4 个 CPU tick，overrun_policy=terminate_unsupported
   ▼
cpu_external_irq_sample → cpu_external_irq_taken（CPU 真实取中断）      【Ibex】
   │  ⑤ vectored：pc 跳到 0x10200（rejected 的 vector slot 是自环哨兵）→ ISR
   ▼
mmio_acceptance(0x40000008, read) → mmio_delivery(read_value=0x106)     【Router + GPIO B】
   │  ⑥ 读回的值就是 pin8=1 所在的 PADIN 字
   ▼
SW 写入持久 RAM → 后续 case 或 replay 可观察                        【跨例结果】
```

**与例子 A 的本质差别**：

| | 例子 A（CPU→IP→CPU） | 例子 B（IP→CPU→IP） |
|---|---|---|
| 被决策的输入 | **程序字节**（写在预留指令槽） | **外部事件值**（GPIO pin / peer 字节） |
| 程序的角色 | 就是变异对象 | 固定支持代码（ISR） |
| 谁触发动作 | CPU 执行指令 | 外设 RTL 的真实 IRQ |
| 消费闭环 | 寄存器提交 + 退休耦合消费 | ISR 真实读回值 + 写 RAM |

---

## 5. 涉及哪些组件

### 5.1 双 PULP GPIO wiring（例子 A/B 所用）

来自该运行的 `online_session_manifest.json`：

| 组件 | 实例 | 角色 | 真实 RTL 身份 |
|---|---|---|---|
| CPU | `cpu` | Ibex（OBI）＋RVFI 退休探针 | `build_identity.artifact_digest=9f192578…`，Verilator 5.051 |
| 外设 A | `gpio_a` | PULP GPIO，APB3，4096 B @ `0x40001000` | `pulp_gpio_causal_local/component_profile.json` |
| 外设 B | `gpio_b` | PULP GPIO，APB3，4096 B @ `0x40000000` | 同上（另一实例） |
| 内存 | `ram` | host 侧 `PersistentMemory`；指令槽 `[ram, 4096…]` 预留 | 由 `memory-init-v1`、`initialization_seed=37` 初始化 |

`bindings`（声明式绑定，不可当随机源）：

| 源 | 目标 | 宽度 |
|---|---|---|
| `gpio_a.gpio_out` | `gpio_b.gpio_in` | 8 |
| `gpio_b.irq` | `cpu.irq` | 1 |

`irq_pulses`：`{binding: gpio_b.irq→cpu.irq, width_cpu_ticks: 4, overrun_policy: terminate_unsupported}` —— 注意这是 **Runner 的交付策略**，不是 DUT 行为。

`windows`：`cpu` 只能通过 `0x40001000`（→gpio_a）与 `0x40000000`（→gpio_b）两个声明窗口访问外设。

### 5.2 不产生 RTL 的"控制面"组件

| 组件 | 模块 | 在一次 case 里做什么 |
|---|---|---|
| 依赖图 / 路径 | `runtime_path_contract.py`、`dependency.py` | 决定 `path_id` 与哪些源/边属于这条路径 |
| 所有者表 | `ownership.py` | 判定源是否可写（`bound_input`/`fixed_input` 直接拒绝） |
| 路由 | `router.py`（`DataflowRouter`） | 按声明窗口把 CPU 的 MMIO 事务送到目标 session |
| 调度 | `scheduler.py` | 按 `advances` 推进各组件本地 tick |
| 内存服务 | `memory_service.py`、`memory.py`、`ledger.py` | 提交/回滚 RAM 事务，冻结写事务键与逐 lane 版本 |
| 先决条件闸门 | `dynamic_prerequisites.py`、`source_actions.py` | 在 RTL 之前判 `instruction_slot` / `ram_byte_version` / `transport_idle` |
| 检查器 | `checker.py`、`assertion_classes.py` | 协议 / 跨组件 / CPU-IP 三类断言分开计数 |
| 证书 | `chain_certificates.py`、`edge_provenance.py`、`uart_chain_certificates.py` … | 从事件流生成可复算的链与逐边证据 |
| 运输 | `integration/scenario_rfuzz*.py` ＋ `kfuzz` | 把候选提交给 fuzzer 进程；回执与事件切片的来源 |

### 5.3 UART 异构 wiring 的组件差异（对比用）

`runs/p5-uart-routing-gate-20261008-online` 的组件是 `cpu`（Ibex）＋ `uart`（OpenTitan TL-UL，窗口 base `0x40000000`、size `0x1000`）。它的 case 类型多一种：

```text
CPU 侧候选：instruction 源 → MMIO 写 UART（TXDATA @0x4000001c，SB lane）
UART 侧候选：source_event（uart.external_rx_byte）→ 真实 8N1 RX 波形 → FIFO → IRQ → CPU 读 RDATA
启动前拒绝：UART 波形进行中的 TL-UL 访问 → input_invalid（uart_rx_waveform_conflict，
            证据 uart-waveform-idle:1832/4456/6296，先决条件 kind=transport_idle）
```

---

## 6. 跨 case 保持什么

普通 case 边界**不做**的事：不 reset、不重装程序镜像、不要求事务已结清。保持下来的东西：

| 状态 | 载体 | 后续 case 如何用它 |
|---|---|---|
| RAM 字节及其版本 | `PersistentMemory` + 逐 lane `versions` | 跨例读回（`ram_byte_version` 先决条件精确等于前例 `memory_write_commit`） |
| DUT 寄存器与引脚 | 真实 RTL 内部状态 + `gpio_register_commit` 的逐 bit `version` | 下例的 RTL 从该状态继续 |
| pending event / IRQ | RTL 与 Runner 的事件队列 | 后续 case 可能消费前例产生的中断 |
| 事务账本 | `ledger.py` | 重复事务复用原凭据，不重复计数 |
| 指令槽预留 | 会话级 slot 表 | 每例只物化自己声明的槽位，上界 `(0x2fe00-0x11000)/4 = 31616` |
| 反馈与能量 | `feedback.py`、`interaction_feedback.py` | 影响后续 case 的选源/选路 |

实测到的跨例形态：`CPU_TO_IP_TO_CPU` 有 `case_gap=1` 的跨例链（600 秒运行 6 条）；UART 侧 7 条认证链全部是"帧在第 A 例注入、读发生在第 B 例"的跨例见证链。

---

## 7. 故障注入 case 有什么不同

受控故障（P5）**不改程序、不改外部源**，而是**改写 checker 看到的观测副本**：

```text
正常：真实 trace → checker 输入 = 真实观测
校准：真实 trace → checker 输入 = 真实观测 + 声明式改写（如 outputs.irq 1→0）
       标记 calibration_only=true、observation_boundary=checker_input_copy
结果：checker 报 gpio_b_irq_source_mismatch，会话停在 finding；
       最小重放输入 minimal_replay.json 记录原始值、替换值与锚点事件号
复现：在新进程里从最小重放启动真实 RTL，得到同一 finding
```

关键点：**原始 trace 字节不变**（控制/故障两条 trace 的观测事件逐字段相同），所以"报警"确实来自 checker 的不变量，而不是 DUT 真的坏了。

---

## 8. 一句话总结

> 一次 testcase ＝**一个上游源值 ＋ 让它生效所需的局部 tick 序列**；它不划定执行边界，只划定"这一次决策"。
> 数据流在 case 内走：**源 → 真实 RTL 执行 → 事务/事件交付 → 真实消费 → 可观测结果**；
> 沿途身份（`admission_id`、事务六字段键、`access_id`、逐 bit 版本）把每一步钉死，所以"谁消费了谁"是**可复算**的，而不是"时间上挨着"。

---

### 附：本文用到的原始产物

| 文件 | 内容 |
|---|---|
| `runs/current-dataflow-p5-chain-acceptance-20261007-online/online_plan.json` | 24 个 case 的完整声明（direction/path/source/advances） |
| `runs/current-dataflow-p5-chain-acceptance-20261007-online/online_session_manifest.json` | 组件、构建身份、绑定、窗口、IRQ 交付策略、owner |
| `runs/current-dataflow-p5-chain-acceptance-20261007-online/receipts.jsonl` | 每例回执（事件切片、本地 tick、状态） |
| `runs/current-dataflow-p5-chain-acceptance-20261007-online/online_final_trace.json` | 31,795 个事件（含本文引用的每个事件号） |
| `runs/current-dataflow-p5-final-20261007-logs/case_flow_example.tsv` | 例子 A 的完整事件序列（本次提取） |
| `runs/current-dataflow-p5-final-20261007-logs/case_flow_ip2cpu2ip.tsv` | 例子 B 的完整事件序列（本次提取） |
