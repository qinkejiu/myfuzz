# IRQ/F5 可声明范围的扩展：盘点、新声明与真实批次

日期：2026-11-01。状态：**声明层与真实 RTL 批次**。本轮新增两个设备行为文件、五个场景配置、一个纯 Python 测试和五条真实 fuzz 批次；没有改任何既有文件，也没有新增 CPU/总线适配器。本文只陈述能由真实 profile、固定 RTL 源码和本轮 `runs/stage2-irq-decl-20261101/` 的 case 行核对的事实；它不是覆盖率、不是证书、不是 replay，也不证明设备因果。

本轮回答三件事：

1. 现有 IRQ 声明各自是什么（CPU 输入/ABI、端口/位、pulse/level、状态读、清除/EOI、cause、是否多源），哪些已能由声明表达，哪些仍写死在执行器/宿主里；
2. 在不改执行器的前提下，能新声明出哪一种 IRQ 变体，并用真实批次证明它被交付、被读取、被分类；
3. 一个“仍然有效的 level IRQ”跨 case 时如何被分类和报告，以及本宿主诚实的边界（无 EOI、无 cause 采样、`clear_writes` 与通过判据冲突、无覆盖率/证书/replay）。

---

## 1. 现有声明的盘点与分类

### 1.1 从真实文件读出的 F5 声明

| 设备 / 声明文件 | CPU IRQ 输入与 ABI | 源端口 / 位 | pulse / level | 状态读 | 清除 / EOI | cause 位 | 多源 |
|---|---|---|---|---|---|---|---|
| PULP APB Timer（overflow）`configs/behaviors/pulp_timer_f5.json:11-17`，场景 `configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json:9-15` | Ibex / CV32E20 的 OBI 1-bit machine-external | `irq_o[0]`（profile `timer0_overflow`，`bit 0`） | **pulse**：profile `trigger: pulse`、`pulse_width_cycles: 1`；宿主按声明拉宽 16 tick | `TIMER0_COUNT` offset 0，`rw`，宿主报告 kind `count` | 无 ack：profile 写“Automatic counter reset … no acknowledge register”；`clear_writes: []` | `null`（timer 的 IRQ 是组合等式输出，不是状态字） | 是：目标 link 0 + ZipDMA 完成 link 1 |
| PULP APB SPI（EOT）`configs/behaviors/pulp_spi_eot_f5.json:10-16`，场景 `configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json:17-38` | 同上 | `events_o[1]`（profile `spi.eot`，`bit 1`） | **pulse**：`assign events_o[1] = s_eot;` 一拍；宿主拉宽 16 tick | `INTSTA` offset 40（0x28）；profile 明确 0x28 没有 read-mux 分支，录得的 F5 状态读为 0 | 无：pulse 自己结束；`clear_writes: []` | `null` | 场景本身只有目标源；timer+ZipDMA 场景才是双源 |
| PULP APB GPIO `configs/behaviors/pulp_gpio_f5_pins.json:12-19`，场景 `configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5-fuzz.json:17-42,78` | 同上 | `interrupt[0]`（profile `gpio.interrupts`，`bit 0`） | **pulse**（profile 明确 `trigger: pulse`、`pulse_width_cycles: 1`；`interrupt=s_rise_int`，不是 `OR(r_status)`）。**注意**：这里不是 level IRQ；是“pulse IRQ + 读清的独立状态字” | `INTSTATUS` offset 36（0x24），`ro`、`side_effect: read_clears` | 不是写清：读 `INTSTATUS` 清状态；`INTSTATUS` 是 `ro`，执行器会拒绝把它当 `clear_writes`（本轮测试钉住）。`clear_writes: []` | `null`；运行记录另有真实引脚 cause：`irq_cause_pins`、`inten_at_irq`（C++ `scripts/inprocess_obi_apb_f1f4_spike.cpp:1543-1544,2336`） | 单源场景 |
| ZipDMA（F6 完成中断）`configs/behaviors/zipdma_f6.json:11-13` + 场景 `dma_capability` | 同上 | `o_interrupt[0]`（宿主生成绑定） | **level**（`summary.irq_sources` 里 `trigger: level`、`delivery_ticks: 0`） | 不经 F5 状态字；F6 读 `CONTROL_STATUS` | **写清**：`clear {offset 0, value 0x80000000}`，来自 DMA 源声明（`src/myfuzz/scenario/f6_dma_source_provider.py:17-77`；执行器 `scripts/run_inprocess_f1f6.py:643-646`），**不在** `configs/behaviors/*.json` | F6 不声明 cause 位；busy/err 位由行为文件或 builtin 默认 | 双源中的 link 1 |
| wbdmac（F6 完成中断）`configs/behaviors/wbdmac_f6.json:9-11`，profile `inprocess_generality_wbdmac` | 同上 | `o_interrupt`（生成绑定） | **pulse**（profile `trigger: pulse`） | 同 F6，不读 F5 状态 | DMA 源声明 | busy/err 位 31/30 由行为文件声明 | 双源中的 link 1 |

结论（按真实文件，而不是按任务标题的字面）：

- **Timer 是 pulse**（两拍输出：overflow 与 compare），没有 ack 寄存器，`clear_writes` 为空是设备事实，不是漏写。
- **SPI EOT 是 pulse**，状态字 0x28 在固定 RTL 上没有读通道，录得的读值为 0；把它写成 status 是 profile 的真实结论。
- **GPIO 不是 level IRQ**：profile 明确 `trigger: pulse`，`INTSTATUS` 是“读清”的独立状态字。把 GPIO 描述成 “level/clear” 会与固定 RTL 冲突；本轮测试专门钉住“不能把 `INTSTATUS` 声明成 `clear_writes`”（`tests/fuzz/test_irq_declaration_expansion.py::test_a_cleared_level_source_needs_a_writable_word_which_the_gpio_does_not_have`）。
- **DMA 完成中断是 level**，清除是源声明里的真实写（ZipDMA 控制字 bit 31），不是 F5 行为文件的键；这就是本轮批次里 level 交付有真实证据、且不会跨 case 遗留的原因（handler 真的执行了那次写）。

### 1.2 CPU IRQ 输入 / ABI 的真实清单

| CPU（profile） | 声明的 IRQ 输入 | 本入口怎么处理 | 锚点 |
|---|---|---|---|
| Ibex（`configs/cpus/ibex_rvfi_local`） | 1-bit、`active_high`、`machine_external` | 正常交付；F5 可用 | `scripts/run_inprocess_f1f6.py:293-301, 1204-1208` |
| CV32E20（`configs/cpus/cv32e20`） | 1-bit、`active_high`、`machine_external` | 同上；与 Ibex 只差 CPU artifact，本轮用同一新声明跑通 | 同上 |
| PicoRV32 Wishbone（`configs/cpus/picorv32_wb_irq_rvfi`） | 32-bit `irq` 向量，无逐位接线声明 | 未声明 `cpu_irq_bit` 时整条向量被钉 0，F5 按名拒绝：`unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero`；声明 `cpu_irq_bit: 3..31` 后走“自定义 IRQ 位 + CPU 自己的 EOI 向量”路径（`scripts/inprocess_wishbone_irq.py:8-34`，EOI 字 `0x0400000b`） | `scripts/run_inprocess_f1f6.py:498-500, 2760-2768`；C++ `1139-1142, 1307-1323` |
| ZipCPU axiluart（AXI4-Lite 目标，不是 CPU） | 4 个 **level** 输出，各自独立端口：`o_uart_rx_int`、`o_uart_rxfifo_int`、`o_uart_tx_int`、`o_uart_txfifo_int` | 执行器**结构上**接受单个 level 源（本轮测试用 `o_uart_tx_int` 验证 `trigger: level`、`pulse_ticks: 0`），但没有场景声明它：tx/txfifo 在复位后就为高（会在 F5 之外打断 CPU），rx 需要串行激励而本宿主不随时间驱动 RX；现有场景按缺事实拒绝：`unsupported-f5:target-irq-semantics:axi4-lite:source_port,source_bit_offset,trigger_writes,status_offsets` | 拒绝理由写在 `configs/scenarios/inprocess-obi-axi4lite-axiluart-zipdma-f1f6-fuzz.json` 的 notes；拒绝原文见 `runs/stage2-acceptance-20261101/axiluart-80/summary.json` 的 `f5.reason` |
| OpenTitan rv_timer/gpio/uart（`*_local`） | 声明 level IRQ、`INTR_STATE` W1C 清除、逐位 cause，形式上最丰富 | **本入口跑不了**：目标侧只有 APB3 与 AXI4-Lite 两种协议，这些 profile 的 MMIO 是 TL-UL；`profile_protocol()` 直接拒绝 `unsupported-target-protocol:tl-ul/1` | `scripts/run_inprocess_f1f6.py:229-262`；本轮纯 Python 验证了该拒绝 |

所以：**不能声称“所有 CPU IRQ ABI 都支持”**。本入口支持的是“OBI 上的 1-bit、active-high、machine-external”和“PicoRV32 Wishbone 上由 `cpu_irq_bit` 指定的自定义位 + EOI”；其他宽度/极性/向量入口、NMI、PLIC 都没有适配器。level 交付本身是支持的（DMA 完成中断每批都在用），但“level 目标 IRQ”在现有可运行设备里没有可诚实声明的触发序列。

### 1.3 已能声明 vs 仍写死（精确锚点，本轮未改）

| 关注点 | 今天可声明 | 仍写死在执行器/宿主（file:line） |
|---|---|---|
| CPU IRQ 输入 | CPU profile 的 `cpu.irq_entry_endpoint/role/polarity/semantics` | 输入必须由 endpoint_id 以 `interrupts` 结尾的 input 找到：`scripts/run_inprocess_f1f6.py:293-301`；OBI 必须 1-bit/active-high/machine-external：`1197-1208`；Wishbone 必须声明 `cpu_irq_bit`：`498-500, 2760-2768` |
| 源端口/位 | `source_port`、`source_bit_offset`（单个整数 0..63） | 必须恰好匹配 profile 的**一个** `(bit, role, alias)`：`scripts/run_inprocess_f1f6.py:455-465`；行为层只接受整数位：`src/myfuzz/composition/inprocess_behavior.py:213-217` |
| pulse / level | profile 的 `interrupts[].trigger`；行为文件只声明 pulse 的宿主拉宽 `pulse_width_ticks` | 极性/触发枚举、pulse 必须有 1..4096 宽度：`scripts/run_inprocess_f1f6.py:467-473`；交付实现：C++ `363-367, 1503-1561`；level 无宽度（`pulse_ticks 0`） |
| 状态读 | `status_offsets`（**恰好 1 个**） | 必须 32-bit 可读：`scripts/run_inprocess_f1f6.py:433-438`；kind 由寄存器名子串决定：`404-423, 477`；ISR 只读这一个字：`1033-1034`；F5 通过判据要求 `target_reads == 1`：C++ `2135-2136` |
| 清除 / EOI | `clear_writes`（**最多 1 条** `[offset,value]`），ISR 真的执行：`scripts/run_inprocess_f1f6.py:951-956, 1041-1044` | 必须 32-bit 可写：`447-454`；**但 F5 通过判据把目标写次数固定为触发次数**：C++ `2136, 2140`；因此目标上的 clear 写会让每个触发的 F5 case 失败（见 §5） |
| cause 位 | `status_cause_bits` 形状（null 或 0..31 数组） | 没有采样：C++ case 行永远打印 `isr_cause unknown`（`2331`）；summary 的 `irq_cause observed` 只看 `IP_CAUSE_DECLARED`（`2594-2596`，Python 侧 `1352`）；GPIO 的 cause 是引脚 mask，不是状态位（`1543-1544, 2336`） |
| 多源组合 | 目标源 + DMA 完成源两条 link；顺序固定 target=0、dma=1 | 目标侧只能有一个源：`scripts/run_inprocess_f1f6.py:1296-1310, 3012-3022`；`f5_declaration` 只返回一个 dict：`482-504`；ISR 只有一组 status/result/clear 单元：`1033-1048`；`flow_arity` 的 F5 只数触发写：`710-721` |
| 目标协议 | APB3 / AXI4-Lite | 其他协议按名拒绝：`scripts/run_inprocess_f1f6.py:229-262`（TL-UL 实测 `unsupported-target-protocol:tl-ul/1`） |

---

## 2. 新声明：在不改执行器的前提下能扩展什么

本轮新增两个 F5 行为文件（同一台 PULP APB timer 的另外两个真实源）与五个场景。

### 2.1 `configs/behaviors/pulp_timer_compare_f5.json`（timer0 compare，`irq_o[1]`）

| 键 | 值 | 真实依据 |
|---|---|---|
| `source_port` / `source_bit_offset` | `irq_o` / `1` | profile `pulp_timer_irq` 的 `timer0_compare`（bit 1）；`third_party/soc-pulp-apb-timer/src/apb_timer.sv` 的 `irq_o[2*k+1:2*k]`，k=0 → bit 1 |
| `pulse_width_ticks` | 24 | **宿主交付宽度**，不是 RTL 宽度：profile 写 `pulse_width_cycles: 1`，host 拉宽；同设备的兄弟文件用 16/32，说明这是场景选择 |
| `trigger_writes` | `[[4,0],[8,3],[0,3]]` | `TIMER0_CTRL=0, TIMER0_CMP=3, TIMER0_COUNT=3`。`timer.sv`：写 CMP 会把 count 清 0；`irq_o[1] = (REG_CMP != 0 && REG_TIMER == REG_CMP && prescaler == cycle_counter)`；CTRL[0]=0 时 count 不递增，所以“写 COUNT=CMP”是一次性等式，事件后 RTL 把 count 清 0，不会自重新武装 |
| `status_offsets` | `[8]` | profile `TIMER0_CMP`（rw, 32-bit）；ISR 读 compare 字，case 行报 `isr_read_register_kind compare` |
| `status_cause_bits` | `null` | timer 没有状态/cause 字，IRQ 是组合等式输出 |
| `clear_writes` | `[]` | profile 与 `timer.sv` 都说明事件后自动清 count、无 ack 寄存器 |

这个变体同时覆盖：**第二个源位**（bit 1 而不是 0）、**不同的触发序列语义**（等值写 vs 溢出写）、**不同的状态读寄存器与 kind**（compare vs count）、**不同的交付宽度**（24 vs 16）。它不覆盖 level，也不覆盖 clear/cause（见 §5 为什么不能诚实地声明）。

### 2.2 `configs/behaviors/pulp_timer1_overflow_f5.json`（timer1 overflow，`irq_o[2]`）

| 键 | 值 | 真实依据 |
|---|---|---|
| `source_port` / `source_bit_offset` | `irq_o` / `2` | profile `timer1_overflow`；`irq_o[2*k+1:2*k]`，k=1 → bit 2 |
| `pulse_width_ticks` | 32 | 宿主交付宽度，与 timer0 的 16、compare 的 24 都不同 |
| `trigger_writes` | `[[20,0],[24,0],[16,4294967295]]` | timer1 窗口 `0x10/0x14/0x18`（`TIMER1_CTRL/CMP/COUNT`）。`apb_timer.sv` 用 `PADDR[4]` 选择实例（`slave_address_int = PADDR[4:4]`，TIMER_CNT=2）；`timer.sv` 的 overflow 条件 `REG_TIMER == 0xffffffff` 等价于“直接写 COUNT=0xffffffff” |
| `status_offsets` | `[16]` | profile `TIMER1_COUNT`（rw, 32-bit），kind `count` |
| `status_cause_bits` / `clear_writes` | `null` / `[]` | 同 timer 的设备事实 |

事实核对由测试逐项完成：断言的 bit、source_id、trigger、极性、端口 alias、trigger/status 偏移、寄存器宽度/可写性都直接读 profile，而不是复制本文件的说法（`tests/fuzz/test_irq_declaration_expansion.py::test_each_new_file_states_only_facts_the_profile_declares`）。

### 2.3 场景

| 文件 | 用哪个行为文件 | 与基准的唯一差别 | CPU / ABI |
|---|---|---|---|
| `configs/scenarios/inprocess-obi-apb-ibex-timer-overflow-baseline-fuzz.json` | 既有 `pulp_timer_f5.json` | —— | Ibex / OBI 1-bit |
| `configs/scenarios/inprocess-obi-apb-ibex-timer-compare-f5-fuzz.json` | 新 `pulp_timer_compare_f5.json` | `source_behavior`（其余键逐项相同，测试钉住 `differing == {"source_behavior"}`） | Ibex / OBI 1-bit |
| `configs/scenarios/inprocess-obi-apb-ibex-timer1-overflow-f5-fuzz.json` | 新 `pulp_timer1_overflow_f5.json` | 源声明 | Ibex / OBI 1-bit |
| `configs/scenarios/inprocess-cv32e20-timer1-overflow-f5-fuzz.json` | 同上 | 只换 CPU profile | CV32E20 / OBI 1-bit |
| `configs/scenarios/inprocess-wbcpu-apb-timer1-overflow-f5-fuzz.json` | 同上 | 换 CPU、`cpu_irq_bit: 3`、RAM 从 0、`handler_wait_iterations 64`、`case_tick_budget 12000` | PicoRV32 / **自定义 IRQ 位 + EOI** |

场景只写 `"source_behavior": "configs/behaviors/..."`，不再重复设备事实；执行器仍把行为文件与 profile 的寄存器映射、中断声明交叉校验（`scripts/run_inprocess_f1f6.py:2769-2775` 的 `f5_declaration`）。文件与内联值冲突按 `behavior-source-conflict:<key>` 拒绝（模块 `245-284`），本轮测试覆盖了 6 个键。

---

## 3. 真实批次

命令、顺序、缓存见 `runs/stage2-irq-decl-20261101/commands.txt`；证据索引见同目录 `README.md` 与 `evidence.json`。五条批次一次一个 RTL 进程，共用一个缓存。

| 批次 | case | 状态 | 失败分类 | F5 case（通过） | `irq_edges/irq_takes/wait_timeouts/device_resets` | `total_seconds`（含一次构建） |
|---|---|---|---|---|---|---|
| `baseline-120` | 120 | `fuzz_completed` | `{passed 114, not_triggered 6}` | 10（4） | 32/32/6/6 | 24.57 |
| `compare-120` | 120 | `fuzz_completed` | `{passed 114, not_triggered 6}` | 8（2） | 24/24/6/6 | 11.90 |
| `timer1-80` | 80 | `fuzz_completed` | `{passed 76, not_triggered 4}` | 7（3） | 13/13/4/4 | 12.25 |
| `cv32e20-timer1-80` | 80 | `fuzz_completed` | `{passed 76, not_triggered 4}` | 7（3） | 13/13/4/4 | 14.54 |
| `wb-custom-80` | 80 | `fuzz_completed` | `{passed 76, not_triggered 4}` | 7（3） | 13/13/4/4 | 13.83 |

五批 `findings` 都是 0，`fuzz.json` 的 `session_status` 都是 `completed`，`expected_failures` 为 6/6/4/4/4；即所有失败都是随机值没有让设备产生中断，没有协议/设备/执行异常，也没有对应不符。`summary.json` 明写 `certificate: "none"`、`replay: "not_performed"`。

### 3.1 A/B：只换源声明

`baseline-120` 与 `compare-120` 用同一 CPU、同一 DMA、同一窗口、同一 `f1_program_words: 4`、同一 `handler_wait_iterations: 128`、同一 seed；差别只有 `source_behavior`。两批的 case 流分布和通过数因此高度一致，但 F5 的**状态读**和**交付宽度**不同：

| 批次 | 第 0 例（种子=声明示例向量） | 状态读 | kind | `delivered_high_ticks` / `device_high_ticks` |
|---|---|---|---|---|
| baseline | `F5:00000000:00000000:ffffffff` | offset 0，值 0 | `count` | 16 / 1 |
| compare | `F5:00000000:00000003:00000003` | offset 8，值 3 | `compare` | 24 / 1 |

`compare-120` 第 0 例的完整关键字段（原文）：

```
case 0 observations_passed flow F5 record F5:00000000:00000003:00000003 ... trigger_writes 3
apb_read_offset 0x00000008 apb_read_data 0x00000003 apb_last_write_offset 0x00000000
apb_last_write_data 0x00000003 irq_edges 1 irq_high_ticks 1 device_high_ticks 1
delivered_high_ticks 24 irq_takes 1 wait_timeout 0 isr_result 0x00000003 isr_flag 1
isr_read_addr 0x40001008 isr_read_value 0x00000003 isr_read_register_kind compare isr_cause unknown
```

失败的一例（`CMP=0x40002003`、写入的 `COUNT=0x00000403` 不相等，等式不成立；等待到期）：

```
case 13 failed flow F5 record F5:00000000:40002003:00000403 ... apb_read_offset 0x00000000
apb_read_data 0x00000000 ... irq_edges 0 irq_high_ticks 0 device_high_ticks 0
delivered_high_ticks 0 irq_takes 0 wait_timeout 1 ... isr_flag 0 ... isr_cause unknown
```

这被分类为 `not_triggered`（`expected: true`），不是设备缺陷：声明的触发值本身要求两个字相等，随机变异经常只改其中一个。

### 3.2 第二个源位与第二个 timer 实例

`timer1-80` 的通过例（第 0 例）与 baseline 的唯一差别是 bit 2 / 32 tick / 状态 offset 16：

```
case 0 observations_passed flow F5 record F5:00000000:00000000:ffffffff ... apb_read_offset 0x00000010
apb_read_data 0x00000000 ... apb_last_write_offset 0x00000010 apb_last_write_data 0xffffffff
irq_edges 1 device_high_ticks 1 delivered_high_ticks 32 irq_takes 1 wait_timeout 0
isr_result 0x00000000 isr_flag 1 isr_read_addr 0x40001010 isr_read_value 0x00000000
isr_read_register_kind count isr_cause unknown
```

第 54 例展示了 count 源的真实状态语义：变异把 `TIMER1_CTRL` 写成 1（计数使能），`COUNT=0xfffffbfd` 在几拍内数到 `0xffffffff` 触发 overflow；事件后 count 清 0 并继续计数，ISR 读到时是 15：

```
case 54 observations_passed flow F5 record F5:00000001:40002002:fffffbfd ... apb_read_offset 0x00000010
apb_read_data 0x0000000f ... irq_edges 1 device_high_ticks 1 delivered_high_ticks 32 irq_takes 1
wait_timeout 0 isr_result 0x0000000f isr_flag 1 isr_read_addr 0x40001010 isr_read_register_kind count
```

`cv32e20-timer1-80` 用同一条声明、同一 seed 在 CV32E20 上得到同一组输入和同样 3 个 F5 通过例（`76/4`），说明声明与 CPU artifact 无关；两片 CPU 的 IRQ 输入仍是同一种 ABI，不能据此说“换了 ABI”。

### 3.3 不同 CPU IRQ ABI：PicoRV32 自定义位 + EOI

`wb-custom-80` 用 `cpu_irq_bit: 3`（PicoRV32 的自定义 IRQ 位，CPU 自己的 EOI 向量），共享同一个行为文件。第 0 例：

```
case 0 observations_passed flow F5 record F5:00000000:00000000:ffffffff ... apb_read_offset 0x00000010
apb_read_data 0x00000000 ... irq_edges 1 irq_high_ticks 1 device_high_ticks 1 delivered_high_ticks 1
irq_takes 1 wait_timeout 0 isr_result 0x00000000 isr_flag 1 isr_read_addr 0x40001010
isr_read_value 0x00000000 isr_read_register_kind count isr_cause unknown
```

同一条 timer1 输入（第 54 例）在更慢的 Pico handler 下读到 0x63（99），而不是 15：

```
case 54 observations_passed flow F5 record F5:00000001:40002002:fffffbfd ... apb_read_data 0x00000063
... irq_edges 1 device_high_ticks 1 delivered_high_ticks 1 irq_takes 1 wait_timeout 0
isr_result 0x00000063 isr_flag 1 ... isr_read_register_kind count
```

这证明同一个设备行为声明可以被两种 CPU IRQ 实现消费；不证明支持第三种 ABI。`delivered_high_ticks` 在自定义路径上计的是 CPU 位脉冲次数（1），不是共享线被拉宽的 32 tick：C++ `1139-1142` 与 `1503-1561` 是两套交付计数。

---

### 3.4 行号与共享工作树的说明

`scripts/run_inprocess_f1f6.py` 与 `scripts/inprocess_obi_apb_f1f4_spike.cpp` 在 shared dirty tree 里都是未跟踪的共享文件；本轮五批运行使用的是运行当时链接的宿主可执行文件，保存下来的 `run.log`/`summary.json` 是该版本的证据。C++ 宿主在五批运行之后又被其他 agent 更新过（新增 AHB 等路径），本报告引用的行号按写作时（2026-11-01 00:02）的树重新核对过；`IrqLink`、pulse/level 交付、F5 通过判据、cause 打印这些 IRQ 段落的内容与批次运行时一致。Python 入口 `scripts/run_inprocess_f1f6.py` 未在本轮运行后改动。若共享树之后继续变化，以函数名和段落为准，行号只作当前树的定位。

## 4. 仍然有效的 level IRQ：本宿主如何分类和报告

### 4.1 只有 case 行，没有跨 case 的 IRQ 模型

分类器只读一个 case 行里真实打印的字段（`classify_case`，`scripts/run_inprocess_f1f6.py:1785-1927`；类目表 `1766-1777`）：

| 现象（合成或真实 case 行） | 分类 | 严重度 | 依据 |
|---|---|---|---|
| 非 F5/F6 的 case 出现 `irq_takes > 0` | `state_contamination` | anomaly（finding） | `1817-1821`：前序 case 留下的 pending IRQ/handler 状态 |
| F4 出现目标读（handler 读过状态） | `state_contamination` | anomaly | `1822-1828`：store-only case 里完成了目标读 |
| F5/F6 `wait_timeout 1` 且 `irq_edges 0` | `not_triggered` | expected（非 finding） | `1829-1837` |
| F5/F6 `wait_timeout 1` 且 `irq_edges > 0`，`takes 0` 或 ISR 未完成 | `wait_budget_exceeded` | limit | `1838-1846` |
| F5 被服务但状态/标志不符 | `device_anomaly` / `observation_mismatch` | anomaly | `1848-1865` |
| traps | `execution_exception`（先于污染判定） | anomaly | `1801-1806` |

### 4.2 一个未清除的 level IRQ 会怎样

- **后续非 IRQ 流**：如果电平仍然有效且 CPU 在某个 F1–F4 case 里接受了中断，该 case 会带 `irq_takes 1`，按 `1817-1821` 报 `state_contamination`。这是“真的被后续 case 看到”的准确证据，而不是把整个批次判坏。
- **后续 F5 case**：如果电平已经有效、但这一例没有新的边沿，超时分支先看 `irq_edges == 0` → 报 `not_triggered`（expected），即使 CPU 已经接受过它。这是当前实现的真实语义：`not_triggered` 的意思是“声明的触发没有产生新的采样边沿”，不是“线是低的”。若没有超时，同样的字段会落到 `observation_mismatch`（F5 缺“声明的边沿”观察）。本轮的纯 Python 测试把这两种结果都钉住了。
- **中断风暴**：handler 唯一的“确认”是声明的 `clear_writes`（没有就什么都不写）后置标志并 `mret`（`scripts/run_inprocess_f1f6.py:1033-1048`）；`mret` 恢复 MIE 后，如果 level 仍然有效，CPU 会立刻再次进入 handler，主循环再也跑不到。宿主对每个 case 有 4000 tick 守卫（C++ `242-243, 1976-1977`），到点抛错 → 驱动判 `host_error`、批次 `fuzz_failed`，**不是一条 case finding**。也就是说：没有 EOI 的 level 源最坏情况下不是“下一例被污染”，而是整批在守卫处中止。这是本入口对持久 level 的诚实边界。
- **唯一的恢复**：只有 `wait_timeout 1` 会在下一例前复位 IP/DMA（CPU/RAM 保留），并明确清除“pending sampled IRQ edges/levels”（`recovery_declaration`，`scripts/run_inprocess_f1f6.py:1963-1994`；文档 `docs/inprocess-fuzz-loop.md` §7.2）。普通完成的 case 不复位设备。

### 4.3 cause 的报告不是证据

- 每个 F5 case 行永远打印 `isr_cause unknown`（C++ `2331`）。
- 批次 summary 行的 `irq_cause observed` 完全由声明驱动：`IP_CAUSE_DECLARED` 为 1 就打印 observed（C++ `2594-2596`；Python `1352` 渲染该宏，`478` 用 `bool(status_cause_bits)` 置位）。它没有采样任何 cause 位。
- 唯一真实的 cause 证据是引脚目标的 `irq_cause_pins` / `inten_at_irq`（C++ `1543-1544, 2336`；Python `PIN_F5_KEYS`），GPIO 批次里它在 case 行里。
- 因此本轮所有新声明都保持 `status_cause_bits: null`；测试还加了一条“随仓库发布的所有 source 行为文件都不得声明 cause 位或 clear 写”的守卫，避免把声明当成观察。

---

## 5. 诚实的限制

1. **一个目标只能有一个 F5 源。** 行为层只接受一个整数位（`src/myfuzz/composition/inprocess_behavior.py:213-217`），执行器 `irq_declaration` 只返回一个 `(port, bit, status, clear)`（`scripts/run_inprocess_f1f6.py:455-479`），绑定头只构造一条 target link（`1296-1310`），summary 的 `irq_sources` 目标只占 index 0（`3012-3022`），ISR 只有一组 status/result/clear 单元（`1033-1048`）。把 `source_bit_offset` 写成 `[0,1]` 会分别得到 `unsupported-behavior-value:source_bit_offset`（行为层）和 `config requires source_port and source_bit_offset`（执行器）。本轮没有把两个目标源接进同一构建。
2. **“多源”今天只指 target + DMA 完成。** 两条 link 都被 OR 进 CPU 的一个输入（C++ `1503-1561`）；`irq_edges` 是所有 link 的和（`1566-1567`），case 行没有逐源归属；Pico 自定义路径明确写“one edge pulse per asserted shared line; simultaneous source attribution is unknown”（summary 的 `limitations`，C++ `1139-1142`）。
3. **`clear_writes` 可声明、ISR 真的执行，但与本轮的 F5 通过判据冲突。** C++ 通过判据要求 `target_writes == TRIGGER_COUNT`（`2136`）且最后一次目标写是最后一个触发写（`2140`）；handler 的 clear 写会额外增加一次目标写，于是**声明了目标 clear 的 F5 触发例都会被判 `observation_mismatch`**。这不是本轮新发现导致的设备问题，而是宿主判据的硬编码；仓库里没有任何 behavior 文件声明 `clear_writes`，测试把这条边界钉住（`test_no_shipped_source_behavior_claims_cause_bits_or_a_clear_write`）。§6 给出最小改法。
4. **没有 EOI/ack 概念。** handler 只会执行声明的单次 clear 写，然后 `mret`；没有“读状态即确认”的声明形式。GPIO 的读清状态（`INTSTATUS` 读清）只能靠读本身生效，不能写成 `clear_writes`（寄存器是 `ro`，执行器按名拒绝）。
5. **没有 cause 采样**（§4.3）。
6. **目标协议只有 APB3 / AXI4-Lite**；TL-UL 的 OpenTitan timer/gpio/uart 声明更丰富（level、W1C、逐位 cause），但本入口直接 `unsupported-target-protocol:tl-ul/1`，跑不了。CPU 侧只有 OBI 1-bit 与 Pico 自定义位两种；多 bit 向量、active-low、NMI、PLIC 没有适配器。
7. **设备状态跨 case 保留。** 普通完成的 case 不复位 IP/DMA；只有等待超时会复位 IP/DMA（CPU/RAM 保留）。因此“上一例的 timer 继续计数”“上一例的配置仍在”都是真实状态，必须按 case 行解释。
8. **没有覆盖率、证书、批次 replay。** `summary.json` 明写 `certificate: "none"`、`replay: "not_performed"`；`prefix.txt`/`observations.jsonl` 只是可重放输入与关键观察，不是证书。
9. **fuzz 通过率不是设备质量。** compare 变体的 F5 只通过 2/8，是因为等式触发要求两个随机字相等；`not_triggered` 是预期探索类，不能据此说设备有缺陷或没有缺陷。
10. **静态声明不证明因果。** 行为文件只证明“有人这样声明”；设备是否真的按声明产生/清除/置位，仍以 case 行的边沿、读、标志为准。

---

## 6. 可选的最小改动（只提案，本轮未改代码）

### 6.1 让“目标侧多源”成为可能

- 行为层：把 `_source_facts` 的单个 `source_bit_offset`/`status_offsets`/`clear_writes` 扩成 `links: [{port, bit, pulse_width_ticks, status_offsets, status_cause_bits, clear_writes}]`（`src/myfuzz/composition/inprocess_behavior.py:205-242` 是现在的单源校验；`245-284` 是合并与冲突拒绝）。为保持兼容，可加新 schema `inprocess_source_behavior.v2`，v1 继续按单源解释。
- 执行器：`irq_declaration`（`scripts/run_inprocess_f1f6.py:426-479`）返回 `links` 列表；`f5_declaration`（`482-504`）按每条 link 校验；`render_bindings` 的 `sources` 循环（`1299-1310`）和 `IRQ_SOURCES(X)` 行（`1387-1392`）改为按 link 生成；`summary.irq_sources`（`3012-3022`）按 link 编号。
- 固件/宿主：handler 现在只有一组 `HB_STATUS/HB_RESULT/HB_CLEAR` 单元（`scripts/run_inprocess_f1f6.py:944-960, 1033-1048`），多源需要每组 link 一组单元，或者每条 link 一次独立的 F5 case（更小、更诚实）。C++ 的 `IrqLink`/`IRQ_SOURCES` 已经支持 N 条 link（`scripts/inprocess_obi_apb_f1f4_spike.cpp:363-367, 915-919`），交付和逐 link 边沿（`1503-1561`）不用重写；需要新增的是逐 link 的 case 字段（现在 `irq_edges` 是总和，`2311-2340`）。
- 最小的一步（不改 C++）：只允许**一个** F5 目标源，多源继续用“目标 + DMA”表达；把这条限制写进 schema，而不是把两个目标位塞进 `source_bit_offset`。本轮就是这样做的。

### 6.2 让 `clear_writes` 的 F5 能通过

- C++ 通过判据：`observation.target_writes == TRIGGER_COUNT`（`scripts/inprocess_obi_apb_f1f4_spike.cpp:2136`）改为 `TRIGGER_COUNT + (IP_CLEAR_DECLARED ? 1u : 0u)`；`target_last_write_offset == IP_TRIGGER_LAST_OFFSET`（`2140`）改为忽略 clear 写（宿主需要知道 clear 偏移）。
- 绑定头：在 `render_bindings` 的 F5 段落（`scripts/run_inprocess_f1f6.py:1351-1352` 附近）增加 `IP_CLEAR_DECLARED`、`IP_CLEAR_OFFSET`；Python 的 `irq['clear']` 已经存在（`474-479`）。
- 这是让“读清/写清”类设备可用的最小改动；GPIO 的读清还需要另一个键（例如 `read_clears_status: true`），因为它的“清除”是一次读而不是写。

### 6.3 让 CPU IRQ ABI 可扩展

- Wishbone 自定义位：今天 `cpu_irq_bit` 是场景键（`scripts/run_inprocess_f1f6.py:2760-2768`），段生成在 `scripts/inprocess_wishbone_irq.py:8-34`。最小改动是把合法位范围放进 CPU profile 的 `cpu` 契约（与 `irq_entry_endpoint/role` 同处），场景键保留为覆盖；C++ 的 `CPU_CUSTOM_IRQ`/`CPU_IRQ_EOI` 路径（`1139-1142, 1307-1323`）不用改。
- active-low 或多 bit 向量：`IrqLink` 已有 `invert` 位（C++ `363-367, 915-919`），但入口把“active-high”写死（`scripts/run_inprocess_f1f6.py:1207-1208, 1213`）。最小改动是把 profile 已声明的极性传给 link 的 `invert`，并放开这两处检查；真正的“向量入口/NMI/PLIC”仍需新的 CPU 交付代码和新的 `CPU_IRQ_*` 宏，声明层无法单独完成。
- 新目标协议（TL-UL 等）：需要新适配器和 `profile_protocol` 分支（`scripts/run_inprocess_f1f6.py:229-262`），这不是声明能补的。

### 6.4 让 cause 报告与证据一致

- 要么在 handler 读状态后把声明的 cause 位采样出来（C++ 已有 `isr_read_value`，可在 `2331` 处按 `status_cause_bits` 打印），要么把 `irq_cause observed` 改成 `declared_unobserved`，直到有采样。最小改动是后者：C++ `2594-2596` 与 Python `478, 1352` 一起改；前者需要新的采样字段和 case 行。

---

## 7. 测试与新增文件

### 7.1 测试

```
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 -m pytest tests/fuzz/test_irq_declaration_expansion.py -q
# 54 passed
PYTHONPATH=src:. python3 -m pytest tests/fuzz tests/composition/test_inprocess_behavior.py -q
# 712 passed
```

`tests/fuzz/test_irq_declaration_expansion.py` 覆盖：

- 两个新行为文件的合并结果、`declared_by`/`declaration_path`、元数据不进入事实；
- 逐项对 profile 的核对（bit/source_id/trigger/极性/端口 alias/寄存器偏移与读写性/原生 pulse 宽度）；
- 新场景“只通过文件声明源”且 compare 与 baseline 只差 `source_behavior`；同一文件被 CV32E20 与 Wishbone 自定义位场景共享；
- 文件与内联一致时接受、6 个键冲突时按 `behavior-source-conflict:<key>` 拒绝；
- 16 种越界/越形（位 64、位列表、pulse 0/4097、两个状态偏移、cause 32、两条 clear、空 trigger、负数、未知字段、pins 未知键……）按名拒绝；
- `f5_declaration` 接受 compare/timer1 的事实，拒绝未声明的 bit、错的状态/触发寄存器、错窗口、缺事实、Wishbone 未声明自定义位；
- level 与 pulse 的字段差异（`trigger: level`、`pulse_ticks 0`；`trigger: pulse`、宽度 24）；无 bit 的 level 源只能在 bit 0 被寻址；GPIO 的只读状态不能声明成 clear 写；
- 两个目标位没有声明形状（列表在两层都被拒绝）；
- 跨 case level 分类：F1–F4 的 `irq_takes` → `state_contamination`、F4 目标读 → `state_contamination`、无新边沿的持久 level → `not_triggered`/`observation_mismatch`、F5 正常接受不是污染、trap 先于污染、`state_contamination` 是 anomaly/finding 而非 expected；
- 合成 case 字典与 `parse_case_line` 产出的形状一致（用一行真实格式的 case 行验证）。

### 7.2 新增文件

| 类别 | 文件 |
|---|---|
| 行为声明 | `configs/behaviors/pulp_timer_compare_f5.json`、`configs/behaviors/pulp_timer1_overflow_f5.json` |
| 场景 | `configs/scenarios/inprocess-obi-apb-ibex-timer-overflow-baseline-fuzz.json`、`configs/scenarios/inprocess-obi-apb-ibex-timer-compare-f5-fuzz.json`、`configs/scenarios/inprocess-obi-apb-ibex-timer1-overflow-f5-fuzz.json`、`configs/scenarios/inprocess-cv32e20-timer1-overflow-f5-fuzz.json`、`configs/scenarios/inprocess-wbcpu-apb-timer1-overflow-f5-fuzz.json` |
| 测试 | `tests/fuzz/test_irq_declaration_expansion.py` |
| 证据 | `runs/stage2-irq-decl-20261101/`（`README.md`、`commands.txt`、`evidence.json`、`cache/`、`baseline-120/`、`compare-120/`、`timer1-80/`、`cv32e20-timer1-80/`、`wb-custom-80/`） |
| 报告 | 本文件 |

本轮**没有修改** `scripts/run_inprocess_f1f6.py`、C++ 宿主、`src/myfuzz/**`、既有 configs/behaviors/tests/docs 或其他 run 目录。

---

## 8. 证据索引与相关文档

- 批次索引与原文 case 行：`runs/stage2-irq-decl-20261101/README.md`；机器可读索引：`runs/stage2-irq-decl-20261101/evidence.json`（含每批 `status`、`failure_classes`、`flow_counts`、`irq_sources`、`status_register`、F5 case 字段、文件 sha256）。
- 行为声明层：[单进程 F1–F6：设备行为声明](../inprocess-behavior-declarations.md)（schema、优先级、拒收名）。
- 闭环语义与失败分类：[单进程闭环 fuzz：用法与语义](../inprocess-fuzz-loop.md) §7、§7.1、§7.2。
- 系统能力盘点：[当前系统能力与代码整理盘点](../current-system-capabilities-20261101.md)。
- 行为模块 `src/myfuzz/composition/inprocess_behavior.py`，行为目录 `configs/behaviors/`，测试 `tests/composition/test_inprocess_behavior.py` 与 `tests/fuzz/test_irq_declaration_expansion.py`。

## 9. 本文件不声称什么

- 不声称所有 CPU IRQ ABI、所有目标协议、所有 IRQ 源都已支持；本轮只证明“在 OBI 1-bit machine-external 与 Pico 自定义位上，可用行为文件声明第二个 timer 源，并被真实 RTL 交付、读取和分类”。
- 不声称 level IRQ 已经能安全跨 case：未清除的 level 可能让后续 case 被 `state_contamination` 标记，或在最坏情况下触发 4000-tick 守卫导致 `host_error`；本轮没有用真实批次制造这个风暴，只从代码路径和纯 Python 分类测试说明它。
- 不声称 `clear_writes` 可用：它可声明、ISR 会执行，但与当前 F5 通过判据冲突（§5 第 3 条、§6.2）。
- 不声称 compare/timer1 批次代表设备质量或覆盖率；所有数字只对应 `runs/stage2-irq-decl-20261101/` 里保存的输入、case 行和 summary。
