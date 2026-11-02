# P2 引脚与串行行为真执行（2026-11-03）

本报告只讲 E1 这一条工作流：**声明了但宿主原先不能执行的 `pin_groups` / `serial_peer` 变成真执行**，
以及剩下的形态逐条按名拒绝。证据目录 `runs/p2-pins-serial-20261103/`（`README.md` 有精确命令、
逐字 case 行、tick 级波形、拒绝实录）。工作规约见 [P2 工作规约](p2-workplan-20261103.md)。

## 1. 结论（一句话一条）

1. **多 pin 组真执行**：宿主按声明**顺序**驱动最多 4 个 `dir_resolved_pad_word` 组，每组占线
   `max(hold_ticks,1)` 个宿主 tick（最后一组占满余下 case），direction 真的决定线值（`in`=宿主驱动整字、
   `out`=设备驱动整字、`inout`=按设备 dir 位逐位解析），并对 `in`/`out` 给出可**证伪**的见证
   （设备自己的 `PADDIR` 端口）。case 行逐组给出 `pin_group<i>_{name,kind,ext,direction,hold_ticks,ticks,changes,rise_events,fall_events,direction_witness,pad_before,pad_after}` 与总计
   `pin_groups_{declared,executed,ticks,changes,direction_conflicts}`、`pin_stimulus_group`。
2. **串行 peer 真执行**：宿主按 `serial_peer` 的 `rx_role/tx_role/idle_level/bit_ticks/frame` 真驱动
   与真采样一根串行线。三种帧全有真实批次：8n1（`serial-8n1/`）、8e1（`serial-8e1/`）、8o1（`serial-8o1/`）。
   IP 侧证据不是宿主自说自话，而是 **设备的 RX FIFO/寄存器**：`FIFO_STATUS` 读回 `0x00010000`（RXLVL=1），
   随后 `RDATA` 读回**宿主打进线的那个字节**；反向一例是设备自己发出、宿主从 `tx` 引脚逐 bit 解码
   （`serial_tx_byte 0x5a`/`0xa5`，`framing_ok 1`），并由设备自己的 `tx_done` 中断收尾（`irq_takes 1`）。
   bit 时序按声明还原：`serial rx ... bit <k> level <l>`、`serial tx ... bit <k>` 每 32 tick 一个边界/采样点，
   整帧 320（8n1）/352（8e1、8o1）tick = `frame_bits × bit_ticks`。
3. **`HOST_SOURCE_EXECUTION` 与 summary 同步**：`pin_groups: 4`、`pin_group_kinds` 两种都含、
   `serial_peer: True`、`serial_peers: 1`；run document 的 `pin_groups` 块给出这次**声明**的组/peer 与
   宿主**能力**（`capacity.pin_groups=4`、`capacity.serial_peers=1`），宿主 summary 行再给出
   `pin_group_count/pin_group_ticks/pin_group_changes/pin_group_direction_conflicts/pin_group_driver`
   与 `serial_rx_frames/serial_rx_bits/serial_tx_frames/serial_tx_framing_ok`。
4. **不写 CPU×IP 分支**：宿主的每个判断都来自生成的声明（`PIN_GROUP_TABLE` 行、`SERIAL_PEER_*` 宏、
   角色→模型端口绑定），没有组件名；两个 IP（PULP apb_gpio、OpenTitan UART）走同一段代码。

## 2. hunk 清单（文件 + 位置 + 行为）

### 2.1 `src/myfuzz/composition/inprocess_behavior.py`（声明层，E1 区域）

| 位置 | 改动 |
|---|---|
| 模块 docstring「named pad groups / a serial peer」段 | 改为「两种组都可执行」的现状，并写清仍按名拒绝的三类 |
| `HOST_SOURCE_EXECUTION`（含注释） | `pin_groups: MAX_PIN_GROUPS(4)`、`pin_group_kinds` 含 `serial_peer`、`serial_peer: True`、新增 `serial_peers: 1` |
| `PIN_GROUP_KINDS` / `SERIAL_FRAMES` / `MAX_PIN_GROUPS` 注释 | 说明两种组都可执行、帧只有 8n1/8e1/8o1 |
| `execution_refusals()` | 组 kind 不在能力集→`unsupported-behavior-execution:<kind>`；组数超界→`...:pin_groups:<n>`；peer 数超界→`...:serial_peer:count:<n>`；rx==tx→`...:serial_peer:half_duplex`；tx_en 撞数据角色→`...:serial_peer:role_conflict` |
| `source_behavior()` 里 pad 字派生注释 | 首个 dir 组派生 `pins`（一个 pad 端点=一个 pad 字）；不同 pad 字由入口按名拒绝 |

### 2.2 `scripts/run_inprocess_f1f6.py`（入口）

| 位置 | 改动 |
|---|---|
| `expected_out_after` 之后 | 新增常量 `PIN_GROUP_KIND_DIR/SERIAL`、`SERIAL_FRAME_CODES/BITS`、`SERIAL_ROLE_DIRECTIONS`、`SERIAL_PARKABLE_BUSES` 与新函数 `pin_group_declaration()`、`pin_group_case_keys()`、`serial_peer_case_keys()` |
| `pin_group_declaration()` | 用**绑定的 artifact**（`physical_exports`）校验：dir 组必须有 pad 端点、padin_offset 必须是可读 32 位寄存器、所有 dir 组必须是**同一个** pad 字（否则 `unsupported-pins:pin_groups:second-pad-word`）；peer 的角色必须在该 profile 的 `external_pins` 端点里、方向正确、有 runtime 端口（否则 `unsupported-serial:role|direction|port|width`）；packed AXI4/AHB 上 `unsupported-serial:cpu-clock-not-parkable:<bus>`；多目标 `unsupported-pins:multiple-targets` |
| `parse_record(..., serial=None)` | F2 第二字在**pad 目标或 serial 目标**上都合法（counts `(1,2)`）；serial 情形校验收件只有一个目标、字 ≤ 0xff（`F2 serial stimulus is one byte`） |
| `case_observation_keys(..., groups, serial)` | 有组时并入逐组键、有 peer 时并入串行键；两者都没有时键集与历史**完全相同** |
| `case_document(..., groups, serial)` | 新增 `pin_groups`、`serial_peer` 两个 document 块 |
| `render_bindings(..., pin_groups, serial_peer)` | 新增 `HAVE_PIN_GROUPS/PIN_GROUP_COUNT/PIN_SERIAL_COUNT/PIN_GROUP_TABLE`（每行 name/direction/hold/ext）与 `HAVE_SERIAL_PEER/SERIAL_PEER_{NAME,FRAME,FRAME_CODE,FRAME_BITS,BIT_TICKS,IDLE_LEVEL,RX_PORT,TX_PORT}`（+ 可选 `HAVE_SERIAL_TX_EN/SERIAL_PEER_TX_EN_PORT`） |
| `main()`：`pins/registers` 之后 | 解析 `group_declaration` → `pin_groups` / `serial_peer`；dir 组存在但无 pad 端点时 `unsupported-pins:pin_groups:no-pad-endpoint`；传给 `render_bindings`、三处 `parse_record`、`case_document` |
| `main()`：run document | 新增 `pin_groups` 块：这次声明的组/peer、`capacity`（宿主能力）、`driver`/`serial_driver` 两句事实 |

### 2.3 `scripts/inprocess_obi_apb_f1f4_spike.cpp`（宿主）

| 位置 | 改动 |
|---|---|
| 顶部宏默认值 | `HAVE_PIN_GROUPS/PIN_GROUP_COUNT/PIN_GROUP_ROW/PIN_GROUP_TABLE/PIN_GROUP_KIND_WORD`、`HAVE_SERIAL_PEER/SERIAL_PEER_{FRAME,FRAME_CODE,FRAME_BITS,BIT_TICKS,IDLE_LEVEL,NAME,RX_PORT,TX_PORT,TX_EN_PORT}`、`HAVE_SERIAL_TX_EN` |
| `IpTarget<0>` 回退 trait | 新增 `set_serial_rx/serial_tx/serial_tx_en`（多目标构建不生成这两条路径：串行 peer 在多目标上按名拒绝） |
| `Pads` 之后 | 新增 `PinGroupRow/kPinGroups/PinGroupCase/PinGroupSchedule`：`step()` 按声明顺序切组、`ext()` 处理 case 激励覆盖、`resolve()` 按 direction 选线、`note_dir()` 统计 direction 见证、`note_change()` 逐组归因 |
| `SerialPeer<Model>` 新结构 | 帧字构造（start/8 data LSB-first/可选校验/1 stop）、`step_rx()` 每 tick 一位并 park CPU、`sample_tx()` 在每位中点采样并校验起止/校验位、`reset_case()` 只清逐 case 计数（跨 case 的帧状态保留） |
| `Observation` | 组字段（`pin_group_*` + `PinGroupCase[]`）与串行字段（rx/tx 各自的帧、位、电平、tick、校验、tx_en） |
| `main()`：`Pads pads` 之后 | `PinGroupSchedule pin_schedule`、`SerialPeer<IP_MODEL> serial_peer`、`cpu_clock_drive()` |
| tick 循环开头 | `serial_peer.pending` → `begin_rx()`，然后 `step_rx()`（本 tick 的 rx 电平在时钟边界前设定） |
| 4 处时钟边界 | `apply_phase_boundary(true)` → `apply_phase_boundary(cpu_clock_drive())`：只有串行帧期间为 false，其余构建恒 true（无 peer 时调用序列与改动前完全相同） |
| pad 解析块 | 每组 `step()` 取本 tick 的 ext、按该组 direction 解析、`note_dir()` 见证、变化归因到当前组；`ext_value` 改为**当前呈现**的字；其后接 `serial_peer.sample_tx()` |
| 器件边沿探针块 | `rise/fall` 归因到当前组 |
| case 结束 | 拷贝组与串行的逐 case 事实进 `Observation` |
| case 行 | 新增 `pin_groups_*`/`pin_group<i>_*` 与 `serial_*` 两组字段 |
| F2 通过判据 | 带激励字的串行 case 必须：1 帧、正好 `frame_bits` 个 bit time、每 bit `bit_ticks`、起始位=有效电平、停止位=idle、字节=记录要求的字节 |
| summary | 累计量声明 + `pin_group_count/pin_group_ticks/pin_group_changes/pin_group_direction_conflicts/pin_group_driver` 与 `serial_*` 总计 |

### 2.4 测试

| 文件 | 改动 |
|---|---|
| `tests/integration/test_p2_pins_serial.py` | **新增**，19 例：能力事实、声明层可执行、执行器逐条拒绝、F2 激励字形状、case document 两块、以及 4 个真实批次（8n1/8e1/8o1/多组/方向）与 5 条拒绝实录的**逐字**断言 |
| `tests/composition/test_p1_behavior_extension.py` | 3 处：把「两组/peer 被拒绝」改为「可执行 + 降能力后仍按名拒绝」；shipped 拒绝参数改成 8n2/半双工/两 peer 三个新声明；新增一例断言旧的两个 declaration-only 文件现在完整归一化 |
| `tests/integration/test_p1_replacement_configs.py` | 3 处：导入 `MAX_PIN_GROUPS`/`execution_refusals`；`serial-peer` 样本改为「完整声明」并指出剩余拒绝在入口；能力断言改为 `pin_groups==4`/`serial_peer True`/`serial_peers 1` |

### 2.5 配置

* 新增行为：`configs/behaviors/pulp_gpio_two_groups_f5_pins.json`、`pulp_gpio_direction_groups_f5_pins.json`、`opentitan_uart_serial_peer_f5.json`（8n1）、`opentitan_uart_serial_peer_8e1_f5.json`、`opentitan_uart_serial_peer_8o1_f5.json`；
* 新增 declaration-only：`uart_two_stop_bits_peer_f5.json`、`uart_half_duplex_peer_f5.json`、`uart_two_serial_peers_f5.json`、`uart_serial_peer_missing_role_f5.json`、`gpio_two_pad_words_groups_f5.json`；
* 新增场景：`inprocess-obi-apb-gpio-groups-f1f5.json`、`inprocess-obi-apb-gpio-groups-direction-f1f5.json`、`p2-opentitan-uart-serial-peer-f1f5.json`、`...-8e1-f1f5.json`、`...-8o1-f1f5.json`、5 个 `refused-*.json`。

## 3. 真实结果

| 批次 | 例数 | 关键逐字事实 |
|---|---|---|
| `serial-8n1` | 5/5 | `serial_rx_frames 1 serial_rx_bits 10 serial_rx_levels 0x0000034a serial_rx_first_tick 94 serial_rx_last_tick 413 serial_rx_cpu_held_ticks 320`；`read_value 0x00010000`（FIFO_STATUS RXLVL=1）→ `read_value 0x000000a5`（RDATA）→ `0`；`serial_tx_byte 0x0000005a serial_tx_levels 0x000002b4 serial_tx_framing_ok 1`、`irq_takes 1`、`isr_read_value 0x00000105` |
| `serial-8e1` | 4/4 | `serial_rx_bits 11 serial_rx_levels 0x0000054a serial_rx_parity_bit 0 serial_rx_cpu_held_ticks 352`；RXLVL=1→RDATA 0xa5；`serial_tx_byte 0xa5 serial_tx_framing_ok 1`、`irq_takes 1`，`serial_tx_en_ticks` 94/387/36/504 |
| `serial-8o1` | 4/4 | 同上但 `levels 0x0000074a`、`parity_bit 1` |
| `groups-order` | 7/7 | 每例 `pin_groups_declared 2 pin_groups_executed 2`；`pin_group0_ticks 2`、`pin_group1_ticks>2`；`pin_group0_ext 0x00001111`/`pin_group1_ext 0x00002222` 与各自 `changes`；case 2 `pin_stimulus_group 0`+`pin_group0_ext 0x0000f0f0`；case 5 `read_value 0x0000002a`（设备 PADOUT 上线） |
| `groups-direction` | 5/5 | case 0 `pin_group0_direction out`+`direction_witness contradicted`+`pin_groups_direction_conflicts 32`；case 1–4 `honoured`、冲突 0 |
| `regress-gpio-pins` | 11/11 | 与改动前同配置同 record 的 `base-gpio/` 逐字节相同（除 `seconds`） |
| `regress-uart-f1f5` | 5/5 | 与 P1 已提交证据 case 行逐字节相同（summary 仅多出 F 代理时钟两键） |
| `regress-timer-f1f6` | 6/6 | 没有 `pins`/`pin_groups`/peer 的 F1–F6 sanity：引脚与串行代码全部编译掉，流程不变 |

## 4. 仍拒绝 / 仍未知（逐条）

| 形态 | 拒绝名 | 依据 |
|---|---|---|
| 多停止位 / 非 8 位数据帧（如 `8n2`） | `unsupported-behavior-value:pin_groups.frame` | 宿主的帧字只有一个 stop 位置（`uart_rx.sv` 的 `bit_cnt` 为 10/11），多出来的 bit time 会被静默丢掉 |
| 半双工（rx 与 tx 同一根线） | `unsupported-behavior-execution:serial_peer:half_duplex` | peer 拥有一个输入与一个输出；同线无法同时驱动与采样 |
| 同一目标两个串行 peer | `unsupported-behavior-execution:serial_peer:count:2` | 宿主每目标一条 peer（`serial_peers: 1`） |
| `tx_en` 与数据角色重名 | `unsupported-behavior-execution:serial_peer:role_conflict` | 同一端口不能既是发送使能又是数据 |
| 一张行为文件里两个不同 pad 字 | `unsupported-pins:pin_groups:second-pad-word` | 一个 pad 端点 = 一个 32 位 pad 端口；第二个 pad 字需要第二个端点，现有 profile 都没有 |
| dir 组但目标无 pad 端点 | `unsupported-pins:pin_groups:no-pad-endpoint` | 声明的是这个模型没有的 pad 字 |
| peer 角色不是该器件引脚 | `unsupported-serial:role:<role>`（实录 `rts_n`） | 角色必须来自该 profile 的 `external_pins` 端点 |
| packed AXI4 / AHB-Lite CPU 上的串行 peer | `unsupported-serial:cpu-clock-not-parkable:axi4` / `:ahb` | 这两条路径的 CPU/适配器边沿由 `CpuLink`/beat 适配器拥有，没有 park CPU 打帧的位置（本轮未建 CVA6/CVW，拒绝在函数级取证） |

仍未知（不主张）：串行 peer 与 `rx_break_err`/`rx_frame_err`/`rx_parity_err` 这类**坏帧触发**的中断源教会
（本轮的三个批次都是良性帧，设备侧 `rx_*_err` 不置位）；SPI peer、I2C 双向线没有 peer 模型。
`serial_peer.tx_en_role` 只**采样**（设备自己的发送使能输出），宿主不驱动它。

## 5. 测试

```
PYTHONPATH=src:. python3 -m pytest tests/integration/test_p2_pins_serial.py -q
# 19 passed

PYTHONPATH=src:. python3 -m pytest tests/composition/test_inprocess_behavior.py \
  tests/composition/test_p1_behavior_extension.py -q
# 119 passed

PYTHONPATH=src:. python3 -m pytest tests/integration/test_inprocess_f1f6_entry.py \
  tests/integration/test_p1_replacement_configs.py -q
# 210 passed
```

三组共 348 例全绿；`tests/composition/` 的既有监督式 elaboration 基线失败（pgid/`setsid`）与本轮无关，
未触碰。

## 6. 需要别的代理配合

1. **`docs/reports/README.md` 索引行**（父代理统一插入，本代理按并发纪律未编辑）：
   见下方给父代理的消息里的完整表格行。
2. **P1 的两条既有结论被本轮推进**：`docs/reports/p1-behavior-expressiveness-replacements-20261102.md`
   §1.2 与 `runs/p1-replacements/README.md` 里「多组 → 按名拒绝、串行 peer → 按名拒绝」的表述现在过时
   （本轮已真执行）。本轮没有改它们（不是我的区域），建议父代理或 P1 报告的属主加一句指向本报告。
   同时 `configs/behaviors/declaration-only/opentitan_uart_serial_peer_f5.json` 与 `two_pad_groups_f5.json`
   的 `description`/`notes` 里「本宿主拒绝它」的说法同样过时（文件本身仍被保留为例证，测试已改为断言它们
   **完整归一化**）。
3. **AHB/AHB-Lite 目标代理（C）与时钟代理（F）**：串行 peer 的 `bit_ticks` 以宿主 tick 计价，
   在每模型时钟比 != 1 的构建里，声明者要自己把器件波特率折算进 `bit_ticks`；如果将来要按
   *器件自身* 周期声明，需要 F 代理在 phase clock 里暴露一个"该模型的 tick"换算。
