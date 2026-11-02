# IRQ/F5 通用化：触发/清除分离、cause 采样与多源声明（2026-11-02）

状态：声明层、宿主判据与两条真实 RTL 批次已落地；跨例电平检测已实现并做纯 Python 判据测试，尚缺一个“可触发且单次清除后仍保持”的真实目标批次（原因见 §5）。不是覆盖率、证书或完整 replay 结论。

## 1. 本轮改动

| 项 | 位置 | 结果 |
|---|---|---|
| 触发写与清除写分开计数 | `scripts/inprocess_obi_apb_f1f4_spike.cpp:534-551`；`scripts/run_inprocess_f1f6.py:2306-2342` | 一次目标写若在 CPU 接受中断后命中声明的 clear 偏移/值，计入 `clear_writes`，否则计入 `trigger_writes`；F5 判据同时要求两者等于声明值 |
| cause 位采样 | 入口 `irq_declaration` 的 `status_cause_bits`→`cause_mask`；宿主 `IP_CAUSE_MASK`；case 行 `isr_cause` | cause 取自 ISR 对声明状态字的真实读取值（`target_read_data & cause_mask`），不再由声明直接打印 observed |
| 单目标多 IRQ 源 | 行为层 v2 `irq_sources`（`configs/behaviors/pulp_timer_multilink_f5.json`）；入口 `f5_declaration` 逐 link 校验；固件按 link 分发；宿主 `IRQ_LINK_*` 表 | F5 记录变为 `链路号:触发值...`；每个 link 有自己的端口/位/状态字/cause/clear/触发序列，一例只服务一个 link，不把两个源 OR 进同一次状态读 |
| 电平源清除要求 | `irq_declaration` | level 源必须声明 clear 写或状态字 `side_effect: read_clears`；否则按名拒绝（避免中断风暴） |
| 跨例电平检测 | 宿主 case 末采样每个 level link 的原始输出；`irq_level_final`/`level_stuck`；case 失败后仅复位设备 | 未清除的 level 会失败并报告，随后只复位 IP/DMA，CPU/RAM 保留；不再把持高电平当作 `not_triggered` |
| 无 link 构建 | 宿主 F5 打印/判据按 `IRQ_TARGET_LINK_COUNT` 编译 | AXI4 等无 F5 的构建不会引用不存在的 link 表 |

## 2. 声明形状

v1 继续使用扁平 `source_port/source_bit_offset/trigger_writes/status_offsets/...`。v2 用有序列表：

```json
{
  "schema_version": "inprocess_source_behavior.v2",
  "irq_sources": [
    {"name": "timer0_overflow", "source_port": "irq_o", "source_bit_offset": 0,
     "pulse_width_ticks": 16,
     "trigger_writes": [[4,0],[8,0],[0,4294967295]],
     "status_offsets": [0], "status_cause_bits": null, "clear_writes": []},
    {"name": "timer0_compare", "source_port": "irq_o", "source_bit_offset": 1,
     "pulse_width_ticks": 24,
     "trigger_writes": [[4,0],[8,3],[0,3]],
     "status_offsets": [8], "status_cause_bits": null, "clear_writes": []}
  ]
}
```

规则：1..8 link；每 link 必须完整声明四个 F5 事实；同一声明内触发写数量必须一致（F5 记录用固定长度：链路号 + N 个值）；名称唯一；level 源必须可清除。

## 3. 真实 RTL：同一 timer 的两个源

配置 `configs/scenarios/inprocess-obi-apb-ibex-timer-multilink-f1f6.json`（Ibex OBI + PULP Timer APB3 + ZipDMA，link 0=overflow bit0，link 1=compare bit1）。命令：

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-ibex-timer-multilink-f1f6.json \
  --cache runs/stage2-stepD2-cache \
  --output runs/round1-smoke/multilink \
  --records 'F1:2ab00693,F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff,F5:0:00000000:00000000:ffffffff,F5:1:00000000:00000003:00000003,F6:0110c000:08000000:deadbeef:12345678'
```

结果：7/7 `observations_passed`。两条 F5 的差异全部来自声明的 link，而不是新的 CPU×IP 分支：

| 例 | record | link | 状态读地址/值 | kind | 交付宽度 | cause |
|---|---|---|---|---|---|---|
| 4 | `F5:00000000:00000000:00000000:ffffffff` | 0 | `0x40001000` / `0x0` | count | 16 | unknown（未声明） |
| 5 | `F5:00000001:00000000:00000003:00000003` | 1 | `0x40001008` / `0x3` | compare | 24 | unknown |

两例均 `trigger_writes_observed 3`、`clear_writes 0`、`irq_link_edges 1`、`irq_takes 1`、`irq_level_final 0`。summary：`cases 7 errors 0`、`irq_sources 3`、`irq_target_links 2`、`irq_link_edges 1,1,1`（两条 target link + DMA 完成 link）。

## 4. 真实 RTL：cause 位与读清状态

行为文件 `configs/behaviors/pulp_gpio_cause_f5_pins.json` 在原有 PULP GPIO 行为上声明 `status_cause_bits: [0]`；`INTSTATUS` 0x24 是 profile 的 `ro` + `read_clears` 状态字。场景 `configs/scenarios/inprocess-obi-apb-gpio-cause-f5-pins.json`。命令：

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-gpio-cause-f5-pins.json \
  --cache runs/stage2-unified-gpio-20261101/cache \
  --output runs/round1-smoke/gpio-cause \
  --records 'F1:2ab00693,F4:40000000:00000001,F5:ffffffff:00000001:00000001:0000002b'
```

结果：3/3 通过。关键行（例 2）：

```text
case 2 observations_passed flow F5 record F5:ffffffff:00000001:00000001:0000002b
  apb_read_offset 0x24 apb_read_data 0x1
  irq_edges 1 device_high_ticks 1 delivered_high_ticks 16 irq_takes 1
  isr_result 0x1 isr_flag 1 isr_read_addr 0x40000024 isr_read_value 0x1
  isr_read_register_kind status isr_cause 0x00000001
  irq_cause_pins 0x1 inten_at_irq 0x1 first_transition_tick 225 first_irq_tick 225
  status_after_read 0x0 irq_level_final 0x0
```

这证明 cause 来自 ISR 的真实状态读、读清后 `status_after_read 0`、且引脚边沿与中断同 tick。F4 例先写 PADDIR=1 是设备方向寄存器的真实前置条件，不是宿主造值。

## 4.1 真实 RTL：level 中断 + 写清除（PULP I2C）

新增 profile/行为/场景（只声明，不改 RTL）：

- `configs/peripherals/pulp_i2c_irq/component_profile.json`：原 PULP `apb_i2c` 的 APB3 目标，加真实 `interrupt_o` 导出和 level 中断声明（`irq_flag && s_ien`，`CMD[0]` 为 iack）。
- `configs/behaviors/pulp_i2c_level_f5.json`：`CTRL=0xc0`（core_en|ien）、`TX=0x5a`、`CMD=0x10`（write）；`STATUS` 0xc 的 bit0 是 cause；`clear_writes=[[0x14,1]]`（CMD iack）。
- `configs/scenarios/inprocess-obi-apb-pulp-i2c-level-f5.json`：Ibex OBI + 该目标，SCL/SDA 固定高。

真实批次 `runs/round1-smoke/i2c-level`（3 例）：

```sh
python3 scripts/run_inprocess_f1f6.py   --config configs/scenarios/inprocess-obi-apb-pulp-i2c-level-f5.json   --cache runs/round1-i2c-cache --output runs/round1-smoke/i2c-level   --records 'F5:000000c0:0000005a:00000010,F5:000000c0:0000005a:00000010,F2:00014000'   --max-ticks 300000
```

3/3 `observations_passed`。两条 F5 都是真实 level：

```text
case 0 observations_passed flow F5 record F5:000000c0:0000005a:00000010
  trigger_writes 3 apb_read_offset 0x0c apb_read_data 0x81
  irq_edges 1 device_high_ticks 38 delivered_high_ticks 38 irq_takes 1
  isr_result 0x81 isr_flag 1 isr_read_addr 0x4000000c isr_read_value 0x81
  trigger_writes_declared 3 trigger_writes_observed 3 clear_writes 1
  last_clear_offset 0x14 last_clear_data 0x1 isr_cause 0x1
  irq_link 0 irq_link_edges 1 irq_level_final 0x0
```

第二例同样通过，说明清除后下一例不继承电平；随后的 F2 也通过。`level_stuck` 未出现。

**负控制已修复**：把 clear 故意声明成 `CMD=0x10`（写命令而非 iack）时，电平在 handler 后仍高；修复后 `irq_takes` 超过 4 且电平仍高即记录 `level_stuck`、停止该 case、只复位设备并等待 handler 清命令字。`runs/round1-irq-storm/stuck` 现在 2 例：case0 `failed`/`level_stuck 1`/`device_resets 1`，case1 F2 `observations_passed`，批状态 `failed` 而不是 0 例 host error。`stuck-before` 保留修复前的 0 例证据作对照；正确 I2C 批次仍 3/3、multilink 7/7。

## 5. 仍未完成/未声称

1. **中断风暴边界已缩小**：见 §4.1 负控制。正常的 level + 单次 clear 已真实通过；未清除的 level 在 `irq_takes > 4` 时被转成 `level_stuck` 失败并复位设备。若 handler 长期不执行完成（例如 CPU 永远不返回），case tick 预算仍会接管；这条边界保留。
2. **多源同时有效**：一例只选择一个 link；未选择 link 若为 level 且仍高，会被 case 末检测并按 `level_stuck` 失败/复位，而不是静默 OR。
3. **case_tick_budget 未生效**：入口计算了 `case_tick_budget`，但 `render_bindings` 调用未传该参数，宿主实际仍是 4000；Wishbone six 和 I2C level 场景声明的 12000/80000 没有到达头文件。多 IP 集成正在修。
4. 没有覆盖率、证书、批次 replay；`configs/behaviors` 的声明不证明设备因果，因果仍以 case 行里的真实读/边沿/引脚为准。

## 6. 测试

```sh
PYTHONPATH=src:. python3 -m pytest tests/fuzz tests/composition/test_inprocess_behavior.py tests/integration/test_inprocess_f1f6_entry.py -q
# 894 passed
```

新增/更新的判据测试：`tests/fuzz/test_irq_clear_cause.py`（触发/清除分开、cause 必置位、unknown 拒绝、无 clear 不期望 clear、选中 link 的持高电平失败、其他 link 不影响本 link）。
