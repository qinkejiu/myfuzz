# 单进程 F1–F6：设备行为声明

日期：2026-11-01。状态：声明层与统一入口的接入都已实现；本文件不是新的运行证据，设备是否真的按声明触发/清除/搬运仍以 `runs/` 的日期批次为准。

统一入口 `scripts/run_inprocess_f1f6.py` 此前从场景配置的临时键直接读取 F5/F6 的设备事实，并把 ZipDMA 控制状态位写成两个匿名常量。本次把它拆成两层：**协议连接**按总线写一次，**设备行为描述**由每台设备自己的行为文件声明。模块只有 `src/myfuzz/composition/inprocess_behavior.py` 一个，行为文件在 `configs/behaviors/`。

## 两层模型

| 层 | 内容 | 写几次 | 位置 |
|---|---|---|---|
| 协议连接 | APB3 / AXI4-Lite / Wishbone 适配、握手与错误、RAM 与总线路由、IRQ 交付到 CPU | 每种协议一次 | `scripts/inprocess_obi_apb_f1f4_spike.cpp`、`scripts/run_inprocess_f1f6.py` |
| 设备行为描述 | IRQ 从哪个端口/位产生、如何触发、状态字在哪、清除怎么写、引脚衬垫如何解析、DMA 控制状态位在哪 | 每台设备一份 | `configs/behaviors/*.json` + `src/myfuzz/composition/inprocess_behavior.py` |

行为文件只写设备事实，不写协议，也不写 CPU。换 CPU 或换总线不需要改行为文件；换设备只需换一个行为文件。同一个文件可被多个场景共享（timer 的 F5 事实同时服务于 timer+ZipDMA 和 timer+wbdmac）。这也是[系统能力盘点](current-system-capabilities-20261101.md)「指令、反馈与接入限制」里要求的“新设备不能只写协议名”，只是把能声明的那部分真正声明出来。

## 两个 schema

两个 schema 都是 JSON 文档；`description`（字符串）和 `notes`（字符串数组）只是元数据，读入后不进入事实字典，也不参与校验结论。

### `inprocess_source_behavior.v1`（F5 设备事实）

| 键 | 类型与范围 | 含义 |
|---|---|---|
| `source_port` | 非空字符串 | 承载 IRQ 的真实输出端口名（如 `irq_o`、`events_o`、`interrupt`） |
| `source_bit_offset` | 整数 0..63 | 该端口上的中断位 |
| `pulse_width_ticks` | 整数 1..4096（可缺省） | 宿主按声明拉宽脉冲的拍数 |
| `trigger_writes` | 至少 1 条 `[offset, value]`，整数 | 触发序列；offset/value 为 32 位字（`4294967295` 合法） |
| `status_offsets` | 恰好 1 个整数 | ISR 读取的状态字偏移 |
| `status_cause_bits` | `null` 或 0..31 整数数组 | 允许的 cause 位；`null` 表示未声明 |
| `clear_writes` | 最多 1 条 `[offset, value]`，可为空 | 声明的清除写；无清除写时为空数组 |
| `pins` | 可选对象，键恰为 `padin_offset`、`external_value`、`pad_resolution` | 仅 dir 解析衬垫模型：`pad_resolution` 必须是 `device_drives_when_dir_bit_high_else_host`，`padin_offset` 为整数 ≥ 0，`external_value` 为 32 位字 |

### `inprocess_dma_behavior.v1`（F6 DMA 事实）

| 键 | 类型与范围 | 含义 |
|---|---|---|
| `block_words` | 整数 1..4 | 一次搬运的字数；未声明时为 `None`（执行器 F6 仍要求它） |
| `irq_pulse_ticks` | 整数 1..4096 | DMA 完成脉冲的交付宽度；未声明时为 `None` |
| `busy_bit` | 整数 0..31 | 控制状态寄存器里的忙位 |
| `err_bit` | 整数 0..31，且与 `busy_bit` 不同 | 控制状态寄存器里的错误位 |
| `status_kind` | `status`/`count`/`compare`/`control`/`data`/`undeclared` | 该寄存器的性质；缺省为 `status` |

`busy_bit` / `err_bit` 必须同时声明或同时缺省：只声明一位会把“声明的位”和“内置默认的位”混在同一个返回值里。

## 路径、优先级与拒收

- 场景用 `source_behavior`、`dma_behavior` 写**仓库相对路径**。绝对路径、含 `..` 的路径、解析后逃出 `base_dir` 的路径（包括符号链接逃逸）都按 `unsupported-behavior-path` 拒绝。
- **文件优先，冲突拒绝**：文件声明的键优先于同名内联键；若文件与内联值不一致，拒绝并报 `behavior-source-conflict:<key>`（DMA 用行为键 `block_words` / `irq_pulse_ticks`，引脚用 `pins`），不静默挑一个。两边一致则接受。
- 没有文件时，原有内联键照旧生效：F5 的 7 个键、`dma_block_words`、`dma_irq_pulse_ticks`。
- 既没有文件、也没有任何一个 F5 键时，`source_behavior` 返回 `None`；执行器原有的 `unsupported-f5:target-irq-semantics:...` 拒绝路径保持原样，不会凭空得到默认 IRQ。
- 返回值携带来源：`declared_by` 为 `file`/`inline`，`declaration_path` 为相对路径或 `None`。F5 返回值永远带 `pins` 键（未声明时为 `None`），只出现已声明的其他键。

错误名一览：

| 错误 | 含义 |
|---|---|
| `unsupported-behavior-path` | 路径非相对、含 `..`、逃出 base_dir 或含反斜杠/空字节 |
| `unsupported-behavior-file:<path>` | 文件不存在或不可读 |
| `unsupported-behavior-json:<path>` | 不是合法 JSON |
| `unsupported-behavior-document:<path>` | 顶层不是对象 |
| `unsupported-behavior-schema:<version>` | `schema_version` 缺失或不是本 schema |
| `unsupported-behavior-field:<key>` | 文件出现未知顶层键（`pins` 内的未知键写作 `pins.<key>`） |
| `behavior-source-conflict:<key>` | 文件与内联值不一致 |
| `unsupported-behavior-value:<key>` | 类型、范围或组合不合法（如位越界、行长度不对、`busy_bit == err_bit`） |

## 现有行为文件

| 文件 | 设备 | 声明内容 |
|---|---|---|
| `configs/behaviors/pulp_timer_f5.json` | PULP APB Timer | `irq_o[0]`、16 拍、触发 `[[4,0],[8,0],[0,4294967295]]`、状态字 offset 0（`TIMER0_COUNT`）、无 cause 位、无清除写 |
| `configs/behaviors/pulp_spi_eot_f5.json` | PULP APB SPI | `events_o[1]`（EOT）、16 拍、触发 `[[16,65536],[24,171],[0,2]]`、状态字 offset 40（`INTSTA`）、无 cause 位、无清除写 |
| `configs/behaviors/pulp_gpio_f5_pins.json` | PULP APB GPIO | `interrupt[0]`、16 拍、触发 `[[4,4294967295],[24,1],[28,1],[12,43]]`、状态字 offset 36（`INTSTATUS`，读清）、`pins`：`padin_offset 8`、`external_value 0`、dir 解析模型 |
| `configs/behaviors/zipdma_f6.json` | ZipDMA | `block_words 4`、`busy_bit 31`、`err_bit 30`、`status_kind status` |
| `configs/behaviors/wbdmac_f6.json` | wbdmac | 该设备 RTL 自己声明的 control readback busy 位 31、error 位 30，以及此场景的四字搬运 |

各文件的 F5 事实逐值对应 `configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json`、`inprocess-verify-irq-pulp-spi-f1f6.json`、`inprocess-obi-apb-gpio-pins.json`；GPIO 的触发**值**在 `inprocess-obi-apb-gpio-pins.json` 只记 offset、由记录按用例给值，因此取自同一设备的 `inprocess-obi-apb-gpio-pins-f1f5.json`（与 `runs/stage2-breadth-gpio-20261101/run1` 的 F5 记录 `…:0000002b` 一致），文件 `notes` 里写明了这一点。测试逐项比对这四个文件与对应场景，值漂移会直接失败。

## 诚实的边界

- **执行器仍做 profile 交叉校验。** 本模块只负责形状、范围、优先级与来源；`status_offsets`/`trigger_writes`/`pins` 是否与设备自己的 `address.registers`、`interrupts`、`external_pins` 相符，仍由执行器的 `irq_declaration`、`pin_declaration`、`dma_declaration` 判定。行为文件不能替代那一步。
- **DMA 状态位目前是“被报告的内置默认”。** 没有文件声明时返回 31/30，但 `status_bits_declared=false`、`status_bits_source='builtin_zipdma_rtl_default'`；只有 `configs/behaviors/zipdma_f6.json` 声明后才是 `true` 并把文件路径作为来源。这两个数字来自 ZipDMA RTL（`third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:116-117`），不是 profile 声明的事实；`configs/peripherals/zipdma_smoke/component_profile.json` 只声明了 `CONTROL_STATUS` 的副作用。
- **wbdmac 的状态声明来自该设备的 RTL。** `wbdmac_f6.json` 使用 `wbdmac.v` 控制寄存器 readback 中的 busy/error 位，并在 wbdmac generality 固定与 fuzz 场景中显式引用；旧场景未引用行为文件时仍沿用并报告上述内置默认。静态声明不意味着运行中实际激励了 busy 或 error。
- **行为文件不证明因果。** 它证明“有人这样声明”，不证明设备真的按此产生/清除中断、按此解析引脚、按此置位。运行记录里的 IRQ 边沿、状态读、pin 边沿仍是唯一证据；声明与实测不符时应报错而不是解释成通过。
- **统一入口已读取本层。** `scripts/run_inprocess_f1f6.py` 在 `main()` 里调用 `source_behavior()`/`dma_behavior()`，把结果并入随后交给 `f5_declaration`/`pin_declaration`/`dma_declaration` 的声明；DMA 的 `busy_bit`/`err_bit` 由声明的行为或显式报告的 builtin 默认提供，不再由匿名常量静默决定。场景可写 `"source_behavior": "configs/behaviors/<file>.json"` 或 `"dma_behavior": "..."`；文件与同名内联键冲突时按 `behavior-source-conflict:<key>` 拒绝，未写文件时原有内联键继续生效。
- **运行摘要报告来源。** `summary.json` 的 `behavior` 字段记录实际使用的行为文件/内联来源；DMA 块报告 `status_bits_declared`、`status_bits_source` 和 `block_words_declared`，所以“设备声明”和“builtin 默认”不会混在一起。
- 行为文件不是 profile：真实端口、寄存器映射、中断声明仍由 `component_profile.json` 提供，二者互不替代。

## 新设备只加一个行为文件

设备已有 profile 的前提下，新增 `configs/behaviors/my_i2c_f5.json`：

```json
{
  "schema_version": "inprocess_source_behavior.v1",
  "description": "my_i2c F5 behavior",
  "notes": ["facts reviewed against configs/peripherals/my_i2c/component_profile.json"],
  "source_port": "irq_o",
  "source_bit_offset": 2,
  "pulse_width_ticks": 16,
  "trigger_writes": [[4, 1], [0, 2]],
  "status_offsets": [12],
  "status_cause_bits": null,
  "clear_writes": []
}
```

场景只写路径，不重复设备事实：

```json
{
  "source_profile": "configs/peripherals/my_i2c/component_profile.json",
  "source_behavior": "configs/behaviors/my_i2c_f5.json"
}
```

执行器仍会把它与 profile 的寄存器映射、中断声明交叉校验；声明不成立时按上表的名字拒绝，而不是补一个默认值。多个场景共用同一设备时，改行为文件即同时改它们。

验证本层：

```sh
cd /home/qinkejiu/myfuzz && PYTHONPATH=src:. python3 -m pytest tests/composition/test_inprocess_behavior.py -q
```

## 相关文档

- [当前系统能力与代码整理盘点](current-system-capabilities-20261101.md)：两层区分与接入限制见「指令、反馈与接入限制」。
- [Profile 驱动接入原型](profile-onboarding.md)：组件 profile、capability、既有 F5/F6 入口与声明边界。
- 模块 `src/myfuzz/composition/inprocess_behavior.py`，测试 `tests/composition/test_inprocess_behavior.py`，行为文件目录 `configs/behaviors/`。
