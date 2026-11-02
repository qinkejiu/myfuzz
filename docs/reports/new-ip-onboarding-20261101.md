# 统一执行器新 IP 接入：PULP APB3 I2C（2026-11-01）

## 结论

本次把一个此前没有进入统一单进程执行器的同协议 IP——PULP `apb_i2c`（APB3，pinned `third_party/soc-pulp-apb-i2c`）——接入 `scripts/run_inprocess_f1f6.py --fuzz`。接入只用了**新的场景配置文件**：没有改执行器、C++ host、`src/myfuzz/**`，没有改任何既有 config/behavior/doc，也没有为 CPU×IP 组合增加分支。同一份 IP 配置换到 PicoRV32 Wishbone CPU 后也直接运行，F1–F4 全部有真实观察。

- Ibex OBI + PULP I2C：80 例，80 通过，0 失败，F1–F4。
- PicoRV32 Wishbone + 同一 PULP I2C：60 例，60 通过，0 失败，F1–F4。
- F5 被按名拒绝：该 profile 的 `interrupts` 为空，`interrupt_o` 只有 observe；behavior 文件也无法补出 IRQ 源。
- F6 被按名拒绝：本次拓扑没有 DMA（`unsupported-f6:no-dma-model:APB`）。
- 没有新增 behavior 文件，因为该 IP 没有可声明的 F5 事实。
- 本报告只描述实际观察；不声称 RTL 覆盖率、证书或 replay。

## 1. 选型与理由

在 `configs/peripherals/` 中检查了所有 APB3/AXI4-Lite 寄存器目标后选择 `pulp_i2c`：

- **确实还没有进入统一入口**：`configs/scenarios/` 下没有任何 `inprocess-*.json` 使用 `pulp_i2c`；它此前只出现在旧 `compiled_mmio`/共享 DMA 场景里。
- **协议形状匹配**：profile 只有一个 `mmio_slave` 端点 `i2c.bus`，`protocol: ["apb","3"]`；`capabilities` 为 12 位地址、32 位数据、无字节使能、无部分写、有 `PSLVERR`、`max_wait_cycles=16`，正好是 `apb3_register_template` 要求的形状。
- **pinned 源可验证**：`configs/soc/sources.lock.json` 的 `pulp_i2c` 记录有 `elaboration_verified` 与 `configs/soc/closures/pulp_i2c.json`（4 个源文件，exit 0，12 条 nonfatal warning）。
- **通用寄存器读写**：6 个寄存器（PRESCALER 0、CTRL 4、RX 8、STATUS 12、TX 16、CMD 20），没有需要 host 代码的特殊协议端口；六根开漏引脚只是两个输入、四个输出，输入可按常量声明。
- **没有硬造 F5**：profile 明确声明 `interrupts: []`，`interrupt_o` 的 `port_actions` 写的是 observe、没有 CPU IRQ binding。与其为它编一个中断，不如保留 F1–F4 并把拒绝写清楚。

没有选择 PULP SPI 的原因：`inprocess_verify_pulp_spi_irq` 已经被统一入口的固定记录路径（`configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json`）使用，不算“新 IP”；而 `pulp_spi` 基础 profile 同样没有 `interrupts`，F5 一样不可声明。I2C 的“新”是它对统一入口本身是新的，能真正检验“只加声明即可接入”。

## 2. 新增文件（只有声明与证据）

| 文件 | 作用 |
| --- | --- |
| `configs/scenarios/inprocess-obi-apb-pulp-i2c-fuzz.json` | Ibex OBI + PULP I2C APB3，无 DMA，F1–F4 |
| `configs/scenarios/inprocess-wb-apb-pulp-i2c-fuzz.json` | 同一 IP + PicoRV32 Wishbone CPU，无 DMA，F1–F4 |
| `tests/fuzz/test_new_ip_onboarding.py` | 纯 Python 接入测试（不启动 RTL） |
| `docs/reports/new-ip-onboarding-20261101.md` | 本报告 |
| `runs/stage2-fuzz-newip-20261101/` | 两次真实运行输出、`commands.txt`、`README.md` 与构建缓存 |

没有新增或修改 `configs/behaviors/`、`configs/peripherals/`、`scripts/run_inprocess_f1f6.py`、`scripts/inprocess_obi_apb_f1f4_spike.cpp`、`src/myfuzz/**`。工作区里其他 agent 的既有改动没有被触碰。

## 3. 场景声明了什么，入口怎么消费

两个场景声明的是同一组设备事实，只有 CPU profile 和 RAM 镜像不同：

| 键 | 值 | 来源 |
| --- | --- | --- |
| `source_profile` | `configs/peripherals/pulp_i2c/component_profile.json` | pinned profile |
| `target_window` | `{base: 1073741824, size: 4096}`（0x40000000..0x40000fff） | profile 的 `address.window_size`/`alignment` |
| `active_id` | `pulp_i2c_target`（Ibex）/ `target`（Wishbone） | 声明 |
| `source_timing` | 2/3/16 | 声明 |
| `cpu_timing` | Ibex 8/8/16；PicoRV32 4/4/16 | 声明 |
| `image_start`/`image_end` | Ibex 65536/196608；PicoRV32 0/131072 | CPU 自己的 boot contract |
| `f1_program_words` | 4 | 声明 |
| `handler_wait_iterations` | 128 | 声明 |
| `assume_single_clock` | true | 两个 profile 都声明 50 MHz |
| `source_fixed_inputs` | `scl_pad_i=1`、`sda_pad_i=1` | 开漏上拉空闲电平；header 渲染用 |
| `source_tuning.fixed_inputs` | 同上 | 生成的 harness 请求用 |

入口没有从 `pulp_i2c` 这个名字里推断任何东西：它读 profile 的 `endpoints` 得到协议（`profile_protocol` → `apb3`），读 `address.registers` 得到可读/可写偏移，读 CPU 的 boot contract 决定 RAM 基址。实际生成的模型 kind 是 `apb3_register_observe`，bridge 是 `apb3_mmio_bridge`（见两次运行的 `summary.json` 与 `spike_config.h` 的 `TARGET_BRIDGE`）。

`source_fixed_inputs` 与 `source_tuning.fixed_inputs` 之所以写两遍，是因为入口分别消费：前者由 `render_bindings()` 渲染成 header 的 `IP_FIXED_INPUTS`，后者进入 `local_harness.v2` 请求的 tuning。两处值必须一致，否则构建时会被拒绝。这是声明接口的粗糙处，不是本次新增的代码分支。

## 4. 真实运行

两次都使用本次创建的 cache（冷构建），一次只跑一个 RTL 进程；第二次在第一次结束后开始。命令原文见 `runs/stage2-fuzz-newip-20261101/commands.txt`。

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-pulp-i2c-fuzz.json \
  --cache runs/stage2-fuzz-newip-20261101/cache \
  --output runs/stage2-fuzz-newip-20261101/ibex-apb-pulp-i2c \
  --fuzz --cases 80 --seed 21

python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-wb-apb-pulp-i2c-fuzz.json \
  --cache runs/stage2-fuzz-newip-20261101/cache \
  --output runs/stage2-fuzz-newip-20261101/wb-apb-pulp-i2c \
  --fuzz --cases 60 --seed 21
```

结果（命令行原样）：

```json
{"status": "fuzz_completed", "output": "runs/stage2-fuzz-newip-20261101/ibex-apb-pulp-i2c", "cases": 64, "passed": 80, "failed": 0, "distinct_features": 113, "corpus_entries": 52, "run_seconds": 0.02907410598709248, "total_seconds": 17.604599277983652}
{"status": "fuzz_completed", "output": "runs/stage2-fuzz-newip-20261101/wb-apb-pulp-i2c", "cases": 60, "passed": 60, "failed": 0, "distinct_features": 91, "corpus_entries": 40, "run_seconds": 0.02119644999038428, "total_seconds": 14.627796337008476}
```

第一行 `cases: 64` 是 `summary.json` 保留的 case 文档数；`fuzz.json` 的 `cases_total=80`、`cases_dropped=16` 是会话 64 条 case 文档上限造成的截断，执行数仍为 `fuzz_result.executed=80`、`passed=80`。第二行 60 例全部保留。两次的 `fuzz.json` 对应关系为 `matched=64/64` 与 `matched=60/60`，`mismatched` 为空，`findings=0`。

| 运行 | 执行 | 通过 | 失败 | F1 | F2 | F3 | F4 | F5 | F6 |
| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- |
| Ibex | 80 | 80 | 0 | 25 | 28 | 13 | 14 | 拒绝 | 拒绝 |
| Wishbone | 60 | 60 | 0 | 17 | 19 | 12 | 12 | 拒绝 | 拒绝 |

`run_summary` 的真实计数：

| 运行 | ticks | i_fetches | RAM 读 | RAM 写 | APB 读 | APB 写 | 退休 | trap | APB error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ibex | 3085 | 1439 | 192 | 124 | 8 | 14 | 1054 | 0 | 0 |
| Wishbone | 6425 | 846 | 150 | 93 | 4 | 12 | 784 | 0 | 0 |

## 5. 逐流真实观察

以下均取自 `run.log` 的 case 行（省略号处是未引用的字段），不是预测或回填：

- **F1 程序真实退休（Ibex）**
  `case 0 observations_passed flow F1 record F1:29d1f0b7:02092d83 … fetch 0x00012000 retire_pc 0x00012000 retire_insn 0x29d1f0b7 successor_pc 0x00012008 prog_words 2 prog_retires 2 prog_pc_ordered 1 prog_insns_match 1 prog_writebacks 2 prog_rd_mask 0x08000002 prog_last_rd 27 … prog_traps 0 data_changed 0`

  本批 F1 程序长度分布为 1/2/3/4 字（6/9/8/2 例），最大 4 字，与 `f1_program_words=4` 一致。另有带真实 store 的 F1 例：
  `case 29 … flow F1 record F1:29d1f0b7:00192e23:02092d83 … prog_words 3 prog_retires 3 prog_insns_match 1 … data_hash_before 0xa2535a95 data_hash_after 0xbb6f6c9b data_changed 1`

- **F1 同一程序在 Wishbone CPU 上**
  `case 0 observations_passed flow F1 record F1:29d1f0b7:02092d83 … fetch 0x00002000 retire_pc 0x00002000 prog_words 2 prog_retires 2 prog_insns_match 1 prog_traps 0`

- **F2 目标读（真实 PRDATA）**
  `case 4 observations_passed flow F2 record F2:40000008 … apb_reads 1 … read_addr 0x40000008 read_value 0x00000000 read_from apb apb_rdata 0x00000000`

  读的是 RX（offset 8）。本批没有读到 STATUS（offset 12），不把它写成已观察。

- **F2 RAM 读**
  `case 11 observations_passed flow F2 record F2:00014000 … read_value 0xdeadbeef read_from ram`

- **F3 RAM 写**
  `case 2 observations_passed flow F3 record F3:00014034:7aa6540d … ram_before 0x00000000 ram_after 0x7aa6540d`

- **F4 目标写（真实 APB 传输）**
  `case 3 observations_passed flow F4 record F4:40000004:79827b7a … mmio_addr 0x40000004 mmio_value 0x79827b7a apb_offset 0x00000004 apb_pwdata 0x79827b7a apb_pready 1`

  本批 F4 实际写到的偏移：Ibex 为 0x00、0x04、0x10、0x14（PRESCALER、CTRL、TX、CMD）；Wishbone 相同。F2 实际读到的偏移：Ibex 为 0x00、0x04、0x08、0x10、0x14；Wishbone 为 0x00、0x08、0x14。

- **F5：没有观察，按名拒绝。**
  Ibex：`unsupported-f5:target-irq-semantics:apb3:source_port,source_bit_offset,trigger_writes,status_offsets`。
  Wishbone：`unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero`。

- **F6：没有观察，按名拒绝。**
  两次均为 `unsupported-f6:no-dma-model:APB`。

## 6. 换 CPU / IP / DMA 需要写代码吗？

**CPU：不需要。** Wishbone 变体只改了 `cpu_profile`、`image_start`/`image_end` 和 `active_id`；入口用已有的 OBI/Wishbone 适配器、已有的 APB3 bridge 和同一份 I2C 声明直接运行。`summary.json` 里：

- Ibex：`cpu_bus.kind=obi_cpu`、`bus=obi`、`irq_width=1`、`fetch_identity=separate instruction channel`。
- Wishbone：`cpu_bus.kind=wishbone_cpu`、`bus=wishbone`、`irq_width=32`、`fetch_identity=mem_instr`、`instruction_identity=rt_lh_p_2_0_0`。

两次的 `target_protocol` 都是 `kind=apb3_register_observe`、`protocol=apb3`、`bridge=apb3_mmio_bridge`。没有出现任何按 CPU×IP 组合命名的分支。

**IP：不需要。** 新 IP 只增加了 `source_profile`、`target_window`、两个固定输入常量和 timing；协议选择、寄存器表、读写能力全部来自 profile，APB3 模板与 bridge 是既有的一次性适配。执行器、C++ host、`src/myfuzz/**` 都没有改动；工作区里 `src/` 的改动是其他 agent 的既有内容，不是本任务产生的。

**DMA：本次没有。** 没有 DMA profile、没有 `dma_window`，F6 按 `unsupported-f6:no-dma-model:APB` 拒绝。这不是因为需要为 I2C 写 DMA 代码，而是本任务没有选择带 DMA 的拓扑；若另加一个已适配的 DMA，仍需单独声明它的 profile、控制窗口和行为文件，那是另一个场景，不能从本次结果外推。

## 7. 哪里只靠声明不够，以及为什么

### 7.1 F5（I2C 中断）无法只靠场景/behavior 声明表达

- pinned profile 的 `interrupts` 是空数组；`interrupt_o` 只在 `port_actions` 里以 `observe` 出现，注释明确写着“no CPU IRQ binding is declared in this local profile”。
- 执行器的 `f5_declaration()`/`irq_declaration()` 会在场景的 `source_port`/`source_bit_offset`/`trigger_writes`/`status_offsets` 之外，再回到 `profile.interrupts` 里找与端口、位匹配的单一 IRQ 源。behavior 文件只提供场景侧的事实，不能新增 profile 的 `interrupts` 条目。
- 已实测：即使人为补全 4 个 F5 键（`source_port=interrupt_o`、bit 0、触发写、STATUS offset 12），入口仍以 `unsupported: the target declares no single IRQ output on interrupt_o` 拒绝；这不是“少写了 behavior 文件”。
- 另一个独立原因是本入口把 I2C 当作通用 APB3 寄存器目标（`apb3_register_observe` + `apb3_mmio_bridge`），没有实例化 `src/myfuzz/local_harness/rtl/pulp_i2c_single_slave_peer.h` 的 I2C peer；两根 pad 输入在本次运行里是常量 1。因此即使 profile 声明了 IRQ，通用寄存器目标也不会走完一次 I2C 命令、不会产生 completion IRQ。要改变这一点需要改 profile（本次禁止）和/或使用带 peer 的目标适配器（代码，超出本任务）。

所以本次保留 F1–F4，并让 F5 以入口给出的名字被拒绝；没有为它编触发序列、没有把 `interrupt_o` 说成已交付。`summary.json` 的 `f5.status=refused`、`irq_delivery=unknown` 与此一致。

### 7.2 F6 无法声明

F6 需要第二个模型（DMA）和它的控制窗口。本次选型没有天然 DMA 可挂：I2C profile 没有 DMA 端点，场景也没有声明 `dma_profile`/`dma_window`。入口因此按 `unsupported-f6:no-dma-model:APB` 拒绝。这不是 IP 的行为缺口，而是本任务选择的“单 IP、无 DMA”拓扑；要跑 F6 需要另加已适配的 DMA profile 和窗口声明，那是另一个场景。

### 7.3 固定输入需要写两处

如第 3 节所述，`source_fixed_inputs`（header）与 `source_tuning.fixed_inputs`（harness 请求）必须同时声明且一致。这是入口现有的两个消费点，不是新代码；但对“只写声明”的人来说是一个需要注意的重复。

## 8. 测试（不跑 RTL）

`tests/fuzz/test_new_ip_onboarding.py` 按 `tests/fuzz/test_fuzz_integration.py` 的方式构建 `declared_windows`、`f5_declaration`、`flow_arity`、`fuzz_collaborators`，不启动模型或 Verilator。它覆盖两个场景并断言：

- `profile_protocol(profile document) == 'apb3'`，且 profile 只有一个 `mmio_slave`，`interrupts == ()`；
- `declared_windows` 返回 profile 的 4 KiB 窗口、CPU 自己的 RAM 镜像、无 DMA 窗口；
- `flow_arity` 恰为 `{F1:1, F2:1, F3:2, F4:2}`，F5/F6 的拒绝名字符合预期；
- 每个场景各 100 条生成输入全部通过入口自己的 `parse_record`/`validate_record` 门禁，且 100 条里 F1–F4 都出现过；
- `fuzz_inputs` 文档声明 `flows=['F1','F2','F3','F4']` 和 `f1_program_words=4`。

运行结果：`8 passed in 0.37s`（`PYTHONPATH=src:. python3 -m pytest tests/fuzz/test_new_ip_onboarding.py -q`）。

## 9. 诚实的边界

- **拓扑**：一个 APB3 寄存器目标，可选一个 Wishbone DMA；本次没有 DMA。没有多 IP、没有 DMA 到 IP FIFO、没有多通道/不同宽度/复杂背压。CPU 侧只有 OBI 与 Wishbone；目标侧只有 APB3 与 AXI4-Lite。
- **时钟**：一个宿主 tick 驱动两个模型；profile 的 50 MHz 没有被建模，`assume_single_clock=true` 是显式假设。
- **F1**：只覆盖 RV32 直线短程序（LUI/AUIPC/OP-IMM/OP 和 x18 基址全字 LW/SW），不是任意 RISC-V 程序。
- **F2/F4**：只证明实际发生的 APB 传输；没有读到的偏移（如 STATUS 0x0c）不写成已覆盖，设备内部状态仍 unknown。
- **I2C 内部行为**：本次是通用寄存器目标观察，两根 pad 输入是常量 1，host 不做开漏线与解析，也没有 I2C peer；不声称 I2C 总线协议、地址/数据时序或中断语义被执行。
- **不声称**：RTL 覆盖率、证书、fuzz 批次的独立 replay、跨 testcase 状态消费认证。`corpus.json` 只是输入集合；`distinct_features` 是反馈特征数，不是覆盖率。
- **DUT 断言**：Verilator 未编译 `--assert`，不声称 DUT 内部正确性。
- **工作树**：本批在同一棵工作树上完成；工作区有其他 agent 的未提交改动，复跑结果以当时的执行器与 profile 字节为准。本任务只新增声明/测试/报告文件，没有改执行器、C++ host 或 `src/myfuzz/**`。

## 10. 复现

```sh
cd /home/qinkejiu/myfuzz
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-pulp-i2c-fuzz.json \
  --cache runs/stage2-fuzz-newip-20261101/cache \
  --output <新目录> --fuzz --cases 80 --seed 21
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-wb-apb-pulp-i2c-fuzz.json \
  --cache runs/stage2-fuzz-newip-20261101/cache \
  --output <另一个新目录> --fuzz --cases 60 --seed 21
PYTHONPATH=src:. python3 -m pytest tests/fuzz/test_new_ip_onboarding.py -q
```

## 相关文档

- [统一单进程执行器的闭环证据](../../runs/stage2-fuzz-newip-20261101/README.md)：本批的真实输出、命令与逐流原行。
- [设备行为声明](../inprocess-behavior-declarations.md)：为什么 behavior 文件不能替代 profile 的 `interrupts`。
- [Profile 驱动接入原型](../profile-onboarding.md)：profile/capability 的既有接入范围。
- [当前系统能力与代码整理盘点](../current-system-capabilities-20261101.md)：F1–F6、协议与拓扑的总体边界。
- [Fuzz 闭环批次记录](../../runs/stage2-fuzz-loop-20261101/README.md)：本任务之前的统一闭环基线（Timer/GPIO/UART/DMA 等）。


## 11. 合并验收复跑（2026-11-01 晚）

在六项任务合并后的最终代码上，PULP I2C 两条配置再次通过同一入口运行：

- `runs/stage2-acceptance-20261101/i2c-ibex-80/`：Ibex OBI，80/80，F1 16 / F2 24 / F3 25 / F4 15，`fuzz_completed`。
- `runs/stage2-acceptance-20261101/i2c-wb-60/`：PicoRV32 Wishbone，60/60，F1 12 / F2 14 / F3 21 / F4 13，`fuzz_completed`。

两次都没有新增组合代码；F5 仍按 `unsupported-f5:target-irq-semantics:apb3:...` 具名拒绝，F6 仍按 `unsupported-f6:no-dma-model:APB` 拒绝。合并验收总表见 `runs/stage2-acceptance-20261101/README.md`。
