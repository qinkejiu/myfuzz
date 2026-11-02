# 统一执行器第二批新 IP 接入：PULP SPI 进入 fuzz 闭环（2026-11-01）

## 结论

1. **没有剩下可选的未接入 APB3/AXI4-Lite 寄存器 IP。** `configs/peripherals/` 下 13 个 APB3/AXI4-Lite profile 分属 5 个 RTL family（PULP I2C、PULP SPI、PULP Timer、PULP GPIO、ZipCPU AXI UART），每个 family 都已被某个 `configs/scenarios/inprocess-*.json` 选中；没被场景直接引用的 7 个 APB3 profile 都是这些已接入 family 的别名声明。其余未用 profile 分别属于 TL-UL（16 个）、AHB-Lite（1 个）、Wishbone 目标（3 个）和 Wishbone DMA（7 个），**本入口只有 APB3 与 AXI4-Lite 目标适配器**（`PROFILE_PROTOCOLS` 只有 `('apb','3')` 与 `('axi4-lite','1')`），因此它们在构建任何 RTL 之前就被按名拒绝。4 次真实探针运行给出原文拒绝名（见 §3）。
2. **PULP SPI 是"协议相同、RTL 已 pinned、但还没进入 fuzz 路径"的那个 IP。** 它此前只被固定记录路径 `configs/scenarios/inprocess-verify-irq-pulp-spi-f1f6.json` 使用；`configs/scenarios/` 里没有任何 `inprocess-*-fuzz.json` 选过它。本次只加两个场景声明把它接进 `--fuzz`：Ibex OBI 80 例（79 通过、1 个 `not_triggered`）、PicoRV32 Wishbone 60 例（60 通过），**没有改执行器、C++ host、`src/myfuzz/**`，没有改任何既有 config/behavior/doc/test**，也没有 CPU×IP 分支。
3. F5（EOT 脉冲）在 Ibex 上是真实观察：3 次 F5 尝试中 2 次出现 `irq_edges 1`、`irq_takes 1`、`delivered_high_ticks 16`，ISR 读 `INTSTA`（0x28）。第 3 次（case 77）在 1628 tick 内没有 EOT，`wait_timeout 1`，入口按 `not_triggered` 记为**预期失败**；本文不把它说成通过，也不声称已定位原因。
4. F6 两次都按名拒绝：`unsupported-f6:no-dma-model:APB`。Wishbone 运行的 F5 也按名拒绝：`unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero`（原因是 CPU 的 32 位 IRQ 向量未接线，不是目标没有中断源）。
5. 本文只描述实际执行与声明；不声称 RTL 覆盖率、证书、完整 replay 或跨 testcase 状态认证。

## 1. 清单：为什么"未用的同协议 IP"为空

统一入口的目标协议由 profile 的 `mmio_slave` 端点决定，只有 APB3 与 AXI4-Lite 有适配器。按这个口径扫描全部 `configs/peripherals/*/component_profile.json`：

| profile 协议 | 数量 | 代表 profile | 入口能否作为目标 |
| --- | ---: | --- | --- |
| `apb/3` | 12 | `pulp_i2c`、`pulp_spi`、`pulp_timer`、`pulp_gpio`、`inprocess_verify_pulp_spi_irq`、`pulp_timer_irq`、`pulp_gpio_causal_local`、`pulp_gpio_storage`、`profile_only_i2c`、`profile_only_idle_i2c`、`embedded_profile_target`、`shared_profile_target` | 能（已有适配器） |
| `axi4-lite/1` | 1 | `zipcpu_axiluart` | 能（已有适配器） |
| `tl-ul/1` | 16 | `opentitan_pattgen_local`、`opentitan_rv_timer_local`、`opentitan_i2c_local`、`opentitan_uart_local`、`opentitan_spi_host_local` 等 | 否：`unsupported-target-protocol:tl-ul/1` |
| `ahb-lite/1` | 1 | `caliptra_sha256` | 否：`unsupported-target-protocol:ahb-lite/1` |
| `wishbone/classic` | 3 | `zipcpu_timer`、`zipcpu_uart`、`zipcpu_uart_storage` | 否：`unsupported-target-protocol:wishbone/classic` |
| `wishbone/pipelined` | 7 | `zipdma_smoke`、`zipcpu_wbdmac` 等 | 不是目标：只作为 F6 的 DMA 模型 |

**13 个 APB3/AXI4-Lite profile 的 5 个 RTL family 全部已被场景使用**（`source.root` + `source.top_module` 相同即同一 family）：

| family（root / top） | profile 数 | 被哪个 `inprocess-*.json` 选中 |
| --- | ---: | --- |
| `third_party/soc-pulp-apb-i2c` / `apb_i2c` | 5 | `inprocess-obi-apb-pulp-i2c-fuzz.json`、`inprocess-wb-apb-pulp-i2c-fuzz.json` 等 |
| `third_party` / `apb_spi_master` | 2 | 固定记录路径 + **本次新增的两个 fuzz 场景** |
| `third_party/soc-pulp-apb-timer` / `apb_timer` | 2 | Timer 的 F1–F6 / fuzz 场景 |
| `third_party/soc-pulp-apb-gpio` / `apb_gpio` | 3 | GPIO pins F1–F5 / fuzz 场景 |
| `third_party/soc-zipcpu-wbuart` / `axiluart` | 1 | AXI4-Lite UART + ZipDMA 场景 |

未被场景直接引用的 7 个 APB3 profile 是：`pulp_timer`、`pulp_gpio`、`pulp_gpio_storage`、`profile_only_i2c`、`profile_only_idle_i2c`、`embedded_profile_target`、`shared_profile_target`；它们与上面已接入 family 共用同一 RTL 与寄存器表，不是新的 IP。因此按"未接入的 APB3/AXI4-Lite 寄存器 IP"这个定义，**候选集为空**；不为它们造 profile，也不把别名声明说成新 IP。

## 2. 候选与阻断原因（含真实探针）

| 候选 | 事实（profile） | 阻断 | 探针原文 |
| --- | --- | --- | --- |
| `opentitan_pattgen_local` | TL-UL 1；64 B 窗口；INTR_STATE/CTRL/PREDIV/DATA 等 32 位 rw 寄存器；自带 `closure.json`（Verilator lint returncode 0） | 入口无 TL-UL 目标适配器；接入需要新增 TL-UL bridge + 模型 kind（代码，超出本任务） | `unsupported-target-protocol:tl-ul/1` |
| `opentitan_rv_timer_local`、`opentitan_i2c_local`、`opentitan_uart_local`、`opentitan_spi_host/device_local`、`opentitan_sysrst_ctrl(_local)`、`opentitan_gpio(_local)`、`opentitan_uart(_fifo_local)` | 全部 `tl-ul/1`，窗口 4 KiB 级 | 同上 | 同族拒绝名 |
| `caliptra_sha256` | AHB-Lite 1；4 KiB；只有 `NAME0/1`、`VERSION0/1` 等只读字，`CTRL/BLOCK*` 只写，没有通用 32 位 rw 寄存器 | 入口无 AHB-Lite 目标适配器；且不满足"通用 32 位 rw" | `unsupported-target-protocol:ahb-lite/1` |
| `zipcpu_timer` | Wishbone classic；4 B；单个 `COUNT` rw | 入口没有 Wishbone 目标适配器（Wishbone 只作为 CPU 总线与 DMA） | `unsupported-target-protocol:wishbone/classic` |
| `zipcpu_uart` / `zipcpu_uart_storage` | Wishbone classic；16 B；`SETUP/FIFO_STATUS/RXREG/TXREG` | 同上 | `unsupported-target-protocol:wishbone/classic` |
| 7 个 Wishbone DMA profile | `zipdma` / `wbdmac` | 是 DMA 模型，不是寄存器目标；只有声明成 `dma_profile` 才参与 F6 | 不适用 |
| PULP I2C / Timer / GPIO 的别名 profile | 与已接入 family 同 RTL、同寄存器表 | 任务显式排除；I2C 已在 2026-11-01 首批接入 | 不适用 |

探针声明在 `runs/stage2-newip2-20261101/probes/<candidate>/config.json`，只用于拒绝，不是场景；4 次运行均 `exit=1`、未构建 RTL，输出目录里只有拒绝前写出的 `cpu_request.json`。

## 3. 选定的"新"IP：PULP SPI

- **新在哪里**：`inprocess_verify_pulp_spi_irq` 与 `pulp_spi` 的 RTL 已被固定记录路径选中（`inprocess-verify-irq-pulp-spi-f1f6.json`、`inprocess-verify-irq-pulp-spi-unmodified-f1f6.json`），但 `configs/scenarios/` 中没有任何 fuzz 场景选 SPI；此前 fuzz 批次的 IP 只有 Timer、GPIO、I2C、AXI UART。因此对 **fuzz 闭环** 而言它是新 IP，而且不需要新代码。
- **pinned 源**：profile 的 `source.root=third_party`、`top_module=apb_spi_master`、`revision=sha256:c65381184345…020230`，与 `pulp_spi` 完全一致；RTL 源码闭包在 `configs/soc/closures/pulp_spi.json` 与 `pulp_spi_dependencies.json`。`inprocess_verify_pulp_spi_irq` 本身是对同一 pinned RTL 的再声明（不在 `sources.lock` 的组件名列表里，也不新增源码锁），只多了一条 `interrupts` 事实。
- **寄存器**：10 个 32 位字（STATUS 0、CLKDIV 4、SPICMD 8、SPIADR 12、SPILEN 16、SPIDUM 20、TXFIFO 24、RXFIFO 32、INTCFG 36、INTSTA 40），不需要 host 侧的设备专属协议端口。
- **已声明的 IRQ**：profile 的 `interrupts` 恰好一项，`spi.events` 上的 `spi_eot`，bit 1，`trigger=pulse`、`pulse_width_cycles=1`；`hold` 写明是 `spi_master_controller.sv:455` 的一拍脉冲。因此 F5 **可声明**，没有编造中断语义。
- **行为文件**：复用既有的 `configs/behaviors/pulp_spi_eot_f5.json`（`events_o[1]`、16 tick、触发写 `[[16,65536],[24,171],[0,2]]`、状态字 offset 40、无 cause 位、无清除写）。场景只写 `source_behavior` 路径，不重复事实；这些值与固定记录场景 `inprocess-verify-irq-pulp-spi-f1f6.json` 的内联声明逐项一致，本次没有新增触发值或偏移。

## 4. 新增文件（只有新文件）

| 文件 | 作用 |
| --- | --- |
| `configs/scenarios/inprocess-obi-apb-pulp-spi-fuzz.json` | Ibex OBI + PULP SPI APB3，无 DMA，F1–F5 |
| `configs/scenarios/inprocess-wb-apb-pulp-spi-fuzz.json` | 同一 IP + PicoRV32 Wishbone CPU，无 DMA，F1–F4（F5 由 CPU 拒绝） |
| `tests/fuzz/test_new_ip_2_onboarding.py` | 纯 Python 接入 + 清单探针测试（不启动 RTL） |
| `runs/stage2-newip2-20261101/` | 4 次拒绝探针、1 次 4 例冒烟、2 次主批次、构建缓存、`commands.txt`、`run_json_lines.txt`、`README.md` |
| `docs/reports/new-ip-2-onboarding-20261101.md` | 本报告 |

没有新增 behavior 文件（复用既有的一份），没有修改 `scripts/run_inprocess_f1f6.py`、`scripts/inprocess_obi_apb_f1f4_spike.cpp`、`src/myfuzz/**`、既有 config/behavior/test/doc 或其他 run 目录。

## 5. 两个场景声明了什么

| 键 | Ibex 变体 | Wishbone 变体 | 来源 |
| --- | --- | --- | --- |
| `source_profile` | `configs/peripherals/inprocess_verify_pulp_spi_irq/component_profile.json` | 同左 | pinned profile |
| `source_behavior` | `configs/behaviors/pulp_spi_eot_f5.json` | 同左 | 既有行为文件 |
| `target_window` | `{base: 0x40001000, size: 4096}` | 同左 | 与固定记录 SPI 场景相同的窗口；profile `window_size=4096` |
| `active_id` | `spi_active` | `target` | 声明 |
| `cpu_profile` | `ibex_rvfi_local` | `picorv32_wb_irq_rvfi` | CPU 自己的 profile |
| `cpu_timing` | 8/8/16 | 4/4/16 | 声明 |
| `source_timing` | 2/3/16 | 2/3/16 | 声明 |
| `image_start`/`image_end` | 65536 / 196608 | 0 / 131072 | CPU 自己的 boot contract（Wishbone CPU 的 reset vector 为 0） |
| `source_fixed_inputs` + `source_tuning.fixed_inputs` | `sdi0..sdi3 = 0` | 同左 | 四根 SPI 数据输入；两处值必须一致，入口分别消费 |
| `f1_program_words` | 4 | 4 | 声明 |
| `handler_wait_iterations` | 128 | 128 | 声明 |
| `assume_single_clock` | true | true | 两份 profile 都声明 50 MHz |
| DMA | 无 | 无 | F6 按名拒绝 |

入口没有从 IP 名字里推断任何行为：协议读 profile 的 `mmio_slave` 端点，窗口读声明，中断事实读行为文件并再与 profile 的 `interrupts` 交叉校验，寄存器表读 profile。两次运行的 `summary.json` 都是 `target_protocol.kind=apb3_register_observe`、`protocol=apb3`、`bridge=apb3_mmio_bridge`、`combination_specific_branches='none: wiring comes from the generated binding header and the declared device behavior'`。

## 6. 命令与结果

命令原文见 `runs/stage2-newip2-20261101/commands.txt`，输出原文见 `run_json_lines.txt`。两次主批次都使用本次新建的 `runs/stage2-newip2-20261101/cache`，一次只跑一个 RTL 进程。

```sh
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-pulp-spi-fuzz.json \
  --cache runs/stage2-newip2-20261101/cache \
  --output runs/stage2-newip2-20261101/fuzz-obi-spi-80-seed41 \
  --fuzz --cases 80 --seed 41

python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-wb-apb-pulp-spi-fuzz.json \
  --cache runs/stage2-newip2-20261101/cache \
  --output runs/stage2-newip2-20261101/fuzz-wb-spi-60-seed41 \
  --fuzz --cases 60 --seed 41
```

入口 stdout（原文）：

```json
{"status": "fuzz_completed", "output": "runs/stage2-newip2-20261101/fuzz-obi-spi-80-seed41", "cases": 80, "passed": 79, "failed": 1, "distinct_features": 115, "corpus_entries": 50, "run_seconds": 0.03869879900594242, "total_seconds": 6.852674653986469}
{"status": "fuzz_completed", "output": "runs/stage2-newip2-20261101/fuzz-wb-spi-60-seed41", "cases": 60, "passed": 60, "failed": 0, "distinct_features": 86, "corpus_entries": 39, "run_seconds": 0.026739202003227547, "total_seconds": 16.411556773004132}
```

另有冷缓存 4 例冒烟：`{"status": "fuzz_completed", …, "cases": 4, "passed": 4, "failed": 0, …}`（`smoke-obi-spi/`），用于先验证声明能构建。

## 7. 流矩阵

| 运行 | 执行 | 通过 | 失败 | F1 | F2 | F3 | F4 | F5 | F6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Ibex OBI 80 例 | 80 | 79 | 1 | 19 | 29 | 17 | 12 | 2/3（1 次 `not_triggered`） | 拒绝 |
| PicoRV32 WB 60 例 | 60 | 60 | 0 | 11 | 23 | 13 | 13 | CPU 拒绝 | 拒绝 |

`run_summary` 真实计数：

| 运行 | ticks | i_fetches | RAM 读 | RAM 写 | APB 读 | APB 写 | 退休 | trap | IRQ 边沿 | IRQ 接受 | 超时 | 设备复位 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ibex 80 | 4809 | 2307 | 338 | 155 | 9 | 21 | 1657 | 0 | 2 | 2 | 1 | 1 |
| Wishbone 60 | 6625 | 850 | 158 | 105 | 9 | 13 | 788 | 0 | 0 | 0 | 0 | 0 |

`fuzz.json`：Ibex `matched=79/80`、`mismatched=[]`、`defects=0`、`expected_failures=1`；Wishbone `matched=60/60`、`mismatched=[]`、`defects=0`。`cases_total=cases_retained=80/60`，没有截断。

## 8. 真实 case 例子（摘自 `run.log`）

- **F5 成功（Ibex）**
  `case 0 observations_passed flow F5 record F5:00010000:000000ab:00000002 ticks 174 … apb_reads 1 apb_writes 3 trigger_writes 3 apb_read_offset 0x00000028 apb_read_data 0x00000000 apb_last_write_offset 0x00000000 apb_last_write_data 0x00000002 irq_edges 1 irq_high_ticks 1 device_high_ticks 1 delivered_high_ticks 16 irq_takes 1 wait_timeout 0 isr_result 0x00000000 isr_flag 1 isr_read_addr 0x40001028 isr_read_value 0x00000000 …`
- **F5 成功（另一例，fuzzer 把 TXFIFO 值变异成 0xddec9d4f）**
  `case 6 … record F5:00010000:ddec9d4f:00000002 … irq_edges 1 irq_takes 1 delivered_high_ticks 16 wait_timeout 0`
- **F5 未触发（预期失败）**
  `case 77 failed flow F5 record F5:00010000:000000ab:00000002 ticks 1628 … apb_writes 3 irq_edges 0 irq_high_ticks 0 delivered_high_ticks 0 irq_takes 0 wait_timeout 1 isr_flag 0`
- **F1 四字程序（Ibex，RAM 基址 0x10000）**
  `case 1 … F1:21707593:02b5fcb3:01992223:00492083 … fetch 0x00012000 retire_pc 0x00012000 retire_insn 0x21707593 successor_pc 0x00012010 prog_words 4 prog_retires 4 prog_pc_ordered 1 prog_insns_match 1 prog_traps 0 data_hash_before 0xf870121f data_hash_after 0x249f7c1b data_changed 1`
- **F1 四字程序（Wishbone，RAM 基址 0）**
  `case 0 … fetch 0x00002000 … prog_words 4 prog_retires 4 prog_insns_match 1 prog_traps 0 data_changed 1`
- **F2 目标读**
  `case 10 … F2:40001010 … apb_reads 1 read_from apb read_value 0x00010000 apb_rdata 0x00010000`
- **F4 目标写**
  `case 4 … F4:40001018:b0ac88b8 … apb_offset 0x00000018 apb_pwdata 0xb0ac88b8 apb_pready 1`

### 8.1 关于那次 `not_triggered`

- 现象：case 77 用与 case 0 **完全相同**的触发向量 `F5:00010000:000000ab:00000002`，三次 APB 写都发生（`apb_writes 3`、`apb_last_write_offset 0`、`apb_last_write_data 2`），但 1628 tick 内 `irq_edges 0`，随后按 `wait_timeout 1` 结束；入口只复位设备（`device_resets 1`）。
- 分类：入口 `classify_case` 把它归为 `not_triggered`（预期失败），不是 `protocol_error`、`device_anomaly` 或 `observation_mismatch`，`findings=0`。
- 已知事实：case 0 与 case 6 之后设备没有被复位；两次成功之间和之后有 F4 写命中 `CLKDIV(0x04)`、`SPICMD(0x08)`、`SPILEN(0x10)`、`SPIDUM(0x14)`、`TXFIFO(0x18)`，没有 F4 命中 `STATUS(0x00)`。**原因未定位**，因此本文不声称"SPI 有缺陷"，也不声称"同一向量总能触发"；只报告这次真实超时及其分类。
- 这也是当前拓扑的一条边界：成功 case 之间不重置设备，跨 case 的设备内部状态不在本入口的观察范围内。

## 9. F5 / F6 拒绝（原文）

- F6（两次运行）：`unsupported-f6:no-dma-model:APB`。
- F5（Wishbone 运行）：`unsupported-f5:cpu-irq-unwired:wishbone:32-bit-irq-held-at-zero`。`summary.json` 里 `f5.status=refused`，但 `f5.declared_facts` 仍有 4 项，`behavior.source.declared_by=file`、`declaration_path=configs/behaviors/pulp_spi_eot_f5.json`——被拒绝的是 CPU 的 IRQ 接线，不是目标没有声明。
- 未用 IP 探针：`unsupported-target-protocol:tl-ul/1`、`:ahb-lite/1`、`:wishbone/classic`（§2 表）。这些都不是 F5/F6 的拒绝，而是**目标协议**在构建前的拒绝；把它们改写成 F5/F6 需要新代码（TL-UL/AHB-Lite/Wishbone 目标 bridge），不属于"只加声明"。

## 10. 换 CPU / 换 IP 需要写代码吗？

**都不需要（在已有协议适配器范围内）。**

- **换 CPU**：Wishbone 变体只改了 `cpu_profile`、`cpu_timing`、`image_start`/`image_end` 和 `active_id`，其余声明不变。`summary.json` 里 `cpu_bus.kind` 从 `obi_cpu` 变成 `wishbone_cpu`、`irq_width` 从 1 变成 32、`fetch_identity` 从 `separate instruction channel` 变成 `mem_instr`，而 `target_protocol.kind/protocol/bridge` 两次完全相同（`apb3_register_observe` / `apb3` / `apb3_mmio_bridge`）。F5 在 Wishbone 上被拒绝是 CPU 侧的声明问题，改它需要声明 CPU IRQ 位或换 CPU，不是写 CPU×IP 代码。
- **换 IP**：本次只增加了 `source_profile`、`source_behavior`、`target_window`、四个固定输入常量和 timing；协议选择、寄存器表、读写能力、IRQ 事实分别来自 profile 与既有行为文件。执行器、C++ host、`src/myfuzz/**` 均未改动，也没有新增按组合命名的分支。
- **例外要说清**：真正"另一个 RTL family"的 IP（TL-UL/AHB-Lite/Wishbone 目标）不能只靠声明接入——本入口没有这些目标适配器，接入必然要写 bridge/模型代码并重新验证，超出本任务与"只加声明"的边界。

## 11. 剩余拓扑限制

- **一个目标 + 可选一个 Wishbone DMA**，这是入口当前的全部拓扑：没有多目标窗口、没有目标到目标的地址路由、没有多 IP 组装。本场景没有声明 DMA，所以 F6 只能按名拒绝；要跑 F6 必须另加一个已适配的 DMA profile/窗口/行为声明。
- 目标是 APB3 或 AXI4-Lite 的**单个寄存器窗口**；不支持 TL-UL、AHB-Lite、Wishbone 目标，也不支持完整 AXI4。
- 传输只有单拍、全字、32 位；无字节使能、无 burst、无 DMA 到 IP FIFO、无多宽度/多通道。
- 一个宿主 tick 同时驱动所有模型；两份 profile 都声明 50 MHz，未建模时钟比。
- F1 短程序限 1–16 条直线指令，只允许 x18 基址的全字 LW/SW；Wishbone CPU 上的 F5 仍需要显式的 CPU IRQ 声明，本批次没有声明。

## 12. 验证与不声称的内容

- 纯 Python 测试：`PYTHONPATH=src:. python3 -m pytest tests/fuzz/test_new_ip_2_onboarding.py -q` → **14 passed in 0.34s**（不启动 RTL）。它检查两个场景的协议/窗口/arity、行为文件与固定记录场景的逐项一致、100 条生成输入全部通过入口自己的 `parse_record`/`validate_record` 门，以及清单不变式：13 个 APB3/AXI4-Lite profile 的 family 集合固定、未被引用的 APB3 profile 集合固定、每个被阻断的候选都以确切拒绝名失败。清单断言是**探针**：有人新增未接入的寄存器 IP profile 时它会失败，而不是静默通过。
- 本报告与 `runs/stage2-newip2-20261101/` 只证明实际执行过的输入、观察和拒绝名；不声称 RTL 覆盖率、证书、完整 replay、跨 testcase 状态认证，也不声称 SPI 内部协议或外部 SPI 从设备行为正确。
