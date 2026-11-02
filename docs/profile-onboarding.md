# Profile 驱动接入原型

CPU 和外设独立运行 RTL，宿主按声明的地址、协议和信号模拟数据流。组件需要先提供已有框架可使用的 profile、端口映射与必要行为描述；下面的生成器组合已适配组件，不会自动理解任意 RTL。

## 普通 MMIO（APB3 / Wishbone，另有 AXI4-Lite / AHB-Lite / TL-UL 目标）：F1–F4

参照 `configs/scenarios/mmio-profile-examples/` 下的配置，提供 CPU、IP 的 profile 或既有 request、MMIO 地址、RAM 窗口和测试写值。直接提供 `cpu_profile`、`ip_profile` 时，生成器根据各 profile 的 `evidence.local_harness` 生成 request；也可分别以 `cpu_timing`、`ip_timing` 指定时序。IP capability 可用 `ip_capability` 指定，或由 IP profile 的 `evidence.test_capability` 路径／`evidence.embedded_test_capability` 提供。设置 `memory_flows: true` 会在同一会话生成 F1（取指/执行）、F3（RAM 写）、F4（IP 写）、F2（IP 读）记录。

最小字段：

- CPU profile：真实源码清单、顶层/端口、时钟与复位、数据端点（OBI/Wishbone/AHB-Lite/AXI4-Lite 之一）、`cpu.xlen`/`extensions`/`reset_vector`；启动取指由 profile 声明，不由协议名推断。
- IP profile：目标端点协议（`apb`/3 或 `wishbone`/classic）与真实信号、`address.registers`（offset/width/access/side_effect）、复位/时钟和固定输入。
- IP capability：端点 read/write 能力；`register_semantics` 中字段的 `lsb/width/read_mask/write_mask/side_effect`。若 mask 不是 `0xffffffff`，必须声明 `write_policy: full_word_reserved_zero`（表示“全字写、保留位必须写 0”）；该策略与 `side_effect` 是两个独立维度，副作用按真实值声明，不要求为 `none`。例：ZipCPU UART 的 `SETUP` 使用 `mask 0x7fffffff` + `write_resets_uart_state` + `full_word_reserved_zero`。

当前已适配的侧：

- CPU：OBI、Wishbone、AHB-Lite、AXI4-Lite（各一次适配）；另有 AXI4 full（非 Lite）单点适配：VexiiRiscv 受限双通道 AXI4 主端口已接入 `compiled_mmio`，**F1–F4 已真实通过**（`runs/vexii-f1f4-20261031`，descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`，6 例 + fresh；F3/F1 为 `submitted`，F4 joins=2、F2 joins=1；F2/F4 另见 `runs/vexii-axi4-apb-i2c-20261031`）。**CVA6（64 位 packed）也已准入 `compiled_mmio` 并真实通过 F1–F4**（`runs/cva6-f1f4-20261031`，descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`，6 例 + fresh）：取指身份由 **ARID/RID 声明**（`instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`，由 `cva6_axi_mmio.py::cva6_instruction_identity()` 现场重读 6 个 RTL 锚点，缺失即退回 data-only refusal）；**只对当前 pinned WT 配置成立**，AMO 的 `ar.id[1]` 不作取指 hop，`retirement`/内部版本/跨例来源仍 unknown，48 字节片段第 9–12 字无权威快照。**BOOM（TileLink coherent）尚未准入**：Phase A（harness 生成 + 真 RTL lint，exit 0 无 warning，`runs/boom-tl-harness-lint/`）已完成，但 `source_verification=null`、拒绝点前移到 `component-render-refused`（缺源锁）；F2/F4 只有 `directed_standard_runner_router` 的各 6 例 + fresh（`compiled_mmio_admitted=false`），剩余 Phase B 约 850–1120 行。ZipAXI（AXI4 i/d 全双口，需新写 observer）仍移出阶段一。
- IP 目标：APB3、Wishbone、AXI4-Lite、AHB-Lite、TL-UL。AXI4-Lite（ZipCPU AXI UART，`SETUP` rw）与 AHB-Lite（Caliptra SHA，`NAME0` ro，仅 F2，1 例）已在真实 RTL 执行并完成 fresh replay；TL-UL（OpenTitan GPIO，`INTR_ENABLE` rw）的 **F2/F4 6 例 + fresh 已真实通过**（`runs/ibex-obi-tlul-gpio-20261031`），F4 记录为 18 字节（4 字节寄存器流 + A 通道 10 个已声明 pin 的 109 bit 切片），pin 入图由 `src/myfuzz/scenario/target_bus_pins.py` 提供。详见 [扩展总线适配](reports/extended-bus-adapters-20261031.md)。
- 例：`i2c-ibex-obi-profile`（OBI × APB I2C）、`i2c-picorv32-wb-profile`（WB × APB I2C）、`spi-picorv32-wb-memory`（WB × APB SPI）、`uart-picorv32-wb`（WB × Wishbone UART）、`spi-cvw-ahb-memory`（AHB × APB SPI）、`spi-picorv32-axi-memory`（AXI-Lite × APB SPI）。

```sh
python3 scripts/generate_mmio_scenario.py \
  --config configs/scenarios/mmio-profile-examples/uart-picorv32-wb.json \
  --output runs/example-mmio-generated
python3 scripts/run_generic_scenario.py \
  --descriptor runs/example-mmio-generated/generic_scenario.json \
  --records-file runs/example-mmio-generated/acceptance_sequence.json \
  --flow mixed --mode original --case runs/example-mmio-run \
  --cache runs/example-mmio-run/cache --execution-mode search
python3 scripts/run_generic_scenario.py \
  --descriptor runs/example-mmio-generated/generic_scenario.json \
  --records-file runs/example-mmio-generated/acceptance_sequence.json \
  --flow mixed --mode fresh --case runs/example-mmio-run \
  --cache runs/example-mmio-run/cache --execution-mode search
```

`--execution-mode search` 跳过默认的同进程 replay；`--mode fresh` 是独立新进程 replay。每个用例在 CPU 停到片段末尾的下一条未物化取指槽后的小窗口内结束（`instruction_boundary_park` 记录真实地址/tick/settle），这是宿主有意停顿，不应被当成 DUT 协议违规。

当前执行范围为 **单拍 32 位字、单个 IP 目标、APB3/Wishbone 普通 MMIO 的 F1–F4**；AXI4-Lite 与 TL-UL 目标已真实验证 F2/F4，AHB-Lite 只在无 32 位 rw 寄存器的 Caliptra SHA 上验证过 F2（F4 不存在）。宿主只负责传输与观察；DUT 内部正确性将来由插入断言判定，当前 Verilator 未编译 `--assert`，因此本流程不声称 DUT 断言通过。退休、RAM 读取版本、跨例来源、IP 内部状态和副作用一律保持 unknown，不授奖励。暂不支持的协议或变体应明确拒绝，不能静默伪造成功。

### RISC-V 指令生成（F1 输入）

`src/myfuzz/riscv/` 是按 profile 生成合法直线指令的独立模块：RV32I/M/C 可生成，A/Zicsr/Zifencei/RV64 提供编码器；默认生成池保证每条记录可被现有 F1 validator 接受。示例：

```sh
python3 scripts/generate_riscv_program.py \
  --profile configs/cpus/cv32e20/component_profile.json \
  --seed 20261030 --count 4 --ram-base 65536 --ram-size 196608 \
  --output runs/_riscv-f1-program
```

`runs/_riscv-f1-program/records.json` 可直接作为 `--records-file`（含 `F1:` 前缀），或单条 `--record F1:<hex>`。已用 4 条生成指令在 CV32E20 真实 RTL 上完成取指、执行与 52 条 RVFI 退休观察（trap=0），并与 F3/F4/F2 同一会话 fresh replay 匹配；RV64、A/CSR/FENCE 的 F1 执行、压缩指令的 retirement match 和 DUT 内部正确性仍未验证，详见 [RISC-V 生成器报告](reports/riscv-generator-20261030.md)。

## 外设中断

为 IP 提供一次 IRQ 行为描述，例如 `configs/peripherals/pulp_timer/irq_behavior.json`，包括真实中断输出、触发寄存器写和 ISR 读取／清除行为。与已适配 CPU profile 组合：

```sh
python3 scripts/generate_declared_irq_f5_config.py \
  --cpu-profile configs/cpus/cv32e40p_rvfi_local/component_profile.json \
  --irq-behavior configs/peripherals/pulp_timer/irq_behavior.json \
  --output runs/example-irq-config.json
python3 scripts/run_declared_irq_f5.py --native \
  --config runs/example-irq-config.json --mode original \
  --output runs/example-irq-run --cache runs/config-driven-20261028/cache
python3 scripts/run_declared_irq_f5.py --native \
  --config runs/example-irq-config.json --mode fresh \
  --original runs/example-irq-run --output runs/example-irq-fresh \
  --cache runs/config-driven-20261028/cache
```

当前入口面向已注册 OBI CPU 和实际可描述的单路 IRQ pulse；静态准入不等于真实执行，证书是否授予消费奖励以运行结果为准。

## DMA 与共享路径

参照 `configs/scenarios/shared-dma-profile-examples/cv32e20-zipdma.json`，提供已适配 CPU request、DMA request 和 DMA capability：

```sh
python3 scripts/generate_shared_dma_scenario.py \
  --config configs/scenarios/shared-dma-profile-examples/cv32e20-zipdma.json \
  --output runs/example-dma-generated
python3 scripts/preflight_generic_scenario.py \
  --descriptor runs/example-dma-generated/generic_scenario.json
python3 scripts/run_shared_slot_subset.py --native \
  --descriptor runs/example-dma-generated/generic_scenario.json \
  --records F6:0110c00008000000 --output runs/example-dma-run \
  --cache runs/config-driven-20261028/cache
```

生成器复用共享 F1–F6 runtime，从 source-backed provider 选择 DMA 端点、SEL 和中断类型；当前共享 CPU 侧仍限已有适配的 RV32 OBI session。`configs/scenarios/shared-dma-profile-examples/cv32e20-zipdma-timer.json` 展示独立 APB Timer 目标：F2/F4 访问 Timer，GPIO 为 F5 辅助中断源，ZipDMA 为 F6 搬运组件。普通 APB 目标可以只提供总线声明：实际 CPU/APB 传输仍需验证，但如果没有可信内部存储观察，其内部版本和跨例来源为 unknown、不授奖励。PULP I2C 作为该类目标已通过固定六路径及独立进程重放。该场景应使用生成的 `acceptance_sequence.json` 中的目标地址；不要使用包含旧 GPIO 地址的固定默认记录。

`configs/scenarios/shared-dma-profile-examples/cv32e20-profile-zipdma-profile-idle-i2c.json` 展示由 CPU、DMA 和目标 IP 的 profile 自动生成三个 request：CPU/DMA 的复位时序来自各自 `evidence.local_harness`，DMA/IP 的 capability 由各自 profile 引用，目标 IP 的固定输入由 profile 声明。该例的固定八用例与独立进程 replay 已真实通过；capability sidecar 仍是独立文件，组件行为和时序仍需明确提供。

DMA 的 `evidence.f6_dma` 可声明 CSR、长度单位及 IRQ 行为并复用已有 Wishbone 适配器；声明仍须通过来源、实际端口和运行时事务验证。已注册 ZipDMA 的声明式 profile 已执行一条真实 F6；新 DMA 仍需通过相应总线和信号契约，尚未验证任意新 DMA。预检仅报告静态支持，真实运行及 fresh replay 需要单独验证。

CPU profile 可用 `evidence.boot_fetch` 声明启动取指公式，并通过 `evidence.local_source_manifest` 内嵌源码来源清单与 elaboration closure。`configs/cpus/cv32e20_profile_only/component_profile.json` 是不在中央组件名注册表中的示例：已运行两条真实指令，但 RTL 仍是已有 CV32E20；IRQ 观测和共享六路径仍有限定的 CPU 适配，并非任意 CPU 只填此字段就可使用。

`configs/scenarios/shared-dma-profile-examples/profile-only-newid-embedded.json` 使用另一个 CPU ID `cv32e20_profile_irq_adapter`，通过 CPU、DMA 和 I2C profile 生成 request；其固定八例 F1–F6 与同次调用内独立进程 replay 已在真实 RTL 通过，F5 使用辅助 GPIO，F6 使用 ZipDMA。运行摘要为 `runs/profile-only-newid-embedded-all-native-20261030/original/summary.json`，具体证据边界见 [原型报告](reports/profile-prototype-20261030.md)。CPU RTL 仍是已有 CV32E20，I2C 内部版本和跨例来源 unknown，不授奖励；不能外推为新 CPU 设计或任意 IP 自动支持。

已适配 OBI CPU 可通过 profile 声明实际顶层中断信号或已实现的 native IRQ 适配；具体退休字段和来源能力取决于 CPU 的真实观测，不从 profile 名推断。远端 CV32E40P + ZipDMA + I2C + GPIO 也完成上述固定八例及同次调用的独立进程 replay；完整材料位于远端快照，本地保存摘要 `runs/remote-cv32e40p-profile-20261030/summary.json`，未进行跨 CLI 对照。`configs/peripherals/unregistered_zipdma_profile/component_profile.json` 是不在源码注册表中的 DMA ID：内嵌来源清单和行为声明，已用同一 ZipDMA RTL 执行一条真实 F6 及独立进程重放；不能外推到不同 DMA RTL。

含独立目标 IP 的共享场景还会生成 `search_scenario.json`，可由 `scripts/run_dependency_search.py` 使用。F2 的目标由实际布局决定；高层可记录同版本真实观察，但来源为 unknown 时不授奖励。普通目标不自动成为 GPIO 引脚或 IRQ 源。

以上输出目录须为新目录。重放复用已验证构建缓存，但启动独立组件进程；它不等同于独立重新编译。每个结果只证明实际执行并有证据的路径，不能从协议名推断 DMA、中断或外设内部状态。
