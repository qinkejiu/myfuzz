# 步骤 1 基线：现有链路复现与硬编码清单（2026-09-21）

计划来源：`docs/superpowers/plans/2026-09-20-soc-composition-assurance-plan.md` 步骤 1。
本轮 `third_party/` 与 `external_designs/` 子模块已 checkout，原先的环境阻塞消失；本文件记录**实际执行过**的复现结果与源码审阅结论，运行证据保存在 `runs/soc-baseline-step1/`（`/runs/` 已被 gitignore）。

## 1. 锁定源码与工具复现

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 scripts/verify_soc_sources.py   # exit 0
```

结果：全部 9 条锁定记录 `source_verified`；7 条 `elaboration_verified`（opentitan_uart/gpio、pulp_gpio/spi/spi_dependencies、zipcpu_uart/timer），2 条 `elaboration_unverified`（ibex、cva6，按锁文件设计如此）。所有记录的 `runtime_status` 仍是 `runtime_unverified`——本步骤没有把它改写成已验证。

## 2. 一个已有组合的完整复现

调用链（已实测，不是读代码推断）：

```text
scripts/run_soc_campaigns.py::run_matrix
 → soc_matrix_smoke.cell_documents(config_path, mode)
 → build_spec + build_execution + build_contracts
 → soc_plan.build_soc_plan(spec, execution, contracts)
 → soc_stimulus.compile_soc_stimulus(plan, policy)
 → soc_renderer.render_soc(plan, stimulus)
 → soc_builder.build_soc_campaign_artifact → verilator --binary → live_tb.sv
 → soc_campaign.run_soc_campaign → rfuzz_live.run_live → 语料/仿真交互
```

复现命令与结果（12 次真实构建+仿真，全部 `status=OK`）：

| cell | cpu_only | mmio_only | mixed |
| --- | --- | --- | --- |
| ibex-pulp | OK (0.1 s，复用构建) | OK (8.0 s) | OK (8.0 s) |
| ibex-opentitan | OK (10.6 s) | OK (8.4 s) | OK (10.3 s) |
| ibex-zipcpu | OK (9.6 s) | OK (9.0 s) | OK (9.1 s) |
| cva6-pulp | OK (40.4 s) | OK (26.2 s) | OK (39.4 s) |

`ibex-pulp/cpu_only` 的观测行（截取关键字段）：

```text
status=OK cycles=223 cpu_tx=27 cpu_done=26 fuzz_tx=0
window_done_cpu=2 window_rdata_cpu=0x5a5a0002 window_addr=0x4000000c
cpu_flag=0xf00d0001 cpu_readback=0x5a5a0002 side_effect=0x5a5a0002
fabric_error=0 irq=0
```

即：真实 Ibex 执行了生成的启动程序，经真实互联完成了 MMIO 事务，外设真实副作用（`gpio_out`）可观测，完成标志写回 RAM。

## 3. 三种模式在 RTL 中的真实差别

对同一 cell 三种模式的渲染结果做逐字节 diff：

- `cpu_only` ↔ `mmio_only`：仅两行不同——`localparam bit CPU_HELD_IN_RESET = 0/1` 与 `.ADDRESS_STRATEGY(0/1)`。
- `cpu_only` ↔ `mixed`：仅 `.ADDRESS_STRATEGY(0/1)` 一行不同。

**结论**：除 `mmio_only` 的 `CPU_HELD_IN_RESET` 之外，模式差异全部只是渲染参数与元数据，没有任何 RTL 机制阻止被屏蔽段参与。`masked_segments` 只写进 provenance。这是步骤 6A 要补的“归属明确”缺口。

## 4. 六类接口现状—证据—缺口—修改位置

| 接口类 | 现状 | 证据 | 缺口 | 修改位置 |
| --- | --- | --- | --- | --- |
| 时钟/复位 | 单域；顶层 `clk_i`/`reset_i`；`mmio_only` 用 `CPU_HELD_IN_RESET` 保持 CPU；内存模型是**低有效异步复位**（`riscv_boot_memory.sv:38-40` 每个复位周期重写整块内存），beat 侧适配器是高有效 | `render/soc_top.sv:46-48`；内存/适配器复位极性已由新路径的 `SYSTEM_RESET`-类契约声明并审计 | 旧矩阵路径没有复位极性/释放条件的独立核对；新路径有 | 新路径 `soc_structure_audit.py`；旧路径不动 |
| 取指/数据访存 | Ibex 分裂 OBI 经 `obi_processor_memory_adapter` 汇入共享 beat；CVA6 AXI4 统一 | `configs/cpus/*/interface_description.json`、`processor_adapters.py` | 旧路径 `soc_matrix_smoke.build_execution` 仍按“协议是否 AXI4”决定统一/分离（`build_execution` 的 `is_unified`） | 新路径已用 `resolve_processor_adapter` 取代；旧路径保留回归 |
| ROM/RAM | `riscv_boot_memory_{32,64}`，镜像经 `+riscv_boot_image` + `$readmemh`；`LOAD_IMAGE=1` 仅当 policy ∈ {preload, rom} | `riscv_boot_memory.sv:27-35`；`soc_builder._boot_image:1292-1366` | 镜像内容目前是 `build_minimal_boot_image` 的 stub；RAM 未初始化区语义未记录 | 步骤 6B：接 `soc_instruction_stimulus` |
| MMIO | `soc_router` 窗口表 + 每目标适配器；未映射地址走错误响应 | `soc_fabric.py`、`soc_contracts.validate_soc_plan` | 旧路径 `build_spec` 的中断编号（`irq` 从 3 递增）仍是直连；新路径已改为控制器 | 新路径 `soc_interrupt_plan.py`；旧路径保留 |
| 中断 | 旧路径 `soc_irq_router` + 顶层 `irq_claim_i/irq_complete_i` 环境入口；新路径 `soc_irq_controller` 经 MMIO，无环境控制入口 | `soc_irq_router.sv`；`soc_structure_audit.audit_structure` 的 `controller_mmio`/`interrupt_paths` 检查 | **没有任何路径让 CPU 真正执行 ISR**：旧 tb 只驱动 `irq_claim_i/irq_complete_i`，新路径没有运行时 | 步骤 8 |
| 外部/特殊输入 | profile 侧 `drive_strategies` 已声明并校验；`_raw_layout` 已发布 offset/位序/策略与 `layout_hash`；但明确标注 `"static layout only; no random driving is implemented in this phase"` | `soc_composition.py:676-677`；`soc_port_dispositions.py:196-197` | **驱动器不存在**；且旧路径的 raw 段里 `instruction.*` 四个字段没有任何 port 绑定，实际落在 `unmapped_fields` | 步骤 6/6B |
| 随机输入（旧路径） | 224 位 raw：instruction 0–95、mmio 96–191、environment 192–223；tb 从 stdin（FD `0x80000000`）每周期读一个 raw 字后 `assign` 到顶层端口 | `rfuzz_transport.py:27-46`、`soc_builder._testbench:1434-1439` | 运行期投影是**恒等** `SocRawProjector.project`；`run_test` 从不通知投影器“新测试开始”，因此没有 Python 侧状态钩子 | 步骤 6：驱动器放 RTL 侧（与 `fuzz_mmio_master` 同层） |

## 5. 硬编码/型号分支清单

| 位置 | 硬编码内容 | 新路径状态 |
| --- | --- | --- |
| `soc_matrix_smoke.PERIPHERAL_FACTS` / `PERIPHERAL_PROGRAMS` / `PERIPHERAL_RW_TOPICS` / `OBSERVATION_SIGNALS` | 按 `source_lock` 查表的外设事实、程序与观测信号 | 新路径不读这些表 |
| `soc_matrix_smoke.build_spec` | 中断 `irq=3` 起递增；`sink.irq` 直连 CPU；统一/分离由协议名判断；宽度由 xlen 推导 | 新路径改为控制器 + profile 宽度 |
| `soc_matrix_smoke.build_execution` | `axi4`→`axi4_processor_memory_adapter`，否则 `obi_processor_memory_adapter`；`execution_hash` 固定为 `sha256:bbb…` | 新路径按协议表解析并生成真实哈希 |
| `soc_matrix_smoke._build_program` / `PERIPHERAL_PROGRAMS` | 每个 cell 的固定启动程序 | 新路径无程序（步骤 8 生成） |
| `soc_renderer._cell_records` / `_wrapper` / `_cpu_closure` | 按 `source_lock` 找 `soc_{lock}_beat_core.sv` 与 `soc_*_target.sv` 专用包装 | 新路径由 profile 生成包装 |
| `soc_renderer._legacy_document` | 冻结的 P10 Ibex+PULP 文档路径 | 保留 |
| `configs/soc/matrix.json` + `soc_matrix_smoke._matrix_cell_for` | 只认识已登记 cell | 新入口 `scripts/generate_soc.py` 不查矩阵 |

**保留原则**：以上旧路径一行未改，八格回归仍可运行；新链路是加法。

## 6. 本步骤未完成/未验证项

- 未执行 `MYFUZZ_SOC_REAL=1` 的完整八格测试套件（`tests.integration.test_soc_matrix_runtime`），只对 4 个 cell × 3 模式做了等价的直接复现；完整套件留给步骤 10 的最终验收。
- `elaboration_unverified` 的 ibex/cva6 记录未在步骤 1 提升；这需要按锁文件设计补齐 elaboration 证据，不在本步骤范围。
- 运行时投影的恒等性、`reset_dut` 与内存重初始化的差异（`riscv_boot_memory` 在每个复位周期重写内存）已记录为事实，步骤 6B 需要区分 `test_begin` / DUT reset / 驱动器重置。
