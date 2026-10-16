# P6 逐协议行适配清单（可执行）

日期：2026-10-13。上游依据：[总计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md) 的 P6 节（第 313–337 行，含第 329–335 行的五行表）与阶段状态总览（第 163 行）。本文把 P6 的验收句落成**逐行、可执行、可判定的适配清单**，并标明每行当前**已有什么、缺什么**。

> **写作方法：** 本文的"已有/缺失"不是从文档转抄，而是用**实际规划器**（`plan_local_harness` + `load_local_harness_request`）与模板契约注册表（`list_template_contracts()`）逐 profile 实测得出（见 §1、§2）。凡未实测的一律标注"未核实"。

---

## 1. 权威口径（实测）

### 1.1 已注册的 CPU 侧模板契约（`list_template_contracts()`，CPU 侧 6 个／全表 12 个）

| template_id | variant_id | 协议 |
|---|---|---|
| `cpu.obi` | `read-only` / `read-write` | `obi/1` |
| `cpu.axi4` | `single-beat-id` | `axi4/1` |
| `cpu.axi4-lite` | `no-response-code` | `axi4-lite/1` |
| `cpu.wishbone` | `no-err-stall` | `wishbone/classic` |
| `cpu.native-memory` | `completion-no-error` | `ready-valid-memory/1` |
| `cpu.pipelined-memory` | `single-outstanding-completion-edge` | `pipelined-completion-memory/1` |

目标端：`target.tl-ul`（`user-integrity`）、`target.apb3`（`full-word`）、`target.wishbone`（`word-addressed-registered-ack` / `addressless-select-ignored`）。

**（2026-10-13 追加，本行"通用事件"增量）** 目标端契约新增 `target.axi4-lite`（`single-outstanding-error-codes`），故注册表总数由 11 变为 **12**；该条目是**从机侧**契约（驱动 `bresp`/`rresp`），与 CPU 侧 `cpu.axi4-lite`（`no-response-code`）**不是同一条目**。

**口径校正（相对计划五行表）：** 计划写 "PicoRV32 Ready/Valid Memory"，注册表里对应 `cpu.native-memory`（协议名 `ready-valid-memory/1`）；另有第六个 CPU 契约 `cpu.pipelined-memory`（`rvx_core` 用），五行表未列。

### 1.2 每个 CPU profile 声明的协议端点（实测）

| profile | 端点 → 协议 |
|---|---|
| `ibex_obi_local` / `ibex_rvfi_local` / `ibex`※ | `processor.instruction` + `processor.data` → `obi/1`；`processor.interrupts` |
| `cv32e20` / `cv32e20_rv32e` / `cv32e40p` / `cv32e40p_mtimer` | 同上（双 OBI + 中断） |
| `cva6` | `processor.memory.unified` → `axi4/1`；`processor.interrupts` |
| `zipaxi` | `processor.memory.insn` + `processor.memory.data` → `axi4/1` |
| `picorv32_axi` | `processor.memory` → `axi4-lite/1` |
| `picorv32_wb` | `processor.memory` → `wishbone/classic`（**无中断端点**） |
| `picorv32_wb_irq` | `processor.memory` → `wishbone/classic` + `processor.interrupts` |
| `picorv32` | `processor.memory` → `ready-valid-memory/1` |
| `rvx_core` | `processor.memory` → `pipelined-completion-memory/1` |
| `boom` | **无 profile**（本地缺 Chipyard checkout 与 Java/SBT/Mill） |

※ `ibex`（无后缀）实测被拒 `full-top-required`；可规划的是 `ibex_obi_local`／`ibex_rvfi_local`。同理目标端基础 profile（`opentitan_gpio`、`opentitan_uart` 等）被拒，可规划的是各自的 `_local` 变体。

### 1.3 可规划的目标端 profile（实测）

**可规划：** `opentitan_gpio_local`、`opentitan_i2c_local`、`opentitan_pattgen_local`、`opentitan_rv_timer_local`、`opentitan_spi_device_local`、`opentitan_spi_host_local`、`opentitan_uart_local`、`opentitan_uart_fifo_local`、`pulp_gpio`、`pulp_gpio_causal_local`、`pulp_i2c`、`pulp_spi`、`pulp_timer`、`zipcpu_axiluart`、`zipcpu_timer`、`zipcpu_uart`。

**被拒（含原因，均为规划期 fail-closed）：** `opentitan_sysrst_ctrl_local`（`local-clock-schedule-unsupported:reset_edge_not_…`）、基础 profile 各自因 `full-top-required`／`peripheral-profile-requires-address`／`unsupported-endpoint-function`／`odd_ratio` 被拒。

---

### 1.4 CPU 适配目标与协议对应（权威口径）

本节是**目标口径**（要适配哪些 CPU、各自对应什么协议），由项目方给定；它是 §2 五行分行的**上游依据**。
下表逐行核对**仓库现状**，并区分"有 profile 可规划"与"无本地源／无 profile 故 `skipped_unavailable`"。

| CPU / IP | 对应协议 | 仓库现状（实测） |
|---|---|---|
| Ibex | OBI 指令 / 数据 | **可规划**：`ibex_obi_local`／`ibex_rvfi_local`，双 OBI ＋ 中断端点（无后缀 `ibex` 被拒 `full-top-required`） |
| CVA6 | 打包 64 位 AXI4 单主端口 | **可规划**：`cva6`，`processor.memory.unified → axi4/1` ＋ 中断端点；已有 compiler-proven packed AXI4 边界 |
| CV32E40P | 分离 OBI 指令 / 数据 | **可规划**：`cv32e20`／`cv32e20_rv32e`／`cv32e40p`／`cv32e40p_mtimer`，双 OBI ＋ 中断端点 |
| BOOM | TileLink 1.0 指令 / 数据端点 | **`skipped_unavailable`**：`configs/cpus/boom/interface_description.json` 声明 `tilelink/1` 指令＋数据端点，但其 README 明写该目录是**参考用语义描述**（`sha256:` 占位全零，需先由 Chipyard 生成并回填）；仓库**无 `component_profile.json`**，故实测规划以 `FileNotFoundError` 失败。本地亦无 Chipyard checkout 与 Java/SBT/Mill |
| CVW（CORE-V Wally） | AHB-Lite 外部总线（EBU） | **已达会话级可执行（2026-10-14 实测）**，但**不升级为「已通过」**：生成的 CVW harness 启动真实核心，核心从**会话的内存服务**取回完整连续的 64 字节启动行，并**执行了会话供应的程序**——程序里 `lui/addi/lw` 计算出的地址 `0xC0000100` 出现在被接受的请求里（`test_the_session_boots_the_core_and_the_core_executes_the_supplied_program`，8 passed）。三个缺陷依次定位并修复：① 生成物把从属端的**低有效** `rst_ni` 直接接 harness 的**高有效** `reset`（核心跑、从属端一直复位；修法与 obi/axi4-lite/native 同族约定一致）；② 我最初「接受 beat 再扣住响应」的 hold **无效**（接受即拉高 `HREADYEXT`，交易已完成），改为**扣住 `req_ready`**；③ 从属端在 `COMPLETE` 丢掉 AHB 流水的下一拍地址相位 → 突发**每隔一拍丢一个**（地址步进 8 而非 4，取回的行错位）。P7：`cvw-ahb-pulp-gpio` 家族已注册，`--runtime` 实跑 D1→D4 ＋ capability report 全 ok，`compiled_paths {executable:4, unsupported:2}`；会话阶段**如实停在** `cvw-online-assembly-undeclared`（缺 `boot_image`／`online_decoder`／`runner_factory`），**未伪造会话**。**仍未做**：RFuzz 在线 campaign（缺上述三项）、F5 中断消费者、F6 DMA 提供者。分级：**Cross-component accepted（真实会话级交易）**，未到 Coverage-guided searched。 |
| VexiiRiscv | TileLink 内存总线 | **`skipped_unavailable`**：同上，仓库无任何资产 |
| OpenTitan 外设（8 类） | TL-UL | 见 §1.3（可规划者 7 个 `_local` 变体等） |
| PULP 外设（4 类） | APB3 | 见 §1.3 |
| ZipCPU 外设 | Wishbone · AXI4-Lite | 见 §1.3（`zipcpu_uart`／`zipcpu_timer`／`zipcpu_axiluart`） |
| PicoRV32 / RVX 内存目标 | 原生完成式 · AXI4-Lite | `picorv32`（`ready-valid-memory/1`）／`rvx_core`（`pipelined-completion-memory/1`）／`picorv32_axi`（`axi4-lite/1`） |

**协议能力与目标的差距（必须写清，不得用别的协议抵消）：**

- **TileLink 1.0 的 CPU 侧契约已于 2026-10-13 补齐**：依据 BOOM 的真实声明新增 `cpu.tilelink` 的两个 variant（`declared-four-role` 对应 `cpu.instruction_memory` 的 4 个角色；`declared-five-role-write-capable` 对应 `cpu.data_memory` 的 5 个角色，多一个 `write_data`），并新增协议插件 `src/myfuzz/protocols/plugins/tilelink.json`；`list_template_contracts()` 由 12 变为 **14**（CPU 侧 9＋target 侧 5）。**仍未做**：完整 TileLink-1.0 的 A/B/C/D/E 五通道契约（插件标注 `x-channel-mapping='not-declared'`）与 TileLink RTL adapter（`legal_adapters=[]` 是有意的）。
- **AHB-Lite（EBU）已从"无声明可对齐"推进到"契约已立且顶层可 elaborate"**：已取得 **CVW 真实源码**（`third_party/cvw_upstream_reference`，顶层 commit `2f2ddfd`，tag `CVW_v0.9` 可钉定），`src/wally/wallypipelinedsoc.sv` 给出逐字 AHB-Lite CPU 边界：输出 `HCLK`/`HRESETn`/`HADDR`/`HWDATA`/`HWSTRB`/`HWRITE`/`HSIZE`/`HBURST`/`HPROT`/`HTRANS`/`HMASTLOCK`/`HREADY`/`HSELEXT`，输入 `HRDATAEXT`/`HREADYEXT`/`HRESPEXT`。**两个必须记住的真实形态事实**：① 读数据在 CPU 边界叫 **`HRDATAEXT`**（不是 `HRDATA`）；② `src/ebu/ebu.sv` **故意不含 `HRDATA`**，第 125 行注释明写 "HRDATA is sent to all controllers at the core level"，故 `ebu` 不是完整 CPU 边界；`HSELEXT` 是 CVW 的片选扩展、非标准 AHB-Lite 信号。**真实宽度**（读自 CVW 自身 header，rv32imc 配置）：`XLEN=32`、`AHBW=XLEN=32`、**`PA_BITS=34`**（`config/shared/config-shared.vh:18`），故 **`HADDR` 是 34 位、比数据端口宽**——把地址宽度钉成数据宽度会拒绝真实边界。CVW 是 SystemVerilog，**Verilator 可直接吃、不需要 JVM**；**顶层 elaboration 已实测通过**（`verilator --lint-only --top-module wallywrapper`，226 个 `.sv`，退出码 0），且该检查配有"删掉 `ebu.sv` 必须失败"的守卫（RED 已实测）。**2026-10-13 更新**：`configs/cpus/cvw/component_profile.json` 已落盘并由**真实 Verilator elaboration** 提取端口事实（18 端口、`HADDR`=34），**P7-A 通过（`ok cvw 9/9`，supervisor 可用/不可用两条路径结论一致）**；CPU 侧 adapter `src/myfuzz/protocols/rtl/beat_to_ahb_lite.sv` 已实现并带真实时序仿真与变异守卫，运行期渲染器也已有 `ahb_lite_cpu` 分支且形状与提取事实逐字段一致。**不入 source lock（2026-10-13 裁定）**：本仓 local profile（`ibex_rvfi_local`／`opentitan_*_local`）的官方约定是 `root:"."` ＋ sha256 pin 且**不登记 lock 记录**，CVW 遵循同一约定——实测移除该记录后 `verify_soc_sources.py` **恢复 29/29 全通**，保留则唯一失败项就是它。**仍缺**：adapter 未接进任何 profile、未跑任何真实 AHB 交易，故 CVW 行**仍登记 `skipped_unavailable`**——**通过 P7-A 与能 elaborate 都不等于可执行**。另需注意：仓库里的 `target.tl-ul` 是 **TileLink-UL 目标（外设）**契约，与 BOOM／VexiiRiscv 的 **TileLink 1.0 CPU 端点**不是同一条目。
- **2026-10-14 增量：AHB 从属端已按 CVW 的真实主从方向重写，且上游阻断点已定位。**三件事必须一起读，否则会高估本行：
  ① **方向曾经写反**。原 adapter `src/myfuzz/protocols/rtl/beat_to_ahb_lite.sv` 把 harness 当成 AHB **主设备**去驱动 `HTRANS/HADDR`，而 CVW 才是主设备——这样永远不可能从 CPU 产生交易。已改为从属端 `src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv`（消费 CPU 的 address/data phase、以 `HREADYEXT` 完成交易），并配有自检 testbench `tests/integration/rtl/ahb_lite_memory_target_tb.sv`（4 组：IDLE 不是交易、读的相位与完成、写在地址相位后一拍才采 `HWDATA/HWSTRB`、无人应答的交易被**保持**而不是伪造完成）。**首版从属端有真实死锁**：`req_valid_o` 曾在"需要 `HREADYEXT` 为低"的状态里才拉起，而 `HREADYEXT` 变低恰恰要等该请求被受理——自环死锁，实测 `transactions=0`；修为"地址相位被接受后一拍、写数据相位已锁存时才拉起请求"，testbench 由 FAIL(8) 转 **PASS**，`verilator --Wall` **0 warning**。
  ② **上游阻断点（新证据）**：把真实 CVW 接上从属端后，CPU 确实在驱动 `HTRANS=10/11 @ 0x8000_0000`，但 **`HSELEXT` 每一个周期都是 0**，故请求永不产生。根因不是本仓：`src/mmu/adrdec.sv` 的 `Sel = Match & Supported & AccessValid & SizeValid`，而 **CVW 六个已提交配置（rv32e/rv32gc/rv32i/rv32imc/rv64gc/rv64i）的 `EXT_MEM_SUPPORTED` 全部为 0**；且 `EXT_MEM_BASE == UNCORE_RAM_BASE == 0x80000000`，naive 打开会让两个区间同时选中同一地址（`uncore.sv` 再把两路响应合并到一条总线）。CVW 自己也知道：`testbench/testbench.sv:545` 仅在 `P.EXT_MEM_SUPPORTED` 时实例化 AHB RAM，否则 `assign HREADYEXT = 1'b1;`。
  ③ **派生配置已落盘并钉定**：`scripts/derive_cvw_config.py` 从被钉定的上游 `config/rv32gc/config.vh` 派生 `configs/cpus/cvw/config_extmem/config.vh`，**只改三行**（`EXT_MEM_SUPPORTED 0→1`、`EXT_MEM_BASE 0x80000000→0xC0000000`、`EXT_MEM_RANGE 0x07FFFFFF→0x0FFFFFFF`），并在生成时断言新区间与派生配置启用的**每一个**区间都不相交、且落在 `PA_BITS=34` 内（当前实测：与 BOOTROM/CLINT/PLIC/GPIO/UART/SPI/PWM/UNCORE_RAM 均无交集）。`config_extmem` 已排在 profile `include_roots` **首位**（`#include "config.vh"` 必须命中它而非上游同名文件），实测 elaboration 确实读的是派生文件（`EXT_MEM_SUPPORTED=1`、`EXT_MEM_BASE=0xC0000000`、`PA_BITS=34`）。profile 内容 pin 已按**243 文件读集**重算（原 242），closure 已登记该文件，`cvw_contract.py` 新增第四条钉定常量 `_CONFIG_SHA256` 并**同时**做语义断言（`EXT_MEM_SUPPORTED` 必须仍为 1、base 必须仍是 `0xC0000000`、必须仍有 `DERIVED FILE` 头）——两道守卫都已 RED 实测：改字节 → `content-hash-mismatch`；把常量改成"匹配坏字节" → `cvw-config-external-memory-disabled`。
  **④ 2026-10-14 稍后：真实交易已实测达成，四个障碍逐个定位并留了 RED 守卫。** 前三次 probe 都测到 0 笔，各自的原因都不同、且都在 probe 自己身上，值得记下来：**(a)** 核心的 uncore RAM 是 `PRELOAD=0` 且不做 `$readmemh`，内容是 0，所以核心一直在**执行 0**（取十几拍就停）；**(b)** 我按裸地址或单一掩码切片索引 memory 模型，把 `0xC000_0000` **别名**到 `0x8000_0000`（"跳到外部"落回原处）；**(c)** 换成 `(addr - RESET_PC)` 索引 64 MB 数组后，外部队列落到索引 `0x4000_0000`，**越界**返回 `x` 并把核心卡死。最终版本按区分区索引、并把 boot 程序用层次化 poke 放进核心 RAM（`cpu.dut.uncoregen.uncore.ram.ram.memory.ram.RAM`，因为上游 `PRELOAD=0`，不改上游 RTL 就只有这一条路）。
  实测结果：**`CVW_AHB_REAL_TRANSACTION_TB: PASS (external=6 first=0c0000000)`** —— `HSELEXT` 真的选通、`HREADYEXT` 先低后高完成传输、从属端 beat 面看到 `0xC0000000` 的请求、服务返回的字**正是 CPU 随后据以跳转的那条指令**。固化为 `tests/integration/rtl/cvw_ahb_real_transaction_tb.sv` ＋ `tests/integration/test_cvw_ahb_real_transaction.py`，并配**两条 RED 守卫**（各自实测失败）：去掉派生配置 → 无交易；去掉 boot 预载 → 无交易，证明这条 PASS 确实在测量派生配置与真实程序。
  **⑤ 2026-10-14 再进一步：服务自己启动核心（零 poke）。** 派生脚本现在**也**派生 `RESET_VECTOR`（上游 `0x80000000` → `0xC0000000`，即外部区基址），生成期断言"reset vector 必须在**已启用**区间内、且必须是 `EXT_MEM`"（否则 uncore RAM 会应答启动取指）。`component_profile.json` 的 `cpu.reset_vector` 同步为 `0xC0000000`。
  实测 `CVW_AHB_BOOT_FROM_SERVICE_TB: PASS (first=0c0000000 served=6 boot_fetches=21)`：新 bench `tests/integration/rtl/cvw_ahb_boot_from_service_tb.sv` **不含任何 poke**，核心的**第一次取指**就是 AHB-Lite 传输、地址正是 reset vector，而它执行的程序**只存在于服务的内存里**——这正是本仓其它 CPU 的启动方式。
  **过时守卫已换掉（避免假证据）**：上一轮那条"去掉预载 → 无交易"在 reset vector 移走后变成假命题（实测去掉 poke 仍 PASS），故**未**改成"仍然失败"凑绿，而是换成更锐利的 `test_the_program_the_core_executes_comes_from_the_service`（去掉 poke 后必须**仍然 PASS**，证明程序来自服务而非核心 RAM），另加 reset vector 的真 RED。`tests/integration/test_cvw_ahb_real_transaction.py` 现 **5 passed**（3 GREEN ＋ 2 RED）。
  **⑥ 2026-10-14：P7 D1→D4 全绿，F1–F4 由 0 变 executable（补上"统一主设备"这一类）。** P7-E 入口实跑 CVW 组合（新增 `configs/scenarios/cvw-pulp-gpio/`）：`status: complete, exit 0`，阶段 `declaration_review / harness_set(generated) / path_compilation / capability_report` 全 ok，`compiled_paths.v1.json` → **`{executable: 4, unsupported: 2}`**（F1:ram.image、F2、F3、F4 executable；F5 `interrupt-consumer-missing`、F6 `dma-master-not-declared`，都是真实缺失）。
  根因与修法：D3 起初以 `cpu-instruction-master-ambiguous` 拒绝——**CVW 的 AHB 外部总线是统一的**（EBU 把 IFU 与 LSU 仲裁到同一条总线），写成 `data_memory_master` 等于宣称"这颗核没有取指通路"。故 ① 声明正名为 `memory_master`（picorv32 单一口同词汇）；② `auto_harness_test.instruction_master()` 与 ③ `compiled_paths._cpu_master()` 在"profile 只有唯一端点"时接受统一主设备，多主设备仍拒绝；④ `/cpu/{data,instruction}_endpoint` 指针校验与渲染器 AHB 分支同步。
  **一条教训（记录在案）**：第一次只改了指针校验，命令返回 `status: complete` 但**六条流全 unsupported**——**"退出码 0"不等于"路径可执行"**，必须逐条读 `compiled_paths.v1.json` 才发现真正的阻塞点在 flow 级 `_cpu_master`。
  守卫：新增 `tests/integration/test_cvw_unified_master.py`（5 passed），其中 2 条经 RED 实测（禁用回落 → 2 failed）；回归 `test_p7b_to_p7c_chain.py ＋ test_auto_harness_test.py ＋ test_compiled_paths.py` 共 **71 passed**。
  **⑦ 2026-10-14：补上 AHB-Lite 会话类（boot 保持）。** 此前 `_OPERATIONS` 已登记 `ahb_lite_cpu` 的 `STEP_MEMORY`、driver 也早已发同形 beat，但**没有 session 类承认该 kind**——D4 报绿而仓里无法启动该 CPU。新增 `src/myfuzz/local_harness/ahb_lite_session.py`（`GeneratedAhbMemorySession`）：复用 native completion 面握手／预算／观测，改 `artifact_kind`、`read_request_be=15`（CVW 读断言全道；AXI4-Lite 是 0）与 **boot 保持**。boot 保持的必要性：CVW 在 reset 释放瞬间从 reset vector（现位于外部队列）取指，服务看到的**第一个请求**就可能是「程序还没到」的取指；拒绝是错的、填零更糟（核心会执行），只能**保持**——把地址**声明为指令槽**使其抛 `InstructionNotReady`，服务不吐 `rsp_valid`，从属端靠 `HREADYEXT` 拉低延长传输、不伪造错误完成；会话填入字节后恢复。**槽必须在取指到来前声明**（否则按未初始化 RAM 读出**静默 0**），故启动地址取自 artifact 自身的 `boot_contract.configured_boot_base`，在构造／`reset_local`／`begin_case` 幂等声明。验证 `tests/local_harness/test_ahb_lite_session.py` **6 passed**，其中 boot 保持一条经 **RED 实测**（去掉槽声明 → FAIL，返回静默 0）；会话注册与同族回归 **36 passed / 1 skipped**。
  **仍未达成「可执行会话」**：上述证据来自**测试台**（boot 程序靠层次化 poke），不是生成的 harness 在跑；生成物能构建、能与真实 CVW 一起 elaborate，但**还没有一次会话级运行**。故 CVW 行**继续登记 `skipped_unavailable`**，分级停在「RTL operational（边界交易）」，未到「Cross-component accepted」；「配置已开启」「从属端模型正确」「elaboration 通过」「边界有交易」四者**都不得**冒充会话级可执行。
- **TileLink 有意不进运行期各层（2026-10-13 决定，记此以免被读成漏做）**：`scenario/ip_base_coverage.py` 的 `_PROTOCOLS`、`scenario/ip_protocol_checker.py` 的 `_REQUIRED_SIGNALS`、`integration/campaign_report.py` 的 `_KNOWN_PROTOCOLS` 都是"协议 id → **运行期真实信号名**"的闭集。而 TileLink 插件自己声明 `x-channel-mapping='not-declared'`、`x-role-vocabulary='abstract-roles-only'`、`legal_adapters=[]`，仓库里也**没有** TileLink adapter／`component_profile.json`／真实 trace 源。即：**运行期不会有任何 TileLink trace 产生**，因此往这三个闭集里加 `tilelink` 只能靠**凭空发明** A/B/C/D/E 信号名，这正是本仓库"不按名字分支、不编造"所禁止的。**结论：不添加**；待真实 Chipyard 生成的 TileLink 端点与 adapter 到位、确有 trace 可校时再补，届时以被钉定 RTL 的真实端口名为准。
- 因此 **BOOM、CVW、VexiiRiscv 三行按 `skipped_unavailable` 登记**：前者的阻断是"缺 Chipyard 生成与真实 profile"，后两者的阻断是"缺源码与配置"。**不得**用静态扫描结果、也不得用另一协议的 CPU 冒充这三行的证据（§1 的"技能分级"同样禁止一级推出下一级）。
- 六行中**当前可执行的是三行**：Ibex、CVA6、CV32E40P；其协议（OBI／打包 AXI4）均已有 CPU 侧契约与真实 RTL 验收路径。

## 2. 五行的真实状态（逐行）

判据来自计划第 337 行：**每行须先分别通过取指/数据访存/字节使能的本地协议验收，再证明至少一条 CPU→IP 和一条 IP→CPU 真实传播路径；需要 ISR 的组合另证明真实 IRQ→CPU handler。只有达到第一步相同的逐例输入、交互反馈、断言和前缀 replay 门槛，才能在"第二步完整框架复用"列标通过。**

### 行 1：OBI ｜ 首选 CPU：Ibex、CV32E40P ｜ 首选 IP：PULP APB3 GPIO、OpenTitan TL-UL UART/Timer

| 项 | 状态 |
|---|---|
| Ibex（OBI）本地协议验收 | **已有**（取指、Store/Load、byte-enable 均有真实 RTL 证据） |
| Ibex 的 CPU→IP 与 IP→CPU 真实路径 | **已有**（双 PULP GPIO 双向、OpenTitan UART/GPIO/I2C/Timer 多条） |
| Ibex 达到第一步**完整框架**门槛 | **已有**（P1–P5 按声明范围验收；本轮另产出寄存器复位默认值证书） |
| CV32E40P（分离 OBI）本地协议 | **已有** |
| CV32E40P 的跨组件路径 | **已有定向**（→OpenTitan GPIO A→B→RAM、UART RX watermark、RV Timer MTI、SPI Host/Device MEI、I2C MEI） |
| **CV32E40P 复用第一步逐例双侧搜索** | **已闭合（2026-10-13，真实重跑）** —— 见下方"本行结论"；证据为 `runs/cv32e40p-pulp-online-20261014`（未压缩 trace）与 `runs/cv32e40p-pulp-online-20261014b`（压缩 trace），两者均为**当前源码身份**上产出的新鲜会话 |
| **CV32E40P 的多例持续会话产物（2026-10-13 审计）** | **已有产物，已独立审计** —— `runs/cv32e40p-pulp-online-20261007/` 是一次真实的多例在线运行：**133 个唯一用例全部 `complete`**、**双向都有**（`IP_TO_CPU_TO_IP` 75／`CPU_TO_IP_TO_CPU` 58）、单一 runner/checker 会话、**6 次 mutation-hint 更新**、`contract_preflight` 通过、192,020 条事件与 trace 元数据计数一致。新增审计测试 `tests/integration/test_cv32e40p_pulp_online_saved_run_audit.py`（**9 项**）**逐项从 plan/receipts/事件重算并与 report 交叉核对**，不从摘要转抄 |
| **该产物的 fresh replay 现状（必须如实记录）** | **当前树上不可 replay** —— `scripts/run_cv32e40p_pulp_online.py replay` 实跑被**设计性拒绝**：`online decode space source identity mismatch`，实测 **12 个 decode_space 源中 4 个已漂移**（`rv32i_sources.py`／`ibex_pulp_dual_source.py`／`session_runtime.py`／`source_actions.py`），另有 **37 个 source_files 中 8 个漂移**。**根因**：该 bundle 记录的是 **10-07** 的源码身份，其后源码合法演进（其中 `session_runtime.py` 现为冻结身份 `d49ea5cf…`）。**replay 本身不需要客户端二进制**（只要 `--cache-dir/--plan/--trace`），故"缺客户端"从来不是这条 replay 的阻断。**2026-10-13 更正：** 此前同格写的"在线客户端无法构建（`CARGO_EXIT=101`）"**已被实测推翻**——预构建二进制一直在 `third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz`，且能与真实 RTL 完成往返（22 秒内 `tests=10240`、`status=completed`、`4671.8 runs/s`、`actual_rtl_execution` 为真）；`CARGO_EXIT=101` 只是**试图重建**时的 rustup 工具链问题。因此要闭合本行应在**当前身份**上**重跑一次在线会话**（此路已通，需真实 RTL 预算与单 worker），而不是继续记作"客户端不可用" |
| **本行结论** | **本行计划要求的门槛已达成（2026-10-13 更新，真实 RTL 重跑）** —— 原缺口是"CV32E40P 只有定向单场景证据，且其多例产物在当前源码身份上不可 fresh replay"。现已在**当前源码身份**上重跑出新鲜多例持续会话并完成 fresh replay：**唯一用例 13、方向双向（`IP_TO_CPU_TO_IP` 104／`CPU_TO_IP_TO_CPU` 96）、`flow_id` F5 104／F4 96、反馈交换 13、`mutation_hint_updates` 14、`violations` 0、`statuses={"complete": 200}`**，`replay` 实测 **`matches: true`／`first_difference: null`／退出码 0**。证据目录 `runs/cv32e40p-pulp-online-20261014` 与 `…-20261014b`（后者为压缩 trace）。**独立复核方式**：`tests/integration/test_cv32e40p_pulp_online_saved_run_audit.py` 已参数化（`MYFUZZ_CV32E40P_AUDIT_RUN`），**同一套逐项复算**对 10-07 基线（9 passed, 1 skipped）、新未压缩（10 passed）、新压缩（9 passed, 1 skipped）三份 bundle 均通过；该审计**从 plan/receipts/事件重算**并与 report 交叉核对，且把"漂移测量"与"真实 replay 裁决"互相验证。**同时更正两条此前的错误登记**：①"在线客户端不可构建故无 fresh run"**不成立**——预构建 `kfuzz` 一直存在且能与真实 RTL 往返（本机不可的是**从源码重建**）；②该行 replay 的真实阻断从来是**源码身份漂移**，与客户端无关。**未声称**：不声称 CV32E40P 已具备 RVFI retirement 或 native IRQ receipts 观测（`--cpu-retirement` 被设计性拒绝）；不声称本轮产物达到了 P2 之外的性能门槛（本轮 `elapsed≈19.2s`）；本行"通过"仅指本清单为该行列出的要求，不构成对其它行或整个系统的结论 |

### 行 2：完整 AXI4 ｜ 首选 CPU：CVA6 ｜ 首选 IP：OpenTitan TL-UL GPIO/SPI Host、PULP APB3 I2C

| 项 | 状态 |
|---|---|
| CVA6 本地 AXI4（打包 64 位/ID4 单主端口） | **已有**（232 文件读取闭包通过 elaboration 与源码锁；真实取指、Store→Load→Store） |
| CVA6→IP 真实 MMIO 路由 | **已有**（DataflowRouter 路由至真实 OpenTitan GPIO TL-UL 与 PULP I2C APB3） |
| CVA6 的 IP→CPU 路径 | **已有**（SPI Host RXDATA 读回写 RAM；GPIO/I2C M_EXT ISR 读真实状态写 RAM） |
| CVA6 真实 IRQ→handler | **已有**（M_TIMER ISR、GPIO M_EXT、PULP I2C 双 M_EXT） |
| **CVA6 复用第一步逐例双侧搜索** | **已有（2026-10-15 真实 RTL 18 格战役，附明确边界）** —— `runs/scenario/campaign-cva6-g4-18cell-p6-row2-20261014-v2`：3 策略 × 2 方向 × 3 种子共 **18 格全部 `complete`**、`gate_failures` 全空、`gate_status: complete`、**`effective_search_seconds 1410.10`**（要求 1080）、`campaign_source_identity_stable: true`、输入原文件与快照均稳定、18 个逐格 `live/run_identity.json` 全部 `validated_envelope`，共 **1170 例**（bound 648＋independent 522）。逐格为真实 CVA6 ＋ 双 OpenTitan TL-UL GPIO RTL（每例 `cpu`/`gpio_a`/`gpio_b` 的 `local_ticks` 均 > 0、单格单一 `manifest_sha256`）：`CPU_TO_IP_TO_CPU` 两源 `cpu.program`/`cpu.isr`、`IP_TO_CPU_TO_IP` 两源 `b.pin8`/`b.pin9`，且**每个种子**都真的驱动了两侧源；反馈驱动变异每格 5–7 个种子后变异批次、2–10 个种子后有效基因型；独立 checker 每格 20–43 条两轮闭环（其中 14–41 条落在种子后变异体上）；完整前缀 replay 每格 `matched_entries == total_entries ==` 语料条目数、`error: null`。**边界（不得略去）**：① `execution_mode=fresh_genomes`——**每例新建 RTL harness，无跨例持久 DUT 状态**；若「多例持续会话」须为单一 harness 跨例（行 1 的 `online_cases` 那样），本行**仍未满足**；② `runtime_path_status=legacy_unchecked`，**不含** `RuntimePathContract` 逐边来源；③ `closed_loop_energy`／`path_switch` 均 `disabled`，故提供的是 mutation-hint 反馈通道，**不含** `stage_hits`/`edge_hits`/`state_transition_hits`/`closed_loop_hits` 四类命名命中；④ 仅覆盖 OpenTitan GPIO，未含 SPI Host／PULP I2C；⑤ 不含受控错误负例。独立复核 `tests/integration/test_cva6_campaign_saved_run_audit.py`（**10 项，从 receipts／chain_checks／mutation_selections／corpus 逐项复算并与 report 交叉核对**，可经 `MYFUZZ_CVA6_CAMPAIGN_RUN` 审计其它 bundle；10 项守卫各自经 tamper RED 实测） |
| **本行结论（2026-10-15 更新，附未声称项）** | **本清单为该行列出的缺口已闭合，但不升级为整行「通过」** —— 原缺口「同行为定向场景，无多例持续会话＋反馈驱动变异＋完整前缀 replay」中，**反馈驱动变异**与**完整前缀 replay** 已由上述真实 18 格战役闭合；**「多例持续会话」按 fresh-harness 口径成立，按持久 harness 口径不成立**（`execution_mode=fresh_genomes`）。本地验收、双向路径与真实 ISR 此前已记「已有」。另修掉一个**来源身份被外来 fixture 冒充**的 provider 缺陷：`Cva6TwoGpioBoundProvider._fixture` 在 reverse 方向忽略传入 manifest（它加载同目录兄弟 genome），会**静默接受 Ibex/OBI 的 manifest** 并以**外来来源身份**保存 reverse cell——正是「不得用另一协议的 CPU 抵消」这条规则在机制上的对应物；修法 `_require_pinned_bound_seed`（`scenario_campaign.py`）＋ cva6 provider 接上，两个方向对两个 provider 都拒绝外来 seed、被钉定 seed 仍可加载，RED→GREEN 实测。**未声称**：① 跨例持久 RTL 状态；② `RuntimePathContract` 逐边来源；③ 四类命名命中族；④ 受控错误负例（P6「非 Ibex＋非 GPIO」仍未做）；⑤ SPI Host／PULP I2C。**仍未做**：行 3、行 4、TileLink 1.0 完整五通道、BOOM/VexiiRiscv（本地无 JVM／无源码）、CVW 在线 campaign 三缺件。 |

### 行 3：AXI4-Lite ｜ 首选 CPU：PicoRV32 AXI4-Lite ｜ 首选 IP：ZipCPU AXI4-Lite UART

| 项 | 状态 |
|---|---|
| PicoRV32 AXI4-Lite 本地（RAM/ROM） | **已有**（真实 AW/W/B/AR/R 引脚经本地 adapter；两轮 Store/Load、持久 RAM、fresh replay） |
| `picorv32_axi` 的 CPU 侧 adapter（Root 实测） | **已生成** `axi4_lite_processor_memory_adapter`（由 `render_local_runtime` 的 runtime source 实测其 adapter 模块名；其 capabilities 恰为该分支要求的 `(32,32,True,False,1)`） |
| `zipcpu_axiluart`（**真实 AXI4-Lite IP**） | **profile 可规划**（实测 OK），端点 `uart.bus`＝`axi4-lite/1`、16 字节窗口、含 `uart.interrupts`(interrupt_source) 与 `uart.pins`(external_pins)；已有独立 RTL operational 证据（TX 解码 `0x41`、RX 返回 `0x5a`）；其 session `GeneratedAxiLiteUartSession` **已带 `cpu_routed_mode`**（目标侧就绪） |
| **CPU→AXI4-Lite→真实 IP 的端到端组合** | **已有（2026-10-15 真实 18 格 campaign）** —— 见「本行结论」：18/18 格 complete、逐格真实 RTL、25 条 chain check、语料增长、双侧源都被消费。（此前的「表述已过时」记录保留在案：`test_axil_cpu_generic_ip_chain_real.py` 虽然用的是这一对 profile，但它的 `chain()` **只 build 两个 harness、从不 start CPU 进程**，驱动来自测试直接调用 `_service_accepted_request`，故它证明的是「CPU 侧会话的路由把 beat 交付给真实 IP」，**不是**「真实 CPU 进程产生的事务抵达真实 IP」——后者由本次 campaign 的真实执行提供。） |
| **能力表第 64 行标题为误标（Root 实测纠正）** | 运行能力表 "CVE2 ↔ ZipCPU axiluart ↔ CVE2 RAM" 写 "CPU 真实 AXI4-Lite"，但**实测 `cv32e20` 走的是 `obi_processor_memory_adapter`**（其 capabilities `error_response=true` 不满足 `axi4_lite_cpu` 分支要求的 `(32,32,True,False,1)`）。该组合 CPU 侧是 **OBI**、IP 侧真为 AXI4-Lite，二者由**事务级 DataflowRouter**（`DeviceWindow`）相连——是真实且已验收的链，但**不是** AXI4-Lite CPU 证据 |
| **CPU 侧 session 的 MMIO 路由能力** | **✅ 已补齐（2026-10-13 首增量，软件层）** —— `GeneratedAxiLiteMemorySession` 现接受可选 `router: DataflowRouter \| None`：落在 `router.owns()` 窗口内的 beat 经 `router.transact` 交付真实目标（按 32 位 word beat `address & ~3` 寻址），窗口外仍走 RAM；`router=None` 时行为与改动前逐字节相同。实现方式为在父类 `GeneratedNativeMemorySession` 抽出**单一可覆盖钩子** `_service_accepted_request(...)`（**15 增／4 删**），而非在子类重写整个 `step_local`。RED＝`TypeError: … unexpected keyword argument 'router'`（2 failed）→ GREEN 8 passed；定向回归 7 文件 **24 passed＋18 subtests**。改动：`native_session.py 9b9447e8…`、`axi_lite_session.py 8c6cb867…`、新测试 `test_axi_lite_mmio_routing.py 06101d03…`。**明确未做：** 未实现 `defer_mmio` 延迟路径（本轮采同步 `transact`，`max_mmio_target_accesses_per_step=1`）；未接线到真实 IP；未把路由状态写入身份（既有身份是严格闭集，`memory_policy='ram-rom-only'` 与"可路由"的语义需另行设计） |
| **CPU→AXI4-Lite→真实 IP 的端到端组合** | **仍缺**（首增量只闭合了 CPU 侧会话能力） —— 需把 `zipcpu_axiluart` 的 `cpu_routed_mode` 真正接到该 router。**并须先裁定采用哪条路径**：既有的 CVE2↔axiluart 链是经**路由器抽象**（`RegisterTarget`）交付的，而"AXI4-Lite CPU master 直连 AXI4-Lite IP slave"是**另一条路径**（harness 级信号接线），两者接线方式不同，选择须说明理由 |
| **能力表第 64 行标题为误标（Root 实测纠正）** | 运行能力表 "CVE2 ↔ ZipCPU axiluart ↔ CVE2 RAM" 写 "CPU 真实 AXI4-Lite"，但**实测 `cv32e20` 走的是 `obi_processor_memory_adapter`**（其 capabilities `error_response=true` 不满足 `axi4_lite_cpu` 分支要求的 `(32,32,True,False,1)`）。该组合 CPU 侧是 **OBI**、IP 侧真为 AXI4-Lite，二者由**事务级 DataflowRouter**（`DeviceWindow`）相连——是真实且已验收的链，但**不是** AXI4-Lite CPU 证据 |
| 备选 CPU：`zipaxi`（双 AXI4 + 数据/指令分离） | profile 可规划，实测 OK；但其**无 `processor.interrupts` 端点** → ISR 路径需另解 |
| **本行结论（2026-10-15 更新）** | **本行计划要求的门槛已达成** —— 缺口「端到端接线、真实 IP 交付与持续会话」已由一次**真实 18 格 campaign** 闭合：`runs/scenario/campaign-axil-g4-18cell-p6-row3-20261015-v6` → **`gate_status: complete`、`gate: G4`、18/18 格 complete、`gate_failures` 全空**、`effective_search_seconds 2084.8`、`campaign_source_identity_stable: true`。逐格为真实 RTL：`testcases 25`、**`chain_checks.jsonl` 25 行**（此前为 0）、**`corpus` 3 条**（seed ＋ 2 条新生，语料真的在长）、`completed_chains 25`（其中 **22 条落在种子后变异体上**）、`replay {total 3, matched 3, failure_entries 0, error: null}`。**逐方向双侧源**：`applied_source_uses = {'cpu.tx_byte': 14, 'uart0.rx_frame': 8}` —— 两侧都真的被消费（修前 CPU 侧恒为 0）。**为达成它修掉了两个真实缺陷**：① **fixture 侧**：`AxilUartCpuPair` 在构造 CPU 会话**之后**才赋 router，使会话自身的 `max_mmio_target_accesses_per_step = 1` 声明从未执行，`_step_tick_bounds('cpu')` 只给 `{cpu:1}`、无 uart0 额度，首次被路由的访问即超预算 → `RuntimeError("local harness exceeded declared tick bound")` → `uncertain_effect` → **检查器被整段跳过**（`scenario_rfuzz.py` 的 `checks_allowed`），于是无评估、无闭环、语料只剩 seed；修法是**在构造时就带 router 并如实声明**，**runner 的守卫与 `uncertain_effect` 一行未动**；另修了 router 跨 case 存活导致上一 case 的 delivery 被当新事件重放。② **框架侧**：`scenario_rfuzz.py` 的「已消费源」规则只承认 CPU 的 `channel_id ∈ (instr, unified)`，而生成的 memory CPU 把单一统一端口标成 **`memory`**（`local_harness/native_session.py` 每拍发在 `'memory'`），使**任何建立在这种 CPU 上的组合其「逐方向双侧源」门永远不可满足**；已把 `memory` 纳入该标签词汇，并在注释里写明**放宽标签不能凭空造 credit**——同一条件仍要求读回字节等于被变异的镜像字节、且其 writer 必须是字面量 `initial-image`。守卫：`tests/integration/test_cpu_source_channel_labels.py`（5 项，经 RED 实测：标签表改回两项则 `memory` 那条失败）；**独立复核** `tests/integration/test_axil_campaign_saved_run_audit.py`（**10 项，默认即指向本 bundle**，从 receipts／chain_checks／mutation_selections／corpus／run_identity 逐项复算并交叉核对，且在任何被钉定输入字节移动时变红；实测 **10 passed**）。另修掉一处**冻结 peer 成员在 runner 下无法解码**的缺陷（其采样游标被逐拍 drain 打乱，会抛 `invalid observed UART 8N1 frame`），并修正 replay 记账（原 `failure_entries = len(live/failures)`＝73 对 `total_entries`＝1，正是 `replay counts are inconsistent` 的来源；现按语料覆盖计数，**仍逐条重放并比对每一份失败轨迹**）。**未声称**：不构成对其它行或整个系统的结论；F5/F6 类缺口（中断消费者／DMA 提供者）不在本行范围。 |
| **通用协议事件层新增第四种协议 `axi4-lite`**（2026-10-13 本轮增量，软件层） | **已有** —— `src/myfuzz/scenario/ip_protocol_events.py` 新增 `_consume_axi4_lite`，为 AXI4-Lite 的 **19 个从机侧角色**（`awvalid awready awaddr awprot wvalid wready wdata wstrb bvalid bready bresp arvalid arready araddr arprot rvalid rready rdata rresp`）建立投影；此前该层只有 `tl-ul`／`apb3`／`wishbone` 三种协议。**五通道语义要点：**①请求由 **VALID 触发**，而不是由握手完成触发；②AW 与 W 各自锁存、**可任意先后**，写只在补齐配对的那一拍**被接纳一次**；③响应载荷与**所应答的传输**做字段连接（B/R 携带被应答请求的地址/数据，而不是匿名响应码）；④等待只在"该边沿没有推进"时计数（**前置快照法**，推进的那一拍不算停滞）；⑤**超时只施加于请求相位（AR/AW/W）**，已被接纳后的 B/R 等待只报观测（AXI4-Lite 未给从机响应延迟设上限）；另：非 OKAY 响应码按**测量值**上报并另报 `protocol_error`，reset 切 epoch 取消所有在飞通道组 |
| **通用协议 checker 新增 `axi4lite_*` 违约检查**（同上增量，软件层） | **已有** —— `src/myfuzz/scenario/ip_protocol_checker.py` 的检查规则：载荷在停滞期间不得变化（`axi4lite_payload_changed_while_stalled`）、VALID 未 READY 不得撤销（`axi4lite_awvalid/wvalid/arvalid_withdrawn_before_ready`）、响应必须跟随自己被接纳的请求（`axi4lite_write/read_response_without_request`）、单笔未完成（`axi4lite_write/read_accepted_with_response_outstanding`）、被保持的**请求**通道超出预算（`axi4lite_request_wait_budget_exceeded`）。**明确边界：被保持的响应（B/R 迟迟不来）只作观测、不作违约** |
| **模板契约 11 → 12（仓库存量清单的有意扩增）** | **已有** —— `src/myfuzz/local_harness/template_contracts.py` 新增 `target.axi4-lite` / `single-outstanding-error-codes`，注册表由 11 项变为 **12 项**。它是**从机侧**契约，与既有 CPU 侧 `cpu.axi4-lite` / `no-response-code` **不是同一条目**（从机驱动 `bresp`/`rresp`，CPU 侧契约不含该端口） |
| **真实 IP 的规划实测** | **已有** —— 新增 `src/myfuzz/local_harness/axi4lite_register_template.py`，`src/myfuzz/local_harness/plan.py` 的 v2 白名单接受 `('axi4-lite','1')`；用真实 profile `configs/peripherals/zipcpu_axiluart/component_profile.json` 规划**实测通过**：19 个角色的方向与宽度和 RTL 顶端口一致（`awaddr/araddr` 4 位、`wdata/rdata` 32 位、`wstrb` 4 位、`bresp/rresp` 2 位） |
| **真实 IP 经被动抽头暴露通用 trace** | **已有** —— `src/myfuzz/local_harness/runtime_renderer.py` 的 `axi4_lite_uart` 分支新增被动 `base_protocol_trace`（19 个 `trace_*` 端口，`channel='ip_protocol_trace'`）；`src/myfuzz/scenario/runner.py` 的两处 `kind_protocol` 映射新增 `'axi4_lite_uart': 'axi4-lite'`。`backend_ports` 由 **19 增至 38**（19 个驱动角色＋19 个被动 trace 抽头）；`physical_exports` 仍为 **8**（trace 抽头不参与输入所有权，这是**有意**的）；`tests/local_harness/test_axil_uart_runtime.py` 的断言已同步更新 |
| **真实 RTL 上通用事件已跑通（关键正向证据）** | **已有** —— 在 pinned `zipcpu_axiluart` harness 上写 SETUP(offset 0, value 25) 与 TX(offset 12, value 0x41)，从 RTL tick 样本投影出 `transaction_request`×2、`transaction_accept`×2、`transaction_response`×2、`transaction_timeout`×**0**，**零违约**；两次写完成的载荷携带**实测**地址与数据 `[(0,25,0,'write'),(12,0x41,0,'write')]`，且 TX 那个写的 `wdata` 与 RTL 自己解出的串口字节 `0x41` 一致。测试：`tests/integration/test_axil_uart_generic_events_real.py`（7 项）。**边界：这是通用协议边界事件的观测/投影证据，不是端到端 CPU→IP 组合证据** |
| **本轮新增测试 32 项** | **已有** —— `tests/scenario/test_ip_protocol_events_axi4_lite.py`(12)、`tests/scenario/test_ip_protocol_checker_axi4_lite.py`(13)、`tests/integration/test_axil_uart_generic_events_real.py`(7)。**说明：** 本行的真实 RTL 数字来自**本轮真实的 Verilator 编译与运行**（`tests/integration/test_axil_uart_generic_events_real.py` 可复跑）；本轮未运行 pytest 全量，只跑定向回归 |
| **通用寄存器观测 kind `axi4lite_register_observe`（2026-10-13 后续增量，真实 RTL）** | **已有** —— 新增 `local_harness/axi4lite_register_session.py`（泛化 APB3 会话的命令名，默认值不变故既有 APB3 制品逐字节相同）、`session.py::_OPERATIONS` 条目、`rtl/local_driver_v1.h` 的 `STEP/ACCESS/SOURCE/BIND_AXIL_REG`、`driver_renderer.py` 四处接线、渲染器新分支（用 `axi4_lite_mmio_bridge.sv` 把 beat 驱动到该 IP 自己的 AXI4-Lite 从机口，并暴露 19 个被动抽头）、`generated_register_factory.py` 与 `runner.py` 注册。**真实 RTL 实测：** SETUP 写(0,25) ＋ **TX 部分写(12,0x41, be=1)** ＋ RX 读回，经通用事件投影出 **3 对 request/accept/response、零 timeout、零 protocol_error**，读响应的 `rdata` 与会话自己从 RTL 收到的值相等。驱动侧相应放开 `be`（该 IP 真的实现 `WSTRB`，部分写合法） |
| **独立对抗性复核 REJECT → 真缺陷已修（2026-10-13）** | **已修且已复现验证** —— 复核报告 16 条，我自行复现其中 3 条关键项**全部复现**：①已接纳写的 B 被判超时（守卫写成 `channel != ar and direction == read`，对 `channel=b` 不生效）→ 真实 `max_wait=16` 下「慢但从不出错」的从机会触发，且迟到 B 会让 **run 崩溃**（`KeyError: fields`）；②单通道停滞一拍被计两次（预算翻倍）；③握手成功那拍同时报停滞与超时。**修复：** `_axi4_wait` 增加显式 `budget` 参数（**只有 AW/W/AR 计时并可能超时；已接纳的 B/R 只观测、永不超时**，且超时不清已接纳状态）；每拍只结算一次停滞；字段只在通道当前有效时采样；撤销未接纳 VALID 报 `protocol_error` 并关闭该 offer；已接纳 AW 再握手报 `address_channel_reaccepted_before_completion`；`_axi4_channel` 总是产出完整状态（无请求的 B/R 报错而非崩溃）；应答结算移到请求接纳之前（同拍交接不再误报）；reset 取消去重；删死代码 `_PAYLOAD_WIDTHS`。**跨层：** `ip_base_coverage._PROTOCOLS` 补 `axi4-lite`（此前构造即 `ValueError`）、`ip_protocol_evidence.py` 改读 `bresp`/`rresp`（此前合法事务 `KeyError` 且永远拿不到 certificate）。**新增回归测试：** 事件 13→**20**、checker 13→**16**，每条缺陷一个 |
| **复核未推翻的部分** | 19 条 `assign trace_X = link_...` 与 ABI 端口/位/方向逐条一致；方向推导**不会**放过反向端点（三种篡改均被拒）；`backend_ports` 38 与 `physical_exports` 8 的不对称是**有意且无所有权漏洞**；对既有计划/既有测试的回归面为**空**（既有 axiluart 测试全为 `local_harness.v1`） |
| **一处文档自相矛盾已更正** | 文档同步子代理按其自身范围写下「本轮未跑任何 Verilator 编译」，同段却给出真实 RTL 数字。**实际本轮确实跑了真实 RTL**（786 采样）。已在 `CURRENT_PROGRESS.md`、本清单、`reports/README.md` 三处更正 |
| **多例持久会话（2026-10-13 已闭合，真实 RTL）** | **已有** —— `tests/integration/test_axil_persistent_session_real.py`（7 项）。一个会话进程服务三个用例：首例 `begin_case` 打开、其后每例由 `reset_local()` 在同一进程上开新例；**每例有自己的 reset epoch，且投影出的事件携带产生它们的那个用例的 epoch**；逐例投影得 3 条 `transaction_response`（SETUP 写／TX 部分写／RX 读）、**0 timeout、0 protocol_error、0 违约**，TX 的实测 `wdata` 等于该例自己的字节；并断言最后一例的写集合**不含**第一例的字节（防止跨例重放被误当通过） |
| **驱动命令白名单改为按注册表派生（2026-10-13，通用化）** | **已有** —— `session.py::registered_operations(kind)` 从 `_OPERATIONS` 派生；`driver_renderer.py` 不再列举 kind，而是把该 kind 除 `STEP_/ACCESS_` 外的 `SOURCE_/BIND_` 命令拼进白名单。因此 `axi4lite_register_observe` 自动获得 `SOURCE_AXIL_REG`/`BIND_AXIL_REG`，而 `wishbone_register_observe` 因表中本就没有这两项而**合法地继续拒绝**——一致性是结构性保证，不再依赖第二份手抄列表。测试 `RegisteredOperationTests`(3 项) |
| **两条正确性缺陷（第二轮复核所报）在本轮前的状态** | 已在"第五/第六增量"中修复并各自带回归测试；本清单此前只登记到"独立对抗性复核 REJECT → 真缺陷已修"，未逐条展开，详见 `.superpowers/sdd/progress.md` 第七增量（6 条全部先自行复现再修：同拍 B 崩溃、组合式 R 误报、两拍写证据链、双通道预算减半、AR 超时误清、二次接纳静默丢弃） |
| **CPU→AXI4-Lite→真实 IP 走通用成员（2026-10-13，driver 级已实证换分支）** | **已有** —— `tests/integration/test_axil_cpu_generic_ip_chain_real.py`（5 项）。保留既有 `picorv32_axi` CPU 与同一 pinned RTL，把 IP 侧换成组件中立的 `GeneratedAxi4LiteRegisterSession`（v2 的 `axi4lite_register_observe`）。**逐 kind 渲染对比实证：** v1 `axi4_lite_uart` 用 IP 专属 `ACCESS_AXIL_UART` 且**无** `axi4_lite_mmio_bridge`；v2 `axi4lite_register_observe` 用通用 `ACCESS_AXIL_REG` ＋ **有** `axi4_lite_mmio_bridge`——故新链路走的是**通用驱动分支＋通用会话＋通用事件投影**。覆盖：CPU 写到达通用成员并被投影恰好一次（`awaddr=12`／`wdata=0x41`／零违约）、CPU 读返回设备自己的答案且投影 `rdata` 与逐次观测**逐一相等**（`deliveries=[SETUP,RX,RX]`）、**RAM 地址不进设备**、投影事件身份为通用成员的 `uart.bus`／`zipcpu_axiluart` |
| **本增量明确未声称** | **串行 TX 引脚的解码仍未走通用路径**。既有链路能解出 TX 字节靠的是 `GeneratedAxiLiteUartSession` 的串行 peer 观测；要由通用路径完成需通用层**从声明引脚推导串行 peer**（通用化第 3 步，未做）。故本增量证明的是"寄存器映射事务走通用路径"，**不是**"该链路的串行数据流也走通用路径" |
| **串行链路全走通用路径（2026-10-13，真实 RTL 双向验收）** | **已有** —— 关键发现：TL-UL 的串行 peer **不是 RTL 模块**，而是驱动侧 `SOURCE_<PROTO>_REG` 驱动 RX 引脚 ＋ 逐拍物理采样读 TX 引脚 ＋ Python `Uart8N1Peer` 编解码；这套机制对 AXI4-Lite **已存在**，缺的只是"让 RX 成为可驱动的声明输入"（策略已做）与"工厂按声明选出 peer 会话"（本增量）。改动：`generated_register_factory.py` 新增 `create_generated_axi4lite_session` 并**从 artifact 重新推导 peer**（伪造文档被拒）、`axi4lite_uart_peer_session.py` 接入工厂并修正 TX 观测路径（改从已解码采样读，不再假设命令来源）、渲染器落档 `serial_peer_startup_writes` 与 `axi4lite_register_uart_8n1_peer`。**验收：** `tests/local_harness/test_generic_axi4lite_uart_peer_real.py`（9 项，含 3 项真实 RTL：写发送寄存器→真实 TX 引脚解出、外部 RX 波形→接收寄存器回读、双向同例）；`tests/integration/test_axil_cpu_generic_ip_chain_real.py` 增至 **9 项**，新增 3 项**串行全链路**：**CPU 写 TX → 真实引脚解出 `0x41`**、**RX 波形 → 器件 → CPU 读回 `0x5a`**、双向同例 |
| **一个必须配对的参数（实测教训）** | `clocks_per_bit` 必须等于该 IP 自己的分频值 **25**（`Uart8N1Peer` 默认即 25，因分频值与 SETUP 写入值相等）。照抄 TL-UL 测试的 32 会让 TX 解出 **209** 而非 `0x41`；改 25 后得到 **65**。另：无 peer 时 RX 引脚既非 fixed 也非 dynamic 会被策略**正确拒绝**（`axi4lite-register-unowned-input`），这是 fail-closed 而非缺陷 |
| **本行的受控错误负例（2026-10-13，含对照，真实 RTL）** | **已有** —— 前提已核实：该 IP **无法**产生真实错误响应（profile 自身证据写明 `S_AXI_BRESP`/`S_AXI_RRESP` **tied to OKAY in the RTL**），故受控错误只加在**观测边界**（交付给主机的响应副本），**明确不声称是 RTL 内部故障**。`Axi4LiteControlledErrorTests`(3 项)：①器件所有写完成的 `bresp` 恒为 0；②对照 `0x5a` vs 故障 `0x5a^1` 且**故障确被注入**；③非 OKAY 码被投影为 `transaction_response`＋`protocol_error(native_response_error)`（该形状故障不会被静默接受）。`Axi4LiteControlledValueFaultTests`(1 项，**对比式**)：两次运行共用同一 artifact／场景／注入字节，唯一差别是交付副本是否翻 1 bit——对照组**满足**不变式、故障组**违反**、两值恰为 `x` 与 `x^1`。**没有对照的不变式只是在声称"它总会触发"** |
| **两条低危遗留已清理（N11/N13）** | **已修** —— N11：原正常化器只在 `bvalid and bready` 时检测孤儿响应，对 `bready=0` **完全静默**，与 checker（只要 `bvalid` 即报）在同一采样上结论不同；改为**完成严格需握手、孤儿检测只需 VALID**，并用共用 `_axi4_orphan_response`。**改的过程我自己引入并随即修掉一个真错误**：第一版会让 `bvalid=1,bready=0` 用未握手信号去"完成"一笔写（误报 `transaction_response`）。新增 `Axi4LiteOrphanResponseTests`(5 项)，含**跨层一致性**测试（同一 raw 采样上投影层报 `protocol_error`、检查器报 `axi4lite_write_response_without_request`）。N13：移除只写不读的 `aw_seen`/`w_seen`/`*_abandoned`，修正一处注释与断言不符 |
| **第三轮独立复核 ACCEPT-WITH-NOTES → 两条缺陷已修（2026-10-13）** | **F1【中-高】TX 观测漏读 `step_local` 之外的所有 tick——已修，并取得 RED 证据。** AXI-Lite peer 原只在 `step_local` 观测，而 TL-UL 成员在 `_take` 观测**每个回复**；路由器的 CPU MMIO 交付走**直接** `write_register/read_register`，那条路径的 tick 永不给解码器（会移动采样栅格、**静默解出别的字节**）。修法：单调游标 `_observed_samples` ＋ `_take` **无条件**观测（`begin_case`/`reset_local` 同步）。**RED 证据：** 断言放在 `step_local` 之后时 4 项**全绿**（抓不到）；移到"**直接访问之后、任何 step 之前**"后，旧行为实测 **`AssertionError: 6 != 0`**、修正后 GREEN。**F2【中】直接访问与 RX 波形重叠无守卫——已修**（复用 `peer.source_overlaps`，帧内访问报 `AXI access during serial source waveform is unsupported`，与 IP 专属外壳同语义；帧后放行）。另修 F5 两项：共享 peer 策略错误码前缀**参数化**（AXI-Lite 报 `axi4lite-register-uart-*`）、移除无调用者的死代码 |
| **复核证实为真、我未推翻的** | peer **确非 RTL 模块**（peer artifact 与纯寄存器成员的 `adapter_sources`/`runtime_ports`/`backend_ports` **逐字节相同**）；fail-closed 矩阵 **20 条反例全部被拒**；伪造 peer 文档（各字段＋双向不一致）全部被拒；两条返回路径都是 5 元组；TL-UL 参数化未改变行为（14 项邻接测试通过）；MRO／`reset_local` 语义经其实测符合预期；**未发现任何回归** |
| **复核部分推翻的一条（已更正）** | `clocks_per_bit` 是 tuning 的**必填**字段、**没有默认值**（`Uart8N1Peer` 的默认 25 在 artifact 路径上从不生效），且**与 IP 分频值无交叉校验**——实测 `clocks_per_bit=32` 配该 IP 也能渲染并装配成功。诚实表述：对本 IP 正确性**要求** 25，但**机制不强制**（仓库自带的策略形状测试正是用 32） |
| **未修的残留（第四轮起）** | **F3【低-中】RX 波形非 tick 精确**：动态输入经独立 `SOURCE_*_REG` 下发，每次电平跳变多耗 1 tick（0x5a 时整帧拉长 2.8%，cpb 越小越糟）；IP 专属外壳把 RX 作为 STEP 字段下发因而 tick 精确。此为 TL-UL 机制的**继承性**差异，非本轮引入，但**"通用 peer 与 IP 专属外壳等价"这一说法因此不成立**，只能在"非 tick 精确"意义上说功能等价。**F4【低】** `serial_peer_startup_writes` 目前是装饰性落档键（真正生效的启动写来自 `serial_peer`，工厂会校验，故不影响执行） |
| **本行结论（2026-10-13 本轮更新）** | **本行计划要求的各项均已达成**（①端到端数据流、②通用寄存器观测 kind、③串行链路方向、④多例持久会话、⑤本行受控错误负例），全部有**真实 RTL** 证据。**但这不是"整行无保留通过"**：下列残留仍明确存在，且本行的"通过"仅指本清单为该行列出的要求，不构成对其它行或整个系统的结论。**残留：**①**CPU→AXI4-Lite→真实 IP 的寄存器映射事务与串行数据流均已走通用路径**（通用驱动分支＋通用会话＋声明式 8N1 peer＋通用事件投影；真实 RTL 上 CPU 写 TX→引脚解出 `0x41`、RX 波形→CPU 读回 `0x5a`）；②**通用寄存器观测会话（`axi4lite_register_observe`）已实现并在真实 RTL 上跑通**（见上表新行）；③**串行链路方向（RX 波形→器件→CPU 从 RX 寄存器读回）已在通用事件路径上验收**（真实 RTL，见上表新行）；④**多例持久会话已闭合**（见上表新行，真实 RTL 7 项）；⑤**本行的受控错误负例已做**（见上表新行，含对照，真实 RTL；因该 IP 的 `BRESP/RRESP` 恒 OKAY，故障加在观测边界并明确不声称是 RTL 内部故障）；⑥`has_error=false` 的从机缺 `single-outstanding-okay-only` 变体（现以 `axi4lite-register-okay-only-variant-unregistered` 明确拒绝）；pinned RTL 的 `BRESP/RRESP` 恒 OKAY，故「非 OKAY 上报」只有合成测试覆盖；⑦**无 AXI 版的 trace 接线自动守卫**（APB3 有 `_verify_native_apb_trace` 的对应物） |

### 行 4：classic Wishbone ｜ 首选 CPU：PicoRV32 Wishbone ｜ 首选 IP：ZipCPU wbuart/Timer、OpenTitan GPIO

| 项 | 状态 |
|---|---|
| PicoRV32 Wishbone 本地 | **已有**（真实取指、RAM 写入、deferred MMIO、显式 reset、fresh replay） |
| `picorv32_wb_irq`（`ENABLE_IRQ=1`）+ ZipCPU timer IRQ3 | **已有**（真实 IRQ 绑定、custom0 handler 写 RAM、EOI 拉高/归零、trap=0、主线恢复、fresh replay） |
| Pico Wishbone ↔ OpenTitan GPIO TL-UL | **已有**（`gpio_in` 变异 `0x01→0x81`、真实 pin0 上升沿＋sticky IRQ 绑 `irq[3]`、custom0 ISR 读状态/数据、W1C、`retirq`） |
| Pico Wishbone ↔ ZipCPU wbuart RX IRQ | **已有**（`uart_rx_byte` 变异 `0x35→0xa6`、真实 SETUP 先于 8N1 RX、RX FIFO level IRQ 绑 `irq[3]`、ISR 读 RXREG、FIFO pop 后 IRQ 撤销） |
| **复用逐例搜索与依赖边反馈** | **缺，但缺口比原记录更窄（2026-10-15 实测更正）** —— campaign 框架已具备（`run_scenario_campaign` ＋ `CampaignProvider`，行 2／行 3 已各用它跑通 18/18 格）；而 **Wishbone 的 CPU 会话本身已存在且已具备 MMIO 路由**：`GeneratedWishboneCpuSession`（`wishbone_cpu`、`max_local_ticks_per_step=1`）**构造即强制要求** `memory` 与 `router`，内部已实现 `router.owns/enqueue/transact` 与 `max_mmio_target_accesses_per_step = 0 if defer_mmio else 1`；真实 RTL 也已在用：`tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py` 现场组装 `ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio}, …)` 跑通。**故真正缺的只有三件**：① **scenario 层 fixture**——`myfuzz.scenario` 下**没有** `make_picorv32_wb_*` runner 工厂（上述测试是在测试文件里内联组装的）；② 一个 **`CampaignProvider`**（现有：`IbexTwoGpioBoundProvider`＝行 1、`Cva6TwoGpioBoundProvider`＝行 2，行 3 的 `AxilUartCpuBoundProvider` 为本轮新增）；③ 一份**保留 Pico `custom0` IRQ ABI**（getq/maskirq/retirq，非标准 machine-mode CSR）的闭环 checker，外加 bound／independent 两份 manifest。 |
| **本行结论** | **未通过。** 本地与双向路径、ISR 全部已有且证据扎实，**只差接进持续会话框架并保留自定义 IRQ ABI** |

### 行 5：Pico 原生 Ready/Valid Memory ｜ 首选 CPU：PicoRV32 native ｜ 首选 IP：PULP APB3 GPIO 或 OpenTitan TL-UL GPIO

| 项 | 状态 |
|---|---|
| PicoRV32 native 的 CPU RAM/ROM | **已有**（`ready-valid-memory/1`，真实两轮 Store/Load、持久 RAM、fresh replay） |
| **新增受约束 MMIO 目标与真实 IP 消费链** | **缺** —— 当前 `picorv32` profile **只有 1 个 `memory_master` 端点、无任何 MMIO 窗口**；该协议形态尚无 MMIO 路由器 |
| **本行结论** | **未通过，且缺口最大。** 需要**新增**：该协议形态下的受约束 MMIO 目标、地址窗口声明、以及到真实 GPIO 的消费链。这是五行中唯一需要**新增协议能力**而非"接线已有能力"的一行 |

### 额外：计划要求"至少一个非 Ibex＋非 GPIO 组合证明受控错误由 checker 捕获"

| 项 | 状态 |
|---|---|
| 非 Ibex＋非 GPIO 的受控错误捕获 | **未做**（现有受控故障校准在 Ibex＋双 PULP GPIO 上完成） |
| 可选落点 | CVA6＋OpenTitan SPI Host、CV32E40P＋OpenTitan UART、Pico Wishbone＋OpenTitan GPIO（三者都已有真实链，加一次受控扰动即可） |

---

## 3. 建议的执行顺序（按"已有能力可复用度"排序，而非按五行表顺序）

| 序 | 行 | 为什么这个顺序 | 主要新工作 |
|---|---|---|---|
| **1** | **行 3（AXI4-Lite）** | CPU 与 IP 两侧都已可规划、IP 已有独立证据，只缺一条 MMIO 路由与数据链。**五行中最短路径** | `axi4-lite` CPU 侧的 MMIO 窗口路由 → `zipcpu_axiluart`；TX 写→引脚解码、RX 引脚→RDATA→CPU 读回；再接持续会话 |
| **2** | **行 1（OBI/CV32E40P）** | 把已验收的 Ibex 框架原样套到 CV32E40P，**几乎无新协议工作** | 复用第一步逐例双侧搜索＋反馈＋断言＋前缀 replay |
| **3** | **行 4（Wishbone）** | 本地与双向路径、ISR 全有，只差接框架；**注意保留自定义 IRQ ABI** | 接持续会话；把 custom0 IRQ ABI 纳入断言与 replay |
| **4** | **行 2（完整 AXI4/CVA6）** | 能力最完整（含真实 ISR），但 CVA6 的 AXI4 适配体量与本地时序更重 | 接持续会话；确认 64 位/ID4 打包下单拍 MMIO 的字段约束 |
| **5** | **行 5（Pico 原生 Ready/Valid）** | 唯一需要**新增协议能力**（MMIO 目标＋路由）的行，风险最高 | 新增受约束 MMIO 目标与地址窗口、真实 GPIO 消费链 |
| **6** | 受控错误负例 | 可依附任一行完成后做，成本低 | 在选定的非 Ibex＋非 GPIO 组合上注入受控扰动并证明 checker 报警＋fresh replay |

**并行提示：** 行 1、行 4 主要是"接线已有能力"，行 3、行 5 涉及新协议工作。若按计划允许的方式并行，建议 **行 3 与行 1 并行**（互不共享协议实现），行 5 单独串行。

---

## 4. 每行共用的验收清单（照第一步的口径）

每行在标"通过"前，须逐项有真实运行证据（不得以定向场景或配置成功代替）：

1. **本地协议验收**：取指、数据访存、byte-enable 三项在该 CPU 协议形态下各有真实 RTL 证据。
2. **双向真实传播**：至少一条 CPU→IP、一条 IP→CPU，各带真实生产者/消费者身份（`RuntimePathContract` 的逐边来源）。
3. **IRQ→handler**（需要 ISR 的组合）：真实 IP IRQ → CPU 真实 trap → ISR 读真实状态 → 写回，且 IRQ **不得**由 Scheduler 合成。
4. **逐例双侧源**：多例持续会话中 CPU 侧与 IP 侧源**都**被真实选取并驱动（不按固定频率交替、不用 direction 标签硬限）。
5. **交互反馈**：`stage_hits`／`edge_hits`／`state_transition_hits`／`closed_loop_hits` 各带路径、源、真实生产/交付/消费事件；缺下游消费只算阶段到达。
6. **断言与负例**：协议/跨组件/CPU-IP 三类断言分节；受控错误能被独立 checker 捕获并在新进程复现。
7. **完整前缀 fresh replay**：从会话初态重放第 1～N 例，`matches=True`、`first_difference=None`。
8. **能力分级逐项登记**：`Catalog → Generated → RTL operational → Cross-component accepted → Coverage-guided searched → Bug confirmed`**逐行给级**，一级不得自动推出下一级；不可执行的 CPU 记 `skipped_unavailable`（BOOM 目前即此）。

---

## 5. 能力表更新规则（计划第 370 行）

每完成一行，必须：①更新 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md) 的对应组合行；②在 [报告索引](../../reports/README.md) 追加验收条目（含命令、退出状态、源码/配置身份、真实观察、负例、证据路径、replay 结论、未覆盖范围）；③再改总计划的阶段状态。**不能仅靠计划复选框宣布通过**——本仓库已多次因"复选框 vs 实测"不一致而返工。

---

## 6. 已知边界与不做什么

- **BOOM / CVW / VexiiRiscv 无本地可执行条件**：BOOM 无 profile 且缺 Chipyard checkout 与 Java/SBT/Mill；VexiiRiscv 无任何资产。**CVW 的阻断点已换**（2026-10-14 实测更正）：不再是"缺源码/配置/profile"——源码、派生配置、profile、真实 elaboration、从属端时序模型都已在位——而是**尚无真实 AHB 交易**，且上游 `EXT_MEM_SUPPORTED=0` 使外部端口在六个已提交配置里都不可达（详见 §1 的 2026-10-14 增量）。三者按计划记 `skipped_unavailable`，**不得**用静态扫描或另一协议的 CPU 抵消。
- **不生成具体 SoC Bus/Bridge/PLIC/全局 cycle-accurate 时序**；跨组件只交换事务、数据与事件。
- **不宣称任意同协议组件即插即测**；每行只按实际通过的局部交易与跨组件路径登记能力。
- **五行全部通过才等于 P6 通过**；单行通过只更新该行。
- **P7 依赖本清单**：P7 的自动接入范围上限＝本清单已验收的协议形态（详见 [P7 实现文档](2026-10-13-p7-automatic-onboarding-implementation.md)）。
