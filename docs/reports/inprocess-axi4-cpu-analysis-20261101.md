# 完整 AXI4 CPU（CVA6 / VexiiRiscv）接入单进程统一执行器：身份审计、原生探针与补丁方案

日期：2026-11-01（实际执行时间 2026-11-01 深夜至 11-02 凌晨）
范围：**只新增文件**。未修改 `scripts/inprocess_obi_apb_f1f4_spike.cpp`、`scripts/run_inprocess_f1f6.py`、`src/myfuzz/**`、任何既有测试/配置/文档，也未触碰其他 agent 的 run 目录。统一入口/宿主正由 AHB agent 并发修改（本次读到的最新状态已带 `CPU_BUS_AHB`），本文对宿主的行号引用以“本次读取时刻”为准，函数/分支名是稳定锚点。

> **一句话结论：** CVA6 的真实归档 + 仓库既有完整 AXI4 CPU 侧适配器 + 宿主 RAM 已在**一个原生进程**里跑通真实取指、真实 load/store；取指/数据身份来自 pinned 配置的 ARID/RID（0 = I$，1 = D$），不是地址推断；**退休仍是 unknown**（生成的 runtime top 不导出 RVFI）；把同一程序槽改写后，**不带 `fence.i` 时 I$ 继续执行旧代码（实测 0 次重取、继续写旧值）**，执行 `fence.i` 或复位后才重取。统一入口要接入该行，除了 AXI4 分支外还必须解决“入口目前强制要求 RVFI”这一硬性拒绝，否则 F2–F4 也构建不出来。

## 1. 实测 vs 仅分析（先划清界限）

| 项 | 状态 | 证据 |
|---|---|---|
| CVA6 身份分类器（ARID 0/RID 0 = I$）单元测试 | **实跑** | `tests/native/inprocess_axi4_identity_test.cpp`，51 条断言通过 |
| CVA6 真实归档 + 既有完整 AXI4 适配器 + 宿主 RAM 原生探针 | **实跑** | `tests/native/inprocess_axi4_cva6_probe.cpp`；日志 `runs/stage2-axi4-cpu-20261101/logs/probe-run.log` |
| 真实取指 / 行填充 / load / store / B·R 响应 | **实跑并观测** | 下文第 4 节计数 |
| 退休（RVFI） | **未观测**：归档无 RVFI 引脚，报告为 `retirement unknown` | 第 5 节 |
| 同一程序槽跨 case 改写（无 fence / 有 fence / 复位） | **实跑并观测** | 第 6 节 |
| VexiiRiscv 真实执行 | **仅分析（未运行）** | 第 3.2 节；未构建/未跑 Vexii 探针 |
| 统一宿主/入口的 AXI4 分支、F1–F6 准入 | **仅分析（补丁方案）** | 第 7 节；未改任何共享文件 |
| 任意 AXI4 CPU / 任意配置的普适性 | **不声称** | 第 8 节 |

没有把 F1 宣告为通过，没有覆盖率/证书声明。

## 2. 交付物

- `scripts/inprocess_axi4_identity.h`：AXI4 CPU 身份声明（packed ARID/RID 映射、structural i/d 端口、未声明即 Unknown）。
- `tests/native/inprocess_axi4_identity_test.cpp`：身份分类器单元测试（纯 C++，无 RTL）。
- `tests/native/inprocess_axi4_cva6_probe.cpp`：真实 CVA6 归档 + `axi4_processor_memory_adapter` + 宿主 RAM 的原生探针。
- `scripts/run_inprocess_axi4_cpu_probe.py`：可复现的构建/身份校验/运行脚本。
- `tests/integration/test_inprocess_axi4_cpu_analysis.py`：重读身份锚点、编译运行单元测试、校验保存的探针日志（证据不在时跳过）。
- 证据：`runs/stage2-axi4-cpu-20261101/`（`identity.json`、`logs/`、`README.md`、`commands.txt`、探针源码副本 `probe/`）。

## 3. 信号 / 身份矩阵（全部来自真实 profile、生成物与 RTL 锚点）

### 3.1 CVA6（`cva6_packed_axi4_cpu`，cv64a6_imafdc_sv39，WT D$）

| 事实 | 值 | 精确锚点 |
|---|---|---|
| 物理端口 | 单一 packed AXI4 主口 `noc_req_o`(470b) + `noc_resp_i`(210b) | `core/cva6.sv:345,347`（`output noc_req_t noc_req_o` / `input noc_resp_t noc_resp_i`）；profile `configs/cpus/cva6/component_profile.json:71`（`processor.memory.unified`）|
| 地址/数据/ID 宽度 | addr 64 / data 64 / **ID 4** / user 64 | `core/include/cv64a6_imafdc_sv39_config_pkg.sv:32`（`AxiIdWidth=4`）、profile 各 role 的 `width` |
| **取指身份** | **ARID = 0 → I$；ARID ≠ 0 → D$；RID = 0 → I$ 返回** | `core/cache_subsystem/wt_axi_adapter.sv:116`（`arb_req = {dcache…, icache…}`）、`:144`/`:159`（`axi_wr/rd_id_in = {0…, arb_idx}`）、`:597`（`axi_rd_id_out == 0` → icache）、`:638`（`axi_rd_id_out[0]` → dcache）|
| HPROT 类属性 | **不可用**：ARPROT/AWPROT 恒 0，`ar.user`/`aw.user` 恒 0 | `core/axi_shim.sv:95`（aw.prot）、`:101`（aw.user）、`:258`（ar.prot）、`:263`（ar.user）；profile `"role": "arprot"`（169）、`"aruser"`（243）|
| AW 身份 | 写只来自 D$：AWID = 1；AW 永不可能是取指 | 同上 `:144`；本次探针实测 `aw … id=1` 全部 |
| RVFI 退休 | **RTL 有、生成物无**：RTL 端口 `rvfi_probes_o`（6974 bit、88 成员），配置 `RvfiTrace=1`；但 profile 动作 `unconnected`，生成的 runtime top 不导出任何 rvfi 引脚 | `core/cva6.sv:339`；`cv64a6_imafdc_sv39_config_pkg.sv:76`；profile `port_actions[rvfi_probes_o].action == "unconnected"`；`runs/cva6-f1f4-20261031/cache/20c5…/inputs/generated/artifact.json` 的 `structural_abi.dispositions` 与 `runtime_ports`（无 rvfi）|
| IRQ | RTL `irq_i[1:0]` + `time_irq_i`；profile 把 `irq_i[1]`（supervisor-external）恒 0、`time_irq_i` 为 fuzz 输入；生成物导出 `rt_lh_p_7_0_0`= `irq_i`（machine_external，1 bit）、`rt_lh_p_12_0_0`= `time_irq_i` | `core/cva6.sv:331,335`；profile `port_actions[irq_i]`（action=constant, bits=[1]）、`[time_irq_i]`（action=fuzz）；artifact `physical_exports` |
| 复位 | RTL `rst_ni` 异步低有效；wrapper 归一化为高有效 `reset` | profile `resets[0].port=rst_ni`（62）；`inputs/generated/structural.sv:118`（`assign dut_p_10 = ~reset;`）、`:133`（`.rst_ni(dut_p_10)`）|
| 启动地址 | `boot_addr_i = 65536 (0x10000)`（常量，不在宿主改） | profile `port_actions[boot_addr_i]`（797）；artifact `boot_contract.configured_boot_base=65536` |
| 取指缓存策略 | I$ 16 KiB / 4 路 / **128 bit 行**；D$ 32 KiB / 8 路 / 128 bit，**WT**；cached 区域 `0x8000_0000..0xC000_0000`；execute 区域含 `0x0`、`0x10000..0x20000`、`0x8000_0000..` | `cv64a6_imafdc_sv39_config_pkg.sv:40-45,72,139-144`；非缓存判定 `core/cache_subsystem/cva6_icache.sv:139-141`（`paddr_is_nc`）|
| `fence.i` 语义 | 置位 `flush_icache_o` → I$ flush（D$ 不 flush，`DcacheFlushOnFenceI=0`） | `core/controller.sv:142-149`；`core/cva6.sv:1400,1489`；`cv64a6_imafdc_sv39_config_pkg.sv:48` |
| 适配器能力（既有 RTL） | 单 outstanding；AWLEN 必须 0；ARLEN ≤ 1 且 INCR；LOCK/ATOP/DECERR 失败关闭；RTL 自行序列化两拍行填充 | `src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv:135-142,166-191,293-356` |

**重要边界**：`0x10000` 在 execute 区域但**不在** cached 区域，因此启动取指是非缓存单拍（`ARLEN=0, ARSIZE=3`）；`0x8000_0000` 在 cached 区域，取指是 128-bit 行填充 = 两拍 64-bit（`ARLEN=1`）。探针实测两者都出现过（第 4 节）。

### 3.2 VexiiRiscv（`reduced_dual_axi_cpu`，pinned generated cacheless RV32）

| 事实 | 值 | 精确锚点 |
|---|---|---|
| 物理端口 | **结构化的两个主口**：`i_*`（仅 AR/R）与 `d_*`（AW/W/B/AR/R），无 LEN/BURST/LOCK/QOS/REGION；addr/data 32 bit；ID 1 bit；`rlast`/`wlast` 存在 | `configs/cpus/vexiiriscv/component_profile.json:39`（`processor.memory.i`）、`:127`（`processor.memory.d`）；`:47..119`（i 的 AR/R 角色）、`:135..303`（d 的完整角色）；`configs/cpus/vexiiriscv/generated/VexiiRiscv.v:7-54`（顶层端口，无 `*_payload_len`/`_burst`）|
| **取指身份** | **端口本身**：`i_arvalid`/`i_r*` 即取指；`d_*` 即数据；ID 不是身份（1 bit，保留） | 生成模型头 `runs/vexii-f1f4-20261031/cache/0532…/obj/Vlocal_runtime_processor.h:36,61`（`d_awvalid`/`i_arvalid`）；artifact `runtime_ports` |
| RVFI | **无**：RTL 顶层没有 rvfi 端口，生成物也没有 | `VexiiRiscv.v:7-54`；artifact `runtime_ports`（仅 clk/reset/i/d AXI）|
| IRQ | RTL 顶层有三个 m-mode 中断输入（`int_m_timer/software/external`），但生成 wrapper **全部恒 0**，artifact `physical_exports` 为空 | `VexiiRiscv.v:10-12`；`runs/vexii-f1f4-20261031/cache/0532…/inputs/generated/structural.sv:131-136`（`assign dut_p_42/43/44 = 1'd0`）、`:186-188`；artifact `physical_exports: []` |
| 复位 | profile 声明高有效、异步；wrapper 直接连 `reset`（不反相） | profile `resets[0].port=reset`；`structural.sv:142`（`assign dut_p_47 = reset;`）|
| 缓存 | profile 描述与插件名均为 **cacheless**（`FetchCachelessAxi4Plugin_*` / `LsuCachelessAxi4Plugin_*`），预期无 I$ 陈旧问题 | profile `description`；`VexiiRiscv.v:8-54` 端口名 |
| 结论 | 身份是结构性的、无需 ID 映射；但**该归档无 IRQ、无 RVFI**，统一入口目前既不能构建（见 7.2），也不能声明 F1/F5 | — |

## 4. 原生探针：设计与实测

探针（`tests/native/inprocess_axi4_cva6_probe.cpp`）在**一个进程**里实例化：

1. 真实 CVA6 生成模型 `Vlocal_runtime_processor`（归档 `runs/cva6-f1f4-20261031/cache/20c52c0…/obj/Vlocal_runtime_processor__ALL.a`，SHA-256 `76ef92e0…761708`；其 `runtime.sv` 的 SHA-256 与 artifact 记录的 `22218423…b268d7` 一致；`source_verification.source_status=source_verified`、`runtime_status=runtime_unverified`，**不是本次重建的认证**）。
2. 仓库既有完整 AXI4 CPU 侧适配器 `src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv`（本次用 Verilator 5.051 `e413e67` 以 `ADDRESS_WIDTH=64 DATA_WIDTH=64 ID_WIDTH=4 USER_WIDTH=64` 重新 Verilate，产物在证据目录 `build/adapter-cva6/`）。
3. 宿主稀疏 RAM 与逐拍握手采样（不在宿主重写 AXI4 状态机）。

身份分类只用 pinned 配置声明：ARID 0 / RID 0 = 取指；写一律数据；未声明身份时一律 Unknown（`scripts/inprocess_axi4_identity.h`）。

### 4.1 实际运行命令

```bash
python3 scripts/run_inprocess_axi4_cpu_probe.py \
  --archive runs/cva6-f1f4-20261031/cache/20c52c04097f4e1cf2635eae196a71569dd9f47ac2a57a0bcdddc6b4a3d6fa85/obj/Vlocal_runtime_processor__ALL.a \
  --output runs/stage2-axi4-cpu-20261101 --max-ticks 12000
```

退出码 0；日志 `runs/stage2-axi4-cpu-20261101/logs/probe-run.log`（1.2k 行），身份/工具/摘要写到 `identity.json`。

### 4.2 观测到的真实事务计数

总计（3851 tick，4 个阶段）：

| 通道 | 握手数 | 身份拆分 |
|---|---|---|
| AR | 146 | 取指 20（8 次非缓存单拍 + 12 次两拍行填充），数据 126 |
| R | 158 | 取指 32 拍（12×2 + 8×1），数据 126 |
| AW | 126 | 全 D$（AWSIZE=3 的 116 次、AWSIZE=2 的 10 次）|
| W | 126 | 全 D$（`strb=0xff` 116 次、4 字节 10 次；`wlast=1` 全部）|
| B | 126 | 全部 `bresp=0`（OKAY）|
| 适配器 beat | 284 | req/rsp 各 142 对 |

关键逐条（`probe-run.log`）：

```text
verdict boot_fetch=observed tick=250 address=0x10000 arid=0 arlen=0
ar 278 0x80000000 id=0 len=1 size=3 kind=instruction
r 281 0x110059300020537 id=0 last=0 kind=instruction
r 284 0x85260300b52023 id=0 last=1 kind=instruction
aw 319 0x20000 id=1 len=0 size=3
w 319 data=0x123400000011 strb=ff last=1
b 322 id=1 resp=0
```

- 启动取指是 **0x10000 的非缓存单拍**（`arlen=0, arsize=3`），真实返回 `0x01f51513_00100513`（两条 RV64 指令）。
- 跳到 `0x8000_0000` 后是 **两拍行填充**（`arlen=1`，`rlast` 先 0 后 1），返回 16 字节真实程序：
  `0x00020537, 0x01100593, 0x00b52023, 0x00852603, 0x00c52223, 0xfedff06f`。
- 真实 load：`ar 0x20008 id=1 size=2` → `r 0x1234`；真实 store：D$ 写缓冲把同一循环的两个 4 字节 store **合并成一次 8 字节写** `AWADDR=0x20000, AWSIZE=3, WSTRB=0xff`，内存最终 `[0x20000]=0x11`、`[0x20004]=0x1234`（探针回读确认）。
- **没有 DECERR/SLVERR**：所有读都在适配器支持范围内（ARLEN≤1、INCR），B/R 均 OKAY。

## 5. 退休证据：unknown（明确、可复核）

- CVA6 的 RVFI 是真端口（`core/cva6.sv:339`，配置 `RvfiTrace=1`，6974 bit / 88 成员），但 profile 的 `port_actions[rvfi_probes_o].action = "unconnected"`，生成的 runtime top `runtime_ports` 中没有任何 rvfi 名字，`structural_abi.dispositions` 明确记录“left open … coverage loss”。
- 因此本次探针**没有任何退休见证**；`summary` 打印 `retirement unknown rvfi_pin=absent`。
- store 真正写入 RAM、load 的值随后被 store 出去，证明这些指令**确实执行**，但这是体系结构副作用，**不是** RVFI 退休见证；报告不据此声称 F1。
- 若将来要让 CVA6 有真实退休：需要新的生成 wrapper 导出 `rvfi_probes_o` 的成员（或 `--public-flat` 等直接观察），并让宿主消费 `rvfi_valid/pc_rdata/insn/trap/order/rd_*`。这属于 `src/myfuzz/local_harness/runtime_renderer.py` 与 profile 的改动（本轮禁止），不在本任务内。

## 6. 缓存一致性发现（同一程序槽改写）

四个阶段（每阶段 900 tick，程序在 cached 区 `0x8000_0000`）：

| 阶段 | 动作 | 观测 |
|---|---|---|
| A | 安装 V=0x11 程序（无 fence），运行 | 2 次程序行填充、真实 store 0x11、真实 load 0x1234 并回存；循环继续（57 次写、60 次数据读）|
| B | **不 reset、不改时钟**，把同槽改写成 V=0x22，继续 900 tick | **程序 AR = 0**；60 次写 **仍是 0x11**；`saw_0x22=0` → **I$ 继续执行旧代码，宿主写内存对它不可见** |
| C | 硬复位 + 安装带 `fence.i` 的 V=0x33 程序 | 复位后 **6 次程序 AR**（重新取指），最后 store = 0x33 → 复位会清 I$（enable 时 cache clear，`cva6_icache.sv:239`）|
| D | 在 `fence.i` 循环运行中改写为 V=0x44 | **4 次程序 AR（>0）**，store 出现 0x44 → `fence.i` 的 I$ flush 使新代码生效 |

结论（可直接用于统一执行器）：

1. 现有 CVA6 F1–F4 场景把程序槽放在 **0x10000**（execute 区但非 cached 区），取指是非缓存单拍，所以跨 case 改写天然会重取——**当前能工作是因为槽不在缓存区，不是因为宿主处理了缓存一致性**。
2. 如果程序槽落在 `0x8000_0000..0xC000_0000`，同槽改写**必须**由 CPU 执行 `fence.i`（或每 case 复位 CPU）才能看见；否则执行旧指令且毫无总线迹象（D 侧仍在跑，容易被误判为“已切换”）。
3. `fence.i` 代价很高：本探针每个“fence.i + 重取两行 + load/store”迭代约 **285–290 tick**（阶段 C 时间戳间隔），统一执行器若每 case 靠 fence.i 刷新，tick 预算必须计入。
4. 复位可清 I$，但会丢失 CPU 的连续会话状态；统一执行器的 `recovery_scope=devices_only_cpu_and_ram_retained`（宿主现有约定）与“每 case 复位 CPU”不兼容，需要显式决策。

## 7. 统一宿主 / 入口的接入补丁方案（不改共享文件，仅方案）

### 7.1 宿主 `scripts/inprocess_obi_apb_f1f4_spike.cpp`（行号=本次读取时刻；AHB agent 并发编辑中）

| 位置（当前行） | 现状 | AXI4 CPU 需要的改动 |
|---|---|---|
| `:51-64`（宏）、`:31-33`（AHB 身份头包含） | `CPU_BUS_WISHBONE`、`CPU_BUS_AHB` 两个宏 + “one header cannot select two buses” 检查 | 新增 `CPU_BUS_AXI4`（默认 0），并把它加入互斥检查；头文件里包含 `inprocess_axi4_identity.h`（照 `:31-33` 的 AHB 写法） |
| `:1114-1128` | `#if WISHBONE … #elif AHB …` 驱动 CPU 侧 | 新增 `#elif CPU_BUS_AXI4`：把 CPU 的 `awready/wready/bvalid/bid/bresp/buser/arready/rvalid/rid/rdata/rresp/rlast/ruser` 从**第二个 Verilator 模型**（既有 `axi4_processor_memory_adapter`）读入；把 CPU 的 `aw*/w*/bready/ar*/rready` 输出接到该模型；`req_ready/rsp_valid` 用与本探针相同的单 beat 服务（探针 `settle()`/`tick()` 已证明收敛） |
| `:1136-1260` | 采样各总线的请求/响应（AHB 分支在 `:1155`） | 新增 AXI4 分支：逐拍采样 AW/W/B/AR/R 五通道握手；用 `Axi4CpuIdentity` 按 ARID/RID 分类；**写通道分类为数据**；每个通道单独计数（`ar_instruction/ar_data/...`） |
| `:1578-1738`（WISHBONE `:1578` / AHB `:1665` 的 beat 服务） | 由宿主在 beat 级服务 RAM/MMIO | AXI4 分支同样只服务适配器的 `req_*`/`rsp_*`（**不要在 C++ 重写多拍/outstanding**）：读写按地址解码；取指只允许 RAM；数据可路由到 IP/DMA 窗口；`req_be` 为 64-bit lane 掩码，写 RAM 按字节；`rsp_error` 仅对越界/越权窗口置 1（这样 DECERR/SLVERR 是**真实驱动**的，不是伪造） |
| `:1992` 的 `idle` 判定 | `idle = !mmio.busy …` | 加入 `!beat.active && !adapter.req_valid`，保证 case 边界的 `frame_done` 不被适配器未完成事务提前满足 |
| `:2524,2542` | 汇总打印 `cpu_bus wishbone-…` / `ahb-…` | 新增 `cpu_bus axi4-packed-single-master` + `instruction_identity arid0_rid0_at_address_phase` + 各通道计数 + `retirement missing`（没有 RVFI 时不得复用 `retired` 词） |
| `:2599-2610` | `bus_error_<bus> unknown` | 新增 `bus_error_axi4_ar/r/aw/w/b`：适配器/宿主能真实驱动错误时打印 `observed`，否则 `unknown` |
| `:1434-1511` | `!CPU_BUS_AHB` 包住 RVFI 采样 | AXI4 CPU 归档没有 RVFI，**必须**和 AHB 一样被排除在 RVFI 块外；不要用取指计数冒充退休 |

**通道状态机结论**：不要在宿主重写。既有 `axi4_processor_memory_adapter` 已实现单 outstanding、AW/W 独立捕获、B 在响应后、R 逐拍 `rlast`、ARLEN≤1 的两拍序列化、LOCK/ATOP/DECERR 失败关闭（`:135-142,161-191,293-356`）。探针已用 CVA6 真实流量验证它够用。若未来需要 >1 outstanding 或更长 burst，应扩展该 RTL（新 owner/新文件），宿主 beat 服务再排队；本轮不做。

### 7.2 入口 `scripts/run_inprocess_f1f6.py`（行号=本次读取时刻）

| 位置（当前行） | 现状 | 需要的改动 |
|---|---|---|
| `:133` `CPU_BUSES` | `{'obi_cpu','wishbone_cpu','ahb_lite_cpu'}` | 增加 `'cva6_packed_axi4_cpu': 'axi4'`（packed）与 `'reduced_dual_axi_cpu': 'axi4'`（structural）；标签加 `'axi4'` |
| `:303` `cpu_bus()` | 只按 artifact `kind` 选总线 | 增加 axi4；并对 `reduced_dual_axi_irq_cpu` / ZipCPU `axi4_cpu` 保持**具名拒绝**（2026-10-31 可行性报告的缺口未变） |
| `:1200` RVFI 强制要求 | 每个 build 都要求 `rvfi_valid/trap/insn/pc_rdata`，缺失即 `unsupported: F1 needs the CPU rvfi_*…` | **这是当前最硬的阻断**：CVA6/Vexii 归档无 RVFI，连 F2–F4 都构建不出来。应改为“F1 必需；F2–F4 可选”，并在 case/summary 里写 `retirement unknown`；否则 AXI4 分支再完整也无法落地 |
| `:1410,:1421` 总线宏 | `CPU_BUS_WISHBONE`、`CPU_BUS_AHB` | 新增 `CPU_BUS_AXI4` 三态；`render_bindings` 里按总线渲染 AXI4 端口组 |
| `render_bindings`（CPU 端口段，`:1250` 附近起） | OBI 走 `CPU_I/D_*`，Wishbone 走 `CPU_WB_*` | AXI4 packed：渲染 45 个角色中宿主需要的 `aw*/w*/b*/ar*/r*`（含 `buser/ruser/rlast`）；AXI4 structural：分别渲染 `i_*`（AR/R）与 `d_*`（AW/W/B/AR/R）。适配器模型名/参数写入头文件（如 `#define CPU_AXI4_ADAPTER Vaxi4_processor_memory_adapter` + `-G…`），或在入口的构建步骤里作为独立模型编译（与 CPU/IP 同 tick） |
| `:3030` `cpu_bus=dict(...)` | 汇总/文档 | 增加 `axi4` 的 label 与 identity 描述 |

### 7.3 F1–F6 分级（基于观测）

- **F1（取指+退休）**：当前**不可做**。没有 RVFI 见证；取指 AR 不是退休。要么新增导出 RVFI 的 wrapper/profile（不属于本轮），要么 F1 保持具名拒绝。
- **F2（load）**：可做。数据 AR/R 路由到目标窗口；探针已证明 4 字节读、lane/`arsize=2`、单拍 R 都能工作。注意读地址可在 IP 窗口内，宿主必须按真实 `arsize` 返回 R 数据（不能假设 8 字节）。
- **F3（store）**：可做，但**必须按字节 strobe 记账**。探针实测 WT D$ 会把同一循环的两个 4 字节 store 合并为一次 `AWSIZE=3, WSTRB=0xff` 的 8 字节写；现有宿主的 `be==15`/“一次 store 一条写”的 F3 判定会误判。F3 需要“按 WSTRB 拆分/归属”，且 8 字节写要落到两个 4 字节 granule。
- **F4（MMIO 写）**：可做。AW/W/B 路由到目标 beat 面，取指必须在 IP 窗口被拒绝（现有 Wishbone 分支 `:1598` 的规则照搬）。注意 CVA6 的写可能合并，F4 的“一次事务”判定需按目标实际收到的 beat 判定，而不是按程序里的 store 条数。
- **F5（IRQ）**：CVA6 artifact **有** machine-external `irq_i` 单 bit 导出（`rt_lh_p_7_0_0`），可以尝试；但没有 RVFI/trap 输出，`irq_take` 无法由 CPU 退休见证，只能靠 ISR 的真实 store/读目标等副作用。Vexii 归档 IRQ 恒 0、`physical_exports` 为空 → **Vexii F5 必须重新生成 wrapper/profile**，本轮不做。
- **F6（DMA）**：需要第二个 AXI4 主设备（AXI4 DMA 或 AXI4 到既有 Wishbone DMA 的桥）以及多主仲裁/地址路由；CVA6 是单一 packed AXI4 口，不存在“第二个主机端口”，且无 RVFI。**明确不在本轮范围**；若要做，最小方案是新增 AXI4 DMA 主 + 多主 fabric（新 RTL/新 owner）。

## 8. 精确边界（不声称）

- 只对 **pinned cv64a6_imafdc_sv39 + WT D$ + `CachedRegion=0x8000_0000`** 这一配置的 ARID/RID 身份成立；不外推到任何 AXI4 CPU 或任何 CVA6 配置。
- 归档复用经过 manifest/生成物核对（`runtime.sv` SHA-256、artifact kind/digest、RVFI disposition），但**没有**用它自己的源锁重建成当前工作树的认证；`runtime_status=runtime_unverified`。
- 探针只执行 6–7 条手写 RV64 指令（trampoline + 两个小程序），**没有**执行 CVA6 的 F1–F4 通用场景，也没有跑 IP/DMA/IRQ。
- 没有用地址推断身份；没有把取指当退休；没有覆盖率/证书声明。
- Vexii 只有静态审计，没有真实执行；其 IRQ 恒 0、无 RVFI 是**该归档**的事实，不代表 Vexii 上游能力。
- 统一宿主/入口正被 AHB agent 修改，本文行号是本次读取的快照；补丁以函数/分支名为准。

## 9. 复现与证据

- 身份单元测试：
  `g++ -std=c++17 -Wall -Wextra -Werror tests/native/inprocess_axi4_identity_test.cpp -o /tmp/i && /tmp/i`
- 探针（构建+身份校验+运行）：
  `python3 scripts/run_inprocess_axi4_cpu_probe.py --archive <cva6 …/Vlocal_runtime_processor__ALL.a> --output runs/stage2-axi4-cpu-20261101 --max-ticks 12000`
- 分析测试：`python3 -m pytest tests/integration/test_inprocess_axi4_cpu_analysis.py -q`（7 passed, 1 skipped：报告尚未写入时跳过报告断言）
- 证据目录：`runs/stage2-axi4-cpu-20261101/{identity.json,logs/{adapter-build.log,probe-compile.log,probe-link.log,probe-run.log},build/{adapter-cva6,inprocess_axi4_cva6_probe},probe/,README.md,commands.txt}`
