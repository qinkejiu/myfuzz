# RISC-V 组件组合与 RFuzz 输入结构参考笔记

状态：研究与设计参考，不表示候选 RTL 已被本仓库集成、编译或长测

资料访问日期：2026-09-06

适用范围：CPU、片上协议、存储器/外设、桥接器、依赖感知组合图、RFuzz 输入 ABI 与长测审计

## 1. 结论摘要

本仓库已经具备构造“CPU + 协议桥 + MMIO 组件”实验的基础，但必须把三类事实分开：

1. **已存在的本地能力**：协议描述插件含 APB3、APB4、AXI4-Lite、OBI v1、ready-valid MMIO v1、TL-UL v1；RTL 目录已有 APB4、AXI4-Lite、TL-UL 与统一 MMIO 的 bridge/target adapter。
2. **已批准的组合夹具**：Ibex 协议组合 manifest 使用 32-bit 地址和数据，连接 TL-UL RAM、APB4 timer/GPIO、AXI4-Lite UART/SPI；它是确定性组合夹具，不等于这些外设均已成为完整生产级 IP。
3. **候选生态**：下文列出的 CPU、外设和桥接器是可研究/可引入目录；除非本地 manifest、锁定版本、构建报告和仿真证据同时存在，不得称为“本仓库已支持”。

组件组合不能只按模块名连线。一个可执行的组合必须同时满足地址/数据宽度、地址单位与对齐、突发能力、未完成事务数与顺序、响应/错误语义、中断拓扑、时钟复位域、端序、权限/保护属性，以及必要的原子性或一致性约束。建议把这些信息固化成带类型的依赖图，再由图生成地址译码、桥接器、协议合法化投影和审计清单。

RFuzz 侧的核心不变量是：**输入位宽、位到字段的归属和覆盖口径是实验 ABI，不是实现细节**。当前 Ibex 对照的 DUT 有效输入为 395 bit；字节级 RFuzz 封装提供 56 byte，即 448 bit，因此有 53 bit 传输填充。395 bit 必须连续、无重叠、无遗漏地映射到字段；53 bit 填充必须单独标记，不得算作 DUT 输入或有效变异覆盖。

## 2. 本仓库事实基线

### 2.1 本地证据索引

以下路径均相对于仓库根目录：

| 主题 | 本地文件 | 可确认的事实 |
|---|---|---|
| 多组件实验设计 | `docs/CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md` | Ibex + instruction/data RAM + timer + GPIO + UART + SPI；baseline direct slice 与 depaware projection 的边界 |
| 候选项目调查 | `docs/CANDIDATE_COMPONENT_PROJECTS_RVX_COREV_PULP_20260617.md` | RVX、CV32E40P、CORE-V MCU、PULPissimo、PULP 的本地调查和建议优先级 |
| 系统/组件案例 | `docs/MULTICOMPONENT_SCHEME5_TARGETS_AND_CASES_20260617.md` | Rocket/OpenTitan/CPU/IP/DSP 分类，以及多组件状态模型 |
| Ibex 395-bit 基线 | `docs/IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md` | RFuzz 56-byte 封装、395-bit 有效向量、baseline/pre/post 对照定义 |
| Ibex 约束原则 | `docs/IBEX_SCHEME5_BIT_CONSTRAINTS.md` | 固定位宽、纯输入位投影、协议关系与事件稀有度约束 |
| 精确 Ibex 映射 | `configs/designs/ibex_scheme6_relaxed_bit_constraints/harness/ibex_core_scheme6_relaxed_bit_constraints_harness.sv` | 395 bit 的逐字段切片和 relaxed 合法化 |
| 基础 CPU 配置 | `configs/designs/ibex/config.json`、`configs/designs/cva6/config.json`、`configs/designs/boom/config.json`、`configs/designs/xiangshan/config.json` | 仓库已有四类 CPU/系统目标入口，但第三方源码可用性和实际构建状态需由运行报告确认 |
| 组合 manifest | `configs/designs/ibex_protocol_composition/manifest.json` | 32/32 位目标，TL-UL/APB4/AXI4-Lite 的 RAM/timer/GPIO/UART/SPI 映射 |
| 组合状态说明 | `configs/designs/ibex_protocol_composition/README.md` | 夹具性质；upstream 缺失时应报告依赖不可用而不是成功编译 |
| 依赖清单范例 | `configs/designs/ibex_multicomponent_ip/manifests/ibex_common_ip_dependency_manifest.json` | components、connections、address_map、dependency_rules、fairness |
| 依赖 schema | `configs/designs/multicomponent_cpu_ip/manifests/dependency_manifest.schema.json` | 依赖 manifest 的最低结构要求 |
| 协议插件 | `src/myfuzz/protocols/plugins/*.json` | 当前插件字段、projection action、temporal rule 与版本声明 |
| MMIO RTL | `src/myfuzz/protocols/rtl/` | APB4、AXI4-Lite、TL-UL 的 bridge/target adapter 文件 |
| 输入 ABI | `src/myfuzz/harness/abi.py` | 端口选择、显式 fuzz disposition、固定打包、总位覆盖、ABI hash |
| 依赖投影 | `src/myfuzz/harness/projection.py`、`src/myfuzz/harness/depaware.py` | 不改变 raw ABI 几何；有界状态和有界时序动作；投影计数器 |
| 低资源运行 | `docs/low-resource-running.md` | 保守的候选/种子/构建并发与队列/内存约束原则 |

### 2.2 当前协议层能力

| 协议 | 本地描述 | 关键字段 | 本地时序约束 | 当前 RTL 适配器 |
|---|---|---|---|---|
| APB3 | `src/myfuzz/protocols/plugins/apb3.json` | PADDR/PSEL/PENABLE/PWRITE/PWDATA/PREADY/PRDATA，可选 PSLVERR | setup→access、access→response，最长 16 cycles | 无单独 APB3 RTL 文件；不能由 APB4 文件存在推断完全支持 |
| APB4 | `src/myfuzz/protocols/plugins/apb4.json` | APB3 + PPROT/PSTRB | setup→access、response，最长 16 cycles | `apb4_mmio_bridge.sv`、`apb4_mmio_target.sv` |
| AXI4-Lite | `src/myfuzz/protocols/plugins/axi4_lite.json` | AW/W/B 与 AR/R 五通道、PROT、STRB、RESP | 各握手和读写响应，最长 16 cycles | `axi4_lite_mmio_bridge.sv`、`axi4_lite_mmio_target.sv` |
| OBI v1 本地子集 | `src/myfuzz/protocols/plugins/obi.json` | req/gnt/addr/we/wdata/rvalid/rdata | grant/response 最长 16 cycles | 暂无 OBI↔MMIO RTL 文件 |
| ready-valid MMIO v1 | `src/myfuzz/protocols/plugins/ready_valid_mmio.json` | addr/write/wdata/valid/ready/rdata | response 最长 2 cycles | 作为统一语义接口；无同名独立 RTL 文件 |
| TL-UL v1 本地子集 | `src/myfuzz/protocols/plugins/tl_ul.json` | A/D 通道、opcode/size/source/mask/data/denied/corrupt | A/D 握手和响应，最长 16 cycles | `tl_ul_mmio_bridge.sv`、`tl_ul_mmio_target.sv` |

“插件存在”只表示 manifest/投影层认识这些字段；“RTL 文件存在”只表示有适配实现。完整支持仍应逐项证明：协议握手、backpressure 下 payload 稳定、一次请求只提交一次、错误映射、超时边界、参数合法性、lint、定向仿真与真实上游构建。

### 2.3 已批准 Ibex 协议组合

来自 `configs/designs/ibex_protocol_composition/manifest.json`：

```text
ibex_core (addr=32, data=32)
  ├─ ram0   @ 0x0000_0000 + 64 KiB, TL-UL v1, WORDS=4096
  ├─ timer0 @ 0x8001_0000 + 4 KiB,  APB4, IRQ 1
  ├─ gpio0  @ 0x8002_0000 + 4 KiB,  APB4, IRQ 2
  ├─ uart0  @ 0x8003_0000 + 4 KiB,  AXI4-Lite, IRQ 3
  └─ spi0   @ 0x8004_0000 + 4 KiB,  AXI4-Lite, IRQ 4
```

这张图是研究组合入口。RAM 的 64 KiB 区间与 `WORDS=4096`（若每 word 为 32 bit则为 16 KiB 实体容量）之间存在需要 flow 明确定义的“地址窗口 vs 实体深度”关系，不能靠名称猜测镜像、截断或错误响应策略。

## 3. 依赖字段词典

每个端点至少记录以下字段。未知值应写 `unknown`/`to_be_verified`，不可用默认常识补齐。

| 类别 | 建议字段 | 组合时必须回答的问题 |
|---|---|---|
| 身份 | `component_id`、`instance`、`module`、`kind`、`version/commit`、`license` | 具体是哪一个可复现版本？是 synthesizable RTL、generator 输出还是行为模型？ |
| ISA/CPU | `xlen`、`isa_extensions`、`privilege_modes`、`pmp/pma`、`mmu`、`cache/coherence`、`hart_count` | 外设寄存器是否可由该 hart/权限级访问？是否需要页表、cacheability 或 fence 语义？ |
| 地址 | `address_width`、`address_unit`、`base`、`size`、`decode_mask`、`alignment`、`region_type` | byte 还是 word 地址？自然对齐还是允许非对齐？窗口是否重叠/溢出？ |
| 数据 | `data_width`、`byte_enable_width`、`supported_sizes`、`endianness`、`atomic_granule` | lane 如何映射？窄访问和 partial write 如何处理？是否需要 endian swap/RMW？ |
| 事务 | `protocol_id/version`、`role`、`read/write`、`burst_types`、`max_burst_beats`、`max_outstanding`、`id_width`、`ordering`、`atomic/exclusive` | 对端发出的每种事务是否被接收？桥是否会拆 burst、压缩 ID 或改变顺序？ |
| 流控 | `request_accept`、`response_valid`、`backpressure`、`payload_stability`、`timeout`、`error_codes` | VALID/REQ 未握手时哪些信号必须稳定？响应能否被反压？超时由谁产生且 READY 同周期是否优先？ |
| 中断 | `irq_sources`、`irq_width`、`trigger`、`polarity`、`target_hart/context`、`priority`、`claim_complete`、`clear_semantics` | level/pulse/edge 如何保持与清除？是否需 PLIC/APLIC/IMSIC/CLINT/ACLINT？ |
| 时钟复位 | `clock_domain`、`frequency/ratio`、`reset_domain`、`polarity`、`sync/async`、`deassertion`、`power_domain` | 是否需要 CDC、reset synchronizer、isolation；复位期间 VALID/READY/IRQ 应为何值？ |
| 权限安全 | `prot/user/domain`、`privilege`、`secure/nonsecure`、`instruction/data`、`racl`、`integrity` | 属性是传递、重编码、固定还是拒绝？非法访问返回什么错误并是否产生 alert？ |
| 外部环境 | `pins`、`electrical_mode`、`frame_format`、`peer_timing`、`fifo_depth` | UART/SPI/I2C/GPIO 的输入不是任意独立 bit；何时形成合法帧、事件和 IRQ？ |
| 验证 | `source_url/path`、`assumptions`、`assertions`、`smoke/lint`、`known_limits` | 每个值来自源码、官方规范还是推断？哪项尚未由运行证据证明？ |

## 4. 常见 RISC-V CPU/系统目录

表中“接口/组合关注点”只用于候选筛选，最终值必须从锁定 commit 的生成参数和顶层端口重新抽取。所有外部链接访问于 2026-09-06。

| CPU/系统 | 类型与常见 ISA | 接口/组合关注点 | 建议优先级 | 官方来源 |
|---|---|---|---|---|
| Ibex | 小型 RV32 in-order core | 独立 instruction/data req-gnt-rvalid；32-bit 地址/数据；中断/debug/PMP 配置；active-low async reset | P0，当前主基线 | [Ibex Reference Guide](https://ibex-core.readthedocs.io/en/latest/03_reference/index.html)、[Core Integration](https://ibex-core.readthedocs.io/en/latest/02_user/integration.html) |
| CORE-V CV32E40P | RV32 embedded core | instruction/data OBI；请求/地址稳定；APU 可有未完成事务；IRQ/debug/boot 参数 | P0，替换 Ibex 的严肃 core | [CV32E40P manual](https://docs.openhwgroup.org/projects/cv32e40p-user-manual/en/latest/) |
| CORE-V CVE2/CV32E20 | 小型 RV32 embedded core | OBI、debug、CLIC 等配置随版本变化；必须锁定 OBI/ISA 版本 | P1 | [CVE2 repository](https://github.com/openhwgroup/cve2) |
| CVA6 | RV32/RV64 application core | AXI4/AXI5 atomics 子集、ID/未完成事务、cache/MMU、CLINT/IRQ、active-low reset | P1，协议和资源成本较高 | [CVA6 manual](https://docs.openhwgroup.org/projects/cva6-user-manual/01_cva6_user/index.html)、[AXI constraints](https://docs.openhwgroup.org/projects/cva6-user-manual/01_cva6_user/AXI_Interface.html) |
| Rocket Core / Rocket Chip | RV32/RV64 generator/system | TileLink Diplomacy、cache/coherence、debug、interrupt、clock crossing、TL↔AMBA converters；生成参数决定接口 | P2，系统级对照 | [Rocket Chip](https://github.com/chipsalliance/rocket-chip)、[Chipyard Rocket](https://chipyard.readthedocs.io/en/stable/Generators/Rocket.html) |
| BOOM/SonicBOOM | RV64 out-of-order core | 通常经 Chipyard/Rocket TileLink 系统集成；cache、MMU、未完成事务和乱序使环境更重 | P2，性能核对照 | [BOOM](https://github.com/riscv-boom/riscv-boom)、[BOOM docs](https://docs.boom-core.org/) |
| XiangShan | 高性能 RV64 系统生成项目 | XSTop、cache hierarchy、NoC/CHI 或版本相关总线、MMU、AIA/中断；必须使用生成后 RTL 与确切配置 | P3，重型系统目标 | [XiangShan](https://github.com/OpenXiangShan/XiangShan)、[XiangShan docs](https://docs.xiangshan.cc/) |
| PicoRV32 | 小型 RV32 Verilog core | native valid-ready、AXI4-Lite 或 Wishbone 变体；可选 IRQ/PCPI；单事务模型易做轻量 harness | P0/P1，快速交叉验证 | [PicoRV32](https://github.com/YosysHQ/picorv32) |
| VexRiscv | 可插件化 RV32 core | simple bus 可桥到 AXI4、AHB-Lite、Avalon、Wishbone；cache/MMU/IRQ/debug 均由 plugin 配置 | P1，协议覆盖广 | [VexRiscv](https://github.com/SpinalHDL/VexRiscv) |
| VexiiRiscv | VexRiscv 后继、可参数化 RISC-V core | AXI4、Wishbone、TileLink 等随 SoC 配置；需固定生成配置与插件集合 | P2 | [VexiiRiscv](https://github.com/SpinalHDL/VexiiRiscv) |
| SERV/Servant | bit-serial RV32 core/小 SoC | 常用 Wishbone；吞吐低但资源小，适合低资源长测和协议 sanity check | P1 | [SERV](https://github.com/olofk/serv) |
| RISC-V Sodor | 教学型 RV32 cores | 多种流水线模型；适合作为简单内存接口/ISA 对照，非完整 SoC | P1，教学基准 | [riscv-sodor](https://github.com/ucb-bar/riscv-sodor) |
| SweRV EH1/EH2/EL2 | 嵌入式 RV32 cores | AXI/AHB/interrupt/debug 取决于 core 与 support package；EH2 含双线程情形 | P2 | [Cores-SweRV](https://github.com/chipsalliance/Cores-SweRV)、[support package](https://github.com/chipsalliance/Cores-SweRV-Support-Package) |
| PULPissimo | 单核 MCU 平台 | CV32E40P 或 Ibex、uDMA、APB/AXI 生态、GPIO/UART/I2C/QSPI、interrupt/debug | P1，优先拆 IP 再组合 | [PULPissimo](https://github.com/pulp-platform/pulpissimo) |
| PULP | cluster/SoC 平台 | 多核 cluster、共享存储/互连、DMA 与多时钟；需要更强 ordering/coherence 描述 | P3 | [PULP](https://github.com/pulp-platform/pulp) |
| CORE-V MCU | CV32E40P MCU SoC | APB timer/GPIO、uDMA UART/I2C/QSPI、AXI/APB 互连；已有 top，也可拆组件 | P1 | [CORE-V MCU](https://github.com/openhwgroup/core-v-mcu) |
| OpenTitan Earlgrey | Ibex 安全 MCU SoC | TL-UL、RACL/完整性、alert、PLIC/timer、crypto、存储控制器和多时钟复位 | P2，安全与多 IP 对照 | [OpenTitan top](https://opentitan.org/book/hw/top_earlgrey/) |
| RVX | 小型 RV32 MCU 项目 | core + bus + RAM + UART + mtime + GPIO + SPI；仓库文档记录清晰地址图，外部项目版本须另行锁定 | P0，轻量多组件原型 | 本地调查：`docs/CANDIDATE_COMPONENT_PROJECTS_RVX_COREV_PULP_20260617.md` |

### 4.1 CPU 接入时必须抽取的端口事实

对每个 CPU 生成一份 `cpu_endpoint`，至少包含：

```yaml
cpu_endpoint:
  xlen: 32 | 64
  isa: [I, M, A, F, D, C, ...]
  privilege_modes: [M, S, U]
  instruction_ports: [...]
  data_ports: [...]
  address_width: N
  data_width: N
  address_unit: byte | word
  supported_access_sizes: [1, 2, 4, 8]
  alignment: natural | split_internal | trap | implementation_defined
  max_outstanding: {read: N, write: N}
  ordering: ...
  atomic_exclusive: ...
  irq: {software: ..., timer: ..., external: ..., fast: ..., nmi: ...}
  clock_reset: {clock_domain: ..., reset_polarity: ..., synchronous: ...}
  endian: little | big | bi
  protection: {pmp: ..., pma: ..., mmu: ..., bus_attributes: ...}
```

不能从“都是 RISC-V”推导总线兼容。ISA 兼容只约束软件可见执行语义，不保证顶层 memory bus、reset、interrupt controller 或 debug transport 兼容。

## 5. 常见协议外设目录

外设的“协议”有两层：CPU 侧寄存器总线协议与芯片外部线协议。两者必须建成不同端点，例如 UART 的 TL-UL device 端点和 RX/TX serial 端点不能合并为一个字段组。

| 组件类 | CPU/总线侧依赖 | 外部/功能侧依赖 | 中断/权限重点 | 官方实现或规范入口 |
|---|---|---|---|---|
| ROM/boot ROM | read-only、地址/数据宽、读延迟、错误/完整性 | image、reset vector、endianness | execute permission、secure boot | [OpenTitan ROM controller](https://opentitan.org/book/hw/ip/rom_ctrl/) |
| SRAM/controller | byte enable、读写延迟、partial write/RMW、ECC | 容量、初始化、scramble key | region permission、integrity alert | [OpenTitan SRAM controller](https://opentitan.org/book/hw/ip/sram_ctrl/) |
| Flash controller | MMIO + memory window、erase/program 粒度、长延迟 | flash model、busy/error | execute/read/write policy、alert | [OpenTitan flash controller](https://opentitan.org/book/hw/ip/flash_ctrl/) |
| UART | register bus、FIFO depth、baud divisor | RX/TX frame、data bits、parity、stop、line idle | RX/TX watermark、error IRQ | [OpenTitan UART](https://opentitan.org/book/hw/ip/uart/) |
| SPI host | MMIO、TX/RX FIFO、command queue | CPOL/CPHA、CS、bit order、word length、clock divider | watermark/error/event IRQ | [OpenTitan SPI host](https://opentitan.org/book/hw/ip/spi_host/) |
| SPI device | MMIO/FIFO/mailbox | host-driven SCK/CS/data、mode | upload/read-buffer/event IRQ | [OpenTitan SPI device](https://opentitan.org/book/hw/ip/spi_device/) |
| I2C host/device | MMIO、FIFO、command/status | START/address/RW/ACK/data/STOP、stretching、arbitration | watermark、NAK、timeout IRQ | [OpenTitan I2C](https://opentitan.org/book/hw/ip/i2c/) |
| GPIO | MMIO data/direction/mask | pin width、input synchronizer、output enable | edge/level、polarity、per-pin IRQ | [OpenTitan GPIO](https://opentitan.org/book/hw/ip/gpio/) |
| Timer/mtime | MMIO width与原子访问、tick source | timebase、prescale、compare | per-hart timer IRQ、clear/rearm | [OpenTitan rv_timer](https://opentitan.org/book/hw/ip/rv_timer/)、[ACLINT](https://github.com/riscvarchive/riscv-aclint) |
| PLIC | 32-bit MMIO、source/context count | level gateway、claim/complete | priority/threshold/enable/context | [RISC-V PLIC 1.0](https://github.com/riscv/riscv-plic-spec) |
| APLIC/IMSIC | MMIO/CSR、MSI 地址与 hart/guest ID | wired interrupt 或 MSI | M/S/VS context、delivery mode | [RISC-V AIA](https://github.com/riscv/riscv-aia) |
| Software interrupt | MMIO per hart | inter-hart event | machine/supervisor target | [ACLINT](https://github.com/riscvarchive/riscv-aclint) |
| DMA | control MMIO + bus host ports、burst/ID/outstanding | descriptor/data source/sink、trigger | completion/error IRQ、IOMMU/RACL | [OpenTitan DMA](https://opentitan.org/book/hw/ip/dma/) |
| PWM/advanced timer | MMIO period/duty/channel | output waveform、clock divisor | rollover/compare IRQ | [PULP APB advanced timer](https://github.com/pulp-platform/apb_adv_timer) |
| Watchdog | MMIO、always-on clock | bark/bite timing、pause policy | NMI/reset request、lock bits | [OpenTitan AON timer](https://opentitan.org/book/hw/ip/aon_timer/) |
| AES | MMIO/streaming data、key shares、status | block/mode/key length | done/idle/error、side-channel controls | [OpenTitan AES](https://opentitan.org/book/hw/ip/aes/) |
| HMAC | MMIO/message FIFO | message length/endian/padding | done/fifo/error IRQ | [OpenTitan HMAC](https://opentitan.org/book/hw/ip/hmac/) |
| KMAC/SHA3 | MMIO/application interfaces | entropy/masking、message/output length | done/error、keymgr/entropy dependencies | [OpenTitan KMAC](https://opentitan.org/book/hw/ip/kmac/) |
| Entropy source/CSRNG/EDN | MMIO + request/response networks | entropy health model、seed lifecycle | health/error IRQ、fatal alert | [OpenTitan entropy complex](https://opentitan.org/book/hw/ip/entropy_src/) |
| Alert handler | configuration MMIO | alert sender ping/ack、escalation receiver | class/state/timer/escalation | [OpenTitan alert handler](https://opentitan.org/book/hw/top_earlgrey/ip_autogen/alert_handler/) |
| Debug module | system bus access、DMI/JTAG | halt/resume/reset、abstract command | authentication/lifecycle、debug privilege | [RISC-V Debug Specification](https://github.com/riscv/riscv-debug-spec)、[OpenTitan rv_dm](https://opentitan.org/book/hw/ip/rv_dm/) |
| USB device | MMIO/FIFO/DMA style buffers | USB packet/endpoint/timing | endpoint/event IRQ | [OpenTitan usbdev](https://opentitan.org/book/hw/ip/usbdev/) |
| Mailbox | MMIO from two domains/hosts | message ownership/doorbell | access policy、doorbell IRQ | [OpenTitan mailbox](https://opentitan.org/book/hw/ip/mbx/) |
| IOMMU | command/fault queues、translation requests | page tables、device/process IDs | privilege、fault IRQ、ATS/invalidation | [RISC-V IOMMU](https://github.com/riscv-non-isa/riscv-iommu) |
| Cache/scratchpad | line/beat width、burst、coherence、ECC | replacement/refill/writeback | cacheability/PMA、flush/invalidate | [Rocket inclusive cache](https://github.com/chipsalliance/rocket-chip-inclusive-cache) |
| Ethernet MAC | MMIO + DMA descriptor/data paths | MII/RMII/GMII frames、CRC | RX/TX/error IRQ、DMA permissions | 候选实现必须单独锁定；不要把外部 MAC 协议等同于 MMIO 总线 |
| CAN | MMIO + message RAM | bit timing、arbitration、frames、ACK | RX/TX/error/bus-off IRQ | 候选实现必须单独锁定并记录 CAN 版本 |

外设合法化应围绕“可达状态”而不是固定脚本：raw bits 仍控制配置值、payload、时延和事件选择；投影层只补足 START/ACK/STOP、FIFO 可用性、status→IRQ、busy→done 等必要依赖。

## 6. 常见协议与桥接组件目录

### 6.1 协议能力矩阵

| 协议 | 地址/数据与对齐 | 突发/并发 | 响应与顺序 | 权限/时钟复位 | 官方来源 |
|---|---|---|---|---|---|
| AXI4 | 参数化地址/数据，size/strobe 支持窄或非对齐语义 | burst、多个 outstanding、ID、可乱序返回 | AW/W 独立，B/R 可反压；同 ID/目的地有顺序规则 | PROT/CACHE/QOS/REGION/USER；ACLK/ARESETn | [Arm AXI/ACE IHI 0022](https://developer.arm.com/documentation/ihi0022/latest/) |
| AXI4-Lite | 标准数据宽 32/64，full-width access + WSTRB；无 LEN/SIZE/BURST | 每笔单 beat、无 ID；实现仍需声明可接受的 outstanding 数 | AW 与 W 独立握手；B、AR/R 独立反压 | PROT；ACLK/ARESETn | [Arm AXI/ACE IHI 0022, Annex B](https://developer.arm.com/documentation/ihi0022/latest/) |
| APB3 | 常用于低带宽寄存器；PADDR/PWDATA/PRDATA | 无 burst，单 setup/access 事务 | PREADY wait states、PSLVERR | 单时钟；reset 依实现；无 APB4 PPROT/PSTRB | [Arm APB IHI 0024](https://developer.arm.com/documentation/ihi0024/latest/) |
| APB4 | APB3 + PSTRB/PPROT，需声明 data/addr width | 无 burst、通常单事务 | setup→access；控制与 payload 在等待期间稳定 | PPROT 编码权限/安全/指令属性 | [Arm APB IHI 0024](https://developer.arm.com/documentation/ihi0024/latest/) |
| AHB-Lite | 地址/数据参数化、HSIZE/HADDR 对齐 | 支持 burst，单 manager、流水地址/数据阶段 | HREADY/HRESP；地址和数据相位错开 | HPROT；HCLK/HRESETn | [Arm AHB-Lite IHI 0033](https://developer.arm.com/documentation/ihi0033/latest/) |
| TL-UL | OpenTitan 常用 AW=32、DW=32，可扩展 64；size/mask | 无 burst；split A/D；可多个 outstanding，source 匹配 | 每周期最多一请求/响应；denied/corrupt | user 扩展可带 instruction/data、完整性和安全属性 | [OpenTitan TL-UL](https://opentitan.org/book/hw/ip/tlul/index.html) |
| OBI | 版本化、可选字段多；地址/数据/BE 必须按 profile 声明 | 可配置 outstanding/ID；简单 profile 常为有限并发 | req/gnt 与 response phase；请求不可随意撤回，payload 稳定 | protection/user/integrity 依 OBI 版本/profile | [OpenHW OBI](https://github.com/openhwgroup/obi) |
| Wishbone B4 | 参数化数据宽与 granularity；byte/word address 需 datasheet 明示 | classic/pipelined/block/RMW 由端点声明 | ACK/ERR/RTY；ordering 依 cycle 类型 | CLK/RST 与 tags 可选；端序必须在 datasheet 声明 | [Wishbone B4](https://cdn.opencores.org/downloads/wbspec_b4.pdf) |
| Avalon-MM | 地址 1–64 bit、数据 8–1024 bit 可选；addressUnits 可为 symbols/words | 可选 burst、pipelined reads、pending transactions | waitrequest/readdatavalid/writeresponsevalid | protection 非统一必选；clock/reset 为关联接口 | [Avalon Interface Specifications](https://docs.altera.com/r/docs/683091/22.3/avalon-interface-specifications/introduction-to-the-avalon-interface-specifications) |
| ready-valid MMIO | 项目内统一单请求接口，width 由参数决定 | 本地语义应明确单 outstanding、无 burst | `valid && ready` 提交；读数据/错误与完成同义 | 无标准 PROT/CDC；必须由 wrapper 补充 | 本地：`src/myfuzz/protocols/plugins/ready_valid_mmio.json` |

### 6.2 桥接器/互连候选

| 组件 | 主要作用 | 不能丢失的依赖信息 | 来源/本地位置 |
|---|---|---|---|
| APB4↔统一 MMIO | setup/access 转单请求；target 反向映射 | PSTRB→BE、PPROT policy、PSLVERR、等待期间稳定、一次提交 | `src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv`、`apb4_mmio_target.sv` |
| AXI4-Lite↔统一 MMIO | 合并独立 AW/W；拆分 B；AR→R | AW/W 任意先后、各自 payload latch、单提交、B/R backpressure、RESP 映射 | `src/myfuzz/protocols/rtl/axi4_lite_mmio_bridge.sv`、`axi4_lite_mmio_target.sv` |
| TL-UL↔统一 MMIO | A opcode/size/mask 转请求，D 返回 | source/size 保留、Get/Put legality、denied/corrupt、D backpressure | `src/myfuzz/protocols/rtl/tl_ul_mmio_bridge.sv`、`tl_ul_mmio_target.sv` |
| AXI width converter | 数据宽上/下转换 | address/size/strobe 重排、burst split、ID/last、端序不应暗改 | [PULP AXI `axi_dw_converter`](https://github.com/pulp-platform/axi) |
| AXI-Lite width converter | Lite 数据宽转换 | 单 beat 访问、WSTRB/lane、错误聚合 | [PULP AXI `axi_lite_dw_converter`](https://github.com/pulp-platform/axi) |
| AXI→AXI-Lite | 去 burst/ID/atomic | burst 分解、outstanding 限流、ID/order、unsupported atomic error | [PULP AXI](https://github.com/pulp-platform/axi) |
| AXI-Lite→APB4 | 五通道转 setup/access | AW/W 汇合、APB 串行化、response、timeout | [PULP AXI `axi_lite_to_apb`](https://github.com/pulp-platform/axi) |
| AXI crossbar/demux/mux | 地址路由和仲裁 | 地址窗口、ID 扩展/路由、ordering、backpressure、公平性 | [PULP AXI](https://github.com/pulp-platform/axi) |
| AXI ID remap/serialize | 缩小 ID 或并发度 | collision、每 ID 顺序、最大 outstanding、deadlock | [PULP AXI](https://github.com/pulp-platform/axi) |
| AXI FIFO/cut/register slice | 解组合路径/缓存通道 | 五通道独立深度、fall-through、reset flush、payload stability | [PULP AXI](https://github.com/pulp-platform/axi) |
| AXI CDC/isolation | 跨时钟/电源域 | async FIFO depth、reset handshake、in-flight drain、isolation value | [PULP AXI](https://github.com/pulp-platform/axi) |
| AXI atomic adapter | 实现 RISC-V AMO | exclusive/ATOP 能力、锁粒度、错误/排序、downstream 不支持策略 | [PULP RISC-V atomics](https://github.com/pulp-platform/axi_riscv_atomics) |
| TL-UL 1:N socket/xbar | 地址译码到多个 device | one-hot select、default error、source route、跨域 | [OpenTitan TL-UL primitives](https://opentitan.org/book/hw/ip/tlul/index.html) |
| TL-UL M:1 socket | 多 host 仲裁 | source ID、fairness、response route、starvation | [OpenTitan TL-UL primitives](https://opentitan.org/book/hw/ip/tlul/index.html) |
| TL-UL sync/async FIFO | 弹性或 CDC | request/response FIFO 独立、pass-through、reset/flush | [OpenTitan TL-UL primitives](https://opentitan.org/book/hw/ip/tlul/index.html) |
| TL-UL SRAM adapter | TL 请求到 SRAM req/gnt/rvalid | partial write RMW、request metadata FIFO、read mask、error/integrity | [OpenTitan TL-UL SRAM adapter](https://opentitan.org/book/hw/ip/tlul/index.html) |
| Rocket Diplomacy widgets | width、fragment、buffer、source shrink、FIFO/order fix、TL↔AMBA | edge parameters是生成期事实；不能只看最终信号名 | [Rocket Chip](https://github.com/chipsalliance/rocket-chip)、[Chipyard Diplomacy](https://chipyard.readthedocs.io/en/stable/TileLink-Diplomacy-Reference/) |
| OBI↔AXI/AHB/APB | CORE-V memory interface 接系统总线 | OBI profile/optional fields、outstanding、response errors、address stability | [OpenHW OBI](https://github.com/openhwgroup/obi) |
| Wishbone↔AXI/APB | 开源小核/外设互联 | classic vs pipelined、word/byte addressing、SEL/strobe、ERR/RTY | [Wishbone B4](https://cdn.opencores.org/downloads/wbspec_b4.pdf) |
| Default/error target | 未映射地址确定性终止 | decode error code、响应时限、权限错误区分、不得挂死 | 本地可由统一 MMIO error 语义扩展；PULP `axi_err_slv` 可作参考 |

桥接器的验证优先级高于普通外设：它同时改变协议、时序和并发语义，一个“能读写寄存器”的 smoke test 不能证明 backpressure、独立通道、超时、顺序和错误路径正确。

## 7. CPU + 外设的依赖感知图

### 7.1 图模型

建议使用有向多重图 `G=(V,E)`，同一对节点可同时有 request、response、IRQ、clock 和 reset 多条边。

节点类型：

```text
cpu_hart, cpu_port, cache, memory, peripheral,
interconnect, bridge, irq_controller, clock_domain,
reset_domain, protection_controller, external_peer, error_target
```

边类型：

```text
request, response, snoop/coherence, interrupt, clock,
reset, power/isolation, permission, external_serial, alert
```

每个总线端点保存第 3 节字段；每条边再保存 `protocol/version`、源/目的 role、映射函数、latency bound、buffer depth、CDC/权限变换和证据来源。`components` 说明“有什么”，`connections` 说明“怎么连”，`address_map` 说明“何时选中”，`dependency_rules` 说明“哪些输入关系可以投影”，`fairness` 说明“怎样比较”。本地 schema 已覆盖这五个骨架，但建议扩展上述 typed attributes。

### 7.2 兼容性判定

每条 CPU→外设路径都执行以下判定，任何一项失败都必须插桥或拒绝组合：

1. `protocol(source) == protocol(sink)`；否则存在已批准的协议桥，且桥的两侧版本/profile 均匹配。
2. 地址宽度可无歧义转换；base/size 对齐且窗口不重叠、不溢出；word/byte address 单位已归一化。
3. 数据宽相等，或 width converter 能正确映射 access size、byte enable、lane 和 response。
4. source 可能生成的 burst/atomic/exclusive 全被 sink 接受，或可由 bridge 合法拆分/拒绝。
5. `source.max_outstanding <= path.capacity`；若不满足，插入节流/ID remap/FIFO，并证明无死锁。
6. request/response ordering、ID/source tag 在所有 fork、arbiter、CDC 和 bridge 后仍可恢复。
7. response error 有总映射；未映射、权限失败、timeout 均能终止而不静默成功。
8. clock/reset 域兼容；异步路径有 CDC，复位释放和 in-flight transaction 处理已定义。
9. endian 与 address lane 兼容；若转换，明确交换发生在何处并避免地址/数据双重交换。
10. privilege/security/instruction-data 属性可传递或由 policy 明确降级；缺失属性不能默认为授权。
11. IRQ source 的 trigger/polarity/clear 与 controller target/context 匹配；pulse 不能在 CDC 或屏蔽期间丢失。
12. CPU cache/PMA/MMU 对 MMIO region 的类型正确；device access 不被错误缓存、合并或重排。

### 7.3 自动组合流程

```text
锁定组件版本与生成参数
  → 从 RTL/manifest 抽取端口事实
  → 绑定官方协议 profile
  → 建立 typed nodes/edges
  → 求解宽度、地址、burst、并发、clock/reset、权限、IRQ 约束
  → 插入最少的 bridge/CDC/arbiter/error target
  → 分配无冲突地址与 IRQ
  → 生成 direct 与 depaware 两条 harness
  → 生成 assertions + lint/smoke/negative tests
  → 固化图 hash、ABI hash、coverage universe hash
```

自动组合器只能使用白名单组件与白名单转换。不能因为端口名字相似就自动连接；`valid/ready`、`req/gnt/rvalid`、APB、AXI 和 TL-UL 的事务边界不同。

### 7.4 当前 Ibex 组合的图示例

```text
[clock/reset] ───────────────► [Ibex + decode]
                                     │ instruction/data request
             ┌───────────────────────┼────────────────────────┐
             │                       │                        │
        [TL-UL bridge]          [APB4 bridge]          [AXI4-Lite bridge]
             │                       │                        │
          [RAM0]              [timer0][gpio0]           [uart0][spi0]
                                  │      │                  │     │
                                  └──────┴──── IRQ fabric ──┴─────┘
                                                │
                                                ▼
                                              [Ibex]
```

还需在图中补足的关键事实包括：Ibex 原生 instruction/data 接口到三类总线的具体 host bridge、RAM window/depth 策略、IRQ 1..4 如何映射到 Ibex timer/external/fast pins、PPROT/AWPROT/ARPROT 的生成规则、默认错误 target、所有 adapter 的 timeout 和 reset 行为。

## 8. RFuzz 输入结构：正确性与泛化性

### 8.1 三层输入模型

必须区分：

```text
transport bytes: 56 × 8 = 448 bit
effective raw ABI: 395 bit
projected DUT fields: 395 bit 的确定性解释/合法化结果
```

本地历史文档 `docs/IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md` 记录自动 harness 把 `io_input_bytes_0..55` 拼成 padded input，再切出 395-bit `rfuzz_input_bits`。当前手写 scheme6 harness 的接口直接是 `logic [394:0] rfuzz_input_bits`。因此：

- `448 - 395 = 53` bit 是字节传输层填充/余量，不是额外 DUT fuzz 字段。
- 生成产物必须记录 395 bit 从 448 bit 的具体 slice、byte order 和 padding canonical value；仅凭文档中的省略表达式不能推断填充位位于高端还是低端。
- corpus hash/去重应基于明确版本的 transport normalization；覆盖效率应以 395-bit effective ABI 为分母语义，不能奖励改变无效 padding。
- 手写 395-bit harness 与自动 56-byte harness 比较时，必须先证明二者 effective vector 完全一致。

### 8.2 Ibex 395-bit 精确映射

来源：`configs/designs/ibex_scheme6_relaxed_bit_constraints/harness/ibex_core_scheme6_relaxed_bit_constraints_harness.sv`。

| raw bits | 宽度 | 字段 | 类型 |
|---|---:|---|---|
| 394:331 | 64 | `ic_data_rdata_i[0]` | cache/memory response data |
| 330:267 | 64 | `ic_data_rdata_i[1]` | cache/memory response data |
| 266:245 | 22 | `ic_tag_rdata_i[0]` | cache tag RAM response |
| 244:223 | 22 | `ic_tag_rdata_i[1]` | cache tag RAM response |
| 222:191 | 32 | `boot_addr_i` | static/boot address |
| 190:159 | 32 | `data_rdata_i` | data response payload |
| 158:127 | 32 | `hart_id_i` | identity/configuration |
| 126:95 | 32 | `instr_rdata_i` | instruction response payload |
| 94:63 | 32 | `rf_rdata_a_ecc_i` | register-file/ECC response payload |
| 62:31 | 32 | `rf_rdata_b_ecc_i` | register-file/ECC response payload |
| 30:16 | 15 | `irq_fast_i` | asynchronous event vector |
| 15:12 | 4 | `fetch_enable_i` | multibit fetch control |
| 11 | 1 | `data_err_i` | data response status |
| 10 | 1 | `data_gnt_i` | data request acceptance |
| 9 | 1 | `data_rvalid_i` | data response valid |
| 8 | 1 | `debug_req_i` | asynchronous debug event |
| 7 | 1 | `ic_scr_key_valid_i` | cache key handshake/status |
| 6 | 1 | `instr_err_i` | instruction response status |
| 5 | 1 | `instr_gnt_i` | instruction request acceptance |
| 4 | 1 | `instr_rvalid_i` | instruction response valid |
| 3 | 1 | `irq_external_i` | external IRQ |
| 2 | 1 | `irq_nm_i` | NMI |
| 1 | 1 | `irq_software_i` | software IRQ |
| 0 | 1 | `irq_timer_i` | timer IRQ |

宽度和为：`64+64+22+22+32+32+32+32+32+32+15+4+12×1 = 395`。区间从 394 连续下降到 0，没有空洞或重叠。

这里的“字段类型”很重要：data payload 可接近均匀随机；`hart_id`/boot/config 通常应稳定或低频改变；grant/valid/error 是有关联的协议控制；IRQ/debug 是异步事件。把所有字段都当作同分布独立 bit 会制造大量无意义状态。

### 8.3 固定位宽与总位覆盖不变量

本地 `src/myfuzz/harness/abi.py` 已体现可推广规则：

1. 只有显式标记 fuzzable 且方向为 input/inout、非 clock/reset 的端口进入 raw ABI。
2. 每个非 fuzzable input 必须有 constant/reset 绑定，避免悬空或隐式 X。
3. clock/reset 必须有显式语义、active level；reset 还需声明 synchronous。
4. selected ports 按稳定 `port_id` 排序，逐字段连续打包。
5. 声明的 `raw_width` 必须等于字段宽度总和。
6. `validate_total_use()` 要求 raw slices 连续、非空、目标 slice 有效并覆盖整个 `raw_width`。
7. destinations/mapping 生成内容 hash；depaware action 可以改变解释类别，但不得改变 `(raw_lo, raw_hi, destination_id, destination_lo)` 几何。

还应补充工程级检查：每个 bit 的使用次数恰为 1；signed/unsigned、packed/unpacked array、enum/MuBi/one-hot、byte lane、X/Z 处置必须明确；同一个 raw bit 若用于多个投影输出，应以“派生依赖”记录，而不能伪装成多个独立 destination。

### 8.4 协议合法化原则

合法化函数应是可审计的确定性函数：

```text
(raw_sample, bounded_projection_state) -> driven_fields, next_state, counters
```

它必须满足：

- **不隐藏改变 ABI**：raw width、slice、field order 和 ABI hash 固定；变的是投影函数。
- **不使用 DUT 输出作弊**：若实验定义为 input-only projection，不能按内部覆盖或 DUT 私有状态反推下一输入；必要的总线响应模型应作为公开环境状态并在 baseline/depaware 中等价说明。
- **保持可控性**：raw bits 仍决定地址区域、数据、访问类型、等待时延和事件；mask/fold/gate 不应把大字段坍缩为少数固定模板。
- **请求合法**：地址落在已分配窗口、按 access size 对齐；byte enable 与 size/address lane 一致；write data 在提交前稳定。
- **握手合法**：VALID/REQ 一旦发出，在 READY/GNT 前保持 asserted，相关 payload 稳定；response 只对应已接受请求。
- **通道独立**：AXI4-Lite AW/W 可任意先后且各只接受一次；收齐后只提交一次 MMIO write；B/R 在下游 ready 低时保持 VALID 与 payload。
- **时序有界**：每个等待、延迟选择和 timeout 有有限上界；边界同周期出现 READY/response 时，正常完成优先于 timeout。
- **错误相关**：error 只在对应有效 response 上有意义；未映射、权限、下游错误和 timeout 的编码明确。
- **事件相关**：IRQ 来源于 pending/status 且有 clear/claim/complete 路径；NMI/debug/alert 的优先级和稀有度可调但仍由 raw bits 控制。
- **复位确定**：复位清空 pending/valid/latched payload/counters；释放后无 X、无伪响应。
- **统计可见**：记录 projection、correction category、protocol event、timeout、violation、no-progress，而不是只报告最终覆盖率。

本地 `src/myfuzz/harness/projection.py` 把 action 限为 direct/mask/gate/delay_select/fold_xor，将状态限制在 4096 bit、时序上界限制在 65535 cycles，并要求 temporal action 有有限 `max_cycles`。这些是防止动态资源和无限等待的良好下界，不代表每个具体协议的 16-cycle 策略已经由规范规定；16 是本地实验策略，必须在报告中标注。

### 8.5 跨 CPU 公平性

公平比较分两层，不能混为一个数字：

**同一 CPU 的策略对照**必须保持：

- 相同 top、RTL commit、参数、clock/reset、运行时长、seed 集、资源限制；
- 相同 effective raw width、raw slice geometry、mutation engine 与 transport padding；
- 相同 instrumentation、coverage point 集、coverage universe hash 和统计分母；
- 相同外设/存储模型与初始状态；只允许 projection policy 不同；
- 同时报告 direct 与 depaware 的 ABI hash、projection plan hash 和 correction counters。

**不同 CPU 的横向比较**通常无法同时保持相同物理输入宽度，因为端口和系统复杂度不同。应并列报告：

1. native-ABI 结果：每个 CPU 使用完整、正确的原生环境，不假装位宽相同；
2. normalized-semantic 结果：给每类语义字段相同预算，例如 instruction/data payload、address/access、latency、IRQ/debug、external peripheral event；
3. 资源归一化结果：相同 wall time、CPU affinity/worker 数、内存上限，并报告 executions/cycles；
4. coverage 只做 CPU 内归一化（covered/该 CPU universe），跨 CPU 不直接比较绝对 coverage point 数；
5. 另报 reachability 指标：retired instructions、accepted requests、responses、exceptions、IRQ claims、peripheral transactions、unique states。

禁止通过删除难驱动端口、给某 CPU 预装固定 directed program、扩大某一方 seed corpus 或放宽某一方资源来制造“公平”。若为进入可达状态必须提供 boot image，它应成为共享、版本化实验条件，而不是隐藏在 harness 中。

### 8.6 长测元数据最低集合

每个 run 根目录至少固化以下内容：

```yaml
identity:
  run_id: ...
  repository_commit: ...
  dirty_worktree: false
  source_lock: [{component, url, commit, content_hash}]
  tool_versions: {python, verilator, iverilog, compiler, rfuzz}
design:
  top: ...
  cpu: {name, config, xlen, isa, hart_count}
  components_manifest_hash: ...
  dependency_graph_hash: ...
  address_map: ...
  irq_map: ...
  protocol_profiles: ...
harness:
  mode: direct | depaware
  transport_bytes: ...
  raw_width: ...
  padding_bits: ...
  padding_location_and_value: ...
  byte_order: ...
  abi_hash: ...
  projection_plan_hash: ...
  projection_state_bits: ...
  max_temporal_cycles: ...
coverage:
  instrumentation_config_hash: ...
  instrumented_rtl_hash: ...
  coverage_universe_hash: ...
  coverage_metadata_hash: ...
campaign:
  seed: ...
  corpus_hash: ...
  duration_seconds: ...
  checkpoint_seconds: ...
  max_restarts: ...
  resume_from: ...
resources:
  workers: ...
  build_jobs: ...
  soft_memory_mib: ...
  hard_memory_mib: ...
  token_memory_mib: ...
  waveform_enabled: false
  cpu_affinity: ...
results:
  started_at: ...
  ended_at: ...
  exit_status: ...
  dependency_status: ...
  peak_rss_bytes: ...
  executions: ...
  simulated_cycles: ...
  queue_entries: ...
  crashes: ...
  unique_crashes: ...
  covered_points: ...
  protocol_event_count: ...
  timeout_count: ...
  violation_count: ...
  no_progress_count: ...
  correction_counts: ...
artifacts:
  logs: ...
  checkpoints: ...
  queue_hashes: ...
  crash_reproducers: ...
```

checkpoint 必须原子写入并带 schema/version/hash；restart 与 resume 要记录原因、父 checkpoint 和累计/本段时间。依赖缺失、编译失败、lint 失败、仿真启动失败应分别编码，不能统一写成“0 coverage”或“成功结束”。长测默认不生成 VCD/waveform；崩溃复现时才按需短窗口开启。

## 9. 验收清单

在把一个新 CPU + 外设组合作为 RFuzz 长测目标前，应全部回答“是”：

- [ ] 所有 component/version/commit/license 已锁定，upstream 缺失会显式失败。
- [ ] 每个端点的地址/数据宽度、address unit、对齐、access size、byte enable、端序已声明。
- [ ] burst、ID、outstanding、ordering、atomic/exclusive/coherence 能力沿整条路径可满足。
- [ ] 地址窗口不重叠，default error target 可终止非法访问。
- [ ] IRQ trigger/polarity/target/clear/claim-complete 与 CPU/controller 匹配。
- [ ] clock/reset/power domain 有显式 CDC、复位释放和 in-flight policy。
- [ ] PROT/USER/RACL/PMP/PMA/MMU/完整性属性有传递或拒绝规则。
- [ ] request 与 response 在 backpressure 下保持 VALID 和 payload；每个请求只提交一次。
- [ ] timeout 有界，边界同周期正常响应优先，错误编码可追踪。
- [ ] raw ABI 连续、无重叠、全覆盖；padding 单列；clock/reset 不进入 fuzz bits。
- [ ] direct 与 depaware 的 ABI/coverage universe/资源/seed 公平性证据可机器校验。
- [ ] lint、定向协议测试、负向测试、短 smoke 均通过，且报告不夸大为完整长测。
- [ ] 长测 manifest、checkpoint、资源峰值、correction/timeout/no-progress/crash 元数据完整。

## 10. 官方资料索引

下列资料均访问于 2026-09-06；实现时应进一步锁定规范版本或 Git commit：

- RISC-V ISA：[riscv-isa-manual](https://github.com/riscv/riscv-isa-manual)。
- RISC-V privileged/硬件规范入口：[RISC-V Technical Specifications](https://riscv.org/technical/specifications/)。
- RISC-V PLIC：[riscv-plic-spec](https://github.com/riscv/riscv-plic-spec)。
- RISC-V ACLINT：[riscv-aclint archive](https://github.com/riscvarchive/riscv-aclint)。
- RISC-V AIA：[riscv-aia](https://github.com/riscv/riscv-aia)。
- RISC-V Debug：[riscv-debug-spec](https://github.com/riscv/riscv-debug-spec)。
- Arm AMBA AXI/ACE：[IHI 0022](https://developer.arm.com/documentation/ihi0022/latest/)。
- Arm AMBA APB：[IHI 0024](https://developer.arm.com/documentation/ihi0024/latest/)。
- Arm AMBA AHB-Lite：[IHI 0033](https://developer.arm.com/documentation/ihi0033/latest/)。
- OpenHW OBI：[openhwgroup/obi](https://github.com/openhwgroup/obi)。
- OpenTitan TL-UL 与 bus primitives：[TL-UL Bus](https://opentitan.org/book/hw/ip/tlul/index.html)。
- Wishbone B4：[wbspec_b4.pdf](https://cdn.opencores.org/downloads/wbspec_b4.pdf)。
- Avalon：[Avalon Interface Specifications](https://docs.altera.com/r/docs/683091/22.3/avalon-interface-specifications/introduction-to-the-avalon-interface-specifications)。
- PULP AXI 组件库：[pulp-platform/axi](https://github.com/pulp-platform/axi)。
- OpenTitan IP 总目录：[Hardware IP Blocks](https://opentitan.org/book/hw/ip/index.html)。

## 11. 使用边界

本文是后续设计和实验的字段词典与审计基线，不是支持声明。候选表中的项目只有在完成“锁定源码 → 提取事实 → 图求解 → 生成/手写桥接 → lint/仿真 → 真实 flow 报告”后，才能进入本仓库支持矩阵。尤其不能因存在 design config、manifest 或 RTL 文件，就声称第三方 upstream 已安装、RTL 已成功编译或一小时/多小时 campaign 已完成。
