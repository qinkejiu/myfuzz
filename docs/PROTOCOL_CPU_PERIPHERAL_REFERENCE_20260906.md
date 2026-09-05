# 协议、CPU 与外设组件参考规范

版本：`2026-09-06`
用途：依赖感知的 CPU + 外设多组件模糊测试系统的协议、组件和输入 ABI 基线。
状态：研究基线；后续代码只能声明“已实现”的子集，不能把本文件的参考目录自动视为运行时能力。

## 0. 使用范围和证据等级

本文件把协议和组件描述为可组合的“契约”，供后续协议编译器、依赖图构建器、harness 生成器和长时间测试调度器使用。它不是某一个 CPU 的综合手册，也不替代各协议的规范原文。

每一项能力使用下列标签：

| 标签 | 含义 |
|---|---|
| `core-native` | CPU RTL 本体直接暴露该事务接口；不需要 SoC 总线包装器。 |
| `soc-native` | CPU 的常见 SoC/平台集成直接使用该协议，但未必是 CPU 核心端口。 |
| `bridge` | 可以通过已声明的适配器或桥接器连接，不能当作核心原生能力。 |
| `reference` | 本文件记录了协议/组件，当前运行时可能还没有插件。 |
| `verify-required` | 依赖具体版本、参数或生成的 SoC；组合前必须从事实文件或 manifest 证明。 |

“支持”必须带上下文。例如，Ibex 的 instruction/data 请求-应答端口不是 APB4 或 AXI4-Lite；OpenTitan 可以把 Ibex 放进使用 TL-UL 的系统。CVA6 的外部内存接口是 AXI4；BOOM 通常借助 Rocket Chip/TileLink 集成。三者不能仅凭项目名称被归入同一个协议插件。

本文件优先采用项目官方文档、协议发布组织和规范原文作为证据；访问日期统一为 `2026-09-06`。若项目文档没有固定的片上外设协议，标记为 `verify-required`，后续以生成的 `composition_ir`、端口 ABI 和协议 manifest 为准。

## 1. 常见协议目录

第一阶段至少覆盖以下八种内存映射/片上互连协议：APB4、AXI4-Lite、AXI4、AHB-Lite、TileLink-UL、OBI、Wishbone Classic/B3、Avalon-MM。另将 AXI-Stream 和 AMBA CHI 作为流式/一致性方向的后续协议，不强行塞入第一阶段的 MMIO 插件。

| 协议 | 类别 | 典型拓扑 | 事务核心 | 常见外设/场景 | 本项目第一阶段状态 |
|---|---|---|---|---|---|
| APB4 | 低带宽寄存器总线 | 一个 bridge + 多个 target | `SETUP -> ACCESS -> COMPLETE` | UART、GPIO、Timer、PWM、RTC | 已有插件/桥接方向；只生成无 burst、无 outstanding 合法事务 |
| AXI4-Lite | 简化内存映射 | 一个 manager + 多个 subordinate | 独立读写五通道 | 控制寄存器、DMA 配置、调试寄存器 | 已有插件/桥接方向；当前 profile 限制单 outstanding |
| AXI4 | 完整内存映射 | 高吞吐 manager/interconnect/subordinate | 五通道、burst、ID、乱序响应 | DDR、DMA、PCIe、Ethernet、缓存接口 | 参考协议；第一阶段拒绝 burst/full AXI 事务 |
| AHB-Lite | AMBA 单主机总线 | 单 master + 多 slave | 地址/控制相位 + 数据相位 | MCU SRAM、Flash、低复杂度外设 | 参考；可作为 SweRV/VeeR 等 CPU 的 native/integration 协议 |
| TileLink-UL | RISC-V 生态轻量 MMIO | source + sink/interconnect | `A` 请求与 `D` 响应解耦 | OpenTitan 控制外设、寄存器窗口 | 已有插件/桥接方向；单 outstanding、无重排 |
| OBI | CORE-V/OpenHW 本地接口 | instruction/data master + target | `req/gnt/rvalid` | CV32E40P/E40S 指令、数据、APU | 参考/桥接；版本字段必须在 manifest 中明确 |
| Wishbone Classic/B3 | 开放 FPGA/SoC 总线 | master + slave/interconnect | `CYC/STB` 保持到 ACK/ERR/RTY | FPGA 外设、软核 CPU、SRAM | 参考；Classic 与 Registered/管线模式分开 |
| Avalon-MM | Intel FPGA 内存映射 | master + slave | `waitrequest` 背压与可选 `readdatavalid` | FPGA RAM、PIO、DMA、定制 IP | 参考；等待/读响应属性必须显式声明 |
| AXI-Stream | 无地址流接口 | producer + consumer | `TVALID/TREADY` beat 握手 | Ethernet、视频、DSP、DMA 数据流 | 后续；可与 AXI4 memory-mapped 通过 DMA 组合 |
| AMBA CHI | 一致性/高性能互连 | requester/home/node | 请求、数据、响应、snoop | 多核缓存一致性、服务器/高端 SoC | 后续；不与 MMIO 协议混用 |

### 1.1 当前仓库运行时与参考目录的区别

当前分支已经登记的协议插件 ID 是 `ready-valid-mmio`、`apb`、`axi4-lite`、`obi`、`tl-ul`；`apb` 以 version 3/4 两个 profile 存在。当前 RTL 适配器文件覆盖 APB4、AXI4-Lite、TL-UL；`ready-valid-mmio` 和 OBI 主要作为语义/字段插件，是否有目标 RTL 的直接适配器仍需由 candidate manifest 证明。AXI4、AHB-Lite、Wishbone、Avalon-MM、AXI-Stream、CHI 在本文件中先作为参考协议，不能因为被列入目录就被 CLI 报告为“已实现”。

这一区分是后续自动组合的 fail-closed 边界：插件能解析字段，不等于已经有可编译的 bridge；有 bridge，也不等于目标 CPU/外设的版本、宽度、时序和错误语义都已通过验证。

### 1.2 统一的时序记号

设时钟采样点为离散时间 `t`，信号在一个采样周期内为布尔值或位向量。定义：

```text
fire(v, r, t)       := v(t) ∧ r(t)
hold(x, v, r, t)    := (v(t) ∧ ¬r(t)) -> x(t+1) = x(t)
eventually_[a,b](p) := ∃k ∈ [a,b] : p(t+k)
```

对采用 `VALID/READY` 的通道，`fire` 是一次 beat 被接受的唯一事件。发送方不得让 `VALID` 依赖接收方 `READY` 形成组合环；发送方在 `VALID=1 && READY=0` 时必须保持该通道的 payload 和 VALID 稳定。

对 level/phase 型接口，定义请求和完成事件：

```text
request(t)  := select(t) ∧ enable(t)      // 具体协议按协议契约重命名
complete(t) := request(t) ∧ ready(t)
error(t)    := request(t) ∧ error_flag(t)
```

用于随机输入合法化的最小时序断言集合：

```text
stable_until_fire(v, payload) :=
    G(v ∧ ¬ready -> X(payload = payload_previous ∧ v))

response_after_request(req, rsp) :=
    G(rsp -> previously_outstanding(req))

bounded_response(req, rsp, L) :=
    G(req_fire -> F_[0,L](rsp_fire ∨ error_fire))

no_duplicate_completion :=
    one request instance has at most one response instance

reset_quiescence :=
    G(reset_active -> no_fire ∧ no_side_effect)
```

`L` 不允许写成无限；若协议允许无限等待，测试配置必须给出明确的超时和“未决事务”统计，不得让 harness 无限阻塞。

### 1.3 可编译的协议契约模型

后续实现使用与仓库 `protocol.v1` 兼容的抽象；协议原文的丰富属性可放在 `capability_limits`，但影响合法化的字段必须结构化保存：

```text
ProtocolSpec {
  protocol_id: string,
  plugin_version: semver,
  endpoint_roles: [initiator, target, bridge],
  channels: [
    Channel {
      id: uint32,
      role: string,
      fields: [
        Field { id, role, direction, width_min, width_max, required }
      ]
    }
  ],
  temporal_rules: [
    Rule { kind, antecedent_field_id, consequent_field_id,
           min_cycles, max_cycles }
  ],
  dependency_edges: [FieldId -> FieldId, kind],
  legal_adapters: [protocol_id],
  projection_actions: [direct | fold_xor | gate | mask |
                       event_select | delay_select],
  capability_limits: scalar_map
}
```

协议编译器必须拒绝：宽度不匹配、端点角色不匹配、同一字段多重驱动、无界 delay、超出 `max_state_bits` 的状态机、声明了 full AXI/TL 能力但 runtime profile 没有实现的事务。

## 2. 协议契约

以下每个小节都给出：字段、状态机、必要不变量、依赖边以及对 fuzz projection 的约束。`x` 表示由随机输入填充的值；它不是“忽略协议约束”的通配符。

### 2.1 APB4

#### 2.1.1 信号与角色

| 信号 | 方向（initiator -> target 除注明外） | 作用 |
|---|---|---|
| `PCLK` | 时钟 | APB 采样时钟。 |
| `PRESETn` | 系统 -> 两端 | 低有效复位。 |
| `PSEL` | initiator -> target | 选择一个 target；互连通常保证 one-hot。 |
| `PENABLE` | initiator -> target | 进入 ACCESS 相位。 |
| `PADDR` | initiator -> target | 地址。 |
| `PWRITE` | initiator -> target | `1` 写，`0` 读。 |
| `PWDATA` | initiator -> target | 写数据。 |
| `PSTRB` | initiator -> target | APB4 字节写使能，宽度通常为 `PWDATA/8`。 |
| `PPROT` | initiator -> target | APB4 保护属性；具体 bit 语义按采用的 APB profile 声明。 |
| `PREADY` | target -> initiator | ACCESS 完成/等待。 |
| `PRDATA` | target -> initiator | 读数据。 |
| `PSLVERR` | target -> initiator | 本次访问错误。 |

#### 2.1.2 状态与形式化规则

```text
IDLE   : !PSEL && !PENABLE
SETUP  :  PSEL && !PENABLE
ACCESS :  PSEL &&  PENABLE
DONE   :  ACCESS && PREADY

IDLE -> SETUP -> ACCESS -> (DONE -> IDLE | ACCESS)
```

必要约束：

```text
G(ACCESS && !PREADY ->
  X(PSEL && PENABLE && PADDR/PWRITE/PWDATA/PSTRB/PPROT stable))
G(DONE -> PSEL && PENABLE)
G(PSLVERR -> ACCESS)
G(PSTRB != 0 -> PWRITE)
G(!PWRITE -> PRDATA is sampled only at DONE)
```

APB 没有 burst、ID、乱序 response 或同时多个 outstanding。一个合法输入事务是一个 SETUP 后紧跟一个或多个 ACCESS 等待周期，再以 `PREADY` 完成。APB 选择器、地址解码器和外设 target 之间的依赖边为：`PADDR/PSEL -> selected_target`，`PWRITE/PSTRB/PWDATA -> write_side_effect`，`target_ready/error/data -> PREADY/PSLVERR/PRDATA`。

### 2.2 AXI4-Lite

#### 2.2.1 五个独立通道

| 通道 | 方向 | 主要字段 |
|---|---|---|
| `AW` | manager -> subordinate | `AWVALID/AWREADY/AWADDR/AWPROT` |
| `W` | manager -> subordinate | `WVALID/WREADY/WDATA/WSTRB` |
| `B` | subordinate -> manager | `BVALID/BREADY/BRESP` |
| `AR` | manager -> subordinate | `ARVALID/ARREADY/ARADDR/ARPROT` |
| `R` | subordinate -> manager | `RVALID/RREADY/RDATA/RRESP` |

AXI4-Lite 的写地址和写数据可以独立握手，因此不能用“AWVALID 就代表 WVALID 已经到达”这样的隐含依赖。当前 runtime profile 规定一个写事务收集一个 `AW` beat 和一个 `W` beat 后才产生一次 `B`；一个读事务收集一个 `AR` 后产生一次 `R`。

#### 2.2.2 合法性

```text
aw_fire := AWVALID && AWREADY
w_fire  := WVALID  && WREADY
b_fire  := BVALID  && BREADY
ar_fire := ARVALID && ARREADY
r_fire  := RVALID  && RREADY

G(AWVALID && !AWREADY -> hold(AWADDR, AWPROT))
G(WVALID  && !WREADY  -> hold(WDATA, WSTRB))
G(BVALID  && !BREADY  -> hold(BRESP))
G(RVALID  && !RREADY  -> hold(RDATA, RRESP))
G(b_fire -> prior(aw_fire) && prior(w_fire))
G(r_fire -> prior(ar_fire))
G(WSTRB == 0 -> write is either no-op or explicitly rejected)
```

AXI4-Lite 不支持 burst；规范 profile 的数据宽度常见为 32 或 64 bit，不带 full AXI 的 burst length、`WLAST` 和 ID 语义，不支持 exclusive access。协议本身可以允许多个未完成请求，但本项目第一阶段使用 `max_write_outstanding=1`、`max_read_outstanding=1` 的可重复 profile，使低资源运行和固定宽度投影更容易验证。

### 2.3 AXI4

AXI4 同样有 `AW/W/B/AR/R` 五个通道，但增加 burst、ID 和更丰富的属性。关键字段包括：

```text
AW: AWID, AWADDR, AWLEN, AWSIZE, AWBURST, AWLOCK, AWCACHE,
    AWPROT, AWQOS, AWVALID/AWREADY
W : WDATA, WSTRB, WLAST, WVALID/WREADY
B : BID, BRESP, BVALID/BREADY
AR: ARID, ARADDR, ARLEN, ARSIZE, ARBURST, ARLOCK, ARCACHE,
    ARPROT, ARQOS, ARVALID/ARREADY
R : RID, RDATA, RRESP, RLAST, RVALID/RREADY
```

约束摘要：

```text
beats = AWLEN + 1                  // 读同理
beat_addr(i) = burst_address(AWADDR, AWSIZE, AWBURST, i)
last_write_beat = WLAST
last_read_beat  = RLAST
G(AWVALID && !AWREADY -> hold(all AW payload))
G(WVALID && !WREADY -> hold(WDATA/WSTRB/WLAST))
G(write response -> matching BID and completed WLAST)
G(read response -> matching RID and correct RLAST)
burst must not cross a 4 KiB boundary
```

AXI4 的 outstanding、ID、响应排序、窄传输、burst 类型和 cache/lock 属性必须由 profile 明确，不能随机生成“看起来像 AXI4”的部分字段。当前实现阶段只接受 AXI4-Lite 的子集；full AXI burst 输入必须被 manifest 能力检查拒绝，而不是静默截断成单次访问。

### 2.4 AHB-Lite

常用字段：`HCLK/HRESETn/HSEL/HADDR/HTRANS/HWRITE/HSIZE/HBURST/HPROT/HWDATA/HREADY/HRESP/HRDATA`。AHB-Lite 将一次传输分成地址/控制相位和数据相位：

```text
HTRANS = IDLE  : 无传输
HTRANS = BUSY  : master 保持总线但当前 beat 不传输
HTRANS = NONSEQ: burst 的第一个 beat 或单次传输
HTRANS = SEQ   : burst 后续 beat

address_phase(t) := HSEL && (HTRANS == NONSEQ || HTRANS == SEQ)
complete(t)      := address_phase(t) && HREADY
```

当 `HREADY=0` 时，当前控制/地址和写数据必须保持，target 只能在数据相位给出 `HRESP`/`HRDATA`。`HSIZE` 决定 beat 大小，`HBURST` 决定 single/increment/wrap 等传输属性；第一阶段的低资源适配器只允许 `SINGLE` 或已界定长度的 `INCR`，并在地址对齐和 bus width 上做检查。

依赖关系为 `HADDR/HTRANS/HSEL -> decode`、`HWRITE/HSIZE/HWDATA -> write_payload`、`HREADY/HRESP/HRDATA -> completion`。不得让随机 `HREADY` 在地址相位导致“没有请求却完成”的假事务。

### 2.5 TileLink-UL

TileLink 有多个方言；本项目的第一阶段只把 TL-UL 当作轻量、无一致性 MMIO 方言，不把完整 TL-C/缓存一致性能力混入同一插件。

#### 2.5.1 A/D 通道

| 通道 | 方向 | 关键字段 |
|---|---|---|
| `A` | source -> sink | `valid/ready/opcode/param/size/source/address/mask/data` |
| `D` | sink -> source | `valid/ready/opcode/param/size/source/sink/denied/data` |

TL-UL 不使用完整 TileLink 的 `B/C/E` 通道。常用 A opcode 为 `Get`、`PutFullData`、`PutPartialData`、`Hint`；D opcode 通常为对应的 `AccessAck` 或 `AccessAckData`。精确 opcode/param 以采用的 TL 版本和 RTL 定义为准，manifest 必须保存版本和字段宽度。

#### 2.5.2 单事务 profile

```text
a_fire := a_valid && a_ready
d_fire := d_valid && d_ready

G(a_valid && !a_ready -> hold(A payload))
G(d_valid && !d_ready -> hold(D payload))
G(d_fire -> prior(a_fire) && matching_source/size)
G(PutPartialData -> mask != 0)
G(address_alignment(size, address))
```

当前低资源 profile：`max_outstanding=1`、`source_width` 可以为 0 或固定小宽度、禁止 source-ID 重排、禁止 burst/multibeat data。若后续增加多 beat 或 source 重排，必须升级 protocol plugin version 和依赖图规则。

### 2.6 OBI

OBI 版本会影响可选字段，常见单 beat memory interface 包含：

```text
req, gnt, rvalid, rready,
addr, we, be, wdata, rdata, err,
以及可选的 auser/ruser、aid/rid、memtype 等扩展
```

最小规则：

```text
request_fire := req && gnt
response_fire := rvalid && rready       // 若 profile 没有 rready，则为 rvalid

G(req && !gnt -> hold(addr/we/be/wdata and req))
G(req does not combinationally depend on gnt or rvalid)
G(response_fire -> prior(request_fire))
G(we == 0 -> rdata is meaningful at response_fire)
G(be == 0 -> write is rejected or declared no-op)
```

CV32E40P 的 instruction/data 接口采用 OBI v1.2；CVA6、Ibex、BOOM 不能因此被自动标成 OBI core-native。协议组合器必须把 `OBI-v1.2`、`OBI-v1.6` 视为具有版本约束的能力，字段缺失时只能选取兼容的子 profile。

### 2.7 Wishbone Classic/B3

Wishbone Classic 的最小字段：

```text
master -> slave: CLK, RST, CYC, STB, WE, ADR, DAT_MOSI, SEL
slave  -> master: ACK, ERR, RTY, DAT_MISO
```

一个 Classic 单次传输的核心规则：

```text
cycle := CYC
request := CYC && STB
terminate := ACK || ERR || RTY

G(request && !terminate -> hold(CYC/STB/WE/ADR/DAT_MOSI/SEL))
G(terminate -> request)
G(!(ACK && ERR) && !(ACK && RTY) && !(ERR && RTY))
G(!CYC -> !STB && !terminate)
```

`SEL` 是字节选择；`WE=0` 时 `DAT_MISO` 在 `ACK` 采样，`WE=1` 时 `DAT_MOSI` 与 `SEL` 定义写入。Classic、Registered Feedback、Pipelined 不是同一个时序 profile；组合器必须在协议 ID/版本和能力中区分，不能只看信号名字。

### 2.8 Avalon-MM

Avalon-MM 常见字段：

```text
address, read, write, writedata, readdata, byteenable,
waitrequest, readdatavalid, response, burstcount, beginbursttransfer
```

最小非 burst profile：

```text
write_accept := write && !waitrequest
read_accept  := read  && !waitrequest
read_complete := readdatavalid       // 若接口声明固定零延迟，则按 profile 处理

G((read || write) && waitrequest -> hold(address/read/write/
  writedata/byteenable/burst fields))
G(readdatavalid -> prior(read_accept))
G(read_complete -> matching ordered read)
```

Avalon 允许可变等待和不同的 read latency；因此 `waitrequest`、`readdatavalid`、`burstcount`、`fixedLatency` 等必须进入 capability profile。当前第一阶段只生成单 beat、有限等待、无未界定 burst 的 MMIO 事务。

### 2.9 AXI-Stream 与 AMBA CHI（后续协议）

AXI-Stream 只有流 beat，不带地址；核心为 `TVALID/TREADY`，以及可选 `TDATA/TKEEP/TSTRB/TLAST/TID/TDEST/TUSER`。`TVALID && !TREADY` 时所有有效 payload 必须保持；`TLAST` 标记 packet 边界。它不能直接替代 AXI4-Lite 的寄存器访问，但可通过 DMA/stream bridge 与内存映射组件组合。

AMBA CHI 面向一致性互连，包含 requester、home、snoop 等节点和请求/数据/响应/snoop 事务；其缓存一致性状态和信用/流控远超 MMIO 插件。后续若纳入，必须新增 coherence graph、snoop 依赖和多节点资源预算；当前仅登记为 `reference`。

## 3. CPU 与协议支持矩阵

下表按“核心本体”和“常见平台集成”分列。`✓` 只能解释为该列对应上下文已被官方资料或项目源码明确支持；`~` 表示需要桥接/配置验证。

| CPU/核 | ISA 概况 | core-native 接口 | 常见 SoC/integration | 协议适配结论 |
|---|---|---|---|---|
| Ibex | RV32I/E + 可选 M/C/B 子集；配置决定具体集合 | instruction/data request-grant-response-error、irq/debug | OpenTitan 系统常见 TL-UL 外设互连 | 原生接口不是 APB/AXI/TL；TL-UL/APB/AXI-Lite 需要 integration/bridge |
| CVA6 | RV32/RV64 I，常见 M/A；可选 F/D/C/B/Zc/Zicond | AXI4 memory interface | AXI4 SoC；原子访问受 AXI profile 限制 | AXI4 core-native；APB/TL/WB/OBI 需要 bridge |
| BOOM | 文档化为 RV64GC/IMAFDC + privileged；具体生成配置决定细节 | generated tile-facing interface（非固定通用 MMIO API） | Rocket Chip/TileLink、cache、interrupt/debug 系统 | TileLink 是常见 SoC 集成路径；非 BOOM 单体固定外设协议 |
| Rocket | RV64/RV32 配置依实现 | Rocket Chip 内部总线端口 | TileLink、Diplomacy、AMBA bridges | TileLink native/integration；AXI/APB 等经 bridge |
| PicoRV32 | RV32I，可选 PCPI/M | 简单 memory valid/ready/addr/wdata/wstrb/rdata/ready | `picorv32_axi`、`picorv32_wb` 包装器 | native simple；AXI4-Lite/Wishbone 有官方 wrapper |
| VexRiscv | 由插件组合的 RV32/RV64 变体 | Simple bus 或插件定义的 I/D 总线 | AXI4、AHB-Lite、Avalon、Wishbone 等 bridge/plugin | 协议能力是 configuration-specific，必须记录插件配置 |
| CV32E40P | RV32IM[C]，可选自定义/硬件循环/APU | OBI v1.2 instruction/data；APU 采用 OBI 派生接口 | CORE-V/PULP 平台 | OBI core-native；其他协议需要 bridge |
| CV32E40S | RV32，安全/奇偶校验配置依实现 | OBI 族接口 | CORE-V 平台 | OBI core-native；版本/可选 parity 要核验 |
| NEORV32 | RV32，外设/扩展依配置 | Wishbone-compatible external bus | AXI4 bridge、AXI4-Stream 兼容路径 | Wishbone native/integration；AXI 通过 bridge |
| SweRV EH1 / VeeR EH1 | RV32，具体扩展依版本 | AXI4 或 AHB-Lite 可配置/集成 | MCU/SoC memory fabric | AXI4/AHB-Lite 需按构建参数选择 |
| XiangShan | 高性能 RV64，扩展随版本/配置演进 | 核内 cache/memory 接口并非稳定通用 MMIO API | Kunminghu/V2 等 SoC 集成路径 | 不能从项目名推断协议；以生成 top/manifest 验证 |
| SERV | 极小 RV32 核 | 简单同步 memory interface | 外部 SoC wrapper | reference；桥接前须生成事实 |
| Minerva | FPGA 友好的 RV32 软核 | 简单 memory bus | FPGA SoC wrapper | reference；verify-required |
| mor1kx | OpenRISC，不是 RISC-V | Wishbone 生态常见 | FPGA/SoC Wishbone | 可作为协议候选但不加入 RISC-V ISA profile |
| Sodor | 教学用 RISC-V 核集合 | 依实验实现 | Rocket Chip/教学 SoC | reference；适合小型 decoder/协议 smoke test |
| Hazard3 | RV32 微控制器核 | 参数化本地接口 | MCU/FPGA wrapper | reference；需按版本声明协议 |

### 3.1 Ibex、CVA6、BOOM 的明确边界

#### Ibex

Ibex 的核心 instruction interface 通常有请求、地址、grant、valid、rdata 和 error；data interface 还包括写使能/字节使能等。请求方需要保持请求直到 grant，响应由 valid 标记。Ibex 集成文档还包括 IRQ、debug、fetch enable 等控制端口。当前项目的 395-bit raw vector 正是对这类顶层端口的直接输入映射，而不是一条 APB/AXI 事务。

在 OpenTitan 等系统中，Ibex 周围的 memory fabric 和外设常用 TL-UL；这代表 `soc-native`，不改变 Ibex core-native 的接口事实。

#### CVA6

CVA6 需求文档将其外部 memory interface 定义为遵循 AXI4 的接口；原子访问和 AXI5/AXI5-Lite 的限制必须按该版本需求文档处理。CVA6 的中断、debug、CSR 是 CPU 体系状态，不应伪装成 MMIO 总线字段。

#### BOOM

BOOM 是 Rocket Chip 生态中的乱序 RISC-V 核。Tile、cache、TileLink interconnect、外设和 AMBA bridge 属于 Rocket Chip/SoC 组合层。对于 BOOM candidate，协议组合器要读取生成的 `composition_ir` 和端点绑定，不能假定“BOOM = TL-UL”；通常需要先确定是 TileLink-主端、AXI bridge，还是其他平台包装。

## 4. 常用 CPU、总线和外设组件目录

组件目录是候选库，不是要求每个组合一次性实现。每个组件都必须登记协议端点、地址窗口、时钟/复位、IRQ、宽度和副作用。

### 4.1 CPU/执行基础设施

| 组件 ID 示例 | 组件 | 常见接口/协议 | 关键依赖 |
|---|---|---|---|
| `cpu.ibex` | Ibex RV32 core | native instr/data；TL-UL/APB/AXI bridge | boot、instruction target、data target、irq/debug |
| `cpu.cva6` | CVA6 RV32/RV64 | AXI4 | AXI interconnect、cache/memory、CLINT/PLIC |
| `cpu.boom` | BOOM tile | generated tile-facing interface（非固定通用 MMIO API） | Rocket Chip tile、TileLink、L1/L2、interrupt/debug |
| `cpu.rocket` | Rocket tile | TileLink | Diplomacy、cache、memory bus |
| `cpu.picorv32` | PicoRV32 | simple/native、AXI-Lite/WB wrapper | memory target、irq/PCPI |
| `cpu.vexriscv` | VexRiscv | simple/AXI/AHB/Avalon/WB | 插件配置、总线桥、reset/irq |
| `cpu.cv32e40p` | CORE-V E40P | OBI | instruction/data target、APU 可选 |
| `cpu.neorv32` | NEORV32 | Wishbone-compatible | memory map、外设、interrupt controller |
| `cpu.swerv_eh1` | SweRV/VeeR EH1 | AXI4/AHB-Lite | memory fabric、debug/interrupt |
| `cpu.xiangshan` | XiangShan | generated SoC-specific | cache/coherence、memory、interrupt |
| `infra.bootrom` | Boot ROM | APB/AXI-Lite/TL-UL/WB/OBI | CPU reset PC、read-only、alignment |
| `infra.sram` | SRAM window | AXI/TileLink/AHB/WB/Avalon | byte enable、read latency、ECC 可选 |
| `infra.dram_ctrl` | DDR/LPDDR controller | AXI4/TL full | burst、outstanding、clock crossing、refresh |
| `infra.cache` | I/D/L2 cache | CPU local + AXI/TL | miss、refill、eviction、coherence |
| `infra.tlb_mmu` | TLB/MMU | CPU local | page table、fault、privilege、memory type |
| `infra.xbar` | crossbar/interconnect | 协议同质或带 converter | decode、仲裁、ID/source、deadlock |
| `infra.addr_decoder` | address decoder | 协议依赖 | region/base/size、one-hot select |
| `infra.cdc` | clock-domain bridge | 协议异步封装 | async FIFO、gray pointer、reset release |
| `infra.reset_sync` | reset synchronizer | reset | reset polarity、同步释放、quiescence |

### 4.2 中断、调试和性能组件

| 组件 | 常见挂载协议 | 依赖/约束 |
|---|---|---|
| CLINT/ACLINT timer/software interrupt | APB、AXI-Lite、TL-UL | `mtime/mtimecmp`、软件 IRQ、64-bit 时间、hart 数量 |
| PLIC | APB、AXI-Lite、TL-UL | source 数量、priority、pending、enable、claim/complete、hart context |
| APLIC/IMSIC | TL/AXI/平台特定 | 外部中断消息、guest/hart、优先级/门铃 |
| Debug Module/DM | JTAG DTM + APB/AXI/TL | halt/resume、abstract command、system bus access、权限 |
| JTAG TAP | JTAG | TMS/TDI/TDO/TCK 时序、IR/DR、reset序列 |
| trace encoder | AXI-Stream/TL/内存 | packet framing、backpressure、buffer overflow |
| performance monitor/PMU | CSR + APB/AXI-Lite | event select、counter width、overflow IRQ |
| watchdog | APB/AXI-Lite/TL-UL | window、kick、timeout、reset/IRQ 副作用 |
| RTC | APB/AXI-Lite/TL-UL | clock domain、time compare、低频时钟 |

### 4.3 常用控制与低速外设

| 组件 | 常见协议 | 常见状态/副作用 |
|---|---|---|
| UART 16550/简单 UART | APB、AXI-Lite、TL-UL、WB | TX/RX FIFO、baud、status、IRQ、外部串行输入 |
| GPIO | APB、AXI-Lite、TL-UL、WB | direction、output、input sync、edge/level IRQ |
| SPI master/slave | APB、AXI-Lite、TL-UL、WB | divider、CPOL/CPHA、CS、TX/RX FIFO、DMA/IRQ |
| QSPI/XIP | AXI4-Lite + AXI4/TL | command/address/data phase、dummy cycles、flash busy |
| I2C | APB、AXI-Lite、TL-UL | open-drain、start/stop、ACK/NACK、clock stretch、arbitration |
| PWM | APB、AXI-Lite、TL-UL | period/duty、enable、dead time、output pin |
| general timer | APB、AXI-Lite、TL-UL | prescaler、compare、capture、IRQ |
| DMA engine | AXI4、TileLink、Avalon-MM | descriptor、source/dest、length、burst、completion IRQ |
| mailbox/doorbell | APB、AXI-Lite、TL-UL | producer/consumer、full/empty、IRQ |
| syscon/clock controller | APB、AXI-Lite、TL-UL | mux/divider/gate、safe transition、reset dependency |
| pinmux/I/O pad control | APB、AXI-Lite、TL-UL | alternate function、pull、drive、input enable |
| key manager/OTP | APB、AXI-Lite、TL-UL | lock bits、one-time write、access policy、zeroization |

### 4.4 高速、存储和通信组件

| 组件 | 常见协议 | 依赖/约束 |
|---|---|---|
| Ethernet MAC | AXI4 + AXI-Stream、TL/AXI-Lite control | descriptor DMA、packet length、CRC、flow control、IRQ |
| USB device/host | AXI4、AHB、APB control、AXI-Stream | endpoint、token/data/handshake、FIFO、PHY reset |
| CAN/CAN-FD | APB、AXI-Lite、WB | arbitration、bit timing、mailbox、error state |
| SD/eMMC | AXI4/AHB + control bus | command/data、busy、DMA、CRC、card detect |
| PCIe endpoint/root complex | AXI4/AXI-Stream + config | TLP、BAR、MSI/MSI-X、ordering、DMA、reset link training |
| NVMe/flash controller | AXI4/TL full | queues、doorbell、DMA、completion、persistent state |
| video/display controller | AXI4 + AXI-Stream | frame buffer、stride、line/frame boundary、underflow |
| camera/CSI receiver | AXI-Stream | packet/frame synchronization、backpressure、overflow |
| ADC/DAC interface | AXI-Stream/APB control | sample clock、FIFO、trigger、overrun/underrun |
| audio/I2S | AXI-Stream/APB | frame/slot timing、FIFO、sample rate |
| crypto accelerator | AXI4/TL-UL/AXI-Lite + stream | key lifecycle、block alignment、busy/IRQ、DMA |
| TRNG/RNG | APB、AXI-Lite、TL-UL | entropy valid、health test、conditioning、rate limit |
| AES/SHA/RSA/ECC | APB/TL-UL control + AXI DMA | command sequence、key/data valid、completion/err |
| cache-coherent accelerator | CHI/TL-C/AXI coherent | snoop、barrier、ownership、ordering |

### 4.5 组件契约

后续组件 registry 建议采用以下结构。地址、IRQ、宽度和时钟不可藏在模块名或文件路径中：

```text
ComponentType {
  component_id: string,
  kind: cpu | memory | interconnect | bridge | peripheral | infra,
  version: semver,
  endpoint_roles: [initiator | target | stream_source | stream_sink],
  protocol_endpoints: [
    { protocol_id, version, direction, data_width, addr_width,
      outstanding_limit, burst_profile }
  ],
  address_regions: [{base, size, permissions, alignment}],
  irq_outputs: [{stable_id, kind, polarity, trigger}],
  clocks: [{stable_id, frequency_class, domain}],
  resets: [{stable_id, polarity, synchronous_release}],
  parameters: scalar_map,
  side_effects: [read_clear | write_one_to_clear | write_once |
                 fifo_pop | fifo_push | reset | irq | dma | external_io],
  dependencies: [component_id/endpoint_id/field_id]
}
```

同一组件的多个实例必须使用独立稳定 ID；实例的名字只是诊断和 SV emission 元数据，不参与协议选择、评分或随机策略。

## 5. 依赖感知的自动组合模型

### 5.1 图节点与边

组合图 `G=(V,E)` 的节点使用稳定整数 ID，不使用 RTL 文本名称：

```text
V = CPU | component | endpoint | channel | field | address_region |
    clock | reset | irq | bridge | memory_window
E = drives | consumes | selects | maps_to | responds_to | clocks |
    resets | raises_irq | depends_on | adapts_to | orders_before
```

典型链路：

```text
CPU.instr_endpoint
  -> protocol_adapter/decoder
  -> bootrom or memory
  -> response_channel
  -> CPU.instr_response

CPU.data_endpoint
  -> xbar
  -> {ram, timer, gpio, uart, spi}
  -> irq_router
  -> CPU.irq
```

### 5.2 组合前检查

1. **协议兼容性**：端点协议相同，或存在 manifest 声明的 legal adapter；禁止依赖字符串猜测桥接关系。
2. **宽度与对齐**：地址、数据、byte enable、size、burst beat 必须可转换；若转换会丢信息，直接拒绝。
3. **事务资源**：两端 outstanding、ID/source、response ordering 取交集；不能把 AXI 多 outstanding 接到单槽 TL-UL 而不增加有界队列。
4. **地址空间**：region 不重叠，base/size 对齐，读写权限与组件副作用一致；空洞和默认错误 target 要显式建模。
5. **时钟/复位**：跨时钟域必须有 CDC 组件；复位期间端点必须 quiescent；复位释放顺序要进入依赖图。
6. **中断**：IRQ 线的 polarity、trigger、hart/context 路由可验证；不能只随机拉高 CPU 顶层 IRQ 而绕过控制器状态。
7. **可终止性**：每个请求都有有界完成、错误或 timeout；超时生成诊断事件，不进入无限等待。
8. **公平性**：candidate-direct 与 candidate-depaware 必须使用相同 CPU、RTL、coverage universe、raw width、seed 和预算。

### 5.3 自动组件组合步骤

```text
1. 读取 candidate_manifest + composition_ir + protocol manifests
2. 校验 schema、content hash、端点角色、宽度、地址和版本
3. 构建稳定 ID 的 CSR 依赖图
4. 找到 CPU instruction/data 必需路径
5. 为缺少协议转换的边选择 legal adapter
6. 放置 bootrom、ram、timer、irq controller 和最小控制外设
7. 以地址/IRQ/时钟/复位约束检查图是否闭合
8. 为每个 endpoint 生成类型化 destination
9. 生成 flat-direct、candidate-direct、candidate-depaware 三组 harness
10. 运行 parse/link/width/compile/smoke 验证
11. 通过低资源 scheduler 开始长时间 campaign，并保存 checkpoint/report
```

任何一步失败都返回结构化 reject reason；不能“尽量生成一个可能可编译的组合”。

## 6. RFuzz 输入结构与不可破坏的 ABI

### 6.1 当前 Ibex 基线

仓库已有 Ibex baseline harness 的事实是：RFuzz 输入为 56 字节 `io_input_bytes_0..55`，补齐后取出 395-bit `rfuzz_input_bits`，再直接映射到 Ibex 顶层输入。后续依赖感知 projection 必须以这 395 bit 为 canonical raw ABI，不能为了加入协议状态机而改变 fuzzer 的输入长度或字节结构。

当前 bit mapping（`[hi -: width]`，从 `rfuzz_input_bits` 的高位向低位记录）如下：

| raw 范围 | 宽度 | destination |
|---:|---:|---|
| `[394:331]` | 64 | `ic_data_rdata_i[0]` |
| `[330:267]` | 64 | `ic_data_rdata_i[1]` |
| `[266:245]` | 22 | `ic_tag_rdata_i[0]` |
| `[244:223]` | 22 | `ic_tag_rdata_i[1]` |
| `[222:191]` | 32 | `boot_addr_i` |
| `[190:159]` | 32 | `data_rdata_i` |
| `[158:127]` | 32 | `hart_id_i` |
| `[126:95]` | 32 | `instr_rdata_i` |
| `[94:63]` | 32 | RF ECC A seed |
| `[62:31]` | 32 | RF ECC B seed |
| `[30:16]` | 15 | `irq_fast_i` |
| `[15:12]` | 4 | `fetch_enable` |
| `[11]` | 1 | `data_err_i` |
| `[10]` | 1 | `data_gnt_i` |
| `[9]` | 1 | `data_rvalid_i` |
| `[8]` | 1 | `debug_req_i` |
| `[7]` | 1 | `ic_scr_key_valid_i` |
| `[6]` | 1 | `instr_err_i` |
| `[5]` | 1 | `instr_gnt_i` |
| `[4]` | 1 | `instr_rvalid_i` |
| `[3]` | 1 | `irq_external_i` |
| `[2]` | 1 | `irq_nm_i` |
| `[1]` | 1 | `irq_software_i` |
| `[0]` | 1 | `irq_timer_i` |

总宽度为 `395`，输入承载字节数为 `ceil(395/8)=50`，但当前 RFuzz harness ABI 仍固定为 56 bytes；补齐/切片规则属于兼容性的一部分，不能自行压缩为 50 bytes。

### 6.2 泛化的 raw-to-destination 结构

每个 candidate 都要在 manifest 中保存完整映射，不能仅保存一个生成后的 SV 文件 hash：

```text
RawDestination {
  destination_id: uint32,
  component_id: uint32 | null,
  port_id: uint32,
  width: positive_int
}

RawBitUse {
  raw_lo: int,
  raw_hi: int,                 // inclusive
  destination_id: uint32,
  destination_lo: int,
  action: direct | fold_xor | gate | mask |
           event_select | delay_select,
  category: protocol_legality | progress | dependency_consistency |
             bounded_event_rarity | address_validity | direct
}
```

强制规则：

```text
0 <= raw_lo <= raw_hi < raw_width
0 <= destination_lo
raw_width 与 harness 字节 ABI 固定
所有 raw bit 要么有明确 direct/projection 用途，要么被明确标为 reserved
projection 只能固定宽度切片、mask、XOR fold、gate、有限计数/事件选择
不允许丢弃 sample、额外抽随机数、等待不确定周期、读取外部反馈改变 raw width
```

`candidate-direct` 与 `candidate-depaware` 使用相同 `raw_width`；依赖感知版本只能改变 destination 的合法化投影，不得改变 RFuzz 输入结构。不同 CPU 的自然端口宽度可以形成不同实验 strata，但不能在同一比较组中静默补零或截断。

### 6.3 协议投影示例

将 raw bit 映射到 AXI-Lite 写事务时，可以使用：

```text
awvalid = raw[0]
wvalid  = raw[1]
awaddr  = raw[31:2] masked_to_declared_region
wdata   = raw[63:32]
wstrb   = nonzero_mask(raw[67:64])

if (awvalid && wvalid && awready && wready):
    commit_one_write()
else:
    hold_or_make_no_request_within_bound()
```

这不是把 raw input 改成软件事务序列，而是让固定宽度 bit projection 产生可追踪的协议字段。APB 的 `PSEL/PENABLE`、OBI 的 `req/gnt`、TL-UL 的 A/D valid-ready 同理，所有修正都必须落在 `RawBitUse` 和 `projection_actions` 中。

### 6.4 运行时公平和资源限制

默认低资源策略：

```text
同时只构建一个完整 Verilator DUT
不生成 VCD/FST；只保存 bounded event counters 和 checkpoint
fuzz 并发由 measured/estimated RSS 决定，不由 CPU 核数直接决定
动态依赖 replay 每批最多 64 个 field groups
静态图用 uint32 stable IDs + CSR arrays
单个 projection 的 state bits <= 4096，规则、日志、重放队列均有界
```

长时间测试至少记录：candidate/manifest hash、protocol/plugin versions、raw width、seed、实际测试数、cycle 数、coverage universe hash、peak RSS、timeout/crash/reject 数、每个组件和协议的事务计数。只有在 reset 稳定、未 timeout、可重放的样本上更新动态置信度；失败样本不能直接被当作“负依赖证据”。

## 7. 面向实现的最小交付顺序

1. 把本文件的八个主协议编译为 `protocol.v1` plugin；第一波 runtime 保持 `ready-valid-mmio/apb/axi4-lite/obi/tl-ul` 五个 ID，其他协议先作为 reference manifest。
2. 建立 CPU/外设 registry，先实现 Ibex + APB/TL-UL/AXI4-Lite，再接入 PicoRV32、CV32E40P、CVA6 和 BOOM 的验证型 manifest。
3. 实现 address/IRQ/clock/reset/width/outstanding 的依赖图检查，所有 reject reason 可序列化。
4. 生成三类 harness：`flat-direct`、`candidate-direct`、`candidate-depaware`；后两者保持完全公平的 raw ABI。
5. 先跑短 smoke，再在低资源 scheduler 下逐步延长到小时级；只有报告中区分了协议合法率、有效事务率、覆盖率和资源峰值，才能比较 projection 是否有效。

## 8. 参考资料

### CPU 与平台

- [Ibex instruction fetch interface](https://ibex-core.readthedocs.io/en/latest/03_reference/instruction_fetch.html)
- [Ibex integration and top-level ports](https://ibex-core.readthedocs.io/en/latest/02_user/integration.html)
- [Ibex repository and supported configurations](https://github.com/lowRISC/ibex)
- [CVA6 requirements specification](https://cva6.readthedocs.io/en/stable/02_cva6_requirements/cva6_requirements_specification.html)
- [CVA6 interfaces](https://cva6.readthedocs.io/en/stable/01_cva6_user/Interfaces.html)
- [BOOM RISC-V ISA](https://docs.boom-core.org/en/latest/sections/intro-overview/riscv-isa.html)
- [BOOM and Rocket Chip integration](https://docs.boom-core.org/en/latest/sections/intro-overview/rocket-chip.html)
- [PicoRV32 native/AXI/Wishbone interfaces](https://github.com/YosysHQ/picorv32/blob/main/README.md)
- [VexRiscv bus plugins](https://github.com/SpinalHDL/VexRiscv/blob/master/src/main/scala/vexriscv/plugin/IBusSimplePlugin.scala)
- [CV32E40P user manual](https://cv32e40p.readthedocs.io/en/latest/intro.html)
- [NEORV32 repository](https://github.com/stnolting/neorv32)
- [SweRV EH1 programmer reference manual](https://raw.githubusercontent.com/westerndigitalcorporation/swerv_eh1/d9204cf238aeb98996ad1f95c173eca2c3b91d1f/docs/RISC-V_SweRV_EH1_PRM.pdf)
- [XiangShan repository](https://github.com/OpenXiangShan/XiangShan)

### 协议

- [Arm AMBA specifications](https://www.arm.com/architecture/system-architectures/amba/amba-specifications)
- [AMBA AXI and ACE protocol specification](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/IHI0022H_amba_axi_protocol_spec.pdf)
- [AMBA 3 AHB-Lite specification](https://documentation-service.arm.com/static/5f914801f86e16515cdc2a27)
- [TileLink project/specification entry](https://github.com/chipsalliance/tilelink)
- [TileLink 1.8.1 specification mirror](https://www.starfivetech.com/uploads/tilelink_spec_1.8.1.pdf)
- [OpenTitan TL-UL overview](https://opensecura.googlesource.com/3p/lowrisc/opentitan/%2B/c641c58e3b882e40ef4b6b3cde3aa0142895c2bc/hw/ip/tlul/README.md)
- [OpenHW OBI specification](https://github.com/openhwgroup/obi/blob/main/OBI-v1.6.0.pdf)
- [Wishbone Classic interface rules](https://wishbone-interconnect.readthedocs.io/en/latest/03_classic.html)
- [Wishbone B3 specification](https://opencores.org/cdn/downloads/wbspec_b3.pdf)
- [Intel Avalon-MM specification](https://cdrdv2-public.intel.com/667068/mnl_avalon_spec-683091-667068.pdf)
- [Intel Avalon-MM interface signals](https://www.intel.com/content/www/us/en/docs/programmable/683130/25-3/avalon-memory-mapped-interface-signals.html)

### 本地实现边界

- [protocol.v1 schema](../schemas/protocol.v1.schema.json)
- [composition_ir.v1 schema](../schemas/composition_ir.v1.schema.json)
- [candidate_manifest.v1 schema](../schemas/candidate_manifest.v1.schema.json)
- [Ibex RFuzz baseline harness 事实](IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md)
- [项目 CPU/IP 多组件实验计划](CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md)
