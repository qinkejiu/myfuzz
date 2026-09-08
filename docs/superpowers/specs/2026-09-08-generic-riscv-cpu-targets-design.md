# 通用 RISC-V CPU 直接接入设计

**日期：** 2026-09-08
**状态：** 待审阅
**范围：** 在现有契约编译式 RFuzz 转导器和协议自动组合之上，加入 CPU 无关的内存请求分类和目标适配，使同一套 ISA/协议约束可以直接用于多种 RISC-V CPU。

## 1. 背景与问题

当前系统已经能从带源证据的接口描述中识别时钟、复位、处理器内存端点，并根据协议语义选择 OBI、AXI4 或 TileLink-UL 适配器。Ibex 的真实流程证明了分离的 `instruction_memory_master` 与 `data_memory_master` 可以自动接线、生成 `processor-memory-beat@1` 后端，并运行契约转导器。

目前约束转导器的入口仍有一个不必要的拓扑假设：它只接受两个分离内存端点，并以端点函数名决定 `req_instruction_i`。因此一个只有统一内存端点的 CPU，即使它的协议字段已经完全描述，也无法证明某次请求是取指还是数据。不能通过 CPU 名称分支，也不能通过地址范围猜测取指；这会破坏跨 CPU 复用和输入语义的可证明性。

本设计把“总线协议选择”和“请求是指令还是数据”分开：协议由协议字段和适配器注册表决定，分类由分离端点函数或有 HDL 源证据的显式身份字段决定。

## 2. 目标和非目标

### 目标

* 保持 ISA、协议约束、内存一致性和 RFuzz 周期输入的实现 CPU 无关。
* 让目标 CPU 只通过源定位、接口语义清单和协议字段映射接入；组合器不读取 CPU 名称来选择逻辑。
* 支持两类内存拓扑：
  * 分离端点：`instruction_memory_master` + `data_memory_master`；
  * 统一端点：`memory_master` 或 `processor_memory_master`，并带显式 `instruction_identity` 字段。
* 对统一端点提供 fail-closed 行为：没有显式身份字段、身份字段方向/宽度错误、或身份值无法证明时，拒绝约束模式并给出稳定诊断。
* 第一阶段提供两个真实接口族的运行路径：
  * CV32E40P 类的分离 OBI（RV32IMC 子集）；
  * PicoRV32 类的统一 valid/ready 内存端点（`mem_instr` 作为 `instruction_identity`，可选 `mem_wstrb` 字节使能）。
* 保留完整 AXI4 统一端点（例如 CVA6）的通用扩展点；只有物理 wrapper/导出提供取指身份后才允许进入约束验收。
* 在计划、执行记录、组合 IR 和发布物中保存分类来源、物理位置和证据哈希，保证同构建/独立重建可重放。

### 非目标

* 不按 CPU 名称、RTL 路径名称或地址范围选择取指/数据。
* 不把统一总线强行拆成两个 CPU 专用 wrapper；wrapper 只负责导出真实的协议字段和身份字段。
* 不在本阶段实现 CVA6 的 cache/coherence、AXI burst、atomic 或完整 RV64 IMAFDC 语义；这属于后续协议/ISA 能力扩展。
* 不改变 RFuzz 原始位串的来源模型。原始位仍按周期切片，ISA/协议约束只对生成刺激做合法化和布尔修复。

## 3. 统一边界模型

### 3.1 语义字段

接口描述继续使用 `interface_description.v1`。总线字段使用协议插件声明的角色（如 `req`、`valid`、`addr`、`rdata`），物理端口通过 aliases 或已展开的 `physical` 选择器绑定。统一端点允许额外声明以下分类字段：

```json
{
  "role": "instruction_identity",
  "aliases": ["mem_instr"]
}
```

`instruction_identity` 是 CPU 到内存的单比特请求字段，值为 `1` 表示取指，值为 `0` 表示数据访问。它是分类证据，不是协议 payload，不会被送入 OBI/valid-ready/AXI 适配器。以后如需多态请求类型，可增加新的受控分类角色，但第一阶段只接受这个一比特角色。

### 3.2 内部分类记录

`ProcessorBoundary` 增加不可变的 `RequestClassification` 记录：

* `mode = "split_function"`：分类由端点函数名给出；
* `mode = "explicit_signal"`：分类由一个 `instruction_identity` 字段给出；
* `field_role`、物理端口/位段、宽度、方向、源位置和证据；
* `instruction_value = 1`、`data_value = 0`。

分离端点仍各自生成一条执行路由；统一端点只生成一条物理路由，但执行记录同时保存分类记录。分类字段必须是输出方向、宽度 1、属于同一内存端点，并有 `source` 与 `evidence`。分类字段不得出现在输入布局中，也不得被外部测试端口覆盖。

### 3.3 转导器接口

`processor-memory-beat@1` 的后端接口不变，仍由 `req_instruction_i` 表示分类。组合器按照边界记录生成该信号：

* 分离端点：在路由握手时由函数名产生 1/0；
* 统一端点：在路由握手时采样 `instruction_identity` 的物理信号。

采样后再随后端请求锁存，避免 CPU 在等待响应期间改变身份字段。契约转导器的 ISA、内存域和一致性规则保持不变；统一端点的指令/数据逻辑域仍可映射到同一个物理后端域。

## 4. 协议适配器选择

适配器注册表继续只按 `(protocol_id, version)` 解析，不允许出现 CPU 名称分支。第一阶段新增/完善：

* OBI：保留现有 `obi-to-processor-memory-beat`，支持只读取指端点和读写数据端点；
* `ready-valid-memory@1`：新增 `ready-valid-to-processor-memory-beat`，映射 `valid/ready/addr/wdata/wstrb/rdata`，由 `wstrb != 0` 派生写操作；无 error 信号时由适配器产生零错误；
* AXI4/TL-UL：沿用现有适配器和扩展策略；统一 AXI4 若无分类字段，约束模式拒绝，但非约束的协议组合仍可保留其诊断。

ready-valid 适配器采用单 outstanding FSM：只有 `valid && ready` 才接受一个请求；写请求和读响应都转换为一个后端 response beat；`mem_instr` 只作为分类旁路，不影响 valid/ready 协议握手。PicoRV32 的 `mem_wstrb` 若出现，则作为 `be` 扩展传递；没有 byte-enable 时适配器使用全字节写。

## 5. 目标描述和示例

### 5.1 CV32E40P 类分离 OBI

```json
{
  "endpoint_id": "processor.instruction",
  "function": "instruction_memory_master",
  "protocol": ["obi", "1"],
  "fields": [
    {"role": "req", "aliases": ["instr_req_o"]},
    {"role": "gnt", "aliases": ["instr_gnt_i"]},
    {"role": "addr", "aliases": ["instr_addr_o"]},
    {"role": "rvalid", "aliases": ["instr_rvalid_i"]},
    {"role": "rdata", "aliases": ["instr_rdata_i"]},
    {"role": "error", "aliases": ["instr_err_i"]}
  ]
}
```

数据端点使用同一 OBI 协议字段并额外声明 `we/wdata/be`。组合器从函数名得到分类，CPU 名称不会进入 IR。

### 5.2 PicoRV32 类统一 valid/ready

```json
{
  "endpoint_id": "processor.memory.unified",
  "function": "memory_master",
  "protocol": ["ready-valid-memory", "1"],
  "fields": [
    {"role": "valid", "aliases": ["mem_valid"]},
    {"role": "ready", "aliases": ["mem_ready"]},
    {"role": "addr", "aliases": ["mem_addr"]},
    {"role": "wdata", "aliases": ["mem_wdata"]},
    {"role": "wstrb", "aliases": ["mem_wstrb"]},
    {"role": "rdata", "aliases": ["mem_rdata"]},
    {"role": "instruction_identity", "aliases": ["mem_instr"]}
  ]
}
```

适配器根据 `mem_wstrb != 0` 派生写操作，并按字节映射到后端 `be`；示例只展示字段分类，最终 manifest 必须通过源爬取和方向校验。真正关键的是 `mem_instr`：它有源证据且在每次请求握手时采样。若清单缺少该字段，计划阶段返回 `missing-instruction-identity`，不得静默降级为数据访问。

## 6. 自动组合流程

1. 读取目标接口描述，校验源 revision、文件清单和 elaboration 结果。
2. 源爬取器将 aliases/physical selector 转成带源位置的 `EndpointCapability`。
3. `ProcessorBoundary` 校验时钟、复位、initiator 协议字段，并识别分离/统一拓扑。
4. 对统一端点提取 `instruction_identity`，验证方向、宽度、证据和唯一性；失败即 fail closed。
5. `ProcessorExecution` 按协议注册表选择适配器，分类字段不进入适配器字段连接。
6. 生成 `processor_execution.v1.json`、backend 记录和组合 IR；记录 `classification`、物理选择器和来源哈希。
7. 约束模式校验 route topology：分离模式需要两个逻辑内存函数，统一模式需要一条路由加显式分类记录；两种模式都必须与 `processor-memory-beat@1` 宽度一致。
8. 生成顶层 RTL，锁存分类并连接 CPU、协议适配器、后端和契约转导器。
9. 使用同一 manifest 运行 lint/compile、短时随机激励、corpus 重放和独立重建重放。

## 7. 诊断和安全边界

以下条件固定为拒绝，不允许自动猜测：

* 统一端点没有 `instruction_identity`；
* 分类字段不是 1 bit 输出，或来自另一个端点；
* 分类字段没有源证据、物理位段不完整或与其他输入重叠；
* 一个端点出现多个分类字段，或分离函数与统一分类同时声明；
* 协议字段未被插件声明，或适配器没有显式扩展策略；
* ready/valid 适配器不能证明单 outstanding 和响应终止。

诊断只使用语义原因和 endpoint/role 标识，不包含 CPU 名称匹配分支。发布物的哈希覆盖接口描述、源文件、适配器 RTL、分类记录和组合 IR。

## 8. 测试与验收标准

### 单元/属性测试

* 分离 OBI 的分类记录仍与现有 Ibex 路径一致。
* 统一端点只有一个合法 `instruction_identity` 时生成 `explicit_signal`；缺失、重复、错误方向/宽度和无证据输入均稳定失败。
* 分类字段不进入 RFuzz 输入布局、不产生重复驱动、不被协议适配器声明为未知扩展。
* ready-valid 适配器覆盖读、写、byte-enable、backpressure、复位和超时/错误终止。
* 同一语义描述更换端口别名后，分类哈希和生成 RTL 仅随源证据/物理绑定变化，不出现 CPU 名称字符串。

### 真实/合成 RTL 验收

* CV32E40P 类分离 OBI：自动生成组合、编译/仿真、至少一轮约束 RFuzz 激励、同构建与独立重建重放通过。
* PicoRV32 类统一 valid-ready：`mem_instr=1` 的请求只能命中指令域，`mem_instr=0` 的请求只能命中数据域；两类请求交错、写入后取指和等待周期均通过。
* 缺失分类的 CVA6 统一 AXI4 profile 只能生成明确拒绝诊断；添加真实 wrapper 导出身份字段后，复用同一分类器和 AXI4 适配器进行后续验收。
* 全量 Python 测试、协议/组合测试和可用的 Verilator/Icarus lint/仿真必须通过；环境缺少真实 CPU 源时，测试必须明确标记为 fixture-only，不能宣称真实 CPU 已验收。

## 9. 实施顺序

1. 先扩展 boundary/execution 数据结构和文档，保持现有 Ibex/分离路径兼容。
2. 加入统一端点分类校验、IR/发布物证据和 `_validate_processor_transducer` 的双拓扑验证。
3. 加入 `ready-valid-mmio` 处理器适配器与 RTL，并用重命名的可综合 fixture 做周期级等价测试。
4. 增加 CV32E40P、PicoRV32 的 manifest/示例入口；源清单通过外部 pinned checkout 注入，不把未验证第三方源复制进本仓库。
5. 运行真实 RTL 验收，整理文档和命令；最后再评估 CVA6 wrapper 和完整 AXI4 需求。
