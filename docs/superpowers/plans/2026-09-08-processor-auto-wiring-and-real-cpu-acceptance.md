# Processor Auto-Wiring and Real CPU Acceptance Plan

> **执行方式：** 延续已批准的测试驱动和独立复审流程。每个任务先写失败测试，完成最小实现，通过定向测试和相关回归后单独提交。不得把编译成功、合成流量或 Python 模型计数当作真实 CPU/RFuzz 验收。

**当前检查点：** `af1a6f4`。处理器通用边界、`processor-memory-beat@1` 后端契约、AXI4/OBI/TL-UL RTL 适配器和 packed RFuzz runtime projection 已完成。自动实例化接线、真实 CPU 执行与长时间 RFuzz 验收尚未完成。

**目标：** 根据 HDL 物理事实、显式语义标注、协议契约和组件能力，自动组合 RISC-V CPU、协议适配器、共享内存后端与外设；把 RFuzz 随机 bit 输入经过统一约束和 packed 物理投影后驱动实际 DUT；最后用 Ibex、CVA6、BOOM 作为同一通用路径的测试样本完成真实执行和长时间闭环验收。

## 不可变约束

- 生成器、适配器选择器、输入投影器和顶层模板不得按 `ibex`、`cva6`、`boom` 或模块名称分支。
- CPU 只通过 `ProcessorBoundary` 暴露时钟、复位、可选 boot/hart/中断/debug 和一个或多个 memory-master endpoint。
- 适配器只由 endpoint 的协议、方向、宽度、必需字段和扩展策略选择。
- HDL/编译器证据决定端口方向、宽度、packed member 坐标和参数；接口描述提供功能语义。任一证据缺失、冲突或歧义都失败关闭。
- RFuzz 不直接控制内部总线响应。随机输入只进入布局列出的外部可控字段；clock/reset 由仿真器控制，后端响应由实际组合逻辑产生。
- 约束顺序固定为：读取 raw bits → 字段范围/对齐/门控/byte-enable/ISA 约束 → packed 物理端口重建 → DUT 驱动。布局、约束和物理坐标共同进入稳定哈希。
- 合法指令模式按声明的 RISC-V ISA 契约映射；raw-instruction 模式保留任意指令位。两种模式必须在运行记录中明确区分。
- 所有构建和运行使用单 worker、`nice -n15`、默认无波形、有界超时和进程组 RSS 监测；不得停止无关进程。
- 保留用户修改的 `.superpowers/sdd/task-2-report.md` 和未跟踪 `third_party/` 内容，不得整体提交、删除或重置。

## Task 9：处理器执行连接计划

**目的：** 在生成 SystemVerilog 之前形成完整、确定且可审计的处理器连接记录。

**预计文件：**

- 新增 `src/myfuzz/composition/processor_execution.py`
- 修改 `src/myfuzz/composition/auto.py`
- 修改 `src/myfuzz/composition/__init__.py`
- 新增 `tests/composition/test_processor_execution.py`

**步骤：**

1. 为每个 `ProcessorMemoryBinding` 解析 `ProcessorAdapterDefinition`，记录 endpoint、源协议、目标协议、RTL module/source、参数和字段到端口映射。
2. 从已验证字段推导 address/data/id/source/user 宽度，不从 CPU profile 或名称补默认值。
3. 为 unified memory 或分离 instruction/data memory 生成稳定 route ID；禁止多个 endpoint 被静默选中或覆盖。
4. 对 packed member 保存容器端口与 part-select，对 scalar 保存独立端口；禁止同一物理输入既由 RFuzz 又由 adapter/backend 驱动。
5. 把 adapter source、参数、路由和 backend 契约加入 composition IR 与 hash。
6. 对未知协议、缺字段、宽度不一致、扩展策略未覆盖、重复驱动和不完整 packed input 写失败测试。

**完成门槛：** 使用不同模块名和 endpoint 名的 OBI、AXI4、TL-UL fixtures 得到相同通用 IR；改变 CPU 名称不改变选择结果，改变协议或能力事实才会改变结果。

## Task 10：通用内存后端仲裁与地址路由

**目的：** 让一个或多个 adapter 的 `processor-memory-beat@1` 请求进入同一可执行内存/外设地址空间。

**预计文件：**

- 新增 `src/myfuzz/protocols/rtl/processor_memory_arbiter.sv`
- 新增 `src/myfuzz/composition/processor_backend.py`
- 修改 `src/myfuzz/composition/protocol_composer.py`
- 新增 `tests/protocols/test_processor_memory_arbiter_rtl.py`
- 新增 `tests/composition/test_processor_backend.py`

**步骤：**

1. 单 memory endpoint 直接连接；分离 instruction/data endpoint 通过公平、单 outstanding、响应归属明确的仲裁器连接。
2. 接受请求时锁存源端、地址、写数据和 byte-enable，直到后端响应完成；背压期间所有有效载荷保持稳定。
3. 用 composition 已分配的地址窗口译码 RAM 和外设；未映射地址返回后端 error completion。
4. 指令端若声明 read-only，写请求必须在组合阶段拒绝或在协议适配器中形成明确错误，不能产生副作用。
5. 加入有界等待和超时恢复：超时请求只完成一次错误响应，丢弃对应迟到响应，随后允许新请求继续。
6. 测试同时到达、公平性、响应背压、未映射访问、部分写、超时、迟到响应、复位中止和复位后恢复。

**完成门槛：** 真实 RTL 仿真证明两个不同名称的 initiator 可共享后端，所有接受请求恰好得到一次归属正确的 completion。

## Task 11：自动生成与连接 SystemVerilog 顶层

**目的：** 由 execution plan 自动实例化 CPU、adapter、arbiter/backend、RAM 和外设。

**预计文件：**

- 修改 `src/myfuzz/composition/protocol_composer.py`
- 修改 `src/myfuzz/composition/ir.py`
- 修改 `src/myfuzz/composition/input_layout.py`
- 修改 `tests/integration/test_generic_composition.py`
- 新增 `tests/integration/test_processor_auto_wiring.py`

**步骤：**

1. 根据 route 记录声明 adapter 两侧 wires，并实例化 `rtl_module` 和经过验证的参数。
2. CPU scalar 字段直接连接；packed 字段只使用 compiler-proven part-select。每个 packed 容器只声明、连接一次。
3. adapter 输入由 CPU 输出或 backend 输出驱动；adapter 输出进入 CPU 输入或 backend 输入。生成前检查每根 wire 的唯一驱动者。
4. clock/reset 连接所有时序组件；复位极性和同步方式必须来自显式控制事实，不能从端口名猜测。
5. 将 adapter/backend RTL source 加入确定性 source list，并在发布前后复核 content hash。
6. 输出 `processor_execution.v1.json`，包含所有 endpoint、adapter、参数、packed slices、后端 route 和 source hash。

**完成门槛：** 自动生成的 OBI、AXI4、TL-UL 三种 renamed fixtures 均通过严格 Icarus/Verilator 编译；生成结果不含 CPU 名称判断或手写实例片段。

## Task 12：连接式通用处理器仿真夹具

**目的：** 在接入大型真实 CPU 前证明完整请求路径可执行。

**预计文件：**

- 新增 `tests/fixtures/rtl/generic_processor/` 下的小型 source-backed fixtures
- 新增 `tests/integration/test_connected_processor_fixture.py`
- 修改 `src/myfuzz/integration/rfuzz_simulator.py`

**步骤：**

1. 编写与 CPU 名称无关的小型处理器行为夹具：复位后取指、读数据、部分写、再次读回并发出完成标志。
2. 对 OBI、AXI4、TL-UL 分别只替换 endpoint 协议事实，复用同一 backend/RAM 和验收逻辑。
3. 经 `plan_generic_composition → write_generic_composition → compile → simulate` 验证完整链路。
4. 记录接受的请求数、completion 数、读回值、错误、周期数和退出原因；任何请求丢失、重复或卡死都失败。
5. 加入 RFuzz 输入投影测试，确认随机外部控制与 adapter 驱动的总线响应不存在双重驱动。

**完成门槛：** 三种协议的连接式 fixture 都观察到指令/数据进展和后端 completion；禁止用 Python 合成请求替代 RTL 行为。

## Task 13：真实 RISC-V CPU 执行门槛

**目的：** 依次把 Ibex、CVA6、BOOM 作为通用机制的真实样本接入。

**共同验收条件：**

1. 固定并验证源码 revision、nested repository pins、source closure、工具版本和 elaboration settings。
2. 使用通用 RISC-V 构建流程生成最小 boot image；ISA/XLEN/复位向量来自 profile/接口事实。
3. 自动生成顶层并完成有界编译，不能加入 CPU 名称驱动的 renderer 或 adapter 分支。
4. 仿真必须观察到复位释放、至少一个成功取指、PC/提交或等价执行进展、至少一个后端 completion，以及明确的 pass/fail/timeout。
5. 保存运行 manifest、composition/layout/source/binary/config hash、周期数、RSS 和日志摘要。

### Task 13a：Ibex 样本

- 使用 OBI 指令/数据接口验证分离 memory-master 仲裁。
- 只通过通用 boot/reset/interrupt/OBI 能力事实接入。

### Task 13b：CVA6 样本

- 复用已固定的 compiler-backed packed AXI4 boundary。
- 验证 `noc_req_o`/`noc_resp_i` part-select 与自动 adapter 接线一致。
- 现有 464 条 recorded-nonfatal warnings 继续进入证据，不放宽 error policy。

### Task 13c：BOOM 样本

- 先固定生成 RTL、参数、依赖仓库和 source closure，再走同一个 source crawler/boundary/adapter 流程。
- 若实际外部协议不在已实现集合中，以协议能力缺口失败并新增通用协议工作项；不得写 BOOM 专属桥接代码。

**完成门槛：** 三个样本分别有真实 CPU 执行证据。仅 elaboration 或 wrapper compile 不算通过。

## Task 14：RFuzz 随机输入约束与真实闭环

**目的：** 将 RFuzz raw bitstream 安全、确定地映射到真实组合的外部可控输入，并用实际仿真反馈驱动语料。

**预计文件：**

- 修改 `src/myfuzz/composition/runtime_projection.py`
- 修改 `src/myfuzz/integration/rfuzz_simulator.py`
- 修改 `src/myfuzz/integration/rfuzz_live.py`
- 新增真实 CPU opt-in tests 和 campaign runner/report

**约束规则：**

1. clock/reset 从 RFuzz layout 排除，由 runner 按固定时序产生。
2. boot address、hart ID、调试请求和中断只在接口描述明确允许随机化时进入 layout；否则使用显式常量或门控默认值。
3. 数值字段执行声明的范围、对齐、枚举、掩码和依赖门控。
4. byte-enable 宽度必须匹配数据宽度；无对应有效请求时相关数据字段归零或按契约门控。
5. 指令字段在 legal 模式按声明 ISA 的 opcode/funct/register/immediate 结构投影；raw 模式保持原位，运行记录必须写明模式。
6. packed container 在所有逻辑约束完成后才按 compiler-proven raw offsets 重建；填充位不驱动 DUT。
7. 同一 raw 输入、layout hash、constraint hash 和 binary hash 必须产生相同物理端口值和相同可重放仿真结果。

**闭环门槛：** RFuzz 官方客户端完成 input buffer → RTL simulation → actual coverage buffer → corpus 保存流程；coverage 类型保持真实且准确命名，不以 Python 计数替代。

## Task 15：三组长时间实核验收

**目的：** 完成用户要求的最终随机组合实测。

**步骤：**

1. 从 CPU/外设候选池中只选择已经通过 Task 13 的真实可执行组合；随机种子和选择过程写入 manifest。
2. 顺序运行三组不同组合，每组至少 300 秒；单 worker、`nice -n15`、默认无波形。
3. 每 30 秒记录进度、coverage/hash、语料数、执行数、错误数、CPU/外设进展和进程组 RSS。
4. 对每组保留至少一个新增语料并从保留源码重新构建后重放。
5. 验证正常退出、超时退出、SIGINT/SIGTERM、共享内存/FIFO/子进程清理以及失败报告完整性。
6. 若某组合无法启动或无执行进展，该组不计入三组结果；修复通用缺口后重新抽样运行完整 300 秒。

**完成门槛：** 三组真实 CPU/外设组合各有不少于 300 秒的 RFuzz 记录、真实反馈、资源记录和确定性重放证据。

## Task 16：最终回归、独立复审与文档

1. 运行相关定向测试、composition/integration 聚合测试和全量 Python 回归。
2. 对自动接线、唯一驱动、协议 completion、packed projection、约束哈希、真实 CPU 证据和资源清理做独立复审。
3. 搜索生产代码中的 CPU 名称分支；测试样本、catalog 数据和报告可以包含名称，生成行为不得依赖名称。
4. 编写最终能力矩阵，分别标明：协议已实现、fixture 已执行、真实 CPU 已执行、RFuzz 长测已通过。
5. 更新交接文档和用户指南，列出复现命令、固定 revisions、限制和证据路径。

## 建议提交边界

1. `feat(composition): plan processor execution routes`
2. `feat(protocols): arbitrate processor memory backends`
3. `feat(composition): render processor adapters automatically`
4. `test(integration): execute connected processor fixtures`
5. Ibex、CVA6、BOOM 各自一个真实样本验收提交
6. `feat(rfuzz): run constrained real processor feedback loop`
7. `test(rfuzz): record three real long-run campaigns`
8. `docs: publish processor composition acceptance evidence`

## 进度计算

当前总体估计为 **82% 完成、18% 待完成**。剩余 18% 按验收价值分配：Task 9–11 自动接线 5%，Task 12 通用连接夹具 3%，Task 13 真实 CPU 执行 5%，Task 14–15 RFuzz 与三组长测 4%，Task 16 最终复审和文档 1%。只有对应完成门槛和验证证据全部满足后才扣减该项剩余比例。
