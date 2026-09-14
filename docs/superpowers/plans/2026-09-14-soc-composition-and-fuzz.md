# Ibex / CVA6 多系列外设 SoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在既有代码上实现自动组合 Ibex/CVA6 与 OpenTitan、PULP、ZipCPU 三系列真实外设，支持受约束 CPU 执行、独立 MMIO 和混合激励，并完成真实 RFuzz 运行与重建重放。

**Architecture:** 结构层生成 source-backed CPU、CPU adapter、N 源仲裁、统一地址空间、target adapter、真实外设及 IRQ 路由。输入层在生成的 RTL harness 中修正 RFuzz bits，独立维护指令初始化、MMIO 请求和外部引脚驱动状态；真实外设响应始终进入 CPU。Python 保留配置/编译/参考模型职责。

**Tech Stack:** 现有 Python unittest、SystemVerilog、Verilator、既有前端与插桩链路、官方 RFuzz IPC/client；优先复用现有工具，不新增不必要的运行依赖。

## Global Constraints

- 规格以 [PROJECT_GOALS.md](../../PROJECT_GOALS.md) 为准；整理范围见 [REPOSITORY_ORGANIZATION.md](../../REPOSITORY_ORGANIZATION.md)。
- 当前工作区 `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`；基线 `029840a`。开始每任务前重新核对 HEAD 和 dirty files，不覆盖用户修改。
- 本计划是待执行任务，未勾选表示没有完成；历史报告不是本次验证结果。
- 生成行为由显式 protocol/capability/physical facts 决定；不得按 CPU 名称或外设系列名称在核心算法里分支。系列寄存器语义只存在 profile/contract 数据中。
- 首版同一运行时钟域，复位同步/极性显式适配；多时钟 IP 只有能够声明为合法同域配置时纳入，否则报告 unsupported。
- 单 worker、nice 15、默认无波形，有界周期、进程组 RSS、超时和停止排空。任务不停止无关进程。
- 原始 bits 保留；布局版本、投影版本、输入消费规则、source/tool/config/binary 共同进入 replay 身份。
- 不支持的能力失败关闭；不以静默 truncation、常量绑死 required 输入、假外设、Python 计数替代真实协议和 RTL 执行。
- 不永久删除历史证据和用户文件；清理用精确清单及可恢复隔离。
- 每任务结束先独立复审和定向回归，再按明确文件列表提交；不整体 git add，不自动 push。

## 阶段与依赖

```text
P0 inventory -> P1 source/capability lock -> P2 code organization -> P3 contracts
P3 -> P4 memory coexistence
P3 -> P5 target adapters -> P6 arbitration/width -> P7 synthetic MMIO
P4 + P7 -> P8 instruction harness -> P9 environment/IRQ
P9 -> P10 real Ibex -> P11 real CVA6 -> P12 eight-top matrix
P12 -> P13 internal coverage -> P14 official RFuzz -> P15 campaigns -> P16 closure
```

P4 与 P5 可在契约冻结后独立开发；P2 不与同文件行为修改并行。大型编译串行。每个阶段完成可单独报告；只有 P16 达标才能宣称总体完成。

## 文件职责与新接口

新文件均为计划创建，不代表当前已有 API。跨模块使用版本化 JSON-compatible `dict`，公开入口完整校验，禁止把任意未校验 dict 直接交 renderer。

| 文件 | 公开入口 / 职责 |
|---|---|
| composition/generic_planner.py | 从 auto.py 抽取既有 generic planning，保持原签名 |
| composition/processor_renderer.py | 从 protocol_composer.py 抽取 processor rendering，保留兼容入口 |
| composition/soc_contracts.py | `validate_soc_spec(spec: dict) -> None`、`soc_spec_hash(spec: dict) -> str` |
| composition/soc_plan.py | `build_soc_plan(spec: dict, processor_execution: dict, target_contracts: list[dict]) -> dict` |
| composition/target_adapters.py | `resolve_target_adapter(backend: dict, target: dict) -> dict` |
| composition/soc_stimulus.py | `compile_soc_stimulus(plan: dict, policy: dict) -> dict` |
| composition/soc_renderer.py | `render_soc(plan: dict, stimulus: dict) -> dict[str, str]`，返回文件名到文本 |
| integration/interaction_monitor.py | `evaluate_interactions(events: list[dict], expectations: dict) -> dict` |
| integration/soc_campaign.py | `run_soc_campaign(config: dict, output: Path) -> dict`，执行/报告/清理 |
| scripts/run_soc_campaigns.py | 验证矩阵、调度 campaign、从保留 artifact rebuild/replay |

契约域：`soc_spec.v1` = components/source locks + memory_regions + masters + interrupt_routes + environment_links + resources；`soc_plan.v1` = 已绑定实例/adapter/net/地址/唯一驱动/能力证据；`soc_stimulus.v1` = raw field layout + rule classes + consumption + reset semantics；`soc_result.v1` = 配置身份、逐目标/来源统计、coverage universe、replay、资源与最终状态。

## P0：盘点并执行第一批可恢复整理

**Files:** 新建 `scripts/audit_repository.py`、`tests/test_repository_audit.py`；更新 `docs/REPOSITORY_ORGANIZATION.md`。输出 `runs/repository-audit/<batch>/inventory.json`，不跟踪大型产物。

- [ ] 写临时目录测试：包含一个被 filelist 引用的 untracked RTL、一个用户脏文件、一个重建缓存；前两者处置必须为 keep，默认执行不移动任何文件。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.test_repository_audit -v`，确认测试先失败。
- [ ] 实现 `audit(root: Path) -> dict` 与 CLI `--output`、`--quarantine-list`；默认只审计，隔离清单每条必须有精确相对路径、hash、理由、恢复路径。拒绝绝对路径、越界 symlink、源码引用、dirty/source/user-owned 路径。
- [ ] 用以下断言覆盖拒绝边界：`self.assertEqual(report['entries']['third_party/ip.sv']['action'], 'keep')`；隔离一次后恢复并比对内容 hash。
- [ ] 在工作区跑只读审计，逐条处理可证明可重建且未被引用的缓存，更新实际处置表；没有安全候选则记录零迁移。
- [ ] 定向测试与 `git diff --check` 通过，提交 `chore: inventory repository and record recoverable cleanup`。

## P1：锁定两款 CPU 和三个真实外设系列

**Files:** 新建 `configs/soc/sources.lock.json`、`configs/soc/families/{opentitan,pulp,zipcpu}.json`、`tests/integration/test_soc_source_locks.py`；复用 `source_crawler.py`、`source_elaboration.py`、`configs/cpus/{ibex,cva6}/`。

- [ ] 用两个不同 Git revision、缺一个 nested pin、脏源文件、错误 packed 坐标编写失败测试；测试必须拒绝错误来源。
- [ ] 执行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_source_locks -v`。
- [ ] 固定 Ibex/CVA6 已有执行源快照；固定 OpenTitan UART/GPIO、PULP apb_gpio/apb_spi_master、ZipCPU wbuart/ziptimer 的完整 commit，不用浮动 master。
- [ ] 每个 IP 记录 files/includes/defines/typed parameters、generator 及工具版本、嵌套依赖、许可证文件、物理接口和寄存器语义来源。OpenTitan 生成文件以生成输入与输出 hash 双重记录。
- [ ] 对六个外设逐个真实 elaboration，检查 APB 版本、Wishbone 子集、TL integrity/alert、IRQ 触发形式、写掩码和单寄存器目标地址处理。不能把协议端口存在视为全部行为支持。
- [ ] 输出 `source_status`、`elaboration_status`、`runtime_status` 独立字段；仅 elaboration 通过时 runtime 仍为 unverified。所有六个外设完成来源与边界证明后提交 `feat: pin real CPU and peripheral family sources`。

## P2：拆分现有大文件，保留旧入口

**Files:** 修改 `composition/auto.py`、`composition/protocol_composer.py`；新建 `composition/generic_planner.py`、`composition/processor_renderer.py`、`tests/composition/test_legacy_entrypoint_compatibility.py`。

- [ ] 写相同 fixture 从旧入口与新入口生成 IR、SV 和 source list 的比较测试，断言规范化内容及 hash 相同。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.composition.test_legacy_entrypoint_compatibility -v`。
- [ ] 先抽 generic planning，再抽 processor renderer；旧模块只保留原签名转发。此提交不改变协议、输入 ABI、hash 或 target 选择。
- [ ] 执行 `PYTHONPATH=src python3 -m unittest discover -s tests/composition -p 'test_*.py'` 及 `PYTHONPATH=src python3 -m unittest tests.integration.test_processor_auto_wiring -v`。
- [ ] 检查旧 CLI 和 source list 引用仍可用，更新清理台账；提交 `refactor: separate generic planning and processor rendering`。

## P3：冻结 SoC 与输入所有权契约

**Files:** 新建 `composition/soc_contracts.py`、`composition/soc_plan.py`、`schemas/soc_spec.v1.schema.json`、`schemas/soc_plan.v1.schema.json`、`schemas/soc_stimulus.v1.schema.json`、`tests/composition/test_soc_contracts.py`；复用现有规范化/hash工具。

- [ ] 写失败测试：重复输入驱动、重叠地址、非法源 ID、缺失 required 字段、ROM 可写、CPU 与 RFuzz 同时驱动响应、跨时钟无适配都拒绝。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.composition.test_soc_contracts -v`。
- [ ] 实现上述 validate/hash/build 接口。每条内存区域包含 `base,size,permissions,physical_memory_id,initialization_policy`；同一 RAM 的 I/D 别名映射到同一 physical ID。
- [ ] `masters` 区分 cpu_instruction/cpu_data/cpu_unified/fuzz_mmio，source_id 唯一；CPU execution 的现有一/二路限制保留在 CPU 边界，系统仲裁在其外扩展。
- [ ] 规定三种模式只在 test_begin 生效，reset 分为 CPU reset 与全测试 reset；输出结构事实和假设的 provenance。
- [ ] 使用 `self.assertEqual(soc_spec_hash(a), soc_spec_hash(reordered_a))` 验证确定性，另测试协议/映射改变必改 hash；提交 `feat: define versioned SoC and stimulus ownership contracts`。

## P4：指令模型与真实 MMIO 共存

**Files:** 修改 `contract_transducer.py`、`coherent_memory.py`、`transducer_rtl.py`、`processor_renderer.py`；新建 `tests/integration/test_memory_mmio_coexistence.py`。

- [ ] 写 RTL 失败场景：程序区首次读初始化，重复读不变化，CPU 部分写 RAM 后取指/数据读一致；MMIO 写入真实计数寄存器后读回，ROM 写无副作用，未映射读错误。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_memory_mmio_coexistence -v`。
- [ ] 新模式 memory target 只拥有声明窗口，保留真实 IP 实例与路由；禁止在 constrained 模式全局设置 mapped=1。旧契约模式以版本/显式选项隔离并保留复现。
- [ ] 按已接纳的首次访问锁存初始化 entropy，事务等待不重采样；跨 16/32 位指令、64 位取数和 byte-enable 的字节一致性由 Python reference 与 RTL 对照。
- [ ] 容量耗尽明确结束测试或错误完成，不驱逐仍可寻址数据；复位清理所有测试状态。运行已有 transducer/runtime 定向测试，提交 `feat: coexist constrained memory with real MMIO targets`。

## P5：通用后端到三种外设协议的目标适配

**Files:** 新建 `composition/target_adapters.py`、`protocols/rtl/beat_to_apb.sv`、`beat_to_tlul.sv`、`beat_to_wishbone.sv`、`tests/protocols/test_soc_target_adapters_rtl.py`。

- [ ] 为三种 adapter 分别写独立 RTL scoreboard：接受一读一写、延迟响应、等待时随机改变候选字段、错误响应、复位中断；每笔副作用至多一次。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.protocols.test_soc_target_adapters_rtl -v`。
- [ ] 实现 `resolve_target_adapter(backend, target)`，方向明确为 beat initiator→外设 target；不能倒用 CPU-side adapter。
- [ ] APB 生成 setup/access 和等待保持；APB3 无 strobe 时拒绝不支持的部分写。TL-UL 生成选定版本要求的 size/mask/source/integrity 并校验返回错误；alert 单独绑定。Wishbone 按实际 classic/pipelined 能力生成 CYC/STB，区分 request acceptance 与 ACK/ERR completion。
- [ ] 所有目标测试包含非选中 target 无 strobe、读写边界、错误后恢复；无地址端口的单寄存器目标使用显式窗口，不虚构物理地址 pin。
- [ ] 超时若无法安全取消，终止测试，不在旧请求可能迟到时重新使用相同事务身份。提交 `feat: drive real APB TL-UL and Wishbone targets from beat requests`。

## P6：N 源仲裁、目标路由与 CVA6 位宽边界

**Files:** 新建 `protocols/rtl/soc_arbiter.sv`、`soc_router.sv`、`mmio_width_adapter.sv`；修改 `composition/soc_plan.py`、`processor_backend.py`；新建 `tests/protocols/test_soc_fabric_rtl.py`。

- [ ] 写三个源同时请求不同目标的失败测试，背压后记录 source_id/target_id/address，断言每个 accepted transaction 恰有一次正确归属 completion。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.protocols.test_soc_fabric_rtl -v`。
- [ ] 实现参数化 N 源 round-robin，首版全局一笔 outstanding；选中来源/目标/字段在接受时锁存到完成。等待上界从配置给定，仲裁公平性按有界 target service 验证。
- [ ] CPU I/D 与 fuzz master 共享地址译码；指令源对不可执行 MMIO 的请求按 region policy 返回错误。首版不插入 DMA，未来 master 扩展使用相同接口。
- [ ] 对 CVA6 64-bit beat 与 32-bit 外设验证低/高 lane、地址 bit、读返回扩展和 byte-enable。不能把一个跨两个有副作用寄存器的 wide MMIO 写默认拆为两个写；无显式许可则返回错误。
- [ ] 测試 32 位与 64 位 RAM、未映射、跨 region、out-of-range、迟到响应及全测试复位；提交 `feat: arbitrate SoC masters and preserve MMIO width semantics`。

## P7：独立 MMIO 驱动器与 raw 输入布局

**Files:** 新建 `composition/soc_stimulus.py`、`protocols/rtl/fuzz_mmio_master.sv`、`tests/composition/test_soc_stimulus.py`、`tests/protocols/test_fuzz_mmio_master_rtl.py`。

- [ ] 写状态序列测试：idle 接受地址 A/数据 D；stall 期间新 raw B 不改变 A/D；完成只一次；busy_drop_count 与忙时未接纳候选一致。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.composition.test_soc_stimulus tests.protocols.test_fuzz_mmio_master_rtl -v`。
- [ ] `compile_soc_stimulus(plan, policy)` 生成 instruction、mmio、environment 三段固定 raw ABI，记录有效位、padding、枚举与模式。MMIO 字段为 offer/target_selector/offset/write/wdata/be；driver 执行 idle/request/response 状态机。
- [ ] 同一三模式配置使用同一布局，禁用入口记 mode_masked；busy 时确定性丢弃新 offer 并计数。数据位即使不在本周期消费也有明确映射，不声称每个 bit 每周期都影响 DUT。
- [ ] 支持 bias-off 原始地址和 biased region+offset 两种地址策略；协议基础状态保持相同，错误目标和非法操作返回记录而非无声重试。
- [ ] 测试不随机驱动 CPU 内部响应，MMIO-only CPU reset 不连到 IP reset；提交 `feat: generate constrained independent MMIO stimulus`。

## P8：CPU 随机指令入口与可达性偏置

**Files:** 修改 `isa/transducer.py`、`composition/runtime_projection.py`、`soc_stimulus.py`；新建 `tests/integration/test_soc_instruction_stimulus.py`。

- [ ] 写两组不同 raw corpus 在相同地址得到不同首次初始化指令、同一 corpus 重放相同、重复读保持、压缩指令跨字一致的测试。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_instruction_stimulus -v`。
- [ ] 主路径按需受约束初始化；预加载模式用于确定性启动/验收。实际执行前检查 RV32/RV64、I/M/C 等已实现编码子集与所选 CPU 参数一致；不支持合法化的扩展明确拒绝 legal 模式。
- [ ] 添加独立 `isa_legal`、`mmio_reachability_bias` 规则开关。地址偏置只构造指令/初始数据，不能改 CPU 输出或内部寄存器；随机 bit 决定目标、寄存器、数据及候选操作。
- [ ] 记录每条修正规则次数和指令初始化次数；固定 boot/ISR 只用于标明 directed 的测试，不包装成纯随机程序。提交 `feat: connect replayable random instruction supply to SoC memory`。

## P9：外部协议、真实 IRQ 和交互观测

**Files:** 新建 `protocols/rtl/fuzz_uart_peer.sv`、`fuzz_spi_peer.sv`、`soc_irq_router.sv`、`integration/interaction_monitor.py`、`tests/integration/test_soc_interactions.py`；修改 `soc_plan.py`、`soc_stimulus.py`。

- [ ] 写 UART RX、GPIO 事件、SPI MISO 响应的 RTL 测试；MMIO 配置后观察真实 IP status/IRQ，再由 CPU 响应路径观察后续 MMIO。UART/SPI 参数来自显式环境契约或已完成配置事务，不从信号名猜测。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_interactions -v`。
- [ ] IRQ route 描述 source、level/edge、CPU sink、mask/ack 语义。必要时提供系统模拟的 pending/claim/complete 控制器；不得单纯 OR 边沿中断造成丢失。
- [ ] 定义事件字段 `test_id,cycle,source_id,target_id,transaction_id,kind,value`，监控器只观察，不能反向驱动 DUT。
- [ ] `evaluate_interactions` 对 A event→真实 IRQ→CPU ISR 标记→B accepted transaction 做有界顺序匹配；缺事件、错来源必须失败。差分重放固定其他输入，只改变 A，记录链条是否随之变化。
- [ ] 单独测试 IRQ priority、清除、同时事件、reset；提交 `feat: drive peripheral environments and trace CPU-mediated interactions`。

## P10：真实 Ibex 双外设纵向闭环

**Files:** 新建 `composition/soc_renderer.py`、`configs/soc/ibex-pulp.json`、`tests/integration/test_soc_real_ibex.py`；修改 `integration/rfuzz_simulator.py`。

- [ ] 写 opt-in 实核测试，未安装源码时显式 skip 并报告原因；正式验收开关开启时缺依赖应失败，不能静默 skip。
- [ ] 实现 `render_soc(plan, stimulus)`，包括真实 Ibex、寄存器文件必要依赖、RAM/ROM、GPIO/SPI、适配、仲裁、IRQ 与 fuzz harness；生成物再次 elaboration 验证唯一驱动和完整接口。
- [ ] 用地址图生成最小 boot/ISR 验收程序，三个模式分别验证 GPIO 状态、SPI 实际传输、真实 IRQ、CPU MMIO 和两个来源的事务。
- [ ] 运行 `MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_ibex -v`。期望零 skip、真实行为断言通过，并保存 source/config/hash/执行 trace。
- [ ] 再跑受约束随机指令 smoke，证明随机 bits 改变实际执行；提交 `feat: execute Ibex with real generated multi-peripheral SoC`。

## P11：真实 CVA6 与同一外设集合

**Files:** 新建 `configs/soc/cva6-pulp.json`、`tests/integration/test_soc_real_cva6.py`；仅在通用能力缺口处修改 `processor_adapters.py`、`soc_plan.py`。

- [ ] 用 compiler-proven packed AXI4 边界，检查 source pin、参数、复位向量及 runtime image 一致；不得回退到旧 reference-only profile。
- [ ] 运行 `MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_real_cva6 -v`，先保留失败证据。
- [ ] 明确 RV64 boot ISA、特权模式、cache/MMU 设置与取指 burst 能力。若真实取指依赖 burst，补通用协议支持或使用已证明合法的 CPU 配置；不能用连续 DECERR 冒充执行。
- [ ] 实际执行覆盖高/低 32-bit lane 的合法 MMIO，验证不支持 wide MMIO 无副作用；重复三个模式、真实 IRQ 与 CPU→外设链。
- [ ] 重建后重放得到相同事件与覆盖，定向回归 Ibex 仍通过；提交 `feat: execute CVA6 through generic SoC adapters`。

## P12：补齐八个自动组合配置

**Files:** 新建 `configs/soc/{ibex,cva6}-{opentitan,zipcpu,mixed}.json`、`configs/soc/matrix.json`、`tests/integration/test_soc_matrix.py`。

- [ ] matrix schema 检查 2 CPU × 3 family 六格，每格至少两个不同真实 IP；另两格 mixed 含三个系列各至少一个。重复同一 IP 的 MODE 不能计作不同外设。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_matrix -v`。
- [ ] OpenTitan 把完整 TL integrity/alert/复位依赖纳入 source-backed 契约；ZipCPU 用真实握手与写能力，不假设现有 Wishbone Classic 插件覆盖全部选型。
- [ ] 对八格执行 `MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_matrix -v`，正式执行不得跳过任何格；每格三模式均通过。
- [ ] 记录连接/地址/输入 ABI/实例源码证据，验证跨系列 IRQ→CPU→另一系列访问；提交 `test: validate two CPUs across three real peripheral families`。

## P13：真实 CPU/IP 内部覆盖与公平反馈

**Files:** 新建 `integration/soc_coverage.py`、`tests/integration/test_soc_coverage.py`；复用 source instrumenter、修改 `rfuzz_simulator.py`、`soc_renderer.py`。

- [ ] 写 fixture：输入变化但内部支路未执行不能增加 branch coverage；改变分支应增加对应实例映射点；两个同 module 实例仍可区分。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_coverage -v`。
- [ ] 首选复用源码插桩；若某 HDL 构造无法插桩，提供经过验证的 Verilator 原生 coverage 后端并记录类型与工具版本，禁止退化成输入采样仍标 branch。
- [ ] coverage universe 划分 CPU/IP/fabric/model/harness；正常引导优先用 CPU/IP，交互事件单独命名并记录纳入 feedback 与否。
- [ ] 八配置逐个验证至少一个真实 CPU/IP 内部点，经 IPC 反馈确实进入 RFuzz；同 top 偏置对照使用同一 universe。提交 `feat: feed instance-mapped RTL coverage to SoC fuzzing`。

## P14：官方 RFuzz 与新 harness 的真实闭环

**Files:** 新建 `integration/soc_campaign.py`、`scripts/run_soc_campaigns.py`、`tests/integration/test_soc_rfuzz_live.py`；复用 `rfuzz_live.py`、`rfuzz_wire.py`、`rfuzz_fifo.py`、`rfuzz_shmem.py`。

- [ ] 写真实客户端 opt-in 测试，记录 FIFO reply receipt、实际 RTL 执行、source/target transaction、corpus 与 input transport identity。
- [ ] 运行 `MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_live -v`，client 路径由显式配置给出。
- [ ] `run_soc_campaign` 负责构建/启动/执行/报告；sample reset 清除 driver、memory、CPU/IP、IRQ、coverage 的测试状态。协议/模型错误与合法软件 trap 分开归类。
- [ ] 添加正常结束、SIGINT、SIGTERM、超时、客户端失败、编译失败、复位中断、迟到响应测试，全部保存失败报告并清理本任务进程组/FIFO/shmem。
- [ ] 两个 CPU 各完成短 fuzz，保留语料从独立进程与重新构建二进制 replay；绝不以零输入 probe 代替 RFuzz 随机变异。提交 `feat: close official RFuzz loop on generated SoCs`。

## P15：八配置、三模式和偏置对照长测

**Files:** 更新 `configs/soc/matrix.json`、`scripts/run_soc_campaigns.py`；新建 `tests/integration/test_soc_campaign_matrix.py`；结果保存在 `runs/soc-acceptance/<batch>/`。

- [ ] 矩阵单元测试断言 24 个主任务与 8 个 mixed/bias-off 对照，任何缺格、重复或不足 300 秒有效预算都判 incomplete。
- [ ] 运行 `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_campaign_matrix -v`。
- [ ] 实现 CLI `--matrix PATH --output PATH --seconds 300 --seed INT --preflight-only` 与 `--rebuild-replay PATH`；preflight 不运行长测，完整检查 source/capability/CPU/IP/资源/工具依赖。
- [ ] 执行 `PYTHONPATH=src nice -n15 python3 scripts/run_soc_campaigns.py --matrix configs/soc/matrix.json --output runs/soc-acceptance/preflight --seconds 300 --seed 20260914 --preflight-only`。期望八配置 ready、32 tasks planned、零 unsupported。
- [ ] 使用新的 output 目录去掉 `--preflight-only` 串行执行。每 30 秒输出 tests/receipts/coverage/CPU与各IP进展/errors/RSS；结束后逐任务重建重放所有保留语料。失败任务保留原记录，以新 run ID 重跑，不能覆盖失败证据。
- [ ] 总有效预算至少 160 分钟，编译/初始化不计；报告随机种子与覆盖原始结果，不声称单种子统计显著。提交报告与小型 manifest，不提交大 corpus/编译目录。

## P16：收口、回归与剩余文件整理

**Files:** 更新 `README.md`、`QUICKSTART.md`、`docs/README.md`、`docs/PROJECT_GOALS.md`、`docs/REPOSITORY_ORGANIZATION.md`、`docs/ALL_TEST_RESULTS_MASTER.md`；新增 `docs/reports/soc-acceptance-20260914.md`（实际晚于该日期时按实际日期命名）。

- [ ] 在新功能冻结后运行 composition/protocol/integration 定向及全量 `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'`；分别报告 pass/skip 与真实配置验收。
- [ ] 审查旧入口兼容、名称无关性、唯一驱动、内存/IRQ 真值来源、CPU burst/宽度限制、迟到响应、覆盖类型和 replay 身份。
- [ ] 按 P0 精确清单执行第二批可恢复清理，更新 import/source list/文档命令；清理后运行受影响回归和至少一次保留 artifact 重建。
- [ ] 文档列出实际可执行命令、两款 CPU/六个真实外设 pin、八配置 × 三模式矩阵、偏置对照、错误与限制、恢复方法。
- [ ] 验收条件全部达成后标记项目完成；任一格缺失均写明未完成。提交 `docs: publish SoC acceptance and repository organization`。

## 本计划审阅记录

已按需求逐项映射：结构层 P3–P6/P10–P12；输入层 P7–P9；两 CPU P10/P11；三系列 P1/P5/P12；真实 RFuzz P13–P15；整理 P0/P2/P16。现有执行报告的覆盖边界与真实外设禁用问题已写入目标文件。本轮交付是计划与文档整理，以上代码实现和长测尚未执行。
