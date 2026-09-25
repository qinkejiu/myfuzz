# Ibex + PULP GPIO/SPI 首期缺陷发现设计

日期：2026-09-25
状态：用户已认可混合断言方向；本文件是实现前规格。
适用范围：`myfuzz` profile-driven SoC 组合与官方 RFuzz campaign。

## 1. 目标

建立一条能够针对真实 RTL 报告可复现行为违例的首期闭环：

```text
Ibex + PULP GPIO + PULP SPI profiles
  -> 组合计划与真实 RTL 构建
  -> 有界指令镜像/总线/外部引脚激励
  -> OBI/APB3/CPU/外设独立检查器
  -> 官方 RFuzz 语料、属性反馈与原样重放
  -> 环境排除、隔离复现和缺陷候选归因
```

验收结果必须区分“性质被触发”“组合环境异常”“组件缺陷候选”和“已确认组件缺陷”。构建成功、覆盖增加或单次断言失败都不单独证明某个上游 IP 有 bug。

## 2. 固定目标与基线

组合对象为当前仓库锁定的真实 RTL 和现有 profile：

| 实例 | 组件 | 本期配置 |
| --- | --- | --- |
| `cpu0` | Ibex `ibex_top` | profile 声明的 RV32IMC、指令与数据 OBI、当前固定源码闭包 |
| `gpio0` | PULP `apb_gpio` | `PAD_NUM=32`、APB3、12 位地址、32 位数据 |
| `spi0` | PULP `apb_spi_master` 及其固定依赖 | FIFO 深度 10、APB3、12 位地址、32 位数据 |

三个实例使用现有单时钟、异步低有效复位路径。两个外设各自取得不重叠且满足 4 KiB 对齐的 MMIO 窗口；由组合计划分配并写入 manifest。Ibex 的 `boot_addr_i=0x10000` 对应其 profile 声明的实际首条取指地址 `0x10080`。

新增一份 `composition_request.v1` 请求，组合 Ibex、GPIO、SPI 和现有 ROM/RAM。保留既有 Ibex+SPI 请求、独立 GPIO 请求以及旧 `ibex-pulp` 矩阵，不把它们改成隐式别名。所有 IP 仍以 profile/source lock 绑定；不得改写 vendor RTL 来迎合检查器。

当前已知限制：

- Ibex 顶层确实导出 RVFI，但 CPU profile/interface description 尚未把 RVFI 作为检查器观测端口登记；实现时须显式登记所需观测信号并核实实际连接。
- Verilator 构建下 Ibex `prim_assert` 宏展开为空，不能把 vendor `ASSERT` 宏当作运行时检查器。
- 现有 PULP GPIO 引脚端点还包含 `padcfg` 和 `in_sync`，已存在的通用电气 GPIO peer 因接口角色不匹配而拒绝 attach。不能强行复用该 peer。
- 已有 SPI 线级 oracle/peer 覆盖的是其他 SPI profile；它不自动证明 PULP SPI 固定单线模式的配置、引脚映射和行为。
- 既有 Ibex+PULP SPI 示例请求没有 GPIO；历史旧构建记录过 Ibex 包声明/源顺序问题。新 profile 组合必须对真实源码闭包重新构建和审计，不把旧构建状态外推为通过或失败。

## 3. 组合、输入和执行

### 3.1 复用现有生产链路

继续使用 `composition_request.v1`、component profiles、`soc_composition`、profile renderer、combined input layout、campaign artifact builder、官方 `kfuzz` transport、persistent Verilator testbench、corpus manifest 与 replay。不得另造 RFuzz 输入协议或用 seeded-corpus/mock run 冒充官方变异 campaign。

组合拓扑是 Ibex 的指令/数据 OBI 主接口进入 fabric，fabric 将每笔 MMIO 请求路由到各自的 APB3 adapter 和 GPIO/SPI 从接口。检查器放在生成 harness/边界 monitor，不改变被测 IP 的内部 RTL。

### 3.2 RFuzz 输入如何进入目标

每个原始输入按 artifact 固定的 layout 和 identity 投影：

1. 声明的指令候选在 CPU 仍保持复位时写入指令镜像；镜像冻结后再释放 Ibex。
2. `soc_stimulus.v1` 的总线字段驱动对应声明的 synthetic-MMIO 测试臂；在 CPU 执行臂中不得让 synthetic master 意外与 CPU 同时发请求。
3. 已登记的外部输入端口由原始 per-cycle 字段或有界事件计划驱动。PULP GPIO 的 `gpio_in`、SPI 单线 MISO (`spi_sdi1`) 是输入；其余 SPI 输入 lane 使用 profile 中有来源的空闲常量。
4. 每条测试记录保留 raw 输入、投影输入、镜像哈希、引脚事件哈希、组合/layout/source/tool identity 和 simulator receipt。

首期分开运行两个可解释的目标臂：

- **CPU 执行臂**：`drive_profile=cpu_execute`、`mode=cpu_only`。冻结的引导程序以真实 CPU 访问两个外设；fuzzer 扰动已声明的指令候选和外部 GPIO/MISO 输入。只有 reference checker 支持的指令才允许进入 CPU 正确性判定臂。
- **外设隔离臂**：`mode=mmio_only`，CPU 保持复位，由现有 synthetic MMIO master 产生事务；指令镜像不影响判定。用于增加寄存器/协议状态空间覆盖并定位 IP 边界问题。

`mixed` 作为前两臂独立验收后的组合扩展，单独记录 arbiter/fabric 的证据，不与外设隔离结果混为一类。三个 mode 可在 request 中声明，但不能在没有真实验证时统一写成已验收。

引导程序执行最小、明确的操作序列：启动并写出完成签名；读写两个外设；测试 GPIO 方向、输出、输入同步及只读状态；完成 PULP SPI 标准单线 mode-0 的有限传输，比较 RX 数据并写入 RAM 签名。程序、预期签名和允许指令集合固定并入 image manifest。随机指令若破坏程序进度，应由 CPU reference 归类；不得把“未访问 IP”样本计作有效外设覆盖。

## 4. 独立检查器

使用项目自有 sidecar monitor/scoreboard，在 reset 后启用并输出属性覆盖位、sticky failure 位、首个 property ID 与 cycle。失败只结束当前 testcase 并进入 RFuzz 反馈/证据流，不用 `$fatal` 终止整个 campaign。每条规则登记稳定 ID、时钟/复位、前提条件、判据、契约来源、适用参数、采样次数及负例注入方式。

### 4.1 Ibex OBI 与执行语义

- 分别监视 instruction/data OBI：`req && !gnt` 时请求与契约载荷保持稳定；grant 创建一笔 outstanding；response 必须匹配此前已接受请求并遵守该 profile 声明的顺序/数量边界；不得出现无请求的 response 或丢失/重复响应。
- 只对 profile/OBI 契约和实际信号支持的规则断言；最大 outstanding、错误响应与等待上限没有证据时不自行设定。
- 把 `rvfi_valid/order/insn/pc/mem` 等必要 RVFI 字段接到 harness。检查 retirement 顺序、指令取值/地址与 ROM 镜像一致、RVFI memory commit 与已接受的 CPU 总线事务一致。
- CPU 运算语义使用独立 RV32IMC reference checker。参考模型逐条消费退休记录，并把实际数据/指令响应作为明确的外部输入；不从 DUT 内部状态或 DUT 输出反推期望。只在参考模型支持的指令、异常及内存语义内判定。unsupported opcode、CSR 或 trap 进入 `not_assessed`，不能静默当成 pass。
- 如首期只能建立已知程序签名而没有独立执行参考，则该运行最多证明 CPU 总线/退休接口契约及程序 smoke，不得称为 Ibex 指令功能 fuzz 已通过。

### 4.2 APB3 与 fabric 边界

在 CPU OBI 端、fabric 路由端和每个实际 APB3 target 端关联事务：

- SETUP 后才能进入 ACCESS；ACCESS 等待期间 `PSEL/PENABLE/PADDR/PWRITE/PWDATA` 按 APB3 规则稳定；一次被接受的访问最多产生一次副作用和一次对应响应。
- 地址译码只能命中计划中的唯一 GPIO 或 SPI 窗口；响应数据、错误及完成状态回到原始发起请求。
- 记录 byte enable 到无 strobe APB3 的转换。两个 PULP target 都没有 byte strobe 且 profile 不支持 partial write，任何无法无损表达的子字写必须在 adapter 边界拒绝/显式分类，不能静默执行为全字写。
- 对这两个锁定 PULP 版本，`PREADY=1`、`PSLVERR=0`。这些是当前目标约束；错误地址的响应规则由 fabric 契约决定，不能错误地要求 target 自己拉高 `PSLVERR`。

### 4.3 PULP GPIO 行为

独立 scoreboard 绑定实际 APB 接受事务和 32 个外部 pin。覆盖并判定：

- reset 值及 PADDIR、GPIOEN、PADOUT、PADOUTSET/PADOUTCLR、PADCFG 寄存器语义；对 PADIN、INTSTATUS 等只读/读清副作用按访问顺序更新 reference state。
- `gpio_in` 经 `GPIOEN` 使能的每四 pin group 同步；reference pipeline 根据外部输入样本计算 `gpio_in_sync`/PADIN 期望，不能把 DUT 暴露的 `in_sync` 当成输入真值。
- `gpio_out` 与 `gpio_dir` 逐位符合寄存器状态；仅对 profile 当前 `PAD_NUM=32` 参数作出声明。
- 中断输出作为事件脉冲观测并与配置、同步输入边沿、INTSTATUS latch/read-clear 行为关联。脉冲不直连当前 level-only IRQ controller，也不据此声明 CPU ISR 已验收。
- 只断言 profile/人工审阅的契约行为。源码中上地址位别名等行为可以作为现状观察，但若没有独立规范依据，不作为“符合规范”的断言。

该检查器是针对 PULP 分离式 `gpio_in/out/dir/padcfg/in_sync` 接口的 monitor，不宣称实现真实 `inout` 电气分辨率、pad pull/drive strength 或板级电气行为。

### 4.4 PULP SPI 行为

实现与实际 PULP pin roles 相符的 harness adapter/peer 与独立线级 scoreboard：

- 输入 MISO 接到 `spi_sdi1`，采样 MOSI `spi_sdo0`；在首期标准单线模式下，其余 SDI lane 接有据可查的 idle 值，其他 SDO lane 全部观测，避免漏掉错误的 lane 驱动。
- 只覆盖固定 SPI mode 0、MSB-first、配置范围内的单线有限传输；检查 SCK idle/采样边沿、片选有效窗口、数据位数、MOSI 与预先写入 TXFIFO 的数据、MISO 与预先 armed 的 peer 数据、RXFIFO 返回值。
- scoreboard 的期望来自独立输入事务和固定的 PULP register/serial contract，不读 DUT 内部 FIFO/状态来构造期望。记录完整四线轨迹；轨迹缺失、输入未 arm 或配置不在准入范围时为 `not_assessed`。
- 检查 TXFIFO push/RXFIFO pop、FIFO 深度边界和 APB register side effect，但只对已有明确规范/冻结契约的行为做 pass/fail。软件 reset 不宣称会复位 controller/FSM；`spi_swrst` 仅按已知功能边界处理。
- `events_o` 保持观察，不接入 level-only IRQ controller，不声称完成 CPU 中断闭环。Quad/QPI 与 SPI DMA 不纳入首期。

现有 `soc_spi_peer.sv` 与 PULP 的 4-lane role set 不自动匹配。可在 sidecar harness 内用明确角色映射复用已审阅的 mode-0 peer/trajectory 逻辑，或加一个 profile-declared adapter；实现选择必须通过实际 elaborated port 审计，并纳入 artifact/source identity。

## 5. 断言与 bug 归因边界

按来源把规则分为：

1. **标准/接口契约规则**：例如 APB3、profile 记录的 OBI/PULP/CPU 假设；可作为契约违例候选。
2. **独立行为 reference 规则**：由 checker 自身状态、字面测试向量、独立 ISA interpreter/ISS 产生期望；可以发现相对 reference 的 mismatch。
3. **source-derived 探针**：用于定位上游当前实现的行为或组合偏差；若无外部规范或独立 reference，不可单独升级为已确认组件缺陷。

Checker 失效或执行前提不成立时输出 `not_assessed`/`undiagnosed`，而不是 pass。每个失败保留最早违例上下文、原始/投影样本、波形片段、CPU 提交/总线轨迹、外设操作、检查器版本与完整构建 identity。Fuzz 阶段先分类为 `assertion_candidate`、`composition_defect`、`CPU candidate`、`peripheral candidate` 或 `not_assessed`；通过原样重放、实际结构审计、输入假设核对与适用的独立夹具复验后才能确认组件缺陷。已存在的 NovaSPI 离线注入结论不自动迁移到 PULP SPI。

在 Verilator 运行中不依赖被清空的 vendor assertion macro。检查器应有自己的故障反馈通道，并把属性覆盖与 RTL branch coverage 分开报告。

## 6. 启动门槛和验收

按以下顺序执行；任一门槛失败都保存具体诊断并停在该阶段：

1. **静态组合门槛**：加载三份 profiles 与新请求；校验源码 revision/content hash、端口处置完整、时钟复位一致、地址窗口不重叠、GPIO/SPI 各自接到 APB3。
2. **真实 RTL 构建门槛**：按锁定 source closure 编译 Ibex、两个 PULP IP、fabric、memory 和 checker。缺 package/source 或 toolchain identity 不符均为 build failure，不能回退到 mock。
3. **定向正例**：固定 firmware 能启动；两个 APB target 均有真实事务；GPIO 输入/输出场景通过；PULP SPI 至少完成一笔 full path transfer；RVFI/OBI/APB/GPIO/SPI checker 各有非零采样数。
4. **检查器校准**：逐类注入可控的 checker-side/RTL-boundary mutant（OBI payload stall、APB setup/hold、地址错路由、GPIO readback/同步、SPI lane/edge/data 错误）。好版本不得误报，每个负例触发预期的稳定 property ID；注入故障只计入 checker calibration，不计为自然 bug。
5. **RFuzz 启动**：先运行有界官方 `kfuzz` CPU 执行臂与 `mmio_only` 臂，保存 receipt、非空 corpus、RFuzz/Verilator/source/layout/image/checker identity、RTL coverage、属性覆盖和引脚事件证据；使用既有 interrupted-client policy 时，只有 corpus/replay/cleanup 全部完整才可记为成功。
6. **长时运行**：定向门槛和短 campaign 通过后启动至少 600 秒首期官方 fuzz；持续写入有界周期报告，监测已完成测试、target-side 事务、属性触发、覆盖新增速率、语料增长、超时及进程/共享内存清理。结束后以同一 identity 重放失败样本及保存语料，并记录 replay 状态。
7. **错误分类**：如果出现 mismatch，先原样重放，再按第 5 节分类；只有输入合法、checker 独立、组合结构正确且隔离/等效证据充分，才写 `component_confirmed`。发现 assertion 不自动中断其他样本搜索。

Campaign report 最少包含：目标 arm/mode、计划和地址表、IP/source closure 哈希、工具版本、input/layout/image/checker identity、每个 checker 的 sample/pass/fail/not-assessed 计数、CPU retire/OBI 请求响应计数、每个 APB target 事务、GPIO/SPI 行为覆盖、RFuzz receipt/corpus、replay 与 cleanup 状态。

当前环境 shell 默认解析到 Verilator 5.051 development build，且 `spike`/交叉编译器未在 PATH 中发现；profile RFuzz 生产路径必须用仓库固定的 bundled Verilator 5.020。CPU reference 的具体实现及依赖因此列为 build/preflight 验收项；不能在缺少架构 oracle 时把仅有的 OBI/RVFI 形状检查报告成 CPU 功能 fuzz 通过。

## 7. 首期范围之外

- GPIO/SPI 脉冲到 Ibex ISR 的端到端交付；两 IP 的 pulse outputs 只观测。
- GPIO 真正双向 `inout` pad、电气 pull/drive/contention 与板级 timing。
- PULP SPI Quad/QPI、DMA、多时钟域、其他参数组合及跨时钟接口。
- 未有独立规格的保留寄存器、未定义 reset 或地址 alias 行为的组件缺陷确认。
- 任意 CPU/profile/IP 组合的正确性保证。

## 8. 可交付结果

本设计实现后的首期交付包括：双 PULP IP 的现代 composition request；可审计的真实 SoC 构建；项目自有 CPU/OBI/APB/GPIO/SPI sidecar monitors 与独立 reference；正/负例校准记录；两个官方 RFuzz campaign 的语料、重放和长时运行报告；按证据分级的缺陷候选包。此范围完成之前，不声明 Ibex 指令功能或 PULP 外设功能已被完整 fuzz 验收。
