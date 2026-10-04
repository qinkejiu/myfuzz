# 独立 RTL Harness 自动生成与五协议首期覆盖设计

日期：2026-10-04

## 1. 目标和边界

系统接收一个新 CPU 或 IP 的受信源码描述、接口 profile、协议选择与少量声明式微调，自动生成该组件的**独立** RTL harness、局部协议执行器、构建清单、场景 session 注册信息和可重放身份。用户可以在不修改生成器源码的情况下接入同协议但端口名称、复位、可选信号或中断语义略有不同的组件。每个组件由真实 RTL 执行；现有 ScenarioRunner、Memory Model、Dataflow Router、Dependency Scheduler、Fuzzable Source / Bound Input 和 Dependency Path 继续负责持续 testcase 与跨组件因果传播。

生成器不构造 Bus、Crossbar、Bridge、Arbiter、PLIC 或具体 SoC；各 harness 之间只交换已提交的事务、真实输出、事件和持久状态。每个组件保留其原生接口、局部握手和局部周期；组件之间只保证事件因果，不强行建立全局 cycle-accurate 时序。

“支持”分四级记录，任何页面或命令不得将低等级写成高等级：

1. **Catalog**：协议、组件候选及接口事实可解析。
2. **Generated**：源锁验证、端口绑定、每个 DUT 输入的归属及 wrapper/执行器生成通过。
3. **RTL operational**：真实 RTL 编译、启动、局部协议交易、持续状态与有界结束通过。
4. **Cross-component accepted**：至少两个独立 harness 在同一 testcase 形成真实输出传播、双方向因果链、从初态完整 replay 与约束检查通过。

现有手写 Ibex/CVA6/OpenTitan session 与 G2/G3/G4 证据保留；新生成器的验收另记，不把旧手写 harness 成绩算作生成器成绩。BOOM 若仍缺本地可执行 RTL 和 filelist，标记 `skipped_unavailable`，不计为通过。

## 2. 首期协议与真实 RTL 候选

五种 **CPU 侧**原生协议按以下组合实施。这里“协议”是边界交易契约，不承诺协议标准的所有可选特性。

| 协议模板 | 首个真实 CPU 候选 | 必须显式处理的差异 | 验收范围 |
|---|---|---|---|
| OBI request/grant/response | Ibex，第二实例 CV32E20/CVE2 | 指令和数据端口、fetch 使能宽度、起始 PC、外部 IRQ、可同时在途请求 | 两端口真实取指、Store/Load、响应归属；CVE2 跨系列复用 |
| AXI4 | CVA6 | packed noc 结构字段、ID、burst 与响应通道 | 以当前 CPU 与生成执行器共同声明并实际测试的有限单 beat/在途范围验收；不得宣传完整 AXI4 |
| AXI4-Lite | `picorv32_axi` | 该顶层缺少 BRESP/RRESP 引脚；缺项必须以 profile 的合法固定响应或拒绝规则解释 | 五通道真实完成、写后读、无重复交易 |
| Wishbone classic | `picorv32_wb` | 该顶层没有 ERR/STALL 引脚；ACK、CYC、STB、SEL 规则由实端口证明 | 保持请求至 ACK、byte select 写、无重复交易 |
| PicoRV32 Ready/Valid Memory | `picorv32` | `mem_ready` 表示**完成**，不是请求已被接收；不能在 RAM 返回前提前拉高 | 真实取指、写后读、每次请求仅完成一次；后端错误策略明确 |

PicoRV32 当前普通顶层 profile 的 revision 为占位值，`_axi`/`_wb` 也未有独立 profile。进入 Generated 前必须从本地 checkout 生成受信 revision、完整源清单和逐端口绑定；占位 revision 禁止通过。CV32E20 亦须新建以真实 checkout revision、参数、源闭包和端口为依据的 profile。现有 Composition 的 processor adapter 和协议插件只能作为契约参考，不能作为独立 harness 已可运行的证据；尤其 Ready/Valid 现有 adapter 的 IDLE ready 语义不适合 PicoRV32 的完成握手。

**外设侧**首期组件库使用现有真实 RTL：OpenTitan GPIO、UART、SPI Host、I2C、RV Timer、SPI Device（TL-UL）；PULP GPIO、SPI（APB3）；ZipCPU UART、Timer（Wishbone 变体）。外设类型覆盖 GPIO、UART、SPI、I2C、Timer。APB4 与 AXI4-Lite target 可进入协议模板目录，但没有真实外设独立运行证据之前只标记 Catalog/Generated。每种外设须分别声明寄存器事务、外部环境源、真实输出、IRQ 形态（电平或脉冲）及 peer 要求。PULP/ZipCPU 现有 SoC target wrapper 不算独立场景 harness；ZipCPU UART 的隐式 Verilog wire 必须先解决端口事实提取。

## 3. 输入契约与自动生成流程

输入分为 `component_profile.v1` 和新的 `local_harness.v1` 请求。前者固定 RTL revision、源闭包、顶层、参数、原生端口、协议 endpoint、复位和 pins；后者只选择单个组件、endpoint、局部 transport、时钟/复位策略、环境 source、输出观察点及有限声明式微调。禁止将任意 SV/Python/C++ 代码片段作为微调项。

编译顺序为：

```text
受信源码与 profile
  → 源闭包校验及 elaborate_profile
  → bind_profile 的方向/宽度/结构事实
  → 全 DUT 端口 disposition 与输入所有权证明
  → 协议模板实例化及局部执行器
  → 生成 wrapper、driver、build manifest、session registration
  → Verilator 编译/真实局部交易/可重放身份门禁
```

生成器复用 `component_profile.elaborate_profile/bind_profile` 与端口 disposition 的事实检查，但建立单组件计划/渲染入口；不调用 `build_composition` 或 `render_composition` 来制造多组件 fabric。对于每一 DUT 输入位，只有四种驱动归属：协议执行器、Fuzzable Source 环境执行器、已绑定真实上游值、声明式常量。输出只被观察或送往 Router；未归属、多重归属、宽度不符、方向不符、未经证明的结构成员都 fail closed。inout 端口要求专门 pin transactor；没有时拒绝，不将其默默拆成独立输入输出。

声明式微调限于：端口/结构字段映射、合法常量、参数、复位极性与周期数、取指起点、等待上限、可选信号默认响应、IRQ 电平/脉冲、寄存器字宽/byte-enable 能力、外部 pin/peer 映射、允许的局部在途数。每个微调必须写明适用 endpoint、由已验证源码事实支撑，并纳入 identity；若它改变协议语义，需要协议模板显式提供该变体，不能用后处理脚本改生成 SV。

## 4. 运行时与持续 testcase

生成的 `GeneratedLocalSession` 对现有 ScenarioRunner 提供 begin、step、reset、quiesce、end、identity 与真实输出观察接口。一个 testcase 内不重复 reset，CPU/IP RTL 状态、RAM、事务账本、Pending Event 与场景状态持续；只有显式 reset 或 testcase 结束按现有 policy 清理。局部执行器接收唯一命令/事务 token，重复命令返回缓存结果或拒绝冲突载荷，不能再次驱动同一真实交易。

CPU 程序、初始 RAM、GPIO pin、UART RX、SPI peer、I2C peer 等无真实上游绑定的环境值可变异。若输入已经绑定上游真实输出或持久 RAM，则必须使用该值；首次未初始化 RAM 读取可由 Fuzzer 物化一次并保存，后续读复用，真实 byte-enable 写覆盖对应字节。原始 RTL 输出即使违反预期事件顺序也要记录并交给 checker，Scheduler 只约束**下一步可生成的输入**，不能替 DUT 制造 DONE、IRQ 或 rdata。

Router 仅映射真实数据的来源与去向；Scheduler 仅检查因果先决条件并选择组件下一步。脉冲 IRQ 在观察边界以带序号的事件捕获，再按声明的 delivery policy 交付给 CPU；电平 IRQ 按实际电平保持。两者不得互换。场景 Genome 是连续动作序列，支持 CPU→IP→CPU、IP→CPU→IP 和多组件链；Fuzzer 反向搜索 Dependency Path 以选择最上游可变异源。

## 5. 可重复构建与证据

每份生成结果保存 profile、源 closure/revision、参数、协议模板版本和 SHA、微调配置、生成器版本和 SHA、生成文件 SHA、Verilator/C++ 工具链版本、局部 session 能力表。Replay 从初态重建相同身份，重放完整 Genome、环境首次物化值、事务 token、局部输出、Router/Scheduler 事件、RAM/IRQ 末态；身份不同先拒绝，不以“近似输出”冒充完整回放。

新生成器源码不能无意将旧固定包的全局宿主身份全部作废。宿主身份由每个 harness 实际依赖的代码闭包计算；迁移旧包时保留旧 schema 的验证路径，并在新包中使用新 schema。任何语义源码变化都需要重新录制受影响证据。

## 6. 实施阶段和验收标准

### 阶段 A：生成器底座与 CV32E20＋双 PULP GPIO

1. 从 CVE2 与 PULP GPIO 真实 checkout 建受信 profile；源锁、elaboration 与每个 DUT 输入归属全部通过，错误 profile 被拒绝。
2. OBI CPU 和 APB3 GPIO 的 wrapper/局部执行器由单组件请求确定性生成；两次同输入生成文件 SHA 一致，不包含 SoC fabric。
3. CVE2 真实取指、Store/Load、外部 IRQ；双 PULP GPIO 真实 APB setup/access、pin→状态→脉冲 IRQ；局部请求/响应、超时和重复 token 有可观察证据。
4. 单 testcase 完成 CPU→GPIO A→GPIO B→CPU 与 GPIO B 外部输入→CPU→GPIO A 两方向，至少各两轮、无隐式 reset；每个跨组件值可追溯到真实 RTL 输出或持久状态，Bound Input 无再随机覆盖。
5. 新 Runner 从初态完整 replay 相同事件、局部周期、RAM、IRQ 与事务账本；故障注入可证明重复交易、错方向绑定、未满足依赖和错误 IRQ 类型被拒绝或记录为 checker finding。

### 阶段 B：五种 CPU 协议

每种协议至少一个上述真实 CPU 候选达到 Generated 与 RTL operational：生成 wrapper 和局部执行器，真实程序完成取指、Store、Load、写后读、byte-enable（若该接口有 byte enable）、明确有界结束、无重复事务、完整 replay。CVE2 用于证明 OBI 模板在第二种 CPU 上复用。AXI4 必须记录实测 ID/burst/在途限制；PicoRV32 三变体各有独立受信 profile。若候选源不可执行，只能 `skipped_unavailable`，该协议不能记为通过。

### 阶段 C：常见外设系列

OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 各至少一个**由生成器产生**的真实独立 IP harness 达到 RTL operational；GPIO、UART、SPI、I2C、Timer 的已列本地候选逐个登记其实际等级。需要串行 peer 的 SPI/UART/I2C 必须使用真实 pin/frame 驱动和实际 RTL 输出；无 peer 不得把 register-only 测试记为完整 IP 验收。每个可运行 IP 提供跨组件事务/IRQ 或数据传播案例和完整 replay。

### 阶段 D：未来新组件接入门禁

选择未写入生成器 Python/SV 分支的新同协议 CPU/IP，仅新增受信 profile 与允许的微调配置；生成、编译、真实交易和 replay 均通过，作为“无需手写 harness”的最终证明。若需要新的协议语义，应新增独立模板版本，而不是塞入组件专用条件。统计输出分别列出 Catalog、Generated、RTL operational、Cross-component accepted、skipped_unavailable 和失败原因。

## 7. 拒绝条件与退化防护

- 不能从端口名猜测协议功能或 pin/IRQ 语义；缺源码事实就拒绝。
- 不把协议插件、SoC target wrapper、语法通过或已有手写 session 视为生成 harness 真实运行。
- 不为方便凑闭环直接随机 CPU 的已绑定 rdata/IRQ，或直接随机 IP 的已绑定配置寄存器。
- 不让 Router/Scheduler 生成 DUT 应输出的状态，不过滤不符合期望的真实 RTL 输出。
- 不用跨组件固定 cycle 偏移或 Bus/Bridge/Crossbar 实例来替代抽象因果传播。
- 不用每步重新 reset、每次读重新随机或重复 token 重执行来获得表面覆盖率。
- 不把 APB3 无 PSTRB、脉冲 IRQ、AXI4 有限子集及 PicoRV32 缺省响应信号伪装为协议全功能支持。
