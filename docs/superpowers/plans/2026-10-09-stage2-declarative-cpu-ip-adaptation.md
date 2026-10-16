# 第二阶段：通用 CPU 与 IP 声明式适配实施清单

本轮 Task3 Path 分派聚焦候选（2026-10-12）：Path.open 缓存旧源码攻击 RED 1 failed；公开分派 RED 12 failed；special-entry RED 10 failed。已固定 Path 工厂与实际 concrete 类型完整 MRO、成员/descriptor/accessor identity 与 code，规则绑定和运行时守卫均检查；最终聚焦 26 passed / 73 deselected，10.39s，未执行 native 或最终 full regression，仍待精确 SHA 独立复核。verifier `229485466093033be9f96c38bfc8dfbd757c92daf7ca93912577964b04fb255f`，tests `7b6527f0530869cb0c497517f06d927d5e59e668a1376ae053413630dbd3e090`；旧 92-pass 兼容结果仅属于此前冻结候选，不能证明本轮改动。

支持边界：拒绝标准类属性改写，并假定加载中的 Python 代码对象完整；不覆盖直接改写 function.__code__、显式 type.__setattr__ 或同进程任意私有 Runner slot 改写。覆盖这些攻击需在冻结 Runner/NRE 分派加入独立检查或原生不可变边界。Path 类公开分派已纳入检查；stdlib 内部对象内容（如 `_flavour`）与任意 module helper 改写不在本轮闭合范围。Task3 仍仅 source-rule/refusal 软件范围，不授 native reset certificate、functional 或 verified L2；原 Stage2 D5/D6/D8、完整 E1/E2 与 E3–I 继续开放。

2026-10-12 当前检查点：v5实际 generation 已终态 exit0／resource complete，单worker 178.410330162秒，峰2,626,240,512 bytes低于3,125,706,752限额；原14 cases与完整ordinary／verifier验证范围保持。production fresh CLI串行重试已终态exit0／complete，167.28877223400923秒、available5,320,716,288 bytes、峰2,667,540,480 bytes低于3,173,232,640限额，workers1；完整semantic／event count／ordinary／verifier／preflight比对通过。见[fresh结果](../../../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-cli-verification.json)。独立最终产物审计已通过（exit0）：9认证产物／283项当前源码pins／29,985events／14次exact重编译／13证书／21封存access／28关联／6RAM，fresh全部wrappers及preflight完全相等，两阶段resource均complete；见[独立审计](../../../runs/stage2-e2-register-verifier-cli-20261012-v5/independent-audit.json)。本轮scoped verifier／保存／fresh包已闭合，完整Stage2仍未完成；下一包按declarative generic关系推进SET／CLR alias行为及非空saved-file回放，不授aggregate L2或functional。首轮与大JSON只读审计重叠导致RSS budget_terminated，return124／7.965711960秒的失败证据保留于[首轮归档](../../../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-attempt-1-rss-budget-terminated/)，预算策略未提高；generation与fresh各用独立180秒预算，不是combined180通过。见[实际摘要](../../../runs/stage2-e2-register-verifier-cli-20261012-v5/summary.json)及[资源记录](../../../runs/stage2-e2-register-verifier-cli-20261012-v5/resource.json)。当前build SHA `06334fedf08cacd861806362dc216026af3b426cd80be2ceb10929ff2197056c`、integration SHA `7fe28b291fd2f2164db5edcaffd6ad7b8c0a5a6a52d43d82f87cc974c8583774`已核对；旧v4完整保存但wall_timeout证据保持历史。D5／D6／D8、完整E1／E2及E3–I继续未完成。

2026-10-12 当前继续：v4在178.245秒完成认证保存及summary，但worker整体180.093秒超时，generation未通过、fresh未执行。三子代理并行完整bundle独立审计、退出阶段定位与真实导出成本测量；原预算/源码冻结/失败产物和完整Stage2范围保持。见[执行报告](../../reports/stage2-e2-register-verifier-session-execution-20261012.md)。

2026-10-12 最新执行：窄READ及scoped verifier软件边界已验证；v2真实14case/28确认关联/6RAM/29985events通过（140.50秒），production可信file freshCLI独立通过（133.80秒），完整state/semantic匹配，A/B各148declared/142effective/0verified、L1。首次factory固定READ16失败已补RED修复并保留产物，最终独立audit通过 findings=[]。下一包Session verifier opt-in已有8缺API RED＋1defaultoff GREEN，生产未实现；完整Stage2/E1/E2继续。详见[执行报告](../../reports/stage2-e2-register-verifier-execution-20261012.md)。


初期执行记录（后续v2结果见上）：2026-10-12 寄存器行为 verifier／窄字段实际CPU READ 执行中：三子代理并行，Root completed-access封存4RED→31GREEN，actualreadback/reset/mask/permission/effects与exactfield能力继续，未授storage/functional/aggregateL2，未运行本轮新DUT。见[执行报告](../../reports/stage2-e2-register-verifier-execution-20261012.md)。

2026-10-12 production ordinary APB Session／assembly／可信file fresh CLI已实现并验证：真实10case新增18关联，加bootstrap6条共24完整snapshot，22387事件；分阶段freshCLI exit0，原组合180秒超时保留。默认38/40、启用278项闭包，全部grantsFalse，原Stage2/E1/E2仍继续。见[执行报告](../../reports/stage2-e2-ordinary-access-production-replay-20261012.md)。原 Stage2／E1／E2继续。

2026-10-12 ordinary APB Runner association 软件包已实现并独立复核：实际 CPU closure／请求与响应绑定、私有 parsed sample digest／callback confirmation、命令前解码和容量检查、raw/base 独立 journal 引用及 reset 缺口处理。最终覆盖212个不重复软件测试／34子测试：联合211pass／1旧fixture失败，最终Runner模块10pass补证，生产SHA无漂移；详情见[执行报告](../../reports/stage2-e2-ordinary-access-association-20261012.md)。未运行新DUT门禁，生产Session/assembly/fresh回放和行为verifier继续执行，E1/E2及完整Stage2仍未完成。

2026-10-12 ordinary APB receipt 第一软件包已实现并独立复核：默认关闭的目标端实际 command／APB 边界 receipt 与 Router 真实事务交接；根十模块 **166 passed／34 subtests（128.51 秒）**，独立19项与容量／身份2项通过。typed identity、tick基址错位、同epoch新进程ID覆盖、容量漂移及合法read sourcewdata拒绝均有RED→GREEN；callback确认交付与同步返回分开，失败不重执行。仅 target command observation，不授 storage／verified／functional。未运行新RTL，Runner raw/base journal关联、生产opt-in replay接线与行为verifier仍待继续，E1/E2及完整计划保持未完成。 见[本轮实现与验证报告](../../reports/stage2-e2-ordinary-access-receipts-20261012.md)。此前实际gate仅证明各自冻结版本。

2026-10-12 最新实际结果：E2 capability preflight opt-in 门禁执行通过（exit 0）：10 cases（8 RMW／2 READ）、54条实际APB边界、2次read→RAM认证commit，可信CLI fresh完整22,339events matches。requested minimum L1，startup报告＝plan报告＝fresh CLI报告；每个实际GPIO alias保留完整14寄存器／72字段矩阵，declared L2／effective L1／verified None。46项冻结source pins包含40项production closure；identity SHA `308cb88e87c6b300ae12d60dd9c200a0328d5a0352dd02a2ced48ce918ab716d`，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。singleworker complete154.998309826秒，峰2,472,001,536 bytes、RSSlimit3,291,369,472 bytes，available5,438,853,120 bytes。独立产物audit已通过，findings=[]：46项源码pins／40项production closure／9项authenticated artifacts、10次重编译／18次实际CPU MMIO交付／54条APB边界／2次RAM commit／22,339events核对一致；本轮cache实际GPIO279／279项、CPU348项冻结输入核对通过（旧门禁278／278／347保持历史）。root额外只读startup重建configuration／report同SHA匹配；环境身份差异与fresh全trace未另存的限制见本轮报告。见[独立audit](../../../runs/stage2-e2-register-capability-cli-20261012/independent-audit.json)。详见[本轮capability报告](../../reports/stage2-e2-register-capability-preflight-20261012.md)。 见[本轮实际摘要](../../../runs/stage2-e2-register-capability-cli-20261012/summary.json)及[资源记录](../../../runs/stage2-e2-register-capability-cli-20261012/resource.json)。

`make_register_assembly()` 默认不加入 `requested_minimum_level`，旧schema16／17、runtime configuration与assembly布局保持；默认38项生产闭包。显式None／L1／L2／L3开启通道，40项闭包补入capability helper与等级模块；完整矩阵不能满足L2时在命令前拒绝。安装实际adapter后、begin前调用 `Session.configure_register_capability_preflight()`：startup／begin／fresh重算当前实际支持及minimum，保存manifest／plan的opt-in报告；执行后导出startup pin，不因slot消耗重算能力。保存assessment不是权限，verification=None，不授functional或verified L2。

软件证据：根联合162 passed／36subtests（205.90秒）在最后legacy helper一行修复前完成；修复后联合31 passed（90.49秒），独立软件16 passed（30.19秒）；两项P2均有RED→GREEN证据，当前实际门禁使用最终冻结源码。source-pin漂移在prepare／submit／cached retry三个实际对象负例RED后修复，注册及返回缓存前拒；legacy无native base trace却产生无效报告的负例RED后修复，完整declared矩阵与unsupported gaps保留。本轮实际摘要确认40项production closure／46项总pins；capability preflight与minimum接线已交付。E1／E2 checkbox继续未完成，剩余code-owned分操作verifier／证书、实际reset／权限／mask／width及已支持副作用行为、verified矩阵／L2 minimum证据。旧门禁仅证明各自冻结版本，不能证明本轮源码。

历史冻结版本检查点：2026-10-12 E2可信保存文件CLI门禁执行通过（exit 0）：10 cases（8次窄字段显式CPU RMW＋2次DIR／OUT full-word READ）、54条实际APB边界、2次read→RAM认证commit；保存plan为schema16，production `replay-register-programs` 从fresh实际factory／before-begin adapter重编译原requests，完整22,339events matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。verification scopes为 `register_program_reconstruction`、`register_program_admission`、`online_complete_prefix`；identity SHA `d2a480c0a9e889930782de5e79f083fe4d2bc595f01d1845ca883c6cab9f9277`。44项冻结source pins包含38项生产selector闭包，单worker complete137.546529879秒，峰2,442,502,144 bytes，RSSlimit3,231,547,392 bytes。根软件105 passed／26subtests（136.20秒），另2项保存投影positive通过（9.85秒）；独立软件35 passed／24subtests，selector完整16 passed／24subtests（63.45秒）。独立产物audit已通过：44项源码pins／38项production selector闭包／9项authenticated artifacts、10次当前上下文重编译／18次CPU MMIO交付／54条raw APB边界／2次RAM commit／22,339events及3个cache binary的278／278／347项冻结输入核对一致。E1仍为14寄存器／72字段declared范围；E1／E2完整阶段checkbox保持未完成，schema17已实现并软件验证；真实注入fault门禁不是原计划新增验收前提。原计划剩余为capability等级证据与实际reset／权限／mask／width及已支持副作用行为验证，不授functional、verified L2、RFuzz或BFM。旧四字段／helper／runtime门禁按各自冻结版本保留，不能证明本轮改动。 见 [新门禁摘要](../../../runs/stage2-e2-register-file-cli-20261012/summary.json)及[E2报告](../../reports/stage2-e2-gpio-cpu-register-progress-20261011.md)。 见 [独立audit](../../../runs/stage2-e2-register-file-cli-20261012/independent-audit.json)。

新生产接口为 `make_register_assembly()`、`make_register_factory()`、`make_register_runtime_factory()`、`save_ibex_pulp_register_bundle()` 与 `replay_ibex_pulp_register_files()`。Session在declare slots后、begin前安装实际adapter；schema16保存正常register前缀，schema17保存真实uncertain attempt的phase／case_index与nullable Session failure，均包含原requests／完整配置及actual gate_state。可信闭集ordinary GPIO assembly固定native observation／memory commit／installed persistent gate，checker=None；38项当前源码闭包、artifact SHA、trace事件语义、plan／manifest／terminal state先验证，fresh执行只重编译原requests，不以saved paths／bytes／regions恢复授权。

历史检查点（按当时冻结源码；本轮结果见上）：2026-10-12 最新：E1 GPIO 数据声明覆盖14寄存器／72字段，E2 actual-context `RegisterProgramRuntime` API 与显式CPU RMW已落地。本轮真实门禁执行通过：10 cases（8次窄字段显式RMW＋2次DIR／OUT full-word READ），54条实际APB边界、2次read→RAM认证commit；每次RMW用实际CPU读值核对保留位及新值，同寄存器后续读值与前次写值一致。fresh factory在begin前重装adapter、从当前实际waiting slot重算原始requests并exact核对manifest；完整22,339events、runtime snapshot与plan均matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。36项当前source pins严格冻结核对通过，含72字段sidecar SHA `f9b4837c6ca06b97a0ceb76f134ed7591538ab6d9c3e94c7839fc8ab63b7459b`。singleworker complete72.416334056秒，峰1,619,726,336 bytes，RSSlimit2,815,479,808 bytes。根六模块181 passed（12.54秒）；独立产物审查通过：36源码 pins、10次当前上下文重编译、18次CPU MMIO交付、54条APB原始引用、2次RAM commit、22,339事件摘要及3个cache binary／276、345、276项冻结输入一致；fresh state文件独立相等，fresh plan／全trace由冻结worker断言核对（未另存fresh全trace）。scope=`installed_context_adapter_explicit_cpu_rmw_and_fresh_request_recompilation`；保存context／bytes不作运行授权，不含RFuzz／BFM／可信CLI selector，不授L2 verified或functional，完整Session schema／selector接入仍待完成。旧4字段／helper门禁按各自冻结pins保留为历史证据，不能证明本轮源码。E1／E2、D8／D5／D6及完整E–I仍未完成。 见 [E2报告](../../reports/stage2-e2-gpio-cpu-register-progress-20261011.md)。

日期：2026-10-09。状态：实施中，M0 基线门禁已通过，B1–B6、C1–C7 已完成，M1 软件门禁通过，进入 M2。本文落实用户关于保留架构、基础／功能事件分层、L1–L3 能力、三类依赖、新 IP 验收和 CPU 通用契约的要求，替代此前聊天中以五类功能插件作为 IP 接入前提的方案。

**目标：**保留现有通用 CPU Session、协议适配器、独立 harness、Scenario／Router／Scheduler、持久状态和反馈机制，使有受信接口描述的未知 IP 能按实际能力参与基础测试，再通过寄存器描述和功能族插件增强测试深度。

**实施方式：**各工作包顺序执行；采用 executing-plans 工作流及逐检查点核对。构建和真实运行串行，不默认派生多个实现 agent。功能或缺陷改动先有行为负例，再实现、复核、提交；单项文档编辑不增设镜像测试。

**技术基础：**Python 场景／描述层、现有协议模板与生成式 harness、SystemVerilog／Verilator、本地持续 RTL 会话、RFuzz 输入及反馈、版本化 JSON 证据。

## 1. 已确定的范围与不变量

| 项目 | 本阶段决定 |
|---|---|
| CPU | 六核目标（权威口径，见 [P6 适配清单 §1.4](2026-10-13-p6-per-protocol-row-checklist.md)）：Ibex（OBI 指令／数据）、CVA6（打包 64 位 AXI4 单主端口）、CV32E40P（分离 OBI 指令／数据）、BOOM（TileLink 1.0 指令／数据端点）、CVW/CORE-V Wally（AHB-Lite 外部总线 EBU）、VexiiRiscv（TileLink 内存总线）；每核一个固定单核配置 |
| CPU 条件不足 | 允许 `skipped_unavailable`；必须列具体原因及受影响组合，不能声称六核全部支持（当前可执行三核：Ibex／CVA6／CV32E40P） |
| BOOM | 其 `configs/cpus/boom/interface_description.json` 声明 **TileLink 1.0** 指令／数据端点（不是 AXI）；需经验证的 Chipyard 转换链产出真实 profile，原生边界、内部缓存及转换链均进入身份 |
| 功能增强 IP | GPIO、UART、SPI、I2C、Timer；每个可运行 CPU 覆盖全部五类，最多 20 个组合 |
| 未知 IP | 新增一个此前未接入的真实 IP，必须在关闭功能插件时通过基础接入门禁 |
| DMA、多核 | 留到后续阶段，不加入本轮完成分母 |
| 输入 | CPU 侧变异程序，IP 侧变异声明的环境输入；CPU 发出的事务与 bound 输入不可主机改写 |
| 时间 | 独立 harness 的局部 tick／时钟域及显式交付；不引入全局周期准确 SoC 模拟 |
| 资源 | RTL 构建／生成／运行串行；复用身份缓存，不复制整个仓库 |
| 兼容 | 保留第一阶段有效入口和身份语义，旧证据不自动升级 |

普适性表示在**已验证协议子集、真实端口事实和受信描述**内复用框架。未知功能可降级；未知协议、缺失握手、无法确定 reset、必需输入无合法来源等不能降级成可执行。

CPU 架构观察保持统一 ISA 能力、Session 契约及事务／退休观察。组件专用代码允许存在于边界适配器和探针，核心不得按 CPU／IP 名称分支。不把指令发射、总线请求或推测执行当作架构退休。

## 2. 经代码核对的复用起点

- `src/myfuzz/local_harness/` 已有通用 APB3、TL-UL、Wishbone 寄存器／端口观察模板、生成策略和独立 session，扩展这些实现，不重新建立 harness 系统。
- `src/myfuzz/scenario/` 已有 runtime path contract、逐边来源、交互反馈、来源登记和持久会话；新增分级和基础消费者接到既有事件／证据接口。
- 当前通用模板仍有显式宽度、对齐、输入类型、peer 和启动写入限制。任务首先登记真实子集，不能把“存在通用模板”等同于全部同协议 IP 都可执行。
- 当前 CPU 程序与支持指令部分仍明确限制 RV32I、32-bit word／NOP，需要在能力接口下扩展；不更换既有 ISA 与 Session 抽象。
- 本地已有 OpenTitan HMAC 原生 TL-UL RTL 与寄存器资料；现有 peripheral profile 和运行能力索引没有 HMAC 条目，作为未知 IP 接入门禁的固定对象。其源码存在不等于已完成依赖闭包、harness 或测试。

## 3. 必须实现的接口语义

### 3.1 L1／L2／L3 是本系统测试能力，不是 IP 厂商的成熟度等级

| 级别 | 必需输入 | 可执行测试／检查 | 不授予的能力 |
|---|---|---|---|
| L1 接口级 | 源锁、原生协议／端口事实、reset／clock、地址 aperture、输入归属与合法接口范围 | 接纳／响应／错误／等待、实际端口采样与变化、显式交付、事务身份与基础依赖核对、协议及基础覆盖反馈 | 寄存器读写副作用、内部功能状态、算法正确性、完整功能链 |
| L2 寄存器级 | L1 加经过核对的寄存器／字段描述及可写 mask、访问权限／宽度、明确副作用规则 | 合法寄存器程序、字段边界、reset 值、声明的读写语义、可观察寄存器状态及版本依赖 | 未描述的 FIFO／功能状态、按名称猜测的完成条件 |
| L3 功能级 | L2 加可选功能族插件、环境 peer、真实观察映射与功能规则 | 功能动作、传输、IRQ 原因、操作完成、深层持久状态、完整功能链及语义反馈 | 未观察的内部原因、未验证配置／模式 |

实现 `declared_level`、`effective_level` 和 `verified_level`：分别表示描述请求、启动前可执行能力、已通过证据的最高等级。能力按具体操作／端点登记，不因一个字段缺失整体撤销已有能力。

默认自动选择实际可执行的最高等级，并报告缺口。显式要求最低 L2／L3 时，达不到就启动前拒绝；不能静默降级。缺功能插件可运行 L1/L2；无寄存器描述可运行 L1，但不推断所有 aperture 地址都具有相同寄存器语义。

L1 集成时由 CPU 程序产生访问；独立协议门禁可由既有 BFM 发起事务，必须标记 `standalone_protocol_test`，不得冒充 CPU→IP 证据。声明的保留地址、访问上限和必需前提始终生效；未实现地址返回的真实协议错误单独记录，不凭错误响应判定 IP 功能失败。

### 3.2 基础事件独立于功能族插件

新增版本化 `ip_base_event.v1`，由协议／端口边界产生以下公共事件：

- `transaction_request`、`transaction_accept`、`transaction_response`、`protocol_error`、`wait_observation`。
- `port_sample`、`signal_change`、`binding_delivery`；只有目标实际采样并可关联时记录 `input_sample`。
- `reset_observation`、`clock_domain_progress`；记录实际局部状态，不虚构全局先后。

公共字段：组件／端点、原始事件引用、局部 event ID 和时钟域／tick、reset epoch、原生 transaction key、动作／来源引用、payload、观察映射身份和观察性质。没有原生身份时保留缺口，不能用数组位置假造事务 key。

派生层分两类：L2 的 `register_access`／可观察字段版本；L3 的功能 `transfer`、`interrupt`、`state_transition`、`completion`。普通总线收发仍是基础事务事件；串行帧、FIFO 消费和算法完成才是功能事件。IRQ 引脚变化在 L1 是 `signal_change`；具备声明的 IRQ 交付角色可检查交付；功能原因、CPU 接受及 ISR 退休另需对应证据。

新增 `ip_register_event.v1`、`ip_function_event.v1`；派生事件保留 `base_event_refs`、规则版本和证明范围。观测映射只允许端口／字段选择、位切片、端序转换和证据引用，不允许承载计算功能结果的任意脚本或隐式功能模型。

插件可消费基础／寄存器事件并追加功能事件、动作及语义检查，不改变基础事件，不改变主机数据交付，不提供它唯一知道的基础 coverage，不能成为基础归属检查或协议检查的必需依赖。

### 3.3 依赖分级及证据要求

新增 `dependency_evidence.v1`，使用 `declared`、`candidate`、`verified` 三种类型，并保存关系、范围、证据引用、规则、epoch 和有效性。

| 类型 | 来源 | 允许用途 |
|---|---|---|
| declared 声明依赖 | Profile／路径／输入归属契约 | 路径规划、绑定约束；不证明一次执行已经发生传播 |
| candidate 候选依赖 | 运行时事件相关性、时序、值匹配、覆盖变化 | 探索目标建议；不满足来源前置条件，不产生认证闭环 |
| verified 真实依赖 | 精确请求／交付／消费身份、byte mask／版本或相应真实观察 | 已验证依赖反馈、状态前置 witness、逐边证书；范围不能超出证据 |

不是自动的三个状态晋级：声明存在而运行未验证时，声明继续存在；有证据的运行依赖另行记录并引用声明。声明外候选必须先通过 ownership、路由及协议合法性核对，再产生运行证明；候选不能自动修改执行拓扑。

仅时序相邻、相同数据或一次覆盖变化不能晋级 verified。反事实／变异对照可加强 candidate，但缺少精确身份的关系仍不认证。协议身份只能证明接纳／响应；不能据此宣称寄存器副作用、功能完成或 CPU 已退休。

reset、覆盖写、证据淘汰或身份冲突使相应实时 witness 失效；历史已验证观察保留，当前 prerequisite 不得复用失效 witness。跨例来源保留起始 action／case，不强行归属于消费例。

反馈分别报告 `base_coverage`、`candidate_novelty`、`verified_dependency`、`functional_coverage`。基础事务和真实信号覆盖可在 L1 获得探索权重。候选探索通道默认关闭，显式开启时按 session 去重、每 case 最多一个候选 novelty 单位且最多占该例新增能量的 10%；不得计入认证链收益，配置进入 replay identity。候选过期和淘汰不制造新 novelty。

## 4. 工作包与逐项验收

### A. 基线、已有问题与资源

- [x] A1：冻结实施起点的 Git／第三方／工具链身份及 CPU/IP 能力；核对其他 agent 的已实现部分，按接口兼容增量实施。
- [x] A2：重核首步 replay 输出、证据摘要、缺失身份、零耗时／验证数、异常清理、证书完整性和 batch 状态问题。公共路径负例已修复，最新并行回归覆盖首步／P5、真实事件 fixture 证书身份、serial token、batch 重放身份与失败清理；详见 M0 进度报告和机器摘要。
- [x] A3：把 4 CPU×5 功能族登记为单独验收行，并新增 HMAC 基础接入行；L1/L2/L3、可执行／已验证分别报告。
- [x] A4：构建／运行采用单 worker；进程树 RSS 上限默认 `min(4 GiB, 启动可用内存－2 GiB)`，可用预算不足 1 GiB 时不启动重型任务。生成 JVM 使用显式 heap；预算终止单列，不记 DUT finding。首步 smoke、启动拒绝回执、Java/SBT heap 预检和 Mill fail-closed 均有验证证据。
- [x] A5：单一按身份索引的构建缓存；新 run 使用新目录；不复制整仓库，不覆盖第一阶段材料。启动、运行、replay 任一失败须清理全部组件进程。真实 Verilator cache identity／损坏拒绝测试、fresh output 目录和进程树失败清理均有证据。

**交付与门槛：**起点与能力表、受影响负例结果、资源终止／清理证据、输出规则。基线未达到门槛，不开始长跑。

### B. 公共 IP 描述与等级预检

- [x] B1：沿用现有 component profile／request／tuning，增加可选的版本化测试能力、寄存器语义和观察映射描述；旧 schema 不接受新字段，新字段采用明确的 sidecar／新版本契约。新增 `ip_test_capability.v1` sidecar loader，要求并核对完整 profile 文档的规范化 SHA-256 指纹，再核对端点、字段、寄存器、权限／mask、观察映射及证据引用；现有 `component_profile.v1` 对未知顶层键 fail closed。
- [x] B2：实现等级解析和缺口报告，输出 declared／effective／verified level 与 endpoint／operation 支持矩阵，并单列调用方请求的最低等级。`ip_test_level_assessment.v1` 将静态声明、profile／sidecar 绑定的 runtime preflight、带证据引用的 verifier 分开；L2 使用精确 `Register.Field` 作用域的读写操作，generic read/write 不升级；sidecar typed 内容重新核对 frozen 原文与 fingerprint，最低等级未达时 `require_minimum()` fail closed。复审 Ready，详见 [B2 报告](../../reports/stage2-b2-capability-levels-20261010.md)。
- [x] B3：核对所有必需端口、方向、宽度、clock／reset、aperture、输出映射、输入 ownership 和协议子集；功能未知与接口非法分别处理。绑定预检拒绝缺端口、方向／宽度冲突及非标量 clock/reset；请求载入时核对固定 MMIO 窗口、64 位边界、aperture 和重叠，自动分配不能越过 aperture，构造 request 对象的调用方也会在分配时复核。端口 ledger 覆盖每个 bit，拒绝无 owner、重复 driver、输出 fuzz 和非法常量／方向；协议解析只接受 catalog 中实现的子集。接口函数仍是封闭词表，未知函数作为接口非法拒绝；缺少 IP 功能插件的合法通用 MMIO 描述仍可按 B2 评为 L1。详见 [B3 报告](../../reports/stage2-b3-interface-preflight-20261010.md)。
- [x] B4：L1 无 register map／无插件可运行；L2 应用实际字段权限／mask／副作用规则；L3 插件必须自述需要的观察能力。L1 匿名 profile 可无 map／功能插件评为 L1；`plan_register_operation()` 按精确 `Register.Field` 检查访问权限和有效 mask，返回寄存器偏移及总线 mask/value，并要求非空副作用显式授权。新增 `ip_test_capability.v2` 数据契约声明 provider/version、功能操作、必需 observation mapping 和证据引用；L3 还要求 L2 完整，运行预检必须支持契约指定的每个映射，verified L3 需逐操作证据。无生产 runner 消费这些 API，不能据此声称 DUT 已达到 L2/L3。详见 [B4 报告](../../reports/stage2-b4-level-semantics-20261010.md)。
- [x] B5：基础 `local_harness.v2` 按请求版本和已验证协议契约选择 APB3／TL-UL／Wishbone 通用寄存器观察 executor；TL-UL v2 不读取旧 `local_runtime_variant`，APB3／Wishbone v2 也不按 IP／endpoint 名称分流。扩展回归覆盖多种带 GPIO／UART／SPI／I2C／Timer 标签的 profile、旧变体值和匿名 endpoint ID。旧 v1 专用 executor、PULP GPIO 因果探针及 OpenTitan UART FIFO 源观察仍由原显式 profile/source contract 启用。详见 [B5 报告](../../reports/stage2-b5-executor-selection-20261010.md)。
- [x] B6：六类拒绝负例均有直接覆盖：缺功能契约仍可 L1／运行时 operation 名不能自授 L3；最低 L2/L3 不满足时 `require_minimum()` 拒绝；未知协议不产生 effective L1；bound 输入不能作为 IP→IP fuzz source；物理端口／字段缺失在 bind 阶段拒绝；`DONE.ready` 等寄存器名称只按显式字段描述提供 L2，不推断 completion。详见 [B6 报告](../../reports/stage2-b6-negative-contracts-20261010.md)。

**交付与门槛：**等级接口、描述契约、同一匿名 IP 在 L1/L2/L3 的能力差异测试；L1 启动不导入或调用功能插件。

### C. 基础事件与通用协议／端口检查

- [x] C1：新增 `ip_base_event.v1` 投影层，并在新生成的 v2 通用 local harness raw event 出口生成端口采样／变化事件；事件保存精确 raw `local_tick_sample` 引用、profile endpoint/role、局部 tick、clock domain、reset epoch 和观察性质。原始样本及 event ID 不修改；缺少 schema opt-in 的旧 artifact 不投影。详见 [C1–C2 报告](../../reports/stage2-c1-base-events-20261010.md)。
- [x] C2：APB3、TL-UL、Wishbone 通用目标模板均启用相同基础事件 schema 标记和输出投影；其余未验证形态继续由既有 admission 拒绝。三种模板契约与 factory 回归通过；真实目标 RTL 运行仍未启用，不据此授 DUT 级别。详见 [C1–C2 报告](../../reports/stage2-c1-base-events-20261010.md)。
- [x] C3：基础事件记录请求／接纳／响应／错误／等待；TL-UL outstanding、重复 source、reset 取消、A/D timeout 和迟到响应保留原生 source 身份；APB3／Wishbone 无原生 transaction ID 时保留身份缺口，不造 key。Runner 仅消费声明的协议 tap，判定 pre-edge 握手并保持 raw tick 不变。详见 [C3 报告](../../reports/stage2-c3-protocol-base-events-20261010.md)。
- [x] C4：按 profile 导出任意名称的合法物理输入／输出；从 raw `physical` 快照按 `runtime_name` 读取已选 ABI 切片，记录采样、变化、显式绑定交付值及 reset epoch；仅当目标同 epoch 的实测 pre-edge 输入等于交付值时生成 `input_sample`，不根据名字推断功能。详见 [C4 报告](../../reports/stage2-c4-input-sampling-20261010.md)。
- [x] C5：共用协议 Checker 验证握手、请求稳定、响应关联、mask、至多一次交付和超预算；Runner 记录协议违规并使运行失败；不要求未知 IP 写后读相等。TL-UL 同周期已接纳 A 请求可与对应 D offer 关联；其他 D offer 在首次出现时绑定已 outstanding 的 source，后续请求不可补绑；并行 source 等待周期独立累计。详见 [C5 报告](../../reports/stage2-c5-protocol-checker-20261010.md)。
- [x] C6：无功能插件的独立消费者按游标增量统计 APB3／Wishbone read/write、TL-UL opcode、响应、接纳后延迟 bucket、精确声明物理切片变化与声明目标覆盖位；feature 集合有限、计数饱和、pending 有界，严格校验 raw envelope 与目标导出快照，并提供 detached `ip_base_coverage.v1` 快照。详见 [C6 报告](../../reports/stage2-c6-base-coverage-20261010.md)。
- [x] C7：无功能插件 fixture 覆盖 APB3／TL-UL／Wishbone 合法／非法事务、stall、error、reset、跨例消费，以及 TL-UL 重复 source、timeout 与迟到响应；新解释器禁止功能消费者导入仍通过，功能事件注释不改变基础覆盖。79 项测试、67 项子检查通过；仅为软件回执门禁，不授 DUT 等级。扩大回归修复 direct elaboration 漏检 Git 源锁。详见 [C7 报告](../../reports/stage2-c7-plugin-free-fixtures-20261011.md)。

**交付与门槛：**不依赖功能族的真实基础事件、Checker、覆盖；去掉插件后同一 raw trace 的基础事件及基础覆盖不变。

### D. 三类依赖及运行证据消费

- [x] D1：新增 `dependency_evidence.v1` 不可变记录和分类 ledger，API／报告／JSON 保存加载分开 declared、candidate、verified；声明投影只读既有 prepared contract，运行记录引用声明而不替换声明。类型／scope／epoch／摘要／分组／容量负例通过；报告只计 classified records，不把格式校验视为运行证明或 prerequisite。27 项定向测试及与 D2 合并的 190 项兼容回归通过。详见 [D1 报告](../../reports/stage2-d1-evidence-categories-20261011.md)。
- [x] D2：新增精确声明切片的有界候选发现消费者，读取基础样本／变化和 C6 实际新增覆盖；候选保留源／目标及覆盖 journal 引用，默认 pending/window/details/counter 均有界，有限 session feature 去重不因 reset/expiry/eviction 复活。拒绝伪覆盖标签、畸形事件、假变化、旧 epoch 和非法源引用；不回写 topology、不驱动输入、不授 prerequisite。D1/D2 67 项定向测试及 190 项兼容回归通过；候选生产接入及能量预算仍待 D8；D3 已完成独立的基础精确证据消费。详见 [D2 报告](../../reports/stage2-d2-bounded-candidates-20261011.md)。
- [x] D3：复用既有 runtime edge／source provenance 消费者认证显式 binding 的 producer→delivery→实际 pre-edge input sample；协议消费者重用 C3/C5 normalizer／Checker，从原始握手逐字段认证 request→accept→response，精确请求引用区分 TL-UL source 重用，APB3／Wishbone 保留无原生事务 ID 缺口。协议证书接入 D1 declared／verified 分类台账，保留原始 case、观察／runtime 身份和历史协议 scope，不授功能或 prerequisite。97 项联合定向检查及 378 项兼容回归、218 项子检查通过；真实 DUT 门禁及 D6 active 生命周期仍待后续。见 [D3 绑定报告](../../reports/stage2-d3-binding-progress-20261011.md)和[协议证据报告](../../reports/stage2-d3-protocol-evidence-20261011.md)。
- [x] D4：L2／L3 用精确原生版本／消费证明扩展关系；缺功能 provider 保持 incomplete／unknown，协议接纳不授内部成功。统一 ingest／逐操作报告、既有 profile／sidecar 的 VerifiedCapabilitySnapshot 和派生事件已按软件范围衔接。实际 SET／CLR 不授 direct-write，sync0→sync1 内部消费不授 completion；原生路径缺公共 base 投影明确报缺口。80 项 D4 定向、515 项兼容回归及 218 项子检查通过；真实 DUT、E3 插件输出和 D6 active witness 待后续。见 [D4 衔接报告](../../reports/stage2-d4-capability-events-20261011.md)和[版本／消费报告](../../reports/stage2-d4-register-progress-20261011.md)。
- [ ] D5：RAM writer／byte-enable／读 snapshot、IRQ 交付／接受／退休各自保持证明范围；真实 persistent witness 才可满足前置状态。实施中：首步 18 项 RAM 校验、第二步 28 项实际 host writer→snapshot 分类通过；第三步 IRQ 三类历史 scope 入 D1／统一 ingest，新增 24 项、联合定向 36 passed，reset_barrier／serial 冲突负例已修复。RAM Runner 可信 token 分发及 IRQ Runner 历史入口已衔接；可信 RAM prerequisite 已接入 Runner／Session，仅当前实际 cell 匹配才授字节前置状态；在线 factory／默认 slot gate 组合及 D6 通用生命周期仍待完成。见 [RAM 校验](../../reports/stage2-d5-ram-witness-progress-20261011.md)、[RAM 证据](../../reports/stage2-d5-memory-evidence-progress-20261011.md)和[IRQ 证据](../../reports/stage2-d5-irq-evidence-progress-20261011.md)。
- D5 分发进度：实际 write/read authority 已加入启动注册的有界一次性多消费者视图，新增 12 项检查、联合回归 91 passed；RAM Runner 实际 callback／完整 journal／配置身份已衔接，新增 14 项检查、最终兼容回归 201 passed／4 subtests。第三方消费者延迟退休重复分发缺陷已修复并复核。IRQ Runner 入口现已衔接，新增 12 项检查、272 passed／4 subtests、只读复核通过；可信 RAM 前置状态新增 21 项、324 passed／25 subtests；后安装 gate 旁路与 support instruction 漏检已修复并复核。在线 factory／默认 slot gate 组合仍待完成，不勾选 D5。见 [分发报告](../../reports/stage2-d5-authority-distribution-progress-20261011.md)、[RAM Runner 报告](../../reports/stage2-d5-memory-runner-progress-20261011.md)、[IRQ Runner 报告](../../reports/stage2-d5-irq-runner-progress-20261011.md)和[可信前置状态报告](../../reports/stage2-d5-live-memory-prerequisites-progress-20261011.md)。
- D5 会话恢复记录（2026-10-11）：slot 策略组合与在线启动 gate 选择已有工作区实现，兼容回归 261 passed／21 subtests（22.17 秒），未新增 RTL。只读复核发现 P1 尚待修复：实际 cold_reset 改变 generation、journal barrier 未消费时，旧 slot reservation 会恢复授权。先补负例并绑定实际 generation，再继续 factory opt-in／完整在线衔接；不得据此勾选 D5。
- D5 slot 修复进度（2026-10-11）：上述 cold_reset P1 已补实际 memory 负例并绑定 reservation 的实际 generation，重复注册不续旧授权；reset 后新明确注册路径已验证。slot 共 10 项，联合回归 183 passed／15 subtests（20.69 秒），无新 RTL；只读复核 39 passed，确认 P1 已解决、无新增重要问题。factory 生产 opt-in 与完整在线流程仍未完成。
- D5 factory 衔接：共享 factory／Ibex wrapper 新增默认关闭的 contract identity opt-in，实际 CPU readback 与 Root authorities／slot+RAM gate 每 Runner 独立；在线入口从 decoder 实际 contract 取得身份并选择已安装 gate。联合软件回归 66 passed（41.71 秒），只读复核通过（独立 6 passed），无新 RTL。完整在线辅助指令注册、动态 RAM binding、保存及 replay 尚待完成。见 [slot／factory 报告](../../reports/stage2-d5-live-slot-policy-progress-20261011.md)。
- D5 辅助指令衔接：新增 fixed NOP 注册入口，动作不带可变 payload、完整 fragment 独立精确核对；executor 在 require_case 前注册并记录 support_actions，实际 slot／generation 检查保持生效。定向 4 passed，联合回归 83 passed（45.64 秒），只读复核独立 6 passed、无重要问题；完整在线 execution、动态 RAM binding 和 replay 仍待完成。
- D5 动态绑定进度：LiveMemoryDynamicPrerequisiteBinder 从当前 actual authority／cell 重算 STORE provenance，保存 receipt 不授来源；声明与缓存有界，复用原不可变 binding 与 payload 校验。新增 10 项，首轮扩大 99 passed，claim version／action_id P2 修复后联合 75 passed，修复只读复核独立 75 passed，无新增重要问题；factory admission 结果槽策略与 replay 待衔接。见 [动态绑定报告](../../reports/stage2-d5-live-memory-binding-progress-20261011.md)。
- D5 factory admission：显式可信 provider subtype 复用既有结果槽 load 静态规则与当前 actual STORE binder；缺 witness 不注册动作，策略入启动身份，executor 保存 dynamic_binding。新增两项，联合回归 96 passed（41.14 秒），只读复核独立 28 passed、未发现重要缺陷，无新 RTL。保存 plan／verified bundle factory 重选及 replay 每例动作注册、binding 重算仍待完成，D5 保持未勾选。
- D5 saved/replay 配置：verified manifest 原始摘要、完整默认 evidence／slot／动态策略与读写 authority 精确检查后，replay 显式重选可信 factory；旧无 gate 不转发选项。新增 10 项，定向合计 12 passed、只读复核通过，扩大回归 37 passed／3 subtests（25.60 秒），无新 RTL。plan 动作保存与逐例 replay 注册、binding 重算仍待完成。见 [replay 进度](../../reports/stage2-d5-live-memory-replay-progress-20261011.md)。
- D5 每例 admission 保存 API：gate 保留策略前原始 SourceAction，保存预期 admission／support／dynamic_binding；fresh gate 注册时只用当前 actual authority 重算，完整 canonical 决策对比后再检查 active。新增 5 项真实 factory／host callback 检查，联合回归 46 passed（19.57 秒），只读复核独立 5 passed、无重要误授路径，无新 RTL。Session plan schema 和 replay 逐例调用仍待连接，D5 未完成。
- [ ] D6：实现 history 与 active witness 分离；reset、覆盖写、证据淘汰和冲突不得使旧 witness 重新满足 prerequisites。RAM 可信 gate 已开始这些失效检查并保留历史证书；通用 lifecycle 契约、在线组合与其他 provider 的 active 资格仍待后续。
- D6 GPIO register／sync global reset失效：旧资源续证及native reset双重确认RED已修复；新增17项，九模块231 passed，独立复核97 passed。warm／cold标签两组nativeGPIO reset各50events fresh进程完全匹配，历史保留／新epoch重建；资源singleworker complete10.33秒、峰值427,962,368 bytes，journal软件reload一致；独立产物复核通过（源／271项build inputs及reset／证书一致）。仅directed nativeGPIO同一原生reset与手工barrier，不证明Runner策略差异、CPU／RFuzz／verified文件或其他active资格。见 [D6进度](../../reports/stage2-d6-authority-lifecycle-progress-20261011.md)。
- D6 统一查询首步：Runner history／active 报告和逐 subject 实际资格重算已接入，仅已安装原生 RAM／显式 slot provider，其他 active 范围 unknown；保存 answer／证书不授授权，active counts 不假充历史数。启动半安装／consumer 漂移崩溃 RED 已修复，19 项定向通过，七模块最终回归 120 passed（45.24 秒），只读复核独立 46 passed（1.05 秒）无重要残留；无新 RTL，不勾选 D5／D6。见 [生命周期查询进度](../../reports/stage2-d6-authority-lifecycle-progress-20261011.md)。
- D5 Session／replay 衔接：schema 12／13 保存命令前 admission，replay 启动前检查声明、逐例实际重新注册与重算。factory provenance 复用现有 actual authorities；缺 runtime_paths 及 commit services 冲突须在安装前拒绝。最新联合软件回归 63 passed／3 subtests（5.13 秒），修复只读复核独立 36 passed、无新增重要问题，无新 RTL；真实在线执行与 fresh DUT replay 待验收，不勾选 D5／D6。见 [replay 进度](../../reports/stage2-d5-live-memory-replay-progress-20261011.md)。
- [x] D7：按软件范围覆盖仅事件相邻、值相同但事务不同、不同 epoch、消费先于接纳、删 delivery、删 sample、重传、同 ID 变内容。新增三协议重传／晚到冲突和 response-before-accept、raw TL 未接纳响应共13项；十二模块333 passed（0.94秒），独立复核171 passed（0.52秒），无重要缺口。此为软件负例门禁，无新RTL，不授实际DUT、其他D6 active provider或后续H门禁完成。见 [D7验收矩阵](../../reports/stage2-d7-negative-gate-20261011.md)。
- D5 失败边界补验：实际 Session source_admission 部分写入后保存 schema 13 完整失败记录及命令前 admission；replay 清理失败覆盖实际拒绝的问题已补 RED 修复。联合软件回归 72 passed／5 subtests（5.08 秒），只读复核独立 10 passed、无新增重要问题，无新 RTL。下一步实际 CLI opt-in 与资源监督下的真实在线保存／replay，D5／D6 不勾选。
- [ ] D8：候选探索默认关闭；启用后按第 3.3 节限制，只改变合法目标的探索排序。反馈逐类别可审计，不能用 candidate 提升 verified 计数。
- 2026-10-12续接：D8独立 `--classified-feedback` 门禁执行通过，candidate探索关闭，实际RFuzz3/3 complete；可信CLI fresh完整6,443events matches，semantic SHA `76d867f9a8cc5aee7da2fa1a80c3b921e2fb7833d07a42601333d33739da995e`，范围包含 `classified_case_feedback`／`classified_terminal_state`且无candidate scoring声明。三回执candidate disabled、novelty／energy均0，legacy覆盖单列；实际base GPIO A／B request／accept／response各3／4，verified0、functional unknown。27项当前source pins；singleworker complete76.752490482秒、峰545,849,344 bytes、RSSlimit3,038,162,944 bytes。root冻结九模块最终227 passed（93.18秒）；D8独立产物audit通过：27项源码／13项产物摘要、6443事件、21个APB原始引用、逐例及终态base覆盖重算和3个binary／冻结输入均一致。该组合未安装RAM／IRQ provider，6项positive检查仅软件另列；不授实际verified正例、functional或L2矩阵。D8及E1／E2、D5／D6和完整E–I仍未完成。见 [摘要](../../../runs/stage2-d8-independent-feedback-cli-20261011/summary.json)。
- D8精确反馈分类已接生产并修复ledger伪记录P2：记录锚定实际provider certificate，旧输出谓词单列legacy，无功能provider明确unknown。冻结八模块178 passed（79.02秒）、独立80 passed。新实际RFuzz3/3complete，可信fresh replay6443events matches，三回执分类一致、33context／noveltyenergy1，资源singleworker75.71秒峰551055360，25source pins；独立产物复核通过。此实测无RAM／IRQprovider，verified0，不授正例或功能完成。E1真实GPIO sidecar首四字段声明16项通过，联合51＋2subtests、独立16；无自动授级，实际L2待E2。分类独立开关及功能provider接入仍待推进，D8／D5／D6、E–I保持未完成。见 [分类进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 原生 GPIO APB 已接入实际 raw pre/post 被动观察、严格 ABI/tap 验证和生产 Runner；默认 v1、CPU physical-only保持。软件集成203 passed（107.51秒），独立30 passed。新实际 RFuzz 3/3 complete，可信 fresh replay 6443events完全匹配；GPIO A／B请求、接受、响应各3／4，33条context candidate，novelty／energy1。单worker complete76.15秒、峰547,876,864 bytes，22source SHA；独立产物审计通过。CPU bus协议与完整Stage2功能反馈仍待实现，D8及D5／D6、E–I不勾选。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 protocol／coverage_context：实际v2 projector／checker preflight及逐例静态配置／对象身份漂移拒绝，声明协议base覆盖接入；最多64个明确选择的物理变化／protocol边界上下文、多实例JSON名字空间、base consumer新观察及原始refs、epoch/window/session去重和legal source预算映射。17模块375 passed／1 deselected／207 subtests78.51秒、独立110 passed；新实际RFuzz3/3complete，15条physical context candidate、novelty／energy1，可信CLI fresh6422events完全匹配，资源singleworker69.25秒峰549531648，20source／13artifact核对。native bus protocol trace及完整功能反馈尚缺，不勾选；见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 可信scoring replay CLI：闭集assembly解析参数／RAM原始record及来源，production identity绑定，一次性snapshot及case前比对；固定本地Ibex／双GPIO／checker，保存scores仅比对。GPIO v2身份重建丢tuning及cleanup覆盖原拒绝已修复。最终六模块137 passed／55 subtests（49.87秒），只读复核通过；新r2 actual RFuzz CLI 3/3 complete、replay-candidates完整6422events匹配，novelty／energy1，资源singleworker complete70.81秒、峰526,372,864 bytes，14source／13artifact已核对。首轮失败保留，protocol／coverage_context及完整功能反馈仍待验收，D8不勾选；见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 已补实际出口别名与显式子切片，online builder在候选开关开启时选择native v2观察；关闭时保留旧路径。profile映射漂移及stateful checker身份问题均有负例修复，十四模块296 passed／1 deselected／207 subtests（63.35秒）。当前源码资源监督run CLI实际RFuzz 3/3 complete，fresh RTL从raw重算选择／weights／候选计分，6,422事件完整trace匹配，novelty1／energy1，单worker complete61.46秒、峰528,175,104 bytes；十二source SHA、生产bundle、fresh状态及逐例预算已核对。首轮和r2／r3脚本失败保留。尚缺可信scoring replay CLI selector、protocol／coverage_context与完整Stage2功能反馈，D8及D5／D6、E–I保持未完成。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 原生 v2 观察已接入 planner／renderer／factory／Runner：显式 `physical_observations=True`，闭集 raw pre/post 政策、实际 exports 摘要、CPU stream 校验，默认仍 v1；失败缓存及 kind 篡改旁路两处 P2 已补 RED 修复。29项新增检查，十一模块189 passed／1 skipped／1 deselected／138 subtests（48.17秒），独立软件36 passed。修复后 actual CPU／GPIO 各两个fresh进程、6步含reset，raw各12条／base12及64条全匹配；单worker complete34.18秒、峰470,245,376 bytes，六source SHA及原始摘要已核对。范围仅native receipts→base投影，不含生产journal／candidate计分／RFuzz；下一步port alias／切片、online builder和可信CLI重放，D8及D5／D6、E–I未完成项保持。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 CPU raw drain进展：exact bool默认关闭／身份声明，实际STEP receipts复制／lifetime ticks／FIFO256／命令前容量拒绝；begin/reset拒绝丢证据RED已修复。13项新增、九模块115 passed／1 skipped／31 subtests（39.07秒），独立22 passed／1 skipped。监督actual CPU两fresh进程各8step/reset/3step、11rawsamples全匹配、无MMIO，complete24.82秒峰469MB；4source／sample SHA／身份／资源独立核对，首轮脚本失败保留。只证明CPU raw出口，actual观察声明／v2 projector／port alias切片／完整候选入口及原D8门禁仍待完成，不勾选D8。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 实际观察审计：actual factory三组件均v1且无base/raw schema，CPU无drain、GPIO已有drain，八个physical声明exact export匹配均0；构造无进程、六源码SHA已核对。下一步需补actual port／alias／切片与原始观察契约，不仅放宽kind白名单，不授RTL完成；见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 run CLI／assembly进展：显式opt-in／case容量、默认关闭不传新kwargs，类型／容量factory前检查；enabled actual executor预检在begin／bootstrap前，warmup后创建fresh scoring executor。actual旧Ibex组合缺匹配v2观察契约时预启动拒绝，无进程／evidence；构造失败cleanup RED已修复。新增10项，十一模块192 passed／76 subtests（27.01秒），独立38 passed（5.26秒），无新RTL／RFuzz。受支持实际组合成功CLI运行、scoring replay可信selector／CLI、完整反馈／真实门禁仍待完成，不勾选D8。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 fresh scoring replay 进展：可信新 executor 从 raw 输入重算实际选择、逐例候选计分／weights／分类反馈及完整 plan／trace／终态；保存状态只能比对，不导入授权。cached manifest 隐藏 actual Session checker 漂移的 P2 与 bool/int 类型漏检已补 RED 修复；例间 reset barrier 遗漏已修复，默认／启用旧 pending 链在下一例命令前清除。新增21项 replay＋4项生产 reset，十六模块284 passed／4 skipped／9 subtests（2.57秒），只读复核最终69 passed／2 subtests（1.74秒），无新RTL／实际客户端。下一步实际 selector／CLI、protocol与完整功能反馈及资源监督下 DUT／RFuzz运行重放，不勾选D8；D5／D6、E–I原未完成范围保持。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 生产接线进展：actual prepared paths／ownership／Binding／route 与 v2 projector 预检物理关系并固定合法source映射，逐case预算进入实际decode_candidate权重，两个legal sources选择边界已由软件门禁证明；分类反馈、配置／源码摘要进入live保存与配置verifier。cached projector漂移和保存bool/int等价漏检已补RED修复、容量预命令拒绝。新增21项，十二模块220 passed／4 skipped／9 subtests（1.49秒），修复只读复核48 passed／2 subtests，无新RTL／实际RFuzz客户端。CLI／fresh scoring replay／protocol与完整功能反馈／真实RTL仍待完成，配置verifier不替代逐例重算，不勾选D8。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D8 预算层首步：默认关闭、每case1 novelty／energy、非候选新增能量至少10才加1，session feature永久去重，case摘要幂等、改内容／容量拒绝、饱和不虚报；配置SHA供后续身份封装。新增22项，五模块121 passed（0.40秒），只读复核独立82 passed（0.15秒）无重要缺陷；尚未接actual合法性预检、生产executor／CLI／replay identity及分类反馈，无新RTL，不勾选D8。见 [D8执行进度](../../reports/stage2-d8-candidate-exploration-progress-20261011.md)。
- D6 reset verified文件链：当前源码固定STORE→LOAD非空binding及schema14两类reset，生产identity／selector／文件入口新建RTL的1,455／1,587events均matches true，4条历史证书保留、active0。独立产物复核通过；资源单workercomplete64.78／44.62秒。未执行RFuzz客户端，不授通用provider生命周期完成，D5／D6未勾选。
- D6 authority登记漂移：6项实际callback负例RED，现固定启动服务登记并核对组件、实际对象和region IDs；内部漂移永久失效、恢复/reset不续授权。三模块64 passed（45.74秒），只读复核独立16 passed（12.60秒）、无新增重要问题，无新RTL，D5／D6未完成。
- D6 authority身份冲突：两类实际authority实例替换RED旧RAM误授，现固定实例并永久锁存漂移／degraded；RAM／slot／报告统一撤销资格，恢复实例或reset不续授权，历史保留。新增5项含cell不变的writer淘汰检查，联合软件93 passed（51.66秒），复核通过：独立58 passed（46.27秒），无新增重要问题，无新RTL。见 [D6进度](../../reports/stage2-d6-authority-lifecycle-progress-20261011.md)，通用lifecycle仍未完成。
- D6 reset保存缺口已补：Session边界reset与schema14／15有序after_cases；未记录／部分失败reset拒绝保存，replay reset异常清理保留原错误。10项新增、联合41 passed／5 subtests；实际warm/cold reset的1,455／1,587events fresh RTL replay匹配，单workerresource complete41.70／20.70秒，复核通过：独立28 passed／2 subtests，reset时间线及产物一致。通用淘汰／冲突及其他provider仍未完成，不勾选D5／D6。
- D6 实际warm/cold reset：4条history证书原文保留，旧RAM／slot授权撤销，保存历史不能复活，Session命令前拒绝；资源单workercomplete19.09／18.72秒，21项软件检查通过，产物复核通过：实际reset、generation、历史证书及trace摘要一致。online plan未编码reset，reset replay缺口尚待处理；D5／D6不勾选。
- D6 实际覆盖写负例：真实相同值 STORE 将byte0版本[0,4]→[0,6]，旧绑定LOAD在Session命令前拒绝且事件／ticks／cases不变，历史commit保留；两STORE的1,468 events fresh replay匹配。单worker20.74秒、峰值178,348,032 bytes，产物复核通过：实际 commit 摘要、版本和值一致；拒绝尝试未入 replay plan；通用reset／淘汰／冲突生命周期仍未完成。
- D5 非空 RAM binding 文件链：固定生产 STORE→LOAD，schema 12 两例，7 项 artifact 的生产 identity 校验／selector与新建 RTL replay，1,454 events matches true；单 worker44.94秒、峰值250,613,760 bytes、resource complete。未执行RFuzz客户端（明确记录），只读复核通过：生产 verifier／selector、7 项摘要和 STORE 绑定一致；D5失效场景与D6通用lifecycle尚待继续，不勾选。
- D5 完整 CLI／RFuzz 保存与 verified bundle 文件 replay：3 complete inputs、schema 12 三例、1,763 events fresh matches true；单 worker run／replay 18.65／23.45 秒，资源 complete。三例无动态 RAM binding，仍须补结果槽绑定的 verified 文件 replay；只读复核通过：生产 verifier／selector、11 项摘要及 semantic hash 一致，不勾选 D5／D6。
- D5 结果槽真实短链：固定生产 admission 链的实际 STORE→LOAD 非空 RAM binding，schema 12 两例、1,454 events fresh RTL replay 匹配；单 worker 19.35 秒、峰值 RSS 179,445,760 bytes，产物复核通过、无重要不一致。自适应 executor 首轮切换 GPIO 导致 binding 断言失败，保留失败产物；完整 RFuzz 与 verified bundle 文件入口仍待验收，D5／D6 未完成。
- D5 首轮可信模式 RTL：单 worker 38.35 秒、峰值 RSS 508,370,944 bytes，2 cases／1,478 events fresh replay 匹配。输入实际选择 GPIO MMIO，两例无 dynamic_binding，辅助 trace 导出错误，不作为动态 RAM 保存验收；下一步新目录修正窗口及导出重跑，D5／D6 未完成。产物 runs/stage2-d5-trusted-rtl-20261011。
- D5 CLI 衔接：Ibex run 的 `--persistent-memory-prerequisites` 默认关闭且要求 `--memory-commit`，缺失在 runtime 构建前拒绝。新增 3 项，联合软件兼容回归 26 passed／7 subtests（14.80 秒），只读复核独立 3 passed、无重要问题，无新 RTL；后续在既有单 worker／进程树 RSS 监督下验收真实保存／replay。

**交付与门槛：**基础依赖在 L1 可被验证；未知 IP 可产生协议／交付级证据但不能取得未观察功能的认证。候选伪证样例必须全部拒绝晋级。

### E. 寄存器规则与可选功能族增强

- E1首批PULP GPIO声明数据：四个full32字段及真实输出sample，source SHA／revision／profilefingerprint精确绑定，SET／CLR副作用显式，默认仍L1／verified未授；16项与独立16通过，联合51＋2subtests。实际行为／真实CPU程序及其余register规则待继续，不勾选。见 [源码及声明审计](../../reports/stage2-e1-gpio-register-source-audit-20261011.md)。
- [ ] E1：L2 描述地址／字段／权限／mask／reset／访问宽度，W1C、read-clear、FIFO 等规则只在真实行为已核对且有观察依据时启用。
- [ ] E2：寄存器生成仍通过 CPU 程序；独立 BFM 模式显式单列。未声明副作用不设置写后读 oracle。
- 2026-10-12 E1／E2本轮：14寄存器／72字段声明、explicit CPU RMW、actual-context adapter及schema16可信file CLI接线实际通过10 cases／54APB／2RAM／22339 fresh events；44pins及38项production selector closure，独立artifact audit已通过（44pins／38production闭包／9authenticated artifacts，278／278／347缓存输入）。schema17已软件验证，actualfault门禁不是额外验收前提；原计划capability等级及实际reset／权限／mask行为仍待验证，无functional／verifiedL2／RFuzz／BFM授级，E1／E2不勾选。最新scope与资源见顶部及[E2报告](../../reports/stage2-e2-gpio-cpu-register-progress-20261011.md)。
- 2026-10-12续接：E2 helper新实际定向门禁执行通过，12个连续CPU cases全部使用当前实际router／RAM regions／waiting slot参数重新编译保存声明，并仅接纳helper返回fresh source；36条本例APB边界、6次read→RAM认证commit，fresh Session API完整25,201events matches，semantic SHA `3321aa564f841837b26ee3fa5e09500c721d0623b4ce0c30d65137d97253d3c4`，25项当前source pins。singleworker complete54.221435622秒、峰509,140,992 bytes、RSSlimit3,181,293,568 bytes；独立产物audit通过：25source pins／12program／25,201events／36APB／6RAM及3binary的276／345／276项冻结输入核对一致。scope为 `current_context_program_recompilation_and_directed_cpu_session_replay`，保存声明不作运行授权；生产actual-context adapter／可信CLI selector仍未实现，不授L2 verified或functional。旧r2仅为原冻结源码历史证据，pins未改；目录沿用20261011准备名称，不重命名。D8独立分类实际门禁仍运行，不预授通过；E1／E2、D8／D5／D6及E–I保持未完成。见 [新实际摘要](../../../runs/stage2-e2-gpio-program-verification-20261011/summary.json)。
- E2保存声明重验证进展：新增helper仅用caller当前显式kwargs重新编译并exactcanonical比较saved document，返回fresh source，不用saved regions／bytes／hash授权；16项RED→GREEN，七模块121 passed／4 subtests、独立58 passed。生产actual-context adapter及CLI selector仍待接入，旧r2 pins不改写；新helper实际门禁另准备新目录，尚未执行。
- E2首步编译＋定向CPU：profile/sidecar重算field计划、完整SW/LW→RAM读值，明确region／window／slot检查、不授liveauthority；6模块105 passed／4subtests、独立58 passed。真实r2十二连续DIR／OUT／SETCLR用例、36APB边界、6读回RAM认证commit，fresh Session API25201events匹配；资源singleworker complete48.96秒峰508014592、25source pins；独立产物复核通过。首轮脚本running断言错误保留，无BFM／RFuzz／verifiedCLIselector或L2授级；生产能力绑定／reset／字段规则与后续功能门槛待继续，不勾选。见 [E2执行报告](../../reports/stage2-e2-gpio-cpu-register-progress-20261011.md)。
- [ ] E3：功能族插件只追加功能动作、derived event、语义 Checker 和功能覆盖；使用有界、版本化规则，不改变基础交付及 raw trace。
- [ ] E4：GPIO 增强方向／mask／外部输入／输出及 IRQ 原因；UART 增强帧、FIFO／发送及中断；SPI 增强 CS／串行事务；I2C 增强地址／ACK／NACK／STOP；Timer 增强启停／到期／清除。
- [ ] E5：peer 产生实际合法环境输入；约束状态由协议／RTL 观察获取，不能用主机功能模拟器替代 DUT。
- [ ] E6：同一 IP 分别运行 L1、L2、L3；关闭插件后仍产生基础事件／事务及反馈；功能证据不足只降低对应语义能力。
- [ ] E7：为各族增加 busy、非法字段、缺观察、错误 IRQ 和未完成操作负例；异常实际输出不能因路径未就绪而过滤。

**交付与门槛：**五族增强可独立启停；每族有至少一个真实功能验收。新增未知功能族无需实现 E3–E7 即可执行 L1。

### F. CPU 侧的增量通用化与四核接入

- [ ] F1：保留现有 CPU Session，统一能力查询、begin、程序片段接纳、step、事务／退休观察、带来源 IRQ 交付和幂等 finalize；以已有方法建立能力委托，不替换全部执行体系。
- [ ] F2：按 ISA 能力支持 XLEN、实际 register 集、合法指令子集、地址及访存宽度；固定引导／ISR／NOP 与可变片段分开。初期不 fuzz 浮点、向量及未验证原子指令。
- [ ] F3：缓存／预取涉及的程序字节一经物化不可覆盖；接纳位置及 fence 行为依能力规则。未准备的未来代码不能被普通未初始化 RAM 随机物化后再次提交。
- [ ] F4：事务与退休统一观察，多退休 slot／取消请求与架构顺序分开；不假定总线请求与退休一一对应。
- [ ] F5：CVA6 复用已有 AXI4 harness／source closure，先迁移到公共接口，再逐五类 IP 验收。
- [ ] F6：CVW 固定官方单核可仿真配置；优先 RV64，若官方可运行配置只有 RV32 则记录选择原因。核实实际 AHB 边界，缺协议子集时在 adapter 层实现并验证，不在 Runner 加 CPU 名称分支。
- [ ] F7：VexiiRiscv 固定生成配置、工具链与 RTL，优先已有合法 AXI 导出方式；接口／退休／IRQ 不具备的条件明确记录，不能伪造边界。
- [ ] F8：BOOM 固定受支持最小单核配置和 Chipyard 转换链；验证 AXI 导出、MMIO 属性、内部缓存／一致性与真实 commit 观察。工具链／资源／合法边界缺失则记录 skipped_unavailable。
- [ ] F9：每核先独立 Fetch、RAM Load／Store／byte mask／MMIO／IRQ 门禁，再进入长期组合。缺 IRQ 的 CPU 可以执行基础行，不能把该功能行判为通过；缺退休证据不能授予退休链认证。

**交付与门槛：**统一 CPU 契约与四核逐项状态，核心无 CPU 名称分支；跨核不要求 tick 或微架构 trace 相同。

### G. 新未知 IP 的强制接入门禁

固定对象为本地已有真实 RTL、尚未有本系统 profile 的 **OpenTitan HMAC**。本轮不实现 HMAC 功能族插件，也不验收密码算法。厂商文档里的生命周期 L1/L2 与本系统等级完全无关。

- [ ] G1：在基础框架冻结后检查 profile／report 仍没有 HMAC；记录 baseline 和全部 protected core 路径的 blob SHA。
- [ ] G2：固定现有 OpenTitan revision 及 HMAC 依赖闭包，新增 Profile、接口说明、合法 clock／reset／固定输入及观察映射。需要结构体 scalar wrapper 时只做连线／位映射，进入组件描述包，不写 HMAC Session 或新 executor。
- [ ] G3：使用现有 generic TL-UL 目标适配执行 L1；功能插件列表为空，register map 可省略；测试真实请求／响应、合法错误、输出采样、协议身份和基础覆盖。
- [ ] G4：提供核实的寄存器描述后执行 L2：至少一个无副作用稳定寄存器的受约束写／读、reset 及权限边界；不将任何输出命名成 hash／算法完成结论。
- [ ] G5：与 CVA6 组合，由真实 CPU 程序产生事务，连续至少 3 个 case、一次初始化；产生至少一条协议／交付级 verified dependency，保留 candidate 与未知项。
- [ ] G6：60 秒基础持续搜索及 fresh 完整 replay；改接口／映射／输入摘要时启动前拒绝；缺功能语义显示 L1/L2、L3 未验证，而非 unavailable。
- [ ] G7：改组件 ID 和实例 ID，保持同一 RTL／描述内容，仍可运行；检查基础路径没有名称特判。
- [ ] G8：接入 diff 只允许组件 Profile／接口及观察描述、声明式场景、测试／报告和该组件的透明接线 wrapper。Runner、Router、Scheduler、Mutator、公共 Checker、公共 factory／registry、协议执行器及功能插件不得改动；逐文件 SHA 和 diff 由只读 verifier 核对。

**强制通过条件：**G1–G8 全部成立。若接入暴露通用框架缺陷，回到 B/C 修复、冻结新 baseline 后重新接入；不能一边新增组件专用公共代码一边称门禁通过。HMAC 门禁不得以 skipped_unavailable 抵消；资源或闭包未解决时，该阶段仍缺未知 IP 接入证据。

### H. 20 个组合的功能及分级验收

| CPU | GPIO | UART | SPI | I2C | Timer |
|---|---|---|---|---|---|
| CVA6 | PULP GPIO | OpenTitan UART | OpenTitan SPI Host | PULP I2C | OpenTitan RV Timer |
| BOOM | 同上 | 同上 | 同上 | 同上 | 同上 |
| CVW | 同上 | 同上 | 同上 | 同上 | 同上 |
| VexiiRiscv | 同上 | 同上 | 同上 | 同上 | 同上 |

- [ ] H1：每行依次独立交易、8-case smoke、60 秒连续搜索／replay、600 秒功能门禁／replay；失败不进入后一级。
- [ ] H2：每个可运行 CPU 的五行均验证真实 CPU→IP 消费及 IP→CPU read／IRQ 路径、持续状态、两侧可用上游输入、实际反馈、正常对照、受控错误捕获与完整前缀。
- [ ] H3：非功能插件提供的 L1 基础覆盖／依赖独立报告；L3 功能链单列，不能用基础事务完成抵消缺功能证据。
- [ ] H4：当 IP 没有合法外部数据输入时，按描述登记可探索源，不为满足双侧指标虚构输入；该矩阵默认对象具有外部／时间输入的实际角色，Timer 本地时间推进属于固定调度，只有可合法选择的等待／调度才可作为独立探索动作。
- [ ] H5：每行使用相同预算的反馈启用／关闭短对照，证明选择受影响；不要求覆盖收益必然为正。
- [ ] H6：统计初始化、有效搜索、终结、逐例耗时、资源峰值、覆盖、candidate／verified／functional 指标及来源缺口。零耗时和缺验证数不能通过。
- [ ] H7：增加功能族替换：GPIO PULP→OpenTitan、UART OpenTitan→ZipCPU、SPI OpenTitan→PULP、I2C PULP→OpenTitan、Timer OpenTitan→PULP；在 CVA6 上各 60 秒及 replay，核心不增加名称分支。

**完成口径：**每个可运行 CPU 的五行均达到声明的功能门槛；若某行只能 L1/L2，该行基础能力可登记通过，但功能矩阵仍未完成。跳过 CPU 的整列附原因，不能用其他 CPU 的组合抵消。

### I. 兼容、证据、文档与交付

- [ ] I1：恢复／保留 Ibex 第一阶段有效入口；旧 schema 原样解释，规范化及分级语义进入新 run identity，历史证据不补字段后冒充新版本。
- [ ] I2：完整保存 raw／生成程序／源动作／接纳顺序／等待选择／首次物化／case 前缀／所有身份；实际核验文件 hash，而非仅声明摘要。
- [ ] I3：fresh replay 从新进程初态复现 raw 与规范化事件、证据类别及 finding；候选发现和插件配置冻结。跨 epoch active witness 状态按事件重建。
- [ ] I4：只读验收器验证分级、插件禁用、依赖负例、SHA 冻结、新 IP protected diff、20 行、可用 CPU、完整 replay 和资源边界。
- [ ] I5：能力查询和报告支持按 operation／endpoint 的 L1–L3，显示 declared／effective／verified、candidate／verified 与 skipped 原因，不按插件安装情况推断运行可用性。
- [ ] I6：更新系统说明、能力矩阵及总计划 P6/P7 的声明范围；新 IP 基础接入是本阶段强制子门禁，不等于 P7 任意组件全功能自动测试完成。
- [ ] I7：提交源码、配置、单测、真实门禁、只读复算命令与最小恢复材料；cache 集中保留，临时副本清理依据身份清单。

## 5. 测试清单与完成证据

| 测试组 | 必须覆盖 |
|---|---|
| 分级 | 无插件运行 L1；无 register map 仍 L1；合法 map→L2；缺功能观察只禁对应功能；最低等级请求不满足拒绝 |
| 基础事件 | APB3／TL-UL／Wishbone 的 request／accept／response、wait/error；任意端口名与切片；raw 不变；插件关闭基础流不变 |
| 寄存器 | mask／权限／宽度／reset；已核实副作用；无描述不推断写后读相等；CPU 与 BFM 来源明确 |
| 依赖 | 声明不等于真实；时间和值相同只有候选；删精确 hop 撤销认证；epoch／版本／容量／冲突／重试／迟到消费 |
| 反馈 | 基础覆盖独立可用；候选默认关闭且预算有界；候选不认证；功能 novelty 单列；当前 witness 与历史计数分开 |
| CPU | ISA／XLEN、缓存物化、burst／ID、推测／退休、实际 IRQ、未知能力拒绝；核心无 CPU 名称分支 |
| 新组件 | 真实 HMAC 无插件 L1、寄存器描述 L2、CVA6 组合、60 秒及 replay、核心文件 SHA 不变 |
| 资源与清理 | 单 worker；进程树预算；异常释放；新日志不覆盖旧证据；候选和观察详情不能无界保留 |
| 兼容 | 第一阶段轻量回归及短真实 Ibex smoke；旧 replay 明确版本；不重解释历史结论 |

长跑不作为开发阶段反复调试方法。真实结果按构建／独立／smoke／短跑／长跑递进；每项结论绑定当前配置，禁止把多份短跑 union 宣称为一份持续会话。

## 6. 实施顺序、检查点和最终交付

| 检查点 | 任务 | 进入下一步条件 |
|---|---|---|
| M0 | A | 公共证据风险重核，资源控制及基线有效 |
| M1 | B、C | 匿名／未知功能 IP 可按已支持协议运行 L1，基础事件不需功能插件 |
| M2 | D、E1–E2 | 三类依赖隔离，基础反馈及 L2 已验证，不发生候选伪认证 |
| M3 | F1–F5、G | CVA6 接入保留架构，真实新 HMAC 仅描述接入门禁通过 |
| M4 | E3–E7、H7 | 五类功能插件可选，基础测试仍可运行，替换证明复用 |
| M5 | F6–F9、H1–H6 | 四核逐项可用状态明确；全部可运行 CPU 的五行完成 |
| M6 | I | 分级及依赖验收器、兼容、文档、恢复材料齐全 |

CPU 实施顺序 CVA6→CVW→VexiiRiscv→BOOM；后三核工具链／来源条件在 A 同时核清，但重型生成仍串行。若原有第二阶段任务已经完成，按同一 gate 补证／复用，不重复实现。

最终交付：保留既有架构的增量 patch；四核能力／配置；L1–L3 描述及预检；基础／寄存器／功能事件；三类依赖和分离反馈；五族增强及替换证据；HMAC 未知 IP 强制门禁；最多 20 个组合的逐行结果；完整身份／replay／资源报告；缺口清单和最小恢复资料。

**当前状态：**A1–A5 已完成，M0 基线门禁通过；B1–B6、C1–C7 已完成，M1 软件门禁通过，D1–D4 已完成（软件范围），下一项 D5 RAM／IRQ 精确证明范围；Stage 2 生产运行／真实 DUT 门禁仍未完成。A2 修复首步 replay 日志消费和配对验收伪通过，并审计 fresh RTL trace counts／identity、证书精确身份、serial token、batch replay identity 与异常清理。A4/A5 的单 worker／进程树 RSS、启动拒绝、heap fail-closed、身份缓存、fresh run 目录与失败清理均有测试或真实 smoke／Verilator 证据。当前尚无 Stage 2 CPU/IP 生产命令消费者；B–I 建立具体重型命令时必须接入同一 worker 与身份缓存，这属于后续工作包的执行约束。Java/SBT/Mill 不可用，直接 Mill 命令 fail closed；不声称真实 JVM generator 已运行。B1 sidecar 有独立版本、闭集字段校验、完整 profile 指纹绑定、引用核对和深度不可变身份。B2 能力解析区分声明、可执行预检和证据验证；实际矩阵仍未授级，边界见 [B2 报告](../../reports/stage2-b2-capability-levels-20261010.md)。B5 验证 v2 通用 executor 选择不依赖外设标签或 endpoint ID，同时保留旧专用及已验证探针路径；B6 六类负例锁定等级降级、最低等级拒绝、协议／端口拒绝、bound ownership 和寄存器名不推断功能。C1–C2 增加版本绑定的基础端口采样／变化事件投影，raw sample 原样保留；C3 加入声明式协议事务与原生身份事件；C4 补齐 profile 物理输入采样、显式绑定交付及实际输入采样关联；C5 增加不依赖功能插件的协议 Checker 并由 Runner 记录违规、失败关闭；C6 增加有界增量基础覆盖和 `base_coverage` 快照。C7 fixtures 已通过验收，新增功能消费者禁止导入与基础覆盖不变检查，证据见 [C7 报告](../../reports/stage2-c7-plugin-free-fixtures-20261011.md)。详见 [B5 报告](../../reports/stage2-b5-executor-selection-20261010.md)、[B6 报告](../../reports/stage2-b6-negative-contracts-20261010.md)、[C1–C2 报告](../../reports/stage2-c1-base-events-20261010.md)、[C3 报告](../../reports/stage2-c3-protocol-base-events-20261010.md)、[C4 报告](../../reports/stage2-c4-input-sampling-20261010.md)、[C5 报告](../../reports/stage2-c5-protocol-checker-20261010.md)和[C6 报告](../../reports/stage2-c6-base-coverage-20261010.md)。Ibex retry1 的 3/3 legacy cases 与 fresh replay 不能授予 Stage 2 矩阵等级。见 [M0/B1 进度报告](../../reports/stage2-m0-baseline-progress-20261009.md)、[起点身份](../../reports/stage2-baseline-20261009.json)和[逐行矩阵](../../STAGE2_ACCEPTANCE_MATRIX.md)。

2026-10-12 verifier Session／可信file replay最新检查点：Runtime66项及closed saved／Session／CLI联合50项软件通过；实际generation完成14case检查并产13项scope证书（A10操作/B0），但180.18秒在认证保存阶段超时，未获bundle/fresh验收。所有失败产物保留，预算不变，导出重复成本正独立定位。见[执行报告](../../reports/stage2-e2-register-verifier-session-execution-20261012.md)。完整E1/E2/Stage2保持未完成。

2026-10-12 导出优化最终软件：Session15项、独立export4项、singleexport/closed saved/CLI联合35项通过；v2实际14case generation正在运行，原独立180秒/RSS预算保持，production冻结。上一轮wall_timeout及partial audit仍只证明部分实际观察，不能冒称认证保存/fresh通过。见[最新执行报告](../../reports/stage2-e2-register-verifier-session-execution-20261012.md)。原E1/E2及完整Stage2未完成。


2026-10-12 chunk4 LOW pins10–13 fresh78630已exit0／complete：119.3633515190013秒、peak1,847,529,472 bytes低于3,129,950,208限额、available5,277,433,856，完整fullmatch断言通过。generation与fresh均通过，独立audit刚GO、尚未最终验收；accepted仍12指定points，不能提前记16。chunk5 INTTYPE_HIGH准备未执行，原D5／D6／D8、完整E1／E2及E3–I、全值／权限／width／reset范围保持开放。


2026-10-12 chunk4 fullaudit72392终态PASS，accepted current16个LOW exact单取值points，不是0..3穷举／整bank能力授级。HIGH chunk5 generation95236已实际启动、仍运行未通过，当前源码／脚本SHA／AST／tuple及actual PAD_NUM32 preflight一致；chunk6 HIGH18–21仅prepared未执行。完整Stage2及全值／权限／width／reset边界仍保持开放。


2026-10-12 HIGH首组generation95236已exit0／complete：132.3070836919942秒、available5,243,768,832／peak2,046,111,744低于3,096,285,184限额／worker1／DUTFalse，8cases／18,218events／18关联。Root separatefresh59768已实际运行，尚无最终验收；accepted仍16LOW points，不借历史HIGH证明。chunk7 HIGH22–25 prepared未执行，完整Stage2继续OPEN。


2026-10-12 HIGH首组fresh59768已exit0／complete：116.24226334200648秒、available5,239,918,592／peak1,848,770,560低于3,092,434,944限额／worker1／DUTFalse；完整trace／count／semantic／ordinary／verifier／preflight断言通过。fullaudit已GO但尚未验收，accepted仍16LOW points，不提前计20或授整bank／全部值能力。


2026-10-12 HIGH首组fullaudit45969已终态PASS：18,218events／8current与8historical证书／identity、semantic及完整generation／fresh一致；accepted current20 exactpoints（16LOW＋4HIGH），非全值穷举。chunk6 HIGH18–21 generation50635实际运行、尚未通过，same singleworker180／own empty cache／source冻结；chunk8 HIGH26–29仅prepared未执行。原Stage2所有开放范围不缩减。


2026-10-12 chunk6 HIGH18–21 generation50635已exit0／complete：131.0059881999914秒、available5,244,407,808／peak2,046,242,816低于3,096,924,160限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh69170实际运行、未最终验收，accepted仍20指定points。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15（4bit，offset0x28）prepared未执行，不借旧pin0／7证明当前scope；原Stage2开放。


2026-10-12 chunk6 fresh69170已exit0／complete：117.59755330599728秒、available5,260,267,520／peak1,849,614,336低于3,112,783,872限额／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight通过。独立audit待终态，accepted仍20points；chunk10 PADCFG_0.pin2／3／4／5 values2／6／9／14 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk6 fullaudit45184已终态PASS，exacttuple／18,227events／8证书及完整fresh一致，见[独立报告](../../reports/stage2-e2-inttype-high-pins18-21-independent-audit-20261012.md)。accepted current24单valuepoints（16LOW＋8HIGH），不是全值穷举。chunk7 HIGH22–25 values3／1／2／3 generation42268实际运行、未通过，own absent cache／singleworker180／无native或audit重叠；原scope继续OPEN。


2026-10-12 chunk7 HIGH22–25 generation42268已exit0／complete：131.44182803299918秒、available5,353,672,704／peak2,046,332,928低于3,206,189,056限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh75326运行中、audit待完成，accepted仍24；chunk12 PADCFG_1.pin10–13 values2／6／9／14 prepared未执行，完整原scope保持OPEN。


2026-10-12 chunk7 fresh75326已exit0／complete：116.5613808670023秒、available5,327,286,272／peak1,849,888,768低于3,179,802,624限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、accepted仍24；chunk13 PADCFG_2.pin16／17／22／23 values1／5／10／15 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk7 fullaudit93696已终态PASS，exacttuple／18,227events／8证书及完整fresh一致；accepted current28 singlepoints（16LOW＋12HIGH），不是全值穷举。chunk8 HIGH26–29 values1／2／3／1 generation70283实际运行、尚未通过，own absent cache／singleworker180／current source-script preflight一致且无overlap；原Stage2仍OPEN。


2026-10-12 chunk8 HIGH26–29 generation70283已exit0／complete：132.64775778599142秒、available5,336,645,632／peak2,046,345,216低于3,189,161,984限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh31823运行中、独立audit待完成，accepted仍28points；chunk15 PADCFG_3.pin24／25／30／31 values1／5／10／15 prepared未执行，原全scope继续OPEN。


2026-10-12 chunk8 fresh31823已exit0／complete：118.06382439300069秒、available5,314,101,248／peak1,851,424,768低于3,166,617,600限额／worker1／DUTFalse，fulltrace／wrappers／semantic／count／preflight通过；独立audit待终态，accepted仍28。chunk16 PADCFG_3.pin26–29 values2／6／9／14 prepared未执行；16chunks均准备不等于已执行或已验收，原Stage2开放。


2026-10-12 chunk8 fullaudit79481已终态PASS：exacttuple／18,227events／8证书与完整fresh一致；accepted current32指定points（16LOW＋16HIGH），每INTTYPE field一个合法value，非穷举／整bank授级。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15 generation38477实际运行、尚未通过，offset0x28／own absent cache／singleworker180／source-script preflight一致且无overlap；原Stage2完整scope保持OPEN。


2026-10-12 chunk9 PADCFG_0首组generation38477已exit0／complete：132.42977688899555秒、available5,366,063,104／peak2,046,464,000低于3,218,579,456限额／worker1／DUTFalse，8cases／18,222events／18关联；fresh60729实际运行、未最终验收，accepted仍32。轻量16组preparation／current source与script SHA／AST／exact field-value tuples核对PASS，完整覆盖32INTTYPE＋32PADCFG无漏重；10–16prepared不等于executed，原scope不缩减。


2026-10-12 chunk9 PADCFG0 fresh60729已exit0／complete：119.73843699799909秒、available5,316,136,960／peak1,851,084,800低于3,168,653,312限额／worker1／DUTFalse，完整trace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍32points、不提前36；nextchunk10 preflight通过仍未执行，16组exact64无漏重核对不替代实际验收。


2026-10-12 chunk9 fullaudit99824终态PASS，exactPADCFG_0.pin0／1／6／7 values1／5／10／15、18,222events／8证书及完整fresh一致，见[独立报告](../../reports/stage2-e2-padcfg0-first-field-independent-audit-20261012.md)。accepted current36单points（32INTTYPE＋4PADCFG），非全值穷举。chunk10 PADCFG_0.pin2–5 values2／6／9／14 generation48852实际运行、尚未通过，offset0x28／singleworker180／own absent cache／preflight一致且无overlap；原全scope保持OPEN。


2026-10-12 chunk10 PADCFG0 pins2–5 generation48852已exit0／complete：133.4572914129967秒、available5,361,512,448／peak2,046,603,264低于3,214,028,800限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh60114正在独立预算运行、audit待完成，accepted仍36指定points，不提前40或全bank授级；原Stage2保持OPEN。


2026-10-12 chunk10 fresh60114已exit0／complete：118.20331636900664秒、available5,377,863,680／peak1,850,490,880低于3,230,380,032限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、accepted仍36，不提前40；chunk11 PADCFG_1首组 offset0x2c preflight通过尚未执行，remaining word gate仅设计／只读审查，不计passed。


2026-10-12 chunk10 fullaudit30129终态PASS，exactPADCFG0 pins2–5 values2／6／9／14、18,231events／8证书与完整fresh一致；accepted current40单points（32INTTYPE＋8PADCFG0），非全值穷举。chunk11 PADCFG1首组 pin8／9／14／15 values1／5／10／15 generation12336实际运行、尚未通过，offset0x2c／own absent cache／singleworker180／preflight一致无overlap；word设计无审查阻断但仍未执行，原scope开放。


2026-10-12 chunk11 PADCFG1首组generation12336已exit0／complete：132.28506910100987秒、available5,405,487,104／peak2,046,394,368低于3,258,003,456限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh25753实际运行、audit待完成，accepted仍40points；DIR／OUT六request word包只准备、16matrixchunks后再执行，不提前native验收。


2026-10-12 chunk11 fresh25753已exit0／complete：118.60419732998707秒、available5,349,089,280／peak1,850,675,200低于3,201,605,632限额／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight通过。独立fieldaudit待终态，accepted仍40；chunk12 offset0x2c preflight通过尚未执行。DIR_OUT word包（checkd9937f…7677）仅准备，16矩阵后独立审查／执行，不计native通过。


2026-10-12 chunk11 fullaudit57934已终态PASS，exactPADCFG1 pins8／9／14／15 values1／5／10／15／18,222events／8证书及完整fresh一致；accepted current44单points（32INTTYPE＋12PADCFG），非穷举。chunk12 PADCFG1 pins10–13 values2／6／9／14 generation10967实际运行、尚未通过，offset0x2c／own absent cache／singleworker180／preflight一致且无overlap；word尚未运行，原fullscope保持开放。


2026-10-12 chunk12 PADCFG1 pins10–13 generation10967已exit0／complete：133.12426655500894秒、available5,433,249,792／peak2,046,672,896低于3,285,766,144限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh17134实际运行、audit待完成，accepted仍44；第二word GPIOEN_INTEN六case包仅准备、16矩阵后再执行，不计native通过。


2026-10-12 chunk12 fresh17134已exit0／complete：118.8060304679966秒、available5,397,753,856／peak1,850,212,352低于3,250,270,208限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fieldaudit待终态、accepted仍44不提前48；chunk13 offset0x30 preflight通过未执行。GPIOEN_INTEN第二word包（check590d73…32f5）仅prepared／轻量review无阻断，仍未运行、待16矩阵后，原scope开放。


2026-10-12 chunk12 fullaudit8463已终态PASS，exactPADCFG1 pins10–13 values2／6／9／14、18,231events／8证书与完整fresh一致；accepted current48单points（32INTTYPE＋16PADCFG），非全值穷举。chunk13 PADCFG2首组 pin16／17／22／23 values1／5／10／15 generation92288实际运行、尚未通过，offset0x30／own absent cache／singleworker180／preflight一致无overlap；两个word包prepared未执行，原Stage2全scope仍OPEN。


2026-10-12 chunk13 PADCFG2首组generation92288已exit0／complete：132.9991300420079秒、available5,449,052,160／peak2,046,648,320低于3,301,568,512限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh97116实际运行、audit待完成，accepted仍48；PADIN word四request包（check219240…9c8c）仅prepared／APB_CPU_RAM consistency，不授sampling或reset证明，待16矩阵后运行。


2026-10-12 chunk13 fresh97116已exit0／complete：119.25131022800633秒、available5,386,960,896／peak1,850,802,176低于3,239,477,248限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、accepted仍48不提前52；chunk14 offset0x30 preflight通过未执行。PADIN word轻量review无阻断／audit准备仍未执行，原全scope保持OPEN。


2026-10-12 chunk13 fullaudit35340终态PASS，exactPADCFG2 pins16／17／22／23 values1／5／10／15／18,222events／8证书及完整fresh一致，见[独立报告](../../reports/stage2-e2-padcfg2-first-field-independent-audit-20261012.md)。accepted current52单points（32INTTYPE＋20PADCFG），非穷举。chunk14 PADCFG2 pins18–21 values2／6／9／14 generation43790实际运行、未通过，offset0x30／own absent cache／singleworker180／preflight一致无overlap；3word包prepared未执行，原scope开放。


2026-10-12 chunk14 PADCFG2 pins18–21 generation43790已exit0／complete：132.3194965099974秒、available5,438,459,904／peak2,046,128,128低于3,290,976,256限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh11311运行中、audit待完成，accepted仍52；next reset-default只读设计未实现或运行、不预授grant，原fullscope保持OPEN。


2026-10-12 chunk14 fresh11311已exit0／complete：118.92392746800033秒、available5,382,307,840／peak1,849,397,248低于3,234,824,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍52不提前56；chunk15 offset0x34 preflight通过尚未执行，原Stage2完整scope保持OPEN。


2026-10-12 chunk14 fullaudit60628已终态PASS，exactPADCFG2 pins18–21 values2／6／9／14／18,231events／8证书及完整fresh一致，见[独立报告](../../reports/stage2-e2-padcfg2-pins18-21-independent-audit-20261012.md)。accepted current56单points（32INTTYPE＋24PADCFG），非全值穷举。chunk15 PADCFG3首组pin24／25／30／31 values1／5／10／15 generation62291实际运行、未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；reset-default只读设计不计实现或grant，原scope保持OPEN。


2026-10-12 chunk15 PADCFG3首组generation62291已exit0／complete：134.15973644101177秒、available5,471,129,600／peak2,045,935,616低于3,323,645,952限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh77906运行中、audit待完成，accepted仍56；reset-default独立设计review指出actualcommand全覆盖／未知命令fail closed／完整field-affect／process boundary实施前缺口，只有docs修订，未实现或授grant。


2026-10-12 chunk15 fresh77906已exit0／complete：120.05253920699761秒、available5,461,848,064／peak1,850,097,664低于3,314,364,416限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、accepted仍56不提前60；chunk16 offset0x34 preflight通过未执行。reset-default设计reconciled仅docs、未实现或授grant，原全scope保持OPEN。


2026-10-12 chunk15 fullaudit41628已终态PASS，exactPADCFG3 pins24／25／30／31 values1／5／10／15／18,222events／8证书与完整fresh一致，见[独立报告](../../reports/stage2-e2-padcfg3-first-field-independent-audit-20261012.md)。accepted current60单points（32INTTYPE＋28PADCFG），非穷举。chunk16 PADCFG3 pins26–29 values2／6／9／14 generation9338实际运行、尚未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；64fieldpoints后仍有word／permission／width／reset及原Stage2完整scope，不能标阶段完成。


2026-10-12 chunk16 PADCFG3 pins26–29 generation9338已exit0／complete：131.9667810839892秒、available5,477,412,864／peak2,046,443,520低于3,329,929,216限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh6576正在运行、audit待完成，accepted仍60不提前64；3word包prepared待矩阵完成后执行，原Stage2全scope保持OPEN。


2026-10-12 chunk16 fresh6576已exit0／complete：118.51990141399438秒、available5,447,532,544／peak1,851,146,240低于3,300,048,896限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。最后独立audit待终态，accepted仍60不提前64；16组小证据聚合核对仅准备，各bundle current8证书不能伪称global active128，非exhaustive／fullE2。


2026-10-12 最后chunk16 fullaudit11089实际exit0／PASS，16bundle轻量聚合PASS：accepted current64 exact指定单valuepoints（32个2bit INTTYPE＋32个4bit PADCFG），无漏重；每bundle current8证书，不能拼成global active128；16gen／16fresh各自singleworker／≤180秒，与全部sourcefreeze／fresh／resources小证据一致。见[聚合报告](../../reports/stage2-e2-register-field-matrix-aggregate-20261012.md)。不是全值穷举或完整E2，word／permission／width／reset仍OPEN。Root DIR_OUT word generation48145已实际运行、尚未通过，原Stage2完整范围不缩减。


2026-10-12 DIR_OUT word generation48145已exit0／complete：119.19223787200463秒、available5,482,065,920／peak1,715,609,600低于3,334,582,272限额／worker1／DUTFalse，6cases／13,907events／12关联／18selectedAPB／3RAM。fresh3571实际运行、独立audit待完成，word尚未accepted；narrow64已审计单valuepointscope保持独立，不扩成global或完整E2。


2026-10-12 DIR_OUT word fresh3571已exit0／complete：101.75905876699835秒、available5,479,596,032／peak1,575,030,784低于3,332,112,384限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。word独立fullaudit待终态、尚未accepted；narrow64单值scope保持独立，原Stage2继续OPEN。


2026-10-12 DIR_OUT word fullaudit42062终态PASS，13,907events／6证书／exact B.INTEN0与A.PADDIR／PADOUT 0x80000000三instance-specific write/read pairs验收，见[独立报告](../../reports/stage2-e2-word-dir-out-independent-audit-20261012.md)。不授functional／reset／fullL2，narrow64保持独立。EN_INTEN generation49060实际运行、未通过，source-script SHA／AST／exact6tuple与own absent cache preflight一致／singleworker180／无overlap；PADIN未运行、reset-default未实现，原全scope保持开放。


2026-10-12 EN_INTEN word generation49060已exit0／complete：116.19795339199482秒、available5,497,872,384／peak1,715,634,176低于3,350,388,736限额／worker1／DUTFalse，6cases／13,905events／12关联／18selectedAPB／3RAM。fresh74249运行中／audit待完成，EN_INTEN尚未accepted，DIR_OUT3pairs与narrow64分别独立。current alias zero-mask八case包仅准备、PADIN之后再执行，不借旧source，不提前native验收。


2026-10-12 EN_INTEN fresh74249已exit0／complete：100.39961130799202秒、available5,492,273,152／peak1,573,228,544低于3,344,789,504限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态，尚未accepted、DIR_OUT与narrow64scope保持独立。current alias zero-mask八request包（check86a6e8…bd97）仅prepared，待PADIN后／独立review，不提前native验收。


2026-10-12 EN_INTEN fullaudit99853已终态PASS，13,905events／6证书／exact B.INTEN0、A.GPIOEN与A.INTEN 0x80000000三instance-specific fullword pairs验收；B.INTEN0与DIR_OUT重复，不重复计unique，不授functional／reset／fullL2，narrow64scope独立。PADIN generation83748实际运行、未通过，current typed RO／exact4request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。alias zero-mask仍prepared／review、reset-default未实现，原全scope保持OPEN。


2026-10-12 PADIN generation83748已exit0／complete：103.98888060198806秒、available5,509,058,560／peak1,414,696,960低于3,361,574,912限额／worker1／DUTFalse，4cases／10,129events／10关联／12selectedAPB／3RAM。fresh88629实际运行、audit待完成，PADIN尚未accepted，scope只APB→CPU→RAM consistency、不授sampling／reset；EN_INTEN3pairs与narrow64独立，aliaszero仍仅prepared，原scopeOPEN。


2026-10-12 PADIN fresh88629已exit0／complete：87.21911255799932秒、available5,506,846,720／peak1,302,310,912低于3,359,363,072限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、尚未accepted，不授sampling／reset，existing wordpairs与narrow64独立。current alias fullmask八case包只准备、待PADIN＋aliaszero之后；aliaszero prepared／review通过仍未native，原scope开放。


2026-10-12 PADIN fullaudit75237已终态PASS，10,129events／4证书／exact B.INTEN0 pair与A／B.PADIN READs，见[独立报告](../../reports/stage2-e2-word-padin-independent-audit-20261012.md)。scope仅APB_CPU_RAM consistency，不授sampling／reset／fullL2，重复B.INTEN0不新增unique。current aliaszero generation52350实际运行、未通过，current v3 relation／exact8request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。fullmaskprepared未执行／reset只读，原Stage2全scope保持OPEN。


2026-10-12 current aliaszero generation52350已exit0／complete：132.50322782000876秒、available5,517,291,520／peak2,044,710,912低于3,369,807,872限额／worker1／DUTFalse，8cases／17,677events／14关联／24selectedAPB／5RAM。fresh75682实际运行、audit待完成，aliaszero尚未accepted；fullmaskprepared／轻量review通过仍未执行，PADINscoped与wordpairs／narrow64独立，原全scopeOPEN。


2026-10-12 current aliaszero fresh75682已exit0／complete：117.51322904099652秒、available5,533,614,080／peak1,847,062,528低于3,386,130,432限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态、zero尚未accepted，fullmaskprepared未执行；partial／high／repeat current alias下一步只读设计，不borrow旧source，原Stage2全scope开放。


2026-10-12 current aliaszero fullaudit30129（本轮process）终态PASS，17,677events／8证书／exact8requests zero SET／CLR＋B.INTEN0 pair一致，见[独立报告](../../reports/stage2-e2-alias-zero-current-independent-audit-20261012.md)。仅2source-bound zero brackets验收，不授storageversion／prerequisite／functional／reset／fullE2，word／narrow64scope独立。fullmask generation66978实际运行、未通过，actualFFFFFFFF builder／currentv3／source-script preflight一致／own absent cache／singleworker180／无overlap；partial_repeat current-source仅design待独立review，未准备执行。


2026-10-12 current aliasfullmask generation66978已exit0／complete：130.43963241600432秒、available5,511,983,104／peak2,043,985,920低于3,364,499,456限额／worker1／DUTFalse，8cases／17,683events／14关联／24selectedAPB／5RAM。fresh32283实际运行、audit待完成，fullmask未accepted；partial_repeat独立designreview中现规则允许shared actual adjacent READ boundary，新gate独立before为实验要求，仅docs修订／未执行，原scope开放。


2026-10-12 current fullmask fresh32283已exit0／complete：115.31429795100121秒、available5,522,804,736／peak1,849,442,304低于3,375,321,088限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、fullmask未accepted／currentzero2brackets已验收；SET partial_repeat十request新worker仅prepare，sharedactualREAD规则与独立newbefore2实验要求已reconciled、未native，原scope开放。


2026-10-12 current fullmask fullaudit39840终态PASS，17,683events／8证书／exactSET_CLRFFFFFFFF一致，见[独立报告](../../reports/stage2-e2-alias-fullmask-current-independent-audit-20261012.md)。仅2fullmask brackets验收，不授functional／reset／storageversion／fullE2；zero2／word／narrow64scopes独立。SET partial_repeat十request包（check42b3ca…05dc）prepared／Root preflight通过，轻量review／audit准备中、NOTnative；当前全部native已终态，原Stage2全scope仍OPEN。


2026-10-12 SET partial_repeat generation64745实际启动、新v1／own absent cache／singleworker180／无overlap，独立lightreview无阻断／auditprepared及Root source-SHA／AST／exact10request preflight一致。尚未通过：10cases（6READ／2plain／2alias）／10selectedMMIO／30selectedAPB／6RAM／expected16关联48allAPB仅准备断言，high／repeat不预授。current fullmask2brackets已accepted，generic规则不改，原Stage2全scope保持OPEN。


2026-10-12 partial SET generation64745已exit0／complete：151.32340373699844秒、available5,571,547,136／peak2,346,278,912低于3,424,063,488限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh51736实际运行、audit待完成，partialSET尚未accepted，全部10cases与原预算保持；CLR partial_repeat十request包（checkf3e984…bc49）prepared，待SET全终态／独立review，未native执行，原scope开放。


2026-10-12 partial SET fresh51736已exit0／complete：133.26829966400692秒、available5,504,163,840／peak2,122,182,656低于3,356,680,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、SET尚未accepted，全部10cases／原180预算保持；CLR prepared lightreview无阻断／auditprepared（b3c85a…5f3b），未执行、待SET audit终态，原scopeOPEN。


2026-10-12 partial SET finalaudit16667终态PASS，21,451events／10证书／exact seed55aa00ff_SET80000000＋repeat一致，见[独立报告](../../reports/stage2-e2-alias-partial-set-current-independent-audit-20261012.md)。firstaudit69511 exit1 NameError cap为audit setup漏sidecar load，仅补load、不改事实断言，失败保留／非DUT finding。仅2SET brackets验收，不预授CLR／reset／functional／storageversion／fullE2。CLR generation60831实际运行、未通过，source-script preflight／lightreview一致／own absent cache／singleworker180／无overlap，全部10cases保留，原scopeOPEN。


2026-10-12 partial CLR generation60831已exit0／complete：143.68561087400303秒、available5,575,970,816／peak2,345,062,400低于3,428,487,168限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh48813实际运行、audit待完成，CLR未accepted，全部10cases／原180保持。SET2brackets已accepted，首次audit setup失败真实script／stderr／receipt与SHA证据保留、非DUT finding；原scope保持OPEN。


2026-10-12 partial CLR fresh48813已exit0／complete：139.66191233199788秒、available5,607,415,808／peak2,120,609,792低于3,459,932,160限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、CLR尚未accepted，全部10cases／原180保持，原scope开放。


2026-10-12 partial CLR fullaudit28385已终态PASS，21,451events／10证书／exact seed d5aa00ff，见[独立报告](../../reports/stage2-e2-alias-partial-clr-current-independent-audit-20261012.md)；仅2CLR brackets验收，不授arbitrary masks／reset／storageversion／functional／fullL2。全部native与audit终态后，current f7da exact14权限软件测试exec66607 exit0，14 passed／23.06秒（真实外层wall23.440831127998536），前后源码／fixture SHA不变、stdout／stderr／终态receipt保存在[本轮证据](../../../runs/stage2-e2-current-register-permission-software-20261012/receipt.json)。actual对象软件transport，无Generated Popen／DUT／RTL；仅前effect声明policy拒绝，不是PSLVERR硬件权限证明；历史22.92秒记录保持，原Stage2全scope仍OPEN。


2026-10-12 native reset-default实施前checkpoint：current CLR2 source-bound brackets已审计accepted，current f7da permission14软件PASS23.06秒，均仅各自scope。新[ordinary native reset-default计划](2026-10-12-stage2-ordinary-native-reset-default.md)已存在、尚未实现。为保留未提交历史源闭包，已新增[当前源码原始bytes冻结manifest](../../../runs/stage2-e2-pre-native-reset-source-freeze-20261012/manifest.json)：20baseline文件／815,794bytes逐件archivebytes＝currentbytes／真实SHA核对，manifest SHA `dbb3dbc4d43fffcb808468eac67fae84cfe3c1ef6b2fb9f316dd390b8ec5a4bc`。仅historical source reconstruction材料，非runtime authority；未复制cache／binary，未改旧run pins。后续新源码必须单列证据，不能以新SHA重写已验收历史门禁；原全scope仍OPEN。


2026-10-12 ordinary native reset-default计划已冻结、Task1获Root GO。Task1／2独立review三条件继续作为实施约束：ACK至postparse／callback全错误范围、实际pinned build issuance资格、public export与private issuer／registry分离。20baseline源码bytes已归档；Task1修改后既有f7da／bfbb native门禁仅历史source qualification，旧pins不重写。Task2 Runner private consumer仅只读接口与测试准备，等待renderer final契约，未修改生产／运行测试，不记为完整E1／E2完成。
