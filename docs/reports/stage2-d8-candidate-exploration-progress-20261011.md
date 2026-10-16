# D8 候选探索预算与生产接线进度

## 2026-10-12：独立分类实际执行通过，最终回归及独立audit通过

2026-10-12续接：D8独立 `--classified-feedback` 门禁执行通过，candidate探索关闭，实际RFuzz3/3 complete；可信CLI fresh完整6,443events matches，semantic SHA `76d867f9a8cc5aee7da2fa1a80c3b921e2fb7833d07a42601333d33739da995e`，范围包含 `classified_case_feedback`／`classified_terminal_state`且无candidate scoring声明。三回执candidate disabled、novelty／energy均0，legacy覆盖单列；实际base GPIO A／B request／accept／response各3／4，verified0、functional unknown。27项当前source pins；singleworker complete76.752490482秒、峰545,849,344 bytes、RSSlimit3,038,162,944 bytes。root冻结九模块最终227 passed（93.18秒）；D8独立产物audit通过：27项源码／13项产物摘要、6443事件、21个APB原始引用、逐例及终态base覆盖重算和3个binary／冻结输入均一致。该组合未安装RAM／IRQ provider，6项positive检查仅软件另列；不授实际verified正例、functional或L2矩阵。D8及E1／E2、D5／D6和完整E–I仍未完成。

[新门禁摘要](../../runs/stage2-d8-independent-feedback-cli-20261011/summary.json)与[资源记录](../../runs/stage2-d8-independent-feedback-cli-20261011/resource.json)保存本次结果。source pins读数27，包含独立channel源码闭包及本轮脚本。trusted replay从raw重算逐例classified反馈、source selection和完整终态，再逐事件核对fresh trace；不载入保存反馈作为授权。下文软件阶段“正在执行”保留为本次启动前记录，旧门禁仍属于各自冻结SHA。

## 独立分类开关：初始软件阶段（历史，最终结果见顶部）

新增默认关闭的 `--classified-feedback` 及有界 `--classified-feedback-max-records`，分类反馈与 `decode_candidate`／候选探索开关解耦。独立开启时从实际Runner的观察配置创建基础覆盖，保留实际已安装provider的verified历史反馈；未安装功能provider仍明确functional unknown。candidate关闭时不出现candidate exploration report，每例candidate novelty／energy使用disabled记录且均为0，legacy目标覆盖继续单列。关闭分类开关保持旧路径，不凭分类观察增加候选排序或权重。

完整分类configuration、实际观察配置及source closure进入保存身份；逐例反馈与terminal state由fresh executor重算。可信 `replay-candidates` 命令沿用入口名称，classified-only验证范围明确为完整admitted prefix、Session／decoder checker、online source selection、`classified_case_feedback`与`classified_terminal_state`，不声称candidate scoring或candidate terminal验证。

冻结软件：renderer五模块 **121 passed（62.65秒）**；off／同raw五例对照 **1 passed（0.33秒）**；root adapter的实际RAM／IRQ provider软件检查 **6 passed（0.46秒）**。这些检查不替代新真实门禁；独立review和资源监督actual gates正在执行，尚不宣称审查或实际门禁通过。新分类独立门禁准备目录为 `runs/stage2-d8-independent-feedback-cli-20261011`，仅最终保存结果可作为该冻结源码的实际证据。旧分类／candidate门禁保留各自历史source pins，不能证明本轮新开关。

D8及完整Stage2计划保持未完成：独立分类接线不补齐功能provider的真实反馈，软件RAM／IRQ正例不授未执行组合的实际验收，也不提升candidate为verified或prerequisite。D5／D6及E–I原未完成门槛保持。下文为各轮历史源码与证据。

## 精确反馈分类：真实执行通过，独立产物复核通过

独立产物复核：25source SHA、13artifacts生产verifier／trusted selector、三例分类与终态、6443压缩语义、21条真实pre APB／33candidate context及逐例预算一致。门禁仅无provider分类路径，真实RAM／IRQ positive保持未授。文档616文件／1568链接检查保持83历史断链，本轮无新增。

只读审计确认旧 `functional_coverage` 是 legacy输出谓词命中，不提供Stage2功能证明；五族功能增强归属E3–E7，不以CPU OBI trace作为D8额外完成条件。现新增实际Runner已安装RAM／IRQ provider的只读分类器，完整ledger验证、session去重、bootstrap不计新例、provider配置／身份漂移拒绝及容量原子拒绝；分类不授prerequisites。旧输出目标单列 `legacy_target_coverage`，未配置Stage2功能provider时 `functional_coverage` 明确unknown／new_features空。配置、实现sourceclosure与终态进入候选identity，fresh重放须重算。当前仍随候选开关启用，独立分类开关与功能provider消费后续继续，D8不勾选。

分类器／provider聚焦43 passed（1.19秒）；集成四模块89 passed（40.45秒）。新增真实门禁位于 `runs/stage2-d8-classified-feedback-cli-20261011`，十模块兼容回归220 passed（82.26秒），rehashed功能伪证明fresh拒绝1 passed。只读审查发现ledger格式正确但未锚定实际certificates的P2，实际4证书可注入第五伪记录；已补4条memory／IRQ合法重哈希append／replace负例及2条certificate事实漂移负例RED→GREEN，逐条锚定实际certificate ID并重建scope／规则／epoch／refs；分类／provider49 passed（1.25秒），独立80 passed（2.09秒），原P2复现拒绝且计数0。冻结源码最终八模块178 passed（79.02秒）；新实际门禁已运行通过，独立产物复核通过。[真实分类门禁](../../runs/stage2-d8-classified-feedback-cli-20261011/summary.json)：actual RFuzz 3/3 complete，可信 fresh CLI replay完整6443events matches，33context、novelty／energy1、GPIO A／B协议三种边界各3／4。三份实际回执均保留legacy target且functional unknown／empty；此组合没有安装RAM／IRQ provider，verified0，只证明无provider分类路径与兼容，不授实际verified正例或功能完成。25source pins固定配置及源码；[资源记录](../../runs/stage2-d8-classified-feedback-cli-20261011/resource.json) singleworker complete75.708541秒、峰551,055,360 bytes、RSSlimit3,026,165,760 bytes。独立产物复核通过。

另有 [E1 GPIO寄存器源码审计](stage2-e1-gpio-register-source-audit-20261011.md)，记录14寄存器实际RTL及四个首批字段、无PSTRB字段mask边界和有条件read-clear，未授L2／L3完成。

## Native GPIO passive APB trace：实际执行通过，独立产物复核通过

显式 `local_harness.v2` 的 `raw_tick_stream`／`pre_post` 政策为 native `apb_gpio` 增加八个被动观察出口：`psel`、`penable`、`pwrite`、`paddr`、`pwdata`、`pready`、`prdata`、`pslverr`。trace 同时记录完整 role→signal 映射、宽度、endpoint clock与有效wait bound。native validator 将声明与实际 plan、structural ABI、backend/runtime ports 和生成 wiring 核对；Runner 只在实际 helper 验证通过后准入 native APB projector／checker，缺失或篡改 trace 在receipt drain／case命令前拒绝，失败不缓存为关闭。bootstrap及路由目标沿用真实 raw tick drain→base event 管道。

CPU 仍为 physical-only，OBI 没有 `IpProtocolNormalizer` 契约；默认 v1 不新增协议投影。GPIO receipt 的嵌套raw深拷贝缺口已按5项 RED→GREEN 修复，防止调用方修改观察快照影响后续保留证据。冻结源码的集成回归 **203 passed（107.51秒）**；renderer聚焦45 passed、Runner及旧协议聚焦62 passed、独立只读复核30 passed。以上是构造／软件验证；实际协议执行结果另见下段，独立产物复核通过。

新 [r2门禁摘要](../../runs/stage2-d8-native-apb-cli-20261011-r2/summary.json)记录actual RFuzz 3/3 complete，可信CLI fresh replay完整 **6,443events matches**；`gpio_a` 的request／accept／response各3，`gpio_b`各4，33条context records，novelty1／energy1。[资源记录](../../runs/stage2-d8-native-apb-cli-20261011-r2/resource.json)为singleworker complete76.145718秒、峰547,876,864 bytes、RSS上限3,367,346,176 bytes；22source pins已记录。执行门禁通过，独立产物复核通过：22源码SHA、13artifacts、压缩语义及真实raw引用均一致。真实协议范围仅native GPIO APB，CPU仍physical-only，完整Stage2功能反馈未完成。首轮脚本因 `str` 误替换在RTL前失败，失败产物保留；不计为实际RTL通过。D8仍缺完整Stage2功能反馈及余下真实门槛，D5／D6与E–I保持未完成。下文是各轮冻结源码的历史证据，不覆盖本节独立产物复核通过状态。

本轮独立产物审计：21条APB边界事件全部来自真实raw pre八项taps，request为setup，accept／response为access+ready，相关请求引用同组件／epoch的实际setup；18条属于bootstrap、3条属于observed case。无protocol violation，transaction／native identity为空并保留明确identity gap。13artifacts通过生产verifier及可信selector，逐例预算满足≤1及10%，不授prerequisite。

D8 尚未完成。独立预算层、协议基础覆盖与coverage_context已接入生产候选反馈；可信 `replay-candidates` 已完成闭集本地组合选择。真实3例物理context CLI／RFuzz及完整fresh候选计分／trace重放通过；native GPIO APB已实测；CPU bus协议及完整Stage2功能反馈仍待验收。

## 实际端口、子切片与候选 CLI：本轮续接

### 协议基础覆盖与 coverage_context 接线

adapter 不再把协议映射固定为空：从实际 Runner 的 v2 protocol projector/checker 与 artifact 的 `base_protocol_trace` 重建并比对闭集配置，只有已声明协议／端点才进入基础覆盖。协议请求、接纳、响应、操作、响应状态与延迟桶沿用 `IpBaseCoverageConsumer` 的有限特征；没有原生协议 trace 的 native Ibex／GPIO保留空协议映射。静态信号映射、宽度、clock和wait bound及cached对象身份在case命令前检查，动态协议状态由raw样本新建。

`DependencyCandidateConsumer` 可显式接受最多1024个fresh base consumer的tuple，拒绝重复component/instance，旧单consumer调用保持原特征名称。grouped context 特征采用 `[component_id, instance_id, feature]` 的canonical JSON名字空间；所有consumer与discovery共享同一journal cursor，重叠prefix不重计。只有实际consumer新观察的特征进入context，调用方仍不能传入伪造new_base_features。production按字典序明确选择最多64个port-change／protocol request/accept/response边界特征，并把实际闭集及选择政策存入候选configuration身份；对应关系只映射到已预检的legal source，保持窗口、epoch失效和session去重。

上述context仍是 `candidate` 的event_correlation；原始base/journal引用保留，每case最多1novelty／1energy并受非候选新增能量10%约束，不提升verified、不授prerequisite。软件raw APB由实际Runner完整投影，保存bundle的fresh replay重新计算协议与context终态一致；cached projector/checker drift和非法width在case命令前拒绝。三模块110 passed（1.64秒），独立110 passed（1.63秒）无重要问题；十七模块回归375 passed／1 deselected／207 subtests（78.51秒）。本次软件协议不是真实RTL协议验收，实际物理context CLI门禁另行记录，完整功能反馈及其他真实组合门槛保持。

[真实物理上下文门禁](../../runs/stage2-d8-coverage-context-cli-20261011/summary.json)实际RFuzz CLI 3/3 complete，15条 `coverage_context` candidate；新的可信 replay CLI 新建RTL，从raw重算所有选择／weights／计分／终态，完整6,422events相等（semantic SHA `7d5ca9282d9ac459936ef82379980037181b0f963bf1f09f4426d09fcab26e4d`）。逐例novelty／energy／非候选能量为0/0/0、0/0/0、1/1/10；最后一例实际credit来自CPU `irq_external_i` 的物理port-change context，归属合法 `cpu.online_instruction` source，不授prerequisite。[资源记录](../../runs/stage2-d8-coverage-context-cli-20261011/resource.json)singleworker complete69.253108秒、峰549,531,648 bytes、动态上限3,300,626,432 bytes。20source SHA／13artifact生产verifier／trusted selector／压缩数量和语义核对通过；该组合没有bus protocol trace，真实门禁只证明物理上下文，不能提升为协议或功能链验收。

### 可信候选计分重放入口

最终独立产物复核通过：十四source SHA／十三artifact／trusted selector与压缩语义正确，两份CLI stdout和summary一致；逐例novelty／energy／非候选能量为0/0/0、0/0/0、1/1/10，不授prerequisite，资源低于上限。复核未启动RTL。

新增 `replay-candidates --cache-dir PATH --run-dir SAVED`，先按生产 verifier 核对 bundle，再允许本地固定 Ibex／双 PULP GPIO／标准 checker 构造。`ibex_pulp_candidate_assembly.v1` 是闭集数据声明，拒绝未知字段、bool/int 混用、容量越界、非法 RAM record／来源和不成立的 IRQ／persistent-memory 前置开关；不提供导入路径或源码模板。

候选 builder 在 warmup 后把解析后的构造开关、RAM record 和声明来源写入 executor 的一次性 canonical 快照，live run identity 绑定它。fresh executor 明确使用该已验证配置，避免重读当前环境；公开快照返回独立副本，case 开始后不能改写。通用 fresh API 在 case 命令前比对实际 assembly 声明，旧无声明的 caller-supplied factory 路径保持；保存 scores、source selection 和终态只用于比较，从 raw 输入重新计算。

首轮 [真实 CLI 资源记录](../../runs/stage2-d8-candidate-selector-cli-20261011/resource.json)为 command_failed42.779秒、峰526,938,112 bytes，实际RFuzz 3/3 complete，重放被旧 `_verify_generated_session` 固定 v1 请求拒绝。诊断定位为 GPIO 身份重建丢失 v2 tuning；补普通／consumption GPIO 的 JSON 保存身份无进程回归，保留原 request schema/tuning 并严格重算 artifact，篡改观察政策仍拒绝。首轮源码／命令／stderr保留，不改写其SHA。两处 assembly setter 清理失败覆盖原拒绝的问题也经只读审查修复，cleanup异常仅加 note。

修复后的 [r2门禁摘要](../../runs/stage2-d8-candidate-selector-cli-20261011-r2/summary.json)证明实际 RFuzz CLI 3/3 complete，新的可信 replay CLI 从 fresh RTL 重算选择／weights／候选计分／终态，完整6,422事件匹配，semantic SHA `7d5ca9282d9ac459936ef82379980037181b0f963bf1f09f4426d09fcab26e4d`；novelty1／energy1，重放不重启RFuzz客户端。[资源记录](../../runs/stage2-d8-candidate-selector-cli-20261011-r2/resource.json)为singleworker complete70.807733秒、峰526,372,864 bytes、动态上限3,425,808,384 bytes。十四source SHA、十三artifact生产verifier及闭集selector、压缩trace数量／语义已核对。最终六模块137 passed／55 subtests（49.87秒）；只读复核cleanup修复64 passed、GPIO JSON保存身份2 passed，无新重要问题。该短门禁配置的RVFI／consumption／native IRQ／memory commits／persistent gate／initial RAM／cross-case均关闭，仅source actions开启；其他模式只有闭集与构造软件检查，不声称组合真实运行全覆盖。本节不提升候选为 verified，也不补齐 protocol／coverage_context 和完整功能反馈，D8 保持未勾选。

为实际被候选 adapter 选中的 physical→physical 关系补上出口映射：GPIO A低8位→B低8位，以及B脉冲→CPU IRQ。pin8驱动仍通过既有 source ownership 准入；含logical／state端的关系没有被升级为physical候选。显式 CandidateSignal 可以声明真实观察向量的 bit offset／width，同时保留路径要求的子切片；读取时按两个 offset 的差取实际值，原始 journal 和 base 引用不改写。未声明观察向量时仍要求原有 exact slice。拒绝半声明、bool／越界／不包含、错误向量 envelope；全向量的 signal_change 若未改变选中位，不制造该子切片的变化 receipt。

两个路径可以显式引用同一 IRQ 物理样本。消费者新增 exact bool `allow_signal_aliases=False`，默认仍拒绝重复 physical key；生产候选 adapter 显式开启，逐个更新各自声明节点。相同 base event 不得建立 source→target 相关，候选上限、session 去重与 epoch 失效仍适用。12项新增检查初始全部缺接口 RED，消费者模块随后52 passed。

native renderer 记录有摘要的 observation mapping，并按实际 plan／已准入 executor 重新派生核对。CPU `irq` 对应 profile 明确的 irq_entry endpoint／role／单bit输入；GPIO `irq` 对应原生 STEP_GPIO 返回的 `interrupt`，要求 profile 明确 observe action 和真实单bit输出。仅此 observe port 投影到中性 `local_observed_ports`，不推断 interrupt-source 功能或认证 IRQ 接受；其他私有 probe 仍原始保留。driver 的 physical exports 和原始值不变，mapping 只声明观察与别名。4项新增真实 renderer／raw引用／重算摘要仍拒绝假alias的检查先 RED 后 GREEN；native模块33 passed。

actual 三组件 factory／Session／decoder 的生产 executor 预检现可通过，测试在 begin 处截停，明确没有RTL；adapter 为 native policy 接受唯一包含节点的真实出口，generic 路径仍 exact 并保留宽度漂移负例。online Ibex builder 在 candidate opt-in 时选 `physical_observations=True`，关闭时不传新参数；enabled selector RED 已修复。复核发现逐例冻结配置未覆盖 profile.cpu irq_entry 与 port_actions，两项 actual profile 漂移 RED 已修复：命令前重新校验 actual native 合同，重复拒绝、恢复可重试、计分状态不变。独立软件复核110 passed，修复后58 passed（14.56秒），无额外RTL。

首轮真实 CLI／RFuzz [资源回执](../../runs/stage2-d8-candidate-native-cli-20261011/resource.json) complete42.44秒、峰值525,651,968 bytes；3/3 complete，candidate novelty1／energy1。它早于最后的逐例 profile 校验修复，保留 [原源码与命令](../../runs/stage2-d8-candidate-native-cli-20261011/source-and-command.json)及完整 live bundle，不重写为当前来源。修复后 r2 新目录运行实际 CLI，并用预定可信 builder 新建 RTL executor、从保存 raw 输入重算 source／weights／候选计分与完整 journal；终态结果另记录。

修复 profile 漂移后的 r2 [资源回执](../../runs/stage2-d8-candidate-native-cli-20261011-r2/resource.json)为 command_failed60.59秒、峰值526,286,848 bytes：CLI 3/3 complete，但 actual fresh factory 在 manifest 配置比对处拒绝；不得记作重放成功。独立监督诊断另建新目录，首轮诊断脚本因 dict 整数 key 格式化失败保留，修正后的 [差异列表](../../runs/stage2-d8-candidate-replay-diagnostic-20261011-r2/differences.json)仅为 checker 的运行游标／历史状态，candidate／decoder／targets／其余 actual manifest相同；资源complete19.48秒。诊断执行实际 warmup，没有候选case或RFuzz客户端。

根因是 checker 身份此前默认序列化所有实例字段。新增显式 `checker_configuration_only=False` 模式，仅 candidate builder 开启；有声明方法的实际 checker 提供稳定构造参数，源码与闭包仍入身份。默认 Ibex/PULP checker 声明 result_address／gpio_settle_ticks，历史观测由 actual bootstrap和case重新执行；无声明方法的自定义 checker保持旧身份回退，不猜哪些字段可忽略。旧默认模式仍保留所有字段。稳定配置与真实warmup重放两项先 RED 后 GREEN，另补 public参数漂移不能藏在cached begin manifest的拒绝；actual manifest仍重新构造，未恢复此前已修复的缓存身份旁路。之后新建 r3 重新实际 CLI／计分重放。

r3 CLI再次3/3 complete，fresh scoring API 已返回 matches且通过其内部逐例／终态／全trace核对；但监督脚本随后直接用 Python equality比较fresh内存容器与JSON解码容器而断言失败，[资源回执](../../runs/stage2-d8-candidate-native-cli-20261011-r3/resource.json)仍为 command_failed63.33秒、峰值528,228,352 bytes，不能计整次脚本门禁通过。新目录r4仅改检查脚本为canonical JSON比对，并先保存fresh状态；生产源码不变，不改写r3失败记录。

最终十四模块软件回归 **296 passed、1 deselected、207 subtests passed（63.35秒）**，排除的是 lint，不算实际门禁。新增24项检查包含显式slice／同源节点alias12项、实际native mapping4项、preflight／builder／profile漂移5项及checker稳定身份／重放3项。独立只读软件分轮110 passed、profile漂移修复58 passed、checker身份修复32 passed／3 subtests。旧 exact slice、宽度／ownership拒绝、cached projector漂移、candidate budget、generic基础事件及CV32构造保持回归通过。

最终实际产物：[r4 summary](../../runs/stage2-d8-candidate-native-cli-20261011-r4/summary.json)、[源码与完整CLI命令](../../runs/stage2-d8-candidate-native-cli-20261011-r4/source-and-command.json)、[监督脚本](../../runs/stage2-d8-candidate-native-cli-20261011-r4/check.py)、[资源回执](../../runs/stage2-d8-candidate-native-cli-20261011-r4/resource.json)、[fresh候选终态](../../runs/stage2-d8-candidate-native-cli-20261011-r4/fresh-candidate-state.json)、[实际report](../../runs/stage2-d8-candidate-native-cli-20261011-r4/live/report.json)。run CLI实际启动RFuzz客户端，三个case全部complete；已有可信Python builder新建CPU／双GPIO RTL进程，从保存raw输入重新选source、重算逐例weights／energy／novelty／分类反馈及终态。完整plan、checker、6,422条事件与trace语义摘要一致，`matches=true`。CPU149tick、GPIO A161tick／B165tick；候选novelty1／energy1，获益例实际非候选新增能量10，其他两例0；不增加verified或prerequisite资格。候选adapter为选中物理对配置6个节点，原始样本／基础事件来自生产Runner journal。

单worker／180秒／动态RSS监督最终 **complete，61.46秒、峰528,175,104 bytes，RSS上限3,588,444,160 bytes**；包含CLI运行、新建RTL warmup与fresh scoring replay。有效搜索0.368秒，不作为长跑吞吐或故障发现质量比较。replay不重启RFuzz客户端。十二当前实现源码SHA、生产identity及其artifact摘要、压缩trace语义／数量、fresh完整候选状态和逐例10%预算已由主代理重新核对。独立只读复核亦通过：production verifier接受13项artifacts、六节点alias／32→8切片、fresh状态及资源均一致，未启动额外RTL。三次前置失败的资源、原脚本和live证据保留，各绑定当时源码；r4未以新SHA修补旧证据。

D8 尚未完整验收。支持组合的端口观察、run／可信scoring replay CLI与物理coverage_context已通过上文新门禁；native bus protocol trace及完整 Stage2 functional反馈仍须补齐，generic协议只有软件门禁。短运行不代替原计划的全部真实组合与长跑门禁。D5／D6、E–I保持原范围。

## 原生 v2 物理观察契约：本轮续接

新增闭集 tuning `raw_tick_stream: [{sampling: pre_post}]`，只声明实际 pre/post 观察，不驱动输入或授予协议、功能、前置状态资格。未声明时 canonical tuning 文档保持旧格式；原生路径拒绝同时声明其他 tuning，避免默默忽略驱动要求。planner 保留实际 source、binding 和 ownership 检查，仅接受原生 OBI1／APB3 协议集合，renderer 仍须通过既有 CPU／GPIO 形状准入。renderer 记录观察契约、实际 physical exports 摘要及 base/raw schema，新增 helper 进入实现源码身份。

实际 Ibex／双 GPIO factory 增加 exact bool `physical_observations=False`；显式开启才构造三份 v2 request、开启 CPU raw drain 并由 Runner 安装基础 projector。默认路径保留 v1。实际 factory 构造检查曾因 planner 只允许 generic register executor 而 RED，已补原生观察计划分支；测试使用真正 planner，不以替换 plan 冒充生产接线。

复核发现两处 P2，均补负例先 RED 后修复：验证失败不得提前缓存 None，重复调用仍须拒绝；是否校验不得由 runtime kind 决定，原生政策／契约被换成 generic 或未知 kind 时必须拒绝，不能关闭 stream 后绕过。CPU／GPIO 四项 kind 篡改负例覆盖重复调用；修复契约后可重新安装 projector。独立软件复核 **36 passed（15.07秒）**，未发现新的重要问题。

首轮真实检查保留在 [原始运行](../../runs/stage2-d8-native-v2-observation-rtl-20261011/summary.json)，资源 complete 32.62秒、峰值471,654,400 bytes；它早于最后的 Runner kind 校验修复，源码 SHA 不改写为当前版本。修复后另建 r2 并由同一 singleworker／动态 RSS／180秒资源监督运行，最终结果见下文。

最终软件门禁：十一模块 **189 passed、1 skipped、1 deselected、138 subtests passed（48.17秒）**；跳过的是旧实际检查，排除的是 lint，不将二者计作 RTL 成功。原生新增29项覆盖 closed tuning、实际 planner／renderer、factory、projector、原始引用及拒绝／重试；其余覆盖旧 CPU／GPIO、generic renderer、CLI／计分重放、候选 executor、CV32 factory 与 base events。

修复后实际产物：[r2 summary](../../runs/stage2-d8-native-v2-observation-rtl-20261011-r2/summary.json)、[检查脚本](../../runs/stage2-d8-native-v2-observation-rtl-20261011-r2/check.py)、[资源回执](../../runs/stage2-d8-native-v2-observation-rtl-20261011-r2/resource.json)。实际 CPU／GPIO A 各两个新进程，6次STEP、第四步后native reset；每份12条raw pre/post，CPU12条base、GPIO64条base，raw／base／identity完整相等。public ticks1..6跨reset连续、epoch0／1，CPU无MMIO acceptance。最终单worker **complete，34.18秒、峰值470,245,376 bytes，RSS上限3,305,086,976 bytes**。六项当前实现源码SHA、保存JSON、raw/base摘要、数量、原始引用、tick／epoch与资源已由主代理重新核对。只读独立复核亦全部通过，另逐条核对phase和epoch；未启动额外RTL。

本检查只将真实 native STEP receipt 的原始 pre/post 样本交给实际基础 normalizer；没有执行生产 ScenarioRunner journal、candidate discovery／scoring 或 RFuzz 客户端，不授予 CPU-IP 整链、L2／L3 或完整 D8 验收。当前 online builder 仍未选择此 factory 开关，物理 node 与出口的 exact port／alias／切片匹配仍待补齐，旧 CLI 开启 candidate exploration 仍拒绝缺契约的组合。

实现：[观察契约](../../src/myfuzz/local_harness/native_physical_observation.py)、[factory](../../src/myfuzz/scenario/ibex_pulp_dual_source.py)、[Runner](../../src/myfuzz/scenario/runner.py)；检查：[29项软件测试](../../tests/local_harness/test_native_physical_observation.py)。此前 CPU raw 出口及构造审计保留为各自冻结源码的历史范围。D8、D5／D6 及 E–I 原未完成门槛不变。

## CPU 原始 STEP 样本出口：最新续接

实际 CPU 驱动已通过 local_driver parser 验证 `STEP_CPU` 的 pre/post physical 样本，但此前仅保留 `last_samples`，没有 Runner 可消费的 drain。新增 exact bool `physical_tick_samples=False`：启用时复制实际 receipt 的样本并换算 lifetime tick，保留原始 physical／backend／clock 数据；不重建主机握手或从 IRQ 行为推导样本。默认关闭返回空 drain、不增加 identity 字段；启用身份明确 `cpu_physical_tick_stream.v1`、capacity256、pre_post。这个接口还没有让 artifact 成为 v2，也没有安装基础 projector。

FIFO 固定256，满时在下一条 CPU command 前拒绝，不淘汰旧样本；深拷贝 receipt／last_samples，drain 一次且与已有 last_samples 隔离。正常新 begin／成功 reset 清空旧未消费样本；拒绝 reset／重复 begin／非法 begin 不得删证据。新增13项软件检查，初始10项缺接口 RED、reset 拒绝保留 RED、复核发现 begin 验证前 clear 的 P2 并补两项 RED，均已修复。最终九模块 **115 passed、1 skipped、31 subtests passed（39.07秒）**；skipped 是未显式启用的旧 real CPU 检查。本轮另行执行下面的监督实际检查，不能把 skipped 算作实际证明。只读软件复验 **22 passed、1 skipped**，begin／reset 拒绝丢样本缺口已解决。

实际产物：[监督检查目录](../../runs/stage2-d8-cpu-raw-ticks-rtl-20261011-r2/summary.json)、[检查脚本](../../runs/stage2-d8-cpu-raw-ticks-rtl-20261011-r2/check.py)、[资源回执](../../runs/stage2-d8-cpu-raw-ticks-rtl-20261011-r2/resource.json)。从实际 factory 的 CPU artifact 和 Router 构造新的 `GeneratedCve2Session`，两个独立 RTL 进程各执行8步、同一 native reset、3步；只跑 NOP／loop，不发生 MMIO acceptance。每步 drain 一条，11条 raw pre/post 样本逐项一致，reset 后 public ticks9..11连续。source SHA、sample SHA、stream identity、两份保存 JSON 与资源回执已独立重新核对。单worker锁／动态RSS上限／180秒监督 **complete，24.82秒、峰值469,245,952 bytes**。不执行候选 discovery／scoring／RFuzz 客户端，不授 GPIO／v2 projector／CPU-IP整链或完整 D8验收。

首轮 [失败目录](../../runs/stage2-d8-cpu-raw-ticks-rtl-20261011/resource.json)保留：脚本构造空 Router 不符合已有接口，CPU begin 前 command_failed（8.77秒）。修正后使用 actual factory Router；未覆盖或改写失败脚本／资源记录。

实现：[CPU raw drain](../../src/myfuzz/local_harness/cpu_session.py)。检查：[raw stream 软件门禁](../../tests/local_harness/test_cpu_physical_tick_stream.py)。下一步仍为实际 raw观察／v2声明、physical port／alias／切片映射、factory／CLI／可信 scoring replay 接线，然后完整资源监督DUT门禁；上述 raw 出口是必要基础，不缩减 D8 原验收范围。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/local_harness/test_cpu_physical_tick_stream.py \
  tests/local_harness/test_cpu_session.py \
  tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py \
  tests/local_harness/test_cpu_memory_commit_optin.py \
  tests/scenario/test_online_reset_replay.py \
  tests/integration/test_candidate_exploration_cli.py \
  tests/integration/test_candidate_exploration_replay.py \
  tests/integration/test_scenario_candidate_exploration.py --tb=short
```

## Run CLI 与组合预启动检查：最新续接

此前构造审计已定位实际缺口，产物：[观察审计](../../runs/stage2-d8-observation-audit-20261011/audit.json)。当时用实际 factory 渲染三个组件但未启动进程：全部 request 为 `local_harness.v1`，没有基础／raw observation schema，base normalizer 全不可用；两 GPIO 有 `drain_tick_samples`，CPU 当时没有。八个声明物理节点的 exact export match 全为0。审计冻结六项相关源码 SHA 并核对，范围仅 construction，不证明真实采样／DUT 行为。现 CPU drain 基础接口已补，但 factory 默认不采集、v2和精确切片仍未完成；旧审计保持当时快照，不改写为当前验收。下一步须明确实际 physical port／alias 与切片声明、补原始观察和 v2 projector 接口；只放宽 kind 白名单或改 schema 标签不能满足门禁。

`scripts/run_ibex_pulp_online.py run` 新增 `--candidate-exploration` 和 `--candidate-exploration-max-cases`（1..65536，默认65536）。默认关闭时不传新的 builder kwargs；参数容量不合法在 runtime 构造前返回错误。Ibex 与共享双源 builder 接收 exact bool／exact int，类型／容量异常在 factory 渲染／调用前拒绝；不增加隐藏环境默认。

共享 builder 启用时，先配置 actual Session runtime paths，再在 `Session.begin()`／初始 RAM 变异／bootstrap 前构造无 evidence 输出的候选 executor 做实际预检。这个对象不执行任何 case，其计分状态丢弃；warmup 完成后另建返回的 production executor，消费实际 bootstrap 后缀但不计 case 能量。关闭时仍按此前顺序在 warmup 后构造 executor。候选路径／projector 不支持须在 begin 前拒绝，不能先跑旧 harness 再报告不支持。

实际渲染的 Ibex／双 PULP GPIO 旧组合已检查：开启后明确因基础观察契约缺口拒绝，`begin()` 未调用，三个 session 的 `_process` 均为 null，evidence 目录未创建。此为真实 artifact 的构造检查，没有启动 Verilator／RTL。当前 shipped 组合仍不具备匹配的 v2 观察契约；CLI 参数接入不能代替升级组合并成功执行。共享 builder 启用正向顺序由 mocked assembly 检查，已有生产 PhysicalSession 门禁单独证明预算接线；两者不合并声称实际 CLI DUT 成功。

新增10项 CLI／assembly 检查：先观察7项缺开关／缺参数 RED；另补 warmup 后返回 executor 构造失败的 cleanup RED，已把 `begin`、warmup、最终构造纳入同一异常清理范围，finish 不掩盖原错误。最终十一模块 **192 passed、76 subtests passed（27.01秒）**，含 fresh replay、两 CPU 构造、初始 RAM、IP cross-case 以及默认 trusted-memory CLI 兼容。只读独立三模块 **38 passed（5.26秒）**，无重要残留；`git diff --check` 通过，没有新 RTL／实际 RFuzz 客户端。

实现：[run CLI](../../scripts/run_ibex_pulp_online.py)、[共享／Ibex builder](../../src/myfuzz/integration/ibex_pulp_online.py)。检查：[CLI 与预启动软件门禁](../../tests/integration/test_candidate_exploration_cli.py)。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/integration/test_candidate_exploration_cli.py \
  tests/integration/test_candidate_exploration_replay.py \
  tests/integration/test_scenario_candidate_exploration.py \
  tests/scenario/test_persistent_memory_cli.py \
  tests/integration/test_cv32e40p_pulp_online_factory.py \
  tests/scenario/test_initial_ram_data_operator.py \
  tests/scenario/test_ip_cross_case_advance.py \
  tests/integration/test_scenario_online_credit.py \
  tests/integration/test_rfuzz_runtime_path_preflight.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/integration/test_online_run_identity.py --tb=short
```

## Fresh 候选计分重放：本轮续接

新增 `replay_candidate_exploration_files(output_dir, executor_factory=...)`。调用方提供可信的新装配，包括 actual Session／Runner、decoder、checker、bootstrap 与搜索开关；保存文件中的 source、weights、discovery／budget 状态只能用来比对，不能作为运行配置或恢复授权。入口先验证生产 run identity、源码及 artifact 摘要，再检查每条 raw records 的格式／SHA、receipt 容量、buffer／slot 唯一性与顺序、reset 时间线。无效 raw 或配置类型在 factory 创建前拒绝；factory 自身可能执行合法 bootstrap，配置不符的返回对象在首个 case 前拒绝并清理。

actual executor 必须没有已处理 case／receipt／decision、收益、选择使用计数或候选计分。其候选配置、decoder document、targets、decoder checker，以及用当前 `session.runner`／当前 `session.checker`／当前 runtime paths 重新生成的 Session manifest，须与已验证保存身份匹配。只读复核复现 cached begin manifest 掩盖后改 Session checker 的 P2；正式负例先 RED，现改为重算 actual manifest，漂移在 local tick=0 时拒绝。两项保存开关 False→0 的 RED 也已修复，避免 Python bool/int 等价绕过配置检查。匹配的非空 Session checker 正例实际重算相同 violation。

通过预检后，新 executor 逐 buffer 执行 raw 输入。每条实际 receipt 的 source／path／candidate 选择、online weights、coverage／status／violations、interaction 分类反馈和候选 novelty／energy／非候选新增能量，均与保存值逐项 canonical 比对。终态 discovery／base／budget 状态完整比对，重新生成的 plan 字节和完整事件、semantic／manifest 摘要也须一致；host timing 不参与判定。这里没有重启 RFuzz 客户端，也不声称重现客户端自身的生成策略。

warm／cold reset 检查首先暴露生产 executor 遗漏例间 reset barrier，下一例报 `online interaction events must be contiguous`。现从实际 Runner journal 同步例间后缀，按 barrier 清除未完成的 instruction／pin／pending source 链，保留 session novelty 去重；feedback 初始游标与已开始 Session 的实际 event count 对齐。新增四项默认关闭／启用 × warm／cold 的生产路径检查，确认旧 pending 证据在下一例 submit 前已清除；不靠仅调用清理 helper 的测试。已完成事务的历史计分不因 reset 改写。

新增21项 fresh replay 检查，覆盖新会话正例、重新封装 SHA 后修改逐例 answer／source／weights、report 总数、无效 raw／artifact、容量配置、已用 executor、actual checker、类型替换、普通／压缩 trace、拒绝输入、两类 reset、确定性 physical 失败及 cleanup 不能掩盖原错误。先观察缺入口及 reset 的 RED，再修复上述三项预检 RED。最终十六模块 **284 passed、4 skipped、9 subtests passed（2.57秒）**；四项 skipped 仍需显式启用实际客户端。只读复核发现并复验 P2，最终独立三模块 **69 passed、2 subtests passed（1.74秒）**，无新的重要遗漏。`git diff --check` 通过；全为软件 PhysicalSession／模拟 transport，没有新 RTL／实际 Rust RFuzz 运行。

实现：[fresh scoring replay](../../src/myfuzz/integration/scenario_rfuzz_replay.py)、[executor 例间同步](../../src/myfuzz/integration/scenario_rfuzz.py)。检查：[fresh replay 软件门禁](../../tests/integration/test_candidate_exploration_replay.py)、[默认／启用 reset 门禁](../../tests/integration/test_scenario_candidate_exploration.py)。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/integration/test_candidate_exploration_replay.py \
  tests/integration/test_scenario_candidate_exploration.py \
  tests/integration/test_scenario_online_credit.py \
  tests/integration/test_rfuzz_runtime_path_preflight.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/integration/test_online_run_identity.py \
  tests/integration/test_online_decode_space_identity.py \
  tests/integration/test_scenario_rfuzz_wall_cut_replay.py \
  tests/integration/test_scenario_rfuzz_live_client.py \
  tests/integration/test_scenario_rfuzz_acceptance.py \
  tests/scenario/test_candidate_exploration_budget.py \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_dependency_retransmission.py \
  tests/scenario/test_dependency_lifecycle.py \
  tests/scenario/test_online_reset_replay.py --tb=short
```

## 生产 executor 与保存配置接线

新增默认关闭的 `candidate_exploration=False` 与有界 `candidate_exploration_max_cases=65536`。关闭时不构造消费者、不增加 decision／receipt／report／run_config 的候选字段，旧权重路径保持原公式。启用时从 actual decoder 的 selected runtime paths 与显式 edge contracts 自动构造物理 relation，不接受外部任意 feature→source 标签。`PreparedRuntimePathContract.bind(actual_runner)` 先核对实际 ownership、Binding、Router／window 和声明关系；每个物理节点还须精确匹配 actual v2 projector 的 component／instance／endpoint／role／方向／port／bit range／clock。无可观察关系、无基础事件出口或不匹配的组合在创建 evidence 输出目录前拒绝；接收已开始的 Session 时不声称撤销此前 bootstrap 命令。

新 adapter 从 actual artifact 重建 fresh projector，与已有 cached projector 的静态配置精确比对；每次 source 权重查询／case 前再次检查 topology、source ownership、source 配置以及 artifact／projector 静态配置。已复现并修复缓存 projector 掩盖 runtime export 变化的缺口；cached map 自身变化也在命令前拒绝。case 容量耗尽预命令拒绝，不淘汰旧 budget 状态。bootstrap 与例间非 case 的新 journal 后缀只消费、不计分，逐 case 后缀必须连续。

候选累计增量现直接进入 executor 传给 `decode_candidate` 的权重闭集。两 legal source 的软件门禁找到实际 decoder 的选择边界，同一 raw 输入在候选增量前后选择不同原有 source，随后实际 executor 选择与增量后相同；不是只检查 helper 返回值。每例以固定该例 coverage gaps／use counts 的非候选权重前后差额计算实际正向新增计分，排除已累计 candidate delta；不足10没有候选 energy，至少10且未饱和才加1。novelty 与 energy 分开，候选不增加 closed-loop certificate counts／verified 台账，也不登记 prerequisite。

启用后的 feedback 保存独立 `base_coverage`、`candidate_novelty`、`verified_dependency`、`functional_coverage`。本段早期版本base仅物理切片change，现已由上文新版本加入声明协议base及coverage_context；functional仍仅既有configured legacy CoverageTarget谓词，不能当作L3功能插件验收。未安装闭环认证反馈时verified_dependency为null，不伪报测量零。

live receipt 保存候选 case 记录及上述反馈，report 保存 detached 状态；run_config 固定开关、prepared paths、sources、artifact／projector 映射、发现／预算规则及 bounds、六项 candidate/discovery/base 实现源码摘要和配置 SHA。生产 `_verify_online_run_identity` 核对 report／run_config 的 canonical JSON、分别核对配置摘要与当前源码 closure；复核发现 Python `True == 1` 字典等价会漏掉配置类型变化，四项正式 RED 已修复。此结论仅为保存配置一致性验证，未重新执行候选发现、每例计分或 RFuzz 排序；保存 scoring state 没有导入授权接口。

新增21项 integration 软件检查。先观察12项缺入口 RED，随后缓存／容量／保存字段与四项类型替换 RED，再实现修复；最终十二模块 **220 passed、4 skipped、9 subtests passed（1.49秒）**。四项 skipped 为 `MYFUZZ_SCENARIO_RFUZZ_LIVE=1` 才启用的真实客户端检查，本轮未启用。只读接线复核独立77 passed／1 deselected（排除当时开发中的保存测试），保存身份复核最终48 passed／2 subtests（0.92秒），重要问题已修复；没有新 RTL，也未启动实际 Rust RFuzz 客户端。

实现：[生产 adapter](../../src/myfuzz/integration/candidate_exploration.py)、[executor](../../src/myfuzz/integration/scenario_rfuzz.py)、[live 保存与配置校验](../../src/myfuzz/integration/scenario_rfuzz_live.py)。检查：[生产接线软件门禁](../../tests/integration/test_scenario_candidate_exploration.py)。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/integration/test_scenario_candidate_exploration.py \
  tests/integration/test_scenario_online_credit.py \
  tests/integration/test_rfuzz_runtime_path_preflight.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/integration/test_online_run_identity.py \
  tests/integration/test_scenario_rfuzz_live_client.py \
  tests/integration/test_scenario_rfuzz_acceptance.py \
  tests/scenario/test_candidate_exploration_budget.py \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_dependency_retransmission.py \
  tests/scenario/test_dependency_lifecycle.py --tb=short
```

## 此前独立预算层证据

预算层接收调用方已预检的 legal source 闭集与冻结的 feature→source 数据映射；它不能自行证明 ownership、route 或 protocol 合法，也不能认证任何依赖。配置默认 `enabled=False`，公开 detached 配置及稳定 SHA-256 供后续身份封装，没有保存状态载入／恢复 API。权重查询只对该 legal 闭集追加累计 candidate delta，不能创建新 source 或改变拓扑。

每 case 最多一个 candidate novelty 单位及一个 energy 单位。仅该例实际非候选新增能量至少为 10 时才追加 1；因此 candidate energy 不超过非候选新增能量的 10%，也不超过包含候选后的总新增能量的 10%。更低能量仍可报告一单位 novelty，但 energy 为 0；目标权重饱和时不虚报无法应用的能量。`weights` 必须是不含此预算层 candidate delta 的基线，不能把全部历史权重或候选数量用作该例非候选新增能量。

所有已观察 feature 在 session 内永久去重，包括同一例超出一单位上限而未得分的 feature；过期／淘汰不能重复获益。feature 闭集最多 65,536 项、legal source 最多 4,096 项；case 缓存最多 65,536，容量耗尽拒绝而不淘汰旧去重状态。每 case 的 feature 集合、非候选新增能量和基线权重进入摘要；相同 ID／相同摘要返回 detached 原答案，改变内容拒绝。无效输入不花费 novelty 或占用 case 身份。答案明确 `legal_source_exploration_only` 与 `grants_prerequisites=False`，不增加 verified counts。

新增 22 项定向检查：默认关闭、每例多 feature 上限、六档能量边界、session 去重、未获益 feature 消耗、case 幂等及改内容拒绝、未知 feature／非法 source、饱和、容量拒绝、配置身份和类型／范围拒绝。初始 15 项观察到 RED（模块未实现），再实现预算；最新五模块最终回归 121 passed（0.40 秒）。只读复核独立三模块 82 passed（0.15 秒）、未发现重要逻辑或去重问题；该复核覆盖最初 15 项预算检查及既有发现／分类消费者，新增 7 项输入边界由最终回归验证。git diff --check 通过，未启动新 RTL。

实现：[预算层](../../src/myfuzz/scenario/candidate_exploration.py)。检查：[预算测试](../../tests/scenario/test_candidate_exploration_budget.py)。

```bash
PYTHONPATH=.:src python3 -m pytest -q \
  tests/scenario/test_candidate_exploration_budget.py \
  tests/scenario/test_dependency_candidates.py \
  tests/scenario/test_dependency_evidence.py \
  tests/scenario/test_dependency_retransmission.py \
  tests/scenario/test_dependency_lifecycle.py --tb=short
```

完整 D8 仍须完成以下工作；已完成的物理接线范围不能代替缺失门禁：

1. generic协议base与coverage_context软件接线已完成，真实物理context通过；仍须native总线协议观察，以及完整Stage2 producer／functional consumer契约与反馈，不能以候选替代认证。
2. 通用fresh API及可信CLI配置／逐例计分／选择／terminal已通过当前native组合真实门禁；reset／拒绝时间线仍以软件范围为准，受资源限制失败边界及其他组合仍须验证。配置 verifier 不替代实际逐例重算。
3. run CLI 与新的 `replay-candidates` 均已接实际Ibex／双GPIO，并完成上述短门禁；旧 `replay --plan --trace` 仍只验Session execution。其他组合的真实验收和完整功能反馈保持原门槛。
4. 统一 singleworker／RSS 下的实际Ibex／双GPIO native CLI／RFuzz三例与fresh scoring replay已通过；这项短门禁不代替完整协议／功能反馈、其余组合和长跑验收，软件 PhysicalSession／模拟 transport仍不能作为DUT／客户端证据。
5. D5／D6、E–I 未完成项保留原范围，D8 继续未勾选。


2026-10-12最终独立产物复核：[审计记录](../../runs/stage2-d8-independent-feedback-cli-20261011/independent-audit.json)逐例重新消费actual base事件并核对全部snapshots，校验native APB raw pre refs、当前源码及缓存输入；不恢复保存证据、不重跑RTL，可信fresh比较由本轮已冻结生产replay强制执行。联合九模块227 passed（93.18秒）；本轮没有未解决阻断。下一步生产寄存器adapter／能力证据接线与可选功能provider，D8、E1／E2、D5／D6及E–I保持未完成。

2026-10-12最终文档链接检查：617文件／1598链接，83条原有历史断链，本轮新增0。
