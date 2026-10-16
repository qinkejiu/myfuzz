# Alias 软件证据 fixture：实际对象与私有来源链

本报告最初在 actual gate v2 执行期间编写；这里的 gate v2 是执行目录版本，不是 sidecar schema。当前工作仅准备下一 alias 包，不 render新factory，不修改生产、sidecar或门禁 pins。软件transport产生模拟APB样本，能测试真实parser/CPU/router/private authority接线，不能证明真实RTL alias效果；真实RTL需后续独立门禁。

## 可复用实际接口

`test_register_program_replay.actual_factory` 已构造实际 native GPIO/CPU、DataflowRouter、MemoryService/TransactionLedger 与 commit authority，软件替换仅 begin/step/transport。`test_ordinary_apb_access_session.observed_factory` 示范 actual `cpu._serve('data',...)`、observer.preflight_access、actual router.drain_one、actual Runner receipt/raw drain/finalize；`test_register_program_verifier.read_result_factory` 示范 `_pending_data`消耗后实际RAM `_serve`与 `_append_external_events` 的 preack verifier token消费。

当前 `write_readback_factory` 在同一submit内发 WRITE+laterREAD，适用于当前 plainwrite证据，但不能完整代替 three selected requests alias方案。`software_transport`每command使用真实 `parse_driver_receipt`，更新 sequence/tickspan，产生 setup/access/idle pre/postactualpayload。新fixture应从它的builder模式派生为一个每target独立的 persistent transport闭包，rdata动态取fixture PADOUTstate；一次install固定execution，后续不得每访问重置sequence/case/execution。仅模拟transport状态，不把这个dict注册成生产authority。

## 精确三请求 fixture

before begin 建立实际Session与slot声明→ordinary collector→actualRuntime（显式sidecar路径）→verifier（Sessionhook或实际directAPI），然后软件begin仍发真实instr waiting `_serve`。按每次当前 `runtime._active_submission=(actualcase,manifest)` 的原request执行对应CPU访问，禁止固定helper预制caller TransactionKey或替换completed callback。

第一例是 selected PADOUT.value READ：`cpu._serve('data',0,window.base+0x0c,0,15)` 创建实际data key、request evidence及真正CPU completed闭包。actual observer preflight、router.drain_one后按现fixture顺序flush cpu接受/交付、target ordinary receipt、ticks/raw/base/checker，再 finalize。必须在下一次CPU `_serve`前保存sealed CPU pending response；collector读取pending在其finalize期间，不得提前清None。此后模拟CPU消耗pending、真实 `_serve('data',1,result_address,returned_raw,15)` 进入actual RAM MemoryService，并 `_append_external_events('cpu',round)`，使 verifier 在 actual issue token producer ack 前 resolve一次。result值从实际pendingresponse读取，不从expected/table直接生成RAM结果。

第二例 selected PADOUTSET.bits WRITE：actual CPU `_serve`地址base+0x10，fullword mask，explicitallow_side_effect=True；动态transport模拟 state |= pwdata，其实际driver rdata通常0，真实completed写响应仍需confirmation。flush/finalize之后消耗pending写响应，不产生read-resultRAM证据。CLR相同但offset0x14/state&=~pwdata。callbackfailed例应保留真实completed闭包、令真正CPU counter更新TypeError，不能换noopcallback。

第三例 selected PADOUT.value READ：重复第一段到独立resultspan。期望五个递增actualdata来源序号为 MMIOread→RAMstore→aliaswrite→MMIOread→RAMstore；实际数值必须取 `_serve`生成key，不手填。所有sourcekey execution/testcase/component/sourceepoch沿同一actualCPU域，datachannel，scope目标epoch/generation取actual对象。source Session requestcase label不同于CPU `_case_id`，不得相等绑定。确认三条MMIO completed accesses 严格ordinal前读<alias写<后读，各自raw/base/ref和private commanddigest源一致；两个RAMcommit只由READ active submission消费，并 fullkey.sequence大于相应MMIOread。

多case还必须推进实际instr waiting/address：参考现software CPU fixture，将已填sourcefragment逐word通过实际 `_serve('instr',0,word,0,15)` / memory冻结snapshot消费，再在fragment后下一slot真实 `_serve`建立waiting。不能写造假的 `_waiting_instr` tuple 或反复使用同一个指令地址。此fixture仅软件模拟CPU请求序列，无真实retire证明；真实verifier来源要求依然是既有 actual request/admission/manifest 与完整actual链。

## source-bound temporary sidecar

copy完整当前72字段文档到tmp路径，仅在计划明确的新sidecar schema被parser支持后加入关系声明；当前 v1/v2 register_semantics closedkeys 只允许已有字段与reset_value，不能现在偷偷加入alias_target，不能删除其余fields以抬aggregate等级。临时文件由 `load_ip_test_capability(...,profile=actualtarget.profile)` 完整validate，profile_fingerprint/component_id保留actual，evidence_ref引用真实sourcepath/revision/SHA；Runtime.sidecars使用实际tmpPath，启动配置按真实文件SHA绑定。

关系声明采用下文固定的 v3 八字段行，不再使用临时 alias_target/relation kind 键。parser先核 source/destination 精确字段、同endpoint、32bit/fullmask、源write-one effect与set_bits/clear_bits一致、目标可读普通字段、地址distinct及source证据；generic renamed profile必须同样可用。声明只令规则eligible，不生成证书；本包不通过硬编码PULP名字或旧effect标签绕过尚未实现的parser。

## meaningful tests 与真实验收边界

软件positive：nonzero baseline，SET多位/CLR多位未触位保持，zero/noop/repeat幂等；原请求READ两条各有实际RAMresult证明，aliasWRITE只有三段readback支持。Snapshot只aliasbits register_write的exactqualified规则，PADOUT READ由各自commit另授；allremaining字段gaps保留。

软件negative：仅afterREAD无beforeREAD；只aliasREAD返回default0；before来自gpio_b；夹PADOUT/SET/CLR写；reset/sourceepoch/generation界面；returnedCPU/APB mismatch；private sampledigest/rdata错；RAMstore发生在beforeREAD之前/foreignCPUcase/错误seq/错误resultspan；真实callback失败；新sidecarfilepath内容漂移；savedconsistentrehash后只能比较不能ingest证书。后续RMW前读可当支持READ，但不能投影成独立selectedread。

先运行现实际parser/privateauthority软件fixture，随后新的独立frozenactualnative gate执行同三原请求和fullfreshCLI，认证实际source/provider/transport→raw/base→CPU response→actualRAMcommit；软件模拟PADOUTstate的值正确不算RTL storage已认证。history保留完成interval，reset/uncertain/incomplete清current资格；所有storage/version_dependency/prerequisites/functional grants仍False，不自动wholeL2。

## Task1 loader TDD 准备：v3 与当前包冻结

现有 `ip_test_capability.v2` 已要求 feature_contract，不可将 alias 扩展塞进旧v2或改变其根字段约束。下一包选 `ip_test_capability.v3`：required v1根字段加 register_aliases，optional feature_contract；present沿用旧严格feature解析，absent保持None。闭集关系行为是 set_bits/clear_bits，计算分别OR/AND_NOT；关系行字段为 source_register/source_field/destination_register/destination_field/endpoint_id/operation/bus_width/evidence_ref。v1/v2 typed对象将增加emptytuple register_aliases，但保留其normalized source_document与fingerprint原值。

新增唯一测试文件 `tests/composition/test_register_alias_capability.py`（SHA `027e8977e0021734716ac7054ed8aae8a52e4ed8af3584b60a8c8b78ad0366d7`）使用当前实际完整72fields sidecarclone及generic renamed profile，无renderer/factory/RTL。测试实际RED为33 failed、2 passed（0.23s、pytest exit1）：两项正例都因为unsupported v3失败；旧v1/v2 emptytuple接口尚缺；所有alias负例要求alias专属错误，unsupported schema不会冒GREEN。两项已有GREEN仅证明v1/v2继续拒绝register_aliases根扩展。另含v3 feature兼容与empty关系不授verified、unknown/foreign/width/access/effects/masks/duplicate/self/sourceevidence drift等闭集边界。

这是下一包尚未实现/尚未通过的TDD准备，不属于本轮live gate的通过证据。当前 production/config/gate pins全部不改；Root等待本轮actual/fresh终态后实现parser。primary alias implementation plan由Root维护，不与本报告并写。


## 下一 pure certificate 与实际链测试设计（尚未实现）

纯规则层只计算已认证三段输入的关系：set_bits要求 after == (before | written) & 0xffffffff；clear_bits要求 after == before & (~written & 0xffffffff)。参数包含精确source/destination字段、端点、实例、bus width、mask与source-bound声明引用。数值必须exact uint32，bool/float/子类拒绝；unknown row keys/operation、重复refs、乱序ordinal、跨source testcase/epoch/target epoch/memory generation拒绝。纯函数只能返回关系判定/闭集证书shape，不能把caller JSON或saved一致rehash升级成VerifiedCapabilitySnapshot。生产授证入口仍由actual verifier读取私有sealed accesses和issued commit。

建议分成两个新测试文件，待parser GREEN后实施。`test_register_alias_certificate.py`覆盖set/clear非零基线、多位、zero、重复幂等，以及未触位损坏（例如SET只检查written位仍应拒）。Generic renamed fixture与PULP fixture共用规则；外来profile/sidecar/source证据、别名目标自身为alias/read-clear、宽度mask漂移均拒。测试证书只投影source alias的register_write；支持前后读不会自动投影成其他selected operation。

`test_register_alias_verifier.py`复用上述actual三请求fixture，测试private completed ordinal和两次RAM issue链：两个READ各自必须先真实CPU/APB一致，后真实RAM STORE同CPU execution/testcase/component/sourceepoch/datachannel且seq递增。真实RAM值从pending读取，不能从模拟state直接写；before/after请求跨实例、夹任意destination普通写或其全部alias写、reset、callbackfailure、只有before或after、STORE提前/foreigncase均不授alias证书。支持RMW前读的测试单列为support-only，不冒充独立READ请求。所有stream accesses都参与干扰判断，不能只扫描selected manifests。

成功interval后普通新写保留historical行为资格；reset/uncertain/collector incomplete清current，history仍保留且grants_storage/version_dependency/prerequisites/functional=False。软件transport可证明实现消费实际私有链，不证明模拟state对应真实RTL；后续actual native gate必须重复同三段原请求并freshCLI重新计算，不能从保存证书安装authority。

2026-10-12再次运行Task1同一命令：33 failed、2 passed in 0.23s（exit1），测试文件SHA不变。下一两个测试文件此处只有设计，未创建、未运行；Task1仍未完成。

## Task4 接口与非空回放 fixture 准备（只读设计；尚未实现）

当前 integration 已有 `make_register_assembly`、`make_register_runtime_factory`、`save_ibex_pulp_register_bundle` 和 `replay_ibex_pulp_register_files`。verifier opt-in 依赖 ordinary 通道，安装顺序保持 ordinary→actual runtime→optional capability→verifier→begin。现有完整 verifier wrapper 与纯闭集 validator 应承载新 alias rule；无需新增 PULP 名称特判、assembly 权限开关或 CLI 授级字段。固定 sidecar 路径的当前字节 SHA、typed relationship loader、verifier 与 parser 都必须进入当前 code-owned source closure，历史 sidecar 身份不能证明新增关系。

有效非空 RED 使用现有 actual factory、真实 CPU `_serve` callback、Router 与 strict parsed native software transport：先 READ destination PADOUT 并实际 SW 至安全 RAM；随后 explicitly allowed SET 或 CLR source write；再 READ 同一 destination 至另一安全 RAM 地址。必须保留三个真实 ordinary associations 的 acceptance/delivery/receipt/raw/base refs，两个 private issued RAM commits，并断言新 alias certificate 包含 actual before/write/after 与两个结果证明。当前 unsupported_effect_rule 是行为缺口 RED；不能用空 collector、伪造 journal 或纯 host 算术输出证明接入。该 fixture 是软件传输测试，不将其解释器称作 DUT。

完整 production 正例先通过 Session schema16 导出、认证 writer 保存，再从 trusted closed assembly 和原 requests fresh 重编译并执行，逐 source/field metadata、全 trace semantic/count、ordinary state、verifier wrapper/certificate 比较。saved bytes、regions、关系报告和 certificate 都仅是比较材料，不恢复权限；CLI 继续输出完整 observational wrapper。缺关系必须留下 gap，不能从 source register 名称推断 destination。

闭集负例至少包括 unknown relation keys/effect、foreign endpoint/alias、错误 destination scope、certificate 引用缺失；writer 必须在 mkdir 前拒绝，selector 必须在 factory 前拒绝。对结构合法且 envelope/artifact SHA 一致重算的 relation、certificate 或 RAM value 篡改，必须由当前 source-bound declaration 检查或 fresh 全量比较拒绝，不能把重新散列视为授权。保留 default-off 布局、源码/sidecar SHA drift、schema17 uncertain 保存与 fresh 失败边界回归。本节仅准备接口与测试，未新增生产实现、未执行新 RTL 或授予完整 L2/functional/RFuzz 能力。

### Task4 首次有效 RED（2026-10-12）

真实固定 GPIO sidecar v3 冻结后，`PYTHONPATH=src python3 -m pytest -q tests/integration/test_register_alias_replay.py` 终态 exit1：**2 failed in 66.30s**。SET／CLR 两项均在要求 `ordinary_register_alias_readback.v1` certificate 时失败，实际 gap 为 `unsupported_effect_rule`；此前真实软件 CPU `_serve`／Router／strict parsed target 的3条确认关联及非空 raw/base refs、2条 private RAM commits 已通过。before RAM 为 `0x12345678`，SET `0x80000001` 后实际软件 RAM 为 `0x92345679`；CLR `0x10000008` 后为 `0x02345670`。不是缺 schema 或虚构 journal 的失败。certificate 断言位于 writer／fresh 调用之前，**本次没有执行认证保存或 fresh 回放**；这些步骤仍待 live rule 与纯 saved validator 冻结后验证。

### Task4 待实现的 rehashed 篡改测试设计

复用非空成功 bundle 时，修改 comparison document 并一致重算所有对应 artifact/envelope/report SHA。非法 relation unknown key／effect、foreign endpoint、source/destination row 不闭合、commit 引用不存在等结构应分别由 writer 在 mkdir 前、selector 在 factory 前拒绝；测试以 sentinel factory/mkdir 检查命令边界，不把 rehashed JSON 当运行授权。对结构合法的 `alias_relation` destination/effect 或 certificate `expected_value` 改动，应核当前 v3 source-bound relation与纯关系条件拒绝；若仍为有效 comparison 值，则 fresh 原 requests 实际重编译／执行后完整 wrapper mismatch。RAM 篡改应同时改 certificate result_commit、saved journal commit cells及相关 trace semantic/artifact hashes，分别覆盖私有 issued commit 内容约束与 fresh mismatch，不仅测试陈旧 SHA 拒绝。所有合法 fresh authority 仍来自 actual private对象，不能安装 saved relation/commit/bytes。

需再覆盖 generic renamed register/endpoint 的实际 source-locked provider路径：保留真实 admitted component source identity，改声明与实际 profile register/endpoint 名称，验证相同 generic rule；不能修改 source-lock whitelist或核心加入 PULP 名称映射来制造正例。本节仅测试设计，尚未实现这些篡改或 generic production 回放测试；等待 live＋pure implementation 最终冻结，不重跑移动源码测试。

## Task2 actualprivate 软件执行 checkpoint

新增 `tests/scenario/test_register_alias_verifier.py`：共享 `alias_factory(factory, initial=..., after_override=...)` 复用既有field_factory对actual admitted RV32I words的软件解释器，只将target transport改为每target一次安装的persistent strict `parse_driver_receipt`，实际CPU `_serve`、真实completed闭包、router/collector/sealedaccess与preack私有RAM issuance链不替换。完整三selected请求before READ→alias WRITE→after READ，两个READ结果均从实际pending response经真实RAM STORE提交。模拟PADOUT字典仅transport fixture内部状态，不注册成authority或RTL语义结论。

初两run是setup错误，不是alias RED：absolute临时profile被closed request拒绝（6.77秒）；generic component identity被真实source-lock拒绝（16.25秒）。fixture随后用configs下临时目录的root-relative profile路径并ExitStack全清理；production config未改。实际renamed fixture只改变register/endpoint名字，保留source-locked component_id=pulp_gpio。纯loader的generic_register_device正例不替代完整实际generic component测试；下一步仍需temp source-lock root、真实source bytes及trusted verifier证明新component identity，不绕source-lock。

真正alias-rule RED是73459（35.17秒），完整实际链后仅 `unsupported_effect_rule`、aliascertificate0；runner另有两SET/CLR实际integration RED66.30秒。live规则实现使用单一 `ordinary_register_alias_readback.v1`，loaded v3八字段关系区分set_bits/clear_bits。closed result为alias_relation/before_readback_access/after_readback_access/before_result_commit/after_result_commit/expected_value；READ支持通过其自身successful request/case receipt和私有issued commit查证，aliascertificate的association仅实际alias write，observed_accesses仅该selectedwrite。前读<写<后读，完整CPU域/target epoch/generation/endpoint及全部目标写干扰检查保持。proof_scope仍observed_cpu_register_readback_consistency，四种storage/version_dependency/prerequisites/functional grants=False。

19695先已通过真实certificate/result链，末尾snapshot断言误用不存在的VerifiedOperation.register，属fixture错误；修为实际scope属性。78752七项终态GREEN109.64秒：SET/CLR与renamed names四positive；缺前读、夹普通write、未触位损坏三negative。随后按审读补actual endpoint==origin==request检查，live verifier c180e729c55a16d9c4c28baa78e9258107289203f6fd879e328a6934e703f813停源，7GREEN仅覆盖此前候选，新endpoint条件与pure saved certificate validator待Root同文件分时实现后统一复验。新tests SHA eff7465449404a7d1c0f0385abfb0e828c2655d4a7ba519f1230198b0afba82f；尚未报告alias包save/fresh/native通过或wholeL2。

### Task4 GREEN 与 Task5 脚本准备

最终 live＋pure 候选冻结后，同一 Task4 integration 模块 **2 passed in 171.85s（exit0）**。SET／CLR 均完成真实软件3条非空关联／2条私有RAM证明、新 alias certificate、认证schema16保存及原requests可信fresh执行，ordinary／verifier完整报告一致。每种 bracket 还验证未知关系字段与缺失 afterRAM event：writer 在 mkdir 前拒绝，重新认证plan/envelope的保存文件在 factory 前拒绝。此处不宣称已覆盖结构合法且全部journal/RAM一致篡改的深层 fresh mismatch。

Task5仅准备新 `runs/stage2-e2-register-alias-verifier-20261012-v1/` 中 `supervise.py`、`fresh_cli.py`、`independent_audit.py`；未执行、未复制cache。generation与fresh分别保持singleworker／180秒／原RSS策略，重型JSON审计必须在两个worker终态后串行执行。审计预期12cases（8READ／4alias）、case36APB／8RAM、bootstrap6加case12共18关联／54APB，8READ＋4alias证书及12个唯一case access封存。核对真实before/write/after和两个RAM证明、9认证产物、当前sourceclosure/cache inputs、全部fresh wrappers/preflight与实际trace semantic/count；不固定历史29985事件数。zero/fullmask、observable reset与完整能力scope保留后续要求，不因首轮4brackets缩减验收。本段状态为 prepared_not_executed。

Root pure validator后继候选637f713c…17994冻结后，Task2 tests新增真实before MMIO但停在RAM STORE前（没有issuance token）与真实completed callback计数TypeError边界，均不改私有commit历史或公共journal。48405实跑9PASS/1fixtureFAIL148.02秒：原7（含最终endpoint条件）、missing privateRAM以及callbackfailure保持before READ history/current清空均通过。剩余foreign CPU testcase直接改_case_id后，actual ledger新testcase要求sequence1而旧data counter是4，已在upstream out_of_order_transaction拒绝；最初fixture误期待进入alias-specific gap，不是verifier漏洞。修正为确认实际upstream拒绝、runtime uncertain/current清空/history无alias授证，不手工重置counter/造TransactionKey绕ledger。58072单项纠正后GREEN36.50秒（9deselected），组合本轮实际10项验证范围；不称该例覆盖alias_scope_mismatch的成功输入路径。

实际reset边界需完整软件RESET transport或后续真实Session reset/barrier；不能手改target/source epoch冒实测。完整新component identity的source-lock fixture仍开放。上述软件通过与Root纯保存validator/fresh软件证明不替代后续alias native gate，snapshot仍仅精确scope，未授wholeL2。

## 实际 Session reset 软件生命周期边界

后继verifier0375ed3…0470冻结后，新增 `resettable_alias_factory` 为三个实际GeneratedLocalSession提供临时Python READY/END worker：真实begin_case严格parse_driver_ready，真实reset_local/end_case/end_local_process终止并reap旧Popen、由基类代码更新epoch、真实begin_case启动新Popen；不替换reset_local，不手改epoch/counter。ACCESS仍使用上述strictparsed软件transport。真实Session.reset驱动Runner原warm/cold memory policy、commandepoch及reset_barrier，reset后真实CPU `_serve`在已声明unused指令槽建立新waiting，再执行aliasWRITE与afterREAD/privateRAM。finally逐真实end_case清理，新旧进程都确认已退出，无孤儿worker。

warm单项59885：1PASS/11deselected35.08秒；cold单项43924：1PASS/11deselected35.68秒。两项均旧3Popen退出、新3Popen不同且live，实际source/target epochs+1；warm memorygeneration不变、cold+1。beforeREAD history保留但旧current清空，跨reset before/write/read不能授aliascertificate，明确alias_scope_mismatch；reset后afterREAD的实际CPU/APB/RAM一致结果可保其新epoch current资格。fixture有意不把模拟GPIO字典当RTL reset默认值或activewriter证明；即使数值表面满足旧OR关系也须epoch隔离拒绝。

测试文件最终SHA d0705d7bdc3583dc643820fcd57a18d23c2cbc3800a7b199208fcf74651b9a4e。未改生产；此前10项scope保留其各自冻结source证据，此轮只跑新warm/cold不虚称完整12项单次重跑。真正native reset-default/read-clear/权限硬件观察与完整genericcomponent source-lock fixture仍属于原计划待完成范围。

### Task5 当前执行状态（2026-10-12）

Root-owned generation74397已启动于新的alias v1目录，空新cache／singleworker／180秒／原RSS策略；尚无终态，不宣称native通过。源码与三个准备脚本以及Root check冻结至generation／fresh／最终audit终态。JSON大型审计不与worker并发，待资源释放后执行。最终verifier `0375ed3…0470` 下Task4软件保存／fresh重新验证2 passed／165.70秒，历史171.85秒仅证明此前候选。完整Stage2与zero/fullmask及actual reset等后续范围继续未完成。


Task5状态更新：generation74397 exit0／complete，164.01385019000736秒、峰2,355,449,856 bytes／limit3,176,628,224／workers1；12cases／18确认关联／8RAM／25,237events与4alias＋8READ证书、gaps=[]。fresh11283已终态exit0／complete，153.30511558598664秒／峰2,359,955,456 bytes／limit3,156,848,640／workers1；完整fresh比对通过。独立audit已终态exit0／PASS：283pins／9产物／12exact／25,237events／12封存access／8READ＋4alias／18关联／8RAM／54APB及完整resources/phases/planSHA/journal/fresh核对通过。四括号scope已审计，完整Stage2保持未完成。源码与脚本继续冻结。

### 下一次 zero／fullmask native 四括号准备（仅只读设计）

在当前scope审计完成后，可另建新目录、独立预算运行四个完整 bracket：SET `0x00000000`、CLR `0x00000000`、SET `0xffffffff`、CLR `0xffffffff`。每个仍为原request READ PADOUT→实际安全RAM、explicitly allowed alias full32 WRITE、READ PADOUT→另一安全RAM；共12cases／8READ／4alias／8RAM，case12关联／36APB，固定bootstrap6关联／18APB时总18关联／54APB。zero两项以实际before值证明完全不变；full SET以实际before及actualwrite证明32bits全1，full CLR证明32bits全0，不能裁成旧低8／高位“安全mask”而声称fullmask。每个规则仍须完整private before/write/after sealing与两RAM证明，保存及production fresh全state／semantic相等。

fullmask须在专用directed运行中评估实际连线／GPIO输出传播／CPU IRQ状态，不复用旧RFuzz source PADOUT消费契约来扩大其权限。若当前bootstrap使fullword输出影响CPU运行或后续waiting，应先以actualfactory原连线和声明明确选择可隔离实例／独立Session，而不是host强制GPIO值、BFM或忽略失败。选哪个target和是否每个fullmask独立Session须由实际route／IRQ观察与同profile两个实例身份核实；结果按每Session真实bootstrap计数，不能继续硬称总18。当前12case成功仅覆盖非zero／非fullmask，不能预授这些新输入。

该四括号之后仍需原计划observable reset（实际RESET命令前后epoch/command/sample变化及真实CPU读回）、权限／width／mask和全部已支持effect矩阵；zero/fullmask运行不能代替它们。当前目录／source／script冻结不改，本节没有执行任何新worker或声称新门禁通过。


Mask实际门禁状态更新：Root generation50928正在新mask v1目录运行，尚未终态；预计14cases／20关联／9RAM／60APB不作通过声明。实际B.INTEN写读0与pending pulse drain隔离在四zero/fullmask括号之前。源码verifier037及四脚本冻结，预算不变；仅经binary SHA核对的3个旧已审计build cache复制到独立新cache，production完整currentinputs检查仍执行，不恢复saved authority。旧alias v1 audit通过与此新执行保持区分；等待worker终态后串行审计，actualreset等完整范围仍继续。


Mask generation50928现已exit0／complete（152.13179933300125秒，peak2,590,924,800／limit3,251,445,760，workers1）：实际14cases／20关联／9RAM／28,995events，14证书（4alias／9READ／1plain）且gaps=[]，B.INTEN隔离后13条native IRQ quiet snapshots为0，zero不变/full SETffffffff/full CLR0。fresh85373已exit0／complete（166.55756382399704秒，peak2,641,014,784／limit3,242,532,864，workers1），完整fresh比对通过。最终audit已PASS：283pins／9产物／14exact／28,995events／20关联／60APB／9RAM／14封存access／14证书、13 IRQ quiet snapshots及CPU／B各1,152raw零值、完整fresh／resources／current3cache／source一致。zero/fullmask scope已审计通过；native reset与完整权限矩阵／Stage2仍未完成。


2026-10-12 permission前effect软件矩阵：实际当前factory／Session／CPU waiting／runtime私有对象的14项声明拒绝全部通过（14 passed／22.92秒），命令sequence／ticks／detached journal／gate／RAM与slot／ledger序列前后不变；不是PSLVERR硬件权限错误或完整native矩阵证明。首轮14 failed／20.59秒为fixture deepcopy EventLog底层BufferedRandom失败，未执行任何请求；test-only改为复制事件列表后通过，生产未改。完整Stage2／native reset／全部权限与字段行为仍继续。


2026-10-12 reset-resume有效软件RED：真实GeneratedSession end／begin及READY／END子进程生命周期、实际CPU读取fixed bootstrap words／MMIO与deferred fetch后，Session warm reset成功，所有target epoch实际增加1／CPU waiting清空；随后公共 `advance_after_reset` 缺API产生1 failed／27.53秒。不是伪造PC／waiting／epoch或fixture错误。生产尚未修复；warm／cold＋真实LW／RAMSTORE重执行＋fresh原requests及前effect API guards测试已准备，待新源码冻结后运行。完整Stage2与native observable reset仍未完成。


2026-10-12 recorded post-reset resume计划已review并批准执行：`docs/superpowers/plans/2026-10-12-stage2-recorded-post-reset-resume.md`，Task1 Session与Task2 integration schema接线并行实施；两个实际RED已终态，尚待GREEN。没有新增assemblyflag，未使用resume时旧schema16／17布局保留；实际warm／cold与认证saved-file fresh软件测试已准备，待双方源码冻结后运行，不预授native reset通过。


2026-10-12 recorded reset-resume候选软件检查点：Session `d743b4b2…0af348a`／integration `bfbb72…9510bf` 下实际warm／cold Session两项＋认证saved-file fresh两项联合4 passed／308.04秒（exit0）。真实GeneratedSession READY／END进程生命周期与reset_local、CPU读取bootstrap及warm驻留LW／RAMSW重执行、实际waiting／epoch与原requests fresh全wrapper匹配均通过，生产未改。该结果只证明d743候选，不证明随后serializer／checker pin修复；已确认的dynamic serializer覆盖缺口仍有独立RED。schema19实际registration／appendedsubmission terminal两项已准备未运行，旧16／17与legacy回归亦待新源码冻结；不得宣称最终软件包或native reset验收完成。


2026-10-12 recorded reset-resume最终软件检查点：Session `f7da03f4…c4bafa0`／integration `bfbb72…9510bf` 冻结后，实际schema19两terminal phases（真实warm reset／bootstrap resume后registration未追加case、session_submission已追加case，原requests自然同故障fresh）2 passed／135.56秒；实际warm／cold Session两项＋认证saved-file fresh两项4 passed／320.83秒，均exit0、没有fixture或生产修复。两次独立终态共6项实际软件测试，不合并耗时，d743候选4项308.04秒保留历史不能代表最后pin修复。旧16／17／legacy四模块回归由Root负责，未重复运行；本轮仍不是native reset门禁，完整Stage2与实际reset／权限／字段矩阵保持未完成。


2026-10-12 recorded post-reset resume Task1／2 scoped软件包已通过：最终Session f7da03f4…c4bafa0、integration bfbb72…9510bf下实际schema19 terminal2 passed／135.56秒，schema18 warm／cold与认证file fresh4 passed／320.83秒；Root旧16／17／online reset／final export兼容四模块59 passed／300.98秒，独立34项通过。native warm generation1400已终态exit0／PASS：144.04320875299163秒，峰1,112,051,712 bytes低于3,103,797,248限额，available5,251,280,896、workers1／dutFindingFalse。实际2requests／9,391events／15关联／3条全部RAM（selected2）／6selectedAPB，initial159steps／resume183steps；semantic SHA `b90e6895f2f036ec03cde3a059231a94c72b1b21a79270dbfa410b86beb0b5b2`、identity SHA `afec5d21838c2756f2aceccb415b56f096eaad886ca12413494582bbd74a9766`，见[warm实际摘要](../../runs/stage2-e2-register-reset-resume-warm-20261012-v1/summary.json)。warm fresh64505已终态exit0／complete：126.435815431003秒、峰1,040,527,360 bytes低于3,105,226,752限额，available5,252,710,400／workers1／dutFalse；完整matches／9,391events／semantic／ordinary／verifier／preflight逐项一致。warm完整audit尚待worker释放，不预授最终验收。cold generation45096已终态exit0／complete：136.89256155700423秒，峰1,119,137,792 bytes低于3,142,094,848限额，available5,289,578,496／worker1／dutFalse；实际2READ／9,114events／14关联／2条全部RAM（selected2）／6selectedAPB，initial159／resume159steps。semantic SHA `34f235e3c711c79ae54378af886baa130e1c613821edd77f9e4062ba716a3b1e`、identity SHA `7de9ff4b411fe6a0bf78ae2d671c657a9b9f99135e6db91f8bfc92afaf99c68f`，见[cold实际摘要](../../runs/stage2-e2-register-reset-resume-cold-20261012-v1/summary.json)。cold fresh14369已终态exit0／complete：118.051542753994秒，峰1,041,219,584 bytes低于3,134,656,512限额，available5,282,140,160／workers1／DUTFalse；完整matches／9,114events／semantic／ordinary／verifier／preflight相等。warm／cold全部4次native generation／fresh均complete、各独立180秒预算；两门禁完整独立audit已终态PASS：warm282 currentpins／9产物／2exact重编译／9,391events／15关联／45APB／3RAM（selected2）／183resume，historical2／current1证书；cold同282pins／9产物／2exact，9,114events／14关联／42APB／2RAM／159resume。全部IRQ projections／plan SHA／journal／fresh wrappers／resources逐项核对、各阶段≤180秒；3个native build currentbinary及282／351／282输入核对通过。见[warm审计](../../runs/stage2-e2-register-reset-resume-warm-20261012-v1/independent-audit.json)、[cold审计](../../runs/stage2-e2-register-reset-resume-cold-20261012-v1/independent-audit.json)及[独立报告](stage2-e2-native-reset-resume-independent-audit-20261012.md)。recorded reset-resume scoped软件／native／fresh／fullaudit包已闭合；历史门禁pins保留f7da／bfbb，不改旧身份。源码冻结释放不表示整体完成：D5／D6／D8、完整E1／E2及E3–I、native瞬时reset defaults及全字段权限矩阵仍OPEN。f7da／bfbb源码冻结，没有竞争native或重型审计。见[warm准备](../../runs/stage2-e2-register-reset-resume-warm-20261012-v1/preparation.json)及[cold准备](../../runs/stage2-e2-register-reset-resume-cold-20261012-v1/preparation.json)，prepared source／script SHA逐项已核对。scope仅recorded reset-resume read consistency，bootstrap reset后重新配置GPIO，不能据此证明瞬时RTL reset defaults；完整Stage2、native observable reset默认值与权限字段矩阵仍未完成。


2026-10-12 下一phase全窄字段矩阵：64个exact(register,field,lsb,width)已逐项列入[执行inventory](stage2-e2-register-field-matrix-execution-20261012.md)，历史native只覆盖4字段而非整bank；拟16个独立4field chunk，首chunk INTTYPE_LOW.pin0／pin1／pin14／pin15已由Root generation70951实际启动、尚无终态／未通过。额外word GPIOEN／INTEN／PADIN／条件read-clear、访问width／权限与瞬时reset defaults继续单列OPEN；这16chunks不是完整E2验收替代，D5／D6／D8、完整E1／E2及E3–I继续未完成。


2026-10-12 field矩阵下一准备：chunk2 INTTYPE_LOW.pin2／pin3／pin4／pin5新目录已由renderer准备、尚未执行；chunk1状态仍以Root实际监督器终态／fresh／audit逐阶段验收，不因输出文件存在更新全矩阵计数。当前f7da／bfbb／verifier037源码不变，完整Stage2继续。


2026-10-12 首field chunk generation70951已实际exit0／complete：133.03611893299967秒、workers1／DUTFalse，峰2,046,107,648 bytes低于3,134,181,376限额、available5,281,665,024；actual8cases／18,218events／18关联／36selectedAPB／4RAM／8证书（4RMW＋4READ）、gaps=[]。Root fresh65778正在独立180秒预算运行，54allAPB与完整audit待核实；4fields尚未最终验收，不计为整bank或全阶段通过。chunk2仍prepared未执行，f7da／bfbb／verifier037不变。


2026-10-12 首field chunk fresh65778已exit0／PASS：117.5034022149921秒、peak1,849,569,280 bytes低于3,116,818,432限额、available5,264,302,080／worker1／DUTFalse，完整matches18,218events／semantic6150db…bd6／ordinary／verifier／preflight相等。generation与fresh均通过，独立audit正在执行、尚未最终验收。仅INTTYPE_LOW.pin0=1／pin1=2／pin14=3／pin15=1各一次合法RMW＋READ观察，不能宣称每field0..3穷举或fullwidth／reset boundary完成。chunk2尚未执行，完整Stage2仍OPEN。


2026-10-12 首field chunk独立audit55320终态PASS：8exact／9产物／282pins／18关联／54APB／12selectedMMIO／36selectedAPB／4RAM／18,218events，current及historical各8证书／IRQ2,766samples0events／cache282／351／282 currentbinary与全部resources／fresh一致。exact LOW.pin0=1／pin1=2／pin14=3／pin15=1当前合法RMW＋READ valuepoints已验收；见[独立报告](stage2-e2-inttype-low-first-field-independent-audit-20261012.md)。不是全值或整bank通过，原Stage2继续OPEN。next chunk2 LOW.pin2／3／4／5已由Root generation86087实际启动，own empty cache／singleworker180／无重型audit竞争，尚未通过。


2026-10-12 field下一准备：chunk3 LOW.pin6=3／pin7=1／pin8=2／pin9=3 pins6-9新目录由renderer准备，NOTEXECUTED。firstchunk四valuepoints已audit PASS；chunk2 generation86087仍运行，phase到export前但无实际resource终态，不能预授通过。f7da／bfbb／verifier037 source与282current pins一致，完整Stage2不缩减。


2026-10-12 chunk2 generation86087已exit0／complete：132.4123047089961秒，peak2,046,140,416／limit3,134,119,936／available5,281,603,584／worker1／DUTFalse；actual8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]，仅LOW.pin2=2／pin3=3／pin4=1／pin5=2四valuepoints。fresh72553运行中、独立audit待完成，未计最终通过；chunk3准备完整仍未执行，不扩展为整bank／全部值或全阶段通过。


2026-10-12 chunk2 fresh72553已exit0／complete：117.86604998000257秒，peak1,850,150,912 bytes低于3,119,108,096限额、available5,266,591,744／worker1／DUTFalse；matches18,227events／fc2b38…3502 semantic与全部wrappers一致。generation＋fresh均通过，独立fullaudit进行中、四valuepoints尚未最终验收；chunk3仍prepared_not_executed，当前源码不变，不授整bank／全值／完整Stage2。


2026-10-12 chunk2 fullaudit16526已PASS：18,227events／18关联／54APB／8exact／9产物／282pins／4RMW＋4READ／12selectedMMIO／36selectedAPB／4RAM及全部IRQ／cache／fresh／resources一致，见[独立报告](stage2-e2-inttype-low-pins2-5-independent-audit-20261012.md)。前2chunks共8fields指定单valuepoint已验收，非全部值／整bank通过。chunk3 generation18307现实际运行，LOW6=3／7=1／8=2／9=3／own empty cache／singleworker180，尚未通过；其余13chunks提议，源码不变、完整Stage2继续OPEN。


2026-10-12 next chunk4 LOW.pin10=1／pin11=2／pin12=3／pin13=1 pins10-13 v1目录由renderer准备，未执行。chunk3 generation18307仍运行，轻量phase为保存前、282currentpins一致但resource／summary尚无；accepted只为前2chunks8指定valuepoints，不猜终态或授整bank／全部值。


2026-10-12 chunk3 generation18307已exit0／complete：132.3857018879935秒、peak2,046,533,632低于3,117,260,800限额、available5,264,744,448／workers1／DUTFalse，8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]；exact LOW6=3／7=1／8=2／9=3。fresh64101运行中、audit待完成，当前四valuepoints未最终验收；chunk4准备完整NOTEXECUTED，原全scope与源码保持。


2026-10-12 chunk3 fresh64101已终态PASS：118.39475587400375秒、peak1,850,974,208 bytes低于3,117,637,632限额、available5,265,121,280／workers1／DUTFalse，full18,227events／1aef8e…59186 semantic／state／preflight一致。独立audit运行中，LOW6／7／8／9四valuepoints尚未最终验收，accepted仍前8points；chunk4prepared未执行，完整scope保持OPEN。


2026-10-12 chunk3 fullaudit55905已终态PASS，exact LOW6=3／7=1／8=2／9=3 current合法valuepoints验收，见[独立报告](stage2-e2-inttype-low-pins6-9-independent-audit-20261012.md)。前3chunks共12points不是0..3穷举或整bank授级。chunk4 generation12344实际运行（LOW10=1／11=2／12=3／13=1，own empty cache／singleworker180），尚未通过；剩余12chunks提议，原scope与当前源码不变。


2026-10-12 nextchunk5 A.INTTYPE_HIGH.pin16=1／pin17=2／pin30=3／pin31=2 HIGH新目录由renderer准备，NOTEXECUTED；pin31=2覆盖bus bit31单valuepoint，旧high16／31历史证据不能替代当前运行。accepted仍12LOW points，chunk4等待Root监督器实际终态；轻量pins282一致，未运行额外任务或授整bank。


2026-10-12 chunk4 generation12344已exit0／complete：132.04403735398955秒、peak2,046,468,096 bytes低于3,120,099,328限额、available5,267,582,976／worker1／DUTFalse；8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]，exactLOW10=1／11=2／12=3／13=1。fresh78630运行中、audit待完成，四valuepoints未最终验收；HIGH新目录准备完毕尚未执行，accepted12LOW points及原全scope不变。


2026-10-12 chunk4 LOW pins10–13 fresh78630已exit0／complete：119.3633515190013秒、peak1,847,529,472 bytes低于3,129,950,208限额、available5,277,433,856，完整fullmatch断言通过。generation与fresh均通过，独立audit刚GO、尚未最终验收；accepted仍12指定points，不能提前记16。chunk5 INTTYPE_HIGH准备未执行，原D5／D6／D8、完整E1／E2及E3–I、全值／权限／width／reset范围保持开放。


2026-10-12 chunk4 fullaudit72392终态PASS，accepted current16个LOW exact单取值points，不是0..3穷举／整bank能力授级。HIGH chunk5 generation95236已实际启动、仍运行未通过，当前源码／脚本SHA／AST／tuple及actual PAD_NUM32 preflight一致；chunk6 HIGH18–21仅prepared未执行。完整Stage2及全值／权限／width／reset边界仍保持开放。


2026-10-12 HIGH首组generation95236已exit0／complete：132.3070836919942秒、available5,243,768,832／peak2,046,111,744低于3,096,285,184限额／worker1／DUTFalse，8cases／18,218events／18关联。Root separatefresh59768已实际运行，尚无最终验收；accepted仍16LOW points，不借历史HIGH证明。chunk7 HIGH22–25 prepared未执行，完整Stage2继续OPEN。


2026-10-12 HIGH首组fresh59768已exit0／complete：116.24226334200648秒、available5,239,918,592／peak1,848,770,560低于3,092,434,944限额／worker1／DUTFalse；完整trace／count／semantic／ordinary／verifier／preflight断言通过。fullaudit已GO但尚未验收，accepted仍16LOW points，不提前计20或授整bank／全部值能力。


2026-10-12 HIGH首组fullaudit45969已终态PASS：18,218events／8current与8historical证书／identity、semantic及完整generation／fresh一致；accepted current20 exactpoints（16LOW＋4HIGH），非全值穷举。chunk6 HIGH18–21 generation50635实际运行、尚未通过，same singleworker180／own empty cache／source冻结；chunk8 HIGH26–29仅prepared未执行。原Stage2所有开放范围不缩减。


2026-10-12 chunk6 HIGH18–21 generation50635已exit0／complete：131.0059881999914秒、available5,244,407,808／peak2,046,242,816低于3,096,924,160限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh69170实际运行、未最终验收，accepted仍20指定points。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15（4bit，offset0x28）prepared未执行，不借旧pin0／7证明当前scope；原Stage2开放。


2026-10-12 chunk6 fresh69170已exit0／complete：117.59755330599728秒、available5,260,267,520／peak1,849,614,336低于3,112,783,872限额／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight通过。独立audit待终态，accepted仍20points；chunk10 PADCFG_0.pin2／3／4／5 values2／6／9／14 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk6 fullaudit45184已终态PASS，exacttuple／18,227events／8证书及完整fresh一致，见[独立报告](stage2-e2-inttype-high-pins18-21-independent-audit-20261012.md)。accepted current24单valuepoints（16LOW＋8HIGH），不是全值穷举。chunk7 HIGH22–25 values3／1／2／3 generation42268实际运行、未通过，own absent cache／singleworker180／无native或audit重叠；原scope继续OPEN。


2026-10-12 chunk7 HIGH22–25 generation42268已exit0／complete：131.44182803299918秒、available5,353,672,704／peak2,046,332,928低于3,206,189,056限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh75326运行中、audit待完成，accepted仍24；chunk12 PADCFG_1.pin10–13 values2／6／9／14 prepared未执行，完整原scope保持OPEN。


2026-10-12 chunk7 fresh75326已exit0／complete：116.5613808670023秒、available5,327,286,272／peak1,849,888,768低于3,179,802,624限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、accepted仍24；chunk13 PADCFG_2.pin16／17／22／23 values1／5／10／15 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk7 fullaudit93696已终态PASS，exacttuple／18,227events／8证书及完整fresh一致；accepted current28 singlepoints（16LOW＋12HIGH），不是全值穷举。chunk8 HIGH26–29 values1／2／3／1 generation70283实际运行、尚未通过，own absent cache／singleworker180／current source-script preflight一致且无overlap；原Stage2仍OPEN。


2026-10-12 chunk8 HIGH26–29 generation70283已exit0／complete：132.64775778599142秒、available5,336,645,632／peak2,046,345,216低于3,189,161,984限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh31823运行中、独立audit待完成，accepted仍28points；chunk15 PADCFG_3.pin24／25／30／31 values1／5／10／15 prepared未执行，原全scope继续OPEN。


2026-10-12 chunk8 fresh31823已exit0／complete：118.06382439300069秒、available5,314,101,248／peak1,851,424,768低于3,166,617,600限额／worker1／DUTFalse，fulltrace／wrappers／semantic／count／preflight通过；独立audit待终态，accepted仍28。chunk16 PADCFG_3.pin26–29 values2／6／9／14 prepared未执行；16chunks均准备不等于已执行或已验收，原Stage2开放。


2026-10-12 chunk8 fullaudit79481已终态PASS：exacttuple／18,227events／8证书与完整fresh一致；accepted current32指定points（16LOW＋16HIGH），每INTTYPE field一个合法value，非穷举／整bank授级。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15 generation38477实际运行、尚未通过，offset0x28／own absent cache／singleworker180／source-script preflight一致且无overlap；原Stage2完整scope保持OPEN。


2026-10-12 chunk9 PADCFG_0首组generation38477已exit0／complete：132.42977688899555秒、available5,366,063,104／peak2,046,464,000低于3,218,579,456限额／worker1／DUTFalse，8cases／18,222events／18关联；fresh60729实际运行、未最终验收，accepted仍32。轻量16组preparation／current source与script SHA／AST／exact field-value tuples核对PASS，完整覆盖32INTTYPE＋32PADCFG无漏重；10–16prepared不等于executed，原scope不缩减。


2026-10-12 chunk9 PADCFG0 fresh60729已exit0／complete：119.73843699799909秒、available5,316,136,960／peak1,851,084,800低于3,168,653,312限额／worker1／DUTFalse，完整trace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍32points、不提前36；nextchunk10 preflight通过仍未执行，16组exact64无漏重核对不替代实际验收。


2026-10-12 chunk9 fullaudit99824终态PASS，exactPADCFG_0.pin0／1／6／7 values1／5／10／15、18,222events／8证书及完整fresh一致，见[独立报告](stage2-e2-padcfg0-first-field-independent-audit-20261012.md)。accepted current36单points（32INTTYPE＋4PADCFG），非全值穷举。chunk10 PADCFG_0.pin2–5 values2／6／9／14 generation48852实际运行、尚未通过，offset0x28／singleworker180／own absent cache／preflight一致且无overlap；原全scope保持OPEN。


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


2026-10-12 chunk13 fullaudit35340终态PASS，exactPADCFG2 pins16／17／22／23 values1／5／10／15／18,222events／8证书及完整fresh一致，见[独立报告](stage2-e2-padcfg2-first-field-independent-audit-20261012.md)。accepted current52单points（32INTTYPE＋20PADCFG），非穷举。chunk14 PADCFG2 pins18–21 values2／6／9／14 generation43790实际运行、未通过，offset0x30／own absent cache／singleworker180／preflight一致无overlap；3word包prepared未执行，原scope开放。


2026-10-12 chunk14 PADCFG2 pins18–21 generation43790已exit0／complete：132.3194965099974秒、available5,438,459,904／peak2,046,128,128低于3,290,976,256限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh11311运行中、audit待完成，accepted仍52；next reset-default只读设计未实现或运行、不预授grant，原fullscope保持OPEN。


2026-10-12 chunk14 fresh11311已exit0／complete：118.92392746800033秒、available5,382,307,840／peak1,849,397,248低于3,234,824,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍52不提前56；chunk15 offset0x34 preflight通过尚未执行，原Stage2完整scope保持OPEN。


2026-10-12 chunk14 fullaudit60628已终态PASS，exactPADCFG2 pins18–21 values2／6／9／14／18,231events／8证书及完整fresh一致，见[独立报告](stage2-e2-padcfg2-pins18-21-independent-audit-20261012.md)。accepted current56单points（32INTTYPE＋24PADCFG），非全值穷举。chunk15 PADCFG3首组pin24／25／30／31 values1／5／10／15 generation62291实际运行、未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；reset-default只读设计不计实现或grant，原scope保持OPEN。


2026-10-12 chunk15 PADCFG3首组generation62291已exit0／complete：134.15973644101177秒、available5,471,129,600／peak2,045,935,616低于3,323,645,952限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh77906运行中、audit待完成，accepted仍56；reset-default独立设计review指出actualcommand全覆盖／未知命令fail closed／完整field-affect／process boundary实施前缺口，只有docs修订，未实现或授grant。


2026-10-12 chunk15 fresh77906已exit0／complete：120.05253920699761秒、available5,461,848,064／peak1,850,097,664低于3,314,364,416限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、accepted仍56不提前60；chunk16 offset0x34 preflight通过未执行。reset-default设计reconciled仅docs、未实现或授grant，原全scope保持OPEN。


2026-10-12 chunk15 fullaudit41628已终态PASS，exactPADCFG3 pins24／25／30／31 values1／5／10／15／18,222events／8证书与完整fresh一致，见[独立报告](stage2-e2-padcfg3-first-field-independent-audit-20261012.md)。accepted current60单points（32INTTYPE＋28PADCFG），非穷举。chunk16 PADCFG3 pins26–29 values2／6／9／14 generation9338实际运行、尚未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；64fieldpoints后仍有word／permission／width／reset及原Stage2完整scope，不能标阶段完成。


2026-10-12 chunk16 PADCFG3 pins26–29 generation9338已exit0／complete：131.9667810839892秒、available5,477,412,864／peak2,046,443,520低于3,329,929,216限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh6576正在运行、audit待完成，accepted仍60不提前64；3word包prepared待矩阵完成后执行，原Stage2全scope保持OPEN。


2026-10-12 chunk16 fresh6576已exit0／complete：118.51990141399438秒、available5,447,532,544／peak1,851,146,240低于3,300,048,896限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。最后独立audit待终态，accepted仍60不提前64；16组小证据聚合核对仅准备，各bundle current8证书不能伪称global active128，非exhaustive／fullE2。


2026-10-12 最后chunk16 fullaudit11089实际exit0／PASS，16bundle轻量聚合PASS：accepted current64 exact指定单valuepoints（32个2bit INTTYPE＋32个4bit PADCFG），无漏重；每bundle current8证书，不能拼成global active128；16gen／16fresh各自singleworker／≤180秒，与全部sourcefreeze／fresh／resources小证据一致。见[聚合报告](stage2-e2-register-field-matrix-aggregate-20261012.md)。不是全值穷举或完整E2，word／permission／width／reset仍OPEN。Root DIR_OUT word generation48145已实际运行、尚未通过，原Stage2完整范围不缩减。


2026-10-12 DIR_OUT word generation48145已exit0／complete：119.19223787200463秒、available5,482,065,920／peak1,715,609,600低于3,334,582,272限额／worker1／DUTFalse，6cases／13,907events／12关联／18selectedAPB／3RAM。fresh3571实际运行、独立audit待完成，word尚未accepted；narrow64已审计单valuepointscope保持独立，不扩成global或完整E2。


2026-10-12 DIR_OUT word fresh3571已exit0／complete：101.75905876699835秒、available5,479,596,032／peak1,575,030,784低于3,332,112,384限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。word独立fullaudit待终态、尚未accepted；narrow64单值scope保持独立，原Stage2继续OPEN。


2026-10-12 DIR_OUT word fullaudit42062终态PASS，13,907events／6证书／exact B.INTEN0与A.PADDIR／PADOUT 0x80000000三instance-specific write/read pairs验收，见[独立报告](stage2-e2-word-dir-out-independent-audit-20261012.md)。不授functional／reset／fullL2，narrow64保持独立。EN_INTEN generation49060实际运行、未通过，source-script SHA／AST／exact6tuple与own absent cache preflight一致／singleworker180／无overlap；PADIN未运行、reset-default未实现，原全scope保持开放。


2026-10-12 EN_INTEN word generation49060已exit0／complete：116.19795339199482秒、available5,497,872,384／peak1,715,634,176低于3,350,388,736限额／worker1／DUTFalse，6cases／13,905events／12关联／18selectedAPB／3RAM。fresh74249运行中／audit待完成，EN_INTEN尚未accepted，DIR_OUT3pairs与narrow64分别独立。current alias zero-mask八case包仅准备、PADIN之后再执行，不借旧source，不提前native验收。


2026-10-12 EN_INTEN fresh74249已exit0／complete：100.39961130799202秒、available5,492,273,152／peak1,573,228,544低于3,344,789,504限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态，尚未accepted、DIR_OUT与narrow64scope保持独立。current alias zero-mask八request包（check86a6e8…bd97）仅prepared，待PADIN后／独立review，不提前native验收。


2026-10-12 EN_INTEN fullaudit99853已终态PASS，13,905events／6证书／exact B.INTEN0、A.GPIOEN与A.INTEN 0x80000000三instance-specific fullword pairs验收；B.INTEN0与DIR_OUT重复，不重复计unique，不授functional／reset／fullL2，narrow64scope独立。PADIN generation83748实际运行、未通过，current typed RO／exact4request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。alias zero-mask仍prepared／review、reset-default未实现，原全scope保持OPEN。


2026-10-12 PADIN generation83748已exit0／complete：103.98888060198806秒、available5,509,058,560／peak1,414,696,960低于3,361,574,912限额／worker1／DUTFalse，4cases／10,129events／10关联／12selectedAPB／3RAM。fresh88629实际运行、audit待完成，PADIN尚未accepted，scope只APB→CPU→RAM consistency、不授sampling／reset；EN_INTEN3pairs与narrow64独立，aliaszero仍仅prepared，原scopeOPEN。


2026-10-12 PADIN fresh88629已exit0／complete：87.21911255799932秒、available5,506,846,720／peak1,302,310,912低于3,359,363,072限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、尚未accepted，不授sampling／reset，existing wordpairs与narrow64独立。current alias fullmask八case包只准备、待PADIN＋aliaszero之后；aliaszero prepared／review通过仍未native，原scope开放。


2026-10-12 PADIN fullaudit75237已终态PASS，10,129events／4证书／exact B.INTEN0 pair与A／B.PADIN READs，见[独立报告](stage2-e2-word-padin-independent-audit-20261012.md)。scope仅APB_CPU_RAM consistency，不授sampling／reset／fullL2，重复B.INTEN0不新增unique。current aliaszero generation52350实际运行、未通过，current v3 relation／exact8request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。fullmaskprepared未执行／reset只读，原Stage2全scope保持OPEN。


2026-10-12 current aliaszero generation52350已exit0／complete：132.50322782000876秒、available5,517,291,520／peak2,044,710,912低于3,369,807,872限额／worker1／DUTFalse，8cases／17,677events／14关联／24selectedAPB／5RAM。fresh75682实际运行、audit待完成，aliaszero尚未accepted；fullmaskprepared／轻量review通过仍未执行，PADINscoped与wordpairs／narrow64独立，原全scopeOPEN。


2026-10-12 current aliaszero fresh75682已exit0／complete：117.51322904099652秒、available5,533,614,080／peak1,847,062,528低于3,386,130,432限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态、zero尚未accepted，fullmaskprepared未执行；partial／high／repeat current alias下一步只读设计，不borrow旧source，原Stage2全scope开放。


2026-10-12 current aliaszero fullaudit30129（本轮process）终态PASS，17,677events／8证书／exact8requests zero SET／CLR＋B.INTEN0 pair一致，见[独立报告](stage2-e2-alias-zero-current-independent-audit-20261012.md)。仅2source-bound zero brackets验收，不授storageversion／prerequisite／functional／reset／fullE2，word／narrow64scope独立。fullmask generation66978实际运行、未通过，actualFFFFFFFF builder／currentv3／source-script preflight一致／own absent cache／singleworker180／无overlap；partial_repeat current-source仅design待独立review，未准备执行。


2026-10-12 current aliasfullmask generation66978已exit0／complete：130.43963241600432秒、available5,511,983,104／peak2,043,985,920低于3,364,499,456限额／worker1／DUTFalse，8cases／17,683events／14关联／24selectedAPB／5RAM。fresh32283实际运行、audit待完成，fullmask未accepted；partial_repeat独立designreview中现规则允许shared actual adjacent READ boundary，新gate独立before为实验要求，仅docs修订／未执行，原scope开放。


2026-10-12 current fullmask fresh32283已exit0／complete：115.31429795100121秒、available5,522,804,736／peak1,849,442,304低于3,375,321,088限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、fullmask未accepted／currentzero2brackets已验收；SET partial_repeat十request新worker仅prepare，sharedactualREAD规则与独立newbefore2实验要求已reconciled、未native，原scope开放。


2026-10-12 current fullmask fullaudit39840终态PASS，17,683events／8证书／exactSET_CLRFFFFFFFF一致，见[独立报告](stage2-e2-alias-fullmask-current-independent-audit-20261012.md)。仅2fullmask brackets验收，不授functional／reset／storageversion／fullE2；zero2／word／narrow64scopes独立。SET partial_repeat十request包（check42b3ca…05dc）prepared／Root preflight通过，轻量review／audit准备中、NOTnative；当前全部native已终态，原Stage2全scope仍OPEN。


2026-10-12 SET partial_repeat generation64745实际启动、新v1／own absent cache／singleworker180／无overlap，独立lightreview无阻断／auditprepared及Root source-SHA／AST／exact10request preflight一致。尚未通过：10cases（6READ／2plain／2alias）／10selectedMMIO／30selectedAPB／6RAM／expected16关联48allAPB仅准备断言，high／repeat不预授。current fullmask2brackets已accepted，generic规则不改，原Stage2全scope保持OPEN。


2026-10-12 partial SET generation64745已exit0／complete：151.32340373699844秒、available5,571,547,136／peak2,346,278,912低于3,424,063,488限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh51736实际运行、audit待完成，partialSET尚未accepted，全部10cases与原预算保持；CLR partial_repeat十request包（checkf3e984…bc49）prepared，待SET全终态／独立review，未native执行，原scope开放。


2026-10-12 partial SET fresh51736已exit0／complete：133.26829966400692秒、available5,504,163,840／peak2,122,182,656低于3,356,680,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、SET尚未accepted，全部10cases／原180预算保持；CLR prepared lightreview无阻断／auditprepared（b3c85a…5f3b），未执行、待SET audit终态，原scopeOPEN。


2026-10-12 partial SET finalaudit16667终态PASS，21,451events／10证书／exact seed55aa00ff_SET80000000＋repeat一致，见[独立报告](stage2-e2-alias-partial-set-current-independent-audit-20261012.md)。firstaudit69511 exit1 NameError cap为audit setup漏sidecar load，仅补load、不改事实断言，失败保留／非DUT finding。仅2SET brackets验收，不预授CLR／reset／functional／storageversion／fullE2。CLR generation60831实际运行、未通过，source-script preflight／lightreview一致／own absent cache／singleworker180／无overlap，全部10cases保留，原scopeOPEN。


2026-10-12 partial CLR generation60831已exit0／complete：143.68561087400303秒、available5,575,970,816／peak2,345,062,400低于3,428,487,168限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh48813实际运行、audit待完成，CLR未accepted，全部10cases／原180保持。SET2brackets已accepted，首次audit setup失败真实script／stderr／receipt与SHA证据保留、非DUT finding；原scope保持OPEN。


2026-10-12 partial CLR fresh48813已exit0／complete：139.66191233199788秒、available5,607,415,808／peak2,120,609,792低于3,459,932,160限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、CLR尚未accepted，全部10cases／原180保持，原scope开放。


2026-10-12 partial CLR fullaudit28385已终态PASS，21,451events／10证书／exact seed d5aa00ff，见[独立报告](stage2-e2-alias-partial-clr-current-independent-audit-20261012.md)；仅2CLR brackets验收，不授arbitrary masks／reset／storageversion／functional／fullL2。全部native与audit终态后，current f7da exact14权限软件测试exec66607 exit0，14 passed／23.06秒（真实外层wall23.440831127998536），前后源码／fixture SHA不变、stdout／stderr／终态receipt保存在[本轮证据](../../runs/stage2-e2-current-register-permission-software-20261012/receipt.json)。actual对象软件transport，无Generated Popen／DUT／RTL；仅前effect声明policy拒绝，不是PSLVERR硬件权限证明；历史22.92秒记录保持，原Stage2全scope仍OPEN。


2026-10-12 native reset-default实施前checkpoint：current CLR2 source-bound brackets已审计accepted，current f7da permission14软件PASS23.06秒，均仅各自scope。新[ordinary native reset-default计划](../superpowers/plans/2026-10-12-stage2-ordinary-native-reset-default.md)已存在、尚未实现。为保留未提交历史源闭包，已新增[当前源码原始bytes冻结manifest](../../runs/stage2-e2-pre-native-reset-source-freeze-20261012/manifest.json)：20baseline文件／815,794bytes逐件archivebytes＝currentbytes／真实SHA核对，manifest SHA `dbb3dbc4d43fffcb808468eac67fae84cfe3c1ef6b2fb9f316dd390b8ec5a4bc`。仅historical source reconstruction材料，非runtime authority；未复制cache／binary，未改旧run pins。后续新源码必须单列证据，不能以新SHA重写已验收历史门禁；原全scope仍OPEN。


2026-10-12 ordinary native reset-default计划已冻结、Task1获Root GO。Task1／2独立review三条件继续作为实施约束：ACK至postparse／callback全错误范围、实际pinned build issuance资格、public export与private issuer／registry分离。20baseline源码bytes已归档；Task1修改后既有f7da／bfbb native门禁仅历史source qualification，旧pins不重写。Task2 Runner private consumer仅只读接口与测试准备，等待renderer final契约，未修改生产／运行测试，不记为完整E1／E2完成。
