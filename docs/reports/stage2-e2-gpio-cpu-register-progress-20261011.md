# E2 声明式 GPIO 字段到真实 CPU 寄存器程序进度

2026-10-12 ordinary APB receipt 第一软件包已实现并独立复核：默认关闭的目标端实际 command／APB 边界 receipt 与 Router 真实事务交接；根十模块 **166 passed／34 subtests（128.51 秒）**，独立19项与容量／身份2项通过。typed identity、tick基址错位、同epoch新进程ID覆盖、容量漂移及合法read sourcewdata拒绝均有RED→GREEN；callback确认交付与同步返回分开，失败不重执行。仅 target command observation，不授 storage／verified／functional。未运行新RTL，Runner raw/base journal关联、生产opt-in replay接线与行为verifier仍待继续，E1/E2及完整计划保持未完成。 见[本轮实现与验证报告](stage2-e2-ordinary-access-receipts-20261012.md)。此前实际gate仅证明各自冻结版本。

2026-10-12 最新实际结果：E2 capability preflight opt-in 门禁执行通过（exit 0）：10 cases（8 RMW／2 READ）、54条实际APB边界、2次read→RAM认证commit，可信CLI fresh完整22,339events matches。requested minimum L1，startup报告＝plan报告＝fresh CLI报告；每个实际GPIO alias保留完整14寄存器／72字段矩阵，declared L2／effective L1／verified None。46项冻结source pins包含40项production closure；identity SHA `308cb88e87c6b300ae12d60dd9c200a0328d5a0352dd02a2ced48ce918ab716d`，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。singleworker complete154.998309826秒，峰2,472,001,536 bytes、RSSlimit3,291,369,472 bytes，available5,438,853,120 bytes。独立产物audit已通过，findings=[]：46项源码pins／40项production closure／9项authenticated artifacts、10次重编译／18次实际CPU MMIO交付／54条APB边界／2次RAM commit／22,339events核对一致；本轮cache实际GPIO279／279项、CPU348项冻结输入核对通过（旧门禁278／278／347保持历史）。root额外只读startup重建configuration／report同SHA匹配；环境身份差异与fresh全trace未另存的限制见本轮报告。见[独立audit](../../runs/stage2-e2-register-capability-cli-20261012/independent-audit.json)。详见[本轮capability报告](stage2-e2-register-capability-preflight-20261012.md)。 见[本轮实际摘要](../../runs/stage2-e2-register-capability-cli-20261012/summary.json)及[资源记录](../../runs/stage2-e2-register-capability-cli-20261012/resource.json)。

`make_register_assembly()` 默认不加入 `requested_minimum_level`，旧schema16／17、runtime configuration与assembly布局保持；默认38项生产闭包。显式None／L1／L2／L3开启通道，40项闭包补入capability helper与等级模块；完整矩阵不能满足L2时在命令前拒绝。安装实际adapter后、begin前调用 `Session.configure_register_capability_preflight()`：startup／begin／fresh重算当前实际支持及minimum，保存manifest／plan的opt-in报告；执行后导出startup pin，不因slot消耗重算能力。保存assessment不是权限，verification=None，不授functional或verified L2。

软件证据：根联合162 passed／36subtests（205.90秒）在最后legacy helper一行修复前完成；修复后联合31 passed（90.49秒），独立软件16 passed（30.19秒）；两项P2均有RED→GREEN证据，当前实际门禁使用最终冻结源码。source-pin漂移在prepare／submit／cached retry三个实际对象负例RED后修复，注册及返回缓存前拒；legacy无native base trace却产生无效报告的负例RED后修复，完整declared矩阵与unsupported gaps保留。本轮实际摘要确认40项production closure／46项总pins；capability preflight与minimum接线已交付。E1／E2 checkbox继续未完成，剩余code-owned分操作verifier／证书、实际reset／权限／mask／width及已支持副作用行为、verified矩阵／L2 minimum证据。旧门禁仅证明各自冻结版本，不能证明本轮源码。

历史冻结版本检查点：2026-10-12 E2可信保存文件CLI门禁执行通过（exit 0）：10 cases（8次窄字段显式CPU RMW＋2次DIR／OUT full-word READ）、54条实际APB边界、2次read→RAM认证commit；保存plan为schema16，production `replay-register-programs` 从fresh实际factory／before-begin adapter重编译原requests，完整22,339events matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。verification scopes为 `register_program_reconstruction`、`register_program_admission`、`online_complete_prefix`；identity SHA `d2a480c0a9e889930782de5e79f083fe4d2bc595f01d1845ca883c6cab9f9277`。44项冻结source pins包含38项生产selector闭包，单worker complete137.546529879秒，峰2,442,502,144 bytes，RSSlimit3,231,547,392 bytes。根软件105 passed／26subtests（136.20秒），另2项保存投影positive通过（9.85秒）；独立软件35 passed／24subtests，selector完整16 passed／24subtests（63.45秒）。独立产物audit已通过：44项源码pins／38项production selector闭包／9项authenticated artifacts、10次当前上下文重编译／18次CPU MMIO交付／54条raw APB边界／2次RAM commit／22,339events及3个cache binary的278／278／347项冻结输入核对一致。E1仍为14寄存器／72字段declared范围；E1／E2完整阶段checkbox保持未完成，schema17已实现并软件验证；真实注入fault门禁不是原计划新增验收前提。原计划剩余为capability等级证据与实际reset／权限／mask／width及已支持副作用行为验证，不授functional、verified L2、RFuzz或BFM。旧四字段／helper／runtime门禁按各自冻结版本保留，不能证明本轮改动。 见 [新门禁摘要](../../runs/stage2-e2-register-file-cli-20261012/summary.json)。 见 [独立audit](../../runs/stage2-e2-register-file-cli-20261012/independent-audit.json)。

新生产接口为 `make_register_assembly()`、`make_register_factory()`、`make_register_runtime_factory()`、`save_ibex_pulp_register_bundle()` 与 `replay_ibex_pulp_register_files()`。Session在declare slots后、begin前安装实际adapter；schema16保存正常register前缀，schema17保存真实uncertain attempt的phase／case_index与nullable Session failure，均包含原requests／完整配置及actual gate_state。可信闭集ordinary GPIO assembly固定native observation／memory commit／installed persistent gate，checker=None；38项当前源码闭包、artifact SHA、trace事件语义、plan／manifest／terminal state先验证，fresh执行只重编译原requests，不以saved paths／bytes／regions恢复授权。

可信文件重放命令（本轮实际执行；不授功能等级）：

```bash
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py replay-register-programs \
  --cache-dir runs/stage2-e2-register-file-cli-20261012/cache \
  --run-dir runs/stage2-e2-register-file-cli-20261012/bundle
```

保存入口从实际完成Session取 `session.manifest_document`、`session.encode_plan()`、`session.finish()` 返回trace与 `adapter.snapshot()`；调用 `save_ibex_pulp_register_bundle(output_dir=<new bundle directory>, assembly=assembly, session_manifest=..., plan_bytes=..., trace=..., runtime_state=...)`。该bundle用既有run identity envelope认证，client身份为None且RFuzz未执行；assembly／adapterstate置于artifact SHA覆盖的corpus目录。schema17已软件验证，不据本轮schema16实际门禁声称fault实测通过。

当前剩余工作按[最新next-steps](stage2-e2-register-replay-next-steps-20261012.md)四项继续，保存／schema／可信CLI接线已实现：

1. 在实际adapter外接入opt-in capability preflight，用实际artifact／router／gate／compiler形成 `RuntimeCapabilitySnapshot`，保存身份绑定的等级评估与requested minimum，begin前 `require_minimum()`，fresh核对。
2. 将code-owned寄存器verifier绑定实际transaction、raw APB/base引用与声明语义，复用适用的D4接口；仅授实际观察支持的分操作 `VerifiedCapabilitySnapshot`，不由APB响应或RAM存储事实推广GPIO等级或功能。
3. 通过已交付CPU request／file replay验证原E1/E2的可观察reset、权限／mask／width、稳定普通寄存器和已支持副作用；观察实际post-reset状态，不用profile默认值充当host oracle，CPU与BFM结果分列。
4. 发布该组合declared／effective／verified操作矩阵与具体缺口，再判断B2 aggregate L2 minimum。RFuzz声明式寄存器生成、其他CPU／ISA、匿名IP L2选择和L3功能族属于下游接入；E1／E2及M2仍依原计划行为／等级要求开放，不增加schema17注入fault前提。

独立audit未启动RTL或重复重放，fresh全trace未单独另存；fresh结果由已冻结worker与production CLI输出佐证，审计独立核对保存trace、请求重编译、admission、原始APB／RAM引用、源码与cache输入。

历史检查点（按当时冻结源码；本轮结果见上）：2026-10-12 E2 schema16／17与可信文件入口生产接线已冻结：runtime失败phase／actualcase索引／256字符请求上界／uncertain停止Session命令；Session保存完整manifest与actual gate_state，fresh仅从原request重编译，不用saved bytes注册；closed assembly与production replay-register-programs CLI已接。嵌套闭集、totalattempt容量、Unicode canonical、38项selector源码闭包、trace语义及fresh plan SHA检查已补RED→GREEN。根最终五模块105 passed／26subtests（136.20秒），另窄字段RMW／READ保存投影2项通过；独立35 passed／24subtests，selector16 passed／24subtests，新Session19 passed。此前联合200pass／29subtests＋旧空字典fixture失败已记录并修正test-only，不放宽production。新runs/stage2-e2-register-file-cli-20261012监督器已启动，singleworker180秒，尚待实际终态及独立audit；不预授RTL／CLI或完整E2通过。

2026-10-12 E2保存接线新检查点：runtime phase／实际case索引、prebegin enrollment和短期提交许可8项RED→GREEN，request文本上界与接纳不确定后停止Session其他命令7项RED→GREEN；runtime模块52 passed（11.42秒）。Session schema16／17与fresh重编译基础7项已通过，后续失败前缀／总attempt容量／嵌套闭集负例仍检查；可信selector15项软件检查，source closure补authority分发及raw协议三个依赖，新CLI门禁已准备但未执行。上一轮actual adapter门禁仅历史冻结版本，本轮不预授RTL、file-selector或完整E2通过。

2026-10-12 E2保存重放接线执行中：已复现5项失败边界RED并补runtime attempt phase／实际case_index，42 passed（10.61秒）；另3项constructor enrollment／提交token测试RED，Session安装hook与schema16／17、fresh request重编译、可信assembly／CLI由子代理并行实现。当前生产SHA已变化，上一轮10case真实adapter／RMW门禁仅证明其冻结版本；本轮尚无新RTL或file-selector验收，不授E2完成。

历史实施方案：[Session 保存／可信重放实施细化](stage2-e2-register-replay-next-steps-20261012.md)。该方案中的接纳失败阶段记录、schema16／17、fresh request重编译与可信assembly／CLI已接线，本轮schema16实际文件门禁结果见顶部；schema17已实现并软件验证，实际fault门禁不是原计划新增验收前提；原计划剩余capability等级证据与实际reset／权限／mask行为验证见上述四项。

独立证据：[实际摘要](../../runs/stage2-e2-register-runtime-rmw-20261012/summary.json)、[产物审计](../../runs/stage2-e2-register-runtime-rmw-20261012/independent-audit.json)、[资源回执](../../runs/stage2-e2-register-runtime-rmw-20261012/resource.json)。

2026-10-12 最新：E1 GPIO 数据声明覆盖14寄存器／72字段，E2 actual-context `RegisterProgramRuntime` API 与显式CPU RMW已落地。本轮真实门禁执行通过：10 cases（8次窄字段显式RMW＋2次DIR／OUT full-word READ），54条实际APB边界、2次read→RAM认证commit；每次RMW用实际CPU读值核对保留位及新值，同寄存器后续读值与前次写值一致。fresh factory在begin前重装adapter、从当前实际waiting slot重算原始requests并exact核对manifest；完整22,339events、runtime snapshot与plan均matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。36项当前source pins严格冻结核对通过，含72字段sidecar SHA `f9b4837c6ca06b97a0ceb76f134ed7591538ab6d9c3e94c7839fc8ab63b7459b`。singleworker complete72.416334056秒，峰1,619,726,336 bytes，RSSlimit2,815,479,808 bytes。根六模块181 passed（12.54秒）；独立产物审查通过：36源码 pins、10次当前上下文重编译、18次CPU MMIO交付、54条APB原始引用、2次RAM commit、22,339事件摘要及3个cache binary／276、345、276项冻结输入一致；fresh state文件独立相等，fresh plan／全trace由冻结worker断言核对（未另存fresh全trace）。scope=`installed_context_adapter_explicit_cpu_rmw_and_fresh_request_recompilation`；保存context／bytes不作运行授权，不含RFuzz／BFM／可信CLI selector，不授L2 verified或functional，完整Session schema／selector接入仍待完成。旧4字段／helper门禁按各自冻结pins保留为历史证据，不能证明本轮源码。E1／E2、D8／D5／D6及完整E–I仍未完成。 见 [实际门禁摘要](../../runs/stage2-e2-register-runtime-rmw-20261012/summary.json)。

## 历史软件推进阶段：actual-context adapter与显式CPU RMW

GPIO sidecar现覆盖14个寄存器、72个字段；源码、相对mask与打包位置已独立核对，18项新增声明检查RED→GREEN，五模块108 passed／2 subtests（0.97秒）。原4字段实际门禁按旧sidecar SHA保留，不能证明新增声明。

`compile_register_program()` 新增显式 `read_modify_write=False` 开关与独立mask scratch register，默认仍拒普通窄字段。开启只接受完整32位寄存器所有字段均plain RW、无副作用且read/write masks完整，并要求实际声明窗口同时允许LW和完整word SW。程序36字节、9个CPU指令：LW原值→AND清目标字段→OR新字段→SW；不填host reset/readback值，不授原子RMW、retirement或L2验证。read-clear、FIFO和混合RO/不完整字段仍拒绝。

首批42项RMW检查RED→GREEN；独立审查发现新增AND／OR被 `instruction_operator_id()` 误标SB，3条身份负例RED后修复。另补未选择字段缺声明／RO／partial mask与窗口读写/宽度拒绝。最终11模块337 passed（1.48秒）；actual-context runtime adapter正在独立子代理实现与审查，新的10case资源监督门禁脚本准备中，尚未执行，不预授通过。该API从actual Session／Runner／router／memory／slot与installed persistent gate解析上下文，保存manifest只作重编译比对；完整Session schema／可信文件selector与能力证据授级仍待继续。


## 历史冻结版本：2026-10-12 helper实际门禁（独立audit通过）

2026-10-12续接：E2 helper新实际定向门禁执行通过，12个连续CPU cases全部使用当前实际router／RAM regions／waiting slot参数重新编译保存声明，并仅接纳helper返回fresh source；36条本例APB边界、6次read→RAM认证commit，fresh Session API完整25,201events matches，semantic SHA `3321aa564f841837b26ee3fa5e09500c721d0623b4ce0c30d65137d97253d3c4`，25项当前source pins。singleworker complete54.221435622秒、峰509,140,992 bytes、RSSlimit3,181,293,568 bytes；独立产物audit通过：25source pins／12program／25,201events／36APB／6RAM及3binary的276／345／276项冻结输入核对一致。scope为 `current_context_program_recompilation_and_directed_cpu_session_replay`，保存声明不作运行授权；生产actual-context adapter／可信CLI selector仍未实现，不授L2 verified或functional。旧r2仅为原冻结源码历史证据，pins未改；目录沿用20261011准备名称，不重命名。D8独立分类实际门禁仍运行，不预授通过；E1／E2、D8／D5／D6及E–I保持未完成。

新 [门禁摘要](../../runs/stage2-e2-gpio-program-verification-20261011/summary.json)记录 `helper_used=True`、`saved_document_not_runtime_authority=True`；[资源记录](../../runs/stage2-e2-gpio-program-verification-20261011/resource.json)保存上述singleworker结果。[独立audit](../../runs/stage2-e2-gpio-program-verification-20261011/independent-audit.json)已通过；根冻结九模块最终227 passed（93.18秒），包含独立开关25项、provider6项、候选兼容／replay／selector／CLI／classifier及compiler／helper16项。全部旧APB／RAM／完整前缀断言保留；只证明当前context重编译接入定向Session及Session fresh replay，不声称生产寄存器adapter或可信CLI已实现。下文原r2和helper软件记录保持各自冻结来源。

本轮编译器与定向真实门禁已通过：12连续CPU寄存器用例、6读回RAM认证commit，完整fresh Session API25201events相等；独立产物复核通过，见 [独立审计](../../runs/stage2-e2-gpio-cpu-register-20261011-r2/independent-audit.json)。这里只验收四字段完整word行为与编译路径，不授完整E1／E2、L2 verified或功能完成。下文初轮／执行中描述是保留的历史过程，当前结果以r2章节为准。

本轮沿用E1已核实 [GPIO sidecar与源码审计](stage2-e1-gpio-register-source-audit-20261011.md)，实现 `compile_register_program()`，复用已有 `plan_register_operation` 与RV32I `mmio_access_fragment`／`mmio_write_fragment`。不接受调用方伪造的operation plan；每次以实际profile及精确sidecar重新计算。返回版本化声明身份、合法instructions、fragment bytes及已有 `OnlineInstruction`，由真实Session接纳并执行，编译本身不证明执行／退休／功能完成或prerequisites。

首步限定32bit bus／register和完整word访问。普通窄字段SW会clobber未选择位，故拒绝；SET／CLR等闭集write-only副作用需显式授权。program slots与read result都要求显式RAM region，边界、权限、alias／重叠及scratch registers检查；read生成实际LW→SW到结果RAM，不填host预期值。MMIO窗口严格限制profile aperture，但地址base／RAMregion是调用方声明，不冒充liveauthority。

软件首轮三模块68 passed／2subtests，root四模块76 passed／4subtests（0.49秒）。实际pinned sidecar的PADDIR／PADOUT side_effect为none，原READ可编译；额外对匹配profile／sidecar中明确write-only的write_drives_output_enable／write_drives_pads添加2条READ拒绝RED修复，只对这些闭集标记允许读取，read-clear／FIFO仍拒绝。最终三模块74 passed／2subtests（0.35秒），root六模块最终105 passed／4subtests（9.93秒），独立58 passed（0.33秒）；真实门禁已按资源监督启动。

资源监督定向门禁准备在 `runs/stage2-e2-gpio-cpu-register-20261011`：实际factory普通GPIOprofile与sidecar fingerprint一致，从实际router/CPU RAM取得窗口／region，独立ScenarioSession source路径 `standalone_cpu_register_test`，保留固定bootstrap和新instruction slots；12例覆盖PADDIR 0／全1读写、PADOUT高位混合读写、SET／CLR保留未选择位、恢复0读取。低8位保持0以避免触发无关固定ISR。每例核对真实CPU MMIO delivery／source_transaction、原生APB pre taps与RAM认证commit，随后完整fresh API replay。首轮定向执行在case0验收脚本错误期望receipt.status complete时退出：通用Session逐例正常running，仅finish后complete；实际PADDIR写及APB三边界已有观察，无protocol violation。原case／sourcepins／resource command_failed42.196秒、峰507129856保留。修正只验收脚本，新的 `runs/stage2-e2-gpio-cpu-register-20261011-r2` 单worker／进程树RSS／180秒预算执行中，生产源码冻结，不提前授通过。脚本额外核对真实APB写数据等于程序value、accept／response精确关联本例setup raw refs及epoch，保留APB无原生transaction ID缺口。

这是定向CPU寄存器程序测试，非BFM、非RFuzz、非可信CLI selector；不授闭环或Stage2 L2 verified level。全部寄存器规则／窄字段RMW／read-clear／reset／语义provider及五族功能验收仍未完成，E1／E2及D8／D5／D6、后续E–I维持未完成。

## 历史冻结版本：r2 定向实际 CPU 行为门禁

新 [r2门禁摘要](../../runs/stage2-e2-gpio-cpu-register-20261011-r2/summary.json)已执行通过：12个连续定向case，PADDIR 0／全1写读、PADOUT高位混合写读、SET／CLR保留未选择位及恢复0；本例36条真实APB request／accept／response、6个实际LW后RAM认证commit。每例实际CPU等待新的未物化slot后再接纳，12个fragment连续不重填；所有MMIO完整word byte_enable15。只比较source声明规则对应行为，不把物理out等同外部pad驱动或IRQ完成。

新进程完整 `replay_online_session` API重放**25,201 events matches**，schema4完整初始前缀／12例，semantic SHA `3321aa564f841837b26ee3fa5e09500c721d0623b4ce0c30d65137d97253d3c4`。编译document／source bytes与plan、初始bootstrap和warmup均保存；25source pins含真实RTL/profile/sidecar/compiler及脚本。此次没有RFuzz、没有BFM、没有verified CLI selector bundle，也不授L2 verified level或functional completion。

[资源记录](../../runs/stage2-e2-gpio-cpu-register-20261011-r2/resource.json)：singleworker complete48.963999秒、峰508,014,592 bytes、RSSlimit3,224,297,472 bytes。前轮脚本running／complete错误断言目录保留，其case0真实写观察不能替代本轮完整验收。独立产物复核通过：25source／12program身份与plan source一致，25201语义摘要、36真实APB、6RAM commit及3binary／276/345/276inputs SHA核对。

下一步：编译身份／能力与实际CPU SourceAction/生产入口绑定、L2按操作证据授级、已声明寄存器语义及reset／权限边界、窄字段完整word或可信RMW策略。D8独立反馈开关／功能provider及D5／D6、后续E–I仍继续。

独立审计还核对12个完整CPU delivery／原生APB写数据读数据及related setup／epoch／identity gap；6个commit完整hash、payload hash、四字节值与实际CPU transaction一致。三个cache binary与276／345／276项冻结输入SHA一致。首轮失败保持单独记录。

文档链接检查617文件／1579链接，83条历史断链，本轮新增0。

## 编译声明重验证 helper：初始软件检查阶段（历史；当前实际结果见顶部新门禁）

本轮新增 `verify_register_program_document(profile, capability, saved_document, **current_compile_arguments)`，16项负例先RED后GREEN，联合软件 **74 passed（0.40秒）**。helper只使用当前调用方提供的显式编译参数重新调用编译器；保存document中的profile、fragment、regions、operation plan及hash都不是重编译输入。重编译结果与保存声明按精确canonical JSON比较，保留bool／int类型区别，不能利用Python的True==1等价绕过身份比对。

此helper为后续生产adapter提供重验证边界；当前参数仍属于调用方声明，helper不自动从Runner解析授权context，不授live authority、prerequisites或能力等级。它没有实现生产adapter、decoder模式或可信文件selector。此初始检查阶段仅为软件验证；上节r2实际门禁属于helper新增前的冻结源码，不作为新helper的RTL门禁。新增helper已改变compiler SHA；r2的25项source pins保持原冻结值，不能冒充当前compiler／新增helper或尚未实现replay adapter的实际证明。后续实际门禁必须新目录、新source pins单列，不改写历史身份。

## 历史生产接入设计与仍需保留的完整门槛

1. 新增闭集、版本化寄存器请求，明确目标实例／endpoint、`register.field`、操作、值、显式副作用授权及结果槽。新可选decoder模式提供既有decode／commit／source_action／document契约，保留旧PADOUT decoder身份。不得修改旧decoded proposal后跳过一致性检查，也不把独立定向访问伪装为已认证闭环。
2. adapter从实际Runner取得目标artifact profile、真实route／window、CPU RAM regions和instruction-slot范围，核对sidecar fingerprint与源码身份。命令前拒绝目标、权限、槽、宽度或配置漂移；保存的region／window及调用方声明不能作为live授权来源。
3. 由实际context调用 `compile_register_program()`，将精确fragment注册为F4 instruction SourceAction，沿用executor admission与 `Session.submit_case()`。把编译结果与真实slot接纳绑定，明确每例预算、未完成及失败边界；不以程序生成成功代替CPU执行证据。
4. plan保存原始寄存器请求、编译manifest及实际context身份。fresh replay从原始请求和当前实际context调用新增helper重编译核对，不恢复保存fragment或regions作为授权。可信文件selector须显式重建该模式，并验证失败前缀、cleanup和reset；当前schema4定向Session API重放不能代替这条生产文件入口。
5. 生产预检输出限定操作的 `RuntimeCapabilitySnapshot`；精确实际观察provider产生证书后才输出 `VerifiedCapabilitySnapshot`。APB成功、物理输出和RAM认证commit保持各自证据范围，不能单独认证GPIO存储／功能规则。

现有 `gpio_register_version.v1` 的能力绑定使用固定causal probe profile及source contract，本轮普通PULP profile／sidecar不能直接套该证书。后续必须选择精确匹配的profile、sidecar和观察契约，或实现普通出口的独立证据provider，并通过正反例证明范围；不能只放宽既有validator。`gpio_sync_consumption.v1` 当前明确不能认证完整外部功能操作，接入它也不能授completion或E4 GPIO通过。

E1／E2完整要求仍包括其余寄存器字段、reset、访问宽度、合法mask及已支持副作用的真实行为验证。普通窄字段须明确RMW或完整word组装；缺观察的read-clear／FIFO规则继续拒绝，不由名称推断oracle。E3–E7另需可关闭功能插件、L1／L2／L3对照、五族真实功能门禁及异常负例；四字段编译与本次重验证helper不能替代这些最终要求。E1／E2、D8／D5／D6与后续E–I保持未完成。

2026-10-12 Runner ordinary APB association 软件包已实现：[执行与验证报告](stage2-e2-ordinary-access-association-20261012.md)。实际source closure／请求／响应与target parsed phase、私有callback confirmation、原始及base journal引用独立绑定；queued decode与容量在命令前拒绝，缺失delivery标incomplete。最终软件212不重复项／34子测试覆盖，完整联合旧fixture失败和修后Runner10项独立补证如实保留；无新DUT门禁，不授storage／verified／functional。生产 opt-in replay及真实readback/reset等完整E2工作继续。
