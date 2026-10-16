# 当前方案的验收报告入口

2026-10-12 Task3 software-only refusal step accepted at the frozen Path-MRO candidate after independent exact-SHA security and source-contract reviews. Full Task3 regression: 99 passed / 18.04s; Task2 three-module compatibility: 92 passed / 52.79s. Verifier SHA 229485466093033be9f96c38bfc8dfbd757c92daf7ca93912577964b04fb255f; tests SHA 7b6527f0530869cb0c497517f06d927d5e59e668a1376ae053413630dbd3e090. Receipts and 12-file source archive are under runs/stage2-e2-native-reset-task3-software-20261012/path-mro-final-*. No native/build or positive certificate.

支持边界：拒绝标准类属性改写，并假定加载中的 Python 代码对象完整；不覆盖直接改写 function.__code__、显式 type.__setattr__、同进程任意私有 Runner slot 改写，或 pathlib 内部对象/module helper 改写。Task3 只证明 source-rule/refusal 软件路径；不授 native reset certificate、functional 或 verified L2。原 Stage2 D5/D6/D8、完整 E1/E2 与 E3–I 继续开放。
以下按时间记录的旧状态仅作过程证据；其中 Task3 仍在进行或未接受的表述已由本文件顶部与最终执行检查点更新，不代表当前状态。

2026-10-12 zero／fullmask实际门禁当前状态：generation50928已终态exit0／complete，152.13179933300125秒、workers1、峰2,590,924,800 bytes低于3,251,445,760限额。实际14cases／20确认关联／9RAM／28,995events，4alias＋9READ＋1plain共14证书、gaps=[]；实际B.INTEN写读0及13条native IRQ quiet snapshots为0，zero操作不变／full SET为ffffffff／full CLR为0。60总APB与完整cached currentinputs待独立产物audit。semantic SHA `7f1ea66fd9c05f9592ed49be66c7bf03e2f519b91ad35c9d6c5242b6730664c1`，identity SHA `974ffd0d7967cdb04cdee6e4acc03f47834cf93e362258347dcb04687097ad18`；见[实际摘要](../../runs/stage2-e2-register-alias-mask-verifier-20261012-v1/summary.json)与[资源记录](../../runs/stage2-e2-register-alias-mask-verifier-20261012-v1/resource.json)。fresh85373已终态exit0／complete：166.55756382399704秒、workers1、峰2,641,014,784 bytes低于3,242,532,864限额，完整fresh比对通过；独立最终产物audit已PASS：283pins／9产物／14exact重编译／28,995events／20关联／60APB／9RAM／14封存access／14证书、13 IRQ quiet snapshots及CPU／GPIO B各1,152条raw采样零值核对；完整fresh／resources／3个current cache／source一致。zero/fullmask scoped native包已审计通过，完整Stage2及native reset／权限矩阵仍未完成。原非zero/fullmask四括号audit通过保持历史；完整Stage2及actual reset／权限／width／mask／effects矩阵仍未完成。

2026-10-12 alias实际门禁当前状态：generation74397已终态exit0／complete，164.01385019000736秒、workers1、峰2,355,449,856 bytes低于3,176,628,224限额。12cases／18确认关联／8RAM／25,237events，4alias＋8READ证书、gaps=[]；semantic SHA `e744874aa3c1660c455f081713c9c77d406734156db92717a1136911420d1ae0`、identity SHA `8019be229437fb9b1784f7a0d6cca2d1aa8705246374fb7ed486fe62262c6c81`。见[实际摘要](../../runs/stage2-e2-register-alias-verifier-20261012-v1/summary.json)与[资源记录](../../runs/stage2-e2-register-alias-verifier-20261012-v1/resource.json)。fresh11283已终态exit0／complete：153.30511558598664秒、workers1、峰2,359,955,456 bytes低于3,156,848,640限额，完整fresh比对通过；generation与fresh各自独立180秒预算。独立最终产物审计已终态exit0／PASS：283项pins／9认证产物／12exact重编译／25,237events／12封存access／8READ＋4alias证书／18关联／8RAM／54总APB；资源与阶段顺序、plan SHA、journal及全部fresh报告比对通过。四括号scoped包已审计，完整Stage2仍未完成。源码／脚本继续冻结，历史产物保留；最终037软件2 passed／165.70秒仍仅软件证据。完整Stage2未完成，zero／fullmask及actual reset／权限／mask／width／effects矩阵保留后续要求。

2026-10-12 当前检查点：v5实际 generation 已终态 exit0／resource complete，单worker 178.410330162秒，峰2,626,240,512 bytes低于3,125,706,752限额；原14 cases与完整ordinary／verifier验证范围保持。production fresh CLI串行重试已终态exit0／complete，167.28877223400923秒、available5,320,716,288 bytes、峰2,667,540,480 bytes低于3,173,232,640限额，workers1；完整semantic／event count／ordinary／verifier／preflight比对通过。见[fresh结果](../../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-cli-verification.json)。独立最终产物审计已通过（exit0）：9认证产物／283项当前源码pins／29,985events／14次exact重编译／13证书／21封存access／28关联／6RAM，fresh全部wrappers及preflight完全相等，两阶段resource均complete；见[独立审计](../../runs/stage2-e2-register-verifier-cli-20261012-v5/independent-audit.json)。本轮scoped verifier／保存／fresh包已闭合，完整Stage2仍未完成；下一包按declarative generic关系推进SET／CLR alias行为及非空saved-file回放，不授aggregate L2或functional。首轮与大JSON只读审计重叠导致RSS budget_terminated，return124／7.965711960秒的失败证据保留于[首轮归档](../../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-attempt-1-rss-budget-terminated/)，预算策略未提高；generation与fresh各用独立180秒预算，不是combined180通过。见[实际摘要](../../runs/stage2-e2-register-verifier-cli-20261012-v5/summary.json)及[资源记录](../../runs/stage2-e2-register-verifier-cli-20261012-v5/resource.json)。当前build SHA `06334fedf08cacd861806362dc216026af3b426cd80be2ceb10929ff2197056c`、integration SHA `7fe28b291fd2f2164db5edcaffd6ad7b8c0a5a6a52d43d82f87cc974c8583774`已核对；旧v4完整保存但wall_timeout证据保持历史。D5／D6／D8、完整E1／E2及E3–I继续未完成。

2026-10-12 当前继续：v4在178.245秒完成认证保存及summary，但worker整体180.093秒超时，generation未通过、fresh未执行。三子代理并行完整bundle独立审计、退出阶段定位与真实导出成本测量；原预算/源码冻结/失败产物和完整Stage2范围保持。见[执行报告](stage2-e2-register-verifier-session-execution-20261012.md)。

2026-10-12 最新执行：窄READ及scoped verifier软件边界已验证；v2真实14case/28确认关联/6RAM/29985events通过（140.50秒），production可信file freshCLI独立通过（133.80秒），完整state/semantic匹配，A/B各148declared/142effective/0verified、L1。首次factory固定READ16失败已补RED修复并保留产物，最终独立audit通过 findings=[]。下一包Session verifier opt-in已有8缺API RED＋1defaultoff GREEN，生产未实现；完整Stage2/E1/E2继续。详见[执行报告](stage2-e2-register-verifier-execution-20261012.md)。


初期执行记录（后续v2结果见上）：2026-10-12 寄存器行为 verifier／窄字段实际CPU READ 执行中：三子代理并行，Root completed-access封存4RED→31GREEN，actualreadback/reset/mask/permission/effects与exactfield能力继续，未授storage/functional/aggregateL2，未运行本轮新DUT。见[执行报告](stage2-e2-register-verifier-execution-20261012.md)。

2026-10-12 production ordinary APB Session／assembly／可信file fresh CLI已实现并验证：真实10case新增18关联，加bootstrap6条共24完整snapshot，22387事件；分阶段freshCLI exit0，原组合180秒超时保留。默认38/40、启用278项闭包，全部grantsFalse，原Stage2/E1/E2仍继续。见[执行报告](stage2-e2-ordinary-access-production-replay-20261012.md)。原 Stage2／E1／E2继续。

2026-10-12 ordinary APB Runner association 软件包已实现并独立复核：实际 CPU closure／请求与响应绑定、私有 parsed sample digest／callback confirmation、命令前解码和容量检查、raw/base 独立 journal 引用及 reset 缺口处理。最终覆盖212个不重复软件测试／34子测试：联合211pass／1旧fixture失败，最终Runner模块10pass补证，生产SHA无漂移；详情见[执行报告](stage2-e2-ordinary-access-association-20261012.md)。未运行新DUT门禁，生产Session/assembly/fresh回放和行为verifier继续执行，E1/E2及完整Stage2仍未完成。

2026-10-12 ordinary APB receipt 第一软件包已实现并独立复核：默认关闭的目标端实际 command／APB 边界 receipt 与 Router 真实事务交接；根十模块 **166 passed／34 subtests（128.51 秒）**，独立19项与容量／身份2项通过。typed identity、tick基址错位、同epoch新进程ID覆盖、容量漂移及合法read sourcewdata拒绝均有RED→GREEN；callback确认交付与同步返回分开，失败不重执行。仅 target command observation，不授 storage／verified／functional。未运行新RTL，Runner raw/base journal关联、生产opt-in replay接线与行为verifier仍待继续，E1/E2及完整计划保持未完成。 见[本轮实现与验证报告](stage2-e2-ordinary-access-receipts-20261012.md)。此前实际gate仅证明各自冻结版本。

2026-10-12 最新实际结果：E2 capability preflight opt-in 门禁执行通过（exit 0）：10 cases（8 RMW／2 READ）、54条实际APB边界、2次read→RAM认证commit，可信CLI fresh完整22,339events matches。requested minimum L1，startup报告＝plan报告＝fresh CLI报告；每个实际GPIO alias保留完整14寄存器／72字段矩阵，declared L2／effective L1／verified None。46项冻结source pins包含40项production closure；identity SHA `308cb88e87c6b300ae12d60dd9c200a0328d5a0352dd02a2ced48ce918ab716d`，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。singleworker complete154.998309826秒，峰2,472,001,536 bytes、RSSlimit3,291,369,472 bytes，available5,438,853,120 bytes。独立产物audit已通过，findings=[]：46项源码pins／40项production closure／9项authenticated artifacts、10次重编译／18次实际CPU MMIO交付／54条APB边界／2次RAM commit／22,339events核对一致；本轮cache实际GPIO279／279项、CPU348项冻结输入核对通过（旧门禁278／278／347保持历史）。root额外只读startup重建configuration／report同SHA匹配；环境身份差异与fresh全trace未另存的限制见本轮报告。见[独立audit](../../runs/stage2-e2-register-capability-cli-20261012/independent-audit.json)。详见[本轮capability报告](stage2-e2-register-capability-preflight-20261012.md)。 见[本轮实际摘要](../../runs/stage2-e2-register-capability-cli-20261012/summary.json)及[资源记录](../../runs/stage2-e2-register-capability-cli-20261012/resource.json)。

`make_register_assembly()` 默认不加入 `requested_minimum_level`，旧schema16／17、runtime configuration与assembly布局保持；默认38项生产闭包。显式None／L1／L2／L3开启通道，40项闭包补入capability helper与等级模块；完整矩阵不能满足L2时在命令前拒绝。安装实际adapter后、begin前调用 `Session.configure_register_capability_preflight()`：startup／begin／fresh重算当前实际支持及minimum，保存manifest／plan的opt-in报告；执行后导出startup pin，不因slot消耗重算能力。保存assessment不是权限，verification=None，不授functional或verified L2。

软件证据：根联合162 passed／36subtests（205.90秒）在最后legacy helper一行修复前完成；修复后联合31 passed（90.49秒），独立软件16 passed（30.19秒）；两项P2均有RED→GREEN证据，当前实际门禁使用最终冻结源码。source-pin漂移在prepare／submit／cached retry三个实际对象负例RED后修复，注册及返回缓存前拒；legacy无native base trace却产生无效报告的负例RED后修复，完整declared矩阵与unsupported gaps保留。本轮实际摘要确认40项production closure／46项总pins；capability preflight与minimum接线已交付。E1／E2 checkbox继续未完成，剩余code-owned分操作verifier／证书、实际reset／权限／mask／width及已支持副作用行为、verified矩阵／L2 minimum证据。旧门禁仅证明各自冻结版本，不能证明本轮源码。

历史冻结版本检查点：2026-10-12 E2可信保存文件CLI门禁执行通过（exit 0）：10 cases（8次窄字段显式CPU RMW＋2次DIR／OUT full-word READ）、54条实际APB边界、2次read→RAM认证commit；保存plan为schema16，production `replay-register-programs` 从fresh实际factory／before-begin adapter重编译原requests，完整22,339events matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。verification scopes为 `register_program_reconstruction`、`register_program_admission`、`online_complete_prefix`；identity SHA `d2a480c0a9e889930782de5e79f083fe4d2bc595f01d1845ca883c6cab9f9277`。44项冻结source pins包含38项生产selector闭包，单worker complete137.546529879秒，峰2,442,502,144 bytes，RSSlimit3,231,547,392 bytes。根软件105 passed／26subtests（136.20秒），另2项保存投影positive通过（9.85秒）；独立软件35 passed／24subtests，selector完整16 passed／24subtests（63.45秒）。独立产物audit已通过：44项源码pins／38项production selector闭包／9项authenticated artifacts、10次当前上下文重编译／18次CPU MMIO交付／54条raw APB边界／2次RAM commit／22,339events及3个cache binary的278／278／347项冻结输入核对一致。E1仍为14寄存器／72字段declared范围；E1／E2完整阶段checkbox保持未完成，schema17已实现并软件验证；真实注入fault门禁不是原计划新增验收前提。原计划剩余为capability等级证据与实际reset／权限／mask／width及已支持副作用行为验证，不授functional、verified L2、RFuzz或BFM。旧四字段／helper／runtime门禁按各自冻结版本保留，不能证明本轮改动。 见 [新门禁摘要](../../runs/stage2-e2-register-file-cli-20261012/summary.json)及[E2报告](stage2-e2-gpio-cpu-register-progress-20261011.md)。 见 [独立audit](../../runs/stage2-e2-register-file-cli-20261012/independent-audit.json)。

新生产接口为 `make_register_assembly()`、`make_register_factory()`、`make_register_runtime_factory()`、`save_ibex_pulp_register_bundle()` 与 `replay_ibex_pulp_register_files()`。Session在declare slots后、begin前安装实际adapter；schema16保存正常register前缀，schema17保存真实uncertain attempt的phase／case_index与nullable Session failure，均包含原requests／完整配置及actual gate_state。可信闭集ordinary GPIO assembly固定native observation／memory commit／installed persistent gate，checker=None；38项当前源码闭包、artifact SHA、trace事件语义、plan／manifest／terminal state先验证，fresh执行只重编译原requests，不以saved paths／bytes／regions恢复授权。

历史下一执行点（capability接线、新实际门禁与独立audit现已通过）：保存／schema16／17／可信CLI接线已实现，原实际schema16门禁与独立audit已通过；按[最新next-steps](stage2-e2-register-replay-next-steps-20261012.md)四项继续：实际capability preflight与minimum等级、code-owned分操作verifier／证书绑定、真实reset／权限／mask／width及副作用行为、declared／effective／verified矩阵与L2 minimum判定。schema17注入fault不是原计划新增验收前提。

2026-10-12 最新：E1 GPIO 数据声明覆盖14寄存器／72字段，E2 actual-context `RegisterProgramRuntime` API 与显式CPU RMW已落地。本轮真实门禁执行通过：10 cases（8次窄字段显式RMW＋2次DIR／OUT full-word READ），54条实际APB边界、2次read→RAM认证commit；每次RMW用实际CPU读值核对保留位及新值，同寄存器后续读值与前次写值一致。fresh factory在begin前重装adapter、从当前实际waiting slot重算原始requests并exact核对manifest；完整22,339events、runtime snapshot与plan均matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。36项当前source pins严格冻结核对通过，含72字段sidecar SHA `f9b4837c6ca06b97a0ceb76f134ed7591538ab6d9c3e94c7839fc8ab63b7459b`。singleworker complete72.416334056秒，峰1,619,726,336 bytes，RSSlimit2,815,479,808 bytes。根六模块181 passed（12.54秒）；独立产物审查通过：36源码 pins、10次当前上下文重编译、18次CPU MMIO交付、54条APB原始引用、2次RAM commit、22,339事件摘要及3个cache binary／276、345、276项冻结输入一致；fresh state文件独立相等，fresh plan／全trace由冻结worker断言核对（未另存fresh全trace）。scope=`installed_context_adapter_explicit_cpu_rmw_and_fresh_request_recompilation`；保存context／bytes不作运行授权，不含RFuzz／BFM／可信CLI selector，不授L2 verified或functional，完整Session schema／selector接入仍待完成。旧4字段／helper门禁按各自冻结pins保留为历史证据，不能证明本轮源码。E1／E2、D8／D5／D6及完整E–I仍未完成。 见 [实际门禁摘要](../../runs/stage2-e2-register-runtime-rmw-20261012/summary.json)。 [E2报告](stage2-e2-gpio-cpu-register-progress-20261011.md)。

2026-10-12续接：D8独立 `--classified-feedback` 门禁执行通过，candidate探索关闭，实际RFuzz3/3 complete；可信CLI fresh完整6,443events matches，semantic SHA `76d867f9a8cc5aee7da2fa1a80c3b921e2fb7833d07a42601333d33739da995e`，范围包含 `classified_case_feedback`／`classified_terminal_state`且无candidate scoring声明。三回执candidate disabled、novelty／energy均0，legacy覆盖单列；实际base GPIO A／B request／accept／response各3／4，verified0、functional unknown。27项当前source pins；singleworker complete76.752490482秒、峰545,849,344 bytes、RSSlimit3,038,162,944 bytes。root冻结九模块最终227 passed（93.18秒）；D8独立产物audit通过：27项源码／13项产物摘要、6443事件、21个APB原始引用、逐例及终态base覆盖重算和3个binary／冻结输入均一致。该组合未安装RAM／IRQ provider，6项positive检查仅软件另列；不授实际verified正例、functional或L2矩阵。D8及E1／E2、D5／D6和完整E–I仍未完成。见 [新摘要](../../runs/stage2-d8-independent-feedback-cli-20261011/summary.json)及[D8报告](stage2-d8-candidate-exploration-progress-20261011.md)。下方保留历史源码记录。

2026-10-12续接：E2 helper新实际定向门禁执行通过，12个连续CPU cases全部使用当前实际router／RAM regions／waiting slot参数重新编译保存声明，并仅接纳helper返回fresh source；36条本例APB边界、6次read→RAM认证commit，fresh Session API完整25,201events matches，semantic SHA `3321aa564f841837b26ee3fa5e09500c721d0623b4ce0c30d65137d97253d3c4`，25项当前source pins。singleworker complete54.221435622秒、峰509,140,992 bytes、RSSlimit3,181,293,568 bytes；独立产物audit通过：25source pins／12program／25,201events／36APB／6RAM及3binary的276／345／276项冻结输入核对一致。scope为 `current_context_program_recompilation_and_directed_cpu_session_replay`，保存声明不作运行授权；生产actual-context adapter／可信CLI selector仍未实现，不授L2 verified或functional。旧r2仅为原冻结源码历史证据，pins未改；目录沿用20261011准备名称，不重命名。D8独立分类实际门禁仍运行，不预授通过；E1／E2、D8／D5／D6及E–I保持未完成。见 [新门禁摘要](../../runs/stage2-e2-gpio-program-verification-20261011/summary.json)及[E2报告](stage2-e2-gpio-cpu-register-progress-20261011.md)。

E2 GPIO寄存器CPU编译首步已接线：`register_program.py` 将实际profile＋真实sidecar的字段计划编译为 `OnlineInstruction`，闭集full-word SW／LW，读值可由CPU真实SW存入声明RAM窗口；产物仅declared，不授live authority。首版支持PADDIR／PADOUT／SET／CLR四字段，普通窄字段无RMW时拒绝；实际sidecar的DIR／OUT副作用仍是none，额外 `write_drives_*` 声明的READ兼容缺口已用2项RED修复，不能误称实际sidecar此前被拒。最终根六模块105 passed／4 subtests（9.93秒），代理三模块74 passed／2 subtests（0.35秒），最终独立compiler复核58 passed（0.33秒）。真实12例定向门禁首轮已执行case0 PADDIR写及3条APB边界、无protocol violation，但监督脚本错误要求receipt.status为complete；实际Session正常逐例返回running，finish后才complete。首轮case0／source pins及command_failed42.196秒、峰507,129,856 bytes原始记录保留，此为脚本断言失败，不是RTL bug。仅修正脚本后的新 [r2门禁摘要](../../runs/stage2-e2-gpio-cpu-register-20261011-r2/summary.json)执行通过，生产源码未改：12个连续定向CPU cases完成full32 DIR／OUT／SET／CLR访问，36条本例APB边界、6次真实read→RAM authenticated commits；fresh Session API完整25,201events matches、schema4、25source pins，semantic SHA `3321aa564f841837b26ee3fa5e09500c721d0623b4ce0c30d65137d97253d3c4`。资源singleworker complete48.963999秒、峰508,014,592 bytes、上限3,224,297,472 bytes；独立产物复核通过。实际指令仅用scratch x1／x2，保持输出低8位不变避免触发IRQ；不含BFM／RFuzz／verified CLI selector，不授L2等级或functional能力，也不授整个E2完成。E1／E2、D8／D5／D6及E–I保持未完成。见 [E2执行进度](stage2-e2-gpio-cpu-register-progress-20261011.md)。下方为各轮历史源码进度。

D8精确反馈分类已接生产并修复ledger伪记录P2：记录锚定实际provider certificate，旧输出谓词单列legacy，无功能provider明确unknown。冻结八模块178 passed（79.02秒）、独立80 passed。新实际RFuzz3/3complete，可信fresh replay6443events matches，三回执分类一致、33context／noveltyenergy1，资源singleworker75.71秒峰551055360，25source pins；独立产物复核通过。此实测无RAM／IRQprovider，verified0，不授正例或功能完成。E1真实GPIO sidecar首四字段声明16项通过，联合51＋2subtests、独立16；无自动授级，实际L2待E2。分类独立开关及功能provider接入仍待推进，D8／D5／D6、E–I保持未完成。见 [执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 原生 GPIO APB 已接入实际 raw pre/post 被动观察、严格 ABI/tap 验证和生产 Runner；默认 v1、CPU physical-only保持。软件集成203 passed（107.51秒），独立30 passed。新实际 RFuzz 3/3 complete，可信 fresh replay 6443events完全匹配；GPIO A／B请求、接受、响应各3／4，33条context candidate，novelty／energy1。单worker complete76.15秒、峰547,876,864 bytes，22source SHA；独立产物审计通过。CPU bus协议与完整Stage2功能反馈仍待实现，D8及D5／D6、E–I不勾选。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)及[门禁摘要](../../runs/stage2-d8-native-apb-cli-20261011-r2/summary.json)。

D8 协议基础覆盖与 coverage_context 已接入生产候选反馈：actual v2 protocol projector／checker配置在case命令前冻结核对，多实例上下文带component／instance／feature身份，只由base consumer的新观察产生，保持候选预算与拒绝授权。三模块110 passed、独立110 passed；十七模块最终375 passed／1 deselected／207 subtests（78.51秒）。新真实物理context门禁实际RFuzz 3/3 complete，15条context candidate、novelty／energy1，可信CLI重放完整6422events相等；singleworker complete69.25秒、峰549,531,648 bytes，20source SHA／13artifact核对。generic协议只有软件raw→真实Runner投影／fresh replay；native Ibex／GPIO尚无bus protocol trace，不授真实协议或完整功能验收。下一步真实协议观察与完整Stage2功能反馈，D8及D5／D6、E–I保持原未完成范围。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)及[门禁摘要](../../runs/stage2-d8-coverage-context-cli-20261011/summary.json)。下方为各自冻结源码的历史进度。

D8 可信候选计分重放 CLI 已接入并通过真实短门禁：`replay-candidates` 先验证闭集 assembly 与固定本地组合，fresh executor 从 raw 重算选择、weights、逐例计分和终态，不载入保存 scores。GPIO v2 身份重建丢 tuning 的拒绝缺口及两处 cleanup 覆盖原异常已修复；最终六模块137 passed／55 subtests（49.87秒）。新 r2 实际 RFuzz CLI 3/3 complete，可信 replay CLI 的6,422事件完整匹配，novelty1／energy1；单worker complete70.81秒、峰526,372,864 bytes，十四source SHA／十三artifact与压缩语义已核对，首轮失败保留。下一步 protocol／coverage_context 与完整Stage2功能反馈，D8及D5／D6、E–I原未完成范围保持。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)及[门禁摘要](../../runs/stage2-d8-candidate-selector-cli-20261011-r2/summary.json)。下方记录属于各自历史源码版本。

D8 已补实际出口别名与显式子切片，online builder在候选开关开启时选择native v2观察；关闭时保留旧路径。profile映射漂移及stateful checker身份问题均有负例修复，十四模块296 passed／1 deselected／207 subtests（63.35秒）。当前源码资源监督run CLI实际RFuzz 3/3 complete，fresh RTL从raw重算选择／weights／候选计分，6,422事件完整trace匹配，novelty1／energy1，单worker complete61.46秒、峰528,175,104 bytes；十二source SHA、生产bundle、fresh状态及逐例预算已核对。首轮和r2／r3脚本失败保留。尚缺可信scoring replay CLI selector、protocol／coverage_context与完整Stage2功能反馈，D8及D5／D6、E–I保持未完成。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 原生 v2 观察已接入 planner／renderer／factory／Runner：显式 `physical_observations=True`，闭集 raw pre/post 政策、实际 exports 摘要、CPU stream 校验，默认仍 v1；失败缓存及 kind 篡改旁路两处 P2 已补 RED 修复。29项新增检查，十一模块189 passed／1 skipped／1 deselected／138 subtests（48.17秒），独立软件36 passed。修复后 actual CPU／GPIO 各两个fresh进程、6步含reset，raw各12条／base12及64条全匹配；单worker complete34.18秒、峰470,245,376 bytes，六source SHA及原始摘要已核对。范围仅native receipts→base投影，不含生产journal／candidate计分／RFuzz；下一步port alias／切片、online builder和可信CLI重放，D8及D5／D6、E–I未完成项保持。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 CPU raw drain：默认关闭、receipt复制、FIFO256／命令前容量拒绝，begin/reset拒绝不删样本；13项新增、九模块115 passed／1 skipped／31 subtests，独立软件22 passed／1 skipped。actualCPU两个fresh进程11rawsamples一致、reset后ticks连续，资源complete24.82秒峰469MB；仅CPU原始出口，无候选计分／RFuzz／v2／整链。D8继续未完成，见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 实际组合观察审计：三个组件v1／无base/raw schema，CPU无drain、GPIO已有drain，八个physical声明无exact export匹配；无进程、六项源码摘要已核对。已明确下一步需补实际port／alias／切片与原始观察契约，非仅放宽白名单。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 run CLI／assembly opt-in：默认关闭／容量校验，实际预检在begin前、warmup后新建计分executor；actual旧Ibex组合不支持v2出口时预启动拒绝，构造失败cleanup已修复。新增10项，十一模块192 passed／76 subtests，独立38 passed，无新RTL／客户端。支持组合完整CLI运行、scoring replay selector及实际门禁仍待完成，D8未勾选。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 fresh scoring replay：新 actual executor 从 raw inputs 重算每例 source／weights／候选预算和完整终态／plan／trace，不导入保存状态；actual checker 漂移、bool/int 配置漏检及例间 reset barrier 缺口已修复。新增21项 replay＋4项生产 reset，十六模块284 passed／4 skipped／9 subtests；只读复核最终69 passed／2 subtests。仅软件验证，无新RTL／实际客户端；下一步实际 selector／CLI、完整反馈及 DUT 门禁，D8未勾选。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 生产 executor与保存配置：实际声明物理路径自动预检／映射、逐例候选预算接入decode_candidate排序，保持默认关闭；projector漂移和配置bool/int等价漏检RED已修复，分类反馈／source SHA进入run身份。新增21项，十二模块220 passed／4 skipped／9 subtests；修复只读复核48 passed／2 subtests，无新RTL／实际客户端。CLI／fresh scoring replay／完整功能反馈及真实RTL未验收，D8保持未完成。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D8 首步预算层：默认关闭、每case最多1 novelty／energy、10%上限、session去重、饱和／幂等／容量拒绝；新增22项，五模块121 passed，独立复核82 passed，无新RTL。生产合法性预检／executor／CLI／replay identity未接入，D8未完成。见 [D8执行进度](stage2-d8-candidate-exploration-progress-20261011.md)。

D7 八类负例的软件门禁通过：补齐重传、同ID晚到冲突与消费先于接纳，新增13项；十二模块333 passed，独立复核171 passed，无重要缺口。未运行新RTL，不授实际DUT／其他D6 active／后续H门禁；D8生产候选探索仍待实施。见 [D7负例验收矩阵](stage2-d7-negative-gate-20261011.md)。

D6 GPIO register／sync global reset失效与双重确认修复：新增17项、九模块231 passed，独立软件复核97 passed；warm／cold标签两组nativeGPIO reset各50events新进程重建匹配，旧历史保留／新epoch资源重建，资源complete10.33秒，保存journal软件reload通过。独立产物复核通过（源／271项build inputs、reset／证书一致）；两组同一native reset，不证明Runner策略差异、CPU／RFuzz／online verified文件或active prerequisites。见 [D6进度](stage2-d6-authority-lifecycle-progress-20261011.md)。

D6 统一查询接口首步：history 数量与当前 RAM／slot 资格分离，逐次重算；无 provider 明确 unknown。19 项定向通过，启动原子性与 consumer 漂移 RED 修复；七模块最终回归 120 passed（45.24 秒），只读复核独立 46 passed，无新增重要问题，无新 RTL。见 [D6 lifecycle 查询进度](stage2-d6-authority-lifecycle-progress-20261011.md)。

D6 两类reset verified文件重放通过：非空结果槽binding、schema14reset时间线、1,455／1,587events matches true，历史证书保留／active撤销；独立生产verifier／selector及产物复核通过，资源监督complete。固定admission、未执行RFuzz客户端。见 [reset文件重放进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D6 新增authority内部登记漂移负例及快照校验：6项RED旧writer误授已修复，三模块64 passed（45.74秒），只读复核独立16 passed（12.60秒）、无新增重要问题，无新RTL。见 [D6 lifecycle进度](stage2-d6-authority-lifecycle-progress-20261011.md)。

D6 固定实际commit/read authority实例，漂移永久撤销RAM／slot资格且历史保留；新增5项实际软件检查，联合93 passed（51.66秒），只读复核通过：独立58 passed（46.27秒），无新增重要问题，无新RTL。见 [authority lifecycle进度](stage2-d6-authority-lifecycle-progress-20261011.md)。

D6 schema14／15已保存Session reset时间线；两类真实reset fresh RTL replay匹配，未记录／部分失败reset拒绝保存，replay异常清理已补负例。联合软件41 passed／5 subtests，只读复核通过：独立28 passed／2 subtests，reset时间线及产物一致；通用lifecycle未完成。见 [reset保存与失效进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D6 两类真实RTL reset失效通过：4条历史证书保持、旧RAM与slot资格撤销、保存历史不能复活，命令前拒绝。资源监督complete、21项软件检查通过，只读复核通过：实际reset、generation、历史证书及trace摘要一致；reset replay未实现。见 [失效进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D6 实际同值覆盖写使旧 RAM 前置状态失效：真实 Session 命令前拒绝，历史 commit 保留，两 STORE 的1,468 events fresh replay匹配，资源监督 complete。只读复核通过：实际两次 STORE 的 commit 摘要、版本和值一致；拒绝尝试未入 replay plan，通用 lifecycle 未完成。见 [replay 与失效进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 非空 RAM binding 的生产 verified 文件 replay 已通过：两例、1,454 events、新建 RTL matches true，7 项 artifact identity，资源单 worker complete；固定 admission、未运行 RFuzz 客户端，产物复核通过：生产 verifier／selector、7 项摘要和 STORE 绑定一致。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 完整可信 CLI／RFuzz 3 inputs complete、1,763 events，生产 verified bundle 文件 replay matches true，资源监督正常。三例无 RAM binding，不作为动态绑定文件 replay 验收；产物只读复核通过：生产 verifier／selector、11 项摘要及 semantic hash 一致。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 结果槽 STORE→LOAD 可信 binding 的真实 RTL 短链已产生：schema 12 两例、1,454 events fresh RTL replay 匹配，正确事件数组导出；固定生产 admission 链，未覆盖自适应 RFuzz／verified bundle 文件 replay。资源监督 complete，产物只读复核通过：plan／semantic hash、连续事件及实际 STORE lane 绑定一致。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 可信模式首轮真实 RTL：2 case、1,478 events fresh replay 匹配；单 worker 38.35 秒、峰值 RSS 508 MB。但输入选中 GPIO MMIO、无动态 RAM binding，辅助 trace 导出格式需修正，不作为完整保存／binding 验收。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 Ibex run CLI 已暴露默认关闭的可信 RAM opt-in；缺 commit 在构建前拒绝。新增 3 项，联合兼容回归 26 passed／7 subtests（14.80 秒），只读复核独立 3 passed、无重要问题，无新 RTL。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 schema 13 已补实际部分写入后的失败边界检查；replay 清理失败不再覆盖实际 admission 拒绝。联合软件回归 72 passed／5 subtests（5.08 秒），只读复核独立 10 passed、无新增重要问题，无新 RTL；真实在线执行仍待验收。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 Session schema 12／13 与逐例 replay 注册已接入；声明启动前预检，实际 authority 决策逐例重算，factory provenance 复用现有 authorities。启动冲突及部分安装负例已修复，联合软件回归 63 passed／3 subtests（5.13 秒）；修复只读复核独立 36 passed、无新增重要问题，无新 RTL，D5 未完成。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 gate 每例声明保存／重算 API 已加入工作区，新增 5 项实际 factory／callback 检查；联合回归 46 passed（19.57 秒），只读复核独立 5 passed、无重要误授路径。Session plan schema／逐例 replay 尚未接入。见 [replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 saved trusted factory 配置选择已接 replay，verified manifest／完整策略／读写 authority 精确检查；定向 12 passed、只读复核通过，扩大回归 37 passed／3 subtests（25.60 秒）。逐例 replay 注册／binding 重算仍待后续。见 [保存与 replay 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

D5 factory 结果槽动态 admission 与绑定决策记录已衔接，联合软件回归 96 passed（41.14 秒），只读复核独立 28 passed、未发现重要缺陷；可信 gate 保存及 replay 仍未完成。见 [动态绑定进度](stage2-d5-live-memory-binding-progress-20261011.md)。

D5 新增仅从 actual authority／当前 cell 取得 STORE provenance 的动态 RAM binder；10 项新增检查，P2 修复后联合 75 passed，修复只读复核独立 75 passed，无新增重要问题，factory admission／replay 尚待衔接。见 [动态绑定进度](stage2-d5-live-memory-binding-progress-20261011.md)。

D5 固定辅助指令注册已衔接 executor admission，精确 fragment 与实际 slot 均检查；联合软件回归 83 passed（45.64 秒），只读复核通过。动态 RAM binding／完整在线执行／replay 待后续。见 [slot／factory 进度](stage2-d5-live-slot-policy-progress-20261011.md)。

D5 slot／factory opt-in 已加入工作区，generation 恢复授权缺陷已修复并复核；本轮联合回归 66 passed（41.71 秒），只读复核通过（独立 6 passed），完整在线流程尚未完成。见 [slot／factory 进度](stage2-d5-live-slot-policy-progress-20261011.md)。

D5 可信 RAM 前置状态已接入 Runner／Session，21 项新增、324 passed／25 subtests；后安装 gate 与辅助指令遗漏负例已修复并复核。D5 保持未勾选，在线 factory／默认 slot gate 组合和 D6 通用生命周期待后续。见 [可信前置状态报告](stage2-d5-live-memory-prerequisites-progress-20261011.md)。

D5 IRQ Runner 历史入口已接通，启动预检及身份配置、完整 journal、RAM／IRQ 共存，新增 12 项检查、联合定向 115 passed、兼容回归 272 passed／4 subtests、只读复核通过；仍不授 active prerequisite。见 [IRQ Runner 报告](stage2-d5-irq-runner-progress-20261011.md)。

D5 RAM Runner 衔接已完成软件范围：实际 callback drain／连续 journal／身份配置，新增 14 项检查、最终兼容回归 201 passed／4 subtests；第三方消费者延迟退休导致重复分发的问题已修复并只读复核。IRQ Runner 现已衔接，可信 RAM 前置状态现已接入，在线组合与 D6 通用生命周期待后续。见 [Runner 报告](stage2-d5-memory-runner-progress-20261011.md)。

D5 实际 authority 有界一次性多消费者接口已准备，RAM 历史消费者可独立领取；新增 12 项检查、联合回归 91 passed、只读复核通过。RAM Runner 已衔接，IRQ Runner 现已衔接，可信 RAM 前置状态现已接入，在线组合尚未完成。见 [分发进度](stage2-d5-authority-distribution-progress-20261011.md)。

D5 IRQ 三类历史范围已分别入台账及统一 ingest，新增 24 项检查、联合定向 36 passed、最终兼容回归 297 passed；reset_barrier 与 serial 冲突负例通过。仅明确配置的 native UART／Ibex provider，不授 IRQ 原因、ISR 或 active prerequisite。见 [D5 IRQ 报告](stage2-d5-irq-evidence-progress-20261011.md)。

D5 实际 RAM writer／read snapshot 已接入 D1 历史字节台账及统一 ingest，28 项定向、305 项兼容回归及 18 项子检查通过；IRQ 历史范围已衔接；生产分发及 active prerequisite 仍待后续。见 [D5 RAM 证据报告](stage2-d5-memory-evidence-progress-20261011.md)。

D5 实施中：RAM prerequisite 首步修复完整 byte-enable／span／版本校验，18 项新增软件检查通过，最新软件回归 110 passed／7 subtests，首版兼容回归 145 passed／7 subtests；read snapshot／IRQ 历史范围已衔接；生产前置状态及 active 生命周期未完成。见 [D5 进度报告](stage2-d5-ram-witness-progress-20261011.md)。

D4 最新扩大兼容回归 515 passed、218 subtests passed；D4 80 项定向加 B2 预检共 99 passed。证明范围仅软件消费者及冻结 trace 复算。

D4 已按软件范围完成：统一 ingest、L2／L3 精确范围、既有 profile／sidecar 能力接口和统一派生投影已衔接；SET／CLR 不授 direct-write，内部消费不授 completion。下一项 D5，D6 active witness 和真实 DUT 门禁仍未完成。见 [D4 衔接报告](stage2-d4-capability-events-20261011.md)及[版本／消费报告](stage2-d4-register-progress-20261011.md)。

D3 已按软件范围完成：通用显式 binding 的 raw producer→精确交付→实际 input sample，以及 APB3／TL-UL／Wishbone request→accept→response 已复用既有逐边／来源消费者和 C3/C5 认证；协议证书进入 D1 台账，仅授历史协议边界 scope。联合定向 97 passed，兼容回归 378 passed、218 subtests passed；只读复核通过。D4 已完成软件范围，下一项 D5 RAM／IRQ 精确证明范围；D6 active 生命周期和真实 CPU/IP／HMAC 门禁仍未完成。见 [D3 协议证据报告](stage2-d3-protocol-evidence-20261011.md)和[绑定报告](stage2-d3-binding-progress-20261011.md)。

D2 已完成有限特征、有界窗口的基础事件／覆盖候选发现；最终回归 190 passed、218 subtests passed。候选只供探索建议；D3 已新增独立的基础精确认证，候选生产接入及调度能量仍待 D8。见 [D2 验收报告](stage2-d2-bounded-candidates-20261011.md)。

D1 已完成三类依赖记录的不可变 API、分类报告及保存重载；27 项定向测试；与 D2 合并的 190 项兼容回归通过。格式合法不代表运行证明，不授 prerequisite；D3 协议消费者已接入分类台账，active witness 仍待 D6。见 [D1 记录契约报告](stage2-d1-evidence-categories-20261011.md)。

C7 新增无功能消费者导入、新旧 case 精确请求／交付／采样关联和基础覆盖不变检查；79 项测试、67 项子检查通过。同步修复 direct elaboration 的 Git 源锁漏检。证明范围及失败记录见 [C7 验收报告](stage2-c7-plugin-free-fixtures-20261011.md)。真实 DUT／功能矩阵仍待验收。

第二阶段当前为 M0 基线、B1–B6、C1–C7 已完成，M1 软件门禁通过，D1–D4 已完成（软件范围），下一项 D5 RAM／IRQ 精确证明范围；暂无 Stage 2 CPU/IP 生产运行器或 DUT 矩阵授级。见 [B2 等级与缺口报告](stage2-b2-capability-levels-20261010.md)、[B3 接口预检报告](stage2-b3-interface-preflight-20261010.md)、[B4 等级语义报告](stage2-b4-level-semantics-20261010.md)、[B5 executor 选择报告](stage2-b5-executor-selection-20261010.md)、[B6 负例报告](stage2-b6-negative-contracts-20261010.md)、[C1–C2 基础事件报告](stage2-c1-base-events-20261010.md)、[C3 协议事务事件报告](stage2-c3-protocol-base-events-20261010.md)、[C4 输入采样与绑定交付报告](stage2-c4-input-sampling-20261010.md)、[C5 通用协议 Checker 报告](stage2-c5-protocol-checker-20261010.md)、[C6 基础覆盖报告](stage2-c6-base-coverage-20261010.md)、[M0/B1 基线进度](stage2-m0-baseline-progress-20261009.md)、[起点机器身份](stage2-baseline-20261009.json)及[逐行矩阵](../STAGE2_ACCEPTANCE_MATRIX.md)。

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
先看 [当前工作进度](../CURRENT_PROGRESS.md)，再按下表查对应范围的验收报告。设计见 [当前设计](../CURRENT_DESIGN.md)，待办见 [计划索引](../superpowers/plans/README.md)。

第一步 P1–P5 的命令、原始运行目录和本次只读复核结果集中在[复现手册](../reproduction/first-step-p1-p5-20261008.md)。阶段验收原报告依次为 [P1](current-dataflow-p1-cli-identity-20261006.md)、[P2](current-dataflow-p2-stage-acceptance-20261007.md)、[P3](current-dataflow-p3-stage-acceptance-20261007.md)、[P4](current-dataflow-p4-stage-acceptance-20261008.md)、[P5](current-dataflow-p5-stage-acceptance-20261008.md)。

当前代码与历史路线的目录归类、文档矛盾和未修复缺陷见[代码与文档核对](../reproduction/first-step-code-doc-audit-20261008.md)。

报告按写作时的源码、配置和工具链身份解释。下面列出与当前独立 harness、连续 testcase 和跨组件数据流直接相关的证据；旧完整 SoC 对照报告仍保留原路径。

| 主题 | 报告 | 可证明的范围 |
|---|---|---|
| 第二阶段 D5 可信 RAM 前置状态 | [可信 gate 衔接](stage2-d5-live-memory-prerequisites-progress-20261011.md) | 实际 retained writer＋当前 cell；21 项新增、324 项回归及 25 项子检查；在线 factory／通用 lifecycle 未完成 |
| 第二阶段 D5 IRQ Runner 入口 | [IRQ Runner 衔接](stage2-d5-irq-runner-progress-20261011.md) | 完整 journal／精确 native binding 预检／身份；12 项新增、272 项回归及 4 项子检查；不授 active prerequisite |
| 第二阶段 D5 RAM Runner 分发 | [Runner 衔接](stage2-d5-memory-runner-progress-20261011.md)、[authority 接口](stage2-d5-authority-distribution-progress-20261011.md) | 私有一次性 view／实际 callback／连续 journal／启动身份；14 项新增、201 项回归及 4 项子检查；不授 active prerequisite |
| 第二阶段 D5 IRQ 历史证据 | [IRQ 范围分类](stage2-d5-irq-evidence-progress-20261011.md) | 交付／接受／精确 serial 退休独立 scope；新增 24 项，不授 IRQ 原因、ISR 效果或 active prerequisite |
| 第二阶段 D5 RAM 历史字节证据 | [RAM 证据衔接](stage2-d5-memory-evidence-progress-20261011.md)、[prerequisite 校验](stage2-d5-ram-witness-progress-20261011.md) | 实际 host callback token／逐 byte writer→read；28 项定向、305 项兼容回归，不授 active prerequisite；RAM Runner 现已衔接 |
| 第二阶段 D4 语义证据 | [能力与派生衔接](stage2-d4-capability-events-20261011.md)、[版本／内部消费](stage2-d4-register-progress-20261011.md) | 80 项 D4 定向、515 项兼容回归；范围和访问路径精确过滤，不授实际 IP 等级或 prerequisite |
| 第二阶段 D3 精确基础依赖 | [协议证据](stage2-d3-protocol-evidence-20261011.md)、[绑定证据](stage2-d3-binding-progress-20261011.md) | 97 项联合定向、378 项兼容回归；生产 Runner 跨 case 软件 fixture；不授功能／active prerequisite，真实门禁及 D6 未完成 |
| 第二阶段 C7 无插件 fixtures | [基础路径软件验收](stage2-c7-plugin-free-fixtures-20261011.md) | 三协议合法／非法事务、stall/error/reset、迟到／重复、跨例消费、功能消费者禁止导入及基础覆盖不变；不授 DUT 等级 |
| 第二阶段 D1 三类记录 | [不可变证据分类与存储](stage2-d1-evidence-categories-20261011.md) | declared/candidate/verified 分组与引用、摘要、scope/epoch 校验；格式合法不认证运行事实 |
| 第二阶段 D2 候选发现 | [有界实测事件及基础覆盖相关性](stage2-d2-bounded-candidates-20261011.md) | 精确端口切片、实际覆盖上下文、有界详情／窗口／特征及 session 去重；不授 prerequisite 或修改拓扑 |
| 第二阶段 C3 协议事务基础事件 | [原生身份、握手、等待、超时与取消](stage2-c3-protocol-base-events-20261010.md) | 通用 v2 APB3／TL-UL／Wishbone 生成协议 tap 与 `ip_base_event.v1` 请求／接纳／响应／错误／等待投影；TL-UL 保留 source ID，APB3／Wishbone 明示无原生 key；真实 target RTL 测试仍跳过 |
| 第二阶段 C4 输入采样与绑定交付 | [Profile 物理输入／输出、交付值与 reset epoch](stage2-c4-input-sampling-20261010.md) | 按 runtime export 记录任意命名物理信号及变化，绑定交付由显式 binding 产生；只有目标同 epoch 的实测 pre-edge 输入匹配交付值才产生 `input_sample`；不主张真实 DUT 结果 |
| 第二阶段 C5 通用协议 Checker | [握手、关联、mask 与等待预算检查](stage2-c5-protocol-checker-20261010.md) | Runner 对声明的 APB3／TL-UL／Wishbone pre-edge trace 记录协议违规并使运行失败；不判未知 IP 的寄存器语义，真实 target RTL 仍跳过 |
| 第二阶段 C6 基础覆盖 | [有界、按游标增量消费的基础覆盖](stage2-c6-base-coverage-20261010.md) | 事务类型／响应／接纳后延迟、完整声明切片变化和实际目标位；计数饱和、pending 有界、快照独立标记为 `base_coverage`；standalone utility，未授 DUT 等级 |
| 第二阶段 C1–C2 基础事件 | [`ip_base_event.v1` 采样／变化投影](stage2-c1-base-events-20261010.md) | 新生成通用 APB3／TL-UL／Wishbone v2 artifact 的 raw 样本可投影为 profile 端口采样／变化事件，引用原始事件且不改其字段；不含协议事务 Checker 或真实 DUT 新结果 |
| 第二阶段 B6 拒绝负例 | [等级、接口与 ownership 拒绝边界](stage2-b6-negative-contracts-20261010.md) | 缺功能契约降级、最低等级与未知协议拒绝、bound 输入不可 fuzz、端口缺失拒绝、`DONE` 名称不推断 completion；不代表未知 DUT 已运行 |
| 第二阶段 B5 通用 executor 选择 | [协议／请求驱动的基础执行器](stage2-b5-executor-selection-20261010.md) | v2 APB3／TL-UL／Wishbone 基础路径按 schema 与协议契约选通用 executor；旧 v1 专用执行器、GPIO 因果探针和 UART FIFO 源观察保持显式合同；无 Stage 2 生产 runner/HMAC DUT 结果 |
| 第二阶段 B4 等级语义 | [字段级 L2 规则与 L3 观察需求](stage2-b4-level-semantics-20261010.md) | 无插件 L1、字段权限/mask/副作用规则、L3 provider/操作/观察映射契约及有效／验证门槛；无生产 runner/DUT 授级 |
| 第二阶段 B3 接口预检 | [端口、时钟复位、MMIO aperture 与 ownership](stage2-b3-interface-preflight-20261010.md) | 必需端口／方向／宽度绑定、标量 clock/reset、固定地址边界与重叠、逐位端口映射和输入 driver、已实现协议子集；不包含生产 runner/DUT 结果 |
| 第二阶段 B2 能力等级与缺口 | [declared／effective／verified 解析](stage2-b2-capability-levels-20261010.md) | L1/L2 分级、字段级读写 scope、profile/sidecar 绑定、最低等级拒绝与部分证据缺口；无生产 runner/DUT 授级 |
| 连续场景基线 | [Ibex＋双 OpenTitan GPIO 阶段验收](persistent-scenario-acceptance-20260927.md) | 已列固定组合的状态、约束、重放和受限 G4 搜索 |
| 当前重点闭环 | [Ibex＋双 PULP GPIO](generated-ibex-two-pulp-gpio-acceptance-20261005.md) | 真实双向传播与定向 600 秒搜索；不等于通用 RFuzz coverage 搜索 |
| 在线多轮 | [Ibex＋PULP GPIO 在线 batch](generated-ibex-pulp-gpio-online-batch-20261005.md) | 同一 testcase 三轮持续输入与重放；RFuzz live FIFO 尚未统一 |
| 在线 RFuzz 双侧搜索 | [Ibex＋双 PULP GPIO](ibex-pulp-online-rfuzz-smoke-20261006.md) | 120 例短跑、1000 例连续搜索、真实 IRQ taken 观测、受控断言与完整前缀 fresh replay；十分钟吞吐仍待验收 |
| 异构 IP 在线试点 | [Ibex＋OpenTitan UART](ibex-opentitan-uart-online-rfuzz-20261006.md) | CPU 指令与 UART RX 双源、12 例真实 RFuzz、定向 CPU TXDATA 写及 fresh replay；局部调度吞吐仍低 |
| P1 CLI、能力查询与身份进度 | [统一 CLI 与运行身份](current-dataflow-p1-cli-identity-20261006.md) | 统一入口、能力文档查询、标准/fresh/live/continuous 身份、异常终结、模板声明与 campaign 门禁通过；continuous replay 的搜索策略/累计 verdict 不在验证范围 |
| P2 受控 UART 入口与退休读取 | [v2 入口／RDATA read 与容量边界](current-dataflow-p2-controlled-entry-read-20261006.md) | 隔离快照 2048 版本为 4/4/4、零屏障、48,323 事件完整 fresh 一致，8 项／8 子检查通过；旧 256 容量失败及其他源码版本分别保留，仅证明快照的受控 UART 子路径 |
| P3 UART Store→host RAM byte | [冻结源码真实门禁](current-dataflow-p3-store-real-gate-20261007.md) | 新 StoreMemoryJoin 快照 4/4 例、27,031 事件、2 条低字节 writer 来源 accepted，完整 fresh replay 一致；高位、RTL RAM、后续读及整阶段仍未验收 |
| P3 UART→host RAM→退休 Load | [读回真实短门禁](current-dataflow-p3-host-ram-readback-real-gate-20261007.md) | 独立快照 4/4 例、27,068 事件、1 条跨逻辑例低字节读回证书 accepted，完整 fresh replay 一致；通用跨例和 RTL RAM 未验收 |
| P3 当前代码时期读回回归 | [独立冻结快照短门禁](current-dataflow-p3-current-tree-readback-20261007.md) | 4/4 例、27,068 事件、Store 低字节与后续退休 Load 证书，完整 fresh replay 一致；并行编辑导致的主树身份漂移失败不计验收 |
| P3 长会话时长截止 | [多 slot buffer 预算修复与真实短门禁](current-dataflow-p3-live-duration-buffer-20261007.md) | 原 180 秒运行被整批处理延长并中断；逐 slot 截止后 3/3 例、36,669 事件与完整 fresh replay，通过预算约束短门禁；256 writer 长跑仍缺 |
| P3 长会话 read 发行与指令容量 | [重复 token 根因、600秒压力运行与 UART 列表释放](current-dataflow-p3-read-issuance-capacity-20261007.md) | 旧失败 trace 49,572 issuance 仅 41 个唯一完整 key；review 快照 76/76 例、535,269 事件及完整 fresh replay，跨旧 fetch 容量点、零重复 read issuance；后续独立快照释放已归档 UART 生产者列表，4/4 真实例与完整 replay 通过，受控 1000 条内存测量证实列表不再累积；256 writer 与新版长跑 RSS 仍缺 |
| P3 readback writer 历史 | [有证据回收与容量门禁](current-dataflow-p3-readback-history-20261007.md) | 300 次实际 MemoryService callback 周转不超 256 容量、82 项软件检查；新源码 4/4 RTL 短回归与完整 replay 通过，真实长跑回收仍缺 |
| P3 定向真实 writer 超 256 | [持续会话 271 个 writer 门禁](current-dataflow-p3-directed-writer-capacity-20261007.md) | 独立快照 270 条在线 `sw` 加 ISR 写入，271 个不同的受限低字节 writer 证书，29,174 事件完整 fresh replay；第 257 条之后的退休 `lw` 读回未验证 |
| P3 超 256 writer 后读回 | [最后 writer 版本到退休 `lw` 门禁](current-dataflow-p3-late-readback-capacity-20261007.md) | 新冻结快照 271 个不同 accepted writer，最后版本 `[0,282]` 经真实 RAM read/response 和 RVFI `lw` 退休读回，29,401 事件完整 fresh replay；仅限受控 host RAM 低字节 |
| P3 Store→RAM 实施前审查 | [旧join缺口与验收要求](current-dataflow-p3-uart-store-memory-20261007.md) | 记录旧 late-commit 生命周期缺口及新实现的前置要求；实际结果以冻结源码真实门禁为准 |
| P3 host RAM 提交凭据生产者 | [MemoryService commit receipt](current-dataflow-p3-memory-commit-producer-20261006.md) | 该早期报告的冻结源码软件134项／26子检查、独立86项／11子检查验证完整key、版本、BE0、重复提交和uncertain；该报告本身不授予 Store→RAM 来源，后续真实 join 见上行 |
| P3 UART 寄存器版本 seed | [实际退休LW到受限seed](current-dataflow-p3-uart-operand-seed-20261006.md) | 冻结源软件41／43通过；实际online 4 read／4 seed、零UART屏障；fixture／fresh 8项／8子检查通过。fixture不独立验证seed语义，另由raw独立审计验证；后续operand/copy/store与generic ISR仍unknown |
| P3 UART `sw` 源寄存器读取 | [精确旧版本到实际rs2](current-dataflow-p3-uart-operand-use-20261006.md) | 冻结源码软件83项组合通过；48,323事件真实online有4条SW rs2 use、零相关屏障；独立raw fixture 3项／2子检查与完整fresh 8项／8子检查通过。仅证明该次操作数低8位来源，RAM commit/整字Store/通用ISR仍unknown |
| A2 静态 MMIO 输入约束 | [窗口权限、写宽度与合法变异](current-dataflow-a2-mmio-permissions-20261006.md) | 生成前拒绝静态只读写入／只写读取或不支持的 `SB/SW` 宽度，变异只选择有合法对齐槽的窗口；`SB` 的真实 CPU/Router 路径未由这些单元测试证明 |
| P4 UART WDATA lane 0 字节写 | [Ibex `SB` 到真实 UART 输出短门禁](current-dataflow-p4-sb-uart-byte-real-gate-20261007.md) | 独立快照 9/9 例、63,830 事件，唯一 `SB` 的 RVFI 退休、同事务 `be=1` 投递与实际串口字节相符，完整 fresh replay；范围限于 opt-in 单地址单候选 |
| P4 CPU 计算到 UART 写入 | [冻结 trace 的受限架构审计](current-dataflow-p4-computed-uart-store-audit-20261007.md) | 同一真实 trace 核对连续 `LUI→ADDI→LUI→SB` 的 x2 计算/读取、同键字节投递与串口输出；是架构关联，缺内部硬件来源 token |
| P3 在线 slot 重传 | [原回执补交与去重](current-dataflow-p3-slot-receipt-retry-20261006.md) | sink 失败后按原 slot 补交回执，不重复执行 RTL；27 项定向测试，完整长会话验收仍待完成 |
| P3 在线取指槽先决条件 | [shipped 策略与跨例见证（软件门禁）](current-dataflow-p3-online-slot-prerequisites-20261007.md) | Ibex＋双 PULP GPIO 在线路径默认挂载 `InstructionSlotReservationGate`：按例声明自身取指槽仍未物化、惰性登记（窗口 0x11000..0x2fe00＝31616 字上界，不预登记）、真实 `instruction_source` 物化后同槽用例在任何 RTL 命令前被拒；未跑真实 RTL |
| P4 路径先选与 flow 身份 | [在线路径选择及决策元数据](current-dataflow-p4-online-path-selection-20261007.md) | 先选择可执行路径再选其合法源；真实 GPIO/UART 工厂声明 F4/F5 主要目标，v3 manifest 与 replay 软件门禁通过；完整反馈搜索未验收 |
| P4 真实反馈短门禁 | [GPIO 新边到后续权重](current-dataflow-p4-feedback-real-gate-20261007.md) | 冻结源码 100/100 例、38,625 事件完整 replay；见证增益进入后续源权重，完整 P4/P5 搜索仍未验收 |
| P4 反馈增益因果对照 | [同前缀同 raw 的真实 RTL 分支](current-dataflow-p4-feedback-causal-branch-20261007.md) | 16 例相同前缀后仅扣除当例增益，使第 17 例同一 raw 改选并实际消费不同源；两支完整 fresh replay 一致 |
| P4 路径选择熵 | [1,000 例真实双侧在线门禁](current-dataflow-p4-path-entropy-real-gate-20261007.md) | 修正固定低字节导致的选路偏置；F4/F5 为 491/509，两侧真实消费与完整 fresh replay 一致；同预算覆盖/故障收益未验收 |
| P4 路径选择同例数对照 | [旧／新选择器各 1,000 例真实 RTL](current-dataflow-p4-path-selector-paired-1000-20261007.md) | 只改路径取模语句；完整 fresh replay 均一致。F4/F5 更均衡且 IRQ 观测增多，4 个目标位及 20 种交互新特征未增长 |
| P4 候选拒绝码 | [35 个分层 `candidate_rejection.v1` 码软件门禁](current-dataflow-p4-rejection-codes-20261007.md) | ISA／字段／片段／MMIO／解码／所有权／槽位／预算／路径分层码，含失败指针与冻结目录摘要；66 项定向测试、226 项兼容回归通过；声明期校验、live 回执接入与真实拒绝例仍未完成 |
| P5 热路径效率 | [在线反馈事件查找剖析与长跑](current-dataflow-p5-efficiency-profile-20261006.md) | 内部事件查找优化；隔离快照 600.979 秒、5,563/5,563 例、2,236,544 事件完整 fresh replay 一致；同源码冷启动 30/30 例、598.988 秒。状态/覆盖不同，完整链效率仍待验收 |
| P5 完整链与覆盖审计 | [冻结 600 秒原始证据复算](current-dataflow-p5-chain-audit-20261007.md) | 4 个本地目标新颖率 0.00665581 位/秒；缺源到 IRQ/MMIO/Store 的关联，严格完整链/秒无法由该记录确定 |
| P5 首步端到端验收入口与严格完整链/s | [带全部探针的有界真实门禁](current-dataflow-p5-chain-acceptance-20261007.md) | 新增增量链证书生产者与流式分析入口；24/24 complete、31.273544 秒得 8 条认证链（5 IP→CPU→IP／3 CPU→IP→CPU）＝0.255807 链/s、4/4 目标位、9 条见证边、逐例 p50/p95 与 11.550 秒终结，独立缓存完整 fresh replay 一致；证书终点不含 ISR 写 GPIO A 之后的回流，且非十分钟门禁 |
| P2 RVFI IRQ serial sideband 身份与构建输入 | [重录身份、sideband 认证与构建缺陷修复](current-dataflow-p2-rvfi-sideband-identity-20261007.md) | 重算 elaborated 内容哈希并重录 profile revision 与 contract 三钉；新增 sideband 显式身份与 closure 交叉核对，修掉 sideband 未进 `authenticated_inputs` 导致的 Verilator 构建失败；lint 重跑 exit 0、聚焦 224 项通过，真实运行以新 wrapper 完成 24/24 与完整 replay；host 侧尚未消费 serial |
| **P2 阶段验收** | [路径、逐边来源与绑定门禁逐条汇总](current-dataflow-p2-stage-acceptance-20261007.md) | 验收门禁在真实 run 上 **exit 0**：两方向 `certified`（CPU 8 边、IP 7 边）、9/9 声明边 certified、叠加持久状态边后 **11/11 certified**；提前 IRQ 有 2 个未被接受的实例（6007/6058、13318/13369）仍写入 trace；6 个声明破坏变体零进程拒绝；同 graph 不同 edge identity 的 replay 双向拒绝（API 级）；边界：无"不同 edge identity"的真实 run 对、`writer_event_ids` 无整数写事件 id、消费依赖目标侧观测字段 |
| P3 IP→CPU→IP 跨例链 | [源 case 单 round 的真实门禁](current-dataflow-p3-ip-cross-case-20261007.md) | 诊断确认绑定两半的是 IP 源 case 的 32-round 预算（case 边界本不清理 pending IRQ）；opt-in 让源 case 只走 1 round 后，真实运行中 `IP_TO_CPU_TO_IP` **3 条跨例链**（gap 全为 1，代表链源 case 2 → 端点 case 3，17 跳含 `cpu_irq_taken` 与 `isr_padin_retirement`），`all_directions_have_cross_case=true`；限制：该模式在本次运行出现 1 次 `unsupported_irq_overrun`，未做长跑稳定性验收 |
| **P3 阶段验收** | [目标动作、持续会话与跨例传播逐条汇总](current-dataflow-p3-stage-acceptance-20261007.md) | 跨 run 套件 **exit 0**：7 项关键验收各至少被一个声明 run 证明——单次初始化（4 run）、`store_then_load`（232 lane 匹配/20 次部分字节使能写/0 误采纳）、`cross_case_chains`（新增 IP→CPU→IP 3 条跨例链，gap=1）、反馈改选、受控故障停止+新进程复现、chunk 切分不变、execution ID 不接受旧回执；边界：无单 run 全项（最高 5/7）、finding 为注入校准、RTL 分块等价半项恒 null |
| P2 持久状态逐边来源 | [RAM 字节版本与 GPIO 寄存器位版本边均 certified](current-dataflow-p2-persistent-state-edges-20261007.md) | 在线契约追加 rule 15/16 两条 `persistent_state` 边（既有边逐字段不变）；真实 trace 上扩展为 **10 certified / 1 incomplete / 0 unknown**：RAM 边按写 `version=[gen,seq]`+`byte_enable` 覆盖与读 lane `versions/writer_kinds` 精确引用连接（引用为写记录自身事务键规范 repr），寄存器边按位行 `version`/`observation_event_id` 全等连接；剩余字段缺口（`writer_event_ids` 无整数写事件 id、无 `commit_id`、初始化无跨度）都在 host 写入器侧，不需要新 RTL 探针 |
| P2 通用逐边来源 | [9 条声明边的 certified/incomplete 实测](current-dataflow-p2-edge-provenance-20261007.md) | 新增按契约声明边统计的 `runtime_edge_provenance.v1` 消费者；真实 run 上 **8/9 边 certified**（6 条 mmio_route 按事务键六字段全等、2 条 IRQ binding 按 `source_event_id` 精确连接）、1 条 `gpio_a→gpio_b` incomplete（缺 consumer）、0 unknown；契约未声明 `persistent_state` 边，故 RAM/寄存器版本逐边来源仍是缺口 |
| P2 IRQ serial 精确来源 token | [host 采集与真实 RTL 精确 join](current-dataflow-p2-irq-serial-token-20261007.md) | 新增 `IrqSerialCertificates`（10 条 fail-closed join 条件、`zero=no_provable_lineage`）；真实运行 24 例得 5 条、600 秒 368 例得 **68 条** `decision_serial == retirement_serial` 证书；仅到 IRQ 决策→RVFI 退休一跳，未接入完整链或 live 回执 |
| P3 正向 RAM 跨例消费 | [Store M[A]=X → 后例 Load 的真实绑定门禁](current-dataflow-p3-ram-cross-case-real-20261007.md) | 结果槽读窗口 + `--memory-commit` 两个 enabler（默认关闭）后，真实 40/40 complete：`policy_matched=1`、`dynamic_binding{requests:1,bound:1,unbound:0,refused:0}`；被绑定 case 的 `ram_byte_version.evidence_ref` **精确等于**更早真实 `memory_write_commit`（event 17567，`ram`/offset 0/`writer_kind=STORE`）的 commit_id，`evaluation.satisfied=true`；绑定只证明"读之前该版本被见证并 pin 住"，Load 返回值语义仍由既有读/退休证据承担 |
| P3 通用源动作与跨例依赖 | [`source_action.v1` 契约与有界跨例见证](current-dataflow-p3-source-actions-20261007.md) | 6 种先决条件、终止观察与预算、严格拒绝（IRQ 不可作可变源）；`ScenarioSession(prerequisite_gate=)` 在 RTL 命令前拒绝且状态零变化；36+8 tests、全量 tests/scenario 1697 passed；**未接线**到 scheduler/live RFuzz |
| P5 受控故障族 | [4 类 9 变体与最小重放配置](current-dataflow-p5-controlled-fault-family-20261007.md) | 只扰动 checker 观测副本，原始 trace 字节不变；每类唯一 finding ID 与完整来源链；真实窗口 6/9 变体校准、其余同形合成；未跑真实 RTL 门禁 |
| P5 受控故障真实校准 | [真实 RTL 捕获 + 新进程复现](current-dataflow-p5-controlled-fault-real-20261007.md) | 保存 trace 选出真实见证后，真实会话第 3 例被 `gpio_b_irq_source_mismatch` 捕获并停止（2 complete + 1 dut_violation）；从 `minimal_replay.json` 在新进程复现同一 finding；控制/故障两份 trace 的 event 4609 逐字段相同，证明只改 checker 副本 |
| P5 受控故障族通用校准运行器 | [9/9 变体见证选择 + 独立复核器（未跑真实 RTL）](current-dataflow-p5-fault-family-calibration-20261007.md) | 新增 `scripts/run_p5_fault_calibration_family.py`（`run`/`--select-only`/`--variant` + `verify`）：9 个变体全部在保存真实事件上选出真实见证（PULP 8 个来自 24 例 paired、UART 1 个来自 uart-gate2），选择器键集合严格等于 `_SPECS` 声明；`observation_irq_level` 的钉住文档 SHA-256 与既有真实校准逐字节一致（`cd753d41…`）；`--select-only` 两跑逐字节相同、6.4 秒、源运行只读（前后指纹一致）；复核器 7 项检查直接重读 receipts/trace 并以 exit 4 拒绝任一不一致；软件测试 21 passed + 18 subtests；真实会话由 root 串行执行 |
| P4 真实拒绝与不确定例 | [定向校准运行的 7 类拒绝 + 1 类不确定](current-dataflow-p4-rejection-calibration-real-20261007.md) | 真实回执 14 条：7 条 `input_invalid` 各带精确 `code`/`pointer`（decode/budget/mmio/ownership 四层）、6 条 complete、1 条 `uncertain_effect`（`rejection=null`）；`verify` 独立复算 exit 0；拒绝均在任何 RTL 命令之前 |
| P4 闭环能量接入 live 选源 | [同 seed 60 秒真实 A/B](current-dataflow-p4-closed-loop-live-ab-20261007.md) | 开关 ON 时 report `closed_loop_enabled=true`、消费 33 张证书、7 条闭环命中，选源向 CPU 指令源偏移（39.0%→51.4%）且逐例序列第 2 例起分叉；两枝 raw 序列不同故为搜索过程对照，且同预算例数 41→35，不声称吞吐提升 |
| P4 CPU 侧门禁可判定化 | [改走 profile 路径让运行自己声明 RVFI opcode 窗口](current-dataflow-p4-cpu-side-gate-decidability-20261008.md) | 路由证据（源码+只读复算）：`examples/soc_generation/request-ibex-pulp-gpio-spi.json` 的 `request_id` 即 `CHECKER_REQUEST_ID`，其 checker profile 的 bit 16（`RVFI.ORDER`）激活 12 位 `rvfi_opcode_coverage_o`，计数器区间 `[228,239]`（11 个已保存 profile 运行一致），正是门禁 `cpu-stimulus` 读的键；legacy 路径不渲染任何 `rvfi_*` 端口（实测 0）故只能作为"报告不改"的备选。驱动 `scripts/run_p4_cpu_side_profile_campaign.py`（21 项测试，`--check-only` 预检不建目录） |
| P4 通用消费端证书 | [声明式设备内部见证登记表（12 类）](current-dataflow-p4-computed-consumer-generic-20261008.md) | 新模块 `computed_consumer_certificate.v1`（43 项测试）：只有全部跳都按精确身份 join 才发证书，否则点名**首个缺失跳/身份**；8 个冻结运行只读复算 **192 认证 / 528 拒绝 / 0 unknown**——`gpio_register_commit` 178、`gpio_apb_access` 4、`uart_tick_observation_access` 8、`uart_serial_observation` 2（含 event 28002 字节 `0x0c` 与 18060 字节 `0x06`）；`spi_transfer`/`timer_tick` 在全部 8 个产物中 0 事件，记 `absent_from_artifact` 而非伪造 0；每条记录带 `proof_scope`/`not_proof_of`（不证寄存器堆 token、设备内部 FIFO 溯源、跨指令依赖或消费逻辑正确性） |
| P4 CPU 侧覆盖映射修复真实生效 | [单 cell 真实运行：CPU 12/64 点亮、0 死计数器，门禁 7/8 INCONCLUSIVE 原因已定位](current-dataflow-p4-cpu-side-branch-coverage-real-20261008.md) | 根因（配额落在未 elaborate 的 `u_ibex_lockstep`/`i_ibex_trvk`）修复后，真实 instrumented 单 cell（300 秒、59,753 测试、两次编译）给出 **CPU `elaborated-lit=12`/64、`unelaborated-bound=0`**（旧 28/28 运行为 64/64 死计数器），IP 18/64，覆盖身份 `verified`（30/128），elaboration 探针排除集/模型摘要/读回完整性全过；唯一 FAIL 是 `cpu-stimulus` 前置（legacy 单 cell 不声明 RVFI opcode 窗口），故门禁 verdict=INCONCLUSIVE，不是映射失败；顺带把覆盖 attestation 读取统一到新旧两种 provenance 形态 |
| P4 `first_seen` 写侧与真实台账 | [每测试计数器回读 → 有界身份绑定台账](current-dataflow-p4-first-seen-real-20261008.md) | 用仿真器**已有的**每测试计数器回读写出 `soc_coverage_first_seen.v1`（不需要改 Rust/harness/协议）；真实单 cell 运行 300 秒／54,157 次 RTL 测试／点亮 30/128，报告 `first_seen.available=true points=30 earliest=bit:21@event:1`，独立交叉复核 exit 0（`points=128 lit=30 readbacks=54157`，台账命中集合 == 计数器非零集合、每条目命名自己的点）；旧产物仍 `available=false`+原因而绝不写 0 |
| **P4 阶段验收（按声明范围）** | [四条清单项与验收口径逐项证据](current-dataflow-p4-stage-acceptance-20261008.md) | 入口 `p4_acceptance_suite.v1` 关键项 **8/8 成立、exit 0**；清单四项均有真实 RTL 证据（路径先选/候选身份、九类合法操作子含序列编辑与初始 RAM、反馈与 CPU 侧内部分支覆盖含 first_seen、energy 与同 seed 基线）；边界：F4/SPI 实例属 P6、本预算下算子无可测收益、CPU 8 点阈值是搜索质量问题、消费端证书不证内部溯源 |
| P4 整阶段验收入口 | [只读串起全部门禁的 `p4_acceptance_suite.v1`](current-dataflow-p4-acceptance-suite-20261008.md) | 新增 `first_seen_ledger` 与 `cpu_side_gate_decidable` 两项后关键项 **8/8 成立、exit 0**（序列编辑两枝、覆盖身份、算子收益对照、slot 不可变性、拒绝码回执），CPU 侧门禁 verdict 以非关键 `partial` 记录原因；48 项 hermetic 测试在编写过程中抓出并修掉 **11 处判据缺陷**（含“空 checks 文档被真空判真”、陈旧产物让失败门禁通过、超时丢弃全部判决、`external_binding` 未纳入等），并保证“未测得绝不算通过” |
| **⚠ 已删除的原始产物（2026-10-09 清理）** | [瘦身说明、已重建项与 83 条断链明细](DELETED_ARTIFACTS_20261009.md) | `runs/` 由 114.75 GB 瘦到 19 GB：删除 99 个无引用目录 + 104 个仅被文档引用的历史目录 + 36 GB 备份 tar + 31.7 GB 构建缓存；保留 68 个被代码/测试引用的目录与 4 个当前 P5 证据目录。**本索引与部分报告中指向已删目录的链接现在是断链**（结论仍有效，复算能力不再有）；`p3-ip-cross-case`、`p3-ram-prereq`、`first-step-reproduction` 已重建，`cv32e40p-pulp-online` 与 `individual-review` 未恢复 |
| **P5 阶段验收（按声明范围）** | [四条清单项与验收口径逐项证据](current-dataflow-p5-stage-acceptance-20261008.md) | 入口 `p5_acceptance_suite.v1` 联合判定关键项 **6/6 成立、exit 0、unmet=[]、no_proving_run=[]**：三类断言分节＋fail-closed 普查（2 run 证明）、受控故障真实捕获＋**新进程复现**（`compare_run` 复现根逐字段一致）、正常对照静默（5 个干净对照，唯一带 finding 的对照就是故障运行自身）、启动前身份拒绝＋完整前缀（2 run）、十分钟 600.362953 秒／27 条认证链／**自然 finding 0 如实记零**＋fresh replay、同预算 16.08× 且链/s 等价如实记“不可测”；边界：**非单 run 通过**（`heterogeneous_uart` 单跑 0/6 被完整报告）、旧联合验收运行上的 UART 路由见证与链证书为 0；后续独立 UART 证书和新运行自身见证另见当前进度、无自然 RTL 缺陷、故障质量/灵敏度未验收、冷组聚合报告无 `session_status` |
| P5 阶段验收入口（独立交付） | [六项关键项的 per-run 判定 + union](current-dataflow-p5-stage-acceptance-entry-20261008.md) | `p5_acceptance_report.v1` + `p5_acceptance_suite.v1`（48 项测试，RED→GREEN）：`met=true` 不可能在 `measured=false` 下出现，角色是显式声明且不匹配会报 `role_evidence.matched=false`，产物解析必须绑定被声明运行（共享证据库只服务自带 run 绑定的产物、schema 不符即跳过、`compare_run` 不能顶替声明运行）；真实联合 6/6、**每 run 最高 3/6**（union 的意义正在此）；边界：异构外设的**十分钟**长会话未做（十分钟项目前只由 GPIO 证明）、受控 finding 是注入校准、27 条链只证产物能力 |
| **P5 异构 UART 真实路由见证与冷组状态** | [从已保存运行读出真实路由表；冷组对照判定修正](current-dataflow-p5-uart-routing-witness-20261008.md) | Gap A：新 `online_source_target_transactions.v1` 记录器接线（执行器 `case_witness_recorder=` 钩子 + 门禁逐候选决策日志），并从**已保存运行**只读推导出真实表——7 例产生真实 UART 读链（`uart-access:uart:0:4/7/11/13/15/17/19`，offset `0x18`），每例 3 条已 join 见证（`uart_fifo_pop` ＋ 被 pop 的 `uart_consumption_match` ＋ 被接受的 `uart_retired_read_match`，`matched.complete=true`）且可回溯到注入该帧的 origin case/action（3 例 UART 侧源／4 例 CPU 侧源）；共 77 条消费见证（21 joined／56 unjoined IRQ-cause+retention）、37 例无见证、3 例拒绝 `null`+原因；门禁 24 例判定（21 采纳＋3 拒绝 `uart-waveform-idle:1832/4456/6296`，prerequisite kind `transport_idle`）、36 例 UART 侧 `not_judged`（门禁只绑 `cpu`）。Gap B：`p5_acceptance` 新增 `DECLARED_SESSION_STATUS_FIELDS`，只在报告缺 `session_status` 键时按 schema 声明的 `execution_status` 取值，显式 `null` 仍拒绝、声明 `complete` 还要求逐例回执全 `complete` 且与 `report.json:statuses` 一致，`paired_cold_start` 因此成为第 5 个干净对照。边界：该路由表是**脚本推导**而非运行自身所写（旧运行 report 无该键），实时证明需要一个新 UART 会话；受影响的 decode-space 源已漂移，旧 bundle 按设计不可再 replay |
| **P5 UART 路由见证实时证明** | [新运行自带 `source_target_transactions` ＋ fresh replay 一致](current-dataflow-p5-uart-routing-witness-20261008.md) | 同 cache／同 seed `20261007`／同预算的新真实会话 `runs/p5-uart-routing-gate-20261008-online`：60 例（57 complete ＋ 3 `input_invalid`，与旧运行逐状态一致）、79.934 有效秒、**fresh replay `matches=true`**，`report.json` **首次自带** `source_target_transactions`（`online_source_target_transactions.v1`）：`cases_with_register_access=7`／`register_accesses=7`／`target_consumption_witnesses=73`／`matched=21`／`unmatched=52`／`cases_without_any_witness=37`／`event_slices_unavailable=3`；门禁决策日志 `{count:24, admitted:21, refused:3, omitted:0}`。只读交叉核对独立推导得 77／21，差异**逐 case 定位**为脚本扫全 trace 多算 bootstrap 例 `uart-fixed-warmup` 的 4 条**未 join** 保留类见证（记录器只覆盖已提交搜索例），两侧 `matched=21`／`register_accesses=7` 一致，链证据不受影响；**并由独立子代理对抗式复核**（自解析 receipts＋自流式读 trace＋自实现 join 与 RV32I 解码，29 条 claim 中 27 条一致、0 条无法核对、2 条不一致）：①"声明式窗口访问 `SB @0x40000002`"是**出货解码器真缺陷**——`fragment_mmio_accesses` 对存储按 I-type 取立即数，把 rs2 折进地址并丢掉 `imm[4:0]`，真实地址是 **`0x4000001c`（UART TXDATA）**；已按 TDD 修复（新增回归用例先回退得 RED `1 failed, 6 passed`，修复后 `7 passed`）并重新生成见证 JSON（`086ed820…`→`006a5a52…`）；②报告原写"6/7 读出值等于注入字节"实为 **7/7**（`online-10` 读的 `0x00` 正是 `online-0` 注入帧），已更正并写明"值为 0 的相等不是消费证据，join 才是" |
| **P5 UART 链路证书（只读生产者）** | [7 条认证链 ＋ 30 条具名首缺跳的 incomplete](current-dataflow-p5-uart-chain-certificates-20261008.md) | 新增 `runtime_uart_chain_certificate.v1`（32 项测试，RED 11 failed/21 passed→GREEN 32 passed；回归 `test_chain_certificates.py` 50 passed）：16 跳声明 DAG（含 `uart_source_frame_end`，因 frame 2 的 IRQ ack 段先于自己的 `frame_end` 故不能按到达顺序约束），逐跳精确 join；对 `runs/p5-uart-waveform-gate-20261008-online` 的 274,782,641 字节／76,332 事件单片 trace 流式扫描得 `candidates_total=37`、**`certified=7`／`incomplete=30`**、首缺跳直方图 `{uart_source_frame_begin: 30}`、`refusals_total=0`（诚实 0，全 trace 读完且无 join 键矛盾）、`duplicates=28`、`skipped=240`、两跑逐字节相同、`semantic_sha256_verified=true`；**边界**：IRQ→CPU 因果不成立为证明（只按 take 的 `source_output_key` 定义把该帧 entry 列为队首归因，无法归因的记为 unresolved 而绝不猜）、polling 不可证故 30 条 incomplete 三项写 `null`+原因、每证书 7 条 `not_proof_of`、`cross_case=true` 只在源/端点 case 确实不同时给出 |
| P5 单臂指标聚合 | [12 个清单分组逐项落到真实臂](current-dataflow-p5-arm-metrics-20261008.md) | `p5_arm_metrics.v1`（32 项测试）：每叶 `{value, source, reason}`，缺失即 `null`+原因绝不写 0；与 `paired_efficiency.compare_runs` **29/29 字段逐位相同**、与 `acceptance_metrics.analyze_run` **10/10 逐位相同**；600 秒臂 0.612963 有效例/s、27 链、0.044973 链/s、无效/超时 0.0；UART 臂 0.662254 有效例/s、无效/超时 0.05；六臂 `router_transact` 全为 0（默认 GPIO 不走同步 Router 事务，是实测 0）；`compare_runs` **拒绝** frozen 对（`continuous=24 cold=15`）；边界：无 RTL 编译计时 artifact 故 `compilation_seconds` 恒 `null`、连续会话无每例初始化归属、分项嵌套不可相加、链数是生产器对产物的能力计数 |
| P4 slot 不可变性全扫描 | [9/9 可判运行 immutable，1 个运行证据缺失被点名](current-dataflow-p4-slot-immutability-sweep-20261008.md) | 只读扫描 10 个运行（含路径切换、初始 RAM、序列编辑、CPU 侧插桩）：**36,985 个 slot 全 immutable、0 violated、0 insufficient**；`runs/p4-cpu-side-coverage-20261008-online` 因既无 `decoder_manifest.json` 也无事件 trace 记 `unavailable`（计数 `null`，绝不并入 immutable）——所谓 10/10 immutable 的说法是错的 |
| P5 臂等价判定 | [共享 raw 窗口内的逐字段等价/不等价/未知](current-dataflow-p5-arm-equivalence-20261008.md) | `arm_equivalence.v1`（26 项测试，流式读、峰值 RSS ≈ 23 MB、两次运行逐字节一致）：5 对真实臂**没有一对** `claimed=true`，三种“不等价”都真实出现——序列编辑对因零共享前缀被**拒绝**、路径切换对 4 族 `not_equivalent`（含同一 raw 却不同 `operator_id`）、初始 RAM 对 3 族 `unknown`（2 例 `input_invalid` 两侧皆 null，绝不当作相等）；明确它只回答“字段是否等价”，不回答“哪一臂搜得更好” |
| P4 内部 RTL 分支覆盖 | [与端口语义命中的分离计数](current-dataflow-p4-rtl-branch-coverage-20261007.md) | 身份校验（插桩器/逐文件/树摘要/manifest 字节/harness 绑定）任一不符即拒绝、绝不降级；扫描 303 个 run 得 **28 个带插桩证据且 28/28 校验通过**，样例 18/128、最好 50/128，端到端链条（RTL 行→插桩文本→manifest 位→真实 `coverage_maxima=64`）闭合；**边界：128 点中 CPU 侧 0/64 从未点亮**，`first_seen` 不可用 |
| P4 计算值到外设消费 | [通用 `computed_value_certificate.v1` 与四份真实 artifact](current-dataflow-p4-computed-value-certificates-20261007.md) | 以 RVFI 退休重算值为起点、同事务键逐跳按**被使能 lane** 比较、终点必须是设备内部见证：真实 run 上 30/33 张认证（GPIO `gpio_register_commit`），并在既有 UART trace 上独立复现 `ADDI→0x0c` 经 MMIO 投递到 `serial_tx_last=0x0c`（event 28002）；未认证链给出精确缺失跳；边界：只证 lane 值同一性，不证寄存器堆 token/跨指令依赖/路由归属 |
| P4 移位操作子与真实退休 | [SLLI/SRLI/SRAI 编码、37 码与新操作退休门禁](current-dataflow-p4-shift-operators-real-20261007.md) | 逐位金标准编码；新增 `field.bad_shamt`/`isa.reserved_imm_bit`（35→37 码，摘要更新）；三次定向真实会话中 SLLI/SRLI 各 1 条被真实取指、退休、`matcher=accepted`、来源指向该例 admission；SRAI 未在真实侧观察到，且被验证实例 rs1=0 |
| P5 十分钟全探针门禁 | [368 例、27 条认证链、68 条 serial 证书](current-dataflow-p5-chain-600s-20261007.md) | 600.362953 秒、368/368 complete、570,196 事件；严格链/s **0.044973**（CPU→IP→CPU 20／IP→CPU→IP 7，跨例 6）；同 trace 复算 68 条 `decision_serial == retirement_serial`；流式分析 55.19 秒 / 58.4 MB，完整 fresh replay 一致 |
| P5 异构外设（OpenTitan UART） | [当前源码栈的多例会话与 lane 语义修复](current-dataflow-p5-uart-heterogeneous-gate-20261007.md) | 修复按 lane 判值的误拒后，7 例中 6 例 complete（含 `rv32i:SLLI`、`rv32i:LUI+ADDI+LUI+SB` TX 字节写与 3 例 UART RX 外部源），完整 fresh replay 一致；第 7 例因"RX 波形进行中的 TL-UL 访问不支持"以 `uncertain_effect` 停机（已知并发限制），异构长会话仍受限 |
| P5 冷组逐例 fresh replay | [冻结源码同源 bundle：15/15 可复现例一致，9 例级联拒绝有精确原因](current-dataflow-p5-cold-group-replay-20261008.md) | 连续枝 24 例（23 complete＋1 `input_invalid`）replay 一致；冷组 15 例发布并**逐例各起独立 RTL 进程 replay，15/15 `matches=true`**；其余 9 例不是独立缺陷——第 15 例是 `source_action_not_constructible` 预 RTL 拒绝例（回执 `effective_genome_sha256=null`），冷组用一个 raw 重放时新解码器能产出候选故 `decode_reproduces_saved_case=false`，此后前缀链不可复现，工具 fail-closed 不发布 plan；对照器因 24≠15 拒绝出结论 |
| P5 同预算配对对照 | [连续会话 vs 逐例冷启动真实 RTL](current-dataflow-p5-paired-continuous-cold-start-20261007.md) | 9 项可比性先决条件全满足；两组 24/24 complete、0 violation、逐例 status/raw/genome/path/断言 24/24 一致；墙钟 31.905 秒对 512.881 秒（含 24×18.736 秒初始化）≈**16.08×**，节省来自免重复初始化；coverage 22/24、ticks 15/24 不同故不声称输出等价；连续组 replay 一致，冷组逐例 replay 未跑 |
| P5 在线例分项计时 | [冻结 GPIO 100 例真实短门禁](current-dataflow-p5-online-phase-timing-20261007.md) | 每例选择、RTL submit、摘要、反馈和 checker 的 p50/p95 已入回执，100/100 complete 且完整 fresh replay 一致；十分钟全成本仍缺 |
| P5 submit 调用边界 | [本地命令往返与主机其余时间](current-dataflow-p5-command-roundtrip-split-20261007.md) | 16/16 例中将 1.454 秒 submit 分为 0.464 秒命令往返和 0.990 秒其余主机，完整 replay；命令往返包含 IPC/解析，非纯 RTL 求值 |
| P5 Runner/Router/Scheduler 内部分项 | [在线逐例嵌套计时短门禁](current-dataflow-p5-runner-router-scheduler-timing-20261007.md) | 独立快照 16/16 例、6,996 事件、完整 fresh replay；Scheduler、Runner 与 Router 排队耗时进入回执，但各项包含子调用，非纯 RTL 计时或十分钟门禁 |
| P5 十分钟嵌套计时与压缩终结 | [冻结 GPIO 6,272 例门禁](current-dataflow-p5-runner-zlib-600s-20261007.md) | 600.067 秒有效搜索、2,355,748 事件、逐例分项及输入哈希绑定的完整 replay；终结 92.702 秒，完整链/s 与同条件 JSONL 对照仍缺 |
| P5 同源码逐例冷启动成本 | [十例精确 raw／权重对照](current-dataflow-p5-same-snapshot-cold-start-20261007.md) | 10/10 source/path 相同；十次初始化累计 194.220 秒，对应持续会话前十例逐例处理 1.056 秒；状态与总成本边界不同，不证明覆盖等价 |
| P5 压缩 trace 写入效率 | [真实保存事件前缀配对测量与 RTL 短回归](current-dataflow-p5-trace-write-efficiency-20261007.md) | 内部序列化省去逐事件深拷贝；131,072 事件字节及语义摘要相同，中位写入 4.038→1.973 秒；新快照 16/16 例及完整 replay，全量加速未测 |
| P5 600 秒分项与终结 | [冻结 GPIO 长跑门禁](current-dataflow-p5-streamed-600s-timing-20261007.md) | 6,276/6,276 complete、2,112,036 事件、逐例 p50/p95、93.915 秒终结及全量 fresh replay；完整链/s 与 Router/Scheduler 内部分项仍缺 |
| P5 GPIO B pin8 来源消费证书 | [有界真实输入子链审计](current-dataflow-p5-pin8-consumption-certificate-20261007.md) | 既有带探针 trace 产生 13/14 张 admission→padin_latch 版本证书；IRQ→CPU→输出和完整链率仍缺 |
| P2/P5 pin8 原生 IRQ 子链 | [有界 GPIO B trigger/高电平证书](current-dataflow-p2-p5-pin8-native-irq-certificate-20261007.md) | 两份既有带探针 trace 各有 5 条精确 native IRQ 子链；CPU taken 缺 trigger 身份，不能接入完整链 |
| P2/P5 pin8→CPU IRQ 接受 | [新身份真实门禁](current-dataflow-p2-pin8-cpu-irq-identity-20261007.md) | 新快照 25/25 例、5 条 pin8→native trigger→CPU `irq_taken_pre` 精确证书和完整 fresh replay；ISR、MMIO、输出未连接 |
| P2 pin8 IRQ→trap 退休 | [受限架构关联审计](current-dataflow-p2-pin8-trap-retirement-architectural-20261007.md) | 保存的真实 RTL trace 有 5 条单未决 IRQ、连续 RVFI order、`intr=1` 的关联；退休无硬件来源 token，不计完整链 |
| P2 pin8 原生 CPU 采样回执 | [显式 opt-in 的真实门禁](current-dataflow-p2-native-irq-sampled-receipt-20261007.md) | 冻结源码 18/18 例、4 次同 tick native sample/take 回执与完整 fresh replay；RVFI 退休晚 5 tick，仍不具有精确来源 token |
| P2 pin8 原生回执到 trap 退休 | [连续 STEP_CPU 回执的受限关联](current-dataflow-p2-pin8-native-trap-relation-20261007.md) | 保存的 24,508 事件真实 trace 中得 4 条 take→首次 RVFI 退休关联；新消费者只读审计，退休无硬件来源 token，不计精确全链 |
| P2 trap 来源归属可行性与拒绝门禁 | [中间 native notification 审计](current-dataflow-p2-native-trap-attribution-audit-20261007.md) | 伪造中间通知反例已修复，54 项测试与 21 个 subtests；旧 trace 仍只有 4 条受限关联，精确来源需 RTL 流水级 serial |
| P5 断言三类分开报告 | [协议 checker／跨组件来源顺序／CPU-IP 行为各自计数，异常记录 fail-closed 普查](current-dataflow-p5-assertion-classes-20261007.md) | `p5_assertion_classes.v1`（18 项测试）：同一份只读流式扫描分别产出三类计数，声明/生成约束与检查期望分开；真实 run 上 protocol 0/24、cross_component 22（6 `not_a_runtime_edge` + 16 不完整链证书）、cpu_ip 118/1308（另一 run 该层无记录时写 `null`+原因而非 0）；异常记录普查 140/140、42/42、24/24 全部在文档中可回查，未分类记录一律 exit 2 |
| P5 故障质量同条件对照 | [逐变体检测/边界/可复现三维度 + 同条件降级显式化](current-dataflow-p5-fault-quality-comparison-20261007.md) | 只读工具 `p5_fault_quality.v1`（27 项测试）复核 9/9 校准：`detected=9 boundary_ok=9 reproducibility_ok=9`、锚点数据流差异 0、故障 trace 保留原值且注入值不出现、9/9 最小重放摘要与该变体文档一致；并**显式暴露同条件降级**——控制运行与故障会话 `topology_sha256` 相同但 `graph_sha256` 与 6 个 source 文件不同、case 窗口掩码后仍有 80 个事件不同（372 身份摘要叶 + 67 内容叶全在 event 5826），故"同条件"只到 case_id/事件 ID/tick/原值/锚点逐字段一层 |
| P5 异构 UART 长会话解锁 | [RX 波形互斥改为接纳前声明式拒绝（60 例、0 停机）](current-dataflow-p5-uart-waveform-admission-20261008.md) | 会话新增 `register_access_conflict()`（与 `_access` 同一谓词，改为查询）；新门 `UartWaveformAdmissionGate` + 声明词汇 `transport_idle` 只对**片段自身含 UART 窗口访问**的 CPU 候选在 RTL 命令前拒绝。真实运行由 7 例（1 次 `uncertain_effect` 停机）变为 **60 例、57 complete、3 次声明式拒绝、0 停机**，CPU 指令源 24 例 + UART RX 源 36 例同会话使用、54/60 命中目标位、fresh replay `matches=true`；边界：底层互斥仍不支持，只是不再崩溃 |
| P5 受控故障族 9/9 真实校准 | [四类九变体真实 RTL 捕获 + 独立复核 exit 0](current-dataflow-p5-fault-family-real-9-variants-20261007.md) | 前一版只校准 1/9 变体；本轮 9/9 各自在全新真实会话中被既有 checker 不变量捕获（错 IRQ 2／错 read data 3 含 1 个 UART／重复提交 2／破坏绑定值 2），会话命中即停并各写 `minimal_replay.json`；只读复核器独立重读产物 exit 0（0 失败），逐变体记录 8 条 `declaration_drift`（控制运行是更早声明）并修复两处复核器缺陷 |
| P5 受控故障校准 | [GPIO B IRQ 观测副本故障与 fresh RTL replay](current-dataflow-p5-controlled-irq-fault-20261007.md) | 前 4 例 complete、第 5 例受控 checker 输入扰动报警并停止，新进程同配置复现；原始 RTL trace 无故障注入 |
| P4 合法 CPU 算术变异 | [在线 XORI 子集](current-dataflow-p4-legal-mutation-20261007.md) | 8 字节在线输入可选到合法 XORI；44 项定向软件检查通过，该报告写作时尚无 RTL/候选身份，后续门禁见下方 |
| P4 XORI 真实退休来源 | [冻结源码 RTL 短门禁](current-dataflow-p4-xori-retirement-real-gate-20261007.md) | 25/25 在线例，3 条 XORI 的真实取指来源与 RVFI 退休 accepted，完整 fresh replay 一致；计算结果向 IP 的传播未证明 |
| P4 路径／源／操作子候选身份 | [冻结源码 RTL 短门禁](current-dataflow-p4-candidate-identity-real-gate-20261007.md) | 25/25 在线例的候选 ID 与回执字段独立复算一致，6 类候选含 3 例 XORI，完整 fresh replay 一致；后续选择／接纳原因见下行 |
| P4 初始 RAM 数据算子 | [会话启动前变异 + 真实 RTL 首次读回证据](current-dataflow-p4-initial-ram-data-operator-20261007.md) | 软件 26 项测试；真实门禁四步 exit 0：ON 枝在任何读取前写入 `initial-ram-data.ram.6`（`0x100E6`=`0x94`，event 6 `initial_image`），真实 Ibex 首次读该四字节（event 774 lane 2）的 lane 值即 `0x94` 且 writer kind 为 `INITIAL_IMAGE`，slot 判定 `immutable`／0 violated；抽取地址与取值可由运行自己的 `seed.bin` 复算，ON 枝 fresh replay 一致；OFF 枝不声明算子 |
| P4 指令插入/删除真实门禁 | [种子 raw 直投 + RVFI 逐字退休（两枝 PASS）](current-dataflow-p4-sequence-edit-real-gate-plan-20261008.md) | 用 `--initial-ram-record` 把 8 字节 raw 作为**首例**直投客户端（`seed.bin` → `--seed-input` → Rust `fuzz_one(identity)`）：insert 枝 raw `00000007c00200fc` 解出 12 字节 `b72300c093c3c37f93832300`（`LUI+XORI+ADDI`），delete 枝 raw `00000011a10100aa` 解出 4 字节 `b71300a0`（`LUI`）；两枝各 8/8 complete、6 项判据全部 proven（种子直投、算子接纳、指令通道取指逐字、RVFI `status=accepted`+`typed_writer_refs`+`source_refs=action_id`+pc/insn 逐字、保留区走查、fresh replay `matches=true`） |
| P4 算子收益同预算对照 | [路径切换／初始 RAM／闭环能量三对真实 A/B](current-dataflow-p4-operator-benefit-comparison-20261008.md) | 只读对照器（13 项测试）：三对同 seed/同预算下**没有算子显示覆盖或完整链收益**；初始 RAM 是最强对照（96/96 raw 与逐例 status/coverage/genome/path 完全一致——算子生效但不改变判定结果），路径切换只改变轨迹（共享前缀 1 例，目标位与链数不变），闭环能量确实改变逐例选源/覆盖（前缀内 23/35 `coverage_hex` 不同、三目标首中位 3/2/2→11/10/11）却**证书更少**（7 对 12 条、0.115 对 0.196 链/s，且同 60 秒例数更少）；边界：每臂单次运行、目标集已饱和 4/4、`certified=0` 只表示生产者未认证 |
| P5 ISR 写回端点 | [链扩展不可精确 join（缺身份已点名），ISR 写回的 A→B 回流已认证](current-dataflow-p5-isr-writeback-endpoint-20261008.md) | 新证书 `isr_writeback_certificate.v1`（10 条精确身份跳、18 项测试）：**链扩展 0/27（600 秒）与 0/8（验收运行）**，`adjacency_fallbacks_used=0`；唯一关键缺失身份 `cpu_retired_transaction_target_delivery.registered_origins` 全为 `[]`/`unknown`（ISR 指令不在唯一指令槽 69632 内、也不在任何 `source_admission` 中），报告给出三种最小 harness 补记方案并用合成 journal 测出"补上即 join"；可 join 的部分已证书化：600 秒运行 3/68、验收运行 2/5 条 handler 写回完整连到第二次 CPU IRQ 输入（例：acceptance 5908→commit 5925→binding 5951/5953→trigger 6007→retire 6023→match 6024→delivery 6025→input 6027→observation 6058）|
| P4 声明式路径／源切换算子与 slot 不可变性 | [算子声明池、shipped 拒绝码与只读不可变性检查](current-dataflow-p4-path-switch-operators-20261007.md) | 软件门 45 项通过：真实 profile F4/F5 两路径互切、GPIO B bound/fixed 切片按 ownership 拒绝、原地切换保持身份、伪造记录摘要拒绝、有界保留淘汰；真实运行只读判定 p3 1716/1716、p4 1296/1296 slot `immutable`（0 violated／0 insufficient），CLI `0/1/2` 区分通过／违反／证据不足 |
| P4 live 路径切换真实生效 | [同 seed 真实 RTL A/B＋2,400 例长枝逐例复算](current-dataflow-p4-path-switch-live-20261007.md) | `MYFUZZ_PATH_SWITCH` 接线进在线主循环：对照枝 46/96、长枝 1199/2400 例候选被重定向到声明池内另一路径；三枝 96/96、96/96、2400/2400 例的 `candidate_id` 与算子摘要由该例 raw＋权重＋声明池独立复算一致，report 计数零不一致，两枝 fresh replay `matches=true`；边界：长枝余量 99,076 字节故 0 拒绝，真实声明下的拒绝由软件门证 `budget.exhausted@switch.source_id` |
| P4 候选选择与接纳原因 | [冻结源码 RTL 短门禁](current-dataflow-p4-candidate-disposition-real-gate-20261007.md) | 25/25 在线回执中直接选源 14、权重回退 11、确认提交 25，完整 replay 一致；拒绝／不确定分支由软件门禁验证 |
| P2 UART 原生 IRQ taken 来源 | [RX 留存到实际外部 taken](current-dataflow-p2-uart-native-irq-20261006.md) | 冻结源码真实 4 项／7 子检查、48,378 事件完整 fresh prefix 一致；20 cause 版本、4 taken、4 留存／4 读取，1 bootstrap／3 fuzz_source；generic ISR/operand unknown，最终冻结源软件 166 项／56 子检查通过 |
| P2 UART FIFO 实际消费 | [接收、留存与路由读取](current-dataflow-p2-uart-fifo-consumption-20261006.md) | 软件 738 项、真实 RTL 2 项、Ibex 在线 4 例及完整 replay 通过；4 条留存/4 条读取来源证明，CPU IRQ/ISR 来源仍待闭合 |
| P2 GPIO 实际消费 | [寄存器、同步器与原生 IRQ 消费证据](current-dataflow-p2-gpio-consumption-20261006.md) | 别名修正版本 RTL 5 项、软件 637 项、在线 16 例与完整 replay 通过；独立审计确认 1617 个 pin8 已知 stage、9 个已知原生触发及 1 条指令提交证明；旧限制保留 |
| P2 退休与物理帧 | [退休、帧及交易证据](current-dataflow-p2-retirement-frames-20261006.md) | 真实RVFI44、冻结响应、受限退休/交易与实际UART帧驱动；完整寄存器/FIFO/IRQ闭环仍待验收 |
| P2 来源与见证基础设施 | [来源实施与当前RTL验收](current-dataflow-p2-source-provenance-20261006.md) | typed writer/原始case来源、plan10/11与见证引用已接入；完整退休/MMIO/FIFO因果仍缺 |
| P2 入口审计与契约实施 | [基础接口进度](current-dataflow-p2-path-contract-20261006.md)、[专题计划](../superpowers/plans/2026-10-06-runtime-path-contract-implementation.md) | edge-aware 路径、显式 compiler、新 decoder/RFuzz 身份与接纳已接入；启动前归属及异常/replay-only 封口已审查；当前源 GPIO 120例及完整 replay 通过，逐边来源尚缺 |
| 新 CPU／外设例子 | [CV32E40P＋双 OpenTitan GPIO](generated-cv32e40p-two-opentitan-gpio-irq-20261005.md)、[CVA6＋双 PULP GPIO](generated-cva6-two-pulp-gpio-mext-irq-20261005.md) | 各自固定 profile、协议子集和中断路径 |
| 单组件生成与协议 | [生成式本地 harness 状态](generated-harness-status-20261004.md) | 生成器和局部交易的分层验收；跨组件能力须查对应组合报告 |
| 清理与保留 | [源码引用审计](current-design-cleanup-source-audit-20261006.md) | 仓库文件的当前、共享及历史用途 |

完整组合表与具体限制见 [运行能力表](../LOCAL_HARNESS_RUNTIME.md)。`soc-*` 报告、较早 RFuzz 对照和日期更早的计划属于当时实现的证据；不要把它们计入当前独立 harness 路线的验收。

## 原始证据位置

- [固定场景证据](../../runs/scenario/acceptance/)：场景与 replay 材料。
- [UART FIFO 定向证据](../../runs/current-dataflow-p2-uart-fifo-20261006-directed/)及[在线证据](../../runs/current-dataflow-p2-uart-fifo-20261006-online/)：接收、留存与读取验收。
- [UART 原生 IRQ 别名修正后证据](../../runs/current-dataflow-p2-uart-native-irq-20261006-online-alias-fixed/)：完整来源链和 fresh prefix；早期失败记录保留，不能替代最终门禁。
- [受控入口／退休读取2048冻结源证据](../../runs/current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online/)及[独立身份审计](../../.superpowers/sdd/current-dataflow-p2-controlled-capacity-identity-audit.md)：4／4／4、0 barrier及完整fresh；仅认证记录时源码。
- [UART seed最终冻结源证据](../../runs/current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-online/)及[本次fixture／fresh日志](../../.superpowers/sdd/current-dataflow-p3-uart-operand-seed-finalfreeze-fixture-gate.md)：4条read／4条seed、完整fresh一致；seed语义见对应报告引用的raw独立审计。
- [当前工作日志与独立审查](../../.superpowers/sdd/)：软件检查、真实门禁日志、失败定位及交接草案；最终状态查当前工作进度和对应报告。

证据目录不是构建缓存；清理前检查报告引用与重放依赖。新增验收先写明源码身份、检查结果及证明边界，再在此处加入报告链接。

2026-10-12 verifier Session／可信file replay最新检查点：Runtime66项及closed saved／Session／CLI联合50项软件通过；实际generation完成14case检查并产13项scope证书（A10操作/B0），但180.18秒在认证保存阶段超时，未获bundle/fresh验收。所有失败产物保留，预算不变，导出重复成本正独立定位。见[执行报告](stage2-e2-register-verifier-session-execution-20261012.md)。完整E1/E2/Stage2保持未完成。

2026-10-12 导出优化最终软件：Session15项、独立export4项、singleexport/closed saved/CLI联合35项通过；v2实际14case generation正在运行，原独立180秒/RSS预算保持，production冻结。上一轮wall_timeout及partial audit仍只证明部分实际观察，不能冒称认证保存/fresh通过。见[最新执行报告](stage2-e2-register-verifier-session-execution-20261012.md)。原E1/E2及完整Stage2未完成。


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


[Remaining word-field gates design](stage2-e2-remaining-word-field-gates-design-20261012.md)：只读设计／审查，尚未执行，不计验收通过。


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


[Native reset-default design](stage2-e2-native-reset-default-design-20261012.md)：只读设计，尚未实现／执行，不授reset-default证明。


2026-10-12 chunk15 PADCFG3首组generation62291已exit0／complete：134.15973644101177秒、available5,471,129,600／peak2,045,935,616低于3,323,645,952限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh77906运行中、audit待完成，accepted仍56；reset-default独立设计review指出actualcommand全覆盖／未知命令fail closed／完整field-affect／process boundary实施前缺口，只有docs修订，未实现或授grant。


[Native reset-default independent design review](stage2-e2-native-reset-default-independent-design-review-20261012.md)：实施前边界审查／设计修订，不是native执行或能力grant。


2026-10-12 chunk15 fresh77906已exit0／complete：120.05253920699761秒、available5,461,848,064／peak1,850,097,664低于3,314,364,416限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、accepted仍56不提前60；chunk16 offset0x34 preflight通过未执行。reset-default设计reconciled仅docs、未实现或授grant，原全scope保持OPEN。


2026-10-12 chunk15 fullaudit41628已终态PASS，exactPADCFG3 pins24／25／30／31 values1／5／10／15／18,222events／8证书与完整fresh一致，见[独立报告](stage2-e2-padcfg3-first-field-independent-audit-20261012.md)。accepted current60单points（32INTTYPE＋28PADCFG），非穷举。chunk16 PADCFG3 pins26–29 values2／6／9／14 generation9338实际运行、尚未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；64fieldpoints后仍有word／permission／width／reset及原Stage2完整scope，不能标阶段完成。


2026-10-12 chunk16 PADCFG3 pins26–29 generation9338已exit0／complete：131.9667810839892秒、available5,477,412,864／peak2,046,443,520低于3,329,929,216限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh6576正在运行、audit待完成，accepted仍60不提前64；3word包prepared待矩阵完成后执行，原Stage2全scope保持OPEN。


2026-10-12 chunk16 fresh6576已exit0／complete：118.51990141399438秒、available5,447,532,544／peak1,851,146,240低于3,300,048,896限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。最后独立audit待终态，accepted仍60不提前64；16组小证据聚合核对仅准备，各bundle current8证书不能伪称global active128，非exhaustive／fullE2。


2026-10-12 最后chunk16 fullaudit11089实际exit0／PASS，16bundle轻量聚合PASS：accepted current64 exact指定单valuepoints（32个2bit INTTYPE＋32个4bit PADCFG），无漏重；每bundle current8证书，不能拼成global active128；16gen／16fresh各自singleworker／≤180秒，与全部sourcefreeze／fresh／resources小证据一致。见[聚合报告](stage2-e2-register-field-matrix-aggregate-20261012.md)。不是全值穷举或完整E2，word／permission／width／reset仍OPEN。Root DIR_OUT word generation48145已实际运行、尚未通过，原Stage2完整范围不缩减。


2026-10-12 DIR_OUT word generation48145已exit0／complete：119.19223787200463秒、available5,482,065,920／peak1,715,609,600低于3,334,582,272限额／worker1／DUTFalse，6cases／13,907events／12关联／18selectedAPB／3RAM。fresh3571实际运行、独立audit待完成，word尚未accepted；narrow64已审计单valuepointscope保持独立，不扩成global或完整E2。


2026-10-12 DIR_OUT word fresh3571已exit0／complete：101.75905876699835秒、available5,479,596,032／peak1,575,030,784低于3,332,112,384限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。word独立fullaudit待终态、尚未accepted；narrow64单值scope保持独立，原Stage2继续OPEN。


[Register word root execution](stage2-e2-register-word-root-execution-20261012.md)：DIR_OUT generation／fresh已通过、独立audit待验收；其他word按各实际phase记录，不代替原scope。


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


[Current partial-repeat alias design](stage2-e2-current-partial-repeat-alias-design-20261012.md)与[独立设计review](stage2-e2-current-partial-repeat-alias-independent-review-20261012.md)：只读设计／文档修订，未执行，不扩展为能力grant。


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


[Native reset-default Root执行checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md)：Task1已按五个SHA完成终审、59 passed＋15 subtests兼容回归并冻结；Task2首个40项候选随后被独立终审发现两项重要边界（barrier外reset可被snapshot愈合、若干helper/registry/reader/hash/dispatch pin在install时才捕获），并由Root核对出Task2计划要求的actual memory commit pre-ack hook尚未实现，该候选不接受。修复候选新增10项负例聚焦回归全过，actual CPU→MemoryService commit hook经真实2 RED→2 GREEN；首次完整回归66/2失败源于write-only探针错误期待读回证书，原收据保留；修正断言后完整三模块回归68 passed／34.53秒，源码前后SHA稳定。随后独立精确SHA复审发现baseline-checker可被安装前替换、journal append内consumer callback失败没有把Runner/evidence标记uncertain/incomplete，并要求明确authority配置和consumer注册顺序；当前68-pass版本不接受，新一轮修复中。成功Runner begin/global-reset及native qualification仍未验证，原Stage2仍未完成。

Task2 latest checkpoint: the 75-pass／44.52-second full regression receipt is historical, not accepted. Independent review identified four remaining fail-closed gaps: replaceable checker table/alias, mutable checker defaults, replaceable `inspect.sys` caller-frame dependency, and receipt drain/lookup/issuance failures outside the terminal handler. The callback/ack failure block is confirmed repaired. All four findings are assigned for RED→GREEN repair; Task2 remains open, Task3 and native qualification deferred. Details: [execution checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md) and [exact-SHA review record](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-checker-commit-v3-candidate-20261012.md).

Task2 follow-up confirmed a remaining consumer atomicity blocker: verify the `NativeResetEvidence` method-table contents before registering any Task1 issuer. A suspected Task1 target-observer class-method gap is covered by `observer.validate()` before registration, but its dispatch through `_NATIVE_RESET_CHECK_PRODUCERS` lacks an independent pin and can be replaced to bypass that check; Task2 must pin it. Corrected REDs now reproduce `inspect.sys` caller forgery and unhandled actual receipt lookup failure; an earlier pytest-internal-error fixture is excluded as setup-only. The unpinned Task1 producer-dispatch tuple has a valid RED receipt (1 failed／56 deselected／9.26秒), showing a no-op replacement is accepted; Task2-only pin repair and full regression remain pending. See the detailed [execution checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md).

2026-10-12 Native reset-default Task2 third repair candidate：精确三模块回归82 passed／44.18秒，六份Task1/Task2源SHA与receipt前后稳定；独立终审匹配所有pin后发现导入基线guard可于安装前被替换，造成method drift在issuer注册后才报错并残留，合并替换方法表还可绕过晚期检查。该82-pass候选不接受；Task2窄RED→GREEN修复和同命令全回归待执行。Task3只读准备审计完成；Task3实现及native positive均未开始。详见[Root执行检查点](stage2-e2-native-reset-default-root-execution-20261012.md)、[独立终审](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-import-baseline-guard-9932199.md)、[Task3准备审计](../../runs/stage2-e2-native-reset-task2-software-20261012/task3-ready-audit.md)及[回归收据](../../runs/stage2-e2-native-reset-task2-software-20261012/sealed-task1-anchor-final-green-receipt.json)。

Task2 guard-entry repair follow-up：组合替换与alias单独替换均有真实RED（各2项），固定词法调用入口并校验原guard导出身份后聚焦8项通过；同三模块完整回归86 passed／43.92秒，六源SHA前后稳定，diff --check通过。当前精确SHA与封存回执一致，独立终审进行中，Task2尚未接受。Task3只读准备审计已完成；实现等Task2通过。见[执行检查点](stage2-e2-native-reset-default-root-execution-20261012.md)、[最终回归收据](../../runs/stage2-e2-native-reset-task2-software-20261012/lexical-guard-entry-final-green-receipt.json)、[Task3审计](../../runs/stage2-e2-native-reset-task2-software-20261012/task3-ready-audit.md)。

Task2 exact-SHA follow-up review发现第二个Important blocker：可在安装前替换NativeResetEvidence构造器wrapper；同步替换方法表后，Runner构造证据对象时不触发词法guard，_attach仍可能先注册issuer再因后续校验失败。86-pass候选不接受；下一轮修复将把可独立pin的检查放在Runner创建证据对象之前，并以零issuer残留RED覆盖。详细最小复现见[独立复审记录](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-lexical-guard-entry-candidate.md)；Task3仍等待Task2复审。见[Root执行检查点](stage2-e2-native-reset-default-root-execution-20261012.md)。

Task2 pre-construction-anchor candidate：有效组合RED复现构造器替换导致issuer残留；Runner-owned一次性NRE import anchor修复后聚焦5 passed／9.28秒，同三模块完整回归87 passed／44.85秒。Root独立核对当前SHA、六源收据与manifest，diff --check通过。独立终审正在检查anchor注册和pre-construction guard是否仍有可替换入口；Task2尚未接受，Task3待其通过。详见[执行检查点](stage2-e2-native-reset-default-root-execution-20261012.md)、[完整回归收据](../../runs/stage2-e2-native-reset-task2-software-20261012/preconstruction-anchor-final-green-receipt.json)和[RED收据](../../runs/stage2-e2-native-reset-task2-software-20261012/preconstruction-anchor-red-receipt.json)。

Task2 pre-construction-anchor follow-up review发现Runner check函数别名与guard tuple可被同步替换为noop；再替换NRE构造器／方法表会绕过当前入口检查并造成issuer先注册、后失败。87-pass候选不接受；另一个Task2 RED→GREEN修复已委派，Task3继续等待。详见[独立复审记录](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-preconstruction-anchor-candidate.md)及[执行检查点](stage2-e2-native-reset-default-root-execution-20261012.md)。

Task2 follow-up: exact-path review confirmed the bypass can delegate the replaced constructor to the unwrapped original, then fail only after issuer registration. The combined RED was reproduced; the repair now uses a lexical Runner install wrapper. Focused regression is running, with the isolated first-import ordering check, full three-module receipt and exact-SHA review still pending. The candidate remains unaccepted; no Task3 or native work has started. See the [Root execution checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md).

Task2 lexical Runner-entry candidate is sealed at 90 passed／53.28秒 with stable six-source pins and clean `git diff --check`; see [receipt](../../runs/stage2-e2-native-reset-task2-software-20261012/lexical-runner-entry-final-v2-green-receipt.json) and [byte manifest](../../runs/stage2-e2-native-reset-task2-software-20261012/final-source-lexical-runner-entry-manifest.json). Independent review rejected it after finding synchronized Runner method-table accessor/tuple replacement can bless a patched method table as baseline. Next: RED→GREEN for that combined path; Task2 stays open, Task3/native remain gated.

Detailed exact-path report for the 90-pass rejected candidate: [lexical Runner-entry review](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-lexical-runner-entry-candidate.md). It records the synchronized accessor/table replacement exploit and required pre-registration no-residue assertions.

The next Task2 RED now reproduces synchronized method-table accessor/tuple replacement in two cases; the installer currently accepts the spoofed baseline. Repair is in progress. See the exact exploit report above and the Root execution checkpoint for status.

Latest Task2 candidate: the synchronized accessor/table RED is now fixed; focused 4 passed／18.21秒 and the final three-module regression 92 passed／54.18秒. Root matched all six pins to the receipt/manifest; independent exact-SHA review is active. The candidate is pending, not accepted. See [receipt](../../runs/stage2-e2-native-reset-task2-software-20261012/lexical-accessor-final-green-receipt.json) and [Root checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md).

Task2 software core has now passed independent exact-SHA review (92 passed／54.18秒; all six pins matched; previous software blockers clear). Task3 is released only for source-rule conformance and fail-closed software refusal tests; native-positive certificates remain deferred. See the [Task2 review](../../runs/stage2-e2-native-reset-task2-software-20261012/final-review-lexical-accessor-candidate.md), [Task3 readiness audit](../../runs/stage2-e2-native-reset-task2-software-20261012/task3-ready-audit.md) and [Root execution checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md).

Task3 initial RED: missing module/API produced 7 failures in 9.58 seconds. Source-bound INTEN rule must report profile reset as undeclared (`None`) while binding sidecar reset 0 and the pinned RTL reset assignment 0. RED receipt is being sealed; no positive certificate path is allowed. See the Root execution checkpoint.

Task3 source-rule audit is complete and recorded at [source-rule-audit.md](../../runs/stage2-e2-native-reset-task3-software-20261012/source-rule-audit.md); it pins current profile/sidecar/RTL facts and the fail-closed mutation matrix. The profile omits INTEN reset_value while sidecar and RTL specify zero. Initial missing-API RED is under the Task3 run directory.

Task3 is still in progress and no candidate is accepted. Historical source/refusal runs found and fixed offset classification, command-shape and closed-document gaps; the 34-pass candidate was later rejected by independent review for preconstruction method replacement, mutable source/helper pins, replaceable saved-document validation, and memory-resolver dispatch drift. A follow-up passed 43 tests / 13.12 seconds at `sealed-source-refusal-green.stdout`, then target-shape (`target-shape-red.stdout`, 3 failed) and recipient-projection (`recipient-projection-red.stdout`, 2 failed) probes added valid REDs. Those outputs are retained and the exact target/source binding is being tightened. Related compatibility regression, stable receipt/manifest, and exact-SHA review remain pending. Keep the profile's absent INTEN reset value distinct from sidecar/RTL reset 0. Scope remains software source-rule/refusal only, without native build/gate or injected positive evidence.

Task3 latest follow-up: target/recipient-focused regression reached 49 passed / 12.52 seconds (`exact-target-recipient-green.stdout`), then a new probe-decode drift RED failed as expected (1 failed / 49 deselected, `probe-decode-red.stdout`): mutating the shared current GPIO probe map's alias period to 256 did not make rule derivation refuse. The current candidate hardcodes decode mask/period and does not consult that map. Independent snapshot audit also flags runtime revalidation of external RTL/probe bytes, rejecting unknown post-install authority recipients, and validating caller-supplied classifier rules. Implementation is adding RED→GREEN coverage; Task3 remains unaccepted pending full compatibility regression, sealed hashes/receipt, and exact-SHA review. Details and evidence: [Root execution checkpoint](stage2-e2-native-reset-default-root-execution-20261012.md), [source audit](../../runs/stage2-e2-native-reset-task3-software-20261012/source-rule-audit.md), [Task3 evidence directory](../../runs/stage2-e2-native-reset-task3-software-20261012/).

Follow-up negative evidence (`external-source-rule-recipient-red.stdout`) adds 4 failed / 50 deselected in 9.31 seconds: foreign recipient acceptance, two caller-mutated rule cases, and missing explicit RTL source pin. Test SHA at this RED is `142b03a0…83a1fe`; implementation SHA remains `8421bede…348d6`. The corresponding GREEN and runtime source-drift checks are pending.

Focused RED→GREEN now passes 54 tests / 12.80 seconds at `probe-rule-recipient-green.stdout`, implementation SHA `1ea48e7b…a74a`. It covers probe/source helper drift, foreign consumers, forged classifier rules, and explicit RTL/target bindings. Full Task3 plus compatibility regression, external drift behavior through report/preflight, receipt/manifest, and exact-SHA review are still pending.

Instance-state follow-up exposed 2 more valid REDs (`private-floor-method-red.stdout`, 2 failed / 54 deselected / 9.67 seconds): replacing `_consumer_floor` can authorize a foreign recipient, and clearing the instance method projection can hide a `report` override. The candidate is adding immutable closure-owned baseline checks; the earlier focused GREEN is not final.

Those instance-state probes now pass in the 56-case focused GREEN (`private-binding-green.stdout`, 13.07 seconds), implementation SHA `f01fd901…c6f8c`. Source-byte drift after installation, full compatibility regression, receipt/manifest freeze and exact-SHA review remain pending.

The actual external-source drift and valid later `RegisterProgramVerifier` control tests now pass (3 passed / 56 deselected / 11.92 seconds) at `actual-file-later-consumer-green.stdout`; RTL/probe bytes were restored and their current SHA values match pins. Complete regression, final receipt/manifest and exact-SHA review remain pending.

Final same-content recipient-set replacement RED (1 failed / 59 deselected) is fixed by explicit object-identity pins; its focused GREEN passes 1 / 59 deselected (`recipient-object-green.stdout`, 9.33 seconds), with implementation SHA `096e306f…c14d`. Frozen full regression and exact-SHA review are running.

Task3's frozen single-module regression passes 60 / 15.49 seconds; the accepted Task2 three-module compatibility regression passes 92 / 52.90 seconds. Both receipts show unchanged 12-file SHA pins and `native_execution=false`; final Task3 SHAs are verifier `096e306f…c14d`, tests `47ea4bfd…f66a5`. Source manifest and clean diff-check are sealed. Exact-SHA independent source/security reviews are underway; no native positive or certificate is claimed.


2026-10-12 Task3复核回退：此前Task3 60项与Task2兼容92项收据仅对应候选SHA `096e306f…c14d`，不再作为当前验收。独立实际提交路径审查发现 authority 实例覆盖 `resolve` 可让Runner确认成功但保留未消费recipient；后续又发现覆盖 `register_consumer` 可导致Task3半安装，覆盖 `validate_consumer_registration` 可绕过启动阶段recipient门槛。实现代理正在同一轮补RED与fail-closed前置校验；审查仍在检查相关动态dispatch。新GREEN、完整回归、源manifest和精确SHA独立复核全部完成前，Task3保持未接受；不运行native/build、不产生正向证书。

2026-10-12 Task3复核补充：动态调用边界还包括 `RegisterProgramRuntime.validate` 与 `validate_static_configuration`；实例覆盖后者可让已安装 verifier 的 report/preflight 绕过结构校验，且当前未固定运行时验证方法。此项已并入实现代理本轮RED范围；审查代理继续收集完整动态dispatch清单。共享源码漂移测试等候实现候选冻结后串行执行。

Task3复核又复现实际提交dispatch bypass：Task2 pre-effect hook动态调用实例上的 `_preflight_command`，Runner pre-ack hook动态调用实例上的 `_consume_actual_commit`；同时以no-op遮蔽两者可跳过各方法内部的实例绑定检查，并让默认ack路径成功、Task3 recipient token仍待消费。实现代理已收到要求增加真实Runner提交RED和闭合dispatch修复。现有候选保持拒收，需覆盖所有新发现再冻结。

Task3范围可行性裁定：精确改写 `runner._register_reset_default_verifier` 私有槽位无法仅通过本轮授权的 verifier/test 两文件可靠拦截；冻结的 Task2 `NativeResetEvidence._preflight_command` 与 Runner pre-ack 都只以该槽位作分派入口，槽位被清空/替换时不存在仍会执行的 Task3 hook。独立复核建议：若要支持防御此类外部私有槽位篡改，最小解冻点是 native_reset_evidence.py preflight anchor 和 runner.py pre-ack anchor；本轮保持冻结，因此将此类外部改写列为明确支持边界外，不宣称 Task3 两文件防护该攻击。对象实例方法shadow、authority方法覆盖及 runtime validator 覆盖仍须在当前范围内修复并复审。

新实例分派／authority／runtime RED 已保存：`instance-dispatch-enrollment-red.stdout` 为6 failed／60 deselected／9.66秒，覆盖真实 issued commit、resolve instance override、成对 verifier 方法shadow、rogue consumer registration、已stage token后 validator no-op、runtime validator前后shadow。真实提交路径已观察到异常终态和未ack断言；resolve no-op时异常清理也会命中同一被覆盖方法，因此测试记录仍有1 pending token，不能要求该受损resolver同时完成清理；已要求修正此断言与fixture teardown。当前仅测试更改，生产修复仍在进行，未接受。

Task3动态调用补审： verifier还对 `NativeResetEvidence` 实例动态调用 `validate/configuration/snapshot`；NRE验证体检查其实例方法表，但实例把 `validate` 自身遮蔽时可绕过该检查体。已交实现代理评估 Task3侧固定调用/身份校验可行性，并由独立复核只读分类；尚无代码修复或接受结论。

NRE分派范围复核已完成：Task3可且应 pin `native_reset_evidence._METHODS` identity，并通过固定unbound entries执行 validate/configuration/snapshot；测试安装前/后 shadow，构造拒绝应先于recipient enrollment，post-install报告/preflight应sticky拒绝。Task2独立API未安装Task3时的instance shadow仍需解冻NRE/Runner才可覆盖，归外部私有Task2对象篡改边界；当前不改冻结文件。

Task3已复现NRE validator-shadow RED：`task2-instance-validator-red.stdout` 为2 failed／66 deselected／9.36秒，构造前与安装后覆盖 `NativeResetEvidence.validate` 都被当前实现放过。实现正用 frozen NRE method table固定 `validate/configuration/snapshot` unbound dispatch，并改 Task3 sensitive method lookup；聚焦8项GREEN结果待回报，完整回归和复审未进行。

Task3 unbound dependency source RED有效：`dispatch-source-dependency-red.stdout` 为1 failed／72 deselected／9.17秒，配置未显式包含固定unbound分派所依赖的 `native_reset_evidence.py`、`register_program_runtime.py`、`memory_commit_authority.py`、`memory_authority_distribution.py`、`register_program_verifier.py`。实现已扩展关键source pin并正跑13项聚焦GREEN，完成前继续不冻结。

候选SHA `51a9abd2…b838`/`3ff36bf5…72d6` 的独立source-contract review确认profile/sidecar/RTL/probe与拒绝式文档闭合，但指出条件source-path blocker：安装检查 `target.base_dir/_SOURCE`，持续`_current_source_files()`仅重hash仓库根RTL。标准factory为canonical ROOT；已交实现代理添加canonical安装拒绝或逐target路径pins与负例。另请安全复核类级 `__getattribute__` 替换/authority-runtime class method改写可行性；最终收据暂不生成。

精确候选安全复审发现真实class-level bypass：把已安装动态类 `RegisterResetDefaultVerifier.__getattribute__` 标准赋值替换成no-op，会使其自身词法guard不可达，冻结Runner/NRE随后可能ack并遗留Task3 recipient。因当前契约已pin class methods，此项为阻断；实现代理被要求用密封动态类/metaclass拦截标准class属性替换并加真实拒绝测试。纯 `type.__setattr__` 等低层替换仍可归为任意class metadata tamper边界。与canonical `target.base_dir` 检查一并合入新候选，当前SHA不接受。

复核新增source-drift blocker：只pin `Path.read_bytes`而未pinTask3模块全局 `Path` alias；换成继承Path子类并覆写 `open()` 返回旧缓存bytes，可掩盖被改写源码的漂移检查。实现代理需在两个guard中固定Path alias本身并添加alias/source-drift RED→GREEN。共享文件漂移测试串行运行；精确候选仍未接受。

新边界RED有效：`sealed-class-path-alias-red.stdout` 为2 failed／9.36秒（标准class special入口替换与缓存Path别名掩盖自身源码漂移）；`canonical-target-root-red.stdout` 为1 failed／9.12秒（alternate target base仍可安装）。source-file修改测试已finally恢复；实现正在合并metaclass闭包seal、Path alias pins与canonical安装拒绝，Green和新SHA待定。

2026-10-12 Task3 软件范围闭合（拒绝式，无正向证书）：精确候选 verifier SHA `229485466093033be9f96c38bfc8dfbd757c92daf7ca93912577964b04fb255f`、tests SHA `7b6527f0530869cb0c497517f06d927d5e59e668a1376ae053413630dbd3e090` 通过 Task3 99/99 与 Task2 三模块兼容 92/92，两份独立精确 SHA 复核均放行该 refusal-only 范围。收据、独立复核记录与 12 文件源码归档位于 [Task3 运行目录](../../runs/stage2-e2-native-reset-task3-software-20261012/path-mro-final-task3-receipt.json)（另见 [回归批量收据](../../runs/stage2-e2-native-reset-task3-software-20261012/path-mro-final-regression-batch-receipt.json)、[独立复核](../../runs/stage2-e2-native-reset-task3-software-20261012/path-mro-final-independent-review.md)、[源码清单](../../runs/stage2-e2-native-reset-task3-software-20261012/path-mro-final-source-manifest.json)）。`native_execution=false`、`build_execution=false`，不产生 native eligibility、私有事实/token、已完成区间或正向 reset-default 证书。支持边界：拒绝标准类属性改写，假定加载中的 Python 代码对象完整；不覆盖直接改写 `function.__code__`、显式 `type.__setattr__`、同进程任意私有 Runner slot 改写，或 pathlib 内部对象／module helper 改写。Task1/Task2 冻结保持，Task4（Session opt-in 闭包与 fresh 重构）与 Task5（可信 assembly/file selector 与 warm/cold native 门禁）为下一步；完整 Stage2、E1/E2 与 E3–I 继续开放。

2026-10-12 ordinary native reset-default 推进：Task3b 正向证书范围化重开**已冻结封存**（verifier `4c90712e90db87a15bd0071769b51c3a8c7f9608a4420366bb9eff6692e76296`，原 `2294854660…b255f`；tests `2354492ac83351ba0a383f02a971aac4531bc7e4efac41178bc84d4cc8f60ee1`，原 `7b6527f0…3e090`；其余 10 项 Task3 基线输入经重算字节相同）。Task3 全套 **132 passed／27.98 秒**（原 99 项拒绝式测试以字节相同 AST 保留），Task2 三模块兼容 **92 passed／55.46 秒**；正向路径已确认接在活路径上（`report()` 从 `NativeResetEvidence.completed_intervals()` 取区间并据此签发），故软件 fixture 下恒空、只有真实 native 证据才可能出证书。收据与源码归档见 [Task3b 清单](../../runs/stage2-e2-native-reset-task3b-certificate-20261012/task3b-final-source-manifest.json)、[正向 RED 收据](../../runs/stage2-e2-native-reset-task3b-certificate-20261012/task3b-red-positive-certificate-receipt.json)、[边界收据](../../runs/stage2-e2-native-reset-task3b-certificate-20261012/task3b-boundary-receipt.json)。**未证明：** 活 `report()` 签发正向证书未被执行，归 native 门禁。

2026-10-12 Task4（Session opt-in 闭包与 fresh 重构）软件半程封存并经**独立精确 SHA 复核 ACCEPT-WITH-NOTES（无阻断）**。`session_runtime.py 5dbd9c94…d92a`、`register_program_runtime.py 1bdc8188…03c8`、`tests/scenario/test_register_reset_default_session.py 12266661…66d0`（21 tests）。缺失 API RED exit 1／9.26 秒；**五文件全回归 exit 0、241 passed／487.67 秒**（复核者独立重跑 241 passed／482.09 秒一致），运行期间全 `src/tests` 哈希 before==after==now。默认关闭布局以**环境无关结构等价**证明：递归骨架 pre/post 均 280875 字节、digest 均 `57d719dc263d8be9284d12a030be927ad8885a4e10eb04cf729460046597d656`，且复核者独立两侧重算并验证 9/9 布局变异都会移动该 digest。复核见 [Task4 独立复核](../../runs/stage2-e2-native-reset-task4-independent-review-20261012/task4-independent-review.md)；证明见 [布局证明](../../runs/stage2-e2-native-reset-task4-software-20261012/default-off-layout-proof.json)；收据见 [全回归收据](../../runs/stage2-e2-native-reset-task4-software-20261012/full-regression-green-receipt.json)及[源码清单](../../runs/stage2-e2-native-reset-task4-software-20261012/source-manifest.json)。遗留 Important：RED 收据未与 RED 时刻的测试字节绑定（stdout 第 98 行 vs 封存第 122 行）。**未证明：** joined begin/reset/advance/resume、`finish_export`、正向 fresh replay 与正向证书均属 native 门禁范围。

2026-10-12 Task5（可信 assembly/file selector）软件半程封存（**独立复核进行中**）。`integration/ibex_pulp_register_replay.py 37d308be…3a45`、`scripts/run_ibex_pulp_online.py 78fd8614…8080`、`tests/integration/test_register_reset_default_replay.py 2b36c54d…5044`（37 tests）。真 RED exit 1、3 failed／6.05 秒；GREEN：新建测试独立实跑 **37 passed／137.05 秒**、`green-combined-resume` 45 passed／159.40 秒、默认关闭 selector 回归 **66 passed＋34 subtests／634.44 秒 exit 0**（先前的 0 字节与 3 字节无效捕获已降级标注 not evidence）。结构不变量经独立实测：默认关闭 **16 键／闭包 38 行／零 native-reset 模块**，启用后 **19 键／闭包 282 行**且 `register_reset_default_verifier.py` 仅在启用时进入。安装顺序按裁定为 Task3 verifier **先于**可选 `RegisterProgramVerifier`（计划 L227 行文顺序被拒且有通过性负例）。收据见 [Task5 摘要](../../runs/stage2-e2-native-reset-task5-software-20261012/task5-software-summary-receipt.json)、[源码清单](../../runs/stage2-e2-native-reset-task5-software-20261012/task5-source-manifest.json)。**未证明：** 无正向证书；已启用 selector 读写路径与 minimal-bootstrap 选取须由 native 门禁证明。

2026-10-12 Task6（剩余 reset 义务）软件半程完成（**独立复核待启动**）。`scenario/ibex_pulp_dual_source.py 86460398…085a`、`tests/scenario/test_register_reset_default_bootstrap.py 7730cc8e…c658b7`（9 tests）、`tests/scenario/test_register_reset_default_rejections.py efa51614…b57b9`（6 tests）。真 RED exit 1、`7 failed, 1 passed in 8.62s`（7 项全为缺失符号 AttributeError）。minimal bootstrap 移除 gpio_b GPIOEN／INTEN 与 gpio_a PADDIR／PADOUT，保留 gpio_a GPIOEN（保 checker）与 gpio_b INTTYPE_LOW；**shipped bootstrap 五个镜像 SHA 全部不变**；可达性以真实执行证明停在 `0x11000` 且 store 账本无禁止地址。**PADIN/INTSTATUS 诚实标注为非 RED**（6 项在任何改动前即通过，报为回归守卫），版本 profile `reset_value=None` 与 sidecar `0` 分别断言，未放宽 `_READ_EFFECTS`／`_WRITE_EFFECTS`／`CLEARING_SIDE_EFFECTS`。主张已按裁定改写为"固定 ISR 字节保持存在，且在记录式 arming 后被执行"（原句按字面不可满足）。报告见 [Task6 报告](../../runs/stage2-e2-native-reset-task6-software-20261012/task6-report.md)、[源码清单](../../runs/stage2-e2-native-reset-task6-software-20261012/task6-source-manifest.json)。**遗留交接：** `ibex_pulp_register_replay._verify_bootstrap_plan` 的 minimal-bootstrap 选取分支与 `ibex_pulp_online.py:674` 硬编码 shipped bootstrap 尚未接通，故 minimal bootstrap 目前不可被运行选取。

2026-10-12 native 门禁阶段启动：按计划 Task5 准备 `runs/stage2-e2-register-reset-default-warm-20261012-v1/` 与 `-cold-20261012-v1/`（`check.py`／`supervise.py`／`fresh_cli.py`／`preparation.json`），随后串行执行 warm generation → warm fresh → cold generation → cold fresh，每阶段独立 180 秒 single-worker／RSS 预算（不放宽），全部终态后再做独立完整 JSON audit。**尚无任何正向 `ordinary_register_reset_default_certificate.v1` 证据；本节只记录启动，不代表通过。**

2026-10-13 Task2b（用户授权的 Task2 范围化重开，native build 资格认证记忆化）**完成并通过独立精确 SHA 复核 ACCEPT-WITH-NOTES（无阻断）**。起因：冻结 Task2 在每次 `validate()` 内对每个 target 重跑 `local_build_identity`→`build._prepare`→`_prepared_if_current`→`_validate_cache`→`_host_sources`，实测每次 `advance_initial` 19 次 `validate()`×2 target＝**38 次重认证**、约 **68×** 于禁用路径（2.53 vs 0.036 秒/组件步），而完整门禁约需 430 组件步（≈18 分钟）对计划硬编码的 **180 秒**预算，故任何已启用门禁都不可能通过。修法：模块私有 `_QUALIFICATIONS` 纳入四路身份 pin，`_native_build_qualified` 以 `(target, 已提交 lifecycle_ordinal, 记录的 build_inputs_sha256)` 记忆化，`_drain` 提交 lifecycle 时显式驱逐。**实测 5 次 validate 重认证 10→0（1.664→0.014 秒，118×）、advance 形状重放 38→0（6.370→0.059 秒，108×），`_validate` 执行次数仍为 19。** SHA：`native_reset_evidence.py` `180bd069…b2f3` → `409af86efa09ac2efa5fc577c3fab3e8dabf0e4bd5dd4938ef006683a502f133`；测试 `5f6539ff…e3a` → `f93c181c228e5fe531f2a31a1b25c2aaad0ad1d45fb3dd0912374358c211f945`。回归 81／25／132／21 全 exit 0；复核者自跑同一批并独立复现 0 次重认证与 19 次 `_validate`。**诚实语义边界：** 同一未变已提交 lifecycle 内，首次资格认证后的 build 字节漂移不再重检；但每个 lifecycle 提交边界仍重算并拒绝，证据永久 incomplete。复核另证：同进程伪造 memo 被限定在该边界内，**错误 digest 的伪造键仍被拒**。见 [源码清单](../../runs/stage2-e2-native-reset-task2b-memoization-20261012/task2b-source-manifest.json)、[测量收据](../../runs/stage2-e2-native-reset-task2b-memoization-20261012/task2b-measurement-receipt.json)、[独立复核](../../runs/stage2-e2-native-reset-task2b-independent-review-20261012/task2b-independent-review.md)。复核遗留两项记录缺陷（RED 收据的 machine-readable SHA 写成了新字节、未声明下游旧 SHA 后果）已交实现方修正。

2026-10-13 native 门禁在 Task2b 身份上执行：**Task2b 效果获真实门禁确认**（159 bootstrap 步由 2.53 秒/步降至 **0.19 秒/步**，28.66 秒完成），两门禁均跑完 bootstrap 与两个 case（write `0x80000000` 已验证、reset 前 read 已验证），随后被**冻结 Task4 的真实地址空间缺陷**拦在 reset 之前。warm generation 166.165 秒／峰值 705,069,056 字节；cold 168.933 秒／峰值 705,122,304 字节；均 `status=command_failed`、`dut_finding=false`，预算与 RSS 上限未放宽。**三态分类：既非正向证书、亦非 verifier 拒绝/缺口文档，而是"在 reset 前被冻结生产代码拒绝"**；独立 audit 未执行，fresh 两阶段因无认证 bundle 不可达。缺陷：`_register_reset_default_selected_spans` 以**绝对** `result_address`（65540）构造 span，而 `_register_reset_default_selected_commit` 以**内存相对** `byte_offset`（4）判定包含，`65540 <= 4` 为假 ⇒ 该 READ 自身结果提交被误判 unselected ⇒ `session.reset()` 抛 `register-reset-default-unselected-commit`。门禁代理以直接调用冻结方法的对照实验证成（同一 commit 与方法：声明 span→False、解析器构 span→True）。**覆盖缺口：** Task4 唯一相关测试是反例（`test_register_reset_default_session.py:556`），无正例。Root 已更正此前"门禁脚本漏调用 configure"的误判（通道经 Task5 可信安装器正确配置；`:935-938` 在 `binding is None` 时提前返回而异常在 `:1004`，该状态不可达）。用户授权重开 Task4 修正地址空间比较并补正例与边界反例。证据见 [缺陷复现](../../runs/stage2-e2-register-reset-default-warm-20261012-v1/attempt-3-task2b-unselected-commit-refusal/selected-span-reproduction.json)、[地址空间证据](../../runs/stage2-e2-register-reset-default-warm-20261012-v1/attempt-3-task2b-unselected-commit-refusal/selected-commit-address-space-evidence.json)及 cold 门禁同名 attempt 目录。**仍无任何正向 `ordinary_register_reset_default_certificate.v1` 证据。**

2026-10-13 native 门禁**首次跑完整条流程**并精确定位正例阻塞原因。在 `native_gate_budget.v3`（600 秒，具名版本化修订，取代 v2=300／v1=180；单 worker／RSS／锁／串行／不重试／完整捕获不变，`rss_limit_raised=false`）下，warm generation 完成 bootstrap→两个 case→reset→183 步 resume→post-reset case→`finish_export`→认证保存，`python_atexit` 442.06 秒、`worker.exit=3`（断言失败非预算终止）、`dut_finding=false`、峰值 1,354,801,152 字节；**warm fresh exit 0、489.641 秒、`matches=True`、event_count 12,784 相等、`first_difference=None`**，拒绝文档在 fresh replay 下逐项复现。**正例仍不出证**：`reset_default_readbacks={before:2147483648, after:2147483648}`、状态 scope 拒绝式。**真实原因经两次自我纠正后确定为 `incomplete_command_in_reset_interval`**——两种 policy 的共同阻塞是规则拒绝 bootstrap 的源码已知"无关写"（gpio_a 首 offender ord177/seq23 `write offset=0 value=255` PADDIR；gpio_b ord161/seq9 `offset=4 value=257` GPIOEN；gpio_a 共 4 个 offender，其中 ord220 为重放的 INTEN `affecting_write`），故重放的 affecting 写只是 **warm 特有的第二层**，**cold 才是证书工具**（cold 清空指令槽、resume 停在 `instruction_start`，可观察到 0），warm 仅作记录式 resume 证据。**"复位未投递"假设已撤回**：渲染确为 `assign dut_p_1 = ~reset`＋`.HRESETn(dut_p_1)`、`driver_reset` 8/8 tick、`driver.cpp` 输出 0→1→0 真实脉冲，且新进程的 Verilated 实例按构造即处于复位值；同时存在**独立缺陷——gap 原因被掩盖**（冻结 verifier `:513/:514/:523/:530`，pre-reset interval 先以 `setdefault` 写入 `missing_actual_reset_barrier_binding` 并丢弃真正原因，致真实原因在产物中完全不存在并把一轮调查引向错误方向；修法为发布逐 interval 原因，诊断投影、fail-closed 不变，**与规则范围决策合并为一次范围化重开**）。规则放宽有 RTL 依据：`apb_gpio.sv` 中 `r_gpio_inten` 仅有两个写入者（`:217` 异步复位清零、`:234` 自身 APB 写），其余皆读，故对 PADDIR/PADOUT/GPIOEN 的写不可能改变 INTEN 的值；但 `r_gpio_en` 在 `:138` 门控 IRQ 输出，放宽须限定在被观察读回范围。**Root 不预先授权**，待 cold 逐字实测原因到手后一并裁定。另：**Task4b（地址空间＋信封解包）已获独立复核 ACCEPT-WITH-NOTES（无 Blocker／无 Important）**，`session_runtime.py` `d49ea5cf…`、测试 `8b15bc5e…`；**Task2c（增量验证）进行中未冻结**，实测门禁规模 1106 条 fact／1.80 MB／549 命令，两条逐 fact JSON 腿（14.0 ms／23.3 ms）主导，设计以内容派生 `_revision` 折叠实际读取内容（含经 `_event_ref_by_id` 读回的活动 journal 事件），从而以内容派生指标解决 `event_journal.py` 仅有 `_count` 的漏洞。**仍无任何正向 `ordinary_register_reset_default_certificate.v1` 证据；cold/warm 四阶段须在 Task2c 冻结后重跑。**

2026-10-13（本会话最终状态）Task2c 增量验证仍在 RED→GREEN 循环中、**身份未冻结**，故 native 四阶段尚未在最终身份上重跑，**仍无任何正向 `ordinary_register_reset_default_certificate.v1` 证据**。两个更正与一条教训：①Root 曾把"一段时间未变动"的 `native_reset_evidence.py = 4c8edce9…` 误当作已冻结身份放行门禁——**该判断错误**，Task2c 从未声明冻结；门禁代理纪律使其只花 **14.031 秒**即在安装期失败（`ValueError: not enough values to unpack (expected 6, got 0)`：空元组哨兵 `_CONTENTS[self]=()` 与 `:292` 的六项解包不匹配），分类为"未跑完"、由当时生产代码所致，非 DUT finding、非预算停止，cold 全部 attempt 保留。**流程教训：宣布冻结前必须先在候选字节上跑通约 10 秒的安装/自检测试；"一段时间未变动"不等于冻结。** ②该缺陷在 Root 复核时已不复现：当前 `3a90d5a3…`，哨兵已改为 `None` 并走 `revision=None` 分支，Root 实跑自测 **1 failed / 81 passed**，唯一失败是**真实 RED**——`assert 430 <= 12`（十次未变 validate 在 26 条缓存 fact 上执行 430 次昂贵逐 fact 腿）。**Task2c 的诚实缩围：** 门禁规模测量（1106 facts／4,003,223 规范化字节）显示冻结 `_validate` 约 25.85 ms/次，记忆化仅使已提交前缀腿 11.42→1.50 ms（7.6×），而 **journal tie 不可约简**（14.43→14.42 ms，1.00×），因为检出活动 journal 事件的原地变更必须读取其内容，唯一廉价的 `sha256(declared)`（1.4 ms）恰是有漏洞的类计数捷径；故设计改为内容派生 `_revision` 只门控前缀重建、**live journal tie 每次调用全量严格运行**，实现方明说为**部分收益**。**交接：** Task2c 发出 "FROZEN"＋两个最终 SHA 且通过安装自测后，`repin.py` 重指 19＋3 pins → 复核 22/22 drift 0 → **cold generation → cold fresh → warm generation → warm fresh**（v3 600 秒、单 worker、RSS 不变）→ 先取 cold 逐字实测原因与真实读回 → Root 作规则范围决策 → 两门禁终态 PASS 后才做独立完整 JSON audit。仍待授权（合并为一次范围化重开）：**规则放宽**（允许与 INTEN 无共享状态的命令；RTL 依据已核实：`r_gpio_inten` 仅 `:217` 异步复位与 `:234` 自身 APB 写两个写入者）与 **gap 掩盖缺陷修复**（冻结 verifier `:513/:514/:523/:530`）。

2026-10-13 ★★★ **Task5 native 验收闭合：正向 `ordinary_register_reset_default_certificate.v1` 首次产出并在 fresh replay 下复现；两门禁终态 PASS、独立 audit 双双 exit 0。** cold（证书工具）generation exit 0／`status=complete`／377.646 秒／峰值 1,358,082,048 字节／`dut_finding=false`，fresh exit 0／423.831 秒／`matches=True`／`first_difference=None`，五项断言相等且证书**逐字节同一**（`evidence_id=482723a625d613daf23fa78faf9e1a5ed48eccbb61ac3158f3a997c51f9d71d4`，跨两次 generation 与一次 fresh 复现）。warm（记录式 resume 证据）generation exit 3／454.563 秒／0 证书／`affecting_write_in_reset_interval`（未掩盖），fresh exit 0／408.213 秒／`matches=True`。独立 audit：cold `passed_positive_certificate_and_fresh_replay`（12,052 事件、1 证书、285 pins、闭包 45/274/21/274/274）、warm `passed_terminal_refusal_and_fresh_replay`（12,784 事件、0 证书），二者均重算身份/产物哈希、经 `_verified_register_bundle` 重建 bundle、活体校验三份通道文档、检查 lifecycle/epoch/命令游标连续性、重编译全部原始请求、校验 cache 构建，并交叉核对证书 `evidence_id` 重哈希、seal↔reset-lifecycle、`read_access_ref`↔case-2 记录、`ram_commit_ref`↔case-2 commit、`coverage_cursor`↔重算账本哈希。证书字段：`proof_scope=observed_source_bound_reset_default_readback`、`reset_value=0`／`observed_reset_value=0`、**四项 grants 全 False**、`read_access_ref.observed_readback=0`、`coverage_cursor.command_count=105`、`reset_seal={barrier 6996,target_epoch 1,logical_process 2,cpu_source_epoch 1,memory_generation 1}`、`ram_commit_ref={byte_offset 8,be 15,cells all 0}`、`readback_allowance={scope:observed_readback_only, irq_semantics_granted:false, permitted_command_ordinals:[177,181,185], permitted_registers:[PADDIR,GPIOEN,PADOUT], inten_writer_source_lines:[217,234], irq_output_gate_source_line:138}`。gap 已诚实：cold headline 仅 `[{gpio_b, affecting_write_in_reset_interval}]`（gpio_a 因出证不在列），`interval_refusals` 逐 interval 发布。冻结身份（22/22 pins drift 0）：verifier `f04ec508…`、native_reset_evidence `feec776a…`、session_runtime `d49ea5cf…`、replay `37d308be…`、CLI `78fd8614…`。脚本侧 bundle 轮换修复已生效（`exist_ok=False` 未动）；`attempt-5` 为保存阶段失败且其前驱已签发同一证书。证据见 [cold audit](../../runs/stage2-e2-register-reset-default-cold-20261012-v1/independent-audit.json)、[cold summary](../../runs/stage2-e2-register-reset-default-cold-20261012-v1/summary.json)、[warm audit](../../runs/stage2-e2-register-reset-default-warm-20261012-v1/independent-audit.json)、[Task3c 复核](../../runs/stage2-e2-native-reset-task3c-independent-review-20261013/task3c-independent-review.md)。**仍欠：** 运行能力表/阶段状态更新；Task3b 复核因 verifier SHA 变更失效须重做（`downstream-stale-pins.json` 记录 86 个产物须重指）；Task6 minimal-bootstrap 选取分支未接通；P6/P7/P8（多协议复用、自动接入、F6 DMA）继续开放。

2026-10-13 P6 行 3（AXI4-Lite）通用 IP 事件层增量已登记（本轮为**文档同步**，不新增 native/verifier 证据）。**通用协议事件层新增第四种协议 `axi4-lite`**（此前只有 `tl-ul`／`apb3`／`wishbone`）：`scenario/ip_protocol_events.py` 的 `_consume_axi4_lite` 投影 19 个从机侧角色（`awvalid awready awaddr awprot wvalid wready wdata wstrb bvalid bready bresp arvalid arready araddr arprot rvalid rready rdata rresp`），语义为请求由 **VALID 触发**（不由握手完成触发）、AW 与 W 可任意先后且写只被接纳一次、响应载荷与所应答的传输做**字段连接**、等待只在"该边沿没有推进"时计数（前置快照法）、**超时只施加于请求相位（AR/AW/W）**、已被接纳后的 B/R 等待只报观测、非 OKAY 响应码按测量值上报并另报 `protocol_error`；`scenario/ip_protocol_checker.py` 新增 `axi4lite_*` 违约检查（停滞期间载荷不得变化、VALID 未 READY 不得撤销、响应必须跟随自己被接纳的请求、单笔未完成、被保持的**请求**通道超预算），而**被保持的响应（B/R 迟迟不来）只作观测、不作违约**。**目标端模板契约由 11 增至 12：** `local_harness/template_contracts.py` 新增 `target.axi4-lite` / `single-outstanding-error-codes`（仓库存量清单的**有意扩增**；**从机侧**契约，与 CPU 侧 `cpu.axi4-lite` / `no-response-code` 不同，从机驱动 `bresp`/`rresp`）。**规划实测通过：** 新增 `local_harness/axi4lite_register_template.py`，`plan.py` 的 v2 白名单接受 `('axi4-lite','1')`，真实 profile `configs/peripherals/zipcpu_axiluart/component_profile.json` 的 19 个角色方向/宽度与 RTL 顶端口一致（`awaddr/araddr` 4 位、`wdata/rdata` 32 位、`wstrb` 4 位、`bresp/rresp` 2 位）。**真实 RTL 正向证据：** `local_harness/runtime_renderer.py` 的 `axi4_lite_uart` 分支新增被动 `base_protocol_trace`（19 个 `trace_*` 端口，`channel='ip_protocol_trace'`）、`scenario/runner.py` 两处 `kind_protocol` 映射新增 `'axi4_lite_uart': 'axi4-lite'`，该 target `backend_ports` 19→**38**（19 驱动角色＋19 被动抽头）、`physical_exports` 仍为 **8**（抽头不参与输入所有权，这是有意的）；在 pinned `zipcpu_axiluart` harness 上写 SETUP(offset 0, value 25) 与 TX(offset 12, value 0x41)，从 RTL tick 样本投影出 `transaction_request`×2／`transaction_accept`×2／`transaction_response`×2／`transaction_timeout`×**0**，**零违约**，两次写完成的载荷为**实测**地址与数据 `[(0,25,0,'write'),(12,0x41,0,'write')]`，且 TX 写的 `wdata` 与 RTL 自己解出的串口字节 `0x41` 一致。**测试：** `tests/scenario/test_ip_protocol_events_axi4_lite.py`(12)、`tests/scenario/test_ip_protocol_checker_axi4_lite.py`(13)、`tests/integration/test_axil_uart_generic_events_real.py`(7)，本轮新增共 32 项。**边界（显式未做）：** ①**CPU→AXI4-Lite→真实 IP 的端到端组合仍走 IP 专属的 `RegisterTarget`（路由器抽象）路径，尚未改走通用事件路径**；②**通用寄存器观测会话（`axi4lite_register_observe` 这一类 kind）尚未实现**（需要 beat→AXI4-Lite 的 RTL adapter 与一条新的 `ACCESS_AXIL_REG` 驱动命令）；③**双向数据链的 RX 方向（引脚→RDATA→CPU 读回）在通用事件路径上尚未验收**；④**多例持久会话未做**（受控错误负例另见 CV32E40P＋OpenTitan UART 的独立增量）。上述真实 RTL 数字来自**本轮真实的 Verilator 编译与运行**（同目录集成测试可复跑），并非遗留证据；本轮未运行 pytest 全量。P6 行 3 结论仍为**未通过**，详见 [P6 逐协议行适配清单](../superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md)。
