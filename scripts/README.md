# Scripts

本轮 Task3 Path 分派聚焦候选（2026-10-12）：Path.open 缓存旧源码攻击 RED 1 failed；公开分派 RED 12 failed；special-entry RED 10 failed。已固定 Path 工厂与实际 concrete 类型完整 MRO、成员/descriptor/accessor identity 与 code，规则绑定和运行时守卫均检查；最终聚焦 26 passed / 73 deselected，10.39s，未执行 native 或最终 full regression，仍待精确 SHA 独立复核。verifier `229485466093033be9f96c38bfc8dfbd757c92daf7ca93912577964b04fb255f`，tests `7b6527f0530869cb0c497517f06d927d5e59e668a1376ae053413630dbd3e090`；旧 92-pass 兼容结果仅属于此前冻结候选，不能证明本轮改动。

支持边界：拒绝标准类属性改写，并假定加载中的 Python 代码对象完整；不覆盖直接改写 function.__code__、显式 type.__setattr__ 或同进程任意私有 Runner slot 改写。覆盖这些攻击需在冻结 Runner/NRE 分派加入独立检查或原生不可变边界。Path 类公开分派已纳入检查；stdlib 内部对象内容（如 `_flavour`）与任意 module helper 改写不在本轮闭合范围。Task3 仍仅 source-rule/refusal 软件范围，不授 native reset certificate、functional 或 verified L2；原 Stage2 D5/D6/D8、完整 E1/E2 与 E3–I 继续开放。

2026-10-12 zero／fullmask实际门禁当前状态：generation50928已终态exit0／complete，152.13179933300125秒、workers1、峰2,590,924,800 bytes低于3,251,445,760限额。实际14cases／20确认关联／9RAM／28,995events，4alias＋9READ＋1plain共14证书、gaps=[]；实际B.INTEN写读0及13条native IRQ quiet snapshots为0，zero操作不变／full SET为ffffffff／full CLR为0。60总APB与完整cached currentinputs待独立产物audit。semantic SHA `7f1ea66fd9c05f9592ed49be66c7bf03e2f519b91ad35c9d6c5242b6730664c1`，identity SHA `974ffd0d7967cdb04cdee6e4acc03f47834cf93e362258347dcb04687097ad18`；见[实际摘要](../runs/stage2-e2-register-alias-mask-verifier-20261012-v1/summary.json)与[资源记录](../runs/stage2-e2-register-alias-mask-verifier-20261012-v1/resource.json)。fresh85373已终态exit0／complete：166.55756382399704秒、workers1、峰2,641,014,784 bytes低于3,242,532,864限额，完整fresh比对通过；独立最终产物audit已PASS：283pins／9产物／14exact重编译／28,995events／20关联／60APB／9RAM／14封存access／14证书、13 IRQ quiet snapshots及CPU／GPIO B各1,152条raw采样零值核对；完整fresh／resources／3个current cache／source一致。zero/fullmask scoped native包已审计通过，完整Stage2及native reset／权限矩阵仍未完成。原非zero/fullmask四括号audit通过保持历史；完整Stage2及actual reset／权限／width／mask／effects矩阵仍未完成。

2026-10-12 alias实际门禁当前状态：generation74397已终态exit0／complete，164.01385019000736秒、workers1、峰2,355,449,856 bytes低于3,176,628,224限额。12cases／18确认关联／8RAM／25,237events，4alias＋8READ证书、gaps=[]；semantic SHA `e744874aa3c1660c455f081713c9c77d406734156db92717a1136911420d1ae0`、identity SHA `8019be229437fb9b1784f7a0d6cca2d1aa8705246374fb7ed486fe62262c6c81`。见[实际摘要](../runs/stage2-e2-register-alias-verifier-20261012-v1/summary.json)与[资源记录](../runs/stage2-e2-register-alias-verifier-20261012-v1/resource.json)。fresh11283已终态exit0／complete：153.30511558598664秒、workers1、峰2,359,955,456 bytes低于3,156,848,640限额，完整fresh比对通过；generation与fresh各自独立180秒预算。独立最终产物审计已终态exit0／PASS：283项pins／9认证产物／12exact重编译／25,237events／12封存access／8READ＋4alias证书／18关联／8RAM／54总APB；资源与阶段顺序、plan SHA、journal及全部fresh报告比对通过。四括号scoped包已审计，完整Stage2仍未完成。源码／脚本继续冻结，历史产物保留；最终037软件2 passed／165.70秒仍仅软件证据。完整Stage2未完成，zero／fullmask及actual reset／权限／mask／width／effects矩阵保留后续要求。

2026-10-12 当前检查点：v5实际 generation 已终态 exit0／resource complete，单worker 178.410330162秒，峰2,626,240,512 bytes低于3,125,706,752限额；原14 cases与完整ordinary／verifier验证范围保持。production fresh CLI串行重试已终态exit0／complete，167.28877223400923秒、available5,320,716,288 bytes、峰2,667,540,480 bytes低于3,173,232,640限额，workers1；完整semantic／event count／ordinary／verifier／preflight比对通过。见[fresh结果](../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-cli-verification.json)。独立最终产物审计已通过（exit0）：9认证产物／283项当前源码pins／29,985events／14次exact重编译／13证书／21封存access／28关联／6RAM，fresh全部wrappers及preflight完全相等，两阶段resource均complete；见[独立审计](../runs/stage2-e2-register-verifier-cli-20261012-v5/independent-audit.json)。本轮scoped verifier／保存／fresh包已闭合，完整Stage2仍未完成；下一包按declarative generic关系推进SET／CLR alias行为及非空saved-file回放，不授aggregate L2或functional。首轮与大JSON只读审计重叠导致RSS budget_terminated，return124／7.965711960秒的失败证据保留于[首轮归档](../runs/stage2-e2-register-verifier-cli-20261012-v5/fresh-attempt-1-rss-budget-terminated/)，预算策略未提高；generation与fresh各用独立180秒预算，不是combined180通过。见[实际摘要](../runs/stage2-e2-register-verifier-cli-20261012-v5/summary.json)及[资源记录](../runs/stage2-e2-register-verifier-cli-20261012-v5/resource.json)。当前build SHA `06334fedf08cacd861806362dc216026af3b426cd80be2ceb10929ff2197056c`、integration SHA `7fe28b291fd2f2164db5edcaffd6ad7b8c0a5a6a52d43d82f87cc974c8583774`已核对；旧v4完整保存但wall_timeout证据保持历史。D5／D6／D8、完整E1／E2及E3–I继续未完成。

2026-10-12 当前继续：v4在178.245秒完成认证保存及summary，但worker整体180.093秒超时，generation未通过、fresh未执行。三子代理并行完整bundle独立审计、退出阶段定位与真实导出成本测量；原预算/源码冻结/失败产物和完整Stage2范围保持。见[执行报告](../docs/reports/stage2-e2-register-verifier-session-execution-20261012.md)。

2026-10-12 最新执行：窄READ及scoped verifier软件边界已验证；v2真实14case/28确认关联/6RAM/29985events通过（140.50秒），production可信file freshCLI独立通过（133.80秒），完整state/semantic匹配，A/B各148declared/142effective/0verified、L1。首次factory固定READ16失败已补RED修复并保留产物，最终独立audit通过 findings=[]。下一包Session verifier opt-in已有8缺API RED＋1defaultoff GREEN，生产未实现；完整Stage2/E1/E2继续。详见[执行报告](../docs/reports/stage2-e2-register-verifier-execution-20261012.md)。


初期执行记录（后续v2结果见上）：2026-10-12 寄存器行为 verifier／窄字段实际CPU READ 执行中：三子代理并行，Root completed-access封存4RED→31GREEN，actualreadback/reset/mask/permission/effects与exactfield能力继续，未授storage/functional/aggregateL2，未运行本轮新DUT。见[执行报告](../docs/reports/stage2-e2-register-verifier-execution-20261012.md)。

2026-10-12 production ordinary APB Session／assembly／可信file fresh CLI已实现并验证：真实10case新增18关联，加bootstrap6条共24完整snapshot，22387事件；分阶段freshCLI exit0，原组合180秒超时保留。默认38/40、启用278项闭包，全部grantsFalse，原Stage2/E1/E2仍继续。见[执行报告](../docs/reports/stage2-e2-ordinary-access-production-replay-20261012.md)。原 Stage2／E1／E2继续。

2026-10-12 ordinary APB Runner association 软件包已实现并独立复核：实际 CPU closure／请求与响应绑定、私有 parsed sample digest／callback confirmation、命令前解码和容量检查、raw/base 独立 journal 引用及 reset 缺口处理。最终覆盖212个不重复软件测试／34子测试：联合211pass／1旧fixture失败，最终Runner模块10pass补证，生产SHA无漂移；详情见[执行报告](../docs/reports/stage2-e2-ordinary-access-association-20261012.md)。未运行新DUT门禁，生产Session/assembly/fresh回放和行为verifier继续执行，E1/E2及完整Stage2仍未完成。

2026-10-12 ordinary APB receipt 低层目标接口首包通过根回归166项／34subtests；新增默认关闭的 `configure_ordinary_apb_access_receipts()`，Router保留真实命令receipt并区分callback确认与同步返回。当前生产CLI尚无ordinary-receipt启用选项，Runner事件引用绑定与fresh接线待后续实现；不授行为verified或L2。见[实现报告](../docs/reports/stage2-e2-ordinary-access-receipts-20261012.md)。

2026-10-12 最新实际结果：E2 capability preflight opt-in 门禁执行通过（exit 0）：10 cases（8 RMW／2 READ）、54条实际APB边界、2次read→RAM认证commit，可信CLI fresh完整22,339events matches。requested minimum L1，startup报告＝plan报告＝fresh CLI报告；每个实际GPIO alias保留完整14寄存器／72字段矩阵，declared L2／effective L1／verified None。46项冻结source pins包含40项production closure；identity SHA `308cb88e87c6b300ae12d60dd9c200a0328d5a0352dd02a2ced48ce918ab716d`，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。singleworker complete154.998309826秒，峰2,472,001,536 bytes、RSSlimit3,291,369,472 bytes，available5,438,853,120 bytes。独立产物audit已通过，findings=[]：46项源码pins／40项production closure／9项authenticated artifacts、10次重编译／18次实际CPU MMIO交付／54条APB边界／2次RAM commit／22,339events核对一致；本轮cache实际GPIO279／279项、CPU348项冻结输入核对通过（旧门禁278／278／347保持历史）。root额外只读startup重建configuration／report同SHA匹配；环境身份差异与fresh全trace未另存的限制见本轮报告。见[独立audit](../runs/stage2-e2-register-capability-cli-20261012/independent-audit.json)。详见[本轮capability报告](../docs/reports/stage2-e2-register-capability-preflight-20261012.md)。 见[本轮实际摘要](../runs/stage2-e2-register-capability-cli-20261012/summary.json)及[资源记录](../runs/stage2-e2-register-capability-cli-20261012/resource.json)。

`make_register_assembly()` 默认不加入 `requested_minimum_level`，旧schema16／17、runtime configuration与assembly布局保持；默认38项生产闭包。显式None／L1／L2／L3开启通道，40项闭包补入capability helper与等级模块；完整矩阵不能满足L2时在命令前拒绝。安装实际adapter后、begin前调用 `Session.configure_register_capability_preflight()`：startup／begin／fresh重算当前实际支持及minimum，保存manifest／plan的opt-in报告；执行后导出startup pin，不因slot消耗重算能力。保存assessment不是权限，verification=None，不授functional或verified L2。

软件证据：根联合162 passed／36subtests（205.90秒）在最后legacy helper一行修复前完成；修复后联合31 passed（90.49秒），独立软件16 passed（30.19秒）；两项P2均有RED→GREEN证据，当前实际门禁使用最终冻结源码。source-pin漂移在prepare／submit／cached retry三个实际对象负例RED后修复，注册及返回缓存前拒；legacy无native base trace却产生无效报告的负例RED后修复，完整declared矩阵与unsupported gaps保留。本轮实际摘要确认40项production closure／46项总pins；capability preflight与minimum接线已交付。E1／E2 checkbox继续未完成，剩余code-owned分操作verifier／证书、实际reset／权限／mask／width及已支持副作用行为、verified矩阵／L2 minimum证据。旧门禁仅证明各自冻结版本，不能证明本轮源码。

历史冻结版本检查点：2026-10-12 E2可信保存文件CLI门禁执行通过（exit 0）：10 cases（8次窄字段显式CPU RMW＋2次DIR／OUT full-word READ）、54条实际APB边界、2次read→RAM认证commit；保存plan为schema16，production `replay-register-programs` 从fresh实际factory／before-begin adapter重编译原requests，完整22,339events matches，semantic SHA `0ddbd7be8c0a956d2997957bf0c064fce4036f2ef4de0df576a98115af4feb08`。verification scopes为 `register_program_reconstruction`、`register_program_admission`、`online_complete_prefix`；identity SHA `d2a480c0a9e889930782de5e79f083fe4d2bc595f01d1845ca883c6cab9f9277`。44项冻结source pins包含38项生产selector闭包，单worker complete137.546529879秒，峰2,442,502,144 bytes，RSSlimit3,231,547,392 bytes。根软件105 passed／26subtests（136.20秒），另2项保存投影positive通过（9.85秒）；独立软件35 passed／24subtests，selector完整16 passed／24subtests（63.45秒）。独立产物audit已通过：44项源码pins／38项production selector闭包／9项authenticated artifacts、10次当前上下文重编译／18次CPU MMIO交付／54条raw APB边界／2次RAM commit／22,339events及3个cache binary的278／278／347项冻结输入核对一致。E1仍为14寄存器／72字段declared范围；E1／E2完整阶段checkbox保持未完成，schema17已实现并软件验证；真实注入fault门禁不是原计划新增验收前提。原计划剩余为capability等级证据与实际reset／权限／mask／width及已支持副作用行为验证，不授functional、verified L2、RFuzz或BFM。旧四字段／helper／runtime门禁按各自冻结版本保留，不能证明本轮改动。 见 [新门禁摘要](../runs/stage2-e2-register-file-cli-20261012/summary.json)及[E2报告](../docs/reports/stage2-e2-gpio-cpu-register-progress-20261011.md)。 见 [独立audit](../runs/stage2-e2-register-file-cli-20261012/independent-audit.json)。

新生产接口为 `make_register_assembly()`、`make_register_factory()`、`make_register_runtime_factory()`、`save_ibex_pulp_register_bundle()` 与 `replay_ibex_pulp_register_files()`。Session在declare slots后、begin前安装实际adapter；schema16保存正常register前缀，schema17保存真实uncertain attempt的phase／case_index与nullable Session failure，均包含原requests／完整配置及actual gate_state。可信闭集ordinary GPIO assembly固定native observation／memory commit／installed persistent gate，checker=None；38项当前源码闭包、artifact SHA、trace事件语义、plan／manifest／terminal state先验证，fresh执行只重编译原requests，不以saved paths／bytes／regions恢复授权。

历史检查点（按当时冻结源码；本轮结果见上）：2026-10-12 E2 directed API：先构造实际factory／Session并declare_instruction_slots，再在begin前安装 `RegisterProgramRuntime`；warmup到真实waiting slot后仅submit原始 `register_program_request.v1`。fresh重放需新factory及同样before-begin adapter，submit原requests＋expected_manifest；禁止用保存bytes／regions恢复授权。新门禁 [监督器](../runs/stage2-e2-register-runtime-rmw-20261012/supervise.py)已实际通过10 cases／54 APB／2 RAM及完整22,339events重算匹配，独立产物审查通过：36源码 pins、10次当前上下文重编译、18次CPU MMIO交付、54条APB原始引用、2次RAM commit、22,339事件摘要及3个cache binary／276、345、276项冻结输入一致；fresh state文件独立相等，fresh plan／全trace由冻结worker断言核对（未另存fresh全trace）；该API仍为directed-only，不是生产file-selector／CLI授级入口。旧helper和四字段脚本保留历史pins。

可信register文件重放：

```bash
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py replay-register-programs \
  --cache-dir runs/stage2-e2-register-file-cli-20261012/cache \
  --run-dir runs/stage2-e2-register-file-cli-20261012/bundle
```

该分支输出matches、verification_scope、event_count、semantic_sha256与差异上下文；opt-in bundle另输出fresh `capability_preflight`，默认不加该字段。匹配退出0、比较不符退出2、身份／配置错误退出1。保存bundle通过新integration的 `save_ibex_pulp_register_bundle`，assembly固定local selector，不能传保存路径选择任意provider代码。

Scripts for the current independent-harness workflow live here and under
`src/myfuzz/scripts/`.

```text
generate_local_harness.py             create a generated local harness from a registered profile
record_scenario.py                    record a continuous multi-component testcase
replay_scenario.py                    replay saved evidence using a scenario factory
run_scenario_campaign.py              run a configured scenario mutation campaign
query_capabilities.py                 list documented runtime evidence and limits without starting RTL
run_ibex_pulp_online.py                 run/replay one persistent Ibex + dual PULP GPIO RFuzz pilot
bench_ibex_pulp_cold_start.py         one fresh runtime per saved input: startup-cost baseline JSON
run_first_step_cold_start_run.py      one fresh session per frozen continuous case, aggregated into a pairable cold run directory
bench_first_step_paired.py            pair a continuous run directory with a per-case cold-start one (paired_efficiency_report.v1)
run_first_step_acceptance.py          analyze (or run + analyze) one saved online session: certified chain/s, coverage novelty, per-case p50/p95
check_doc_links.py                    verify relative Markdown links and anchors without touching the files
source_branch_instrumenter.py         optional source-level RTL coverage inserter
instrument_ibex.sh / instrument_cva6.sh optional CPU-only source-instrumentation helpers
generate_soc.py / run_soc_campaigns.py separate historical full-SoC composition path
runs/                                 dated campaign and comparison launchers
```

The independent-harness design is documented in [`docs/CURRENT_DESIGN.md`](../docs/CURRENT_DESIGN.md).
The current code boundary and staged implementation work are in
[`docs/CODE_ORGANIZATION.md`](../docs/CODE_ORGANIZATION.md) and the
[`current implementation plan`](../docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md).
The local harness generator and scenario runner use registered component facts,
protocol adapters and explicit dependency bindings.

For the Ibex online runner, `run --memory-commit --persistent-memory-prerequisites`
enables the current authenticated RAM witness and instruction-slot policy.
The policy is off by default; requesting it without `--memory-commit` is rejected
before runtime construction. Replay selects the policy from the verified saved
manifest and recomputes each admission against fresh actual memory evidence.

`run --classified-feedback --classified-feedback-max-records 4096` enables
independent base and classified evidence reporting (capacity 1..65536); it is
off by default and does not enable candidate exploration. With candidates off,
receipt candidate novelty/energy are explicitly disabled and zero; legacy target
coverage remains separate, and a missing functional provider reports unknown.
The channel pins actual observation configuration, installed evidence providers,
source closure and terminal state. `replay-candidates` accepts either feedback
channel and recomputes enabled channels from raw inputs; classified-only scopes
are `classified_case_feedback` and `classified_terminal_state`, without a
candidate scoring claim.

`run --candidate-exploration --candidate-exploration-max-cases 65536` explicitly
requests bounded candidate exploration (capacity 1..65536). The default is off.
The shared builder checks the actual selected paths and matching v2 physical
observations before `begin`, preload or bootstrap. The Ibex/PULP builder now
selects explicit native v2 raw observations for this opt-in: authenticated
executor aliases map the CPU IRQ input and GPIO pulse, and declared GPIO
sub-slices are read from actual vector samples. When both candidate exploration and classified feedback are off, the factory
keeps v1 observations. Explicitly supplied legacy factories still fail preflight.
Candidate mode declares the shipped checker's stable behavior parameters for
fresh replay; observed state is reconstructed by the real bootstrap and cases. The existing `replay --plan --trace`
command checks session execution. `replay-candidates --cache-dir PATH --run-dir SAVED`
verifies a candidate-enabled or classified-feedback-enabled bundle and its closed assembly declaration before
selecting the shipped local Ibex/PULP factory. It reconstructs the bootstrap,
decoder, checker and initial RAM declaration, then recomputes source selection,
weights, per-case scoring and terminal state from raw inputs. Saved scores are
comparison evidence. Historical bundles without the assembly declaration use
the Python `replay_candidate_exploration_files(..., executor_factory=...)` API
with a caller-supplied trusted fresh assembly and matching pinned source version.
The native run CLI and Python fresh scoring API have passed a bounded actual
RTL/RFuzz gate; full protocol and functional feedback remain pending. See the [D8 execution report](../docs/reports/stage2-d8-candidate-exploration-progress-20261011.md).

Candidate mode now counts protocol base coverage only when the actual v2
artifact declares a matching protocol projector and checker. Its bounded
coverage contexts use component/instance/feature namespaces and come from
fresh base observations; they remain candidate correlations and grant no
prerequisites. The native Ibex/GPIO physical context gate passed the run and
trusted replay CLI with 15 context records. This native combination does not
declare a bus protocol trace; generic protocol integration has software raw
projection and fresh replay tests, while native protocol and full functional
feedback still require validation.

`generate_soc.py` belongs to a separate historical tool path. It implements the generation phase of
`docs/superpowers/plans/2026-09-20-soc-composition-assurance-plan.md`: it binds
source-pinned component profiles to elaborated RTL facts, builds the port
disposition ledger and the validated plan, renders the SoC top and independently
audits the generated structure. See `examples/soc_generation/README.md`; this
path is not the active independent-harness architecture.

The three unreferenced prototype generators formerly under `scripts/codegen/`
and two unrelated Codex workspace-management scripts were moved outside the
repository. Their recoverable copies and SHA-256 values are listed in the
external `excluded-files-manifest.json` created for the 2026-10-06 cleanup.

The full pipeline runner is `src/myfuzz/scripts/run_design_flow.py`.

原生 GPIO APB 候选观察门禁见 [执行摘要](../runs/stage2-d8-native-apb-cli-20261011-r2/summary.json)：run CLI 实际 RFuzz 3/3 complete，可信 `replay-candidates` 从 fresh RTL 重算6443事件、候选计分及终态一致；GPIO A／B完整 APB 边界各3／4组。仍仅默认关闭的候选探索，不提供 prerequisites 授权；CPU bus 协议与完整 Stage2 功能验收待继续。首轮脚本在 RTL 启动前失败的记录保留。

[准确分类短门禁](../runs/stage2-d8-classified-feedback-cli-20261011/summary.json)通过实际RFuzz 3/3与可信fresh CLI replay6443events：旧输出谓词为legacy_target_coverage；无Stage2功能provider时functional unknown且无features，verified只消费实际安装provider证书。此门禁memory／IRQprovider未配置，verified0，不证明真实verified正例或功能完成；候选默认关闭及预算保持。

[E2定向CPU寄存器门禁](../runs/stage2-e2-gpio-cpu-register-20261011-r2/summary.json)：新 `compile_register_program` 将声明式四字段计划变成现有Session接纳的真实CPU SW／LW→RAM程序；12例实际GPIO行为检查与完整fresh Session API25201events重放一致。该脚本不是RFuzz、BFM或trusted replay CLI selector，不授L2／功能完成；首轮状态断言失败保留。使用同一heavy-worker／进程树RSS／180秒监督。


2026-10-12续接：D8独立 `--classified-feedback` 门禁执行通过，candidate探索关闭，实际RFuzz3/3 complete；可信CLI fresh完整6,443events matches，semantic SHA `76d867f9a8cc5aee7da2fa1a80c3b921e2fb7833d07a42601333d33739da995e`，范围包含 `classified_case_feedback`／`classified_terminal_state`且无candidate scoring声明。三回执candidate disabled、novelty／energy均0，legacy覆盖单列；实际base GPIO A／B request／accept／response各3／4，verified0、functional unknown。27项当前source pins；singleworker complete76.752490482秒、峰545,849,344 bytes、RSSlimit3,038,162,944 bytes。root冻结九模块最终227 passed（93.18秒）；D8独立产物audit通过：27项源码／13项产物摘要、6443事件、21个APB原始引用、逐例及终态base覆盖重算和3个binary／冻结输入均一致。该组合未安装RAM／IRQ provider，6项positive检查仅软件另列；不授实际verified正例、functional或L2矩阵。D8及E1／E2、D5／D6和完整E–I仍未完成。见 [独立分类摘要](../runs/stage2-d8-independent-feedback-cli-20261011/summary.json)。

2026-10-12 verifier Session／可信file replay最新检查点：Runtime66项及closed saved／Session／CLI联合50项软件通过；实际generation完成14case检查并产13项scope证书（A10操作/B0），但180.18秒在认证保存阶段超时，未获bundle/fresh验收。所有失败产物保留，预算不变，导出重复成本正独立定位。见[执行报告](../docs/reports/stage2-e2-register-verifier-session-execution-20261012.md)。完整E1/E2/Stage2保持未完成。

2026-10-12 导出优化最终软件：Session15项、独立export4项、singleexport/closed saved/CLI联合35项通过；v2实际14case generation正在运行，原独立180秒/RSS预算保持，production冻结。上一轮wall_timeout及partial audit仍只证明部分实际观察，不能冒称认证保存/fresh通过。见[最新执行报告](../docs/reports/stage2-e2-register-verifier-session-execution-20261012.md)。原E1/E2及完整Stage2未完成。


2026-10-12 permission前effect软件矩阵：实际当前factory／Session／CPU waiting／runtime私有对象的14项声明拒绝全部通过（14 passed／22.92秒），命令sequence／ticks／detached journal／gate／RAM与slot／ledger序列前后不变；不是PSLVERR硬件权限错误或完整native矩阵证明。首轮14 failed／20.59秒为fixture deepcopy EventLog底层BufferedRandom失败，未执行任何请求；test-only改为复制事件列表后通过，生产未改。完整Stage2／native reset／全部权限与字段行为仍继续。


2026-10-12 reset-resume有效软件RED：真实GeneratedSession end／begin及READY／END子进程生命周期、实际CPU读取fixed bootstrap words／MMIO与deferred fetch后，Session warm reset成功，所有target epoch实际增加1／CPU waiting清空；随后公共 `advance_after_reset` 缺API产生1 failed／27.53秒。不是伪造PC／waiting／epoch或fixture错误。生产尚未修复；warm／cold＋真实LW／RAMSTORE重执行＋fresh原requests及前effect API guards测试已准备，待新源码冻结后运行。完整Stage2与native observable reset仍未完成。


2026-10-12 recorded post-reset resume计划已review并批准执行：`docs/superpowers/plans/2026-10-12-stage2-recorded-post-reset-resume.md`，Task1 Session与Task2 integration schema接线并行实施；两个实际RED已终态，尚待GREEN。没有新增assemblyflag，未使用resume时旧schema16／17布局保留；实际warm／cold与认证saved-file fresh软件测试已准备，待双方源码冻结后运行，不预授native reset通过。


2026-10-12 recorded reset-resume候选软件检查点：Session `d743b4b2…0af348a`／integration `bfbb72…9510bf` 下实际warm／cold Session两项＋认证saved-file fresh两项联合4 passed／308.04秒（exit0）。真实GeneratedSession READY／END进程生命周期与reset_local、CPU读取bootstrap及warm驻留LW／RAMSW重执行、实际waiting／epoch与原requests fresh全wrapper匹配均通过，生产未改。该结果只证明d743候选，不证明随后serializer／checker pin修复；已确认的dynamic serializer覆盖缺口仍有独立RED。schema19实际registration／appendedsubmission terminal两项已准备未运行，旧16／17与legacy回归亦待新源码冻结；不得宣称最终软件包或native reset验收完成。


2026-10-12 recorded reset-resume最终软件检查点：Session `f7da03f4…c4bafa0`／integration `bfbb72…9510bf` 冻结后，实际schema19两terminal phases（真实warm reset／bootstrap resume后registration未追加case、session_submission已追加case，原requests自然同故障fresh）2 passed／135.56秒；实际warm／cold Session两项＋认证saved-file fresh两项4 passed／320.83秒，均exit0、没有fixture或生产修复。两次独立终态共6项实际软件测试，不合并耗时，d743候选4项308.04秒保留历史不能代表最后pin修复。旧16／17／legacy四模块回归由Root负责，未重复运行；本轮仍不是native reset门禁，完整Stage2与实际reset／权限／字段矩阵保持未完成。


2026-10-12 recorded post-reset resume Task1／2 scoped软件包已通过：最终Session f7da03f4…c4bafa0、integration bfbb72…9510bf下实际schema19 terminal2 passed／135.56秒，schema18 warm／cold与认证file fresh4 passed／320.83秒；Root旧16／17／online reset／final export兼容四模块59 passed／300.98秒，独立34项通过。native warm generation1400已终态exit0／PASS：144.04320875299163秒，峰1,112,051,712 bytes低于3,103,797,248限额，available5,251,280,896、workers1／dutFindingFalse。实际2requests／9,391events／15关联／3条全部RAM（selected2）／6selectedAPB，initial159steps／resume183steps；semantic SHA `b90e6895f2f036ec03cde3a059231a94c72b1b21a79270dbfa410b86beb0b5b2`、identity SHA `afec5d21838c2756f2aceccb415b56f096eaad886ca12413494582bbd74a9766`，见[warm实际摘要](../runs/stage2-e2-register-reset-resume-warm-20261012-v1/summary.json)。warm fresh64505已终态exit0／complete：126.435815431003秒、峰1,040,527,360 bytes低于3,105,226,752限额，available5,252,710,400／workers1／dutFalse；完整matches／9,391events／semantic／ordinary／verifier／preflight逐项一致。warm完整audit尚待worker释放，不预授最终验收。cold generation45096已终态exit0／complete：136.89256155700423秒，峰1,119,137,792 bytes低于3,142,094,848限额，available5,289,578,496／worker1／dutFalse；实际2READ／9,114events／14关联／2条全部RAM（selected2）／6selectedAPB，initial159／resume159steps。semantic SHA `34f235e3c711c79ae54378af886baa130e1c613821edd77f9e4062ba716a3b1e`、identity SHA `7de9ff4b411fe6a0bf78ae2d671c657a9b9f99135e6db91f8bfc92afaf99c68f`，见[cold实际摘要](../runs/stage2-e2-register-reset-resume-cold-20261012-v1/summary.json)。cold fresh14369已终态exit0／complete：118.051542753994秒，峰1,041,219,584 bytes低于3,134,656,512限额，available5,282,140,160／workers1／DUTFalse；完整matches／9,114events／semantic／ordinary／verifier／preflight相等。warm／cold全部4次native generation／fresh均complete、各独立180秒预算；两门禁完整独立audit已终态PASS：warm282 currentpins／9产物／2exact重编译／9,391events／15关联／45APB／3RAM（selected2）／183resume，historical2／current1证书；cold同282pins／9产物／2exact，9,114events／14关联／42APB／2RAM／159resume。全部IRQ projections／plan SHA／journal／fresh wrappers／resources逐项核对、各阶段≤180秒；3个native build currentbinary及282／351／282输入核对通过。见[warm审计](../runs/stage2-e2-register-reset-resume-warm-20261012-v1/independent-audit.json)、[cold审计](../runs/stage2-e2-register-reset-resume-cold-20261012-v1/independent-audit.json)及[独立报告](../docs/reports/stage2-e2-native-reset-resume-independent-audit-20261012.md)。recorded reset-resume scoped软件／native／fresh／fullaudit包已闭合；历史门禁pins保留f7da／bfbb，不改旧身份。源码冻结释放不表示整体完成：D5／D6／D8、完整E1／E2及E3–I、native瞬时reset defaults及全字段权限矩阵仍OPEN。f7da／bfbb源码冻结，没有竞争native或重型审计。见[warm准备](../runs/stage2-e2-register-reset-resume-warm-20261012-v1/preparation.json)及[cold准备](../runs/stage2-e2-register-reset-resume-cold-20261012-v1/preparation.json)，prepared source／script SHA逐项已核对。scope仅recorded reset-resume read consistency，bootstrap reset后重新配置GPIO，不能据此证明瞬时RTL reset defaults；完整Stage2、native observable reset默认值与权限字段矩阵仍未完成。


2026-10-12 下一phase全窄字段矩阵：64个exact(register,field,lsb,width)已逐项列入[执行inventory](../docs/reports/stage2-e2-register-field-matrix-execution-20261012.md)，历史native只覆盖4字段而非整bank；拟16个独立4field chunk，首chunk INTTYPE_LOW.pin0／pin1／pin14／pin15已由Root generation70951实际启动、尚无终态／未通过。额外word GPIOEN／INTEN／PADIN／条件read-clear、访问width／权限与瞬时reset defaults继续单列OPEN；这16chunks不是完整E2验收替代，D5／D6／D8、完整E1／E2及E3–I继续未完成。


2026-10-12 field矩阵下一准备：chunk2 INTTYPE_LOW.pin2／pin3／pin4／pin5新目录已由renderer准备、尚未执行；chunk1状态仍以Root实际监督器终态／fresh／audit逐阶段验收，不因输出文件存在更新全矩阵计数。当前f7da／bfbb／verifier037源码不变，完整Stage2继续。


2026-10-12 首field chunk generation70951已实际exit0／complete：133.03611893299967秒、workers1／DUTFalse，峰2,046,107,648 bytes低于3,134,181,376限额、available5,281,665,024；actual8cases／18,218events／18关联／36selectedAPB／4RAM／8证书（4RMW＋4READ）、gaps=[]。Root fresh65778正在独立180秒预算运行，54allAPB与完整audit待核实；4fields尚未最终验收，不计为整bank或全阶段通过。chunk2仍prepared未执行，f7da／bfbb／verifier037不变。


2026-10-12 首field chunk fresh65778已exit0／PASS：117.5034022149921秒、peak1,849,569,280 bytes低于3,116,818,432限额、available5,264,302,080／worker1／DUTFalse，完整matches18,218events／semantic6150db…bd6／ordinary／verifier／preflight相等。generation与fresh均通过，独立audit正在执行、尚未最终验收。仅INTTYPE_LOW.pin0=1／pin1=2／pin14=3／pin15=1各一次合法RMW＋READ观察，不能宣称每field0..3穷举或fullwidth／reset boundary完成。chunk2尚未执行，完整Stage2仍OPEN。


2026-10-12 首field chunk独立audit55320终态PASS：8exact／9产物／282pins／18关联／54APB／12selectedMMIO／36selectedAPB／4RAM／18,218events，current及historical各8证书／IRQ2,766samples0events／cache282／351／282 currentbinary与全部resources／fresh一致。exact LOW.pin0=1／pin1=2／pin14=3／pin15=1当前合法RMW＋READ valuepoints已验收；见[独立报告](../docs/reports/stage2-e2-inttype-low-first-field-independent-audit-20261012.md)。不是全值或整bank通过，原Stage2继续OPEN。next chunk2 LOW.pin2／3／4／5已由Root generation86087实际启动，own empty cache／singleworker180／无重型audit竞争，尚未通过。


2026-10-12 field下一准备：chunk3 LOW.pin6=3／pin7=1／pin8=2／pin9=3 pins6-9新目录由renderer准备，NOTEXECUTED。firstchunk四valuepoints已audit PASS；chunk2 generation86087仍运行，phase到export前但无实际resource终态，不能预授通过。f7da／bfbb／verifier037 source与282current pins一致，完整Stage2不缩减。


2026-10-12 chunk2 generation86087已exit0／complete：132.4123047089961秒，peak2,046,140,416／limit3,134,119,936／available5,281,603,584／worker1／DUTFalse；actual8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]，仅LOW.pin2=2／pin3=3／pin4=1／pin5=2四valuepoints。fresh72553运行中、独立audit待完成，未计最终通过；chunk3准备完整仍未执行，不扩展为整bank／全部值或全阶段通过。


2026-10-12 chunk2 fresh72553已exit0／complete：117.86604998000257秒，peak1,850,150,912 bytes低于3,119,108,096限额、available5,266,591,744／worker1／DUTFalse；matches18,227events／fc2b38…3502 semantic与全部wrappers一致。generation＋fresh均通过，独立fullaudit进行中、四valuepoints尚未最终验收；chunk3仍prepared_not_executed，当前源码不变，不授整bank／全值／完整Stage2。


2026-10-12 chunk2 fullaudit16526已PASS：18,227events／18关联／54APB／8exact／9产物／282pins／4RMW＋4READ／12selectedMMIO／36selectedAPB／4RAM及全部IRQ／cache／fresh／resources一致，见[独立报告](../docs/reports/stage2-e2-inttype-low-pins2-5-independent-audit-20261012.md)。前2chunks共8fields指定单valuepoint已验收，非全部值／整bank通过。chunk3 generation18307现实际运行，LOW6=3／7=1／8=2／9=3／own empty cache／singleworker180，尚未通过；其余13chunks提议，源码不变、完整Stage2继续OPEN。


2026-10-12 next chunk4 LOW.pin10=1／pin11=2／pin12=3／pin13=1 pins10-13 v1目录由renderer准备，未执行。chunk3 generation18307仍运行，轻量phase为保存前、282currentpins一致但resource／summary尚无；accepted只为前2chunks8指定valuepoints，不猜终态或授整bank／全部值。


2026-10-12 chunk3 generation18307已exit0／complete：132.3857018879935秒、peak2,046,533,632低于3,117,260,800限额、available5,264,744,448／workers1／DUTFalse，8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]；exact LOW6=3／7=1／8=2／9=3。fresh64101运行中、audit待完成，当前四valuepoints未最终验收；chunk4准备完整NOTEXECUTED，原全scope与源码保持。


2026-10-12 chunk3 fresh64101已终态PASS：118.39475587400375秒、peak1,850,974,208 bytes低于3,117,637,632限额、available5,265,121,280／workers1／DUTFalse，full18,227events／1aef8e…59186 semantic／state／preflight一致。独立audit运行中，LOW6／7／8／9四valuepoints尚未最终验收，accepted仍前8points；chunk4prepared未执行，完整scope保持OPEN。


2026-10-12 chunk3 fullaudit55905已终态PASS，exact LOW6=3／7=1／8=2／9=3 current合法valuepoints验收，见[独立报告](../docs/reports/stage2-e2-inttype-low-pins6-9-independent-audit-20261012.md)。前3chunks共12points不是0..3穷举或整bank授级。chunk4 generation12344实际运行（LOW10=1／11=2／12=3／13=1，own empty cache／singleworker180），尚未通过；剩余12chunks提议，原scope与当前源码不变。


2026-10-12 nextchunk5 A.INTTYPE_HIGH.pin16=1／pin17=2／pin30=3／pin31=2 HIGH新目录由renderer准备，NOTEXECUTED；pin31=2覆盖bus bit31单valuepoint，旧high16／31历史证据不能替代当前运行。accepted仍12LOW points，chunk4等待Root监督器实际终态；轻量pins282一致，未运行额外任务或授整bank。


2026-10-12 chunk4 generation12344已exit0／complete：132.04403735398955秒、peak2,046,468,096 bytes低于3,120,099,328限额、available5,267,582,976／worker1／DUTFalse；8cases／18,227events／18关联／36selectedAPB／4RAM／8证书gaps=[]，exactLOW10=1／11=2／12=3／13=1。fresh78630运行中、audit待完成，四valuepoints未最终验收；HIGH新目录准备完毕尚未执行，accepted12LOW points及原全scope不变。


2026-10-12 chunk4 LOW pins10–13 fresh78630已exit0／complete：119.3633515190013秒、peak1,847,529,472 bytes低于3,129,950,208限额、available5,277,433,856，完整fullmatch断言通过。generation与fresh均通过，独立audit刚GO、尚未最终验收；accepted仍12指定points，不能提前记16。chunk5 INTTYPE_HIGH准备未执行，原D5／D6／D8、完整E1／E2及E3–I、全值／权限／width／reset范围保持开放。


2026-10-12 chunk4 fullaudit72392终态PASS，accepted current16个LOW exact单取值points，不是0..3穷举／整bank能力授级。HIGH chunk5 generation95236已实际启动、仍运行未通过，当前源码／脚本SHA／AST／tuple及actual PAD_NUM32 preflight一致；chunk6 HIGH18–21仅prepared未执行。完整Stage2及全值／权限／width／reset边界仍保持开放。


2026-10-12 HIGH首组generation95236已exit0／complete：132.3070836919942秒、available5,243,768,832／peak2,046,111,744低于3,096,285,184限额／worker1／DUTFalse，8cases／18,218events／18关联。Root separatefresh59768已实际运行，尚无最终验收；accepted仍16LOW points，不借历史HIGH证明。chunk7 HIGH22–25 prepared未执行，完整Stage2继续OPEN。


2026-10-12 HIGH首组fresh59768已exit0／complete：116.24226334200648秒、available5,239,918,592／peak1,848,770,560低于3,092,434,944限额／worker1／DUTFalse；完整trace／count／semantic／ordinary／verifier／preflight断言通过。fullaudit已GO但尚未验收，accepted仍16LOW points，不提前计20或授整bank／全部值能力。


2026-10-12 HIGH首组fullaudit45969已终态PASS：18,218events／8current与8historical证书／identity、semantic及完整generation／fresh一致；accepted current20 exactpoints（16LOW＋4HIGH），非全值穷举。chunk6 HIGH18–21 generation50635实际运行、尚未通过，same singleworker180／own empty cache／source冻结；chunk8 HIGH26–29仅prepared未执行。原Stage2所有开放范围不缩减。


2026-10-12 chunk6 HIGH18–21 generation50635已exit0／complete：131.0059881999914秒、available5,244,407,808／peak2,046,242,816低于3,096,924,160限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh69170实际运行、未最终验收，accepted仍20指定points。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15（4bit，offset0x28）prepared未执行，不借旧pin0／7证明当前scope；原Stage2开放。


2026-10-12 chunk6 fresh69170已exit0／complete：117.59755330599728秒、available5,260,267,520／peak1,849,614,336低于3,112,783,872限额／worker1／DUTFalse，fulltrace／wrappers／count／semantic／preflight通过。独立audit待终态，accepted仍20points；chunk10 PADCFG_0.pin2／3／4／5 values2／6／9／14 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk6 fullaudit45184已终态PASS，exacttuple／18,227events／8证书及完整fresh一致，见[独立报告](../docs/reports/stage2-e2-inttype-high-pins18-21-independent-audit-20261012.md)。accepted current24单valuepoints（16LOW＋8HIGH），不是全值穷举。chunk7 HIGH22–25 values3／1／2／3 generation42268实际运行、未通过，own absent cache／singleworker180／无native或audit重叠；原scope继续OPEN。


2026-10-12 chunk7 HIGH22–25 generation42268已exit0／complete：131.44182803299918秒、available5,353,672,704／peak2,046,332,928低于3,206,189,056限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh75326运行中、audit待完成，accepted仍24；chunk12 PADCFG_1.pin10–13 values2／6／9／14 prepared未执行，完整原scope保持OPEN。


2026-10-12 chunk7 fresh75326已exit0／complete：116.5613808670023秒、available5,327,286,272／peak1,849,888,768低于3,179,802,624限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、accepted仍24；chunk13 PADCFG_2.pin16／17／22／23 values1／5／10／15 prepared未执行，原Stage2全scope继续OPEN。


2026-10-12 chunk7 fullaudit93696已终态PASS，exacttuple／18,227events／8证书及完整fresh一致；accepted current28 singlepoints（16LOW＋12HIGH），不是全值穷举。chunk8 HIGH26–29 values1／2／3／1 generation70283实际运行、尚未通过，own absent cache／singleworker180／current source-script preflight一致且无overlap；原Stage2仍OPEN。


2026-10-12 chunk8 HIGH26–29 generation70283已exit0／complete：132.64775778599142秒、available5,336,645,632／peak2,046,345,216低于3,189,161,984限额／worker1／DUTFalse，8cases／18,227events／18关联。fresh31823运行中、独立audit待完成，accepted仍28points；chunk15 PADCFG_3.pin24／25／30／31 values1／5／10／15 prepared未执行，原全scope继续OPEN。


2026-10-12 chunk8 fresh31823已exit0／complete：118.06382439300069秒、available5,314,101,248／peak1,851,424,768低于3,166,617,600限额／worker1／DUTFalse，fulltrace／wrappers／semantic／count／preflight通过；独立audit待终态，accepted仍28。chunk16 PADCFG_3.pin26–29 values2／6／9／14 prepared未执行；16chunks均准备不等于已执行或已验收，原Stage2开放。


2026-10-12 chunk8 fullaudit79481已终态PASS：exacttuple／18,227events／8证书与完整fresh一致；accepted current32指定points（16LOW＋16HIGH），每INTTYPE field一个合法value，非穷举／整bank授级。chunk9 PADCFG_0.pin0／1／6／7 values1／5／10／15 generation38477实际运行、尚未通过，offset0x28／own absent cache／singleworker180／source-script preflight一致且无overlap；原Stage2完整scope保持OPEN。


2026-10-12 chunk9 PADCFG_0首组generation38477已exit0／complete：132.42977688899555秒、available5,366,063,104／peak2,046,464,000低于3,218,579,456限额／worker1／DUTFalse，8cases／18,222events／18关联；fresh60729实际运行、未最终验收，accepted仍32。轻量16组preparation／current source与script SHA／AST／exact field-value tuples核对PASS，完整覆盖32INTTYPE＋32PADCFG无漏重；10–16prepared不等于executed，原scope不缩减。


2026-10-12 chunk9 PADCFG0 fresh60729已exit0／complete：119.73843699799909秒、available5,316,136,960／peak1,851,084,800低于3,168,653,312限额／worker1／DUTFalse，完整trace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍32points、不提前36；nextchunk10 preflight通过仍未执行，16组exact64无漏重核对不替代实际验收。


2026-10-12 chunk9 fullaudit99824终态PASS，exactPADCFG_0.pin0／1／6／7 values1／5／10／15、18,222events／8证书及完整fresh一致，见[独立报告](../docs/reports/stage2-e2-padcfg0-first-field-independent-audit-20261012.md)。accepted current36单points（32INTTYPE＋4PADCFG），非全值穷举。chunk10 PADCFG_0.pin2–5 values2／6／9／14 generation48852实际运行、尚未通过，offset0x28／singleworker180／own absent cache／preflight一致且无overlap；原全scope保持OPEN。


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


2026-10-12 chunk13 fullaudit35340终态PASS，exactPADCFG2 pins16／17／22／23 values1／5／10／15／18,222events／8证书及完整fresh一致，见[独立报告](../docs/reports/stage2-e2-padcfg2-first-field-independent-audit-20261012.md)。accepted current52单points（32INTTYPE＋20PADCFG），非穷举。chunk14 PADCFG2 pins18–21 values2／6／9／14 generation43790实际运行、未通过，offset0x30／own absent cache／singleworker180／preflight一致无overlap；3word包prepared未执行，原scope开放。


2026-10-12 chunk14 PADCFG2 pins18–21 generation43790已exit0／complete：132.3194965099974秒、available5,438,459,904／peak2,046,128,128低于3,290,976,256限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh11311运行中、audit待完成，accepted仍52；next reset-default只读设计未实现或运行、不预授grant，原fullscope保持OPEN。


2026-10-12 chunk14 fresh11311已exit0／complete：118.92392746800033秒、available5,382,307,840／peak1,849,397,248低于3,234,824,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态，accepted仍52不提前56；chunk15 offset0x34 preflight通过尚未执行，原Stage2完整scope保持OPEN。


2026-10-12 chunk14 fullaudit60628已终态PASS，exactPADCFG2 pins18–21 values2／6／9／14／18,231events／8证书及完整fresh一致，见[独立报告](../docs/reports/stage2-e2-padcfg2-pins18-21-independent-audit-20261012.md)。accepted current56单points（32INTTYPE＋24PADCFG），非全值穷举。chunk15 PADCFG3首组pin24／25／30／31 values1／5／10／15 generation62291实际运行、未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；reset-default只读设计不计实现或grant，原scope保持OPEN。


2026-10-12 chunk15 PADCFG3首组generation62291已exit0／complete：134.15973644101177秒、available5,471,129,600／peak2,045,935,616低于3,323,645,952限额／worker1／DUTFalse，8cases／18,222events／18关联。fresh77906运行中、audit待完成，accepted仍56；reset-default独立设计review指出actualcommand全覆盖／未知命令fail closed／完整field-affect／process boundary实施前缺口，只有docs修订，未实现或授grant。


2026-10-12 chunk15 fresh77906已exit0／complete：120.05253920699761秒、available5,461,848,064／peak1,850,097,664低于3,314,364,416限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。audit待终态、accepted仍56不提前60；chunk16 offset0x34 preflight通过未执行。reset-default设计reconciled仅docs、未实现或授grant，原全scope保持OPEN。


2026-10-12 chunk15 fullaudit41628已终态PASS，exactPADCFG3 pins24／25／30／31 values1／5／10／15／18,222events／8证书与完整fresh一致，见[独立报告](../docs/reports/stage2-e2-padcfg3-first-field-independent-audit-20261012.md)。accepted current60单points（32INTTYPE＋28PADCFG），非穷举。chunk16 PADCFG3 pins26–29 values2／6／9／14 generation9338实际运行、尚未通过，offset0x34／own absent cache／singleworker180／preflight一致无overlap；64fieldpoints后仍有word／permission／width／reset及原Stage2完整scope，不能标阶段完成。


2026-10-12 chunk16 PADCFG3 pins26–29 generation9338已exit0／complete：131.9667810839892秒、available5,477,412,864／peak2,046,443,520低于3,329,929,216限额／worker1／DUTFalse，8cases／18,231events／18关联。fresh6576正在运行、audit待完成，accepted仍60不提前64；3word包prepared待矩阵完成后执行，原Stage2全scope保持OPEN。


2026-10-12 chunk16 fresh6576已exit0／complete：118.51990141399438秒、available5,447,532,544／peak1,851,146,240低于3,300,048,896限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。最后独立audit待终态，accepted仍60不提前64；16组小证据聚合核对仅准备，各bundle current8证书不能伪称global active128，非exhaustive／fullE2。


2026-10-12 最后chunk16 fullaudit11089实际exit0／PASS，16bundle轻量聚合PASS：accepted current64 exact指定单valuepoints（32个2bit INTTYPE＋32个4bit PADCFG），无漏重；每bundle current8证书，不能拼成global active128；16gen／16fresh各自singleworker／≤180秒，与全部sourcefreeze／fresh／resources小证据一致。见[聚合报告](../docs/reports/stage2-e2-register-field-matrix-aggregate-20261012.md)。不是全值穷举或完整E2，word／permission／width／reset仍OPEN。Root DIR_OUT word generation48145已实际运行、尚未通过，原Stage2完整范围不缩减。


2026-10-12 DIR_OUT word generation48145已exit0／complete：119.19223787200463秒、available5,482,065,920／peak1,715,609,600低于3,334,582,272限额／worker1／DUTFalse，6cases／13,907events／12关联／18selectedAPB／3RAM。fresh3571实际运行、独立audit待完成，word尚未accepted；narrow64已审计单valuepointscope保持独立，不扩成global或完整E2。


2026-10-12 DIR_OUT word fresh3571已exit0／complete：101.75905876699835秒、available5,479,596,032／peak1,575,030,784低于3,332,112,384限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。word独立fullaudit待终态、尚未accepted；narrow64单值scope保持独立，原Stage2继续OPEN。


2026-10-12 DIR_OUT word fullaudit42062终态PASS，13,907events／6证书／exact B.INTEN0与A.PADDIR／PADOUT 0x80000000三instance-specific write/read pairs验收，见[独立报告](../docs/reports/stage2-e2-word-dir-out-independent-audit-20261012.md)。不授functional／reset／fullL2，narrow64保持独立。EN_INTEN generation49060实际运行、未通过，source-script SHA／AST／exact6tuple与own absent cache preflight一致／singleworker180／无overlap；PADIN未运行、reset-default未实现，原全scope保持开放。


2026-10-12 EN_INTEN word generation49060已exit0／complete：116.19795339199482秒、available5,497,872,384／peak1,715,634,176低于3,350,388,736限额／worker1／DUTFalse，6cases／13,905events／12关联／18selectedAPB／3RAM。fresh74249运行中／audit待完成，EN_INTEN尚未accepted，DIR_OUT3pairs与narrow64分别独立。current alias zero-mask八case包仅准备、PADIN之后再执行，不借旧source，不提前native验收。


2026-10-12 EN_INTEN fresh74249已exit0／complete：100.39961130799202秒、available5,492,273,152／peak1,573,228,544低于3,344,789,504限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态，尚未accepted、DIR_OUT与narrow64scope保持独立。current alias zero-mask八request包（check86a6e8…bd97）仅prepared，待PADIN后／独立review，不提前native验收。


2026-10-12 EN_INTEN fullaudit99853已终态PASS，13,905events／6证书／exact B.INTEN0、A.GPIOEN与A.INTEN 0x80000000三instance-specific fullword pairs验收；B.INTEN0与DIR_OUT重复，不重复计unique，不授functional／reset／fullL2，narrow64scope独立。PADIN generation83748实际运行、未通过，current typed RO／exact4request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。alias zero-mask仍prepared／review、reset-default未实现，原全scope保持OPEN。


2026-10-12 PADIN generation83748已exit0／complete：103.98888060198806秒、available5,509,058,560／peak1,414,696,960低于3,361,574,912限额／worker1／DUTFalse，4cases／10,129events／10关联／12selectedAPB／3RAM。fresh88629实际运行、audit待完成，PADIN尚未accepted，scope只APB→CPU→RAM consistency、不授sampling／reset；EN_INTEN3pairs与narrow64独立，aliaszero仍仅prepared，原scopeOPEN。


2026-10-12 PADIN fresh88629已exit0／complete：87.21911255799932秒、available5,506,846,720／peak1,302,310,912低于3,359,363,072限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、尚未accepted，不授sampling／reset，existing wordpairs与narrow64独立。current alias fullmask八case包只准备、待PADIN＋aliaszero之后；aliaszero prepared／review通过仍未native，原scope开放。


2026-10-12 PADIN fullaudit75237已终态PASS，10,129events／4证书／exact B.INTEN0 pair与A／B.PADIN READs，见[独立报告](../docs/reports/stage2-e2-word-padin-independent-audit-20261012.md)。scope仅APB_CPU_RAM consistency，不授sampling／reset／fullL2，重复B.INTEN0不新增unique。current aliaszero generation52350实际运行、未通过，current v3 relation／exact8request builder／source-script preflight一致、own absent cache／singleworker180／无overlap。fullmaskprepared未执行／reset只读，原Stage2全scope保持OPEN。


2026-10-12 current aliaszero generation52350已exit0／complete：132.50322782000876秒、available5,517,291,520／peak2,044,710,912低于3,369,807,872限额／worker1／DUTFalse，8cases／17,677events／14关联／24selectedAPB／5RAM。fresh75682实际运行、audit待完成，aliaszero尚未accepted；fullmaskprepared／轻量review通过仍未执行，PADINscoped与wordpairs／narrow64独立，原全scopeOPEN。


2026-10-12 current aliaszero fresh75682已exit0／complete：117.51322904099652秒、available5,533,614,080／peak1,847,062,528低于3,386,130,432限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立audit待终态、zero尚未accepted，fullmaskprepared未执行；partial／high／repeat current alias下一步只读设计，不borrow旧source，原Stage2全scope开放。


2026-10-12 current aliaszero fullaudit30129（本轮process）终态PASS，17,677events／8证书／exact8requests zero SET／CLR＋B.INTEN0 pair一致，见[独立报告](../docs/reports/stage2-e2-alias-zero-current-independent-audit-20261012.md)。仅2source-bound zero brackets验收，不授storageversion／prerequisite／functional／reset／fullE2，word／narrow64scope独立。fullmask generation66978实际运行、未通过，actualFFFFFFFF builder／currentv3／source-script preflight一致／own absent cache／singleworker180／无overlap；partial_repeat current-source仅design待独立review，未准备执行。


2026-10-12 current aliasfullmask generation66978已exit0／complete：130.43963241600432秒、available5,511,983,104／peak2,043,985,920低于3,364,499,456限额／worker1／DUTFalse，8cases／17,683events／14关联／24selectedAPB／5RAM。fresh32283实际运行、audit待完成，fullmask未accepted；partial_repeat独立designreview中现规则允许shared actual adjacent READ boundary，新gate独立before为实验要求，仅docs修订／未执行，原scope开放。


2026-10-12 current fullmask fresh32283已exit0／complete：115.31429795100121秒、available5,522,804,736／peak1,849,442,304低于3,375,321,088限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、fullmask未accepted／currentzero2brackets已验收；SET partial_repeat十request新worker仅prepare，sharedactualREAD规则与独立newbefore2实验要求已reconciled、未native，原scope开放。


2026-10-12 current fullmask fullaudit39840终态PASS，17,683events／8证书／exactSET_CLRFFFFFFFF一致，见[独立报告](../docs/reports/stage2-e2-alias-fullmask-current-independent-audit-20261012.md)。仅2fullmask brackets验收，不授functional／reset／storageversion／fullE2；zero2／word／narrow64scopes独立。SET partial_repeat十request包（check42b3ca…05dc）prepared／Root preflight通过，轻量review／audit准备中、NOTnative；当前全部native已终态，原Stage2全scope仍OPEN。


2026-10-12 SET partial_repeat generation64745实际启动、新v1／own absent cache／singleworker180／无overlap，独立lightreview无阻断／auditprepared及Root source-SHA／AST／exact10request preflight一致。尚未通过：10cases（6READ／2plain／2alias）／10selectedMMIO／30selectedAPB／6RAM／expected16关联48allAPB仅准备断言，high／repeat不预授。current fullmask2brackets已accepted，generic规则不改，原Stage2全scope保持OPEN。


2026-10-12 partial SET generation64745已exit0／complete：151.32340373699844秒、available5,571,547,136／peak2,346,278,912低于3,424,063,488限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh51736实际运行、audit待完成，partialSET尚未accepted，全部10cases与原预算保持；CLR partial_repeat十request包（checkf3e984…bc49）prepared，待SET全终态／独立review，未native执行，原scope开放。


2026-10-12 partial SET fresh51736已exit0／complete：133.26829966400692秒、available5,504,163,840／peak2,122,182,656低于3,356,680,192限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。fullaudit待终态、SET尚未accepted，全部10cases／原180预算保持；CLR prepared lightreview无阻断／auditprepared（b3c85a…5f3b），未执行、待SET audit终态，原scopeOPEN。


2026-10-12 partial SET finalaudit16667终态PASS，21,451events／10证书／exact seed55aa00ff_SET80000000＋repeat一致，见[独立报告](../docs/reports/stage2-e2-alias-partial-set-current-independent-audit-20261012.md)。firstaudit69511 exit1 NameError cap为audit setup漏sidecar load，仅补load、不改事实断言，失败保留／非DUT finding。仅2SET brackets验收，不预授CLR／reset／functional／storageversion／fullE2。CLR generation60831实际运行、未通过，source-script preflight／lightreview一致／own absent cache／singleworker180／无overlap，全部10cases保留，原scopeOPEN。


2026-10-12 partial CLR generation60831已exit0／complete：143.68561087400303秒、available5,575,970,816／peak2,345,062,400低于3,428,487,168限额／worker1／DUTFalse，10cases／21,451events／16关联／30selectedAPB／6RAM。fresh48813实际运行、audit待完成，CLR未accepted，全部10cases／原180保持。SET2brackets已accepted，首次audit setup失败真实script／stderr／receipt与SHA证据保留、非DUT finding；原scope保持OPEN。


2026-10-12 partial CLR fresh48813已exit0／complete：139.66191233199788秒、available5,607,415,808／peak2,120,609,792低于3,459,932,160限额／worker1／DUTFalse，fulltrace／count／semantic／wrappers／preflight通过。独立fullaudit待终态、CLR尚未accepted，全部10cases／原180保持，原scope开放。


2026-10-12 partial CLR fullaudit28385已终态PASS，21,451events／10证书／exact seed d5aa00ff，见[独立报告](../docs/reports/stage2-e2-alias-partial-clr-current-independent-audit-20261012.md)；仅2CLR brackets验收，不授arbitrary masks／reset／storageversion／functional／fullL2。全部native与audit终态后，current f7da exact14权限软件测试exec66607 exit0，14 passed／23.06秒（真实外层wall23.440831127998536），前后源码／fixture SHA不变、stdout／stderr／终态receipt保存在[本轮证据](../runs/stage2-e2-current-register-permission-software-20261012/receipt.json)。actual对象软件transport，无Generated Popen／DUT／RTL；仅前effect声明policy拒绝，不是PSLVERR硬件权限证明；历史22.92秒记录保持，原Stage2全scope仍OPEN。


2026-10-12 native reset-default实施前checkpoint：current CLR2 source-bound brackets已审计accepted，current f7da permission14软件PASS23.06秒，均仅各自scope。新[ordinary native reset-default计划](../docs/superpowers/plans/2026-10-12-stage2-ordinary-native-reset-default.md)已存在、尚未实现。为保留未提交历史源闭包，已新增[当前源码原始bytes冻结manifest](../runs/stage2-e2-pre-native-reset-source-freeze-20261012/manifest.json)：20baseline文件／815,794bytes逐件archivebytes＝currentbytes／真实SHA核对，manifest SHA `dbb3dbc4d43fffcb808468eac67fae84cfe3c1ef6b2fb9f316dd390b8ec5a4bc`。仅historical source reconstruction材料，非runtime authority；未复制cache／binary，未改旧run pins。后续新源码必须单列证据，不能以新SHA重写已验收历史门禁；原全scope仍OPEN。


2026-10-12 ordinary native reset-default计划已冻结、Task1获Root GO。Task1／2独立review三条件继续作为实施约束：ACK至postparse／callback全错误范围、实际pinned build issuance资格、public export与private issuer／registry分离。20baseline源码bytes已归档；Task1修改后既有f7da／bfbb native门禁仅历史source qualification，旧pins不重写。Task2 Runner private consumer仅只读接口与测试准备，等待renderer final契约，未修改生产／运行测试，不记为完整E1／E2完成。
