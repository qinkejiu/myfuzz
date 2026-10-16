# D5 可信内存保存配置与 replay 衔接进度

D6 reset的verified文件重放（2026-10-11）：runs/stage2-d6-reset-verified-rtl-20261011 使用当前源码和生产runtime固定执行RESULT_ADDRESS STORE→LOAD，随后Session.reset分别warm_all／cold_all。每套schema14记录两例、bindings [null, 非空]、after_cases=2的reset；生产保存函数生成7项artifact identity，文件入口replay_ibex_pulp_online_files经生产verifier和可信factory selector后，新建CPU/IP RTL分别完整匹配1,455／1,587events。该轮覆盖当前authority实例及登记快照校验的正常运行路径。

4条historical证书reset前后原文一致，worker检查active RAM为0；LOAD binding仍精确对应reset之前的实际STORE event921、byte0/value0/version[0,4]，不将保存binding当作reset后的授权。warm/cold reset_barrier的RAM generation分别0／1。单worker资源均complete：warm64.7794秒、峰值509,915,136 bytes、预算3,632,054,272 bytes；cold44.6168秒、峰值249,176,064 bytes、预算3,545,346,048 bytes，dut_finding false。

独立只读复核通过：生产verifier／selector、全部artifact摘要、plan与semantic摘要、连续事件及精确binding核对一致，未重跑RTL。identity.run_config明确client_executed=false／fixed_production_admission，result.statuses为空；范围是固定生产admission、实际reset及verified文件fresh replay，不证明完整RFuzz执行或通用provider生命周期完成。D5／D6不勾选。

D6 reset时间线保存／重放（2026-10-11）：新增Session.reset，要求active已提交case前缀、warm_all／cold_all闭集、至多65536个操作；成功后记录after_cases位置，Runner command_epoch必须等于已记录reset数。reset部分失败halt且标记不确定，encode_plan拒绝；直接Runner.reset_all造成未记录epoch也拒绝保存，不将缺命令的输入计划当作可重放证据。

schema14用于含reset的成功前缀，15用于含reset的case失败前缀，保留可选runtime／provenance／trusted admissions。启动前严格核对操作闭集、整数位置、合法范围与单调顺序；失败case后不得有reset。replay提交相应case后按序执行真实Session.reset。reset失败也结束全部组件，清理异常附加note而不掩盖原reset错误；已观察RED ended=[]后修复。10项新增检查覆盖正常顺序重放、直接Runner旁路保存拒绝、五类畸形时间线构建前拒绝、部分reset失败、schema15终止失败及replay异常清理。六模块联合41 passed／5 subtests（5.32秒），git diff --check通过。

新真实产物 runs/stage2-d6-reset-replay-rtl-20261011 以Session.reset重新执行warm_all／cold_all，schema14保存两已提交case后reset，runtime.replay新建CPU/IP RTL分别完整匹配1,455／1,587events。原历史4条字节证书保留、旧LOAD的RAM／slot授权撤销、命令前拒绝与保存history不可复活检查仍通过。单worker资源complete：warm41.6953秒、峰值507,273,216 bytes；cold20.6990秒、178,741,248 bytes，dut_finding false。

只读复核通过：独立28 passed／2 subtests，reset时间线及产物一致。范围为固定生产admission／实际reset和内存入口fresh replay；未称RFuzz客户端或reset verified文件入口验收，旧LOAD拒绝尝试不进入已提交plan。真实运行发生在随后异常cleanup修复前，该修复仅涉及reset失败分支且已软件RED/GREEN；旧产物保留运行时源身份。通用淘汰／冲突与其他provider生命周期仍待继续，D5／D6不勾选。

D6 两类实际 reset（2026-10-11）：runs/stage2-d6-reset-rtl-20261011 的生产 runtime先实际 STORE→LOAD，生成4条历史字节证书，再注册未来instruction slot的旧LOAD。Runner.reset_all分别运行warm_all和cold_all，实际CPU/IP reset与内存策略产生reset_barrier；warm memory generation保持0、cold推进1。旧LOAD在真实Session的gate检查中被拒绝，event_count／local_ticks／cases不增加；RAM active查询为空，旧保存declaration不变，重新observe完整历史不能恢复资格。

history_before／history_after的4条certificate原文一致，audit.json核对实际reset_barrier与generation。warm trace1,455events、cold1,587events；单worker资源complete，分别19.0936／18.7181秒，峰值178,855,936／178,343,936 bytes，dut_finding false。21项live_memory_prerequisites软件回归通过（0.22秒）。只读产物复核通过：实际reset、generation、历史证书及trace摘要一致。

范围：本轮实际执行reset，但online plan目前不编码reset命令，未调用replay，不宣称reset前缀可重放。该缺口须在完整在线生命周期验收前处理；通用淘汰／冲突和其他provider仍待后续，D5／D6保持未完成。

本轮伴随软件回归：live_memory_prerequisites 与 live_memory_replay_actions 联合31 passed（5.18秒），git diff --check通过。覆盖写拒绝尝试未入已提交 plan，fresh replay比较的是实际两STORE前缀，不声称拒绝尝试本身通过文件replay。

D6 覆盖写失效的真实在线检查（2026-10-11）：runs/stage2-d6-ram-overwrite-rtl-20261011 的 worker 使用生产 runtime，先执行真实 RESULT_ADDRESS STORE，再按合法 decoder 的 LOAD 声明注册未来 instruction slot，绑定当前 byte0 [0,4]。未来地址显式移至 cursor+0x100，避免与第二次实际 STORE 的 instruction slot 重叠；未运行该 LOAD 的 CPU 命令。

第二次相同真实 RTL STORE 使 byte0 value 保持0、version推进到[0,6]。实际 Session.submit_case(stale) 在 gate 检查中抛 SourceActionPrerequisiteError／no_retained_live_memory_byte，前后 event_count、local_ticks、cases 数完全相同；旧 replay declaration 不变，不因保存格式恢复 active 资格。最终 trace 保存两次历史 memory_write_commit，commit_audit.json核对各版本和值，完整1,468 events fresh RTL replay matches true。

单 worker20.7398秒、峰值RSS178,348,032 bytes，预算3,685,253,120 bytes、resource complete、dut_finding false。只读复核通过：实际两次 STORE 的 commit 摘要、版本和值一致；拒绝尝试未入 replay plan。该检查证明实际同值覆盖写失效和历史 journal 保留，不授通用 history／active lifecycle 完成；reset、证据淘汰、身份冲突的全部在线组合及其他 provider 仍待继续，D5／D6 不勾选。

非空绑定的 verified 文件 replay（2026-10-11）：新目录 runs/stage2-d5-trusted-binding-bundle-20261011 重新运行固定生产 decoder／executor admission／真实 Session 的 RESULT_ADDRESS STORE→LOAD。schema 12 两例、bindings [null, 非空]、最终 trace complete；生产 `_write_online_trace` 与 `_write_online_run_identity` 保存完整 trace、plan、session manifest、decoder manifest、targets、seed 和配置，共 7 项 artifact 身份摘要。

worker 随后调用生产 `replay_ibex_pulp_online_files`，通过 verified bundle 身份校验与可信 factory selector，逐例在新建 CPU/IP RTL 的实际 RAM authority 下重新注册及重算绑定，完整 1,454 events matches true、无差异。资源监督单 worker、44.9446 秒、峰值 RSS 250,613,760 bytes，预算 3,696,648,192 bytes，status complete、dut_finding false。只读产物复核通过：生产 verifier／selector、7 项摘要和 STORE 绑定一致。

此 worker 未执行 RFuzz 客户端，run_config 明确 client_executed=false／fixed_production_admission，rfuzz.toml 仅记录此事实；不伪装完整 RFuzz campaign，result.statuses 为空也不作为 receipt 验收。完整 RFuzz trusted-mode 的无 binding 文件链证据保留在此前目录，本轮补非空动态绑定文件链。D5／D6 未勾选：失效场景的在线组合、通用 active 生命周期以及后续 Stage 2 真实矩阵仍待继续。

完整 CLI／RFuzz 与文件 replay（2026-10-11）：runs/stage2-d5-trusted-rfuzz-20261011 的 launch_command.json 记录生产 CLI、实际 kfuzz 客户端、2 秒／3 inputs、显式 memory commit 与 persistent prerequisites。3 inputs 全 complete，schema 12 保存三例，online_final_trace.json 为完整 1,763 events／complete；生产保存 online_run_identity envelope、11 项 artifact 摘要。随后生产 CLI replay 文件入口执行 identity 校验、重新选择可信 factory、逐例注册及新建 RTL，全事件 matches true、无差异。

两次运行分别由 run_budgeted_process 串行监督：run 18.6478 秒、峰值 RSS 179,130,368 bytes、预算 3,698,130,944 bytes；replay 23.4481 秒、峰值 RSS 202,215,424 bytes、预算 3,624,599,552 bytes，均单 worker／complete／dut_finding false。原始 stdout／stderr 和资源回执保留。

范围限制：自适应 executor 选择 sources 为 gpio_b、cpu、gpio_b，三个 dynamic_binding 均 null；此结果证明完整可信模式 CLI／RFuzz 保存与 verified bundle fresh 文件 replay，不证明动态 RAM binding 的文件 replay。前轮固定 RESULT_ADDRESS STORE→LOAD 已证明实际 binding 与内存入口 fresh replay，仍需补其 verified bundle 文件链。只读产物复核通过：生产 verifier／selector、11 项摘要及 semantic hash 一致；D5／D6 未完成。

结果槽真实短链（2026-10-11）：decoder 预检输入 `0000000405000000` 为实际 RESULT_ADDRESS STORE、`0000000301000000` 为 RESULT_ADDRESS LOAD。但完整 executor 的探索选择在 runs/stage2-d5-trusted-ram-rtl-20261011 将两例改为 GPIO 源，worker 的非空 binding 断言失败，资源回执 command_failed／dut_finding false；保留失败产物，不作为成功。

新目录 runs/stage2-d5-trusted-ram-fixed-rtl-20261011 固定生产 decoder.decode→executor._bind_online_source_action→真实 Session.submit_case→decoder.commit；两个 source 均断言为 cpu，实际运行后两例 admission 的 dynamic_binding 为 [null, 非空]。LOAD 绑定引用 actual STORE event 921，RAM generation 0、byte offset 0；完整 trace 有一项 memory_write_commit 和一项 memory_read_issuance。schema 12、2 cases、trace complete、1,454 events；runtime.replay 新建 CPU/IP RTL 全事件比较 matches true。trace.json 已逐事件导出数组，未再用 default=str 隐藏不可序列化事件。

单 worker 19.3452 秒，峰值进程树 RSS 179,445,760 bytes，启动可用 5,851,611,136 bytes，预算 3,704,127,488 bytes，资源 status complete、dut_finding false。worker 未调用 execute_batch，result.statuses 为空，case 的实际 receipt.status 在 stdout 为 running、最终 trace complete；不将空列表当作 executor receipt 验收。产物只读复核通过：plan／semantic hash、连续事件及实际 STORE lane 绑定一致。此结果证明固定生产 admission 链的实际 RAM 绑定与 fresh RTL replay，不证明完整 RFuzz 自适应运行／verified bundle 文件 replay／Stage 2 全矩阵，D5／D6 未勾选。

首次真实 RTL 运行（2026-10-11）：runs/stage2-d5-trusted-rtl-20261011 保存 worker.py、online_plan.json、result.json、resource.json 和 stdout／stderr。通过 resource_policy.run_budgeted_process 执行生产 runtime，单 worker，180 秒监督超时；实际 38.3497 秒，峰值 RSS 508,370,944 bytes，启动可用 5,855,834,112 bytes，预算 3,708,350,464 bytes，status complete、dut_finding false。两个 case complete，schema 12，fresh RTL 完整 1,478 events 匹配。

验收限制：原固定 STORE／LOAD records 的窗口选择为 GPIO MMIO（payload 地址 0x4000100c），两例保存的 dynamic_binding 均为 null，不能证明 RESULT_ADDRESS 的实际 STORE→LOAD 绑定。worker 辅助 trace 导出使用 asdict/default=str，将惰性事件序列转为字符串，trace.json 不可用作重载证据；内存中的 reference trace 与 fresh replay 比较实际完成，不受该导出影响。保留此次产物与限制，不覆盖；下一次使用新目录，修正窗口选择和标准 trace 导出后重跑。D5／D6 保持未完成。

CLI 衔接（2026-10-11）：`scripts/run_ibex_pulp_online.py run` 新增 `--persistent-memory-prerequisites`，默认调用不增加 runtime 参数；显式开启要求 `--memory-commit`，缺失时在 factory／runtime 构建和输出目录创建之前拒绝。replay 保持从 verified manifest 选择策略。新增三项 CLI 隔离检查，RED 为未识别新参数，修复后与旧 native IRQ、profile selection、可信 replay actions 联合 26 passed／7 subtests（14.80 秒）。只读复核独立 3 passed、无重要问题，未启动 RTL。真实运行必须调用已有 resource_policy.run_budgeted_process，遵守单 worker、进程树 RSS 与失败清理约束；下一步真实在线保存／fresh replay，D5／D6 不勾选。

失败边界补验（2026-10-11）：保存快照检查新增失败参数，运行真实 Session._execute_case；只隔离 CPU instruction admission 的 DUT 边界，先实际写入 instruction memory 再抛异常，确认 schema 13 保存命令前 admission，以及 source_admission／case index／case ID／error type／message 的完整终止记录。此检查不启动 RTL，也不是 schema 13 的 fresh DUT replay 验收。

清理失败负例实际 RED：缺 actual writer 导致 DynamicBindingUnbound，随后 session.finish 抛 RuntimeError，原始拒绝被覆盖。现仍尝试清理，但将清理异常作为原始 admission 异常的 note，重新抛原始拒绝；不将它作为预期 DUT 失败接受。新增负例核对原始 ValueError 类型、清理尝试及 note。七模块联合软件回归 72 passed／5 subtests（5.08 秒），只读复核独立 10 passed、无新增重要问题，git diff --check 通过。真实 runtime 已有 persistent_memory_prerequisites opt-in，现有 scripts/run_ibex_pulp_online.py run 尚未暴露该参数；后续须衔接实际运行入口并在计划规定的单 worker／RSS 监督下验收。D5／D6 仍未完成。

共享 PULP replay 入口新增 `_saved_persistent_memory_mode`，只从已验证且重新核对原始字节摘要的 online manifest 读取可信 factory 配置。拒绝 symlink／缺文件／路径错误或验证后字节变化；旧无 gate 声明返回关闭。

显式可信配置必须同时匹配实际 factory 的完整默认 RAM evidence 配置、runtime contract identity、instruction-slot declaration、动态 RAM policy、实际 CPU read/write authority 的 schema／capacity。配置通过 canonical JSON 精确比较，额外字段、bool 替代 int、窗口／writer whitelist 变化均拒绝。策略声明函数与实际 factory provider 共用。

replay factory 参数只在显式保存可信模式时转发 contract identity 与 source_actions=True，同时保留原有 commit-stream mode 选择。此阶段重新创建配置，保存 receipt 不加入 actual writer authority。

新增 10 项软件检查：实际 factory manifest 选择、旧默认关闭、manifest 改动、contract 冲突、缺 read/write、预算类型错误、slot 窗口及动态 whitelist 变化拒绝、replay 参数转发。RED 缺 API／未转发后修复，定向与旧 saved/replay 模式合计 12 passed（10.90 秒）；独立只读复核 10 passed、无重要问题。扩大兼容回归 37 passed／3 subtests（25.60 秒），未启动 RTL／fresh replay。

D5 保持未勾选。下一步保存 plan 的动作与固定辅助动作，并在新进程 replay 每例 admission 前注册、从当前实际 witness 重算／核对绑定；现有 replay 仍缺逐例 gate 注册，不宣称完整可信 replay 可运行。完整在线执行、D6 通用生命周期及 Stage 2 CPU/IP／HMAC 真实门禁保持原计划范围。

后续动作保存／重算 API：gate 现在按注册容量保留策略绑定前的原始 SourceAction，并提供 `persistent_memory_case_admission.v1`：原始 source_action、预期 admitted_action、固定 support_actions 与 dynamic_binding。PULP provider 保留动态 binder 之前的原始动作；保存记录不作为 actual authority。

`register_replay_case` 先校验闭集格式、主动作 ID／payload 与 case 输入及支持片段数，再重新注册当前实际 RAM／slot／固定辅助动作；完整 canonical JSON 必须与保存的预期决策一致，最后 require_case 再核对当前 active 条件。保存 declaration 或 binding 不会经 receipt ingest 加入授权。所有缓存仍受已注册 action 的 max_actions 限制。

新增 5 项真实 factory／host callback 软件检查：fresh actual writer 重算得到相同完整决策、缺 actual writer 拒绝且不注册、保存 binding 改值拒绝且无 CPU 命令、固定辅助片段重注册、重算摘要的主 payload 篡改在注册前拒绝。RED 缺 API 已观察；联合回归 46 passed（19.57 秒），只读复核独立 5 passed、无重要误授路径，无新 RTL。

这轮交付 gate 层保存／重算 API。Session.encode_plan 的 schema 扩展与 replay_online_session 逐例调用仍待接入，不能据此声称端到端可信 replay 已实现。

后续 Session 衔接（2026-10-11）：可信 gate 使用 plan schema 12，失败前缀使用 13；主 case 命令执行前捕获完整 admission，旧模式 schema 保持兼容。replay 对声明数量及闭集结构做启动前预检，provenance 必须同时具有 runtime_paths；逐例提交前重新注册实际 RAM／slot／support 并精确比较保存决策，注册拒绝会结束会话且不作为预期 DUT 失败吞掉。

新增软件检查覆盖真实 Session 保存时机、新 schema 解析、逐例注册顺序与缺实际 writer 拒绝、畸形声明在 begin 前拒绝，以及真实 factory／Session 的 runtime paths 配置。后者发现 provenance 原先拒绝已安装 RAM consumer，现允许复用同一尚未消费的 actual commit/read authorities；实际 callback drain 仍释放全部 token 并产生四个历史字节证书。软件 replay 顺序检查隔离了 Session 执行边界，不能证明 DUT replay 一致性。

只读复核发现 native UART commit services 不匹配的检查过晚：配置拒绝时已安装 provenance／UART tracker。负例在修正只读属性的 fixture 设置后实际 RED（provenance_enabled 为 True）；检查移至所有状态修改前，拒绝后保留未配置状态。最新六模块联合回归 63 passed、3 subtests passed（5.13 秒）。修复后只读复核独立 36 passed、确认 P2 已解决且无新增重要问题，未新增 RTL 或 fresh DUT replay；D5／D6 仍未勾选。下一步补齐失败前缀与完整在线执行验证，再按资源监督约束验收真实保存／replay。
