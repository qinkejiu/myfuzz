# Ordinary APB访问证据：Session／可信文件重放接线

2026-10-12：本包生产接线与稳定软件回归已完成；本包未执行RTL。ordinary receipt与Runner association只有观察证据，不授verified／storage／functional。默认关闭，既有schema16／17、assembly、runtime配置及38／capability40项selector闭包保持原字段布局。

可信assembly新增可选 `ordinary_apb_access_evidence={"max_records":256}`，省略时不加字段；显式配置要求exact单字段、整数1..65536，拒None、bool、unknown provider／路径。`make_register_runtime_factory` 在构造adapter前调用实际Session hook，再按现有方式安装adapter及可选capability preflight。不开新saved setter，不从保存target路径选择代码。

Session闭集方案：before-begin `configure_ordinary_apb_access_evidence(max_records=...)` 配置实际native ordinary GPIO targets及实际Runner collector；manifest仅opt-in增加 `ordinary_apb_access_evidence_configuration` 和 `ordinary_apb_access_source_files`，Runner identity也保留实际collector配置。plan.register_programs仅opt-in增加 `ordinary_apb_access_evidence`，闭集为schema_version=`ordinary_apb_access_session.v1`、configuration及实际state。state嵌入已有认证plan artifact，无需改变默认artifact／run_config字段集合。

保存数据先经 `validate_ordinary_apb_access_session_document` 形状／容量／配置hash检查；selector再核assembly开启状态、容量、plan／manifest／Runner配置一致及当前源码闭包。全部检查在factory前；writer同样在mkdir前拒绝自相矛盾报告。saved shape检查不是authority：fresh trusted factory与原requests重编译，before-begin重新安装当前实际collector并完整比较startup config，最终完整trace、register runtime state和ordinary collector state精确比较。保存receipt／raw/base refs／CPU key只供比较，不恢复ledger、private callback确认、parsed sample pins或slot权限。

ordinary opt-in source闭包使用code-owned `build._host_sources()` 的实际AST递归import闭包，Session `_ordinary_apb_access_source_files()`统一生成排序relative path／SHA记录；selector把同名单与原38／40项闭包排序去重合并。包括新collector／helper、真实wire parser／local transport／protocol_io／build及协议投影依赖；不使用saved路径推导闭包。AST扫描发生在startup／保存／selector验证，Session执行期核startup已pin路径hash，避免进入每STEP热路径。名单规模按实际结果报告，不能仍称40项。

软件非空正例使用固定bootstrap／slots与actualfactory／Session。软件bus driver只decode当前接纳的闭集LUI／ADDI／SW／LW编译片段，驱动实际CPU._serve、live router、严格parser的native target receipt和Runner journal；不建立寄存器hostoracle、不声称执行了CPU RTL。至少一个非空cpu_delivery_confirmed association及真实raw/base refs，经过encode_plan／认证bundle writer，再用可信file入口fresh实际对象与原requests重编译、全trace／全snapshot比较。本包负例覆盖unknown assembly配置、默认布局、installer顺序、通道presence、saved raw refs非法类型及source SHA漂移；完整fresh差异拒绝由Session重放比较及selector终态比较共同实现。CLI只报告fresh返回snapshot，默认不新增输出字段。

E1／E2保持未完成；实际reset／权限／mask／width及副作用行为、code-owned分操作verifier／证书和verified矩阵仍需后续验收。本报告不替代之前冻结源码门禁，也不预授本包实际门禁通过。

软件执行记录：最初 assembly／installer 两项因缺少新参数 RED，接线后 GREEN；新增通道 presence／闭包负例先 RED 后修。非空实际对象链路首次暴露合法 bootstrap 的 126,464 字节槽被新 Session 校验器 65,536 上限拒绝，随后由 Session owner 按 region 字节容量修复。下一轮暴露旧 generated-session validator 拒绝新 ordinary identity 字段，生产 selector 增加闭集 opt-in 分支：新扩展必须与 channel target 一致、绑定实际 alias 及已认证 artifact 的 native trace SHA，拒 causal 字段后，才在 detached copy 去掉该已验证扩展并复用原 artifact 再生校验；默认路径继续原 helper。

中间冻结软件结果：新 integration 6 passed／80.70s（非空 confirmed association、6 raw／3 base refs、认证保存及 fresh 原请求全 trace／snapshot 比较），旧 integration 20 passed／34 subtests／58.66s。后增一致伪造 trace SHA／foreign alias 的 helper RED→GREEN，当前 6 项 pure tests passed／1.53s；最终 7 项联合复验待 collector 最终冻结。这些是纯软件 fixture 结果，不是新增 RTL 门禁。ordinary selector 实际闭包 278 项（无 capability 时与 capability L1 时相同），默认 38／40 项保持。

额外只读一致性审查发现 writer 起初只核 collector/channel 配置，未复用 selector 的 GPIO identity extension 检查，可能保存随后被 selector 拒绝的自相矛盾 bundle（无 live 权限逃逸）。按批准范围增加独立 sequencing RED，显示原代码已创建目录才失败；修复在 mkdir 前复用同一实际 alias／native trace SHA／artifact 再生检查，仅 ordinary opt-in 生效。最后 pure subset 7 passed／1.49s，完整新模块现为 8 项，最终稳定源码回归仍待 root 热点优化冻结。保存数据的 refs／hash／grants 一致性不能替代 fresh 实际配置和原请求重编译。

最终稳定源码联合验证：`PYTHONPATH=src python3 -m pytest -q tests/integration/test_ordinary_apb_register_replay.py tests/integration/test_ibex_pulp_register_replay.py`，28 passed／34 subtests／146.50s，exit 0（新 ordinary 8 项＋旧 integration 20 项）。完整非空 actual-object 软件证据通过认证 writer／可信 file selector／fresh 原请求重编译并比较全 trace 与实际 snapshot。之后仅细化 foreign alias 的独立负例，确保 native trace SHA 正确时 alias guard 单独拒绝；单项复核 1 passed／0.27s。此前“最终待冻结”条目为过程历史，现由本结果替代。

本轮冻结源码 SHA：integration `bfc33d3c554f3401291bd57d40690f9ec16365e840add2900a691bb9aaf6ee8d`，Session `3eebb6c82ebc9ed209b39c9bbd6f169318303f6815d70ae17f37d6357d7a82e4`，collector `131304413d2abb2ffcdd4790522cbc52025bc4f85324a0ac2847ea6c4866f2bf`；联合执行前后相同。新测试最终 SHA `9bb8960ad27ee31912b91b97662733d0bda164e55760bbf51e34d0faa53e6a96`。软件结果不授实际 RTL 门禁、verified capability 或 functional coverage；后续重型门禁由 root 单 worker 监督执行。

## v3 timeout 后的只读热点审查

v3 的 bundle 实际已完整落盘，原 180 秒 combined generation＋fresh CLI 门禁超时不能定位为 writer 拒绝或 RTL 错误。只读所见 plan 约 29 MiB、runtime state 22 MiB、manifest 12 MiB、ordinary state 4 MiB；下述为源码复杂度分析，未运行 profiler／RTL，也未修改生产。

ordinary validator 的 association 循环仅 O(records×refs)，24 条记录本身不会逐条扫描完整 slots。大开销在循环外：`_register_plain_json` 遍历 channel.configuration 与 state.configuration 两份大配置，两个 binding 的 126,464 字节槽逐项检查、sorted 和 tuple-set 构造；configuration 相等／SHA 又数次 `_json`，返回再做全量 canonical JSON roundtrip。writer 的 `_validate_saved_register_documents` 经 plan validator 已检查 ordinary channel，随后 `_verify_ordinary_channel` 再检查一次。保存／selector 还分别扫描 code-owned source closure。

更大的共享成本来自 register plan／state：每个 case manifest 保存完整 runtime configuration，plan 与 state 分别包含 10 份；root `_register_plain_json` 扫全部副本，`_validate_register_manifest` 每次 canonical 序列化 candidate configuration 和相同 expected configuration；state validator 再走同样 10 条、canonical 比较整个 manifest 列表，最后各自 JSON roundtrip。Session encode／finish、writer、selector、fresh encode 均可能再走这条严格校验链。GPIO identity 再生在 writer／selector 各两次，每次包括 render／source lock／local_build_identity；build `_prepare` 还解析并读取完整 host-source AST closure。它是独立较固定的成本，不能删掉 artifact/source 验证换取性能。

建议后续 TDD（尚未实施）：先用纯软件固定大槽＋10 manifest／24 association fixture，以 deterministic 计数断言重复 expected-configuration canonical 调用不会随 case 数重新扫描，记录非门禁 profiling 时间供判断。把已验证 plan channel 通过内部代码生成的验证结果复用于 writer／selector 配置绑定，不能接受 saved “validated” flag；每个保存输入仍完整校验一次。单次 validation context 可缓存相同 expected configuration 的 canonical bytes/hash，候选副本仍须逐一精确核对 bool/int 类型和所有字段，拒绝后续 case 的单字节 slot／configuration 变更。detached 返回可考虑一次 deepcopy 替代重复 JSON roundtrip，但必须保留 plain JSON／exact-type 检查及默认 canonical 输出字节兼容。普通 channel 的 config JSON 仅计算一次并同时用于相等与 SHA；sorted unique slots 可用单次有序检查替代额外 sorted/set 分配。所有缓存仅限当前校验调用，不能从保存的 hash、path、report 或旧源码验证结果恢复权限。TDD 必须保留 late-case mutation、bool/int、alias／native trace forgery、source drift、detached mutation，以及完整 fresh trace/state mismatch 负例。
