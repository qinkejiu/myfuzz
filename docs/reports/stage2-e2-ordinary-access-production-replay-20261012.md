# E2 ordinary APB production Session and fresh replay — 2026-10-12

状态：本轮生产接线与分阶段真实 fresh CLI 已通过；原整段 180 秒门禁超时保留，完整 Stage2 尚未完成。本轮接续已经交付的 [Runner association 软件包](stage2-e2-ordinary-access-association-20261012.md)，原 Stage2、E1/E2 与后续阶段继续执行。

本轮结果：默认关闭的 Session/assembly/可信保存文件/CLI ordinary APB 接线已实现，完整 startup configuration、原始 requests 重编译与实际终态比较均有软件和真实证据。真实执行 10 cases（8 RMW、2 READ），新增 18 次访问；bootstrap 另有 6 次实际访问，完整 snapshot 共 24 条，全部 confirmed、pending0。独立核对 192 raw refs、72 APB base refs、2 RAM commits及 22387 个完整事件。完整保存 bundle 后，同一个 production CLI 在单独资源预算下 exit0、matchesTrue、全24条 snapshot 完全一致。

资源范围必须区分：最初两版脚本分别因固定 raw count、把总数当作case数而失败，历史产物保留。v3 原组合门禁180.074秒 wall_timeout，peak2,628,591,616 bytes；保存 bundle 已完整认证，但该组合门禁没有通过。其后对原 bundle 单独执行 production fresh CLI，103.455秒、peak2,116,165,632 bytes、limit2,558,029,824 bytes、workers1、complete。没有放宽180秒预算或删除bootstrap证据。下一步需要定位组合耗时，再继续 code-owned verifier、实际CPU readback/reset/权限/mask/width/effects；本包不授 storage/verified/functional/L2。

最终软件检查：Session19（59.76秒）、独立边界19（21.63秒）、integration新旧28及34subtests（146.50秒）、root collector/Runner/CLI/sourceguard46（60.99秒）、root default/capability replay27（98.10秒）、collector配置成本7（9.32秒），均 exit0。各项范围与中间失败记录见下文，不使用历史源码门禁替代当前版本。

真实证据：[v3保存目录](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/)、[完整状态](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/ordinary-access-state.json)、[单独fresh核对](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/fresh-cli-verification.json)、[fresh资源](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/fresh-cli-resource.json)、[原组合超时](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/resource.json)。semantic SHA `7eab0303fdf4c4116174a032ee33651ebc977fb3dab4577299595ca31705da5d`；saved identity `99f608b5243fdb8f4a9ea46f86196e0d9d79742eed16bd1c189add4dbba5c47c`。

独立最终审计见 [independent-audit.json](../../runs/stage2-e2-ordinary-access-file-cli-20261012-v3/independent-audit.json)，无残余具体 P1/P2。281 个外层源码 pin、278 项认证闭包及缓存全部 frozen inputs 一致。

以下保留执行过程与中间验证记录；最终结论以上述范围为准。


三个已授权子代理分别处理 Session/闭集保存 schema、可信 assembly/fresh file replay、独立拒绝边界。Root 负责 CLI 和执行文档。仅在各自源码所有权内修改，不提交或清理既有 dirty 工作区。

assembly 默认不包含新增字段。显式启用采用 `ordinary_apb_access_evidence={'max_records': N}`，只允许 exact dict、唯一 max_records 键及 exact int 1..65536。可信 installer 在 instruction slots 已声明之后、register adapter 和 begin 之前配置实际目标 receipt 与 Runner collector；保存引用不能安装 authority。

Session API 为 `configure_ordinary_apb_access_evidence(max_records=256)`。保存 schema16/17 可选 `register_programs.ordinary_apb_access_evidence` 采用 `ordinary_apb_access_session.v1`，闭集 schema_version/configuration/state，state 为实际完整 collector snapshot。manifest 单独保存启动 configuration 和 code-owned source files，终态不能改变启动身份。关闭时旧 plan/manifest/source closure 布局保持。

启用时可信 selector 补齐 collector/helper 及 actual transport/wire/session/build 的完整源码依赖。复用 code-owned `_host_sources()` AST import closure 并排序去重；默认关闭时原 38 项、开启 capability preflight 时原 40 项列表保持。新 closure 不能从保存文件指定的路径派生，既有 build artifact SHA 也不能替代当前 selector 核对。

fresh 回放在任何 harness 命令前重建当前实际对象，完整比较启动 configuration/manifest；只从原始 register requests 在当前上下文重编译、执行，再比较实际 terminal snapshot、plan 与 trace。保存 state/refs 只作比较，不恢复私有 target registry、callback confirmations、CPU request 或 memory authority。CPU/readback 功能 verifier 仍在后续，不授 storage/verified/functional/L2。

Root CLI 新 optional evidence 输出先复现 1 RED（缺字段，0.28 秒），最小接线后新测试与既有 capability CLI 共 3 passed（0.30 秒）。replay mismatches 保持 exit2；未启用时不添输出字段。此 CLI 检查使用受控结果对象，不替代实际文件或 DUT gate。

初始待验证记录（已在上述最终检查覆盖）：Session 原子配置失败、beforebegin/slots/对象/source drift；schema16/17 嵌套字段闭集及终态；一致重哈希的 saved config/state 拒绝；双目标实例、默认布局与 source closure；可信 file fresh 执行及 CLI 终态。当前未运行本增量实际 DUT gate。


### 2026-10-12 完整配置热点优化与并行验证

实际默认 bootstrap 保留 126464 byte slots、约 4.1 MB 完整 startup configuration。无 DUT 命令的测量：collector 五次 validate 从 0.695416 秒降为 0.037100 秒；通过启动时固定完整 slot 集合、每次对实际集合与 regions/seed 做完整漂移检查，避免重复排序/序列化。Session 五次 guard 仍需 1.123271 秒，因此 renderer 正以只读实际 startup SHA 和专用轻量 guard 分离命令检查与完整导出，不削减配置或证明范围。测量分别保存在 /tmp/myfuzz-ordinary-full-config-cost-20261012.json、/tmp/myfuzz-ordinary-full-config-cost-final-20261012.json、/tmp/myfuzz-ordinary-session-guard-cost-20261012.json，仅性能证据。

Root collector cached SHA 与 incomplete-prefix export 专项 2 RED（9.15 秒，缺接口）后完整 cost 模块 7 passed（9.32 秒，24642 exit0）。allow_incomplete=True 只允许读取既有失败前缀，仍拒所有实际配置漂移，默认 Runner 仍拒下一命令；不清除原因、不赋予权限。此前 cost/collector/boundaries/Runner 联合 48 passed（46.27 秒）是此前源码证据，新 freeze 后再验证。Integration 子代理正在修 writer/selector 对实际 GPIO identity extension 的一致闭集检查，独立 reviewer 并行审查。新实际 DUT gate 尚未启动。


Session 新轻量 guard 实际默认 bootstrap 五次检查 0.089285 秒（优化前 1.123271 秒，约 12.6 倍），仍 126464 slots，无 DUT 命令；证据 /tmp/myfuzz-ordinary-session-guard-cost-final-20261012.json。Root 32719 在当前接口上完成 collector/evidence boundaries/Runner/CLI/Runtime source guards 五模块 46 passed，60.99 秒，exit0。当前生产冻结候选：Session 3eebb6c82ebc9ed209b39c9bbd6f169318303f6815d70ae17f37d6357d7a82e4；collector 131304413d2abb2ffcdd4790522cbc52025bc4f85324a0ac2847ea6c4866f2bf；integration bfc33d3c554f3401291bd57d40690f9ec16365e840add2900a691bb9aaf6ee8d；CLI 3052d615d215c5c9ef545424a4615346d930d54d557635dcaa2b21136d768b08。Integration writer 已复用 selector 的 ordinary GPIO identity 语义检查，在创建输出目录前拒自相矛盾身份；旧关闭路径保持。三个子代理 final owned Session19、integration8+legacy20、independent19 验证正在运行；无新实际门禁成功声明。

Session 子代理最终完整 19 passed，59.76 秒，20831 exit0，生产 SHA 3eebb6c82ebc9ed209b39c9bbd6f169318303f6815d70ae17f37d6357d7a82e4，测试 SHA af53a6f9cc0f30ad1903213a47e37741a7ea0551b0097fb0744b68d17c1c81be。独立真实门禁脚本预审已派发，不改生产，不启动额外 worker。


最终软件冻结验证：Session19 passed59.76秒；independent19 passed21.63秒；integration8+legacy20共28passed/34subtests146.50秒（79906 exit0，额外精确alias单项0.27秒）；root46passed60.99秒与default/capability Scenario replay27passed98.10秒。Root真实门禁已于本轮启动，46821，singleworker180sec/fullprocess resource policy，runs/stage2-e2-ordinary-access-file-cli-20261012；check.py 独立增强精确 raw/base/source/receipt关联，SHA5be4d4d7c09bf0d6864c01241eccc9ba1b7aa4f33b498b6566a7cdf5b4d76da9。结果尚未产生，不声明通过。


第一实际门禁 46821 exit1，55.484768 秒、peak610742272 bytes、limit3248095232、workers1，resource status command_failed、dut_finding=false。首个case gate错误假定每访问固定6 raw refs，实际 target command完整sample span可含更多tick；生产closedvalidator原本接受完整偶数span。没有freshCLI成功证据。本次worker.stderr/resource/sourcepins永久保留在原目录。Root准备独立 v2目录，保留完整 tagged sample_ticks×pre/post精确集合和3base真实投影检查，并在verify前先保存实际用例事件；生产源码不改、不重用失败输出目录。


第二实际门禁 v2终态 command_failed（12502 exit1，96.250152 秒、peak1647923200、limit3244351488、workers1）；10cases全部实际通过，独立review确认18case associations、54APBbase、144rawrefs、2RAMcommits及281当前sourcepins。终态脚本把全Session记录数固定18失败：bootstrap实际ordinary访问也在完整collector中，不可丢弃或以case范围替代完整终态。尚无bundle/freshCLI成功。本次全部case actualinput/result与日志永久保留。第三版14974已启动，新目录-v3保存startupjournal/snapshot并以完整实际journal对完整collector.records逐条比较，total=startupactual+18case记录，fresh仍完整snapshot精确比较；生产freeze不变。


第三版14974原整段gate wall_timeout180.074089秒exit124，peak2628591616<limit3247824896、workers1。实际startup6+case18=24完整关联、192rawrefs、72base和2RAMcommit独立核对通过；全journal22387rows与snapshot完整一致。超时前bundle完整落存，独立审查正验证9artifact身份，但无完整CLI结果。Root对该已保存bundle单独singleworker180秒production fresh CLI预算启动75768，fresh-cli-command/resource/stdout/stderr将单独保存；不重跑generation、不掩盖整段timeout、不将分阶段结果说成原组合gate通过。


### 本轮最终结果与下一步

Root75768实际production fresh CLI exit0、matchesTrue，103.455044701秒、peak2116165632<limit2558029824、workers1/complete；全24 actualsnapshot exact一致，22387events/semantic7eab0303fdf4c4116174a032ee33651ebc977fb3dab4577299595ca31705da5d。独立v3审计已落 independent-audit.json：9认证artifact、281externalpins、278closure、6bootstrap+18cases/24fullrecords、192raw/72base、2RAM和cache所有frozeninputs SHA、fullfresh24snapshot/semantic/startupcap一致，无P1/P2。原combined180.074秒timeout保留，不将分阶段success标为原整体budgetpass。

四进度入口与原计划/nextsteps/本报告已同步。最终doclink扫描628files/1696links，83既有历史broken、0Stage2 broken，exit1如实记录。四production SHA与final软件测试freeze一致，未commit/stage/清理dirty。原完整Stage2目标继续active；下一步先用timedmarkers/faulthandler定位combined预算成本，再处理code-owned peroperation verifier/实际CPU后续readback/reset/权限/mask/width/effects，D5/D6/D8、E1/E2及E3–I未关闭。
