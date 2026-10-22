# Native exact-source completion：attempt2–5 未验收记录与 attempt6 frozen plan

## 当前共享工作区整合（2026-10-22）

- Tasks 1–4 的源代码变更已从 `codex/native-exact-source-completion-20261018` worktree 整合至当前工作区；`session_runtime.py` 通过三方合并保留已有 DMA binding additions。独立 diff review 未发现 blocker。聚焦 source-completion、identity 和 campaign 门 **96 passed、2 skipped、46 subtests**；DMA-bound session/replay 回归 **42 passed、3 subtests**。
- Native opt-in receipt parsing 已增加 exact tap name/width admission。仅当被认证 artifact 显式含 `native_completion_observation` 时，RESULT 内每个 PRE/POST sample 必须有固定六个 tap、无多余字段、数值为非 bool 整数且在位宽范围内；`NativeBusObserver` 继续负责 tap 之间的协议语义。聚焦 wire/session/native-runtime tests **29 passed、48 subtests**；HARNESS V2 identity tests **6 passed**。
- DMA-bound payload reader 的 online-plan schema 白名单扩至 22/23。schema 22/23 envelope 往返及其解包后进入 native replay comparison-policy 检查的回归 **4 passed**；该软件组合测试不等同于 combined real session/replay。
- Task 5 independent evidence auditor 已改为显式 identity manifest＋外部 SHA；复读逐项重核固定 hash，拒绝非规范路径、工作区外 heavy lock、旧分支摘要错配，并逐项检查 source/tool 清单记录。共同 64 位 `gate_run_id` 现贯穿 intent/plan/claim/launch/start/end/post、三分支结果与 summary；分支名、gate PID、分支摘要和 summary 摘要均由 auditor 交叉校验。auditor focused suites **37 passed、3 skipped、21 subtests**，独立复审未发现 blocker；与 producer CLI identity、gate-check 和 D1 声明测试的合并门 **63 passed、3 skipped、32 subtests**。
- 审计输出明确 `source_tree_closure_verified=false`、`external_tool_bytes_verified=false`、`gate_executable_identity_verified=false`。这些边界尚未验证，不能声称完整源码闭包或执行时解释器身份已认证。
- 已有 gate/controller 仍未生成并传递共同 `gate_run_id`，也未在终态收据中绑定三个分支和 summary 的最终哈希；新 CLI 和 auditor 因此会对旧调用/收据 fail closed。Task 5 尚未运行。新的 [r11 controller 计划](../superpowers/plans/2026-10-22-native-completion-r11-controller.md)已起草。并行只读审查推动补入审计器精确 argv/identity、tool-freeze 路径与行结构、Stage 1/2 gate 字节相等、launch-intent SHA 强关联和外部独立 identity SHA；修订版复核中。SSH 目标探测返回 `No route to host`，未读取或写入远端。尚无 r11 实现、包、上传或运行结果。
- 本次未运行 native RTL/build、远端 controller 或 Task 5 gate。PicoRV32 source-completion real-process positive/no-grant/refusal + full fresh replay + independent evidence audit 仍未完成；proof scope 仍限 `native_instruction_bus_transfer_completed`。

## 本地实现 Tasks 1–4（2026-10-19）

本地分支 `codex/native-exact-source-completion-20261018` 的 HEAD 为 `e5d798a`。Tasks 1–4 已按实现计划完成并分别留有实现报告：Task 1 `07bffcf`/`b07e749`（实际 MemoryService read issuance）；Task 2 `bc15221`（精确 live source-binding lookup）；Task 3 `78494e0`/`b1e0cf9`/`f1cd387`（仅在验证后的 next-PRE 握手签发 completion）；Task 4 `e5d798a`（默认关闭配置、Runner 消费和独立 fresh owner replay）。

- Task 1 聚焦门：29 passed、5 subtests；Task 2：38 passed、5 subtests；Task 3：43 passed、15 subtests，另有可用 PicoRV32 campaign 24 passed/2 个 RTL-gated skips；Task 4：74 passed、2 skipped、22 subtests，独立 review clean。这些是既有本地软件/适配器证据，不等于 Task 5 real-process gate。
- Task 3 相邻 native runtime/reset suites 在该 worktree 因缺少 `third_party/picorv32_upstream_reference/picorv32.v` 未能 setup（17 setup errors）；因此不能记作通过，也不替代 Task 5 的冻结真实门。
- Completion 对象的 proof scope 仍只有 `native_instruction_bus_transfer_completed`；不声称 decode、retirement、CPU semantic consumption、peripheral payload consumption、source authority 或 feedback。下一阶段逐边反馈边界见[独立设计规格](../superpowers/specs/2026-10-19-native-source-completion-feedback-design.md)，该规格尚待用户审阅，不是实现或验收。

## Attempt6 frozen plan 状态（2026-10-19）

**当前状态：** Task5 auditor candidate8 已通过两名 reviewer 独立静态 ACCEPT；run-plan v12 已通过独立复核并写入远端，attempt6 仍未启动。最新实际 gate 仍是 attempt5-v2 rc `1`，失败点为 `native-comparison-completion-source-join`。Task5、P6/P7 尚未验收。

- Final auditor SHA `281807c1d93bf9f64afa60dc87c376805adcc0e9a8cf28a0483e2187c9be848c`：本地 AST/空白/换行检查通过；两名独立 reviewer 确认其 intent、controller v12 产物及终态 join 无必然拒绝项。Candidate7 `d575d37f…43eb363` 曾通过初轮静态审查，之后的 producer-contract 交叉核对发现 Python hash 单字符错误、launch-intent 不含 `claims`、canonical-lock 多一个 `access_policy` 字段及未定义 `ZERO_SHA`；candidate8 已修复这些点，并保留其余严格身份、路径、状态与错误拒绝检查。
- 非阻断的失败路径资源清理限制仍在：匿名报告 fd 的早期 `fchmod/fstat` 失败、Reader 拒绝特殊文件或根目录身份变化时，长寿命调用可能留下 fd；当前一次性 CLI 会非零退出、不会发布成功报告，进程退出后由 OS 回收。若改作长寿命库调用，应继续收紧清理。
- Auditor 已部署到远端固定路径 `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261018-attempt6/independent_audit_task5.py`，核验为 root-owned regular file、mode `0600`、SHA 与本地一致。旧 candidate7 原件保存在同目录 `independent_audit_task5.candidate7.py`，SHA `d575d37fb3fb0a0c3286f85f173833c96daa2836421d8a8efd6d8f31843eb363`。没有执行 auditor。
- Frozen run-plan 已写入 `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261018-attempt6/attempt6-run-plan-v12.json`，SHA `bc6747eb5fdd5c3eee15af6239b2dd9b040b385f5b093182521c7bc87b5ffcfb`，root-owned regular file、mode `0600`；远端回读字节与本地草案完全一致。它嵌入的 intent v1 SHA 为 `b8f240eb769d8c1c830a1170cddb4d06c1063915c028bfe99bbeb10a8580c1a6`，controller/receipt 分别固定为 `0f9a1912…f87f9e`／`857cfa03…e9118`，post-gate audit 固定 candidate8 SHA。
- Plan 精确绑定 intent 声明的 v1 claim leaf 与 controller 实际写入的 v12 claim leaf，并记录 `attempt6_launch_claim_path_binding.v1`、v1 leaf 必须不存在、claim `O_EXCL|O_NOFOLLOW` 和三个输入哈希绑定。`post_gate_audit.status=deferred_to_parent_after_gate_terminal`、`executed_by_controller=false`；审计 argv/cwd/Python identity/输出路径均已与 controller 和 auditor 契约复核。
- 远端 operation/evidence 目录只读检查确认 frozen plan 之前 claim、launch-intent、gate start/end、post-run integrity、controller-error 与 auditor 输出均不存在；evidence 输出目录也尚未创建。Plan 内 `gate_started=false`、`gate_executed=false`。没有创建 launch claim，没有运行 controller、auditor、tests 或 gate，也没有 attempt6 gate evidence。
- v10 controller 因 emergency process-group 清理缺口拒绝启动；v11 因 signal handler 过早恢复导致终态写入缺口拒绝启动。Frozen v12 controller SHA `0f9a1912e52b4411d78924e96e1dedf5cd0a59d5449703dbf42162c854f87f9e`／receipt SHA `857cfa0384776b92c76299f5445489bed32d23608f1caf887dabc1ecbe6e9118` 已通过独立安全复核；二者仍未执行。
- 只读 producer 核对确认 CPU native projection 的 `component`、`event_id`、`producer_event_id` 与顶层 `provenance` 是 Runner/EventJournal 投影时补入；`response_consumed` kind 有 `value` 和 `native_post_is_offer_only`，没有 `native`。Source-binding journal 也带顶层 provenance；poison 的原始 `MemoryService` write payload 与 Runner 装饰后的 journal event 必须分层核验，不能要求两者全字典相等。Completion kind `native_instruction_bus_completion` 的 provenance 绑定 selected case 的 `case_id/case_index`，`resource=null`；当前 `RuntimeEdgeIndex.match_event` 对该 kind 返回空候选，因此 scope 仍为 `observation_only`、`edge_candidates=[]`，不主张 CPU 消费、decode、退休或 source authority。
- 远端 evidence 所在文件系统的只读 metadata 为 `/dev/sda2` ext4、rw，root SSH context `CapEff=000001ffffffffff`（含 `CAP_DAC_READ_SEARCH`），符合 `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` 的静态前提；未做 syscall 探针，也未据此声称审计器运行成功。

日期：2026-10-18。本文汇总远程 attempt2 与 attempt3 的失败记录，以及 attempt4/5 状态：attempt2 在首个 bootstrap read 校验处退出，attempt3 在 fresh comparator 的 completion-shape 检查处退出；两次 gate 均失败。attempt4 的 gate 启动前失败且无 DUT evidence。attempt5 v1 preflight 已通过；独立审查发现未来写入点存在静态 hardening 缺口，但未发现现有路径逃逸。远端已停止 gate，保留 v1 并准备 v2；v2 审查和重做 preflight 待完成。

## 结果

- Gate controller PID `1870994` 启动 gate PID `1875999`，UTC `2026-10-18T13:36:36Z` 至 `13:38:23Z`；gate 被 controller 实际 wait/reap，退出码 **1**。stdout/stderr 均为空（SHA-256 均为 `e3b0c442…b855`）。
- 只运行了 `positive` 分支。第一个 testcase 尚未提交：保存的 `attempted_plan.cases=[]`、`source_admissions.admissions=[]`。PicoRV32 在启动时对地址 `0` 发出首笔 bootstrap instruction fetch；一次实际 RAM read 和 backend response consumption 后，分支以 `ValueError: native read is not an unchanged issued result` 失败。失败事件标为 `harness_failure/status=uncertain_effect`，本地 tick 从 2 到 3。
- Partial bundle 共 123 个事件，记录首笔 `memory_read`（event 99，地址/byte offset `0`，数据 `b7000040`；四 lane 的 writer 均为 `initial-image`／`INITIAL_IMAGE`）、首个 tick 的 raw PRE/accepted observation（events 108/109，PRE `valid=1, ready=0, instruction=1, addr=0, wstrb=0`）、下一 tick 的 raw PRE/response-consumed observation（events 115/116）和失败（event 121；event 122 为失败 tick 的 raw PRE sample）。事件中没有 `native_instruction_source_bound` 或 `native_instruction_bus_completion`。
- CPU/GPIO DUT 确实启动并走到第一次 backend response consumption，但首例未完成。CPU PID `1943242`、nonce `2a0f3edc6bd4442ab91174bc88404838`、terminal return code `-9`；GPIO PID `1943417`、nonce `88274a34658c44a4867340bce8ab9e3e`、terminal return code `0`。只有这一组 original 进程，没有 fresh 进程。
- 没有 selected-source positive credential、成功的 noncandidate no-grant 控制、selected-source contradiction 注入/拒绝记录或独立 refusal audit。没有 fresh comparison；`matches`、`verification_scope`、`first_difference` 均不存在。`summary.json.gz` 和其他分支的 `result.json.gz` 未生成。由于 bootstrap fetch 的处理本身报错，本记录不把它登记成“bootstrap 诊断通过”或“no-grant control 通过”。

## 根因：issued-read 校验与正常事件释放冲突

已由 attempt2 调用链确认，这不是 read 凭据的三 tick 有效期：`MemoryService` 注册 issued read 时保存了原 `memory_read` event、它在 `service.events` 中的 index，以及 canonical event 内容。`NativeBusObserver.bind_read_snapshot` 在服务 read 返回的同一调用内执行首次 lookup，因此当时该 index 仍指向原 event，handle 成功写入 pending。

CPU 这一步返回 Runner 后，`Runner._append_external_events` 将 `service.events` 中的记录复制到 EventJournal；EventJournal 路径随后清空 producer list 并重置 offset。报告中的 event 99 保留在 Runner journal 中，但已不再位于 `service.events`。Events 108/109、115/116 展示 accepted 到 response-consumed 的前两 tick；event 121/122 标出第三 tick 的失败与 raw PRE。该 PRE 完成路径调用 `_ISSUE_NATIVE_COMPLETION`，其前置时序与握手检查通过后进入 `_VALIDATE_ISSUED_READ`；attempt2 的 `lookup` 仍检查保存的 index 是否位于 `service.events` 且对象身份未变。list 已清空，所以 index 越界条件触发 `ValueError: native read is not an unchanged issued result`。

这是实现校验与正常事件释放生命周期的冲突。失败发生在 `lookup_issued_source_for_read` 之前，source candidate classifier 没有运行；既没有完成凭据，也没有 no-grant 或拒绝结果。本根因解释不改变 gate 失败结论，也不关闭任何验收门。

## 冻结身份与完整性

- Evidence：远端 `/root/fanzehui/myfuzz/evidence/p6-native-instruction-bus-completion-v1-20261018-attempt2/`。仅保存 `positive/result.json.gz`（SHA-256 `a418d0fee8b4c67e68fc1b6a352ac359993ce223f61cdd4b470a93699d54ca96`）和 `positive/runner-0-partial.json.gz`（压缩文件 SHA-256 `6c9b422ec79200c6cb927fd9cc231cee79bef5c9772992761620329f26f35100`；解压 JSON SHA-256 `7724de3f949ff6b47568b96e40d919def8530916c5fdac8571da7067b54a87c2`）。
- Operation：远端 `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261018-attempt2/`。源父 HEAD `e5d798a5f9f3d105b74af9375c267ea406563462`；source archive SHA-256 `f8be7c7774db40726e7642cc53c52a263810d0a45231f107ba3055f044e46801`；Task5 scoped patch SHA-256 `569b3fe384606e71b87c8f700938452fb686e8e0951e08a3df983164a50e55ab`。PicoRV32 与 PULP APB GPIO submodule 分别固定在 `ef203c2b0a3fb793280f5114941416c425c5b461`、`f82caeb7f7d89427f05e9af5ed31e0675efe0d83`，run plan 记录二者 clean。
- Remote/local source manifest 各 5,806 entries。Local manifest 文件 SHA 为 `14bdc8d66ea96f2c556c9c2859e7a0a276fcebc8458c8c5191d9febfcc65a100`，远端重算 manifest 文件 SHA 为 `2377cf3e5132847e81b78a2162f7a1ab7b5d72ee2fc3a4c619a9522db6582c12`；两者的 canonical entries SHA 均为 `6ddabfc6cf3613f472a8a10db376de08fb397ce3a7ff1361f6bd7f378d5f15f9`。Preflight 和 postflight 均为 `source_tree_manifest_match`，`metadata_match=true`，changed/missing/extra 均为空；`post-run-integrity.json` 的 `source_tree_matches=true`。
- Tool freeze SHA-256 `6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b`，environment script SHA-256 `9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c`，均与 run plan 一致。记录了 11 项工具身份；Python `3.12.3`，Verilator `5.051 devel rev vUNKNOWN-built20260806-e413e67`。
- 受保护路径 pre/post 状态相同：`/root/fanzehui/myfuzz/project`、attempt1 project 与 `/root/fanzehui/system-20261016/project` 均仍为 HEAD `42a9ce99cc7d1b11d37f44b90e4753563691c44b`，97 个 status entries，status SHA-256 均为 `a6d9dad3a1bca28ad48cd03533d3c1b51b3eba9d76a1490b87e901883e0e5619`；`protected_status_matches=true`。

## 能力边界

本次只证明 attempt2 在新源码副本上启动了真实 DUT，并在首个 bootstrap fetch 的 read-result 校验处失败。它不证明 `native_instruction_bus_completion.v1` 正向发行、来源精确完成、bootstrap/no-grant 行为、矛盾拒绝或 fresh replay。凭据目标口径仍为 `proof_scope=native_instruction_bus_transfer_completed`、`grants_source_authority=false`；这类凭据本身不表示 decode、执行、架构退休、CPU 语义消费、外设 payload 消费或反馈。本次没有凭据可授予。

P6 行5/整体以及 P7 gate 均未由本次 attempt2 关闭；P6/P7/P8 整体状态不因本次运行提升。后续重试应保留本次失败证据并使用新的 attempt 目录。

## Attempt3 终态：三例完成，fresh comparator 拒绝

日期：2026-10-18。attempt3 是独立新运行；attempt2 的失败记录、根因和证据保持不变。

- Gate PID `2894076` 于 `2026-10-18T14:01:48Z` 至 `14:04:15Z` 运行，controller 实际 wait/reap，退出码 **1**；stdout/stderr 均为空。三例 directed cases 均完成，relation findings 为空。Original 与 fresh 的 CPU/GPIO 共四个 DUT 进程均以 rc `0` 终止。
- Original bundle 已保存，首个 native completion event 为 event `502`。关联顺序为 admission `472` → instruction source `473` → host binding `474` → read `476` → accepted `486`（tick 47）→ response `493`（tick 48）→ completed `500`（tick 49）→ completion `502`。来源 provenance 仅为 `observation_only`／`unknown`，不证明 CPU 语义消费、decode 或退休。
- Gate 在 comparator 处理 completion event 的 `provenance` 多字段时，以 `native-comparison-completion-shape` 失败。虽然 fresh DUT 已运行并正常退出，但 fresh bundle 未保存；source-completion、controlled-response 与 refusal gates 均未执行。因而这不是 Task5 通过，也没有新的能力级别可授予。
- Evidence 位于远端 `/root/fanzehui/myfuzz/evidence/p6-native-instruction-bus-completion-v1-20261018-attempt3/`：`positive/result.json.gz` SHA `549b180e…6781a1`；`positive/runner-0-partial.json.gz` SHA `0b2ace7a…69be3`；`positive/runner-1-partial.json.gz` SHA `019f47ba…ea0d85`；`positive/first.json.gz` SHA `706248e8…24d1c`。
- Postflight source map 为 5,806/5,806，protected status 与 canonical lock 的 before/after 均匹配。canonical lock 文件为 0 B、mode `644`，SHA 为 empty-file hash `e3b0c442…b855`。attempt2 的 evidence 与工作集未变。

attempt3 不关闭 Task5、P6 或 P7 gate，也不改变 attempt2 的失败结论。后续索引修复和 attempt4 gate 前状态见下节。

## Attempt4 状态：v2 preflight 通过，gate rc1，审计待完成

attempt3 的 gate 终态仍为失败。其后 comparator 已增加对 `observation_only`／`unknown` 多字段 `provenance` 的明确白名单校验；跨事件关联也增加了 `admission.case_index` 约束：必须是精确的非负整数，并且必须与 binding 的 `case_index` 相等。

对应 TDD 负例先复现旧行为，再在修复后通过；独立只读 review 通过。本地五文件回归为 **83 passed、3 skipped、57 subtests**。这些软件检查不构成 Task5 DUT gate 结果。

attempt4 的独立目录与 545 MB project copy 已创建。两个 overlay hashes 与目标 SHA 一致；attempt3→4 patch、5,806-entry source manifest、source receipt 和 controller 已生成。已知 controller SHA 为 `b84e1e…068fdd`，receipt SHA 为 `04a649…9b27d5`。

首次 final preflight 在 gate 启动前安全拒绝：`evidence/attempt4` 已存在且为空，但继承 controller 要求 `OUT` 不存在。此次拒绝未新增 preflight 或 gate-run receipts。原规范 v1 controller/receipt 已恢复，SHA 分别为 `b84e1e…068fdd`／`04a649…9b27d5`；中间方案保留为唯一 `proposal-rejected-no-gate` artifact。v2 controller/receipt SHA 分别为 `dddf20…63f4a1`／`a2e919…b71a9`，run plan 中两个引用点均指向 `attempt4-source-receipt-v2.json`。v2 的 `OUT` guard 要求经 realpath 确认位于目标 evidence 根目录内、不是 symlink 且为空目录；`cache`、`tmp`、`home`、`xdg` 仍按 absent-only 检查。

随后 attempt4-only 完整 preflight 通过：5,806-entry source map 匹配，overlay、submodule、protected baseline 和 canonical lock 均匹配。Controller PID `3660671` 于 `14:21:25Z` 启动，run plan 引用 v2 receipt。Gate PID `3664610` 于 `14:21:30Z` 启动，已由 controller wait/reap，rc `1`。失败发生在 `verify_picorv32_native_online.py:626`：`args.output.mkdir(..., exist_ok=False)` 因预建空 `OUT` 已存在而抛 `FileExistsError`；它早于 canonical lock open/acquire（line 627）和 `run_gate()`。因此没有 DUT 或 source-bus transaction，`evidence/attempt4` 仍为空，没有 gate evidence。stdout 为空；stderr 为 702 bytes，SHA-256 `3836c713d63c7c6653366a62fc2e8dc1b766f3aa922e63f4f29e53d279008abe`。

Postflight 确认 source manifest 匹配，三条 protected status/HEAD 前后未变；canonical lock 前后均为 mode `644`、0 B、empty-file SHA。失败分析文件 SHA-256 为 `b13c25f47157fc3e79f2c5e5165006aed7bf2b1906ae3a0ffe75b7c2a2f4acaf`。**attempt4 未重跑、没有 gate evidence，Task5 能力不升级，P6/P7 gate 未关闭。**下一步使用全新 attempt5 evidence path，让 verifier 创建输出目录，并保留 attempt4 原件。

## Attempt5 当前状态：v2 gate rc1，比较器格式根因已确认

attempt5 的 operation/evidence 新路径已安全确认不存在；project 从 attempt4 v2 copy 建立，5,806 entries 逐项一致。attempt5 manifest 有 5,806 entries，与 attempt4 v2 的 entry diff 为空；canonical digest 为 `5fc3fe…c695`，manifest SHA 为 `4df1c7…54b5`。patch 为空字节，SHA 为 `e3b0c4…b855`；controller SHA 为 `b6e735…03bc`，receipt SHA 为 `9aeca4…e469`；三份 v2 文件的 hash 一致。

此前独立审查记录 v1 controller 的 OP mode 为 `700`。最新 `stat` 收据与该记录有差异：本次按新收据记为 root-owned mode `755`，没有其他用户写权限；未更改权限。controller 不是 symlink，检查到的现有输出路径是普通文件或缺失，没有观察到路径逃逸。v1 preflight 已通过，但独立只读审查发现静态 hardening 缺口：部分未来写入点只用 `! -e`，不能拒绝 dangling symlink；Python `write_text` 与 shell redirection 也没有防止跟随 symlink 的独占创建保护。这是潜在的未来写入路径风险，不是已发生的路径逃逸。

远端代理停止 gate 并保留 v1 原件后，已冻结 v2 controller（SHA `f8e3eeed…f8f55`）、source receipt（`8dadefe5…c92c0`）、intent（`088b1522…2346b`）和 preflight helper（`698de23e…3c022`）。V2 对所有 leaf 同时检查 `! -e && ! -L`，JSON 使用 `O_EXCL | O_NOFOLLOW`，日志使用 `noclobber`，旧 preflight 文件只读校验、不覆盖。Preflight status 为 `PASS`、`gate_started=false`，SHA `f07c732e…6a37f`（冻结 preflight 时点的状态）。独立审查已通过，核对了五个文件哈希、leaf guards、JSON 原子/不跟随 symlink 创建、日志策略、manifest、protected paths 和 lock。

审查边界：初始独立审查时实际 `run-plan-v2` 尚未生成，因此该轮只审查 intent 和生成代码。随后实际 `run-plan-v2` 生成并独立审计通过，SHA-256 `8d67714ae2ea0cbfd09d4177b4963cf2b5f98b1377d6a3aa49acd0d34ea825c5`；flags、paths、source manifest、8 个 Task5 文件哈希、11 项工具身份和所有 claims=false 均匹配。Controller PID `232858` 于 `14:41:07Z` 启动，gate PID `238584` 于 `14:41:16Z` 启动。输出 `attempt5-v2` mode `700`，三 flags 与 frozen plan 一致。

Gate PID `238584` 于 `14:41:16Z`–`14:43:52Z` 运行，终态 rc `1`；stdout/stderr 均为空。`positive` 下 `first`、`case-1..3`、`result`、`runner-0-partial` 和 `runner-1-partial` artifacts 均存在。Positive/negative 两侧 original/fresh 的 CPU/GPIO DUT 进程均 rc `0`。Postflight source tree match；protected HEAD/status 与 canonical empty mode `644` lock 的前后状态均匹配。

Gate 失败原因为 `native-comparison-completion-source-join`：运行时来源记录使用 tuple，而比较器只接受 list；gzip JSON 序列化会将 tuple 编为 list。首个失败 event `502` 对应 case `0`、地址 `0x200`、指令 `1305e003`；event `2354` 也有同形结构。Gate rc1 与这些 DUT/partial artifacts 均不构成 Task5 通过。

只读 failure-analysis receipt 位于远端 `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261018-attempt5/attempt5-v2-failure-analysis.json`，SHA-256 `3d863df62ce0c12929fcc27fde2f8db1fc668e32366113b395934b097e9c251b`。本次仅记录既有审计收据，未重跑 attempt5 gate。

本地已做窄修复：该比较器在此 join 处精确接受 list/tuple 两种等价容器，同时严格检查字段、元素、长度、顺序和值；`native_pre` 仍只接受 list。Targeted suite 为 **85 passed、3 skipped、60 subtests passed**。最终 SHA：`native_replay_identity.py` `64436efe41fd5443a0d3425f9bd55d88c520470f81a472d00624c51c6f7440bf`；`test_native_instruction_bus_completion.py` `f68b0839a61fcd189b5518b16839268b5345a9844796169e2d1d67dcda247041`。这是本地软件修复证据，未重跑远程 gate。

**Gate rc1 和本地定向 suite 不表示 Task5 通过；attempt5 未重跑，能力级别不变，P6/P7 gate 未关闭。**

执行 `py_compile` 在 OP 内产生 `__pycache__/attempt5-preflight-v2.cpython-312.pyc`，该文件已保留；它位于 operation 内，没有改变源码或 evidence。**attempt5 gate 已以 rc1 结束，未重跑；能力级别不变，P6/P7 gate 未关闭。**
