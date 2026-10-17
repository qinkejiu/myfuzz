# 三代理并行源码增量：CVW 域修正 / APB A2 主机消费 / 通用 F4 D1

2026-10-17。本文汇总本轮三个并行源码增量的**实际提交、实际纯软件测试与根代理独立复核**，并明确未完成的原生门。整个系统、P6/P7/P8 仍未验收。

## 1. CVW AHB manager-domain 观察修正

**提交**

- `87bef94` `fix: correct CVW AHB manager-domain observation (contract core)`
- `782b091a8f267677e33db2b6d7b6f08a954a767c` `fix: correct CVW AHB manager-domain observation (negatives and identity)`
- `fc1a0f7`、`e6912b1` 报告/证据

**实际改动**

- `configs/cpus/cvw/component_profile.json` 新增非协议 observation 端点 `cpu.manager_domain`：`manager_ready=HREADY`、`bus_reset_n=HRESETn`；移除冲突的 HREADY/HRESETn port_actions（HCLK 保留 observe）。十三角色外部端点不变，`hready` 仍是 `HREADYEXT`。
- 新增 `src/myfuzz/local_harness/ahb_manager_domain.py`：版本化 `ahb_manager_domain_contract.v1`，认证 profile 端点、结构 ABI、physical export、clock/reset provenance、唯一 source wire；拒绝 EXT 回退、reset 反相回退、protocol-tap 别名。
- `AhbCpuObserver` 升级到 observer version 3：显式 PRE/POST 域行；只用 PRE；实测 bus-reset assert→release 才建立前缀；manager_ready 接受地址；外部 ready 用于自有 selected-external data phase completion；缺实测 reset 时 `finish_startup` fail closed。
- 旧 16 边沿 native artifact 通过 `project_saved_manager_domain` 做 **software projection**：原始样本/收据字节不变，明确标注旧 profile SHA `c60ddb…` 与新 profile `a04865…`，不重签、不冒充新原生运行。

**实际测试**

- 保存 RED：旧解释（把 `HREADYEXT` 当 manager_ready）在 edge11 POST 地址变化处仍 `ahb_address_hold`，raw=11。
- 保存 GREEN：新域 16 edges，仅 edge11 接受 `0xc0000000`；`external_ready_at_accept=0`；`completed=0`；pending `0xc0000000`；bus reset assert@3/release@11；startup 后 prefix=false；全部 observation_only。
- `tests/scenario/test_ahb_manager_domain.py` **36 passed**。
- 聚焦回归（`test_ahb_manager_domain`、`test_ahb_startup`、`test_ahb_cpu_contract`、`test_ahb_cpu_observer`、`test_ahb_lite_renderer_shape`、`test_cvw_ahb_gate`、`test_contracts`）**160 passed，2 subtests passed**。
- 根代理独立脚本重放保存字节（不使用代理测试）得到同一结果；脚本与期望值保留在 `.superpowers/cvw-manager-domain-root-audit/`。

**边界与已知问题**

- 未做新 profile/runtime 的 native/elaboration 验证；**不宣称原生门通过**。旧 attempt1 仍是唯一原生证据且仍为失败。
- aggregate HRESP/HRDATA 未导出；其它 slave 上下文仍 `unvalidated`；不声称 reset 同步器延迟。
- 既有 source freeze 因源字节变化失效，不可复用。
- `tests/integration/test_cvw_ahb_runtime_generation.py` 中 `test_the_built_harness_drives_real_ahb_traffic_from_the_core` 仍直接发 STEP_MEMORY，未先 READ_AHB_STARTUP；它在 AHB startup v2 后是**既存 stale 测试**，本轮未修（修它需要一次原生构建验证）。
- `tests/local_harness/test_ahb_lite_session.py` 在本 checkout 中 `real_plan` 于 elaboration 前即报 `content-hash-mismatch:cvw`（CVW 子模块工作树与 profile pin 不一致，属既存环境；profile 的 source 列表/bytes 未被本轮改动）。随后 `-k ahb` 的整组回归出现该文件 8 failed，均非本次源码结论；根代理误将该文件选入一次 adjacent 跑，未把它当证据。
- **代理越界已如实记录**：整文件运行上述 integration 模块触发了 Verilator-gated 用例；随后又把 `test_ahb_lite_session.py` 的五个构造用例当纯测试，实际再次触发 elaboration。两次结果均**不作证据**，无残留进程，生成缓存已删除。详见 `.superpowers/sdd/cvw-manager-domain-report.md` 第 7 节。

## 2. APB A2 启动采样主机消费

**提交**

- `4c0a62c15e1f24404dc86fb1a2f83c5710be2db4` `feat: consume generated APB storage startup pages`
- `d4594e38ff11fe2e707543a85732b32621d94c72` `feat: finalize generated APB storage startup host consumer`

**实际改动**

- `_expected_ready` 只对精确 A2 文档（generic APB + `apb_storage_startup.v2` + selection + capture + canonical `contract_from_document`）放行；跨 kind/partial/unknown/tampered 拒绝；普通 v1 与 AHB v2 分支不变。
- 私有 `READ_APB_STORAGE_STARTUP` 操作表只在 A2 admission 后合并；`registered_operations(kind)` 对旧调用方不变。
- `begin_case` 在真实 READY 后、任何 setup/STEP/ACCESS/SOURCE/BIND 之前按序取回全部页；页零 command tick、消耗真实 wire sequence/ACK 容量、逐页校验 contract/probe/width/budget，保留 parsed+raw receipt。
- 丢失/畸形/partial/duplicate/reorder/EPIPE/OSError/lost-ACK 页记录 `possible_effects=true`/unknown、保留 raw/已收页、abort+reap、永久 poison、不自动重试。
- 新增 `validate_startup_handoff`：last startup post → first command pre 的持久 storage/reset 连续；实际命令字段 join；readback/pready/pslverr 变化合法；release=0 不合成释放。
- C issuer 增加 startup-retrieval phase：独立 `last_wire_sequence`、页顺序/scope/epoch/tick-base、真实 frame/receipt/pending operation-fields-sequence 匹配、每次零 tick READ 清空旧 token、handoff 前拒绝 issue/consume。
- B 闭合新增 `apb_storage_startup` 依赖/源哈希，并核对 A2 私有 contract/ports。

**实际测试（纯软件）**

- 8 文件 A2 focused 套件：**250 passed，59 skipped**（29.69s）。
- AHB/build/host-source 套件：**147 passed**（71.26s）。
- session/driver/GPIO/default：**41 passed，3 skipped，15 subtests passed**。
- GPIO/native reset evidence：**135 passed，2 skipped**。
- 根代理实跑 8 文件子集（含新 host/issuer/startup 文件）：**232 passed，16 skipped**；另外 `test_native_reset_evidence.py` **95 passed**。

**边界**

- 未执行真实 native gate：elaborated hierarchy/probe/reset waveform、实际 startup pages、first-command 连续、fresh prefix、counter/negative control 均未做。
- C native-positive startup→first-command→issue/consume 在非 eligible 软件 fixture 上不可执行；C issuer 原冻结于 `053ff9c`，本任务明确分配 startup 路径，**需 C owner 复审**。
- `grants_reset_prerequisite=false`、`hierarchy_verified=false`、`native_verified=false`、`reset_authority=false`、`version_authority=false`、`source_authority=false` 全部保留；startup levels 不是 F4 reset prerequisite。
- fresh-scope/reset consumer、F4 witness join、Runner/P7 未完成。

## 3. 通用 F4 封闭生产者选择（D1）

**提交**

- `cd4154a` `feat: add closed compiled F4 storage producer selection`

**实际改动**

- 新增 `src/myfuzz/integration/compiled_storage_producer.py`：两行封闭 selector（`gpio_causal_abi`、`generic_apb_storage_abi`）；session/issuer 类与 consumer 函数由代码命名并 import-time pin；不可变 `AdmittedStorageProducerBinding`（canonical JSON + self-hash）；`validate_storage_producer_binding`；`build_storage_producer`。
- `compiled_f4.admit_f4` 删除 GPIO/GPIOEN 硬限制，改走 selector；GPIO 行构造参数/顺序/consumer 不变；generic timer 行只在 registered source contract（重读源字节）+ D3 声明 + 生成 `storage_observation` 契约同时匹配时选中。
- `CompiledF4Runtime` 在构造 generic session/process 前明确 `compiled-F4-generic-commit-consumer-unsupported`；capability 仍 `execution_supported=0/runtime_admitted=false`（附 binding）。
- binding 进入 checker、prefix、stability/readmission/fresh 重建。

**实际测试**

- RED：旧硬限制实测拒绝 generic timer；新测试实现前 `28 failed`。
- GREEN：`tests/integration/test_compiled_f4_storage_producer.py` **29 passed**（根代理在静止树复跑 22.14s）。
- `tests/integration -k compiled_f4`：**60 passed，1 skipped**（skip 为 `MYFUZZ_COMPILED_F4_REAL` 原生门未执行）。
- `test_timer_f4_declarations.py` **5 passed**；`test_compiled_execution_files.py` **32 passed**；`tests/local_harness -k compiled` 1 passed；`tests/scenario -k f4` 1 passed。
- 负例覆盖：未知/跨协议 kind、template variant、跨协议 artifact、component 改名、register/offset/width/mask/address、source/probe/contract digest、caller factory/method、caller metadata、tampered/stale/foreign binding。

**边界**

- **D2 未做**：generic commit/raw join、before→after 版本、C opaque token、Router/APB/storage/readback 关联、`tick_base` 导出。
- **D3 未做**：timer 公开 file entry/CLI 仍拒绝执行；未更新 supplement/README。
- 未运行任何 native/远程/Verilator/构建/模型；未宣称 live token/certificate/native eligibility；无真实 timer 链通过。

## 4. 结论

三项均为**源码增量**，分别绑定自己的冻结提交。已完成的只是源码/软件控制与保存数据重放；原生/层次/复位波形、真实新 IP 端到端、D2/D3、持续搜索、六 CPU 统一验收与 P6/P7/P8 全部仍开放。不得把本报告的任何通过数读作原生门或整系统验收。
