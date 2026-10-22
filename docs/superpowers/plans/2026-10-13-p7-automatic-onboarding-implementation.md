# P7 实现文档：已支持协议范围内自动接入与自动测试

日期：2026-10-13。上游依据：[总计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md) 的 P7 节（第 339–353 行）与[阶段状态总览](2026-10-06-current-dataflow-fuzz-implementation-plan.md) 第 164 行。本文只讲**怎么做**，不重述目标。

> **前置事实（写作时实测）：** `src/myfuzz/scenario/runner.py` 与 `router.py` **已不含按组件名分支**（`grep 'component_id ==|component_id in ('` 无命中）。P7 验收句里"新组件接入的 diff 中没有组件名硬编码进 Runner/Router/mutator"的**一半前提已成立**；P7 的真实工作量在"自动把新组件接到既有框架上"，而不是"拆掉硬编码"。

---

## 1. P7 的验收句拆成可执行的四件事

总计划 P7 验收（第 351 行）要求：**新组件接入的 diff 中没有组件名硬编码进 Runner、Router、mutator 或既有协议模板；生成入口自动得到正确的局部 harness、路径、输入约束、持续 testcase 与 checker，并在真实 RTL 上跑出双向传播、受控错误捕获及 fresh replay。故意提供缺失来源、保留位随机源或错误握手时，系统在执行前拒绝或明确降级。自动报告只对已证明的协议子集和可执行路径给出通过等级。**

拆成四个可判定的交付：

| # | 交付 | 判据 |
|---|---|---|
| **D1** | **声明核对器**：从受信 profile／源码自动核对端口、时钟/reset、协议形态、地址窗口、输入归属、IRQ 电平/脉冲、外部环境模型 | 缺信息时**不猜**，输出可定位的"声明式微调需求"，含 `code`+`pointer` |
| **D2** | **harness 生成器**：在**已验收协议子集**内选版本化模板，为 CPU 与 IP 各生成独立 harness | 生成物可编译；不支持的协议形态**在规划期拒绝**，不生成"看起来能跑"的 harness |
| **D3** | **路径/输入编译器**：从组件能力与数据流契约编译该组合**真正可走**的 F1～F6 路径、Fuzzable Source／Bound Input、字段 mask/range、前置状态、初始种子、断言集 | 每条路径**可执行或给出不支持理由**；没有真实生产者的边不得标为"已支持" |
| **D4** | **自动跑通**：一次初始化 → 逐例输入 → 按反馈变异 → 真实 Router/Scheduler 传播 → checker → 故障保存 → 完整前缀 fresh replay | 输出每条路径与组件的能力等级与不支持原因；**不以"生成成功"代替可 fuzz 的性能门槛** |

**P7 完成的最终门禁（计划原文）：** 用**一个新增的同协议 CPU** 和**一个新增 IP** 各做一次端到端，并**保留一个旧组件负例**，确认生成器没有因名称相似而错误套用模板。

---

## 2. 现状：已有什么、缺什么

### 2.1 已有的可复用起点（不要重造）

| 层 | 真实入口 | 作用 |
|---|---|---|
| 请求 | `local_harness/request.py`：`LocalHarnessRequest`（`profile_path`/`instance_id`/`reset_assert_ticks`/`reset_release_ticks`/`max_wait_cycles`）与 `LocalHarnessRequestV2`；`load_local_harness_request()` | 版本化请求与解析 |
| 规划 | `local_harness/plan.py`：`plan_local_harness(request, *, base_dir)` | **已有大量 fail-closed 拒绝**：请求类型、profile 必须位于 `configs/` 内、时钟比例、有序复位等均在生成/启动前拒绝 |
| 模板 | `local_harness/template_contracts.py`：`list_template_contracts()`、`select_template_contract(endpoint, capabilities, *, explicit…)`、`generated_executor_selection(...)`、`ProtocolTemplateContract` | 协议模板注册表与**端点→模板**选择 |
| 渲染 | `local_harness/runtime_renderer.py`：`render_local_runtime(plan, structural)` | 生成 runtime（含 `reset`/`clk` 端口与控制信号接线，如 `assign dut_p_1 = ~reset` + `.HRESETn(dut_p_1)`） |
| 构建 | `local_harness/build.py`：`_host_sources()`（AST 依赖发现）、`host_source_discovery_scope()`、`local_build_identity()` | 源码闭包与构建身份；**注意：不带 scope 时每次调用重扫源码树**（见 §6 陷阱） |
| 源锁 | `local_harness/source_lock.py`：`verify_local_source_lock(profile, *, base_dir…)` | 源码 revision/文件闭包校验 |
| 组合 | `composition/`（`interface_description.py`、`endpoint_capabilities.py`、`declarations.py`、`input_layout.py`、`generic_planner.py` 等） | 端口事实、端点能力、声明式微调、通用规划 |
| 协议插件 | `protocols/plugins/*.json`（`obi`/`axi4`/`axi4_lite`/`wishbone`/`tl_ul`/`apb3`/`apb4`/`ready_valid_memory`/`ready_valid_mmio`/`processor_memory_beat`/`pipelined_completion_memory`） | 协议规则词表 |
| 会话 | `local_harness/{native_session,cpu_session,axi4_cpu_session,axil_session,apb3_register_session,gpio_session,…}.py`、`generated_register_factory.create_generated_register_session(artifact,…)` | 独立 session |
| 场景 | `scenario/`（`contracts/dependency/ownership/router/scheduler/genome/mutation/checker/evidence/replay`） | **不按组件名分支**，可直接复用 |
| CLI | `scripts/generate_local_harness.py --request R --output O [--build-cache C]`（经 `Generate` → `plan_local_harness` → 渲染 → 构建） | 已有单组件生成入口 |

### 2.2 缺的三件（P7 的实际工作）

1. **没有"组合级"入口。** 现有 CLI 一次只生成**一个**组件 harness（`--request` 单数）。P7 需要"给我一组受信 profile → 生成 CPU＋IP 一整套独立 harness，并自动接线成可跑的跨组件场景"。
2. **路径/输入是**手写声明**而非编译产物。** 现在的 path/source/ownership 声明（`configs/scenario/`）由人针对具体组合书写；P7 要求从**组件能力＋数据流契约**编译出来，并对不可走的路径给出理由。
3. **能力等级报告是分散的。** `composition/test_capability.py`、`local_harness/*_contract.py`、report 层各自有一块；P7 要求**一个**入口输出"每条路径＋每个组件"的 `Catalog→Generated→RTL operational→Cross-component accepted→Coverage-guided searched→Bug confirmed` 等级或不支持原因。

---

## 3. 实现路线（五个阶段，每阶段可独立验收）

> **原则：先拒绝，后生成。** 计划反复强调"缺信息时给出可定位的声明式微调需求，不猜测 RTL 语义"。所以 P1 阶段的产出**不是**生成成功，而是**拒绝清单**。这与本仓库的既有风格一致（`plan_local_harness` 已有的十几条 fail-closed 拒绝即是模板）。

### 阶段 P7-A：声明核对器（对应 D1）

**目标：** 输入一组受信 profile 路径，输出**核对报告**：每个组件的端口/时钟/复位/协议形态/地址窗口/输入归属/IRQ 形态逐项 `ok` / `missing` / `conflict`，缺失项带 `code` 与 `pointer`（指向 profile 的 JSON pointer）。

**做法：**
1. 复用 `composition/interface_description.py` 与 `endpoint_capabilities.py` 已有的端口与端点事实提取，**不要**新写一个端口解析器。
2. 复用 `local_harness/source_lock.py:verify_local_source_lock` 核对源码 revision 与文件闭包。
3. 复用 `plan_local_harness` 的**既有拒绝路径**：把它的每条 `raise ValueError('…')` 收成一个**结构化拒绝码表**（`code` + 触发条件 + 修法提示），而不是让 P7 自己再判一遍。这不是重构，是给既有拒绝补 `code`/`pointer` 字段。
4. IRQ 形态必须**显式声明**（电平/脉冲、极性、是否需要 W1C、是否 sticky），不得从端口名推断——这一条已被 P7 目标第 345 行明确要求。

**退出判据：**
- 对一个**故意缺字段**的 profile，核对器给出具体 `code` 与 `pointer`，且**不**产出 harness。
- 对一个**故意把 IRQ 极性写反**的 profile，核对器给出 conflict（而不是让 RTL 跑出错误结果）。
- 核对器对**已有**的正确 profile 全部报 `ok`。

### 阶段 P7-B：组合级 harness 生成（对应 D2）

**目标：** 新增一个入口，接受一组 profile（至少一个 CPU＋一个 IP）与一个组合声明，产出**多个独立 harness** ＋ 一份**接线契约**。

**做法：**
1. 新增 `scripts/generate_local_harness_set.py`（或给现有 CLI 加 `--profiles`），内部对每个 profile 分别调用既有 `plan_local_harness` ＋ `render_local_runtime` ＋ 构建，**复用** `build.py` 的缓存与身份（注意 §6 的 discovery scope）。
2. **模板选择只走** `select_template_contract(endpoint, capabilities, explicit=…)`。若某端点匹配不到已验收模板，**拒绝并在报告里点名**"该协议形态尚未验收"，绝不回退到"相似名字的模板"——这正是"名称相似错误套用"负例要防的。
3. 接线契约要声明：谁生产、谁消费、宽度、协议窗口、事件先决条件、持久版本（与 `scenario/contracts.py` 的 `RuntimePathContract` 对齐），**不**生成总线/桥/仲裁器。

**退出判据：**
- 给定"已验收协议子集"内的一个 CPU＋一个 IP，生成物可编译，且每个 harness 的 artifact 身份（source closure + build identity）被记录。
- 给定一个**协议形态未验收**的 IP，规划期拒绝并给出理由，**不产出**任何 harness。
- 旧组件（现有 Ibex＋PULP GPIO）经新入口生成的结果与**既有手工路径**一致（回归对照）。

### 阶段 P7-C：路径与输入编译（对应 D3）

**目标：** 从组件能力＋接线契约**编译**出该组合可走的 F1～F6 路径集合、每条路径的 Fuzzable Source／Bound Input、字段 mask/range、前置状态、初始种子、断言集；对不可走的路径给出**具名理由**。

**做法：**
1. **路径编译的输入是能力而非名字：** 用 `composition/test_capability.py` 的 `ip_test_capability.v1/v2` sidecar（含 access/mask/side_effect/observation mapping）与 CPU profile 的 ISA/地址字段，**不使用**寄存器名做语义推断。
2. 逐条路径做**可达性判定**：例如 F2（IP→CPU 读）要求存在"IP 真实读响应 → CPU rdata"的接线；F5（IRQ）要求 IRQ 的生产者与消费者都真实存在且形态匹配。任一端缺失即标 `unsupported`，**不得**由 Fuzzer 随机制造该端。
3. 输入约束沿用既有 `composition/constraints.py`／`input_constraints.py`／`input_layout.py`，把 mask/range/对齐/源归属编译进 `RuntimePathContract`。
4. 输出必须是**可机读**的：一个 `compiled_paths.v1` 文档，列出每条 `path_id` 的 `status ∈ {executable, unsupported}`、`reason`、`sources`、`constraints`、`assertions`。

**退出判据：**
- 编译输出对**每条** F1～F6 路径给出 `executable` 或 `unsupported` + 理由，无第三种含糊状态。
- 对故意提供的"保留位随机源"（把只读/保留字段声明为 fuzzable），编译期拒绝并给出 pointer。
- 对故意提供的"缺失来源"（如声明 F2 但没有真实 IP 读响应端），编译期标 `unsupported` 并点名缺什么。

### 阶段 P7-D：自动跑通与分级报告（对应 D4）

**目标：** 把 P7-B/C 的产物直接接到既有多例持续会话上跑，并输出分级报告。

**做法：**
1. 复用 `scenario/` 全套与 `integration/scenario_rfuzz_live`：**一次 `begin()`**，逐例 `submit_case()`，不逐例重建 Runner（这条在 P1–P5 已验收，直接继承）。
2. 断言集来自 P7-C 的编译输出；checker 沿用既有三类分节（协议/跨组件/CPU-IP）。
3. 报告复用既有能力等级词表，**逐路径**给级：`Catalog`（仅在注册表里）→ `Generated`（能生成）→ `RTL operational`（真实局部交易）→ `Cross-component accepted`（真实跨组件传播）→ `Coverage-guided searched`（被搜索覆盖）→ `Bug confirmed`。**一级不能自动推出下一级。**
4. 性能门槛：报告必须给构建成本与"稳定后有用吞吐"（有效例/s、完整链/s），**不以"自动生成成功"代替可 fuzz 的性能证据**。可复用 `scripts/report_p5_arm_metrics.py` 的 `p5_arm_metrics.v1` 分组。

**退出判据：** 一次命令得到：生成物身份、编译路径表、逐例回执与反馈、断言结果、fresh replay 结论、逐路径/逐组件等级、不支持原因清单。

### 阶段 P7-E：端到端验收（P7 的正式门禁）

**做法（严格照计划第 349 行）：** 选**一个已有受支持协议形态、但未被 Runner/Router/mutator 以组件名分支处理的新 CPU** 与**一个新 IP**，仅用受信 profile 与允许的声明式微调完成端到端；同时**保留一个旧组件负例**确认生成器没有因名称相似而错误套用模板。

**退出判据：** 见 §5 验证命令。

---

## 4. 一个完整调用的形态（目标产物）

```bash
# 目标：一条命令完成"声明核对 → 生成 → 路径编译 → 持续搜索 → 断言 → replay → 分级报告"
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu   configs/cpus/<new_cpu>/component_profile.json \
  --ip    configs/peripherals/<new_ip>/component_profile.json \
  --compose configs/scenarios/<new_combo>.json \
  --output runs/<new_combo>-<utc>/ \
  --budget-seconds 600
```

产出（全部在 `--output` 下，均为机读）：

| 文件 | 内容 |
|---|---|
| `declaration-review.json` | D1 的逐项核对结果；缺失/冲突带 `code`+`pointer` |
| `generated/` | 每个组件一份 harness 产物 + build identity |
| `compiled_paths.v1.json` | D3 的逐路径 `executable`/`unsupported` + 理由 + sources/constraints/assertions |
| `session/` | 逐例回执、事件 trace、checker findings |
| `bundle/` | 认证前缀（用于 fresh replay） |
| `fresh-verification.json` | fresh replay 结论（`matches`/`first_difference`） |
| `capability-report.json` | 逐路径/逐组件等级 + 不支持原因 + 构建成本与吞吐 |

---

## 5. 逐阶段验证命令

```bash
# P7-A 声明核对器
PYTHONPATH=src python3 -m pytest -q tests/onboarding/test_declaration_review.py
# 负例必须成立：缺字段、IRQ 极性写反、源码 revision 不符 —— 各自给出 code+pointer 且不产出 harness

# P7-B 组合级生成
PYTHONPATH=src python3 -m pytest -q tests/onboarding/test_harness_set_generation.py
# 含"协议形态未验收 → 规划期拒绝"与"旧组件结果与手工路径一致"两条对照

# P7-C 路径/输入编译
PYTHONPATH=src python3 -m pytest -q tests/onboarding/test_path_compilation.py
# 含"保留位随机源被拒"与"缺失来源标 unsupported 且点名"两条负例

# P7-D 自动跑通（软件）
PYTHONPATH=src python3 -m pytest -q tests/onboarding/test_auto_run_flow.py

# P7-E 端到端（真实 RTL，需预算与单 worker 锁）
PYTHONPATH=src python3 scripts/auto_harness_test.py --cpu … --ip … --compose … \
  --output runs/p7-e2e-<utc>/ --budget-seconds 600
PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_compiled_artifact_admission.py \
  tests/integration/test_auto_harness_test.py \
  tests/integration/test_compiled_f4_storage_producer.py \
  tests/onboarding/test_p7_n3_forced_apb3.py \
  tests/integration/test_generated_factory_consumption.py \
  tests/local_harness/test_harness_set.py
# 当前 N1–N8 软件负例组；须与新 CPU/IP 真实 RTL 门及 CLI 拒绝证据合看
```

**注意：** 所有真实 RTL 运行必须走既有单 worker／RSS 预算与 heavy-worker 锁（`.superpowers/heavy-worker.lock`）。本仓库已因并发与超时付出过多次代价（见 `.superpowers/sdd/progress.md`）。

---

## 6. 已知陷阱（写作时实测，务必规避）

1. **`_host_sources()` 不带 `host_source_discovery_scope()` 时每次调用重扫源码树**（实测未带 scope 约 1.17 秒/次，带 scope 后第二次 0.031 秒）。P7 的生成器会大量调用它——**必须在 scope 内运行**，否则会像门禁那样把墙钟吃光。
2. **`save_*_bundle` 用 `mkdir(exist_ok=False)`**：同一输出目录二次运行会 `FileExistsError`。生成器必须把旧 `bundle/` 轮换（如 `bundle-superseded-<UTC>`）而不是复用或放宽该策略。
3. **源码闭包不要按位置切片。** 闭包行数会随启用通道增长（默认 38 → 启用后 282+），历史上出现过 `[-2:]` 式假设的隐患。
4. **`ps aux` 在本沙箱不可信**（每次 bash 调用在 `bwrap --unshare-pid` 下运行）。并发判断要用锁与产物 mtime。
5. **测试可能自改写源码**：如 `tests/scenario/test_register_reset_default_verifier.py` 会临时改写自身/探针/RTL 并在 `finally` 还原——必须**单独串行**运行。
6. **不要从寄存器名推断语义。** 本仓库反复在此踩坑（PADIN/INTSTATUS 的"读即清除"就是典型）：一切语义必须来自被钉定 RTL 原文＋sidecar 声明。

---

## 7. 边界：P7 不做什么（避免越界声称）

- **不宣称"任意同协议 RTL 即插即测"。** 自动化范围**只包括 P6 已证明可运行的协议形态与受信组件能力**。报告必须逐路径/逐组件给级并列出不支持原因。
- **不生成具体 SoC Bus/Bridge/PLIC/全局 cycle-accurate 时序。** 跨组件只交换事务、数据与事件（总计划 §"技术与边界"）。
- **功能未知的 IP 降级到 L1/L2 是允许的**（Stage2 的 L1–L3 分级），但**未知协议、缺失握手、无法确定 reset、必需输入无合法来源不得降级为可执行**。
- **不以"生成成功"代替性能门槛。** 若某组合生成通过但每秒有效例数远低于既有组合，须先定位是协议执行器还是日志瓶颈，再计入"可搜索能力"。
- **P7 依赖 P6。** 若 P6 尚未在某个协议形态上验收，该形态不得进入 P7 的自动范围——生成器应把它列为"尚未验收的协议形态"，而不是尽力尝试。

---

## 8. 建议的落地顺序与工作量提示

| 顺序 | 阶段 | 说明 |
|---|---|---|
| 1 | **P7-A 声明核对器** | 纯软件，复用既有拒绝路径补 `code`/`pointer`。收益最大：让"缺声明/错声明"在生成前就暴露。**先做这个**，因为它同时改善人和自动化的体验 |
| 2 | **P7-C 路径/输入编译** | 纯软件，复用 `RuntimePathContract` 与 sidecar 能力。可与 P7-A 并行 |
| 3 | **P7-B 组合级生成** | 需要真实编译，成本较高；须先解决 §6 的 scope 与 bundle 陷阱 |
| 4 | **P7-D 自动跑通与分级报告** | 复用 P1–P5 已验收的会话与报告设施，相对薄 |
| 5 | **P7-E 端到端验收** | 真实 RTL，按既有预算与门禁习惯执行 |

**诚实的工作量提示：** P7 的**代码量**不大（大量是复用与把既有拒绝结构化），**真正的时间成本在 P7-E**——因为"新增同协议 CPU"与"新增 IP"意味着要找到／固定真实源码、写 profile 与 sidecar、通过源码锁，这正是 P6 里**每个组合四道门禁**的同类工作。因此 P7 的可行性上限由 **P6 的已验收协议子集大小**决定：P6 覆盖越宽，P7 能自动接入的形态越多。


---

## 9. 与当前状态的衔接

- 本文件成文时，**P6 仍未验收**（五类 CPU 协议中只有 Ibex 跑通过第一步完整框架；Stage2 的 21 格矩阵全部 `pending`）。因此 **P7 现在只能先做 P7-A 与 P7-C（纯软件、不依赖新协议实例），P7-B/D 可对既有 Ibex＋PULP GPIO 组合做"与手工路径一致"的对照**，而 **P7-E 的"新增 CPU＋新增 IP"必须等 P6 在相应协议形态上验收后才能作为正式门禁**。
- 建议把 P7-A/P7-C 作为**独立可交付**先落地：它们不依赖任何新的真实 RTL，且能立刻改善"新组件声明是否完备"的反馈速度——这恰好是计划里"缺信息时给出可定位的声明式微调需求，不猜测 RTL 语义"的直接实现。

---

## 10. 实施进展（2026-10-13 追加，实测）

本节记录**已经落地**的部分与**仍然空缺**的部分，逐条给证据入口；未落地的阶段不在此处声称。

### P7-B 组合级 harness 生成（D2）——已实现

- **模块：** `src/myfuzz/local_harness/harness_set.py`（保留 `harness_set.v1`／`wiring_contract.v1`；2026-10-20 增加 route-bearing `harness_compose.v2` → `harness_set.v2`／`wiring_contract.v2`，见[静态 DMA route intent 报告](../../reports/p7-d2-d3-static-dma-route-intents-20261020.md)）。
- **入口：** `scripts/generate_local_harness_set.py --compose <声明> --output <新目录> [--build-cache C] [--skip-review] [--base-dir ROOT]`；**退出码即裁决**（0＝generated，非 0＝refused）。
- **声明形状（闭合，不猜角色）：** `harness_compose.v1` 必须显式给出 `cpu.instance_id/request/data_endpoint` 与 `devices[].device_id/instance_id/request/bus_endpoint/base/size`，并可**可选**声明 `memory[]`。缺失／多余字段都被拒（`compose-field-missing`／`compose-field-unknown`；可选字段拼错同样被拒，不被静默丢弃）；**不从目录名、文件名或 component_id 推断角色**。
- **`memory[]`（2026-10-13 追加，为 P7-C 补的接缝）：** 每行 `resource_id`＋`component_instance`＋`base`＋`size`＋**必写的 `read`/`write`/`execute`**（可选 `initialization_policy`）。三项权限**没有默认值**：没写的权限不会被"地址范围像指令区"推断出来，缺任一项即 `compose-memory-permission-missing`。`component_instance` 必须由**同一份组合声明**给出（CPU 亦为合法属主），否则 `compose-memory-owner-missing`／`compose-memory-owner-undeclared`。其余拒绝：`compose-memory-id-duplicate`、`compose-memory-empty`、`compose-memory-field-invalid`、`compose-memory-object-required`、`compose-memory-array-required`。声明后写进 `wiring_contract.json` 的 `resources[]`；未声明该段时契约里**不出现 `resources` 键**。
- **模板选择只走** `select_template_contract`：任一被声明端点匹配不到已验收模板即**整套拒绝**并点名（`protocol-shape-not-admitted`，带 instance＋endpoint＋protocol＋底层 error），**不产出任何 harness**；另有 `component-endpoint-undeclared`、`component-instance-id-mismatch`、`component-request-missing`、`harness-set-output-exists`（**永不覆盖既有目录**）。
- **不生成总线／桥／仲裁器**：wiring contract 显式声明 `delivery='transaction_level_explicit'`、`global_interconnect=false`、`cycle_accurate=false`。
- **分级不越级：** 产物 `tier='generated'`，并列出 `not_claimed=['cross_component_accepted','rtl_operational','coverage_guided_searched','bug_confirmed']`。
- **P7-A 的判决是生成的输入：** 传入 `review` 时，任何非 `ok` 组件都会阻断生成（`declaration-review-refused`）。
- **实测：** 真实 `ibex_obi_local`（`cpu.obi`／`read-write`）＋`pulp_gpio`（`target.apb3`／`full-word`）生成成功，两份 harness 与 `wiring_contract.json` 落盘；把设备端点故意写成 `gpio.pins`（非总线）时整套拒绝且**不留下任何产物**，CLI 退出码 1。测试 `tests/local_harness/test_harness_set.py`（**10 项**）＋`tests/integration/test_p7b_to_p7c_chain.py`（**6 项**，见下节）。

### P7-B → P7-C 接缝（2026-10-13 追加，RED→GREEN 已实测）

- **发现的真实缺口：** P7-B 与 P7-C 各自绿，但**串起来产出零条可执行路径**。P7-B 写出的 `wiring_contract.v1` 只有 `cpu`＋`windows`，P7-C 因此对 F1～F4 一致报 `instruction-image-resource-undeclared`、F5 `interrupt-delivery-missing`、F6 `dma-master-not-declared`，`counts.executable = 0`。**这不是缺测试，是缺产品能力。**
- **修法（未放宽任何拒绝）：** ① P7-B 的 `harness_compose.v1` 增加可选 `memory[]` 并把它写进契约的 `resources[]`；② P7-C 的 `_from_wiring_contract` 接受 `resources`（`_closed` 的可选键），并按**文档里真实存在的键**报告 `declared_sections`／`absent_sections`（初版把 `resources` 无条件算作已声明，被既有测试 `test_variant_a_…` 当场抓住后改为按实际键判定）。
- **实测（真实 profile ＋ 真实编译器，非 mock）：** 同一 `ibex_obi_local`＋`pulp_gpio` 组合，声明 `rom0`（0x10000＋0x8000，read＋execute，含 reset_vector）与 `ram0`（0x80000000＋0x10000，read＋write）后，**F1～F4 `executable`**（`sources[0].source_id='rom0.image'`、`origin_ref='wiring:wiring_contract.v1'`、`constraint_basis` 明写 read＋execute），F5／F6 仍如实 `unsupported` 并点名；含 CLI 子进程路径的端到端用例一并通过。
- **RED 守卫（防止空洞通过）：** 同一文件先断言**不声明 `memory` 时仍须 0 条可执行**、且理由须是 `instruction-image-resource-undeclared`。把 P7-B 发 `resources` 的代码临时停掉后重跑，该守卫文件的 3 个用例（含 CLI）确实变红，证明它抓得住这个缺口；恢复后 6 项全绿。另断言"取走 `execute` 权限后 `rom0` 不再成为指令镜像"，确认选择依据是**声明的权限**而不是区名。
- **明确未声称：** 仍**不生成总线／内存服务组件**，`component_instance` 只是"谁服务这个区"的声明（此处为 CPU 自身的本地指令/数据存储），**没有**新的 memory service harness；`memory` 段**不含** `deliveries`／`environment_links`，故 F5／F6 不受影响；未跑任何 RTL，`tier` 仍只到 `generated`。

### P7-C 路径与输入编译（D3）——已实现，验收进行中

- 目标与退出判据见 §3 阶段 P7-C：输出 `compiled_paths.v1`，每条 F1～F6 只有 `executable`／`unsupported` 两态且不可走者必须**点名缺什么**。**已落地**：`src/myfuzz/scenario/compiled_paths.py`＋`tests/scenario/test_compiled_paths.py`（**33 项**）＋2 个夹具；真实组合 `configs/soc/ibex-pulp.json` 编译出 F1～F4 `executable`（F5 `interrupt-producer-missing`、F6 `dma-master-not-declared` 如实 `unsupported`），并产出 `runtime_path_contract.v1`／`runtime_dependency_graph` 可直接喂既有 `PreparedRuntimePathContract`。
- **本轮（2026-10-13）追加：** 接线文档 `wiring_contract.v1` 现已支持 `resources` 段（见上节接缝），因此 **P7-B 自己生成的契约也能编译出 F1～F4**，不再只有手写 `configs/soc/ibex-pulp.json` 能走通。**仍未做：** 未接 Runner/Router/Session（P7-D 范围），未跑 RTL，`executable` 的定义仍是"每条 hop 的每个端都有声明"而非"该 hop 被观测到"。
- **2026-10-20 静态 DMA route 子切片已通过软件门：** D3 读取并验证 `wiring_contract.v2`／`path_wiring.v2` route intent、严格检查 route master 与 sidecar `transfer` endpoint、将 route/binding 摘要纳入编译 wiring identity；D2→D3 supplement merge 与 v1 regression 均通过。**这不等于 D3/P7 整体验收：** route-bearing F6 仍 `unsupported`（`dma-route-live-topology-binding-required`），没有 live Runner topology、runtime route edge、DMA transfer 或完成 IRQ/CPU 消费证明。具体范围和命令见[报告](../../reports/p7-d2-d3-static-dma-route-intents-20261020.md)。

### P7-A 声明核对器（D1）——已完成

- **模块：** `src/myfuzz/local_harness/declaration_review.py`（`declaration_review.v1`），每组件固定 **9 行**（`source`/`clock`/`reset`/`endpoint`/`interrupt`/`interrupt_entry`/`serial_peer`/`address`/`ownership`），逐行给 `ok`/`missing`/`conflict`/`unsupported` ＋ `code` ＋ **JSON pointer**；IRQ 极性/保持/清除必须显式声明，极性绝不从端口名推断。`interrupt_entry` 仍要求文档显式声明极性，因为 `CpuContract.irq_entry_polarity` 缺省值是 `active_high`。除下述 ZipCPU AXI UART RX source rule 外，其他 IRQ 目前仍只核对声明的内部一致性。文档恒 `generated: false`。
- **入口：** `scripts/review_component_declarations.py --profile P [--profile P …] [--base-dir D] [--output X.json]`；stdout 逐组件结论与未通过行的 `code at pointer`；**退出码 0＝全 ok，1＝有 refused**。测试 `tests/local_harness/test_declaration_review.py`（**17 项**）。
- **权威归属（本阶段修掉的关键缺陷）：** 初版自行合成 ABI 并把每个字段的 `disposition` 硬写成 `functional`，导致**驱动被适配端点的功能端口也被报成"未归属输入"**（`pulp_gpio` 误报 `PADDR/PSEL/PWRITE/…`）。现改为与 `plan_local_harness` **同一调用**的 `build_port_dispositions(profile.component_id, binding, …)`，并只读 `DispositionEntry`；账本自身的拒绝 token 收成 `code`＋`pointer` 码表，**未列出的 token 记 `unsupported`，绝不当作干净**。
- **另修三处核对器自身的误报**（只在核对器错时才改核对器）：合法的 `interrupt_entry`（无 protocol）被判 unsupported；向 CPU 索要 MMIO 地址块（loader 明文禁止 CPU 声明地址）；把正确声明的 **`active_high` 复位**判 unsupported——最后一条是本阶段唯一的行为放宽，依据是 `renderer.py` 的 wrapper 自声明 `reset_assertion='active_high'`、`port_rendering.py` **只对 `active_low` 取反**（`active_high` 域直连）、以及既有 `tests/local_harness/test_multiclock_runtime.py` 钉住的 `= reset_aon;`。
- **实测：** `pulp_gpio`／`zipcpu_axiluart`／`zipcpu_uart`／`ibex_obi_local`／`cva6` 全部 `ok`（每组件 9/9 行）；**全仓 38 个 profile sweep：32 ok／6 非 ok**，6 个（`opentitan_i2c`、`opentitan_rv_timer`、`opentitan_spi_device`、`opentitan_spi_host`、`opentitan_spi_host_local`、`opentitan_sysrst_ctrl`）**全部是真实问题而非误报**，本阶段**只诊断、未修改它们**。
- **明确未声称：** 未把静态声明核对等同于 CPU 收到 IRQ、接受中断或完成 ISR；`active_high` 复位仍没有本阶段新增的端到端真实门证据。

**2026-10-22 增量（ZipCPU AXI UART RX IRQ polarity source oracle）：** 对 source root `third_party/soc-zipcpu-wbuart`、revision `f43a6b83c3a70fb2ac0696a45c5545b233fb860b`、top `axiluart` 且物理 alias 为 `o_uart_rx_int` 的 `rx` 声明，核对器从 `_pinned_source_reader` 读取 `rtl/axiluart.v` 与 `rtl/ufifo.v`，验证 RX FIFO 实例连接、`o_uart_rx_int = rxf_status[0]`，并检查 `o_status` 的完整拼接使 `!will_underflow` 位于 LSB。结合 RXFIFO 参数为 1、`will_underflow` reset=1/写入清空=0，推出源电平为 active-high；声明 active-low 返回 `/interrupts/0/polarity` conflict。其他 source/revision/端口形态或源锥变化报告 unsupported。TDD 源码布局变异与组合 gap 用例在 `tests/local_harness/test_declaration_review.py` 中；最终 **19 passed**。本地真实 UART RTL 另观测到 RX IRQ 电平 `0→1→0`（[证据/边界](../../reports/p7-d1-zipcpu-irq-polarity-20261022.md)），但不含 CPU IRQ consumer/ISR；P7 D1 整体验收与 P7 仍依总计划判定。

### CPU 侧协议契约缺口——TileLink 1.0 与 AHB-Lite

- **TileLink 1.0（2026-10-13 声明切片，历史记录）：** 仓库里的真实声明是 `configs/cpus/boom/interface_description.json`：`cpu.instruction_memory` 声明 **4 个角色**（`address`/`read_data`/`request`/`response`），`cpu.data_memory` 声明 **5 个角色**（多一个 `write_data`）。新增协议插件 `src/myfuzz/protocols/plugins/tilelink.json` 与 CPU 侧 `cpu.tilelink` 两个 variant；其各自与抽象四/五角色端点逐字相等，但**不是**完整 A/B/C/D/E 契约。插件标注 `x-channel-mapping='not-declared'`，当时没有通用 RTL adapter。后文“BOOM 无 profile、不可规划、`skipped_unavailable`”仅适用于该历史快照，已被当前资产取代。现有派生 `BoomTile` profile/RTL、定向 CPU/RAM 与独立 BOOM→PULP GPIO A/D 路径，以及 generic TileLink 尚缺的关系/时序/适配字段，见[BOOM 当前适配状态](../../reports/boom-adaptation-status-20261018.md)。
- **TileLink 运行期通用事件边界（2026-10-13 判定，经 2026-10-18 复核）：** `ip_base_coverage._PROTOCOLS`／`ip_protocol_checker._REQUIRED_SIGNALS`／`campaign_report._KNOWN_PROTOCOLS` 是"协议 id → **运行期真实信号名**"闭集。当前仓库已有专用 BOOM coherent accepted-event 投影，但仅含 A/C/D/E accepted rows；没有完整逐边 valid/ready、跨通道关系、时序规则、B-probe 覆盖或 generic adapter。故旧 coherent trace 不能直接冒充完整 TileLink 或 TL-UL 通用事件。详细字段与限制见[BOOM 当前适配状态](../../reports/boom-adaptation-status-20261018.md)及 P6 清单。
- **AHB-Lite（2026-10-13 声明阶段，历史记录）：** 当时 `grep -rli ahb configs/` 为空。后续真实 CVW SystemVerilog 源码确认 CPU 边界端口：输出 `HCLK`/`HRESETn`/`HADDR`/`HWDATA`/`HWSTRB`/`HWRITE`/`HSIZE`/`HBURST`/`HPROT`/`HTRANS`/`HMASTLOCK`/`HREADY`/`HSELEXT`，输入 `HRDATAEXT`/`HREADYEXT`/`HRESPEXT`；读数据名是 `HRDATAEXT`，`src/ebu/ebu.sv` 则故意不含 `HRDATA`。当时“无 profile／无契约／`skipped_unavailable`”的结论仅指早期快照。当前 CVW 已有真实 Caliptra SHA256 CPU/IP/RAM 链和 PULP GPIO 定向会话；分别见[CPU→Caliptra 报告](../../reports/cvw-caliptra-cpu-chain-20261017.md)和[CVW 定向会话报告](../../reports/cvw-directed-session-20261018.md)。这些运行不自动授予在线搜索或 P6 整行通过。

**2026-10-14 增量（CVW／AHB-Lite 阻断点上移，当时状态）：**P7-A 之后 CVW 的运行期链路已**真正接通并有测试**——`ahb_lite_cpu` kind 实例化从属端 `src/myfuzz/protocols/rtl/ahb_lite_memory_target.sv`（不再实例化方向曾写反的 `beat_to_ahb_lite.sv`），beat 地址宽度修正为 **34**，runtime top 与真实 CVW 源码经 `run_verilator_elaboration` 一起通过。**但 A→B→C 走通不等于当时可执行**：`adrdec.Sel = Match & Supported & AccessValid & SizeValid`，六个已提交配置的 `EXT_MEM_SUPPORTED` 全为 0，`HSELEXT` 永不选通；CVW testbench 因而把 `HREADYEXT` 恒置 1。随后以 `scripts/derive_cvw_config.py` 派生并钉定开启外部存储窗口的 `config_extmem/config.vh`。这段记录保留当时问题与修复，不代表当前状态。2026-10-18 已完成 CVW 的定向 PULP GPIO 会话和 Caliptra SHA256 数据链；当前仍需按各冻结证据分别判断能力，不能把它们合并为在线 campaign 或 P6 整行通过。

**2026-10-14 增量（CVW 会话级 GREEN ＋ 家族注册）：**① 家族 **`cvw-ahb-pulp-gpio`** 已落地（`src/myfuzz/integration/cvw_pulp_online.py`，注册于 `auto_harness_test.py` 的闭集），声明全部从真实 profile／派生配置推导；实跑 `--runtime cvw-ahb-pulp-gpio` 得 **D1/D2/D3 ＋ capability report ＋ runtime_family 全 ok**、`compiled_paths {executable:4, unsupported:2}`。② 会话阶段**如实停在** `cvw-online-assembly-undeclared`，`session-refusal.json` 点名三项缺失：`boot_image`／`online_decoder`／`runner_factory`；**未启动 RTL、未伪造会话**。③ 与此同时，**会话级真实交易已经达成**（不经 RFuzz）：`GeneratedAhbMemorySession` 启动生成的 CVW harness，核心从会话内存服务取回完整 64 字节启动行并**执行会话供应的程序**（计算地址 `0xC0000100` 出现在被接受请求里）。路径上有三个缺陷被定位修复：生成物从属端 `rst_ni` 极性接反、会话 hold 形状错误（应扣 `req_ready` 而非扣响应）、从属端在 `COMPLETE` 丢掉 AHB 流水下一拍（突发隔拍丢失）。**故 D4 对 CVW 的判读是：路径 executable 且会话可启动，但 RFuzz 在线 campaign 仍未接通**——不得据 D1–D4 绿而宣称 campaign 可跑。

**2026-10-18 更新（CVW 会话装配已落地；上述“三项缺失”成为历史）：** `cvw-ahb-pulp-gpio` 的会话阶段不再以 `cvw-online-assembly-undeclared` 停止。家族现在声明并通过 CLI 实跑三件真实代码：`myfuzz.scenario.cvw_session` 的启动镜像（AHB-Lite 内存服务供应）、固定镜像指令源（按实测复位取指地址供给启动字，并经 `accept_instructions` 校验）与 runner 工厂（真实 `GeneratedAhbMemorySession`＋`GeneratedPulpGpioSession`＋`DataflowRouter`）。本机 `flock` 实测：`--runtime cvw-ahb-pulp-gpio`（无 client）exit 0、D1–D3＋capability report ok、会话 `execution_mode=directed_fixed_image`、7 笔真实 CPU→PULP GPIO APB 交付、RAM `[0x35,0x6a,1,0xa5]`、首次取指 `0xC0000000`、fresh 重跑 `matches:true`／`scope:full`，报告对 `F4:ram.image` 授予 RTL operational＋Cross-component accepted。**边界**：这是**定向固定镜像会话**，不是 RFuzz 在线 campaign（无 `OnlineCaseDecoder`、无逐例保留指令窗、无 client、无覆盖反馈）；F5/F6 仍未做。证据 `docs/reports/evidence/cvw-session-20261018/`，说明 [CVW 定向会话报告](../../reports/cvw-directed-session-20261018.md)。

**2026-10-14 历史具名 family 运行（不构成正式 P7-E 验收）：**一条命令曾从受信声明跑到 D1–D4、RFuzz 会话及 fresh replay：`PYTHONPATH=src python3 scripts/auto_harness_test.py --cpu configs/cpus/ibex_obi_local/component_profile.json --ip configs/peripherals/pulp_gpio/component_profile.json --compose configs/scenarios/ibex-pulp-dual-gpio/compose.json --output <新目录> --runtime ibex-pulp-dual-source --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --budget-seconds 60 --max-tests 200`。保存记录 `runs/p7-e2e-run2-20261014-185652`（Ibex family）与 `runs/p7-e2e-cv32-20261014-185910`（CV32E40P family）报告 `status: complete`、exit 0、七阶段 `ok`、200 条 receipts 和历史 fresh 匹配。后续独立审计发现这些具名 family invocation 没有把同一调用生成的精确 D2 对象和 typed D3 编译交给 D4，也没有证明 D4 执行 D3 的 sources、constraints、seeds、paths、assertions；因此不能按本计划 §10 计作正式 P7-E。命令行/文档陷阱修复与这些历史运行记录保留，但不改变此门禁结论。**仍未做**：CVW 的在线 campaign（缺 `boot_image`／`online_decoder`／`runner_factory` 三项）——CVW 的**会话级真实交易已单独达成**，缺的是把它接进在线 campaign 的那三段；共享在线装配是按 Ibex／CV32E40P 固件布局写的，CVW 走 `0xC0000000` 外部队列＋AHB，直接套用会造成证据来自另一颗核的假绿。

### P7-D 分级能力报告（D4）——已实现，尚未接进一次端到端调用

- **模块：** `src/myfuzz/scenario/capability_report.py`（`capability_report.v1`）＋入口 `scripts/report_capability.py`（`--compiled-paths` 必填，可选 `--harness-set`／`--session`／`--fresh-verification`／`--checker-findings`／`--unavailable`／`--output`）。测试 `tests/scenario/test_capability_report.py`（**22 passed**）。
- **等级词表逐字取权威出处**（`docs/superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md:92`）：`Catalog` → `Generated` → `RTL operational` → `Cross-component accepted` → `Coverage-guided searched` → `Bug confirmed`（输出里带 `tier_vocabulary.authority`），并显式把 `skipped_unavailable` 列为 **non-tier**（它是状态，不是级）。
- **一条级只有在自己的证据到位时才给**：每次给级都带 `evidence{artifact,fact,supports}`；**缺证据 = "not claimed" 并给理由**，与 P7-C 的 `unsupported` 用两套词表分开（`disposition ∈ {awarded, grade_not_claimed}`；P7-C 的 `code/pointer/detail/missing` 原样进 `unsupported_reasons`）。
- **相邻级不互相推出**（五对逐一断言）：`Generated` 不推出 `RTL operational`；"有 run"不推出 `Cross-component accepted`；"有覆盖数字"不推出 `Bug confirmed`。路径级与组件级**分开**评定，故组件可以到 `Generated` 而它参与的 F5 路径仍是 `unsupported`。
- **构建成本与吞吐是必填段，缺席也要具名**："生成成功"**不得**替代可 fuzz 性能证据；无会话时 `throughput.status='not_measured'` 且每个叶为 `None`＋理由＋来源，**不写 0**（0 会被读成"跑了且为 0"）。分组复用既有 `p5_arm_metrics` 的 `CHECKLIST_METRIC_GROUPS`，不新造吞吐词表。
- **实测（我在真实输入上独立复核）：** 用真实组合（`ibex_obi_local`＋`pulp_gpio`，rom0/ram0）的 `compiled_paths.v1` ＋ 真实 `harness_set.v1`：F1～F4 `executable` 各得 `['Catalog','Generated']`、**其上四级一律 not_claimed**；F5／F6 `unsupported` 只得 `['Catalog']`；`throughput.status='not_measured'`。**未声称**：本阶段自身不生成/不编译/不运行/不 replay（文档级 `not_claimed` 已写明）；未把会话的组件身份摘要与 `harness_set.artifact_digest` 对比（该限制已在文档中标明）；**尚未接进"一条命令"的端到端调用**（见 `## 4`）；P7-E 未开始。

### P7-D 自动跑通与分级报告（D4）——**已端到端跑通（2026-10-13，真实 RTL）**

- **模块与入口：** `src/myfuzz/local_harness/auto_harness_test.py` ＋ `scripts/auto_harness_test.py`（参数形状即本节 §4 的目标命令，另加 `--runtime`／`--client-binary`／`--cache-dir`／`--skip-session`）。测试 `tests/integration/test_auto_harness_test.py`（**16 passed**）。分级报告模块本身为 `capability_report.py`（`capability_report.v1`，测试 22 passed，见下）。
- **实测（真实 RTL，一条命令，退出码 0、`refusals: []`、`absences: []`）：** 组合 `configs/scenarios/ibex-pulp-dual-gpio/`、族 `ibex-pulp-dual-source`，输出 `runs/p7-e2e-dualgpio-r4/`——**§4 表列的七个产物全部产出**：`declaration-review.json`（ok）／`generated/`（tier=`generated`，3 组件）／`compiled_paths.v1.json`（`executable 4`／`unsupported 2`）／`session/`（**tests 200**、`complete 192`／`input_invalid 8`、客户端 rc 0、搜索 21.1 s）／`bundle/`／`fresh-verification.json`（**`matches: true`／`first_difference: null`／`verification_scope: full`**）／`capability-report.json`（`throughput.status='measured'`）。
- **分级无膨胀（逐项核对）：** 三组件到 `Coverage-guided searched`；**F1/F2/F3 只到 `Generated`**（会话未证明它们）；`F4` 到 `Coverage-guided searched`；**F5/F6 仅 `Catalog`**；文档 `generated: false`。
- **修掉的阻塞（真缺陷）：** `compiled_paths._layout_annotations` 原以 `(endpoint_id, role)` 去重，导致**同一 profile 的第二个实例**被判重复并拒绝整次编译（`duplicate-layout-field`）。两个已交付运行族都恰好接 `cpu`＋两个 PULP GPIO，故**任何族可满足的组合都无法编译**。已改为按实例键控，`duplicate-input-port`（真端口碰撞）保留。
- **已修（2026-10-13）：** CV32E40P 的无 bus-error 引脚 `cpu.obi` variant 已可通过 D2，`source-width-undeclared` pointer 也已按实例限定。此前把这些能力与历史在线 run 合并表述为“P7-E 三要件已达成”的结论已由后续独立审计撤回；正式状态见 §10 与 [保存工件独立审计](../../reports/p7e-cv32e40p-independent-audit-20261021.md)。

### 2026-10-13 CV32E40P historical named-family run (not formal P7-E acceptance)

- Historical run `runs/p7-e2e-cv32e40p-r5/` reports exit 0, no refusals, seven stages marked `ok`, 200 complete receipts, and a matching historical full replay. This preserves what the saved invocation reports; it does not establish that D4 consumed the same invocation's exact D2 and typed D3 objects or executed D3 sources, constraints, seeds, paths, and assertions through the live decoder, Runner, and checker. The independent audit also found current-source identity drift and did not rerun the original/fresh pair. See the [2026-10-21 saved-run audit](../../reports/p7e-cv32e40p-independent-audit-20261021.md).
  - **"未被按名分支"有据**：`runner.py`／`router.py`／`source_actions.py`／`online_case_decoder.py` 中 `cv32e40p` **零出现**；`scenario/` 内仅 4 处引用，分别是该变体的声明模块、`decode_space.py` 的文档串、源码行号注释与 `profile_path=` **参数**。
- PULP GPIO (APB3) appeared in that historical composition, but the invocation does not meet the formal same-call D2/D3-to-D4 execution requirement.
- The name-similar `cv32e20` negative exists as a source-level guard in `tests/integration/test_auto_harness_test.py::test_a_name_similar_sibling_component_is_refused_by_name`. The independent audit found no archived CLI output or negative `run-summary.json`; do not describe it as an independently witnessed negative run.
- **为达成要件①而修掉的两个真实缺口：** ①新增两个**无 bus-error 引脚**的 `cpu.obi` variant（依据：CV32E40P profile 的 `capabilities.evidence` 明写 "It has no instr_err_i/data_err_i physical pins"，且 `third_party/` 内该引脚只见于 Ibex 文档），并写明 `fail_stop` 后端错误策略；②`_layout_annotations` 原把 **CPU 中断入口**当成"环境可驱动"的输入来布局，遇到"在更宽打包端口内只绑定一个位"的真实声明（`cv32e40p` 绑 `irq_i[11]`＝`CSR_MEIX_BIT`）必然失败——现按既有权威规则（`source_actions.py:68/448`：CPU IRQ 是 bound real output，不得作为可变源）**跳过中断入口端点**。
- **明确未声称（历史 P7-E 阶段边界）：** 当时 P7-E 三项结果尚无独立复核；该限定仍适用于对应旧门。BOOM、CVW、VexiiRiscv 已不应标成“无 profile／无运行能力”或 `skipped_unavailable`：现有真实运行入口与边界分别见[BOOM 当前适配状态](../../reports/boom-adaptation-status-20261018.md)、[CVW 定向会话](../../reports/cvw-directed-session-20261018.md)及[Vexii CPU/IP/IRQ 报告](../../reports/vexiiriscv-cpu-ip-irq-20261018.md)。这不等同于三者均已完成 P7 或 P6 整行验收。

### 2026-10-20 bounded F4 D4 executor update

[CV32E40P + PULP Timer APB3 sibling gate](../../reports/p7-f4-cv32e40p-apb3-sibling-20261020.md) now exercises the registered F4 executor without a runtime-family request: four cases are certified and the complete fresh prefix matches. Its `compiled_F4_execution_binding.v1` includes the compiled path/D3 digest, per-file hashes for generated CPU and IP artifacts, OBI/error policy, candidate layout, source producer, target window, prerequisites and assertions; the runtime rebuilds it at each stability check. The APB proof scope names the selected producer row and register.

This is a bounded D4 execution slice for one registered PULP timer source and a second OBI CPU instance. It does not establish arbitrary APB3 semantics, runtime support for every D3 path, the P7-E broad onboarding gate, or overall P7 completion. Earlier dated entries below retain their historical evidence scope.

### 2026-10-20 bounded D4 DMA target admission: PULP GPIO APB3

[The D4 PULP admission report](../../reports/p7-d4-pulp-gpio-apb3-admission-20261020.md) adds one exact generated PULP GPIO target to the live DMA topology binder: adapted `gpio.bus` APB3, `target.apb3` v1 `full-word`, and write-only PADOUT offset 12. The bound credential exposes an exact route-fit lookup through the existing runtime edge index and reuses the exact prepared graph object without reconstructing a graph. Reuse checks the read-only graph/path/source caches against the saved declaration. The credential rechecks topology before each lookup and refuses post-bind provider method shadowing. The lookup does not certify an accepted transaction, target effect, or native response. The joint software gate passed 209 tests and 61 subtests. This slice does not turn F6 into an executable path, add a DMA transfer edge, establish physical Wishbone-to-APB bridging, or close P7-E.

### 2026-10-21 bounded D4 PULP native route consumption

[The native route-consumption report](../../reports/p7-d4-pulp-native-route-consumption-20261021.md) now connects the topology-bound PULP route lookup to the opt-in native DMA session. The old compile API remains compatible through a pure prepare API plus one bind/install; the native fixture binds D4 once against the same prepared graph, then checks the RAM-read and PADOUT-write routes before dispatch. The distinct transaction keys join to MemoryService read/native response and APB3 provider effect/native response; independent fresh replay matches. The `PADOUT+4` write is refused before provider/APB activity. The native gate passed 2 tests and the joint software gate passed 236 tests plus 61 subtests.

This is still a bounded single-word, transaction-level process composition. P7-C F6 remains unsupported with no new compiler DMA edge; there is no physical Wishbone-to-APB bridge, CPU DMA programming/retirement, generic F6 execution, or P7-E general onboarding result. P6/P7/P8 and the full six-CPU/four-IP objective remain open.

### 2026-10-21 bounded D4 protocol-neutral DMA route consumption

[The protocol-neutral route-consumption report](../../reports/p7-d4-protocol-neutral-dma-route-consumption-20261021.md) extracts exact D4 route matching, transaction recording, and response-key association into `DmaMasterRouteAdmission`. The same implementation now guards the PULP APB3 PADOUT native flow and ZipCPU Wishbone TXREG native flow; each keeps its own target provider and beat policy. ZipCPU uses a generated CPU artifact, linked DMA endpoint identity, live RAM matching D2/D3, and one bind of the same prepared graph per execution. The software gate passed 68 tests, PULP native passed 2 tests, and ZipCPU native passed 1 test; both protocols have equal fresh normalized comparison and in-window wrong-offset refusal evidence.

This extends D4 route consumption across two target protocols, not arbitrary APB3/Wishbone support. F6 remains unsupported, there is no physical Wishbone↔APB bridge or CPU programming/retirement claim, and P7-E plus the six-CPU/four-IP P6/P7/P8 objective remain open.

### 2026-10-22 bounded I5 supplemental run: CV32E20 + PULP Timer

[The current-source attempt-1 record](../../reports/p7-i5-candidate-20261018.md) adds five certified selected `F4:ram.image` cases, a matching full fresh replay (1,340 events / 5 records), original/fresh CPU and target process exit audits, a saved CV32E40P override refusal before harness/session startup, and a software negative-group run (231 passed, 2 skipped). The attempt strengthens the bounded I5 evidence and closes the earlier missing-original-process-return-code gap for this new run.

It does not close P7-E. The compiled-F4 prefix carries a selected-path binding, while that saved online session reports `runtime_path_status=legacy_unchecked`; the execution projection supports only F4, not the general D3 runtime-path contract. The capability report has no assertion results, and the D2 harness artifact records `binary=null`, `built=false`, and `structural_only`, so no generated D2 harness binary identity is joined to the native F4 execution. Effective cases/s and certified chains/s are both 0.0, build/RTL compile cost is absent, and the all-receipt rate alone does not meet §3's useful-throughput gate. The wrong-CPU CLI negative is an early `composition-profile-not-reviewed` config refusal; N1–N8 remain covered separately by the software regression command in §5. The former `tests/onboarding/test_p7_negative_fixtures.py` path was absent from the current tree, so §5 now names the six current test modules used for those N1–N8 groups. F5/F6 remain unsupported and the broader same-protocol onboarding gate remains open.

### 2026-10-22 selected F4 actual-session runtime contract

[Runtime-path admission report](../../reports/compiled-f4-runtime-path-admission-20261022.md): same-call selected D3 F4 graph/contract and explicit image-source/RAM binding now enter the actual session before begin, and fresh construction repeats admission. Frozen software gate: 399 passed / 48 subtests. Timer and CV32E40P+SPI native gates each certified 2/2 cases; full first/fresh prefixes match 538 and 2806 events respectively, all eight native process exits are recorded reaped/0. Both sessions report `contract_preflight` with schema24 source-bound plans. Timer and SPI independent raw-evidence audits both passed. This closes the selected-F4 session-path gap for these two runs only. D2 output-binary/process identity, build cost/useful throughput, general F1-F6 execution and P7-E remain open.

### 2026-10-22 selected F4 built executable identity

[Built-identity report](../../reports/compiled-f4-built-identity-20261022.md): two new real F4 CLI runs now associate each exact D2 artifact with validated build/output receipts, live process executable and READY hashes, distinct original/fresh PID/nonces and reaped exit0. Timer has2 certified/538events; CV32E40P+SPI has2/2806; complete prefixes and run-level build joins match, and both independent raw-evidence audits passed. Original preparation compiled both components; fresh validated cache hits, with separate observations. Structural D2 generation remains binary-null when it did not build itself. Final frozen software acceptance passed:611 tests,30 explicitly reasoned skips and53 subtests;2059 inputs unchanged, independent terminal audit passed. Only one test fixture changed after the native runs (SPI also has its own wrapper); all production/native build inputs remain identical. This is selected-F4 output identity, not arbitrary D2/D3 runtime support or formal P7-E.

### 仍然空缺（不得读作已具备）

**P7-E 正式门禁仍 OPEN。** 2026-10-13/14 的历史具名 family runs 没有把同一调用产生的 exact D2/D3 对象带入 D4 并执行编译路径来源、约束、种子、路径和断言；2026-10-22 新 selected-F4 runtime-path 切片已使两次实际 session 达到 `contract_preflight`，但只覆盖选定 F4；此前 I5 的 `legacy_unchecked` 属于旧保存运行。两组新 F4 native 证据已有 D2/build/output/process 关联，最终软件门 611 passed／30 skipped／53 subtests 及独立终态审计通过；其他路径的通用执行、完整初始化/构建成本与有效吞吐验收仍缺失。当前保存的 wrong-CPU CLI negative 是早期 `composition-profile-not-reviewed` 拒绝，不等同于 N1 相似名 artifact/admission CLI gate；N1–N8 当前仍以软件回归覆盖。P7-D 的一条命令曾在 Ibex 与 CV32E40P 两个具名 family 上产出七类报告，但不替代 P7-E 退出条件。P7-A／P7-C 的独立复核也仍需按对应计划逐项判定；P7 的可行性上限受 P6 已验收协议子集约束（见 §8 末段）。详情见[保存工件独立审计](../../reports/p7e-cv32e40p-independent-audit-20261021.md)、[当前 I5 补充记录](../../reports/p7-i5-candidate-20261018.md)和[I5 Attempt1 独立验收审计](../../reports/P7_I5_ATTEMPT1_INDEPENDENT_AUDIT_20261022.md)。

### 2026-10-17 D2/D3/D4 接缝复核与状态更正

前述 2026-10-13/14 的“一条命令端到端”结论只证明具名 runtime family 的预置装配跑通；它没有证明 D4 执行了同一调用刚生成的 D2/D3 对象，也没有证明 D3 编译的来源、约束、种子、路径和断言被实际 decoder/Runner/checker 执行。按本计划 D4/E 的定义，这些历史运行不能授予 P7 自动接入验收。

[本次严格复核](../../reports/p7-d4-bounded-artifact-execution-20261017.md)已使 CLI 加载并传递精确 D2 artifact、typed D3 和实际 ownership，且在执行前拒绝无法投影的 D3。显式 `loaded_artifacts` 子集把精确 D2 对象送入现有 CV32E40P＋双 GPIO factory：真实本地隔离门 2 passed，三个进程连续执行 8 例，fresh 全量重放 4,021 事件匹配；禁用默认 artifact 重建仍可运行。默认完整 D3 范围因两个 bound producer、一个未编译 source 及逐路径语义映射缺口而拒绝。此子集只证明 D2 对象消费，不等于无适配新 CPU/IP 的 D3 自动执行，P7-D/E 正式门仍开放。

后续[执行可行性投影](../../reports/p7-d3-execution-feasibility-20261017.md)在不改 capability-only D3 文档的前提下，把四条声明可执行路径全部标为当前运行不支持：F1 缺认证退休；F4 的 GPIOEN 编译源与固定 PADOUT 候选窗口、访问对齐语义及断言处理器不匹配。真实 GPIOEN 写仅有启动阶段来源，不能计为候选。CLI 在启动前落盘 `execution_projection.v1.json` 并拒绝无映射的 D3；本地隔离 D2-only 八例及 fresh replay 再次通过。P7-D/E 仍开放。

其后[寄存器源合同](../../reports/p7-register-source-access-20261017.md)已将 GPIOEN `+4` 精确地址、4 字节访问对齐和 4096 字节窗口对齐分离，并验证 CPU 数据端归属、目标、全字字节使能、保留位及伪读响应的候选拒绝。固定 runtime 仍只对 PADOUT `+12` 生成候选，GPIOEN `+4` 的 writer／版本／checker 执行绑定不存在，故 F4 仍不授执行等级。D2-only 真实八例与 full fresh 再次通过。

其后[精确编译寄存器 writer](../../reports/p7-d3-directed-register-writer-20261017.md)已把 D3 的 GPIOEN `+4` 变成实际 CPU 指令候选，两个不同值经真实 CV32E40P→原生 APB→读回→RAM，并各自完整 fresh 匹配；隔离真实门 8 passed／132.21 秒。writer 与目标访问现有定向观察关联，仍缺 `ip_register_version` 前置状态认证、编译断言处理器和通用路径 executor。完整 D3/D4 仍拒绝，该定向子集不授予 P7-D/E。
