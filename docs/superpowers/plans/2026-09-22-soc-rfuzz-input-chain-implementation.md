# SoC RFuzz 输入两段闭环实施计划（路线图阶段 1）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用同一 raw 语料在真实 RTL 上证明“raw → 合法候选 → 真实 CPU/peer 行为 → 可重放记录”两段闭环，并给出三臂（`direct_input`、`constrained_baseline`、`dependency_repair`）的同语料度量。

**Architecture:** 不重写变异器和投影器，只在既有 `soc_stimulus.v1 → build_image_plan → combined_input_layout → ProfileCampaignProjector → build_profile_runtime → run_sample → EvidencePackage/replay_package` 主链上补“逐字段冻结 + 逐字段 A/B + 三臂同语料度量 + 真实负例”。路线图阶段 1 的“真实 RTL”门槛走 `soc_runtime`（项目 Verilator），**不走** `soc_builder.build_soc_campaign_artifact`：后者被 `validate_rfuzz_verilator_version` 钉在 bundled RFuzz Verilator 5.020 上，而路线图 Global Constraints 明确“官方 RFuzz 客户端和固定 Verilator 版本是官方 campaign 验收的环境条件，不是开发、测试 RFuzz 输入生成/投影/驱动链的先决条件”。三臂的 campaign 级 `soc_comparison` 报告仍属阶段 4。

**Tech Stack:** Python 3 `unittest`、现有 `RuntimeBuild`/`RunResult`/`EvidencePackage`/`replay_package`、项目 Verilator（本机 5.051）、`soc_candidate_program` 修复器。

## Global Constraints

- 从现有生产代码和回归出发。不新增按 CPU/外设型号选择的分支。
- 每个输入保留 raw、投影、实际施加值、规则/布局/源码/工具身份和拒绝原因；变异测试与重放使用同一版本的规则。
- 修复器只能修改尚未提交的环境输入、候选指令/初始镜像及合法事件计划；不得改写 CPU 已发出的请求、DUT 响应或 IRQ 输出。
- peer 的期望不得仅从被测外设或 peer 自己的成功计数推导；未观测性质写成 `not_assessed`，不写成通过。
- 保留脏工作树中的既有改动。先写失败测试、观察失败、实现、定向真实 RTL 验证、再更新能力矩阵。
- 不用“单元测试通过”外推所有组件行为；BFM isolated/contention 与 CPU 执行模式分别统计，不把 BFM 请求计作 CPU 覆盖。

---

## 冻结的 raw ABI（本阶段观察字段的唯一事实来源）

一个 RFuzz record 是 `RuntimeSample.raw: tuple[int, ...]`，每个 int 是一个**周期值**，位宽 = `build.raw_width`。字段偏移一律取自 `combined_input_layout(plan, image)` 的 `field.raw_lo/raw_hi`，不硬编码。已实测的四类组合：

| 组合 | drive profile | raw_width | 依赖段 owner | peer 段 |
| --- | --- | --- | --- | --- |
| `request-ibex.json` | `cpu_execute` | 141 | `soc_image`（`init_*`，`data_*`） | 无 |
| `request-ibex.json` | `cpu_execute` + 3 instruction / 1 data 候选 | 279 | `soc_image`（`init0_*`、`init1_*`、`init2_*`、`data_*`） | 无 |
| `request.json` / `request-peers.json` | `cpu_execute` | 145 / 179 | `soc_image` | `soc_peer`（`uart.tx_byte`、`spi.arm_byte`、`gpio.drive`） |
| `request.json` | `bfm_isolated` / `contention` | 369 | `soc_stimulus`（`stim_offer`、`stim_target_selector`、`stim_offset`、`stim_write`、`stim_wdata`、`stim_be`）+ `soc_image` | 无 |

冻结的字段角色（`role`）与消费语义：

- **instruction 候选（`soc_image`）**：`<prefix>_offer`（1，valid）、`<prefix>_address`（32，address）、`<prefix>_data`（32，data）、`<prefix>_be`（4，byte_enable）；`prefix ∈ {init, init1, init2, …}` 为指令候选，`{data, data1, …}` 为数据候选。`init*` 的地址必须 4 字节对齐且 `be==0xF`，否则 `profile-image-full-aligned-instruction-required`。
- **MMIO 候选（`soc_stimulus`，仅 synthetic master）**：`stim_offer`、`stim_target_selector`（enum）、`stim_offset`（address/offset，按 `address_strategy` 解释）、`stim_write`、`stim_wdata`、`stim_be`。非法选择子 → `invalid_target_selector`，未映射地址 → `unmapped_address`，不可达 source → `unsupported_source`，不支持操作 → `unsupported_operation`；四者都**不重写**成合法请求。
- **peer 事件（`soc_peer`）**：`<instance>__<signal>`，`signal.source ∈ {pulse, level}`；pulse 事件之间必须 ≥ slot 的 `minimum_gap_cycles`，违反 → `PeerRawReplayError` 转成 `SocBuildError`。
- **profile special input**：`owner` 为具体 instance（如 `gpio0::pin_mode_i`），由 `compile_input_constraints` 生成的策略投影，投影只作用于 environment-owned 位。

---

## 执行结果（2026-09-22 复核）

**阶段 1 已完成。** 六个新测试模块共 181 个用例；纯测试 288 个通过、66 个按依赖跳过，`MYFUZZ_SOC_REAL=1` 全量真实套件 0 跳过通过；`git diff --check` 干净。

| 交付物 | 用例数 | 纯/真实 |
| --- | --- | --- |
| `tests/integration/test_soc_input_arms_projection.py` | 39 | 纯 |
| `tests/integration/test_soc_input_transport_ab.py` | 22 | 9 纯 + 13 真实 |
| `tests/integration/test_soc_input_chain_report.py` | 39 | 33 纯 + 6 真实 |
| `tests/integration/test_soc_input_real_rtl_gate.py` | 28 | 12 纯 + 16 真实 |
| `tests/integration/test_soc_input_stale_identity_refusals.py` | 31 | 27 纯 + 4 真实 |
| `tests/integration/test_soc_input_event_refusals.py` | 20 | 19 纯 + 1 真实 |
| `src/myfuzz/composition/soc_input_chain_report.py` | 纯聚合模块 | — |

**顺带修复的源码缺陷（都是本轮真实运行暴露的，不是重构）：**

1. `SocRawProjector` 缺 `project_records`，三臂在记录级走了两条不同代码路径。
2. 图像叠加的样本缓冲按 slot 数而非周期数分配，越界写破坏叠加状态。
3. `rst_ni` 释放被错误地放进 image-plan 分支：所有非 image-plan 构建永久停在复位。
4. 对端激励端口同时有初值和连续赋值，Verilator 直接 `CONTASSINIT` 拒绝——所有对端组合此前**根本无法编译**（真实对端套件 50 个用例此前 6 个 setUpClass 报错，现已全绿）。
5. `build_profile_runtime` 未清理旧的 `obj_dir/myfuzz_profile_sim`，编译失败会被误判为成功并运行陈旧二进制。
6. `RuntimeBuild.document()` 只记可执行文件 basename，重建路径永远不存在，`runs/` 构建缓存实际全部失效（每次静默重编）。
7. 声明式候选程序用 `image.raw_width`（145）约束记录宽度，而组合 ABI 是对端场景下的 179/403 位，任何带对端字段的合法记录都被拒绝——声明式程序与对端 raw ABI 此前互斥。
8. 重放逐字段比对未覆盖 `image_placements`/`image_errors`：两次运行可以放置不同镜像却比较相等。

**诚实的边界（不写成通过）：**

- 官方 RFuzz campaign 仍未验收：`soc_builder.build_soc_campaign_artifact` 被 bundled RFuzz Verilator 5.020 钉住，本机缺失，`test_soc_profile_rfuzz_build`/`test_soc_campaign_arms` 的 profile-build 用例按设计 skip；留给阶段 4。
- 三臂报告的 seeded 语料每条都是同一个 `addi x0,x0,0`，因此该语料**在构造上**无法让两条记录产生不同的 CPU 事务；报告如实记录 `cpu-coverage-gap`，真实写入 A/B 由 `test_soc_input_transport_ab` 与 `test_soc_input_real_rtl_gate` 用真实候选直接测量。已回退为此临时加在共享语料生成器上的 per-slot 字支持，避免为一个不需要的调用方改动共享契约。
- `soc_peer_oracle.v1` 的 `uart-tx-sent-count` 期望取自 peer 事件计划，对 raw 驱动的帧会报 `mismatch`（实际寄存器读回证明字节到达）；该限制已被三个模块如实断言，修它属于阶段 2 的独立判据工作。
- 声明式程序通道无法把 `target_policy="strict"` 的跳转拒绝暴露到 arm 级：参考 ISA 层会先把手写 JAL/BRANCH 修正掉再交给分析器；该顺序已被测试钉住，跳转拒绝仍由 `tests/composition/test_soc_input_repair.py` 的 directed 通道覆盖。
- BFM/contention 的真实运行在本阶段未做（BFM 覆盖只用真实 BFM 计划的布局与投影器在纯夹具上验证）；真实 BFM 套件 `test_soc_bfm_modes` 本身通过。

---

## Task A：三臂逐字段投影与修复验证

**Files：** 新建 `tests/integration/test_soc_input_arms_projection.py`；复用 `tests/composition/soc_generation_fixture.py`；只读 `src/myfuzz/integration/soc_builder.py`、`src/myfuzz/composition/soc_candidate_program.py`、`src/myfuzz/composition/input_constraints.py`。

**Interfaces：** 用真实 `CompositionPlan` 构造三臂：`build_projection_arms(layout=..., constraint_hash=..., special_width=..., policy=..., image=..., candidate_program=...)`。测试用 `projector.project_records(values)` 拿投影后的周期序列，用 `projector.repair_counts` / `projector.last_repaired_test` / `projector.last_peer_events` 拿修复与事件记录。

- [ ] **Step A1：写失败测试（逐字段 A/B + 拒绝）**。对 `request.json`（`cpu_execute` + `bfm_isolated` 两种 drive profile）和 `request-peers.json` 的真实计划，逐类断言：
  - `direct_input` 是恒等投影：`project_records([w]) == [w]`，且不读策略。
  - `constrained_baseline` 只投影 `<special_width` 的 environment 位；一位之差的 raw 只在被约束字段的 **projected** 值上不同，`raw` 本身保持记录。
  - `dependency_repair` 对每个候选段：只改 `offer/address/data/be` 中一个字段 → 投影结果只在对应位段变化；`last_repaired_test.placements` 出现该 slot；`repair_counts` 对应计数器 +1。
  - 拒绝路径逐条命名：非 4 对齐或 `be != 0xF` 的 `init_*_offer`、`data_offer` 开启但地址越界、两个 `init*_offer` 同时开启、`candidate-repairer-already-committed` 的重复 slot。
- [ ] **Step A2：跑红**。`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_input_arms_projection`；预期新模块 import/断言失败。
- [ ] **Step A3：补缺失案例（只补测试与最小缺口）**。若某类字段当前没有任何投影/记录（例如某 role 未被 `_Analyze` 记录），先在模块里补**最小**实现并在测试注释里写明依据；不得为测试方便改生成器分支或放宽拒绝。
- [ ] **Step A4：跑绿**。同命令；并且 `tests.integration.test_soc_profile_rfuzz_build.ProfileAdmissionTest`（不依赖 bundled 工具的部分）保持通过。

**覆盖判据：** ISA 编码、指令/数据候选、基址加偏移、寄存器定义-使用、分支目标、MMIO 权限、peer pulse 间隔、特殊端口时序——每一项都有“合法值改变投影结果”和“非法值得到具名拒绝”两个方向。

---

## Task B：传输/实际驱动段 A/B

**Files：** 新建 `tests/integration/test_soc_input_transport_ab.py`；只读 `src/myfuzz/composition/soc_runtime.py`、`src/myfuzz/composition/soc_failure_evidence.py`。

**Interfaces：** 用 `build_profile_runtime` 编译一次真实 SoC（`request-ibex.json` 与 `request-peers.json`），对同一 build 运行 A/B 两个 `RuntimeSample`，比较：

- `RunResult.requests`（CPU 实际总线事务：`cycle/addr/write/wdata/be/source`）
- `RunResult.peer_applied`（peer 实际被施加的周期/实例/slot/值）
- `RunResult.peer_wire_trace` / `peer_wire_status`
- `RunResult.applied`（逐周期实际施加的 raw 值）
- `RunResult.observations` 与 `EvidencePackage` replay

**A/B 对：** 只改一个合法 raw 字段（`init_data`、`init_address`、`data_value`、`data_address`、`stim_wdata`、`stim_offset`、`stim_write`、`stim_target_selector`、peer `*_data_i`、peer `*_valid_i`、`gpio0__pin_mode_i`），断言契约要求的那个可观测量发生变化，其余保持不变。

- [ ] **Step B1：写失败测试**。至少包含：`init_data` 改变 → CPU 读到的指令/CPU 发出的请求变化；`data_value` 改变 → CPU 从 RAM 读回的值变化；`stim_wdata` 改变 → DUT 收到不同的写数据；peer `uart.tx_byte`/`spi.arm_byte` 数据位改变 → peer 侧的 `rx_data_o`/`rx_count_o` 观测变化；peer `gpio.drive` 值改变 → `pin_value_o`/`contention_o` 变化；`gpio0__pin_mode_i` 改变 → 该实例的观测变化。
- [ ] **Step B2：写“被拒绝的字段没有悄悄退回 raw 直驱”的负例**：对投影会拒绝的 raw 值，断言 `projector.project_records` 抛出具名错误，且**没有**任何 `RunResult` 产生（即拒绝发生在驱动之前）。用 `unittest.mock` 记录 `run_sample` 未被调用。
- [ ] **Step B3：跑红** → 补最小实现 → **跑绿**：`python3 -m unittest -q tests.integration.test_soc_input_transport_ab`（纯投影部分）+ `MYFUZZ_SOC_REAL=1` 真实运行。
- [ ] **Step B4：断言身份不变**：同一 build、同一 executable、同一 layout hash 贯穿两个 A/B 样本；`recorded_build_identity` 与 `EvidencePackage.identity` 一致。

---

## Task C：重放与三臂同语料度量

**Files：** 新建 `src/myfuzz/composition/soc_input_chain_report.py`（只做汇总，不做投影）；新建 `tests/integration/test_soc_input_chain_report.py`；扩展 `tests/integration/test_soc_dependency_replay.py`。

**Interfaces：**

```python
def arm_metrics(arm: str, outcomes: Sequence[Mapping[str, object]]) -> dict[str, object]: ...
def build_chain_report(*, plan, build, arms, corpus, evidence) -> dict[str, object]: ...
```

`outcomes` 的每一项由一次真实 `project_records` + `run_sample` 得到，字段固定为：
`{"index", "arm", "status", "reason", "raw", "applied", "projected", "repairs", "counters", "cpu_requests", "cpu_writes", "peer_applied", "coverage_bits", "execution_mode"}`。

- [ ] **Step C1：写失败测试**。断言报告包含三臂的：有效输入率（`status == "executed"` 占比）、修复率（每个 `repairs[*].kind` 计数 / 有效输入）、拒绝率（按具名 reason 分组）、唯一投影输入数（对 `projected` 去重的 sha256 计数）、CPU 覆盖（`cpu_requests` 非空、`cpu_writes` 非空、触及的地址集合）、peer 覆盖（`peer_applied` 非空）。断言三臂使用**同一输入集**（`shared_corpus_hash` 相同）和**同一可执行产物**（`executable_sha256` 相同）。
- [ ] **Step C2：写失败测试（BFM 与 CPU 分离）**。`execution_mode` 为 `bfm_isolated`/`contention` 的样本，其 `cpu_requests` 必须为空且**不计入** CPU 覆盖；`cpu_execute` 的样本必须至少有一条 CPU 请求才计入 CPU 覆盖。`bfm_request_count` 与 `cpu_request_count` 分别统计，报告里不得相加。
- [ ] **Step C3：写失败测试（逐字段重放比对）**。`build_chain_report` 的每个 outcome 保存 `layout_hash`/`policy_hash`/`image_hash`/`source_closure_hash`/`executable_sha256`/`raw`/`applied`；重放时逐字段比对 `applied`，任何一位不同都要在报告里定位到 `(index, cycle, field_role, bit)`。复用 `replay_package` 的字段定位，不改它。
- [ ] **Step C4：跑红 → 实现 `soc_input_chain_report.py` → 跑绿**：`python3 -m unittest -q tests.integration.test_soc_input_chain_report tests.integration.test_soc_dependency_replay`。
- [ ] **Step C5：真实三臂同语料运行**（`MYFUZZ_SOC_REAL=1`）。用与 `soc_comparison.build_seed_corpus` 相同的确定性语料生成方式（同一 seed、同一 entries），把三臂各自的 outcome 汇总成报告，并把报告写入 `runs/soc-input-chain/<plan-prefix>/report.json`。**不重新运行三次独立搜索**，只做同一语料的三次投影+驱动。

**边界：** 本任务的度量是 seeded 语料的机制度量；官方 corpus 的三臂重放留给阶段 4，报告必须写明 `execution_mode: seeded-corpus-real-rtl`。

---

## Task D：真实 RTL 门槛与稳定拒绝负例

**Files：** 扩展 `tests/integration/test_soc_input_transport_ab.py`（真实部分）与 `tests/integration/test_soc_dependency_replay.py`；只读 `src/myfuzz/composition/soc_runtime.py`、`src/myfuzz/integration/soc_builder.py`。

- [ ] **Step D1：CPU 执行真实样本**。至少一组 `cpu_execute` 样本显示不同 instruction 候选与不同 data 候选**改变 CPU 实际请求**（`RunResult.requests` 的地址或数据集合不同），并有 `EvidencePackage` + `replay_package` 的 agreement。
- [ ] **Step D2：peer raw 事件改变真实外设行为**。至少一组 peer 样本显示改一个 peer raw 字段改变外设的真实可观测行为（读回寄存器值或 peer 侧观测计数），且该期望**不来自 peer 自身计数**：期望由独立判据（`soc_peer_oracle.v1` 的 `check_id`）给出，peer 计数只作为被观测对象。
- [ ] **Step D3：四类负例稳定拒绝**（每个都断言具名 reason，且拒绝在驱动/执行之前）：
  1. **过期 layout/规则**：旧 `layout_hash` 或旧 `plan_hash` 的策略 → `policy-layout-mismatch` / `policy-plan-mismatch`；旧 layout 的证据包 replay → `REPLAY_REFUSED`。
  2. **越界地址**：`*_address` 指向可执行窗口之外且无法投影 → `candidate-target-outside-executable-region` 或 `profile-image-*` 具名拒绝。
  3. **pulse 间隔冲突**：两个 peer pulse 事件小于 `minimum_gap_cycles` → `SocBuildError` 携带原始 `PeerRawReplayError` 名称。
  4. **试图覆盖已提交输入**：同一 slot 在一个 test 内被第二次 offer → `repair-would-rewrite-committed-word`；已发出的 CPU 请求/DUT 响应在任何负例中都不被修改（比较负例前后的 saved `RunResult.requests`）。
- [ ] **Step D4：跑绿**：`MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_input_transport_ab tests.integration.test_soc_input_chain_report tests.integration.test_soc_dependency_replay`，并确认既有 `test_soc_input_repair_runtime`、`test_soc_peer_models`（真实部分）继续通过。

---

## 验证命令

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_input_arms_projection \
  tests.integration.test_soc_input_chain_report \
  tests.integration.test_soc_dependency_replay
MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_input_transport_ab \
  tests.integration.test_soc_input_repair_runtime \
  tests.integration.test_soc_dependency_replay
git diff --check
```

## 验收

有真实 RTL 证据证明“raw → 合法候选 → 真实 CPU/peer 行为 → 可重放记录”，并能逐项证明无效位如何被修复或具名拒绝；三臂在同一输入集、同一可执行产物上给出有效率、修复率、拒绝率、唯一投影输入数与 CPU/peer 覆盖，且 BFM 与 CPU 覆盖分开统计。

**通过本阶段不等于完成官方 RFuzz 搜索**：`soc_builder.build_soc_campaign_artifact` 仍被 bundled RFuzz Verilator 5.020 钉住，`test_soc_profile_rfuzz_build`/`test_soc_campaign_arms` 的 profile-build 用例在本机保持 skip，官方单臂 campaign 与官方语料三臂重放留给阶段 4。

## 环境记录

- 项目 Verilator：`/home/qinkejiu/.local/bin/verilator`，`Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67`，sha256 `fb2cc573b1055cf096c90e1efc9966fe56bdb4b265c83590cf2a49f7a0defcdf`。
- Icarus：`/home/qinkejiu/.local/bin/iverilog`，`Icarus Verilog version 14.0 (devel) (f493076)`，sha256 `9b3f0a6942cf5065b4f6a95f49d2d9369f126e14f4ed55c7ace3f9f8de0dbe6a`。
- bundled RFuzz Verilator 5.020：缺失（`third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator` 不存在）。这阻塞的是阶段 4 的官方 campaign 验收，不阻塞本阶段。
