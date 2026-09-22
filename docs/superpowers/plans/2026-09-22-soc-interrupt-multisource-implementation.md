# SoC 中断多源持续样本与故障注入实施计划（路线图阶段 3）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development。每个 Task 由独立子代理实施，各自只写自己的新文件；`src/myfuzz/composition/soc_interrupt_plan.py`、`soc_runtime.py` 由本阶段不修改（若必须修改，先在报告中报告缺口而不是静默改）。

**Goal:** 在同一真实 SoC 上用**多个不同 raw 样本**逐源证明 通知→claim→清除→COMPLETE，并对已准入的触发组合逐项做 source-specific latch/掩码/ID 映射负例；结构故障稳定归为组合缺陷，缺可观测轨迹时不推断闭环。

**Architecture:** 复用 `soc_interrupt_plan.py`、`soc_irq_controller.sv`、`soc_irq_edge_detect.sv`、`test_soc_interrupt_lifecycle.py`、`test_soc_multi_latch_fault.py` 与 `RunResult.observations`/`responses`。工作集中在：把单样本闭环扩展为同周期/错峰/屏蔽/复位边界四类样本，并把每源的 pending、claim ID、外设清除、COMPLETE 逐项记录进统一 `EvidencePackage`/replay。

## Global Constraints

- 不得只看 `all_sources_closed` 这类软件汇总计数：它不证明 ID↔物理源映射。逐源断言外部原因、pending、claim ID、外设清除、COMPLETE。
- 结构故障（缺 latch 位、ID 置换、掩码错误）必须是 `composition_defect`；缺可观测轨迹时 `not_assessed`，不得推断闭环。
- 跨域 CDC 与非 `machine_external` CPU 入口继续拒绝，不纳入本阶段。
- 保留脏工作树。先写失败测试、观察失败、实现、真实 RTL 验证、再更新报告。

## 已确认的真实证据边界（不要重复宣称）

2026-09-21 报告已记录：双 GPIO 同周期、UART+GPIO、SPI+GPIO 的异构单样本闭环；edge+level latch 位缺失注入归为组合缺陷；**错开事件的真实运行未闭环**；`all_sources_closed` 可能仅因完成次数达到 2 而为 1，本身不证明 ID 映射。

---

## Task 1：多样本 IRQ 矩阵（同周期、错峰、屏蔽、复位边界）

**Files：** 新建 `tests/integration/test_soc_irq_sample_matrix.py`。

- [ ] **Step 1.1 冻结准入。** 以 `test_soc_interrupt_lifecycle.py` 的真实双源 SoC 为基准，明确本 Task 覆盖：同周期两个源、错峰两个源（间隔 > 1 拍）、屏蔽期间到达（被屏蔽源不得被 claim）、复位边界（复位期间到达的事件在释放后如何表现）。每个组合一个**不同的 raw 样本**。
- [ ] **Step 1.2 失败测试。** 对每个样本逐源断言（不是汇总计数）：
  - 外部原因：该源的外部事件在 `RunResult.observations`/`peer_applied` 里有对应记录；
  - pending：控制器该源的 pending 位在 claim 前为 1；
  - claim ID：CPU 读到的 claim ID 等于该源的声明 ID；
  - 外设清除：profile 声明的清除动作确实清了该源的状态寄存器；
  - COMPLETE：CPU 写入 COMPLETE 后该源 pending 归零。
  先观察哪些组合当前失败，**如实记录**。
- [ ] **Step 1.3 实现/补缺。** 只允许补测试；若某组合需要源码改动才能闭环，在报告中报告而不是改源码。
- [ ] **Step 1.4 真实 RTL 跑绿**（`MYFUZZ_SOC_REAL=1`，无 skip）。

**边界：** 错峰事件若当前确实不闭环，必须记为未达成并给出具名原因，不得用汇总计数粉饰。

---

## Task 2：逐触发组合的 latch/掩码/ID 负例

**Files：** 新建 `tests/integration/test_soc_irq_trigger_negatives.py`。

- [ ] **Step 2.1 冻结准入组合。** `pulse`、`rising_edge`、`falling_edge`、`both_edges` 与 level，逐项列出已准入者。
- [ ] **Step 2.2 失败测试（每个组合 × 每类负例）：**
  - **source-specific latch 注入**：删/固定某一个源对应的 latch 位 → 该源必须不闭环，另一源不受影响；整体必须分类为 `composition_defect`。
  - **掩码注入**：错误掩码 → 被屏蔽源不得被 claim；未被屏蔽源仍闭环。
  - **ID 映射置换**：交换两个源的 ID 映射 → 独立结构审计必须拒绝，或运行必须显示 claim ID 与物理源不符；不得只靠 `all_sources_closed`。
- [ ] **Step 2.3 缺可观测轨迹时的行为。** 构造一个故意缺轨迹的样本，断言 `not_assessed` 而非 `pass`。
- [ ] **Step 2.4 真实 RTL 跑绿。**

---

## Task 3：多样本 IRQ 记录进入统一 EvidencePackage 与 replay

**Files：** 新建 `tests/integration/test_soc_irq_evidence_package.py`。

- [ ] **Step 3.1 失败测试。** 把 Task 1 的多个样本打包进**一个** `EvidencePackage`（与 RFuzz 输入同一入口），断言：
  - 每个样本的 raw、施加轨迹、逐源 IRQ 记录、per-source claim/clear/COMPLETE 都在包里且带身份（plan/layout/policy/build/source/tool）；
  - `replay_package` 逐字段比对成功（agreement）；
  - 篡改任一源的 claim ID 或删掉一个源的记录 → replay 必须 `REPLAY_REFUSED` 或报出不匹配字段。
- [ ] **Step 3.2 缩减反例保持失败性质。** 用现有 `minimize_sample` 缩减一个失败样本，断言缩减后仍保持导致失败的 source ID、事件先后与已接受事务。
- [ ] **Step 3.3 跑绿。**

---

## 验证命令

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_irq_sample_matrix \
  tests.integration.test_soc_irq_trigger_negatives \
  tests.integration.test_soc_irq_evidence_package \
  tests.integration.test_soc_interrupt_lifecycle tests.integration.test_soc_multi_latch_fault \
  tests.integration.test_soc_irq_edge_lifecycle
MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_irq_sample_matrix tests.integration.test_soc_irq_trigger_negatives \
  tests.integration.test_soc_interrupt_lifecycle tests.integration.test_soc_multi_latch_fault
git diff --check
```

## 验收

CPU 真实执行的多样本证据能逐源证明 通知→claim→清除→COMPLETE；混合触发负例能定位连接/控制器问题而不误报外设内部 bug。

## 环境记录

- 项目 Verilator：`/home/qinkejiu/.local/bin/verilator` 5.051（sha256 `fb2cc573…fcdf`）。
- Icarus：`/home/qinkejiu/.local/bin/iverilog` 14.0（sha256 `9b3f0a69…be6a`）。
