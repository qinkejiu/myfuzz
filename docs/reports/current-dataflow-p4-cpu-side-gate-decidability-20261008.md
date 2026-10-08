# P4 CPU 侧门禁可判定化：改走 profile 路径，让运行自己声明 RVFI opcode 计数窗口

日期：2026-10-08。承接 [CPU 侧映射修复报告](current-dataflow-p4-cpu-side-branch-coverage-real-20261008.md)：那份运行 **7/8 PASS、verdict=INCONCLUSIVE（exit 4）**，唯一 FAIL 是前置判据 `cpu-stimulus`——"该运行没有声明 RVFI opcode 计数窗口"。本报告回答：**用最便宜且诚实的方式让这条门禁变成可判定的**，并给出 root 只需执行一条命令的驱动脚本。

> **诚实声明（先写在最前面）**：本报告**不主张任何新的 RTL 结果**。所有结论来自三类证据：(a) 源码阅读；(b) 对**已保存产物**的只读复算（`run_p4_cpu_side_branch_gate.py verify` 不启动 Verilator）；(c) 纯软件测试。本次任务**没有**运行任何 Verilator/RTL/fuzz 作业，新运行由 root 执行。

---

## 1. 路线选择：走 (a) profile 路径，不改 legacy 路径

两条候选路线的取舍是**用源码与已保存产物证明**的，不是偏好：

### 1.1 为什么 legacy 路径（路线 b）不是"最小改动"

| 事实 | 证据 |
|---|---|
| legacy 渲染的是 `build/soc_top.sv`，其中 `rvfi` 出现 **0** 次 | `grep -c rvfi runs/p4-cpu-side-coverage-20261008-online/build/soc_top.sv` → `0` |
| legacy 渲染器**完全没有** checker / RVFI 支持 | `grep -c "rvfi\|checker" src/myfuzz/composition/soc_renderer.py` → `0`（全文 2009 行） |
| legacy 构建文档是**另一种 schema**：嵌套 `coverage` 字典，**没有** `checker_feedback`，**没有**扁平 `branch_coverage_ports` / `coverage_ports` | `runs/p4-cpu-side-coverage-20261008-online/report.json` → `client_result.artifact_provenance` 的键为 `build_command / coverage / input_layout / rendered_files / …`，`checker_feedback` 缺省、`branch_coverage_ports` 长度 0 |
| 两条路径在 `build_soc_campaign_artifact` 里分叉 | `src/myfuzz/integration/soc_builder.py` 中 `if "composition_request" in config: return _build_profile_campaign_artifact(...)`（当前工作树第 2178 行） |

也就是说，路线 (b) 要在 legacy 侧**同时**做四件事：在 `soc_renderer.py` 里声明 12 位输出端口并实例化 `soc_ibex_rvfi_checker`（当前该文件 0 处引用）、把 CPU 的 `rvfi_valid/order/insn/trap` 接到该实例、在 legacy 分支的观测计划里新增 12 个计数器槽位并重排 128 槽配额、再把 legacy 构建文档改成能携带 `checker_feedback`/`rvfi_opcode_coverage_counter_range`（否则 `report_rtl_branch_coverage.py` 与门禁会对同一份文档的 schema 产生分歧）。这是**跨两个生产模块的行为改动**，不是"最小改动"，且与"不要改生产代码"的约束冲突。

### 1.2 profile 路径为什么天然满足前置条件

配置里只要带 `composition_request`，就进入 profile 构建路径，其中三个条件全部由**现有生产代码**满足（行号为当前工作树，见 §6 的并发提示）：

1. **composite request id 对上就加载 checker profile**：`_build_profile_campaign_artifact` 中 `if plan.request_id == CHECKER_REQUEST_ID`（`CHECKER_REQUEST_ID = "ibex-pulp-gpio-spi"`，`src/myfuzz/composition/soc_checker_profile.py:18`）。`examples/soc_generation/request-ibex-pulp-gpio-spi.json` 的 `request_id` 正是它。
2. **active bit 16 ⇒ 绑定 12 个 RVFI opcode 计数器**：`opcode_coverage_ports` 块（当前第 1633–1645 行）要求找到 `output logic [11:0] rvfi_opcode_coverage_o`，否则 `raise SocBuildError("profile-rvfi-opcode-coverage-port-invalid")`（第 1643 行）。该端口由 profile 渲染器在 `checker_profile` 存在且 `RVFI_ACTIVE_BITS = frozenset({16})`（`soc_profile_renderer.py:83`）时声明（`:404`）并接线到 `soc_ibex_rvfi_checker`（`:982–990`）。
3. **provenance 发布门禁读取的那两个键**：`checker_feedback.rvfi_opcode_coverage_counter_range = [len(branch_ports)+100, len(branch_ports)+100+12-1]`（第 2096 行）；同一文档发布 `branch_coverage_ports`（第 2071 行）与 `coverage_ports = branch + checker + opcode`（第 2144 行）。`client_result.artifact_provenance` 就是这份构建文档：`rfuzz_live.py:612–615` 读取 `build/artifact_provenance.json`；profile 路径在 `soc_builder.py:2148` 写入它。

### 1.3 已保存 profile 运行上的实测（决定性证据）

对 `runs/` 下**所有**带 profile provenance 的 `report.json` 做只读扫描：**11 个**已保存运行声明了 RVFI 窗口，**全部**是 `[228, 239]`，**全部**窗口内有非零 bin（即 CPU 确实在搜索中退休过指令）；不同时长与不同 `--seed-cycles`（160 / 200 家族）都不改变这个窗口——它是 `COUNTER_LIMIT + 2×50` 的纯函数。

其中最有代表性的一个是 `runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926`。对它做只读复算（**当前**代码树）：

```text
$ PYTHONPATH=src:. python3 scripts/run_p4_cpu_side_branch_gate.py verify \
      --run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926 --min-cpu-points 1
  [PASS] run-artifact: 128 observed points, cpu=64
  [PASS] coverage-identity: verified branch_points=18/128
  [PASS] cpu-stimulus (precondition): RVFI opcode counters [228, 239]
         maxima=[5, 0, 4, 0, 0, 0, 1, 8, 2, 0, 0, 0] (sum=20)
  [FAIL] elaboration-attested / exclusions-reported / no-dead-counters / cpu-side-observable
verdict=BLOCKED   (exit 3)
```

要看清楚这份证据的边界：

* **`cpu-stimulus` 与 `coverage-identity` 双双 PASS** —— profile 路径确实发布门禁读取的键，且窗口内有非零 bin（CPU 真的退休过指令）。这直接消除了本次唯一的 FAIL 判据；而且这不是孤例，11 个已保存 profile 运行都是同样的窗口与同样的"有非零 bin"。
* 其余 4 条 FAIL 是**修复前**的既有缺陷，与本次问题无关：该运行早于构建期 elaboration 探针（无 `elaboration` 记录），且 CPU 配额仍绑在 `u_ibex_lockstep` 影子实例上（`unelaborated-bound=64`）。**当前**代码树对同一 cell 走 legacy 路径时已经能重规划掉这些实例（`runs/p4-cpu-side-coverage-20261008-online`：`status=replanned`、696 个被拒点、128 个仍被观测、`elaborated-lit=12`）。

键位与规模实测（同一份 `report.json`）：

| 键 | 值 |
|---|---|
| `client_result.artifact_provenance.checker_feedback.rvfi_opcode_coverage_counter_range` | `[228, 239]` |
| `client_result.artifact_provenance.checker_profile_hash` | `sha256:1311a43c85b4987b0f32466a4c5f02793eccbe9c8f1720669f6cfa8647133683` |
| `client_result.artifact_provenance.branch_coverage_ports` | 长度 **128** |
| `client_result.artifact_provenance.coverage_ports` | 长度 **240**，末 12 项为 `["rvfi_opcode_coverage_o", 0..11]` |
| `client_result.coverage_maxima` | 长度 **240**（= `coverage_ports`，即 harness 按槽位发布的 240 个计数器） |

**结论：选路线 (a)。** 它零生产改动、复用现成的 `run_soc_campaign` + `build_soc_campaign_artifact`，并且能把门禁的 8 条判据**全部**变成可判定的（identity 与 RVFI 前置在原运行上已 PASS，其余 4 条由当前树的探针负责）。

---

## 2. 新驱动脚本

新增 `scripts/run_p4_cpu_side_profile_campaign.py`（**NEW** 文件，未改动任何既有脚本/生产代码）。风格对齐 `runs/current-dataflow-p4-cpu-side-20261008-logs/run_single_cell.py`：不重实现任何 campaign 逻辑，只用 shipped 的加载器/渲染器/构建器/运行器。

它做什么：

1. 用 shipped `load_profile_campaign_request` 加载 `examples/soc_generation/request-ibex-pulp-gpio-spi.json`（profile fixture）；
2. **纯软件**地复算 `soc_builder` 的三条件：`request_id == "ibex-pulp-gpio-spi"` → checker profile 中必须有 `status=="active" and bit==16` → 渲染后的 `myfuzz_soc_top.sv` 必须声明 `output logic [11:0] rvfi_opcode_coverage_o`（复用 shipped 的 `_parse_ports` 与 `checker_feedback_observations`，不是复刻判定）；
3. 由 plan 的 disposition 推导 `external_input_defaults`（构建器要求与渲染端口集合**完全相等**）；
4. 生成 campaign config（`composition_request` + `component_profiles` + `drive_profile=cpu_execute` + `mode=cpu_only` + `instruction_candidates=5`（生成候选程序与 boot image，无需外部镜像）+ `seed_cycles=160`（沿用唯一被证明会让 CPU 退休的 profile 运行参数）+ `verilator=bundled`）；
5. 写身份文档 `<output>.task.json`（在 campaign 之前写，构建失败也留下可审计的声明）；
6. 调 shipped `run_soc_campaign(..., rebuilder=build_soc_campaign_artifact)`；
7. 打印机器可读摘要，并在运行结束后**只读**复算一次门禁的 `_cpu_stimulus`，把 `rvfi_precondition` 一并打印。

参数：`--output`（必填）、`--seconds`（默认 300）、`--seed`（默认 20260926）、`--client`（默认 `runs/rfuzz_client_bounded_build/target/debug/kfuzz`）、以及 `--seed-cycles` / `--instruction-candidates` / `--check-only`。

**Fail closed**：上面三条件任一不满足，脚本在启动任何构建/客户端之前以 **exit 3** 退出，stderr 打出命名原因（`profile-checker-bit16-inactive` / `profile-rvfi-opcode-coverage-port-invalid` / `profile-checker-request-mismatch` / `profile-checker-manifest-missing`）。这正是"soc_builder 会因缺 bit 16 而不发窗口"的前置拒绝，不会变成一次白跑的编译。

---

## 3. root 要执行的命令

```bash
cd /home/qinkejiu/myfuzz

# 0) 可选：纯软件自证前置条件（不建、不编译、不启动客户端；不创建输出目录）
PYTHONPATH=src:. python3 scripts/run_p4_cpu_side_profile_campaign.py \
  --output runs/p4-cpu-side-profile-rvfi-20261008-online --check-only

# 1) 真实运行（启动 Verilator + RFuzz client；探针触发重规划时会编译两次）
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 \
  scripts/run_p4_cpu_side_profile_campaign.py \
  --output runs/p4-cpu-side-profile-rvfi-20261008-online \
  --seconds 600 --seed 20260926 \
  --client runs/rfuzz_client_bounded_build/target/debug/kfuzz

# 2) 判定（只读，不启动 RTL）
PYTHONPATH=src:. python3 scripts/run_p4_cpu_side_branch_gate.py verify \
  --run runs/p4-cpu-side-profile-rvfi-20261008-online --min-cpu-points 8

# 2b) 若 lit CPU 点不足 8，用阈值 1 仍然判定"映射问题"
PYTHONPATH=src:. python3 scripts/run_p4_cpu_side_branch_gate.py verify \
  --run runs/p4-cpu-side-profile-rvfi-20261008-online --min-cpu-points 1
```

第 1 步的脚本自身会在结束时打印 `rvfi_precondition`（对刚产出的 `report.json` 只读复算门禁的 `_cpu_stimulus`）与 `verify_command`，因此第 2 步的命令可以直接从摘要里抄。

`--check-only` 在当前树的实际输出（已执行，exit 0；此处完整照抄）：

```json
{"branch_counter_quota": 128, "checker_counter_count": 100,
 "checker_profile_hash": "sha256:1311a43c85b4987b0f32466a4c5f02793eccbe9c8f1720669f6cfa8647133683",
 "checker_property_bit": 16, "checker_property_id": "RVFI.ORDER",
 "composition_request": "examples/soc_generation/request-ibex-pulp-gpio-spi.json",
 "coverage_counter_count": 240, "coverage_maxima_length": 240,
 "keys": ["client_result.artifact_provenance.checker_feedback.rvfi_opcode_coverage_counter_range",
          "client_result.coverage_maxima",
          "client_result.artifact_provenance.coverage_ports",
          "client_result.artifact_provenance.branch_coverage_ports"],
 "mode": "check-only", "opcode_counter_count": 12,
 "opcode_coverage_port": {"direction": "output", "name": "rvfi_opcode_coverage_o", "width": 12},
 "proven_profile_run": "runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926",
 "request_id": "ibex-pulp-gpio-spi",
 "rvfi_opcode_coverage_counter_range": [228, 239],
 "schema_version": "p4_cpu_side_profile_campaign.v1"}
```

### 3.1 残留不确定性（必须说清楚）

* "profile 路径下 elaboration 探针会把 CPU 配额从 `u_ibex_lockstep` 影子实例上挪开"这一条，是**从共享代码路径 + 修复后 legacy 运行的保存计划推断**的（`_plan_observations_with_elaboration_probe` 被两条路径共用；legacy 侧实测 696 拒 / 128 观测），**尚未**在任何 profile 路径运行上直接观测到——工作区里 11 个已保存的 profile 运行**全部**早于该修复。这正是必须由 root 跑第 1 步才能闭合的那一格。
* 若探针在 profile 路径下找不到足够的合格点，构建会**fail closed**（`*-coverage-elaboration-probe-failed`），即构建失败而不是"静默发布死计数器"；这属于修复失效的 FAIL，不是"没有覆盖率"。
* 若新运行的 RVFI 窗口在一个 300/600 秒的搜索里仍然全 0，那是"CPU 在该 profile 配置下没有在搜索中退休"的**独立**问题（可用 `--seed-cycles` 上调复跑），门禁会正确地判 INCONCLUSIVE，而不是把它当成映射结论。

---

## 4. 判定标准（PASS / FAIL / BLOCKED / INCONCLUSIVE）

以 `scripts/run_p4_cpu_side_branch_gate.py verify` 的退出码为准：

| 退出码 | verdict | 含义（针对本次新运行） |
|---|---|---|
| `0` | **PASS** | 8/8 判据全过：identity 验证通过、RVFI 窗口非零、`unelaborated-bound=0`、CPU `elaborated-lit ≥ --min-cpu-points`、读回一致。**CPU 侧映射问题被判定为已解决。** |
| `1` | **FAIL** | 有判据不成立且 `unelaborated-bound==0`：例如 identity 被拒、排除记录不自洽、或 `cpu-side-observable` 未达阈值（**搜索质量不足**，不是映射问题）。 |
| `3` | **BLOCKED** | `unelaborated-bound > 0`：CPU 配额仍绑在编译模型未 elaborate 的实例上——修复对 profile 路径无效（或该运行早于修复）。 |
| `4` | **INCONCLUSIVE** | 没有编译模型，**或** `cpu-stimulus` 仍 FAIL（无 RVFI 窗口 / 窗口内全 0）：CPU 是否退休不可证，此时"CPU 分支为 0"什么也证明不了。 |
| `2` | 用法错误 | 参数问题。 |

**若运行结束时点亮的 CPU 点少于 8 个**：门禁会给出 `cpu-side-observable: FAIL`，整体 verdict=**FAIL（exit 1）**，这就是一条**搜索质量不足**的报告——它**不会**被误读成"映射修复失败"，因为 `no-dead-counters`（`unelaborated-bound=0`）与 `elaboration-attested` 仍然是 PASS。此时把阈值降为 1 再跑一次（第 2b 步）：只要 RVFI 窗口非零、`unelaborated-bound=0`、且至少 1 个 CPU 点 `elaborated-lit`，就是 **PASS**——**映射问题已被判定**，剩下的是搜索/激励质量问题。反之，若 RVFI 窗口内全 0，则 `cpu-stimulus` FAIL → **INCONCLUSIVE**，此时必须先解决"CPU 在 profile 路径下不退休"（可用 `--seed-cycles` 上调，上限 200）才能谈映射。

---

## 5. 软件自证（未运行 RTL）

新增测试 `tests/scenario/test_p4_cpu_side_profile_campaign_driver.py`（21 个用例），覆盖：

* **fixture 前置断言**：shipped checker manifest 里确有 `status=="active" and bit==16`（`RVFI.ORDER`，owner `cpu0`）；渲染后的 top 确有 12 位输出 `rvfi_opcode_coverage_o`；`checker_feedback_observations` 返回 100 个 checker 槽位；预测窗口 `[128+100, 128+100+11] = [228, 239]`、总线长 `240`。
* **窗口稳定性**：另外 3 个不同时长/不同 `--seed-cycles` 的已保存 profile 运行，窗口同样是 `[228, 239]`、`coverage_maxima` 与 `coverage_ports` 同长、窗口内非零——预测不依赖搜索长度。
* **provenance 键位钉死**：直接对已保存的 profile 运行断言门禁读取的**精确键路径** `client_result.artifact_provenance.checker_feedback.rvfi_opcode_coverage_counter_range`、`client_result.coverage_maxima`、`...coverage_ports`、`...branch_coverage_ports` 的形状与长度（240/240/128），并调用 **shipped 门禁函数 `_cpu_stimulus`** 复算得到 PASS。
* **配置一致性**：fixture 复现的 `checker_profile_hash` 与已保存运行完全一致（说明"同一个配置"）；`_normalise_config` 接受驱动生成的 config 并解析出 `cpu0`/`gpio0`/`spi0`/`cpu_only`。
* **配额重填的实证**：修复后 legacy 运行的 `build/soc_coverage_plan.json` 在拒掉 696 个点后仍是 `limit=128 / observed=128`，证明"探针重规划后仍发布 128 个分支槽位"这一预测前提。
* **参数处理与 fail-closed**：缺 `--output` → exit 2；输出目录已存在 → exit 2；`--seconds 60` → exit 2；`--check-only` 绝不调用 campaign；manifest 撤掉 bit 16 → **exit 3** 且 `run_soc_campaign` 一次都没被调用；把渲染端口改名/改窄 → **exit 3**；正常路径 → 只调用一次 shipped `run_soc_campaign`，先写 `<output>.task.json` 身份文档，并打印 `verify_command`。

聚焦测试命令与 RED/GREEN：

```bash
# RED（先写测试、驱动脚本尚不存在时）：
#   E ImportError: cannot import name 'run_p4_cpu_side_profile_campaign' from 'scripts'
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_p4_cpu_side_profile_campaign_driver.py -q

# GREEN（驱动脚本就位后）：
#   21 passed in ~16s
PYTHONPATH=src:. python3 -m pytest tests/scenario/test_p4_cpu_side_profile_campaign_driver.py -q
```

---

## 6. 风险与并发提示

* **工作树正在被并发修改。** 本任务期间（2026-10-08 01:15–01:20）观察到 `src/myfuzz/integration/soc_builder.py`、`src/myfuzz/integration/rfuzz_simulator.py`、`src/myfuzz/integration/soc_coverage.py`、`scripts/report_rtl_branch_coverage.py` 被其他 agent 改动（`soc_builder.py` 相对 HEAD 已有 310 行新增改动，行号在本报告写作过程中发生过迁移）。因此：本报告的行号引用以**当前工作树**为准，驱动脚本内部只按**符号名 + 代码片段**引用生产逻辑，不写死行号；测试会在这些符号消失或语义变化时立刻变红。
* 本次交付**未修改**任何生产文件、配置、RTL 或既有脚本；新增的只有 1 个驱动脚本、1 个测试文件、本报告。
* 本次交付**未运行**任何 Verilator/RTL/fuzz 作业；第 1.3 节的门禁输出是对**已保存产物**的只读复算。
