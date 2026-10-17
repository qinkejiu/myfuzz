# CVW 定向会话（D4）实测：`cvw-ahb-pulp-gpio` 会话装配落地

日期：2026-10-18。范围：`/home/qinkejiu/myfuzz` 当前工作树（HEAD `ade3fe6` ＋本任务源码改动），本机真实 RTL。上游依据：[P6 逐协议行清单](../../superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md) §CVW、[P7 自动 onboarding 计划](../../superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md)。证据目录：`docs/reports/evidence/cvw-session-20261018/`。

## 1. 结论

CVW 家族的会话阶段**不再**停在 `cvw-online-assembly-undeclared`。三件被点名的缺失现在都是真实代码，并由 CLI 的 directed session 阶段实跑：

| 缺失项 | 现在的真实组件 |
|---|---|
| `boot_image` | `myfuzz.scenario.cvw_session.make_cvw_boot_image`：派生自 `cvw_pulp_gpio_wiring` 的 RV32 启动镜像（256 B／64 words，base `0xC0000000`，result `0xC0000400`），经 AHB-Lite 内存服务供应，SHA-256 `8444b6abf7450558…` |
| `online_decoder`（指令源） | `CvwBootInstructionSource`：观察**实测** AHB 请求地址（生成驱动的 pre-phase `m_req_addr`），启动字经 `accept_instructions`（字节级 ISA 校验）供给，镜像其余字节按声明初始镜像供给；**不是** RFuzz `OnlineCaseDecoder` |
| `runner_factory` | `make_cvw_gpio_session_factory`：渲染/消费 D2 生成的 CVW `ahb_lite_cpu` 与 PULP `apb_gpio` harness，构造真实 `GeneratedAhbMemorySession`＋`GeneratedPulpGpioSession`＋`DataflowRouter` 的 `ScenarioRunner` |

CLI 实跑（`flock` 单 worker，`setsid`，真实 Verilator RTL）：

```text
PYTHONPATH=src setsid python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cvw/component_profile.json \
  --ip configs/peripherals/pulp_gpio/component_profile.json \
  --compose configs/scenarios/cvw-pulp-gpio/compose.json \
  --output docs/reports/evidence/cvw-session-20261018/run \
  --runtime cvw-ahb-pulp-gpio \
  --cache-dir .superpowers/cache/cvw-session-gate \
  --budget-seconds 600 --label cvw-session-gate-20261018
```

实测：**exit 0，wall 69 s**，`status: complete`，`refusals: []`；D1 `declaration_review`、D2 `harness_set`、D3 `path_compilation`、`execution_projection`、`session`、`fresh_verification`、`capability_report` 全 `ok`。

## 2. 会话实测（`run/session/`）

| 观测量 | 实测值 | 来源 |
|---|---|---|
| `execution_mode` | `directed_fixed_image` | `report.json` |
| `tests`／`statuses` | `1`／`{"complete":1}` | `report.json` |
| CPU 步数 | **172** | `report.json:evidence.cpu_steps` |
| 本地 tick（receipt） | CPU 172／GPIO 201，合计 373 | `receipts.jsonl` |
| 被接受 AHB beat | **43** | `report.json:evidence.accepted_beat_count` |
| 真实 CPU→IP 交付 | **7**（APB） | `report.json:evidence.delivery_count` |
| 交付序列 | `(0,W,0xFFFFFFFF) (4,W,0xFFFFFFFF) (12,W,0x35) (12,R,0x35) (12,W,0x6a) (12,R,0x6a) (8,R,0xa5)` | `session/directed-session.json:first.deliveries` |
| RAM 结果字 | `[0x35, 0x6a, 1, 0xa5]` | `report.json:evidence.result_words` |
| GPIO 最终真实状态 | `gpio_out=0x6a`，`gpio_dir=0xffffffff`，`gpio_in_sync=0xa5` | 最终 `STEP_GPIO` |
| 首次实测取指 | `0xC0000000`（复位向量） | `evidence.first_measured_fetch_address` |
| 启动字保持 | **1 tick**（未供给时不接受 beat，不注入错误完成） | `evidence.boot_hold_ticks` |
| 首次/重跑耗时 | 27.71 s／8.20 s（同一次会话报告内；会话报告总计 35.90 s） | `session/directed-session.json:elapsed_seconds` |
| 产物 digest | CPU `37038890…`；GPIO `1331b597…` | `report.json:evidence.artifact_digests` |

**边界**：这是**定向固定镜像**会话，不是 RFuzz 在线 campaign。没有 `OnlineCaseDecoder`、没有逐例保留指令窗、没有 RFuzz client、没有覆盖反馈或变异；CPU 执行的是声明的固定程序。会话文档的 `not_claimed` 明确写入了这一点。

## 3. Fresh replay（`run/fresh-verification.json`）

真实 first 与 fresh 两次独立进程的完整投影比较：`matches: true`、`first_difference: null`、`verification_scope: full`、`event_count: 98`；比较字段包括被接受 beat 序列、7 笔路由交付、RAM commit、结果字、最终 GPIO 状态、指令源实测证据与组件/构建身份（运行期 UUID 类字段被显式剔除）。`session/directed-session.json` 保留 first/fresh 原始证据与比较结论。

**它不是**一次新的搜索，也不确认 first 未记录的事实；`fresh-verification.json` 的 `not_a_substitute_for` 逐字声明。

## 4. D4 分级（`run/capability-report.json`）

| 路径 | 授予 | 未授予 |
|---|---|---|
| `F4:ram.image`（CPU→外设） | Catalog、Generated、**RTL operational**、**Cross-component accepted** | Coverage-guided searched、Bug confirmed |
| F1/F2/F3 | Catalog、Generated | 其余四项（本次 directed 会话的 receipt 只声明 F4） |
| F5/F6 | Catalog | 其余（真实 unsupported：`interrupt-consumer-missing`／`dma-master-not-declared`） |

`RTL operational` 的证据是 `receipts.jsonl` 中 `flow_id=F4`、`candidate_disposition_reason=rtl_case_committed`、`total_local_ticks=373`；`Cross-component accepted` 的证据是 5 个 `cpu:gpio:apb…` 交互特征（均来自真实路由交付）。报告没有授予覆盖引导搜索或 bug 确认。

## 5. 负例与边界（同一次门禁）

- **RFuzz client 不被 directed 家族消费**：以 `--client-binary third_party/rfuzz/.../kfuzz` 实跑，D1–D3 完成后在 session 阶段拒绝，`code=directed-session-does-not-consume-client-binary`（`client-binary-refusal/` 目录）。
- **RFuzz live 路径不会静默借用 CVW**：`run_live_session` 缺 D3 compiled inputs 时固定拒绝 `compiled-runtime-input-required`，不启动 RTL、不取 heavy lock（`test_the_rfuzz_live_route_does_not_start_cvw_without_d3_inputs`）。
- **指令源拒绝猜测**：实测首地址不是声明复位向量 → `ValueError`；未实测到请求 → 不供给任何字节；无 `OnlineCaseDecoder` 语义。
- **启动保持仍在**：`GeneratedAhbMemorySession` 的无 source 旧行为逐字保留；`_boot_word_required()` 与既有两个保持测试不变。
- 旧的 `cvw-online-assembly-undeclared` 字符串不再出现在 family 模块中；`test_the_opt_in_observations_are_refused_by_name` 钉住这一点，CLI help 守卫也把该字符串加入 stale 词表。

## 6. 测试计数（实测）

| 命令 | 结果 |
|---|---|
| `pytest tests/integration/test_cvw_session_assembly.py tests/integration/test_cvw_runtime_family.py tests/integration/test_cvw_unified_master.py tests/integration/test_cvw_derived_config.py "tests/integration/test_auto_harness_test.py::test_the_help_text_matches_the_shipped_stages"` | **69 passed, 1 skipped** in 48.01 s（`pure-tests.log`；skipped 为真实门） |
| `MYFUZZ_SCENARIO_REAL=1 pytest tests/integration/test_cvw_runtime_family.py::test_the_family_cli_starts_a_real_directed_session_and_grades_f4` | **1 passed** in 69.43 s（`pytest-gate.log`） |
| `pytest tests/local_harness/test_ahb_lite_session.py` | **8 passed** in 144.98 s（`ahb-session-tests.log`） |
| `pytest tests/integration/test_cvw_cpu_pulp_gpio_chain_real.py` | **2 passed** in 112.72 s（`static-chain-tests.log`；既有静态镜像链回归） |
| `pytest tests/integration/test_cvw_ahb_runtime_generation.py` | **4 passed** in 62.22 s（`ahb-runtime-generation-tests.log`）。其中 raw-wire `test_the_built_harness_drives_real_ahb_traffic_from_the_core` 原先直接发 `STEP_MEMORY`，在 `c341b1a` 的零时钟 `READ_AHB_STARTUP` 前置之后会收到 `ahb_startup_incomplete`；本次按驱动的真实顺序先读完全部启动页再 step，测试重新通过（**测试修正，不改变驱动行为**） |

## 7. 改动的文件

源码：

- `src/myfuzz/scenario/cvw_session.py`（新：boot image、instruction source、runner factory、assembly）
- `src/myfuzz/integration/cvw_directed_session.py`（新：directed session 运行、证据、fresh replay、report/receipt）
- `src/myfuzz/integration/cvw_pulp_online.py`（family 声明 `CVW_SESSION_ASSEMBLY`、runtime 返回 assembly、replay 边界）
- `src/myfuzz/local_harness/ahb_lite_session.py`（可选 declared instruction source；hold 覆盖实测的未填充声明槽）
- `src/myfuzz/local_harness/auto_harness_test.py`（family `session_assembly`、directed session 分支、directed bundle、cache 解析）
- `scripts/auto_harness_test.py`（help/边界文档）

测试：

- `tests/integration/test_cvw_session_assembly.py`（新，29 passed）
- `tests/integration/test_cvw_runtime_family.py`（修复 family 期望与跳过/真实门）
- `tests/integration/test_auto_harness_test.py`（stale 词表加入旧 CVW refusal）
- `tests/integration/test_cvw_derived_config.py`（`D_SUPPORTED`/`ZCD_SUPPORTED` 加入 LLEN=32 派生参数集）
- `tests/integration/test_cvw_ahb_runtime_generation.py`（raw-wire 测试按驱动的真实顺序先读启动页）

文档：

- `docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md`（2026-10-18 追加）
- `docs/superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md`（2026-10-18 更新）
- `docs/LOCAL_HARNESS_RUNTIME.md`（CVW 会话装配实测段）
- 本报告与 `docs/reports/evidence/cvw-session-20261018/`

## 7. 仍未做（不得由本报告推出）

- RFuzz 在线 CVW campaign（`OnlineCaseDecoder`、逐例保留指令窗、client 驱动、覆盖反馈、持久多例会话）。
- F5 中断消费者与 F6 DMA 提供者。
- CPU retirement／native IRQ receipt（AHB-Lite 边界不导出 RVFI 端口）。
- 任何 P6 整行“通过”升级：本次只关闭“会话装配缺失”这一具体阻塞。
