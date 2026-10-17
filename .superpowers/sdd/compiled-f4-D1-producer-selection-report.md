# D1 — 封闭生产者选择的实现报告（2026-10-17）

本增量只做 [D1 closed producer selection](apb-storage-D-generic-f4-integration-brief.md#proposed-atomic-ownership--ordering)：
新增 code-owned storage producer selector，并把 `compiled_f4` 的 GPIO/GPIOEN 硬限制替换为经 selector 的
两行封闭选择。**不做** D2 generic commit/raw join、不做 live token/certificate、不做任何原生/模型/构建门。

## 结论（可审查边界）

- 新增 `src/myfuzz/integration/compiled_storage_producer.py`：唯一两行（`gpio_causal_abi`、
  `generic_apb_storage_abi`），行内 session/issuer 类与 consumer 函数由代码命名并 import-time pin；
  用户 JSON 不能提供 factory/method/expression/authority descriptor；component_id/profile 名不参与选择。
- `compiled_f4.admit_f4` 不再硬性要求 `apb_gpio`/`GPIOEN`：经 selector 取 binding，并用 binding 的
  `prerequisite.expected` 校验唯一 `ip_register_version`。GPIO 行构造参数、顺序、consumer 与语义保持原样。
- generic timer 行只在 **registered source contract（重读精确源字节）+ D3 声明 + 生成的
  `storage_observation` 契约（`verify_apb_register_trace` 规范重投影）** 同时匹配时选中；selector 返回
  不可变 binding。`CompiledF4Runtime` 在**构造任何 session/process 之前**以
  `compiled-F4-generic-commit-consumer-unsupported` fail closed（D2 未实现），因此本增量不声称 timer
  F4 可执行、不签发 live token/live certificate/native eligibility。
- binding 进入 checker（`online_identity_configuration`）、prefix（`finish`）与每次
  stability/readmission/fresh 构造（`_admit_f4`/`_stable` 重建并比较，drift 拒绝）。

## 变更文件

| 文件 | 变化 |
|---|---|
| `src/myfuzz/integration/compiled_storage_producer.py` | 新增 selector、不可变 binding、`validate_storage_producer_binding`、`build_storage_producer` |
| `src/myfuzz/integration/compiled_f4.py` | admit 移除 GPIO 硬限制改走 selector；`admit_f4(..., base_dir=None)`；`_admit_f4` 返回 `(path, binding)`；构造经 `build_storage_producer`；checker/prefix/stability 纳入 binding；generic 行构造前明确拒绝 |
| `src/myfuzz/local_harness/compiled_execution_projection.py` | 最小 D1 接线：`assess_compiled_f4_support(..., base_dir=None)`；generic 行 capability 仍 `execution_supported=0`（reason `compiled-F4-generic-commit-consumer-unsupported`，附 binding），GPIO 报表逐字段不变 |
| `src/myfuzz/integration/compiled_execution_files.py` | 最小 D1 接线：把已解析的 `base` 传给 capability 评估 |
| `tests/integration/test_compiled_f4_storage_producer.py` | 新增 28 项纯 source 控制（RED→GREEN） |

未改 `third_party/`、`docs/` 既有报告、CVW observer/profile、APB session/startup/version（另一代理范围）、
`apb_storage_register_version.py`（C issuer 只读，未修改）。

## RED（先写，保存于 `.superpowers/compiled-f4-d1/red.log`）

- 先以**现状硬限制**直接验证：generic timer profile + 已登记 CTRL0 声明（纯 source 生成 artifacts 与
  compiled inputs）在 `admit_f4` 被拒绝：

  ```
  REFUSED: compiled-F4-register-authority-unsupported
  ```

  对应旧代码 `src/myfuzz/integration/compiled_f4.py:373-382`（`kind=='apb_gpio'` / `GPIOEN` /
  `gpio_observation_contract` / `verify_native_physical_observation` 硬块）。
- 新增测试文件在实现前整体 RED：`28 failed in 27.59s`（selector 缺失、GPIO 旧行无 binding、
  negatives 无对应拒绝、binding 未进入 checker/prefix/stability）。同时 GPIO 现有 F4 路径在该 RED 运行时仍
  通过（`test_forged_compilation_never_admits` 等既有控制未因 RED 改动失败）。

## GREEN（实现后）

- `PYTHONPATH=src:. python3 -m pytest tests/integration/test_compiled_f4_storage_producer.py -q`
  → **29 passed**（38.69s；RED 时 28 failed）。覆盖：
  - generic timer：admission 通过；binding 精确 register/offset/width/masks/decode/probe/source/producer
    digest、template/variant、source closure、allowed prerequisite kinds；
  - generic 未可执行：`CompiledF4Runtime` 构造前拒绝 `compiled-F4-generic-commit-consumer-unsupported`，
    capability report `execution_supported=0, runtime_admitted=false`；
  - GPIO 旧行：`GeneratedPulpGpioSession` / `GpioRegisterVersionAuthority` /
    `check_writer_observation` 语义的 binding 保持；
  - 负例（全部 fail closed）：未知/跨协议 kind、template variant 错配、跨协议 artifact 填充、
    component_id 改名、wrong register/offset/width/mask/address、缺失或篡改 source/probe/contract digest、
    无 trusted source dir、caller-supplied factory/method（含 import-time pin drift）、
    caller metadata 冒充 binding、tampered/stale/foreign binding；
  - binding 进入 checker identity、prefix、stability 重建（drift → `compiled-F4-producer-binding-changed`）；
  - 两行在 fixture 层各构造出精确 session/issuer：generic 为 `GeneratedApb3RegisterSession`（空
    setup/probe）+ `ApbStorageRegisterVersionAuthority`，GPIO 为 `GeneratedPulpGpioSession` +
    `GpioRegisterVersionAuthority`；foreign artifact 构造被 `artifact-binding-mismatch` 拒绝。
    该构造是纯 Python，不启动进程也不签发 token。
- 回归（本机只跑 pytest；无原生）：
  - `pytest tests/integration -k compiled_f4` → **60 passed, 1 skipped**（skip 为
    `MYFUZZ_COMPILED_F4_REAL` 原生门，未执行；含本文件 29 项）；
  - `pytest tests/integration/test_timer_f4_declarations.py` → **5 passed**；
  - `pytest tests/local_harness -k compiled` → **1 passed**（1331 deselected）；
  - `pytest tests/scenario -k f4` → **1 passed**（4956 deselected）；
  - `pytest tests/integration/test_compiled_execution_files.py` → **32 passed**；
  - 相邻 APB storage 纯软件回归（隔离，另一代理改共享文件期间）：
    `tests/local_harness -k "apb_storage or native_reset or generic_apb"` →
    **277 passed, 49 skipped**；`tests/scenario -k "apb_storage or register_version"` →
    **50 passed, 13 skipped**。日志见 `.superpowers/compiled-f4-d1/green-*.log`。

## 选择与绑定设计要点

- **行由代码命名**：GPIO 行固定 `myfuzz.local_harness.gpio_session.GeneratedPulpGpioSession` +
  `myfuzz.scenario.gpio_register_version.GpioRegisterVersionAuthority` +
  `myfuzz.integration.generated_register_writer.check_writer_observation`；generic 行固定
  `GeneratedApb3RegisterSession(setup_writes=(), probe_offsets=())` +
  `ApbStorageRegisterVersionAuthority`，commit consumer 显式记为 `pending_D2_generic_commit_join`。
- **import-time pins**：session/issuer 类、source/probe/observation 校验函数、writer consumer 在模块导入时
  捕获；每次 select 校验模块属性与函数 `__code__` 及入口函数自身 pin；替换即
  `compiled-F4-producer-selection-drift`，不重新基线化。
- **来源可信性**：generic 行要求显式 `base_dir`，调用已审查的
  `validate_apb_storage_source_contract`（重读 `third_party/soc-pulp-apb-timer` 两文件 SHA 与 profile
  身份）；再要求 `verify_apb_register_trace` 的规范生成重投影通过；`storage_observation.selection` 必须等于
  代码生成的 probe selection。仅 `kind=='apb3_register_observe'` 或 profile 名字不构成选择。
- **binding 不可变**：`AdmittedStorageProducerBinding` 为 frozen+slots，只持规范化 JSON；
  `binding_sha256` 自校验；`document()` 每次返回新 dict；`build()` 丢弃调用者传入的 `binding_sha256`
  后重算，故无法借 `replace` 伪造。
- **重建点**：`_admit_f4`（初次 admission 与 `_private_admission_snapshot` 私有重建）、`_stable`
  （每次 stability/submit/finish/replay 前）与 fresh `CompiledF4Runtime` 构造都会重建 binding；
  `_stable` 与 private snapshot 均从 trusted inputs 重新选择，不接收 caller metadata。

## 开放边界（明确未完成）

1. **D2 generic commit/raw join**：generic 行目前只被选中/准入，runtime 在构造前拒绝；尚未实现
   实测 CTRL alias commit 消费、`before→after` 版本、Router/APB/storage/readback 关联、C opaque
   before-token 消费与 `process_scope` 连接。`producer_binding` 已暴露 D2 所需字段（register/offset/
   width/masks/decode/source/probe/producer digests、source closure、allowed prerequisite kinds、
   `runtime_commit_join='D2_pending_generic_commit_raw_join'`）。
2. **C issuer `tick_base` 导出**：按 brief 仍为 D2 待办；未修改 `apb_storage_register_version.py`。
3. **D3 公开入口**：generic capability 仍 `execution_supported=0`；file entry/CLI 对 timer 目标仍拒绝运行；
   未更新 timer supplement/README、未授予 F4 timer 执行。本增量的 `assess_compiled_f4_support(base_dir=)`
   只是不误报的 D1 最小接线。
4. **原生/真实门**：未运行任何 native/远程/Verilator/构建/模型；`MYFUZZ_COMPILED_F4_REAL` 门保持跳过。
   GPIO 历史原生证据仍绑定其原始快照，未重标为当前代码回归通过；CV32 未伪造 error0。
5. **D3 前置条件**：仍要求 reset precondition 时拒绝；`grants_reset_prerequisite=false` 保持；
   A2 host/reset issuer 未接入。

## 环境备注

- 运行期间其他子代理正在修改共享的 `runtime_renderer.py`/`apb3_register_session.py`/`session.py`/
  `cvw_contract.py`/`apb_storage_register_version.py`/`native_reset_producer_contract.py` 等文件；一次既有
  F4 测试在编辑中途出现 `driver-runtime-identity-mismatch`，隔离重跑 6/6 通过；一次本文件的 fixture
  构造控制在共享文件写入中途瞬时失败，隔离重跑 29/29、整文件重跑 29/29 通过。最终证据日志
  （`.superpowers/compiled-f4-d1/`）以隔离命令结果为准；selector 对 session/issuer/consumer 做
  import-time pin，并在每次选择时重读 producer 模块字节，因此共享文件的后续合法改动会使 binding 变化，
  这是预期行为（D2/D3 需相应复核）。

## Commit

- SHA: 见最终交付消息（commit message 以 `feat: add closed compiled F4 storage producer selection` 开头）。
