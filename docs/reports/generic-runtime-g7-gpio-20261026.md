# 通用运行框架 G7：真正新增同协议 source（PULP GPIO PADDIR）

本报告记录一次真实执行及其边界，不替代设计/计划，也不把 G7 的 APB storage 结果
扩大为 G8–G10 或 P7-E。所有结论只来自 `runs/generic-runtime/G7/` 下的归档输入与
真实进程证据；软件 mock/skip 不计为 native 通过。

## 任务状态

| 任务 | 结论 | 关键实际结果 |
|---|---|---|
| G7 | **PASS（声明式接入范围）** | 新增 PULP `apb_gpio` 的 `PADDIR` source contract/profile/scenario；真实 3 例持久 F4（CPU 写 + 读回）与跨进程 fresh（plan 字节一致、PID 不同、replay 匹配）；改名实例 `gpio0` 真实 3 例；混合 F4+F2+F4 单 session original/fresh（F2 读前例值）；真实非 alias 地址 effect 前拒绝；14 项错误语义/相似名/模板负例全部拒绝；saved pair 52 checks verified、8 类篡改拒绝；共享功能源码除一处 docstring 外字节不变。 |

`runs/generic-runtime/G7/task-report.json` 的 `verdict` 为 PASS；`checks` 14/14
为 true。

## 新增 source（不是改名）

- RTL：`third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv`，sha256
  `1e271914…bcaef`，revision `git:f82caeb7…5efe0d83`，参数
  `APB_ADDR_WIDTH=12/PAD_NUM=32/NBIT_PADCFG=4`。
- 注册：`src/myfuzz/local_harness/apb_storage_source_contract.py` 新增
  `pulp-apb-gpio.paddir.source.v1` 文档；`registered_apb_storage_source_contracts()`
  现为 timer/SPI/GPIO 三项。文档 digest
  `714212bc…9afd0`。这是 source-verifier 登记，不是 registry/adapter/kernel 的
  名称分派。
- source 事实（独立审计见 `runs/generic-runtime/G7/source-audit.md`）：
  `s_apb_addr=PADDR[6:2]`，`REG_PADDIR_00_31=0`；mask `0x7c`、value `0`；
  忽略位 `[0,1,7..11]`；alias 周期 128 字节，原始 alias 128 个、4 字节对齐 32 个；
  storage 为 `r_gpio_dir`，仅异步 reset 与选中 full-word APB 写可改变（PAD_NUM=32
  时 upper-bank 0x38 只置 `s_write_dir[63:32]`，提交循环只到 `i<PAD_NUM`）；
  读为 `PSEL && PENABLE && !PWRITE` 的组合 mux；`PREADY=1`、`PSLVERR=0`。
- profile：`configs/peripherals/pulp_gpio_storage/component_profile.json`，只声明
  `gpio.bus` 为 APB3 target、`PADDIR` 为 `rw/none/32-bit/reset 0`。复用现有
  `pulp_gpio` source-lock 记录与真实 closure `configs/soc/closures/pulp_gpio.json`；
  没有伪造新的 elaboration 证据。capability 只列 `PADDIR`，不把
  PADOUT/SET/CLR/PADIN/PADCFG/INT*/interrupt 纳入 storage。
- scenario：`configs/scenarios/compiled-f4-obi-apb-gpio-storage/`（compose、
  v2 peripheral request、fixed `gpio_in=0`、`apb_storage_observations=PADDIR`、
  capability、supplement）；矩阵选择：
  `configs/scenarios/generic-storage-contracts/gpio.json` 与 `renamed-gpio.json`。

## 真实执行

源码闭包：`1c2dbbf2…4d2cbf`（570 个 `src/myfuzz/*.py`，
`runs/generic-runtime/G7/source-freeze.json`；original/fresh/renamed 的
`source_files` 完全相同）。工具：Verilator 5.051、Python 3.12。

每次执行为：`create_preparation`（固定 generated 路径）→ verify/select →
单计划 → `CompiledF4Runtime(defer_begin=True)` → adapter 在 begin **之前**绑定 →
engine 一次 begin → 3 case → finish → 同进程 replay（replay 会真实重跑完整前缀）。

| 运行 | plan identity | PID（peripheral/processor） | 三例值 | 结果 |
|---|---|---|---|---|
| GPIO original | `ba1f5ee0…a81bd1` | 1193960 / 1194031 | 0x55, 0xaa, 0x12345678 | 3/3 effective，证据 certified，replay matches，712.33s |
| GPIO fresh | `ba1f5ee0…a81bd1` | 1218607 / 1218685 | 同上 | 3/3 effective，证据 certified，replay matches，691.97s |
| 改名实例 `gpio0` | `3bcabc59…98971e` | 1245111 / 1245167 | 同上 | 3/3 effective，证据 certified，replay matches，709.26s |

- 两次 original/fresh 的 `execution_plan.json` 字节相同；d2
  `19d530bc…`、d3 `f0a49144…` 相同；两组 PID 不相交。
- 每例 `initialization_counts={build:1,start:1,begin:1,init:1}`，case 之间共享同一
  runner/memory/session，无 reset、无新 harness；三个 campaign 的
  `execution_audit.json` 均为 `closed:true`，两个进程均 `reaped:true`、returncode 0，
  report checks 也要求该条件。
- 跨例持久证据：case N 的 `prerequisite` 值/`write_count`/`command_sequence` 等于
  case N-1 的 `postcondition`（0→0x55→0xaa→0x12345678，write_count 0→1→2→3）；
  每例含真实 CPU 写→APB 采样→CPU 读回→结果 RAM 的 hop。
- 证据：`runs/generic-runtime/G7/gpio-F4-final/{original,fresh}/`、
  `renamed-gpio-F4-final/original/`。

## 混合 F4+F2+F4（附加真实序列）

使用与 G6 相同的 `CompiledF4Runtime(mixed_flows=True)`、`MixedStorageKernel`/
`MixedStorageFlowBackend`：一个 CPU session、一个 GPIO target session、一个
`PersistentMemory`、一个 `ScenarioRunner`、一次 begin。计划
`7982dd61…a3392d`，序列 F4 写 `0x55` → F2 CPU 读 `PADDIR` 前例值 `0x55` 并 XOR
存 RAM → F4 写 `0xaa`。

| 模式 | PID（peripheral/processor） | 三例 | F2 version_before / witness | F2 RAM | replay |
|---|---|---|---|---|---|
| original | 1320516 / 1320592 | F4/F2/F4 全 effective+certified | 0x55 / 0x55 | 1520 = 0x55^0x5a5 | matches |
| fresh | 1333731 / 1333785 | 同上 | 0x55 / 0x55 | 1520 | matches |

plan 字节 original/fresh 相同，PID 不相交，`initialization_counts` 每模式均为
`{build:1,start:1,begin:1,init:1}`。证据：`runs/generic-runtime/G7/mixed-gpio/`
与 `runs/generic-runtime/G7/mixed-addendum.json`。

## 拒绝负例（全部在 native effect 之前）

`runs/generic-runtime/G7/negatives/negative-report.json`：正例 `PADDIR` 通过；
14 项负例全部 refused，`all_pipeline_cases_before_native=true`。

| 负例 | 拒绝层 / code |
|---|---|
| `PADOUT`、`PADOUTSET`、`PADOUTCLR`、`INTSTATUS`、`GPIOEN`、`PADDIR0` | `select_apb_storage_source_contract`：`apb-storage-selection-unsupported`（只接受登记行的 register 名） |
| timer contract on GPIO / GPIO contract on timer | source identity：`apb-storage-source-identity-unsupported` |
| profile register 改名 `PADDIR0`（仍选 `PADDIR`） | `apb-storage-register-mismatch` |
| 相似 module 名 `apb_gpio_v2` | `apb-storage-source-identity-unsupported` |
| APB3 → APB4 endpoint | `apb-storage-endpoint-mismatch` |
| source 字节追加注释 | `apb-storage-reviewed-source-bytes-changed` |
| pipeline 选 `PADOUTSET` / 模板改为 `partial-word` | `generic-source-unverified`（生成期拒绝，无 native） |

真实非 alias 探针：`window_base+4`（`GPIOEN`，非 `PADDIR` alias）由生产 adapter
`prepare` 拒绝为 `generic-route-refused /request/address`，`decode_mask=124`、
`decode_value=0`；alias `window_base+0` prepare 成功；session sequence/ticks 前后
不变，无进程启动（`runs/generic-runtime/G7/non-alias-gpio/refusal.json`）。

## 保存证据

- `generic_runtime_bundle.v1` original/fresh：
  `ebcdbff5…54d72` / `267aaa70…5320e`，fresh 记录 `fresh_of`；
  CLI `verify_generic_runtime.py` 通过 **52 checks**，`fresh_verified=true`，
  `case_count=3`（`verification/gpio-pair.json`）。
- 真实包 8 类篡改全部拒绝：read-return、byte-version、counter、process pid、
  source archive、plan、evidence status、fresh pid 复用
  （`tamper/gpio-tamper.json`，`all_refused=true`，pristine verified）。

## 共享 core/adapter 未追加分支

- `core-freeze-pre.json`（combined `73c03a5c…`）/ `core-freeze-post.json`
  （combined `e515eb19…`）覆盖 runtime/compiler/engine/kernel/adapter/consumer
  等 27 个功能文件；除 `src/myfuzz/runtime/semantics/storage.py` 外全部 SHA
  相同。该文件只有模块 docstring 从“two rows”更新为 timer/SPI/GPIO 三行；
  无语句/分支/默认值变化（`runs/generic-runtime/G7/docstring-change.md`）。
- `src/myfuzz/runtime/` 中唯一出现 `gpio`/`paddir` 的文件就是该 docstring；
  没有按实例名选择 adapter/kernel/factory。
- `src/myfuzz/local_harness/apb_storage_source_contract.py` 是允许的
  source-verifier 登记文件；其 pre/post SHA 单独记录，变化仅为新增 GPIO 文档、
  factory 注册和 GPIO endpoint 事实校验。

## 独立原始证据审计

独立审计见 `runs/generic-runtime/G7/independent-audit.md`（sha256
`9524423b…`），结论 **PASS**：9 项 claim 均由归档字节独立复核；没有 mock 证据
冒充 native、没有每例新 harness/reset、fresh 仅归一化声明的 pid/nonce/
execution_id、没有把 skip 记为通过、没有 legacy fallback。审计还独立重跑了
selection 负例、`verify_saved_bundle`（52/52）、8 类 tamper 和 source-contract
digest 重算。

审计记录 9 项**不阻塞**差异（D1–D9），本次不通过改写归档证据或共享 core 来隐藏：

- **D1/D2（继承，中）**：所有 G5/G6/G7/混合 `campaign.json` 仍带
  `software_only: true`、`native_certification.claimed: false`，且
  `terminal_records`/`summary.identities` 的 pid 为 null；这是 engine/campaign
  的旧硬编码字段，和同文件的真实 `process_identities`、`execution_audit`
  reaped/rc0 矛盾。G7 真正依赖的是 `process_identities`、`execution_audit`
  argv/binary hash、replay 与 saved bundle，不是这两个字段；字段本身留待共享
  core 的单独清理修复，未在此任务中篡改。
- D3：plan 只含 artifact/semantic digest，不含 source-contract digest；后者在
  artifact/bundle/source-freeze。
- D4：既有 closure 的 lint log 路径悬空，但 closure 文件与 lock hash 完整。
- D5：负例报告的 `process_started=false` 是声明字段；已测事实是
  `generated_exists=false` 与真实 refusal code。
- D6：审计后已加强 report checks（精确 code/pointer/mask、52/52 verified、
  8/8 tampered refused、独立审计文件）。
- D7：artifact 保留保守的 prospective hierarchy 状态；`hierarchy_verified`/
  `native_verified` 仍为 false。
- D8：`source-freeze.git_status_short_sha256` 是时间点快照；570 个冻结 `src/`
  文件仍与磁盘一致。
- D9：`build=1` 是 lifecycle/harness 计数，不宣称 fresh 重新编译；fresh 证据是
  新 PID/nonce 与独立 replay。

## 门与实际命令

```bash
# 软件门（本次实际 633 passed, 23 skipped, exit 0；skip 不计通过）
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q \
  tests/runtime tests/integration/test_generic_storage_native.py \
  tests/integration/test_generic_storage_gpio_native.py \
  tests/integration/test_compiled_f2_read_response.py \
  tests/integration/test_compiled_f4_build_join.py \
  tests/local_harness/test_apb_storage_source_contract.py \
  tests/local_harness/test_apb_storage_probe_generation.py \
  tests/local_harness/test_apb_storage_probe_verification.py

# 真实门（已归档证据；arm 后实际 9 passed 与 8 passed）
MYFUZZ_RUN_GENERIC_NATIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m pytest -q tests/integration/test_generic_storage_native.py
MYFUZZ_RUN_GENERIC_NATIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m pytest -q tests/integration/test_generic_storage_gpio_native.py
```

- G7 原生证据门：`tests/integration/test_generic_storage_gpio_native.py`
  **8 passed**（arm）；未 arm 时 8 skipped，不记通过。
- G6 回归门：同一 arm 下 **9 passed**，证明新增登记没有破坏首切片。
- 软件门日志：`runs/generic-runtime/G7/software-gate.log`。
- 兼容回归 `tests/integration/test_compiled_f2_execution_files.py`：**6 passed,
  1 failed**；失败的 `test_public_factory_maps_each_executor_to_one_flow` 是
  G0 已记录的**原有** dirty F6 `_FLOW_BY_EXECUTOR` 差异，与 G7 无关（日志
  `runs/generic-runtime/G7/f2-execution-files.log`）。G7 未新增失败。

## 边界与后续

- 本任务只关闭“新增同协议 APB storage source”的声明式接入；不关闭 RFuzz
  mixed wire、F2-only 无前例独立 campaign、G8–G10、P7-E 或 F6 真实门。本任务
  已实际跑通 mixed F4/F2/F4 directed 序列（见上）。
- `has_error=true` 只描述 APB3 信号集；PSLVERR 恒 0，不声明 error-generation。
  非 storage 寄存器/中断/pins 明确 `not_claimed`。
- 未修改任何 saved bundle schema、runtime adapter、kernel、compiler、engine、
  registry 匹配算法或旧的具名 causal 路径。
- 全部改动保留在工作树，未提交、未 reset/clean/stage-all；工作树中前驱 F2/F6
  修改与既有失败 attempt 保持不变。
