# 通用 CPU/IP 数据流运行框架：G0–G6 执行记录（2026-10-26）

本报告记录一次真实执行的结果与边界，不替代原设计/计划，也不改变既有 F2/F4/F6
结论。软件测试只证明合同和拒绝路径；原生执行仅按文末所列实际命令记录。

## 任务状态

| 任务 | 结论 | 关键实际结果 |
|---|---|---|
| G0 | PASS | 冻结工作树（295 tracked 修改、17,965 untracked、1.8 MB binary patch）、2659 个输入 SHA-256、基线 80 passed/10 subtests、121 个原有断链与缺失 `sources.f` 原样记录 |
| G1 | PASS（软件） | 四个合同模块；54 tests；bool/int、重复 key、NaN/Inf、额外字段、重复列表、超宽值、detached plan/descriptor/semantic 均覆盖 |
| G2 | PASS（软件） | 受信认证 + 唯一能力选择；108 runtime tests（54+24+30）；G2 gate 95 passed + 1 个**原有** F6 映射失败 |
| G3 | PASS（软件） | APB3 storage provider/OBI 边界；50 gate tests（25+21+4）；真实 session/issuer 类构造但不启动原生；软件 fixture 证据恒为 unsupported |
| G4 | PASS（软件） | 同次 D2/D3 计划、`--mode prepare` CLI、进程内 binding；38 tests；timer/SPI 各一份同次 F2+F4 计划 |
| G5 | PASS（软件） | 持久生命周期/引擎、storage kernel、directed+RFuzz adapter；87 tests；一次 build/start/begin、所有 case 复用同一 runner/memory；混合 F2+F4 明确拒绝 |
| G6 | **PASS（首切片范围）** | 两个已登记 APB storage 源各跑真实 3 例持久 F4（写 + CPU 回读）与跨进程 fresh；证据全 certified；改名实例、真实非 alias 拒绝、真实 saved bundle original/fresh 验证与 8 类篡改拒绝均通过。另补 **混合 F2+F4 单 session** directed 序列（F4 写→F2 读前例值→F4 写）original/fresh 真实通过（见下节）。 |

## G4 同次计划（真实 prepare，冻结源码）

- timer：paths `F2:ram.image` + `F4:ram.image`，plan
  `2dcb4250694513e78c9155c97ad59960982bf506e37adb893f632d3ce0c94a6f`，
  d2 `eefd3e99…`，d3 `ee198c27…`，refusals 空。
- SPI：paths `F2:ram.image` + `F4:ram.image`，plan
  `6936f42394b7a16dad95c2924ee9c696c70ec9c2e4c1b3eaa72e0d71e850a9d6`，
  d2 `54dd5399…`，d3 `f4b3d689…`，refusals 空。
- 证据：`runs/generic-runtime/G4/{timer,spi}-attempt-frozen/` 与
  `runs/generic-runtime/G4/task-report.json`。

## G6 真实执行（两个已登记 APB storage 源）

冻结源码闭包：`a189bc7e90eed7d87d52993e680ecd4d368c1f4570a646ec329e0ee753a6c658`
（569 个 `src/myfuzz/*.py`），`runs/generic-runtime/G6/source-freeze.json`。

每次执行均为：`create_preparation`（固定 generated 路径）→ verify/select → 单计划
→ `CompiledF4Runtime(defer_begin=True)` → 真实 adapter 在 `ScenarioSession.begin`
**之前**绑定 → engine 一次 begin → 3 case → finish → 同进程 fresh replay。

| 源 | 计划 identity | original PID | fresh PID | 三例值 | 结果 |
|---|---|---|---|---|---|
| PULP timer（`TIMER0_CTRL`） | `d6b32da2…` | 848135/848189 | 859403/859457 | 85, 170, 0x12345678 | 3/3 effective，证据 certified，replay matches |
| PULP SPI（`SPICMD`） | `95a1efec…` | 871516/871582 | 885955/886023 | 同上 | 同上 |
| 改名实例（`cpu0`/`timer0`） | `cdb4ebd1…` | 896882/896936 | —（未跑 fresh） | 同上 | 3/3 effective，证据 certified，selection 与 timer 相同、身份摘要不同 |

- 每例 `initialization_counts = {build:1, start:1, begin:1, init:1}`；case 之间复用
  同一 runner/memory/session，无 reset。
- 跨例持久证据：case N 的 `prerequisite` 值/`write_count`/`command_sequence` 与
  case N-1 的 `postcondition` 完全相等（0→85→170→0x12345678），且每例的 F4
  certificate 含真实 CPU 写→读回→写结果 RAM 的 hop（读回 native rdata 与版本值
  一致）。
- 真实非 alias 拒绝：使用真实 `GeneratedApb3RegisterSession` 与生产 adapter，地址
  `window_base+8` 在 `PADDR[4:2]==1` 之外；`prepare` 返回
  `generic-route-refused /request/address`（`decode_mask=0x1c, decode_value=4`），
  `session._sequence`/`local_ticks` 前后不变，alias `window_base+4` 的 prepare 成功。
- 真实 saved bundle：两源各产出 `generic_runtime_bundle.v1` original/fresh，CLI
  `verify_generic_runtime.py` 通过（每对 52 checks，`fresh_verified=true`）；
  真实包上 8 类篡改（read-return、byte-version、counter、process pid、source
  archive、plan、evidence status、fresh pid 复用）全部拒绝。
- 证据目录：`runs/generic-runtime/G6/{timer-F4-final,spi-F4-final,renamed-timer-F4-final,non-alias-timer}/`，
  每目录含 `original/`、`fresh/`、`bundle-original/`、`bundle-fresh/`、
  `verification/real-pair.json`、`tamper/tamper-report.json`。
- 真实门测试 `tests/integration/test_generic_storage_native.py`（需
  `MYFUZZ_RUN_GENERIC_NATIVE=1`）：**8 passed**；未设开关时 8 skipped，不记通过。
- 配置：`configs/scenarios/generic-storage-contracts/{timer,spi,renamed-timer}.json`
  与 `renamed-timer/` 显式 compose/request/capability/supplement。

## 混合 F2+F4 单 session 持久序列（设计 §5.2 补齐）

- 运行时：`CompiledF4Runtime(mixed_flows=True)` 共享同一 CPU session、APB target
  session、`ApbStorageRegisterVersionAuthority`、`PersistentMemory`、
  `ScenarioRunner` 与 `ScenarioSession`；`submit(raw, flow)` 按 flow 选择
  写/读程序与 checker，`defer_begin` 保留先绑定后 begin。
- 通用层：`runtime/flows/mixed.py` 的 `MixedStorageKernel`（按 case 的
  path/flow 选择 per-flow kernel；`capture` 按 certificate schema 分派）与
  `MixedStorageFlowBackend/Channel`；engine 的 `accepts_flow` 通道逐例传递 flow；
  campaign 仅对 `supports_mixed` backend 放开 mixed directed 序列。
- 真实序列：F4 写 `0x55` + 读回 → F2 CPU load 前例值 `0x55` 并 XOR 存 RAM →
  F4 写 `0xaa` + 读回。
- 证据（`runs/generic-runtime/mixed/`）：
  - 直接 runtime：`timer/original/`，三例 certificate 全 `certified`，同进程 fresh
    replay `matches=true`，audit PID 1026157/1026211。
  - 通用 engine：`timer-generic/{original,fresh}/`，plan identity `204db6e9…`
    两进程字节一致；original PID 1046213/1046274，fresh PID 1058196/1058250；
    两进程均 `{build:1,start:1,begin:1,init:1}`、三例 effective、四态证据全
    certified、replay matches；F2 case 的 `version_before`/`version_witness`
    均为 `0x55`（前例写入值），dependent RAM 值为 `0x55^0x5a5=1520`。
- 真实门测试（`MYFUZZ_RUN_GENERIC_NATIVE=1`）现为 **9 passed**。
- 限制：混合仅支持 directed 序列；RFuzz 仍一 campaign 固定一个 wire flow；
  混合 flow 的 saved bundle 尚未产出（F4 单流真实 bundle 已验证）。详见
  `runs/generic-runtime/G5/mixed-addendum.json`。

## 未完成项 / 不在本次范围

1. 混合序列目前只支持 directed；RFuzz wire 仍是一 campaign 一个 flow/layout，
   没有混合 wire selector（需要单独版本化外层分派合同）。
2. 混合 flow 的 saved `generic_runtime_bundle.v1` 尚未产出；F2/F4 单流真实
   bundle 已验证（52 checks + 8 类篡改拒绝）。
3. 改名实例只跑 original 3 例，未跑 fresh；F2 单流独立 campaign 未跑。
4. `compiled_paths.v1` 的 `identity.request_sha256` 仍含绝对 generated 路径；
   跨进程 fresh 通过“同一绝对 generated 路径、原目录归档后重生成”实现，未归一化
   任何证据字段。
5. 既有 F2 execution-files 预存失败、121 文档断链、缺失 static-campaign
   `sources.f` 保持原样。
## 未完成项（G6 不通过的原因）

1. 四态证据 live capture 与真实 runtime 事件流未接通（上述）。
2. 混合 F2+F4 单 session directed 序列未实现（现有 F2/F4 runtime 各自构造
   session），真实“后例读取前例写入值”的 CPU 读路径因此未跑。
3. `generic_runtime_bundle.v1` 真实原始/fresh bundle 未由运行产生，saved
   verifier 仅有合成 fixture 证据（90 tests）。
4. 改名实例真实正例与真实非 alias 地址 effect 前拒绝未执行；G3 软件层已覆盖
   拒绝逻辑。
5. SPI 真实原生活动未执行（仅 timer F4）。
6. 跨进程 fresh 使用同一绝对 generated 路径以保持 `compiled_paths.v1` 的
   location-sensitive 身份；该继承限制已记录，未归一化任何证据字段。

## 复现命令（节选）

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m pytest -q tests/runtime \
  tests/integration/test_compiled_f4.py tests/integration/test_compiled_f2.py \
  tests/integration/test_compiled_f4_build_join.py \
  tests/integration/test_compiled_f2_read_response.py tests/test_current_cli.py
# 455 passed, 1 skipped (native-gated), 10 subtests passed (broad regression)
# 429 passed, 5 skipped (native gate unset) — plan G6 software command; skips are not passes

PYTHONPATH=src:. python3 scripts/run_generic_runtime.py \
  --compose configs/scenarios/compiled-f4-obi-apb-timer/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-timer/execution_supplement.json \
  --flow F2 --flow F4 --mode prepare \
  --output runs/generic-runtime/G4/timer-attempt-frozen

G6_ROUNDS=32 G6_CACHE=runs/generic-runtime/G6-probe/f4-timer-persistent/cache \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 \
  runs/generic-runtime/G6/run_native_campaign.py --scenario timer --flow F4 \
  --mode original --case runs/generic-runtime/G6/timer-F4-final

MYFUZZ_RUN_GENERIC_NATIVE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m pytest -q tests/integration/test_generic_storage_native.py
# 9 passed on the archived real evidence (including the mixed F2+F4 campaign)

PYTHONPATH=src:. python3 scripts/verify_generic_runtime.py \
  --bundle runs/generic-runtime/G6/timer-F4-final/bundle-original \
  --fresh-bundle runs/generic-runtime/G6/timer-F4-final/bundle-fresh \
  --output runs/generic-runtime/G6/timer-F4-final/verification/real-pair.json
```

## 结论边界

G0–G6 首切片（OBI CPU + 两个已登记 APB storage 源、F4 持久写读回、跨进程
fresh、独立 saved bundle 验证）以及设计 §5.2 的混合 F2+F4 单 session directed
持久序列（含后例 CPU 读取前例写入值、跨进程 fresh）已在记录的源码快照
（`f1dd22f5…`）和原始证据上通过；G1–G5 是软件合同/认证/计划/引擎结果。仍然不含：
混合 RFuzz wire、G7 新 source、G8 协议/ABI 扩展、G9 F6 真实门、G10 系统矩阵/
P7-E/P8。因此不能把本次结果说成通用框架全部完成或系统矩阵完成；下一步按计划
进入 G7（新增同协议 source，不改通用 core）。
