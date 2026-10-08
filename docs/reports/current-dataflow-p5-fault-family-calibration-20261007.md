# P5 受控故障族**通用校准运行器**与**独立复核器**（软件实现与软件门禁）2026-10-07

> **边界（先读）**：本轮只做软件侧交付——新增通用校准运行器 + 独立复核器 + 测试，并**只读**流式读取已保存的真实运行事件来选择见证窗口。
> `--select-only`（9/9 变体，6.4 秒）已真实执行；**本轮没有启动任何真实 RTL 会话、没有跑在线 fuzz、没有重放真实 RTL**。
> 9 个变体的真实校准会话由 root 在软件侧全绿之后串行执行（命令见下）；本文任何"已校准"字样都不指真实 RTL 结果。

## 结论

- 此前 [`p5_controlled_fault.v1` 四类九变体](current-dataflow-p5-controlled-fault-family-20261007.md)里只有 `wrong_irq`/`observation_irq_level` 有真实 RTL 校准。本轮把**真实保存事件上的见证窗口选择**扩展到**全部 9 个变体**，并给出逐变体的可执行真实会话命令。
- **交叉验证**：新运行器为 `observation_irq_level` 选出的选择器与钉住文档，与既有真实报告里那份**真实 RTL 校准过的**文档逐字节一致（canonical SHA-256 `cd753d419c2860b94f302a672c90a17f8da3fbdef5ea5d1f1158419db03304d6`，见[受控故障真实校准](current-dataflow-p5-controlled-fault-real-20261007.md)）——说明通用选择与既有单变体门禁选的是同一个见证。
- **确定性**：同一命令连续两次 `--select-only` 得到逐字节相同的 9 份 `fault_document.json`、相同的选择器、相同的扫描记录。
- **fail-closed**：见证锚点找不到就是 `no_witness_window`（`selector`/文档为 `null` + 精确原因，含扫了多少 case/事件、是否全量扫描）；扰动后既有 checker 不变量没触发就是 `not_fired`；抛错就是 `error`。运行器从不把"没触发"写成"已校准"。
- **只读源运行**：选择阶段只流式读取（`TraceEventStream`），扫描前后各做一次目录指纹（名字/大小/mtime 清单 SHA-256）并要求相等，源运行目录内不写任何文件；指纹写进汇总的 `source_runs[].read_only`。
- 独立复核器不信任汇总字段：直接重读 `receipts.jsonl`、控制/故障两份 trace 的锚点事件与控制 trace 的文件 SHA-256，任一不一致就以非零退出码 + 精确原因拒绝。

## 新增 / 改动文件

| 文件 | 说明 |
| --- | --- |
| `scripts/run_p5_fault_calibration_family.py` | 新增：通用校准运行器（`run`，含 `--select-only`/`--variant`/`--max-cases`）与独立复核器（`verify`） |
| `tests/scenario/test_p5_fault_family_calibration.py` | 新增：21 项测试 + 18 个子测试（见证选择、fail-closed、文档 canonical、`--select-only`、汇总 schema、run 模式三种终态、复核器 5 类拒绝） |
| `docs/reports/README.md` | 报告索引追加一行 |

未改动任何 `src/myfuzz/**`、任何既有脚本或既有测试；未改动、未写入任何 `runs/**` 里已保存的运行目录（只在其下新增本轮的 `--select-only` 产物目录）。

## 命令

选择见证（**不启动任何 RTL**；本轮已执行，exit 0，6.4 秒）：

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py run --select-only \
  --output-root runs/current-dataflow-p5-fault-family-20261007-select-only \
  --cache-dir runs/current-dataflow-p5-fault-family-20261007-cache \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
```

真实 RTL 校准（**root 串行执行；输出根必须不存在或为空**；每个变体一次独立在线会话，默认 120 s / 24 例 / seed 20261007 / `max_runs_per_batch=1`，命中后期望 finding 后会话自行停止）：

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py run \
  --output-root runs/current-dataflow-p5-fault-family-20261007-online \
  --cache-dir runs/current-dataflow-p5-fault-family-20261007-cache \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
# 单变体（可选）：追加 --variant <name>；只用指定源运行：追加 --continuous-run <dir>（可重复）
```

独立复核（校准完成后）：

```bash
PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py verify \
  --calibration-root runs/current-dataflow-p5-fault-family-20261007-online
```

退出码：`0` 全部请求变体达到目标状态 / 复核通过；`1` 参数、路径、只读性等前置条件错误；`3` 有变体未达标（`no_witness_window` / `not_fired` / `error`）；`4` 复核发现不一致。

## 见证窗口表（来自保存的真实事件，`--select-only` 产物）

源运行与 trace：`runs/current-dataflow-p5-paired-20261007-online`（24 例、31,795 事件，SHA-256 `7d3cd06c…`；PULP 8 变体）与
`runs/p5-uart-gate2-20261007-online`（7 例 + 1 预热例、18,620 事件，SHA-256 `7d3a6886…`；UART 1 变体）。
选择器键集合**严格等于**该变体在 `_SPECS` 里声明的 `selector_keys`；窗口是该 case 在 trace 里的完整事件段（与在线 receipt 同语义）。

| 类别 | 变体 | 源运行 | case | 选择器（真实事件字段） | 期望 finding | 原值 → 扰动值 | 钉住文档 SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `wrong_irq` | `observation_irq_level` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"observation_event_id":4609,"original_value":1,"source_start_event_id":4610,"source_tick":131}` | `gpio_b_irq_source_mismatch` | 1 → 0 | `cd753d419c2860b9…` |
| `wrong_irq` | `cpu_irq_input_bit` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"cpu_event_id":4612,"local_tick":120,"original_value":1,"pulse_start_event_id":4611}` | `cpu_irq_pulse_input_mismatch` | 1 → 0 | `0556ad7bf7558be2…` |
| `wrong_read_data` | `cpu_response_data` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"original_value":262,"read_event_id":5560,"response_event_id":5569}` | `cpu_gpio_b_padin_response_mismatch` | 262 → 263 | `d7f368fa1b43a632…` |
| `wrong_read_data` | `delivery_read_data` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"original_value":262,"read_event_id":5560,"response_event_id":5569}` | `cpu_gpio_b_padin_response_mismatch` | 262 → 263 | `0f0430572ea56596…` |
| `wrong_read_data` | `uart_cpu_response_data` | uart-gate2 | `online-1-819b265ed890cbfc934efd3e` | `{"case_id":…,"original_value":90,"read_event_id":13712,"response_event_id":13737}` | `cpu_uart_rxdata_response_mismatch` | 90 → 91 | `f81cbadadef085a3…` |
| `duplicate_submission` | `irq_pulse_resubmission` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"insert_before_event_id":4779,"local_tick":124,"pulse_start_event_id":4611}` | `cpu_irq_pulse_input_mismatch` | 提交计数 1 → 2 | `dff747d341172f79…` |
| `duplicate_submission` | `mmio_delivery_replay` | paired | `online-2-604caae5c07e4c776cb357d1` | `{"case_id":…,"insert_before_event_id":5569,"original_value":262,"read_event_id":5560}` | `cpu_gpio_b_padin_response_mismatch` | 262 → 263 | `7ac2b3005a2171a5…` |
| `broken_binding_value` | `delivery_value` | paired | `online-0-af5570f5a1810b7af78caf4b` | `{"case_id":…,"delivery_event_id":2226,"original_value":0,"producer_event_id":2225}` | `gpio_a_to_b_delivery_mismatch` | 0 → 1 | `966256bc7e393ff2…` |
| `broken_binding_value` | `bound_input_value` | paired | `online-0-af5570f5a1810b7af78caf4b` | `{"case_id":…,"delivery_event_id":2226,"observation_event_id":2229,"original_value":0}` | `gpio_b_bound_input_mismatch` | 0 → 1 | `ddb9f48243d7694a…` |

相关窗口：`online-2-…` 的窗口为事件 4518–5858（1,341 条），`online-0-…` 为 2205–3344（1,140 条），UART `online-1-…` 为 12935–14411（1,477 条）。

**没有不可见证的变体**。作为 fail-closed 的真实演示：把 UART 变体指向 PULP 运行时会全量扫描 24 例 / 31,795 事件后给出
`no witnessed anchor for wrong_read_data/uart_cpu_response_data | candidate source runs: runs/current-dataflow-p5-paired-20261007-online[cases=24,events=31795,scan=full]` 并以 exit 3 结束（`selector=null`，不编造）。

## 运行器行为

1. **候选源运行按 checker 声明**（`CANDIDATE_SOURCE_RUNS`）：PULP 优先 24 例 paired（备选 368 例 600 s chain），UART 用 uart-gate2；`--continuous-run` 可显式覆盖（可重复，按给定顺序回退）。
2. **见证选择复用故障族自己的定位器**（`_LOCATORS` + `_Search`，与 `family.inject` 注入时同一函数，杜绝规则漂移）：在**每个 case 窗口**上以空选择器定位锚点，读出真实原值，按变体声明推导替换值（`outputs.irq` 1→0、`inputs.irq` 清 bit0、读数据/交付值 `(v+1) & maximum`、纯重提交 `null`），再用 `ControlledFaultFamily.from_document` 严格校验并**注入两次**（空选择器一次 + 钉住选择器一次）要求同一 `finding_id`。
3. **早期停止**：每个变体取工件顺序上的**第一个**见证，命中后不再继续扫描；`max_cases` 之外未找到的变体，其 `no_witness_window` 原因会显式标注 `stopped_early`，不冒充全量结论。
4. **每个变体一次全新在线会话**：`make_ibex_pulp_online_runtime`/`make_ibex_uart_online_runtime(checker=family)` + `run_scenario_rfuzz_live`，运行时开关逐字沿用源运行自己的声明（PULP：RVFI+GPIO 消费+原生 IRQ 收据；UART：RVFI+UART FIFO+memory commit/readback+WDATA lane0 字节写）。
5. **产物**：`<root>/<variant>/fault_document.json`、`fault_run_summary.json`、`minimal_replay.json`（或 `minimal_replay.error`），真实会话产物落在 `<root>/<variant>/session/`（在线运行器要求输出目录全新）；汇总为 `<root>/fault_family_calibration.json`（`p5_fault_family_calibration.v1`，逐变体给出 status / reason / selector / expected finding / observed findings / case id / 精确命令 / 文档路径与 SHA-256）。
6. **状态**：`selected`（仅 `--select-only`）、`calibrated`（收据与故障族 finding 双证）、`no_witness_window`、`not_fired`、`error`（后两者在 `run` 模式产生，`reason`/`observed_findings` 如实记录，`observed_findings` 在会话报错时为 `null` 而不是 0）。

## 独立复核器（`verify`）

对每个 `calibrated` 变体独立重算 7 项检查，任一失败即 `ok=false`、exit 4、`failures[].reason` 指明变体与原因：

| 检查 | 内容 |
| --- | --- |
| `fault_document_canonical` | 重新 `from_document` 校验并要求 canonical 往返、记录 SHA-256 一致、文档内容与汇总的选择器/变更一致 |
| `minimal_replay_canonical` | `p5_controlled_fault_replay.v1` schema、`calibration_only`、边界、内嵌文档 canonical、`fault_document_sha256`、finding 身份 |
| `fault_run_finding` | **直接读**故障运行 `receipts.jsonl`：期望 finding 必须出现在见证 case 的收据里（不信汇总字段） |
| `control_run_clean` | 控制（源）运行必须有该 case 且**从未报告**该 finding |
| `control_window_baseline` | 从控制 trace 重建该 case 窗口，用原生 checker 复算未扰动 baseline 必须为空 |
| `anchored_events_identical` | 控制/故障两份 trace 的锚点事件（选择器里所有 `*_event_id`）在**同一 case 窗口内**按 id 精确 join 后必须逐字段相同；被扰动事件字段值、`local_tick`/`source_tick` 必须等于选择器记录值 |
| `control_trace_unchanged` | 控制 trace 文件 SHA-256 与字节数必须等于选择时刻记录值（证明源运行只读、字节未变） |

复核报告写在 `<calibration-root>/fault_family_calibration_verify.json`；对 `--select-only` 根（没有 `calibrated` 变体）会以 exit 4 + `没有任何 status=calibrated 的变体可供复核` 拒绝，而不是假装通过。

对既有真实校准的一次独立交叉核对（软件只读，复用复核器的 case 内精确 join）：控制 `runs/current-dataflow-p5-paired-20261007-online` 与故障 `runs/current-dataflow-p5-fault-calibration-20261007-online` 的 `event_id=4609`（`gpio_b`/`local_tick=131`/`interrupt=1`）与 `event_id=4610`（`source_tick=131`）**逐字段相同**。

## 测试与 RED/GREEN

命令：`cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_fault_family_calibration.py -q -p no:randomly`

- **RED**（实现前，仅测试文件存在）：`21 failed in 0.35s`，全部为 `AssertionError: calibration runner is not implemented: …/scripts/run_p5_fault_calibration_family.py`。
- **GREEN**（实现后）：`21 passed, 18 subtests passed in 5.66s`。

覆盖：9 个变体各自的见证选择（选择器键集合 = `_SPECS` 声明、取值 = 真实事件字段）与 fail-closed 无窗口原因；源运行只读（文件清单、trace 字节、SHA-256 前后一致）；真实保存运行上的有界选择（UART 与 PULP 各一次，只读）；文档 canonical；`--select-only` 在 client/cache 路径不存在时仍写文档（证明不启动 RTL）与缺窗口时 exit 3；汇总 schema 与逐变体命令；run 模式三种终态（calibrated / not_fired / error）与产物；复核器的 5 类拒绝（finding 缺失、锚点字段不同、控制 trace 字节变化、文档非 canonical、控制侧已报告该 finding）与 CLI 退出码 0/4。
run 模式的真实 RTL 会话在测试里通过 `session_runner` 注入点替换为"只回放保存窗口 + 真跑故障族注入"的软件假会话；CLI 永远使用真实 RTL 路径。

相关回归（未改动任何既有文件）：`tests/scenario/test_p5_fault_family.py tests/test_repository_audit.py tests/test_doc_link_check.py` → `104 passed, 51 subtests passed in 3.60s`；
`scripts/check_identifier_policy.py --paths scripts/run_p5_fault_calibration_family.py tests/scenario/test_p5_fault_family_calibration.py` → exit 0。

## 已知限制与未完成项

- **没有真实 RTL 结果**：本轮 `run` 模式一次都没有执行；上表的 `selected` 只表示"见证与文档已定"，不是 `calibrated`。真实会话与 `verify` 由 root 串行执行。
- 复核器的 `calibrated` 路径在软件夹具（假会话产出的真实产物布局）上验证；真实 run 根的复核尚未执行。
- 见证来自**保存运行**，真实会话能否复现同一 case 身份取决于同 seed/同预算/同运行时开关的确定性：既有真实门禁已在 `online-2-…` 上证明一次（同 seed 第 3 例复现同一 case 与同一 event 4609）；本轮其余变体沿用同一机制，若复现失败则故障族在钉住选择器上直接抛错、会话记为 `environment_error` → `error`，不会伪造校准。
- UART 变体的新会话沿用 uart-gate2 的运行时开关声明（来自[异构门禁报告](current-dataflow-p5-uart-heterogeneous-gate-20261007.md)）；开关不同会改变事件流，届时以 `error` 结束而不是静默通过。
- 选择只利用**同一个 receipt 内**的见证（跨 case 边界的见证不注入）；`calibrated` 只表示该变体触发了声明的既有不变量，不表示检测灵敏度。
