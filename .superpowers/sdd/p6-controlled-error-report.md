# P6 附加项：非 Ibex ＋ 非 GPIO 受控错误捕获与 fresh-process replay

日期：2026-10-17。范围：CV32E40P（OBI）＋ OpenTitan UART（TL-UL）。
状态：**链路选择、受控错误、同进程真实门、五阶段新进程真实门均已有实际运行证据**。
源码冻结后又在当前树完成一次五阶段冻结复跑：`attempt-13-frozen`，1 passed / 127.97s，
exit 0；绑定 HEAD `d24da4d`（`7e08913` 为 docs-only），测试/驱动 SHA 与 attempt-04 完全一致。
本报告不把 105.12 秒的同进程结果冒充新进程门，也不把历史失败复跑算作通过。

---

## 1. 选定组合与边界

| 项 | 值 |
|---|---|
| CPU | OpenHW CV32E40P，`configs/cpus/cv32e40p/component_profile.json`（sha256 `21d04c8a…`），OBI |
| IP | OpenTitan UART TL-UL，`configs/peripherals/opentitan_uart_local/component_profile.json`（sha256 `759f8647…`） |
| 链 | `cv32e40p-opentitan-uart-rx-watermark-irq`：外部 RX 字节 `0x5a` → 真实 8N1/UART RTL → 真实 `uart_rx_watermark` → `cpu.irq[11]` → CV32E40P 真实 trap/ISR → 读 `INTR_STATE`(0x00) 与 `RDATA`(0x18) → 写持久 RAM `0x20000` |
| 非 Ibex | CV32E40P，不是 Ibex |
| 非 GPIO | OpenTitan UART，不是 GPIO |
| 链定义来源 | 直接 import 既有真实链测试 `tests/integration/test_scenario_cv32e40p_opentitan_uart_irq_real.py` 的 `_artifact/_genome/_make_factory`；未复制、未改写真实链 |
| 现有受控错误测试 | `tests/integration/test_cv32e40p_opentitan_uart_controlled_error_real.py`（`aebfc090…`，2026-10-16 已提交） |

选择理由：CVA6＋SPI Host 也是非 Ibex/非 GPIO，但现有 SPI Host 链没有 IRQ/ISR，只有单拍 MMIO 读回，
受控错误只能落在投递值一处；CV32E40P＋UART 已有真实 IRQ→trap→ISR→状态/RDATA→RAM，
可在投递数据、IRQ 断言与持久 RAM 三处同时对照。Pico Wishbone＋GPIO 属 GPIO，被条件排除。

---

## 2. 实际命令、退出码与通过数

全部在 `/home/qinkejiu/myfuzz` 本机运行，真实 Verilator，未远程 SSH。
所有长 RTL 运行均使用
`flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock` 串行化。

### 2.1 既有同进程真实门（历史证据，仅此用途）

```bash
MYFUZZ_SCENARIO_REAL=1 \
MYFUZZ_CONTROLLED_ERROR_OUTPUT=runs/p6-controlled-error-non-ibex-non-gpio-20261017/attempt-01-existing-test/evidence \
PYTHONPATH=src flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock \
python3 -m pytest -q \
  tests/integration/test_cv32e40p_opentitan_uart_controlled_error_real.py
```

结果：**exit 0，1 passed in 105.12s**。该测试在同一 Python 进程内完成
control/fault 两组及各自的 `replay_evidence_bundle`；它是历史对照，**不算**
“新进程 fresh replay 门”通过。

### 2.2 五阶段新进程真实门（核心证据）

```bash
MYFUZZ_SCENARIO_REAL=1 \
MYFUZZ_CONTROLLED_ERROR_OUTPUT=runs/p6-controlled-error-non-ibex-non-gpio-20261017/attempt-04-fresh-process/evidence \
PYTHONPATH=src flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock \
python3 -m pytest -q \
  tests/integration/test_non_ibex_non_gpio_controlled_error_real.py
```

结果：**exit 0，1 passed in 162.03s**。测试内部按顺序启动 5 个独立 OS 进程：

1. `run --group control`：真实 RTL，正常组，保存完整 bundle
2. `run --group fault`：真实 RTL，同一场景，注入一次 RDATA 响应位翻转
3. `replay --group control`：加载 bundle，新 Verilator/新会话，完整 trace 比较
4. `replay --group fault`：同上，故障组
5. `check`：不跑 RTL，仅从四份已保存 trace 重新构造 receipt 并跑新 checker

进程事实（来自 `fresh-process-report.json`）：

| phase | PID | 开始–结束 (CST) | 结果 |
|---|---:|---|---|
| control run | 6 | 15:22:48.414 – 15:23:42.755 | `[]`，静默 |
| fault run | 1334 | 15:23:43.065 – 15:24:24.697 | `['uart_rxdata_source_mismatch']` |
| control replay | 2548 | 15:24:25.329 – 15:25:07.202 | `matches=true`，`[]` |
| fault replay | 3762 | 15:25:07.500 – 15:25:36.458 | `matches=true`，`['uart_rxdata_source_mismatch']` |
| checker-only | 4976 | 15:25:36.655 – 15:25:37.207 | 四份 trace 判决与上面逐一相同 |

五个 PID 互异、父进程均为该 pytest 进程（PID 5），时间区间互不重叠；
control run 先于 fault run。replay 的 `verification_scope="full"`、
`first_difference=null`，且故障 replay 的 `_violation_evidence` 与原始故障运行**逐字段相等**：

- `rdata_delivery_event_id = 10455`
- `real_rtl_uart_rsp_sample_event_id = 10468`，`real_rtl_uart_rsp_local_tick = 1007`
- 交付/CPU 消费/RAM 数据均为 `0x5b(91)`；RTL 原始 TL-UL 响应样本仍为 `0x5a(90)`
- `intr_state_read_value = 259 = 0x103`（bit1 `rx_watermark` 置位）
- source injection event 4，源字节 `0x5a`

两组 `manifest_sha256 = b6497f9d4cbe013553d90de5d528dc171a2d58f62627ce4ea00f7c9e83851d7e`，
与 2.1 同进程运行的 `declared_identity_sha256` 逐字节相同：同一场景、同一所有权/绑定/窗口/RTL 身份，
唯一差异是那一次受控扰动。

### 2.3 纯软件 checker 复算（无 RTL）

```bash
PYTHONPATH=src python3 \
  tests/integration/non_ibex_non_gpio_controlled_error_process.py check --group fault \
  --trace control-run=.../control-bundle/trace.json \
  --trace fault-run=.../fault-bundle/trace.json \
  --trace control-replay=.../control-replay-trace.json \
  --trace fault-replay=.../fault-replay-trace.json \
  --observation .../checker-recheck-software.json
```

结果：**exit 0**；control-run `[]`、fault-run `['uart_rxdata_source_mismatch']`、
control-replay `[]`、fault-replay `['uart_rxdata_source_mismatch']`。
该进程只读 trace JSON，不创建 harness。

另：不设 `MYFUZZ_SCENARIO_REAL` 时
`PYTHONPATH=src python3 -m pytest -q tests/integration/test_non_ibex_non_gpio_controlled_error_real.py`
为 **1 skipped in 0.06s**（显式环境门），`py_compile` 通过。

---

## 3. 注入点、对照结果与不声称事项

### 3.1 注入点

- 位置：**目标和会话的寄存器读响应副本**
  （`target_register_read_response_copy`）。在测试进程内只包装该 `uart` 会话实例的
  `read_register(offset)`；`DataflowRouter` 对普通目标正是调用它。
- 机制：先调用真实方法（真实 Verilator RTL 执行并返回 `0x5a`），记录真实值，然后只把返回给总线的
  副本低字节翻转 bit0：`0x5a → 0x5b`。
- fail-closed：只有 **offset == 0x18（RDATA）** 且 **真实 RTL 返回值低字节 == 0x5a** 时才触发；
  只触发一次；否则不注入，测试会在 `fault_document is None` 处失败，不会静默通过。
- 标注：`schema_version=controlled_target_response_fault.v1`、
  `mode=uart_rdata_read_response_xor1.v1`、`calibration_only=true`、
  `rtl_internal_fault=false`、`observation_boundary=target_register_read_response_copy`、
  `injected_once=true`、`real_rtl_rdata=0x5a`、`delivered_rdata=0x5b`。
- 未修改：RTL、router、session 实现、checker、receipt、owner、evidence 格式均未改；
  包装仅存在于测试进程内的该会话实例上。

### 3.2 对照组 vs 故障组

| 观察点（两组 event 相同） | 正常组 | 故障组 |
|---|---|---|
| source injection（event 4） | `0x5a` (90) | `0x5a` (90) |
| **RTL 原始 TL-UL 响应样本 `uart_rsp_rdata`（event 10468 / uart tick 1007）** | **0x5a (90)** | **0x5a (90)** |
| `mmio_delivery.read_value`（event 10455, offset 0x18） | `0x5a` (90) | **`0x5b` (91)** |
| CPU 消费 `data_rsp_rdata`（event 10472, epoch 0 / seq 4） | `0x5a` (90) | **`0x5b` (91)** |
| ISR 写持久 RAM `0x20000` | `0x5a` (90) | **`0x5b` (91)** |
| `INTR_STATE` 读回（offset 0x00） | `0x103`（bit1 置位） | `0x103`（同） |
| IRQ 上升沿/下降沿（`uart_rx_watermark → cpu.irq`） | 真实存在 | 真实存在 |
| **checker findings** | **`[]`（静默）** | **`['uart_rxdata_source_mismatch']`** |

RTL 自身的 raw TL-UL 响应样本仍为 `0x5a`，因此可以证明：**故障由观测边界注入，
不是 RTL 内部产生了错误响应**。本次不修改 RTL，也不声称 RTL 内存在故障。

### 3.3 checker

- checker：`myfuzz.scenario.ibex_uart_online_checker.IbexUartOnlineChecker`
  （`src/myfuzz/scenario/ibex_uart_online_checker.py`，sha256
  `3a5b044d5a66802950cce87ba8ad112c6aeb91c8f993960c82a1aab8ce73ffe3`），未修改、未放宽。
- 它只引用：`uart` 的源注入字节、`device_id=uart & offset=0x18 & write=false` 的 MMIO 读、
  CPU 的 `data_rsp_*` 字段；不引用任何 Ibex 专属字段，所以原样适用于非 Ibex 的 CV32E40P。
- 第 5 个进程完全从已保存 trace 重建 receipt，再跑**新实例** checker；判决与原始运行一致。
- `IbexUartOnlineChecker` 名字中的 “Ibex” 是历史命名，不是本次链的 CPU 类型。

### 3.4 明确不声称

- 不声称 RTL 内部故障注入、不声称自然 DUT bug、不把注入故障计入自然 finding。
- 只做一个链、一个注入点、一个故障变体；未做多例持续在线会话、coverage-guided 搜索、
  多故障族灵敏度对照。
- 未修改 `third_party/`、`agent.md`、未跟踪 DMA 证据或其它代理文件。
- 本报告与本次 commit 不更新 P6 计划清单/运行能力表；那需要 root 按计划 §5 统一登记。

---

## 4. 证据路径与身份

### 4.1 已提交的紧凑证据

`docs/reports/evidence/p6-controlled-error-non-ibex-non-gpio-20261017/`

| 文件 | 内容 |
|---|---|
| `attempt-01-existing-test/` | 同进程真实门 stdout（105.12s）、exit 0、`controlled_error_report.json` |
| `attempt-04-fresh-process/` | 五阶段新进程 stdout（162.03s）、exit 0、五个进程的 observation、`fresh-process-report.json`、`witness-events.json`、四份 gzip 完整 trace、两份 gzip manifest |
| `failures/` | 保留的失败：attempt-02 驱动 import；attempt-03 测试断言类型笔误；attempt-05 并发源码漂移导致的 manifest 拒绝；attempt-12 冻结 snapshot 的 elaboration 证据失败 |
| `commands.json` | 每条实际命令、exit、结果、stdout 路径 |
| `source-identity.json` | HEAD、测试/驱动/真实链/checker/profile 的 sha256、green run 的进程/事件/tick/数据身份 |
| `sha256sums.txt` | 全部证据文件校验和（已 `sha256sum -c` 全 OK） |

### 4.2 未提交的完整原始 bundle

`runs/p6-controlled-error-non-ibex-non-gpio-20261017/attempt-04-fresh-process/evidence/fresh-process-5/`

- `control-bundle/trace.json` sha256 `2907278758892f68cc4986cecaa81ab8463757566c614b235880800764a89c90`
- `fault-bundle/trace.json` sha256 `cefecc2a6c2e71d657dc4ebd8e08e51cace2744c9a55209f46ed5fadf2efad1b`
- `control-replay-trace.json` sha256 `5ce7f6374287793969f656ff5518ebc979c89250fc77040476eb7e7770ddb715`
- `fault-replay-trace.json` sha256 `e35516686a4f7ac8f2786583258d14adc29d4fe5fc747e7d38f9d4f42e6610bf`
- `manifest_sha256 = b6497f9d…`（两组相同）

提交的 gzip 与上述未压缩 trace 一一对应；`sha256sums.txt` 记录 gzip 文件的哈希，
文件头注释记录未压缩 trace 的哈希。

### 4.3 源码身份

- base commit：`67fb73c1c7260c9d6372f43255198195acb31e2a`
- 新测试 `tests/integration/test_non_ibex_non_gpio_controlled_error_real.py`：
  `a456c1263a33bddcd88980f30252daac0025ea372bc30c6fefc601e1eaa878a9`
- 新驱动 `tests/integration/non_ibex_non_gpio_controlled_error_process.py`：
  `15cf8df4269def8a3a2ef1adfbb067ba22b9f2cb875821283adaa441c80db505`
- 既有受控错误测试：`aebfc090bd7b9294a77ff6a3821d7440fad51d636a4f255292ae3a0190f312b2`
- 真实链测试：`236358adb47101cead0a49245dd190060d74bef656a67f6a3ad83eb8a8e59c32`
- checker：`3a5b044d…`（见 3.3）
- CPU/UART profile：`21d04c8a…` / `759f8647…`

上述测试/驱动的 sha256 与 attempt-04 通过时使用的版本**完全一致**；
attempt-04 之后没有对这两个文件做功能性修改。

---

## 5. 失败历史与源码漂移（不冒充通过）

| attempt | exit | 结果 | 说明 |
|---|---:|---|---|
| `attempt-01-existing-test` | 0 | 1 passed / 105.12s | 既有同进程真实门，历史对照 |
| `attempt-02-fresh-process` | 1 | 未进 RTL | 驱动 sibling import 名写错（`test_...` vs `test_scenario_...`），保留 |
| `attempt-03-pre-fix` | 1 | 1 failed / 121.44s | 五阶段均跑完；失败原因是测试断言把 `str` 与 `list` 比较，已修 |
| **`attempt-04-fresh-process`** | **0** | **1 passed / 162.03s** | **五阶段新进程真实门，本报告核心证据** |
| `attempt-05-final` | 1 | 1 failed / 105.99s | 运行期间 sibling 修改 `src/myfuzz/scenario/compiled_paths.py`，control replay 正确拒绝 `replay manifest identity mismatch`；不是产品失败，也不能算通过 |
| `attempt-06`–`attempt-11` | 1 | 未进 RTL / snapshot 构造失败 | 为隔离并发源码漂移而构建 HEAD 物化快照；依次遇到 external_designs 缺失、symlink、submodule git 身份、third_party 路径等问题，保留在 `runs/` |
| `attempt-12-frozen-head-snapshot` | 1 | 2 failed / 4.18s | 快照无 `.git` 跟踪元数据，`configs/soc/closures/cv32e40p.json` 被 source-lock 判为 untracked；未启动 RTL |
| **`attempt-13-frozen`** | **0** | **1 passed / 127.97s** | **源码冻结后的五阶段新进程复跑（HEAD d24da4d）；与 attempt-04 同测试/驱动 SHA，五 PID 顺序执行，control/fault 及两条 full replay 与 checker-only 全通过** |

**结论边界：** attempt-04（162.03s）与 attempt-13-frozen（127.97s）都是真实、独立进程、
完整 RTL 的运行；attempt-13 在 `d24da4d` 上重跑并通过，测试/驱动 SHA 与 attempt-04 完全一致。
attempt-05–12 的并发漂移/快照失败保留为失败历史，不计为通过。
`attempt-13-frozen.tar.gz` 收录 `fresh-process-6/` 五阶段日志、报告、checker 与两条完整 trace
（sha256 `b64a4ebd…ae875`），因此本项的证据链已绑定到冻结源码与可复现命令。
