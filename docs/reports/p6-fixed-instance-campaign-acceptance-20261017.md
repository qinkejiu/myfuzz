# P6 固定实例多协议 campaign 验收记录（2026-10-17）

本记录汇总 P6 五行（OBI / 完整 AXI4 / AXI4-Lite / classic Wishbone / Pico native Ready/Valid）
在当前源码上的真实 RTL campaign 与独立保存产物审计，以及“非 Ibex＋非 GPIO”受控错误负例。
**结论：固定实例 campaign 范围已闭合；`fresh_genomes`（每例独立 RTL harness）是本记录的明确边界。**
若把 P6 的“多例持续会话”按单一持久 harness 解释，行 2–5 仍未满足，见 §5。

## 1. 实际结果

| 行 | CPU / IP | 证据 | 关键计数 | 保存产物审计 |
|---|---|---|---|---|
| 1 | CV32E40P / PULP GPIO | `runs/cv32e40p-pulp-online-20261014` | 200 例、`statuses={complete:200}`、`online_cases`、13 次反馈/14 次 hint | `test_cv32e40p_pulp_online_saved_run_audit.py` **10 passed** |
| 2 | CVA6 / 双 OpenTitan GPIO | `runs/scenario/campaign-cva6-g4-18cell-p6-row2-20261017-current` | 18/18 cell、`effective=1323.83≥1080`、1226 例、406 完整链、30 corpus、30/30 replay；双侧源 `cpu.program/cpu.isr` 与 `b.pin8/b.pin9` 均 measured | `test_cva6_campaign_saved_run_audit.py` **10 passed** |
| 3 | Pico AXI4-Lite / ZipCPU AXI4-Lite UART | `runs/scenario/campaign-axil-g4-18cell-p6-row3-20261017-current` | 18/18、`effective=2123.20≥1080`、714 例、300 完整链、54 corpus、54/54 replay；双侧源 `cpu.tx_byte/uart0.rx_frame` | `test_axil_campaign_saved_run_audit.py` **10 passed** |
| 4 | Pico Wishbone（ENABLE_IRQ=1）/ 双 OpenTitan GPIO | `runs/scenario/campaign-pico-wb-g4-18cell-p6-row4-20261017` | 18/18、`effective=3767.47≥3600`、1615 例、871 完整两轮链、36 corpus、36/36 replay；双侧源 `cpu.program/b.pin9` | `test_scenario_picorv32_wb_campaign.py` **21 passed, 2 skipped** |
| 5 | Pico native Ready/Valid / PULP APB3 GPIO | `runs/scenario/campaign-pico-native-g4-18cell-p6-row5-20261017` | 18/18、`effective=2862.57≥2700`、1711 例、1141 完整两轮链、30 corpus、30/30 replay；双侧源 `cpu.padout_byte/gpio0.pin_byte` | provider identity sidecar 后 **24 passed, 2 skipped**；saved-run audit **9 passed** |
| 附加 | CV32E40P / OpenTitan UART（非 Ibex、非 GPIO） | `docs/reports/evidence/p6-controlled-error-non-ibex-non-gpio-20261017/attempt-13-frozen.tar.gz` | 五进程 control→fault→control replay→fault replay→checker-only；**1 passed / 127.97s**；control `[]`，fault `uart_rxdata_source_mismatch`；两条 replay `full/matches=true` | `attempt-13-frozen.meta.json` 绑定 HEAD `d24da4d`、test/driver SHA、PIDs、archive SHA |

所有 campaign 均为真实 pinned RTL：每个 receipt 的 `local_ticks` 组件集合/值正确且 >0，单格一个
`manifest_sha256`，18 格 `live/run_identity` 为 `validated_envelope`；corpus 文件数 = report 条目数 =
replay total，`matched_entries==total_entries`，`error=null`。没有 `environment_error/uncertain_effect`。

行 4 的 5 条 incomplete assessment（4 格）是合法搜索结果：`completed_chains` 只计
`complete=true && rounds==2`，因此 871 = 876−5；审计在 `d24da4d` 修正为同一口径，未放宽。
行 5 的 provider identity sidecar 由
`python3 -m myfuzz.integration.picorv32_native_scenario_campaign <run_dir>` 生成，绑定 `ac5f564`。

## 2. 独立审计

- P6 逐行只读审计：`.superpowers/sdd/p6-independent-acceptance-audit.md`。
- 行 4/5 campaign 归档：`docs/reports/evidence/p6-campaigns-20261017/`，含完整 run tar.gz、
  `manifest.json`（gate/effective/provider/fixture/archive/report/run-identity SHA）、
  `CAMPAIGN_EVIDENCE.md`。
- 行 2/3 当前源码复跑：`…-20261017-current`；saved-run audit 各自 10 passed。
- 受控错误：`attempt-13-frozen.tar.gz` + meta；`sha256sum` 校验通过。

## 3. 复跑命令

```bash
# 行 2
PYTHONPATH=src python3 scripts/run_scenario_campaign.py \
  --manifest configs/scenario/cva6_cpu_two_gpio_campaign_seed.json \
  --baseline-manifest configs/scenario/cva6_two_gpio_campaign_baseline.json \
  --seconds 60 --seed 20260927 \
  --output runs/scenario/campaign-cva6-g4-18cell-p6-row2-20261017-current \
  --provider myfuzz.integration.cva6_scenario_campaign:Cva6TwoGpioBoundProvider

# 行 3
PYTHONPATH=src python3 scripts/run_scenario_campaign.py \
  --manifest configs/scenario/axil_picorv32_uart_campaign_seed.json \
  --baseline-manifest configs/scenario/axil_picorv32_uart_campaign_baseline.json \
  --seconds 60 --seed 20260927 \
  --output runs/scenario/campaign-axil-g4-18cell-p6-row3-20261017-current \
  --provider myfuzz.integration.axil_scenario_campaign:AxilUartCpuBoundProvider

# 行 4/5 命令见各自报告与 docs/reports/evidence/p6-campaigns-20261017/CAMPAIGN_EVIDENCE.md
```

审计（默认已指向当前 bundle）：

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_cv32e40p_pulp_online_saved_run_audit.py \
  tests/integration/test_cva6_campaign_saved_run_audit.py \
  tests/integration/test_axil_campaign_saved_run_audit.py \
  tests/integration/test_scenario_picorv32_wb_campaign.py \
  tests/integration/test_picorv32_native_campaign_saved_run_audit.py \
  tests/integration/test_non_ibex_non_gpio_controlled_error_real.py
# 59 passed, 4 skipped（native/controlled opt-in 按环境跳过）
```

## 4. 已覆盖与未覆盖

**已覆盖：** 五类 CPU 协议各有真实 CPU+RTL IP 组合；每行双向路径；行 1/3/4 的真实 IRQ→CPU
handler；每行多例搜索/反馈/断言/完整 replay；行 4 保留 Pico `getq/maskirq/retirq` custom0 ABI；
行 5 真实 queued MMIO（6/6 delivery 在 device 自己 step）；非 Ibex+非 GPIO 受控错误捕获与
新进程 fresh replay。

**未覆盖 / 明确不声称：**

1. **`fresh_genomes`**：行 2–5 的 72/72 cell 都是每例新建 RTL harness；只有行 1 是
   `online_cases` 单一持久会话。若 P6 的“多例持续会话”必须按持久 harness 解释，行 2–5 仍不满足。
2. `runtime_path_status=legacy_unchecked`；未对每行做 `RuntimePathContract` 逐边来源预检。
3. `closed_loop_energy.enabled=false`、`path_switch.enabled=false`；反馈只到 mutation-hint 通道，
   未声称 P5 的四类命名命中族。
4. 行 4 只覆盖 OpenTitan GPIO，未覆盖 ZipCPU wbuart/Timer；行 5 profile 无中断端点
   （`ENABLE_IRQ=0`），不合成 IRQ。
5. campaign 是固定实例组合；不构成任意同协议 CPU/IP 自动接入（P7）或 DMA 路径（P8）。
6. 行 4 campaign 的 provider 源码 pin 在逐格 `run_identity.checker.source` 与归档 manifest；
   campaign report 本身不自包含 provider pin。该缺口已用归档 manifest + commit 补足，
   未重跑；若验收方要求 report 自包含，需重跑。
7. P6 的“受控错误”只有一条链、一个注入点、一个故障变体；不代表一般故障族。

## 5. 结论

**固定实例 campaign 范围：通过（附上列边界）。** 这不等于：
持久 harness 的多例会话、RuntimePathContract 逐边来源、四类闭环命中、P7 自动接入或 P8 DMA。
若验收方要求持久 harness 字面项，本记录不满足，需要新的持久会话实现与重跑。
