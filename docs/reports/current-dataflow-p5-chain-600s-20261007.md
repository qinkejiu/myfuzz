# P5 十分钟全探针门禁：严格完整链/s 与 IRQ serial token

日期：2026-10-07。本报告把["31 秒有界验收"](current-dataflow-p5-chain-acceptance-20261007.md)升级到**十分钟口径**，并在同一次真实运行上同时复算两类证书：增量完整链证书（`runtime_chain_certificate.v1`）与 IRQ serial 精确来源证书（`irq_serial_certificate.v1`）。

## 运行

```bash
cd /home/qinkejiu/myfuzz
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/current-dataflow-p5-final-20261007-cache \
  --output runs/current-dataflow-p5-chain-600s-20261007-online \
  --seconds 600 --max-tests 100000 --seed 20261007 \
  --run-id current-dataflow-p5-chain-600s-20261007 \
  --cpu-retirement --native-irq-receipts --gpio-consumption --compressed-trace
```

退出码 0：`{"tests": 368, "statuses": {"complete": 368}, "effective_search_seconds": 600.3629527319999, "elapsed_seconds": 601.4723930119999}`。运行身份 `online_run_identity_sha256 = 4a86c7dfb6207cde76916b64198cc197de9625b302cddd8d679eb3db99b4a205`（见 `report.json`，`execution_status = complete`），decoder manifest `b68042f0a0cbd76918d4066108a93b987a4d6de37261af50fa2d4941908fff84`（与有界验收运行一致）。证据：`online_events.zlib` 172,324,767 字节、570,196 条事件，声明 `semantic_sha256 = 359f4e59c609b544b7280b3b89b61a1883571c6ba331cf5d740f257c34a7fef1`，流式重算一致（`semantic_sha256_verified = true`）。

## 结果（十分钟口径）

| 指标 | 实测值 |
|---|---:|
| complete 例 | 368/368 |
| 有效搜索秒 | 600.362953 |
| 例/s | 0.612963 |
| **认证链总数** | **27**（CPU→IP→CPU 20；IP→CPU→IP 7） |
| **严格认证链/s** | **0.044973** |
| 同例／跨例完成 | 21 / 6 |
| incomplete 证书 | 341（首个缺口：`instruction_fetch` 137、`pin8_injection` 184、`retired_target_delivery` 20） |
| 唯一链签名 | 2（0.003331/s） |
| 本地目标位首次命中 | 4/4（0.006663 位/s） |
| 见证运行时边（唯一/观测） | 9 / 26,990（0.014991 边/s） |
| **IRQ serial 精确证书** | **68 条**（全部 `decision_serial == retirement_serial != 0`） |
| 无效/超时例比例 | 0.0 |
| 证据终结 | 67.786835 秒（trace 写 48.051、session_finish 19.334、identity 0.300、plan 0.003） |

流式分析（`scripts/run_first_step_acceptance.py analyze`）wall 55.19 秒、峰值 RSS 58.4 MB（输入为 172 MB 压缩 trace 的 57 万条事件，逐块解压 + 逐行解析，未整文件加载）。serial 证书由 `IrqSerialCertificates` 在保存 trace 上独立复算，输出 `runs/current-dataflow-p5-final-20261007-logs/chain_600s_serial_certificates.json`。

**链/s 比 31 秒短跑低（0.0450 对 0.2558）**：短跑的前若干例正好覆盖了链路必需的中断/ISR 场景，而长跑中大量选源是指令写路径与未被原生 IRQ cause 采纳的 pin 注入（首缺口计数 `instruction_fetch` 137 / `pin8_injection` 184 / `retired_target_delivery` 20 说明证据缺口分布）。这不是 DUT 链率下降，而是**本负载下证书产出率**的实测差异；两个数字各自只属于自己的运行窗口。

## fresh replay

```bash
python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir runs/current-dataflow-p5-chain-600s-20261007-replay-cache \
  --plan runs/current-dataflow-p5-chain-600s-20261007-online/online_plan.json \
  --trace runs/current-dataflow-p5-chain-600s-20261007-online/online_final_trace.meta.json
```

退出码 0，`matches = true`、`first_difference = null`、`difference_context = null`：新进程在新缓存中重建真实 Ibex＋双 PULP GPIO RTL，重放全部 368 例、570,196 条事件与 local ticks 完全一致。

## 证书语义（不得外推）

- 链证书仍是"每条 `fuzz_source` admission 至多一张"：`hops` 为已认证前缀，`missing_hops` 为第一个未见证跳及其后全部必需跳。`IP_TO_CPU_TO_IP` 终点为 ISR 读 GPIO B `PADIN` 并退休（17 跳），`CPU_TO_IP_TO_CPU` 终点为该指令写 GPIO A 的退休交付（13 跳）；两者都**不包含** ISR 后续写 GPIO A、A→B 绑定回流与第二次中断。
- serial 证书只证明 `外部 IRQ 决策 → RVFI 退休` 的同流水级硬件 token 相等；`not_proof_of` 显式列出事件相邻、指令来源、操作数/FIFO 污点、完整传播链、handler 入口或 ISR 效果。两类证书目前是**并行**产物，尚未在链证书里合并为单一跳。

## 限制

- 本运行是**负载特定**的一次十分钟门禁：默认 Ibex＋双 PULP GPIO 场景、seed `20261007`；不同外设或不同 RFuzz 负载需要重跑。
- 未做同条件 JSONL/压缩对照、未做故障质量对照；`router_transact` 未在本负载触发。
- 新颖率覆盖整个扫描窗口（回执与证书无逐例完成时间戳），不能重建按秒曲线。
- 分析器只统计 producer 发出的证书，不独立重推 hop 证据（hop 级正确性由冻结 fixture 的逐字段断言保证）。
- 本次未发现自然 RTL 缺陷。

## 复现材料

`runs/current-dataflow-p5-chain-600s-20261007-online/`（plan、zlib trace、identity、receipts、session manifest）、`...-replay-cache/`、日志与报告在 `runs/current-dataflow-p5-final-20261007-logs/`（`chain_600s_run.log`、`chain_600s_acceptance.json/.md/.time`、`chain_600s_replay.log`、`chain_600s_serial_certificates.json`）。
