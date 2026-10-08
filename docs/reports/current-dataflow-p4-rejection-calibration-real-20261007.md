# P4 真实拒绝与不确定例门禁（定向校准运行）

日期：2026-10-07。P4 长期缺口之一是"**真实拒绝／不确定例**尚未验收"：此前 368 例真实运行的 368 条回执全部 `admitted`、`rejection` 全为 null，`candidate_rejection.v1` 的 35 个码只有软件负例。本报告用**受信声明驱动**的定向校准运行，在真实 RTL 会话中产生 7 类结构化拒绝与 1 类不确定，并逐项复算。

## 运行

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_pulp_rejection_calibration.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/current-dataflow-p5-final-20261007-cache \
  --output runs/current-dataflow-p4-rejection-calibration-20261007-online \
  --run-id current-dataflow-p4-rejection-calibration-20261007 \
  --seconds 300 --max-tests 64 --seed 4711
```

退出码 0，`calibration_complete = true`、`calibration_unsatisfied = []`。真实回执 14 条：`{"complete": 6, "input_invalid": 7, "uncertain_effect": 1}`，`effective_search_seconds = 0.616555`（校准计划按设计在不确定例处提前结束）。

## 实测拒绝码与失败指针

7 条 `input_invalid` 回执各带一个精确 `rejection` 文档（`schema_version="candidate_rejection.v1"`，含 `code`、`pointer`、规范化 `detail`）：

| 校准类 | 实测 `code` | 实测 `pointer` | 受信制造手段 |
|---|---|---|---|
| decode_unbounded_input | `decode.unbounded_input` | `input.raw` | 校准实例把输入上界声明为 1 字节（dispatcher 仍为 8，executor 不变量不变） |
| budget_exhausted | `budget.exhausted` | `instruction.cursor` | 仅声明 CPU 指令源且预留游标已到 `instruction_end` |
| mmio_window_denied | `mmio.window_denied` | `mmio.operation` | 窗口声明为可读不可写，只允许 `SW` |
| mmio_bad_width | `mmio.bad_width` | `mmio.width` | 窗口可写但 `write_widths=(1,)`，只允许 4 字节 `SW` |
| mmio_no_aligned_address | `mmio.no_aligned_address` | `mmio.windows` | 窗口 `size=1` 却声明 4 字节写 |
| ownership_bound_input | `ownership.bound_input` | `source.port` | 构造后把外部 PADIN 源替换为 bound owner |
| ownership_fixed_input | `ownership.fixed_input` | `source.port` | 构造后替换为 fixed owner |

不确定例：`candidate_disposition="uncertain"`、`candidate_disposition_reason="rtl_submit_failed_or_partial"`、`rejection = null`、`status = "uncertain_effect"`（指令预留声明越过在线 slot 区，解码通过但真实 session 内存模型拒绝提交）。

所有 7 条拒绝都发生在**任何 RTL 命令之前**：测试断言 runner 事件数、local ticks、`session.cases`、harness accept 计数与 cursor/sequence 全部不变；每类的受信配置（含被替换的 ownership 与 `ownership_replaced_after_construction: true`）写入 `decoder_manifest.json["rejection_calibration"]` 与 `rejection_calibration.json`。**没有 RTL 改动、没有事件伪造、没有回执注入。**

## 独立复算（两条互不依赖的路径）

```bash
PYTHONPATH=src python3 scripts/run_ibex_pulp_rejection_calibration.py verify \
  --output runs/current-dataflow-p4-rejection-calibration-20261007-online
# exit 0：{"complete": true, "manifest_plan_matches_report": true, "matches": true,
#  "receipts": {"by_code": {...7 类各 1...}, "by_status": {"complete": 6, "input_invalid": 7,
#  "uncertain_effect": 1}, "structured_rejections": 7, "total": 14, "uncertain_receipts": 1},
#  "unsatisfied": []}
```

以及对 `receipts.jsonl` 的直接复算（`Counter(rejection.code)` 与 `(code, pointer)` 去重集合）与 `verify` 完全一致。

## 限制

- 覆盖 35 码中的 **7 个**：`isa.disallowed_operation`、`mmio.out_of_window` 等分支在在线解码路径不可达（此前已由 12,288 次决策空间扫描机器证明），因此本报告只授予这 7 类**真实回执级**证据。
- `decode.unbounded_input` 依赖校准实例**故意收紧**的输入上界（1 字节）；发车 profile 仍是 8 字节单记录，所以这是校准声明，不是生产配置。
- 三个 mmio 类依赖客户端 stage 内决策扫描（软件已镜像证明每类 ≤4 slot 必中；真实运行由 `verify` 与逐类计数裁决，未命中即退出码 3）。
- 运行窗口仅 0.617 秒（校准在不确定例处停止），不是长会话；`uncertain` 语义只证明"提交失败/部分执行"，不代表 DUT 缺陷。
