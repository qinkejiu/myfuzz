# P5 同条件 trace 容器对照：JSONL vs zlib 分块

日期：2026-10-08。P5 的缺口之一是"同条件 JSONL/故障质量对照"，且 P5 效率项要求"仍保留完整可重放日志"。本报告在同一冻结源码、同一 seed、同一预算、同一组件身份与同一组探针下，只切换 trace 容器（`jsonl.v1` vs `zlib_chunks.v1`）做真实 RTL 对照，并用 fresh replay 证明两种容器都可独立重放。

## 两次运行

```bash
BIN=third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
for mode in jsonl zlib; do
  extra=""; [ "$mode" = zlib ] && extra="--compressed-trace"
  python3 scripts/run_ibex_pulp_online.py run --client-binary $BIN \
    --cache-dir runs/p5-format-cache-20261007 \
    --output runs/p5-format2-$mode-20261007-online \
    --seconds 120 --max-tests 120 --seed 20261007 --run-id p5-format2-$mode-20261007 \
    --cpu-retirement --native-irq-receipts --gpio-consumption $extra
done
PYTHONPATH=src python3 runs/current-dataflow-p5-final-20261007-logs/p5_trace_format_compare.py \
  --jsonl runs/p5-format2-jsonl-20261007-online --zlib runs/p5-format2-zlib-20261007-online \
  --write runs/current-dataflow-p5-final-20261007-logs/p5_trace_format_compare_v2.json   # exit 0
```

| 量 | JSONL | zlib 分块 |
|---|---:|---:|
| 例数（statuses） | 77（75 complete／2 input_invalid） | 81（79 complete／2 input_invalid） |
| 有效搜索秒 | 120.716374 | 120.467550 |
| trace 字节 | 493,194,248 | 36,903,052 |
| 事件数（容器声明） | 108,113 | 114,309 |
| trace 写入秒 | 20.744583 | 9.146172 |
| 终结总秒（`finalization_timing_seconds.total_before_report`） | 24.610933 | 13.469331 |

## 判定（`p5_trace_format_comparison.v1`，全部为真）

1. `same_decoder_identity`：两枝 `decoder_manifest.json` 摘要相同。
2. `shared_input_prefix_nonempty` + `shared_prefix_fields_equal`：**77/77** 个共享前缀例的逐例字段完全相同（`status`、`effective_genome_sha256`、`path_id`、`applied_sources`、`applied_source_ids`、`violations`、`coverage_hex`、`local_ticks`、`semantic_sha256`、`source_selection_reason`、`candidate_id`），0 处不一致。
3. `event_streams_identical_before_divergence`：逐事件比对后，**108,113** 个前导事件逐字节相同，且该数**正好等于 JSONL 枝声明的完整事件数**（`difference_kind=shorter_arm_complete_event_prefix`、`identical_prefix_is_a_complete_declared_stream=true`）——即较短那一枝的**整条**事件流是另一枝事件流的精确前缀，差异只来自 zlib 枝在墙钟预算内多跑完的那几例（77 → 81）。
4. `semantic_digest_recomputed_matches_recorded`：两种容器各自的规范化语义摘要由**各自容器**重新流式读取后重算，均等于其记录值（`declared_semantic_sha256`）。
5. `containers_differ`：容器类型确实不同；字节比 **0.074825**（zlib ≈ JSONL 的 7.5%，约 13.4× 更小），终结总耗时少 **11.14 秒**。

## fresh replay（两种容器各自独立重放）

```bash
python3 scripts/run_ibex_pulp_online.py replay --cache-dir runs/p5-format2-jsonl-replay-cache-20261007 \
  --plan runs/p5-format2-jsonl-20261007-online/online_plan.json \
  --trace runs/p5-format2-jsonl-20261007-online/online_final_trace.meta.json   # matches=true
python3 scripts/run_ibex_pulp_online.py replay --cache-dir runs/p5-format2-zlib-replay-cache-20261007 \
  --plan runs/p5-format2-zlib-20261007-online/online_plan.json \
  --trace runs/p5-format2-zlib-20261007-online/online_final_trace.meta.json   # matches=true
```

两枝都对新起的独立 RTL 进程重放成功（`{"matches": true, "first_difference": null}`）；JSONL 枝通过 `JsonlEventView`、zlib 枝通过 `ZlibChunkEventView`（并校验其自身语义摘要）读出。

## 结论与限制

**结论**：在同一条件下，zlib 分块容器**不改变任何事件**（较短枝的 108,113 条事件是另一枝的完整前缀，77/77 例逐字段相同，两种容器的语义摘要都自洽），同时把 trace 体积降到约 1/13.4、把终结写入耗时从 20.74 秒降到 9.15 秒（终结总耗时少 11.14 秒），并且两种容器都能独立 fresh replay。

**限制（不得外推）**：

- 两枝例数不同（77 vs 81）是**墙钟预算逐运行生效**的结果；所有断言都限定在共享输入前缀与"较短枝为完整事件前缀"这一形状上，不是两枝全量等价。
- 本报告不比较搜索质量（覆盖/完整链/缺陷），只比较容器语义与写入成本；不含故障质量对照。
- 结论只属于本 seed、本负载、本次 120 秒窗口；JSONL 枝的 493 MB 未压缩 trace 是本对照的对照物，不代表推荐默认。
- 更早一次（冻结窗口之前）的同名两枝运行（75/76 例）其 JSONL 枝 replay 被 shipped 解码空间身份守卫拒绝（期间有并发源码编辑），因此本报告改用冻结源码重录的两枝；那条拒绝按设计工作，不是缺陷。
- `p5_trace_format_compare.py` 只读已保存产物；它不重跑 RTL，"可重放"结论由上面的独立 replay 命令给出。
