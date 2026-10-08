# P4 路径、源与操作子候选身份：冻结源码真实短门禁

日期：2026-10-07。在线决策与 RFuzz 回执新增 `operator_id` 和 `candidate_id`。CPU 指令按实际解码后的 RV32I 操作序列标识（例如 `rv32i:XORI`）；外部输入事件标识为 `external_event`。候选 ID 是方向、flow、路径、目标、源与操作子身份的规范 JSON 的 SHA-256 摘要，不含原始输入字节或 testcase 编号；同一类候选可跨例聚合，实际字节仍保存在原回执中。TDD 覆盖相同路径和来源下 ADDI/XORI 候选不同，相关聚焦组合共 **91 passed、2 subtests passed**，包括新的 pin8 证书与相邻 GPIO 检查。

## 源码身份与真实运行

独立快照 `/home/qinkejiu/myfuzz_snapshot_p4_candidate_20261007` 的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 1,808 文件见 [SHA-256 清单](../../runs/current-dataflow-p4-candidate-snapshot-20261007.sha256)，清单哈希为 `e43899d1e2f3b43076ad0e7ff718705796ae58fb0f1d64163fea6754215dacbe`。在线身份列出的 36 个源码文件逐项匹配快照，清单复核 0 差异。

在快照中执行：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-candidate-20261007-online \
  --seconds 30 --max-tests 25 --seed 20261007 \
  --run-id current-dataflow-p4-candidate-20261007
```

退出码 0；25/25 例 `complete`，有效搜索 1.991 秒，完整 trace 10,390 事件。25 份[回执](../../runs/current-dataflow-p4-candidate-20261007-online/receipts.jsonl)中有 6 个不同候选身份，包括 3 例 `rv32i:XORI`；独立按回执六字段规范化并计算 SHA-256，**25/25** 个 ID 均一致。操作子分布为 NOP 4、LUI+ADDI+LUI+SW 2、LUI+LW 2、XORI 3、LUI 1、外部输入 13。候选种类数不是新覆盖或完整传播链数。

同一冻结快照用独立 cache 从保存的 plan 与完整 trace 做 fresh replay：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-candidate-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-candidate-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-candidate-20261007-online/online_final_trace.json
```

重放退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`。本次未启用 CPU RVFI/GPIO 消费探针，故只验证真实在线选择、回执身份与原有完整语义 replay；XORI 真实退休证据见[单独门禁](current-dataflow-p4-xori-retirement-real-gate-20261007.md)。候选身份尚未包含采用/拒绝原因，也未证明反馈推动了同预算下更高的真实覆盖或传播链率，P4 仍未整阶段验收。
