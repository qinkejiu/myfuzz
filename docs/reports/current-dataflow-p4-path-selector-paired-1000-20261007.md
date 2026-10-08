# P4 路径选择器同源码、同例数真实对照

日期：2026-10-07。目标是检验固定 RFuzz 路径字节下，全量 raw 混合是否改变真实搜索分布及下游观测。两组均以 `myfuzz_snapshot_p4_path_mix_20261007` 为基底，旧组的实验副本 `/home/qinkejiu/myfuzz_snapshot_p4_old_selector_20261007` **只**将 `online_case_decoder.py` 的域分离 SHA-256 路径选择语句换回旧版 `int.from_bytes(raw[1:8] + raw[:1], "little") % sum(path_weights)`。`src/` 目录逐文件比较仅该文件不同；旧组 2,749 个核心文件的 [SHA-256 清单](../../runs/current-dataflow-p4-old-selector-1000-snapshot-20261007.sha256)自身哈希为 `10d1e3f4800b86d1af38a863b96032aa817efa289e7953c82f3ebcb90b4143e0`，运行前清单校验通过。新组源码及原门禁见[路径熵报告](current-dataflow-p4-path-entropy-real-gate-20261007.md)。

两组均使用 Ibex＋双 PULP GPIO、相同真实 RTL/profile、RFuzz seed `20261007`、`--max-tests 1000 --seconds 120` 与默认 checker；各 1,000 例均为 `complete`、0 checker 错误。旧组命令：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p4_old_selector_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-old-selector-1000-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-old-selector-1000-online \
  --seconds 120 --max-tests 1000 --seed 20261007 \
  --run-id current-dataflow-p4-old-selector-1000-20261007
```

| 指标 | 旧选择器 | 新选择器 |
|---|---:|---:|
| complete 例数 | 1,000 | 1,000 |
| 有效搜索秒 | 99.084 | 103.314 |
| F4 CPU／F5 GPIO 选路 | 745／255 | 491／509 |
| 4 个本地目标位的并集 | 4 | 4 |
| 新交互特征种类 | 20 | 20 |
| CPU／GPIO 来源增益 | 3／4 | 3／4 |
| `irq_taken:gpio_b:cpu` 累计增量 | 270 | 346 |
| `observed_path:irq_taken_read_then_write` 累计增量 | 133 | 170 |
| 真实 trace 事件数 | 362,858 | 379,209 |

逐例回执汇总保存为[对照 JSON](../../runs/current-dataflow-p4-selector-comparison-1000-20261007.json)，包含所有交互 stage 的累计值、flow/source、目标位并集和特征集合。两组输入在相同 case 序号上只有 41 个 raw hash 相等，全集有 176 个 raw hash 重合；路径决策改变后，反馈驱动的 RFuzz 输入也分叉。因此这是相同代码基底、种子和案例预算下的搜索过程对照，不能把每个累计事件差值解释为单条输入的直接因果效应。`irq_taken` 与 `observed_path` 计数可重复、可跨逻辑 case，不能计作独立完整传播链或 RTL 内部分支覆盖。**本对照证明选择分布更均衡且下游 IRQ 观测次数增加；没有证明目标覆盖位或交互特征种类增加。**

旧组在独立缓存执行完整 fresh replay：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p4_old_selector_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-old-selector-1000-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-old-selector-1000-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-old-selector-1000-online/online_final_trace.meta.json
```

退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`；全量核对旧组 362,858 条 JSONL 事件及 local ticks。运行和重放后再次执行旧组源码清单 `sha256sum -c --quiet`，退出码 0，零差异。新组的独立完整 fresh replay 和运行后零差异检查见原[路径熵报告](current-dataflow-p4-path-entropy-real-gate-20261007.md)。这完成同例数真实对照的证据封口；P4 整阶段仍缺通用变异、真实拒绝/不确定例以及覆盖搜索验收。
