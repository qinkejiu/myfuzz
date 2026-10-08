# P4 闭环能量接入 live 选源的真实 A/B 对照

日期：2026-10-07。P4 要求"根据新目标、新传播边和失败证据分配后续 mutation energy"且"同一条跨例链的增量反馈至少一次改变后续选源/能量"。本报告把[闭环反馈消费者](../CODE_ORGANIZATION.md)真正接入在线选源后，做同 seed、同预算、同组件身份的真实 A/B 对照。

## 开关与运行

闭环能量由 `MYFUZZ_CLOSED_LOOP_ENERGY`（构造参数 `closed_loop_energy`）控制，默认关闭时 `_online_weights()` 与改动前逐值一致。两次运行除该环境变量外完全相同：

```bash
CACHE=runs/current-dataflow-p5-final-20261007-cache
BIN=third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
MYFUZZ_CLOSED_LOOP_ENERGY=1 python3 scripts/run_ibex_pulp_online.py run --client-binary $BIN \
  --cache-dir $CACHE --output runs/current-dataflow-p4-closed-loop-on-20261007-online \
  --seconds 60 --max-tests 48 --seed 20261007 --run-id current-dataflow-p4-closed-loop-on-20261007 \
  --cpu-retirement --native-irq-receipts --gpio-consumption          # ON
# 同命令去掉环境变量 → runs/current-dataflow-p4-closed-loop-off-20261007-online   # OFF
```

两次均退出码 0、全部 `complete`（ON 35 例 / 61.062 秒；OFF 41 例 / 61.081 秒）。

## 结果

| 量 | ON（闭环能量） | OFF（默认） |
|---|---:|---:|
| `closed_loop_enabled`（report） | true | false |
| 证书消费（`certificate_count` 累计） | 33 | 0 |
| 闭环命中（`closed_loop_count`） | **7** | 0 |
| 部分传播／阶段到达 | 0 / 26 | 0 / 0 |
| 选源分布 `cpu.online_instruction` | 18 / 35 = 51.4% | 16 / 41 = 39.0% |
| 选源分布 `gpio_b.external_pin8` | 17 / 35 = 48.6% | 25 / 41 = 61.0% |
| 选源原因 direct / feedback-weighted | 18 / 17 | 16 / 25 |
| 例数（同 60 秒预算） | 35 | 41 |

逐例选源序列在第 2 例（0 基）首次分歧；两枝的 raw 输入序列**不相同**（分歧后 RFuzz 反馈随之分叉）。

## 结论与限制

**结论**：闭环反馈确实进入了 live 选源路径——ON 运行在报告与回执里带 `closed_loop_count=7`（由 33 张真实链证书结算），选源分布相对 OFF 向 CPU 指令源偏移（39.0% → 51.4%），且逐例选择序列从第 2 例起分叉。

**限制（不得外推）**：
- 两枝 raw 输入在第 2 例后不同，因此这是**搜索过程对照**，不是逐例因果证明；单例因果已由[同前缀反馈因果对照](current-dataflow-p4-feedback-causal-branch-20261007.md)在相同 raw 下给出。
- ON 在**相同墙钟预算**内完成例数更少（35 对 41，约 −15%），即闭环证书消费有真实开销；本报告不声称吞吐提升。
- 选源分布偏移的方向与幅度只属于本 seed、本负载、本 60 秒窗口。
- 本次未对两枝各做独立 fresh replay；闭环能量是运行态开关，不进入 manifest 身份闭包（同一 plan 两枝都可回放），但本报告没有声称回放结论。
- 未发现自然 RTL 缺陷；ON/OFF 两枝 checker violation 均为空。
