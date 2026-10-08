# P5 同冻结源码十例逐例冷启动对照

日期：2026-10-07。为量化持续在线会话所避免的重复初始化，本次在[P5 十分钟压缩运行](current-dataflow-p5-runner-zlib-600s-20261007.md)的同一冻结源码 `/home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007` 上，取该运行前十条 `receipts.jsonl` 的精确八字节输入与当时保存的在线权重，每条分别新建 Ibex＋双 PULP GPIO runtime。该对照测量启动成本；每条冷启动输入的前置硬件状态都不同于原持续会话，不能用它证明覆盖、传播链或故障质量等价。

源码清单为 [snapshot.sha256](../../runs/p5-runner-zlib-600s-20261007/snapshot.sha256)，清单 SHA-256 `ee6191e8f5344f260d2ce17a51f5e6cd2f711bd3562decfe7d657eede49100bd`。对照前后在快照根目录执行 `sha256sum -c --quiet` 均退出 0。输入回执文件 SHA-256 为 `8ee86ee2273d80e629a55f73871827bbe1e8a56ee1fe7093f264d2ed08310977`。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007
/usr/bin/time -f 'cold10_wall_seconds=%e\ncold10_peak_kb=%M' \
  -o /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/cold10-time.txt \
  /usr/bin/python3 scripts/bench_ibex_pulp_cold_start.py \
  --receipts /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/online/receipts.jsonl \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/cold10-cache \
  --output /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/cold10.json \
  --count 10
```

命令退出 0；[逐例结果](../../runs/p5-runner-zlib-600s-20261007/cold10.json)中的十条 raw 均与对应原回执相同，原例与冷启动例均 10/10 `complete`、零错误，选择的 source 与 path 各 10/10 相同。结果文件 SHA-256 为 `3c9bf4e731554963e49f0910a61152135c99594b17b32553cf3c735b21e30144`。

| 十例计时边界 | 累计秒 | 单例中位秒 |
|---|---:|---:|
| 逐例冷启动总处理 | 195.394 | 17.613 |
| 其中 runtime 初始化 | 194.220 | 17.483 |
| 其中解码 | 0.00385 | 0.000430 |
| 其中执行 | 0.794 | 0.0747 |
| 其中 session 终结 | 0.376 | 0.0377 |
| 原持续会话前十例逐例处理 | 1.056 | 0.0839 |
| 原持续会话前十例 RTL submit | 1.006 | 0.0790 |

初始化占冷启动逐例总处理累计时间的 99.4%。`/usr/bin/time` 记录整条冷启动对照命令壁钟 210.67 秒、峰值 RSS 300,504 KB；它还包含 Python 启动和读取输入等脚本外层工作。原持续运行的逐例阶段计时不含那次会话的单次构建／启动、搜索后的终结或 replay，因此不能用表中累计时间直接计算完整系统吞吐倍数。冷启动十例没有保存可重放的完整 trace；其正确性结论限于完成状态、解码选择身份和无报告错误，不能替代原长会话的完整 fresh replay。
