# P4 在线路径选择熵与真实双侧搜索短门禁

日期：2026-10-07。旧 600 秒 GPIO 在线运行的 6,276 份回执中，F4 占 6,021、F5 占 255；路径字节 `raw[1]` 有 6,182 次为 1。该运行后期两条路径权重通常同为 8，而旧算法以 `raw[1]` 作为取模低字节，使其余输入字节在模 16 时无法改变路径。读回旧回执的历史权重后，仅把相同 raw 经域分离 SHA-256 混合再取模，离线投影为 F4 3,130、F5 3,146；该投影不是新搜索轨迹或 RTL 证据。

新增测试先固定 `raw[1]` 而变动 payload，旧实现只选中一条路径（1 failed）；修改后路径选择使用全部 raw 的域分离摘要，再按当前反馈权重选择路径。直接源字节仍只在选中路径内生效，未改变输入归属、候选身份或真实反馈来源。MMIO 窗口清单恢复时同时将 JSON 的 `write_widths` 列表还原为受信 tuple；旧 manifest roundtrip 测试先因此失败，修复后通过。当前主树相关软件回归为 50 passed、4 skipped、33 subtests passed。

## 冻结源码 RTL 运行

源码快照 `/home/qinkejiu/myfuzz_snapshot_p4_path_mix_20261007` 的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 2,749 文件见 [SHA-256 清单](../../runs/current-dataflow-p4-path-mix-snapshot-20261007.sha256)，清单哈希 `0147c2403b0331fc44a59aac59c562612ae51d1b3797eebe5b396dab07472176`。运行与重放后清单复核零差异。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p4_path_mix_20261007
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-path-mix-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-path-mix-1000-online \
  --seconds 120 --max-tests 1000 --seed 20261007 \
  --run-id current-dataflow-p4-path-mix-1000-20261007
```

退出码 0，1,000/1,000 `complete`，有效搜索 103.314 秒。回执按 `flow_id` 为 F4 491、F5 509；901 份输入的旧路径字节同为 0。按回执实际消费身份，单独消费 GPIO pin8 494 例、单独消费 CPU 指令 462 例、两源跨例同时见证 15 例、当前例无已证明消费 29 例。后两类不能按选择量充作完整传播链。完整 trace 为 379,209 事件、CPU/GPIO A/GPIO B local ticks 分别为 32,053/33,557/33,465。

同一快照使用独立缓存执行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-path-mix-1000-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-path-mix-1000-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-path-mix-1000-online/online_final_trace.meta.json
```

退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`，覆盖完整 JSONL 事件与 local ticks。这证明新路径选择在此真实运行中未被固定传输字节锁定，且 CPU/IP 两类上游源都发生实际消费；不证明相同 600 秒预算的覆盖或故障收益、完整跨组件链/s，也不把 F4/F5 例数当作 RTL 内部分支覆盖。
