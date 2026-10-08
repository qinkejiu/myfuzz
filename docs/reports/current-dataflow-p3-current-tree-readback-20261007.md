# P3 当前代码时期的 UART→host RAM→退休 Load 短回归

日期：2026-10-07。并行修改中的主工作树先完成 4/4 在线例，但 fresh replay 在启动前报 `online runtime source identity mismatch`；该结果不计验收。随后将当时的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 复制到 `/home/qinkejiu/myfuzz_snapshot_p3_current_20261007`，第三方源码和外部设计也复制到快照，并独立重跑。2,742 个核心文件的 [SHA-256 清单](../../runs/current-progress-p3-current-snapshot-20261007.sha256)自身哈希为 `87f08351ba098aae37c12c3a8db2c0d7a3a23fb656d202f8dac975d57f82d552`；运行及重放后执行 `sha256sum -c --quiet` 退出 0。

从快照运行：

```bash
python3 scripts/run_ibex_uart_online.py run \
  --client-binary /home/qinkejiu/myfuzz_snapshot_p3_current_20261007/third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-progress-p3-current-cache \
  --output /home/qinkejiu/myfuzz/runs/current-progress-p3-current-online \
  --seconds 20 --max-tests 4 --seed 43 \
  --run-id current-progress-p3-current-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback
```

退出码 0；4/4 `complete`，有效搜索 15.943 秒。[完整 trace](../../runs/current-progress-p3-current-online/online_final_trace.json)为 27,068 个事件，CPU/UART local ticks 分别为 1,024/2,784；4 条 host `memory_write_commit`、2 条 `uart_store_memory_match` accepted、2 条 `memory_read_issuance`、1 条 `uart_memory_readback` accepted。读回证书将 warmup UART 来源连接到第 3 例退休 `lw`，只认证 host RAM 低 8 位，`influenced_bits=[0,8]`。

同一快照、新 replay cache 执行：

```bash
python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-progress-p3-current-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-progress-p3-current-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-progress-p3-current-online/online_final_trace.json
```

退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`，覆盖完整事件及 local ticks。此结果只证明快照中的固定受控 ISR、建模 host RAM 低字节和 4 例短跑；通用跨例动作、RTL RAM、高 24 位及长会话容量仍未验收。
