# P4 在线 XORI 取指来源与真实退休：冻结源码短门禁

日期：2026-10-07。此前在线 XORI 操作子仅通过软件解码；带 CPU RVFI 的诊断短跑虽观察到 XORI `cpu_retire`，旧 `CpuRetirementMatcher` 对它返回 `unsupported_instruction_observation_only`。本轮先补一项失败测试，要求匹配器用冻结取指响应、精确寄存器和 XOR 结果来接受 XORI；错误结果或错误 rs1 寄存器必须拒绝。修改后 `test_cpu_retirement.py`、`test_rv32i_xori_mutation.py`、UART operand seed/use 的组合检查 **157 passed、369 subtests passed**。

## 冻结身份与实际结果

独立源码快照 `/home/qinkejiu/myfuzz_snapshot_p4_xori_retire_20261007` 的 1,806 个 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 文件见 [SHA-256 清单](../../runs/current-dataflow-p4-xori-retire-snapshot-20261007.sha256)，清单哈希 `5d151f9cbf3ec3a61950a33731c4b0a96c23e74aa230e4df4cf0f4da7be85cd8`。在线身份中的 36 个源码文件逐项匹配快照，0 个不符。

在快照目录执行：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p4-xori-certified-20261007-online \
  --seconds 30 --max-tests 25 --seed 20261007 \
  --run-id current-dataflow-p4-xori-certified-20261007 \
  --cpu-retirement --gpio-consumption
```

退出码 0，25/25 例 `complete`，真实搜索 34.208 秒，完整 [trace](../../runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json)有 31,651 个事件。第 14、19、24 例分别提案一条 XORI，三条均有 `cpu.online_instruction` 实际消费；其真实 Ibex RVFI `cpu_retire` 由 `cpu_retirement_match` 返回 `accepted/matched_instruction`，每条各有一份冻结 instruction response，`source_refs` 与该例的精确 `OnlineInstruction.action_id` 一致，退休 PC 分别为 `0x110a8`、`0x110d8`、`0x1111c`。这些证书只证明已取指并退休的 XORI 指令字节及其已核对的寄存器结果；不证明该计算结果传播到外设或完整 SoC 数据流。

## Fresh replay 与限制

在同一冻结快照中以独立 cache 执行：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p4-xori-certified-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p4-xori-certified-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json
```

重放退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`；重放后清单复核 0 个文件不符。另按保存的原始 RVFI 事件独立计算 `rs1_rdata XOR sign_extend(imm12)`，核对三条证书的精确 source action ID、指令字和 `rd_wdata`，3/3 一致。

这个定向门禁覆盖单条合法 XORI 的真实指令来源与退休；P4 仍缺显式 operator 身份及采用/拒绝原因、插入/删除和更广的 ISA/外设变异、CPU 计算结果至 IP 的传播证书、同预算独立驱动对照和整阶段搜索验收。CPU 退休与被动 GPIO 消费探针在 25 例中增加了大量事件与耗时，本门禁的 34.208 秒搜索不能直接当作无探针 fuzz 吞吐。
