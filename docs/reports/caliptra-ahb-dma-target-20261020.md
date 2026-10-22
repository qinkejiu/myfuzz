# Caliptra AHB-Lite DMA target：本地单字路径（2026-10-20）

## 已实现范围

新增 Caliptra SHA256 AHB-Lite DMA provider 和单字 route：ZipCPU `wbdmac` 从 host `PersistentMemory` 读取 `0x00010100` 的值 `5`，向已绑定的 Caliptra `sha256.bus` 写 `CTRL` byte offset `0x10`、full-word byte enable `0xf`。route 只允许这一地址和数值，使用版本化 `dma_master_target_access.v1` provider dispatch、精确 `TransactionKey`、关闭式 delivery context 和编译后的 topology admission。

Provider 的 `target_effect` 语义已限定为 `caliptra_sha256_ctrl_ahb_write_completion.v1`：它证明 AHB 写数据相位携带 `5` 且 HREADYOUT/HRESP 成功，不单独证明 SHA 控制器在 `sha256_ready` 时接受了 start。真实正向门另外观察 STATUS 与八个 digest word，SHA-256(`abc`) 与标准摘要相等，证明这次完整组合运行确实完成了散列。

## 本地原生证据

最终运行是 [attempt7 证据](evidence/caliptra-ahb-dma-20261020-local-attempt7/)；pytest 为 **1 passed in 46.50s**。descriptor 与独立 fresh 运行使用不同 DMA/SHA execution IDs；除 execution 身份正规化后，完整 descriptor 相等。两次均得到：

- RAM read `0x00010100 → 5`，DMA read transaction sequence 1；
- DMA write `0x40002010 → 5`、byte enable 15，sequence 2；
- 实际 AHB accepted request/data-response 分别位于 local tick 66/67；所有 target witness 绑定同一 DMA write key 和 access ID；
- Caliptra STATUS VALID，摘要 `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`；
- native refusal 将真实 Wishbone write `0x40002014`、`mwb_dat_w=5` 路由到未选窗口。admission 在 provider 前拒绝；直接包装 provider 方法计数为 0，AHB local ticks 前后均为 68。

[独立 audit](evidence/caliptra-ahb-dma-20261020-local-attempt7/independent-audit.json) 从压缩原始证据重新 join RAM read、DMA request/response、AHB address/data phase、摘要、fresh equality 和拒绝请求的完整 `pre_backend`、tick 及 typed transaction key，结果 `status=pass`。原生 pytest 命令与结果收据见同目录 `run-receipt.json`。

scoped software gates：

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_ahb_dma_target_provider.py \
  tests/scenario/test_caliptra_sha256_dma_paths.py
```

结果 **25 passed in 0.24s**。测试覆盖 provider identity/context、AHB phase join、uncertain terminal、route admission 和 topology identity。

## 证据解释与剩余范围

实际原生证据支持本地这一条 `declared`、`topology_bound`、`runtime_observed`、`replay_verified` 事务级路径。route compiler 的序列化仍明确标记 `runtime_causality_verified=false` 与 `resource_versions_verified=false`；runtime/fresh结论来自上述实际 typed joins 和原生输出，不从编译布尔字段推导。

attempt5 在 route 编译前因 provider implementation identity pin 仍是旧版本而失败；attempt6 正向运行成功后，拒绝证据包装器因把参数 tuple 转成 dict 而失败。两条脚本失败均保留在 [attempt5](evidence/caliptra-ahb-dma-20261020-local-attempt5/failure.json) 和 [attempt6](evidence/caliptra-ahb-dma-20261020-local-attempt6/failure.json)；它们未产生最终证据，attempt7 为修复后的新运行。

这不验证物理 Wishbone-to-AHB bridge、同一 SoC 时钟/仲裁、真实 SRAM RTL、CPU 发起或消费/退休、Caliptra BLOCK DMA、多字 DMA feeding、IRQ、任意 AHB target、持续 fuzz，也不关闭 P6/P7/P8 或六 CPU/四 IP 整体验收。此报告仅记录本地运行；远程 gate 未运行。总体设计与执行清单见[规格](../superpowers/specs/2026-10-20-caliptra-ahb-dma-target-design.md)和[计划](../superpowers/plans/2026-10-20-caliptra-ahb-dma-target.md)。
