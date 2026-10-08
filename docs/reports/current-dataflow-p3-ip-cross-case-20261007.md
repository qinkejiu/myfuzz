# P3 IP→CPU→IP 跨例链真实门禁

日期：2026-10-07。P3 验收要求"CPU→IP→CPU 和 IP→CPU→IP **能跨例完成**"。跨例链报告在既有两条真实 run 上的实测是：`CPU_TO_IP_TO_CPU` 有跨例证据（600 秒 6 条、`p4-shift-fuzz` 5 条），而 `IP_TO_CPU_TO_IP` **cross_case = 0**，首缺口为 `pin8_injection`。本报告记录该方向的诊断、最小改动与真实门禁结果。

## 诊断（真实 artifact 只读复算）

对 `runs/p3-ram-prereq-20261007-online` 逐条追踪 24 条 IP admission（7 条 certified）：**7/7 的 native 消费 case == admission case**，链尾也在同一例。代表证书 `1c62a845…`（case 16）的 hop 全部落在 case 16，其中 segment 在第 1 个 gpio_b tick、ISR 读在第 27 个 tick。机制结论：

1. **绑定两半的是 case 预算**：IP 源 case 的 `advance_rounds=32` × 声明 schedule（cpu,gpio_a,gpio_b = 96 local steps）足以把 injection→segment→trigger→observation→`cpu_irq_taken`→ISR 读全部装进同一例；`irq_pulses={cpu.irq:4}` 只保证脉冲能被打到，不是绑定原因。
2. **case 边界本身不清理 pending IRQ**（`session_runtime.py` 明确"A case boundary … is not reset"；唯一取消 pulse 的是显式 reset 路径）。
3. 首缺口是 `pin8_injection` 属于**另一件事**：24 条 admission 中 13 条注入 `value=0`（无上升沿），4 条 `value=1` 但无真实 0→1 跳变，1 条被 fail-closed 校验删源。

## 最小改动（显式 opt-in，默认关闭）

`IpCrossCaseOnlineDecoder` 声明规则 `declared_external_source_case_advances_one_declared_round`：**仅被声明的外部源（`gpio_b.external_pin8`）的 case 只走 1 个声明 round**，其余 case（含 CPU 指令 case）保持 32 round。开关为 `make_ibex_pulp_dual_source_online_decoder(ip_cross_case=False)` / `make_ibex_pulp_online_runtime(ip_cross_case=None)`，后者可用环境变量 `MYFUZZ_IP_CROSS_CASE=1` 打开；策略写入 `decoder.document()["ip_cross_case"]`（进 decoder manifest 与 run 身份）。

**结构保证（不依赖 RTL 时延）**：源 case 唯一 device 步是它的最后一步（schedule 以 gpio_b 结尾），pulse 只能在 gpio_b 步被观察 ⇒ case 内此后再无 CPU 步 ⇒ **源 case 不可能接受它自己引发的 IRQ**。默认（关闭）时 decoder document 与既有 run 保存的 manifest 规范化**逐字节相等**（sha256 `625710f4…`）。

## 真实 RTL 结果

```bash
cd /home/qinkejiu/myfuzz
MYFUZZ_IP_CROSS_CASE=1 PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p3-ip-cross-case-20261007-cache \
  --output runs/p3-ip-cross-case-20261007-online \
  --seconds 180 --max-tests 200 --seed 20261007 --run-id p3-ip-cross-case-20261007 \
  --cpu-retirement --gpio-consumption
```

退出码 0：60 例（57 `complete`、2 `input_invalid`、1 `unsupported_irq_overrun`），有效搜索 49.87 秒。跨例链报告（`scripts/report_cross_case_chains.py`，退出码 0）：

| 方向 | certified | **cross_case** | same_case | incomplete | case_gap |
|---|---:|---:|---:|---:|---|
| `IP_TO_CPU_TO_IP` | 3 | **3** | 0 | 30 | p50 = max = 1 |
| `CPU_TO_IP_TO_CPU` | 3 | 1 | 2 | 22 | p50 = max = 1 |

`all_directions_have_cross_case = true`。代表 IP 跨例链：证书 `4dd1a703b4c351086196cf28ebd1fe6f7aec56a5d52d07d5621d47a180aea2c6`，源 case 2（`online-2-604caae5…`）→ 端点 case 3（`online-3-87356b6a…`），`case_gap = 1`，终点 `isr_padin_retirement`（event 4447），17 跳：

```
pin8_admission 3378 → pin8_injection 3379 → pin8_segment_applied 3419 → pin8_input_resource 3420
→ pin8_sync0_sample 3421 → pin8_sync1_sample 3465 → gpio_b_native_irq_trigger 3466
→ gpio_b_native_irq_observation 3506 → cpu_irq_input 3555 → cpu_irq_taken 3556
→ isr_padin_mmio_acceptance 4343 → isr_padin_target_receipt 4378 → isr_padin_target_access 4382
→ isr_padin_register_read 4384 → isr_padin_mmio_delivery 4391 → isr_padin_data_response 4410
→ isr_padin_retirement 4447
```

即：**外部 pin 注入在第 2 例被接纳，CPU 的中断接受与随后 ISR 对 `PADIN` 的真实 MMIO 读在第 3 例完成**——P3 的 IP 方向跨例要求由此在真实 RTL 上成立。

## 限制

- 该 opt-in 模式在本次运行中出现 **1 次 `unsupported_irq_overrun`**（待决 IRQ 与后续 IRQ 竞争导致会话停止）；结构论证不排除这种现象，本报告不声称该模式已通过长跑稳定性验收。
- 首个缺口仍是 `pin8_injection`（30 条 incomplete）：大量注入为 0 或无 0→1 跳变，属注入值/边沿问题，不是跨例失败。
- `serial_token_status = absent`（该 run 未启用 native IRQ receipts）。
- 打开 opt-in 会改变 decoder manifest 与 run 身份；旧 bundle 仍按其自身身份 replay。
