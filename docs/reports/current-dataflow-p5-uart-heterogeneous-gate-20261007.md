# P5 异构外设门禁：Ibex＋OpenTitan UART 在当前源码栈上的多例会话

日期：2026-10-07。P5 验收要求"在 Ibex＋双 PULP GPIO 与**至少一种不同协议/行为的真实外设**上"跑通 F1–F5 的声明路径、跨例状态、真实路由、逐例反馈、断言、完整前缀保存与 fresh replay。本报告给出异构侧（Ibex＋OpenTitan TL-UL UART）在当前源码栈上的真实结果，包括一次真实阻塞的修复与仍然存在的并发限制。

## 运行与结果

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p5-uart-gate2-20261007-cache \
  --output runs/p5-uart-gate2-20261007-online \
  --seconds 60 --max-tests 60 --seed 20261007 --run-id p5-uart-gate2-20261007 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback --uart-wdata-byte-store
```

退出码 0：`{"tests": 7, "statuses": {"complete": 6, "uncertain_effect": 1}, "effective_search_seconds": 9.430715}`。逐例：

| # | operator | 结果 |
|---:|---|---|
| 0 | `external_event`（UART RX 源） | complete |
| 1 | `rv32i:SLLI` | complete |
| 2 | **`rv32i:LUI+ADDI+LUI+SB`**（UART WDATA 字节写） | complete |
| 3 | `rv32i:NOP` | complete |
| 4 | `external_event` | complete |
| 5 | `external_event` | complete |
| 6 | `rv32i:LUI+ADDI+LUI+SB` | **uncertain_effect** |

fresh replay：

```bash
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir runs/p5-uart-gate2-20261007-replay-cache \
  --plan runs/p5-uart-gate2-20261007-online/online_plan.json \
  --trace runs/p5-uart-gate2-20261007-online/online_final_trace.json
```

退出码 0、`matches = true`、`first_difference = null`、`difference_context = null`。

## 修复的真实阻塞（修复前 → 修复后）

修复前同一命令（`runs/p5-uart-gate-20261007-online`）只跑 3 例就停机：2 complete + 1 `uncertain_effect`，错误 `ValueError: unsupported UART register write`。失败候选为 `raw=000000c30c0106b0 → LUI x2,0x0cc3b; ADDI x2,x2,6; LUI x1,0x40000; SB x2,0x1c(x1)`，`x2=0x0CC3B006`、`be=1`：**被使能 lane 0 的字节是 `0x06`（合法）**，但接纳前的判定拿**整字**与 WDATA 的 8 位声明字段比较，于是把 session 实际会接受并只写低字节的输入误判为非法；提交时才抛错并升级为 `uncertain_effect`。

修复：把运行时接受集抽成唯一声明 `UART_REGISTER_WRITES` + 纯谓词，并新增 `enabled_write_mask(be)`（`be=1→0xFF`、`3→0xFFFF`、`15→0xFFFFFFFF`）与 `written_value = value & mask`，**只比较被使能 lane 的字**；`be=15` 仍按整字判定。静态 RTL 证据：wrapper 原样透传 `a_mask/a_data`，`tlul_adapter_reg.sv` 的 `wdata_o=a_data, be_o=a_mask`，`uart_reg_top.sv` 的 `u_wdata` 为 `prim_subreg #(.DW(8), SwAccessWO)`、`wdata_d=reg_rdata[7:0]`，与 P4 已归档的 `be=1` 真实串口字节一致。

结果对比：complete 例 2 → **6**；TX 字节写候选（`rv32i:LUI+ADDI+LUI+SB`）现在**被接纳并真实提交**；拒绝不再落到 `uncertain_effect`（未声明 offset/be 或不可物化 store 会在任何 RTL 命令之前以结构化 `candidate_rejection.v1` 拒绝并继续会话）。软件侧另以 **486 组 (offset×be×value) 网格**断言真实 `write_register` 与门禁的接受/拒绝逐点一致，并有 15 项定向测试（RED：把 `written_value` 退回整字比较 → `4 failed, 11 passed`；GREEN：`15 passed`）。

## 仍然存在的限制（真实阻塞，未修复）

第 7 例停机原因是另一条**已知**限制：`RuntimeError: TL-UL access during serial source waveform is unsupported`（失败包 `failures/online_uncertain_effect_8f102f4b_1_5_1a0521246692a4c0.json`）。即：**UART RX 串行波形进行中，CPU 发起 TL-UL MMIO 访问不被 UART session 支持**。这与能力表既有记载一致（"两个 ISR 场景都在帧完成后访问 UART，尚未覆盖 RX 波形活动期间的并发 TL-UL 访问"）。它意味着：

- 异构路径的多例会话是**有界**的：一旦 fuzz 提出与在途 RX 波形并发的 MMIO 访问，会话以 `uncertain_effect` 结束并保存失败前缀（这是正确的 fail-closed 行为，不是重复事务）。
- 本报告**不**声称异构路径已达到与 Ibex＋双 GPIO 相同的长会话能力；也不声称 P5 整阶段通过。

## 其他范围说明

- 链证书（`chain_certificates`）的 hop 是 GPIO/pin8 语义，**不适用于** UART 路径：对 UART 运行不会产出认证链（如实为 incomplete/unknown），UART 侧的专项证书（`uart_consumption`、`uart_retired_read`、`uart_operand_*`、`uart_ram_commit_join` 等）仍按其各自报告与门禁成立。
- 运行窗口 9.43 秒、7 例，不是十分钟门禁；异构侧的十分钟口径未做。
- 本次未发现自然 RTL 缺陷；唯一的 finding 是受控/环境级停机，已如实归类为 `uncertain_effect`。
- 修复同时补上了 `tests/integration/test_uart_fifo_replay_selector.py` 的既有失效（原缺 `_saved_memory_readback_mode` 的 patch），现 6 passed。
