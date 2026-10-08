# OpenHW CV32E40P generated local OBI RAM acceptance

日期：2026-10-05。本文记录固定 OpenHW CV32E40P RTL 在生成式独立 harness 中运行 OBI 指令/数据端口并访问持久 host RAM 的验收。该实例没有接入外设，因此不构成 CPU→IP 或完整 SoC 数据流闭环。

## 固定源码与 harness

- 官方源码来自仓库登记的 `external_designs/cv32e40p` 子模块，固定 revision 为 `6033d2b1be3295ec774d17ac4cf226faacfdeb08`。
- Profile 用完整 `cv32e40p_core` 端口事实表达分离的 32 位 OBI instruction/data channel。运行时复用 `obi_cpu` 通用模板和 `GeneratedCve2Session`，没有按 `component_id` 加 CPU 专用分支。
- CPU 的 error-response 能力按真实端口声明为不支持。通用 OBI adapter 以 `HAS_ERROR=0` 实例化；若 RAM/MMIO backend 报错则 fail-stop，不伪造 CPU error 输入。
- 固定源码记录经 Verilator lint 验收，读取闭包 31 个文件，0 error、64 non-fatal warnings。源码锁中的 `runtime_status` 保持 `runtime_unverified`：该字段描述 source-lock/SoC 集成验收等级，本报告只证明 local OBI RAM 路径。

## 真实 RTL 执行与状态

测试程序由真实 CV32E40P RTL 取指执行：

```text
SW 0x12345678 → [A=0x20000]
LBU [A+1] → x3=0x56
ADDI x3, x3, 1 → x3=0x57
SB x3, [A+1]
LW [A] → 0x12345778
SW 0x12345778 → [A+4]
loop
```

实际观察到的 accepted RTL data writes 保留原始 byte address、write data 和 byte-enable：

| 操作 | RTL 地址 | RTL 写数据 | BE |
|---|---:|---:|---:|
| `SW [A]` | `0x20000` | `0x12345678` | `0xf` |
| `SB [A+1]` | `0x20001` | `0x00005700` | `0x2` |
| `SW [A+4]` | `0x20004` | `0x12345778` | `0xf` |

OBI CPU session 只在 RAM/MMIO backend lookup 前将地址规范化到 32-bit beat；RTL sample 仍保留原始地址。RAM memory service 因而收到地址 `0x20000, 0x20000, 0x20004`，并原样按 beat 数据和 BE 做写入。定向 session 测试确认 `addr=0x20001, BE=0x2, wdata=0x5700` 只改写 word 的 byte lane 1。另一个 MMIO Router 边界测试确认 `base+1` 路由到寄存器 offset 0，`wdata` 和 BE 仍为 `0x5700`、`0x2`。

后续真实 Load 读到 `0x12345678` 和 `0x12345778`；程序将第二个结果写入 `0x20004`。单个 testcase 中 RTL reset epoch 保持不变，循环继续运行。预算化 evidence bundle 使用新 harness 从初始镜像 fresh replay 后，trace 完整匹配且 RAM 终值仍为 `0x12345778`。

## 验收命令与结果

| 命令 | 结果 |
|---|---|
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/local_harness/test_cv32e40p_obi_runtime.py` | `2 passed`；覆盖真实取指、Store/Load、lane-1 LBU/SB、连续 testcase 状态和 fresh evidence replay |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/local_harness/test_ibex_obi_runtime.py` | `2 passed`；既有对齐 OBI 访问及其 budgeted fresh replay 在通用 byte-beat service / budget-bound 修改后继续通过 |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q tests/scenario/test_evidence_budget.py tests/local_harness/test_cpu_session.py tests/local_harness/test_cv32e40p_obi_profile.py` | `60 passed, 1 skipped, 4 subtests passed`；包含 zero-deferred-MMIO 自路由预算合同、positive-access fail-closed、RAM 与 MMIO subword lane service、profile/source-lock 合同 |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 scripts/verify_soc_sources.py` | exit 0；CV32E40P 为 `source_verified`、`elaboration_verified`、`runtime_unverified`，closure 31 files，Verilator lint 0 errors / 64 warnings |

## 能力边界

本验收证明固定 CV32E40P 的双 OBI 请求/响应能由通用 harness 驱动，真实 CPU 指令可以经持久 RAM backend 完成字和子字访存，并能在连续执行和 fresh replay 中复现。它没有生成 CPU MMIO 事务，没有连接 GPIO 或其他外设，没有验证 IRQ/ISR，也没有模拟 Bus、Crossbar、Bridge、PLIC 或全局 SoC cycle。不能据此声称 CV32E40P 已完成 CPU→IP 或 IP→CPU 集成验收，也不能把 `runtime_status` 标为 `runtime_verified`。
