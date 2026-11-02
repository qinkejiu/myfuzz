# 完整 AXI4（CVA6）接入统一入口：F2/F3/F4 固定与连续 fuzz（2026-11-02）

状态：**已接入统一入口并通过 F2/F3/F4**（固定 3/3、连续 fuzz 30/30）。F1 与 F5 仍按名拒绝；不是覆盖率、证书或 replay 结论，也没有改 RTL。本报告只汇总并链接已保存证据，不复制整批日志。

## 结论

- 共享单进程入口 `scripts/run_inprocess_f1f6.py` + 共享宿主 `scripts/inprocess_obi_apb_f1f4_spike.cpp` 现有一个 `axi4` CPU 总线分支，通过仓库既有 `axi4_processor_memory_adapter` 驱动 pinned CVA6 packed AXI4（`cva6_packed_axi4_cpu`，实例 `processor`）。
- 固定批：`F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff` → `observations_passed`，3/3。
- 连续 fuzz：`--fuzz --cases 30 --seed 0` → `fuzz_completed`，30/30 通过、0 失败（F2 18 / F3 7 / F4 5），逐例对应检查 30/30 一致。
- F1/F5 按名拒绝：该归档不导出 RVFI，取指不是退休；`retirement_observation none:cva6_no_rvfi_exported`。
- 保存证据：[run README](../../runs/round1-axi4-unified/README.md)、[summary](../../runs/round1-axi4-unified/summary.md)、`commands.txt`、`summary.json`、`run.log`。

## 根因：适配器 beat 在捕获上升沿前被撤销

`summary.md` 的根因分析：适配器 beat 的握手在 tick 的低相被采样，但宿主在适配器采样所用的**上升沿之前**就撤销了 `req_ready_i`。适配器因此停在 `READ_REQUEST`，从不进入 `READ_RESPONSE`，`rsp_ready_o` 不抬升，响应永不被消费——16 字节 boot fetch 只服务了恰好两拍，CPU 等到 tick 预算。同一原因也让 `beat_response()` 只能靠下一 tick 的 settle 被适配器看到。

## 修复（共享宿主与入口）

- `scripts/inprocess_axi4_host.h`（`CpuLink`）：在 `begin_tick()` 捕获握手，把 `req_ready_i` 保持过该 tick 的上升沿，边沿之后才提交答案，并在下一低相驱动 `rsp_valid_i`；与原生探针 `tests/native/inprocess_axi4_cva6_probe.cpp` 已用的顺序一致。新增 `request_handshaked()`/`beat_outstanding()`/`response_phase_pending()`/`busy()` 等状态访问器。
- `scripts/inprocess_obi_apb_f1f4_spike.cpp`：AXI4 事件层（`axi4 ar/r/aw/w/b`、`axi4 beat req/rsp`、`boot_fetch`/`firmware_fetch`）；按 `request_handshaked()` 服务 beat，目标 beat 在途时拒绝新 beat；`frame_done` 由固件写命令字触发；`idle` 等目标 beat、适配器 beat 与 B/R 响应相；IP 窗口内取指与合并的 64 位 IP store 按名拒绝；summary 打印 `cpu_bus axi4-packed-single-master`、`instruction_identity arid0_rid0_at_address_phase`、各通道/beat 计数、`retirement_observation none:cva6_no_rvfi_exported`、`bus_error_axi unknown`。
- `scripts/run_inprocess_f1f6.py`：头文件声明 `CPU_BOOT_ADDRESS`/`CPU_MAIN_ADDRESS`；`cpu_bus.retirement_observation` 为 `none:cva6_no_rvfi_exported`；AXI4 专属限制条目。
- `scripts/inprocess_build.py` 与 `configs/scenarios/inprocess-cva6-axi4-timer-f2f4.json` **未改**。

## 固定批次 F2/F3/F4

命令与 JSON 判定见 [run README](../../runs/round1-axi4-unified/README.md)；逐事件流在 `fixed-f2f4/run.log`。

| 例 | record | ticks | 观察 |
|---|---|---|---|
| F2 | `F2:00014000` | 537 | `read_addr 0x14000`、`read_value 0xdeadbeef`、`read_from ram` |
| F3 | `F3:00014004:0badf00d` | 107 | `write_be 15`、`ram_after 0x0badf00d` |
| F4 | `F4:40001008:0fffffff` | 124 | `apb_offset 0x8`、`apb_pwdata 0x0fffffff`、`apb_pready 1` |

汇总计数器（`fixed-f2f4/summary.json` / summary 行）：`cpu_axi_ar 77`、`cpu_axi_r 77`（68 取指 / 9 数据）、`cpu_axi_aw/w/b 11/11/11`、`cpu_axi_beat_requests/responses 88/88`、`cpu_axi_beat_errors 0`、`apb_writes 1`、`failures 0`；boot fetch `0x10000` @ tick 251（ARID 0），firmware fetch `0x11000` @ tick 335，`poll_reads 3`。11 次写全部是部分字节使能的 4 字节 store（CPU 真实 WSTRB），没有出现 8 字节全使能写。

## 连续 fuzz 30 例

`fuzz-30/summary.json`：`executed 30 / passed 30 / failed 0`，`flows` F2 18、F3 7、F4 5，`correspondence_checked 30`、`correspondence_mismatched 0`、`findings 0`，`ticks 3432`；host summary `cpu_axi_ar 498`（408 取指 / 90 数据）、`cpu_axi_aw/w/b 65/65/65`、`cpu_axi_beat_requests/responses 563/563`、`poll_reads 30`。fuzz 路径的 `run.log` 事件层按 `--quiet` 抑制，计数器仍是实测握手。

## 明确不声称：F1/F5 按名拒绝

- F1：`unsupported-f1:no-retirement-observation:cva6_packed_axi4`；`retirement_evidence missing`、`retirements 0`。
- F5：`unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`；该构建 CPU IRQ 输入恒零，没有中断交付。
- 没有把取指当退休，也没有 F6（该路径无 DMA）。

## 限制（来自 run 自带 limitations）

- **单 outstanding**：一次只有一个适配器 beat；ARLEN 0 或合法两拍 INCR 读，更长 burst/LOCK/ATOP 由适配器 DECERR。
- **IP beat 必须正好一个完整 32 位字**：合并 IP store 的 64 位 beat 按名拒绝（消息带 64 位地址与 WSTRB），不拆分、不伪造；已保存批次未出现该合并。
- 64 位 AXI beat 按适配器自身的 WSTRB/lane 与 32 位字 RAM 拆分/拼合。
- 程序槽 `0x12000` 在配置的非缓存 `0x10000..0x20000` 窗口内，因此不声称 `fence.i`/缓存失效；CVA6 I$ 保留。
- 只声称这一个 pinned CVA6 packed AXI4 配置（ARID 0/RID 0 = I$，其余 = D$）；没有其他 AXI4 CPU 的普适性。
- 该 run 的测试记录：同批 `tests/fuzz`、`tests/composition/test_inprocess_behavior.py`、`tests/integration/test_inprocess_f1f6_entry.py` 为 **2 failed, 1032 passed**；两个失败是其他 agent 并发新增文件上的数据雷（`pulp_i2c_level_f5.json` 的 `clear_writes`、新增 profile 计数），与本 AXI4 宿主/入口无关，且回退本次入口改动后同样失败。另有 `tests/integration/test_inprocess_axi4_cpu_analysis.py::test_host_has_no_axi4_cpu_branch_and_entry_refuses_the_kinds` 按设计失败（它断言的是接入前的状态）。

## 证据与复现

- 目录：[`runs/round1-axi4-unified/`](../../runs/round1-axi4-unified/README.md)
  - `fixed-f2f4/`：`summary.json`、`run.log`（完整 AR/R/AW/W/B 与 beat 事件流）、构建/链接日志。
  - `fuzz-30/`：`summary.json`、`fuzz.json`、`observations.jsonl`、`prefix.txt`、`corpus.json`。
  - `commands.txt`：按顺序的精确命令、退出码与入口 JSON 判定。
  - `debug/run_inprocess_f1f6.py.current`：交接时的入口备份，SHA-256 与当时活动文件一致。
- 原生探针（独立于统一入口的证据）：[`runs/round1-axi4/`](../../runs/round1-axi4/README.md)，`verdict all=pass`，`summary ticks=369 ar=12 r=16 aw=6 w=6 b=5`，`beat_traffic requests=22 ... errors=0 outstanding=1`。
- 缓存/工具：`runs/round1-cva6-cache/`（目录名 `8f5f…` 开头，artifact `7411ff18…`）、`runs/round1-axi4/build/adapter-cva6`；Verilator 5.051。整机 wall time 约 18.5 s（固定）/18.2 s（fuzz），主要是一次性适配器构建与链接。

## 与旧分析的关系

[2026-11-01 的 AXI4 分析](inprocess-axi4-cpu-analysis-20261101.md) 记录的是**接入前**状态：只有原生探针、统一入口强制要求 RVFI、F2–F4 构建不出来。其中"入口需先放开 RVFI 强制"的判断已被本批验证；其余分析（ARID/RID 身份、缓存槽与 `fence.i` 的发现、适配器单 outstanding 能力）仍然成立。更新后的整体状态见 [当前能力盘点](../current-system-capabilities-20261101.md) 的「2026-11-02 增量」一节。
