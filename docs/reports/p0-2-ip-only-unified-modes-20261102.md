# P0-2：IP-only 模式与统一 `--mode` 入口（2026-11-02）

本报告对应 P0-2 增量 D：在统一入口 `scripts/run_inprocess_f1f6.py` 上增加
`--mode {combined,cpu-only,ip-only}`（默认 `combined`），实现只构建目标 IP、
不构建 CPU/DMA 的 IP-only 会话，并把断言捕获与总线超时分开记录。所有结论只
适用于本报告列出的真实命令、缓存与运行目录；不声明覆盖率、证书或 replay。

## 1. 结论

| 项 | 结果 |
| --- | --- |
| 统一入口 | `--mode` 由 arg 解析声明；`combined` 路径与摘要字段除新增三个组件清单键外不变；`cpu-only` 只调用 agent C 的 `run_cpu_only(...)`，不接触 target 声明；`ip-only` 只调用 `run_ip_only(...)` |
| IP-only 真实批次 | `runs/p0-ip-only/declared/`：PULP APB Timer，13 个声明事务 × 2 轮 = 26 例，26/26 通过；单模型 1 个 archive，无 CPU archive |
| 真实设备响应 | 读回写入值（`0x55`/`0x28`/`0x08`）、APB3 trace 完成（`psel+penable+pready` 每例 1 次）、真实 `irq_o` 边沿（wait 例 ≥1） |
| 断言捕获 | Verilator 5.051 默认执行 `assert`；`runs/p0-ip-only/assertion-probe/` 以真实 abort 证明 source/line/scope/text/tick/transaction 全字段捕获；另对 PULP I2C（archive 内确有 2 个编译断言）做了带捕获的真实 IP-only 批次：14/14 通过、0 个断言事件，并给出**可达性层面的精确原因**（下述），未伪造 |
| 总线超时 | 单独归入 `environment_issues`（`kind=bus_timeout`），`assertions.events=[]`；`env-budget` 批次 26/26 超时、状态 `environment_issue`、退出码 1 |
| 三模式证据 | `runs/p0-unified-modes/`：`combined` 6/6（CPU+Timer+DMA 三个 archive）、`cpu-only` 5/5（仅 `Vlocal_cpu__ALL.a`）、`ip-only` 26/26（仅 Timer archive） |
| 回归 | 指定套件 `test_inprocess_f1f6_entry / test_inprocess_mixed_targets / test_inprocess_target_protocols / test_inprocess_ip_only`：297 passed；相邻入口套件（AHB/AXI4/Wishbone/fuzz）1051 passed |

## 2. 入口与模式选择

`scripts/run_inprocess_f1f6.py` 的改动只有四处（均为 D 的 `--mode`/IP-only 归属）：

1. 新增 `--mode` 参数（`MODES = ('combined','cpu-only','ip-only')`，默认
   `combined`），非法名字由 argparse 按名拒绝（exit 2）。
2. 新增 `dispatch_secondary_mode(args, parser)`：`cpu-only` 惰性导入
   `scripts.inprocess_cpu_only.run_cpu_only`，缺失时 `parser.error` 命名拒绝；
   `ip-only` 导入 `scripts.inprocess_ip_only.run_ip_only`；`--replay-prefix` 在
   非 combined 模式按名拒绝；返回值映射退出码（`observations_passed` 与
   fuzz/replay 完成态为 0，其余 1，用法拒绝 2）。
3. `main` 在 combined 的记录/fuzz/replay 解析之前分派：次要模式只检查输出目录
   不存在，然后进入各自 runner；combined 分支以下代码完全不执行。分派器在次要
   模式输出目录写 `entry_mode.json`（同一 `mode`/`components_loaded`/
   `model_archives` 形状，`components_source` 说明计数来源），使三种模式都有一份
   可预测路径的模式文档。
4. combined 的 `result.update(...)` 新增 `mode='combined'`、
   `components_loaded={cpu,targets,dma,ram,model_archives}`、
   `model_archives={cpu,targets,dma,all,sha256,source}`。archive 列表来自
   `build_link_run` 的链接结果，不是从声明推断。

`--mode cpu-only` 的调用签名固定为
`run_cpu_only(config_path, cache, output, records=..., fuzz=..., max_ticks=...)`，
不传任何 target profile 或 archive。record 列表由入口按逗号拆分后交给该
runner（它自己解析 mailbox word）；`--fuzz` 时把入口的 `--cases/--seed` 映射为
`{"cases": n, "seed": s}`，由其执行 fuzz 循环；`fuzz` 未开启时传 `None`。

## 3. IP-only 运行器

新增 `scripts/inprocess_ip_only.py`（Python）与
`scripts/inprocess_ip_only_host.cpp`（C++ 主机），场景
`configs/scenarios/p0-ip-only-pulp-timer.json`。

* **只构建一个模型**：`source_request_from_profile`（现有 APB3 请求构造器）
  → `timer_artifact`（现有 artifact/builder）→ `build_link_run((artifact,),
  HOST_SOURCE, ...)`。Python 断言 `len(build['archives']) == 1`，并从
  `link.log` 读取 `local_runtime_cpu` 是否出现，得到
  `cpu_archive_present=false`；`components_loaded={cpu:0,targets:1,dma:0,ram:0}`。
* **复用 target traits**：`ip_port_fields` 依据 artifact 自身的
  `backend_ports` 与 `base_protocol_trace` 推导 beat/trace 端口名；
  `render_header` 调用统一入口的 `_generated_target_traits` 生成同一个
  `myfuzz_ip::IpTarget<0>` trait（clock/reset/eval/request/response/trace/irq
  访问器），主机循环没有器件名分支。生成头中只有
  `#include "Vlocal_runtime_pulp_timer_active.h"`，无 `CPU_MODEL`/`DMA_MODEL`。
* **协议范围**：本增量只驱动 APB3（本轮唯一被证明的 IP-only 路径）；
  AXI4-Lite/Wishbone/TL-UL 由 `ip_port_fields`/`run_ip_only` 以
  `unsupported-ip-only:protocol:<p>` 按名拒绝，而不是把它们当作 APB3 驱动。
* **事务记录**：`R:<offset>` / `W:<offset>:<value>` / `WAIT:<ticks>`，也可
  直接复用 combined 的 `CASE R ...` 消息；offset 支持窗口内绝对地址换算，
  非对齐/越界/读带值/写缺值等在解析期按名拒绝；场景可声明
  `expect_rdata`/`expect_error`/`expect_irq_edges_min`。record 列表长度与声明
  一致时按位置继承期望，否则只检查真实响应（summary 会说明）。
* **会话输入**：`--records` 固定列表、`--online` 逐条 `NEED_RECORD` 交接、
  `sequence.loops` 轻量循环（1..16）；`--fuzz` 以
  `unsupported-ip-only:fuzz-loop` 命名拒绝。
* **每例判定**：一次总线事务必须同时满足 beat 响应（`response_seen=1`）与
  APB3 trace 完成（`psel&penable&pready` 采样恰好 1 次），否则失败；读的
  `expect_rdata`、`expect_error` 与实际比较；`WAIT` 例比较真实
  `irq_edges`。超时不是“响应失败”，而是下一节的独立环境问题。
* **断言捕获**：默认 `case_isolation=true`，采用 **prefix replay**：第 k 例
  在子进程中执行前 k+1 个事务。这样既保留“先写后读”的序列语义，又让 abort
  精确落在新增的 1 个事务上；每个前缀重复出现的旧 case 行必须完全一致
  （`prefix_replay.consistent=true`）。子进程崩溃被解析为 source/line/scope/
  text/tick/transaction，并写入 `assertions.jsonl` 与 summary。
* **总线超时**：主机在 case 预算内未看到 request 被接受或 response 返回时，
  打印 `case <i> environment_timeout reason <phase>`；Python 生成
  `environment_issues[].kind=bus_timeout`（`classification=environment`），
  状态 `environment_issue`，绝不进入 `assertions.events`。

## 4. 真实批次（`runs/p0-ip-only/`）

```sh
python3 scripts/run_inprocess_f1f6.py --mode ip-only \
  --config configs/scenarios/p0-ip-only-pulp-timer.json \
  --cache runs/stage2-stepD2-cache --output runs/p0-ip-only/declared
```

* 模型 `local_runtime_pulp_timer_active`（APB3，窗口 `0x40000000+4096`），
  archive `.../Vlocal_runtime_pulp_timer_active__ALL.a`，sha256
  `d2e71305…c0048b`；`components_loaded={cpu:0,targets:1,dma:0,ram:0,
  model_archives:1}`，`cpu_archive_present=false`。
* 26/26 例通过；两轮循环结果一致（`prefix_replay.consistent=true`）。
* 真实响应证据：`rdata=0x55`（写后读 count）、`0x28`（ctrl）、`0x08`
  （cmp）、`0x00`（两笔声明故障偏移 0x0c/0x1c）；每笔总线事务
  `target_transfers=1`、`apb_pready=1`、`response_error=0`；enable 后的
  `WAIT 12` 观察到 `irq_o` 真实边沿（每轮 wait 例 `irq_edges=1`）。
* 其他会话形状：`online/`（逐条交接，13/13）、`records/`（8 record × 2 loop =
  16/16）、`env-budget/`（`--max-ticks 8`，26/26 超时，`environment_issue`，
  `assertions.events=[]`，退出码 1）。
* 完整 case 行、事务表、archive 列表与逐例 wall 见
  `runs/p0-ip-only/README.md` 及同目录 `declared/run.log`、
  `declared/summary.json`。

## 5. 断言证据与阻塞

**工具链事实**：本工作区 Verilator 5.051 在**没有 `--assert`** 的构建下仍执行
`assert`，失败时打印
`%Error: <file>:<line>: Assertion failed in <scope>: <text>` → `%Error: ...
Verilog $stop` → `Aborting...`，进程退出 1，控制流不返回主机。因此断言只能由
父进程按“退出码 + stderr/stdout 文本”捕获。

**捕获机制已用真实 abort 证明**：`runs/p0-ip-only/assertion-probe/` 是一个独立
`assert` 探针模型（非目标 IP），主机循环打印与 IP-only 相同的
`case_begin`/`tick` 行；真实运行被 `classify_child_process` 与
`scan_assertion_lines` 读成：

```json
{"kind":"dut_assertion","source":"probe.sv","line":13,
 "scope":"probe.probe","text":"declared assertion probe fired","returncode":1}
```

以及事件 `tick=2`、`transaction={index:0, record:"CASE R 00000000"}`。该证据在
README 中明确标注为 **capture self-test，不是 DUT 断言**。

**模型级断言审计（`model_assertion_sites`）。** IP-only summary 直接扫描本次
链接的 model archive 是否含 Verilator 断言串，因此“无断言”是关于已构建模型的
事实而不是假设：

| archive | 编译断言位置 | IP-only 带捕获批次 |
| --- | --- | --- |
| `Vlocal_runtime_pulp_timer_active__ALL.a` | 无 | 26/26，0 事件 |
| `Vlocal_runtime_pulp_i2c_target__ALL.a` | `i2c_master_bit_ctrl.sv:374`、`i2c_master_byte_ctrl.sv:220` | 14/14，0 事件 |
| `Vlocal_runtime_tlultimer_target__ALL.a` | `rv_timer_reg_top.sv:622`（TL-UL，非 APB3 IP-only 目标） | 未跑 |
| `Vlocal_runtime_axiluart_target__ALL.a` | 无（`assert` 全在 `` `ifdef FORMAL `` 内） | 未跑 |
| `Vlocal_runtime_wbuart_target__ALL.a` | 无（同上） | 未跑 |

`runs/p0-ip-only/i2c-assertion-armed/` 是对真实 IP 断言的实际尝试：PULP APB I2C
模型确实带 2 个编译断言，捕获按例武装（prefix replay），批次驱动合法寄存器序列
（PRESCALER 回读 `0x0a`、CTRL 回读 `0x80`、START/STOP 命令、STATUS 观测）外加
两个声明故障事务（全命令位置 1 的 `CMD` 字、6 个已声明寄存器之外的 0x18 读），
**没有断言触发**；summary 明确写出 `model_assertion_code_present=true`、
`model_assertion_sites=[...]`、`assertions.events=[]`、
`triggers="none fired: ..."`。

**精确原因（未触发，未伪造）。**

* PULP timer/gpio/I2C RTL 本身没有 `assert` 语句；timer 的 archive 不含任何
  断言代码，其 IP-only 批次在构造上不可能触发。
* I2C 的两个编译点都是语言级 `unique case`（`full_case parallel_case`）检查：
  `i2c_master_byte_ctrl.sv:220` 只在 5-bit onehot FSM 状态不匹配任何分支时触发，
  `i2c_master_bit_ctrl.sv:374` 同样检查 onehot FSM 状态；FSM 只会写入 6 个已定义
  onehot 状态，合法 APB beat 与声明故障命令字（RTL 命令解码有优先级、状态仍有
  定义）都无法到达该检查。
* TL-UL timer 的编译点是 `rv_timer_reg_top.sv:622`，对 onehot
  `racl_addr_hit_read` 的 `unique case (1'b1)`：只有两个地址命中同时成立才触发，
  而 onehot 解码在构造上不会。OpenTitan `prim_assert` 在 `VERILATOR` 下还会切换
  到 `prim_assert_dummy_macros.svh`（宏被编译为空）。
* zipCPU UART 的断言全部位于 `` `ifdef FORMAL ``，不进入 harness 模型
  （archive 审计为空）。
* 本工作区确有真实 DUT 断言被捕获：agent C 的 CPU-only 故障用例在
  `runs/p0-cpu-only/assertion/` 真实 abort 于 Ibex 的
  `NoMemResponseWithoutPendingAccess` / `PendingAccessTrackingCorrect`。IP-only
  可选 IP 中没有等价的可达断言点。

因此本轮没有触发任何 IP 断言，也没有声称触发；集成点固定为
`scripts/inprocess_ip_only.py` 的 `classify_child_process` /
`scan_assertion_lines`，agent C 的共享 helper 可直接替换这两个函数。

## 6. 三模式证据（`runs/p0-unified-modes/`）

```sh
python3 scripts/run_inprocess_f1f6.py --mode combined --config \
  configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json \
  --cache runs/stage2-stepD2-cache --output runs/p0-unified-modes/combined \
  --quiet --records 'F1:2ab00693,F2:00014000,F3:00014004:0badf00d,\
F4:40001008:0fffffff,F5:00000001:00000000:ffffffff,F6:0110c000:08000000:deadbeef:12345678'

python3 scripts/run_inprocess_f1f6.py --mode ip-only --config \
  configs/scenarios/p0-ip-only-pulp-timer.json \
  --cache runs/stage2-stepD2-cache --output runs/p0-unified-modes/ip-only

python3 scripts/run_inprocess_f1f6.py --mode cpu-only --config \
  configs/scenarios/p0-cpu-only-ibex.json \
  --cache runs/p0-cpu-only/cache \
  --output runs/p0-unified-modes/cpu-only
```

| mode | 真实结果 | components_loaded | archives |
| --- | --- | --- | --- |
| `combined` | `observations_passed`，6/6（F1–F6） | cpu 1、targets 1、dma 1、ram 1 | CPU + Timer + DMA 三个 |
| `ip-only` | `observations_passed`，26/26 | cpu 0、targets 1、dma 0、ram 0 | 仅 Timer 一个；link.log 无 CPU archive 名 |
| `cpu-only` | `observations_passed`，5/5（合法 mailbox 字；真实 load/ALU/store 回读） | cpu 1、targets 0、dma 0 | 仅 `Vlocal_cpu__ALL.a` 一个 |

`cpu-only` 由 agent C 的 `run_cpu_only` 执行：`cpu-only/result.json` 状态
`observations_passed`、`case_count=5`、`input_mode=records`、模型
`local_cpu`（kind `baseline`），`archives` 只有一行 `kind="cpu"` 的
`Vlocal_cpu__ALL.a`，没有 target 或 DMA archive；stdout 的 5 条 case 行给出真实
`input/expected/result`（`0x1→0x2`、`0x2→0x3`、`0x3→0x4`、`0x100→0x101`、
`0xffffffff→0x0`）。`modes.json` 中该模式的组件行由 archive 的 `kind` 字段推导，
不是假设。

入口的 dispatch 只向 `run_cpu_only` 传 config/cache/output/records/fuzz/
max_ticks；`--cases/--seed` 被映射为 C 的 fuzz mapping。交付前按名拒绝的调用与
stub dispatch 记录分别保留在 `cpu-only-unavailable.log` 与
`cpu-only-dispatch-dry-run.json`，作为依赖来源，已被真实批次取代。

## 7. 测试与回归

* 新增 `tests/integration/test_inprocess_ip_only.py`：record 解析/命名拒绝、
  场景校验、`ip_port_fields`/`render_header`（只含目标模型、无 CPU/DMA 宏、
  trait 文本）、`classify_child_process`（真实 Verilator 断言文本 → source/
  line/scope/text）、`scan_assertion_lines`（tick + transaction 归因）、
  `check_case`（响应+trace 双条件、rdata/error/irq 期望）、`case_issue`
  （超时=environment）、`component_inventory`/`model_archive_inventory`
  （cpu=0、dma=[]）、模式分派（ip-only/cpu-only stub 调用参数、非通过状态 →
  exit 1、replay 命名拒绝、非法 mode、非法场景不创建输出）。
* 更新 `tests/integration/test_inprocess_f1f6_entry.py`：无 `--mode` 时必须走
  combined（缺 `--records` 的既有拒绝），锁定默认值。
* 指定套件：297 passed（entry/mixed/target/ip-only）。相邻入口套件
  （AHB/AXI4/Wishbone/fuzz）：1051 passed。运行期间共享文件的并发改动曾使
  mixed/target 两个 F5 拒绝字样测试短暂失败，P0-1 更新测试后恢复；最终结果
  以上述 297/1051 为准。

## 8. 文件与 hunk（仅本 agent 归属）

新增：

* `scripts/inprocess_ip_only.py`、`scripts/inprocess_ip_only_host.cpp`
* `configs/scenarios/p0-ip-only-pulp-timer.json`、`configs/scenarios/p0-ip-only-pulp-i2c.json`
* `tests/integration/test_inprocess_ip_only.py`
* `runs/p0-ip-only/{README.md,declared/,online/,records/,env-budget/,i2c-assertion-armed/,assertion-probe/}`
* `runs/p0-unified-modes/{README.md,modes.json,combined/,cpu-only/,cpu-only-cache/,ip-only/,cpu-only-unavailable.log,cpu-only-dispatch-dry-run.json}`（`cpu-only/entry_mode.json`、`ip-only/entry_mode.json` 由分派器写出）
* 本报告

修改（`scripts/run_inprocess_f1f6.py`）：

1. `MODES` / `SECONDARY_MODE_OK_STATUSES` / `dispatch_secondary_mode`（新增）；
2. `main` 的 `--mode` 参数；
3. `main` 在 combined 记录解析前的分派分支；
4. combined `result.update` 的 `mode` / `components_loaded` / `model_archives`。

修改（`tests/integration/test_inprocess_f1f6_entry.py`）：新增
`test_the_entry_defaults_to_the_combined_mode`。

未改动：`scripts/inprocess_cpu_only.py` 及其 host（agent C 的实现，仅调用）、P0-1 的
profile/assembly/IRQ/DMA 段、target 协议语义、任何既有 run/report。

## 9. 限制

* 仅 APB3 target 被本轮 IP-only 主机执行；其他协议按名拒绝。
* IP-only 不消费中断：只采样设备真实 `irq_o`，不投递、不进入 handler。
* `prefix replay` 的每例 wall 由子进程启动主导，逐例差值常为 0；逐例真实成本
  以 case 行 `ticks` 为准（summary 同时保留 prefix wall 与 derived case wall）。
* 无 RTL 覆盖率、无证书、无 replay；总线超时是环境事实，DUT 断言是另一类
  事件，两者在 summary 中分开。
