# P2 IP-only：`--fuzz` 闭环、四种目标协议、长驻执行（2026-11-03）

本报告只覆盖 `--mode ip-only`（`scripts/inprocess_ip_only.py` +
`scripts/inprocess_ip_only_host.cpp`）。证据目录：
`runs/p2-ip-only-20261103/`（`README.md` 有逐字 case 行、精确命令、实测对比与
限制；`run.sh` 可整套复现，`campaign.log` 是这次的完整记录）。所有批次都是真实
Verilator 5.051 模型 + 真实 RTL，每个 run 只链接一个 target archive，无 CPU、无 DMA、
无 RAM（summary `cpu_archive_present: false`，`model_archives` 长度 1，`link.log`
不含 `local_runtime_cpu`）。

## 1. 结论

1. **`--fuzz` 接通为真闭环**：`IpFuzzPolicy` 在同一个长驻进程里通过
   `NEED_RECORD` / `CASE ...` 逐例交接；每个写之后紧跟同偏移回读，**下一次变异的
   种子来自设备自己的回读值**，而不是来自写进去的值。每例的输入、变异策略与依据、
   观察、结果、回读比较都写进 `fuzz.json`。APB3 64 例（seed 11）与 TL-UL 48 例
   （seed 23）全部 `fuzz_completed`。
2. **单 IP 模式扩到四种目标协议**：`apb3` / `tl-ul` / `wishbone` / `axi4-lite`
   各有一条真实批次（26 / 15 / 9 / 9 例，全部 `observations_passed`）。每例的完成
   判据与 trace 采样来自该 target 自己的 trait 与 trace 角色（`psel+penable+pready`、
   `cyc+ack`、A→D、AW+W→B / AR→R），没有按组件名写分支；case 行里的 offset 是
   target 地址端口真正采到的地址。
3. **默认改成 `long-running`**：一次初始化、连续推进全部事务；`prefix-replay`
   保留为显式选项（`--case-isolation prefix-replay`，配置文件仍可用 P0 的
   `case_isolation: true` 拼写）。同一 26 例序列实测：1 个子进程 / 125 ticks /
   0.00424 s，对照 26 个子进程 / 1718 ticks / 0.10871 s（每例 0.163 ms 对 4.181 ms，
   重放 325/351 次事务）。
4. **断言在长驻模式下命中即中止**：进程内 `%Error: <file>:<line>: Assertion failed
   in <scope>: <text>` 结束整个会话，事件保留 source/line/scope/text/tick 与正在
   执行的事务，后续 case 记入 `cases_not_run`，不回放任何已执行事务。真实中止用
   `assertion-probe/`（独立 model 的真实 Verilator 断言，明确标注不是所选 IP）证明；
   本次所选 IP 的 archive 审计显示没有可达断言（I2C 两处 `unique case` one-hot 检查
   不可达，timer/wbuart/axiluart 无编译进 archive 的断言串），因此不宣称任何 DUT
   断言。
5. **统一入口未坏**：三模式入口照旧，`--mode ip-only` 仍然只链接 target archive；
   P0 的四种会话形态（declared / online / records / env-budget）case 行与 P0 证据
   **逐字节相同**。

## 2. Hunk 清单

### `scripts/inprocess_ip_only.py`（本代理负责）

| 位置 | 行为 |
| --- | --- |
| 模块 docstring | 改为四协议 + `fuzz` + 长驻默认 + 断言语义（原文只写 APB3 与 prefix replay） |
| `SUPPORTED_PROTOCOLS` | `('apb3',)` → `('apb3','axi4-lite','wishbone','tl-ul')`；新增 `CASE_ISOLATION_MODES`、`CASE_ISOLATION_DEFAULT='long-running'` |
| `build_request(config, protocol, profile)` | 原 `build_request(config)` 只调 APB3 builder；现在按协议选 builder（APB3 = `run_inprocess_f1f4.source_request_from_profile`，Wishbone/TL-UL = 入口 `generic_target_request_from_profile`，AXI4-Lite = `run_inprocess_axi4lite.source_request_from_profile`），失败包成 `unsupported-ip-only:target-request:<协议>:<原原因>` |
| `ip_port_fields` | 删掉“只驱动 APB3”的具名拒绝；四协议共用 beat 角色，trace 角色仍按 `PROTOCOL_TRACE_ROLES` 校验（缺角色 = `unsupported-ip-only:trace-lacks:<角色>`） |
| `_profile_window` | 地址宽度检查按 profile 自己的地址单位（`capabilities.address_units == 'word'` 时字节窗口 = 4×地址空间），否则 word-addressed Wishbone 窗口会被误拒 |
| `case_isolation_mode(config, override, online, fuzz)` | 新函数：默认 `long-running`；`True`→`prefix-replay`（P0 拼写）、`False`→`long-running`；online 交接强制单进程并写明原因，显式 CLI 与 online 冲突时 `unsupported-ip-only:case-isolation:prefix-replay-with-online-handover`；未知形状具名拒绝 |
| `FUZZ_*`、`fuzz_specification`、`fuzz_offsets`、`IpFuzzPolicy` | 新增：预算/种子校验；偏移语料 = 声明事务偏移 + profile 寄存器表 + 窗口；闭环策略（写→回读→用回读做下一轮变异种子；回读不等者记为 device-derived 并被更频繁地重选；`wait` 每 `wait_every` 例插入）；策略对同一 seed + 同一观察序列确定性可重放 |
| `check_case` | 新增：采样地址（`target_offset`，APB3 回退 `apb_paddr`）必须等于请求偏移；fuzz 生成的写不因设备回 `response_error=1` 判失败（那是真实设备应答，写进 case 行）；`expect_*` 为 `None` 视作未声明 |
| `parse_ip_run_log` / `_timing_row` | 解析 host 的 `timing` 行（wall/dut/tick），供 §3.3 的实测 |
| `online_session(...)` | 新增：父进程用管道驱动一个 online host，逐条回答 `NEED_RECORD` 并把 host 的 `case` 行折回策略；`stop_after` 用于前缀子进程 |
| `run_ip_only` | 重写会话部分：`fuzz`/`case_isolation` 选择、按协议建 request、三个 runner（`fuzz_long_runner` / `fuzz_prefix_runner` / `isolated_runner` / `batch_runner`）、前缀子进程日志保存到 `prefix-runs/`、`advance` 实测段、`fuzz` 段、`fuzz.json`、`cases_not_run`、新状态 `fuzz_completed`；`request` 先算再建输出目录（具名拒绝不再留下空目录） |
| `session_advance_measurement(...)` | 新增：单次 pass 的 ticks/DUT 秒、总 ticks/DUT 秒、子进程数、事务执行次数与重放次数、重启/IO 开销（`run_seconds - dut_seconds`） |
| `main()` | 新增 `--fuzz`、`--cases`、`--seed`、`--case-isolation`；退出码接受 `observations_passed`/`fuzz_completed` |

### `scripts/inprocess_ip_only_host.cpp`（本代理负责）

| 位置 | 行为 |
| --- | --- |
| 文件头注释 | 写明四种协议的 trace 采样与完成判据、online 闭环用途、`timing` 行 |
| `#include <chrono>`、`seconds_since`、`decimal6`、`g_started`、`g_dut_seconds` | 宿主自测时间 |
| `Run::eval()` | 只在 `model.eval()` 里累计 DUT 秒（`edge()` 三次 eval 自然计入，不重复计） |
| `Observation` | 新增 Wishbone / TL-UL / AXI4-Lite 采样字段 + `trace_offset`/`have_offset`（APB3 字段不动） |
| `trace_tick` | 由“只有 APB3”改为 `#if IP_ONLY_PROTOCOL_*` 四分支：`psel&penable&pready`；`cyc&ack`（另计 `stb` 脉冲与可选 `stall`）；A 通道握手 + D 通道握手；AW+W+B / AR+R（BRESP/RRESP 非零记 `axi_resp_non_okay`） |
| case 行 | APB3 分支逐字节不变；新增 Wishbone（`wb_*`、`wb_offset`、`wb_acks`、`wb_stb_pulses`、可选 `wb_stall`）、TL-UL（`tlul_*`、两个握手计数）、AXI4-Lite（`axi_*` 五通道 + 地址/数据/响应码）字段组，三种都带 `target_offset` |
| `main()` 结语 | 在 `summary` 前多打一行 `timing wall_seconds <f> dut_seconds <f> dut_fraction <f> ticks <n> cases <n>`（`summary` 行本身未改） |

### `scripts/run_inprocess_f1f6.py`（只动 ip-only 分派那一处 + 一个参数）

| 位置 | 行为 |
| --- | --- |
| `dispatch_secondary_mode` 的 `elif args.mode == 'ip-only':`（约 7739 行） | `fuzz=(True if args.fuzz else None)` → `fuzz=dict(cases=args.cases, seed=args.seed)`（与 cpu-only 分支同形）；新增 `case_isolation=getattr(args, 'case_isolation', None)`（`getattr` 是为了不要求调用方一定带该属性） |
| `main()` argparse（`--quiet` 之后） | 新增一行 `--case-isolation {long-running,prefix-replay}`，`default=None`，帮助文本注明仅 `--mode ip-only` 使用 |

### 配置与测试

| 文件 | 内容 |
| --- | --- |
| `configs/scenarios/p2-ip-only-pulp-timer-apb3.json` | P0 的 13 条 APB3 事务 + `loops: 2`，不声明 `case_isolation`（→ 长驻默认）；`fuzz.wait_every: 9` |
| `configs/scenarios/p2-ip-only-opentitan-rv-timer-tlul.json` | TL-UL rv_timer 15 条（INTR_STATE0 rw1c / INTR_TEST0 脉冲 / CTRL bit0 / CFG0 复位值 `0x00010000` / compare 写清除 / mtime 推进） |
| `configs/scenarios/p2-ip-only-zipcpu-uart-wishbone.json` | Wishbone wbuart 9 条（SETUP 复位值 25 / 读写往返 / FIFO_STATUS / TXREG 真实入队） |
| `configs/scenarios/p2-ip-only-zipcpu-axiluart-axi4lite.json` | AXI4-Lite axiluart 9 条（同一寄存器的五通道读写） |
| `configs/scenarios/p2-ip-only-pulp-i2c-assertion-armed.json` | P0 的 I2C 断言武装批次，改为长驻形状 |
| `tests/integration/test_p2_ip_only_fuzz.py` | 新增 44 个测试（协议/角色/请求、case 检查、会话形状、fuzz 策略与确定性、timing 聚合、真实断言分类、入口分派） |
| `tests/integration/test_inprocess_ip_only.py` | **改动 1 个测试**：`test_a_protocol_this_increment_does_not_drive_is_refused_by_name` 原本断言 `ip_port_fields(..., 'axi4-lite')` 被拒——这正是本轮取消的限制；改为“四种协议被驱动 + 第五种（ahb-lite）具名拒绝”。其余 57 个测试未动 |

## 3. 真实结果

### 3.1 四种目标协议（全部 `--mode ip-only`，长驻）

| run | profile | model | cases | status | ticks |
| --- | --- | --- | --- | --- | --- |
| `apb3-long-running` | `pulp_timer_irq` | `local_runtime_pulp_timer_active` | 26 | observations_passed | 125 |
| `tlul-long-running` | `opentitan_rv_timer_local` | `local_runtime_tlultimer_target` | 15 | observations_passed | 69 |
| `wishbone-long-running` | `zipcpu_uart` | `local_runtime_wbuart_target` | 9 | observations_passed | 52 |
| `axi4lite-long-running` | `zipcpu_axiluart` | `local_runtime_axil_target` | 9 | observations_passed | 52 |

每种协议被这批 case 钉住的设备事实（逐字 case 行见证据 README）：

* **TL-UL**：`INTR_STATE0` 复位 0 → 写 `INTR_TEST0=1` → 读回 `1` → 写 1 清除 → 读回
  `0`；`CFG0` 复位 `0x00010000`（step=1）；`CTRL=1` 读回 1；active 期间
  `TIMER_V_LOWER0` 由 0 推进到 `0x13`；写 compare 清 `INTR_STATE0`；A 通道
  `a_opcode` 读=4/写=0、`a_mask=15`。
* **Wishbone**：`SETUP` 复位 `0x19`（`INITIAL_SETUP=25`），写 `0x0a` 读回 `0x0a`；
  `FIFO_STATUS=0x403f4000`；`TXREG` 写 `0x41` 真入发送 FIFO。完成样本是 `cyc=1`、
  `ack=1`、`stb=0`（registered-ack 的单周期 `stb` 脉冲 + `cyc` 保持），`wb_adr` 是
  从机自己的字地址，`wb_offset=4*adr`。
* **AXI4-Lite**：读 = 一次 AR + 一次 R，写 = 一次 AW + 一次 W + 一次 B（五通道计数
  各为 1），`wstrb=15`，`bresp/rresp=0`。该从机只驱 OKAY，非 OKAY 记为 `unknown`。
* **APB3**：与 P0 相同的 26 条观测（count 回读、compare 复位、compare 中断脉冲、
  两个声明 fault 事务返回 0 字）。

### 3.2 闭环 fuzz

| batch | cases | seed | status | strategy counts | 回读对 |
| --- | --- | --- | --- | --- | --- |
| `fuzz-apb3` | 64 | 11 | fuzz_completed | read 20 / readback 19 / wait 5 / write-increment 5 / write-readback-mutated 4 / write-random 3 / write-bitflip 2 / write-corpus-mutated 2 / write-ones 2 / write-seed 1 / write-zeros 1 | 19 可比（14 相等、5 不等），0 errored |
| `fuzz-tlul` | 48 | 23 | fuzz_completed | 见 `fuzz.json` | 14 可比（6 相等、8 不等），2 errored |

* APB3 的 5 个“不等”全部落在偏移 `0x0c`：PULP timer 只解码两个 16 字节寄存器块，
  寄存器 3 未实现，写进去什么都读回 `0x00000000`——与 P0 的声明 fault 事务是同一个
  设备事实，这次是**闭环从设备身上学到的**。
* TL-UL 的 2 个 errored 是真实错误应答：未映射地址回 `d_error=1`、`d_data=0xffffffff`，
  仍是“完成了一次传输”的设备应答，case 行同时给出 `response_error 1` 与
  `tlul_d_error 1`。
* 回读比较从不作为设备通过/失败，只记 `equal`/`differs`/`errored`。

### 3.3 长驻 vs 前缀重放（同一序列，实测）

APB3、26 例、同一份声明；`dut_seconds` 是 host 在 `model.eval()` 里自己量的。

| 事实 | long-running | prefix-replay |
| --- | --- | --- |
| 子进程数 | 1 | 26 |
| 执行 ticks（单 pass / 实际） | 125 / 125 | 125 / 1718 |
| 事务执行次数（其中重放） | 26 / 0 | 351 / 325 |
| run wall（s） | 0.00424 | 0.10871 |
| DUT eval（s，单 pass / 总） | 0.000019 / 0.000019 | 0.000019 / 0.000281 |
| 重启+IO 开销（s） | 0.00422 | 0.10842 |
| 每例 run wall（ms） | 0.163 | 4.181 |

闭环 fuzz 同一 64 例序列：long-running 1 进程 / 282 ticks / 0.00868 s，prefix-replay
64 进程 / 9174 ticks / 0.38161 s（2080 次事务执行，其中 2016 次是重放）。两次
`fuzz.records` 完全相同、`prefix_replay.consistent=true`，说明前缀形状跑的是**同一个
会话**，只是更贵。

诚实说明：这些 target 很小，`eval()` 只有几十微秒，所以两种形状里“DUT 占比”都低；
真正变化的是**固定成本（进程启动 + 模型初始化）被付了多少次**和**事务被重复执行了
多少次**。长驻把固定成本付 1 次、事务每条只跑 1 次；前缀形状付 26/64 次并把 351/2080
次事务真正驱动了一遍。这正是“初始化一次、时间用于推进 DUT”与“逐例重启”的实测差别。

### 3.4 断言长驻行为

* 语义：`%Error: <file>:<line>: Assertion failed in <scope>: <text>` → 进程中止 →
  长驻会话在该事务处结束，事件保留 source/line/scope/text/tick/`case_begin` 记录，
  后续 case 计入 `cases_not_run`，不重跑任何事务；`prefix-replay` 下归因到唯一新增
  事务，并逐条校验早前 case 行一致（`prefix_replay.consistent`）。
* 真实中止证明（`assertion-probe/`，一次真实 Verilator 中止，无 `--assert`）：
  `classify_child_process` → `{kind: dut_assertion, source: probe.sv, line: 11,
  scope: probe.probe, text: declared probe assertion fired at cycle 9}`，
  `scan_assertion_lines` → `tick 9`、事务 `index 1 (write)`、
  `record CASE W 00000008 00000001`。**明确标注：这是捕获自检，不是所选 IP 的断言。**
* 所选 IP 的断言审计（从链接后的 archive 读，不假设）：I2C 有 2 处编译进 archive
  （`i2c_master_bit_ctrl.sv:374`、`i2c_master_byte_ctrl.sv:220`，都是 one-hot FSM 的
  `unique case`，RTL 只会给定义态，合法寄存器序列与声明 fault 命令字都到不了）；
  timer / wbuart / axiluart archive 里没有任何断言串。长驻 I2C 批次：14 例、
  `model_assertion_code_present=true`、`events=[]`、单进程 89 ticks。

### 3.5 回归

`p0-regression-{declared,online,records,env-budget}` 用 P0 场景与 P0 记录列表重跑，
case 行与 `runs/p0-ip-only/{declared,online,records,env-budget}/run.log` **逐字节相同**
（26 / 13 / 16 / 26 行；`diff` 为空，命令见证据 README §6）。APB3 长驻批次与 P0
declared 的唯一差异是第二轮的 `loop` 标签（`loop 1` 对 `loop 0`），因为 P0 的前缀
子进程一次只跑一轮；所有观测字段（rdata、response_error、total_tick、transfers、
irq、trace）相同。

## 4. 仍拒绝 / 仍未知（具名）

实录在 `runs/p2-ip-only-20261103/refusals/refusals.log`（每次真实调用，退出码 2）：

| 拒绝名 | 触发条件 |
| --- | --- |
| `unsupported-ip-only:protocol:ahb-lite` | Caliptra SHA-256 的 AHB-Lite MMIO 从端；AHB 目标适配不在本轮（C 代理的区域） |
| `unsupported-ip-only:window-size-differs-from-profile` | 声明窗口与 profile `address.window_size` 不一致 |
| `unsupported-ip-only:target-request:wishbone:unsupported-target-trace:wishbone:addressless:<profile>` | 无地址端口的 classic Wishbone 从机（`zipcpu_timer`）：没有 `adr` 就无法报告从机真正解码的偏移 |
| `unsupported-ip-only:case-isolation:prefix-replay-with-online-handover` | `--online` 与显式 `--case-isolation prefix-replay` 同时给 |
| `unsupported-ip-only:fuzz-with-handover-records` | `--fuzz` 与 `--records` 同时给（闭环不接受固定记录） |
| `unsupported-ip-only:fuzz-cases` / `fuzz-seed` / `fuzz-key` | fuzz 预算/种子/键非法 |

仍未知/限制（不宣称）：

* 四种目标都是寄存器窗口；UART 的引脚输入仍由声明常量绑死（`rx=1`、`cts_n=0`），
  TXREG 写真的进了发送 FIFO，但本轮**没有观测串行帧**（E1 的串行 peer 主题）。
* fuzz 只在声明窗口内做事务/偏移/值变异，不解析寄存器位域，可能命中保留位——那本身
  是真实激励，回读记录设备怎么处理。
* 回读对里任一侧设备回错误应答的记为 `errored`，不作为保持性证据。
* 无 RTL 覆盖率、无证书、无 replay、不宣称 bug；总线超时仍是 environment，不是断言。
* `unsupported-ip-only:window-wider-than-address-bus` 这个守卫仍在，但修好 word-addressed
  窗口换算后，审计过的 profile 已无法触发它（本目录实录的是
  `window-size-differs-from-profile`）。

## 5. 测试

* 新增 `tests/integration/test_p2_ip_only_fuzz.py`：**44 passed**。
* `tests/integration/test_inprocess_ip_only.py`：**57 passed, 1 failed**。失败的是
  `test_cpu_only_mode_maps_the_entry_fuzz_options_onto_its_fuzz_mapping`
  （`AttributeError: 'types.SimpleNamespace' object has no attribute 'fuzz_mode'`）：
  CPU-only 分派已经读 `args.fuzz_mode`（见 `scripts/run_inprocess_f1f6.py` 约 8111 行），
  该测试的 `fake_args` 还没跟上，属 A 代理区域的在途改动，与本代理的 hunk 无关
  （本代理只改 ip-only 那一处分派与一个 argparse 参数，没有碰 cpu-only 分支）。
* `tests/integration/test_inprocess_f1f6_entry.py`：**196 passed**（该文件正被其他代理
  扩展，计数以当时工作树为准）。
* 三个文件合计 **297 passed / 1 failed**（失败即上面 A 代理那条）。本代理新增与改动涉及
  的 44 + 57 个测试里，除该用例外全部通过。

## 6. 需要其他代理配合

1. **A 代理**：`scripts/run_inprocess_f1f6.py` 的 cpu-only 分派现在读 `args.fuzz_mode`，
   但 `tests/integration/test_inprocess_ip_only.py::fake_args`（以及 A 自己的测试）没有
   `fuzz_mode`，导致该用例 `AttributeError`。请在自己的区域补 `fuzz_mode='program'`
   并更新 cpu-only 期望（顺带说一句：本代理只改了 ip-only 那一处分派与一个 argparse
   参数，没有碰 cpu-only 分支）。
2. **F 代理**：`tests/inprocess/.../test_inprocess_f1f6_entry.py::test_a_clock_rate_mismatch_is_normalized_or_refused_by_name`
   目前失败，因为非整数比时钟已经不再按名拒绝。请按新的行为更新该用例。
3. **C 代理（AHB 目标）**：本轮的 IP-only 宿主已经做到“按 target trait 选协议采样”，
   但 AHB-Lite 两相（`htrans`+`hready`）采样不在本轮；ip-only 对 AHB profile 仍以
   `unsupported-ip-only:protocol:ahb-lite` 拒绝（实录在证据目录）。若 C 的适配器落地，
   ip-only 侧的接入点就是 `ip_port_fields` + `PROTOCOL_TRACE_ROLES` + 宿主
   `trace_tick` 的第五个分支，不需要再动会话逻辑。
4. **入口索引**：`docs/reports/README.md` 的索引行由父代理统一插入（本轮不编辑该文件）。
   建议插到「2026-11-02 通用化」表末尾：

   ```markdown
   | **P2 IP-only：fuzz、四目标协议、长驻执行**：`--fuzz` 真闭环（写→回读→以设备回读为下一轮变异种子；APB3 64 例/TL-UL 48 例，每例输入/依据/观察/结果在 `fuzz.json`）；单 IP 模式扩到 `apb3`/`tl-ul`/`wishbone`/`axi4-lite`（26/15/9/9 例，真实 trace 完成判据与采样地址）；默认改长驻（26 例：1 进程 125 ticks 0.004 s vs 26 进程 1718 ticks 0.102 s，325/351 次事务为重放），`--case-isolation prefix-replay` 保留；断言命中的长驻中止语义与真实中止捕获；P0 四形态 case 行逐字节回归 | [P2 IP-only 报告](p2-ip-only-fuzz-and-protocols-20261103.md)、[证据](../../runs/p2-ip-only-20261103/README.md) |
   ```

## 7. 证据与复现

* 证据：`runs/p2-ip-only-20261103/README.md`（逐字 case 行、精确命令、实测对比、
  断言行为、拒绝实录、限制）、`campaign.log`、`measurements.json`、
  `refusals/refusals.log`、`assertion-probe/capture.json`。
* 整套复现：`sh runs/p2-ip-only-20261103/run.sh`（约 2 分钟，含 14 个 run、6 条拒绝、
  探针重建与测量表生成；每一步都用 `expect <status>` 卡住状态）。
