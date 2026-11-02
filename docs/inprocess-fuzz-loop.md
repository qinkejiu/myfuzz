# 单进程闭环 fuzz：用法与语义

日期：2026-11-01。状态：用法与语义说明。本文件不新增运行证据，也不把模块测试当作真实 RTL 结果；真实批次的结果只以 `runs/` 和 `docs/reports/` 里的日期报告为准。

统一入口 `scripts/run_inprocess_f1f6.py` 原来按 `--records` 预载一组记录。`--fuzz` 把同一条回路接上：**同一进程**执行一个 case，读回它自己的 `case` 行，生成或变异下一条合法输入，再交给同一组模型。普通 case 之间不重启、不 reset、不重建模型；只有 F5/F6 的有界等待超时会在下一例前重置设备。

## 1. 变的是什么，没变的是什么

- 一个 CPU 模型、一个寄存器目标模型、一个可选 DMA 模型、一份宿主 RAM 镜像，只在批开始时初始化一次；绑定头、固件、trampoline 槽、邮箱、handler block、DMA 源/目的 RAM 都只生成一份。
- 每条输入的交付只是写 RAM：F1 写 trampoline 槽并补一条返回跳转，F2 写参数格，F3/F4 写参数和值，F5/F6 写 CPU 读的 input block，再写命令字。没有任何一条普通 case 触发模型 reset。
- `--records` 仍是固定序列入口；`--fuzz` 与它互斥，按构造走 `--online`，不预载记录。
- 宿主与驱动的会话协议固定为：宿主打印 `NEED_RECORD <n> tick <t>`，驱动写一行 `CASE <FLOW> <hex...>`，宿主回 `CASE_INSTALLED <n>` 和一行 `case <n> <status> flow <FLOW> record <text> ...`，整批末尾一行 `summary <status> cases <n> ...`。解析器就是固定记录路径用的 `parse_case_line`/`parse_summary_line`。
- 一个宿主 tick 驱动这一批里的所有模型；声明的时钟频率不建模，`summary.json` 的 `clock_assumption` 只把这句事实写成文字。

## 2. 命令行与预算

```sh
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json \
  --cache runs/_fuzz-cache-20261101 \
  --output runs/_fuzz-example-20261101 \
  --fuzz --cases 64 --seconds 120 --seed 20261101
```

示例输出目录必须是**新目录**（`--output` 已存在会直接报错），本次没有运行这条命令，因此不引用它的任何数字。该配置声明 `f1_program_words: 4`，六条流都由现有组件声明提供。

| 参数 | 默认/约束 | 语义 |
|---|---|---|
| `--fuzz` | 开关；不能与 `--records` 同用 | 闭环模式；强制 `--online`，不预载记录 |
| `--cases` | 默认 32；正整数 | case 预算；每执行完一例检查一次 |
| `--seconds` | 默认无；正数 | 墙钟预算；到点在当前 case 结束后停止；与 `--cases` 先到者生效 |
| `--seed` | 默认 0；非负整数 | 策略 PRNG 的种子；同一棵树、同一预算下可复现输入序列 |
| `--corpus` | 默认无；路径 | 用保存的 `corpus.json` 给 corpus 播种；**保存的 corpus 不是执行许可**，见第 5 节 |
| `--max-ticks` | 默认见下 | 整个宿主进程的 tick 总预算 |
| `--quiet` | 开关；fuzz 模式总是加 | 抑制逐 tick/逐传输事件行，`case` 和 `summary` 行不变 |
| `--retain-cases` | 默认 512；正整数 | `summary.json`/`fuzz.json` 里保留的 case 行上限；滚动统计始终完整 |
| `case_tick_budget`（场景键） | 默认 4000；1..1,000,000 | 宿主每例 tick 守卫；慢 CPU 的 F5 等待会被它截断，需与 `handler_wait_iterations` 一起声明，见 Wishbone 证据 |
| `--stall-seconds` | 默认 30；正数 | 宿主超过该时长没有任何输出时终止并记为 `host_stalled`，不无限阻塞 |
| `--no-prefix` | 开关 | 不写 `prefix.txt`/`observations.jsonl`（长跑不需要复现时用） |
| `--log-mode` | `case`（默认）/`summary` | `summary` 只写 summary/错误/声明行，仍解析每一例；长跑可显著减小 `run.log` |
| `--replay-prefix` | 路径 | 用保存的 `prefix.txt` 在新进程按序重放；不能再给 `--fuzz`/`--records` |
| `--replay-observations` | 路径 | 与 `--replay-prefix` 配套的 `observations.jsonl` |
| `--replay-limit` | 正整数 | 只重放前缀的前 N 条，用于复现某条依赖前序配置的 case |
| `--records` | 字符串 | 固定序列；给 `--fuzz` 或 `--replay-prefix` 时被拒绝 |

`--max-ticks` 的实际默认值是 `max(20000, cases*4096)`（`--fuzz`）或 `20000`（固定记录），`--help` 与实现一致。此外每个 case 另有 **4000 tick** 的宿主守卫；超过时 C++ 抛出异常、本轮没有 `summary` 行，结果是 `host_error`，不是一条 case finding。

## 3. 输出目录

| 文件 | 何时写 | 内容 |
|---|---|---|
| `summary.json` | 总是（宿主结束后） | 入口结果：`status`、`fuzz_result`、`fuzz`、`fuzz_inputs`、`cases`、`run_summary`、`certificate: "none"`、`replay: "not_performed"` |
| `fuzz.json` | 仅 `--fuzz` | `inprocess_fuzz_session.v1` 会话文档，加 `inputs` 和 `correspondence` |
| `fuzz_inputs.json` | 仅 `--fuzz` | `inprocess_fuzz_inputs.v1`：`seed`、`flows`、`f1_program_words`、`seed_records`、`word_space`、`f1` |
| `corpus.json` | 仅 `--fuzz` | `inprocess_fuzz_corpus.v1`：含载入、seed 和发现条目，每条带 `picks`、`discoveries`、`origin`、`parent` |
| `prefix.txt` | 仅 `--fuzz`（`--no-prefix` 关闭） | 逐行保存实际交付的输入文本，顺序即会话顺序 |
| `observations.jsonl` | 仅 `--fuzz`（`--no-prefix` 关闭） | 每例一行关键观察（flow/record/status 和该流的可比较字段），供前缀重放比较 |
| `replay.json` | 仅 `--replay-prefix` | `inprocess_prefix_replay.v1`：期望/实际 case 数、逐例关键观察和第一个不符 |
| `run.log` | 总是 | 宿主标准输出与错误的完整日志；fuzz 模式没有事件行 |
| `spike_config.h`、`firmware.txt` | 总是 | 生成的绑定头和 RAM 镜像 |
| `cpu_request.json`、`source_request.json`、`dma_request.json` | 按组件 | 生成模型用的 request；无 DMA 时不写 `dma_request.json` |
| `inprocess-spike` | 总是 | 链接出的宿主可执行文件 |

不写 `coverage.json`、`replay.json` 或证书文件；fuzz 批次也不做独立进程 replay。`corpus.json` 由入口写出，`--corpus` 只负责读入。

## 4. 输入空间

流由组件声明决定：`F1`–`F4` 从基础 arity 出发，其中 `F1` 还要求 CPU profile 声明 RV32（`xlen == 32`）；RV64 CPU 的固定记录 F1 仍可运行，但 fuzz 不提供 F1，并在 `fuzz_inputs.json` 的 `f1` 字段说明原因。`F5` 需要目标声明一组可用的 IRQ 事实；`F6` 需要 DMA 模型和块长。缺声明时入口按名字拒绝（`unsupported-f5:...`、`unsupported-f6:no-dma-model:...`），fuzz 不会凭空补一条流。声明的候选集为空（例如没有任何可写 32 位寄存器因而没有 F4 地址）时，该流不会进入 fuzz 的 `flows`，而是连同原因记录在 `fuzz_inputs.json` 的 `excluded_flows`；只有所有流都不可用时才以生成错误结束，而不是伪造输入。

| 流 | 记录形状 | fuzz 生成的空间 |
|---|---|---|
| `F1` | `F1:<word>[:<word>...]` | 1 到 `f1_program_words`（1..16，默认 1）条 32 位直线指令 |
| `F2` | `F2:<addr>` 或 `F2:<addr>:<stim>` | 声明的可读 32 位目标寄存器，加 RAM 数据窗口；二词形式只允许 PADIN。引脚目标的读值只要求等于设备同步锁存；瞬时 wire 另记为 `pad_settled`，因同步器延迟而不要求同拍相等 |
| `F3` | `F3:<addr>:<value>` | 声明的程序数据窗口（`PROGRAM_DATA_WORDS` 为 16 字，按 RAM 裁剪），按 4 字节对齐 |
| `F4` | `F4:<addr>:<value>` | 声明的可写 32 位目标寄存器，按 4 字节对齐 |
| `F5` | `F5:<w0>:...:<wN>` | 每个声明的 trigger write 一个值，`N+1` 等于 trigger 数 |
| `F6` | `F6:<w0>:...:<wN>` | 每个声明的 DMA block word 一个值，`N+1` 等于 `block_words` |

F1 的硬约束：只允许 LUI、AUIPC、OP-IMM、OP，以及多字模式下的 LW/SW；LW/SW 必须以 `x18` 为基址、4 字节对齐、落在声明的 `PROGRAM_DATA_WORDS`（16 字，64 字节）窗口内；不允许控制流、CSR、压缩指令。程序生成/变异器把 `x8`（邮箱指针）、`x9`（槽基址）、`x18`（数据窗口基址）当作保留寄存器；入口的程序门和 C++ 宿主在程序模式下都按名字拒绝写这三个寄存器（单字旧模式的门口保持原样）。`f1_program_words` 为 1 时保留原来的单字 ALU 输入。

F2 的二词形式只在引脚目标上存在：第二个字是宿主外部驱动值，按声明位宽掩码；其他地址不允许第二个字。F5 的新输入有一半概率取声明的示例值行，并常保留最后一个触发字（该字决定中断是否发生）；F6 的第一次 fresh（通常作为 seed）取模块内置示例向量，之后随机。目标没有可写寄存器时 F4 的候选集为空，这是声明问题，不是 fuzz 能补的。

## 5. 变异与门口

- F1 每次 `mutate_program` 恰好做一处结构改动：替换一条指令、改一个操作数、在长度未满时插入一条、在多于一条时删除一条；结果始终是合法程序。
- F2–F6 的字级变异由 `WordSpace.mutate` 完成：地址改选、值位翻、加/减 delta、interesting value（`0`、`1`、`0xffffffff`、`0x80000000`），F2 在 PADIN 上还会做一词/二词切换，F5/F6 改值。实现一次施加 **1–3 处**合法改动，不是严格的一步一处；要严格单步必须改 `src/myfuzz/fuzz/word_spaces.py`。
- 每条候选在交给宿主前都过入口自己的门：`parse_record` 生成规范文本和 `CASE ...` 消息，`validate_record` 再按当前 ISA、窗口、引脚和 `f1_words` 检查。生成最多重试 8 次，仍不合法则整批以生成错误结束；不会把手写不合法的记录送进模型。
- `fuzz_seed_records` 里的场景前置记录也过同一个门，并先于生成输入交付；它们只声明一个真实前置条件（例如先让引脚成为输出），不是额外执行权限。
- 策略以 0.85 的概率从 corpus 选父本做变异，否则从声明的流中取 fresh；从 corpus 取出的父本只作为变异起点，不直接原样交付。

## 6. 反馈与 corpus

反馈只读 `case` 行里真实打印的字段；缺失是 unknown，不是 0。计数器先归桶（`0`、`1`、`2-4`、`5-8`、`9-16`、`17+`），值先分类（`zero`、`one`、`small`、`all-ones`、`high`、`other`），少数身份本身就是发现的字段保留精确值。

| 流 | 从 case 行读的字段 | 特征（feature 元组） |
|---|---|---|
| 通用 | `i_fetches`、`d_reads`、`d_writes`、`apb_reads`、`apb_writes`、`retires`、`rvfi_writebacks`、`rvfi_order_monotonic`、`traps`、`bus_errors` | `('count', <key>, <bucket>)`；case `failed` 时另有 `('status', <flow>, 'failed')` |
| `F1` | `prog_words`、`prog_retires`、`prog_pc_ordered`、`prog_insns_match`、`prog_rd_mask`、`prog_last_rd`、`prog_last_wdata`、`prog_traps`、`data_changed`、`data_hash_after` | `words`、`retires`、`pc_ordered`、`insns_match`、`rd_mask`（精确）、`last_rd`、`last_wdata_class`、`traps`、`data_changed`；仅当窗口变化时加 `data_hash` |
| `F2` | `read_from`、`read_addr`、`target_reads`/`apb_reads`、`read_value`、`echo_value`、`pin_stimulus` | `read_from`、`read_addr`、`target_reads` 桶、`value_class`、`echo`（`committed`/`lost`）、`pin_stimulus` |
| `F3` | `write_addr`、`write_value`、`ram_after`、`write_be` | `write_addr`、`value_class`、`ram_committed`（`yes`/`no`）、`be` |
| `F4` | `target_offset`/`apb_offset`、`mmio_value`、`target_writes`/`apb_writes`、`target_resp`、`out_after`、`dir_after` | `target_offset`、`value_class`、`target_writes` 桶、`target_resp`；引脚目标另有 `out_after`、`dir_after` |
| `F5` | `irq_edges`、`irq_takes`、`apb_read_data`/`target_read_data`、`isr_read_register_kind`、`irq_cause_pins`+`inten_at_irq`、`pad_rise_events`/`pad_fall_events`/`first_transition_tick` | `irq_edges`（上限 3）、`irq_takes`（上限 2）、`status_class`、`isr_kind`；引脚目标另有 `cause_enabled`。因果检查接受上升或下降，只要方向由设备编程的中断类型决定且 cause mask 有使能 pin |
| `F6` | `dma_reads`、`dma_writes`、`ctl_status`、`busy_after`、`err_after`、`irq_takes`、`dst0`..`dst3` | `dma_reads`/`dma_writes` 桶、`status_class`、`busy_after`、`err_after`、`irq_takes`、`dst_hash`（四个字都在时算 FNV-1a） |

`wait_timeout` 是 F5/F6 的 case 字段和 summary 计数，不是特征元组；超时的 case 以 `failed` 状态特征进入反馈。`feedback` 文档的 `distinct` 就是本次发现的去重特征数。

一个 case 只要提供了此前未见过的特征，它的输入就进入 corpus，并记一次 `discoveries`；没有新特征的 case 不扩容。corpus 在入口固定上限 **256** 条，溢出时淘汰“被选最多、发现最少”的条目，从不淘汰刚刚加入的条目；`choose` 在“被选次数最少”的四分之一里均匀抽取，所以新条目先被用到。`--corpus` 只恢复队列和计数：载入的条目仍要经过当前场景的 `valid`/门，流不被提供、地址越界或 F1 词不合法时会被拒绝并回退到 fresh（corpus 条目本身不因此删除），不能靠旧 corpus 打开新空间。

反馈是**观察**，不是覆盖率：没有 RTL coverage、没有证书、没有 replay。相反，`summary.json` 明写 `"certificate": "none"`、`"replay": "not_performed"`。

## 7. 失败处理

- 宿主把当前 case 判为 `failed` 时照常打印 `case ... failed`、继续下一例，并在末尾写 `summary failed ...`。驱动把这一例放进 `fuzz.json` 的 `findings`，批次状态是 `fuzz_completed_with_findings`，进程仍以 0 退出。**case 失败是 finding，不是整批中止。**
- F5/F6 的等待有界：`handler_wait_iterations`（场景键，默认 256，允许 1..2047）耗尽时，固件把标志格写成 **2**；宿主读回后打印 `wait_timeout 1`，在 summary 里累计 `wait_timeouts`，并在下一例前调用 `recover_devices()` 只重置 IP/DMA（CPU 和 RAM 不重置），同时累计 `device_resets`。CPU 回到轮询循环，批继续。
- 普通完成的 case 不重置设备，设备状态会带到下一例；只有上面的超时恢复会清设备状态。这是“跨 case 设备状态”的准确边界。
- 每个 case 的 4000-tick 守卫、宿主未消费邮箱等属于宿主异常：C++ 抛错，日志里只有一行错误，没有 `summary`，驱动判为 `host_error`，`summary.json` 状态是 `fuzz_failed`，退出码 1。
- 宿主在预算用完前自行停止（包括 `--max-ticks` 提前耗尽）且驱动没有主动结束，也是 `host_error`。
- 驱动侧的生成/解析错误会把 `fuzz.json` 的 `session_status` 记为 `completed_with_error`；摘要状态目前只把 `host_error` 和通过 case 的对应不符升级为 `fuzz_failed`，所以这类错误要同时看 `fuzz.json`，不能只看 `summary.json` 的 `status`。
- `fuzz.json` 的 `correspondence` 只把**通过 case** 的对应不符升级为批失败；失败 case 自己的对应差异是预期 finding。`session_status` 原样记录 `completed`、`completed_with_error` 或 `host_error`。

| `summary.json` 的 `status` | 含义 | 退出码 |
|---|---|---|
| `fuzz_completed` | 预算内跑完；failed case 中只有 `not_triggered`（随机输入没有触发设备），或没有 failed case | 0 |
| `fuzz_completed_with_findings` | 跑完，至少一个非预期类别（`wait_budget_exceeded`、`protocol_error`、`device_anomaly`、`execution_*`、`observation_mismatch`） | 0 |
| `fuzz_failed` | `host_error`、驱动侧生成/解析错误（`completed_with_error`），或通过 case 的对应不符 | 1 |

### 7.1 失败分类（2026-11-01 修正）

每个 failed case 由 `classify_case()` 依据 case 行里真实打印的字段分类，分类和详情写入 `summary.json` 的 `cases[].failure_class/failure_detail/failure_severity`、`failure_classes`，以及 `fuzz.json` 的 `findings`（异常）或 `expected_failures`（正常未触发）。`not_triggered` 不再被当成硬件缺陷。

| 类别 | 判据（只看 case 行） | 含义 | 是否 finding |
|---|---|---|---|
| `passed` | case 状态通过 | — | 否 |
| `not_triggered` | F5/F6 `wait_timeout 1` 且 `irq_edges 0` | 声明触发序列执行完，但随机值没有让设备产生 IRQ；有界等待到期 | 否，进 `expected_failures` |
| `wait_budget_exceeded` | `wait_timeout 1` 且 `irq_edges > 0`（CPU 未接受，或接受了但 ISR 未完成） | 设备已产生 IRQ，预算内未走完；是预算限制，不是已证明的硬件缺陷 | 是 |
| `protocol_error` | `bus_errors > 0`、AXI `target_resp != 0`、宿主协议异常（握手/窗口/请求不完整） | 总线/协议层错误 | 是 |
| `device_anomaly` | CPU 接受了 IRQ 但 ISR 未置标志；ISR 存的状态值不符；DMA 完成后仍 busy/err；目标读数据与 CPU 响应不符；F3 RAM 未提交 | 设备/数据通路异常 | 是 |
| `execution_exception` | `traps > 0` | CPU 报告了 trap；RVFI 无 cause | 是 |
| `execution_anomaly` | F1 退休数/顺序/指令不匹配；F2 CPU 未写回读值 | CPU 执行路径观察不一致 | 是 |
| `state_contamination` | 非 F5/F6 的 case 实际接受了中断（`irq_takes > 0`），或 F4 出现目标读 | 前序 case 留下的 IRQ/handler 状态在后续 case 生效；当前没有声明 EOI/clear 的设备会这样 | 是 |
| `observation_mismatch` | 其余已执行但未满足声明观察的情况 | 需要进一步诊断 | 是 |

`fuzz_result.expected_failures`、`fuzz_result.findings` 和 `fuzz_result.failed` 分开计数；`summary.json` 的 `failure_classes` 给出完整计数。宿主异常另有 `host_failure: {kind, message}`，`kind` 为 `wait_budget_exceeded`、`protocol_error` 或 `host_abort`。

### 7.2 超时恢复的状态边界（2026-11-01）

`wait_timeout 1` 后，下一例之前只复位 IP/DMA，保留 CPU 与 RAM；这段语义同时写进 `summary.json` 的 `recovery` 和 summary 行的 `recovery_scope devices_only_cpu_and_ram_retained`。

| 状态 | 超时恢复后 |
|---|---|
| IP/DMA 内部寄存器和输出 | 复位到 reset 状态 |
| 采样中的 IRQ 边沿/电平 | 清除 |
| 宿主的 MMIO/DMA 在途事务 | 清除 |
| CPU PC、寄存器、流水线 | 保留 |
| RAM、邮箱、handler block、程序/槽 | 保留 |
| 引脚模型 | 从复位后的设备端口重新采样 |
| 固件位置 | 已回到轮询循环，等待下一例 |

后果：超时 case 之前写入的设备配置会丢失；该 case 的未完成中断/DMA 被丢弃；下一例从设备复位态开始，而不是超时前状态；CPU/RAM 状态仍在。不能把“下一例能跑”理解为设备状态已还原到超时前。

## 7.3 输入前缀与失败复现（2026-11-01）

设备和 RAM 状态会跨 case 保留，所以单条输入可能不足以复现一条依赖前序配置的观察。fuzz 模式因此把**实际交付的输入顺序**流式写入 `prefix.txt`，把每例的关键观察写入 `observations.jsonl`；finding 里另有 `prefix_lines`（该例之前的输入条数）。这两份文件只用于重放，不是证书、不是执行权限，也不表示每例都被验证。

```sh
# 复现前缀中的前 N 条（N=2：种子 F4 把引脚设为输出，随后 F5 产生真实 IRQ）
python3 scripts/run_inprocess_f1f6.py   --config configs/scenarios/inprocess-obi-apb-gpio-pins-f1f5-fuzz.json   --cache <cache> --output <new dir> --quiet   --replay-prefix <run>/prefix.txt   --replay-observations <run>/observations.jsonl --replay-limit 2
```

重放在**新进程**中从相同的 reset 状态开始，按序交付前缀输入，只比较 `replay_view()` 选出的关键观察（F1 退休/写回/数据窗口、F2 读取、F3 提交、F4 目标写、F5/F6 IRQ/DMA 事实）；不比较 `ticks`/`seconds`。全部一致时状态为 `replay_matched`，第一处不符写入 `replay.json` 并以 1 退出。重放使用当前配置和当前构建；换树/换配置后不保证相同。`prefix.txt`/`observations.jsonl` 会随 case 数线性增长（磁盘），长跑不需要复现时用 `--no-prefix`。

## 7.4 长批次边界（2026-11-01）

- 会话只保留 `max_cases_recorded` 条 case 行和 `max_submitted_recorded` 条提交行（入口传 `--retain-cases`，默认 512）；首尾各保留一半，`cases_total`/`submitted_total`/`cases_dropped` 精确。**每个通过的 case 都在到达时做对应检查**（`fuzz.json` 的 `correspondence.checked` 覆盖全批，`sampled=false`），不只抽样保留行；失败样本最多保留 32 条原因。
- `--log-mode summary` 可关闭逐例 `case`/`NEED_RECORD` 文本，保留 summary/错误；对话仍逐例解析。F4 写 Timer COUNT 最大值会自触发 IRQ：现由启动时初始化的安全 handler cell 防止未映射访问，并由 F1–F4 的 `irq_takes` 归类为 `state_contamination`（不是设备缺陷）。
- `FeedbackState` 的词汇表有硬上限（默认 8192）；达到上限后新特征只计数、不再保留，`document()` 只嵌入 2048 条样本，同时保留精确的 `distinct`/`by_family`/`features_truncated`。这样 F6 的逐例哈希之类的近似唯一特征不会让内存线性增长。
- corpus 仍有 256 条上限，按“被选最多、发现最少”淘汰；`findings`/`expected_failures` 各自有上限。
- 宿主 stdout 由读线程 + 队列消费，`--stall-seconds` 到期或时间预算到期都能结束，不会因无输出永久阻塞；正常 case 从不重启 CPU/IP/DMA。
- 长跑内存/吞吐的实测见 `runs/fuzz-soak-20261101/`（200k 会话级、约 60 s 入口级）；入口级旧版 `summary.json` 仍因完整特征表而偏大，本版已按上述上限截断，需要以新一轮 soak 数字为准。

## 8. 诚实的限制

- **一个宿主 tick 驱动所有模型。** 声明的 Hz 不建模；不同频率的组件被视为等周期，`clock_assumption` 明写这一点。
- **没有覆盖率。** 反馈只是 case 行里的观察事实，不度量 RTL 行/翻转/状态覆盖，也不证明变异充分。
- **跨 case 状态不是干净的。** 完成的 case 会把设备状态带到下一例；只有超时恢复会重置设备，CPU 与 RAM 仍不重置。
- **F1 只跑直线程序。** 1..`f1_program_words` 条，无分支、无 CSR、无压缩；LW/SW 只能经 `x18` 落在 64 字节数据窗口内。
- **F5/F6 仍要声明。** 没有 IRQ 事实就没有 F5；没有 DMA 模型/块长就没有 F6；行为文件只声明形状，最终仍由 profile 的寄存器、中断、端口交叉校验。
- **新设备仍要 profile/协议/适配器。** 只写一个行为文件不能接入新总线、新 CPU IRQ 形态、新引脚模型或新 DMA 数据通路。
- **协议适配器仍只有两种 CPU 侧和两种目标侧。** CPU 侧是 OBI 与 Wishbone；目标侧是 APB3 与 AXI4-Lite。其他组合按名字拒绝。
- **fuzz 批次没有 replay。** 同一 seed 可复现输入序列，但入口不重放整批，也不产生独立进程 replay。
- **性能数字不在本文件。** 需要数字时看 `runs/` 里的日期报告；本文件不给吞吐或耗时。

## 9. 给设备加闭环输入

已有设备 profile 的前提下，按下面顺序加声明；每步都不改变协议适配器：

1. **行为文件。** F5 写 `configs/behaviors/<device>_f5.json`，schema 为 `inprocess_source_behavior.v1`，字段是 `source_port`、`source_bit_offset`、`pulse_width_ticks`、`trigger_writes`（`[[offset, value], ...]`）、`status_offsets`、`status_cause_bits`、`clear_writes`，需要引脚时再加 `pins`（`padin_offset`、`external_value`、`pad_resolution`）。F6 写 `<device>_f6.json`，schema 为 `inprocess_dma_behavior.v1`，字段是 `block_words`、`irq_pulse_ticks`、`busy_bit`、`err_bit`、`status_kind`。
2. **场景接线。** 在场景里加 `"source_behavior": "configs/behaviors/<device>_f5.json"` 或 `"dma_behavior": "..."`。文件优先于同名内联键，冲突按 `behavior-source-conflict:<key>` 拒绝；没有文件时原有内联键仍生效。需要 F1 短程序时加 `"f1_program_words": 1..16`，需要前置状态时加 `"fuzz_seed_records": ["F4:..."]`，需要更短/更长的有界等待时加 `"handler_wait_iterations": 1..2047`。
3. **仍要写代码的部分。** 新的 CPU 或目标协议要新增适配器和绑定头渲染；新的 IRQ 端口/位宽、新的引脚解析、新的 DMA 数据通路或宽度要改 C++ 宿主；新的流或新的记录形状要同时扩展 `parse_record`、`validate_record` 和 `word_spaces.py`；行为文件与 profile 的交叉校验仍在 `f5_declaration`/`pin_declaration`/`dma_declaration` 里。行为文件不能替代这些。
4. **验证。** 先跑模块测试，再用第 2 节的命令做真实批次；结果和限制写进 `runs/` 的日期报告，不把静态声明当成真实执行：

```sh
PYTHONPATH=src:. python3 -m pytest tests/fuzz tests/composition/test_inprocess_behavior.py -q
```

## 10. 本文件不声称什么

- 不声称已有 fuzz 批次通过、发现了缺陷或达到某个覆盖率/吞吐数字；这些只能在 `runs/` 的日期报告里逐条核对。
- 不声称 `--fuzz` 能替代固定记录入口的 replay 或证书；它明确不产生 replay 和证书。
- 不声称所有 CPU×目标×DMA 组合都能跑六条流；组合受协议适配器、IRQ 交付、DMA 模型和行为声明限制。
- 不声称 F1 程序等价于任意 RISC-V 程序，或 F2–F6 的地址/值空间覆盖了设备全部寄存器与数据宽度。
- 不声称 corpus 中的输入已验证过；corpus 只是“曾产生新观察”的队列，不是执行权限。
- 不声称行为文件证明了设备因果；设备是否真的按声明触发、清除、搬运，仍以 case 行的实际观察为准。

## 相关文档

- [单进程 F1–F6：设备行为声明](inprocess-behavior-declarations.md)：行为文件 schema、优先级、拒收名，以及它与 profile 的分工。
- [当前系统能力与代码整理盘点](current-system-capabilities-20261101.md)：入口、六条流、已记录组合与接入限制。
- [通用系统路线](universal-system-roadmap.md)：分阶段目标、验收口径和当前缺口。
- [Profile 驱动接入原型](profile-onboarding.md)：CPU/IP profile 的最小字段、既有入口和声明边界。
- 本日真实闭环批次见[闭环证据](../runs/stage2-fuzz-loop-20261101/README.md)（各组合的 `summary.json`/`run.log` 与限制），分项计时见[性能报告](reports/fuzz-loop-performance-20261101.md)；本文件不重复其中的数字或状态。

代码入口：`scripts/run_inprocess_f1f6.py`（`main()`、`fuzz_collaborators()`、`build_firmware()`、`render_bindings()`、`parse_record()`/`validate_record()`、`correspondence()`）与 `scripts/inprocess_obi_apb_f1f4_spike.cpp`；闭环模块在 `src/myfuzz/fuzz/`（`strategy.py`、`word_spaces.py`、`feedback.py`、`corpus.py`、`session.py`、`rv32_program.py`），对应测试在 `tests/fuzz/`。
