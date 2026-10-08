# myfuzz 现有系统说明

日期：2026-10-08。本文是**当前实现**的系统级说明：系统是什么、由哪些层组成、一次运行怎么走、已经真实验收到哪里、以及明确**不**主张什么。所有数字都来自仓库内的证据报告与运行产物，行文中的"已验收"一律指[主实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)定义的阶段验收，而不是"代码写完了"。

> 最新状态以 [当前工作进度](CURRENT_PROGRESS.md) 为准；本文解释结构，不替代那里的状态表。
> **组件逐个功能说明见 [组件清单与功能](COMPONENT_REFERENCE.md)**；**testcase 的种类与数据流见 [testcase 的种类与数据流](TESTCASE_TYPES.md)**（逐事件号的完整例子见 [testcase 与数据流](TESTCASE_AND_DATAFLOW.md)）。
> 目标与边界见 [当前设计](CURRENT_DESIGN.md)；代码职责见表见 [代码组织](CODE_ORGANIZATION.md)；已有 CPU/IP 实例的逐条能力与限制见 [运行能力表](LOCAL_HARNESS_RUNTIME.md)；验收结论与原始证据见 [报告索引](reports/README.md)。

---

## 1. 一页速览

| 问题 | 答案 |
|---|---|
| 系统做什么 | 在**多个各自独立的真实 CPU/IP harness** 上做数据流 fuzz：总控初始化一次，然后连续接纳多条有独立身份的 testcase，让真实 RTL、RAM 与 pending event 跨例保持 |
| 输入是什么 | 上游源的随机 bit 串（Genome 的 raw），经 ISA/协议/组件字段约束转导后成为合法输入；Fuzzer 不直接改写 CPU 产生的地址/写值/byte enable |
| 目标是什么 | 用户原件 `SoC内部数据流动与去向.docx` 的六类流 F1～F6（取指、数据读、数据写、MMIO、IRQ→ISR→再 MMIO、DMA） |
| 关键机制 | 依赖路径反向选最上游 Fuzzable Source；Bound Input / persistent slot 不可写；逐边来源与链证书；身份绑定＋fresh replay |
| 当前阶段 | **P1～P5 全部通过阶段验收（按声明范围）**；P6 多协议实例复用、P7 自动接入、P8 真实 DMA 未验收 |
| 主验收口径 | `p4_acceptance_suite.v1` 关键项 8/8、exit 0；`p5_acceptance_suite.v1` 关键项 6/6、exit 0 |
| 规模 | 671 个测试文件；`scenario` 118 模块/66.8k 行、`integration` 38/26.9k、`composition` 67/49.7k、`local_harness` 64/12.5k |

---

## 2. 问题与设计原则

### 2.1 要解决的问题

传统做法把 CPU 与 IP 按名称硬编码连成一颗 SoC，再用随机位流打整条总线。本项目换成两条约束：

1. **组件各自独立**：每个 DUT 保留自己的真实 RTL、原生接口、局部协议和局部时序；组件间只通过**显式声明的事务级交付**相连，不假装成一颗 SoC，也不做全局 cycle-accurate 时序。
2. **随机只发生在最上游**：CPU 产生的地址、写值、byte enable 来自真实 RTL 输出，Fuzzer 不得跳过 CPU 直接随机；外设已绑定的输入、真实 Store/取指决定过的程序字节也不可再覆盖。

### 2.2 六条贯穿全系统的原则

| 原则 | 具体含义 |
|---|---|
| **身份先于运行** | 源文件、decode space、plan、manifest、trace 语义摘要、host、artifact 摘要全部哈希绑定；replay 身份不符在**任何 RTL 启动之前**拒绝 |
| **fail-closed** | 不确定就记 `null` + 原因，绝不写 0；未知信号、重叠归属、未验证源码在规划阶段拒绝 |
| **精确 join，不用相邻性** | 逐边来源与链证书只按事件身份（事件号、事务键、`entry_id`、`source_output_key`）连接；join 不上就保留并标 `matched=false`，不猜 |
| **声明式受信事实** | 可变 mask/范围、协议形状、路径与源都来自受信 profile/模板声明，不从名字推断 |
| **可复算** | 每份验收报告都给出独立复算入口（只读 CLI 或 verify 子命令），结论可由第三方重跑 |
| **诚实边界** | 每份报告都有"本文不主张什么"节；阶段完成绑定声明的范围 |

---

## 3. 分层架构

```text
┌ 入口层 ────────────────────────────────────────────────────────────┐
│ python -m myfuzz {capabilities,harness,scenario,compat}            │
│ scripts/*.py（57 个）：验收套件、在线运行、只读分析器              │
└──────────────┬─────────────────────────────────────────────────────┘
               │
┌ 组合与规划 ───┴─────────────────────────────────────────────────────┐
│ src/myfuzz/composition/  从源码事实核对 CPU/IP 说明文件，生成 wrapper│
│ src/myfuzz/elaboration_probe.py  编译→探针→按同配额重规划→只重建一次 │
└──────────────┬─────────────────────────────────────────────────────┘
               │
┌ 单组件 harness ┴────────────────────────────────────────────────────┐
│ src/myfuzz/local_harness/  源码锁、逐位端口事实、协议模板、时钟/复位、│
│                            独立 RTL session（Verilator）、产物身份   │
│ src/myfuzz/protocols/      OBI / AXI4 / AXI4-Lite / Wishbone / TL-UL /│
│                            APB3 模板注册表                          │
└──────────────┬─────────────────────────────────────────────────────┘
               │
┌ 场景执行 ─────┴─────────────────────────────────────────────────────┐
│ src/myfuzz/scenario/  Genome、Runner、持久 RAM/事务账本、Router、     │
│                       Scheduler、source_action、ownership、checker、  │
│                       反馈、证书、replay                            │
└──────────────┬─────────────────────────────────────────────────────┘
               │
┌ RFuzz 接入 ───┴─────────────────────────────────────────────────────┐
│ src/myfuzz/integration/  scenario_campaign、scenario_rfuzz_live、    │
│                          ibex_pulp_online、ibex_uart_online、replay  │
│ third_party/rfuzz/…/kfuzz  运输进程（共享内存 + 套接字协议）          │
└──────────────┬─────────────────────────────────────────────────────┘
               │
┌ 证据与验收 ───┴─────────────────────────────────────────────────────┐
│ runs/<run-id>/  身份、计划、回执、trace、报告、replay 日志             │
│ docs/reports/   验收结论 + 复算入口；.superpowers/sdd/  工作日志       │
└────────────────────────────────────────────────────────────────────┘
```

### 3.1 组件说明文件（组合的输入）

| 说明 | 里面写什么 | 示例 |
|---|---|---|
| CPU 接口说明 | 源码位置、顶层模块、时钟/复位、取指端口、数据端口、中断端口的真实名字与方向 | `configs/cpus/ibex/official_core_interface_description.json` |
| 外设连接说明 | 模块位置、地址范围、数据宽度、原生总线、需编译的源码 | `configs/peripherals/…/component_profile.json` |
| 协议规则说明 | 一次读写需要哪些信号、先后关系、字段一致性、最长等待 | `src/myfuzz/protocols/plugins/*.json` |
| 场景声明 | 路径、源、ownership、断言、预算 | `configs/scenario/`、`configs/campaigns/` |
| 生成结果 | 接线、输入 bit 含义、源文件清单、约束逻辑 | `generic_composition_top.sv`、`input_layout.json`、`sources.f` |

组合器从源码里核对这些字段；**缺口、重叠、未知信号、未验证源码都会拒绝**，不会生成一个"看起来能跑"的 harness。

### 3.2 单组件多时钟运行

每个 DUT 的时钟/复位各自映射，每次本地 `tick()` 只推进该 DUT 的最快时钟一个完整周期，**不代表全局 SoC cycle**。较慢时钟按整数频率比翻转；当前只接受正整数频率与可整除的偶数慢时钟比（≤1024），不支持的比例在规划阶段拒绝。每域必须收到至少一个复位采样上升沿才 READY；声明了有序复位依赖的 profile 直接拒绝运行，避免把顺序要求折叠成同时释放。

---

## 4. 一次在线运行的执行链

以当前主用路径 `Ibex（OBI）＋双 PULP GPIO` 的在线 RFuzz 为例：

```text
1  选目标与路径      F4/F5 目标 → 依赖路径 → 反向取最上游 Fuzzable Source
2  解码候选          online_case_decoder 把 raw 解成合法动作，写入候选身份
                     （direction / flow_id / path_id / source_id / operator_id / candidate_id）
3  接纳前检查        ownership（bound_input / fixed_input 拒绝覆写）、
                     source_action 先决条件（如 instruction_slot、ram_byte_version、transport_idle）
4  提交真实 RTL      经 kfuzz 运输提交该例；CPU/IP 真实执行多个本地周期
5  观察与检查        checker（协议/跨组件/CPU-IP 三类断言分开）、事件日志、回执
6  反馈              新目标/新边/失败证据 → energy 与后续选源；闭环能量可选接入
7  停止              发现 finding / 预算耗尽 / 用户结束
8  保存与重放        身份、plan、manifest、回执、trace、报告 + fresh replay 对照
```

### 4.1 一次 testcase 的定义

testcase 是**一次有身份的上游输入及其观察过程**（例如给 CPU 的未来合法取指位置提供一条 RISC-V 指令，或给外设一次外部事件）。它不划定执行边界：普通 testcase 边界**不 reset、不重装程序镜像**，RAM、DUT 寄存器、事务账本、pending event 与场景状态跨例保持；只有显式 reset 或会话结束才按策略清理。

### 4.2 输入归属（谁能决定什么）

| 输入或状态 | 谁可以决定 |
|---|---|
| CPU 程序、初始 RAM、未绑定的外部 pin / peer 字节 | Fuzzer 选择的上游 Fuzzable Source |
| CPU 产生的地址、写值、byte enable | **真实 CPU RTL 输出**，Fuzzer 不得跳过 CPU 随机 |
| 已绑定输入（如 GPIO A 输出 → GPIO B 输入） | 上游真实 RTL 输出；拒绝当随机源 |
| 真实 Store / 取指决定过的程序字节 | 不可被后例变异（slot 不可变性，实测 36,985 slot 全 `immutable`） |
| 会话内未知数据字节的首次读取 | 可物化一次，之后保持 |

---

## 5. 六类数据流与当前状态

| 流 | 含义 | 当前状态 |
|---|---|---|
| F1 程序存储器→CPU 取指 | 指令来源与真实取指 | 已验收（合法指令替换/插入/删除、RVFI 逐字退休） |
| F2 RAM/外设→CPU 数据读 | 真实读回 | 已验收（含 byte-enable lane 语义、RAM 版本跨例读回） |
| F3 CPU→RAM 数据写 | 真实写提交 | 已验收（`memory_write_commit` 事务键、持久字节版本） |
| F4 CPU→外设 MMIO 控制 | 配置与写 | 已验收（路径切换、初始 RAM 数据、MMIO 字节写） |
| F5 外设 IRQ→CPU trap/ISR→再 MMIO | 完整中断闭环 | 已验收（GPIO pin8 / UART RX watermark 两条链） |
| F6 CPU 配置 DMA→DMA 主设备搬运→IRQ | 真实 DMA | **未实现**（属 P8，无 harness 与闭环证据） |

---

## 6. 验证体系（最重要的一节）

### 6.1 三阶段验收入口的形状

每一层都有一个**只读**入口，把该层的判据串起来，并**从不启动 RTL**：

```bash
# P4：合法变异与反馈
PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --skip-heavy \
  --write runs/p4-acceptance.json
#   p4 acceptance suite: exit=0 ready=True critical=8/8 unmet=[]

# P5：断言、故障保存与效率
PYTHONPATH=src python3 scripts/run_p5_acceptance_suite.py \
  --run chain_acceptance=runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --run long_search=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run paired_continuous=runs/current-dataflow-p5-paired-20261007-online \
  --run paired_cold_start=runs/current-dataflow-p5-paired-cold-start \
  --run fault_calibration=runs/…-online@runs/…-reproduce \
  --run fault_family=runs/current-dataflow-p5-fault-family-all-20261007-online \
  --run heterogeneous_uart=runs/p5-uart-routing-gate-20261008-online \
  --artifact long_search=replay=runs/…/chain_600s_replay.log
#   exit_code: 0 (critical 6/6)
```

套件的共同语义：**`met=true` 不可能在 `measured=false` 下出现**；每个判据都写明读了哪个产物的哪个字段；"没测到"一律是 `null` + 精确原因，绝不折算成通过或 0。P5 还支持"联合"（union）：六项关键项分散在多个声明运行上，每个运行单跑最高 3/6——**联合通过不等于单次运行通过**，套件把这一点写进自己的 `boundaries`。

### 6.2 已验收的真实数字（摘要）

| 量 | 实测 |
|---|---|
| 十分钟搜索 | 600.362953 有效秒、368/368 例、570,196 事件、**27 条认证链＝0.044973 链/s**（跨例 6）、同 trace 复算 68 条 IRQ serial 精确证书、fresh replay `matches=true`、**自然 finding 0 如实记零** |
| 短门禁（全探针） | 31.27 秒、24/24 例、8 条认证链＝0.255807 链/s、9 条见证边 |
| 同预算对照 | 连续会话 31.905 秒 vs 逐例冷启动 512.881 秒 ≈ **16.08×**；9 项可比性先决条件全满足；链/s 等价**如实记不可测** |
| 受控故障 | 真实捕获（2 complete ＋ 1 `dut_violation`）＋**新进程复现**；9 变体全真实 RTL 校准；`calibration_only=true` 独立标注 |
| 异构外设（UART） | 60 例（57 complete ＋ 3 启动前声明式拒绝）、79.934 有效秒、fresh replay 一致；`report.json` 自带 `source_target_transactions`（7 例真实读链、21 条已 join 见证）；只读链生产者给出 **7 certified／30 incomplete**（首缺跳具名） |
| 效率分项 | 无效/超时：GPIO 臂 0.0、UART 臂 0.05；有效例/s 0.613／0.662；p50/p95 全分项逐例入回执 |
| CPU 侧覆盖 | profile 路径门禁 `--min-cpu-points 1` 8/8 PASS exit 0；`first_seen` 台账 54,157 次 RTL 测试点亮 30/128 |
| 回归基线 | `pytest tests/scenario tests/integration`：**8 failed, 4627 passed, 587 skipped, 3734 subtests passed**；8 条失败全部归类为 Verilator 不可用、配置漂移或既有文案不一致 |

### 6.3 逐边来源与证书

系统不靠"相邻事件"推断因果，而是产出可分级的身份证据：

| 证书 | 证明什么 | 明确不证明什么 |
|---|---|---|
| 边来源 `runtime_edge_provenance.v1` | 声明边（mmio_route / direct_binding / persistent_state）在真实 trace 上被精确 join | 不证 DUT 没有其它行为 |
| 链证书 `runtime_chain_certificate.v1` | 一条链的每一跳都在**该产物内**被见证（GPIO 路径 27 条） | 计数是生产者的产物能力，不等于 DUT 事实 |
| UART 链证书 `runtime_uart_chain_certificate.v1` | UART 读链 16 跳逐跳见证（7 条），30 条 incomplete 首缺跳具名 | 不证 IRQ→CPU 因果、不证 polling |
| 消费证书 `computed_consumer_certificates` | 计算值到外设的消费 lane 身份（192 认证/528 拒绝/0 unknown） | 不证内部溯源 |
| IRQ serial 证书 | `decision_serial == retirement_serial != 0` 的精确对应（68 条） | 不证中断源唯一 |
| 断言类 `p5_assertion_classes.v1` | 协议/跨组件/CPU-IP 三类分开计数 ＋ 异常记录 fail-closed 普查 | 不证 finding 是真阳性 |

### 6.4 复现与身份

```text
online_run_identity.json
  ├─ identity.sources      源文件与 decode space 的 sha256 清单
  ├─ identity.plan         online_plan.json 摘要
  ├─ identity.manifest     online_session_manifest.json 摘要
  ├─ identity.trace        trace 语义 sha256（容器无关）
  ├─ identity.artifacts    receipts/seed/plan/manifest 逐文件摘要
  └─ identity.host         主机与工具链身份

replay 路径：_verify_online_run_identity 在 RTL factory 构建之前校验全部字段
              → 任一不符即拒绝（有真实拒绝日志：冷组 24 例 decode-space 漂移）
```

实测中的两条重要事实：①**语义摘要与容器无关**（zlib 分块容器逐事件等价 JSONL，体积约 1/13.4，终结写入少 11.14 秒）；②**改动 decode-space 源文件就会让旧 bundle 按设计不可 replay**，这是机制在生效而不是缺陷。

---

## 7. 怎么用

### 7.1 只想看/复算已有结论

```bash
PYTHONPATH=src python3 scripts/check_doc_links.py                     # 文档链接 0 断链
PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --skip-heavy # P4 8/8
PYTHONPATH=src python3 scripts/run_p5_acceptance_suite.py --run …      # P5 6/6
PYTHONPATH=src python3 scripts/report_p5_arm_metrics.py RUN_DIR… --json-out /tmp/arm.json
PYTHONPATH=src python3 scripts/report_uart_chain_certificates.py --run RUN_DIR --json-out /tmp/x.json
PYTHONPATH=src python3 scripts/report_p5_uart_routing_witness.py --run-dir RUN_DIR --json-out /tmp/y.json
PYTHONPATH=src python3 scripts/survey_online_trace_kinds.py RUN_DIR    # trace 事件种类普查
```

这些命令都是只读的：不渲染 harness、不启动 RTL、不写回运行目录。

### 7.2 想自己跑一次真实在线搜索

```bash
# Ibex ＋ 双 PULP GPIO（带 RVFI 退休探针）
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py --help   # 参数以 QUICKSTART.md 为准

# Ibex ＋ OpenTitan UART（异构外设；含波形互斥声明式拒绝）
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/<cache> --output runs/<new-dir> --seconds 120 --max-tests 60 \
  --seed 20261007 --run-id <id> \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback --uart-wdata-byte-store
# 然后必须做 fresh replay（输出目录必须是全新的，已存在会被拒绝）
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py replay \
  --cache-dir runs/<replay-cache> --plan runs/<new-dir>/online_plan.json \
  --trace runs/<new-dir>/online_events.zlib   # 期望 {"matches": true, "first_difference": null}
```

运行注意事项（来自实际经验）：

- **输出目录必须全新**，否则拒绝（防止覆盖证据）。
- **重 RTL 任务串行**：一次只跑一个 Verilator 会话；本机 32 核 / 7.5 GB 内存下并发跑多个会 OOM。
- **不要在同一时间改 `src/`**：在线身份在启动前校验 decode-space 源文件摘要，边跑边改会让运行自己失败或让刚记录的 bundle 不可 replay。
- `pytest` 未安装 `pytest-timeout`，不要传 `--timeout=`。

### 7.3 想接一个新组件

1. 写 CPU 接口说明或外设连接说明（真实源码位置、顶层、端口、总线）；
2. 确认协议模板覆盖其形状（TL-UL / APB3 / Wishbone / AXI4 / AXI4-Lite / OBI），否则先补模板；
3. 用 `scripts/generate_local_harness.py --request request.json --output DIR` 生成并审阅产物；
4. 先跑**定向**真实闭环（一个源值、一次 transaction、fresh replay），再接入在线搜索；
5. 新能力要按"真实 RTL → replay 一致 → 报告写明边界"的顺序登记，不能靠 lint 或编译成功。

---

## 8. 已知边界（P5 完成**不**主张这些）

| 边界 | 现状 |
|---|---|
| 异构外设的**十分钟长会话** | 未做：十分钟项目前只由 Ibex＋双 PULP GPIO 证明，UART 为 79.934 有效秒 |
| UART 侧跨例持久状态 | 未做 |
| 故障**灵敏度**对照 | 未做（现有只是命中/未命中与 9 变体校准） |
| 链终点 | 不含 ISR 写 GPIO A 之后的 A→B 回流（不可精确 join 的身份已点名） |
| p95 尾部 | `interaction_ingest` 114.8 ms、`rtl_submit` 2.28 s 仅记录，未消除 |
| `interaction_deferred` | 600 秒臂 345/368、UART 臂 54/60 |
| 单 run 全项 | 六项关键项分散在多个运行，单 run 最高 3/6 |
| F6 DMA | 未实现（P8） |
| P6/P7 | 多协议实例复用、同协议自动接入均未验收 |
| 环境依赖 | 部分集成测试需要 Verilator 前端与已构建的 `kfuzz`；缺失时按 `skipped_unavailable` 跳过并如实记录 |

---

## 9. 证据放在哪里

| 位置 | 内容 |
|---|---|
| `docs/CURRENT_PROGRESS.md` | 阶段状态表 + 本轮证据（最新状态以此为准） |
| `docs/reports/README.md` | 按验收范围的报告索引（562 文件、1071 链接、0 断链） |
| `docs/reports/current-dataflow-p{2,3,4,5}-stage-acceptance-*.md` | 各阶段验收：清单逐项 + 验收口径对照 + **声明范围与边界** |
| `runs/<run-id>/` | 原始产物：身份、plan、manifest、回执、trace、报告、replay 日志 |
| `runs/*-logs/` | 门禁脚本与其日志、只读分析产物 |
| `.superpowers/sdd/` | 工作日志与独立审查（**不等于**验收结论） |

证据目录不是构建缓存：清理前先查报告引用与 replay 依赖。

---

## 10. 延伸阅读顺序

1. 本文（结构）
2. [当前工作进度](CURRENT_PROGRESS.md)（状态与边界）
3. [当前设计](CURRENT_DESIGN.md)（目标与实现边界）
4. [P5 阶段验收报告](reports/current-dataflow-p5-stage-acceptance-20261008.md)（最完整的"已证/未证"样本）
5. [代码组织](CODE_ORGANIZATION.md)（模块职责与入口）
6. [运行能力表](LOCAL_HARNESS_RUNTIME.md)（逐组件已验收能力与限制）
7. [QUICKSTART](../QUICKSTART.md)（跑起来）
