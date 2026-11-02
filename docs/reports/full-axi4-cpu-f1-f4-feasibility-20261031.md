# 完整 AXI4（非 Lite）CPU 接入通用 F1–F4：可行性分级与交付

日期：2026-10-31
范围：只读调查 + 新增文件（未修改任何共享文件，未跑 RTL/Verilator）

> **状态说明（同日后续）：** 本文是当时的可行性分级。VexiiRiscv（`reduced_dual_axi_cpu`）的 session 缺口其后已补齐并**真实通过 F1–F4**（`runs/vexii-f1f4-20261031`，6 例 + fresh；见[扩展总线适配](extended-bus-adapters-20261031.md) §5.2），因此下表中该行“需补 X / ①–③”已不成立。
>
> 同日更晚的后续（见文末「同日后续」）：
> - **CVA6**：先准入 `compiled_mmio` 做 **F2/F4（data-only）**（`runs/cva6-f2f4-20261031`），随后把取指身份改为 **ARID/RID 声明**并**真实通过 F1–F4**（`runs/cva6-f1f4-20261031`，`campaign.json` bound adapters = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`）；user/ARPROT 确实钉 0，但取指身份在 AXI ID 上（`instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`）。此前“无法取指”的 data-only 判定已被更正。新增 `src/myfuzz/local_harness/cva6_axi_mmio_session.py`、`src/myfuzz/integration/cva6_axi_mmio.py`、`src/myfuzz/integration/native_mmio_data_hops.py`、`src/myfuzz/runtime/adapters/cva6_axi4_cpu.py`、`tests/integration/test_cva6_axi_mmio.py`（9 passed）、`tests/integration/test_cva6_fetch_identity_hops.py`（8 passed）。
> - **BOOM（`tilelink_coherent_cpu`）**：通用 `compiled_mmio` 仍未准入。Phase A（harness 半）已完成：新增 `tl_coherent_memory_adapter.sv`(468)、39-role `('tilelink-coherent','1')` 契约、runtime/driver renderer 与 `tilelink_coherent_fields.py`(93)，真 RTL `verilator --lint-only` **exit 0 无 warning**（`runs/boom-tl-harness-lint/`，518 modules / 36.9 MB / 20.88 s），但 artifact `source_verification=null`；拒绝点前移为 `component-render-refused at /processor/request` ← `local-source-lock-missing-component:boom`。F2/F4 仍只有 `directed_standard_runner_router` 各 6 例 + fresh；剩余 Phase B 约 **850–1120 行**。
> - `reduced_dual_axi_irq_cpu` 与 ZipCPU `axi4_cpu` 的分级不变。

## 结论（先看这里）

**四个 kind 目前都不能"直接接入"通用 F1–F4。** 适配层（trace 映射 + 真实
passive 采样解析）对 Vexii 两个 kind 已经可交付并被测试覆盖；阻止接入的是
**session 侧**缺口，不是协议解析缺口。因此 `cpu_adapter()` 现在对这四行全部
给出具名拒绝（`MMIO-CPU-adapter-unsupported:axi4:<kind>:<gap>`），而不是返
回一个 `mmio_support` 会误报 `supported` 的 adapter。

| kind | 协议解析（adapter 层） | 接入通用 F1–F4 | 缺口 |
|---|---|---|---|
| `reduced_dual_axi_cpu`（VexiiRiscv） | **可直接复用**：session 自身有 `ReducedAxiObserver`，`driver_samples.pre/post.backend` 携带完整 `i_*`/`d_*` AXI4 角色 | 需补 X | ① session 只接受 `mmio_router=`，通用执行器传 `router=`；② 无 `declare_instruction_slots`/`accept_instructions`；③ 无 `waiting_instruction_address`（F1/F3 的 `fragment_boundary_park` 直接依赖它） |
| `reduced_dual_axi_irq_cpu` | 同上（`SHAPES` 完全相同） | 需补 X | ①–③ 同上；④ `_step_inputs` 要求每步一个 `irq` 位，通用 F1–F4 驱动不提供 |
| `axi4_cpu`（ZipCPU 双全 AXI4） | **需补**：session 不保留任何每拍 AXI4 观测，没有可复用解析函数（只有 `i_ar_accepted` 之类的步骤汇总） | 需补 X | ① `native-observer-missing`（需新增和 reduced 同级的 AXI4 observer，含 burst/`AWLEN`/`WLAST` 语义）；② 构造器无 `router=`；③④ 同 reduced 的 online-slot/park |
| `cva6_packed_axi4_cpu`（CVA6） | 现有 `BoundedFullAxiObserver` 可复用，但**语义不足** | **本阶段不可行** | ① 单一 packed 64 位 AXI4 端口**没有取指/数据通道身份**（observer 契约原话："single master has no ISA channel identity"），F2/F4 的 `('instr', seq)` 取指 hop 无法证明；② 64 位 `WDATA/WSTRB` 对 32 位 MMIO 寄存器 beat；③ session 用独立 `mmio` 通道，而 unified 模型要求 `memory`；④ online-slot/park 缺失 |

## 新增文件

- `src/myfuzz/integration/cpu_axi4.py`
  - `cpu_adapter(artifact, image, stream, *, base_dir=None)`：扩展缝实现（返回
    `Axi4MmioCpuAdapter` 或 `None`，不可行时抛具名 `ValueError`）。
  - `axi4_cpu_adapter(...)`：解析层完整构造器（供本阶段测试与下一阶段 wrapper 使用）。
  - `reduced_axi_traces(artifact)`：从 artifact 自己的 `backend_ports` 行构造
    `traces`，并与 session 模块声明的 `SHAPES` 逐角色校验 direction/width/name；
    `traces['data']` 含完整 AR/R/AW/W/B 映射（`d_arvalid`…`d_bresp`），
    `traces['instr']` 为只有 AR/R 的取指面。
  - `error_policy(artifact, traces)`：真实 `rresp`/`bresp` 观察策略
    （`native_error_observation=True`，`accepted_status='okay_only'`）。
  - `replay_reduced_axi(events, component, traces)`：**复用 session 自己的
    `ReducedAxiObserver`** 重放 `driver_samples`，返回
    `completed[(channel, sequence)]`（含 `acceptance_event`/`response_event`/
    `address`/`write`/`value`/`byte_enable`/`rdata`）与取指
    `[(event_id, address)]`；同时把 session 报告的
    `<p>_<c>_accepted/_consumed` 与真实引脚交叉校验，不一致即拒绝。
  - `executor_gaps(session_type)`：结构化（`inspect.signature` + 类属性）检查
    通用执行器契约，`AXI4_KIND_GAPS` 是机器可读缺口表。
- `tests/integration/test_cpu_axi4.py`（27 passed，合成数据，无 RTL）

## 已证实的实现边界

- 全 AXI4 CPU 行**没有** `protocol_taps` 分组；唯一物理证据是
  `driver_samples[*].pre/post.backend`，本模块只读该处。
- 空/外来 component/坏 sample 一律拒绝（`native-sample-shape`），不跳拍——跳拍
  会平移全部 sequence。
- reset 标记（`reset_barrier`/`cpu_reset`）按既有 `collect_native_obi_beats`
  约定重置 pending 与 sequence。
- 声明准备复用 `MmioCpuAdapter.prepare_declaration`（4 字节 granule）。

## 建议的下一步（按收益排序）

1. **新增一个 wrapper session（新文件，不改共享文件）**：
   `src/myfuzz/local_harness/vexii_axi_mmio_session.py`，
   `class GeneratedReducedAxiMmioCpuSession(GeneratedReducedAxiCpuSession)`：
   - `__init__` 增加 `router=` 形参并转交 `mmio_router=`；
   - 实现 `declare_instruction_slots`/`accept_instructions`（走
     `PersistentMemory` 的 slot 接口）；
   - 实现 `waiting_instruction_address`：在 fetch 面 AR 已被接受、但
     `memory.instruction_slot_unmaterialized(addr)` 为真时返回该地址；
   - 保持 `artifact_kind='reduced_dual_axi_cpu'`（`contracts._generated_session_class_kind`
     只按模块/类名与 `artifact_kind` 校验，新模块即可注册）。
   然后 `cpu_axi4.axi4_cpu_adapter` 的 `session_type` 指向该 wrapper，
   `executor_gaps` 为空，`cpu_adapter` 即可返回真 adapter。
2. **IRQ 变体**：同一 wrapper 派生 `_step_inputs` 接受缺省 `irq=0`，或让通用驱动
   提供声明式默认输入；在补齐前保持拒绝。
3. **ZipCPU `axi4_cpu`**：新增一个与其 `AXI_SHAPE` 对齐的原生 AXI4 observer
   （burst/`AWLEN`/`WLAST`/1-bit ID），再把 `traces`/reader 接到本模块同一接口；
   同时给 session 加 `router=`。
4. **CVA6**：本阶段不建议做。要么在 RTL 侧找到取指身份（例如声明 `aruser`
   某一 bit 为取指标志并写进 profile），要么放弃"F1–F4 取指 hop"，只做
   data-only 的 MMIO 证据；此外还需 64→32 位 beat 与 MMIO 通道 id 的处理。

## 同日后续：CVA6 的 F1–F4（ARID/RID 取指身份）与 BOOM Phase A（2026-10-31 晚）

### CVA6（`cva6_packed_axi4_cpu`）：F1–F4 已真实通过（走通用 `compiled_mmio`）

- descriptor：`configs/scenarios/compiled-f1-f4-axi4-apb-i2c-cva6/`（`flow_ids=[F1,F2,F3,F4]`、`executors` 全 `compiled_mmio`）。
- 真实 RTL：`runs/cva6-f1f4-20261031/{original,fresh}`，各 6 例；original `wall_seconds=117.09`、fresh `106.63`、`replay_matches=true`、`first_difference=null`；`original/campaign.json` 的 `bound_documentary.adapters` = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`，确认走通用执行器。
- 逐例：F3 `memory_store=observed`（5 条 `memory_write_commit`，`channel=memory`、width 4、be 15）、F1 `memory_read=observed`；F4 joins=2 / hops=6，F2 joins=1 / hops=6。本轮 6 例序列执行两对写读（0x55、0xaa），`read_value` 85/170、`result=read^0x5a5`（1520/1295）；descriptor 另声明 0x1234 一对，未在本轮 6 例中执行（此前 F2/F4 6 例跑过三对，`runs/cva6-f2f4-20261031`）。
- **取指身份 = ARID/RID**（更正此前 data-only 判定）：user/ARPROT 确实钉 0，但身份在 AXI ID 上——`wt_axi_adapter.sv:116/159/597/638`（`arb_req={dcache…,icache…}`、`id_in=arb_idx`、`rid==0→I$`、`rid[0]→D$`）+ `cv64a6_imafdc_sv39_config_pkg.sv:32/:72`（AxiIdWidth=4、DcacheType=WT）⇒ `instruction_id_map {arid:0, rid:0, granule:8, rsize:3}`。声明由 `cva6_axi_mmio.py::cva6_instruction_identity()` **现场重读这 6 个锚点**生成，任一缺失退回 data-only refusal（无默认打开）。
- hop 证据：每例 6 granule / 12 拍 / 12 字；每 hop 有 `granule_address`、`fetched_hex`（真实 8 字节）、`acceptance_event`/`response_event`/`memory_read_event`、`native_beats[]`、`instruction_words[2]`（`source_word_hex`/`fetched_word_hex`/4 字节 `bytes_match`/`authoritative_snapshot`）。示例：granule `0x10038` 读到 `b700004093800000`，两字 `b7000040`、`93800000` 逐字节 4/4 匹配，事件 `AR 2438 → memory_read 2663 → R 2696`。
- 实现与测试：`src/myfuzz/local_harness/cva6_axi_mmio_session.py`(461)、`src/myfuzz/integration/cva6_axi_mmio.py`(311)、`src/myfuzz/integration/native_mmio_data_hops.py`(220)、`src/myfuzz/runtime/adapters/cva6_axi4_cpu.py`(202)、`tests/integration/test_cva6_axi_mmio.py`(169)、`tests/integration/test_cva6_fetch_identity_hops.py`(8 passed)；相关批 270 passed + 57 subtests。为跑通 RV64 的小改（带注释）：`isa/constraints.py`、`scenario/memory.py`、`runtime/flows/memory.py`（F3 store 源宽度接受 64 位口，实测仍 4 字节存储）、`scenario/runner.py`；另修 `cpu_axi4._parse_adapter` 位置参数 bug（否则 vexii 行会被误开 F1/F3）。
- **边界**：只对本 pinned WT 配置成立，不外推到所有 AXI/所有 CVA6；AMO 的 `ar.id[1]` 永不作取指 hop；`retirement`、DUT 内部存储版本、跨例来源仍 unknown；48 字节片段第 9–12 字无权威快照（`authoritative_snapshot: not-in-declared-window`）；composition SoC 面的 `src/myfuzz/runtime/adapters/cva6_axi4_cpu.py` 仍只发 refusal，未扩展。

### BOOM（`tilelink_coherent_cpu`）：Phase A（harness 半）完成，仍未准入

- Phase A 产物：`src/myfuzz/protocols/rtl/tl_coherent_memory_adapter.sv`(468，A/B/C/D/E 从端 + 8 字节 backend beat，不支持者 `fault_o` 不伪装成功)；`template_contracts.py` +133/−5 增加 39-role `('tilelink-coherent','1')` 契约（role/width/direction 派生自 `protocols/plugins/tilelink-coherent.json` 并导入期逐条校验）；`runtime_renderer.py` +120/−1（kind 分支 + 39 tap + 五通道视图 + 具名 `instruction_hop_refusal`）；`driver_renderer.py` +45/−1（`STEP_TL_COHERENT`）；`local_harness/tilelink_coherent_fields.py`(93)、`tests/local_harness/test_tilelink_coherent_contract.py`(188, 9 passed)。
- 真 RTL lint：`verilator --lint-only` **exit 0 无 warning**（518 modules / 36.9 MB / 20.88 s），产物 `runs/boom-tl-harness-lint/{wrapper.sv,runtime.sv,driver.cpp,artifact.json,abi.json,lint-command.txt,lint.log,README.md}`；该 artifact `source_verification=null`（缺源锁），**不声称已准入**。
- 拒绝点前移：`protocol-shape-not-admitted` → `component-render-refused at /processor/request` ← `local-source-lock-missing-component:boom`（`src/myfuzz/local_harness/source_lock.py:164`；`scripts/verify_soc_sources.py:432` 仍用前端爬 18 MB top，故 BOOM 尚无 `sources.lock.json` 记录）。
- **F2/F4 仍只有 directed 基线**：`runs/boom-f2-20261031`、`runs/boom-f4-20261031`，各 6 例 + fresh `compare.json` 匹配；executor `directed_standard_runner_router`、`compiled_mmio_admitted=false`。F2 fresh `total_wall_seconds=21.42`（`wall_seconds=21.83`）、F4 fresh `21.0`（`21.48`）；F4 joins=2、F2 joins=1，`read_value` 85/170/4660/17185/48879/32767；PULP APB I2C `PRESCALER` @`0x4000`（BOOM uncached 页钉在 `0x4000..0x5000`）。
- 实现（directed 基线）：`src/myfuzz/integration/cpu_tlul.py`(283)、`src/myfuzz/scenario/boom_tl_apb_f2f4.py`(568)、`tests/integration/test_cpu_tlul.py`(198)、`tests/scenario/test_boom_tl_apb_f2f4.py`(295)、descriptor `configs/scenarios/compiled-f2-f4-apb-i2c-boom/`；`extension_plugins.py` 里悬空的 `boom_cpu` 映射改为真实的 `tilelink_coherent_cpu: myfuzz.integration.cpu_tlul`。测试新增 33 passed。
- 剩余 Phase B：①`verify_soc_sources.py` 复用 stored 端口证据 + BOOM 进 `sources.lock.json`（约 150–220 行）；②host 播放器 + `cpu_tlul` 适配器 + `tilelink.cpu.v1` 注册（约 700–900 行）；之后才是 12 例真跑与 fresh。

### 不声称

- CVA6 的取指 hop 只对当前 pinned WT 配置成立，仅对已声明窗口内的字有权威快照；`retirement`/内部存储版本/跨例来源仍 unknown。
- BOOM 的 Phase A 只是生成 + lint（`source_verification=null`），F2/F4 是 directed runner 的有向运行，不是通用 `compiled_mmio` 准入。
- 两组运行 `feedback.certified=0`；不声称任意 CPU/IP 自动支持。

## 未做的事（明确声明）

- 没有运行任何 RTL/Verilator/native 会话；所有结论是静态代码 + 合成样本。
- 没有修改 `compiled_mmio.py`、`mmio_cpu_adapter.py`、`extension_plugins.py`、
  `scripts/*` 或任何 session 文件。
- 本文写作时没有声称任何 AXI4 CPU 行已获得 F1–F4 运行时支持；其后 Vexii 与 CVA6 的 F1–F4 结果见上方「同日后续」，BOOM 仍未准入。
