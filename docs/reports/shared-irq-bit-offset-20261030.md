# 共享 IRQ 装配的 CPU 位切片端口（CV32E40P `irq_i[11]`），2026-10-30

本报告只覆盖软件层的共享装配、host IRQ 投递和 GPIO IRQ 依赖证据：真实 profile/plan/
artifact/session 会被渲染和构造，但**没有**启动 DUT、没有跑 RTL 仿真、没有执行 Verilator
构建，也没有改动 `research/` 或 `runs/` 下的任何证据。结论不声称 native 通过。

## 1. 真实位切片端口

在 `configs/**/component_profile.json` 中，`direction=input` 且声明了非零 `bit_range`
的端点只有下面几处（`cv32e40p` 系列的机器外部/定时器中断）：

| profile | 端点 / 角色 | 别名 | 声明 `bit_range` | verified export 行（`physical_exports`） |
| --- | --- | --- | --- | --- |
| `cv32e40p_rvfi_local` | `processor.interrupts` / `external` | `irq_i` | `[11,11]` | `physical_port=irq_i, bit_lo=bit_hi=11, width=1, runtime_name=rt_lh_p_34_11_11` |
| `cv32e40p` | `processor.interrupts` / `external` | `irq_i` | `[11,11]` | 同一 RTL 端口（该 profile 尚未注册 native IRQ contract） |
| `cv32e40p_mtimer` | `processor.interrupts` / `machine_timer` | `irq_i` | `[7,7]` | `irq_i[7]` |
| `cva6` | `processor.interrupts` / `machine_external` | `irq_i` | `[0,0]` | 显式声明但仍是 0 |
| `ibex_rvfi_local`、`cv32e20` | `processor.interrupts` / `external` | `irq_external_i` | 未声明 | 整 1 位端口，`bit_lo=bit_hi=0` |

`irq_i` 是 32 位 RTL 端口；profile 的 `port_actions` 已把 `irq_i[0..10]` 和
`irq_i[12..31]` 声明为常量 0，只有 11 号位是 `functional` 的外部中断线。这一次要绑定的是
真实切片，而不是 0 号位。

## 2. 坐标系统（本次的关键结论）

仓库里存在两套坐标，必须分开：

* **host 坐标是 port-local**：host 输入字段就是该 CPU 的 ABI 输入行，host 偏移 =
  声明位 − ABI 行 `bit_lo`；
* **DUT 位号是文档证据**：profile 的 `bit_range`、verified export 行的 `bit_lo/bit_hi`、
  CPU IRQ contract 的 `input_bit_offset`、以及真实 `irq_id_o==11` 的前沿决策探针。

依据（都来自现有真实代码/输入）：

* `src/myfuzz/local_harness/runtime_renderer.py:_admit` 对 `obi_cpu` 只接受
  `direction=input, width==1, endpoint_id==irq_entry_endpoint, role==irq_entry_role` 的
  ABI 行，因此 CV32E40P 对 host 暴露的是 **1 位切片** `irq_i`
  （`runtime_ports` 里 `rt_lh_p_34_11_11` 宽 1），另外 31 位是 wrapper 内部常量；
* `src/myfuzz/local_harness/compiled_artifact_admission.py` 强制
  `sum(ABI 输入行宽) == ownership 字段宽`，32 位字段会被 `ownership-input-not-physical`
  拒绝。

所以：

* CV32E40P 的行为偏移是 **0**（和 Ibex/CV32E20 相同），`cpu_session.step_local` 不需要
  任何移位；DUT 位 11 保留在文档证据里；
* `wishbone_cpu` 风格（ABI 行本身就是 32 位向量）仍然是真正的非零 host 偏移。本次用
  仓库里已声明的 `picorv32_wb_irq` host 位 `CPU_IRQ_CPU_ROUND1 = 3` 做这类回归，
  没有凭空发明偏移。

先前一度按"host 值是整个 32 位向量"实现（字段宽 32、偏移 11）已按上述准入规则回退；
被放弃的方案不需要也不应该修改 `cpu_session`。

两套坐标之间只保留一个**非行为**的映射字段：`IrqDeliveryGroup.target_input_bit_lo`
（host 字段 bit 0 对应的 DUT 位，即 verified export 行的 `bit_lo`；默认 0，为 0 时
`document()` 不输出该键，因此 Ibex/CV32E20 的 group 文档仍是原来的 7 个键和原 sha256）。
映射关系恒为 `DUT 位 = target_input_bit_lo + target_bit_offset`；行为路径只用
`target_bit_offset`，`target_input_bit_lo` 仅用于把 runtime path contract 的 DUT 节点
坐标转换成 host 坐标。

## 3. 改动站点

### 3.1 `src/myfuzz/integration/shared_f6_assembly.py`

* 新增 `_declared_field_span`：只从 profile 读取该端点角色声明的包含位区间，
  `bit_range` 缺省时只允许整 1 位端口（归一到 `(0,0)`）。
* 新增 `verified_shared_cpu_irq_input`：用
  `verify_native_irq_receipt_artifact` 返回的 runtime name 选择唯一 export，要求
  `direction=input`、`disposition=functional`、`endpoint_id/role` 与 profile 一致、
  export 跨度**包含**声明的 DUT 位，并交叉核对 ABI 行。零匹配或多匹配都拒绝
  （`verified-CPU-IRQ-export`），ABI 行不唯一也拒绝（`verified-CPU-IRQ-ABI`）。
  改动前这里是 `e['bit_lo']==e['bit_hi']==0` 的硬编码，因此 CV32E40P 根本无法绑定。
* 新增 `cpu_irq_host_input_field`：host 字段宽 = ABI/export 行宽；除 host 偏移外的每一位
  都必须是 profile 已经声明的常量 0，否则 `CPU-IRQ-host-field-unclassified`。
  对 1 位切片行没有其它位；对宽向量行必须全部已声明，绝不猜测。
* `shared_irq_group`：`target_bit_offset = 声明位 − export['bit_lo']`
  （CV32E40P 0、Ibex/E20 0、宽向量保持真实非零），并把 export 的 `bit_lo` 记入文档字段
  `target_input_bit_lo`（见 §2；为 0 时 `document()` 不输出该键，所以 Ibex/CV32E20 的
  saved/recomputed group 文档字节与 sha256 完全不变）。
* `shared_irq_ownership`：字段宽 = ABI 行宽、bound owner 位于 host 偏移；接受原来的
  `dma.irq` / `irq-group:*` owner 迁移（`irq` host 占位别名必须 offset 0，物理端口必须是
  host 偏移），并对已改写的 map 幂等。

最终文档（真实 artifact 构造，`group_id=shared-external`）：

```json
{"fields":[{"component_id":"cpu","port":"irq_i","width":1}],
 "owners":[{"bit_offset":0,"component_id":"cpu","kind":"bound","port":"irq_i",
            "producer_ref":"irq-group:shared-external","width":1}]}
```

group 文档（E40，含文档字段）：

```json
{"schema_version":"host_irq_delivery_group.v1","group_id":"shared-external",
 "target_component":"cpu","target_port":"irq_i","target_bit_offset":0,
 "target_input_bit_lo":11,"operation":"or",
 "members":[{"source_component":"dma","source_port":"irq","mode":"pulse",
             "pulse_width_ticks":16,"source_bit_offset":0},
            {"source_component":"peripheral","source_port":"interrupt","mode":"pulse",
             "pulse_width_ticks":4,"source_bit_offset":0}]}
```

两个 member 的 binding `target_bit_offset` 都是 0；Ibex/CV32E20 的同名文档没有
`target_input_bit_lo` 键。

### 3.2 `src/myfuzz/scenario/runner.py`

`configure_gpio_irq_dependency_evidence` 不再过滤 `b.target_bit_offset == 0`：它按
source/port/target/`irq_input_port`/`width==1`/`source_bit_offset==0` 选出唯一物理
binding（多于一个显式拒绝），用该 binding 的真实偏移做 owner 校验、校验它与已安装 group
的偏移一致，并把偏移传给 consumer，同时记录到
`_gpio_irq_dependency_configuration['target_bit_offset']`。

复核（未改动）：`_effective_inputs` 的 group/pulse 分支本来就用
`binding.target_bit_offset` / `group.target_bit_offset` 计算掩码；
`_route_observed_outputs` 的 `dataflow_delivery` 与 `gpio` origins 也用 binding 偏移；
`_append_irq_events` 把 binding 的 `source_bit_offset/target_bit_offset/width` 写进
pulse/`cpu_irq_input`/`cpu_irq_taken` 事件。这些对 offset 0 的 CPU 输出字节不变。

### 3.3 `src/myfuzz/scenario/gpio_irq_dependency_evidence.py`

`GpioNativeIrqEvidenceConsumer` 增加构造参数 `target_bit_offset=0`（默认值保证既有调用与
文档字节不变）：

* `_endpoint` 用 `('source_bit_offset',0)`, `('target_bit_offset',self.target_bit_offset)`,
  `('width',1)` 匹配事件；
* `_valid_sample` 比较 `step['inputs'][self.target_port] == 1 << self.target_bit_offset`
  （offset 0 时与原 `== 1` 完全等价）；
* `_input`/`_accept` 继续使用 `self.target_port` 和 pulse 的 0/1 值（这些值本来就不含
  偏移），`report()` 文档形状不变。

已核对 host 输入键：CPU session 的 `inputs` 字典以 ABI 物理端口名（CV32E40P 为
`irq_i`）为键，值是声明位（1 位切片即 0/1），不是 runtime name
（`rt_lh_p_34_11_11` 只出现在 driver/runtime wrapper 层）。

### 3.4 `src/myfuzz/scenario/irq_delivery_group.py` 与
`src/myfuzz/integration/saved_irq_group.py`

* `IrqDeliveryGroup.__post_init__` 原来要求 `target_bit_offset != 0` 直接 `ValueError`，
  现在接受 `0 <= target_bit_offset < 64`（与 member 的 `source_bit_offset` 同一约束）；
  新增文档字段 `target_input_bit_lo`（默认 0，`document()` 仅在非 0 时输出，
  `from_document()` 同时接受有/无该键的文档）。
* `saved_irq_group.rebuild_group` 现在从原始 `topology['bindings']` 中两个成员行
  **推导** host 偏移（两成员必须一致、`source_bit_offset==0`、行必须唯一），再要求
  saved group 文档与推导结果完全相等；"额外驱动"检查、唯一 bound owner 检查都改用该
  偏移，owner 数组允许宽字段（`len(owners[0]) > offset`）。成员行缺失/重复、group 文档
  被改写、owner 不是 bound、owner 出现在多个位等原有拒绝全部保留。

### 3.5 `src/myfuzz/integration/shared_f5_slots.py::extend_shared_pin_path`

F5 的 D3 契约把 IRQ 跳转记录为 `direct_binding`，节点是 **DUT 坐标**
（`F5.cpu_irq_entry = (cpu, irq_i, 11)`），而安装的 group 是 host 坐标。原实现直接用
`target.bit_offset` 与 group 比较，E40 上必然抛
`shared-F5-actual-IRQ-group-endpoint-mismatch`。现在：

* `host_target_bit = target.bit_offset - irq_group.target_input_bit_lo`，先要求
  `>= 0`，再比较 `(target.component, target.port, host_target_bit)`；
* 生产者一侧保持原样并在代码里说明：GPIO `interrupt` 是整 1 位输出端口，DUT 位与 host
  偏移都是 0，所以无需映射。

E40 上该 hop 会把契约边改写成 `irq_delivery_group`（`irq_group_sha256` 来自含
`target_input_bit_lo=11` 的真实 group 文档）。

### 3.6 `src/myfuzz/integration/saved_irq_group.py::frame_for_sample`（epoch 绑定）

原实现只要求成员样本的 `reset_epoch` 等于**它自己的引用**，因此旧 epoch 的成员样本可以
离线拼进新 epoch 的 frame。现在额外要求
`raw['reset_epoch'] == frame['target_epoch']` 且 `ref['reset_epoch'] == frame['target_epoch']`，
否则以 `member native sample epoch differs from the frame target epoch` 拒绝；
raw/reference 不一致仍保留原来的 `member native sample/epoch mismatch` 理由。
已有的 saved-group 用例全部保持通过。

### 3.7 `src/myfuzz/integration/compiled_f6.py`

原 `binding = Binding(dma_id, 'irq', cpu_id, cpu.irq_input_port, 1)` 对非零偏移 CPU 会
指向错误的位，并使 `self.runner._irq_pulses[self._irq_binding]` 抛 `KeyError`（pulses
的键来自 `IrqDeliveryGroup.member_bindings()` 的真实偏移）。现在由
`_f6_actual_irq_binding(runner, dma_id, cpu_id, cpu_port)` 推导：

* 在已安装 bindings 中要求唯一匹配（source 端口 `irq`、`width==1`、
  `source_bit_offset==0`，target 端口 = `cpu.irq_input_port`），保留真实
  `target_bit_offset`；
* 若 runner 安装了 delivery group，要求它就是该 group 的 DMA 成员（端口与偏移一致）；
* 无匹配 / 歧义 / 无 pulse 分别以 `compiled-F6-DMA-IRQ-binding-unavailable`、
  `...-ambiguous`、`...-pulse-unavailable` 干净拒绝。

`compiled_f6_consumer.py` 的 binding 使用（`runner.irq_group_for(binding)`、
`runner.irq_group_delivery(binding, cpu_tick=...)`、`binding.source_component + '.' +
binding.source_port`）与偏移无关，推导后自动拿到真实偏移，文档/join 字节对 offset 0
CPU 不变，因此未改动。

## 4. CV32E40P 与 Ibex 的最终文档（port-local）

同一份真实 `shared-external` 声明、同一对真实 artifact（DMA + PULSAR APB GPIO）：

| 项目 | CV32E40P（`irq_i[11]`） | Ibex（`irq_external_i`，整 1 位） |
| --- | --- | --- |
| verified CPU export | `physical_port=irq_i, bit_lo=bit_hi=11, width=1` | `physical_port=irq_external_i, bit_lo=bit_hi=0, width=1` |
| CPU observation contract | `input_port=irq_i, input_width=1, input_bit_offset=11` | `input_port=irq_external_i, input_width=1`（无 bit offset） |
| group `target_port` / `target_bit_offset` | `irq_i` / **0** | `irq_external_i` / **0** |
| group `target_input_bit_lo`（文档） | **11**（写入文档） | 0（键省略） |
| member binding `target_bit_offset` | 0、0 | 0、0 |
| ownership 字段 | `[{cpu, irq_i, width:1}]` | `[{cpu, irq_external_i, width:1}]` |
| ownership owner | `[{bit_offset:0,width:1,bound,irq-group:shared-external}]` | `[{bit_offset:0,width:1,bound,irq-group:shared-external}]` |
| `_f6_actual_irq_binding` | `(dma,irq)->(cpu,irq_i) width 1 src 0 tgt **0**` | `(dma,irq)->(cpu,irq_external_i) width 1 src 0 tgt 0` |
| runtime path contract 节点 | `F5.cpu_irq_entry=(cpu,irq_i,**11**)` | `=(cpu,irq_external_i,0)` |

E40 的 group 文档（真实准备产物，`shared_flow_paths['F5']['irq_group']`）：

```json
{"group_id":"shared-external","members":[{"mode":"pulse","pulse_width_ticks":16,
 "source_bit_offset":0,"source_component":"dma","source_port":"irq"},
 {"mode":"pulse","pulse_width_ticks":4,"source_bit_offset":0,
 "source_component":"peripheral","source_port":"interrupt"}],
 "operation":"or","schema_version":"host_irq_delivery_group.v1",
 "target_bit_offset":0,"target_component":"cpu","target_input_bit_lo":11,
 "target_port":"irq_i"}
```

真实六流程准备（`configs/scenarios/compiled-f1-f6-cv32e40p-rvfi-gpio-dma-shared`，
`elaboration_mode_scope('direct')`）结果：`shared_flow_paths` 覆盖
`{F1,F2,F3,F4,F5,F6}`；F5 hop 已改写成 `irq_delivery_group`；
`validate_shared_flow_admission(admission)`（从保存 JSON 重建整条 union）通过。

## 5. offset 0 兼容证据

* `tests/integration/test_shared_irq_bit_offset.py::
  test_bit_zero_cpus_keep_byte_identical_group_and_ownership[ibex_rvfi_local]` 与
  `[cv32e20]`：真实 artifact 上得到
  `group.target_port="irq_external_i"`、`group.document()['target_bit_offset']==0`、
  两个 member binding 偏移 0、ownership 文档与改动前逐字节一致（1 位字段、offset 0
  bound owner）。CV32E40P 的文档与它们只在物理端口名不同（`irq_i`），偏移同为 0。
* `test_gpio_evidence_consumer_default_offset_zero_is_unchanged`：默认构造
  `target_bit_offset==0`，既有 documented trace 仍给出
  `counts={irq_delivery:1, irq_acceptance:1, cpu_retirement_serial:1}`。
* `test_irq_delivery_group_accepts_only_a_real_bit_offset`：0/3/11 都可序列化并
  往返一致；`-1`、`64`、`True`、`11.0`、`'11'` 仍被拒绝。
* `test_saved_group_rederivation_reads_the_bound_target_offset`：offset 0 与 offset 3
  都能从原始行重建；伪造 group 偏移、非 bound owner、缺失成员行仍被拒绝。
* 宽向量回归（真实声明）：`picorv32_wb_two_gpio_example` 已声明的 host 位 3 通过
  consumer、runner `_effective_inputs`（`{'irq': 1<<3}`）和
  `_f6_actual_irq_binding` 的用例，证明偏移通用代码对 wishbone 风格仍有效。
* `test_saved_frame_requires_member_samples_from_the_frame_epoch`：成员样本 epoch 与
  frame `target_epoch` 一致时正常返回；旧 epoch（1）样本对 fresh frame（0）被
  `member native sample epoch differs from the frame target epoch` 拒绝；
  raw 样本与自身 reference 不一致仍用原 `member native sample/epoch mismatch`。
* `test_bit_zero_cpus_keep_byte_identical_group_and_ownership`：Ibex/CV32E20 的
  group 文档仍是原来 7 个键（无 `target_input_bit_lo`）且 JSON 往返一致，
  ownership 文档逐字节相同。

## 6. 执行的测试

全部为软件测试（`PYTHONPATH=src python3 -m pytest ...`），没有任何 native/仿真。

### 6.1 指定回归（最终一次合并运行）

```text
PYTHONPATH=src python3 -m pytest tests/integration/test_shared_irq_bit_offset.py \
    tests/integration/test_f6_gpio_companion.py \
    tests/scenario/test_irq_delivery_group.py \
    tests/integration/test_compiled_f6_saved_semantics.py -q
```

最终结果：**449 passed，234.8s**（4 个目标集合一次运行）。单文件/组合参考：
新增文件 24 passed/76.4s；`test_compiled_f6_saved_semantics.py` 404 passed/46.3s。

其他引用本次被改模块、已单独跑过的用例：

| 范围 | 结果 |
| --- | --- |
| `tests/runtime/test_gpio_irq_runtime_mapping.py tests/local_harness/test_pulp_timer_irq_contract.py tests/local_harness/test_declared_irq_output.py tests/local_harness/test_timer_irq_smoke.py tests/local_harness/test_boom_irq_factory_binding.py tests/integration/test_shared_irq_firmware.py -q` | 64 passed，39.8s |
| `tests/integration/test_compiled_f6_saved_semantics.py -q`（`frame_for_sample` epoch 修改后） | 404 passed，46.3s |
| `tests/integration/test_shared_irq_bit_offset.py -q`（最终） | 24 passed，76.4s |
| `tests/scenario` 中直接引用被改模块的 16 个文件（`test_declared_irq_group_review/transport`、`test_edge_provenance*`、`test_gpio_irq_dependency_evidence`、`test_irq_boundary_evidence`、`test_irq_delivery_group`、`test_irq_dependency_evidence`、`test_p2_negative_gates`、`test_timer_irq_group`、`test_uart_*`） | 219 passed，71 subtests，112.3s |
| 同上但为间接的 runtime-path/IRQ/ownership 14 个文件（`test_session_runtime_paths`、`test_runtime_path_contract`、`test_runtime_edge_index`、`test_prepared_runtime_paths`、`test_compiled_ownership`、`test_ownership`、`test_irq_delivery`、`test_irq_dependency_runner`、`test_irq_return_successor`、`test_irq_serial_certificates*`、`test_pin8_*`、`test_registered_irq_serial`） | 182 passed，70 subtests，87.2s |
| `tests/integration/test_shared_f5_runtime.py` | 12 passed，46.3s |

### 6.2 早先的宽回归与共享装配回归

| 命令范围 | 结果 |
| --- | --- |
| `tests/integration/test_cv32e20_shared_config.py tests/integration/test_f6_gpio_companion.py tests/scenario -q` | 见下方状态 |
| `tests/integration/{test_compiled_f6_shared_assembly,test_f6_storage_shared_assembly,test_shared_slot_pin_provider,test_gpio_non_gpio_dispatch,test_shared_f5_runtime,test_shared_f5_support_binding,test_live_f5_crosswalk,test_compiled_f6_saved_semantics}.py -q` | 447 passed，7 failed（归因见 6.3），578.8s |

`tests/scenario` 覆盖 `test_irq_delivery_group.py`、`test_gpio_irq_dependency_evidence.py`、
`test_irq_boundary_evidence.py`、`test_declared_irq_group_review.py`、
`test_timer_irq_group.py`、`test_p2_negative_gates.py` 等所有引用本次被改模块的用例；
该宽回归两次尝试都被并行 agent 的多个 pytest 抢占 CPU 与内存，且期间 lead 正在改
`runtime_path_contract.py`/`runtime_edge_index.py`，50 分钟超时只跑到 49%，失败分散在
与本次改动无关的文件上，未取得可信汇总。可替代的证据是：所有**直接**引用被改模块的
scenario 文件（219 passed + 71 subtests）与**间接**的 runtime-path/IRQ/ownership 文件
（182 passed + 70 subtests）全绿；`test_irq_delivery_group.py` 也包含在 6.1 的
449 passed 里。

### 6.3 7 个失败的归因（与本改动无关）

失败都在 `local_harness/build.py:local_build_identity → _prepare →
runtime_renderer._admit`，错误是 `runtime-physical-facts-mismatch`
（`elaborate_profile(...) != plan.facts`）。这些测试文件都是并行 agent 新增的
**未跟踪**文件（`git status` 显示 `??`），并且失败与本次改动无关，最小复现：

```text
with elaboration_mode_scope('direct'):   # 计划/结构在 direct 模式下产生
    plan = plan_local_harness(request, base_dir=ROOT)
    render_local_runtime(plan, structural, verified, base_dir=ROOT)   # OK
render_local_runtime(plan, structural, verified, base_dir=ROOT)       # ValueError
# ValueError: runtime-physical-facts-mismatch
```

宿主上 `supervisor_available() == True`，于是 `elaborate_profile(mode='auto')` 走
supervised 路径，其 `content_hash`/`modules` 与 direct 路径不同；同一 `plan` 在 scope
外重新准入就会不匹配。该现象对上述 7 个用例与本次改动无因果关系（改动的 6 个文件都不
参与 profile elaboration）。

## 7. 仍依赖其他 owner 的部分

* `src/myfuzz/local_harness/native_physical_observation.py`
  `native_physical_observation_mapping`（`obi_cpu` 分支）仍硬编码
  `row['bit_lo'] == 0 and row['width'] == 1` 选 CPU IRQ 输入。当前 F6 CPU 请求是
  `local_harness.v1`、不带 `raw_tick_stream`，所以尚未触发；但这是同一类硬编码，需要
  `local_harness` owner 泛化为"声明跨度"，否则带原始 tick 流的位切片 CPU 会被拒绝。
* `src/myfuzz/local_harness/cv32e40p_irq_receipt_contract.py` +
  `native_irq_receipt_contract.py`（并行 agent 正在添加）：`input_port='irq_i'`、
  `input_bit_offset=11` 是本报告 DUT 位 11 的权威。新增测试在
  `native_irq_receipt_contract_for_profile` 尚未接受 `cv32e40p_rvfi_local` 时 **skip**
  （不失败）。
* `src/myfuzz/local_harness/cpu_session.py`：按 port-local 坐标**不需要**位切片移位；
  运行值是 `0/1`。之前"需要移位"的判断已作废（已同步给 lead，由 lead 通知
  `cpu_session` owner）。
* `src/myfuzz/scenario/runtime_path_contract.py`（`relation=='irq_delivery_group'`）与
  `src/myfuzz/scenario/runtime_edge_index.py`（同 relation 的 edge row）：这两处用
  runtime path contract 的 DUT 节点偏移去查 runner 的 host 坐标 group/binding，E40 上会
  分别抛 `IRQ group identity mismatch on edge ...` 与
  `compiled IRQ group source membership mismatch`（均在 native 启动前的
  `configure_runtime_paths` → `bind`/`RuntimeEdgeIndex` 阶段）。该 DUT↔host 桥接由
  **lead 本人**实现（见最终验收报告），本报告与本次改动**不**声明这两个文件，
  也未修改它们。
* `src/myfuzz/integration/shared_f5_runtime.py::prepare_shared_f5` 已用
  `ip.bit_offset` / `entry.bit_offset` 建立 binding 与 ownership；
  `compiled_f5_crosswalk._validate_f5_topology` 用 `binding.target_bit_offset ==
  cpu['bit_offset']`；`compiled_execution_files.py:362` 的
  `serial_source_and_physical_irq_binding_not_admitted` 只是 F5 支持状态文案，
  没有偏移假设 → 均无需改动（非本 agent 文件）。
* `src/myfuzz/integration/compiled_f6_saved_semantics.py` 调用
  `rebuild_group(contract,binding,provider['input_port'])` 的签名未变，自动获得新推导；
  它对 CPU 物理导出的比较按 `physical_port` + 1 位宽进行，不比较 `bit_lo`，对位切片 CPU
  无需改动。
* `src/myfuzz/scenario/native_f6_isr_return.py:210` 的 `bit_lo == 0` 针对 64 位
  serial **输出** 导出，与 IRQ 输入无关，未改。

## 8. 未声明

没有 native 通过、没有 RTL 仿真、没有 Verilator 构建、没有修改 `research/`/`runs/`。
