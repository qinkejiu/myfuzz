# P7 下一条通用接入链：只读差距审计

本轮只读检查了 P7 implementation plan 最新 2026-10-17 更正、D3 编译器与执行投影、compiled F4 executor/file entry、register writer、GPIOEN live authority，以及 Ibex/CV32 fixtures 和相关测试源码。未运行测试、生成器、native 构造或远端任务，未修改实现。以下是可实施顺序，不是已完成能力或验收结论。

## 当前真实起点

旧具名 runtime family 的端到端通过不能证明 D4 消费同次 D2/D3，最新更正已正确收回该泛化。当前 `compiled_f4` 确实消费精确 artifacts、私有重建的 typed request/D3/ownership，执行真实 CPU writer、native OBI/APB hops 和 live GPIOEN 版本，并支持完整成功 prefix 的 fresh reconstruction。这比 D2-only 前进了一步，但只覆盖实验性 F4。

当前 Ibex fixture 声明真实 instr/data error pins；`_cpu_traces` 要求每端一个 `cpu_physical_abi` OBI trace、max_outstanding=1，并要求 error 信号。原 CV32E40P fixture 虽是同 OBI 名称，其 trace 缺 physical error role，因此当前 admission 把它保留为不支持负例。不能删掉 error 要求、补一个伪常量或借旧 CV32 evidence 宣称当前新 executor 已验证。这里应把协议子形态及 fail-stop 能力说清，不能以组件名判断支持。

## 最短实现链（依赖顺序，五项）

### 1. 把执行能力选择变成真实声明投影，保留受信实现闭集

**具体接缝：** `integration/compiled_f4.py:admit_f4/_cpu_traces/_f4_edges`；`local_harness/compiled_execution_projection.py:assess_compiled_execution/assess_compiled_f4_support`；`generated_execution_admission.py:create_compiled_execution`。

当前可由合同替代的限制包括：单 F4、一个 instruction image/一个 MMIO stream、一个设备、固定三种 source、一套 prerequisites/assertions、seed 必须 None、只允许一个 bound commit、没有 deliveries/physical bound ownership，以及 reachable_window rule 里的字面 `owner='cpu'`/`bus_owner='cpu'`。其中 owner 应绑定声明角色与实际 source owner，不能靠换 instance 名通过或失败。单设备/单流可先作为显式支持预算保留；不要一次实现所有拓扑。

先产生 typed execution plan：逐项携带 source/constraint/precondition/bound/assertion/termination 的代码拥有 handler 与具体声明参数；每项有 implemented/refused 和 JSON pointer；只有全部有实际 handler 的路径才能启动。把现有 F4 收为第一个受信 executor，而不是把“handler 名已声明”当作实现。按 protocol variant、ISA、native trace capability、ownership 和资源权限选择，不能按 CPU/IP component_id 或场景目录分支。

**真正通用：** 编译语义到受信 handler 的逐项选择和拒绝；**仍专用：** GPIOEN register authority 和 APB GPIO observer。F1/F2/F3/F5/F6 不应随 F4 扩展被自动授级。

### 2. 从 D3 source/constraints 生成候选布局与 seed/decoder

**具体接缝：** `compiled_f4.py:CompiledF4Runtime.submit`；`integration/generated_register_writer.py:declare_writer`；`scenario/compiled_paths.py:_compile_constraints/_layout_annotations/_runtime_declaration`；`compiled_execution_files.py:run_compiled_execution_files`。

当前 raw 固定八字节，前四字节仅做一个寄存器值、后四字节被所有 external pin source 复用；不是由 D3 独立位段生成。decoder 固定 SW→LW→RAM 的 RV32I fragment，固定寄存器和 NOP 布局；result 位于 instruction image 最后四字节，image 必须可写；seed 被 admission 明确拒绝。`check_f4_exact_hops` 还按固定 instruction snapshot 范围检查，应改由实际 fragment 长度/指令布局描述驱动。

最短扩展是声明一个 bounded register-word candidate schema：独立 source slices、mask/range/ownership/access alignment 校验和确定性 invalid 分类；由合法访问合同生成 writer/readback fragment；将 result scratch 声明为独立资源；把已实现 seed 映射成真实初始 bytes/记录，未知 seed 继续拒绝。首期仍只 RV32I/word access，不能包装成任意指令搜索。多个 source 不应无声明地共享 raw 高四字节。

**真正通用：** source layout、约束、seed、预算和 instruction arena 的绑定；**不等价于通用语义：** rw 寄存器可读回同值仅适用于 sidecar 明确 none side effect/full-word 的子集，不能推广到 W1C/read-clear/FIFO。

### 3. 分离协议观察、寄存器 live authority 和编译断言调度

**具体接缝：** `compiled_f4.py:admit_f4/_check_chain/_check_receipt`；`scenario/gpio_register_version.py:GpioRegisterVersionAuthority.issue`；`generated_register_writer.py:check_writer_observation`。

最强具名限制不在 CPU 名称，而在 `kind='apb_gpio'`、`register='GPIOEN'`、固定 pulp_gpio_observation_contract、固定 `ip_register_version(GPIOEN, epoch=0)` 和直接创建 GeneratedPulpGpioSession/GpioRegisterVersionAuthority。当前 `_check_chain` 实际执行了三个受支持检查，随后写出 passed assertions；它不是可消费任意 D3 assertion 的通用派发器。

先定义 register state witness 接口（issue/consume、epoch、version、source-pinned observation、commit context），再注册 GPIOEN 既有实现；通用 APB request/response checker不能凭总线读回自行制造内部 register authority。其他同 APB IP 若没有已实现 witness，应只授 protocol observation 能力，明确拒绝依赖 live register version 的路径。断言按 expectation_id+class 派发到代码实现，输入是精确事件 joins/authority，输出 passed/failed/unsupported，缺一个不能授路径 certified。保留 native actual hop/error ownership检查。

**真正通用：** 受信 assertion/witness 接口和逐断言证据绑定；**GPIOEN 专用：** 内部使能寄存器版本、原生 probe、commit before/after 关系。给接口改名不会自动产生新 IP authority。

### 4. 接入真实覆盖反馈与候选循环，保持 directed/search 分级

**具体接缝：** `compiled_f4.py:feedback/submit`；`compiled_execution_files.py:run_compiled_execution_files`；`scenario/compiled_paths.py` 的路径 source/termination 与 capability report 接口。

当前反馈只有 cases/certified/distinct_values/changed_versions；file entry 明写 coverage_guided=False，只执行 records 文件，没有接收 RTL coverage、协议状态、断言相关 coverage 或据此选择下一 candidate 的循环。changed_versions 是功能历史计数，不是覆盖引导搜索证据。

先让受信 observer 提供带来源和 schema 的 protocol/state coverage；candidate decoder 输出与 source_id/path_id 绑定的反馈；再接既有预算搜索客户端，将 accepted candidate、覆盖增量、invalid/failed 分类、语义 checker 结果和耗时共同保存。后续才允许报告 coverage-guided searched；发现协议/功能失败仍须 fresh counterfactual/replay 才能升级 bug confirmed。GPIOEN 值分布可作为一个受限反馈项，但不能替代通用协议/IP 覆盖。

### 5. 将失败 bundle 与 fresh replay 绑定到原始尝试，而不只成功 records

**具体接缝：** `compiled_f4.py:submit/finish/replay/_private_admission_snapshot/_stable`；`compiled_execution_files.py:run_compiled_execution_files`。

现有强项是 exact live plan 比较、私有重建、source closure、artifact digests、compiled digest 和成功 records fresh 重执行。缺口是 submit 仅在 certificate 成功后 append self.records；失败候选可能已执行 CPU/目标动作却不在 records；file entry 保存 partial_events/.incomplete/report，但没有同时保存原始 attempted record、失败 phase/command boundary、未决/不确定账本、完整失败 online plan 和可重放的 finalize 边界。启动失败时 runtime 变量尚未取得，外层明确只能报告 startup_partial_trace_available=False。

最短修法：执行前追加不可变 attempted-candidate journal，记录 raw、D3/source mapping、case/phase、native execution scope；成功再附 certificate，失败保留 uncertain effect；finalize 时输出同一 source/artifact/ownership/budget/decoder/checker identity 下的 failure bundle。fresh 必须重建 exact declarations并重复原 attempted prefix，匹配失败边界与完整原始 native journal；只对声明 process scopes 归一化，现场检查 fresh PID/nonce 不复用，不能只删除 certificate.process_scope 后凭 matches 字段断言 fresh。独立离线 bundle 不得恢复 live authority。

## 建议最小交付边界

优先完成 1→2→3，得到“已验收 OBI 单 outstanding + RV32I + 已实现 APB word/witness 子集”的声明驱动 executor；现有 Ibex 是正例候选，缺 physical error 的 CV32 保持具名原因负例。随后 4 接搜索反馈、5 补完整失败复现；失败 journal 的基础记录可随 2 同时接入，避免新候选丢失。

正式 P7 同协议无新增组件适配的证据，应在冻结 executor 后，仅变更声明/profile/source pins 接入另一个满足同一 protocol variant 的 CPU 和另一个具备明确受信语义/observer能力的 IP；若新 IP 仍需新增内部 probe/witness 实现，必须记为新能力扩展，不能称“仅同协议自动获得 GPIOEN 语义”。每条路径独立给能力等级，保留相似名称/缺角色/缺约束/缺断言处理器的启动前拒绝。本文不授 P7-D/E 或任何新增 native pass。
