# F5 与 MixedStorage 共会话接线审查

本次实现范围：`MixedStorageKernel.requirements` 对共享端点合并 operations 和 evidence_obligations，拒绝其他 capability token 冲突；按已注册 kernel 路由。没有实现 F5 共会话。MemoryFlowKernel 尚没有 requirements 协议，现明确返回 generic-semantic-unsupported，不能据此宣称 F1/F3 capability 已完成。

软件验证：`PYTHONPATH=src:. pytest -q tests/runtime/test_mixed_requirements_union.py tests/runtime/test_generic_mixed_entry.py tests/runtime/test_storage_kernel.py`，66 passed。新测试先观察到 4 个预期失败，再实现通过。没有运行 native。

## 实际缺口

`CompiledF4Runtime` 当前构造 CPU 和一个 storage target，ScenarioRunner 的 bindings 为空。F1/F3 的路径、instruction binding 与 F2/F4 一起在 begin 前配置；其 source ownership 来自本次 compiled_inputs。

F5 当前 `IbexPulpOnlineRuntime.submit_f5` 使用实际 decoder、逐次 `_require_f5_current`、真实 gate、session.submit_case 和 decoder.commit。`validate_compiled_f5_crosswalk` 固定要求 cpu/gpio_a/gpio_b 三组件、固定 pin8、f5_only ownership 与 4 tick IRQ pulse。它不能直接复用于两个组件的 storage runner，也不能把独立 runtime 的 decoder 挂到另一个 runner。

已有 `mixed_external_runtime.prepare_external` 可把实际 OnlineCaseDecoder 绑定为 ExternalPinSource，并以真实 waiting instruction transaction、未物化 instruction slots、实际 ownership/gate 验证 fixed support。这是 register-program runtime 的授权路径，不能仅凭其保存 manifest 安装到 CompiledF4Runtime。

## 推荐实施顺序

1. 将 F5 crosswalk 的实际 source/IRQ delivery/physical ABI 检查提取成以 preparation、真实 runner、选中 F5 path 为输入的组件级适配；保留当前固定 PULP crosswalk 为兼容包装。验证实际 session.artifact 身份、物理 ownership、pulse delivery 和 contract identity。不能放宽为接受保存的 source 字典。
2. 在 CompiledF4Runtime begin 前 opt-in 配置 F5。由同一 compiled_inputs 的 wiring.deliveries 构造实际 Binding/IrqPulseDelivery；要求 CPU/target 已由 component adapter 声明支持 IRQ，拒绝不支持的 Timer/SPI 组合。把 F5 runtime path 与 F1–F4 路径一起配置，不创建第二个 session/memory/runner。
3. 建立 F5 decoder 的共享 cursor 分配器。独立 decoder 当前自行 commit，storage runtime 使用 runtime.cursor；必须以真实 CPU waiting instruction address 和统一未物化槽分配为准，避免交错后复用旧槽。先支持 external pin + 固定 NOP support；ISR/CPU 配置必须来自合法 F1/F4 动作，不能由宿主写寄存器补齐。
4. 新增 F5FlowKernel/LoweredCase 支持与 mixed.submit_lowered 分派。raw8 解码、source action 注册、提交、commit 仍走 live 适配；实际成功后才记录 flow/testcase_id/raw8/receipt。capture 没有版本消费 provider 时返回空，不给奖励。checker 需支持 F5 receipt，不能把 IRQ delivery 当成 storage 写读 certificate。
5. 完整前缀保存与 fresh 根据 records 的 flow 重新执行 F1–F5；对共享 session 边界、同一 memory 对象、交错槽不重用、预算截断、F5 后 F4/F2 authority 有效性做 mock 测试。冻结全部源码后再由主代理运行至少 F4→F5→F2 与 F1→F5 的 native original/fresh。

下一阶段适合先完成第1项与第2项的 fail-closed admission，再扩大合法动作目录。当前 requirements 修复只保证共享 capability 要求不丢失，不等于统一系统已完成，也不证明搜索收益。

## 后续增量：live F5 crosswalk 已实际接入

新增 `validate_live_f5_crosswalk(preparation, runner, path, binding, pulse_width_ticks)`；要求真实 `PreparationContext`，边界重验 current 与生成 artifact 文件，按实际 F5 path 选择 pin source、IRQ producer/consumer、delivery 和 path contract 内物理节点。检查 ABI/export 一致、实际 `GeneratedLocalSession` artifact 身份、物理 source/IRQ ownership、实际 runner source ownership 与 IRQ bound producer、绑定范围以及真实 `IrqPulseDelivery` 宽度。

组件 adapter 仍负责声明逻辑 Binding 与预期 pulse 宽度；此函数只对照实际 runner 检查，不创建 binding 或安装权限。目前只支持单 bit pin、单 bit pulse IRQ，要求 path 能唯一解析物理节点。它不证明 runtime 的任意逻辑 alias 与物理端口实现正确，也不证明 CPU 接受中断或执行 ISR；这些仍需组件适配与消费证据。

`validate_compiled_f5_crosswalk` 固定包装保留原固定拓扑、profile/session 类型、ownership、pin8 与4 tick约束以及 v1输出；其内部调用通用拓扑校验。提供实际 preparation 时调用公开 live API。生产 `ibex_pulp_online.validated_factory` 和 `_require_f5_current` 两个边界均传入当前 preparation，因此构造/重放和每次 F5 submit 已走 live 检查。旧调用方不传 preparation 的包装接口仍保持原有行为与约束。

通用 crosswalk 仍未将 F5 加入 MixedStorage session。报告实施顺序第2–5项仍未完成。

本增量最终软件验证：crosswalk/live/online-entry/requirements 联合门中25 passed；另1个负例因误改固定CPU source形成空操作而失败，已修正为修改 external_pin 的 component，单独复验1 passed。生产源码在联合门启动前已定稿，其后只修正上述测试。最终26个独立测试均有通过证据；没有把旧失败输出改写为联合全绿。额外 storage/mixed 回归66 passed/0.70s。未运行native。
