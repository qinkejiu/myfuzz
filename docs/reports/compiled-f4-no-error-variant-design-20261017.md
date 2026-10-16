# OBI 无 error pin 的合法 variant：设计与缺口

这是后续设计，尚未修改或验证正在运行过的 F4 source snapshot。Ibex 本次通过不代表 CV32E40P 已接入；CV32 的真实无 error pin ABI 必须保留。

## 已存在的受信基础

`template_contracts.py` 已有 `read-only-no-error-pins` / `read-write-no-error-pins`，要求显式 `error_response=False`，声明 `backend_error_policy=fail_stop_no_error_pin_to_raise`。`runtime_renderer.py` 只观察实际 CPU 物理角色：无 error 时不生成伪 tap，adapter 使用 `HAS_ERROR=0`。`obi_processor_memory_adapter.sv:65` 对真实 backend `rsp_valid && rsp_ready && rsp_error` 执行 `$fatal`。这些闭包应被精确复用，不能改 CPU profile 或补常量 error=0。

## 建议显式 policy

| 受信 variant | admission 条件 | 成功响应证据 | 不授予的能力 |
| --- | --- | --- | --- |
| `native_error_role` | `error_response=True`；两个 native endpoint/trace 均含实际 1-bit error role；精确 artifact/template/adapter closure | 实际 handshake、rdata 与实际 error 样本；当前 success-only F4 要求 error=0 | 未经 gate 的错误注入、trap/异常响应证明 |
| `fail_stop_no_error_pin` | `error_response=False`；两个 endpoint/trace 均无 error role；精确 no-error template pair 与 `HAS_ERROR=0`/fail-stop closure | 实际 handshake/rdata、完整 producer/route/target joins；`error_observation=null` 或显式 `not_exposed_by_ABI` | native error=0 断言、CPU 可观测 error/trap 能力 |

Policy 应来自实际已选模板、profile fact、物理角色与 source-pinned adapter，进入 checker/prefix/capability identity；不按 component 名称分支。混合/矛盾/缺失能力声明启动前拒绝。任何明确需要 native error 观测的断言在 no-error variant 上返回 unsupported，不能标 passed。

现有三项 F4 声明仍须保留 exact instruction/CPU/router/APB/commit hops。No-error 只说明 CPU ABI 无该角色；真实 APB `pslverr`、服务失败和 adapter fail-stop 仍须独立检查并绑定 transaction，不能把 adapter 内部状态冒充 native error pin。

## 必须补齐的门

1. 加代码拥有的 policy 选择与一致性验证，输出 null/absent error 证据；保留当前 native-error 变体全部检查。证明缺/伪 error tap、矛盾 capability、错 template、错 adapter closure 均拒绝。
2. 复用现有 `tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel`，并在实际生成 no-error CPU 边界加入受控 backend ERR 门，核对真实非零进程终态/原生 fatal、没有可接受的 CPU 成功响应，保存 raw 日志与边界。仅此设计文档没有运行这些门。
3. 将旧 CV32 配置作为合法 no-error success-only 正例候选；把“要求 native error 观测却没有角色”保留为能力负例。不能将整个组件永久等同于非法 ABI。
4. 新冻结 executor 后，分别运行 Ibex native-error 与 CV32 no-error 的相同 F4 continuous/fresh-prefix 门；失败也保留 attempted prefix、进程终态及不确定边界。不要借用旧 CV32 evidence 升级新 consumer。

这只扩展一个协议 ABI variant 的可执行观察合同，不自动获得任意 IP 内部 register authority、搜索能力或完整 P7 验收。
