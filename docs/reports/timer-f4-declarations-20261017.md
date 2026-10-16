# 同协议新 IP：真实 timer 的 F4 声明 — 2026-10-17

[声明式组合](../../configs/scenarios/compiled-f4-obi-apb-timer/README.md)选择现有真正不同的 PULP apb_timer RTL，使用同一 generic APB3 register template。sidecar 仅声明 TIMER0_CTRL（+4），不把自主变化的 COUNT 当成稳定寄存器。原两份 RTL 的字节 SHA、profile fingerprint 与寄存器引用已在纯软件控制中核对。

现有 D3 编译器无需增加组件名分支，即选择该寄存器，并从声明导出单一32位输入，即4字节候选；没有为沿用 GPIO 的8字节格式而加入假引脚。F5 没有 IRQ 消费者，保持 unsupported。缺少 sidecar 或给 GPIO 使用 timer sidecar 均不能借用能力。

新增控制先3项因缺声明 RED，后4项通过0.35秒。只运行 profile/sidecar/声明加载、现有路径编译与候选布局，不执行 frontend、模型或构建。手工声明的 wiring 合同明确不是 D2 产物。

- [完整 D3 输出](evidence/timer-f4-declarations-20261017/compiled_paths.json)
- [证据范围](evidence/timer-f4-declarations-20261017/scope.json)

该 IP 对编译F4支持集是新的，对仓库不是新的。实际 storage/reset/command producer、版本令牌和原生CPU/fresh门仍缺；当前live F4 admission继续拒绝generic目标，不以声明或读回替代ip_register_version。P6/P7/P8未因此升级。
