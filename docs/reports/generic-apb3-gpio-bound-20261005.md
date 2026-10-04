# 通用 APB3 GPIO Bound Input 真实闭环

两个独立的 PULP GPIO RTL 实例使用同一个 `local_harness.v2` APB3 register-observe 模板生成。实例 A 的 `gpio.pins.in` 是固定环境输入；实例 B 的同一输入由 `bound_bindings` 声明为 `a.gpio_out`，ScenarioRunner 的 `Binding` 只转交 A 的真实 `gpio_out`。两个进程在同一 testcase 中持续运行，没有每步复位。

真实 RTL 验收先由 A 的 APB3 写操作配置并驱动输出 bit 0；数据流事件记录 A 输出值 `1` 交付给 B，且 B 的输入在至少两个后续本地步骤保持 `1`。B 随后由自身 RTL 产生 `interrupt`；断言要求交付事件先于 IRQ。整个场景从新进程 fresh replay，结果一致。

负例验证目标 artifact 的生产者身份进入 digest，`fixed_inputs` 与 `bound_bindings` 重叠时拒绝，缺少精确真实输出路由时拒绝，Fuzzer 直接变异 B 的 bound 输入时拒绝。此验收证明 APB3 模板可承载真实 IP→IP 数据流与持久输入；它不等同于 CPU 参与的跨组件链，也不证明其他 APB3 外设的寄存器和 IRQ 语义。
