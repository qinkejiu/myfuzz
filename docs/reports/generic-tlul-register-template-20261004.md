# 通用 TL-UL 寄存器模板：限定范围与验收

## 目标与边界

`local_harness.v2` 请求可以为已锁定源码、完整物理顶层且匹配 `target.tl-ul`/`user-integrity` 协议合同的 OpenTitan IP 选择同一 `tlul_register_observe` 模板。生成物复用单一 TL-UL beat 适配器、C++ 驱动和持续运行 session。一次 testcase 中 RTL 仅在开始时 reset，后续寄存器访问和逐周期 step 共用同一 DUT 实例；每个读值、错误位、中断及引脚观测来自真实 RTL。

这个模板只做 TL-UL 寄存器读写和**观测**非总线输出。它不产生 SPI/UART/I2C 串行波形、不验证完整串行协议、也不把寄存器配置推断成 DONE/IRQ。源自 IP 的 IRQ 可被场景路由给 CPU，但模板自己不制造 IRQ 或其他下游值。现有各组件专用运行路径保持可用。

## 声明式选择与输入归属

请求须包含唯一 `endpoint_policies` 记录，选择本 profile 的 TL-UL MMIO endpoint、`target.tl-ul`、版本 `1`、`user-integrity`、最多 1 笔未完成事务。所有非 TL-UL 的物理输入都必须在 `fixed_inputs` 中逐字段声明符合位宽的常量；未声明、重复、超位宽、试图覆盖 TL-UL 输入、指定输出或使用未支持的调优类别都会被拒绝。运行期间场景不能再随机或重写这些常量输入。

例如 GPIO 需要声明 `gpio.pins.in` 和 `gpio.pins.strap_en`；RV Timer 没有额外物理输入，不需声明。常量在 DUT reset 前赋值，并在每条命令前保持。声明及其 SHA-256 进入 plan、生成 artifact、build/session 身份，改变常量会导致不同身份。TL-UL 请求、响应仍由真实 RTL 与通用协议适配器握手；访问偏移限制在 profile 窗口内，并按 4 字节对齐。

## 两个 profile-only 实例

`tests/local_harness/test_generic_tlul_register_real.py` 的两个请求只更换 profile 路径、对应 TL-UL endpoint、必要的固定输入和寄存器场景。没有新增 Timer/GPIO 专用生成器分支。RV Timer 用真实寄存器配置 compare 与 enable，并观测真实 `intr_timer_expired_hart0_timer0_o`；GPIO 写 DIRECT_OUT 与 DIRECT_OE，读取真实寄存器和 `cio_gpio_o`。两个场景各保存证据并在新的 RTL 进程 fresh replay；完整事件和最终状态应逐项匹配。

验收命令：

```bash
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.local_harness.test_generic_tlul_register_real -v
```

通过条件：两个 profile 均生成 `tlul_register_observe`，所有未拥有输入拒绝，真实寄存器和输出断言成立，两份 fresh replay 匹配。该结果证明限定模板可复用，**不证明任意 TL-UL IP 自动可运行**；新 IP 仍需源码锁、完整 profile、真实端口事实、局部时序与外设语义验收。动态环境源、跨组件绑定、串行对端和复杂多时钟/复位仍需独立扩展与验收。
