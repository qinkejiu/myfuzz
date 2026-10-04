# Wishbone 目标寄存器通用模板验收

日期：2026-10-04

`local_harness.v2` 可以通过既有的 `target.wishbone/1` endpoint policy，针对具有不同端口形态的 ZipCPU ziptimer 与 wbuart 生成同一个 `wishbone_register_observe` runtime/session/driver。模板依据已验证的 profile 能力选择两种已声明的协议变体：Timer 的无地址、SEL 忽略、CYC 忽略、registered ACK；wbuart 的字地址、SEL 有效、CYC 有效、registered ACK。适配器保留 DUT 的原生局部 Wishbone 握手；不按 component_id、profile 路径或外设类型选择生成器分支。

## 证据

- 源锁与全端口事实分别来自 `configs/peripherals/zipcpu_timer/component_profile.json` 和 `configs/peripherals/zipcpu_uart/component_profile.json`，test 用相同的 request schema 和同一 session class 渲染两份 artifact。
- `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_wishbone_register_real -v`：2/2 通过。真实 RTL 完成写寄存器、读寄存器，且每一笔事务恰有一次 DUT 原生 STB；Timer 读到下降中的真实 COUNT，wbuart 读到实际 SETUP 值。连续 8 个场景步骤无再次 reset，完整 evidence 从新 session 初态 replay 一致。
- wbuart 的 RX 与 CTS 输入必须由 `fixed_inputs` 明确归属。缺少任何一个时生成失败；输出 pin/IRQ 只观察真实 RTL 值。Timer 的 `i_ce=1` 继续由受信 profile 的端口 disposition 声明。
- profile window、地址位数、字对齐和无地址变体的 4-byte 窗口均被检查。无部分写能力时 session 拒绝部分字节写。

## 能力边界

此模板只证明寄存器交易、固定环境输入和物理输出观察；不驱动 wbuart 串行 RX/TX peer，也不宣称 UART 功能闭环或跨组件验收。串行验收仍由已有专用 `wishbone_uart` session 承担。当前 Wishbone 通用 v2 模板还未接入动态环境源和真实上游 Bound Input；新 IP 若需要这些输入，须扩展模板契约并重新做真实 RTL 验收。现有两个 profile 属于同一 ZipCPU 外设系列，因此不能由此推断任意 Wishbone IP 已自动支持。
