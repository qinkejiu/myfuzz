# 自动生成独立 Harness：当前能力边界

日期：2026-10-04。此表只统计新的单组件自动生成链；既有手写会话和 SoC 组合实验单列，不替代生成器验收。等级定义见 `docs/superpowers/specs/2026-10-04-generated-local-harness-five-protocol-design.md`。

| CPU 侧原生协议 | 固定源码与完整端口事实 | 新生成器当前产物 | 尚缺的正式等级门槛 |
|---|---|---|---|
| OBI | CV32E20/CVE2 已有固定源锁和 full-top profile；Ibex 现有 profile 只选部分顶层端口 | CVE2 单 DUT wrapper、双 OBI 局部 adapter 顶层，真实 Verilator lint | C++ driver、持续 CPU session、真实取指/Store/Load、replay；另一个 OBI CPU 的生成式复用 |
| AXI4 | CVA6 已有 profile 与手写真实会话 | Catalog | 明确有限 ID/burst/在途契约的生成式 driver、真实局部执行和 replay |
| AXI4-Lite | PicoRV32 `_axi` 已有固定源锁和 full-top profile | Catalog | 处理物理顶层无 BRESP/RRESP 的生成式模板及真实会话 |
| Wishbone classic | PicoRV32 `_wb` 已有固定源锁和 full-top profile | Catalog | 处理物理顶层无 ERR/STALL 的生成式模板及真实会话 |
| Pico Ready/Valid Memory | PicoRV32 普通顶层已有固定源锁和 full-top profile | Catalog | `mem_ready` 作为完成信号的生成式模板、真实会话及 replay；现有通用 IDLE-ready adapter 不能直接使用 |

| IP 侧系列 | 已有真实源码候选 | 新生成器当前产物 | 尚缺门槛 |
|---|---|---|---|
| OpenTitan TL-UL | GPIO、UART、SPI Host、SPI Device、I2C、RV Timer | Catalog；手写 OpenTitan session 另有真实证据 | 生成式 TL-UL 局部执行器、每类真实 pin/frame peer、完整 replay |
| PULP APB3 | GPIO、SPI | GPIO 单 DUT wrapper、APB3 adapter 顶层与真实地址边界仿真；SPI 仍为 Catalog | GPIO 持续 session/寄存器/脉冲 IRQ、SPI peer、CPU 与双 GPIO 双向多轮验收 |
| ZipCPU Wishbone | UART、Timer | Catalog；旧 SoC target 证据单列 | 生成式独立 Wishbone IP session；Timer 的特殊 CYC/SEL/地址单位须明示语义变体 |

当前结构与来源门禁：`local_harness.v1` 请求、full-top planner、逐位 disposition、参数类型源码证据、确定性结构 wrapper、CV32E20/PULP GPIO 外层局部协议 adapter、固定源码锁校验都已落地。C++ 严格命令协议头已落地。`local_harness.v2` 的微调只解析并验证有事实依据的配置，记录 `runtime_effective=false`，尚未作用于执行。最新 `tests/local_harness` 为 **84/84**，包含 CVE2/PULP RTL lint 与 PULP 地址窗口仿真；这些结果仍不证明生成式会话已启动。

正式等级目前仍为 **Catalog**：按设计定义，Generated 还要求 wrapper 和执行器都已生成；RTL operational 要求真实持久会话与交易；Cross-component accepted 要求多个独立会话在同一 testcase 中完成双向传播并从初态完整 replay。现有手写 Ibex/CVA6/OpenTitan 场景和旧 Pico adapter bench 保留各自证据，但不会给新生成器升级。

下一验收顺序：生成 C++ 驱动与身份缓存 → PULP GPIO APB3 持久会话 → CVE2 OBI 持久会话 → 双 PULP GPIO 双向各两轮及 replay → Pico 三协议 → 有限 CVA6 AXI4 → OpenTitan TL-UL、PULP SPI、ZipCPU Wishbone 的生成式独立外设会话。未来新同协议组件必须只增加固定 profile 与声明式微调，即可生成、真实运行、replay，才算达到通用化目标。
