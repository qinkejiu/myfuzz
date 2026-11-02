# 声明式 SPI IRQ 输出适配验收，2026-10-29

同一公共脚本和 SPI 配置在 Ibex 与 CV32E20 主 profile 上完成实际 CPU MMIO → SPI threshold pulse → host OR → native CPU take → 首 handler 退休。两次配置精确比较后，唯一差异是 `cpu_profile`；没有 CPU×SPI 专用执行器。独立逐项核验及输入 SHA 保存在[验收 JSON](declared-irq-spi-acceptance-20261029.json)，未修改 raw summary。

原生材料为 [Ibex summary](../../research/input-strategy-audit-20261027/runs/declared-irq-20261029/spi-ibex-v1/summary.json) 和 [CV32E20 summary](../../research/input-strategy-audit-20261027/runs/declared-irq-20261029/spi-cv32e20-v1/summary.json)。每组 original/fresh 都有 CPU、active SPI、idle SPI 三个独立进程，六个 PID/nonce 不同，全部 reaped、exit 0；实际 binary/manifest SHA 与记录身份相符。逐条重新解析 raw DriverReceipts 并核对 sequence、tick 和 execution nonce；每阶段 CPU/active/idle 命令分别为 103/106/104。fresh 是**同调用独立 native sessions**，不是另一次 CLI 的 cross-CLI 验证。

| 实际证据 | Ibex original/fresh | CV32E20 original/fresh |
| --- | --- | --- |
| CPU profile / native contract | `ibex_rvfi_local` / `ibex_native_irq_receipts.v2` | `cv32e20` / `cv32e20_native_irq_receipts.v1` |
| 首取指 | `0x10080` | `0x10000` |
| CPU 实际 SW 退休 | tick 74，`0x40001024=0x80000000`，mask 15 | 相同 |
| 原始 APB PRE 完成 | source tick 76，PSEL/PENABLE/PREADY/PWRITE=1，offset `0x24`，PWDATA `0x80000000`，PSLVERR=0 | 相同 |
| 原始 threshold pulse | event 5551，source tick 77 POST，`events_o=1` | 相同 |
| take 时最新 source sample | source tick 81，`events_o=0`；pulse origin 仍指向 tick 77 | 相同 |
| native CPU take / decision serial | CPU tick 76 / 非零 token 1 | 相同 |
| 同 token 首退休 | CPU tick 81，PC `0x1022c` | 相同 |
| events | 每阶段 8018 | 每阶段 8015 |

CPU 与 source tick 是独立本地时钟，不能直接比较数值判断跨组件时间先后。核验依据实际 event/reference、OR frame 的唯一 active source、parsed CPU expected/pre/post input 均为 1，以及 native decision→retirement 的同 token；不是从候选值或最终 source summary 推测中断。两 CPU 的 serial schema 分别是 `ibex_irq_serial_observation.v1` 与 `cpu_irq_serial_observation.v1`，没有将 E20 冒充 Ibex。每组 original/fresh 的结果精确相等。

SPI RTL 中 `events_o[0]=s_int_tx|s_int_rx`，bit1 才是 EOT。实际写 INTCFG `0x24=0x80000000` 使空 FIFO、零 threshold 条件下的 TX/RX FSM 从 ACTIVE 进入 GEN_INT 一周期，再进入 INACTIVE；SDI0..3 静态固定 0。此次没有启动串行 SPI 传输或验证 EOT，也未测试 APB 错误响应。

新 `declared-output.v1` 是**通用 native 输出 transport mapping**：检查现有协议 session、source lock、实际 ABI/vector/bit 和原始 sampler，按配置路由实际输出。它不是 SPI 内部 IRQ source contract。旧 Timer 强 source adapter 仍可通过默认配置选择，其默认程序字节不变；没有把新的弱 transport 资格替代 Timer 的强合同。

两组结果均明确 `transport_only=true`、`source_version=unknown`、`isr_mmio=unknown`、`grants_F5=false`、`grants_F6=false`、`reward_eligible=false`。验收只覆盖声明输出到 CPU 首 handler 的真实链，不授予内部因果、完整 F5/F6、ISR MMIO 或奖励；不外推到其他输出位、CPU、WB/AHB target 或性能改进。

## 后续 target 协议复用：ZipTimer Wishbone

同一脚本以实际 artifact kind 选择已有 Wishbone target session，未新增 IRQ source contract 或 CPU×IP 执行器。[WB summary](../../research/input-strategy-audit-20261027/runs/declared-irq-20261029/wb-timer-ibex-v1/summary.json) 与[独立 raw 核验 JSON](declared-irq-wb-acceptance-20261029.json) 覆盖原/fresh：CPU tick 74 实际 SW 写 `0x40001000=8`、mask15；这是单个 4-byte addressless COUNT 窗口，不是 APB register transaction。

实际 **Wishbone** PRE 请求在 target tick75：CYC/STB/WE=1、DATA=8、SEL15、STALL0、ACK0；tick76 为 CYC1/STB0/ACK1 的注册响应。不存在 RTL address port，未伪造地址信号；CPU byte address 由真实 router window 核对。复用 `IpProtocolEventNormalizer` 从 raw PRE 独立重建请求/接受/响应，不将 Wishbone 表标成 APB。RTL 忽略 SEL，不把观测到 SEL15 等同于支持 partial write；ACK 也不能证明 CYC 是该 IP 的必要条件。

实际 `o_int` 在 target tick83 POST 为1，take时最新 source tick84已经为0，frame仍保留真实高脉冲 origin。idle Timer 的全部 native `o_int` 为0。CPU tick79 native take、非零 serial1 与 tick85 PC `0x1022c` 首 handler 退休相连。两边各2130events，raw命令 CPU/active/idle 为107/110/108，逐条重新解析；六个PID/nonce独立、reaped exit0，实际binary/manifest SHA逐一匹配，两边结果相同。

这里的 target tick 与 CPU tick 仍是独立本地时钟；fresh 为同调用独立进程。范围仅为声明式 Wishbone 输出 transport→CPU首handler，internal version/ISR MMIO unknown，不授予F5/F6或奖励。AHB target 尚未由该结果验证。
