# AHB SHA 声明式 IRQ transport 验收，2026-10-29

CV32E20 主 profile 与原 Caliptra AHB target 经同一公共脚本完成 software-triggered `error_intr` → host pulse/OR → native CPU take → 首 handler 退休。[原生 summary](../../research/input-strategy-audit-20261027/runs/declared-irq-20261029/ahb-sha-cv32e20-v1/summary.json) 和[独立 raw 核验 JSON](declared-irq-ahb-sha-acceptance-20261029.json) 均为 verified。未改写 raw summary，未运行额外 native。

CPU 在本地 tick78/88/98 真实退休三次 SW，完整地址为 `0x40001800/0x40001804/0x4000181c`，各写1、mask15；不存在 signed12 offset 截断。target 的原始 AHB address/data 阶段分别在本地 tick79→80、94→95、109→110：HSEL/HWRITE=1、HTRANS=NONSEQ、HSIZE=word，地址为窗口内 byte offsets `0x800/0x804/0x81c`；后续 data phase 的 HWDATA=1、HREADYOUT=1、HRESP=0。独立复用既有 `IpProtocolEventNormalizer` 从 raw PRE 重建三组请求/响应及精确 request references，没有把 AHB 标成 APB 或把当前 address phase 的值套给另一 data phase。

真实 `error_intr` 在 source tick112 POST 变高，take时最新 source tick115仍高；它是 sticky level，不是原生单周期 pulse。显式 host pulse16 仅捕获首次观察到的 rise。actual OR frame 为唯一 `sha_active.error_intr`，CPU expected/pre/post input 均1；CPU本地 tick100 native take 的非零 decision token1，在 tick105 PC`0x1022c` 首 handler 退休以 `cpu_irq_serial_observation.v1` 精确相连，CPU contract 为 `cv32e20_native_irq_receipts.v1`。CPU首取指实际为`0x10000`。两边 idle SHA 的全部 `error_intr` 均0。不同组件 tick 不代表同一全局时间轴，顺序由原始 event/reference 核对。

original/fresh 各3635events，CPU/active/idle raw命令127/134/128，逐条重新解析 wire reply 的 execution nonce、sequence、tick。六个PID/nonce独立，全部reaped/exit0；实际binary/manifest SHA与保存身份一致，原/fresh结果完全相同。fresh为**同调用独立native sessions**，不是cross-CLI。

范围仅为已有 AHB session 与通用 `declared-output.v1` mapping 的复用，不新增 SHA source contract。此次写 global error enable、error0 enable 和 software error0 trigger，不执行SHA digest，也不验证HRESP错误；原wrapper的AHB err固定0。`transport_only=true`，source version/ISR MMIO unknown，`grants_F5=false`、`grants_F6=false`、`reward_eligible=false`。未将输出transport升级为内部因果或完整F5/F6能力。
