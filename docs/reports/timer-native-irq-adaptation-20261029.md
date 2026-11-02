# Timer 原生 IRQ 组件适配验收（2026-10-29）

Ibex 与 CV32E20 均通过同一脚本的 original/fresh 验收。本次独立离线复核了两组原始事件、APB 波形字段、CPU 物理采样和进程记录，未重跑 DUT。产物 SHA-256、逐 phase 事件索引及进程身份见[核验 JSON](timer-native-irq-adaptation-20261029.json)。

| CPU / 产物 | original / fresh 事件数 | 原生 IRQ / CPU take / 首次退休 |
|---|---:|---|
| [Ibex](../../research/input-strategy-audit-20261027/runs/timer-native-irq-20261029/ibex-v1/summary.json) | 2636 / 2636 | Timer tick 91 / CPU tick 81 / CPU tick 85 |
| [CV32E20](../../research/input-strategy-audit-20261027/runs/timer-native-irq-20261029/cv32e20-v1/summary.json) | 2634 / 2634 | Timer tick 91 / CPU tick 81 / CPU tick 85 |

两份运行配置仅 `cpu_profile` 不同；两个 Timer 的生成 artifact 在两组运行间逐字节相同。CPU 启动地址按各自已验证源合同确定（Ibex `0x10080`，CV32E20 `0x10000`），不要求两 CPU 的程序布局或事件数相同。均复用公共 CPU session、Generic APB session、router 和 IRQ delivery group，没有新增 CPU×Timer 执行器。

四个 phase 均确认：

- 真实 CPU MMIO 经路由驱动 APB，在 Timer 本地 tick 74、82、91 分别写 `CTRL[4]=0`、`CMP[8]=0`、`COUNT[0]=0xffffffff`；原始 PRE 样本的 `PSEL/PENABLE/PREADY/PWRITE=1`、`PSLVERR=0`。
- 实际四位 `irq_o` 的 bit 0 在 tick 91 POST、92 PRE 为 1，随后消退。另一 Timer 的 216 个原生样本全部为 0，未以常量替代采样。显式 host pulse adapter 将该真实脉冲捕获为 16 个 CPU tick；这不是 RTL 持续电平中断。
- OR frame 唯一来源为 `timer_active.irq_o`，保留实际脉冲 event 1872；同一 CPU sample/take 关联物理输入 1 与真实 `irq_taken_pre=1`。decision serial 为 1，精确关联首条 `intr=1` 的退休：PC `0x1022c`、order 38、retirement serial 1；指令与固定 vector 字节一致。
- 每组 original/fresh 独立重算结果相等。CPU、active Timer、idle Timer 的 PID 和 execution nonce 均分别不同，六个进程均已回收且 exit 0。fresh 范围是**同次调用内的独立 native sessions**，不冒称跨 CLI fresh。

Timer 与 CPU 使用独立本地 tick；上表的 91 与 81 不用于跨时钟比较，来源关系由真实样本、组成员、OR 输入及 take/serial 引用建立。

复跑入口（输出目录必须不存在）：

```sh
PYTHONPATH=src python3 scripts/run_timer_irq_smoke.py --native --config configs/peripherals/pulp_timer_irq/smoke.json --output /tmp/timer-irq-ibex-new --cache runs/config-driven-20261028/cache
PYTHONPATH=src python3 scripts/run_timer_irq_smoke.py --native --config configs/peripherals/pulp_timer_irq/smoke-cv32e20.json --output /tmp/timer-irq-e20-new --cache runs/config-driven-20261028/cache
```

完成范围仅为真实 CPU MMIO→Timer 原生脉冲→host OR→CPU acceptance→serial 首次 handler 退休。它没有接入 F5 外部 pin grammar，不代表完整 F5/F6；内部版本、跨例 writer 消费及 ISR 设备 MMIO 仍为 unknown，`reward_eligible=False`。未增加策略奖励或把该诊断作为搜索实验。
