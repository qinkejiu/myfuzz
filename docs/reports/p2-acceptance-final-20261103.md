# P2 验收：单组件模式补全、剩余协议与行为（2026-11-03）

本文件汇总本轮七个并行增量与最终代表批次。每条结论都对应 `runs/` 下保存的 case
行与 `summary.json`；不把声明、单元测试或取指当作执行通过，不声称覆盖率、证书或
replay。逐项细节见各自的 `docs/reports/p2-*.md`。

## 0. 需求 → 落点

用户本轮两条要求被拆成七条工作流（拆分与区域边界见
[p2 工作规约](p2-workplan-20261103.md)）。

| 要求 | 工作流 | 报告 | 证据 |
|---|---|---|---|
| ② CPU-only 的 fuzz 只改固定程序的数据、依赖旧 artifact、协议范围窄 | A | [p2-cpu-only](p2-cpu-only-program-fuzz-20261103.md) | `runs/p2-cpu-only-20261103/` |
| ② IP-only 拒绝 `--fuzz`、只支持 APB3、逐例重启重放开销大 | B | [p2-ip-only](p2-ip-only-fuzz-and-protocols-20261103.md) | `runs/p2-ip-only-20261103/` |
| ③ AHB-Lite 目标没有统一适配器 | C | [p2-ahb](p2-ahb-lite-target-adapter-20261103.md) | `runs/p2-ahb-target-20261103/` |
| ③ IRQ：Wishbone/AXI4-Lite 的 F5、NMI、PLIC、多位 CPU IRQ、清除形态 | D | [p2-irq](p2-irq-round-two-20261103.md) | `runs/p2-irq-20261103/` |
| ③ 多 pin 组、串行 peer 只能声明不能执行 | E1 | [p2-pins](p2-pins-serial-execution-20261103.md) | `runs/p2-pins-serial-20261103/` |
| ③ DMA 多通道/宽 beat/多 outstanding 受限；同 RTL 换 profile 不算新器件 | E2 | [p2-dma](p2-dma-capabilities-new-device-20261103.md) | `runs/p2-dma-20261103/` |
| ③ 时钟只支持整数比、更快模型与非整数比被拒、异步未验证 | F | [p2-timing](p2-timing-ratios-async-20261103.md) | `runs/p2-timing-20261103/` |

## 1. 真正新增的能力（都有真实 RTL 批次）

* **CPU-only 的程序 fuzz**：`--fuzz-mode program`（默认）每例生成并真实执行一条不同
  RV32 程序，复用仓库既有 F1 生成器/门禁/参考模型；`program-ibex` 的实机退休数与
  参考逐例相等（2/8/1/6/1/8/4/1），`program-picorv32-wb` 同样有真实退休与 trace 对比；
  `picorv32_axi`、`cv32e40p` 无 RVFI 面，如实 `retires/trap=unknown`，靠完成字与数据
  窗口判据而不是把总线成功当退休。`--fuzz-mode data` 保留 P0 的数据形状，case 行逐字不变。
  artifact 由 profile 现场解析并按 `artifact_digest` 命中/构建，summary 如实写
  `cache_hit`/`compiled_this_invocation`。
* **IP-only 的闭环与长驻**：`--fuzz` 在同一长驻会话里逐例 `NEED_RECORD` 交接，
  **下一轮变异种子取自设备回读值**（APB3 64 例、TL-UL 48 例）；单 IP 模式扩到四种
  协议（apb3 26/26、tl-ul 15/15、wishbone 9/9、axi4-lite 9/9）；默认 `long-running`，
  同 26 例实测 **1 进程 125 ticks 0.00424 s vs 26 进程 1718 ticks 0.10871 s**
  （351 次事务里 325 次是重放），`--case-isolation prefix-replay` 显式保留。
* **AHB-Lite 目标**：第五种目标协议，由 profile 的 `mmio_slave` 端点派生模板与桥，
  宿主按十个真实从端口角色采 address/data 两相；Caliptra `sha256_ctrl` 已知答案
  67/67（`abc`/`abd` 摘要与 `hashlib` 逐字节一致、STATUS READY→VALID、BLOCK 写后读 0）；
  APB3+AHB-Lite+TL-UL 混合 9/9。
* **IRQ 两个清除形态真的执行**：TL-UL OpenTitan GPIO 的写 1 清除保持低
  （`irq_takes 1 clear_writes 1 last_clear_data 0x1 irq_level_final 0 level_stuck 0`，
  两例之后能再次取中断）；PULP GPIO 读清（`isr_read_clears 1 clear_writes 0`）。
* **引脚与串行真执行**：最多 4 个 pad 组按声明顺序执行（direction 真选线、`hold_ticks`
  真窗口、方向以设备 `PADDIR` 为可证伪见证）；`serial_peer` 按 8n1/8e1/8o1 真驱动与
  真采样，宿主打进整帧后设备 `FIFO_STATUS` 读回 RXLVL=1 且 `RDATA` 读回同一字节，
  设备发出的字节由宿主逐 bit 解码且 `tx_done` 真取中断。
* **真不同 DMA**：`wbdmac`（与 ZipDMA 不同的 RTL）在统一入口 F6 自主搬运 4 字与 8 字块
  （keyed start `0x0fed0004`/`0x0fed0008` → 真实 read/write beat → 器件完成脉冲 →
  CPU 读回目标块逐字正确）；`inprocess_generality_wbdmac` 与 `zipcpu_wbdmac` 经核对是
  同一 RTL 的不同 profile，**没有**被当作新器件（测试钉住）。
* **时钟有理网格与子步进**：一格 = `1/(2·lcm(声明频率))` s；50+30 MHz 实测 131/218 沿
  = 30/50，50+30+60 MHz 实测 262/218 = 60/50；比 CPU 更快的模型在同一 tick 内多次推进
  （`static_assert` 钉死「一 tick = 一个 CPU 周期」）。

## 2. 有意保持的拒绝（每条给到 RTL 行或端口事实）

| 项 | 精确拒绝 / 依据 |
|---|---|
| Wishbone / AXI4-Lite 目标的 F5 | 卡在比协议门更早的设备层：`a level IRQ source needs a declared clear write or a read-clearing status word`；该协议下带 IRQ 的寄存器目标只有 wbuart 家族，四个中断都是组合 FIFO 电平，`zipcpu_timer` 无地址端口 |
| NMI | 卡在 profile 的端口处置层（`structural.sv:175-176` 把 `irq_nm_i` 接 0），不是 RTL 也不缺 RVFI 面；CV32E20 在 `cv32e20_real_wrapper.sv:41` 直接 tie |
| PLIC | `rv_plic` 是 **TL-UL** 设备、claim/complete 本就是普通 MMIO，所以不缺 CPU 端口；缺的是组合 profile、184 位 `intr_src_i` 扇入、`irq_id_o`/`msip_o`/alert 属主 |
| CVA6 `irq_i[1]` | 按位归因但未取：`cpu_vector_partial:cva6:irq_i[1]=constant-0-not-taken`；架构原因是 S 态外部中断在 M 态被屏蔽（`csr_regfile.sv:2661,2724-2729`），要真取需 S 态引导与 `scause` 见证 |
| >2 步清除写 | `unsupported: this host performs at most 2 declared clear writes` |
| AHB-Lite 的 F5 | `unsupported-f5:target-irq-semantics:ahb-lite:...`（该器件 profile 明确无 IRQ 契约，未伪造触发序列） |
| DMA 路由到 AHB-Lite | `unsupported-dma-declaration:dma-route-target-protocol-unsupported:ahb-lite`（准入名单未含；C 已给出两行接通建议，本轮未越界） |
| DMA 多通道 / 8 字节 beat / 多 outstanding | `dma-capability-beyond-device:{channels:2>1, beat_bytes:8>4, max_outstanding:2>1}`；深度 2 有**实测失败**（4 字块读成 7 beat、只写 2 不成），RTL 依据 `wbdmac.v:472-491` |
| 异步时钟、不可采样的更快模型流量 | `unsupported: ... no common phase grid fits the 1024-step phase-grid bound ...`（32.768 kHz RTC 的精确网格 12.8 GHz / 390625 格）；更快模型的流量会落在两次采样之间（窗口 10 格 < tick 12 格），有真实超时存档 |
| 多停止位 / 半双工 / 两个 peer / 第二个 pad 字 | `unsupported-behavior-value:pin_groups.frame`、`...:serial_peer:half_duplex`、`...:serial_peer:count:2`、`unsupported-pins:pin_groups:second-pad-word` |
| IP-only 的 AHB-Lite 目标 | `unsupported-ip-only:protocol:ahb-lite`（接入点已由 B 指明，未越界） |

## 3. 最终代表批次（`runs/final-verify-p2/`）

七个增量各自的复现脚本在**同一棵整合树**上按序重跑，**7/7 exit 0**，合计 707 s：

| 增量 | 脚本 | 用时 |
|---|---|---|
| A CPU-only | `bash runs/p2-cpu-only-20261103/run.sh` | 22 s |
| B IP-only | `sh runs/p2-ip-only-20261103/run.sh` | 91 s |
| C AHB-Lite | `bash runs/p2-ahb-target-20261103/run.sh` | 75 s |
| D IRQ | `sh runs/p2-irq-20261103/run.sh` | 87 s |
| E1 pins/serial | `bash runs/p2-pins-serial-20261103/run.sh` | 119 s |
| E2 DMA | `bash runs/p2-dma-20261103/run.sh all` | 210 s |
| F 时序 | `bash runs/p2-timing-20261103/run.sh` | 103 s |

各脚本内部按自己的期望判定具名拒绝（`expect` 状态），所以「exit 0」表示该增量的
真实批次与拒绝实录都符合预期，不是「全部通过」。完整输出见
`runs/final-verify-p2/campaign.log`。

## 4. 测试与回归

* 整合后综合套件 **1950 passed / 0 failed**（`tests/fuzz`、composition 五组、entry、
  混合/目标协议、ip-only、cpu-only、IRQ 声明、DMA 路由、时序能力、P1 替换、七个 P2
  测试文件、CVA6 RVFI 两组、文档链接）。
* 增量间回归：APB3/AXI4-Lite/Wishbone/TL-UL 的既有 case 行、P0 的 ip-only 四形态、
  p1 的 IRQ/时序 case 行、ZipDMA 的 47 条 F6 行，除 `seconds` 外逐字节不变
  （各增量自己的 `p1-diff.txt` / 基线对比脚本）。

## 5. 整合期修掉的三处（并行编辑的遗留）

并行改同一棵树必然留下交叉残留，整合时逐条修好，都不是新功能的语义变化：

1. `tests/fuzz/test_new_ip_2_onboarding.py` 的「AHB-Lite 目标必须被拒」tripwire：
   C 落地适配器后该断言过期，改为只保留地址无关 Wishbone 目标这一条真正阻塞项。
2. `tests/integration/test_inprocess_mixed_targets.py` 用 `ahb-lite` 当「集合外协议」，
   C 把它纳入集合后失效；改为把五协议集合显式断言，并用真正不存在的 `ahb5` 触发拒绝。
3. `tests/integration/test_inprocess_ip_only.py` 的 `fake_args` 缺 `args.fuzz_mode`
   （A 给入口加了 `--fuzz-mode`），补上并新增一条 `data` 模式的映射断言。

## 6. 被本轮取代的旧表述（已就地更正）

* `docs/reports/p1-behavior-expressiveness-replacements-20261102.md`：多 pin 组与
  serial peer「按名拒绝」的两处表述已加更正行，指向 p2 引脚/串行报告。
* `configs/behaviors/declaration-only/{opentitan_uart_serial_peer_f5,two_pad_groups_f5}.json`
  的 description 已注明「声明样本保留，宿主自 2026-11-03 起可执行」。
* `runs/p1-timing/run.sh` 里两个时钟拒绝 fixture（nondivisor、faster-model）现在是
  **UNEXPECTED PASS**：F 的有理网格与子步进把这两条能力变成了现实。p1 的证据按当时
  状态保留不改，重跑 p1 脚本时这两行应按「已被取代」阅读；F 的对照表见
  [p2-timing](p2-timing-ratios-async-20261103.md) §6。

## 7. 仍未验证（不主张）

* wbdmac 的 busy 位从未观测到拉高、native error 未注入、halt/abort 控制字未真实执行；
* SPI/I2C 的串行 peer 模型、坏帧触发的 `rx_*_err` 中断源；
* `rv_plic` 组合成真实 IP 未做（只列名了缺口）；
* AHB-Lite 目标的 F6 路由与 F5 声明、IP-only 的 AHB-Lite 目标：接入点已给出，未实现；
* 更快模型的总线流量（需要把四个协议的 trace 采样挪进子步循环）。
