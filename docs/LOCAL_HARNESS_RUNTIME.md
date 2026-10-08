# 生成式独立 Harness 的实际运行边界

本页逐组件/组合列出已记录的实际运行能力、命令与限制。统一阶段状态、正在运行的门禁及最新证据入口见 [当前进度](CURRENT_PROGRESS.md)；下一步验收顺序见 [实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)，模块入口见 [代码组织](CODE_ORGANIZATION.md)。

P1 已完成，P2/P3 部分完成，P4～P8 未验收。下表和报告按保存时源码身份解释。v2 CPU POST、RDATA→retired LW 与受控 entry 的2048冻结源门禁得到4／4／4证明、0 barrier和48,315事件完整 fresh 一致；后续 Runner 已变，不表示当前源码重验。最新状态见当前进度页。

本系统保持每个真实 CPU/IP RTL 在自己的本地 harness 中运行。测试系统只在事务、事件和数据流层转交真实输出；不生成总线矩阵、桥、仲裁器或一颗具体 SoC，也不推断 DUT 应该给出的结果。

## 当前可运行路径

| 组件/协议 | 当前证据 | 等级 |
|---|---|---|
| CV32E20/CVE2，OBI 指令与数据端口 | 固定源码、全顶层端口、生成式 wrapper/driver；真实取指、Store/Load、byte-enable、显式 reset 后 RAM 保持 | RTL operational |
| OpenHW CV32E40P，分离 OBI 指令与数据端口 | 固定官方 gitlink；复用 `obi_cpu` 生成模板与 `GeneratedCve2Session`；真实 Fetch、Store/Load、LBU/SB byte lane、连续 testcase 内 RAM 状态与 fresh evidence replay | 独立 CPU＋RAM 的 local RTL acceptance；未接外设，不代表 CPU→IP SoC 数据闭环 |
| RVX `rvx_core`，单 outstanding completion-memory pins | 固定 standalone `rvx_core` 源码；生成 runtime/session 只把真实内存请求交给 `PersistentMemory`；128 个 CPU-local tick 内完成 SW/SB/LW/SW 与持久 RAM 状态，lane-1 byte-enable 和 fresh process replay 一致 | 定向 standalone CPU＋RAM RTL acceptance；source-lock `elaboration_status=elaboration_unverified`、`runtime_status=runtime_unverified`；未接 IP、IRQ 或 RVX bus |
| Ibex，OBI 指令与数据端口 | 66/66 顶层端口、70 个实际读取文件固定；复用 OBI 生成器与 session，真实取指、Store/Load、byte-enable、预算化证据 fresh replay | 第二种 OBI CPU RTL operational |
| CV32E20/CVE2 RV32E 参数变体，OBI | 仅增加 profile、源码锁和闭包；复用同一 OBI 模板/driver/session，真实 Store/Load、byte-enable 与 fresh replay | 同 CPU 参数复用通过；不代表新 CPU 型号仅靠 profile 接入 |
| PicoRV32，原生 Ready/Valid 完成式内存端口 | 固定源码、生成式本地 adapter/driver；真实程序连续两轮 Store/Load、持久 RAM、预算化证据与 fresh replay | RAM/ROM RTL operational；暂不支持 MMIO/IRQ |
| PicoRV32，classic Wishbone | 固定源码、生成式 driver；真实取指、RAM 写入、deferred MMIO 与显式 reset，预算化证据在新进程重放一致 | RTL operational；单 outstanding，无 IRQ |
| PicoRV32，classic Wishbone，`ENABLE_IRQ=1` | 独立参数 profile 与源码闭包；真实 ZipCPU timer IRQ 绑定 IRQ3，Pico custom0 handler 写 RAM，观察真实 EOI 拉高/返回后归零、trap=0 和主程序恢复执行，fresh replay 一致 | 自定义 IRQ ABI 的单 IRQ 闭环通过；旧 IRQ=0 profile 保持原样；标准 machine-mode ABI 与嵌套中断未验收 |
| PicoRV32，AXI4-Lite | 固定源码、真实 AW/W/B/AR/R 引脚经本地 adapter；真实程序两轮 Store/Load、持久 RAM、预算化证据 fresh replay | RAM/ROM RTL operational；固定 no-response-code 变体，无 MMIO/IRQ |
| ZipCPU，完整 AXI4 双主端口 | 15 文件固定源码闭包；真实五通道握手、八拍取指突发、两次 RAM 写入、预算化证据 fresh replay | RAM RTL operational；不接受 exclusive 与非 RAM 地址 |
| CVA6，打包 64 位/ID4 AXI4 单主端口 | 固定源码与 232 文件读取闭包通过 elaboration 和源码锁校验；生成式 driver 完成真实 RAM 取指、Store→Load→Store；DataflowRouter 路由至真实 OpenTitan GPIO TL-UL 与 PULP I2C APB3；OpenTitan RV Timer 原生 IRQ 绑定 `time_irq_i` 并执行 M_TIMER ISR；OpenTitan GPIO 与 PULP I2C 原生 IRQ 绑定 `irq_external` 并执行 M_EXT ISR，均 fresh replay | RAM 与单拍、32 位、地址对齐的 MMIO operational；当前场景已验收 M_TIMER 与 GPIO/PULP I2C M_EXT 中断链，其中 PULP I2C 为地址 `0x42` 单字节双次中断；突发 MMIO、PLIC/完整 SoC、通用 packed AXI4 CPU 复用未验收 |
| PULP GPIO，APB3 | 固定源码、全顶层端口、生成式 wrapper/driver；持续 APB 寄存器事务、双实例状态隔离、真实边沿脉冲逐本地 tick 记录 | RTL operational |
| PULP SPI master，APB3＋模式 0 外部串行 peer | 两份固定源码记录共同认证；真实 APB 配置、32 个选中 SCK 上升沿、EOT、RXFIFO `0xA5C396F0`、fresh replay | CLKDIV=1 单次 TX/RX RTL operational；其余模式见限制 |
| PULP Timer，APB3 | 固定源码、完整顶层端口、声明式 timer 执行器变体；真实双计数器、比较 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；CPU IRQ 未绑定 |
| ZipCPU ziptimer，Wishbone target | 固定源码、12/12 顶层端口、无地址单寄存器变体；真实注册 ACK、读写、单周期 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；不支持部分写 |
| ZipCPU axiluart，AXI4-Lite target | 固定五文件源码闭包和 29/29 顶层端口；真实 AW/W/B、AR/R 握手，TX pin 解码 `0x41`，串行 RX 返回 `0x5a`，预算化 fresh replay | UART RTL operational；固定 8N1/波特配置 |
| ZipCPU wbuart，Wishbone target | 固定四文件源码闭包和 19/19 顶层端口；2 位 word 地址、byte select、注册 ACK；真实 TX `0x41`、两种 RX 源值及原生 IRQ 均可 fresh replay | UART RTL operational；固定 8N1、单字节，CPU 数据链已验收 |
| PULP I2C master，APB3＋开漏串行 peer | 固定四文件源码闭包和 17/17 顶层端口；testcase 选择 8 位 peer 字节，真实 APB 配置、从设备 ACK、串行读取和原生 IRQ，预算化 fresh replay | I2C RTL operational；固定地址 `0x42` 的单从设备单字节模式 |
| OpenTitan GPIO，TL-UL | 固定上游源码与完整本地 wrapper 边界；真实寄存器读写、pin 输出、边沿 IRQ、合法及非法部分写响应、预算化证据 fresh replay | GPIO RTL operational；RACL 默认关闭，alert ack peer 未接入 |
| OpenTitan RV Timer，TL-UL | 固定上游源码、25/25 物理端口与本地标量 wrapper；真实计数、比较 IRQ、停止后的 INTR_STATE W1C 与 fresh replay | Timer RTL operational；该 standalone 行不包含 CPU；Ibex 与 CVA6 的独立集成分别验收了 IRQ/ISR 闭环 |
| OpenTitan sysrst_ctrl，TL-UL，24 MHz/200 kHz | 固定上游闭包与全顶层端口；两域各自复位和时钟；通过真实 CSR 配置 key0 H2L，PIN_IN_VALUE 观察到 high `0xc2`→low `0xc0`，真实 KEY_INTR_STATUS=`2`、INTR_STATE=`1`、native IRQ 上升；完整 ScenarioTrace fresh replay 一致 | 一个 key0 H2L 场景 RTL operational；无 reset/wakeup 回接、无 PLIC/完整 SoC |
| OpenTitan SPI Host，TL-UL | 固定上游源码、29/29 物理端口；受限 4 字节 mode-0 环境源经真实 32 个采样边沿进入 RXDATA，两种 Genome 源值及 fresh replay 一致；CV32E40P MEI 绑定 Host 原生 IRQ，真实 ISR 读取 RXDATA 并记录 `mcause`/RAM，fresh replay 一致 | SPI Host RTL operational；当前 CV32E40P 固定配置下的 IRQ/ISR 场景通过，不代表其他 CPU 或 SPI 模式 |
| OpenTitan pattgen，TL-UL | 独立固定 profile 与认证闭包；通用 TL-UL session 配置两个真实图样，检查 LSB-first 输出、不同分频周期、双完成 IRQ、闲置电平及 fresh replay | 双通道短图样 RTL operational；alert handshaking 与 CPU/外设路由未验收 |
| Ibex → OpenTitan pattgen → Ibex RAM | CPU OBI 真事务经抽象 MMIO Router 配置两个 pattgen 通道；两种程序图样产生不同的真实串行输出，CPU 轮询真实双完成状态并写持久 RAM；fresh replay 使用新 harness 重现 | 两通道输出与 CPU 状态读回闭环通过；未验收 CPU IRQ handler |
| OpenTitan I2C，TL-UL | 固定上游源码、33/33 物理端口；真实开漏 ACK/单字节读、RDATA、原生 IRQ 和 fresh replay；CV32E40P 与 Ibex 的 command-complete MEI ISR 分别在独立场景验收 | I2C RTL operational；当前 peer 是地址 `0x50` 的单字节、无 clock stretching |
| OpenTitan UART，TL-UL | 固定上游源码、37/37 物理端口；真实 TX `0x41`、RX `0x5A/0xA6`、原生 IRQ 与 fresh replay | UART RTL operational；CVE2 数据链、Ibex 与 CV32E40P RX watermark IRQ/ISR 链均已验收 |
| OpenTitan SPI Device，TL-UL | 固定上游源码、35/35 物理端口；专用 session 验收 mode-0 单线 JEDEC 应答、CSR 改写、上传 IRQ/FIFO/SRAM 与 fresh replay；CV32E40P 真实 MEI ISR 读取上传 FIFO/SRAM、W1C 清除及 fresh replay；通用 v2 模板另验收静态引脚下寄存器事务 | 串行行为只覆盖当前单线场景；ISR 仅在固定 CV32E40P/SPI Device 组合及当前上传路径验收 |
| CVE2 ↔ GPIO A ↔ GPIO B | 同一 testcase 两个方向各两轮，4 次真实 GPIO IRQ 和 CPU ISR，RAM 历史为 6、8、11、15；有预算证据包从初态重放一致 | 双向多组件链通过 |
| Ibex ↔ PULP GPIO A ↔ PULP GPIO B | 三个生成式独立 harness；CPU 程序变异经 A 真实输出绑定 B 输入、B 真实 IRQ 回 Ibex ISR 和持久 RAM；反方向 B 外部 pin `0x49/0x81/0xff` 经真实 IRQ 使 Ibex MMIO 写 A；另有一个连续 testcase 内三轮 `0x49→0x81→0xff`，RAM 写历史、状态依赖 WAW 和 fresh replay 均一致。两方向 checker 通过。CPU 上游单源 600 秒运行 420/420 完整链，128/128 合法奇数字节，26/26 抽样重放一致。新冻结在线 25 例另有 5 条 pin8→GPIO B native trigger→CPU IRQ 接受精确身份与完整 replay；600 秒在线计时运行 6,276/6,276 complete，见[P2 身份门禁](reports/current-dataflow-p2-pin8-cpu-irq-identity-20261007.md)、[原生 CPU 采样回执](reports/current-dataflow-p2-native-irq-sampled-receipt-20261007.md)与[P5 计时门禁](reports/current-dataflow-p5-streamed-600s-timing-20261007.md) | 双方向定向闭环；新在线身份只到 CPU IRQ 接受。带全部现有探针的 31.273544 秒有界运行（24/24 complete）测得 8 条认证链＝0.255807 链/s 与完整 fresh replay（[首步验收门禁](reports/current-dataflow-p5-chain-acceptance-20261007.md)）；十分钟口径 600.362953 秒、368/368 例、570,196 事件测得 **27 条认证链＝0.044973 链/s**（跨例 6）与完整 fresh replay，同 trace 另复算 **68 条** IRQ serial 精确证书（[十分钟门禁](reports/current-dataflow-p5-chain-600s-20261007.md)、[serial token](reports/current-dataflow-p2-irq-serial-token-20261007.md)）；链证书已把 serial 接入 IP 方向第 18 跳。同预算配对对照证明连续会话墙钟约为逐例冷启动的 1/16 且逐例有效性/断言不退化（[配对对照](reports/current-dataflow-p5-paired-continuous-cold-start-20261007.md)）；受控故障在真实 RTL 被捕获并新进程复现（[故障校准](reports/current-dataflow-p5-controlled-fault-real-20261007.md)）；真实运行另产出 7 类结构化拒绝＋1 类不确定（[拒绝校准](reports/current-dataflow-p4-rejection-calibration-real-20261007.md)）。链终点不含 ISR 写 GPIO A 后的回流；完整链率、同条件 JSONL/故障质量对照与通用逐边来源仍未验收；未发现自然 RTL 缺陷 |
| Ibex＋双 PULP GPIO 在线路径选择 | 冻结源码的 1,000 例真实在线搜索按全 raw 熵与反馈权重选路径，F4/F5 为 491/509，单独实际消费 CPU/GPIO 源分别为 462/494 例，379,209 事件完整 fresh replay；见[路径熵门禁](reports/current-dataflow-p4-path-entropy-real-gate-20261007.md)及[同例数对照](reports/current-dataflow-p4-path-selector-paired-1000-20261007.md) | 证明本次短跑双侧可达；同例数旧算法对照显示目标位与新特征未增长；仍缺完整链率和任意路径的通用验收 |
| CV32E20/CVE2 RV32E → PULP GPIO A → B → RV32E | 生成式 OBI 参数变体真实写 A、A 输出绑定 B、B IRQ 进入 CPU ISR；程序值 `0x49/0xff` 均到持久 RAM 且 fresh replay 一致 | 同核 RV32E 参数变体验收，不等于新增 CPU 架构 |
| PicoRV32 Wishbone → PULP GPIO A → B → PicoRV32 RAM | CPU 真实 Wishbone MMIO 写 A、APB3 A 真实输出绑定 B、CPU 读 B.PADIN 和 A.PADOUT 后写持久 RAM；`0x49/0xff` 变异、Bound Input 拒绝随机覆盖与 fresh replay 通过 | 跨 Wishbone/APB3 数据闭环；此 Pico profile 的 IRQ 关闭 |
| PicoRV32 Wishbone ↔ OpenTitan GPIO TL-UL | 唯一外部源 `gpio_in[7:0]` 经依赖图变异 `0x01→0x81`；真实 GPIO pin0 上升沿和 sticky IRQ 绑定 CPU `irq[3]`；custom0 ISR 读状态/数据、保存 q1=`8` 到 RAM、W1C 清 IRQ、`retirq` 后 main 标记可见；两种 payload 均 fresh evidence replay 一致 | 独立 generated harness，IRQ-enabled profile；一次性 ISR 在 W1C 后 `maskirq -1`，抑制默认 LATCHED_IRQ 的遗留 pending；无 PLIC/SoC/全局时序，未发现缺陷。详见 [验收报告](reports/generated-picorv32-wishbone-opentitan-gpio-irq-20261005.md) |
| PicoRV32 Wishbone ↔ ZipCPU wbuart RX IRQ | 唯一外部源 `uart_rx_byte[7:0]` 经依赖图变异 `0x35→0xa6`；CPU 真实 SETUP 先于完整 8N1 RX pin receipts，RX FIFO 非空 level IRQ 绑定 `irq[3]`；custom0 ISR 真实读 RXREG、保存 byte/q1=`8` 到 RAM，FIFO pop 后真实 IRQ 撤销，`retirq` 后主线标记及两份 fresh replay 一致 | 独立 generated harness；固定 25 tick/bit，并增加一个固定 idle cell 满足 SETUP 后 RX 同步；仅 RX 单字节，不含 TX/PLIC/SoC/全局时序。详见 [验收报告](reports/generated-picorv32-wishbone-zipcpu-uart-rx-irq-20261005.md) |
| Ibex → PULP SPI → Ibex RAM | 生成式 Ibex OBI 真 MMIO 配置 APB3 SPI；mode-0 peer 两种外部源使 SPI 真实 RXFIFO 与 CPU RAM 随之变化；独立因果 checker、fresh replay 通过 | RX 数据闭环；SPI `events_o` 仅观察，未验收 CPU ISR |
| Ibex ↔ OpenTitan RV Timer | 生成式 Ibex OBI 与生成式 TL-UL Timer 独立 harness；真实两轮 Timer IRQ→Ibex ISR→Timer 状态/计数读回→RAM；独立 checker 与 fresh replay 通过 | 两轮中断闭环；仅当前固定 Timer 配置和程序 |
| Ibex ↔ OpenTitan sysrst_ctrl | 生成式 Ibex OBI 与独立双时钟 TL-UL sysrst_ctrl harness；外部 key0 高基线后延迟 360 个 sysrst 本地 tick 拉低，真实 native IRQ 绑定至 Ibex，ISR 从 RTL 读取 KEY_INTR_STATUS/PIN_IN_VALUE，写入 RAM `2/0xc0` 并真实 W1C 清状态；新会话 fresh replay 一致 | 一个 key0 H2L→IRQ→ISR→CSR/RAM 场景通过；不含 PLIC、总线拓扑或全局 SoC 时序 |
| Ibex ↔ OpenTitan UART | Genome RX byte 经真实 8N1 peer/UART RTL；真实 watermark 绑定外部 IRQ，固定 ISR 读状态/RDATA 到 RAM；历史显式 RVFI＋FIFO 冻结源另认证原 case 的 RX 留存→cause 版本→实际 binding/input→external taken，4 个实际证明和完整 fresh prefix 一致。当前代码时期的独立快照又以 4 例验证受限 UART RX→退休 Store→建模 host RAM 低字节→后续退休 Load 和完整 replay，见[短回归](reports/current-dataflow-p3-current-tree-readback-20261007.md) | 固定单字节／受控 ISR 子路径通过；不认证 generic ISR、RTL RAM、高 24 位或通用跨例动作；串行帧进行中的 TL-UL 访问仍受限；[原生 IRQ 来源报告](reports/current-dataflow-p2-uart-native-irq-20261006.md) |
| Ibex ↔ OpenTitan GPIO → Ibex RAM | 外部 `gpio_in[0]` 上升沿经 GPIO 真实 RTL 产生 IRQ 并绑定 Ibex；ISR 读取真实 `INTR_STATE`/`DATA_IN`，W1C 清除 IRQ，将两值存入持久 RAM；新 harness fresh replay 一致 | 单 pin 上升沿 IRQ/ISR 闭环通过；下降沿、多 pin 并发和其他 IRQ 模式未覆盖 |
| CV32E40P → OpenTitan GPIO A → GPIO B → CV32E40P RAM | 固定 OpenHW CV32E40P 与 OpenTitan GPIO RTL 各在独立 harness；CPU 真 MMIO 配置 A/B，A 的真实 `gpio_out[0]` 绑定 B 的 `gpio_in[0]`，B 的真实 level IRQ 绑定 CV32 `irq_i[11]`；CPU ISR 读真实 `INTR_STATE`/`DATA_IN`、写 RAM 并 W1C，fresh evidence replay 一致 | 仅此 CPU/IP 组合和一个 pin0 上升沿场景通过，不代表通用 TL-UL CPU 复用或所有 CPU。直连抽象不解析 pad/OE，因此固定并断言产生该 `gpio_out` 的真实 sample 同时有 `gpio_dir[0]=1`；不含 PLIC/SoC 拓扑 |
| CV32E40P ↔ OpenTitan UART RX watermark | Genome 外部 RX 字节经真实 UART RX peer/RTL；真实 `uart_rx_watermark` 绑定 CV32 `irq_i[11]`，CPU ISR 读取 `INTR_STATE`/`RDATA`、将状态写入持久 RAM；读出 FIFO 后 IRQ 由 UART RTL 撤销，fresh evidence replay 一致 | 固定单字节 8N1 场景；CV32 `mtvec` 向量基址按 RTL 的 256-byte 对齐要求放置；帧接收期间不执行 TL-UL 访问；不含 PLIC/SoC 拓扑或 coverage-guided bug search |
| CV32E40P ↔ OpenTitan RV Timer MTI | CPU 真实 OBI 程序配置 TL-UL Timer；Timer RTL 的比较 IRQ 绑定 `irq_i[7]`，CV32E40P 接受 machine-timer 中断并执行 ISR，读真实状态/count、记录 `mcause=0x80000007`、W1C 清除并写完成标记；fresh evidence replay 一致 | 独立 MTI profile；直接向量基址 `0x10100`；Timer 和 CPU 保持独立本地时序；不含 PLIC/SoC 拓扑或 coverage-guided bug search。详见 [验收报告](reports/generated-cv32e40p-opentitan-rv-timer-mti-20261005.md) |
| CV32E40P ↔ OpenTitan SPI Host MEI | CPU 真实 OBI 程序配置 TL-UL Host；Genome 的外部 32-bit 源经真实 mode-0 peer/RTL 采样进入 RXDATA，Host 原生 MEI 绑定 `irq_i[11]`，CV32E40P ISR 读取真实 RXDATA、记录 `mcause=0x8000000b` 和持久 RAM；两种源值及 fresh replay 一致 | 固定四字节传输和直接向量场景；CPU 与 Host 保留各自本地时序；不含 PLIC/SoC 拓扑或 coverage-guided bug search。详见 [验收报告](reports/generated-cv32e40p-opentitan-spi-host-irq-20261005.md) |
| CV32E40P ↔ OpenTitan SPI Device upload MEI | CPU 真实配置 TL-UL Device；Genome 外部帧经过真实 mode-0 上传路径写入 command/address FIFO 与 ingress SRAM，原生 `irq_o[1]` 绑定 CV32E40P `irq_i[11]`；ISR 读真实状态/FIFO/SRAM、记录 `mcause=0x8000000b` 并 W1C，两个 payload 变体均 fresh replay 一致 | 固定单帧单线上传和当前 CPU profile；不含 PLIC/SoC 拓扑或 coverage-guided bug search。详见 [验收报告](reports/generated-cv32e40p-opentitan-spi-device-irq-20261005.md) |
| CV32E40P ↔ OpenTitan I2C command-complete MEI | 外部 peer 字节 `0x5a/0x5b` 经真实 `sda_i` 位采样和 I2C RTL 后进入 RDATA；CPU FDATA 命令启动 START/read，原生 `irq_o[9]` 绑定 MEI `irq_i[11]`；WFI 等待后 ISR 读 INTR_STATE/RDATA、记录 `mcause=0x8000000b`、W1C 清状态并写 RAM；两种字节 fresh replay 一致 | 单字节地址 `0x50`、无 clock stretching；I2C/CPU 各自本地时序，不含 PLIC/SoC 拓扑或 coverage-guided bug search。详见 [验收报告](reports/generated-cv32e40p-opentitan-i2c-irq-20261005.md) |
| Ibex ↔ OpenTitan I2C command-complete MEI | 外部 peer 字节 `0x5a/0x5b` 经真实 `sda_i` 位采样和 I2C RTL 后进入 RDATA；Ibex 的 OBI 程序配置并启动传输，原生 `irq_o[9]` 绑定到 Ibex 外部 IRQ；vectored slot `0x1012c` 的 ISR 读取真实 INTR_STATE/RDATA 与 `mcause=0x8000000b`，W1C 清状态并写 RAM；两种字节均在新建 harness 上完整 replay 一致 | 第二种固定 OBI CPU 的复用实例；单字节地址 `0x50`、无 clock stretching，不含 PLIC/SoC 拓扑或 coverage-guided bug search。详见 [验收报告](reports/generated-ibex-opentitan-i2c-irq-20261005.md) |
| CVE2 → PULP SPI → CVE2 RAM | CPU 真实 APB 配置、SPI 外部源真实接收、CPU 读取 RXFIFO 并写入持久 RAM；改变串行源会改变 RAM 与 trace，预算化证据 fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → OpenTitan GPIO → CVE2 RAM | CPU 真实配置 TL-UL GPIO；外部 pin 在真实输出触发后变化，GPIO RTL 产生中断状态，CPU 真实回读并写 RAM；fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → PULP Timer → CVE2 RAM | CPU 真实配置 APB Timer、读取真实计数并写 RAM；Timer 原生 IRQ 脉冲单独观察，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → ZipCPU ziptimer → CVE2 RAM | CPU 真实 MMIO 写入 Wishbone Timer、回读真实计数并存入持久 RAM；原生 IRQ 脉冲逐 tick 观察，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → PULP I2C → CVE2 RAM | CPU 真实 APB 配置；两个 testcase 分别选择 peer 响应 `0x5A` 与 `0xA6`，I2C RTL 接收对应串行字节并产生原生 IRQ；IRQ 转交 CPU 输入，CPU 轮询状态、回读真值并写 RAM；两份预算证据 fresh replay 一致 | 源变异与数据闭环通过；CPU 中断处理程序未验收 |
| CVE2 ↔ ZipCPU axiluart ↔ CVE2 RAM | CPU 真实 AXI4-Lite 写入 `0x41` 后 peer 从 TX 引脚解码该字节；依赖图变异 RX 源 `0x35→0xA6`，UART RTL 接收后 CPU 真实读出并写 RAM；两份 fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → OpenTitan RV Timer → CVE2 RAM | CPU 真实配置 TL-UL Timer、读取真实中断状态和计数并写 RAM；预算化证据 fresh replay 一致 | 数据闭环通过；CPU IRQ 当前固定为 0 |
| CVE2 → OpenTitan I2C → CVE2 RAM | CPU 真实配置 I2C 时序和 FDATA；固定地址从设备经开漏引脚返回 `0x5A`，CPU 读真实 RDATA 后写持久 RAM，fresh replay 一致 | 数据闭环通过；该 CVE2 数据场景轮询 IRQ 状态，IRQ 输入固定为 0 |
| CVE2 → OpenTitan SPI Host → CVE2 RAM | CPU 真实 MMIO 配置 CONTROL/CONFIGOPTS/COMMAND；两种 4 字节外部源经 32 个真实 SCK 采样边沿改变 RXDATA，CPU 读回后写持久 RAM，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVA6 → OpenTitan SPI Host → CVA6 RAM | CVA6 真实 AXI4 配置 Host；Genome 源字节经 peer 按真实 mode-0 pad 边沿进入 RTL RXDATA；CVA6 读取 64 位 AXI 高 lane 并写入 RAM；fresh replay 一致 | 单四字节 mode-0、单拍 32 位 MMIO 通过；SPI Host 的 CPU IRQ/ISR 未验收；独立 RV Timer 的 M_TIMER ISR 已验收 |
| CVA6 ↔ OpenTitan GPIO M_EXT | 唯一外部源 `gpio_in[7:0]` 经 dependency path 从 `0x01` 变异到 `0x81`；CVA6 真实配置 GPIO 后才注入，GPIO IRQ 绑定 `irq_external`；ISR 保存真实 `mcause=0x800000000000000b`、GPIO 状态与数据，W1C 后 IRQ 拉低，MRET 后 RAM 标记可见；两种源均 fresh replay 一致 | 当前 profile 的 pin 0 上升沿 M_EXT ISR 场景通过；不含 PLIC/SoC 拓扑或全局时序。详见 [验收报告](reports/generated-cva6-opentitan-gpio-mext-irq-20261005.md) |
| CVA6 ↔ PULP I2C APB3 → CVA6 RAM，双 M_EXT | 唯一 peer 字节从 `0x5a` 变异到 `0xa6`，经真实 SDA/SCL 采样和 I2C RXDATA 进入 CVA6；CPU 固定发送地址命令，I2C 两次原生 IRQ 分别触发两次 M_EXT ISR，完成 ACK/NACK 状态、两次 IACK、MRET 和 RAM 标记；两个值均 fresh replay | 独立 generated harness 和本地时序；固定地址 `0x42`、单字节、两次完成 IRQ；无 PLIC/SoC 全局时序。详见 [验收报告](reports/generated-cva6-pulp-i2c-two-mext-irq-20261005.md) |
| CVA6 ↔ ZipCPU axiluart RX M_EXT | 唯一外部源 `uart_rx_byte[7:0]` 经依赖图从 `0x35` 变异到 `0xa6`；真实 8N1 RX pin 进入 ZipCPU RX FIFO，原生 `uart_rx_int` 绑定 CVA6 `irq_external`；CVA6 ISR 经真实 AXI4 MMIO 读 RXREG，保存 byte 与 `mcause=0x800000000000000b`，MRET 后 RAM marker 可见；两个值均 fresh replay 一致 | 独立 CPU/UART harness 与本地时钟；固定 25 tick/bit、额外 350 UART 本地 idle ticks；仅单字节 RX，不含 TX/PLIC/SoC 全局时序。详见 [验收报告](reports/generated-cva6-zipcpu-axiluart-rx-mext-irq-20261005.md) |
| CVE2 ↔ OpenTitan UART ↔ CVE2 RAM | CPU 真实 MMIO 写 CTRL/WDATA，UART TX 引脚解码 `0x41`；两种 Genome RX 字节经 UART 真实 RDATA 被 CPU 存入 RAM，fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 ↔ ZipCPU wbuart ↔ CVE2 RAM | CPU 真实 MMIO 写 SETUP/TXREG，UART TX 引脚解码 `0x41`；两种 Genome RX 字节经真实 RXREG 到 CPU RAM，原生 IRQ 电平交付 CPU 输入，fresh replay 一致 | 双向数据闭环通过；CPU 程序仍轮询，未验收 ISR |
| CVE2 → OpenTitan SPI Device → CVE2 RAM | CPU 真实 TL-UL MMIO 配置 CONTROL、上传命令和中断使能；两种 Genome 外部 master 帧经 mode-0 引脚进入真实上传路径；CPU 轮询真实 IRQ_STATE，读取 FIFO/地址/SRAM 并写持久 RAM，fresh replay 一致 | 数据闭环通过；CPU ISR 未验收，串行限当前单线上传帧 |

协议模板注册表列出 CPU OBI、AXI4、AXI4-Lite、Wishbone classic、Pico native Ready/Valid，以及 OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 和 AXI4-Lite 目标端变体。上表的五种 CPU 协议、PULP APB3 GPIO/SPI/Timer/I2C、OpenTitan TL-UL GPIO/RV Timer/SPI Host/I2C/UART/SPI Device、ZipCPU Wishbone Timer/UART 与 AXI4-Lite UART 实例有真实 RTL 运行证据。`local_harness.v2` 现有三个寄存器观察模板：TL-UL 的 GPIO/RV Timer/SPI Device，APB3 的 PULP GPIO/Timer，Wishbone 的 ZipCPU Timer/wbuart；每组真实交易和 fresh replay 都通过。同一个 TL-UL 模板还验收 GPIO 的动态环境引脚源，以及 GPIO A 真实输出绑定 GPIO B 输入并引出真实 IRQ；APB3 模板验收动态 GPIO 输入及双 GPIO 的真实输出→Bound Input→真实 IRQ 与 fresh replay。APB3 通用模板当前限定 12 位地址、4096 字节窗口和 32 位数据；Wishbone 通用模板要求目标有真实 `stall` 输出，且目前只接收声明式固定物理输入。不符合这些运行时形状的 profile 在规划阶段拒绝。v2 TL-UL 模板上另有 UART 8N1 peer 和 SPI mode-0 单线 master peer：UART 的 RX 帧来自声明式环境源、TX/IRQ 来自真实 RTL；SPI 的 SCK/CS/MOSI 由声明式外部帧驱动，MISO/IRQ/SRAM 由真实 RTL 给出。两者分别在 OpenTitan UART 单字节和 SPI Device 单帧场景通过 fresh replay；UART 和 SPI peer 的引脚、节拍、帧形态及启动写入已进入 v2 tuning 与 artifact 身份，通用 factory 可从 artifact 选择 session。专用 SPI Device session 仍保留其独立验收。

## 生成与启动

1. `local_harness.v1` 请求选择完整源 profile、独立实例 ID、reset/等待界限。
2. `plan_local_harness` 从固定 revision 的真实顶层得到逐位端口事实和唯一输入归属。缺口、重叠、未知信号、未验证源码都会拒绝。
3. `render_local_harness` 生成单 DUT 结构 wrapper；`render_local_runtime` 在 wrapper 外侧接对应的本地 OBI、原生完成式内存、Wishbone、AXI4-Lite、AXI4、APB3 或 TL-UL 执行器；`render_local_driver` 生成逐本地时钟采样的 C++ driver。
4. `build_local_harness` 重建并逐字节核对上述产物、源码闭包、头文件及构建身份，再执行有界 `verilator --cc --exe --build -j 1`。缓存键由实际构建输入决定。
5. 当前 `GeneratedLocalSession.prepare_local()` 在既有单场景 testcase 计时前构建；`begin_case()` 启动一个进程并核对 READY 的产物摘要和实测 reset tick；每个命令有执行 ID、单调序列及有界回复期限。一个现有 testcase 的多个命令共用该进程。这个 API 仍以整段场景为一例，结束时释放/重新初始化；目标长会话要求多个独立 testcase 共用一次启动，其 case 边界不能调用此结束流程，见[当前实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)。

对于 v2 寄存器观察 artifact，`create_generated_register_session` 依据 artifact 类型创建 TL-UL、APB3 或 Wishbone 本地 session，并可接收当前 testcase 的有界寄存器写入/观察动作；`compile_generated_register_ownership` 从其固定、环境源与绑定输入记录编译多个组件的逐位 OwnershipMap；`compile_generated_register_bindings` 将 Bound Input 声明解析为另一生成式 harness 的等宽真实物理输出。编译时拒绝重复字段、无身份的源和未生成的 artifact。Bound Input 后续由 ScenarioRunner 要求连接真实输出，无法改作随机源。串行 peer 使用抽象帧源，其输入归属仍按 peer 的场景合同提供；该通用编译入口目前只覆盖物理寄存器观察输入。

也可将 `local_harness.v1` 请求保存为 JSON，直接生成可审阅文件：

```bash
python3 scripts/generate_local_harness.py --request request.json --output /tmp/generated_component
```

输出包含结构 wrapper、运行时顶层、driver、ABI、源码验证回执和产物身份。重复生成同一请求得到相同字节；已有输出目录会被拒绝。可选 `--build-cache /tmp/myfuzz-build-cache` 会编译并返回二进制路径，但**编译成功只表示构建通过**；`RTL operational` 仍要求真实局部事务、状态和 replay 验收。

`GeneratedCve2Session` 只服务真实 OBI 握手接受的取指/数据请求。RAM 用 `PersistentMemory` 保存：写入后的读取得到先前真实写值，byte-enable 只覆盖对应字节；首次未初始化读取会物化并保留。MMIO 请求由 `DataflowRouter` 交给真实 GPIO session，目标读值再返回 CPU。`GeneratedPulpGpioSession` 只接受合法 GPIO 外部 pin 值与全字 APB3 写；已绑定的 pin、CPU IRQ 和 MMIO read data 由上游真实输出或持久状态决定，不能再次随机覆盖。

### 单组件多时钟运行

Profile 中每个 `ClockBinding`/`ResetBinding` 都映射到单 DUT runtime 上独立的时钟/复位信号。每次本地 `tick()` 只推进该 DUT 的最快时钟一个完整周期；它不与其他 harness 同步，也不代表全局 SoC cycle。所有逻辑时钟从低电平开始，最快域每个 local tick 都执行低→高→低，因此恰有一个上升沿。较慢时钟按固定频率比 `ratio` 在每 `ratio / 2` 个最快时钟周期翻转一次，首次上升沿位于第 `ratio / 2` 个周期；同一时刻发生的边沿在同一次 DUT 求值中观察。当前只接收正整数频率、可整除的偶数慢时钟比，最大 1024；不支持的比例在计划阶段拒绝。时钟比、初相位、复位映射和启动 tick 数进入 runtime artifact 身份。

复位由 driver 统一同时断言和释放，但每个物理端口仍按自己的 `active_high`/`active_low` 极性连接。断言与释放长度以最快域周期计数；每个时钟域必须在 READY 前收到至少一个复位采样上升沿。profile 声明了有序复位依赖时，当前 runtime 会拒绝运行，避免把顺序要求折叠成同时释放。artifact 的 `startup_fast_ticks` 包含复位周期和 READY 前固定的 driver 初始化周期；例如 OpenTitan SPI Device 的 mode-0 peer 启动会先执行 4 个本地周期。多时钟 RESULT 样本在原有 `local_tick`、`pre`、`post` 外增加 `clock_edges`，记录 READY 后每域累计上升沿数；host 根据 artifact 中固定的 schedule 核对每个样本。单时钟仍只输出原有三个 sample 字段和 `clk`/`reset` 控制名，保持旧 wire shape。

### 输入约束的判定

| 输入或状态 | 谁可以决定 | 强制约束 |
|---|---|---|
| CPU 程序、初始内存、未绑定的 GPIO 外部 pin | Fuzzer 选择上游 Fuzzable Source | 只在场景允许的初始或外部事件时改变，变异整段连续场景 |
| PULP SPI 的外部串行数据 | Fuzzer 选择 testcase 的 `SOURCE_SPI` 字节流 | peer 只按真实选中 SCK 边沿推进；同一事务中的回读来自 SPI RTL，不重新随机 |
| ZipCPU UART RX 与 PULP I2C peer 响应 | Fuzzer 选择声明为 source 的 testcase 字节；串行 peer 驱动 pad | UART 的 8 位 `uart_rx_byte` 在帧开始后锁定；I2C 固定从地址 `0x42`，8 位 `peer_response` 必须在 APB 事务前选定，同一 testcase 保持不变。SCL/SDA pad 每个本地周期由真实引脚与开漏电气规则决定，不能另加独立随机位 |
| CPU 产生的 OBI 地址、写值、byte enable | 真实 CPU RTL 输出 | Fuzzer 不能跳过 CPU 而直接随机这些事务 |
| GPIO APB3 配置与寄存器访问 | 已接受的 CPU MMIO 事务，经 Router 转交 | 不能用另一个随机配置值覆盖 CPU 的真实写入 |
| GPIO A 输出绑定到 GPIO B 输入的位 | GPIO A 真实 RTL 输出 | B 对应输入位属于 Bound Input；只有未绑定的其他位可作为环境源 |
| 通用 TL-UL `bound_bindings` 物理输入 | Router 观察的、声明为 `producer_ref` 的真实 RTL 输出 | 运行前核对完整字段宽度、来源身份和绑定；普通 source 命令不能覆盖。当前单场景 testcase 内保持到新的真实输出或显式 reset；目标多例长会话还须跨例保持 |
| CPU 读取 GPIO 的返回值、CPU 外部 IRQ | 真实 GPIO RTL 及 Router/IRQ 调度 | 不能随机改写真实返回值或由状态寄存器推测 IRQ |
| RAM 先前写入字节、首次读取后物化字节 | 持久 Memory Model | 后续读取复用，直到真实写操作覆盖；形成 persistent state dependency |

每个物理输入位在生成前必须有且只有一种归属：局部协议执行器、Fuzzable Source、真实上游绑定或有证据的常量。Dependency Scheduler 决定动作何时可发生；Dataflow Router 只传递真实值。检查属性独立记录异常输出，不因预期因果顺序而丢弃 DUT 的错误结果。

每个 driver RESULT 包含真实前后 tick、完整本地 pre/post 样本、原始物理端口及局部协议端口。调度器以样本中的 GPIO 原生 `interrupt` 脉冲建立后续 CPU 输入，包含 APB 访问期间发生的脉冲；不会从 INTSTATUS 或预期配置合成 IRQ。重复命令只取得历史回执，不再次推进 RTL；回复丢失后终止会话，归类为不确定效果，不重试真实事务。

### 当前路径契约接入的验证范围

新 Genome decoder v3、online decoder v2 保存有边身份的路径和 RuntimePathContract，启动前绑定实际 Runner 的 Binding、Router 和 RAM 声明。存在外部源的搜索会话须传可信 ownership，并在 begin/warmup 前核对 producer；接纳前检查轻量拓扑，replay 在启动前重新比对 graph/contract/path/compiled ownership。旧 decoder 保留旧映射并标记 unchecked，文档重建 decoder 只用于 replay。

历史路径契约冻结源的 Ibex＋双 PULP GPIO 长会话120例（CPU源16、IP源104）及 UART 2例双源入口（CPU/RX各1，另含固定warmup）均通过完整前缀fresh replay；UART短跑未观察IRQ taken，详见[P2阶段报告](reports/current-dataflow-p2-path-contract-20261006.md)。此证据证明固定组合的契约接入与身份校验；逐边原始source/case、资源版本仍未贯通，不提升通用协议接入等级，也不代替10分钟效率与受控错误门禁。

已记录的来源模式以SourceAdmission和plan10/11保存主源、fixed_support和bootstrap，区分observed_case与原始case。实际RAM读快照携带writer_kind/version，STORE/FIRST_READ/INITIAL_IMAGE不能凭同名字符串冒认指令来源。修复后GPIO120/UART2例及完整replay通过，见[来源验收记录](reports/current-dataflow-p2-source-provenance-20261006.md)。该来源登记报告尚未证明 MMIO/IRQ 的最初变异来源；后续受限 FIFO/native 来源范围见下文。物理边候选本身不提升因果闭环或协议能力等级。

真实退休与物理帧接入见[Task4.4报告](reports/current-dataflow-p2-retirement-frames-20261006.md)：显式 `--cpu-retirement` 使用认证RVFI新profile，原profile默认保留。受限指令字节到实际MMIO交易可形成见证，UART帧按真实引脚逐tick验证；该 Task4.4 报告的 scope 不证明操作数 taint、GPIO 寄存器→IRQ 或 UART FIFO 消费；后续显式消费变体按其独立门禁解释。完整P2与十分钟性能仍未验收；每次门禁按其保存源码身份解释。

GPIO 的逐边来源范围已在独立 `--gpio-consumption` 变体扩展到实际 APB 提交、寄存器版本、同步输入、原生触发及状态读取。上一轮冻结源码通过 5 项真实 RTL 与 16 例在线完整前缀 replay，见[GPIO 消费报告](reports/current-dataflow-p2-gpio-consumption-20261006.md)。历史 UART 波形报告仍不证明 FIFO 来源；新 `--uart-fifo` 变体已接入 154 个被动探针、真实帧凭据、有界 FIFO 模型与严格路由绑定，对应历史冻结源通过 2 项真实 RTL、738 项软件与 4 例 Ibex 在线完整 replay，见[UART FIFO 消费报告](reports/current-dataflow-p2-uart-fifo-consumption-20261006.md)。两者均不证明通用 CPU 操作数或 IRQ/ISR 来源。

### UART 原生 external taken 的显式来源模式

`cpu_retirement=True` 与 `uart_fifo=True` 同时启用时，factory 在认证 Ibex RVFI profile 上开启 `native_irq_receipts`；默认 CPU/UART 身份保留。实际完整 parsed receipt 的 PRE/POST `irq_external_i` 必须与提交命令一致，只有真实 PRE taken 才记录 external taken。POST RVFI 扩展通知独立于退休有效位，不能反推 IRQ cause 或 handler 来源。Runner 使用实际 step 前最后应用的 binding；join 经真实编译 RuntimeEdgeIndex 将逻辑 source 解析为 input owner，并核对原 case、retained entry、cause version、context 和 exact CPU sample/taken。

历史 native taken 冻结源真实 fixture 4 项及 7 个负例通过（123.22 秒）；48,378 事件及局部 tick 完整 fresh prefix 相同。实际证明有 20 个 cause 版本、4 external taken、4 retention／4 read，来源 1 bootstrap／3 fuzz_source。GC 保留所有 live queue/receiver/read/input/take 引用；真正未完成容量丢失形成 certainty barrier，初始 unknown 不升级也不 poison。Generic ISR/operand 为 unknown，reset-free gate 不认证实际 reset 波形。

Generic runtime manifest schema 已补 UART v2/v3/v4 与 FIFO/provenance、GPIO causal、CPU RVFI/native additive 字段的结构限制；它不替代 Python canonical 类型、source/build 身份认证。首次 owner/source alias failure 和 raw tuple/list fixture 中断均保留；最终测试逐项比较 strict canonical wire JSON，未改变生产源，也未虚构第二次 online run。该历史冻结源 source-focused 软件 166 项／56 子检查通过（150.20 秒）；旧 GPIO/UART/FIFO/P1 材料按保存时的源身份解释。详见 [本轮原生 IRQ 来源报告](reports/current-dataflow-p2-uart-native-irq-20261006.md)。能力查询仍是 documented evidence，`runtime_revalidated=false`，查表本身不执行 RTL。

新 v2 扩展为实际 `cpu_retire.v2` 绑定完整 POST RVFI、command scope、driver receipt 与 tick；独立 read linker 重构原始 UART/CPU 证据并按完整 key 关联对齐 LW。受控 entry 还要求可信 bootstrap image 安装、固定 CSR setup、真实 native take 与首次 `intr=1` 退休。2048冻结源码真实 fixture 5项／8子检查通过（228.19秒），taken／受控 entry／退休 read 各4，来源1 bootstrap／3 fuzz_source；incomplete／barrier为0，48,315事件及局部tick完整 fresh一致，见[受控入口与退休读取报告](reports/current-dataflow-p2-controlled-entry-read-20261006.md)。后续 Runner 已变化，新补强positive在身份校验处拒绝，不能称当前源码重验；历史native taken保持原scope。Generic ISR、地址/寄存器操作数与后续 store 来源仍为 unknown。

### 在线连续 Scenario Batch

`ScenarioBatchRecorder` 为**已经启动的同一组 harness**提供逐次输入入口。`ScenarioBatchPlan` 保存一个无预编码 Action、无 reset、无 quiesce 的 `ScenarioGenome` 模板，并按执行顺序记录 `BatchSourceEvent` 与 `BatchAdvance`：

```text
begin once
→ observe real CPU/IP output
→ submit one unbound Fuzzable Source
→ advance selected local harnesses
→ observe resulting real RTL output / IRQ / memory effect
→ submit next source event
→ finish once
```

`submit_source_event` 会按模板 direction 再次检查逐位 OwnershipMap，只接受 `source` 所有的输入。Bound Input 继续由 ScenarioRunner/Dataflow Router 从上游真实输出更新，无法被在线提交接口覆盖。`advance(schedule)` 精确执行该顺序中的本地 harness 步数并累计检查 `max_steps`；schedule 不是全局 SoC 时钟，也不要求不同 DUT 使用 cycle-accurate 相位。初始 MemoryImage 在首次 begin 前只加载一次；同一个 CPU/IP session、RAM、事务、Pending Event、IRQ pulse 与输入保持到 `finish()`。

每个在线 source segment 的宽度上限为 **65,536 bit（8 KiB）**。解码和 admission 在任何 mask/移位或 harness 执行之前拒绝超过该上限的宽度；payload 是否能放入字段用 `int.bit_length()` 判定，避免根据未信任的 width 构造巨型整数。

命令日志保存已通过静态 Ownership/宽度检查的输入尝试。若 Runner 在运行时因确定性的资源预算拒绝该尝试，trace 会记录 `budget_exhausted` 且不记录 `source_injection`；batch replay 会重放这条尝试并复现终止结果，避免移除失败输入后无法重现原 trace。

完成后 `recorder.plan` 才可读取。`ScenarioBatchCodec` 使用严格版本化 JSON 保存完整命令序列和每个调用边界；trace 的 `genome_sha256` 标识整个 batch plan，因此把同一串本地步骤拆成不同的在线调用也会有不同身份。`replay_scenario_batch` 创建新的一组 harness，先核对 runner manifest，再按原命令边界重放 source admission 与本地步骤，并比较完整事件、local ticks 和语义摘要。测试 ID 是模板提供的运行标签，结束后 trace 使用完整 plan 的 SHA-256 作为 testcase identity。

若 wall budget 在本地 STEP 或 finalize 清理命令进行中耗尽，trace 会保存该命令开始时剩余的 deadline，replay 会在对应本地命令上恢复同一时长并比较真实观察到的部分事件、tick 与清理错误。此类超时依赖本地命令实际再次超时；若重放时命令在 deadline 内完成，replay 会报告 trace 不匹配，不会合成原 RTL 输出或清理错误。`inflight_finalize` trace 必须包含不超过 testcase wall budget 的剩余清理时间；缺少该字段的旧 trace 会被拒绝，避免无期限清理或伪造 timeout marker。

此能力明确区别于现有预编码 Genome：`DependencyScheduler` 可在开始前知道完整 Action 列表；在线 batch 可以在 RTL 正在运行时根据已观测输出决定下一次输入，再把实际决定完整记录下来。当前整个 batch 是一个 testcase，在线 source 事件没有各自独立的 testcase ID、增量反馈或跨例证据边界。上述 legacy batch API 本身没有独立逐例反馈。标准 fresh decoder 分支仍逐 slot 新建 Runner；独立 online_decoder 分支已经在固定 Ibex＋PULP GPIO/UART 上通过 ScenarioSession 接入 RFuzz FIFO，多个 case 复用同一 Runner、RTL/RAM 状态和完整前缀 replay，范围见[GPIO 在线报告](reports/ibex-pulp-online-rfuzz-smoke-20261006.md)及[UART 在线报告](reports/ibex-opentitan-uart-online-rfuzz-20261006.md)。不能将固定 online 试点提升为所有 batch、CPU/IP 或通用动作契约均已验收。

## 运行验收

在仓库根目录运行：

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests/local_harness -p 'test_*.py' -q
PYTHONPATH=src:. python3 -m unittest discover -s tests/scenario -p 'test_*.py' -q
PYTHONPATH=src:. python3 -m unittest tests.scenario.test_stateful_batch -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_local_pulp_gpio_generated_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_irq_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real tests.integration.test_scenario_ibex_pulp_gpio_reverse_generated_real tests.integration.test_scenario_ibex_two_pulp_gpio_rfuzz_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_pulp_gpio_reverse_generated_real.ReverseGeneratedIbexPulpGpioTests.test_three_external_phases_share_one_rtl_lifetime_and_replay -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_opentitan_pattgen_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generated_opentitan_pattgen tests.local_harness.test_wishbone_cpu_irq -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_pulp_gpio_online_batch_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_rv32e_two_pulp_gpio_generated_real tests.integration.test_scenario_picorv32_wb_two_pulp_gpio_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_pulp_spi_generated_real tests.integration.test_scenario_ibex_opentitan_rv_timer_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_local_native_memory_generated_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_local_axi_lite_generated_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_local_pulp_spi_generated_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_gpio_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_sysrst_ctrl_generated_real tests.integration.test_scenario_ibex_opentitan_sysrst_ctrl_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_opentitan_uart_irq_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_pulp_spi_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_pulp_timer_generated_real tests.integration.test_scenario_cve2_pulp_timer_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_gpio_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_zip_timer_generated_real tests.integration.test_scenario_cve2_zip_timer_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_pulp_i2c_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_rv_timer_generated_real tests.integration.test_scenario_cve2_opentitan_rv_timer_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_zip_axil_uart_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_wishbone_uart_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_opentitan_spi_host_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_i2c_generated_real tests.integration.test_scenario_cve2_opentitan_i2c_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_uart_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_uart_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_tlul_register_real tests.local_harness.test_generic_tlul_dynamic_source_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_tlul_bound_input_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_apb3_register_real tests.local_harness.test_generic_wishbone_register_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_tlul_uart_peer_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_generic_tlul_spi_mode0_peer_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_spi_device_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_spi_device_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_zip_wb_uart_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_spi_host_generated_real -v
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_axil_uart_runtime -v
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_wishbone_cpu -q
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_axi4_cpu -q
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_ibex_obi_runtime -q
```

2026-10-04 至 2026-10-05 回归结果：合入通用 UART/SPI peer 后的本地 harness 全量 236 项运行、17 项按真实 RTL 环境门禁跳过、零失败；场景回归 367/367。此全量结果早于 UART tuning factory 与 CVA6 结构顶层两次提交；之后 UART tuning 真实焦点用例 6/6、CVA6 源码锁和顶层 lint 用例 4/4 均通过。CVA6 真实 packed AXI4 RAM Store→Load→Store、单拍 MMIO→真实 OpenTitan GPIO→CPU 读回/RAM 与 fresh replay 均通过；本次路由相关协议/continuity/Router 回归 19/19 通过，CVA6 RAM 回归 2/2 通过。CVE2 RV32E 参数变体定向真实测试 1/1，通过 fresh replay；SPI Device 专用真实用例 3/3、CPU→SPI Device→CPU RAM 真实链 1/1、通用 TL-UL 固定/动态/Bound Input 的真实及合同用例 12/12、通用 SPI peer JEDEC/上传 3/3、CVE2↔ZipCPU wbuart 真实链 1/1、通用 APB3＋Wishbone 寄存器模板在合同修正后联合真实及负例用例 8/8 在主线通过；各自能力边界见 `docs/reports/` 下的对应报告。Pico 原生内存真实测试 2/2、AXI4-Lite 真实测试 2/2、Wishbone 专项 6/6、ZipCPU AXI4 突发及 schema 2/2、PULP SPI 预算化证据测试均通过。CVE2 双 GPIO 双向真实场景此前 2/2，预算化证据 fresh replay 一致。若本地缺少某 CPU 的可执行固定源码，只跳过该 CPU 的真实验收并记录 `skipped_unavailable`，不让其他 CPU/IP 或协议等级自动通过。

## 尚未满足的验收

F6 DMA 数据流尚未实现：当前没有真实 DMA master harness、DMA 独立读写事务路由，或 CPU 配置→DMA→RAM/IP→IRQ→CPU 的 fresh replay 闭环。DMA 能力归当前总计划 P8，不计入已验收组件和组合。

五类初始 CPU 协议已有至少一个固定 RTL 实例的生成式运行证据；Ibex 与 CVE2 是两种真实 OBI CPU，证明该特定 OBI 形态可复用同一生成器。CVA6 与 ZipCPU 有各自 packed AXI4 RTL 运行实例；CVA6 专用 AXI4 session 已通过 RAM、受限 OpenTitan GPIO/SPI Host MMIO、独立 RV Timer native M_TIMER ISR 与 fresh replay，但不能据此声称 profile-only 复用到其他 AXI4 CPU。双向 CPU/GPIO 首阶段具备连续状态、IRQ、预算化证据和 replay；CPU→PULP SPI→CPU RAM、CPU→OpenTitan GPIO→CPU RAM、CPU→OpenTitan RV Timer→CPU RAM、CPU→OpenTitan I2C→CPU RAM、CPU→OpenTitan SPI Host→CPU RAM、CPU→OpenTitan SPI Device→CPU RAM、CPU→ZipCPU AXI4-Lite UART→CPU RAM、CPU→PULP Timer→CPU RAM、CPU→ZipCPU Timer→CPU RAM 与 CPU→PULP I2C→CPU RAM 数据闭环，以及 CVE2↔OpenTitan UART/ZipCPU wbuart↔CPU RAM 双向数据链已通过。OpenTitan I2C 原生 command-complete IRQ 已分别绑定 CV32E40P 与 Ibex 的 MEI 输入并由各自真实 ISR 清除；既有 CVE2 数据链仍以轮询状态完成，CPU IRQ 固定为 0。OpenTitan GPIO、RV Timer、SPI Host、I2C、UART 与 SPI Device 已有生成式 TL-UL 真实运行与 replay；SPI Device 已验收当前单线 mode-0 串行及 CVE2 轮询数据链，并新增固定 CV32E40P profile 的上传 IRQ/ISR 闭环；其他 CPU 组合与更多串行模式尚未验收。既有 CVE2→OpenTitan I2C→CVE2 数据场景轮询中断状态且 CPU IRQ 固定为 0；CV32E40P 与 Ibex 的 MEI ISR 场景分别通过。Pico 原生及 AXI4-Lite CPU 接口目前只能测试 RAM/ROM；Pico Wishbone profile 已有 ZipCPU timer→IRQ3→custom0 ISR 独立验收、双 PULP GPIO 的 MMIO 数据链、OpenTitan GPIO 边沿 IRQ/custom0 ISR，以及 ZipCPU wbuart RX 非空 level IRQ/custom0 ISR 各自的 fresh replay 验收；ZipCPU AXI4 CPU 当前只服务 RAM。PULP SPI 只验收 CLKDIV=1 单次传输，CLKDIV=0 和 CPU 中断链均未验收。ZipCPU ziptimer 的 IRQ 是单周期脉冲；旧 CVE2 数据链未绑定 CPU IRQ，Pico Wishbone IRQ3/custom0 ISR 场景已独立验收。ZipCPU wbuart 的旧 CVE2 数据链已验收且原生 IRQ 电平交付 CPU 输入，该 CVE2 程序仍轮询；新增 Pico Wishbone 场景已验收 RX 非空 IRQ/custom0 ISR 和 fresh replay；OpenTitan UART 的 CVE2 数据链将 CPU IRQ 固定为 0，Ibex 与 CV32E40P 各有单字节 RX watermark IRQ/ISR 闭环通过。两个 ISR 场景都在帧完成后访问 UART，尚未覆盖 RX 波形活动期间的并发 TL-UL 访问。PULP I2C 固定从地址 `0x42`，peer 响应支持单字节 Genome 变异，尚不支持多字节或多个从设备。新 CPU/IP 仍需固定源码、完整端口 profile、已支持的协议形态与必要的声明式微调；通用寄存器模板已能复用 TL-UL 的 GPIO/Timer/SPI Device、APB3 的 GPIO/Timer、Wishbone 的 Timer/wbuart，动态与绑定输入范围见上文；通用串行 peer 已在限定的 UART/SPI Device 场景验收，不能推断任意同协议 RTL 均可直接运行。

新增 Ibex＋OpenTitan GPIO 的单 pin 上升沿→真实 IRQ→Ibex ISR→GPIO CSR/RAM→fresh replay 闭环通过；其他边沿模式、多 pin 中断与 PLIC 未验收。新增 CVA6＋OpenTitan GPIO 单拍 MMIO→GPIO 真实 pin→RTL 读回→RAM、CVA6＋OpenTitan SPI Host 四字节 mode-0 RX→CVA6 RAM，以及 CVA6＋OpenTitan RV Timer 原生 M_TIMER→CVA6 ISR 的 fresh replay 均通过，均限定在当前 CVA6 packed AXI4 和 32 位单拍 MMIO 服务形态。Timer IRQ 绑定到 `time_irq_i`，并与 `irq_external`/M_EXT 分离；ISR 从真实 Timer 读取 INTR_STATE 和计数，保存完整 `mcause=0x8000000000000007` 并通过 W1C 清除中断。CPU 与 Timer 使用独立 harness 和各自本地时钟，不含 PLIC、具体 SoC 拓扑或全局 cycle-accurate 时序。其细节见 [GPIO 验收报告](reports/generated-cva6-opentitan-gpio-20261005.md)、[SPI Host 验收报告](reports/generated-cva6-opentitan-spi-host-20261005.md)和 [RV Timer M_TIMER 验收报告](reports/generated-cva6-opentitan-rv-timer-irq-20261005.md)。新增 Ibex＋OpenTitan RV Timer 的两轮生成式 IRQ/ISR 链，与上文 CVE2＋RV Timer 仅轮询数据的限制分别适用。新增 Ibex＋PULP SPI 已验收 RX 数据闭环，但未验收 SPI 事件接入 CPU ISR；新增 Pico Wishbone＋双 PULP GPIO 已验收跨 Wishbone/APB3 数据闭环，但 Pico profile 的中断仍关闭。生成式 Ibex＋双 PULP GPIO 的 600 秒结果、证据身份和速度口径见 [验收报告](reports/generated-ibex-two-pulp-gpio-acceptance-20261005.md)。OpenTitan UART RX watermark 中断链的约束和验收边界见 [验收报告](reports/generated-ibex-opentitan-uart-irq-20261005.md)，OpenTitan GPIO 的中断闭环见 [验收报告](reports/generated-ibex-opentitan-gpio-irq-20261005.md)。

新增 CVA6＋OpenTitan GPIO M_EXT 场景：Fuzzer 通过 `IP_TO_CPU` 依赖路径将唯一外部源 `gpio_in[7:0]` 从 `0x01` 变异为 `0x81`；高 24 位固定为零。CPU 先通过自身 packed AXI4、抽象 `DataflowRouter` 和 GPIO TL-UL RTL 真实提交 `INTR_ENABLE=1` 与 pin 0 上升沿使能，只有两笔 `mmio_delivery` 均完成后才注入 GPIO 输入。GPIO RTL 的真实 `irq` 绑定到 CVA6 `irq_external`，`irq_timer` 固定为零。ISR 读取真实 `INTR_STATE=1`、`DATA_IN` 与 `mcause=0x800000000000000b`，W1C 后读回零且 IRQ 拉低；ISR 写入完成标记 `0x55`，MRET 后主程序观察该标记并写入 `0x66`。两种源值都在 epoch 0 完成，并由全新的 CPU/GPIO harness 完整 replay。CPU 与 IP 使用独立 generated harness 和本地时序；此场景不含 PLIC、具体 SoC 总线拓扑或全局 cycle-accurate 时序，也不代表其他 CVA6 中断源和 GPIO 模式。详情见 [CVA6＋OpenTitan GPIO M_EXT 验收报告](reports/generated-cva6-opentitan-gpio-mext-irq-20261005.md)。

新增 CVA6＋双 PULP GPIO 独立 generated harness 验收：CPU memory_image 中唯一可变的 immediate 经依赖图选择并从 `0x01` 变异到 `0x81`，真实 AXI4 MMIO 通过 `DataflowRouter` 提交 A.PADOUT，A.gpio_out 绑定 B.gpio_in；B 同步输入与真实 PADIN 保留 payload，pin 0 原生 IRQ 持续一个 B 本地 tick。现有 `irq_pulses` 将该事件交付为有限四个 CPU tick 的 `irq_external` 脉冲，`irq_timer=0`；这是 runner 交付策略。CVA6 真实 M_EXT ISR 保存完整 `mcause=0x800000000000000b`、PADIN、INTSTATUS 的读清除与零回读，MRET 后主程序写标记；两种值均在 epoch 0 完成，路由 MMIO 事务恰一次且全新 CPU/A/B 完整 replay 一致。范围限定当前 pinned profile，无 PLIC/完整 SoC/全局 cycle 时序或 bug-found 声称，详见 [CVA6＋双 PULP GPIO 验收报告](reports/generated-cva6-two-pulp-gpio-mext-irq-20261005.md)。

新增 CVA6＋PULP I2C 双 M_EXT generated harness 验收：固定 CPU 程序提交 PRESCALER/CTRL/TX=`0x85`/CMD=`0x90`；`TX=0x85` 是七位地址 `0x42` 加读位。地址 ACK 的原生 IRQ 由 I2C `interrupt_o` 绑定到 CVA6 `irq_external`，第一次 M_EXT ISR 记录 STATUS 与完整 `mcause=0x800000000000000b`、CMD IACK 并 MRET；随后主程序提交 CMD=`0x68`，peer 字节 `0x5a→0xa6` 在真实 SDA/SCL 上升沿样本中以 MSB-first 出现，I2C RXDATA 经 CPU MMIO 读取进入 RAM。读完成产生第二次 IRQ 和 M_EXT ISR，记录 RX/STATUS/cause，第二次 IACK 后 IRQ 拉低；MRET 后主程序 marker 可见。STATUS[7] 分别确认地址 ACK=0 与 master NACK=1。两个 peer 值都完整 replay 到新 CPU/I2C sessions，epoch 保持 0。最终本地运行 `1 passed, 2 subtests passed in 72.12s`，独立 root rerun `1 passed, 2 subtests passed in 71.65s`。trace 的 `event_id` 是 evidence receipt append order，只用于跨事务偏序，不表示同一 APB access 内的 cycle 精度。该场景限定固定 CVA6/PULP profile、地址 `0x42` 和单字节；不含 PLIC、真实 SoC 总线拓扑或全局 cycle-accurate 时序，无 DUT bug 发现或 coverage-guided bug search 声称。详见 [CVA6＋PULP I2C 双 M_EXT 验收报告](reports/generated-cva6-pulp-i2c-two-mext-irq-20261005.md)。

新增 CVA6＋ZipCPU AXI4-Lite UART RX M_EXT 场景：唯一外部 `uart_rx_byte` 从 `0x35` 变异到 `0xa6`，经过真实 `i_uart_rx` 8N1 波形、ZipCPU RX FIFO 和 `uart_rx_int` level IRQ；CVA6 ISR 真实读取 RXREG、保存输入 byte 和 `mcause=0x800000000000000b`，FIFO pop 后 IRQ 拉低，MRET 后主程序 RAM marker 可见。测试锁定 SETUP 的 AWID/BID 与 RXREG 的 ARID/RID/RDATA/RLAST，并检查两笔 MMIO acceptance/delivery 一一对应。CPU 与 UART 使用各自独立 harness/本地时钟，路由只做抽象寄存器交付；测试对 UART peer 增加固定 350 本地 tick idle extension，验证 SETUP B 与 RX start 相隔至少 425 ticks。两个 payload 和 fresh replay 均通过。范围限于当前 CVA6/ZipCPU profile、单字节 RX 和固定波特设置；不含 TX、物理 AXI4-to-AXI4-Lite bridge、PLIC、完整 SoC 或全局 cycle-accurate 时序。详情见 [CVA6＋ZipCPU AXI-Lite UART RX M_EXT 验收报告](reports/generated-cva6-zipcpu-axiluart-rx-mext-irq-20261005.md)。

OpenTitan `sysrst_ctrl` 当前只验收 key0 的高到低（H2L）事件：测试先通过真实 TL-UL 写入 KEY_INTR_CTL、debounce 与 INTR_ENABLE，并确认初始 KEY_INTR_STATUS/INTR_STATE 为零、native IRQ 为低；随后才由 Genome 接纳外部高基线，保持 360 个 `sysrst` 本地 tick 后拉低。trace 明确记录 setup/probe 事务先于 high source admission，因此场景动作不会排在寄存器配置之前。RTL 的 24 MHz core 与 200 kHz AON 各自推进，比例为 120；只用 DUT 本地 tick 表达延迟，不模拟全局 SoC cycle。`rst_req_o`、`wkup_req_o` 都只观察，不反馈到 reset 或环境；当前没有 PLIC、复位控制器闭环、其他 pin/key 事件或完整 SoC 总线结构。该证据说明一个场景的端到端能力，不代表已经运行 coverage-guided 缺陷搜索或发现 RTL bug。

OpenHW CV32E40P 的新增验收只覆盖固定 OBI profile 下的真实 CPU 取指和 RAM 事务。程序执行 `SW 0x12345678 → LBU [A+1] → SB [A+1] → LW → SW [A+4]`，确认 RTL 原始总线地址/写数据/byte-enable 为 `(0x20000, 0x12345678, 0xf)`、`(0x20001, 0x5700, 0x2)`、`(0x20004, 0x12345778, 0xf)`；内存服务只将 RAM/MMIO 后端地址规范化到 32-bit beat，保留原始 RTL 观测，最终两个字均为 `0x12345778`。预算化 evidence bundle 由新 harness 完整 fresh replay。该场景没有 CPU→外设事务、外设 RTL、跨组件依赖或中断闭环，因此仅称为 **generated local OBI RAM acceptance**；source lock 的 `runtime_status` 仍为 `runtime_unverified`。详情与命令见 [CV32E40P OBI RAM 报告](reports/generated-cv32e40p-obi-ram-20261005.md)。

新增 RVX standalone `rvx_core` 的 completion-memory RAM 验收：真实 RV32I 程序在同一 testcase、同一个 CPU process 中执行 128 个本地 tick，不做 testcase 内 reset。程序先向 `0x100` 写 `0x12345678`，再以 `SB` 覆盖 lane 1（真实请求为 `write_data=0x00005500`、`write_strobe=0b0010`），随后真实 `LW` 得到 `0x12345578`，写到 `0x104`，最后向 `0x108` 写完成标记。四笔数据写恰好各出现一次，全部真实内存 transaction key 唯一且 ledger 无未完成项；三处 RAM 终值正确，全 trace、状态摘要和事务事件在新的 RTL process replay 中一致。RVX 没有连接任何外设或 IRQ；不是 RVX SoC bus 验收，也没有运行 coverage-guided fuzz campaign。source-lock `elaboration_status` 和 `runtime_status` 保留 `elaboration_unverified`/`runtime_unverified`；本地 generated build 与 directed runtime pass 不会自动提升这两个登记状态。详情见 [RVX persistent RAM 验收报告](reports/generated-rvx-core-persistent-memory-20261005.md)。

另有固定 CV32E40P＋双 OpenTitan GPIO 的单 pin RTL 闭环：CPU 配置 GPIO A/B，GPIO A 输出及方向真实样本驱动 GPIO B 输入，GPIO B IRQ 进入 CV32 `irq_i[11]`，CPU ISR 将 RTL 状态/输入存入 RAM 并真实 W1C；完整证据包 fresh replay 一致。它只证明该 profile、该组件组合和该场景，不代表任意 TL-UL 外设可与任意 CPU 直接复用。因为抽象 binding 只传 `gpio_out` 而不进行 pad/OE 电气解析，测试强制 `gpio_dir[0]=1` 并断言该位和输出值来自同一个 GPIO A RTL sample。source-lock 的 `runtime_status` 保持 `runtime_unverified`。详见 [CV32E40P＋双 OpenTitan GPIO 验收报告](reports/generated-cv32e40p-two-opentitan-gpio-irq-20261005.md)。

新增 CV32E40P＋OpenTitan UART 链将外部 `0x5a` RX 字节经真实串行 peer/UART RTL 转成 `uart_rx_watermark`；该真实输出绑定到 CPU `irq_i[11]`，CPU 观察到 MEI acknowledgement 后执行 ISR、读出 watermark 置位的真实 `INTR_STATE` 和 `RDATA=0x5a`，将两者写入 testcase 持久 RAM。RDATA 弹出 FIFO 后真实 UART IRQ 拉低，且 fresh evidence replay 重现同一状态演化。固件使用 `mtvec=0x10100`，direct vector entry 跳过 vector slots 到延迟块再进入处理代码；IRQ11 vectored slot 是自环哨兵，测试还断言 IRQ acknowledgement 后首个 accepted fetch 位于 `0x10100`。CV32E40P RTL 只保留 `mtvec[31:8]`，因此向量基址需按 256 字节对齐。UART 在帧活动期间不接受 TL-UL 访问，场景先让 CPU 执行 64 条本地 NOP；不含 PLIC 或具体 SoC 总线结构。该场景是定向 RTL 闭环，不是 coverage-guided bug search。详见 [CV32E40P＋OpenTitan UART 验收报告](reports/generated-cv32e40p-opentitan-uart-irq-20261005.md)。

新增 CV32E40P＋OpenTitan RV Timer MTI 链使用独立的单线 profile 将 Timer RTL 的真实 IRQ 绑定至物理 `irq_i[7]`；已有 MEI profile 仍单独映射到 `irq_i[11]`。CV32E40P 真实配置比较值并启用 MTIE，随后由 Timer RTL 拉高中断、CPU 应答 ID 7 并进入对齐的 direct vector。ISR 从 TL-UL 读取真实 `INTR_STATE0` 与计数，保存实际 `mcause=0x80000007`，停止 Timer、W1C 清状态并将结果写入持久 RAM；全程没有 testcase 内 reset，fresh harness replay 全量一致。该定向场景保留两个 RTL 的本地时序，不包含 PLIC、SoC 总线拓扑或 coverage-guided bug search。详情见 [CV32E40P＋OpenTitan RV Timer MTI 验收报告](reports/generated-cv32e40p-opentitan-rv-timer-mti-20261005.md)。

新增 CV32E40P＋OpenTitan SPI Host MEI 链将 Genome 的 32-bit 外部源经真实 mode-0 peer 和 Host RTL 采样进入 RXDATA；Host 原生 IRQ 绑定到 CV32E40P `irq_i[11]`，CPU 真实应答 ID 11 并执行 ISR，读取 RXDATA、记录 `mcause=0x8000000b` 和持久 RAM。源字 `0x12345678→0x12345679` 改变了实际 RXDATA/RAM，两个有界证据包均由全新 CPU/Host harness 完整 replay。该验收固定为四字节传输和当前 CV32E40P/OpenTitan SPI Host profile，不含 PLIC、SoC 总线拓扑、其他 SPI 模式或 coverage-guided bug search。详情见 [CV32E40P＋OpenTitan SPI Host MEI 验收报告](reports/generated-cv32e40p-opentitan-spi-host-irq-20261005.md)。

新增 CV32E40P＋OpenTitan SPI Device upload MEI 链只将外部 `master_frame` 作为 Genome 源；CPU 通过真实 OBI/TL-UL 路由配置 CONTROL、CMD_INFO 和 INTR_ENABLE，设备自身收到 mode-0 上传帧后产生真实 `irq_o[1]` 并绑定到 CV32E40P `irq_i[11]`。ISR 读取真实 INTR_STATE、上传 command/address FIFO、ingress SRAM 与 `mcause=0x8000000b`，将结果存入 testcase 持久 RAM，再以 bit1 W1C 清 IRQ；帧 `0x0012345a→0x0012345b` 的实际 payload/RAM 不同，IRQ 高低变化、MRET 返回和两份 fresh replay 均通过。该闭环限定当前单线 upload opcode、单帧及固定 CPU/IP profile，不包含 PLIC、SoC 总线拓扑或 coverage-guided bug search。详情见 [CV32E40P＋OpenTitan SPI Device MEI 验收报告](reports/generated-cv32e40p-opentitan-spi-device-irq-20261005.md)。

新增 CV32E40P＋OpenTitan I2C command-complete MEI 链只将外部 `peer_response` 作为 Genome 源，START action 仅把字节交给本地环境 peer；CPU 真实写入 FDATA `0x1a1` 才触发 START/address，随后 `0x601` 触发 READ/STOP。trace 逐位检查第二条 FDATA 后真实 SCL 上升沿对应的 `sda_i` 字节窗口为 `01011010`/`01011011`，并且 RTL RDATA 和 CPU RAM 随 `0x5a→0x5b` 变化。I2C 原生 `irq_o[9]` 绑定 CV32E40P MEI `irq_i[11]`；CPU 在 WFI 睡眠期间等待，真实 IRQ 唤醒后 ISR 读取 INTR_STATE/RDATA/`mcause=0x8000000b`、保存 RAM 并 W1C 清除，fresh replay 完整一致。该场景限定地址 `0x50` 单字节读和无 clock stretching，不含 PLIC、SoC 拓扑、全局 cycle-accurate 时序或 coverage-guided bug search。详见 [CV32E40P＋OpenTitan I2C MEI 验收报告](reports/generated-cv32e40p-opentitan-i2c-irq-20261005.md)。

新增 Ibex＋OpenTitan I2C MEI 场景复用固定 OBI CPU 与 TL-UL I2C 的独立生成式 harness；外部 `peer_response` 仍是唯一 fuzzable source，两个值 `0x5a/0x5b` 经真实 `sda_i` 采样、RDATA、ISR 和持久 RAM 传播。Ibex 将 `mtvec` 对齐并强制为 vectored mode，CPU 程序设置基址 `0x10100`，MEI cause 11 实际进入 `0x1012c`；Ibex harness 不暴露物理 IRQ ack/id 输出，因此以真实 IRQ 输入交付、向量取指、ISR 读取 `mcause=0x8000000b`、W1C、后续 IRQ low 和 MRET 作为中断证据。WFI 的 `core_sleep_o` 只用于检查睡眠与唤醒，ISR 状态与 `mcause` 证明陷入执行。与前述 CV32E40P 场景并列，这是第二种 OBI CPU 的固定组合验收，不表示任意 OBI CPU 可仅凭 profile 自动接入；I2C 限地址 `0x50` 单字节且无 clock stretching。详见 [Ibex＋OpenTitan I2C MEI 验收报告](reports/generated-ibex-opentitan-i2c-irq-20261005.md)。
