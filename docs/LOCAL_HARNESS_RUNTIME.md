# 生成式独立 Harness 的实际运行边界

本系统保持每个真实 CPU/IP RTL 在自己的本地 harness 中运行。测试系统只在事务、事件和数据流层转交真实输出；不生成总线矩阵、桥、仲裁器或一颗具体 SoC，也不推断 DUT 应该给出的结果。

## 当前可运行路径

| 组件/协议 | 当前证据 | 等级 |
|---|---|---|
| CV32E20/CVE2，OBI 指令与数据端口 | 固定源码、全顶层端口、生成式 wrapper/driver；真实取指、Store/Load、byte-enable、显式 reset 后 RAM 保持 | RTL operational |
| Ibex，OBI 指令与数据端口 | 66/66 顶层端口、70 个实际读取文件固定；复用 OBI 生成器与 session，真实取指、Store/Load、byte-enable、预算化证据 fresh replay | 第二种 OBI CPU RTL operational |
| CV32E20/CVE2 RV32E 参数变体，OBI | 仅增加 profile、源码锁和闭包；复用同一 OBI 模板/driver/session，真实 Store/Load、byte-enable 与 fresh replay | 同 CPU 参数复用通过；不代表新 CPU 型号仅靠 profile 接入 |
| PicoRV32，原生 Ready/Valid 完成式内存端口 | 固定源码、生成式本地 adapter/driver；真实程序连续两轮 Store/Load、持久 RAM、预算化证据与 fresh replay | RAM/ROM RTL operational；暂不支持 MMIO/IRQ |
| PicoRV32，classic Wishbone | 固定源码、生成式 driver；真实取指、RAM 写入、deferred MMIO 与显式 reset，预算化证据在新进程重放一致 | RTL operational；单 outstanding，无 IRQ |
| PicoRV32，classic Wishbone，`ENABLE_IRQ=1` | 独立参数 profile 与源码闭包；真实 ZipCPU timer IRQ 绑定 IRQ3，Pico custom0 handler 写 RAM，观察真实 EOI 拉高/返回后归零、trap=0 和主程序恢复执行，fresh replay 一致 | 自定义 IRQ ABI 的单 IRQ 闭环通过；旧 IRQ=0 profile 保持原样；标准 machine-mode ABI 与嵌套中断未验收 |
| PicoRV32，AXI4-Lite | 固定源码、真实 AW/W/B/AR/R 引脚经本地 adapter；真实程序两轮 Store/Load、持久 RAM、预算化证据 fresh replay | RAM/ROM RTL operational；固定 no-response-code 变体，无 MMIO/IRQ |
| ZipCPU，完整 AXI4 双主端口 | 15 文件固定源码闭包；真实五通道握手、八拍取指突发、两次 RAM 写入、预算化证据 fresh replay | RAM RTL operational；不接受 exclusive 与非 RAM 地址 |
| CVA6，打包 64 位/ID4 AXI4 单主端口 | 固定源码与 232 文件读取闭包通过 elaboration 和源码锁校验；225 个编译源可生成结构 wrapper 与 13/13 端口 runtime top，57 个输入处置完整，Verilator lint 无错误；生成式 driver 已编译并完成真实 RAM 取指、Store→Load→Store 和 fresh replay | 固定 CVA6 RAM 路径 RTL operational：真实取指、Store→Load→Store 与 fresh replay；MMIO/IP/IRQ 和通用 packed AXI4 复用未验收 |
| PULP GPIO，APB3 | 固定源码、全顶层端口、生成式 wrapper/driver；持续 APB 寄存器事务、双实例状态隔离、真实边沿脉冲逐本地 tick 记录 | RTL operational |
| PULP SPI master，APB3＋模式 0 外部串行 peer | 两份固定源码记录共同认证；真实 APB 配置、32 个选中 SCK 上升沿、EOT、RXFIFO `0xA5C396F0`、fresh replay | CLKDIV=1 单次 TX/RX RTL operational；其余模式见限制 |
| PULP Timer，APB3 | 固定源码、完整顶层端口、声明式 timer 执行器变体；真实双计数器、比较 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；CPU IRQ 未绑定 |
| ZipCPU ziptimer，Wishbone target | 固定源码、12/12 顶层端口、无地址单寄存器变体；真实注册 ACK、读写、单周期 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；不支持部分写 |
| ZipCPU axiluart，AXI4-Lite target | 固定五文件源码闭包和 29/29 顶层端口；真实 AW/W/B、AR/R 握手，TX pin 解码 `0x41`，串行 RX 返回 `0x5a`，预算化 fresh replay | UART RTL operational；固定 8N1/波特配置 |
| ZipCPU wbuart，Wishbone target | 固定四文件源码闭包和 19/19 顶层端口；2 位 word 地址、byte select、注册 ACK；真实 TX `0x41`、两种 RX 源值及原生 IRQ 均可 fresh replay | UART RTL operational；固定 8N1、单字节，CPU 数据链已验收 |
| PULP I2C master，APB3＋开漏串行 peer | 固定四文件源码闭包和 17/17 顶层端口；testcase 选择 8 位 peer 字节，真实 APB 配置、从设备 ACK、串行读取和原生 IRQ，预算化 fresh replay | I2C RTL operational；固定地址 `0x42` 的单从设备单字节模式 |
| OpenTitan GPIO，TL-UL | 固定上游源码与完整本地 wrapper 边界；真实寄存器读写、pin 输出、边沿 IRQ、合法及非法部分写响应、预算化证据 fresh replay | GPIO RTL operational；RACL 默认关闭，alert ack peer 未接入 |
| OpenTitan RV Timer，TL-UL | 固定上游源码、25/25 物理端口与本地标量 wrapper；真实计数、比较 IRQ、停止后的 INTR_STATE W1C 与 fresh replay | Timer RTL operational；CPU 中断入口未验收 |
| OpenTitan SPI Host，TL-UL | 固定上游源码、29/29 物理端口；受限 4 字节 mode-0 环境源经真实 32 个采样边沿进入 RXDATA，两种 Genome 源值及 fresh replay 一致 | SPI Host RTL operational；CPU MMIO 数据链已验收，CPU IRQ/ISR 尚未验收 |
| OpenTitan pattgen，TL-UL | 独立固定 profile 与认证闭包；通用 TL-UL session 配置两个真实图样，检查 LSB-first 输出、不同分频周期、双完成 IRQ、闲置电平及 fresh replay | 双通道短图样 RTL operational；alert handshaking 与 CPU/外设路由未验收 |
| Ibex → OpenTitan pattgen → Ibex RAM | CPU OBI 真事务经抽象 MMIO Router 配置两个 pattgen 通道；两种程序图样产生不同的真实串行输出，CPU 轮询真实双完成状态并写持久 RAM；fresh replay 使用新 harness 重现 | 两通道输出与 CPU 状态读回闭环通过；未验收 CPU IRQ handler |
| OpenTitan I2C，TL-UL | 固定上游源码、33/33 物理端口；真实开漏 ACK/单字节 `0x5A`、RDATA、原生 IRQ 和 fresh replay | I2C RTL operational；从地址 `0x50`，无 clock stretching |
| OpenTitan UART，TL-UL | 固定上游源码、37/37 物理端口；真实 TX `0x41`、RX `0x5A/0xA6`、原生 IRQ 与 fresh replay | UART RTL operational；CPU 数据闭环已验收，CPU IRQ/ISR 尚未验收 |
| OpenTitan SPI Device，TL-UL | 固定上游源码、35/35 物理端口；专用 session 验收 mode-0 单线 JEDEC 应答、CSR 改写、上传 IRQ/FIFO/SRAM 与 fresh replay；通用 v2 模板另验收静态引脚下寄存器事务 | 串行行为只覆盖当前单线场景；CPU 数据链已验收，ISR 未验收 |
| CVE2 ↔ GPIO A ↔ GPIO B | 同一 testcase 两个方向各两轮，4 次真实 GPIO IRQ 和 CPU ISR，RAM 历史为 6、8、11、15；有预算证据包从初态重放一致 | 双向多组件链通过 |
| Ibex ↔ PULP GPIO A ↔ PULP GPIO B | 三个生成式独立 harness；CPU 程序变异经 A 真实输出绑定 B 输入、B 真实 IRQ 回 Ibex ISR 和持久 RAM；反方向 B 外部 pin `0x49/0x81/0xff` 经真实 IRQ 使 Ibex MMIO 写 A；另有一个连续 testcase 内三轮 `0x49→0x81→0xff`，RAM 写历史、状态依赖 WAW 和 fresh replay 均一致。两方向 checker 通过。CPU 上游单源 600 秒运行 420/420 完整链，128/128 合法奇数字节，26/26 抽样重放一致 | 双方向真实闭环；多轮输入仍为预编码的单 Genome actions；定时运行不是 RFuzz coverage-guided 搜索，未发现 RTL 缺陷 |
| CV32E20/CVE2 RV32E → PULP GPIO A → B → RV32E | 生成式 OBI 参数变体真实写 A、A 输出绑定 B、B IRQ 进入 CPU ISR；程序值 `0x49/0xff` 均到持久 RAM 且 fresh replay 一致 | 同核 RV32E 参数变体验收，不等于新增 CPU 架构 |
| PicoRV32 Wishbone → PULP GPIO A → B → PicoRV32 RAM | CPU 真实 Wishbone MMIO 写 A、APB3 A 真实输出绑定 B、CPU 读 B.PADIN 和 A.PADOUT 后写持久 RAM；`0x49/0xff` 变异、Bound Input 拒绝随机覆盖与 fresh replay 通过 | 跨 Wishbone/APB3 数据闭环；此 Pico profile 的 IRQ 关闭 |
| Ibex → PULP SPI → Ibex RAM | 生成式 Ibex OBI 真 MMIO 配置 APB3 SPI；mode-0 peer 两种外部源使 SPI 真实 RXFIFO 与 CPU RAM 随之变化；独立因果 checker、fresh replay 通过 | RX 数据闭环；SPI `events_o` 仅观察，未验收 CPU ISR |
| Ibex ↔ OpenTitan RV Timer | 生成式 Ibex OBI 与生成式 TL-UL Timer 独立 harness；真实两轮 Timer IRQ→Ibex ISR→Timer 状态/计数读回→RAM；独立 checker 与 fresh replay 通过 | 两轮中断闭环；仅当前固定 Timer 配置和程序 |
| CVE2 → PULP SPI → CVE2 RAM | CPU 真实 APB 配置、SPI 外部源真实接收、CPU 读取 RXFIFO 并写入持久 RAM；改变串行源会改变 RAM 与 trace，预算化证据 fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → OpenTitan GPIO → CVE2 RAM | CPU 真实配置 TL-UL GPIO；外部 pin 在真实输出触发后变化，GPIO RTL 产生中断状态，CPU 真实回读并写 RAM；fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → PULP Timer → CVE2 RAM | CPU 真实配置 APB Timer、读取真实计数并写 RAM；Timer 原生 IRQ 脉冲单独观察，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → ZipCPU ziptimer → CVE2 RAM | CPU 真实 MMIO 写入 Wishbone Timer、回读真实计数并存入持久 RAM；原生 IRQ 脉冲逐 tick 观察，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → PULP I2C → CVE2 RAM | CPU 真实 APB 配置；两个 testcase 分别选择 peer 响应 `0x5A` 与 `0xA6`，I2C RTL 接收对应串行字节并产生原生 IRQ；IRQ 转交 CPU 输入，CPU 轮询状态、回读真值并写 RAM；两份预算证据 fresh replay 一致 | 源变异与数据闭环通过；CPU 中断处理程序未验收 |
| CVE2 ↔ ZipCPU axiluart ↔ CVE2 RAM | CPU 真实 AXI4-Lite 写入 `0x41` 后 peer 从 TX 引脚解码该字节；依赖图变异 RX 源 `0x35→0xA6`，UART RTL 接收后 CPU 真实读出并写 RAM；两份 fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 → OpenTitan RV Timer → CVE2 RAM | CPU 真实配置 TL-UL Timer、读取真实中断状态和计数并写 RAM；预算化证据 fresh replay 一致 | 数据闭环通过；CPU IRQ 当前固定为 0 |
| CVE2 → OpenTitan I2C → CVE2 RAM | CPU 真实配置 I2C 时序和 FDATA；固定地址从设备经开漏引脚返回 `0x5A`，CPU 读真实 RDATA 后写持久 RAM，fresh replay 一致 | 数据闭环通过；CPU 轮询 IRQ 状态，IRQ 输入固定为 0 |
| CVE2 → OpenTitan SPI Host → CVE2 RAM | CPU 真实 MMIO 配置 CONTROL/CONFIGOPTS/COMMAND；两种 4 字节外部源经 32 个真实 SCK 采样边沿改变 RXDATA，CPU 读回后写持久 RAM，fresh replay 一致 | 数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 ↔ OpenTitan UART ↔ CVE2 RAM | CPU 真实 MMIO 写 CTRL/WDATA，UART TX 引脚解码 `0x41`；两种 Genome RX 字节经 UART 真实 RDATA 被 CPU 存入 RAM，fresh replay 一致 | 双向数据闭环通过；CPU IRQ 固定为 0 |
| CVE2 ↔ ZipCPU wbuart ↔ CVE2 RAM | CPU 真实 MMIO 写 SETUP/TXREG，UART TX 引脚解码 `0x41`；两种 Genome RX 字节经真实 RXREG 到 CPU RAM，原生 IRQ 电平交付 CPU 输入，fresh replay 一致 | 双向数据闭环通过；CPU 程序仍轮询，未验收 ISR |
| CVE2 → OpenTitan SPI Device → CVE2 RAM | CPU 真实 TL-UL MMIO 配置 CONTROL、上传命令和中断使能；两种 Genome 外部 master 帧经 mode-0 引脚进入真实上传路径；CPU 轮询真实 IRQ_STATE，读取 FIFO/地址/SRAM 并写持久 RAM，fresh replay 一致 | 数据闭环通过；CPU ISR 未验收，串行限当前单线上传帧 |

协议模板注册表列出 CPU OBI、AXI4、AXI4-Lite、Wishbone classic、Pico native Ready/Valid，以及 OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 和 AXI4-Lite 目标端变体。上表的五种 CPU 协议、PULP APB3 GPIO/SPI/Timer/I2C、OpenTitan TL-UL GPIO/RV Timer/SPI Host/I2C/UART/SPI Device、ZipCPU Wishbone Timer/UART 与 AXI4-Lite UART 实例有真实 RTL 运行证据。`local_harness.v2` 现有三个寄存器观察模板：TL-UL 的 GPIO/RV Timer/SPI Device，APB3 的 PULP GPIO/Timer，Wishbone 的 ZipCPU Timer/wbuart；每组真实交易和 fresh replay 都通过。同一个 TL-UL 模板还验收 GPIO 的动态环境引脚源，以及 GPIO A 真实输出绑定 GPIO B 输入并引出真实 IRQ；APB3 模板验收动态 GPIO 输入及双 GPIO 的真实输出→Bound Input→真实 IRQ 与 fresh replay。APB3 通用模板当前限定 12 位地址、4096 字节窗口和 32 位数据；Wishbone 通用模板要求目标有真实 `stall` 输出，且目前只接收声明式固定物理输入。不符合这些运行时形状的 profile 在规划阶段拒绝。v2 TL-UL 模板上另有 UART 8N1 peer 和 SPI mode-0 单线 master peer：UART 的 RX 帧来自声明式环境源、TX/IRQ 来自真实 RTL；SPI 的 SCK/CS/MOSI 由声明式外部帧驱动，MISO/IRQ/SRAM 由真实 RTL 给出。两者分别在 OpenTitan UART 单字节和 SPI Device 单帧场景通过 fresh replay；UART 和 SPI peer 的引脚、节拍、帧形态及启动写入已进入 v2 tuning 与 artifact 身份，通用 factory 可从 artifact 选择 session。专用 SPI Device session 仍保留其独立验收。

## 生成与启动

1. `local_harness.v1` 请求选择完整源 profile、独立实例 ID、reset/等待界限。
2. `plan_local_harness` 从固定 revision 的真实顶层得到逐位端口事实和唯一输入归属。缺口、重叠、未知信号、未验证源码都会拒绝。
3. `render_local_harness` 生成单 DUT 结构 wrapper；`render_local_runtime` 在 wrapper 外侧接对应的本地 OBI、原生完成式内存、Wishbone、AXI4-Lite、AXI4、APB3 或 TL-UL 执行器；`render_local_driver` 生成逐本地时钟采样的 C++ driver。
4. `build_local_harness` 重建并逐字节核对上述产物、源码闭包、头文件及构建身份，再执行有界 `verilator --cc --exe --build -j 1`。缓存键由实际构建输入决定。
5. `GeneratedLocalSession.prepare_local()` 在 testcase 计时前构建；`begin_case()` 启动一个进程并核对 READY 的产物摘要和实测 reset tick；每个命令有执行 ID、单调序列及有界回复期限。一个 testcase 的多个命令共用该进程。只有显式 reset 或 testcase 结束才重新初始化 RTL。

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
| 通用 TL-UL `bound_bindings` 物理输入 | Router 观察的、声明为 `producer_ref` 的真实 RTL 输出 | 运行前核对完整字段宽度、来源身份和绑定；普通 source 命令不能覆盖。值在 testcase 内保持到新的真实输出到达或显式 reset |
| CPU 读取 GPIO 的返回值、CPU 外部 IRQ | 真实 GPIO RTL 及 Router/IRQ 调度 | 不能随机改写真实返回值或由状态寄存器推测 IRQ |
| RAM 先前写入字节、首次读取后物化字节 | 持久 Memory Model | 后续读取复用，直到真实写操作覆盖；形成 persistent state dependency |

每个物理输入位在生成前必须有且只有一种归属：局部协议执行器、Fuzzable Source、真实上游绑定或有证据的常量。Dependency Scheduler 决定动作何时可发生；Dataflow Router 只传递真实值。检查属性独立记录异常输出，不因预期因果顺序而丢弃 DUT 的错误结果。

每个 driver RESULT 包含真实前后 tick、完整本地 pre/post 样本、原始物理端口及局部协议端口。调度器以样本中的 GPIO 原生 `interrupt` 脉冲建立后续 CPU 输入，包含 APB 访问期间发生的脉冲；不会从 INTSTATUS 或预期配置合成 IRQ。重复命令只取得历史回执，不再次推进 RTL；回复丢失后终止会话，归类为不确定效果，不重试真实事务。

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

完成后 `recorder.plan` 才可读取。`ScenarioBatchCodec` 使用严格版本化 JSON 保存完整命令序列和每个调用边界；trace 的 `genome_sha256` 标识整个 batch plan，因此把同一串本地步骤拆成不同的在线调用也会有不同身份。`replay_scenario_batch` 创建新的一组 harness，先核对 runner manifest，再按原命令边界重放 source admission 与本地步骤，并比较完整事件、local ticks 和语义摘要。测试 ID 是模板提供的运行标签，结束后 trace 使用完整 plan 的 SHA-256 作为 testcase identity。

此能力明确区别于现有预编码 Genome：`DependencyScheduler` 可在开始前知道完整 Action 列表；在线 batch 可以在 RTL 正在运行时根据已观测输出决定下一次输入，再把实际决定完整记录下来。当前它是 ScenarioRunner 层的 API，`ScenarioRfuzzExecutor` 尚未接入在线 RFuzz FIFO slot 流，因此不能据此声称 RFuzz 执行入口已经支持运行中逐次供给。

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

2026-10-04 至 2026-10-05 回归结果：合入通用 UART/SPI peer 后的本地 harness 全量 236 项运行、17 项按真实 RTL 环境门禁跳过、零失败；场景回归 367/367。此全量结果早于 UART tuning factory 与 CVA6 结构顶层两次提交；之后 UART tuning 真实焦点用例 6/6、CVA6 源码锁和顶层 lint 用例 4/4 均通过。CVA6 随后通过固定 RAM 路径的真实 Store→Load→Store、2 个受理写 beat 和全新会话 replay；AXI4 外设 MMIO、IRQ 与同协议新 CPU 复用仍未验收。CVE2 RV32E 参数变体定向真实测试 1/1，通过 fresh replay；SPI Device 专用真实用例 3/3、CPU→SPI Device→CPU RAM 真实链 1/1、通用 TL-UL 固定/动态/Bound Input 的真实及合同用例 12/12、通用 SPI peer JEDEC/上传 3/3、CVE2↔ZipCPU wbuart 真实链 1/1、通用 APB3＋Wishbone 寄存器模板在合同修正后联合真实及负例用例 8/8 在主线通过；各自能力边界见 `docs/reports/` 下的对应报告。Pico 原生内存真实测试 2/2、AXI4-Lite 真实测试 2/2、Wishbone 专项 6/6、ZipCPU AXI4 突发及 schema 2/2、PULP SPI 预算化证据测试均通过。CVE2 双 GPIO 双向真实场景此前 2/2，预算化证据 fresh replay 一致。若本地缺少某 CPU 的可执行固定源码，只跳过该 CPU 的真实验收并记录 `skipped_unavailable`，不让其他 CPU/IP 或协议等级自动通过。

## 尚未满足的验收

五类初始 CPU 协议已有至少一个固定 RTL 实例的生成式运行证据；Ibex 与 CVE2 是两种真实 OBI CPU，证明该特定 OBI 形态可复用同一生成器。AXI4 的首个固定 RTL 实例是 ZipCPU；CVA6 现也通过生成式独立 RAM 运行与 replay，但其专用 packed AXI4 形态尚未证明对新 CPU 的 profile-only 复用。双向 CPU/GPIO 首阶段具备连续状态、IRQ、预算化证据和 replay；CPU→PULP SPI→CPU RAM、CPU→OpenTitan GPIO→CPU RAM、CPU→OpenTitan RV Timer→CPU RAM、CPU→OpenTitan I2C→CPU RAM、CPU→OpenTitan SPI Host→CPU RAM、CPU→OpenTitan SPI Device→CPU RAM、CPU→ZipCPU AXI4-Lite UART→CPU RAM、CPU→PULP Timer→CPU RAM、CPU→ZipCPU Timer→CPU RAM 与 CPU→PULP I2C→CPU RAM 数据闭环，以及 CVE2↔OpenTitan UART/ZipCPU wbuart↔CPU RAM 双向数据链已通过。I2C 原生 IRQ 已真实转交 CPU 输入，CPU 程序仍轮询状态。OpenTitan GPIO、RV Timer、SPI Host、I2C、UART 与 SPI Device 已有生成式 TL-UL 真实运行与 replay；SPI Device 只验收当前单线 mode-0 串行和 CPU 轮询数据链，CPU ISR 与更多串行模式尚未验收。OpenTitan I2C 的 CPU 程序轮询中断状态，CPU IRQ 固定为 0。Pico 原生及 AXI4-Lite CPU 接口目前只能测试 RAM/ROM；Wishbone CPU 已服务 RAM 与 GPIO MMIO，但无 IRQ；ZipCPU AXI4 CPU 当前只服务 RAM。PULP SPI 只验收 CLKDIV=1 单次传输，CLKDIV=0 和 CPU 中断链均未验收。ZipCPU ziptimer 的 IRQ 是单周期脉冲，当前 CPU 链未绑定 CPU IRQ。ZipCPU UART 与 OpenTitan UART 的 CPU 双向数据链已验收；前者真实 IRQ 电平交付 CPU 输入但程序仍轮询，后者 CPU IRQ 固定为 0，均未验收 UART ISR。PULP I2C 固定从地址 `0x42`，peer 响应支持单字节 Genome 变异，尚不支持多字节或多个从设备。新 CPU/IP 仍需固定源码、完整端口 profile、已支持的协议形态与必要的声明式微调；通用寄存器模板已能复用 TL-UL 的 GPIO/Timer/SPI Device、APB3 的 GPIO/Timer、Wishbone 的 Timer/wbuart，动态与绑定输入范围见上文；通用串行 peer 已在限定的 UART/SPI Device 场景验收，不能推断任意同协议 RTL 均可直接运行。

新增 Ibex＋OpenTitan RV Timer 的两轮生成式 IRQ/ISR 链，与上文 CVE2＋RV Timer 仅轮询数据的限制分别适用。新增 Ibex＋PULP SPI 已验收 RX 数据闭环，但未验收 SPI 事件接入 CPU ISR；新增 Pico Wishbone＋双 PULP GPIO 已验收跨 Wishbone/APB3 数据闭环，但 Pico profile 的中断仍关闭。生成式 Ibex＋双 PULP GPIO 的 600 秒结果、证据身份和速度口径见 [验收报告](reports/generated-ibex-two-pulp-gpio-acceptance-20261005.md)。
