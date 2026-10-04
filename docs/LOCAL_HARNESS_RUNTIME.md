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
| PicoRV32，AXI4-Lite | 固定源码、真实 AW/W/B/AR/R 引脚经本地 adapter；真实程序两轮 Store/Load、持久 RAM、预算化证据 fresh replay | RAM/ROM RTL operational；固定 no-response-code 变体，无 MMIO/IRQ |
| ZipCPU，完整 AXI4 双主端口 | 15 文件固定源码闭包；真实五通道握手、八拍取指突发、两次 RAM 写入、预算化证据 fresh replay | RAM RTL operational；不接受 exclusive 与非 RAM 地址 |
| PULP GPIO，APB3 | 固定源码、全顶层端口、生成式 wrapper/driver；持续 APB 寄存器事务、双实例状态隔离、真实边沿脉冲逐本地 tick 记录 | RTL operational |
| PULP SPI master，APB3＋模式 0 外部串行 peer | 两份固定源码记录共同认证；真实 APB 配置、32 个选中 SCK 上升沿、EOT、RXFIFO `0xA5C396F0`、fresh replay | CLKDIV=1 单次 TX/RX RTL operational；其余模式见限制 |
| PULP Timer，APB3 | 固定源码、完整顶层端口、声明式 timer 执行器变体；真实双计数器、比较 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；CPU IRQ 未绑定 |
| ZipCPU ziptimer，Wishbone target | 固定源码、12/12 顶层端口、无地址单寄存器变体；真实注册 ACK、读写、单周期 IRQ 脉冲、预算化证据 fresh replay | Timer RTL operational；不支持部分写 |
| ZipCPU axiluart，AXI4-Lite target | 固定五文件源码闭包和 29/29 顶层端口；真实 AW/W/B、AR/R 握手，TX pin 解码 `0x41`，串行 RX 返回 `0x5a`，预算化 fresh replay | UART RTL operational；固定 8N1/波特配置 |
| ZipCPU wbuart，Wishbone target | 固定四文件源码闭包和 19/19 顶层端口；2 位 word 地址、byte select、注册 ACK；真实 TX `0x41`、两种 RX 源值及原生 IRQ 均可 fresh replay | UART RTL operational；固定 8N1、单字节，尚无 CPU 链 |
| PULP I2C master，APB3＋开漏串行 peer | 固定四文件源码闭包和 17/17 顶层端口；testcase 选择 8 位 peer 字节，真实 APB 配置、从设备 ACK、串行读取和原生 IRQ，预算化 fresh replay | I2C RTL operational；固定地址 `0x42` 的单从设备单字节模式 |
| OpenTitan GPIO，TL-UL | 固定上游源码与完整本地 wrapper 边界；真实寄存器读写、pin 输出、边沿 IRQ、合法及非法部分写响应、预算化证据 fresh replay | GPIO RTL operational；RACL 默认关闭，alert ack peer 未接入 |
| OpenTitan RV Timer，TL-UL | 固定上游源码、25/25 物理端口与本地标量 wrapper；真实计数、比较 IRQ、停止后的 INTR_STATE W1C 与 fresh replay | Timer RTL operational；CPU 中断入口未验收 |
| OpenTitan SPI Host，TL-UL | 固定上游源码、29/29 物理端口；受限 4 字节 mode-0 环境源经真实 32 个采样边沿进入 RXDATA，两种 Genome 源值及 fresh replay 一致 | SPI Host RTL operational；CPU MMIO 数据链已验收，CPU IRQ/ISR 尚未验收 |
| OpenTitan I2C，TL-UL | 固定上游源码、33/33 物理端口；真实开漏 ACK/单字节 `0x5A`、RDATA、原生 IRQ 和 fresh replay | I2C RTL operational；从地址 `0x50`，无 clock stretching |
| OpenTitan UART，TL-UL | 固定上游源码、37/37 物理端口；真实 TX `0x41`、RX `0x5A/0xA6`、原生 IRQ 与 fresh replay | UART RTL operational；CPU 数据闭环已验收，CPU IRQ/ISR 尚未验收 |
| OpenTitan SPI Device，TL-UL | 固定上游源码、35/35 物理端口；专用 session 验收 mode-0 单线 JEDEC 应答、CSR 改写、上传 IRQ/FIFO/SRAM 与 fresh replay；通用 v2 模板另验收静态引脚下寄存器事务 | 串行行为只覆盖当前单线场景；CPU 跨组件链尚未验收 |
| CVE2 ↔ GPIO A ↔ GPIO B | 同一 testcase 两个方向各两轮，4 次真实 GPIO IRQ 和 CPU ISR，RAM 历史为 6、8、11、15；有预算证据包从初态重放一致 | 双向多组件链通过 |
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

协议模板注册表列出 CPU OBI、AXI4、AXI4-Lite、Wishbone classic、Pico native Ready/Valid，以及 OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 和 AXI4-Lite 目标端变体。上表的五种 CPU 协议、PULP APB3 GPIO/SPI/Timer/I2C、OpenTitan TL-UL GPIO/RV Timer/SPI Host/I2C/UART/SPI Device、ZipCPU Wishbone Timer/UART 与 AXI4-Lite UART 实例有真实 RTL 运行证据。`local_harness.v2` 的同一个 `tlul_register_observe` 模板已用 RV Timer、GPIO、SPI Device 的 profile/endpoint 和逐字段输入声明验收寄存器与输出观察；GPIO 的 `environment_bindings` 还验收动态外部引脚源、真实状态/IRQ 与 fresh replay。该通用模板目前不驱动串行 peer；SPI Device 的 JEDEC/上传验收由专用 session 提供，不能算作通用模板自动生成的串行能力。

## 生成与启动

1. `local_harness.v1` 请求选择完整源 profile、独立实例 ID、reset/等待界限。
2. `plan_local_harness` 从固定 revision 的真实顶层得到逐位端口事实和唯一输入归属。缺口、重叠、未知信号、未验证源码都会拒绝。
3. `render_local_harness` 生成单 DUT 结构 wrapper；`render_local_runtime` 在 wrapper 外侧接对应的本地 OBI、原生完成式内存、Wishbone、AXI4-Lite、AXI4、APB3 或 TL-UL 执行器；`render_local_driver` 生成逐本地时钟采样的 C++ driver。
4. `build_local_harness` 重建并逐字节核对上述产物、源码闭包、头文件及构建身份，再执行有界 `verilator --cc --exe --build -j 1`。缓存键由实际构建输入决定。
5. `GeneratedLocalSession.prepare_local()` 在 testcase 计时前构建；`begin_case()` 启动一个进程并核对 READY 的产物摘要和实测 reset tick；每个命令有执行 ID、单调序列及有界回复期限。一个 testcase 的多个命令共用该进程。只有显式 reset 或 testcase 结束才重新初始化 RTL。

也可将 `local_harness.v1` 请求保存为 JSON，直接生成可审阅文件：

```bash
python3 scripts/generate_local_harness.py --request request.json --output /tmp/generated_component
```

输出包含结构 wrapper、运行时顶层、driver、ABI、源码验证回执和产物身份。重复生成同一请求得到相同字节；已有输出目录会被拒绝。可选 `--build-cache /tmp/myfuzz-build-cache` 会编译并返回二进制路径，但**编译成功只表示构建通过**；`RTL operational` 仍要求真实局部事务、状态和 replay 验收。

`GeneratedCve2Session` 只服务真实 OBI 握手接受的取指/数据请求。RAM 用 `PersistentMemory` 保存：写入后的读取得到先前真实写值，byte-enable 只覆盖对应字节；首次未初始化读取会物化并保留。MMIO 请求由 `DataflowRouter` 交给真实 GPIO session，目标读值再返回 CPU。`GeneratedPulpGpioSession` 只接受合法 GPIO 外部 pin 值与全字 APB3 写；已绑定的 pin、CPU IRQ 和 MMIO read data 由上游真实输出或持久状态决定，不能再次随机覆盖。

### 输入约束的判定

| 输入或状态 | 谁可以决定 | 强制约束 |
|---|---|---|
| CPU 程序、初始内存、未绑定的 GPIO 外部 pin | Fuzzer 选择上游 Fuzzable Source | 只在场景允许的初始或外部事件时改变，变异整段连续场景 |
| PULP SPI 的外部串行数据 | Fuzzer 选择 testcase 的 `SOURCE_SPI` 字节流 | peer 只按真实选中 SCK 边沿推进；同一事务中的回读来自 SPI RTL，不重新随机 |
| ZipCPU UART RX 与 PULP I2C peer 响应 | Fuzzer 选择声明为 source 的 testcase 字节；串行 peer 驱动 pad | UART 的 8 位 `uart_rx_byte` 在帧开始后锁定；I2C 固定从地址 `0x42`，8 位 `peer_response` 必须在 APB 事务前选定，同一 testcase 保持不变。SCL/SDA pad 每个本地周期由真实引脚与开漏电气规则决定，不能另加独立随机位 |
| CPU 产生的 OBI 地址、写值、byte enable | 真实 CPU RTL 输出 | Fuzzer 不能跳过 CPU 而直接随机这些事务 |
| GPIO APB3 配置与寄存器访问 | 已接受的 CPU MMIO 事务，经 Router 转交 | 不能用另一个随机配置值覆盖 CPU 的真实写入 |
| GPIO A 输出绑定到 GPIO B 输入的位 | GPIO A 真实 RTL 输出 | B 对应输入位属于 Bound Input；只有未绑定的其他位可作为环境源 |
| CPU 读取 GPIO 的返回值、CPU 外部 IRQ | 真实 GPIO RTL 及 Router/IRQ 调度 | 不能随机改写真实返回值或由状态寄存器推测 IRQ |
| RAM 先前写入字节、首次读取后物化字节 | 持久 Memory Model | 后续读取复用，直到真实写操作覆盖；形成 persistent state dependency |

每个物理输入位在生成前必须有且只有一种归属：局部协议执行器、Fuzzable Source、真实上游绑定或有证据的常量。Dependency Scheduler 决定动作何时可发生；Dataflow Router 只传递真实值。检查属性独立记录异常输出，不因预期因果顺序而丢弃 DUT 的错误结果。

每个 driver RESULT 包含真实前后 tick、完整本地 pre/post 样本、原始物理端口及局部协议端口。调度器以样本中的 GPIO 原生 `interrupt` 脉冲建立后续 CPU 输入，包含 APB 访问期间发生的脉冲；不会从 INTSTATUS 或预期配置合成 IRQ。重复命令只取得历史回执，不再次推进 RTL；回复丢失后终止会话，归类为不确定效果，不重试真实事务。

## 运行验收

在仓库根目录运行：

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests/local_harness -p 'test_*.py' -q
PYTHONPATH=src:. python3 -m unittest discover -s tests/scenario -p 'test_*.py' -q
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_local_pulp_gpio_generated_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_irq_real.py -v
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
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_local_opentitan_spi_device_generated_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_cve2_opentitan_spi_host_generated_real -v
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_axil_uart_runtime -v
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_wishbone_cpu -q
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_axi4_cpu -q
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_ibex_obi_runtime -q
```

2026-10-04 回归结果：SPI Device、动态 TL-UL 输入和 UART CPU 链合入后，本地 harness 全量 215 项运行、8 项按真实 RTL 环境门禁跳过，无失败；场景回归 367/367。随后合入的 CVE2 RV32E 参数变体定向真实测试 1/1，通过 fresh replay；源码锁全量校验通过。SPI Device 专用真实用例 3/3、通用 TL-UL 动态/固定输入真实及合同用例 9/9 在主线通过；各自能力边界见 `docs/reports/opentitan-spi-device-generated-20261004.md`。Pico 原生内存真实测试 2/2、AXI4-Lite 真实测试 2/2、Wishbone 专项 6/6、ZipCPU AXI4 突发及 schema 2/2、PULP SPI 预算化证据测试均通过。CVE2 双 GPIO 双向真实场景此前 2/2，预算化证据 fresh replay 一致。若本地缺少某 CPU 的可执行固定源码，只跳过该 CPU 的真实验收并记录 `skipped_unavailable`，不让其他 CPU/IP 或协议等级自动通过。

## 尚未满足的验收

五类初始 CPU 协议已有至少一个固定 RTL 实例的生成式运行证据；Ibex 与 CVE2 是两种真实 OBI CPU，证明该特定 OBI 形态可复用同一生成器。AXI4 的当前固定 RTL 实例是 ZipCPU，原设计计划中的 CVA6 未达到生成式运行验收。双向 CPU/GPIO 首阶段具备连续状态、IRQ、预算化证据和 replay；CPU→PULP SPI→CPU RAM、CPU→OpenTitan GPIO→CPU RAM、CPU→OpenTitan RV Timer→CPU RAM、CPU→OpenTitan I2C→CPU RAM、CPU→OpenTitan SPI Host→CPU RAM、CPU→ZipCPU AXI4-Lite UART→CPU RAM、CPU→PULP Timer→CPU RAM、CPU→ZipCPU Timer→CPU RAM 与 CPU→PULP I2C→CPU RAM 数据闭环，以及 CVE2↔OpenTitan UART↔CPU RAM 双向数据链已通过。I2C 原生 IRQ 已真实转交 CPU 输入，CPU 程序仍轮询状态。OpenTitan GPIO、RV Timer、SPI Host、I2C、UART 与 SPI Device 已有生成式 TL-UL 真实运行与 replay；SPI Device 仅验收当前单线 mode-0 串行子集，其 CPU 多组件链与更多串行模式尚未验收。OpenTitan I2C 的 CPU 程序轮询中断状态，CPU IRQ 固定为 0。Pico 原生及 AXI4-Lite CPU 接口目前只能测试 RAM/ROM；Wishbone CPU 已服务 RAM 与 GPIO MMIO，但无 IRQ；ZipCPU AXI4 CPU 当前只服务 RAM。PULP SPI 只验收 CLKDIV=1 单次传输，CLKDIV=0 和 CPU 中断链均未验收。ZipCPU ziptimer 的 IRQ 是单周期脉冲，当前 CPU 链未绑定 CPU IRQ。ZipCPU UART 和 OpenTitan UART 的 CPU 双向数据链已验收，但 CPU IRQ 尚未绑定。PULP I2C 固定从地址 `0x42`，peer 响应支持单字节 Genome 变异，尚不支持多字节或多个从设备。新 CPU/IP 仍需固定源码、完整端口 profile、已支持的协议形态与必要的声明式微调；通用 TL-UL 寄存器模板已能复用 GPIO/Timer/SPI Device，并有动态 GPIO 引脚源证据；串行 peer、跨组件绑定仍需分别验收，不能推断任意同协议 RTL 均可直接运行。
