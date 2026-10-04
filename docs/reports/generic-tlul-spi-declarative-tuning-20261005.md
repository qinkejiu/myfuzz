# TL-UL 通用 SPI peer 的声明式配置

`local_harness.v2` 新增可选的 `spi_mode0_peers` 行。它声明外部 master 对应的 SCK、CS、MOSI 输入角色，MISO 与输出使能角色，frame source identity 与 Genome 端口，单线 mode-0 格式、前缀、payload/读取字节数、bit lane 和本地半周期长度。原有 `startup_writes` 记录有序的寄存器配置。字段类型和范围封闭，未知字段、超界长度、错误引脚方向/位宽、错误 source 归属、UART/SPI 同时选择、越界 lane 与未对齐寄存器访问均拒绝。

规划与生成时，`tlul_register_observe` 模板依据完整物理端口与逐字段 `environment_bindings` 校验这份配置。规范化的 `serial_peer` 随 runtime artifact 一同哈希。`create_generated_tlul_session(artifact, ...)` 从 artifact 选择通用 SPI peer 或原有 UART peer，不接收组件名、引脚名或时序参数；伪造 artifact peer 字段会被拒绝。没有 SPI 行的旧 v2 请求保持原有 tuning 文档和普通寄存器 session 行为，已有直接创建 SPI peer 的接口继续可用。

验收包括静态拒绝与 identity 测试、原有 UART/tuning 回归，以及 OpenTitan SPI Device 真实 RTL：factory 从声明式配置构建 session，Genome 提供 `0x9F`，真实 `sd_o/sd_en_o` 返回 `A1 34 12`，fresh replay 匹配。另一个静态配置例证明上传帧的 `0x02` 前缀和 32 位 payload 宽度从 artifact 传给同一通用 factory；上传 IRQ/SRAM 的真实运行证据记录在 [generic-tlul-spi-mode0-peer-20261005.md](generic-tlul-spi-mode0-peer-20261005.md)。

范围仍是单线 mode-0 单帧外部 master 与独立 TL-UL harness。它不实现完整 SoC、全局精确时序、其他 SPI 模式、多帧协议或 CPU 中断处理程序。
