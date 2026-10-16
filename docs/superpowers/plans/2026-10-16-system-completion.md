# 系统剩余功能实施计划

> 执行采用 `subagent-driven-development`，逐项实施、审阅并保存实际验证证据。

**目标：** 按 2026-10-06 总计划完成独立 CPU/IP harness 系统的 P6、P7、P8，保留 P1–P5 的声明范围与身份约束。

**架构：** 复用真实组件 session、ScenarioSession、Router、Scheduler、路径契约、独立 checker 与完整前缀 replay。先补可复用场景和协议服务，再实现同一 RTL 进程的在线逐例搜索，最终按固定来源重新生成验收证据。

**技术：** Python、SystemVerilog、Verilator、RFuzz；远程构建用于较大真实 RTL。

## 用户确认的优先级（2026-10-17）

1. 六颗目标 CPU：Ibex、CVA6、CV32E40P、BOOM、CVW、VexiiRiscv；四个系列外设；真实 DMA 数据流。
2. 已支持协议内 CPU/IP 无组件专用适配的通用接入。
3. CPU/IP 事件扩充。

前三个外设系列为 OpenTitan、PULP、ZipCPU。用户将第四系列选型交由实现方，要求有影响力且增加不同协议；当前选择评估 CHIPS Alliance Caliptra（官方 Apache-2.0 RTL，AHB-Lite 外设），先固定正式 release 并验证实际接口/闭包。不得将两个 ZipCPU 协议变体冒充两个独立项目系列。

下列原执行顺序作为工作包清单保留；实际先完成当前已启动的 Wishbone 场景提取，再优先完成 CVW 真实 IP 消费、BOOM/VexiiRiscv 来源与生成链、Caliptra 和 DMA。P7 自动接入的结构性缺口已核实，修复排在上述适配之后。

2026-10-17 实查结果：CVW 当前 GPIO 窗口在地址 0，CPU 的外部 AHB 选通只覆盖 `0xC0000000..0xCFFFFFFF`，故现有声明的 GPIO 不可达。外部区当前可缓存；先使用明确关闭 D-cache 的派生配置验证普通 LSU MMIO，保留 I-cache，并将 GPIO 移入外部区、从主机 RAM 中划出非重叠窗口。此配置的能力边界须由实际 RTL 指令和总线事件证实。Caliptra 选择官方 `v2.1.2`（`49370266d12cb0c4a8f71b3a0ff7e54ba7d4866e`）的 `sha256_ctrl`：其 AHB-Lite 32 位从端口及十一个 RTL 文件在 Verilator 5.051 下完成一次 lint（退出 0，有上游宽度等警告）。这只证明所选闭包可以静态展开，尚未证明实际寄存器访问。

## 全局约束

- 上游验收依据为 `2026-10-06-current-dataflow-fuzz-implementation-plan.md`、P6 逐行清单、P7 实施文档及五协议设计。
- 普通 testcase 边界不 reset、不重装程序、不重建 harness；`fresh_genomes` campaign 不满足此项。
- Bound Input 与 DUT 输出不得变异；链证据使用精确身份关联，缺证据不给级。
- 故障校准与自然 RTL finding 分开报告；F6 必须来自真实 DMA master RTL。
- 保留工作区既有 `agent.md` 和第三方修改。分支：`codex/system-completion-20261016`；起点：`42a9ce9`。
- 远程经 `ssh jumpserver` 再到 `root@192.168.5.70`；所有远程文件操作仅限 `/root/fanzehui`，跳转机只转发。
- 真实运行使用独立输出目录、固定源码与工具链、资源预算和 heavy-worker 锁；冻结后运行，变更后重新录制。
- 每阶段保存命令、退出状态、身份、实际观察、负例、证据位置、fresh replay 与未覆盖项；更新运行能力表和报告后再更新阶段状态。

## 执行顺序与验收

1. [x] 远程隔离快照与工具链准备；验证源锁及最小真实 CPU/IP 构建。远端 `/root/fanzehui/system-20261016` 的固定快照通过 `scripts/verify_soc_sources.py`；下述真实 Wishbone 用例完成首次构建及运行。
2. [x] Wishbone 场景入口：把已有 Pico custom0 IRQ/GPIO 真实组装提取为生产 factory，测试继续覆盖原始链。提交 `bfa9d0a`；本地四项软件合同通过，远端原真实用例 `1 passed, 2 subtests passed in 165.04s`，独立审查无阻断发现。
3. [ ] Wishbone 双向源、独立 custom0 checker、provider 与两份 manifest；先验证单格，随后验证持续在线版本，不能靠 fresh campaign 宣布 P6 通过。
4. [ ] 补完成式内存及 Wishbone 的在线取指接纳/等待、持久状态、路由身份；接逐例双侧源、四类反馈、checker 和完整前缀 replay。
5. [ ] CVA6、AXI4-Lite 持续在线接入，CVW 的 boot_image、online_decoder、runner_factory；逐组合补缺失的协议、IRQ 与受控错误证据。
6. [ ] 在远端核实 BOOM/Chipyard、VexiiRiscv 的真实源码、生成工具及 TileLink 边界；建立受信 profile 与真实 adapter，按实际完成等级登记。
7. [ ] P7 自动链的生成物、编译路径、源约束、checker 和实际执行身份贯通；新增 CPU/IP 及名称相似负例、独立复核与吞吐。
8. [ ] P8 固定真实 DMA RTL，建立 master session、多主事务来源、RAM/IP 方向、真实 IRQ/ISR、非法输入对照及 replay。
9. [ ] 静止源码上逐行执行完整验收并审计；同步能力表、报告索引与总计划，逐项保留不支持原因。

## 当前具体任务：Wishbone GPIO custom0 场景提取

**文件：** 新增 `src/myfuzz/scenario/picorv32_wb_cpu_example.py`；修改 `tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py`；新增聚焦软件合同测试。

**接口：** `make_picorv32_wb_gpio_irq_runner(*, cache_dir)` 返回 `ScenarioRunner`；`make_picorv32_wb_gpio_irq_genome()` 返回现有定向 `ScenarioGenome`；`picorv32_wb_gpio_irq_ownership()` 返回已有逐位归属。

**实现依据：** 上述真实测试的 `_genome()` / `_make_factory()`；使用真实 `picorv32_wb_irq` 与 `opentitan_gpio_local` artifact；生产代码不能导入 tests，组装中的指令编码助手在生产模块内定义。

**步骤：**

- [x] 增加 API 合同测试并确认入口缺失导致失败。
- [x] 提取原程序和组装，保持源、地址、预算、IRQ bit3、custom0 ABI 与 `defer_mmio=True`。
- [x] 原真实测试改调生产 API，保留其因果、引脚、IRQ、EOI、handler、RAM 和 fresh replay 断言。
- [x] 跑聚焦软件测试；远程源码快照准备好后跑真实测试。
- [x] 独立审阅 diff，记录 commit、命令与结果。此任务不授予 P6 campaign 或持续在线等级。

## 进度依据

2026-10-16 初始核对：远端约 123 GiB 可用内存，Verilator 5.020、Java 11；现有 `/root/fanzehui/myfuzz` 是旧版非 Git 目录。P6/P7/DMA 只读核对报告暂存 `/tmp/myfuzz-{p6,p7,dma}-audit-20261016.md`，其中事实需结合代码与后续实际运行解释。

2026-10-17 进度：ZipCPU `wbdmac` 已建立 21 端口源锁、闭包和静态 profile（`debcc5d`，runtime_unverified）；Caliptra v2.1.2 `sha256_ctrl` 已建立 11 文件、16 端口闭包及双复位 profile（`e3e6c7c`，runtime_unverified）。两者均未取得真实事务或 DMA 数据流。VexiiRiscv 固定源码与 SpinalHDL 子模块生成了 RV32 双 AXI Verilog，保存命令、生成物、依赖哈希和 48 端口清单（`379600d`、`e926056`、`5410d4f`）；Verilator lint 退出 0，有 3 项上游警告，尚无 CPU session。CVW 首次真实 CPU→GPIO 运行暴露 `rv32gc` 的 64 位 LLEN/32 位 AHB 掩码截断：地址偏移 4 的实际存储 BE 为 0，路由器正确拒绝；派生配置修复和重新运行仍在进行，不能将该用例标为通过。真实运行日志在远端隔离目录 `/root/fanzehui/system-20261016/evidence/cvw-gpio-real.log`。

2026-10-17 后续实测：CVW 派生配置关闭 D/Zcd 后 `FLEN=LLEN=XLEN=AHBW=32`，真实 CPU→PULP GPIO 正例 `1 passed in 153.24s`，旧零窗口负例 `1 passed in 59.17s`；两次正例进程的六笔 APB 访问、全字 BE、GPIO 引脚输出、两次 CPU 读回及 RAM 结果逐项一致。源闭包重定位与构建器仓库相对路径修复也通过。仍为定向静态程序，不升级 P6 整行或在线 campaign。P7 已新增生成物可信加载切片（`311f25d`，D2）；D3 编译语义和 D4 执行消费仍开放。

2026-10-17 定向双向增量：CVW CPU 还从真实 PULP GPIO PADIN 读取固定外部物理输入 `0xa5`，RAM 结果 `[0x35,0x6a,1,0xa5]`；两次独立进程七笔 APB/路由交付与物理采样一致（正例 127.52s，旧窗口负例 64.46s）。该输入尚未纳入来源绑定和在线变异。ZipCPU `wbdmac` 的双接口生成式 pipelined Wishbone 单边沿 transport 已提交（`0093b7c`），真实 RTL 仅静态展开；自主 DMA session、RAM→RAM 与 IRQ 仍未实测。P7 D3 新增对真实 artifact／编译声明／物理归属的一致性核对（`a14d8e1`），D4 执行消费尚未完成。

VexiiRiscv 固定生成 RTL 已通过独立定向 CPU/RAM 运行：两次真实 fetch AXI/LSU AXI 运行得 `[53,54]`，替换唯一 LSU 读响应的对照得 `[53,1]`，每次 75 tick；仍需受信 profile、生成式 runtime、外设和在线接入。详见 [实测报告](../../reports/vexiiriscv-direct-axi-ram-20261017.md)。
