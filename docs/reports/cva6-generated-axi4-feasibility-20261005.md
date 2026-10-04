# CVA6 生成式本地 harness 可行性核查（2026-10-05）

## 结论与状态

**当前状态：固定 CVA6 的生成式独立 harness 已通过真实 RTL 的 RAM 取指、Store→Load→Store 和全新会话 evidence replay。** 固定版本的真实 CVA6 RTL 及其嵌套源码在本地可用，故不是 `skipped_unavailable`。验收范围是一个 64 位数据/地址、4 位 ID 的 packed AXI4 主端口及持久 RAM；尚未验收 CVA6 与真实外设之间的数据流、外设中断交付或完整 AXI4 特性，不能称作通用 AXI4 CVA6 接入完成。

## 初始阻塞点与当前边界

1. `configs/cpus/cva6/component_profile.json` 固定 `third_party/cva6_upstream_reference@2e1336dcff3d1a0b49fbe6282b97802f32ea32af`，主工作区子模块 HEAD 与之相同。`plan_local_harness` 在已初始化该子模块的主工作区成功，识别 `cva6` 和 57 条物理端口 disposition。新 Git worktree 中必须先初始化子模块，否则会先报 `elaboration-failed:cva6:git-revision-mismatch`；这是工作树准备问题，不是 RTL 不可用。
2. 修复前，`verify_local_source_lock(profile, base_dir=root)` 报 `ValueError: local-source-lock-source-mismatch:include_roots`：CVA6 profile 声明七个 include root，而锁记录为空；锁记录还标记 `elaboration_unverified`。本报告末尾记录了本次完成的源码锁修复及验证结果。
3. 原 `axi4_cpu` 分支只处理**两个** 32 位/ID1 主端点。CVA6 profile 是**一个** 64 位/ID4 `memory_master`，在 `noc_req_o`/`noc_resp_i` 打包结构体上声明 45 个 AXI4 角色及额外字段。固定配置的宽度可从 `core/include/cv64a6_imafdc_sv39_config_pkg.sv` 复核。已增加专用 `cva6_packed_axi4_cpu` 生成模板；它不改变原 ZipCPU 模板的接口假设。
4. 原 `axi4_cpu_session.py` 将 `i/d` 双通道与 32 位数据、4 字节事务写死。已增加 `GeneratedCva6Axi4Session`，服务统一的 64 位总线、8 字节 byte-enable、4 位响应 ID、单个读/写在途槽位和有限 burst。它只以 AXI 握手接受真实 RTL 请求；数据来自持续 RAM。旧 ZipCPU 通过仍不是 CVA6 证据。

## 最小可验收实现路径

1. 已在现有源码锁流程内统一 CVA6 profile 与 lock 的 include roots，生成并核对本地 elaboration 证据，将锁状态提升为 `elaboration_verified`。所有完整顶层端口仍由 profile 明确归属；未归属端口应失败关闭。
2. 已加入针对该固定 CVA6 形态的 `cpu.axi4` 模板变体：一个 64 位 packed AXI4 端点，依据已核实的 member bit range 展开端口；保留 4 位 ID、8 位 strobe、真实 AW/W/B/AR/R 握手。AXI atomic、exclusive、超出支持范围的尺寸/对齐、跨 4K burst 和越界 `WSTRB` 失败关闭。USER/QOS/PROT 等旁带字段作为普通 RAM 服务元数据处理，尚未对其语义做专门验收。
3. 已加入 64 位持久内存服务和 driver/session 变体；每次握手只提交一次，`WSTRB` 逐字节写入，读响应从同一 testcase 的持久状态取得，读写响应 ID 与 `LAST` 必须匹配真实请求。CVA6 内部行为由 RTL 执行。
4. 已用固定 RV64 程序验收真实取指、Store→若干周期→Load→Store；evidence bundle 在全新 CVA6 仿真进程 replay 后逐事件匹配。后续仍需补充分离的协议负例、真实 GPIO 中断及 MMIO 路由验收。

旧 Task 13 记录位于 `third_party/docs/task-13/cva6-fixed/`，`log-summary.txt` 显示 5 次取指、4 个提交 PC、写入通过值及 318 周期退出；它证明该固定 RTL 能在旧 composition/beat backend 下执行，**不证明**新的独立生成式 AXI4 harness 已运行。

## 2026-10-05 源码锁进展

固定 CVA6 源码的 Verilator lint elaboration 已在独立工作树中成功：顶层 `cva6`，输入为当前 profile 展开的 225 个 Verilog/SystemVerilog 文件，实际读取 232 个仓库内文件，其中 108 个由三个嵌套 Git 仓库拥有。退出码为 0，无编译错误，505 条非致命警告保存在 `docs/reports/cva6-elaboration-warnings-20261005.txt.gz`。`configs/soc/closures/cva6.json` 记录精确命令、工具版本、完整读集以及每个文件的 SHA-256；每个文件还逐一与其固定 Git blob 比对。源码锁中的 include roots 与 profile 现已相同，CVA6 elaboration 状态提升为 `elaboration_verified`。

源码锁验证器原先把嵌套 Git 仓库的相对路径误当成工作区根路径；此次改为将其接在组件 source root 下，并增加回归测试。此段记录的是源码锁阶段的状态；生成式运行时的后续验收见下文。

## 2026-10-05 生成式 runtime 阶段证据

生成式全顶层 structural wrapper 和专用 `cva6_packed_axi4_cpu` runtime top 已通过 Verilator lint。随后从这些生成物编译的驱动完成真实 reset，并以 1 个本地周期为单位返回 pre/post 边界快照；在第 400 个受测周期前观察到 CVA6 RTL 自身发出的首个 AXI4 AR 请求，地址为 profile 固定的 `0x10000`。旧手写 harness 的首次 AR 在复位后的第 268 个总周期，因此 200 个受测周期不足以覆盖这段初始化延迟。

此阶段只证明生成式驱动可运行、时钟/复位/端口映射允许真实取指请求到达 AXI4 边界。后续的响应服务与程序执行由下一节单独验收。

## 2026-10-05 真实内存服务与完整 testcase 证据

`GeneratedCva6Axi4Session` 从持久内存提供真实请求的 AXI R/B 响应，使用已接受的 AW/W/AR 握手驱动事务；无外部中断绑定时输入为静默电平 0。固定 boot 程序从 `0x10000` 取指，在 `0x400` 写入 `0x600dcafe`。最小真实 RTL 测试 `test_real_fetch_then_store_through_persistent_memory` 完成，预期值只来自 CPU 执行的写操作。

扩展程序执行 `SW [0x400]`、`LW [0x400]`、`SW [0x404]`。`test_store_load_store_and_fresh_evidence_replay` 的首次会话有至少两个真实读 beat、恰好两个真实写 beat；`0x400` 与 `0x404` 的四字节值均为 `0x600dcafe`。新进程运行的 formal replay 与保存的完整事件轨迹匹配，内存读回值相同，进程对象不同。命令：

```text
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_cva6_axi4_service_real.Cva6Axi4ServiceRealAcceptance.test_store_load_store_and_fresh_evidence_replay -q
Ran 1 test in 178.851s — OK
```

`test_cva6_axi4_service_protocol` 额外检查窄写 strobe 的合法 byte lane，以及 atomic/跨 4K 请求失败关闭。当前验证的能力边界是单个 CVA6 独立 harness 与持久 RAM 的连续 testcase；真实 IP MMIO 路由、跨组件事件/中断传播、更多 AXI 旁带语义及多 outstanding 仍待单独验收。生成模板目前仍通过 `component_id == cva6` 选择；尚未证明同协议的新 CPU 只增加 profile 就能复用，因此不能计为通用协议变体或 Stage D 验收完成。
