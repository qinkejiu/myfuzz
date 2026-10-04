# CVA6 生成式本地 harness 可行性核查（2026-10-05）

## 结论与状态

**状态：`not_supported`（生成式本地运行时）；不是 `skipped_unavailable`。** 固定版本的真实 CVA6 RTL 及其嵌套源码在主工作区可用，旧的 Task 13 有真实取指、提交和程序写入通过值的记录。但当前 `local_harness.v1/v2` 不能把该 CVA6 profile 生成成可运行的本地 AXI4 harness。本次没有运行或声称 CVA6 生成式 testcase/replay 通过。

## 初始阻塞点与当前边界

1. `configs/cpus/cva6/component_profile.json` 固定 `third_party/cva6_upstream_reference@2e1336dcff3d1a0b49fbe6282b97802f32ea32af`，主工作区子模块 HEAD 与之相同。`plan_local_harness` 在已初始化该子模块的主工作区成功，识别 `cva6` 和 57 条物理端口 disposition。新 Git worktree 中必须先初始化子模块，否则会先报 `elaboration-failed:cva6:git-revision-mismatch`；这是工作树准备问题，不是 RTL 不可用。
2. 修复前，`verify_local_source_lock(profile, base_dir=root)` 报 `ValueError: local-source-lock-source-mismatch:include_roots`：CVA6 profile 声明七个 include root，而锁记录为空；锁记录还标记 `elaboration_unverified`。本报告末尾记录了本次完成的源码锁修复及验证结果。
3. `src/myfuzz/local_harness/runtime_renderer.py` 的 `axi4_cpu` 分支要求**两个** `instruction_memory_master`/`data_memory_master` 端点，能力值必须是地址 32 位、数据 32 位、ID 1 位且 `bursts=true`。CVA6 profile 是**一个** `memory_master` 端点，地址/数据各 64 位、ID 4 位，并在 `noc_req_o`/`noc_resp_i` 打包结构体上声明 45 个 AXI4 角色及额外字段。固定配置的 `CVA6ConfigAxiAddrWidth=64`、`CVA6ConfigAxiDataWidth=64`、`CVA6ConfigAxiIdWidth=4` 可直接从 `core/include/cv64a6_imafdc_sv39_config_pkg.sv` 复核。只改字段别名无法满足现有分支。
4. `src/myfuzz/local_harness/axi4_fields.py` 和 `axi4_cpu_session.py` 将 `i/d` 双通道与 32 位数据、4 字节事务写死。CVA6 需要统一的 64 位总线、8 字节 byte-enable、4 位响应 ID，以及对其实际产生的 burst/未完成事务的严格握手服务。现有 ZipCPU 通过不构成 CVA6 通过证据。

## 最小可验收实现路径

1. 已在现有源码锁流程内统一 CVA6 profile 与 lock 的 include roots，生成并核对本地 elaboration 证据，将锁状态提升为 `elaboration_verified`。所有完整顶层端口仍由 profile 明确归属；未归属端口应失败关闭。
2. 增加一个针对该固定 CVA6 形态的 `cpu.axi4` 模板变体：一个 64 位 packed AXI4 端点，依据编译器核实过的 member bit range 展开 `noc_req_o`/`noc_resp_i`；保留 4 位 ID、8 位 strobe、真实 AXI4 AW/W/B/AR/R 握手。模板需显式约束其允许的 ATOP、USER、burst、outstanding 子集；超出子集时记录环境不支持，不能伪造成功响应。
3. 增加相应 64 位持久内存服务和 driver/session 变体；每次握手只提交一次，`WSTRB` 逐字节写入，读响应从同一 testcase 的持久状态取得，读写响应 ID 与 `LAST` 必须回显真实请求。CVA6 内部 RTL 不在跨组件层重建。
4. 用固定 RV64 程序验收真实取指、Store→若干周期→Load 与最终可观察结果；保存 evidence bundle 后创建全新进程/仿真会话 replay，逐项比较 transaction、状态摘要和最终内存。负例需覆盖错误 ID、错误 LAST、重复 W 提交、未归属端口、源码锁漂移。

旧 Task 13 记录位于 `third_party/docs/task-13/cva6-fixed/`，`log-summary.txt` 显示 5 次取指、4 个提交 PC、写入通过值及 318 周期退出；它证明该固定 RTL 能在旧 composition/beat backend 下执行，**不证明**新的独立生成式 AXI4 harness 已运行。

## 2026-10-05 源码锁进展

固定 CVA6 源码的 Verilator lint elaboration 已在独立工作树中成功：顶层 `cva6`，输入为当前 profile 展开的 225 个 Verilog/SystemVerilog 文件，实际读取 232 个仓库内文件，其中 108 个由三个嵌套 Git 仓库拥有。退出码为 0，无编译错误，505 条非致命警告保存在 `docs/reports/cva6-elaboration-warnings-20261005.txt.gz`。`configs/soc/closures/cva6.json` 记录精确命令、工具版本、完整读集以及每个文件的 SHA-256；每个文件还逐一与其固定 Git blob 比对。源码锁中的 include roots 与 profile 现已相同，CVA6 elaboration 状态提升为 `elaboration_verified`。

源码锁验证器原先把嵌套 Git 仓库的相对路径误当成工作区根路径；此次改为将其接在组件 source root 下，并增加回归测试。下一阶段仍须单独实现 64 位 packed AXI4 生成式 harness/session，完成真实 Store/Load 和全新会话 replay。`runtime_status` 仍为 `runtime_unverified`，生成式 CVA6 状态仍是 `not_supported`。
