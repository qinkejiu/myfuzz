# Verilog / SystemVerilog 插装模块核查

日期：2026-09-25

## 结论

插装器已能为常见的 procedural `if/else`、`case` 以及部分单语句过程体插入 sticky hit 位，并把已识别的子模块命中逐层汇总到顶层。SoC profile 与 legacy campaign 构建路径都声明每个 testcase 重启仿真进程；profile 路径已用真实构建和连续样本回归验证。

但它不是完整的 SystemVerilog 语义插装器，目前不能据此声称任意 Verilog/SystemVerilog 都能完整、无副作用地插装。源码扫描器使用自有词法/结构识别；对复杂过程体、宏条件编译、接口/绑定等情况必须看具体生成结果和编译/仿真证据。以下发现需要先处理，尤其是输出目录保护和旧 SoC 入口的 testcase 隔离。

## 核查发现与修复结果

1. **高：`force=True` 可删除输入 RTL —— 已修复。** [`instrument_project`](../../scripts/source_branch_instrumenter.py) 现在拒绝输出树与项目树重叠、输出路径为 symlink、或输出树覆盖 filelist（含嵌套 filelist）、HDL 源、include 目录和 frontend JSON；解析、输入检查和分析均成功后才替换旧输出。正反用例覆盖输出等于/包含/位于项目根、symlink、外部输入和嵌套 filelist，原文件保持不变。

2. **高：旧 SoC campaign 入口的 sticky coverage 会跨 testcase 累积 —— 代码已修复，legacy 真实构建未验收。** 非 `composition_request` 路径现在返回 `isolate_tests=True` 并把重启理由写入 provenance；模拟器回归证明非隔离子进程会累积 sticky 位，隔离后每个测试的反馈从新进程开始。profile 路径的真实 Verilator 测试通过。legacy 的 opt-in 验收断言已加入 `test_soc_coverage_run.py`，但本机对 `ibex-pulp` 的真实构建在插装器之后报 `prim_secded_pkg` 未预声明（`ibex_lockstep.sv` 导入时不可见），因此该 legacy artifact 断言没有实际运行到；这是当前 SoC source closure/order 验证缺口，不能计作插装器通过证据。

3. **中：多个顶层的 coverage bit 编号冲突 —— 已修复。** [`flatten_instance_coverage`](../../scripts/source_branch_instrumenter.py) 在多个不同 top 产生 coverage 点时以 `multiple-coverage-tops-unsupported` 拒绝生成；没有 coverage 点的多 top file-map 用例仍可运行。新增双 branch-top 回归确认拒绝发生在发布输出目录之前。

4. **中：可选构建缓存没有绑定插装器实现身份 —— 已修复并通过真实缓存复用。** cache key 现在包含插装器源码 SHA-256、schema、规范化设置和生成插装 RTL/filelist 的确定性摘要；artifact provenance 同时记录这些身份。缓存命中前重算缓存输出摘要，复制到当前 build 后重定位 filelist/manifest 的绝对路径、校验闭包，再复核摘要；摘要规范化绝对 build 路径。单测覆盖身份/产物变化导致 key 变化及缓存内容篡改拒绝，真实 profile cache 测试确认第二次构建命中且不再引用首次 build 路径。

## 能力边界与覆盖缺口

- 当前实现是源码扫描和插入，不是完整的 SV AST 改写器。过程范围包括 `always`、`initial`、`final`、function、task；无法匹配的结构会跳过并记入插装 manifest 的 `skipped`。SoC 报告主要暴露插装点数、观测计划与未观测点，不把所有跳过项汇总成“RTL 分支完整率”。应把“已发现点数”和“未插装原因”同时作为验收数据。
- `condition`、`toggle`、部分 ternary、静态 generate 等配置项是 metadata 候选，不等同于已进入 RFuzz 的运行时覆盖。运行时默认重点是 if/case；增强配置才打开部分语句、循环、缺失 else 等插装。
- 扫描器不负责 Verilog 预处理。条件编译下的未激活代码、宏导致的模块变体、复杂生成层级，以及不在 filelist 但由 include 间接提供的定义，需要和实际工具展开结果对照；不能只凭静态点数推断已插装。
- 层级传播会改变模块端口列表，并改写源树内已解析到的实例连接。外部未纳入 filelist 的实例、black-box、复杂 wildcard/位置端口混用、接口/modport 和 bind 场景没有本轮充分的独立回归证据。
- RFuzz 覆盖预算有限，SoC 路径当前最多挑选 128 个反馈计数器；更宽的 coverage vector 会有明确的未观测点。它是采样子集，不是“所有分支均反馈给 RFuzz”。

## 修复后验证（2026-09-25）

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.test_source_branch_instrumenter tests.integration.test_rfuzz_simulator tests.integration.test_soc_coverage tests.integration.test_soc_profile_rfuzz_build.ProfileAdmissionTest`：80 项通过。
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_coverage_run`：4 项因默认未设置 `MYFUZZ_SOC_REAL=1` 跳过。
- 在允许进程组监督的环境中运行 `tests.integration.test_soc_profile_rfuzz_build.ProfileArtifactTest.test_profile_build_cache_reuses_the_compiled_rtl_artifact`：真实 Verilator 5.020 构建与缓存命中通过；`test_persistent_protocol_two_executes_and_resets`：真实 profile SoC 连续样本测试通过。
- legacy `ibex-pulp` 真实 artifact build 尝试未通过：编译报告 `prim_secded_pkg` 未预声明、被 `ibex_lockstep.sv` 导入时不可见；所以新增的 legacy 隔离验收断言仍待 source closure/order 修复后运行。
- `git diff --check`：通过。

## 未解决能力边界

- 本轮没有扩展到宏预处理、完整 SystemVerilog AST 改写、interfaces/modports、bind 或所有 generate/过程语法的支持；原有能力边界仍成立。
- `test_soc_coverage_run` 的八组合真实 RFuzz campaign 未执行；legacy builder 的一次真实编译先被 Ibex source closure 的 package 可见性/顺序问题阻挡。代码已设 testcase 隔离，但 legacy 真实产物闭环还不能宣称验收通过。
- 插装器只适用于已有证据覆盖的 RTL 子集；不能宣称任意 SV 都能完整无副作用插装。
