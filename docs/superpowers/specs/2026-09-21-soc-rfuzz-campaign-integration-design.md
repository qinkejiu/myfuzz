# Profile SoC 接入官方 RFuzz campaign 设计

日期：2026-09-21
状态：设计稿，范围已由用户确认；本文件只定义接入方案，不表示源码实现已完成。

## 1. 目标与边界

本项的目标是把现有 `component_profile.v1` 组合路径接入官方 RFuzz 客户端，使用户提交的 CPU/外设 profile 生成的 SoC 能够通过 RFuzz 的 FIFO/共享内存协议接受变异输入、执行真实 RTL、收集覆盖和保存可重放语料。

正式生产入口固定复用现有链路：

```text
campaign config
  -> load_profile_campaign_request
  -> build_soc_campaign_artifact
  -> official kfuzz + rfuzz_live
  -> FIFO/shared-memory protocol
  -> persistent Verilator RTL
  -> corpus / receipts / coverage / replay report
```

本项不做以下事情：

- 不另写一套 RFuzz transport、FIFO、共享内存或客户端生命周期管理；
- 不用 Python、全零探针或 seeded-corpus 运行冒充官方 RFuzz 变异 campaign；
- 不把 BFM `isolated/contention` 主接口塞入本项；
- 不实现异构 peer 的独立协议 oracle；
- 不因 RFuzz 发现异常就直接声称“组件内部 bug”。归因仍必须经过独立规范和边界排除链。

缺少官方 `kfuzz`、bundled Verilator 5.020、真实 RTL 闭包或共享内存清理证据时，运行必须失败或明确标为环境不可用，不能降级为“通过”。

## 2. 当前代码事实与缺口

当前仓库已经具备大部分可复用部件：

- `soc_builder.load_profile_campaign_request` 能从 component profile 和 composition request 读取 CPU、外设、内存和 drive profile；
- `_build_profile_campaign_artifact` 能生成组合计划、RTL top、结构审计、输入 layout、约束策略、image plan、RFuzz transport、persistent testbench、覆盖插桩和可执行文件；
- `SocCampaignArtifact.projection_arms` 已保存 `direct_input`、`constrained_baseline` 和 `dependency_repair` 三个 projector；
- `soc_campaign.run_soc_campaign` 已有默认 builder、客户端阶段、corpus/replay、receipt、异常和中断清理报告；
- `rfuzz_live.run_live` 已实现官方客户端、FIFO、共享内存、RTL 执行、bounded drain 和语料 manifest；
- `soc_comparison.execute_soc_campaign_arms` 已能在真实 RTL 上执行 seeded corpus，并明确记录“没有执行官方 RFuzz client”。

需要补齐的生产缺口是：

1. profile builder 目前允许从 PATH 选择任意 `verilator`，没有强制 bundled RFuzz Verilator 5.020；本机 5.051-devel 不能作为替代。
2. 客户端路径、客户端版本、运行目录和工具环境没有统一的、可审计的 resolver 与冲突检查。
3. profile SoC 的官方客户端正例、缺依赖负例、身份漂移负例和 corpus 重放正例没有形成一组独立的生产验收入口。
4. 三臂的 seeded-corpus 执行不能被写成官方三臂变异结果；当前 `kfuzz` 没有可注入的全局 seed，三次独立客户端运行产生的输入不能声称相同。
5. BFM 主接口仍没有进入 RFuzz layout；本项应保持明确缺口，而不是在 layout 中放一个无语义的随机槽位。

## 3. 目标架构

### 3.1 工具链解析器

新增一个统一的 RFuzz 工具链解析边界（可以放在 `soc_campaign` 或独立的 `soc_rfuzz_toolchain` 模块中）：

- 客户端优先级：配置显式 `client_binary`，其次是明确的 `MYFUZZ_RFuzz_CLIENT`，最后才允许仓库内固定的默认路径；未找到即 `rfuzz-client-unavailable`；
- Verilator 优先使用 `myfuzz.rfuzz_compat.resolve_rfuzz_verilator(root)`；显式 override 也必须经过 regular-file、可执行和版本检查；
- 运行 `verilator --version`，通过 `validate_rfuzz_verilator_version` 强制版本前缀为 `Verilator 5.020`；
- 使用 `rfuzz_verilator_environment` 设置与 bundled 安装匹配的 `VERILATOR_ROOT`/`VERILATOR_BIN`；
- 对客户端保存绝对路径、SHA-256、版本输出和工作目录；对 Verilator 保存绝对路径、SHA-256、版本输出和 bundled/override 来源；
- 禁止 `shutil.which("verilator")` 作为无条件 fallback，禁止把本机其他版本写进 provenance 后继续运行。

工具链身份进入 artifact build hash、cache key、campaign report 和 replay identity。改变客户端、Verilator、版本或环境变量时，缓存必须失效，旧 corpus 必须拒绝重放。

### 3.2 配置归一化

保留当前顶层配置字段的兼容性，同时支持明确的 `rfuzz` 子对象：

```json
{
  "rfuzz": {
    "client_binary": "runs/rfuzz_client_native_build/target/debug/kfuzz",
    "verilator": "bundled",
    "run_dir": "runs/soc-rfuzz",
    "duration_seconds": 30,
    "seed_cycles": 5,
    "build_cache_dir": "runs/soc-rfuzz-cache",
    "arm": "direct_input"
  }
}
```

归一化规则：

- 子对象字段与旧顶层字段同时存在且不相等时拒绝；
- `verilator: bundled` 是默认且唯一的生产模式；显式路径只作为经过版本校验的受控 override；
- `arm` 首期只接受一个正式 RFuzz 臂，值为三个已构建 projector 之一；
- `MYFUZZ_SOC_REAL=1` 仍是生产运行的必要条件；preflight 可以不启动客户端，但必须报告缺少的依赖。

### 3.3 artifact 构建

`build_soc_campaign_artifact` 继续承担组合和编译，但改为接收解析后的工具链记录：

1. 加载 profile 和 composition request；
2. 生成 composition、layout、policy、image、peer slots 和 source closure；
3. 对实际生成 top 做独立结构审计；
4. 使用固定 Verilator 5.020 编译 persistent testbench；
5. 对 executable 做 probe，确认 protocol-2 header、coverage 端口和输入宽度一致；
6. 写出 `artifact_provenance.json`，至少包含 composition/layout/policy/constraint/image/source/tool/coverage/cache 身份；
7. 返回一个可被 `rfuzz_live` 消费的 `SocCampaignArtifact`，其 `projector` 是选择的正式臂，`projection_arms` 保存其他臂供后续重放。

缓存仍然是内容寻址：样本内容不能改变 RTL 编译缓存；composition、layout、policy、image、source closure、工具链、外部默认值或生成器 schema 任一改变都必须改变 cache key。

### 3.4 官方 RFuzz 单臂运行

`run_soc_campaign` 的生产默认路径保持不变，但必须调用统一工具链解析器，并把解析结果传入 builder 和 `run_live`：

- `run_live` 启动官方 `kfuzz`，不自行生成随机输入；
- RFuzz raw input 通过现有 transport/FIFO/shared-memory 进入 RTL；
- `RtlSimulator.run_test` 只在声明的 projector 上投影，并记录 raw/projected/rejection/repair 统计；
- 每次完成的请求保存 raw hash、coverage hash、receipt、执行指标和 peer event hash（若有）；
- 客户端、模拟器、FIFO 和共享内存都由 runner 创建并由 runner 清理；
- 客户端在 deadline 后的 bounded drain 按现有 `interrupted-run-policy.v1` 分类，只有 receipt、corpus、transport identity 和 clean cleanup 全部存在时才允许 `completed_with_client_termination`；
- build、transport、protocol、环境或清理失败不能套用中断成功策略。

首期的“官方 RFuzz 已接入”只在以下意义上成立：一个指定 arm 的 profile artifact 被真实 `kfuzz` 连续驱动，并保存了非空 corpus、FIFO receipt、RTL coverage 和可重放 manifest。

### 3.5 三臂对照

三臂分两个阶段，报告中必须区分执行模式：

1. `official-rfuzz-single-arm`：一个选定 projector 被官方 `kfuzz` 变异；
2. `official-rfuzz-corpus-replay-3arm`：使用该官方运行保留的同一 raw corpus，分别用三个 projector 重新执行并比较覆盖、有效率、拒绝、修复和异常。

第二阶段可以复用 `replay_corpus`/`RtlSimulator`，但每个 arm 必须使用同一 executable、source closure、layout、composition、coverage 和工具身份。报告应明确它是“官方语料 + 三臂重放”，不是三个官方变异器搜索。

在官方客户端提供可审计的 seed/queue 注入能力前，禁止把三次独立 `kfuzz` 运行标记为同输入对照。若未来实现真正的三客户端同 corpus 运行，必须新增客户端版本/seed/queue 身份并单独验收。

## 4. 身份、输出和错误处理

每次运行的 `report.json` 必须至少包含：

- `execution_mode`、`arm`、`config_id`、`composition_hash`、`layout_hash`；
- `constraint_hash`、`policy_hash`、`image_hash`、`source_closure_hash`；
- client/verilator path、version、SHA-256 和 simulator protocol version；
- input transport identity、raw/projected sample count、unique count、rejection reason、repair count；
- FIFO receipt count/sample、RTL tests、coverage identity、execution totals；
- corpus entry count、manifest hash、replay status、rebuild executable hash；
- process group、owned shared-memory segments、removed/remaining segments；
- `status`、`final_status`、`evidence_missing` 和精确失败 phase。

统一的拒绝/失败分类至少包括：

- `rfuzz-opt-in-required`；
- `rfuzz-client-unavailable`；
- `rfuzz-verilator-unavailable`；
- `rfuzz-verilator-version-mismatch`；
- `profile-build-failed`；
- `structure-audit-failed`；
- `transport-identity-mismatch`；
- `rfuzz-client-protocol-failed`；
- `corpus-empty`；
- `corpus-replay-failed`；
- `shared-memory-leak`；
- `arm-identity-mismatch`。

任何失败都必须保留 bounded report 和 stderr/client log；不能用退出码为零但无 receipt、无 corpus 或无 coverage 的运行作为成功。

## 5. 测试与验收

### 5.1 快速契约测试

新增或扩展以下测试：

- 工具链 resolver：缺文件、非 regular file、不可执行、版本不是 5.020、override 环境和 bundled 环境；
- 配置归一化：新旧字段等价、冲突拒绝、缺客户端拒绝、缺 `MYFUZZ_SOC_REAL` 拒绝；
- builder：确认传入固定 Verilator 路径和环境，artifact provenance 包含完整工具身份；
- cache：样本变化命中缓存，profile/layout/policy/tool 变化失效缓存；
- campaign：builder/runner/rebuilder 的注入路径、阶段失败、receipt 缺失、corpus 空、清理泄漏和 bounded-drain 分类；
- 三臂重放：三个 arm 使用同一 corpus 和 identity；任一 layout/composition/tool/executable 变化都拒绝；
- 不支持能力：BFM 主接口缺失不能被报告为 RFuzz 已支持。

### 5.2 真实 opt-in 回归

在具备依赖的机器上运行：

```bash
MYFUZZ_SOC_REAL=1 \
MYFUZZ_RFuzz_CLIENT="$PWD/runs/rfuzz_client_native_build/target/debug/kfuzz" \
PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_soc_profile_rfuzz_campaign
```

该套件必须使用一个 profile composition request，且不能注入 mock builder/runner。最低证据为：

- 使用 bundled Verilator 5.020；
- 官方 `kfuzz` 真正启动并完成至少一个 FIFO/shared-memory exchange；
- RTL 执行次数大于零，coverage 非空或明确记录为零覆盖；
- corpus 非空并有 manifest；
- 重新构建 executable 后 corpus replay 成功；
- owned shared-memory segments 为零；
- report 中的 composition/layout/transport/tool identity 可重放；
- 缺少任一依赖时测试失败并指出具体依赖，而不是 skip 成功。

三臂验收另运行：

```bash
MYFUZZ_SOC_REAL=1 \
MYFUZZ_RFuzz_CLIENT="$PWD/runs/rfuzz_client_native_build/target/debug/kfuzz" \
PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_soc_campaign_arms \
  tests.integration.test_soc_campaign_comparison
```

如果官方客户端只完成单臂变异而其余臂是同 corpus 重放，报告必须使用 `official-rfuzz-corpus-replay-3arm`，不得使用“three official fuzz campaigns”措辞。

## 6. 分阶段实现顺序

1. 抽出并测试 RFuzz client/Verilator resolver，接入 `rfuzz_compat` 的固定 5.020 校验。
2. 扩展 campaign config 的 `rfuzz` 子对象和冲突检查，保持旧顶层字段兼容。
3. 修改 profile builder 的 compile command、环境、artifact provenance 和 cache key，使工具身份成为硬约束。
4. 增加 profile composition 的真实单臂 campaign 测试；先通过缺依赖负例，再在完整环境跑正例。
5. 将官方 corpus 接入三个 projector 的严格重放，对比 direct/constrained/repair，并保存独立 arm reports。
6. 补齐报告、replay identity、client termination 和 cleanup 审计。
7. 更新 capability matrix、acceptance report 和 remaining task 清单；在没有真实客户端证据前保留“seeded-corpus”状态。

## 7. 明确验收结论

实现本设计后，可以声称：在固定工具和客户端可用的环境中，profile-driven SoC artifact 已进入官方 RFuzz protocol-2 运行路径，并能保存、重建和重放真实 RFuzz 语料。

仍不能因此声称：任意 CPU/外设均可组合、BFM 已接入、三次独立 fuzz 是同输入对照、peer 行为已有独立 oracle，或异常已经证明是组件内部 bug。上述结论必须由各自的独立验收证据支持。
